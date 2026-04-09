use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::AppError;
use crate::model::account::{Account, AccountStatus};
use crate::model::api_token::ApiToken;
use crate::service::account::AccountService;
use crate::service::rewriter::{
    clean_session_id_from_body, detect_client_type, ClientType, Rewriter,
};
use crate::service::telemetry::TelemetryService;

const UPSTREAM_BASE: &str = "https://api.anthropic.com";

pub struct GatewayService {
    account_svc: Arc<AccountService>,
    rewriter: Arc<Rewriter>,
    telemetry_svc: Arc<TelemetryService>,
}

impl GatewayService {
    pub fn new(
        account_svc: Arc<AccountService>,
        rewriter: Arc<Rewriter>,
        telemetry_svc: Arc<TelemetryService>,
    ) -> Self {
        Self {
            account_svc,
            rewriter,
            telemetry_svc,
        }
    }

    /// 核心网关逻辑 -- axum handler。
    pub async fn handle_request(&self, req: Request, api_token: Option<&ApiToken>) -> Response {
        match self.handle_request_inner(req, api_token).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        }
    }

    async fn handle_request_inner(&self, req: Request, api_token: Option<&ApiToken>) -> Result<Response, AppError> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        // 提取 header
        let headers = extract_headers(req.headers());
        let ua = headers.get("User-Agent").or_else(|| headers.get("user-agent")).cloned().unwrap_or_default();

        // 读取请求体
        let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
            .await
            .map_err(|e| AppError::BadRequest(format!("failed to read body: {}", e)))?;

        // 解析请求体
        let body_map: serde_json::Value = if body_bytes.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::json!({}))
        };

        // 检测客户端类型
        let client_type = detect_client_type(&ua, &body_map);

        // 生成会话哈希
        let session_hash =
            crate::service::account::generate_session_hash(&ua, &body_map, client_type);

        // 根据令牌限制构建账号过滤条件
        let (allowed_ids, blocked_ids) = if let Some(t) = api_token {
            (t.allowed_account_ids(), t.blocked_account_ids())
        } else {
            (vec![], vec![])
        };

        // 429 自动换号重试循环
        let mut exclude_ids = blocked_ids.clone();
        let mut last_resp: Option<Response> = None;

        loop {
            let attempt = exclude_ids.len().saturating_sub(blocked_ids.len());
            // 选择账号
            let account = match self
                .account_svc
                .select_account(&session_hash, &exclude_ids, &allowed_ids)
                .await
            {
                Ok(a) => a,
                Err(_) if last_resp.is_some() => {
                    // 无可用账号但有上一次的 429 响应，返回给客户端
                    return Ok(last_resp.unwrap());
                }
                Err(e) => {
                    return Err(AppError::ServiceUnavailable(format!(
                        "no available account: {}",
                        e
                    )));
                }
            };

            if attempt > 0 {
                warn!(
                    "429 retry attempt {} with account {}",
                    attempt, account.id
                );
            }

            // 自动遥测：拦截遥测请求 + 激活会话
            if account.auto_telemetry {
                use crate::service::telemetry::{is_telemetry_path, fake_metrics_enabled_response, fake_telemetry_response};

                if is_telemetry_path(&path) {
                    let body = if path.contains("/metrics_enabled") {
                        fake_metrics_enabled_response()
                    } else {
                        fake_telemetry_response()
                    };
                    debug!("telemetry: intercepted {} for account {}", path, account.id);
                    return Ok(axum::Json(body).into_response());
                }

                if path.starts_with("/v1/messages") {
                    self.telemetry_svc.activate_session(&account).await;
                }
            }

            // 获取并发槽位
            let acquired = self
                .account_svc
                .acquire_slot(account.id, account.concurrency)
                .await
                .map_err(|_| AppError::TooManyRequests("concurrency slot unavailable".into()))?;
            if !acquired {
                return Err(AppError::TooManyRequests("concurrency slot unavailable".into()));
            }

            // 确保在函数结束后释放槽位
            let account_svc = self.account_svc.clone();
            let account_id_for_release = account.id;
            let _guard = scopeguard::guard((), move |_| {
                let svc = account_svc.clone();
                tokio::spawn(async move {
                    svc.release_slot(account_id_for_release).await;
                });
            });

            // 改写请求体
            debug!(
                "request body BEFORE rewrite: {}",
                truncate_body(&body_bytes, 4096)
            );
            let rewritten_body =
                self.rewriter
                    .rewrite_body(&body_bytes, &path, &account, client_type);
            debug!(
                "request body AFTER rewrite: {}",
                truncate_body(&rewritten_body, 4096)
            );

            // 重新解析改写后的 body
            let mut rewritten_body_map: serde_json::Value =
                serde_json::from_slice(&rewritten_body).unwrap_or(serde_json::json!({}));

            // 改写 header
            let model_id = body_map
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or("");
            let rewritten_headers = self.rewriter.rewrite_headers(
                &headers,
                &account,
                client_type,
                model_id,
                &rewritten_body_map,
            );

            // 清理 body 中的 _session_id 标记并重新序列化
            let final_body = if client_type == ClientType::API {
                clean_session_id_from_body(&mut rewritten_body_map);
                serde_json::to_vec(&rewritten_body_map).unwrap_or_else(|_| rewritten_body.clone())
            } else {
                rewritten_body.clone()
            };

            let upstream_token = self.account_svc.resolve_upstream_token(account.id).await?;
            let mut final_headers = rewritten_headers;
            final_headers.insert(
                "authorization".into(),
                format!("Bearer {}", upstream_token),
            );

            // 转发到上游
            let resp = self
                .forward_request(
                    &method.to_string(),
                    &path,
                    &query,
                    &final_headers,
                    &final_body,
                    &account,
                )
                .await?;

            // 非 429 直接返回
            if resp.status() != StatusCode::TOO_MANY_REQUESTS {
                return Ok(resp);
            }

            // 429：排除该账号，尝试下一个
            warn!(
                "account {} returned 429, excluding and retrying (attempt {})",
                account.id,
                attempt + 1,
            );
            exclude_ids.push(account.id);
            // 取消 scopeguard 并手动释放槽位，避免重复释放
            std::mem::forget(_guard);
            self.account_svc.release_slot(account.id).await;
            last_resp = Some(resp);
        }
    }

    async fn forward_request(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
        account: &Account,
    ) -> Result<Response, AppError> {
        let mut target_url = format!("{}{}", UPSTREAM_BASE, path);
        if !query.is_empty() {
            let q = if query.contains("beta=true") {
                query.to_string()
            } else {
                format!("{}&beta=true", query)
            };
            target_url = format!("{}?{}", target_url, q);
        } else {
            target_url = format!("{}?beta=true", target_url);
        }

        debug!("upstream URL: {}", target_url);

        let client = crate::tlsfp::make_request_client(&account.proxy_url);

        let mut req_builder = match method {
            "GET" => client.get(&target_url),
            "POST" => client.post(&target_url),
            "PUT" => client.put(&target_url),
            "DELETE" => client.delete(&target_url),
            "PATCH" => client.patch(&target_url),
            _ => client.post(&target_url),
        };

        for (k, v) in headers {
            debug!("upstream header: {}: {}", k, v);
            req_builder = req_builder.header(k, v);
        }
        req_builder = req_builder.header("Host", "api.anthropic.com");
        req_builder = req_builder.body(body.to_vec());

        let resp = req_builder
            .send()
            .await
            .map_err(|e| {
                warn!("upstream error for account {}: {}", account.id, e);
                AppError::BadGateway("upstream request failed".into())
            })?;

        let status_code = resp.status().as_u16();
        debug!("upstream response: {}", status_code);

        // 处理限速：429 自动停用 5 小时
        if status_code == 429 {
            let reset_at = Utc::now() + chrono::Duration::hours(5);
            if let Err(e) = self
                .account_svc
                .disable_account(
                    account.id,
                    AccountStatus::Active,
                    "429 速率限制",
                    Some(reset_at),
                )
                .await
            {
                warn!("failed to disable account {} for 429: {}", account.id, e);
            } else {
                warn!(
                    "account {} rate limited for 5h until {}",
                    account.id,
                    reset_at.to_rfc3339()
                );
            }
        }

        // 处理认证失败：403 永久停用（但如果账号已处于 429 限流中则跳过，避免误判）
        if status_code == 403 {
            let is_rate_limited = account
                .rate_limit_reset_at
                .map(|reset| Utc::now() < reset)
                .unwrap_or(false);
            if is_rate_limited {
                warn!(
                    "account {} got 403 while rate-limited, skipping permanent disable",
                    account.id
                );
            } else if let Err(e) = self
                .account_svc
                .disable_account(
                    account.id,
                    AccountStatus::Disabled,
                    "403 认证失败",
                    None,
                )
                .await
            {
                warn!("failed to disable account {} for 403: {}", account.id, e);
            } else {
                warn!("account {} permanently disabled for 403", account.id);
            }
        }

        // 构建响应
        let mut response_builder = Response::builder().status(
            StatusCode::from_u16(status_code)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );

        for (k, v) in resp.headers() {
            let name = k.as_str();
            // 过滤已知 AI Gateway / 代理指纹响应头，防止客户端检测并上报
            if is_gateway_fingerprint_header(name) {
                continue;
            }
            response_builder = response_builder.header(k.clone(), v.clone());
        }

        // 流式传输响应体
        let body_stream = resp.bytes_stream();
        let body = Body::from_stream(body_stream);

        response_builder
            .body(body)
            .map_err(|e| AppError::Internal(format!("build response: {}", e)))
    }

}

fn extract_headers(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (k, v) in headers {
        if let Ok(val) = v.to_str() {
            map.insert(k.to_string(), val.to_string());
        }
    }
    map
}

/// Claude Code 主动扫描响应头检测 AI Gateway/代理（src/services/api/logging.ts）。
/// 过滤这些指纹前缀以防止客户端上报 gateway 类型。
/// Claude Code 扫描的 AI Gateway 响应头前缀（来源: src/services/api/logging.ts）。
const GATEWAY_HEADER_PREFIXES: &[&str] = &[
    "x-litellm-", "helicone-", "x-portkey-", "cf-aig-", "x-kong-", "x-bt-",
];

fn is_gateway_fingerprint_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    GATEWAY_HEADER_PREFIXES.iter().any(|p| lower.starts_with(p))
}

fn truncate_body(b: &[u8], max: usize) -> String {
    if b.len() > max {
        format!(
            "{}...(truncated)",
            String::from_utf8_lossy(&b[..max])
        )
    } else {
        String::from_utf8_lossy(b).to_string()
    }
}
