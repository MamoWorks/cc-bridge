use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::error::AppError;
use crate::model::account::{Account, AccountStatus};
use crate::model::api_token::ApiToken;
use crate::service::account::AccountService;
use crate::service::rewriter::{
    ClientType, Rewriter, clean_session_id_from_body, detect_client_type,
};
use crate::service::telemetry::TelemetryService;
use crate::store::cache::CacheStore;

const UPSTREAM_BASE: &str = "https://api.anthropic.com";

fn perf_enabled() -> bool {
    static PERF_ENABLED: OnceLock<bool> = OnceLock::new();
    *PERF_ENABLED.get_or_init(|| std::env::var("PERF_TRACE").ok().as_deref() == Some("1"))
}

fn perf_log(rid: &str, phase: &str, elapsed_ms: f64) {
    if perf_enabled() {
        tracing::info!(target: "perf", "rid={} phase={} ms={:.3}", rid, phase, elapsed_ms);
    }
}

/// 持有一个并发槽（cache 中的一个计数键），drop 时触发异步释放。
///
/// 通过 `disarm()` 可以在已手动释放时跳过 drop-time 释放，避免双重扣减。
pub struct SlotHolder {
    cache: Arc<dyn CacheStore>,
    key: String,
    released: bool,
}

impl SlotHolder {
    /// 构造一个将在 drop 时释放指定 key 的 holder。
    /// 调用者必须保证 `cache.acquire_slot(key, ...)` 已经成功获取。
    pub fn new(cache: Arc<dyn CacheStore>, key: String) -> Self {
        Self {
            cache,
            key,
            released: false,
        }
    }

    /// 标记为已释放，阻止 Drop 时再次触发 release。
    pub fn disarm(mut self) {
        self.released = true;
    }
}

impl Drop for SlotHolder {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let cache = self.cache.clone();
        let key = std::mem::take(&mut self.key);
        // 与旧 scopeguard 一致，使用 tokio::spawn 异步释放（Drop 可能在同步上下文）
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { cache.release_slot(&key).await });
        }
    }
}

pin_project! {
    /// 把 SlotHolder 绑定在响应 body 流上：流读完或被 drop 时槽位才释放。
    pub struct SlotHeldStream<S> {
        #[pin]
        inner: S,
        _slot: SlotHolder,
    }
}

impl<S> SlotHeldStream<S> {
    pub fn new(inner: S, slot: SlotHolder) -> Self {
        Self { inner, _slot: slot }
    }
}

impl<S: Stream> Stream for SlotHeldStream<S> {
    type Item = S::Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

pub struct GatewayService {
    account_svc: Arc<AccountService>,
    rewriter: Arc<Rewriter>,
    telemetry_svc: Arc<TelemetryService>,
    limit_store: Arc<crate::service::limit::LimitStore>,
}

impl GatewayService {
    pub fn new(
        account_svc: Arc<AccountService>,
        rewriter: Arc<Rewriter>,
        telemetry_svc: Arc<TelemetryService>,
        limit_store: Arc<crate::service::limit::LimitStore>,
    ) -> Self {
        Self {
            account_svc,
            rewriter,
            telemetry_svc,
            limit_store,
        }
    }

    /// 核心网关逻辑 -- axum handler。
    pub async fn handle_request(&self, req: Request, api_token: Option<&ApiToken>) -> Response {
        match self.handle_request_inner(req, api_token).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        }
    }

    #[allow(unused_assignments)]
    async fn handle_request_inner(
        &self,
        req: Request,
        api_token: Option<&ApiToken>,
    ) -> Result<Response, AppError> {
        let rid = format!("{:08x}", rand::random::<u32>());
        let t_start = Instant::now();
        let mut t_prev = t_start;
        macro_rules! cp {
            ($name:expr) => {
                let _now = Instant::now();
                perf_log(&rid, $name, _now.duration_since(t_prev).as_secs_f64() * 1000.0);
                t_prev = _now;
            };
        }

        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        // 提取 header
        let headers = extract_headers(req.headers());
        let ua = headers
            .get("User-Agent")
            .or_else(|| headers.get("user-agent"))
            .cloned()
            .unwrap_or_default();

        // 读取请求体
        let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
            .await
            .map_err(|e| AppError::BadRequest(format!("failed to read body: {}", e)))?;
        cp!("body_read");

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
        cp!("session_hash");

        // 根据令牌限制构建账号过滤条件
        let (allowed_ids, blocked_ids) = if let Some(t) = api_token {
            (t.allowed_account_ids(), t.blocked_account_ids())
        } else {
            (vec![], vec![])
        };

        // Sonnet 请求旁路：让本地限流状态不拦截 Sonnet，由 Anthropic 自己拒。
        // 约定：request body 里 model 字段含 "sonnet"（大小写不敏感）即认定为 Sonnet。
        let is_sonnet_request = body_map
            .get("model")
            .and_then(|m| m.as_str())
            .map(|m| m.to_ascii_lowercase().contains("sonnet"))
            .unwrap_or(false);

        // 黏性透传策略：429 不再 retry 其它账号（换号会 bust prompt cache，成本爆炸）。
        // 本次请求拿到 429 → 包装成通用错误 body 返回；后续并发请求由 absorb_headers
        // 更新的 state.status / rate_limited_until 让 selector 自然避开此账号。
        let account = match self
            .account_svc
            .select_account(&session_hash, &blocked_ids, &allowed_ids, is_sonnet_request)
            .await
        {
            Ok(a) => a,
            Err(e) => {
                return Err(AppError::ServiceUnavailable(format!(
                    "no available account: {}",
                    e
                )));
            }
        };
        cp!("select_account");

        // 自动遥测：拦截遥测请求 + 激活会话
        if account.auto_telemetry {
            use crate::service::telemetry::{
                fake_metrics_enabled_response, fake_telemetry_response, is_telemetry_path,
            };

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
                let model_id = body_map.get("model").and_then(|m| m.as_str()).unwrap_or("");
                self.telemetry_svc
                    .activate_session(&account, model_id)
                    .await;
            }
        }

        // 获取并发槽位
        let acquired = self
            .account_svc
            .acquire_slot(account.id, account.concurrency)
            .await
            .map_err(|_| AppError::TooManyRequests("concurrency slot unavailable".into()))?;
        if !acquired {
            return Err(AppError::TooManyRequests(
                "concurrency slot unavailable".into(),
            ));
        }
        cp!("slot_acquire");

        // SlotHolder 承载槽位所有权：SlotHeldStream 随 body 流结束/中断才释放；
        // 429 包装时原 resp 被 drop → SlotHolder 也被 drop → 自动释放。
        let slot = self.account_svc.slot_holder_for(account.id);

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

        let mut rewritten_body_map: serde_json::Value =
            serde_json::from_slice(&rewritten_body).unwrap_or(serde_json::json!({}));

        let model_id = body_map.get("model").and_then(|m| m.as_str()).unwrap_or("");
        let rewritten_headers = self.rewriter.rewrite_headers(
            &headers,
            &account,
            client_type,
            model_id,
            &rewritten_body_map,
        );

        let final_body = if client_type == ClientType::API {
            clean_session_id_from_body(&mut rewritten_body_map);
            serde_json::to_vec(&rewritten_body_map).unwrap_or_else(|_| rewritten_body.clone())
        } else {
            rewritten_body.clone()
        };
        cp!("rewrite");

        let upstream_token = self.account_svc.resolve_upstream_token_with(&account).await?;
        let mut final_headers = rewritten_headers;
        final_headers.insert("authorization".into(), format!("Bearer {}", upstream_token));
        cp!("resolve_token");

        let resp = self
            .forward_request(
                &method.to_string(),
                &path,
                &query,
                &final_headers,
                &final_body,
                &account,
                slot,
                &rid,
            )
            .await?;
        cp!("forward_done");

        let status = resp.status();

        // 5xx 黏性透传：wrap body 为通用 api_error，剥离请求追踪头。
        // 避免把上游堆栈 / 请求 ID / 基础设施信息泄漏给下游客户端。
        if status.is_server_error() {
            warn!(
                "account {} returned {} (wrapped, no retry)",
                account.id,
                status.as_u16()
            );
            return Ok(wrap_5xx_response(resp));
        }

        if status != StatusCode::TOO_MANY_REQUESTS {
            perf_log(&rid, "total", t_start.elapsed().as_secs_f64() * 1000.0);
            return Ok(resp);
        }

        // 429 黏性透传：不切号、不 retry，把原 body 替换为通用文案后返回给客户端。
        // absorb_headers 已在 forward_request 里执行，state 更新后续请求会自动避开。
        if crate::service::limit::is_sonnet_rejection(resp.headers()) {
            info!(
                "account {} returned 429 for sonnet quota (sticky, no retry)",
                account.id
            );
        } else {
            warn!(
                "account {} returned 429 (sticky, no retry)",
                account.id
            );
        }
        Ok(wrap_429_response(resp))
    }

    async fn forward_request(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
        account: &Account,
        slot: SlotHolder,
        rid: &str,
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

        let tls_t0 = Instant::now();
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
        perf_log(rid, "forward_prep", tls_t0.elapsed().as_secs_f64() * 1000.0);

        let send_t0 = Instant::now();
        let resp = req_builder.send().await.map_err(|e| {
            warn!("upstream error for account {}: {}", account.id, e);
            AppError::BadGateway("upstream request failed".into())
        })?;
        perf_log(rid, "upstream_send_ttfb", send_t0.elapsed().as_secs_f64() * 1000.0);

        let status_code = resp.status().as_u16();
        debug!("upstream response: {}", status_code);

        // 处理认证失败：403 永久停用
        if status_code == 403 {
            if let Err(e) = self
                .account_svc
                .disable_account(account.id, AccountStatus::Disabled, "403 认证失败", None)
                .await
            {
                warn!("failed to disable account {} for 403: {}", account.id, e);
            } else {
                warn!("account {} permanently disabled for 403", account.id);
            }
        }

        // 吸取限流响应头到内存热态；达到 TTL / 阈值等条件时异步 flush 到 DB。
        // 对空闲 2xx 响应且无 unified-* 字段：无副作用直接 return false。
        // 对 429 响应：即使无 unified-* 字段也会设短期隔离（retry-after 或默认 60s），避免并发请求反复撞同一账号。
        let absorb_t0 = Instant::now();
        let should_flush = self.limit_store.absorb_headers(account.id, status_code, resp.headers());
        if should_flush {
            let ls = self.limit_store.clone();
            let aid = account.id;
            tokio::spawn(async move {
                if let Err(e) = ls.flush_to_db(aid).await {
                    warn!("limit flush failed for account {}: {}", aid, e);
                }
            });
        }
        perf_log(rid, "absorb_headers", absorb_t0.elapsed().as_secs_f64() * 1000.0);

        // 构建响应
        let mut response_builder = Response::builder()
            .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));

        for (k, v) in resp.headers() {
            let name = k.as_str();
            // 过滤已知 AI Gateway / 代理指纹响应头，防止客户端检测并上报
            if is_gateway_fingerprint_header(name) {
                continue;
            }
            response_builder = response_builder.header(k.clone(), v.clone());
        }

        // 流式传输响应体，并把 SlotHolder 搭载到 body 流上：
        // 只有 body 被读完、或客户端提前断开（axum drop body）时，槽位才会释放。
        let body_stream = resp.bytes_stream();
        let held_stream = SlotHeldStream::new(body_stream, slot);
        let body = Body::from_stream(held_stream);

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
    "x-litellm-",
    "helicone-",
    "x-portkey-",
    "cf-aig-",
    "x-kong-",
    "x-bt-",
];

fn is_gateway_fingerprint_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    GATEWAY_HEADER_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// 黏性透传策略下，把上游 429 响应包装成 Anthropic 标准格式的通用文案，
/// 避免把具体的限流窗口 / 剩余额度 / 订阅等级等内部细节泄漏给下游客户端。
///
/// - status 保留 429
/// - body 替换为 GENERIC_429_BODY
/// - content-type 固定 application/json；content-length 由 body 自动计算，跳过原值
/// - 其它响应头原样保留（包括 `retry-after` 给客户端参考、以及 `anthropic-ratelimit-*` 系列）
fn wrap_429_response(resp: Response) -> Response {
    const GENERIC_429_BODY: &str = concat!(
        r#"{"type":"error","error":{"type":"rate_limit_error","#,
        r#""message":"Rate limit reached, please retry shortly."}}"#,
    );

    let status = resp.status();
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        // content-length / content-type 会被新 body 覆盖；跳过避免冲突
        if matches!(k.as_str(), "content-length" | "content-type") {
            continue;
        }
        builder = builder.header(k.clone(), v.clone());
    }
    builder = builder.header("content-type", "application/json");
    builder
        .body(Body::from(GENERIC_429_BODY))
        .unwrap_or_else(|_| {
            (StatusCode::TOO_MANY_REQUESTS, GENERIC_429_BODY).into_response()
        })
}

/// 5xx 黏性透传策略：把上游的 500-599 响应包装成 Anthropic 格式的通用 api_error。
///
/// 原 body 可能包含堆栈 / 内部路径 / SSE 错误帧；原 header 可能含请求追踪信息
/// （`x-request-id` / `cf-ray` 能定位到上游内部的具体请求）。统一过滤掉，下游只看到
/// 一个干净的"上游错误，请稍后重试"。
///
/// - status 保留上游原值（500 / 502 / 503 / 504 / 529 等）
/// - body 替换为 GENERIC_5XX_BODY
/// - 剥离：`x-request-id` / `request-id` / `cf-ray` / `server` / `via`
/// - content-type 固定 application/json；content-length 由新 body 自动计算
fn wrap_5xx_response(resp: Response) -> Response {
    const GENERIC_5XX_BODY: &str = concat!(
        r#"{"type":"error","error":{"type":"api_error","#,
        r#""message":"Upstream error, please retry shortly."}}"#,
    );

    let status = resp.status();
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        let name_lower = k.as_str().to_ascii_lowercase();
        if matches!(name_lower.as_str(), "content-length" | "content-type") {
            continue;
        }
        if matches!(
            name_lower.as_str(),
            "x-request-id" | "request-id" | "cf-ray" | "server" | "via"
        ) {
            continue;
        }
        builder = builder.header(k.clone(), v.clone());
    }
    builder = builder.header("content-type", "application/json");
    builder
        .body(Body::from(GENERIC_5XX_BODY))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, GENERIC_5XX_BODY).into_response())
}

fn truncate_body(b: &[u8], max: usize) -> String {
    if b.len() > max {
        format!("{}...(truncated)", String::from_utf8_lossy(&b[..max]))
    } else {
        String::from_utf8_lossy(b).to_string()
    }
}

#[cfg(test)]
mod tests {
    //! 动态测试：验证 SlotHolder / SlotHeldStream 真实走完 acquire → drop → release
    //! 的完整生命周期，并覆盖流式响应中途断开、并发上限在流生命周期内生效等场景。
    //!
    //! 所有测试直接使用 MemoryStore 作为 CacheStore，不依赖数据库。

    use super::*;
    use crate::store::memory::MemoryStore;
    use futures_util::StreamExt;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::time::sleep;

    fn make_cache() -> Arc<dyn CacheStore> {
        Arc::new(MemoryStore::new())
    }

    /// 探测槽位是否完全空闲（当前计数为 0）。
    ///
    /// 通过 `acquire_slot(..., max=1)` 的行为反推：仅当当前计数 = 0 时返回 true；
    /// 返回 true 时我们已顺带占了一个名额，用 release_slot 立即还回去。
    async fn slot_is_free(cache: &Arc<dyn CacheStore>, key: &str) -> bool {
        let ok = cache
            .acquire_slot(key, 1, Duration::from_secs(60))
            .await
            .unwrap();
        if ok {
            cache.release_slot(key).await;
        }
        ok
    }

    /// 等待 Drop 中 tokio::spawn 的异步释放完成。
    /// 先 yield 让新任务有机会跑，再 sleep 兜底。
    async fn settle() {
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        sleep(Duration::from_millis(20)).await;
    }

    // -------------------- SlotHolder --------------------

    #[tokio::test]
    async fn holder_drop_releases_the_slot() {
        let cache = make_cache();
        let key = "hold/drop";
        assert!(
            cache
                .acquire_slot(key, 3, Duration::from_secs(60))
                .await
                .unwrap()
        );
        assert!(
            !slot_is_free(&cache, key).await,
            "acquire 之后槽位应被占用"
        );

        let holder = SlotHolder::new(cache.clone(), key.into());
        drop(holder);
        settle().await;

        assert!(
            slot_is_free(&cache, key).await,
            "SlotHolder drop 后槽位应释放"
        );
    }

    #[tokio::test]
    async fn holder_disarm_does_not_release() {
        let cache = make_cache();
        let key = "hold/disarm";
        cache
            .acquire_slot(key, 3, Duration::from_secs(60))
            .await
            .unwrap();

        let holder = SlotHolder::new(cache.clone(), key.into());
        holder.disarm();
        settle().await;

        assert!(
            !slot_is_free(&cache, key).await,
            "disarm 不应触发释放"
        );
        // 兜底清理
        cache.release_slot(key).await;
    }

    #[tokio::test]
    async fn multiple_holders_drop_independently() {
        let cache = make_cache();
        let key = "hold/multi";
        // 占 3 个槽位
        for _ in 0..3 {
            assert!(
                cache
                    .acquire_slot(key, 3, Duration::from_secs(60))
                    .await
                    .unwrap()
            );
        }
        // 第 4 次应失败
        assert!(
            !cache
                .acquire_slot(key, 3, Duration::from_secs(60))
                .await
                .unwrap(),
            "max=3 时第 4 次 acquire 应失败"
        );

        let h1 = SlotHolder::new(cache.clone(), key.into());
        let h2 = SlotHolder::new(cache.clone(), key.into());
        let h3 = SlotHolder::new(cache.clone(), key.into());

        // 乱序 drop
        drop(h2);
        settle().await;
        // 还剩 2 个，第 4 次 acquire 应成功（max=3）
        assert!(
            cache
                .acquire_slot(key, 3, Duration::from_secs(60))
                .await
                .unwrap(),
            "drop 一个后应能再占一个"
        );
        drop(h1);
        drop(h3);
        settle().await;
        // 再占一次，确认前面 drop 都归还了：此时持有 1 个（上一次 acquire），预期释放 2 个
        // 也就是总计 1，max=2 再占一次应成功，再占第 3 次应失败
        assert!(
            cache
                .acquire_slot(key, 2, Duration::from_secs(60))
                .await
                .unwrap()
        );
        assert!(
            !cache
                .acquire_slot(key, 2, Duration::from_secs(60))
                .await
                .unwrap()
        );
    }

    // -------------------- SlotHeldStream 自定义流 --------------------

    /// 产出 `count` 个元素后结束的简单同步流。
    struct ReadyStream {
        remaining: usize,
        yielded: Arc<AtomicUsize>,
    }

    impl Stream for ReadyStream {
        type Item = u32;
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            if self.remaining == 0 {
                Poll::Ready(None)
            } else {
                self.remaining -= 1;
                self.yielded.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(self.remaining as u32))
            }
        }
    }

    /// 每次 poll 都返回 Pending，直到收到通道消息。用于测 Pending 期间槽位持有。
    struct ChanStream {
        rx: tokio::sync::mpsc::Receiver<Option<u32>>,
    }

    impl Stream for ChanStream {
        type Item = u32;
        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match self.rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(None)) => Poll::Ready(None),
                Poll::Ready(Some(Some(v))) => Poll::Ready(Some(v)),
            }
        }
    }

    // -------------------- SlotHeldStream --------------------

    #[tokio::test]
    async fn stream_wrapper_is_transparent_to_items() {
        let cache = make_cache();
        let key = "stream/transparent";
        cache
            .acquire_slot(key, 3, Duration::from_secs(60))
            .await
            .unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let inner = ReadyStream {
            remaining: 5,
            yielded: counter.clone(),
        };
        let holder = SlotHolder::new(cache.clone(), key.into());
        let mut wrapper = Box::pin(SlotHeldStream::new(inner, holder));

        let mut collected = Vec::new();
        while let Some(v) = wrapper.as_mut().next().await {
            collected.push(v);
        }
        assert_eq!(collected, vec![4, 3, 2, 1, 0], "元素顺序/值应与内层流一致");
        assert_eq!(counter.load(Ordering::SeqCst), 5, "内层流被 yield 5 次");
    }

    #[tokio::test]
    async fn stream_wrapper_releases_slot_on_exhaustion() {
        let cache = make_cache();
        let key = "stream/exhaust";
        cache
            .acquire_slot(key, 1, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!slot_is_free(&cache, key).await);

        let counter = Arc::new(AtomicUsize::new(0));
        let inner = ReadyStream {
            remaining: 3,
            yielded: counter,
        };
        let holder = SlotHolder::new(cache.clone(), key.into());
        let mut wrapper = Box::pin(SlotHeldStream::new(inner, holder));

        // 读到 None（流耗尽）之前，槽位必须持续被持有
        while wrapper.as_mut().next().await.is_some() {
            assert!(
                !slot_is_free(&cache, key).await,
                "流未结束期间槽位不能释放"
            );
        }

        // 这里流已返回 None；但 SlotHolder 仍在 wrapper 里没 drop
        assert!(
            !slot_is_free(&cache, key).await,
            "流结束后 wrapper 未 drop，槽位仍应持有"
        );

        drop(wrapper);
        settle().await;

        assert!(
            slot_is_free(&cache, key).await,
            "wrapper drop 后槽位应释放"
        );
    }

    #[tokio::test]
    async fn stream_wrapper_releases_slot_on_early_drop() {
        let cache = make_cache();
        let key = "stream/early-drop";
        cache
            .acquire_slot(key, 1, Duration::from_secs(60))
            .await
            .unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let inner = ReadyStream {
            remaining: 100, // 故意做长
            yielded: counter.clone(),
        };
        let holder = SlotHolder::new(cache.clone(), key.into());
        let mut wrapper = Box::pin(SlotHeldStream::new(inner, holder));

        // 只读一个元素，模拟客户端中途断开
        let _ = wrapper.as_mut().next().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(
            !slot_is_free(&cache, key).await,
            "仅读一个元素后槽位应仍被持有"
        );

        drop(wrapper);
        settle().await;

        assert!(
            slot_is_free(&cache, key).await,
            "中途 drop wrapper 后槽位应释放"
        );
    }

    // -------------------- 核心：修复并发限制实效 --------------------

    /// 这是修复这次 bug 的核心回归测试：
    /// 并发上限必须在**整个 body 流持有期间**生效，而不是仅到 TTFB。
    #[tokio::test]
    async fn concurrency_limit_enforced_across_stream_lifetime() {
        let cache = make_cache();
        let key = "concurrency:account:42";
        let max = 3i32;

        // 手动模拟 3 条并发的"仍在流中"的请求：acquire + 挂 SlotHeldStream
        let mut streams = Vec::new();
        for _ in 0..max {
            let ok = cache
                .acquire_slot(key, max, Duration::from_secs(60))
                .await
                .unwrap();
            assert!(ok, "前 {} 次 acquire 必须成功", max);
            let counter = Arc::new(AtomicUsize::new(0));
            let inner = ReadyStream {
                remaining: 10,
                yielded: counter,
            };
            let holder = SlotHolder::new(cache.clone(), key.into());
            streams.push(Box::pin(SlotHeldStream::new(inner, holder)));
        }

        // 第 4 条请求尝试 acquire，预期失败——槽位被 3 条仍在流中的请求占满
        assert!(
            !cache
                .acquire_slot(key, max, Duration::from_secs(60))
                .await
                .unwrap(),
            "max=3 且 3 条流仍挂着时，第 4 次 acquire 必须被拒"
        );

        // 其中一条流继续消费——只要没 drop wrapper，槽位就不应释放
        {
            let s = &mut streams[0];
            let _ = s.as_mut().next().await;
        }
        assert!(
            !cache
                .acquire_slot(key, max, Duration::from_secs(60))
                .await
                .unwrap(),
            "仅消费元素（流未 drop）不应释放槽位"
        );

        // drop 掉第 0 条流 → 触发异步 release → 第 4 条应能 acquire
        let _first = streams.remove(0);
        drop(_first);
        settle().await;

        assert!(
            cache
                .acquire_slot(key, max, Duration::from_secs(60))
                .await
                .unwrap(),
            "第 1 条流 drop 后，第 4 次 acquire 应成功"
        );

        // 清理
        cache.release_slot(key).await;
        drop(streams);
        settle().await;
        assert!(
            slot_is_free(&cache, key).await,
            "全部流 drop 后槽位应归零"
        );
    }

    /// 验证 pin_project 的透明性 + 异步 poll 行为：使用 ChanStream 让 poll_next
    /// 先 Pending，等 sender 送数据后再 Ready。整个过程中槽位持有，直到最终 drop。
    #[tokio::test]
    async fn stream_wrapper_preserves_pending_and_holds_slot() {
        let cache = make_cache();
        let key = "stream/pending";
        cache
            .acquire_slot(key, 1, Duration::from_secs(60))
            .await
            .unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel::<Option<u32>>(4);
        let inner = ChanStream { rx };
        let holder = SlotHolder::new(cache.clone(), key.into());
        let mut wrapper = Box::pin(SlotHeldStream::new(inner, holder));

        // 读者协程：持续读到 None，之后 drop wrapper。
        let reader_cache = cache.clone();
        let reader_key = key.to_string();
        let reader = tokio::spawn(async move {
            while wrapper.as_mut().next().await.is_some() {}
            // 读到 None 时 wrapper 还没 drop → 槽位仍持有
            assert!(
                !slot_is_free(&reader_cache, &reader_key).await,
                "读到 None 但 wrapper 未 drop，槽位应持有"
            );
            drop(wrapper);
        });

        // 读者此时 Pending，槽位必须持有
        sleep(Duration::from_millis(30)).await;
        assert!(
            !slot_is_free(&cache, key).await,
            "读者在 Pending 期间槽位必须持有"
        );

        tx.send(Some(1)).await.unwrap();
        sleep(Duration::from_millis(20)).await;
        assert!(
            !slot_is_free(&cache, key).await,
            "收到一个元素后仍在流中，槽位持有"
        );

        tx.send(None).await.unwrap(); // 显式结束
        drop(tx); // 关闭发送端
        reader.await.unwrap();
        settle().await;

        assert!(
            slot_is_free(&cache, key).await,
            "读者退出（wrapper drop）后槽位应释放"
        );
    }

    // -------------------- Drop 的健壮性 --------------------

    #[tokio::test]
    async fn holder_drop_outside_runtime_is_noop() {
        // Drop impl 只有在有 tokio runtime 时才 spawn；否则应静默无 panic。
        let cache: Arc<dyn CacheStore> = Arc::new(MemoryStore::new());

        // 即便在单独线程的非 tokio 上下文里 drop holder，也不能 panic
        let cache_for_thread = cache.clone();
        let handle = std::thread::spawn(move || {
            let h = SlotHolder::new(cache_for_thread, "no-runtime".into());
            drop(h);
        });
        handle.join().unwrap();
        // 没 panic 即通过
    }

    #[tokio::test]
    async fn many_concurrent_holders_release_cleanly() {
        // 扩展并发压力：同一 key 上 acquire 50 次（max=50），全部封装成 holder，
        // 然后并发 drop；等 settle 后应全部归零。
        let cache = make_cache();
        let key = "stress/many";
        let n = 50;
        for _ in 0..n {
            assert!(
                cache
                    .acquire_slot(key, n, Duration::from_secs(60))
                    .await
                    .unwrap()
            );
        }
        let holders: Vec<_> = (0..n)
            .map(|_| SlotHolder::new(cache.clone(), key.into()))
            .collect();

        // 并发 drop：把每个 holder 丢到独立任务里
        let mut tasks = Vec::new();
        for h in holders {
            tasks.push(tokio::spawn(async move {
                drop(h);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        settle().await;

        assert!(
            slot_is_free(&cache, key).await,
            "大批量并发 drop 后槽位应归零，没有泄漏/负数"
        );
    }

    // -------------------- wrap_429_response --------------------

    use axum::body::to_bytes;

    fn make_429(headers: &[(&str, &str)], body: &[u8]) -> Response {
        let mut builder = Response::builder().status(StatusCode::TOO_MANY_REQUESTS);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(Body::from(body.to_vec())).unwrap()
    }

    #[tokio::test]
    async fn wrap_429_response_replaces_body_with_generic_json() {
        let original = make_429(
            &[("content-type", "application/json")],
            br#"{"type":"error","error":{"type":"rate_limit_error","message":"You have hit your Sonnet limit"}}"#,
        );
        let wrapped = wrap_429_response(original);
        assert_eq!(wrapped.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = to_bytes(wrapped.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            text.contains("rate_limit_error"),
            "通用文案应保留 rate_limit_error 类型: {}",
            text
        );
        assert!(
            text.contains("Rate limit reached"),
            "应是通用文案: {}",
            text
        );
        assert!(
            !text.contains("Sonnet"),
            "不应泄漏原 body 细节: {}",
            text
        );
    }

    #[tokio::test]
    async fn wrap_429_response_drops_content_length_and_sets_json_ctype() {
        // 原响应带错误的 content-length 和 text/html 类型 → 包装后应被覆盖为 application/json
        let original = make_429(
            &[
                ("content-length", "999"),
                ("content-type", "text/html"),
            ],
            b"<html>rate limited</html>",
        );
        let wrapped = wrap_429_response(original);
        let ct = wrapped.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(ct, "application/json");
        // content-length 原值不应存在（axum 会按实际 body 重算或不设）
        let cl_values: Vec<_> = wrapped.headers().get_all("content-length").iter().collect();
        assert!(
            cl_values.iter().all(|v| v.to_str().unwrap() != "999"),
            "旧的 content-length=999 不应保留"
        );
    }

    #[tokio::test]
    async fn wrap_429_response_preserves_retry_after_and_other_headers() {
        let original = make_429(
            &[
                ("retry-after", "60"),
                ("x-custom-debug", "abc"),
                ("anthropic-ratelimit-unified-status", "rejected"),
            ],
            b"original body",
        );
        let wrapped = wrap_429_response(original);
        assert_eq!(
            wrapped.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("60")
        );
        assert_eq!(
            wrapped.headers().get("x-custom-debug").and_then(|v| v.to_str().ok()),
            Some("abc")
        );
        // anthropic-ratelimit-* 默认也保留（用户明确选了"body only"包装，不动 header）
        assert_eq!(
            wrapped
                .headers()
                .get("anthropic-ratelimit-unified-status")
                .and_then(|v| v.to_str().ok()),
            Some("rejected")
        );
    }

    // -------------------- wrap_5xx_response --------------------

    fn make_5xx(status: StatusCode, headers: &[(&str, &str)], body: &[u8]) -> Response {
        let mut builder = Response::builder().status(status);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(Body::from(body.to_vec())).unwrap()
    }

    #[tokio::test]
    async fn wrap_5xx_response_replaces_body_with_generic_api_error() {
        let original = make_5xx(
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("content-type", "text/html")],
            b"<html><body>Traceback (most recent call last):\n  File 'internal/core.py' ...</body></html>",
        );
        let wrapped = wrap_5xx_response(original);
        assert_eq!(wrapped.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(wrapped.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("api_error"), "应包含 api_error type: {}", text);
        assert!(text.contains("Upstream error"), "应是通用文案: {}", text);
        assert!(!text.contains("Traceback"), "不应泄漏堆栈: {}", text);
        assert!(!text.contains("core.py"), "不应泄漏内部路径: {}", text);
    }

    #[tokio::test]
    async fn wrap_5xx_response_preserves_status_code() {
        // 530 是 CloudFlare 的特殊状态，但 is_server_error 都能覆盖
        for code in [500u16, 502, 503, 504, 529] {
            let st = StatusCode::from_u16(code).unwrap();
            let original = make_5xx(st, &[], b"x");
            let wrapped = wrap_5xx_response(original);
            assert_eq!(wrapped.status().as_u16(), code, "status {} 应保留", code);
        }
    }

    #[tokio::test]
    async fn wrap_5xx_response_strips_tracking_headers() {
        let original = make_5xx(
            StatusCode::BAD_GATEWAY,
            &[
                ("x-request-id", "req_abc_123"),
                ("cf-ray", "8a2f1c9e7d5b2a4e-SJC"),
                ("server", "cloudflare"),
                ("via", "1.1 cloudflare"),
                ("retry-after", "30"),
                ("x-custom-debug", "keep-me"),
            ],
            b"origin error",
        );
        let wrapped = wrap_5xx_response(original);

        // 追踪类 header 必须被剥离
        for h in ["x-request-id", "cf-ray", "server", "via"] {
            assert!(
                wrapped.headers().get(h).is_none(),
                "header {} 应被剥离",
                h
            );
        }

        // 其它非追踪 header 应保留
        assert_eq!(
            wrapped.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("30")
        );
        assert_eq!(
            wrapped.headers().get("x-custom-debug").and_then(|v| v.to_str().ok()),
            Some("keep-me")
        );

        // content-type 应是 application/json
        assert_eq!(
            wrapped.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }
}
