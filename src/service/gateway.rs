use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use futures_core::Stream;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{debug, warn};

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

    async fn handle_request_inner(
        &self,
        req: Request,
        api_token: Option<&ApiToken>,
    ) -> Result<Response, AppError> {
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
                warn!("429 retry attempt {} with account {}", attempt, account.id);
            }

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
                    // 通知 usage_poller "有业务活动"，触发活动驱动的用量轮询
                    self.account_svc.record_messages_activity();
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

            // 用 SlotHolder 承载槽位所有权：
            // - 成功响应：move 进 SlotHeldStream，随 body 流结束/中断才释放
            // - 429 重试：SlotHolder 随旧 last_resp 被覆盖而 drop，自动释放
            // - 客户端断开：axum drop response body → drop SlotHolder → 释放
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

            // 重新解析改写后的 body
            let mut rewritten_body_map: serde_json::Value =
                serde_json::from_slice(&rewritten_body).unwrap_or(serde_json::json!({}));

            // 改写 header
            let model_id = body_map.get("model").and_then(|m| m.as_str()).unwrap_or("");
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
            final_headers.insert("authorization".into(), format!("Bearer {}", upstream_token));

            // 转发到上游（SlotHolder 所有权移交给响应流）
            let resp = self
                .forward_request(
                    &method.to_string(),
                    &path,
                    &query,
                    &final_headers,
                    &final_body,
                    &account,
                    slot,
                )
                .await?;

            // 非 429 直接返回
            if resp.status() != StatusCode::TOO_MANY_REQUESTS {
                return Ok(resp);
            }

            // 429：排除该账号，尝试下一个。
            // SlotHolder 已随 resp 移交：被覆盖的旧 last_resp 会 drop → 自动释放旧账号的槽。
            warn!(
                "account {} returned 429, excluding and retrying (attempt {})",
                account.id,
                attempt + 1,
            );
            exclude_ids.push(account.id);
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
        slot: SlotHolder,
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

        let resp = req_builder.send().await.map_err(|e| {
            warn!("upstream error for account {}: {}", account.id, e);
            AppError::BadGateway("upstream request failed".into())
        })?;

        let status_code = resp.status().as_u16();
        debug!("upstream response: {}", status_code);

        // 处理限速：429 根据账号类型分别处理
        // - SetupToken: 保守 5h 限流
        // - OAuth: 查用量判断是撞墙（5h / 7d）还是纯 rate limit，分别设置限流时长
        if status_code == 429 {
            if let Err(e) = self.account_svc.handle_rate_limit(account).await {
                warn!(
                    "failed to handle rate limit for account {}: {}",
                    account.id, e
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
                .disable_account(account.id, AccountStatus::Disabled, "403 认证失败", None)
                .await
            {
                warn!("failed to disable account {} for 403: {}", account.id, e);
            } else {
                warn!("account {} permanently disabled for 403", account.id);
            }
        }

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
}
