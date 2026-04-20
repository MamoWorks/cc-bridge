use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::AppError;
use crate::model::account::{Account, AccountAuthType};
use crate::service::limit::LimitStore;
use crate::service::rewriter::ClientType;
use crate::store::account_store::AccountStore;
use crate::store::cache::CacheStore;

const STICKY_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const OAUTH_REFRESH_BUFFER_SECONDS: i64 = 5 * 60;
const OAUTH_LOCK_TTL: Duration = Duration::from_secs(30);
const OAUTH_WAIT_RETRY: Duration = Duration::from_millis(500);
const OAUTH_WAIT_ATTEMPTS: usize = 20;

/// `/api/oauth/usage` 查询端点的本地缓存有效期：60s 内已有成功结果则直接复用 DB 数据，
/// 避免 UI 反复点击 / poller 同时打上游。
const USAGE_FRESH_TTL: Duration = Duration::from_secs(60);
/// `/api/oauth/usage` 收到 429 后的本地冷却时间：60s 内不再尝试上游。
const USAGE_429_COOLDOWN: Duration = Duration::from_secs(60);

pub struct AccountService {
    store: Arc<AccountStore>,
    cache: Arc<dyn CacheStore>,
    limit_store: Arc<LimitStore>,
    /// 账号级 `/api/oauth/usage` 429 冷却（in-memory，重启即清空，无需持久化）。
    usage_cooldown: Mutex<HashMap<i64, Instant>>,
}

impl AccountService {
    pub fn new(
        store: Arc<AccountStore>,
        cache: Arc<dyn CacheStore>,
        limit_store: Arc<LimitStore>,
    ) -> Self {
        Self {
            store,
            cache,
            limit_store,
            usage_cooldown: Mutex::new(HashMap::new()),
        }
    }

    /// 当前是否处于 429 冷却期。
    fn usage_in_cooldown(&self, id: i64) -> bool {
        let mut map = self.usage_cooldown.lock().unwrap();
        match map.get(&id) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                map.remove(&id);
                false
            }
            None => false,
        }
    }

    fn mark_usage_cooldown(&self, id: i64) {
        let mut map = self.usage_cooldown.lock().unwrap();
        map.insert(id, Instant::now() + USAGE_429_COOLDOWN);
    }

    /// 创建新账号并自动生成身份信息。
    pub async fn create_account(&self, a: &mut Account) -> Result<(), AppError> {
        let (device_id, env, prompt, process) =
            crate::model::identity::generate_canonical_identity();
        a.device_id = device_id;
        a.canonical_env = env;
        a.canonical_prompt = prompt;
        a.canonical_process = process;

        if a.status == crate::model::account::AccountStatus::Active
            && a.status.to_string() == "active"
        {
            // default already active
        }
        if a.concurrency == 0 {
            a.concurrency = 3;
        }
        if a.priority == 0 {
            a.priority = 50;
        }
        if a.billing_mode == crate::model::account::BillingMode::Strip
            && a.billing_mode.to_string() == "strip"
        {
            // default already strip
        }

        normalize_account_auth(a)?;

        self.store.create(a).await
    }

    pub async fn update_account(&self, a: &Account) -> Result<(), AppError> {
        let mut normalized = a.clone();
        normalize_account_auth(&mut normalized)?;
        self.store.update(&normalized).await
    }

    pub async fn delete_account(&self, id: i64) -> Result<(), AppError> {
        self.store.delete(id).await
    }

    pub async fn get_account(&self, id: i64) -> Result<Account, AppError> {
        self.store.get_by_id(id).await
    }

    pub async fn list_accounts(&self) -> Result<Vec<Account>, AppError> {
        self.store.list().await
    }

    pub async fn list_accounts_paged(
        &self,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Account>, i64), AppError> {
        let total = self.store.count().await?;
        let accounts = self.store.list_paged(page, page_size).await?;
        Ok((accounts, total))
    }

    /// 使用粘性会话为请求选择账号。
    /// `exclude_ids` 为令牌的不可用账号，`allowed_ids` 为令牌的可用账号（空表示不限制）。
    pub async fn select_account(
        &self,
        session_hash: &str,
        exclude_ids: &[i64],
        allowed_ids: &[i64],
        skip_rate_limit_filter: bool,
    ) -> Result<Account, AppError> {
        // 检查粘性会话
        if !session_hash.is_empty() {
            if let Ok(Some(account_id)) = self.cache.get_session_account_id(session_hash).await {
                if account_id > 0 {
                    // Try the schedulable cache first; fall back to DB on miss.
                    let account_opt = match self.store.get_schedulable_cached(account_id).await {
                        Some(a) => Some(a),
                        None => self.store.get_by_id(account_id).await.ok(),
                    };
                    if let Some(account) = account_opt {
                        let id_allowed =
                            allowed_ids.is_empty() || allowed_ids.contains(&account_id);
                        let rate_limit_ok = skip_rate_limit_filter
                            || self.limit_store.availability(account_id).is_available();
                        if account.is_schedulable()
                            && !exclude_ids.contains(&account_id)
                            && id_allowed
                            && rate_limit_ok
                        {
                            return Ok(account);
                        }
                    }
                    // 过期绑定，删除
                    let _ = self.cache.delete_session(session_hash).await;
                }
            }
        }

        // 获取可调度账号
        let accounts = self.store.list_schedulable().await?;
        let total_schedulable = accounts.len();

        // 过滤：排除项 + 可用账号限制 + 限流状态（内存热态）
        // Sonnet 请求旁路：skip_rate_limit_filter=true 时不做限流过滤，
        // 让请求透传到上游，由 Anthropic 自己拒（维持"Sonnet 不参与本地限流"约定）。
        let mut limited_out: Vec<i64> = Vec::new();
        let candidates: Vec<Account> = accounts
            .into_iter()
            .filter(|a| {
                if exclude_ids.contains(&a.id) {
                    return false;
                }
                if !(allowed_ids.is_empty() || allowed_ids.contains(&a.id)) {
                    return false;
                }
                if skip_rate_limit_filter {
                    return true;
                }
                let availability = self.limit_store.availability(a.id);
                if !availability.is_available() {
                    limited_out.push(a.id);
                    return false;
                }
                true
            })
            .collect();

        if !limited_out.is_empty() {
            info!(
                "select: {} of {} schedulable accounts filtered by limit state: {:?}",
                limited_out.len(),
                total_schedulable,
                limited_out
            );
        }

        if candidates.is_empty() {
            return Err(AppError::ServiceUnavailable("no available accounts".into()));
        }

        // 按优先级分组，同优先级内随机选择
        let selected = select_by_priority(&candidates);

        // 绑定粘性会话
        if !session_hash.is_empty() {
            let _ = self
                .cache
                .set_session_account_id(session_hash, selected.id, STICKY_SESSION_TTL)
                .await;
        }

        Ok(selected)
    }

    /// 尝试获取账号的并发槽位。
    pub async fn acquire_slot(&self, account_id: i64, max: i32) -> Result<bool, AppError> {
        let key = format!("concurrency:account:{}", account_id);
        self.cache
            .acquire_slot(&key, max, Duration::from_secs(300))
            .await
    }

    /// 释放并发槽位。
    pub async fn release_slot(&self, account_id: i64) {
        let key = format!("concurrency:account:{}", account_id);
        self.cache.release_slot(&key).await;
    }

    /// 构造一个绑定到该账号并发槽的 SlotHolder（不会自行获取；调用者需先 acquire_slot）。
    pub fn slot_holder_for(&self, account_id: i64) -> crate::service::gateway::SlotHolder {
        let key = format!("concurrency:account:{}", account_id);
        crate::service::gateway::SlotHolder::new(self.cache.clone(), key)
    }

    /// 从 Anthropic API 获取账号用量并缓存到数据库。
    /// 仅支持 OAuth 账号，SetupToken 账号无法查询用量。
    ///
    /// 限频策略：
    /// - DB 中 `usage_fetched_at` < 60s 的成功结果直接复用（覆盖 UI 反复点击 / poller 两个调用源）；
    /// - 上游回 429 后，账号进入 60s 本地冷却，期间所有调用直接返回 `TooManyRequests`，
    ///   避免持续打上游被滚雪球。
    pub async fn refresh_usage(&self, id: i64) -> Result<serde_json::Value, AppError> {
        let account = self.store.get_by_id(id).await?;
        if account.auth_type != crate::model::account::AccountAuthType::Oauth {
            return Err(AppError::BadRequest(
                "长效 Token 账号不支持查询用量（仅 OAuth 账号可用）".into(),
            ));
        }

        // 1) 60s 内有成功查询 → 直接复用 DB 数据，不打上游。
        if let Some(fetched_at) = account.usage_fetched_at {
            let age = Utc::now().signed_duration_since(fetched_at);
            if age.num_seconds() >= 0
                && age.to_std().map(|d| d < USAGE_FRESH_TTL).unwrap_or(false)
            {
                info!(
                    "refresh_usage: account {} → cache hit (age={}s, ttl=60s)",
                    id,
                    age.num_seconds()
                );
                return Ok(account.usage_data.clone());
            }
        }

        // 2) 60s 内被上游 429 过 → 直接返回 Err，跳过上游。
        if self.usage_in_cooldown(id) {
            info!(
                "refresh_usage: account {} → in 60s 429 cooldown, skipping upstream",
                id
            );
            return Err(AppError::TooManyRequests(
                "usage query in 60s local cooldown after recent 429".into(),
            ));
        }

        info!(
            "refresh_usage: account {} → fetching upstream /api/oauth/usage",
            id
        );
        let token = self.resolve_oauth_access_token(&account).await?;
        match crate::service::oauth::fetch_usage(&token, &account.proxy_url).await {
            Ok(usage) => {
                let usage_str = serde_json::to_string(&usage).unwrap_or_else(|_| "{}".into());
                self.store.update_usage(id, &usage_str).await?;
                // 同步 LimitStore 内存热态，避免前端手动刷新数据与响应头数据互相覆盖
                self.limit_store.ingest_usage_json(id, &usage);
                info!("refresh_usage: account {} → upstream OK, cached", id);
                Ok(usage)
            }
            Err(e) => {
                if matches!(e, AppError::TooManyRequests(_)) {
                    self.mark_usage_cooldown(id);
                    warn!(
                        "refresh_usage: account {} → upstream 429, cooldown for 60s: {}",
                        id, e
                    );
                } else {
                    warn!("refresh_usage: account {} → upstream error: {}", id, e);
                }
                Err(e)
            }
        }
    }

    pub async fn resolve_upstream_token(&self, id: i64) -> Result<String, AppError> {
        let account = self.store.get_by_id(id).await?;
        self.resolve_upstream_token_with(&account).await
    }

    /// Same as `resolve_upstream_token` but reuses an already-fetched `Account`,
    /// avoiding a redundant `get_by_id` round-trip. The refresh path still
    /// re-reads fresh data internally, so stale local fields are safe.
    pub async fn resolve_upstream_token_with(
        &self,
        account: &Account,
    ) -> Result<String, AppError> {
        match account.auth_type {
            AccountAuthType::SetupToken => {
                if account.setup_token.is_empty() {
                    return Err(AppError::ServiceUnavailable("setup token is empty".into()));
                }
                Ok(account.setup_token.clone())
            }
            AccountAuthType::Oauth => self.resolve_oauth_access_token(account).await,
        }
    }

    async fn resolve_oauth_access_token(&self, account: &Account) -> Result<String, AppError> {
        if account.has_valid_oauth_access_token(OAUTH_REFRESH_BUFFER_SECONDS) {
            return Ok(account.access_token.clone());
        }
        if account.refresh_token.is_empty() {
            let _ = self
                .store
                .update_auth_error(account.id, "missing refresh token")
                .await;
            return Err(AppError::ServiceUnavailable(
                "oauth refresh token is empty".into(),
            ));
        }

        let lock_key = format!("oauth:refresh:account:{}", account.id);
        let lock_owner = Uuid::new_v4().to_string();
        let acquired = self
            .cache
            .acquire_lock(&lock_key, &lock_owner, OAUTH_LOCK_TTL)
            .await?;

        if acquired {
            let result = self.refresh_oauth_access_token(account.id).await;
            self.cache.release_lock(&lock_key, &lock_owner).await;
            return result;
        }

        for _ in 0..OAUTH_WAIT_ATTEMPTS {
            sleep(OAUTH_WAIT_RETRY).await;
            let latest = self.store.get_by_id(account.id).await?;
            if latest.has_valid_oauth_access_token(OAUTH_REFRESH_BUFFER_SECONDS) {
                return Ok(latest.access_token);
            }
        }

        Err(AppError::ServiceUnavailable(
            "oauth token refresh timeout".into(),
        ))
    }

    async fn refresh_oauth_access_token(&self, id: i64) -> Result<String, AppError> {
        let latest = self.store.get_by_id(id).await?;
        if latest.has_valid_oauth_access_token(OAUTH_REFRESH_BUFFER_SECONDS) {
            return Ok(latest.access_token);
        }
        if latest.refresh_token.is_empty() {
            let _ = self
                .store
                .update_auth_error(id, "missing refresh token")
                .await;
            return Err(AppError::ServiceUnavailable(
                "oauth refresh token is empty".into(),
            ));
        }

        let fallback_access_token = latest.access_token.clone();
        let fallback_is_still_valid = latest
            .expires_at
            .map(|expires_at| expires_at > Utc::now())
            .unwrap_or(false);

        match crate::service::oauth::refresh_oauth_token(&latest.refresh_token, &latest.proxy_url)
            .await
        {
            Ok(tokens) => {
                self.store
                    .update_oauth_tokens(
                        id,
                        &tokens.access_token,
                        &tokens.refresh_token,
                        tokens.expires_at,
                    )
                    .await?;
                Ok(tokens.access_token)
            }
            Err(err) => {
                let msg = err.to_string();
                let _ = self.store.update_auth_error(id, &msg).await;
                if fallback_is_still_valid && !fallback_access_token.is_empty() {
                    warn!(
                        "oauth refresh failed for account {}, using current access token until expiry: {}",
                        id, msg
                    );
                    return Ok(fallback_access_token);
                }
                Err(AppError::ServiceUnavailable(format!(
                    "oauth refresh failed: {}",
                    msg
                )))
            }
        }
    }

    pub async fn set_rate_limit(
        &self,
        id: i64,
        reset_at: chrono::DateTime<Utc>,
    ) -> Result<(), AppError> {
        self.store.set_rate_limit(id, reset_at).await
    }

    pub async fn disable_account(
        &self,
        id: i64,
        status: crate::model::account::AccountStatus,
        reason: &str,
        rate_limit_reset_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(), AppError> {
        self.store
            .disable_account(id, status, reason, rate_limit_reset_at)
            .await
    }

    pub async fn enable_account(&self, id: i64) -> Result<(), AppError> {
        self.store.enable_account(id).await
    }
}

fn normalize_account_auth(account: &mut Account) -> Result<(), AppError> {
    match account.auth_type {
        AccountAuthType::SetupToken => {
            if account.setup_token.trim().is_empty() {
                return Err(AppError::BadRequest("setup_token is required".into()));
            }
            account.access_token.clear();
            account.refresh_token.clear();
            account.expires_at = None;
            account.oauth_refreshed_at = None;
            account.auth_error.clear();
        }
        AccountAuthType::Oauth => {
            if account.refresh_token.trim().is_empty() {
                return Err(AppError::BadRequest("refresh_token is required".into()));
            }
            account.setup_token.clear();
            account.auth_error.clear();
            if account.access_token.trim().is_empty() {
                account.access_token.clear();
                account.expires_at = None;
            }
        }
    }
    Ok(())
}

/// 根据客户端类型创建会话哈希。
/// CC 客户端：使用 metadata.user_id 中的 session_id。
/// API 客户端：使用 sha256(UA + 系统提示词/首条消息)。
/// 会话粘滞时长统一由 CacheStore TTL（24h）决定，不再在哈希键中嵌入小时窗口，
/// 否则会把实际 sticky 时长截断到 1 小时，并在跨小时边界引入上游账号抖动。
pub fn generate_session_hash(
    user_agent: &str,
    body: &serde_json::Value,
    client_type: ClientType,
) -> String {
    if client_type == ClientType::ClaudeCode {
        if let Some(metadata) = body.get("metadata").and_then(|m| m.as_object()) {
            if let Some(user_id_str) = metadata.get("user_id").and_then(|u| u.as_str()) {
                // JSON 格式
                if let Ok(uid) = serde_json::from_str::<serde_json::Value>(user_id_str) {
                    if let Some(sid) = uid.get("session_id").and_then(|s| s.as_str()) {
                        if !sid.is_empty() {
                            return sid.to_string();
                        }
                    }
                }
                // 旧格式
                if let Some(idx) = user_id_str.rfind("_session_") {
                    return user_id_str[idx + 9..].to_string();
                }
            }
        }
    }

    // API 模式：UA + 系统提示词/首条消息 + 小时窗口
    let mut content = String::new();

    // Try system prompt first
    match body.get("system") {
        Some(serde_json::Value::String(sys)) => {
            content = sys.clone();
        }
        Some(serde_json::Value::Array(arr)) => {
            for item in arr {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    content = text.to_string();
                    break;
                }
            }
        }
        _ => {}
    }

    // 回退到首条消息
    if content.is_empty() {
        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            if let Some(msg) = messages.first().and_then(|m| m.as_object()) {
                match msg.get("content") {
                    Some(serde_json::Value::String(c)) => {
                        content = c.clone();
                    }
                    Some(serde_json::Value::Array(arr)) => {
                        for item in arr {
                            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                content = text.to_string();
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let raw = format!("{}|{}", user_agent, content);
    let hash = Sha256::digest(raw.as_bytes());
    hex::encode(&hash[..16])
}

fn select_by_priority(accounts: &[Account]) -> Account {
    if accounts.len() == 1 {
        return accounts[0].clone();
    }

    // 找到最高优先级（最小数值）
    let best_priority = accounts.iter().map(|a| a.priority).min().unwrap_or(50);

    // 收集相同优先级的所有账号
    let best: Vec<&Account> = accounts
        .iter()
        .filter(|a| a.priority == best_priority)
        .collect();

    // 同优先级内随机选择
    let idx = rand::thread_rng().gen_range(0..best.len());
    best[idx].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- generate_session_hash ----

    #[test]
    fn session_hash_is_deterministic_for_same_input() {
        let ua = "claude-cli/2.1.81 (external, cli)";
        let body = json!({
            "system": "You are Claude Code",
            "messages": [{"role": "user", "content": "hello"}],
        });
        let h1 = generate_session_hash(ua, &body, ClientType::API);
        let h2 = generate_session_hash(ua, &body, ClientType::API);
        assert_eq!(
            h1, h2,
            "same (ua, content) must yield identical hash — sticky TTL depends on this"
        );
        assert_eq!(h1.len(), 32, "hex of 16-byte prefix should be 32 chars");
    }

    #[test]
    fn session_hash_differs_by_system_prompt() {
        let ua = "claude-cli/2.1.81";
        let a = json!({"system": "prompt-A", "messages": [{"role": "user", "content": "x"}]});
        let b = json!({"system": "prompt-B", "messages": [{"role": "user", "content": "x"}]});
        assert_ne!(
            generate_session_hash(ua, &a, ClientType::API),
            generate_session_hash(ua, &b, ClientType::API)
        );
    }

    #[test]
    fn session_hash_falls_back_to_first_message_when_no_system() {
        let ua = "claude-cli/2.1.81";
        let a = json!({"messages": [{"role": "user", "content": "alpha"}]});
        let b = json!({"messages": [{"role": "user", "content": "beta"}]});
        let ha = generate_session_hash(ua, &a, ClientType::API);
        let hb = generate_session_hash(ua, &b, ClientType::API);
        assert_ne!(ha, hb);
    }

    #[test]
    fn session_hash_no_longer_embeds_hour_window() {
        // 回归测试：哈希不应在任何形式上依赖当前时间。
        // 以前的实现把 Utc::now().format("%Y-%m-%dT%H") 拼到原文里，使 sticky TTL 被截断到 1 小时。
        let ua = "claude-cli/2.1.81";
        let body = json!({
            "system": "stable-prompt",
            "messages": [{"role": "user", "content": "hi"}],
        });
        // 哈希在极短时间内多次调用必须相同（这是显而易见的，但如果再次引入 Utc::now()，跨小时会翻车）。
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            seen.insert(generate_session_hash(ua, &body, ClientType::API));
        }
        assert_eq!(
            seen.len(),
            1,
            "hash must be pure function of (ua, content); any time dependency is a regression"
        );

        // 进一步：已知等价输入的哈希必须等于已预计算的 sha256 前 16 字节 hex。
        let expected = {
            let raw = format!("{}|{}", ua, "stable-prompt");
            let digest = Sha256::digest(raw.as_bytes());
            hex::encode(&digest[..16])
        };
        assert_eq!(
            generate_session_hash(ua, &body, ClientType::API),
            expected,
            "hash formula must be exactly sha256(ua|content)[..16] with no extra inputs"
        );
    }

    #[test]
    fn session_hash_cc_mode_uses_session_id_from_metadata() {
        let ua = "claude-cli/2.1.81";
        let body = json!({
            "metadata": {
                "user_id": "{\"session_id\":\"sess-abc-123\",\"account_id\":\"xyz\"}"
            }
        });
        let h = generate_session_hash(ua, &body, ClientType::ClaudeCode);
        assert_eq!(h, "sess-abc-123");
    }
}
