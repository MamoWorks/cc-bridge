use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;
use uuid::Uuid;

use crate::error::AppError;
use crate::model::account::{Account, AccountAuthType};
use crate::service::rewriter::ClientType;
use crate::store::account_store::AccountStore;
use crate::store::cache::CacheStore;

const STICKY_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const OAUTH_REFRESH_BUFFER_SECONDS: i64 = 5 * 60;
const OAUTH_LOCK_TTL: Duration = Duration::from_secs(30);
const OAUTH_WAIT_RETRY: Duration = Duration::from_millis(500);
const OAUTH_WAIT_ATTEMPTS: usize = 20;

/// 用量利用率达到此阈值即视为“撞墙”。
const USAGE_HIT_THRESHOLD: f64 = 97.0;
/// 撞墙之外的纯速率限制的短冷却时间。
const PURE_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(60);
/// 无法确定限流原因时的保守限流时长（与历史行为一致）。
const FALLBACK_QUARANTINE: Duration = Duration::from_secs(5 * 60 * 60);

pub struct AccountService {
    store: Arc<AccountStore>,
    cache: Arc<dyn CacheStore>,
}

impl AccountService {
    pub fn new(store: Arc<AccountStore>, cache: Arc<dyn CacheStore>) -> Self {
        Self { store, cache }
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
    ) -> Result<Account, AppError> {
        // 检查粘性会话
        if !session_hash.is_empty() {
            if let Ok(Some(account_id)) = self.cache.get_session_account_id(session_hash).await {
                if account_id > 0 {
                    if let Ok(account) = self.store.get_by_id(account_id).await {
                        let id_allowed =
                            allowed_ids.is_empty() || allowed_ids.contains(&account_id);
                        if account.is_schedulable()
                            && !exclude_ids.contains(&account_id)
                            && id_allowed
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

        // 过滤：排除项 + 可用账号限制
        let candidates: Vec<Account> = accounts
            .into_iter()
            .filter(|a| {
                !exclude_ids.contains(&a.id)
                    && (allowed_ids.is_empty() || allowed_ids.contains(&a.id))
            })
            .collect();

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

    pub fn slot_holder_for(&self, account_id: i64) -> crate::service::gateway::SlotHolder {
        let key = format!("concurrency:account:{}", account_id);
        crate::service::gateway::SlotHolder::new(self.cache.clone(), key)
    }

    /// 从 Anthropic API 获取账号用量并缓存到数据库。
    /// 仅支持 OAuth 账号，SetupToken 账号无法查询用量。
    pub async fn refresh_usage(&self, id: i64) -> Result<serde_json::Value, AppError> {
        let account = self.store.get_by_id(id).await?;
        if account.auth_type != crate::model::account::AccountAuthType::Oauth {
            return Err(AppError::BadRequest(
                "usage query is only supported for OAuth accounts, SetupToken accounts cannot query usage via this endpoint".into(),
            ));
        }
        let token = self.resolve_oauth_access_token(&account).await?;
        let usage = crate::service::oauth::fetch_usage(&token, &account.proxy_url).await?;
        let usage_str = serde_json::to_string(&usage).unwrap_or_else(|_| "{}".into());
        self.store.update_usage(id, &usage_str).await?;
        Ok(usage)
    }

    pub async fn resolve_upstream_token(&self, id: i64) -> Result<String, AppError> {
        let account = self.store.get_by_id(id).await?;
        match account.auth_type {
            AccountAuthType::SetupToken => {
                if account.setup_token.is_empty() {
                    return Err(AppError::ServiceUnavailable("setup token is empty".into()));
                }
                Ok(account.setup_token)
            }
            AccountAuthType::Oauth => self.resolve_oauth_access_token(&account).await,
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

    pub async fn clear_warmup_state(&self, id: i64) -> Result<(), AppError> {
        self.store.clear_warmup_state(id).await
    }

    /// 处理上游返回 429 的情况：根据账号类型和用量数据决定限流时长和原因。
    ///
    /// - **SetupToken**：无法查询用量接口，保守限流 5h（与历史行为一致）。
    /// - **OAuth**：立即拉取 `/api/oauth/usage` 判断是否撞墙：
    ///   - 命中 7 天墙 → 限流到周重置时间
    ///   - 命中 5 小时墙 → 限流到 5h 重置时间
    ///   - 都没撞墙 → 纯速率限制，短冷却 1 分钟
    ///   - usage 接口调用失败 → 回退到 5h 保守限流
    ///
    /// Sonnet 7 天墙暂不纳入判断（上游可能只对 Sonnet 请求返回 429，不影响其他模型）。
    pub async fn handle_rate_limit(&self, account: &Account) -> Result<(), AppError> {
        let (reason, reset_at) = self.determine_rate_limit_window(account).await;
        warn!(
            "account {} rate limited ({}) until {}",
            account.id,
            reason,
            reset_at.to_rfc3339()
        );
        self.store
            .disable_account(
                account.id,
                crate::model::account::AccountStatus::Active,
                reason,
                Some(reset_at),
            )
            .await
    }

    async fn determine_rate_limit_window(
        &self,
        account: &Account,
    ) -> (&'static str, chrono::DateTime<Utc>) {
        let now = Utc::now();
        let fallback = || {
            (
                "429 速率限制",
                now + chrono::Duration::from_std(FALLBACK_QUARANTINE).unwrap(),
            )
        };

        if account.auth_type != AccountAuthType::Oauth {
            return fallback();
        }

        let usage = match self.refresh_usage(account.id).await {
            Ok(u) => u,
            Err(e) => {
                warn!(
                    "failed to fetch usage for rate-limited oauth account {}: {}",
                    account.id, e
                );
                return fallback();
            }
        };

        match classify_rate_limit(&usage, USAGE_HIT_THRESHOLD) {
            Some(RateLimitWindow::SevenDay(reset_at)) => ("周限额已满", reset_at),
            Some(RateLimitWindow::FiveHour(reset_at)) => ("5 小时限额已满", reset_at),
            None => (
                "速率限制（未达用量墙）",
                now + chrono::Duration::from_std(PURE_RATE_LIMIT_COOLDOWN).unwrap(),
            ),
        }
    }
}

/// 命中的用量窗口类型。
enum RateLimitWindow {
    /// 7 天窗口命中，携带其 resets_at。
    SevenDay(chrono::DateTime<Utc>),
    /// 5 小时窗口命中，携带其 resets_at。
    FiveHour(chrono::DateTime<Utc>),
}

/// 根据 usage_data JSON 判断哪个窗口撞墙。
/// 优先检查 7 天窗口（同时命中时 7 天 reset 更晚，限流更久）。
/// Sonnet 7 天窗口暂不纳入判断。
fn classify_rate_limit(usage: &serde_json::Value, threshold: f64) -> Option<RateLimitWindow> {
    if let Some(reset_at) = check_usage_window(usage, "seven_day", threshold) {
        return Some(RateLimitWindow::SevenDay(reset_at));
    }
    if let Some(reset_at) = check_usage_window(usage, "five_hour", threshold) {
        return Some(RateLimitWindow::FiveHour(reset_at));
    }
    None
}

/// 检查单个窗口是否达到撞墙阈值，返回其 resets_at（若命中且在未来）。
fn check_usage_window(
    usage: &serde_json::Value,
    key: &str,
    threshold: f64,
) -> Option<chrono::DateTime<Utc>> {
    let window = usage.get(key)?;
    let util = window.get("utilization")?.as_f64()?;
    if util < threshold {
        return None;
    }
    let resets_at_str = window.get("resets_at")?.as_str()?;
    let dt = chrono::DateTime::parse_from_rfc3339(resets_at_str)
        .ok()?
        .with_timezone(&Utc);
    if dt <= Utc::now() {
        return None;
    }
    Some(dt)
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
/// API 客户端：使用 sha256(UA + 系统提示词/首条消息 + 小时窗口)。
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

    let hour_window = Utc::now().format("%Y-%m-%dT%H").to_string();
    let raw = format!("{}|{}|{}", user_agent, content, hour_window);
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
    use chrono::Duration as ChronoDuration;
    use serde_json::json;

    /// 生成一个相对当前时间指定偏移的 RFC3339 字符串。
    fn rfc3339_at(offset: ChronoDuration) -> String {
        (Utc::now() + offset).to_rfc3339()
    }

    fn make_window(util: serde_json::Value, resets_at: &str) -> serde_json::Value {
        json!({ "utilization": util, "resets_at": resets_at })
    }

    // ---- check_usage_window ----

    #[test]
    fn check_window_below_threshold_returns_none() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({ "five_hour": make_window(json!(96.9), &future) });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_at_threshold_returns_some() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({ "five_hour": make_window(json!(97.0), &future) });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_some());
    }

    #[test]
    fn check_window_above_threshold_returns_some() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({ "five_hour": make_window(json!(99.9), &future) });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_some());
    }

    #[test]
    fn check_window_integer_utilization_works() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({ "five_hour": make_window(json!(100), &future) });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_some());
    }

    #[test]
    fn check_window_missing_key_returns_none() {
        let usage = json!({});
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_missing_utilization_returns_none() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({ "five_hour": { "resets_at": future } });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_missing_resets_at_returns_none() {
        let usage = json!({ "five_hour": { "utilization": 100 } });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_invalid_rfc3339_returns_none() {
        let usage = json!({
            "five_hour": { "utilization": 100, "resets_at": "not-a-date" }
        });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_past_time_returns_none() {
        let past = rfc3339_at(ChronoDuration::hours(-1));
        let usage = json!({ "five_hour": make_window(json!(100), &past) });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_null_utilization_returns_none() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({
            "five_hour": { "utilization": null, "resets_at": future }
        });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_string_utilization_returns_none() {
        let future = rfc3339_at(ChronoDuration::hours(1));
        let usage = json!({
            "five_hour": { "utilization": "100", "resets_at": future }
        });
        assert!(check_usage_window(&usage, "five_hour", 97.0).is_none());
    }

    #[test]
    fn check_window_returns_parsed_reset_at() {
        let future = rfc3339_at(ChronoDuration::hours(3));
        let usage = json!({ "five_hour": make_window(json!(100), &future) });
        let result = check_usage_window(&usage, "five_hour", 97.0).unwrap();
        let expected = chrono::DateTime::parse_from_rfc3339(&future)
            .unwrap()
            .with_timezone(&Utc);
        // 允许纳秒级精度差
        assert_eq!(result.timestamp(), expected.timestamp());
    }

    // ---- classify_rate_limit ----

    #[test]
    fn classify_empty_usage_returns_none() {
        let usage = json!({});
        assert!(classify_rate_limit(&usage, 97.0).is_none());
    }

    #[test]
    fn classify_only_five_hour_hit_returns_five_hour() {
        let future = rfc3339_at(ChronoDuration::hours(2));
        let usage = json!({
            "five_hour": make_window(json!(100), &future),
            "seven_day": make_window(json!(50), &rfc3339_at(ChronoDuration::days(5))),
        });
        match classify_rate_limit(&usage, 97.0) {
            Some(RateLimitWindow::FiveHour(_)) => {}
            other => panic!(
                "expected FiveHour, got {:?}",
                match other {
                    Some(RateLimitWindow::SevenDay(_)) => "SevenDay",
                    Some(RateLimitWindow::FiveHour(_)) => "FiveHour",
                    None => "None",
                }
            ),
        }
    }

    #[test]
    fn classify_only_seven_day_hit_returns_seven_day() {
        let usage = json!({
            "five_hour": make_window(json!(50), &rfc3339_at(ChronoDuration::hours(2))),
            "seven_day": make_window(json!(99), &rfc3339_at(ChronoDuration::days(5))),
        });
        assert!(matches!(
            classify_rate_limit(&usage, 97.0),
            Some(RateLimitWindow::SevenDay(_))
        ));
    }

    #[test]
    fn classify_both_hit_prioritizes_seven_day() {
        // 同时命中时，7 天窗口优先（限流更久）
        let usage = json!({
            "five_hour": make_window(json!(100), &rfc3339_at(ChronoDuration::hours(2))),
            "seven_day": make_window(json!(100), &rfc3339_at(ChronoDuration::days(5))),
        });
        assert!(matches!(
            classify_rate_limit(&usage, 97.0),
            Some(RateLimitWindow::SevenDay(_))
        ));
    }

    #[test]
    fn classify_only_sonnet_hit_is_ignored() {
        // Sonnet 7 天窗口命中，但其他两个未命中 → 返回 None（暂不处理 sonnet）
        let usage = json!({
            "five_hour": make_window(json!(10), &rfc3339_at(ChronoDuration::hours(2))),
            "seven_day": make_window(json!(10), &rfc3339_at(ChronoDuration::days(5))),
            "seven_day_sonnet": make_window(json!(100), &rfc3339_at(ChronoDuration::days(5))),
        });
        assert!(classify_rate_limit(&usage, 97.0).is_none());
    }

    #[test]
    fn classify_all_below_threshold_returns_none() {
        let usage = json!({
            "five_hour": make_window(json!(80), &rfc3339_at(ChronoDuration::hours(2))),
            "seven_day": make_window(json!(50), &rfc3339_at(ChronoDuration::days(5))),
        });
        assert!(classify_rate_limit(&usage, 97.0).is_none());
    }

    #[test]
    fn classify_boundary_at_exactly_97() {
        let usage = json!({
            "five_hour": make_window(json!(97), &rfc3339_at(ChronoDuration::hours(2))),
        });
        assert!(matches!(
            classify_rate_limit(&usage, 97.0),
            Some(RateLimitWindow::FiveHour(_))
        ));
    }

    #[test]
    fn classify_boundary_just_below_97() {
        let usage = json!({
            "five_hour": make_window(json!(96.99), &rfc3339_at(ChronoDuration::hours(2))),
        });
        assert!(classify_rate_limit(&usage, 97.0).is_none());
    }

    #[test]
    fn classify_seven_day_expired_reset_falls_through_to_five_hour() {
        // 7d utilization 命中但 resets_at 已过期 → check_usage_window 返回 None，降级到 5h 检查
        let usage = json!({
            "five_hour": make_window(json!(100), &rfc3339_at(ChronoDuration::hours(2))),
            "seven_day": make_window(json!(100), &rfc3339_at(ChronoDuration::hours(-1))),
        });
        assert!(matches!(
            classify_rate_limit(&usage, 97.0),
            Some(RateLimitWindow::FiveHour(_))
        ));
    }

    #[test]
    fn classify_invalid_json_structure_returns_none() {
        let usage = json!("not-an-object");
        assert!(classify_rate_limit(&usage, 97.0).is_none());
    }

    #[test]
    fn classify_threshold_config_is_honored() {
        // 测试不同 threshold 参数行为
        let usage = json!({
            "five_hour": make_window(json!(95), &rfc3339_at(ChronoDuration::hours(2))),
        });
        assert!(classify_rate_limit(&usage, 97.0).is_none());
        assert!(classify_rate_limit(&usage, 90.0).is_some());
    }
}
