use std::fs;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Days, Utc};
use rand::Rng;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::WarmupConfig;
use crate::model::account::{Account, AccountStatus};
use crate::service::account::AccountService;
use crate::service::oauth::TokenTester;
use crate::store::account_store::AccountStore;
use crate::store::cache::CacheStore;
use crate::store::settings_store::SettingsStore;

const WARMUP_LOCK_TTL: Duration = Duration::from_secs(15 * 60);
const SAME_DAY_MIN_DELAY_SECONDS: i64 = 60;

#[derive(Clone, Debug)]
pub struct WarmupSettings {
    pub enabled: bool,
    pub base_utc_hour: u32,
    pub jitter_minutes: i64,
    pub max_retries: u32,
    pub retry_backoff_secs: u64,
    pub account_gap_secs: u64,
    pub poll_interval_secs: u64,
}

impl WarmupSettings {
    pub fn from_defaults(defaults: &WarmupConfig) -> Self {
        Self {
            enabled: defaults.enabled,
            base_utc_hour: defaults.base_utc_hour.min(23),
            jitter_minutes: defaults.jitter_minutes.clamp(0, 720),
            max_retries: defaults.max_retries.min(10),
            retry_backoff_secs: defaults.retry_backoff_secs.max(30),
            account_gap_secs: defaults.account_gap_secs.max(1),
            poll_interval_secs: defaults.poll_interval_secs.max(15),
        }
    }
}

pub struct WarmupSchedulerService {
    account_store: Arc<AccountStore>,
    account_svc: Arc<AccountService>,
    cache: Arc<dyn CacheStore>,
    settings_store: Arc<SettingsStore>,
    token_tester: Arc<TokenTester>,
    defaults: WarmupConfig,
}

impl WarmupSchedulerService {
    pub fn new(
        account_store: Arc<AccountStore>,
        account_svc: Arc<AccountService>,
        cache: Arc<dyn CacheStore>,
        settings_store: Arc<SettingsStore>,
        token_tester: Arc<TokenTester>,
        defaults: WarmupConfig,
    ) -> Self {
        Self {
            account_store,
            account_svc,
            cache,
            settings_store,
            token_tester,
            defaults,
        }
    }

    pub async fn run(self: Arc<Self>) {
        info!("warmup scheduler: started");
        loop {
            let settings = self.load_settings().await;
            if settings.enabled {
                if let Err(err) = self.tick(&settings).await {
                    warn!("warmup scheduler: tick failed: {}", err);
                }
            }
            sleep(Duration::from_secs(settings.poll_interval_secs)).await;
        }
    }

    async fn load_settings(&self) -> WarmupSettings {
        let mut settings = WarmupSettings::from_defaults(&self.defaults);

        if let Ok(Some(value)) = self.settings_store.get("warmup_enabled").await {
            settings.enabled = value != "false";
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_base_utc_hour").await {
            if let Ok(hour) = value.parse::<u32>() {
                settings.base_utc_hour = hour.min(23);
            }
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_jitter_minutes").await {
            if let Ok(minutes) = value.parse::<i64>() {
                settings.jitter_minutes = minutes.clamp(0, 720);
            }
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_max_retries").await {
            if let Ok(retries) = value.parse::<u32>() {
                settings.max_retries = retries.min(10);
            }
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_retry_backoff_secs").await {
            if let Ok(secs) = value.parse::<u64>() {
                settings.retry_backoff_secs = secs.max(30);
            }
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_account_gap_secs").await {
            if let Ok(secs) = value.parse::<u64>() {
                settings.account_gap_secs = secs.max(1);
            }
        }
        if let Ok(Some(value)) = self.settings_store.get("warmup_poll_interval_secs").await {
            if let Ok(secs) = value.parse::<u64>() {
                settings.poll_interval_secs = secs.max(15);
            }
        }

        settings
    }

    async fn tick(&self, settings: &WarmupSettings) -> Result<(), String> {
        let now = Utc::now();
        let accounts = self
            .account_svc
            .list_accounts()
            .await
            .map_err(|e| e.to_string())?;
        let mut due_accounts = Vec::new();

        for account in accounts
            .into_iter()
            .filter(|account| account.warmup_enabled && account.status == AccountStatus::Active)
        {
            let refreshed = self.ensure_schedule(account, settings, now).await?;
            if refreshed
                .next_warmup_at
                .map(|ts| ts <= now)
                .unwrap_or(false)
            {
                due_accounts.push(refreshed);
            }
        }

        due_accounts.sort_by_key(|account| account.next_warmup_at);

        let due_len = due_accounts.len();
        for (idx, account) in due_accounts.into_iter().enumerate() {
            self.run_warmup(account, settings, now).await;
            if idx + 1 < due_len {
                let gap = random_account_gap(settings.account_gap_secs);
                sleep(Duration::from_secs(gap)).await;
            }
        }

        Ok(())
    }

    async fn ensure_schedule(
        &self,
        mut account: Account,
        settings: &WarmupSettings,
        now: DateTime<Utc>,
    ) -> Result<Account, String> {
        if account.next_warmup_at.is_some() {
            return Ok(account);
        }

        let next = next_scheduled_warmup(now, settings, 0);
        self.account_store
            .update_warmup_state(
                account.id,
                Some(next),
                account.last_warmup_at,
                &account.last_warmup_status,
                &account.last_warmup_message,
                0,
            )
            .await
            .map_err(|e| e.to_string())?;
        account.next_warmup_at = Some(next);
        account.warmup_retry_count = 0;
        Ok(account)
    }

    async fn run_warmup(&self, account: Account, settings: &WarmupSettings, now: DateTime<Utc>) {
        let lock_key = format!("warmup:account:{}", account.id);
        let lock_owner = Uuid::new_v4().to_string();
        let acquired = match self
            .cache
            .acquire_lock(&lock_key, &lock_owner, WARMUP_LOCK_TTL)
            .await
        {
            Ok(acquired) => acquired,
            Err(err) => {
                warn!(
                    "warmup scheduler: account {} lock failed: {}",
                    account.id, err
                );
                return;
            }
        };
        if !acquired {
            debug!(
                "warmup scheduler: account {} skipped because another instance holds the lock",
                account.id
            );
            return;
        }

        let message = random_greeting(&self.defaults.greetings_file);
        debug!(
            "warmup scheduler: warming account {} at {}",
            account.id,
            now.to_rfc3339()
        );

        let token = match self.account_svc.resolve_upstream_token(account.id).await {
            Ok(token) => token,
            Err(err) => {
                self.handle_failure(account, settings, now, &message, &err.to_string())
                    .await;
                self.cache.release_lock(&lock_key, &lock_owner).await;
                return;
            }
        };

        match self
            .token_tester
            .test_token_with_message(&token, &account.proxy_url, &account.canonical_env, &message)
            .await
        {
            Ok(()) => {
                let next = next_scheduled_warmup(now, settings, 1);
                if let Err(err) = self
                    .account_store
                    .update_warmup_state(account.id, Some(next), Some(now), "ok", &message, 0)
                    .await
                {
                    warn!(
                        "warmup scheduler: update success state failed for account {}: {}",
                        account.id, err
                    );
                }
            }
            Err(err) => {
                self.handle_failure(account, settings, now, &message, &err.to_string())
                    .await;
            }
        }

        self.cache.release_lock(&lock_key, &lock_owner).await;
    }

    async fn handle_failure(
        &self,
        account: Account,
        settings: &WarmupSettings,
        now: DateTime<Utc>,
        message: &str,
        err: &str,
    ) {
        let current_retry = account.warmup_retry_count.max(0) as u32;
        let status = format!("error: {}", err);
        let (next, retry_count) = if current_retry < settings.max_retries {
            (
                Some(now + chrono::Duration::seconds(settings.retry_backoff_secs as i64)),
                (current_retry + 1) as i32,
            )
        } else {
            (Some(next_scheduled_warmup(now, settings, 1)), 0)
        };

        if let Err(store_err) = self
            .account_store
            .update_warmup_state(account.id, next, Some(now), &status, message, retry_count)
            .await
        {
            warn!(
                "warmup scheduler: update failure state failed for account {}: {}",
                account.id, store_err
            );
        }
    }
}

pub fn next_scheduled_warmup(
    now: DateTime<Utc>,
    settings: &WarmupSettings,
    day_offset: u64,
) -> DateTime<Utc> {
    let target_date = now
        .date_naive()
        .checked_add_days(Days::new(day_offset))
        .unwrap_or(now.date_naive());
    let base = target_date
        .and_hms_opt(settings.base_utc_hour, 0, 0)
        .unwrap()
        .and_utc();
    let window_start = base - chrono::Duration::minutes(settings.jitter_minutes);
    let window_end = base + chrono::Duration::minutes(settings.jitter_minutes);

    if day_offset == 0 {
        if now < window_start {
            return random_datetime_between(window_start, window_end);
        }
        if now < window_end {
            let earliest = (now + chrono::Duration::seconds(SAME_DAY_MIN_DELAY_SECONDS))
                .min(window_end);
            return random_datetime_between(earliest, window_end);
        }
        return next_scheduled_warmup(now, settings, 1);
    }

    random_datetime_between(window_start, window_end)
}

fn random_account_gap(base_secs: u64) -> u64 {
    if base_secs <= 1 {
        return base_secs;
    }
    let mut rng = rand::thread_rng();
    let jitter = (base_secs / 3).max(1);
    let min = base_secs.saturating_sub(jitter);
    let max = base_secs + jitter;
    rng.gen_range(min..=max)
}

fn random_greeting(greetings_file: &str) -> String {
    const GREETINGS: &[&str] = &[
        "晚上好",
        "你好",
        "嗨",
        "晚上好呀",
        "你好呀",
        "在吗",
        "晚上好，打个招呼",
        "你好，来问候一下",
        "嗨，随手发一句",
        "晚上好，随便说一句",
        "你好，先问个好",
        "晚上好，冒个泡",
        "嗨，来打个招呼",
        "你好，路过问候一下",
        "晚上好，先发一句",
        "你好，简单问候一下",
        "嗨，先说声你好",
        "晚上好，来冒个泡",
        "你好，顺手发一句",
        "晚上好，先打个卡",
        "嗨，晚上好",
        "你好，来露个面",
        "晚上好，来问个好",
        "你好，发个招呼",
        "嗨，问候一下",
        "晚上好，过来打个招呼",
        "你好，先冒个泡",
        "嗨，先留一句",
        "晚上好，先问候一下",
        "你好，先来一句",
        "嗨，晚上来打个招呼",
        "晚上好，随手问候一下",
        "你好，轻轻发一句",
        "嗨，来问个好",
        "晚上好，先露个面",
        "你好，打个招呼就走",
        "嗨，来打声招呼",
        "晚上好，先发个你好",
        "你好，来留个言",
        "嗨，简单打个招呼",
        "晚上好，先说句你好",
        "你好，过来问候一声",
        "嗨，顺手来一句",
        "晚上好，发个问候",
        "你好，来报个到",
        "嗨，先打个照面",
        "晚上好，先留一句话",
        "你好，先轻轻问候一下",
        "嗨，发个小招呼",
        "晚上好，来随手问候一下",
    ];

    if let Some(greetings) = load_greetings_from_file(greetings_file) {
        let mut rng = rand::thread_rng();
        return greetings[rng.gen_range(0..greetings.len())].clone();
    }

    let mut rng = rand::thread_rng();
    GREETINGS[rng.gen_range(0..GREETINGS.len())].to_string()
}

fn load_greetings_from_file(path: &str) -> Option<Vec<String>> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            debug!("warmup scheduler: failed to read greetings file {}: {}", path, err);
            return None;
        }
    };
    let greetings = parse_greetings(&content);
    if greetings.is_empty() {
        debug!("warmup scheduler: greetings file {} is empty after parsing", path);
        return None;
    }
    Some(greetings)
}

fn parse_greetings(content: &str) -> Vec<String> {
    content
        .lines()
        .map(normalize_greeting_line)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn normalize_greeting_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn random_datetime_between(start: DateTime<Utc>, end: DateTime<Utc>) -> DateTime<Utc> {
    if end <= start {
        return start;
    }
    let mut rng = rand::thread_rng();
    let span = (end - start).num_seconds();
    start + chrono::Duration::seconds(rng.gen_range(0..=span))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn next_schedule_stays_in_window() {
        let settings = WarmupSettings {
            enabled: true,
            base_utc_hour: 23,
            jitter_minutes: 30,
            max_retries: 2,
            retry_backoff_secs: 300,
            account_gap_secs: 45,
            poll_interval_secs: 60,
        };
        let now = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(20, 0, 0)
            .unwrap()
            .and_utc();
        let scheduled = next_scheduled_warmup(now, &settings, 0);
        let earliest = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(22, 30, 0)
            .unwrap()
            .and_utc();
        let latest = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(23, 30, 0)
            .unwrap()
            .and_utc();
        assert!(scheduled >= earliest);
        assert!(scheduled <= latest);
    }

    #[test]
    fn next_schedule_rolls_forward_after_window() {
        let settings = WarmupSettings {
            enabled: true,
            base_utc_hour: 23,
            jitter_minutes: 0,
            max_retries: 2,
            retry_backoff_secs: 300,
            account_gap_secs: 45,
            poll_interval_secs: 60,
        };
        let now = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(23, 5, 0)
            .unwrap()
            .and_utc();
        let scheduled = next_scheduled_warmup(now, &settings, 0);
        assert_eq!(scheduled.date_naive(), now.date_naive().succ_opt().unwrap());
        assert_eq!(scheduled.hour(), 23);
    }

    #[test]
    fn next_schedule_uses_remaining_time_when_window_is_open() {
        let settings = WarmupSettings {
            enabled: true,
            base_utc_hour: 23,
            jitter_minutes: 30,
            max_retries: 2,
            retry_backoff_secs: 300,
            account_gap_secs: 45,
            poll_interval_secs: 60,
        };
        let now = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(22, 45, 0)
            .unwrap()
            .and_utc();
        let scheduled = next_scheduled_warmup(now, &settings, 0);
        let earliest = now + chrono::Duration::seconds(SAME_DAY_MIN_DELAY_SECONDS);
        let latest = chrono::NaiveDate::from_ymd_opt(2026, 4, 16)
            .unwrap()
            .and_hms_opt(23, 30, 0)
            .unwrap()
            .and_utc();
        assert_eq!(scheduled.date_naive(), now.date_naive());
        assert!(scheduled >= earliest);
        assert!(scheduled <= latest);
    }

    #[test]
    fn parse_greetings_ignores_comments_and_blank_lines() {
        let parsed = parse_greetings(
            "
            # comment
            晚上好

            你好
            ",
        );

        assert_eq!(parsed, vec!["晚上好".to_string(), "你好".to_string()]);
    }

    #[test]
    fn parse_greetings_normalizes_whitespace() {
        let parsed = parse_greetings("  晚上好呀   \n你   好  呀\n");

        assert_eq!(parsed, vec!["晚上好呀".to_string(), "你 好 呀".to_string()]);
    }
}
