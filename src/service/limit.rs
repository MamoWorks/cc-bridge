//! 限流状态管理：从 `anthropic-ratelimit-unified-*` 响应头吸取账号限流信息到内存热态，
//! 按 TTL + 紧急事件条件异步落盘到 `accounts.usage_data`。
//!
//! 设计要点：
//! - **内存热态**：每次响应都更新，selector 的 `availability()` 查询在此之上，~500ns 级别。
//! - **DB 落盘**：5 分钟 TTL + 紧急事件（阈值跨越、状态变化、首次填充）触发，tokio::spawn 异步。
//! - **刻度统一**：内存里 utilization 始终是 0.0-1.0 小数（响应头原生格式），
//!   写 DB 时乘以 100 归一到 0-100（与 `/api/oauth/usage` 返回值一致，保持前端兼容）。

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

use crate::error::AppError;
use crate::store::account_store::AccountStore;

/// 内存 → DB 常规刷新 TTL。
const DB_FLUSH_TTL: Duration = Duration::from_secs(5 * 60);
/// 超过此 utilization（0.0-1.0 刻度）视为该窗口撞墙，立即紧急 flush 且 selector 判不可用。
const HIT_THRESHOLD: f64 = 0.97;
/// CF-layer 429（或 Anthropic 429 但无 retry-after）的默认短期隔离时长。
const DEFAULT_429_BAN: Duration = Duration::from_secs(60);
/// SetupToken RPM/TPM 预抢阈值：任一 counter 的 remaining/limit 低于该值即视为预抢。
const PREEMPT_RATIO: f64 = 0.03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedStatus {
    Allowed,
    AllowedWarning,
    Rejected,
}

impl UnifiedStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allowed" => Some(Self::Allowed),
            "allowed_warning" => Some(Self::AllowedWarning),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWarning => "allowed_warning",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverageStatus {
    Allowed,
    AllowedWarning,
    Rejected,
}

impl OverageStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allowed" => Some(Self::Allowed),
            "allowed_warning" => Some(Self::AllowedWarning),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWarning => "allowed_warning",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowSnapshot {
    /// 0.0-1.0 刻度（响应头原生）。
    pub utilization: f64,
    pub resets_at: DateTime<Utc>,
    pub status: UnifiedStatus,
    pub surpassed_threshold: Option<f64>,
}

/// SetupToken（API key）账号的单个 RPM/TPM counter。
#[derive(Debug, Clone)]
pub struct RpmTpmCounter {
    pub limit: i64,
    /// 注意：tokens 类 counter 的 remaining 被上游四舍五入到千。
    pub remaining: i64,
    pub reset_at: DateTime<Utc>,
}

/// SetupToken 账号的四路限流快照。任一 counter `remaining/limit < PREEMPT_RATIO`
/// 即视为预抢（selector 拉黑）。
#[derive(Debug, Clone, Default)]
pub struct RpmTpmSnapshot {
    pub requests: Option<RpmTpmCounter>,
    pub tokens: Option<RpmTpmCounter>,
    pub input_tokens: Option<RpmTpmCounter>,
    pub output_tokens: Option<RpmTpmCounter>,
}

impl RpmTpmSnapshot {
    /// 按 requests → tokens → input_tokens → output_tokens 顺序扫描。返回首个已预抢的
    /// `(counter_name, reset_at)`；均未预抢则 None。
    fn first_preempted(&self, now: DateTime<Utc>) -> Option<(&'static str, DateTime<Utc>)> {
        for (name, c) in [
            ("requests", self.requests.as_ref()),
            ("tokens", self.tokens.as_ref()),
            ("input_tokens", self.input_tokens.as_ref()),
            ("output_tokens", self.output_tokens.as_ref()),
        ] {
            if let Some(c) = c {
                if counter_preempted(c, now) {
                    return Some((name, c.reset_at));
                }
            }
        }
        None
    }

    /// 返回所有 4 个 counter 的引用迭代器（None 的不产出）。
    fn all_counters(&self) -> impl Iterator<Item = &RpmTpmCounter> {
        [
            self.requests.as_ref(),
            self.tokens.as_ref(),
            self.input_tokens.as_ref(),
            self.output_tokens.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}

/// 判定某个 counter 是否已进入预抢阶段：remaining/limit < PREEMPT_RATIO 且 reset 未到。
fn counter_preempted(c: &RpmTpmCounter, now: DateTime<Utc>) -> bool {
    c.limit > 0
        && (c.remaining as f64) / (c.limit as f64) < PREEMPT_RATIO
        && c.reset_at > now
}

#[derive(Debug, Clone, Default)]
pub struct LimitState {
    pub five_hour: Option<WindowSnapshot>,
    pub seven_day: Option<WindowSnapshot>,
    pub status: Option<UnifiedStatus>,
    pub representative_claim: Option<String>,
    pub reset_at: Option<DateTime<Utc>>,
    pub fallback_percentage: Option<f64>,
    pub overage_status: Option<OverageStatus>,
    pub overage_disabled_reason: Option<String>,
    /// unified-overage-reset 头的时间戳（仅存储，不参与 availability 判定）。
    pub overage_reset_at: Option<DateTime<Utc>>,
    /// 短期隔离窗口：遇到 429 且无 unified-* 证据时填充（retry-after 或 60s fallback）。
    /// 不需要 util>=97% 或 status=Rejected，仅凭"本轮撞到 429"即可拉黑一段时间。
    pub rate_limited_until: Option<DateTime<Utc>>,
    /// Sonnet 专属短期隔离：Sonnet 429（`representative_claim=seven_day_sonnet`）时填充。
    /// 只屏蔽 Sonnet 调度，Opus / 全局 availability 不受影响。
    pub sonnet_limited_until: Option<DateTime<Utc>>,
    /// 7 天 Sonnet 子 quota 快照。仅通过 `/api/oauth/usage` 填充（Anthropic 的响应头
    /// `anthropic-ratelimit-unified-*` 不含 per-model 数据）。UI 展示用。
    pub sonnet_seven_day: Option<WindowSnapshot>,
    /// 7 天 Opus 子 quota 快照。同上。
    pub opus_seven_day: Option<WindowSnapshot>,
    /// SetupToken 账号的 RPM/TPM 四路状态。OAuth 账号一般为 None。
    pub rpm_tpm: Option<RpmTpmSnapshot>,
    pub updated_at: Option<Instant>,
    pub last_db_flush_at: Option<Instant>,
}

/// Selector 查询结果。
#[derive(Debug, Clone)]
pub enum Availability {
    Available,
    Unavailable {
        reason: String,
        until: Option<DateTime<Utc>>,
    },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

pub struct LimitStore {
    store: Arc<AccountStore>,
    states: Mutex<HashMap<i64, LimitState>>,
}

impl LimitStore {
    pub fn new(store: Arc<AccountStore>) -> Self {
        Self {
            store,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// 从响应头吸取状态到内存。返回是否应触发 DB flush。
    ///
    /// 逻辑分支：
    /// - **有 unified-\* 字段**：走既有路径；若 parsed 的全局 `reset_at` 缺失但有 `retry-after`，
    ///   用 retry-after 补齐 `rate_limited_until`（保证 availability 有"截止时刻"锚点）。
    /// - **无 unified-\* 字段 + 429**：CF-layer 或容量问题。
    ///   `rate_limited_until = now + retry-after`，缺 retry-after 则用 60s 默认值。
    /// - **无 unified-\* 字段 + 非 429**：空闲响应，不更新内存，返回 false。
    pub fn absorb_headers(&self, account_id: i64, status: u16, headers: &HeaderMap) -> bool {
        let mut map = self.states.lock().unwrap();
        let prev = map.get(&account_id).cloned().unwrap_or_default();

        let Some(mut new_state) = compute_new_state(&prev, status, headers) else {
            return false;
        };
        new_state.updated_at = Some(Instant::now());

        let flush_r = flush_reason(&prev, &new_state);
        if let Some(reason) = flush_r {
            // 抢先占位：即使 flush 失败也先记，下次 5min 后再尝试，避免连续失败造成风暴。
            new_state.last_db_flush_at = Some(Instant::now());
            let five = new_state
                .five_hour
                .as_ref()
                .map(|w| w.utilization)
                .unwrap_or(0.0);
            let seven = new_state
                .seven_day
                .as_ref()
                .map(|w| w.utilization)
                .unwrap_or(0.0);
            info!(
                "limit absorb: account {} status={} → flush ({}) 5h={:.1}% 7d={:.1}% status={}",
                account_id,
                status,
                reason,
                five * 100.0,
                seven * 100.0,
                new_state.status.unwrap_or(UnifiedStatus::Allowed).as_str(),
            );
        } else {
            debug!(
                "limit absorb: account {} status={} → no flush (within TTL, no threshold event)",
                account_id, status
            );
        }
        let should_flush = flush_r.is_some();
        map.insert(account_id, new_state);
        should_flush
    }

    /// Selector 用：当前账号可否调度。内存无记录 → 乐观 Available。
    pub fn availability(&self, account_id: i64) -> Availability {
        let map = self.states.lock().unwrap();
        let Some(state) = map.get(&account_id) else {
            return Availability::Available;
        };
        judge_availability(state)
    }

    /// Sonnet selector 用：只检查 Sonnet 专属 ban 和全局 Rejected。
    /// 5h/7d 窗口利用率、RPM/TPM 预抢等本地软限流均不适用于 Sonnet 请求。
    pub fn sonnet_available(&self, account_id: i64) -> bool {
        let map = self.states.lock().unwrap();
        let Some(state) = map.get(&account_id) else {
            return true;
        };
        if let Some(until) = state.sonnet_limited_until {
            if until > Utc::now() {
                return false;
            }
        }
        if state.status == Some(UnifiedStatus::Rejected) {
            return false;
        }
        true
    }

    /// flush 当前内存状态到 DB：
    /// 1. `usage_data` JSON（完整快照，供 UI 读）
    /// 2. `rate_limit_reset_at` / `rate_limited_at`：
    ///    任一窗口 util >= 97% 且 resets_at 未来 → 写入最晚的 resets_at；
    ///    否则清空这两列。
    ///
    /// 由 gateway 在 absorb_headers 返回 true 时 tokio::spawn 调用。
    pub async fn flush_to_db(&self, account_id: i64) -> Result<(), AppError> {
        let (json, limit_until) = {
            let map = self.states.lock().unwrap();
            let Some(state) = map.get(&account_id) else {
                debug!("limit flush: account {} not in memory, skip", account_id);
                return Ok(());
            };
            // DB 列 rate_limit_reset_at 取"最迟的限流截止时刻"：
            //   优先 5h/7d 瓶颈窗口；没有瓶颈但存在短期隔离时，退回到 rate_limited_until。
            let db_reset = bottleneck_limit_until(state).or(state.rate_limited_until);
            (build_usage_json(state), db_reset)
        };
        let json_str = serde_json::to_string(&json).unwrap_or_else(|_| "{}".into());
        self.store.update_usage(account_id, &json_str).await?;
        match limit_until {
            Some(reset_at) => {
                self.store.set_rate_limit(account_id, reset_at).await?;
                debug!(
                    "limit flush: account {} → DB (limited until {})",
                    account_id,
                    reset_at.to_rfc3339()
                );
            }
            None => {
                self.store.clear_rate_limit(account_id).await?;
                debug!("limit flush: account {} → DB (cleared)", account_id);
            }
        }
        Ok(())
    }

    /// 从 `/api/oauth/usage` JSON（0-100 刻度）同步到内存，保持两条数据源一致。
    /// 仅用于 Admin 按钮路径。
    pub fn ingest_usage_json(&self, account_id: i64, usage: &serde_json::Value) {
        let mut map = self.states.lock().unwrap();
        let mut state = map.get(&account_id).cloned().unwrap_or_default();

        if let Some(w) = parse_usage_json_window(usage, "five_hour") {
            state.five_hour = Some(w);
        }
        if let Some(w) = parse_usage_json_window(usage, "seven_day") {
            state.seven_day = Some(w);
        }
        if let Some(w) = parse_usage_json_window(usage, "seven_day_sonnet") {
            state.sonnet_seven_day = Some(w);
        }
        if let Some(w) = parse_usage_json_window(usage, "seven_day_opus") {
            state.opus_seven_day = Some(w);
        }
        state.updated_at = Some(Instant::now());
        map.insert(account_id, state);
    }
}

// ---- 解析辅助 ----

/// 根据响应头和 HTTP 状态码计算新的 LimitState（纯函数，便于单测）。
///
/// 返回 `None` 表示本次响应无可吸取信息（保持内存原样）；
/// 返回 `Some(new_state)` 表示调用者应把内存替换为该状态。
fn compute_new_state(prev: &LimitState, status: u16, headers: &HeaderMap) -> Option<LimitState> {
    let is_sonnet_429 = status == 429 && is_sonnet_rejection(headers);
    let parsed_unified = parse_unified_headers(headers).map(|mut p| {
        // Sonnet 旁路：429 + representative-claim=seven_day_sonnet 时，
        // 不把全局 status=Rejected 写入内存热态。这样 judge_availability 不会拉黑账号，
        // 保留账号对 Opus / 5h/7d 聚合等其它模型/窗口的调度能力。
        // 其它字段（5h/7d util、reset、claim、overage）继续吸收，UI/日志仍完整。
        if is_sonnet_429 {
            p.status = None;
        }
        p
    });
    let parsed_rpm_tpm = parse_rpm_tpm_headers(headers);
    let retry_after = parse_retry_after(headers);

    // 只要有 unified-* 或 RPM/TPM 任一头可用，就吸取；两者可共存（OAuth 账号理论上也可能收到 RPM/TPM）。
    if parsed_unified.is_some() || parsed_rpm_tpm.is_some() {
        let mut s = prev.clone();
        if let Some(u) = parsed_unified {
            s = apply_parsed(s, u);
        }
        if let Some(r) = parsed_rpm_tpm {
            s.rpm_tpm = Some(merge_rpm_tpm(s.rpm_tpm.take(), r));
        }
        // 若 429 时全局 reset 缺失，用 retry-after 补一个短期 ban 兜底。
        if status == 429 && s.reset_at.is_none() {
            if let Some(ra) = retry_after {
                s.rate_limited_until =
                    Some(Utc::now() + chrono::Duration::from_std(ra).unwrap_or_default());
            }
        }
        // Sonnet 专属短期隔离：优先用 retry-after，其次用 7d window reset，最后 1h 兜底。
        if is_sonnet_429 {
            let ban_end = retry_after
                .map(|d| Utc::now() + chrono::Duration::from_std(d).unwrap_or_default())
                .or_else(|| s.seven_day.as_ref().map(|w| w.resets_at))
                .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
            s.sonnet_limited_until = Some(ban_end);
        }
        return Some(s);
    }

    if status == 429 {
        // CF-layer 429：没有任何 unified-* / RPM/TPM 头，仅设短期 ban。
        let mut s = prev.clone();
        let ban = retry_after.unwrap_or(DEFAULT_429_BAN);
        let ban_until = Utc::now() + chrono::Duration::from_std(ban).unwrap_or_default();
        s.rate_limited_until = Some(ban_until);
        if is_sonnet_429 {
            s.sonnet_limited_until = Some(ban_until);
        }
        return Some(s);
    }

    None
}

struct ParsedHeaders {
    five_hour: Option<WindowSnapshot>,
    seven_day: Option<WindowSnapshot>,
    status: Option<UnifiedStatus>,
    representative_claim: Option<String>,
    reset_at: Option<DateTime<Utc>>,
    fallback_percentage: Option<f64>,
    overage_status: Option<OverageStatus>,
    overage_disabled_reason: Option<String>,
    overage_reset_at: Option<DateTime<Utc>>,
}

impl ParsedHeaders {
    fn any_present(&self) -> bool {
        self.five_hour.is_some()
            || self.seven_day.is_some()
            || self.status.is_some()
            || self.representative_claim.is_some()
            || self.reset_at.is_some()
            || self.overage_status.is_some()
            || self.overage_reset_at.is_some()
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// 判定响应是否为 Sonnet 周限流（`representative-claim == "seven_day_sonnet"`）。
/// gateway 在 429 分流时使用：命中时直接透传，不 retry / 不拉黑账号。
pub fn is_sonnet_rejection(headers: &HeaderMap) -> bool {
    header_str(headers, "anthropic-ratelimit-unified-representative-claim")
        == Some("seven_day_sonnet")
}

fn parse_unified_headers(headers: &HeaderMap) -> Option<ParsedHeaders> {
    let parsed = ParsedHeaders {
        five_hour: parse_window_from_headers(headers, "5h"),
        seven_day: parse_window_from_headers(headers, "7d"),
        status: header_str(headers, "anthropic-ratelimit-unified-status")
            .and_then(UnifiedStatus::parse),
        representative_claim: header_str(
            headers,
            "anthropic-ratelimit-unified-representative-claim",
        )
        .map(String::from),
        reset_at: header_str(headers, "anthropic-ratelimit-unified-reset")
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|s| DateTime::from_timestamp(s, 0)),
        fallback_percentage: header_str(headers, "anthropic-ratelimit-unified-fallback-percentage")
            .and_then(|s| s.parse::<f64>().ok()),
        overage_status: header_str(headers, "anthropic-ratelimit-unified-overage-status")
            .and_then(OverageStatus::parse),
        overage_disabled_reason: header_str(
            headers,
            "anthropic-ratelimit-unified-overage-disabled-reason",
        )
        .map(String::from),
        overage_reset_at: header_str(headers, "anthropic-ratelimit-unified-overage-reset")
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|s| DateTime::from_timestamp(s, 0)),
    };

    if parsed.any_present() {
        Some(parsed)
    } else {
        None
    }
}

/// 解析 `retry-after` 头为 Duration。规范允许整数秒或 HTTP-date；Anthropic 实际只用秒，
/// HTTP-date 情况当前不处理（返回 None）。
fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let s = header_str(headers, "retry-after")?;
    let secs = s.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(secs))
}

/// 解析单个 RPM/TPM counter（例如 `anthropic-ratelimit-requests-{limit,remaining,reset}`）。
/// `kind` 取 `"requests"` / `"tokens"` / `"input-tokens"` / `"output-tokens"`。
/// 三个字段必须齐全且格式正确，否则返回 None。
fn parse_rpm_tpm_counter(headers: &HeaderMap, kind: &str) -> Option<RpmTpmCounter> {
    let limit = header_str(headers, &format!("anthropic-ratelimit-{}-limit", kind))?
        .parse::<i64>()
        .ok()?;
    let remaining = header_str(headers, &format!("anthropic-ratelimit-{}-remaining", kind))?
        .parse::<i64>()
        .ok()?;
    let reset_str = header_str(headers, &format!("anthropic-ratelimit-{}-reset", kind))?;
    let reset_at = DateTime::parse_from_rfc3339(reset_str)
        .ok()?
        .with_timezone(&Utc);
    Some(RpmTpmCounter {
        limit,
        remaining,
        reset_at,
    })
}

/// 解析 SetupToken（API key）的 4 路 RPM/TPM 头。任一齐全即返回 Some。
fn parse_rpm_tpm_headers(headers: &HeaderMap) -> Option<RpmTpmSnapshot> {
    let s = RpmTpmSnapshot {
        requests: parse_rpm_tpm_counter(headers, "requests"),
        tokens: parse_rpm_tpm_counter(headers, "tokens"),
        input_tokens: parse_rpm_tpm_counter(headers, "input-tokens"),
        output_tokens: parse_rpm_tpm_counter(headers, "output-tokens"),
    };
    if s.requests.is_none()
        && s.tokens.is_none()
        && s.input_tokens.is_none()
        && s.output_tokens.is_none()
    {
        None
    } else {
        Some(s)
    }
}

/// 把新一轮 RPM/TPM 解析结果合并进旧 state：新值覆盖旧值（每个 counter 独立）。
fn merge_rpm_tpm(prev: Option<RpmTpmSnapshot>, new: RpmTpmSnapshot) -> RpmTpmSnapshot {
    let mut out = prev.unwrap_or_default();
    if new.requests.is_some() {
        out.requests = new.requests;
    }
    if new.tokens.is_some() {
        out.tokens = new.tokens;
    }
    if new.input_tokens.is_some() {
        out.input_tokens = new.input_tokens;
    }
    if new.output_tokens.is_some() {
        out.output_tokens = new.output_tokens;
    }
    out
}

fn parse_window_from_headers(headers: &HeaderMap, abbrev: &str) -> Option<WindowSnapshot> {
    let util = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-utilization", abbrev),
    )?
    .parse::<f64>()
    .ok()?;
    let reset_secs = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-reset", abbrev),
    )?
    .parse::<i64>()
    .ok()?;
    let resets_at = DateTime::from_timestamp(reset_secs, 0)?;
    // status 可能按窗口独立返回（5h-status / 7d-status），缺失则落回全局 Allowed。
    let status = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-status", abbrev),
    )
    .and_then(UnifiedStatus::parse)
    .unwrap_or(UnifiedStatus::Allowed);
    let surpassed_threshold = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-surpassed-threshold", abbrev),
    )
    .and_then(|s| s.parse::<f64>().ok());

    Some(WindowSnapshot {
        utilization: util,
        resets_at,
        status,
        surpassed_threshold,
    })
}

/// 把 `/api/oauth/usage` JSON 的单个窗口（0-100 刻度）转为内部 0-1 表示。
fn parse_usage_json_window(usage: &serde_json::Value, key: &str) -> Option<WindowSnapshot> {
    let window = usage.get(key)?;
    let util_0_100 = window.get("utilization")?.as_f64()?;
    let resets_at_str = window.get("resets_at")?.as_str()?;
    let resets_at = DateTime::parse_from_rfc3339(resets_at_str)
        .ok()?
        .with_timezone(&Utc);
    Some(WindowSnapshot {
        utilization: util_0_100 / 100.0,
        resets_at,
        status: UnifiedStatus::Allowed, // JSON 不带 status，保守填 Allowed
        surpassed_threshold: None,
    })
}

fn apply_parsed(mut state: LimitState, parsed: ParsedHeaders) -> LimitState {
    if let Some(w) = parsed.five_hour {
        state.five_hour = Some(w);
    }
    if let Some(w) = parsed.seven_day {
        state.seven_day = Some(w);
    }
    if let Some(s) = parsed.status {
        state.status = Some(s);
    }
    if let Some(c) = parsed.representative_claim {
        state.representative_claim = Some(c);
    }
    if let Some(r) = parsed.reset_at {
        state.reset_at = Some(r);
    }
    if let Some(fp) = parsed.fallback_percentage {
        state.fallback_percentage = Some(fp);
    }
    if let Some(os) = parsed.overage_status {
        state.overage_status = Some(os);
    }
    if let Some(reason) = parsed.overage_disabled_reason {
        state.overage_disabled_reason = Some(reason);
    }
    if let Some(r) = parsed.overage_reset_at {
        state.overage_reset_at = Some(r);
    }
    state
}

/// 判定是否需要 flush 到 DB；返回 Some(reason) 触发，None 不触发。
fn flush_reason(prev: &LimitState, new: &LimitState) -> Option<&'static str> {
    // 1) 首次填充
    if prev.last_db_flush_at.is_none() {
        return Some("first-fill");
    }
    // 2) TTL 到期
    if let Some(last) = prev.last_db_flush_at {
        if last.elapsed() >= DB_FLUSH_TTL {
            return Some("ttl-expired");
        }
    }
    // 3) 全局状态从 Allowed 切走
    let prev_status = prev.status.unwrap_or(UnifiedStatus::Allowed);
    let new_status = new.status.unwrap_or(UnifiedStatus::Allowed);
    if prev_status == UnifiedStatus::Allowed && new_status != UnifiedStatus::Allowed {
        return Some("status-changed");
    }
    // 4) 任一窗口 utilization 跨过 97%
    if crossed_threshold(&prev.five_hour, &new.five_hour, HIT_THRESHOLD)
        || crossed_threshold(&prev.seven_day, &new.seven_day, HIT_THRESHOLD)
    {
        return Some("threshold-crossed-97pct");
    }
    // 5) 任一窗口新出现 surpassed-threshold 头
    if newly_surpassed(&prev.five_hour, &new.five_hour)
        || newly_surpassed(&prev.seven_day, &new.seven_day)
    {
        return Some("surpassed-threshold");
    }
    // 6) 新进入短期隔离（CF 429 或 Anthropic 429 无 reset）
    if prev.rate_limited_until.is_none() && new.rate_limited_until.is_some() {
        return Some("429-short-ban");
    }
    // 7) RPM/TPM 任一 counter 从"充裕"变"预抢"
    if rpm_tpm_newly_preempted(&prev.rpm_tpm, &new.rpm_tpm) {
        return Some("rpm-tpm-preempted");
    }
    None
}

/// 前后两轮 RPM/TPM 比较：上一轮无任何 counter 预抢、这一轮有 → true。
fn rpm_tpm_newly_preempted(
    prev: &Option<RpmTpmSnapshot>,
    new: &Option<RpmTpmSnapshot>,
) -> bool {
    let now = Utc::now();
    let prev_preempted = prev.as_ref().is_some_and(|p| p.first_preempted(now).is_some());
    let new_preempted = new.as_ref().is_some_and(|n| n.first_preempted(now).is_some());
    new_preempted && !prev_preempted
}

fn crossed_threshold(
    prev: &Option<WindowSnapshot>,
    new: &Option<WindowSnapshot>,
    threshold: f64,
) -> bool {
    let new_util = new.as_ref().map(|w| w.utilization).unwrap_or(0.0);
    let prev_util = prev.as_ref().map(|w| w.utilization).unwrap_or(0.0);
    new_util >= threshold && prev_util < threshold
}

fn newly_surpassed(prev: &Option<WindowSnapshot>, new: &Option<WindowSnapshot>) -> bool {
    let new_has = new.as_ref().and_then(|w| w.surpassed_threshold).is_some();
    let prev_has = prev.as_ref().and_then(|w| w.surpassed_threshold).is_some();
    new_has && !prev_has
}

/// 返回"瓶颈窗口"的 resets_at（用于 DB 列 rate_limit_reset_at）：
/// 若任一窗口 util >= 97%、或任一 RPM/TPM counter 预抢，且 resets_at 在未来，
/// 返回这些窗口中最晚的 resets_at；否则返回 None（上层会 clear_rate_limit）。
fn bottleneck_limit_until(state: &LimitState) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let mut picks: Vec<DateTime<Utc>> = Vec::new();
    for w in [&state.five_hour, &state.seven_day].into_iter().flatten() {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > now {
            picks.push(w.resets_at);
        }
    }
    if let Some(rt) = &state.rpm_tpm {
        for c in rt.all_counters() {
            if counter_preempted(c, now) {
                picks.push(c.reset_at);
            }
        }
    }
    picks.into_iter().max()
}

fn judge_availability(state: &LimitState) -> Availability {
    // 短期隔离优先判定：遇到过 429（无论 CF-layer 还是 Anthropic 无 reset 的 fallback）
    if let Some(until) = state.rate_limited_until {
        if until > Utc::now() {
            return Availability::Unavailable {
                reason: "429 短期隔离".into(),
                until: Some(until),
            };
        }
    }
    // SetupToken RPM/TPM 预抢
    if let Some(rt) = &state.rpm_tpm {
        if let Some((name, until)) = rt.first_preempted(Utc::now()) {
            return Availability::Unavailable {
                reason: format!("{} 剩余 < {:.0}%", name, PREEMPT_RATIO * 100.0),
                until: Some(until),
            };
        }
    }
    if let Some(w) = &state.five_hour {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > Utc::now() {
            return Availability::Unavailable {
                reason: format!("5 小时窗口已用 {:.1}%", w.utilization * 100.0),
                until: Some(w.resets_at),
            };
        }
    }
    if let Some(w) = &state.seven_day {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > Utc::now() {
            return Availability::Unavailable {
                reason: format!("7 天窗口已用 {:.1}%", w.utilization * 100.0),
                until: Some(w.resets_at),
            };
        }
    }
    // 全局 status = Rejected → 不可用
    if state.status == Some(UnifiedStatus::Rejected) {
        return Availability::Unavailable {
            reason: "上游已拒绝（status=rejected）".into(),
            until: state.reset_at,
        };
    }
    Availability::Available
}

/// 构造前端兼容的 `usage_data` JSON（utilization 乘 100 转 0-100 刻度）。
fn build_usage_json(state: &LimitState) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(w) = &state.five_hour {
        obj.insert("five_hour".into(), window_to_json(w));
    }
    if let Some(w) = &state.seven_day {
        obj.insert("seven_day".into(), window_to_json(w));
    }
    if let Some(w) = &state.sonnet_seven_day {
        obj.insert("seven_day_sonnet".into(), window_to_json(w));
    }
    if let Some(w) = &state.opus_seven_day {
        obj.insert("seven_day_opus".into(), window_to_json(w));
    }
    if let Some(s) = state.status {
        obj.insert("status".into(), serde_json::Value::from(s.as_str()));
    }
    if let Some(c) = &state.representative_claim {
        obj.insert("representative_claim".into(), serde_json::Value::from(c.clone()));
    }
    if let Some(r) = state.reset_at {
        obj.insert("resets_at".into(), serde_json::Value::from(r.to_rfc3339()));
    }
    if let Some(fp) = state.fallback_percentage {
        obj.insert("fallback_percentage".into(), serde_json::Value::from(fp));
    }
    if let Some(os) = state.overage_status {
        obj.insert(
            "overage_status".into(),
            serde_json::Value::from(os.as_str()),
        );
    }
    if let Some(reason) = &state.overage_disabled_reason {
        obj.insert(
            "overage_disabled_reason".into(),
            serde_json::Value::from(reason.clone()),
        );
    }
    if let Some(r) = state.overage_reset_at {
        obj.insert(
            "overage_reset_at".into(),
            serde_json::Value::from(r.to_rfc3339()),
        );
    }
    if let Some(until) = state.rate_limited_until {
        obj.insert(
            "rate_limited_until".into(),
            serde_json::Value::from(until.to_rfc3339()),
        );
    }
    if let Some(rt) = &state.rpm_tpm {
        obj.insert("rpm_tpm".into(), rpm_tpm_to_json(rt));
    }
    obj.insert("source".into(), serde_json::Value::from("headers"));
    serde_json::Value::Object(obj)
}

fn rpm_tpm_to_json(rt: &RpmTpmSnapshot) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    let put = |m: &mut serde_json::Map<String, serde_json::Value>,
               key: &str,
               c: &Option<RpmTpmCounter>| {
        if let Some(c) = c {
            let mut o = serde_json::Map::new();
            o.insert("limit".into(), serde_json::Value::from(c.limit));
            o.insert("remaining".into(), serde_json::Value::from(c.remaining));
            o.insert(
                "reset_at".into(),
                serde_json::Value::from(c.reset_at.to_rfc3339()),
            );
            m.insert(key.into(), serde_json::Value::Object(o));
        }
    };
    put(&mut m, "requests", &rt.requests);
    put(&mut m, "tokens", &rt.tokens);
    put(&mut m, "input_tokens", &rt.input_tokens);
    put(&mut m, "output_tokens", &rt.output_tokens);
    serde_json::Value::Object(m)
}

fn window_to_json(w: &WindowSnapshot) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "utilization".into(),
        serde_json::Value::from(w.utilization * 100.0),
    );
    m.insert(
        "resets_at".into(),
        serde_json::Value::from(w.resets_at.to_rfc3339()),
    );
    m.insert("status".into(), serde_json::Value::from(w.status.as_str()));
    if let Some(t) = w.surpassed_threshold {
        m.insert("surpassed_threshold".into(), serde_json::Value::from(t));
    }
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn real_200_headers() -> HeaderMap {
        // 来自真实抓包的 200 响应头子集（见 Phase 2 plan）
        make_headers(&[
            ("anthropic-ratelimit-unified-5h-reset", "1776427200"),
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.14"),
            ("anthropic-ratelimit-unified-7d-reset", "1776996000"),
            ("anthropic-ratelimit-unified-7d-status", "allowed"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.03"),
            ("anthropic-ratelimit-unified-fallback-percentage", "0.5"),
            ("anthropic-ratelimit-unified-overage-disabled-reason", "org_level_disabled"),
            ("anthropic-ratelimit-unified-overage-status", "rejected"),
            ("anthropic-ratelimit-unified-representative-claim", "five_hour"),
            ("anthropic-ratelimit-unified-reset", "1776427200"),
            ("anthropic-ratelimit-unified-status", "allowed"),
        ])
    }

    #[test]
    fn parse_real_200_response_headers() {
        let h = real_200_headers();
        let p = parse_unified_headers(&h).expect("has fields");
        let five = p.five_hour.as_ref().expect("5h present");
        assert!((five.utilization - 0.14).abs() < 1e-9);
        assert_eq!(five.status, UnifiedStatus::Allowed);
        let seven = p.seven_day.as_ref().expect("7d present");
        assert!((seven.utilization - 0.03).abs() < 1e-9);
        assert_eq!(p.status, Some(UnifiedStatus::Allowed));
        assert_eq!(p.representative_claim.as_deref(), Some("five_hour"));
        assert_eq!(p.overage_status, Some(OverageStatus::Rejected));
        assert_eq!(p.fallback_percentage, Some(0.5));
    }

    #[test]
    fn parse_none_when_no_unified_headers() {
        let h = make_headers(&[("content-type", "text/event-stream")]);
        assert!(parse_unified_headers(&h).is_none());
    }

    #[test]
    fn parse_ignores_malformed_utilization() {
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-5h-utilization", "not-a-number"),
            ("anthropic-ratelimit-unified-5h-reset", "1776427200"),
        ]);
        let p = parse_unified_headers(&h);
        assert!(p.is_none() || p.unwrap().five_hour.is_none());
    }

    #[test]
    fn decide_flush_first_fill_always_flushes() {
        let prev = LimitState::default();
        let new = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn decide_flush_within_ttl_no_trigger() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.15,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_none());
    }

    #[test]
    fn decide_flush_crossing_97_triggers() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.96,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn decide_flush_status_allowed_to_warning_triggers() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            status: Some(UnifiedStatus::Allowed),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            status: Some(UnifiedStatus::AllowedWarning),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn availability_empty_is_available() {
        let state = LimitState::default();
        assert!(judge_availability(&state).is_available());
    }

    #[test]
    fn availability_14pct_is_available() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            status: Some(UnifiedStatus::Allowed),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    #[test]
    fn availability_97pct_5h_is_unavailable() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() + chrono::Duration::hours(1),
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        match judge_availability(&state) {
            Availability::Unavailable { until, .. } => assert!(until.is_some()),
            Availability::Available => panic!("should be unavailable"),
        }
    }

    #[test]
    fn availability_rejected_is_unavailable() {
        let state = LimitState {
            status: Some(UnifiedStatus::Rejected),
            ..Default::default()
        };
        assert!(!judge_availability(&state).is_available());
    }

    #[test]
    fn availability_97pct_past_reset_is_available() {
        // 即使 utilization = 97%，如果 reset 已经过去，视为已重置
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() - chrono::Duration::hours(1),
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    // ---- bottleneck_limit_until ----

    #[test]
    fn bottleneck_none_when_all_below_97() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(bottleneck_limit_until(&state).is_none());
    }

    #[test]
    fn bottleneck_picks_five_hour_when_only_5h_over() {
        let five_reset = Utc::now() + chrono::Duration::hours(2);
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.98,
                resets_at: five_reset,
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            seven_day: Some(WindowSnapshot {
                utilization: 0.30,
                resets_at: Utc::now() + chrono::Duration::days(5),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert_eq!(bottleneck_limit_until(&state), Some(five_reset));
    }

    #[test]
    fn bottleneck_picks_later_when_both_over() {
        // 两个窗口都撞墙时，取更晚的 resets_at（限流更久）
        let five_reset = Utc::now() + chrono::Duration::hours(2);
        let seven_reset = Utc::now() + chrono::Duration::days(5);
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.98,
                resets_at: five_reset,
                status: UnifiedStatus::Rejected,
                surpassed_threshold: None,
            }),
            seven_day: Some(WindowSnapshot {
                utilization: 0.99,
                resets_at: seven_reset,
                status: UnifiedStatus::Rejected,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert_eq!(bottleneck_limit_until(&state), Some(seven_reset));
    }

    #[test]
    fn bottleneck_skips_past_reset() {
        // 即使 util >= 97%，reset 已过去视为已重置
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.99,
                resets_at: Utc::now() - chrono::Duration::hours(1),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(bottleneck_limit_until(&state).is_none());
    }

    #[test]
    fn build_usage_json_converts_to_0_100_scale() {        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: DateTime::from_timestamp(1776427200, 0).unwrap(),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let json = build_usage_json(&state);
        let util = json
            .get("five_hour")
            .and_then(|w| w.get("utilization"))
            .and_then(|u| u.as_f64())
            .unwrap();
        assert!((util - 14.0).abs() < 1e-9);
    }

    #[test]
    fn ingest_usage_json_converts_0_100_to_0_1() {
        // 没有 AccountStore 可用，只测试纯内存路径
        // 需要小心地构造一个不依赖 store 的测试 helper
    }

    // ---- 429 路径（Phase 3）----

    /// 模拟 CF-layer 429：响应里没有任何 anthropic-ratelimit-* 头也没 retry-after。
    /// 预期：rate_limited_until = now + 60s，availability Unavailable。
    #[test]
    fn absorb_429_cf_without_headers_sets_60s_ban() {
        let h = make_headers(&[("content-type", "text/html")]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        let until = new.rate_limited_until.expect("rate_limited_until set");
        let expected = Utc::now() + chrono::Duration::seconds(60);
        // 允许 2 秒误差（测试机 clock 漂移）
        let diff = (until - expected).num_seconds().abs();
        assert!(diff <= 2, "expected ~60s ban, got diff={}s", diff);
        assert!(!judge_availability(&new).is_available());
    }

    /// CF-layer 429 但带 retry-after：应用 retry-after 数值，忽略默认 60s。
    #[test]
    fn absorb_429_cf_with_retry_after_uses_it() {
        let h = make_headers(&[("retry-after", "120")]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        let until = new.rate_limited_until.expect("rate_limited_until set");
        let expected = Utc::now() + chrono::Duration::seconds(120);
        let diff = (until - expected).num_seconds().abs();
        assert!(diff <= 2, "expected ~120s ban, got diff={}s", diff);
    }

    /// Anthropic-layer 429，有 5h/7d 窗口头 + retry-after，但缺全局 unified-reset。
    /// 预期：rate_limited_until 用 retry-after 兜底（即使窗口数据已被吸收）。
    #[test]
    fn absorb_429_anthropic_without_reset_falls_back_to_retry_after() {
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-5h-reset", "1776427200"),
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.99"),
            ("anthropic-ratelimit-unified-status", "rejected"),
            // 故意不给 unified-reset
            ("retry-after", "300"),
        ]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        // 5h 窗口应被正常吸收
        assert!(new.five_hour.is_some());
        assert_eq!(new.status, Some(UnifiedStatus::Rejected));
        // retry-after 应被用于补 rate_limited_until
        let until = new.rate_limited_until.expect("rate_limited_until set");
        let expected = Utc::now() + chrono::Duration::seconds(300);
        let diff = (until - expected).num_seconds().abs();
        assert!(diff <= 2, "expected ~300s ban, got diff={}s", diff);
    }

    /// Anthropic-layer 429，带完整 unified-* 头（包括全局 reset）：
    /// 预期走既有路径（Phase 2 逻辑），不填 rate_limited_until，既有 97% / status=Rejected 判定生效。
    #[test]
    fn absorb_429_anthropic_with_full_unified_still_works() {
        let reset_ts = (Utc::now() + chrono::Duration::hours(2)).timestamp();
        let h = make_headers(&[
            (
                "anthropic-ratelimit-unified-5h-reset",
                &reset_ts.to_string(),
            ),
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.99"),
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", &reset_ts.to_string()),
        ]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        assert!(new.rate_limited_until.is_none(), "不应走 fallback 路径");
        assert_eq!(new.status, Some(UnifiedStatus::Rejected));
        // availability 应判 Unavailable（5h 97%）
        assert!(!judge_availability(&new).is_available());
    }

    /// 200 响应且无 unified-* 头：不应触发任何更新（Phase 2 回归）。
    #[test]
    fn absorb_200_without_headers_does_nothing() {
        let h = make_headers(&[("content-type", "text/event-stream")]);
        let prev = LimitState::default();
        assert!(compute_new_state(&prev, 200, &h).is_none());
    }

    /// availability 直接尊重 rate_limited_until，即使没有 5h/7d/status 证据。
    #[test]
    fn availability_respects_rate_limited_until() {
        let state = LimitState {
            rate_limited_until: Some(Utc::now() + chrono::Duration::seconds(30)),
            ..Default::default()
        };
        match judge_availability(&state) {
            Availability::Unavailable { until, .. } => assert!(until.is_some()),
            Availability::Available => panic!("应 Unavailable"),
        }
    }

    /// rate_limited_until 过期后立即恢复可用（不需要清字段）。
    #[test]
    fn rate_limited_until_expiring_allows_reuse() {
        let state = LimitState {
            rate_limited_until: Some(Utc::now() - chrono::Duration::seconds(1)),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    /// 首次进入短期隔离应触发 flush（first-fill 覆盖更广，但短期隔离场景值得单测）。
    #[test]
    fn flush_on_short_ban_first_time() {
        // 模拟 prev 已有 last_db_flush_at（前面发过别的请求），但 rate_limited_until 本次首次出现
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            rate_limited_until: Some(Utc::now() + chrono::Duration::seconds(60)),
            ..Default::default()
        };
        assert_eq!(flush_reason(&prev, &new), Some("429-short-ban"));
    }

    #[test]
    fn parse_retry_after_valid_int() {
        let h = make_headers(&[("retry-after", "42")]);
        assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(42)));
    }

    #[test]
    fn parse_retry_after_malformed_none() {
        let h = make_headers(&[("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")]);
        assert!(parse_retry_after(&h).is_none());
        let h2 = make_headers(&[("retry-after", "abc")]);
        assert!(parse_retry_after(&h2).is_none());
        let h3 = make_headers(&[]);
        assert!(parse_retry_after(&h3).is_none());
    }

    // ---- SetupToken RPM/TPM 路径（Phase 4）----

    fn rpm_tpm_full_headers() -> Vec<(&'static str, String)> {
        let reset = "2026-04-17T12:01:00Z".to_string();
        vec![
            ("anthropic-ratelimit-requests-limit", "50".into()),
            ("anthropic-ratelimit-requests-remaining", "48".into()),
            ("anthropic-ratelimit-requests-reset", reset.clone()),
            ("anthropic-ratelimit-tokens-limit", "1000000".into()),
            ("anthropic-ratelimit-tokens-remaining", "998000".into()),
            ("anthropic-ratelimit-tokens-reset", reset.clone()),
            ("anthropic-ratelimit-input-tokens-limit", "500000".into()),
            ("anthropic-ratelimit-input-tokens-remaining", "499000".into()),
            ("anthropic-ratelimit-input-tokens-reset", reset.clone()),
            ("anthropic-ratelimit-output-tokens-limit", "500000".into()),
            ("anthropic-ratelimit-output-tokens-remaining", "499000".into()),
            ("anthropic-ratelimit-output-tokens-reset", reset),
        ]
    }

    fn headers_from(pairs: Vec<(&'static str, String)>) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parse_rpm_tpm_counter_full() {
        let h = headers_from(rpm_tpm_full_headers());
        let snap = parse_rpm_tpm_headers(&h).expect("should parse");
        assert!(snap.requests.is_some());
        assert!(snap.tokens.is_some());
        assert!(snap.input_tokens.is_some());
        assert!(snap.output_tokens.is_some());
        let r = snap.requests.as_ref().unwrap();
        assert_eq!(r.limit, 50);
        assert_eq!(r.remaining, 48);
    }

    #[test]
    fn parse_rpm_tpm_counter_rfc3339_reset() {
        let h = headers_from(rpm_tpm_full_headers());
        let snap = parse_rpm_tpm_headers(&h).unwrap();
        let r = snap.requests.unwrap();
        // 2026-04-17T12:01:00Z
        assert_eq!(r.reset_at.timestamp(), 1776427260);
    }

    #[test]
    fn parse_rpm_tpm_returns_none_without_any_header() {
        let h = make_headers(&[("content-type", "application/json")]);
        assert!(parse_rpm_tpm_headers(&h).is_none());
    }

    #[test]
    fn parse_rpm_tpm_partial_headers_ok() {
        // 只有 requests 齐全，其它 counter 缺字段
        let h = make_headers(&[
            ("anthropic-ratelimit-requests-limit", "50"),
            ("anthropic-ratelimit-requests-remaining", "48"),
            ("anthropic-ratelimit-requests-reset", "2026-04-17T12:01:00Z"),
        ]);
        let snap = parse_rpm_tpm_headers(&h).expect("should parse requests");
        assert!(snap.requests.is_some());
        assert!(snap.tokens.is_none());
    }

    #[test]
    fn parse_rpm_tpm_malformed_reset_yields_none_for_that_counter() {
        let h = make_headers(&[
            ("anthropic-ratelimit-requests-limit", "50"),
            ("anthropic-ratelimit-requests-remaining", "48"),
            ("anthropic-ratelimit-requests-reset", "not-a-date"),
        ]);
        // 所有 counter 都缺/坏 → 整体 None
        assert!(parse_rpm_tpm_headers(&h).is_none());
    }

    fn counter(limit: i64, remaining: i64, reset_future_secs: i64) -> RpmTpmCounter {
        RpmTpmCounter {
            limit,
            remaining,
            reset_at: Utc::now() + chrono::Duration::seconds(reset_future_secs),
        }
    }

    #[test]
    fn availability_preempted_when_requests_below_3pct() {
        // 50 * 3% = 1.5，所以 remaining=1 应预抢
        let state = LimitState {
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 1, 30)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let a = judge_availability(&state);
        assert!(!a.is_available(), "remaining=1/50 应预抢");
        match a {
            Availability::Unavailable { until, reason } => {
                assert!(until.is_some());
                assert!(reason.contains("requests"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn availability_not_preempted_at_exactly_3pct() {
        // 50 * 3% = 1.5，remaining=2 的比例 4% > 3%，应可用
        let state = LimitState {
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 2, 30)),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    #[test]
    fn availability_preempted_by_tokens_even_if_requests_ok() {
        // requests 充裕，但 tokens 预抢 → 仍应 Unavailable，且 reason 指向 tokens
        let state = LimitState {
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 48, 30)),
                tokens: Some(counter(1_000_000, 10_000, 30)), // 1% 剩余
                ..Default::default()
            }),
            ..Default::default()
        };
        match judge_availability(&state) {
            Availability::Unavailable { reason, .. } => assert!(reason.contains("tokens")),
            _ => panic!("should be unavailable"),
        }
    }

    #[test]
    fn bottleneck_includes_rpm_tpm() {
        let rpm_reset = Utc::now() + chrono::Duration::seconds(30);
        let state = LimitState {
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(RpmTpmCounter {
                    limit: 50,
                    remaining: 1,
                    reset_at: rpm_reset,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(bottleneck_limit_until(&state), Some(rpm_reset));
    }

    #[test]
    fn bottleneck_picks_max_across_5h_and_rpm_tpm() {
        let rpm_reset = Utc::now() + chrono::Duration::seconds(30);
        let five_reset = Utc::now() + chrono::Duration::hours(2);
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.99,
                resets_at: five_reset,
                status: UnifiedStatus::Rejected,
                surpassed_threshold: None,
            }),
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(RpmTpmCounter {
                    limit: 50,
                    remaining: 1,
                    reset_at: rpm_reset,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        // 5h 解除更晚，应优先选 five_reset
        assert_eq!(bottleneck_limit_until(&state), Some(five_reset));
    }

    #[test]
    fn flush_on_rpm_tpm_newly_preempted() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 48, 30)), // 充裕
                ..Default::default()
            }),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 1, 30)), // 预抢
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(flush_reason(&prev, &new), Some("rpm-tpm-preempted"));
    }

    #[test]
    fn absorb_200_with_rpm_tpm_updates_state() {
        let h = headers_from(rpm_tpm_full_headers());
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 200, &h).expect("should produce state");
        assert!(new.rpm_tpm.is_some());
        let rt = new.rpm_tpm.unwrap();
        assert_eq!(rt.requests.unwrap().limit, 50);
        assert_eq!(rt.tokens.unwrap().remaining, 998000);
    }

    #[test]
    fn absorb_unified_and_rpm_tpm_coexist() {
        let mut headers = rpm_tpm_full_headers();
        headers.extend([
            ("anthropic-ratelimit-unified-5h-reset", "1776427200".into()),
            ("anthropic-ratelimit-unified-5h-status", "allowed".into()),
            ("anthropic-ratelimit-unified-5h-utilization", "0.14".into()),
            ("anthropic-ratelimit-unified-status", "allowed".into()),
        ]);
        let h = headers_from(headers);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 200, &h).expect("should produce state");
        assert!(new.five_hour.is_some(), "unified 路径应被吸收");
        assert!(new.rpm_tpm.is_some(), "RPM/TPM 路径应被吸收");
    }

    #[test]
    fn usage_json_exposes_rpm_tpm() {
        let state = LimitState {
            rpm_tpm: Some(RpmTpmSnapshot {
                requests: Some(counter(50, 48, 30)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = build_usage_json(&state);
        let rt = json.get("rpm_tpm").expect("has rpm_tpm");
        let req = rt.get("requests").expect("has requests");
        assert_eq!(req.get("limit").and_then(|v| v.as_i64()), Some(50));
        assert_eq!(req.get("remaining").and_then(|v| v.as_i64()), Some(48));
    }

    // ---- Sonnet 旁路（Phase 5）----

    fn reset_future_unix() -> String {
        (Utc::now().timestamp() + 3600).to_string()
    }

    /// 429 + representative-claim=seven_day_sonnet → status 不应被设为 Rejected，
    /// 账号 availability 保持 Available（不影响 Opus 调度）。
    #[test]
    fn absorb_429_sonnet_claim_does_not_set_rejected() {
        let r = reset_future_unix();
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-5h-reset", &r),
            ("anthropic-ratelimit-unified-5h-status", "rejected"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.50"),
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", &r),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "seven_day_sonnet",
            ),
        ]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        // 关键：全局 status 不应被设为 Rejected
        assert_ne!(new.status, Some(UnifiedStatus::Rejected));
        // representative_claim 仍被吸收（UI 要用）
        assert_eq!(new.representative_claim.as_deref(), Some("seven_day_sonnet"));
        // availability 保持 Available（5h util 0.50 远低于 97%，无其它拉黑条件）
        assert!(judge_availability(&new).is_available());
    }

    /// 429 + representative-claim=seven_day_opus → 保持既有拉黑行为（Opus 覆盖所有 Opus 请求）。
    #[test]
    fn absorb_429_opus_claim_still_rejects() {
        let r = reset_future_unix();
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", &r),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "seven_day_opus",
            ),
        ]);
        let prev = LimitState::default();
        let new = compute_new_state(&prev, 429, &h).expect("should produce state");
        assert_eq!(new.status, Some(UnifiedStatus::Rejected));
        assert!(!judge_availability(&new).is_available());
    }

    /// 429 + representative-claim=seven_day（聚合周）→ 保持既有拉黑。
    #[test]
    fn absorb_429_seven_day_aggregate_still_rejects() {
        let r = reset_future_unix();
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", &r),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "seven_day",
            ),
        ]);
        let new = compute_new_state(&LimitState::default(), 429, &h).expect("state");
        assert_eq!(new.status, Some(UnifiedStatus::Rejected));
        assert!(!judge_availability(&new).is_available());
    }

    /// 429 + representative-claim=five_hour → 保持既有拉黑。
    #[test]
    fn absorb_429_five_hour_claim_still_rejects() {
        let r = reset_future_unix();
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", &r),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "five_hour",
            ),
        ]);
        let new = compute_new_state(&LimitState::default(), 429, &h).expect("state");
        assert_eq!(new.status, Some(UnifiedStatus::Rejected));
        assert!(!judge_availability(&new).is_available());
    }

    /// 200 + representative-claim=seven_day_sonnet（正常响应含 Sonnet hint）→ 不触发旁路。
    /// 该场景下 status=Allowed/Warning 本就不会拉黑，但确认我们没有错误地把 status 清成 None。
    #[test]
    fn absorb_200_sonnet_claim_keeps_status_allowed() {
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-status", "allowed_warning"),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "seven_day_sonnet",
            ),
        ]);
        let new = compute_new_state(&LimitState::default(), 200, &h).expect("state");
        // 200 不触发旁路；status 正常吸收
        assert_eq!(new.status, Some(UnifiedStatus::AllowedWarning));
    }

    #[test]
    fn is_sonnet_rejection_detects_header() {
        let h = make_headers(&[(
            "anthropic-ratelimit-unified-representative-claim",
            "seven_day_sonnet",
        )]);
        assert!(is_sonnet_rejection(&h));
    }

    #[test]
    fn is_sonnet_rejection_false_for_other_claims() {
        for claim in ["seven_day_opus", "seven_day", "five_hour"] {
            let h = make_headers(&[(
                "anthropic-ratelimit-unified-representative-claim",
                claim,
            )]);
            assert!(!is_sonnet_rejection(&h), "claim={} should not match", claim);
        }
        let h_empty = make_headers(&[]);
        assert!(!is_sonnet_rejection(&h_empty));
    }
}
