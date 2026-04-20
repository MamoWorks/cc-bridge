use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use chrono::Utc;
use rand::Rng;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::model::account::{Account, CanonicalEnvData, CanonicalProcessData};
use crate::service::account::AccountService;
use crate::store::account_store::AccountStore;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
const EVENT_BATCH_INTERVAL: Duration = Duration::from_secs(10);
const GROWTHBOOK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const METRICS_INTERVAL: Duration = Duration::from_secs(60);
const TICK_INTERVAL: Duration = Duration::from_secs(1);

const UPSTREAM_BASE: &str = "https://api.anthropic.com";
const GROWTHBOOK_CLIENT_KEY: &str = "sdk-zAZezfDKGoZuXXKe";

// ---------------------------------------------------------------------------
// 遥测路径判断
// ---------------------------------------------------------------------------

/// 判断请求路径是否为遥测端点。
pub fn is_telemetry_path(path: &str) -> bool {
    path.contains("/event_logging/batch")
        || path.starts_with("/api/eval/")
        || path.starts_with("/api/claude_code/metrics")
        || path.starts_with("/api/claude_code/organizations/metrics_enabled")
}

/// 针对 metrics_enabled 返回固定 JSON 响应。
pub fn fake_metrics_enabled_response() -> serde_json::Value {
    json!({"metrics_logging_enabled": true})
}

/// 针对其他遥测端点返回空成功响应。
pub fn fake_telemetry_response() -> serde_json::Value {
    json!({})
}

// ---------------------------------------------------------------------------
// 会话状态
// ---------------------------------------------------------------------------

struct TelemetrySession {
    account: Account,
    token: String,
    started_at: Instant,
    expires_at: Instant,
    expires_at_utc: chrono::DateTime<Utc>,
    last_event_batch_at: Instant,
    last_growthbook_at: Option<Instant>,
    last_metrics_at: Instant,
    send_count: i64,
    running: bool,
    /// 最近一次 /v1/messages 使用的模型 ID — 用于 tengu_api_success 的 model 字段。
    last_model: String,
    /// 累积 CPU 用户态微秒数（模拟 process.cpuUsage().user，严格单调递增）。
    cpu_user_total: i64,
    /// 累积 CPU 系统态微秒数（模拟 process.cpuUsage().system）。
    cpu_system_total: i64,
    /// 上次更新 CPU 字段时的 wall time，用于计算 cpuPercent。
    last_cpu_update: Instant,
    /// 待发送事件数 — 由 activate_session 递增，telemetry_loop 消费，避免固定心跳。
    pending_events: i32,
    /// 下次 event_batch 允许发送的时间点（用于抖动）。
    next_event_allowed_at: Instant,
    /// 遥测 session_id — 对标真实 CC `bootstrap/state.ts:331` 的 `randomUUID()`：
    /// **进程级别**，整个遥测会话（10 min）内所有事件共用同一个值。
    /// 修复前：每 batch `Uuid::new_v4()` → Anthropic 看到同一账号每 10s 换新 session_id，
    /// 物理上不可能，属于强指纹。
    telemetry_session_id: String,
    /// 进程已运行秒数的偏移量，对标 `process.uptime()`：
    /// 真实 CC 从 Node 进程启动就开始计时，首次 /v1/messages 往往发生在启动后 20-180s，
    /// 所以首个事件的 uptime 绝不会接近 0。首次激活时随机选一个 "进程已跑了多久" 作基准。
    uptime_offset_secs: f64,
    /// 内存基线（rss/heapTotal/heapUsed/external/arrayBuffers），模拟 process.memoryUsage()：
    /// 真实采样值在基线上做小幅 ±3% 漂移，而非每次重新整区间随机。
    mem_rss: i64,
    mem_heap_total: i64,
    mem_heap_used: i64,
    mem_external: i64,
    mem_array_buffers: i64,
    /// 已累计发送的事件条数（所有 event_logging/batch 内条数之和），用于日志。
    events_sent_total: i64,
    /// 是否已发送过 tengu_startup（整个遥测会话中只发一次）。
    startup_sent: bool,
}

// ---------------------------------------------------------------------------
// TelemetryService
// ---------------------------------------------------------------------------

/// 管理自动遥测会话的后台服务。
pub struct TelemetryService {
    sessions: Arc<Mutex<HashMap<i64, TelemetrySession>>>,
    account_store: Arc<AccountStore>,
    account_svc: Arc<AccountService>,
}

impl TelemetryService {
    pub fn new(account_store: Arc<AccountStore>, account_svc: Arc<AccountService>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            account_store,
            account_svc,
        }
    }

    /// 查询账号的遥测会话过期时间。
    pub async fn get_session_expires_at(&self, account_id: i64) -> Option<chrono::DateTime<Utc>> {
        let sessions = self.sessions.lock().await;
        sessions.get(&account_id).map(|s| s.expires_at_utc)
    }

    /// 当 /v1/messages 请求到来时调用，激活或续期遥测会话。
    /// `model_id` 为本次请求的模型（供后续 tengu_api_success 事件使用）；
    /// 同时每次调用都会把 pending_events += 1，让 telemetry_loop 驱动事件发送。
    pub async fn activate_session(&self, account: &Account, model_id: &str) {
        if !account.auto_telemetry {
            return;
        }

        let token = match self.account_svc.resolve_upstream_token_with(account).await {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "telemetry: cannot resolve token for account {}: {}",
                    account.id, e
                );
                return;
            }
        };

        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();

        if let Some(session) = sessions.get_mut(&account.id) {
            // 续期
            session.expires_at = now + SESSION_TTL;
            session.expires_at_utc = Utc::now() + chrono::Duration::from_std(SESSION_TTL).unwrap();
            session.token = token;
            session.account = account.clone();
            if !model_id.is_empty() {
                session.last_model = model_id.to_string();
            }
            session.pending_events = session.pending_events.saturating_add(1);
            debug!("telemetry: renewed session for account {}", account.id);
            return;
        }

        // 新建会话
        info!("telemetry: starting session for account {}", account.id);
        let resolved_model = if model_id.is_empty() {
            "claude-sonnet-4-5-20250929".to_string()
        } else {
            model_id.to_string()
        };

        // 初始化内存基线（从账号 preset 的区间随机取一个点作为起点）
        let proc_preset: CanonicalProcessData =
            serde_json::from_value(account.canonical_process.clone()).unwrap_or_default();
        // 初始化进程 uptime 偏移（模拟真实 CC 首次 API 调用前已启动了 20-180s）
        let (mem_rss, mem_ht, mem_hu, mem_ext, mem_ab, uptime_offset) = {
            let mut rng = rand::thread_rng();
            (
                rng.gen_range(proc_preset.rss_range[0]..=proc_preset.rss_range[1]),
                rng.gen_range(proc_preset.heap_total_range[0]..=proc_preset.heap_total_range[1]),
                rng.gen_range(proc_preset.heap_used_range[0]..=proc_preset.heap_used_range[1]),
                rng.gen_range(proc_preset.external_range[0]..=proc_preset.external_range[1]),
                rng.gen_range(
                    proc_preset.array_buffers_range[0]..=proc_preset.array_buffers_range[1],
                ),
                rng.gen_range(20.0f64..=180.0f64),
            )
        };

        let session = TelemetrySession {
            account: account.clone(),
            token,
            started_at: now,
            expires_at: now + SESSION_TTL,
            expires_at_utc: Utc::now() + chrono::Duration::from_std(SESSION_TTL).unwrap(),
            last_event_batch_at: now - EVENT_BATCH_INTERVAL, // 立即触发首次
            last_growthbook_at: None,
            last_metrics_at: now - METRICS_INTERVAL,
            send_count: 0,
            running: true,
            last_model: resolved_model,
            cpu_user_total: 0,
            cpu_system_total: 0,
            last_cpu_update: now,
            pending_events: 1,
            next_event_allowed_at: now,
            telemetry_session_id: uuid::Uuid::new_v4().to_string(),
            uptime_offset_secs: uptime_offset,
            mem_rss,
            mem_heap_total: mem_ht,
            mem_heap_used: mem_hu,
            mem_external: mem_ext,
            mem_array_buffers: mem_ab,
            events_sent_total: 0,
            startup_sent: false,
        };
        sessions.insert(account.id, session);

        // 启动后台任务
        let sessions_ref = self.sessions.clone();
        let store_ref = self.account_store.clone();
        let account_id = account.id;
        let proxy_url = account.proxy_url.clone();

        tokio::spawn(async move {
            telemetry_loop(sessions_ref, store_ref, account_id, proxy_url).await;
        });
    }
}

// ---------------------------------------------------------------------------
// 后台循环
// ---------------------------------------------------------------------------

async fn telemetry_loop(
    sessions: Arc<Mutex<HashMap<i64, TelemetrySession>>>,
    store: Arc<AccountStore>,
    account_id: i64,
    proxy_url: String,
) {
    let client = crate::tlsfp::make_request_client(&proxy_url);

    loop {
        tokio::time::sleep(TICK_INTERVAL).await;

        let mut map = sessions.lock().await;
        let session = match map.get_mut(&account_id) {
            Some(s) => s,
            None => break,
        };

        // TTL 过期 → 持久化计数并退出
        if Instant::now() >= session.expires_at {
            let count = session.send_count;
            session.running = false;
            map.remove(&account_id);
            drop(map);
            if count > 0 {
                let _ = store.increment_telemetry_count(account_id, count).await;
            }
            info!(
                "telemetry: session expired for account {}, sent {} requests",
                account_id, count
            );
            break;
        }

        let now = Instant::now();

        // --- event_logging/batch ---
        // 仅当有待发送事件 + 已过最小间隔 + 超过抖动的允许发送时间
        if session.pending_events > 0
            && now.duration_since(session.last_event_batch_at) >= EVENT_BATCH_INTERVAL
            && now >= session.next_event_allowed_at
        {
            // uptime 对标 process.uptime()：从 "进程启动" 算起，而非从首次 API 调用算起
            let uptime_secs = session.uptime_offset_secs
                + now.duration_since(session.started_at).as_secs_f64();
            // 更新累积 CPU 指标（模拟 process.cpuUsage 单调递增）
            let wall_delta_ms = now.duration_since(session.last_cpu_update).as_millis() as i64;
            // 限定 rng 作用域：避免 ThreadRng (非 Send) 跨 .await
            let (user_delta, system_delta, jitter_secs, mem_drifts) = {
                let mut rng = rand::thread_rng();
                let u = rng.gen_range(
                    (wall_delta_ms.max(1) * 5)..=(wall_delta_ms.max(1) * 30).max(1),
                );
                let s = rng.gen_range(
                    (wall_delta_ms.max(1) * 2)..=(wall_delta_ms.max(1) * 10).max(1),
                );
                let j = rng.gen_range(3u64..=12);
                // 每个内存字段 ±3% 漂移（对标 process.memoryUsage() 的自然漂移）
                let mut drift = || rng.gen_range(-0.03f64..=0.03f64);
                (u, s, j, [drift(), drift(), drift(), drift(), drift()])
            };
            session.cpu_user_total = session.cpu_user_total.saturating_add(user_delta);
            session.cpu_system_total = session.cpu_system_total.saturating_add(system_delta);
            let cpu_percent = if wall_delta_ms > 0 {
                ((user_delta + system_delta) as f64) / ((wall_delta_ms * 1000) as f64) * 100.0
            } else {
                0.0
            };
            session.last_cpu_update = now;

            // 在基线上做 ±3% 漂移并 clamp 到合理区间
            let proc_preset: CanonicalProcessData =
                serde_json::from_value(session.account.canonical_process.clone())
                    .unwrap_or_default();
            let clamp = |v: i64, range: [i64; 2]| v.max(range[0] / 2).min(range[1] * 2);
            session.mem_rss = clamp(
                (session.mem_rss as f64 * (1.0 + mem_drifts[0])) as i64,
                proc_preset.rss_range,
            );
            session.mem_heap_total = clamp(
                (session.mem_heap_total as f64 * (1.0 + mem_drifts[1])) as i64,
                proc_preset.heap_total_range,
            );
            // heap_used 不能超过 heap_total
            session.mem_heap_used = clamp(
                (session.mem_heap_used as f64 * (1.0 + mem_drifts[2])) as i64,
                proc_preset.heap_used_range,
            )
            .min(session.mem_heap_total);
            session.mem_external = clamp(
                (session.mem_external as f64 * (1.0 + mem_drifts[3])) as i64,
                proc_preset.external_range,
            );
            session.mem_array_buffers = clamp(
                (session.mem_array_buffers as f64 * (1.0 + mem_drifts[4])) as i64,
                proc_preset.array_buffers_range,
            );

            let emit_startup = !session.startup_sent;
            session.startup_sent = true;

            let payload = build_event_batch(EventBatchCtx {
                account: &session.account,
                uptime_secs,
                model: &session.last_model,
                cpu_user_total: session.cpu_user_total,
                cpu_system_total: session.cpu_system_total,
                cpu_percent,
                session_id: &session.telemetry_session_id,
                mem_rss: session.mem_rss,
                mem_heap_total: session.mem_heap_total,
                mem_heap_used: session.mem_heap_used,
                mem_external: session.mem_external,
                mem_array_buffers: session.mem_array_buffers,
                emit_startup,
            });
            let event_count = payload
                .get("events")
                .and_then(|e| e.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0);
            let token = session.token.clone();
            let c = client.clone();
            session.last_event_batch_at = now;
            session.send_count += 1;
            session.events_sent_total += event_count;
            session.pending_events -= 1;
            // 下次发送加 3–12s 抖动，避免固定周期
            session.next_event_allowed_at = now + Duration::from_secs(jitter_secs);
            drop(map);

            send_telemetry(
                &c,
                &format!("{}/api/event_logging/batch", UPSTREAM_BASE),
                &token,
                &payload,
                &session_ua(&store, account_id).await,
            )
            .await;

            let _ = store.increment_telemetry_count(account_id, 1).await;
            continue;
        }

        // --- GrowthBook eval ---
        let should_gb = match session.last_growthbook_at {
            None => true,
            Some(t) => now.duration_since(t) >= GROWTHBOOK_INTERVAL,
        };
        if should_gb {
            let payload = build_growthbook_eval(&session.account);
            let token = session.token.clone();
            let c = client.clone();
            session.last_growthbook_at = Some(now);
            session.send_count += 1;
            drop(map);

            send_telemetry(
                &c,
                &format!("{}/api/eval/{}", UPSTREAM_BASE, GROWTHBOOK_CLIENT_KEY),
                &token,
                &payload,
                &session_ua(&store, account_id).await,
            )
            .await;

            let _ = store.increment_telemetry_count(account_id, 1).await;
            continue;
        }

        // --- metrics (/api/claude_code/metrics) ---
        // 真实 CC (bigqueryExporter.ts) 对 OAuth 用户也会发，只要 token 有 user:profile scope。
        // 修复前的 "OAuth 不支持" 注释是错的 — 完全静默会被识别为代理。
        // 但当前 build_metrics 还没实现真实 metric，固定发 metrics=[] 会被 Anthropic 400
        // ("At least one metric must be provided")，反复 400 会让 device_id 被标记 →
        // 后续 /v1/messages 被连带 429。空数组时直接跳过本轮发送。
        if now.duration_since(session.last_metrics_at) >= METRICS_INTERVAL {
            let payload = build_metrics(&session.account);
            let has_metrics = payload
                .get("metrics")
                .and_then(|m| m.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if !has_metrics {
                session.last_metrics_at = now;
                drop(map);
                continue;
            }
            let token = session.token.clone();
            let c = client.clone();
            session.last_metrics_at = now;
            session.send_count += 1;
            drop(map);

            send_telemetry(
                &c,
                &format!("{}/api/claude_code/metrics", UPSTREAM_BASE),
                &token,
                &payload,
                &session_ua(&store, account_id).await,
            )
            .await;

            let _ = store.increment_telemetry_count(account_id, 1).await;
            continue;
        }

        drop(map);
    }
}

/// 从 account store 获取最新的 UA 版本号。
async fn session_ua(store: &Arc<AccountStore>, account_id: i64) -> String {
    let version = store
        .get_by_id(account_id)
        .await
        .ok()
        .and_then(|a| serde_json::from_value::<CanonicalEnvData>(a.canonical_env).ok())
        .map(|e| e.version)
        .unwrap_or_else(|| "2.1.81".into());
    format!("claude-code/{}", version)
}

// ---------------------------------------------------------------------------
// HTTP 发送
// ---------------------------------------------------------------------------

async fn send_telemetry(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    body: &serde_json::Value,
    user_agent: &str,
) {
    let result = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", user_agent)
        .header("x-service-name", "claude-code")
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("Authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                debug!("telemetry: {} → {}", url, status);
            } else {
                let text = resp.text().await.unwrap_or_default();
                warn!("telemetry: {} → {} {}", url, status, text);
            }
        }
        Err(e) => {
            warn!("telemetry: {} failed: {}", url, e);
        }
    }
}

// ---------------------------------------------------------------------------
// 请求体构造
// ---------------------------------------------------------------------------

fn parse_env(account: &Account) -> CanonicalEnvData {
    serde_json::from_value(account.canonical_env.clone()).unwrap_or_default()
}

fn parse_process(account: &Account) -> CanonicalProcessData {
    serde_json::from_value(account.canonical_process.clone()).unwrap_or_default()
}

fn build_process_json(
    proc: &CanonicalProcessData,
    uptime_secs: f64,
    mem_rss: i64,
    mem_heap_total: i64,
    mem_heap_used: i64,
    mem_external: i64,
    mem_array_buffers: i64,
    cpu_user_total: i64,
    cpu_system_total: i64,
    cpu_percent: f64,
) -> serde_json::Value {
    json!({
        "uptime": uptime_secs,
        // 模拟 process.memoryUsage()：从会话级基线漂移而来（±3%/次），而非每次整区间重摇
        "rss": mem_rss,
        "heapTotal": mem_heap_total,
        "heapUsed": mem_heap_used,
        "external": mem_external,
        "arrayBuffers": mem_array_buffers,
        "constrainedMemory": proc.constrained_memory,
        // 真实 Node.js process.cpuUsage() 返回自进程启动累积微秒，严格单调递增
        "cpuUsage": { "user": cpu_user_total, "system": cpu_system_total },
        "cpuPercent": cpu_percent,
    })
}

fn derive_account_uuid(account: &Account) -> String {
    account.account_uuid.clone().unwrap_or_else(|| {
        use sha2::{Digest, Sha256};
        let seed = if account.email.is_empty() {
            format!("account-{}", account.id)
        } else {
            account.email.clone()
        };
        let hash = Sha256::digest(seed.as_bytes());
        format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&hash[0..4]),
            hex::encode(&hash[4..6]),
            hex::encode(&hash[6..8]),
            hex::encode(&hash[8..10]),
            hex::encode(&hash[10..16])
        )
    })
}

/// JS Date.toISOString() 兼容格式：毫秒精度 + Z 后缀。
fn js_iso_timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn build_full_env(env: &CanonicalEnvData) -> serde_json::Value {
    crate::model::identity::build_full_env_json(env)
}

/// 从 env.build_time 计算 buildAgeMinutes（对应源码 logging.ts:165）。
fn compute_build_age_minutes(build_time: &str) -> Option<i64> {
    if build_time.is_empty() {
        return None;
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(build_time).ok()?;
    let delta = Utc::now().signed_duration_since(parsed.with_timezone(&Utc));
    Some(delta.num_minutes().max(0))
}

/// build_event_batch 的上下文，避免长参数列表。
struct EventBatchCtx<'a> {
    account: &'a Account,
    uptime_secs: f64,
    model: &'a str,
    cpu_user_total: i64,
    cpu_system_total: i64,
    cpu_percent: f64,
    /// 进程级 telemetry session_id — 整个 TelemetrySession 生命周期共享一个。
    session_id: &'a str,
    mem_rss: i64,
    mem_heap_total: i64,
    mem_heap_used: i64,
    mem_external: i64,
    mem_array_buffers: i64,
    /// 本次是否需要补发 tengu_startup（每个 telemetry session 只发一次）。
    emit_startup: bool,
}

/// 构造 /api/event_logging/batch 请求体。
///
/// 真实 CC 的 `/batch` 端点每次 POST 承载多条事件，且事件类型是混合的
/// （tengu_api_query + tengu_api_success 成对出现；首启时带 tengu_startup；偶发 tool_use_*）。
/// 这里按最少可信集合构造：
///   - 首个 batch 额外带 `tengu_startup`
///   - 每个 batch 都带 `tengu_api_query` + `tengu_api_success` 成对
///   - 偶发带 `tengu_tool_use_success`
fn build_event_batch(ctx: EventBatchCtx<'_>) -> serde_json::Value {
    let env = parse_env(ctx.account);
    let proc = parse_process(ctx.account);
    let account_uuid = derive_account_uuid(ctx.account);

    let process_b64 = {
        let p = build_process_json(
            &proc,
            ctx.uptime_secs,
            ctx.mem_rss,
            ctx.mem_heap_total,
            ctx.mem_heap_used,
            ctx.mem_external,
            ctx.mem_array_buffers,
            ctx.cpu_user_total,
            ctx.cpu_system_total,
            ctx.cpu_percent,
        );
        let bytes = serde_json::to_vec(&p).unwrap_or_default();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    };

    let env_obj = build_full_env(&env);

    let mut auth = json!({});
    auth["account_uuid"] = json!(account_uuid);
    if let Some(ref org) = ctx.account.organization_uuid {
        auth["organization_uuid"] = json!(org);
    }

    // betas: 使用 rewriter 对同一模型计算出的真实 beta 列表
    let betas = crate::service::rewriter::compute_betas_for_model(ctx.model).join(",");
    let build_age_mins = compute_build_age_minutes(&env.build_time);

    // tengu_api_success 的典型载荷 — 合理随机
    let mut rng = rand::thread_rng();
    let input_tokens: i64 = rng.gen_range(500i64..8000);
    let output_tokens: i64 = rng.gen_range(100i64..2000);
    let cached_input: i64 = rng.gen_range(0i64..input_tokens);
    let uncached_input: i64 = (input_tokens - cached_input).max(0);
    let duration_ms: i64 = rng.gen_range(800i64..6000);
    let ttft_ms: i64 = rng.gen_range(200i64..1500);
    let message_count: i64 = rng.gen_range(1i64..20);
    let message_tokens: i64 = input_tokens + output_tokens;
    let cost_usd: f64 = (input_tokens as f64 * 0.000003) + (output_tokens as f64 * 0.000015);
    let request_id = format!(
        "req_{}",
        uuid::Uuid::new_v4().simple().to_string()[..24].to_string()
    );
    let emit_tool_use = rng.gen_bool(0.4); // 40% 概率夹带 tool_use_success
    drop(rng);

    // 统一的事件框架字段：任何 event_data 都带
    let make_base = |event_name: &'static str, process_b64: &str| -> serde_json::Value {
        let mut ev = json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "event_name": event_name,
            "client_timestamp": js_iso_timestamp(),
            "device_id": ctx.account.device_id,
            "email": ctx.account.email,
            "session_id": ctx.session_id,
            "user_type": "external",
            "is_interactive": true,
            "client_type": "cli",
            "entrypoint": "cli",
            "agent_sdk_version": "",
            "swe_bench_run_id": "",
            "swe_bench_instance_id": "",
            "swe_bench_task_id": "",
            "agent_id": "",
            "parent_session_id": "",
            "agent_type": "",
            "team_name": "",
            "skill_name": "",
            "plugin_name": "",
            "marketplace_name": "",
            "additional_metadata": "",
            "auth": auth.clone(),
            "env": env_obj.clone(),
            "process": process_b64,
        });
        if let (Some(map), Some(mins)) = (ev.as_object_mut(), build_age_mins) {
            map.insert("buildAgeMins".into(), json!(mins));
        }
        ev
    };

    let wrap = |event_data: serde_json::Value| -> serde_json::Value {
        json!({
            "event_type": "ClaudeCodeInternalEvent",
            "event_data": event_data,
        })
    };

    let mut events: Vec<serde_json::Value> = Vec::new();

    // --- tengu_startup（会话首个 batch）---
    if ctx.emit_startup {
        let mut ev = make_base("tengu_startup", &process_b64);
        if let Some(m) = ev.as_object_mut() {
            m.insert("model".into(), json!(ctx.model));
            m.insert("provider".into(), json!("firstParty"));
            m.insert("isFirstSession".into(), json!(true));
            m.insert("querySource".into(), json!("user"));
        }
        events.push(wrap(ev));
    }

    // --- tengu_api_query ---（对应源码 logging.ts:196）
    {
        let mut ev = make_base("tengu_api_query", &process_b64);
        if let Some(m) = ev.as_object_mut() {
            m.insert("model".into(), json!(ctx.model));
            m.insert("messagesLength".into(), json!(message_count));
            m.insert("temperature".into(), json!(1.0));
            m.insert("provider".into(), json!("firstParty"));
            m.insert("betas".into(), json!(betas));
            m.insert("permissionMode".into(), json!("default"));
            m.insert("querySource".into(), json!("user"));
            m.insert("thinkingType".into(), json!("disabled"));
            m.insert("fastMode".into(), json!(false));
        }
        events.push(wrap(ev));
    }

    // --- tengu_api_success ---（对应源码 logging.ts:463-520）
    {
        let mut ev = make_base("tengu_api_success", &process_b64);
        if let Some(m) = ev.as_object_mut() {
            m.insert("model".into(), json!(ctx.model));
            m.insert("betas".into(), json!(betas));
            m.insert("messageCount".into(), json!(message_count));
            m.insert("messageTokens".into(), json!(message_tokens));
            m.insert("inputTokens".into(), json!(input_tokens));
            m.insert("outputTokens".into(), json!(output_tokens));
            m.insert("cachedInputTokens".into(), json!(cached_input));
            m.insert("uncachedInputTokens".into(), json!(uncached_input));
            m.insert("durationMs".into(), json!(duration_ms));
            m.insert("durationMsIncludingRetries".into(), json!(duration_ms));
            m.insert("attempt".into(), json!(1));
            m.insert("ttftMs".into(), json!(ttft_ms));
            m.insert("requestId".into(), json!(request_id));
            m.insert("stop_reason".into(), json!("end_turn"));
            m.insert("costUSD".into(), json!(cost_usd));
            m.insert("didFallBackToNonStreaming".into(), json!(false));
            m.insert("isNonInteractiveSession".into(), json!(false));
            m.insert("print".into(), json!(false));
            m.insert("isTTY".into(), json!(true));
            m.insert("querySource".into(), json!("user"));
            m.insert("provider".into(), json!("firstParty"));
        }
        events.push(wrap(ev));
    }

    // --- 偶发 tengu_tool_use_success ---
    if emit_tool_use {
        let mut ev = make_base("tengu_tool_use_success", &process_b64);
        if let Some(m) = ev.as_object_mut() {
            let tool_names = ["Read", "Bash", "Edit", "Grep", "Glob"];
            let tool_idx = (ctx.cpu_user_total as usize) % tool_names.len();
            m.insert("toolName".into(), json!(tool_names[tool_idx]));
            m.insert("durationMs".into(), json!(rand::thread_rng().gen_range(5i64..800)));
            m.insert("isMcp".into(), json!(false));
        }
        events.push(wrap(ev));
    }

    json!({ "events": events })
}

/// 构造 /api/eval/{clientKey} 请求体（GrowthBook remote eval）。
fn build_growthbook_eval(account: &Account) -> serde_json::Value {
    let env = parse_env(account);
    let account_uuid = derive_account_uuid(account);

    let session_id = uuid::Uuid::new_v4().to_string();
    let mut attrs = json!({
        "id": account.device_id,
        "sessionId": session_id,
        "deviceID": account.device_id,
        "platform": env.platform,
        "appVersion": env.version,
        "email": account.email,
        "accountUUID": account_uuid,
    });

    if let Some(ref org) = account.organization_uuid {
        attrs["organizationUUID"] = json!(org);
    }
    if let Some(ref sub) = account.subscription_type {
        attrs["subscriptionType"] = json!(sub);
    }

    json!({
        "attributes": attrs,
        "forcedFeatures": {},
    })
}

/// 构造 /api/claude_code/metrics 请求体。
fn build_metrics(account: &Account) -> serde_json::Value {
    let env = parse_env(account);
    let os_type = match env.platform.as_str() {
        "darwin" => "Darwin",
        "win32" => "Windows",
        _ => "Linux",
    };

    let mut resource = json!({
        "service.name": "claude-code",
        "service.version": env.version,
        "os.type": os_type,
        "host.arch": env.arch,
        "aggregation.temporality": "delta",
        "user.customer_type": "claude_ai",
    });

    if let Some(ref sub) = account.subscription_type {
        resource["user.subscription_type"] = json!(sub);
    }

    json!({
        "resource_attributes": resource,
        "metrics": [],
    })
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::account::{
        AccountAuthType, AccountStatus, BillingMode, CanonicalEnvData, CanonicalProcessData,
    };
    use chrono::Duration as ChronoDuration;

    fn make_env() -> CanonicalEnvData {
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "arm64".into(),
            node_version: "v22.15.0".into(),
            terminal: "iTerm.app".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        }
    }

    fn make_proc() -> CanonicalProcessData {
        CanonicalProcessData {
            constrained_memory: 0,
            rss_range: [300_000_000, 500_000_000],
            heap_total_range: [100_000_000, 200_000_000],
            heap_used_range: [40_000_000, 80_000_000],
            external_range: [1_000_000, 3_000_000],
            array_buffers_range: [10_000, 50_000],
        }
    }

    fn make_account() -> Account {
        Account {
            id: 1,
            name: "t".into(),
            email: "tester@example.com".into(),
            status: AccountStatus::Active,
            auth_type: AccountAuthType::Oauth,
            setup_token: String::new(),
            access_token: "acc".into(),
            refresh_token: "ref".into(),
            expires_at: Some(Utc::now() + ChronoDuration::hours(1)),
            oauth_refreshed_at: None,
            auth_error: String::new(),
            proxy_url: String::new(),
            device_id: "d".repeat(64),
            canonical_env: serde_json::to_value(make_env()).unwrap(),
            canonical_prompt: json!({}),
            canonical_process: serde_json::to_value(make_proc()).unwrap(),
            billing_mode: BillingMode::Strip,
            account_uuid: Some("11111111-2222-3333-4444-555555555555".into()),
            organization_uuid: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
            subscription_type: Some("max".into()),
            concurrency: 3,
            priority: 50,
            rate_limited_at: None,
            rate_limit_reset_at: None,
            disable_reason: String::new(),
            auto_telemetry: true,
            telemetry_count: 0,
            usage_data: json!({}),
            usage_fetched_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// 构造一个标准 EventBatchCtx 用于测试。
    fn ctx_for<'a>(
        account: &'a Account,
        model: &'a str,
        session_id: &'a str,
        cpu_user: i64,
        cpu_system: i64,
        emit_startup: bool,
    ) -> EventBatchCtx<'a> {
        EventBatchCtx {
            account,
            uptime_secs: 42.0,
            model,
            cpu_user_total: cpu_user,
            cpu_system_total: cpu_system,
            cpu_percent: 0.3,
            session_id,
            mem_rss: 400_000_000,
            mem_heap_total: 150_000_000,
            mem_heap_used: 60_000_000,
            mem_external: 2_000_000,
            mem_array_buffers: 30_000,
            emit_startup,
        }
    }

    /// 取出 batch 里的 tengu_api_success event_data（不依赖数组下标，避免与 startup/query/tool_use 冲突）。
    fn event_data<'a>(
        batch: &'a serde_json::Value,
    ) -> &'a serde_json::Map<String, serde_json::Value> {
        batch["events"]
            .as_array()
            .expect("events array")
            .iter()
            .find(|e| {
                e["event_data"]["event_name"].as_str() == Some("tengu_api_success")
            })
            .expect("tengu_api_success event missing")["event_data"]
            .as_object()
            .unwrap()
    }

    /// 按名字找 event_data — 用于验证 startup/query/tool_use。
    fn find_event<'a>(
        batch: &'a serde_json::Value,
        name: &str,
    ) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
        batch["events"]
            .as_array()?
            .iter()
            .find(|e| e["event_data"]["event_name"].as_str() == Some(name))
            .and_then(|e| e["event_data"].as_object())
    }

    // ---- Task #2: Telemetry uses the tracked model + matching betas ----

    #[test]
    fn event_batch_uses_tracked_model_id() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-opus-4-6", "sid", 0, 0, false));
        let data = event_data(&batch);
        assert_eq!(
            data["model"].as_str(),
            Some("claude-opus-4-6"),
            "model field must reflect the tracked last_model, not a hard-coded default"
        );
    }

    #[test]
    fn event_batch_betas_match_rewriter_for_given_model() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, false));
        let betas = event_data(&batch)["betas"].as_str().unwrap().to_string();
        let expected = crate::service::rewriter::compute_betas_for_model("claude-sonnet-4-5")
            .join(",");
        assert_eq!(betas, expected);
        assert!(
            betas.contains("claude-code-20250219"),
            "sonnet must receive claude-code beta"
        );
    }

    #[test]
    fn event_batch_legacy_haiku_betas_omit_isp_and_context() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(
            &account,
            "claude-3-5-haiku-20241022",
            "sid",
            0,
            0,
            false,
        ));
        let betas = event_data(&batch)["betas"].as_str().unwrap();
        assert!(
            !betas.contains("context-management-2025-06-27"),
            "legacy haiku must not advertise context-management beta, got: {}",
            betas
        );
        assert!(
            !betas.contains("claude-code-20250219"),
            "legacy haiku must not advertise claude-code beta, got: {}",
            betas
        );
        assert!(
            !betas.contains("interleaved-thinking-2025-05-14"),
            "legacy haiku must not advertise interleaved-thinking beta, got: {}",
            betas
        );
        assert!(
            betas.contains("oauth-2025-04-20"),
            "legacy haiku still needs oauth beta, got: {}",
            betas
        );
    }

    #[test]
    fn event_batch_haiku_4_5_keeps_isp_and_context_but_strips_claude_code() {
        let account = make_account();
        let batch =
            build_event_batch(ctx_for(&account, "claude-haiku-4-5", "sid", 0, 0, false));
        let betas = event_data(&batch)["betas"].as_str().unwrap();
        assert!(
            !betas.contains("claude-code-20250219"),
            "haiku-4-5 must not advertise claude-code beta, got: {}",
            betas
        );
        assert!(
            betas.contains("prompt-caching-scope"),
            "haiku-4-5 must keep prompt-caching-scope beta, got: {}",
            betas
        );
        assert!(
            betas.contains("context-management-2025-06-27"),
            "haiku-4-5 must keep context-management beta, got: {}",
            betas
        );
    }

    // ---- Task #4: CPU cumulative monotonicity ----

    #[test]
    fn process_json_cpu_usage_is_cumulative() {
        let proc = make_proc();
        let p1 = build_process_json(&proc, 1.0, 400_000_000, 150_000_000, 60_000_000, 2_000_000, 30_000, 1_000_000, 500_000, 0.5);
        let p2 = build_process_json(&proc, 2.0, 400_000_000, 150_000_000, 60_000_000, 2_000_000, 30_000, 2_500_000, 900_000, 0.7);

        let u1 = p1["cpuUsage"]["user"].as_i64().unwrap();
        let u2 = p2["cpuUsage"]["user"].as_i64().unwrap();
        let s1 = p1["cpuUsage"]["system"].as_i64().unwrap();
        let s2 = p2["cpuUsage"]["system"].as_i64().unwrap();

        assert_eq!(u1, 1_000_000);
        assert_eq!(u2, 2_500_000);
        assert_eq!(s1, 500_000);
        assert_eq!(s2, 900_000);
        assert!(
            u2 > u1 && s2 > s1,
            "process.cpuUsage is monotonic across samples (real Node.js behaviour)"
        );
        assert_eq!(p2["cpuPercent"].as_f64().unwrap(), 0.7);
    }

    #[test]
    fn process_json_uptime_is_passed_through() {
        let proc = make_proc();
        let p = build_process_json(&proc, 42.5, 400_000_000, 150_000_000, 60_000_000, 2_000_000, 30_000, 0, 0, 0.0);
        assert_eq!(p["uptime"].as_f64().unwrap(), 42.5);
        assert_eq!(p["constrainedMemory"].as_i64().unwrap(), 0);
    }

    #[test]
    fn process_json_memory_is_passthrough_not_random() {
        // 关键测试：rss/heapTotal/heapUsed 必须原样透传，而不是 random_in_range。
        // 修复前：同一个函数调用两次会得到不同随机值；修复后：完全确定性。
        let proc = make_proc();
        let p1 = build_process_json(&proc, 1.0, 400_123_456, 150_000_000, 60_000_000, 2_000_000, 30_000, 0, 0, 0.0);
        let p2 = build_process_json(&proc, 1.0, 400_123_456, 150_000_000, 60_000_000, 2_000_000, 30_000, 0, 0, 0.0);
        assert_eq!(p1["rss"].as_i64(), Some(400_123_456));
        assert_eq!(p1["rss"], p2["rss"], "same input → same output (not random)");
        assert_eq!(p1["heapUsed"].as_i64(), Some(60_000_000));
    }

    // ---- Task #5: Telemetry schema completeness (tengu_api_success) ----

    #[test]
    fn event_batch_contains_all_tengu_api_success_fields() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 1_000, 500, false));
        let data = event_data(&batch);

        let required = [
            "event_id",
            "event_name",
            "client_timestamp",
            "device_id",
            "session_id",
            "model",
            "betas",
            "messageCount",
            "messageTokens",
            "inputTokens",
            "outputTokens",
            "cachedInputTokens",
            "uncachedInputTokens",
            "durationMs",
            "durationMsIncludingRetries",
            "attempt",
            "ttftMs",
            "requestId",
            "stop_reason",
            "costUSD",
            "didFallBackToNonStreaming",
            "isNonInteractiveSession",
            "print",
            "isTTY",
            "querySource",
            "provider",
            "auth",
            "env",
            "process",
        ];
        for f in required {
            assert!(
                data.contains_key(f),
                "event_data missing required field `{}`",
                f
            );
        }
        assert_eq!(data["event_name"].as_str(), Some("tengu_api_success"));
        assert_eq!(data["provider"].as_str(), Some("firstParty"));
        assert_eq!(data["attempt"].as_i64(), Some(1));
    }

    #[test]
    fn event_batch_auth_carries_account_and_org_uuid() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, false));
        let auth = &event_data(&batch)["auth"];
        assert_eq!(
            auth["account_uuid"].as_str(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(
            auth["organization_uuid"].as_str(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn event_batch_request_id_is_prefixed() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, false));
        let rid = event_data(&batch)["requestId"].as_str().unwrap();
        assert!(rid.starts_with("req_"), "requestId must have `req_` prefix");
        assert!(rid.len() >= 20, "requestId too short: {}", rid);
    }

    // ---- R1: telemetry session_id 稳定性 ----

    #[test]
    fn event_batch_session_id_is_passed_through() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "fixed-sid-123", 0, 0, false));
        let data = event_data(&batch);
        assert_eq!(
            data["session_id"].as_str(),
            Some("fixed-sid-123"),
            "session_id must be driven by ctx, not regenerated inside build_event_batch"
        );
    }

    #[test]
    fn event_batch_session_id_is_same_across_all_events_in_batch() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid-same", 0, 0, true));
        let events = batch["events"].as_array().unwrap();
        assert!(events.len() >= 2, "batch should have multiple events when emit_startup=true");
        for ev in events {
            assert_eq!(
                ev["event_data"]["session_id"].as_str(),
                Some("sid-same"),
                "every event in the same batch must share the session_id"
            );
        }
    }

    // ---- R4: 多事件批次 ----

    #[test]
    fn event_batch_contains_query_and_success_pair() {
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, false));
        assert!(
            find_event(&batch, "tengu_api_query").is_some(),
            "batch must include tengu_api_query (real CC always logs both before and after a call)"
        );
        assert!(
            find_event(&batch, "tengu_api_success").is_some(),
            "batch must include tengu_api_success"
        );
    }

    #[test]
    fn event_batch_emit_startup_adds_tengu_startup_once() {
        let account = make_account();
        let batch_first = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, true));
        assert!(
            find_event(&batch_first, "tengu_startup").is_some(),
            "first batch (emit_startup=true) must include tengu_startup"
        );

        let batch_second = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid", 0, 0, false));
        assert!(
            find_event(&batch_second, "tengu_startup").is_none(),
            "subsequent batches (emit_startup=false) must NOT include tengu_startup"
        );
    }

    #[test]
    fn event_batch_events_have_consistent_identity() {
        // 同一 batch 里所有事件共享 device_id / email / auth，模拟单进程客户端
        let account = make_account();
        let batch = build_event_batch(ctx_for(&account, "claude-sonnet-4-5", "sid-x", 0, 0, true));
        let events = batch["events"].as_array().unwrap();
        let first_device = events[0]["event_data"]["device_id"].as_str().unwrap();
        let first_email = events[0]["event_data"]["email"].as_str().unwrap();
        for ev in events {
            assert_eq!(ev["event_data"]["device_id"].as_str(), Some(first_device));
            assert_eq!(ev["event_data"]["email"].as_str(), Some(first_email));
        }
    }

    // ---- Task #6: buildAgeMinutes helper ----

    #[test]
    fn compute_build_age_minutes_handles_valid_rfc3339() {
        let past = (Utc::now() - ChronoDuration::minutes(60)).to_rfc3339();
        let age = compute_build_age_minutes(&past).unwrap();
        assert!(
            (58..=62).contains(&age),
            "expected ~60 min, got {} min",
            age
        );
    }

    #[test]
    fn compute_build_age_minutes_returns_none_for_empty_or_invalid() {
        assert!(compute_build_age_minutes("").is_none());
        assert!(compute_build_age_minutes("not-a-date").is_none());
    }

    #[test]
    fn compute_build_age_minutes_is_nonnegative_for_future_build() {
        let future = (Utc::now() + ChronoDuration::minutes(10)).to_rfc3339();
        let age = compute_build_age_minutes(&future).unwrap();
        assert!(age >= 0);
    }

    // ---- Telemetry path classification ----

    #[test]
    fn is_telemetry_path_matches_known_endpoints() {
        assert!(is_telemetry_path("/api/event_logging/batch"));
        assert!(is_telemetry_path("/api/eval/sdk-zAZezfDKGoZuXXKe"));
        assert!(is_telemetry_path("/api/claude_code/metrics"));
        assert!(is_telemetry_path(
            "/api/claude_code/organizations/metrics_enabled"
        ));
        assert!(!is_telemetry_path("/v1/messages"));
        assert!(!is_telemetry_path("/api/oauth/usage"));
    }

    // ---- R5: metrics payload 结构（对齐 bigqueryExporter.ts）----

    #[test]
    fn metrics_payload_has_resource_attributes_and_metrics_array() {
        let account = make_account();
        let payload = build_metrics(&account);
        assert!(payload["resource_attributes"].is_object());
        assert!(payload["metrics"].is_array());
        let attrs = &payload["resource_attributes"];
        assert_eq!(attrs["service.name"], "claude-code");
        assert_eq!(attrs["aggregation.temporality"], "delta");
        // OAuth claudeAISubscriber 应带 user.customer_type = claude_ai
        assert_eq!(attrs["user.customer_type"], "claude_ai");
        // 订阅类型透传
        assert_eq!(attrs["user.subscription_type"], "max");
    }
}
