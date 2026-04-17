use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, TimeZone, Utc};
use rust_embed::Embed;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::config::{Config, WarmupConfig};
use crate::error::AppError;
use crate::middleware::auth::{admin_auth, extract_key};
use crate::model::account::{Account, AccountAuthType, AccountStatus};
use crate::model::api_token::{self, ApiToken};
use crate::service::account::AccountService;
use crate::service::gateway::GatewayService;
use crate::service::oauth::TokenTester;
use crate::service::oauth_flow::OAuthFlowService;
use crate::service::telemetry::TelemetryService;
use crate::store::settings_store::SettingsStore;
use crate::store::token_store::TokenStore;

#[derive(Clone)]
pub struct AppState {
    pub gateway_svc: Arc<GatewayService>,
    pub account_svc: Arc<AccountService>,
    pub token_tester: Arc<TokenTester>,
    pub token_store: Arc<TokenStore>,
    pub oauth_flow_svc: Arc<OAuthFlowService>,
    pub telemetry_svc: Arc<TelemetryService>,
    pub settings_store: Arc<SettingsStore>,
    pub warmup_defaults: WarmupConfig,
    pub admin_password: String,
}

pub fn build_router(
    cfg: &Config,
    gateway_svc: Arc<GatewayService>,
    account_svc: Arc<AccountService>,
    token_tester: Arc<TokenTester>,
    token_store: Arc<TokenStore>,
    oauth_flow_svc: Arc<OAuthFlowService>,
    telemetry_svc: Arc<TelemetryService>,
    settings_store: Arc<SettingsStore>,
) -> Router {
    let state = AppState {
        gateway_svc,
        account_svc,
        token_tester,
        token_store,
        oauth_flow_svc,
        telemetry_svc,
        settings_store,
        warmup_defaults: cfg.warmup.clone(),
        admin_password: cfg.admin.password.clone(),
    };

    let admin_password = state.admin_password.clone();

    // 前端页面（显式注册 SPA 路由）
    let frontend_routes = Router::new()
        .route("/", get(spa_handler))
        .route("/login", get(spa_handler))
        .route("/tokens", get(spa_handler));

    // 前端静态资源
    let asset_routes = Router::new()
        .route("/assets/*rest", get(asset_handler))
        .route("/favicon.svg", get(asset_handler));

    // 管理 API（密码认证，完整路径注册）
    let admin_routes = Router::new()
        .route("/admin/accounts", get(list_accounts).post(create_account))
        .route(
            "/admin/accounts/:id",
            put(update_account).delete(delete_account),
        )
        .route("/admin/accounts/:id/test", post(test_account))
        .route("/admin/accounts/:id/usage", post(refresh_usage))
        .route("/admin/tokens", get(list_tokens).post(create_token))
        .route(
            "/admin/tokens/:id",
            put(update_token).delete(delete_token_handler),
        )
        .route("/admin/dashboard", get(get_dashboard))
        .route("/admin/settings", get(get_settings).put(update_settings))
        .route(
            "/admin/oauth/generate-auth-url",
            post(oauth_generate_auth_url),
        )
        .route(
            "/admin/oauth/generate-setup-token-url",
            post(oauth_generate_setup_token_url),
        )
        .route("/admin/oauth/exchange-code", post(oauth_exchange_code))
        .route(
            "/admin/oauth/exchange-setup-token-code",
            post(oauth_exchange_setup_token_code),
        )
        .layer(middleware::from_fn(move |req, next: Next| {
            let pwd = admin_password.clone();
            admin_auth(pwd, req, next)
        }))
        .with_state(state.clone());

    // 组合路由：前端 + 管理 API + 其余全部透传网关
    Router::new()
        .merge(frontend_routes)
        .merge(asset_routes)
        .merge(admin_routes)
        .fallback(gateway_fallback)
        .with_state(state)
}

// --- Handlers ---

/// 网关透传 fallback：鉴权 + 代理上游
async fn gateway_fallback(State(state): State<AppState>, req: Request) -> Response {
    let key = extract_key(&req);
    if key.is_empty() {
        return err_json(StatusCode::UNAUTHORIZED, "missing api key");
    }
    let api_token = match state.token_store.get_by_token(&key).await {
        Ok(Some(t)) => t,
        Ok(None) => return err_json(StatusCode::UNAUTHORIZED, "invalid api key"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "authentication failed"),
    };
    state
        .gateway_svc
        .handle_request(req, Some(&api_token))
        .await
}

/// 统一 JSON 错误响应
fn err_json(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

// --- Account Handlers ---

#[derive(Deserialize)]
struct PageQuery {
    page: Option<i64>,
    page_size: Option<i64>,
}

async fn list_accounts(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(12).clamp(1, 100);
    let (accounts, total) = state
        .account_svc
        .list_accounts_paged(page, page_size)
        .await?;
    let total_pages = (total + page_size - 1) / page_size;

    // 为每个账号附加遥测会话过期时间
    let mut data: Vec<serde_json::Value> = Vec::with_capacity(accounts.len());
    for a in &accounts {
        let mut obj = serde_json::to_value(a).unwrap_or_default();
        if let Some(expires) = state.telemetry_svc.get_session_expires_at(a.id).await {
            obj["telemetry_expires_at"] = serde_json::json!(expires.to_rfc3339());
        }
        data.push(obj);
    }

    Ok(Json(serde_json::json!({
        "data": data,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    })))
}

#[derive(Deserialize)]
struct CreateAccountRequest {
    name: Option<String>,
    email: String,
    token: Option<String>,
    setup_token: Option<String>,
    auth_type: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<ClientDateTime>,
    proxy_url: Option<String>,
    billing_mode: Option<String>,
    account_uuid: Option<String>,
    organization_uuid: Option<String>,
    subscription_type: Option<String>,
    concurrency: Option<i32>,
    priority: Option<i32>,
    auto_telemetry: Option<bool>,
    warmup_enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientDateTime {
    Millis(i64),
    Text(String),
}

async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<Account>), AppError> {
    if req.email.is_empty() {
        return Err(AppError::BadRequest("email is required".into()));
    }
    let auth_type = req.auth_type.unwrap_or_else(|| "setup_token".into()).into();
    let setup_token = req.setup_token.or(req.token).unwrap_or_default();
    let mut account = Account {
        id: 0,
        name: req.name.unwrap_or_default(),
        email: req.email,
        status: AccountStatus::Active,
        auth_type,
        setup_token,
        access_token: req.access_token.unwrap_or_default(),
        refresh_token: req.refresh_token.unwrap_or_default(),
        expires_at: req.expires_at.as_ref().and_then(client_datetime_to_utc),
        oauth_refreshed_at: None,
        auth_error: String::new(),
        proxy_url: req.proxy_url.unwrap_or_default(),
        device_id: String::new(),
        canonical_env: serde_json::json!({}),
        canonical_prompt: serde_json::json!({}),
        canonical_process: serde_json::json!({}),
        billing_mode: req.billing_mode.unwrap_or_else(|| "strip".into()).into(),
        account_uuid: req.account_uuid,
        organization_uuid: req.organization_uuid,
        subscription_type: req.subscription_type,
        concurrency: req.concurrency.unwrap_or(3),
        priority: req.priority.unwrap_or(50),
        rate_limited_at: None,
        rate_limit_reset_at: None,
        disable_reason: String::new(),
        auto_telemetry: req.auto_telemetry.unwrap_or(false),
        telemetry_count: 0,
        warmup_enabled: req.warmup_enabled.unwrap_or(false),
        next_warmup_at: None,
        last_warmup_at: None,
        last_warmup_status: String::new(),
        last_warmup_message: String::new(),
        warmup_retry_count: 0,
        usage_data: serde_json::json!({}),
        usage_fetched_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    state.account_svc.create_account(&mut account).await?;
    Ok((StatusCode::CREATED, Json(account)))
}

async fn get_settings(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let quarantine_on_429 = state.gateway_svc.quarantine_on_429.load(Ordering::Relaxed);
    let warmup_settings = load_warmup_settings(&state).await;
    Ok(Json(
        serde_json::json!({
            "quarantine_on_429": quarantine_on_429,
            "warmup_enabled": warmup_settings.enabled,
            "warmup_base_utc_hour": warmup_settings.base_utc_hour,
            "warmup_jitter_minutes": warmup_settings.jitter_minutes,
            "warmup_max_retries": warmup_settings.max_retries,
            "warmup_retry_backoff_secs": warmup_settings.retry_backoff_secs,
            "warmup_account_gap_secs": warmup_settings.account_gap_secs,
            "warmup_poll_interval_secs": warmup_settings.poll_interval_secs,
        }),
    ))
}

#[derive(Deserialize)]
struct UpdateSettingsRequest {
    quarantine_on_429: Option<bool>,
    warmup_enabled: Option<bool>,
    warmup_base_utc_hour: Option<u32>,
    warmup_jitter_minutes: Option<i64>,
    warmup_max_retries: Option<u32>,
    warmup_retry_backoff_secs: Option<u64>,
    warmup_account_gap_secs: Option<u64>,
    warmup_poll_interval_secs: Option<u64>,
}

async fn update_settings(
    State(state): State<AppState>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(val) = req.quarantine_on_429 {
        state
            .gateway_svc
            .quarantine_on_429
            .store(val, Ordering::Relaxed);
        state
            .settings_store
            .set("quarantine_on_429", if val { "true" } else { "false" })
            .await?;
    }

    if let Some(val) = req.warmup_enabled {
        state
            .settings_store
            .set("warmup_enabled", if val { "true" } else { "false" })
            .await?;
    }
    if let Some(hour) = req.warmup_base_utc_hour {
        state
            .settings_store
            .set("warmup_base_utc_hour", &hour.min(23).to_string())
            .await?;
    }
    if let Some(minutes) = req.warmup_jitter_minutes {
        state
            .settings_store
            .set("warmup_jitter_minutes", &minutes.clamp(0, 720).to_string())
            .await?;
    }
    if let Some(retries) = req.warmup_max_retries {
        state
            .settings_store
            .set("warmup_max_retries", &retries.min(10).to_string())
            .await?;
    }
    if let Some(secs) = req.warmup_retry_backoff_secs {
        state
            .settings_store
            .set("warmup_retry_backoff_secs", &secs.max(30).to_string())
            .await?;
    }
    if let Some(secs) = req.warmup_account_gap_secs {
        state
            .settings_store
            .set("warmup_account_gap_secs", &secs.max(1).to_string())
            .await?;
    }
    if let Some(secs) = req.warmup_poll_interval_secs {
        state
            .settings_store
            .set("warmup_poll_interval_secs", &secs.max(15).to_string())
            .await?;
    }

    let quarantine_on_429 = state.gateway_svc.quarantine_on_429.load(Ordering::Relaxed);
    let warmup_settings = load_warmup_settings(&state).await;
    Ok(Json(
        serde_json::json!({
            "quarantine_on_429": quarantine_on_429,
            "warmup_enabled": warmup_settings.enabled,
            "warmup_base_utc_hour": warmup_settings.base_utc_hour,
            "warmup_jitter_minutes": warmup_settings.jitter_minutes,
            "warmup_max_retries": warmup_settings.max_retries,
            "warmup_retry_backoff_secs": warmup_settings.retry_backoff_secs,
            "warmup_account_gap_secs": warmup_settings.account_gap_secs,
            "warmup_poll_interval_secs": warmup_settings.poll_interval_secs,
        }),
    ))
}

async fn update_account(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(updates): Json<serde_json::Value>,
) -> Result<Json<Account>, AppError> {
    let mut existing = state.account_svc.get_account(id).await?;
    let mut clear_warmup_state = false;

    if let Some(name) = updates.get("name").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            existing.name = name.to_string();
        }
    }
    if let Some(email) = updates.get("email").and_then(|v| v.as_str()) {
        if !email.is_empty() {
            existing.email = email.to_string();
        }
    }
    if let Some(auth_type) = updates.get("auth_type").and_then(|v| v.as_str()) {
        existing.auth_type = auth_type.to_string().into();
        match existing.auth_type {
            AccountAuthType::SetupToken => {
                existing.access_token.clear();
                existing.refresh_token.clear();
                existing.expires_at = None;
                existing.oauth_refreshed_at = None;
                existing.auth_error.clear();
            }
            AccountAuthType::Oauth => {
                existing.setup_token.clear();
            }
        }
    }
    if let Some(token) = updates.get("token").and_then(|v| v.as_str()) {
        existing.setup_token = token.to_string();
    }
    if let Some(setup_token) = updates.get("setup_token").and_then(|v| v.as_str()) {
        existing.setup_token = setup_token.to_string();
    }
    if let Some(access_token) = updates.get("access_token").and_then(|v| v.as_str()) {
        existing.access_token = access_token.to_string();
    }
    if let Some(refresh_token) = updates.get("refresh_token").and_then(|v| v.as_str()) {
        existing.refresh_token = refresh_token.to_string();
    }
    if updates.get("expires_at").is_some() {
        existing.expires_at = updates
            .get("expires_at")
            .and_then(client_datetime_value_to_utc);
    }
    if let Some(proxy_url) = updates.get("proxy_url").and_then(|v| v.as_str()) {
        existing.proxy_url = proxy_url.to_string();
    }
    if let Some(concurrency) = updates.get("concurrency").and_then(|v| v.as_i64()) {
        if concurrency > 0 {
            existing.concurrency = concurrency as i32;
        }
    }
    if let Some(priority) = updates.get("priority").and_then(|v| v.as_i64()) {
        if priority > 0 {
            existing.priority = priority as i32;
        }
    }
    if let Some(status) = updates.get("status").and_then(|v| v.as_str()) {
        if !status.is_empty() {
            if status == "active" {
                state.account_svc.enable_account(id).await?;
                existing = state.account_svc.get_account(id).await?;
                return Ok(Json(existing));
            } else if status == "disabled" {
                state
                    .account_svc
                    .disable_account(id, AccountStatus::Disabled, "手动停用", None)
                    .await?;
                existing = state.account_svc.get_account(id).await?;
                return Ok(Json(existing));
            } else {
                existing.status = status.to_string().into();
            }
        }
    }
    if let Some(billing_mode) = updates.get("billing_mode").and_then(|v| v.as_str()) {
        if !billing_mode.is_empty() {
            existing.billing_mode = billing_mode.to_string().into();
        }
    }
    if updates.get("account_uuid").is_some() {
        existing.account_uuid = updates
            .get("account_uuid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    if updates.get("organization_uuid").is_some() {
        existing.organization_uuid = updates
            .get("organization_uuid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    if updates.get("subscription_type").is_some() {
        existing.subscription_type = updates
            .get("subscription_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    if let Some(auto_telemetry) = updates.get("auto_telemetry").and_then(|v| v.as_bool()) {
        existing.auto_telemetry = auto_telemetry;
    }
    if let Some(warmup_enabled) = updates.get("warmup_enabled").and_then(|v| v.as_bool()) {
        existing.warmup_enabled = warmup_enabled;
        if !warmup_enabled {
            existing.next_warmup_at = None;
            existing.warmup_retry_count = 0;
            clear_warmup_state = true;
        }
    }

    state.account_svc.update_account(&existing).await?;
    if clear_warmup_state {
        state
            .account_svc
            .clear_warmup_state(id)
            .await?;
    }
    Ok(Json(existing))
}

async fn delete_account(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.account_svc.delete_account(id).await?;
    Ok(Json(serde_json::json!({"status": "deleted"})))
}

async fn test_account(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let account = state.account_svc.get_account(id).await?;
    let token = match state.account_svc.resolve_upstream_token(id).await {
        Ok(token) => token,
        Err(e) => {
            return Ok(Json(
                serde_json::json!({"status": "error", "message": e.to_string()}),
            ));
        }
    };
    match state
        .token_tester
        .test_token(&token, &account.proxy_url, &account.canonical_env)
        .await
    {
        Ok(()) => Ok(Json(serde_json::json!({"status": "ok"}))),
        Err(e) => Ok(Json(
            serde_json::json!({"status": "error", "message": e.to_string()}),
        )),
    }
}

async fn refresh_usage(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    match state.account_svc.refresh_usage(id).await {
        Ok(usage) => Ok(Json(serde_json::json!({"status": "ok", "usage": usage}))),
        Err(e) => {
            let message = match &e {
                AppError::TooManyRequests(_) => "用量查询接口超限，请一分钟后再试".to_string(),
                _ => e.to_string(),
            };
            Ok(Json(
                serde_json::json!({"status": "error", "message": message}),
            ))
        }
    }
}

// --- Token Handlers ---

async fn list_tokens(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let total = state.token_store.count().await?;
    let tokens = state.token_store.list_paged(page, page_size).await?;
    let total_pages = (total + page_size - 1) / page_size;
    Ok(Json(serde_json::json!({
        "data": tokens,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    })))
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    name: Option<String>,
    allowed_accounts: Option<String>,
    blocked_accounts: Option<String>,
}

async fn create_token(
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<ApiToken>), AppError> {
    let mut token = ApiToken {
        id: 0,
        name: req.name.unwrap_or_default(),
        token: api_token::generate_token(),
        allowed_accounts: req.allowed_accounts.unwrap_or_default(),
        blocked_accounts: req.blocked_accounts.unwrap_or_default(),
        status: api_token::ApiTokenStatus::Active,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    state.token_store.create(&mut token).await?;
    Ok((StatusCode::CREATED, Json(token)))
}

async fn update_token(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(updates): Json<serde_json::Value>,
) -> Result<Json<ApiToken>, AppError> {
    let mut existing = state.token_store.get_by_id(id).await?;

    if let Some(name) = updates.get("name").and_then(|v| v.as_str()) {
        existing.name = name.to_string();
    }
    if let Some(allowed) = updates.get("allowed_accounts").and_then(|v| v.as_str()) {
        existing.allowed_accounts = allowed.to_string();
    }
    if let Some(blocked) = updates.get("blocked_accounts").and_then(|v| v.as_str()) {
        existing.blocked_accounts = blocked.to_string();
    }
    if let Some(status) = updates.get("status").and_then(|v| v.as_str()) {
        if !status.is_empty() {
            existing.status = status.to_string().into();
        }
    }

    state.token_store.update(&existing).await?;
    Ok(Json(existing))
}

async fn delete_token_handler(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.token_store.delete(id).await?;
    Ok(Json(serde_json::json!({"status": "deleted"})))
}

// --- Dashboard ---

async fn get_dashboard(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let accounts = state.account_svc.list_accounts().await?;
    let token_count = state.token_store.count().await.unwrap_or(0);

    let mut active = 0;
    let mut err_count = 0;
    let mut disabled = 0;
    for a in &accounts {
        match a.status {
            AccountStatus::Active => active += 1,
            AccountStatus::Error => err_count += 1,
            AccountStatus::Disabled => disabled += 1,
        }
    }

    Ok(Json(serde_json::json!({
        "accounts": {
            "total": accounts.len(),
            "active": active,
            "error": err_count,
            "disabled": disabled,
        },
        "tokens": token_count,
    })))
}

// --- OAuth Flow Handlers ---

async fn oauth_generate_auth_url(
    State(state): State<AppState>,
    Json(req): Json<crate::service::oauth_flow::GenerateAuthUrlRequest>,
) -> Json<crate::service::oauth_flow::GenerateAuthUrlResponse> {
    Json(state.oauth_flow_svc.generate_auth_url(&req))
}

async fn oauth_generate_setup_token_url(
    State(state): State<AppState>,
    Json(req): Json<crate::service::oauth_flow::GenerateAuthUrlRequest>,
) -> Json<crate::service::oauth_flow::GenerateAuthUrlResponse> {
    Json(state.oauth_flow_svc.generate_setup_token_url(&req))
}

async fn oauth_exchange_code(
    State(state): State<AppState>,
    Json(req): Json<crate::service::oauth_flow::ExchangeCodeRequest>,
) -> Result<Json<crate::service::oauth_flow::ExchangeCodeResponse>, AppError> {
    let resp = state.oauth_flow_svc.exchange_code(&req).await?;
    Ok(Json(resp))
}

async fn oauth_exchange_setup_token_code(
    State(state): State<AppState>,
    Json(req): Json<crate::service::oauth_flow::ExchangeCodeRequest>,
) -> Result<Json<crate::service::oauth_flow::ExchangeCodeResponse>, AppError> {
    let resp = state.oauth_flow_svc.exchange_setup_token_code(&req).await?;
    Ok(Json(resp))
}

// --- 内嵌前端静态资源 ---

#[derive(Embed)]
#[folder = "web/dist"]
struct Assets;

/// SPA 页面：返回 index.html
async fn spa_handler() -> impl IntoResponse {
    match Assets::get("index.html") {
        Some(index) => Response::builder()
            .header("content-type", "text/html")
            .body(axum::body::Body::from(index.data.to_vec()))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("frontend not built"))
            .unwrap(),
    }
}

/// 前端静态资源：/assets/*
async fn asset_handler(req: Request) -> impl IntoResponse {
    let path = req.uri().path().trim_start_matches('/');
    if let Some(file) = Assets::get(path) {
        let mime = mime_from_path(path);
        return Response::builder()
            .header("content-type", mime)
            .body(axum::body::Body::from(file.data.to_vec()))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(axum::body::Body::from("not found"))
        .unwrap()
}

fn mime_from_path(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}

fn timestamp_millis_to_utc(ts: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::Utc.timestamp_millis_opt(ts).single()
}

fn client_datetime_to_utc(value: &ClientDateTime) -> Option<DateTime<Utc>> {
    match value {
        ClientDateTime::Millis(ts) => timestamp_millis_to_utc(*ts),
        ClientDateTime::Text(text) => parse_client_datetime_str(text),
    }
}

fn client_datetime_value_to_utc(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    match value {
        serde_json::Value::Number(n) => n.as_i64().and_then(timestamp_millis_to_utc),
        serde_json::Value::String(s) => parse_client_datetime_str(s),
        _ => None,
    }
}

fn parse_client_datetime_str(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ms) = trimmed.parse::<i64>() {
        return timestamp_millis_to_utc(ms);
    }
    DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

async fn load_warmup_settings(state: &AppState) -> crate::service::warmup_scheduler::WarmupSettings {
    let mut settings =
        crate::service::warmup_scheduler::WarmupSettings::from_defaults(&state.warmup_defaults);

    if let Ok(Some(value)) = state.settings_store.get("warmup_enabled").await {
        settings.enabled = value != "false";
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_base_utc_hour").await {
        if let Ok(hour) = value.parse::<u32>() {
            settings.base_utc_hour = hour.min(23);
        }
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_jitter_minutes").await {
        if let Ok(minutes) = value.parse::<i64>() {
            settings.jitter_minutes = minutes.clamp(0, 720);
        }
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_max_retries").await {
        if let Ok(retries) = value.parse::<u32>() {
            settings.max_retries = retries.min(10);
        }
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_retry_backoff_secs").await {
        if let Ok(secs) = value.parse::<u64>() {
            settings.retry_backoff_secs = secs.max(30);
        }
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_account_gap_secs").await {
        if let Ok(secs) = value.parse::<u64>() {
            settings.account_gap_secs = secs.max(1);
        }
    }
    if let Ok(Some(value)) = state.settings_store.get("warmup_poll_interval_secs").await {
        if let Ok(secs) = value.parse::<u64>() {
            settings.poll_interval_secs = secs.max(15);
        }
    }

    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_client_datetime_millis_number() {
        let parsed = client_datetime_value_to_utc(&serde_json::json!(1775737845123_i64)).unwrap();
        assert_eq!(parsed.timestamp(), 1775737845);
        assert_eq!(parsed.timestamp_subsec_millis(), 123);
    }

    #[test]
    fn parses_client_datetime_millis_string() {
        let parsed = client_datetime_value_to_utc(&serde_json::json!("1775737845123")).unwrap();
        assert_eq!(parsed.timestamp(), 1775737845);
        assert_eq!(parsed.timestamp_subsec_millis(), 123);
    }

    #[test]
    fn parses_client_datetime_rfc3339_string() {
        let parsed =
            client_datetime_value_to_utc(&serde_json::json!("2026-04-09T12:30:45Z")).unwrap();
        assert_eq!(parsed.timestamp(), 1775737845);
    }

    #[test]
    fn empty_client_datetime_string_becomes_none() {
        assert!(client_datetime_value_to_utc(&serde_json::json!("")).is_none());
    }
}
