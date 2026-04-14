use chrono::{Duration, Utc};
use sqlx::AnyPool;
use std::sync::Arc;

use claude_code_gateway::model::account::{Account, AccountAuthType, AccountStatus, BillingMode};
use claude_code_gateway::store::account_store::AccountStore;

async fn setup() -> Arc<AccountStore> {
    sqlx::any::install_default_drivers();
    let tmp = std::env::temp_dir().join(format!("ccgw_ts_test_{}.db", rand::random::<u64>()));
    let dsn = format!("sqlite:{}?mode=rwc", tmp.display());
    let pool = AnyPool::connect(&dsn)
        .await
        .expect("failed to create sqlite pool");
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("failed to run migrations");
    Arc::new(AccountStore::new(pool, "sqlite".into()))
}

fn new_account(email: &str) -> Account {
    Account {
        id: 0,
        name: "ts-test".into(),
        email: email.into(),
        status: AccountStatus::Active,
        auth_type: AccountAuthType::Oauth,
        setup_token: "sk-ant-oat01-test-placeholder".into(),
        access_token: "access-tok".into(),
        refresh_token: "refresh-tok".into(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        oauth_refreshed_at: Some(Utc::now()),
        auth_error: String::new(),
        proxy_url: String::new(),
        device_id: String::new(),
        canonical_env: serde_json::json!({}),
        canonical_prompt: serde_json::json!({}),
        canonical_process: serde_json::json!({}),
        billing_mode: BillingMode::Strip,
        account_uuid: None,
        organization_uuid: None,
        subscription_type: None,
        concurrency: 3,
        priority: 50,
        rate_limited_at: None,
        rate_limit_reset_at: None,
        disable_reason: String::new(),
        auto_telemetry: false,
        telemetry_count: 0,
        usage_data: serde_json::json!({}),
        usage_fetched_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ─── CREATE: oauth_expires_at and oauth_refreshed_at bound as timestamps ───

#[tokio::test]
async fn test_create_account_with_oauth_timestamps() {
    let store = setup().await;
    let mut a = new_account("create-ts@example.com");
    store.create(&mut a).await.expect("create failed");
    assert!(a.id > 0);

    let fetched = store.get_by_id(a.id).await.expect("get_by_id failed");
    assert!(fetched.expires_at.is_some());
    assert!(fetched.oauth_refreshed_at.is_some());
}

#[tokio::test]
async fn test_create_account_with_null_timestamps() {
    let store = setup().await;
    let mut a = new_account("create-null-ts@example.com");
    a.expires_at = None;
    a.oauth_refreshed_at = None;
    store.create(&mut a).await.expect("create failed");

    let fetched = store.get_by_id(a.id).await.expect("get_by_id failed");
    assert!(fetched.expires_at.is_none());
    assert!(fetched.oauth_refreshed_at.is_none());
}

// ─── UPDATE: oauth_expires_at and oauth_refreshed_at ───

#[tokio::test]
async fn test_update_account_with_oauth_timestamps() {
    let store = setup().await;
    let mut a = new_account("update-ts@example.com");
    store.create(&mut a).await.unwrap();

    let new_expiry = Utc::now() + Duration::hours(2);
    let new_refreshed = Utc::now();
    a.expires_at = Some(new_expiry);
    a.oauth_refreshed_at = Some(new_refreshed);
    store.update(&a).await.expect("update failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert!(fetched.expires_at.is_some());
    assert!(fetched.oauth_refreshed_at.is_some());
}

// ─── UPDATE_OAUTH_TOKENS: oauth_expires_at and oauth_refreshed_at ───

#[tokio::test]
async fn test_update_oauth_tokens_timestamps() {
    let store = setup().await;
    let mut a = new_account("oauth-tok@example.com");
    store.create(&mut a).await.unwrap();

    let new_expiry = Utc::now() + Duration::hours(3);
    store
        .update_oauth_tokens(a.id, "new-access", "new-refresh", new_expiry)
        .await
        .expect("update_oauth_tokens failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert_eq!(fetched.access_token, "new-access");
    assert_eq!(fetched.refresh_token, "new-refresh");
    assert!(fetched.expires_at.is_some());
    assert!(fetched.oauth_refreshed_at.is_some());
    assert!(fetched.auth_error.is_empty());
}

// ─── SET_RATE_LIMIT: rate_limited_at and rate_limit_reset_at ───

#[tokio::test]
async fn test_set_rate_limit_timestamps() {
    let store = setup().await;
    let mut a = new_account("rate-limit@example.com");
    store.create(&mut a).await.unwrap();

    let reset_at = Utc::now() + Duration::hours(5);
    store
        .set_rate_limit(a.id, reset_at)
        .await
        .expect("set_rate_limit failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert!(fetched.rate_limited_at.is_some());
    assert!(fetched.rate_limit_reset_at.is_some());
}

// ─── DISABLE_ACCOUNT: rate_limited_at and rate_limit_reset_at ───

#[tokio::test]
async fn test_disable_account_with_rate_limit_timestamps() {
    let store = setup().await;
    let mut a = new_account("disable-ts@example.com");
    store.create(&mut a).await.unwrap();

    let reset_at = Utc::now() + Duration::hours(1);
    store
        .disable_account(a.id, AccountStatus::Active, "rate limited", Some(reset_at))
        .await
        .expect("disable_account failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert!(fetched.rate_limited_at.is_some());
    assert!(fetched.rate_limit_reset_at.is_some());
    assert_eq!(fetched.disable_reason, "rate limited");
}

#[tokio::test]
async fn test_disable_account_without_rate_limit() {
    let store = setup().await;
    let mut a = new_account("disable-no-rl@example.com");
    store.create(&mut a).await.unwrap();

    store
        .disable_account(a.id, AccountStatus::Disabled, "manual", None)
        .await
        .expect("disable_account failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert!(fetched.rate_limited_at.is_none());
    assert!(fetched.rate_limit_reset_at.is_none());
    assert_eq!(fetched.status, AccountStatus::Disabled);
}

// ─── UPDATE_USAGE: usage_fetched_at ───

#[tokio::test]
async fn test_update_usage_timestamp() {
    let store = setup().await;
    let mut a = new_account("usage-ts@example.com");
    store.create(&mut a).await.unwrap();

    store
        .update_usage(a.id, r#"{"tokens": 1000}"#)
        .await
        .expect("update_usage failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert!(fetched.usage_fetched_at.is_some());
}

// ─── UPDATE_USAGE: JSON data stored and read back correctly ───

#[tokio::test]
async fn test_update_usage_stores_json_data() {
    let store = setup().await;
    let mut a = new_account("usage-json@example.com");
    store.create(&mut a).await.unwrap();

    let json_str = r#"{"tokens": 1000, "messages": 42}"#;
    store
        .update_usage(a.id, json_str)
        .await
        .expect("update_usage failed");

    let fetched = store.get_by_id(a.id).await.unwrap();
    assert_eq!(fetched.usage_data["tokens"], 1000);
    assert_eq!(fetched.usage_data["messages"], 42);
}

#[tokio::test]
async fn test_update_usage_overwrites_previous() {
    let store = setup().await;
    let mut a = new_account("usage-overwrite@example.com");
    store.create(&mut a).await.unwrap();

    store
        .update_usage(a.id, r#"{"v": 1}"#)
        .await
        .expect("first update_usage failed");

    let fetched1 = store.get_by_id(a.id).await.unwrap();
    assert_eq!(fetched1.usage_data["v"], 1);

    store
        .update_usage(a.id, r#"{"v": 2, "extra": true}"#)
        .await
        .expect("second update_usage failed");

    let fetched2 = store.get_by_id(a.id).await.unwrap();
    assert_eq!(fetched2.usage_data["v"], 2);
    assert_eq!(fetched2.usage_data["extra"], true);
    // old key "v":1 should be gone
    assert!(fetched2.usage_data.get("v").unwrap() == &serde_json::json!(2));
}

// ─── LIST_SCHEDULABLE: rate_limit_reset_at comparison ───

#[tokio::test]
async fn test_list_schedulable_excludes_rate_limited() {
    let store = setup().await;
    let mut a = new_account("sched-limited@example.com");
    store.create(&mut a).await.unwrap();

    // Set a future rate limit
    let reset_at = Utc::now() + Duration::hours(1);
    store.set_rate_limit(a.id, reset_at).await.unwrap();

    let schedulable = store.list_schedulable().await.unwrap();
    assert!(
        schedulable.iter().all(|acc| acc.id != a.id),
        "rate-limited account should not be schedulable"
    );
}

#[tokio::test]
async fn test_list_schedulable_includes_expired_rate_limit() {
    let store = setup().await;
    let mut a = new_account("sched-expired@example.com");
    store.create(&mut a).await.unwrap();

    // Set an already-expired rate limit
    let reset_at = Utc::now() - Duration::seconds(10);
    store.set_rate_limit(a.id, reset_at).await.unwrap();

    let schedulable = store.list_schedulable().await.unwrap();
    assert!(
        schedulable.iter().any(|acc| acc.id == a.id),
        "account with expired rate limit should be schedulable"
    );
}
