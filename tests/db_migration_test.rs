use sqlx::AnyPool;
use sqlx::Row;

async fn setup_pool() -> AnyPool {
    sqlx::any::install_default_drivers();
    let tmp = std::env::temp_dir().join(format!("ccgw_mig_test_{}.db", rand::random::<u64>()));
    let dsn = format!("sqlite:{}?mode=rwc", tmp.display());
    AnyPool::connect(&dsn)
        .await
        .expect("failed to create sqlite pool")
}

// ─── SCHEMA COMPLETENESS: accounts table has ALL expected columns ───

#[tokio::test]
async fn test_migrate_sqlite_creates_all_columns() {
    let pool = setup_pool().await;
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("migrate failed");

    let rows: Vec<sqlx::any::AnyRow> =
        sqlx::query("PRAGMA table_info(accounts)")
            .fetch_all(&pool)
            .await
            .expect("PRAGMA table_info failed");

    let col_names: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();

    let expected = vec![
        "id", "name", "email", "status", "token",
        "auth_type", "access_token", "refresh_token",
        "oauth_expires_at", "oauth_refreshed_at", "auth_error",
        "proxy_url", "device_id",
        "canonical_env", "canonical_prompt_env", "canonical_process",
        "billing_mode", "concurrency", "priority",
        "rate_limited_at", "rate_limit_reset_at",
        "account_uuid", "organization_uuid", "subscription_type",
        "disable_reason", "auto_telemetry", "telemetry_count",
        "usage_data", "usage_fetched_at",
        "created_at", "updated_at",
    ];

    for col in &expected {
        assert!(
            col_names.contains(&col.to_string()),
            "missing column '{}' in accounts table. Got: {:?}",
            col,
            col_names
        );
    }
}

// ─── SCHEMA COMPLETENESS: api_tokens table ───

#[tokio::test]
async fn test_migrate_sqlite_creates_token_table() {
    let pool = setup_pool().await;
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("migrate failed");

    let rows: Vec<sqlx::any::AnyRow> =
        sqlx::query("PRAGMA table_info(api_tokens)")
            .fetch_all(&pool)
            .await
            .expect("PRAGMA table_info failed");

    let col_names: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();

    let expected = vec![
        "id", "name", "token",
        "allowed_accounts", "blocked_accounts",
        "status", "created_at", "updated_at",
    ];

    for col in &expected {
        assert!(
            col_names.contains(&col.to_string()),
            "missing column '{}' in api_tokens table. Got: {:?}",
            col,
            col_names
        );
    }
}

// ─── IDEMPOTENCY: running migrate twice should not error ───

#[tokio::test]
async fn test_migrate_idempotent_sqlite() {
    let pool = setup_pool().await;
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("first migrate failed");
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("second migrate should be idempotent");
}

// ─── FULL CRUD on freshly migrated SQLite database ───

#[tokio::test]
async fn test_migrate_sqlite_account_crud() {
    use chrono::{Duration, Utc};
    use claude_code_gateway::model::account::{Account, AccountAuthType, AccountStatus, BillingMode};
    use claude_code_gateway::store::account_store::AccountStore;

    let pool = setup_pool().await;
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("migrate failed");

    let store = AccountStore::new(pool, "sqlite".into());

    // CREATE
    let mut a = Account {
        id: 0,
        name: "mig-test".into(),
        email: "mig@example.com".into(),
        status: AccountStatus::Active,
        auth_type: AccountAuthType::Oauth,
        setup_token: "sk-ant-test".into(),
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        expires_at: Some(Utc::now() + Duration::hours(1)),
        oauth_refreshed_at: Some(Utc::now()),
        auth_error: String::new(),
        proxy_url: String::new(),
        device_id: "dev-1".into(),
        canonical_env: serde_json::json!({"key": "val"}),
        canonical_prompt: serde_json::json!({}),
        canonical_process: serde_json::json!({}),
        billing_mode: BillingMode::Strip,
        account_uuid: Some("uuid-1".into()),
        organization_uuid: Some("org-1".into()),
        subscription_type: Some("pro".into()),
        concurrency: 5,
        priority: 10,
        rate_limited_at: None,
        rate_limit_reset_at: None,
        disable_reason: String::new(),
        auto_telemetry: true,
        telemetry_count: 0,
        usage_data: serde_json::json!({}),
        usage_fetched_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    store.create(&mut a).await.expect("create failed");
    assert!(a.id > 0);

    // READ
    let fetched = store.get_by_id(a.id).await.expect("get failed");
    assert_eq!(fetched.name, "mig-test");
    assert_eq!(fetched.account_uuid, Some("uuid-1".into()));
    assert_eq!(fetched.organization_uuid, Some("org-1".into()));
    assert_eq!(fetched.subscription_type, Some("pro".into()));
    assert!(fetched.auto_telemetry);
    assert_eq!(fetched.concurrency, 5);
    assert_eq!(fetched.priority, 10);

    // UPDATE
    store
        .update_usage(a.id, r#"{"tokens": 500}"#)
        .await
        .expect("update_usage failed");
    let fetched2 = store.get_by_id(a.id).await.unwrap();
    assert!(fetched2.usage_fetched_at.is_some());

    // DELETE
    store.delete(a.id).await.expect("delete failed");
    let result = store.get_by_id(a.id).await;
    assert!(result.is_err());
}
