use chrono::{Duration, Utc};
use sqlx::AnyPool;
use std::sync::Arc;

use claude_code_gateway::error::AppError;
use claude_code_gateway::model::account::{Account, AccountAuthType, AccountStatus, BillingMode};
use claude_code_gateway::service::account::AccountService;
use claude_code_gateway::store::account_store::AccountStore;
use claude_code_gateway::store::memory::MemoryStore;

/// 创建测试用的临时文件数据库和服务
async fn setup() -> (Arc<AccountStore>, Arc<AccountService>) {
    sqlx::any::install_default_drivers();
    let tmp = std::env::temp_dir().join(format!("ccgw_test_{}.db", rand::random::<u64>()));
    let dsn = format!("sqlite:{}?mode=rwc", tmp.display());
    let pool = AnyPool::connect(&dsn)
        .await
        .expect("failed to create sqlite pool");
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("failed to run migrations");

    let store = Arc::new(AccountStore::new(pool, "sqlite".into()));
    let cache = Arc::new(MemoryStore::new());
    let svc = Arc::new(AccountService::new(store.clone(), cache));
    (store, svc)
}

/// 创建一个基础测试账号
async fn create_test_account(svc: &AccountService, email: &str, priority: i32) -> Account {
    let mut account = Account {
        id: 0,
        name: "test".into(),
        email: email.into(),
        status: AccountStatus::Active,
        auth_type: AccountAuthType::SetupToken,
        setup_token: "sk-ant-oat01-test-token-placeholder-value".into(),
        access_token: String::new(),
        refresh_token: String::new(),
        expires_at: None,
        oauth_refreshed_at: None,
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
        priority,
        rate_limited_at: None,
        rate_limit_reset_at: None,
        disable_reason: String::new(),
        auto_telemetry: false,
        telemetry_count: 0,
        usage_data: serde_json::json!({}),
        usage_fetched_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    svc.create_account(&mut account)
        .await
        .expect("failed to create account");
    account
}

// ─── 429 重试换号逻辑测试 ───────────────────────────────────────
// 模拟 gateway 的重试循环：每次 429 后将账号加入 exclude_ids，直到所有账号用尽

#[tokio::test]
async fn test_retry_excludes_429_account_and_picks_next() {
    let (_store, svc) = setup().await;
    // 用不同优先级确保选号顺序确定：priority 越小越优先
    let a1 = create_test_account(&svc, "acct1@example.com", 10).await;
    let a2 = create_test_account(&svc, "acct2@example.com", 20).await;
    let a3 = create_test_account(&svc, "acct3@example.com", 30).await;

    let mut exclude_ids: Vec<i64> = vec![];

    // 第 1 次选号：应选 a1（最高优先级）
    let selected = svc.select_account("", &exclude_ids, &[]).await.unwrap();
    assert_eq!(selected.id, a1.id);

    // 模拟 a1 收到 429，隔离并加入排除列表
    let reset_at = Utc::now() + Duration::hours(5);
    svc.disable_account(a1.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();
    exclude_ids.push(a1.id);

    // 第 2 次选号：a1 被排除，应选 a2
    let selected = svc.select_account("", &exclude_ids, &[]).await.unwrap();
    assert_eq!(selected.id, a2.id);

    // 模拟 a2 也收到 429
    svc.disable_account(a2.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();
    exclude_ids.push(a2.id);

    // 第 3 次选号：a1, a2 被排除，应选 a3
    let selected = svc.select_account("", &exclude_ids, &[]).await.unwrap();
    assert_eq!(selected.id, a3.id);

    // 模拟 a3 也收到 429
    svc.disable_account(a3.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();
    exclude_ids.push(a3.id);

    // 第 4 次选号：所有账号都被排除，应返回 ServiceUnavailable
    let result = svc.select_account("", &exclude_ids, &[]).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::ServiceUnavailable(_) => {}
        e => panic!("expected ServiceUnavailable, got: {:?}", e),
    }
}

#[tokio::test]
async fn test_retry_with_sticky_session_falls_back_on_429() {
    let (_store, svc) = setup().await;
    let a1 = create_test_account(&svc, "sticky1@example.com", 10).await;
    let a2 = create_test_account(&svc, "sticky2@example.com", 20).await;

    let session_hash = "test-session-hash-abc";

    // 首次选号，建立粘性会话绑定到 a1
    let selected = svc.select_account(session_hash, &[], &[]).await.unwrap();
    assert_eq!(selected.id, a1.id);

    // 模拟 a1 收到 429，隔离并加入排除列表
    let reset_at = Utc::now() + Duration::hours(5);
    svc.disable_account(a1.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();
    let exclude_ids = vec![a1.id];

    // 重试选号：虽然有粘性会话绑定到 a1，但 a1 不可调度 + 在排除列表中，
    // 应自动解绑并选择 a2
    let selected = svc
        .select_account(session_hash, &exclude_ids, &[])
        .await
        .unwrap();
    assert_eq!(selected.id, a2.id);
}

#[tokio::test]
async fn test_retry_all_accounts_429_returns_last_error() {
    let (_store, svc) = setup().await;
    let a1 = create_test_account(&svc, "only1@example.com", 10).await;

    let reset_at = Utc::now() + Duration::hours(5);
    svc.disable_account(a1.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();

    // 只有一个账号且已被排除，应直接返回 ServiceUnavailable
    let result = svc.select_account("", &[a1.id], &[]).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::ServiceUnavailable(_) => {}
        e => panic!("expected ServiceUnavailable, got: {:?}", e),
    }
}

#[tokio::test]
async fn test_429_accounts_are_quarantined_for_5h() {
    let (_store, svc) = setup().await;
    let a1 = create_test_account(&svc, "quarantine1@example.com", 10).await;
    let a2 = create_test_account(&svc, "quarantine2@example.com", 20).await;

    // 模拟重试循环中 a1 和 a2 依次收到 429
    let reset_at = Utc::now() + Duration::hours(5);
    svc.disable_account(a1.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();
    svc.disable_account(a2.id, AccountStatus::Active, "429 速率限制", Some(reset_at))
        .await
        .unwrap();

    // 两个账号都应该不可调度
    let a1_updated = svc.get_account(a1.id).await.unwrap();
    let a2_updated = svc.get_account(a2.id).await.unwrap();
    assert!(!a1_updated.is_schedulable());
    assert!(!a2_updated.is_schedulable());

    // 即使不传 exclude_ids，list_schedulable 也不会返回它们
    let result = svc.select_account("", &[], &[]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_retry_respects_allowed_ids_filter() {
    let (_store, svc) = setup().await;
    let a1 = create_test_account(&svc, "allowed1@example.com", 10).await;
    let a2 = create_test_account(&svc, "allowed2@example.com", 20).await;
    let _a3 = create_test_account(&svc, "not_allowed@example.com", 30).await;

    // Token 只允许 a1 和 a2
    let allowed_ids = vec![a1.id, a2.id];

    // a1 被 429
    let mut exclude_ids = vec![];
    let selected = svc
        .select_account("", &exclude_ids, &allowed_ids)
        .await
        .unwrap();
    assert_eq!(selected.id, a1.id);

    exclude_ids.push(a1.id);

    // 重试应选 a2（a3 不在 allowed_ids 中）
    let selected = svc
        .select_account("", &exclude_ids, &allowed_ids)
        .await
        .unwrap();
    assert_eq!(selected.id, a2.id);

    exclude_ids.push(a2.id);

    // a1, a2 都被排除，a3 不允许 → 无可用账号
    let result = svc.select_account("", &exclude_ids, &allowed_ids).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_slot_can_be_reacquired_after_release() {
    let (_store, svc) = setup().await;
    let a1 = create_test_account(&svc, "slot_test@example.com", 10).await;

    // 模拟重试循环中获取槽位 → 收到 429 → 释放槽位
    let acquired = svc.acquire_slot(a1.id, a1.concurrency).await.unwrap();
    assert!(acquired);

    // 释放（模拟 429 重试时手动释放）
    svc.release_slot(a1.id).await;

    // 槽位应可再次获取（下一个账号或后续请求）
    let acquired_again = svc.acquire_slot(a1.id, a1.concurrency).await.unwrap();
    assert!(acquired_again);
}
