use chrono::Utc;
use sqlx::AnyPool;

use claude_code_gateway::model::api_token::{ApiToken, ApiTokenStatus};
use claude_code_gateway::store::token_store::TokenStore;

async fn setup() -> TokenStore {
    sqlx::any::install_default_drivers();
    let tmp = std::env::temp_dir().join(format!("ccgw_tok_test_{}.db", rand::random::<u64>()));
    let dsn = format!("sqlite:{}?mode=rwc", tmp.display());
    let pool = AnyPool::connect(&dsn)
        .await
        .expect("failed to create sqlite pool");
    claude_code_gateway::store::db::migrate(&pool, "sqlite")
        .await
        .expect("failed to run migrations");
    TokenStore::new(pool, "sqlite".into())
}

fn new_token(name: &str, token: &str) -> ApiToken {
    ApiToken {
        id: 0,
        name: name.into(),
        token: token.into(),
        allowed_accounts: String::new(),
        blocked_accounts: String::new(),
        status: ApiTokenStatus::Active,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper: create a token and resolve its id via get_by_token lookup
async fn create_and_resolve(store: &TokenStore, name: &str, token_val: &str) -> ApiToken {
    let mut t = new_token(name, token_val);
    store.create(&mut t).await.expect("create failed");
    // last_insert_id() may return 0 with the sqlx Any driver on SQLite,
    // so resolve the actual id via get_by_token.
    store
        .get_by_token(token_val)
        .await
        .expect("get_by_token failed")
        .expect("token should exist after create")
}

// ─── CREATE + GET ───

#[tokio::test]
async fn test_create_and_get_token() {
    let store = setup().await;
    let created = create_and_resolve(&store, "test-tok", "sk-create-test-001").await;
    assert!(created.id > 0);

    let fetched = store.get_by_id(created.id).await.expect("get_by_id failed");
    assert_eq!(fetched.name, "test-tok");
    assert_eq!(fetched.token, "sk-create-test-001");
    assert_eq!(fetched.status, ApiTokenStatus::Active);
}

// ─── GET BY TOKEN (active only) ───

#[tokio::test]
async fn test_get_by_token_active() {
    let store = setup().await;
    let created = create_and_resolve(&store, "active-tok", "sk-active-lookup-001").await;

    let found = store
        .get_by_token("sk-active-lookup-001")
        .await
        .expect("get_by_token failed");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "active-tok");

    // Disable the token and verify lookup returns None
    let mut disabled = store.get_by_id(created.id).await.unwrap();
    disabled.status = ApiTokenStatus::Disabled;
    store.update(&disabled).await.unwrap();

    let not_found = store
        .get_by_token("sk-active-lookup-001")
        .await
        .expect("get_by_token failed");
    assert!(not_found.is_none());
}

// ─── UPDATE ───

#[tokio::test]
async fn test_update_token() {
    let store = setup().await;
    let created = create_and_resolve(&store, "before-update", "sk-update-test-001").await;

    let mut fetched = store.get_by_id(created.id).await.unwrap();
    fetched.name = "after-update".into();
    fetched.allowed_accounts = "1,2,3".into();
    fetched.blocked_accounts = "4".into();
    fetched.status = ApiTokenStatus::Disabled;
    store.update(&fetched).await.expect("update failed");

    let updated = store.get_by_id(created.id).await.unwrap();
    assert_eq!(updated.name, "after-update");
    assert_eq!(updated.allowed_accounts, "1,2,3");
    assert_eq!(updated.blocked_accounts, "4");
    assert_eq!(updated.status, ApiTokenStatus::Disabled);
}

// ─── DELETE ───

#[tokio::test]
async fn test_delete_token() {
    let store = setup().await;
    let created = create_and_resolve(&store, "delete-me", "sk-delete-test-001").await;

    store.delete(created.id).await.expect("delete failed");

    let result = store.get_by_id(created.id).await;
    assert!(result.is_err(), "deleted token should not be found");
}

// ─── LIST ───

#[tokio::test]
async fn test_list_tokens() {
    let store = setup().await;
    let mut t1 = new_token("first", "sk-list-001");
    let mut t2 = new_token("second", "sk-list-002");
    store.create(&mut t1).await.unwrap();
    store.create(&mut t2).await.unwrap();

    let all = store.list().await.expect("list failed");
    assert!(all.len() >= 2);
}

// ─── LIST PAGED ───

#[tokio::test]
async fn test_list_paged_tokens() {
    let store = setup().await;
    for i in 0..5 {
        let mut t = new_token(&format!("paged-{}", i), &format!("sk-paged-{:03}", i));
        store.create(&mut t).await.unwrap();
    }

    let page1 = store.list_paged(1, 2).await.expect("page 1 failed");
    assert_eq!(page1.len(), 2);

    let page2 = store.list_paged(2, 2).await.expect("page 2 failed");
    assert_eq!(page2.len(), 2);

    let page3 = store.list_paged(3, 2).await.expect("page 3 failed");
    assert_eq!(page3.len(), 1);
}

// ─── COUNT ───

#[tokio::test]
async fn test_count_tokens() {
    let store = setup().await;
    assert_eq!(store.count().await.unwrap(), 0);

    let mut t = new_token("count-tok", "sk-count-001");
    store.create(&mut t).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 1);

    let mut t2 = new_token("count-tok2", "sk-count-002");
    store.create(&mut t2).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 2);
}

// ─── TIMESTAMPS PARSE CORRECTLY ───

#[tokio::test]
async fn test_token_timestamps_parse() {
    let store = setup().await;
    let before = Utc::now();
    let created = create_and_resolve(&store, "ts-tok", "sk-timestamp-001").await;

    let fetched = store.get_by_id(created.id).await.unwrap();
    // created_at and updated_at should be valid timestamps close to now
    let diff_created = (fetched.created_at - before).num_seconds().abs();
    let diff_updated = (fetched.updated_at - before).num_seconds().abs();
    assert!(
        diff_created < 5,
        "created_at should be within 5s of now, got {}s diff",
        diff_created
    );
    assert!(
        diff_updated < 5,
        "updated_at should be within 5s of now, got {}s diff",
        diff_updated
    );
}
