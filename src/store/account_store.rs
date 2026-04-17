use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use sqlx::AnyPool;
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::error::AppError;
use crate::model::account::{Account, AccountStatus};

pub struct AccountStore {
    pool: AnyPool,
    driver: String,
}

impl AccountStore {
    pub fn new(pool: AnyPool, driver: String) -> Self {
        Self { pool, driver }
    }

    fn now_expr(&self) -> &str {
        if self.driver == "sqlite" {
            "strftime('%Y-%m-%dT%H:%M:%SZ','now')"
        } else {
            "NOW()"
        }
    }

    fn is_pg(&self) -> bool {
        self.driver == "postgres"
    }

    fn fmt_time(&self, t: DateTime<Utc>) -> String {
        t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    /// Returns `$N::TEXT` for Postgres to work around sqlx Any driver encoding
    /// all NULLs as `Option::<i32>::None` / INT4 type OID. The explicit `::TEXT`
    /// cast makes the INT4→TEXT conversion succeed before assignment to a TEXT column.
    fn nullable(&self, n: u32) -> String {
        if self.is_pg() {
            format!("${}::TEXT", n)
        } else {
            format!("${}", n)
        }
    }

    /// Like `nullable()` but for TIMESTAMPTZ columns. Uses `$N::TEXT::TIMESTAMPTZ`
    /// for Postgres because TEXT has no implicit assignment cast to TIMESTAMPTZ.
    fn nullable_ts(&self, n: u32) -> String {
        if self.is_pg() {
            format!("${}::TEXT::TIMESTAMPTZ", n)
        } else {
            format!("${}", n)
        }
    }

    /// Returns `$N::JSONB` for Postgres. The Any driver sends String as TEXT type,
    /// but TEXT has no implicit assignment cast to JSONB.
    fn jsonb(&self, n: u32) -> String {
        if self.is_pg() {
            format!("${}::JSONB", n)
        } else {
            format!("${}", n)
        }
    }

    fn parse_datetime_str(s: &str) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
            .or_else(|| {
                NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
                    .map(|n| n.and_utc())
                    .ok()
            })
            .or_else(|| {
                DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%:z")
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            })
    }

    fn parse_time(row: &AnyRow, col: &str) -> DateTime<Utc> {
        if let Ok(s) = row.try_get::<String, _>(col) {
            Self::parse_datetime_str(&s).unwrap_or_default()
        } else {
            Utc::now()
        }
    }

    fn parse_optional_time(row: &AnyRow, col: &str) -> Option<DateTime<Utc>> {
        if let Ok(s) = row.try_get::<Option<String>, _>(col) {
            s.and_then(|s| Self::parse_datetime_str(&s))
        } else {
            None
        }
    }

    fn parse_json(row: &AnyRow, col: &str) -> Value {
        if let Ok(s) = row.try_get::<String, _>(col) {
            serde_json::from_str(&s).unwrap_or_else(|_| Value::Object(Default::default()))
        } else {
            Value::Object(Default::default())
        }
    }

    fn select_account_cols(&self) -> &'static str {
        if self.is_pg() {
            ACCOUNT_COLS_PG_TEXT
        } else {
            ACCOUNT_COLS
        }
    }

    fn row_to_account(row: &AnyRow) -> Account {
        Account {
            id: row.try_get::<i64, _>("id").unwrap_or_default(),
            name: row.try_get::<String, _>("name").unwrap_or_default(),
            email: row.try_get::<String, _>("email").unwrap_or_default(),
            status: row
                .try_get::<String, _>("status")
                .unwrap_or_else(|_| "active".into())
                .into(),
            auth_type: row
                .try_get::<String, _>("auth_type")
                .unwrap_or_else(|_| "setup_token".into())
                .into(),
            setup_token: row.try_get::<String, _>("token").unwrap_or_default(),
            access_token: row.try_get::<String, _>("access_token").unwrap_or_default(),
            refresh_token: row
                .try_get::<String, _>("refresh_token")
                .unwrap_or_default(),
            expires_at: Self::parse_optional_time(row, "oauth_expires_at"),
            oauth_refreshed_at: Self::parse_optional_time(row, "oauth_refreshed_at"),
            auth_error: row.try_get::<String, _>("auth_error").unwrap_or_default(),
            proxy_url: row.try_get::<String, _>("proxy_url").unwrap_or_default(),
            device_id: row.try_get::<String, _>("device_id").unwrap_or_default(),
            canonical_env: Self::parse_json(row, "canonical_env"),
            canonical_prompt: Self::parse_json(row, "canonical_prompt_env"),
            canonical_process: Self::parse_json(row, "canonical_process"),
            billing_mode: row
                .try_get::<String, _>("billing_mode")
                .unwrap_or_else(|_| "strip".into())
                .into(),
            account_uuid: row
                .try_get::<Option<String>, _>("account_uuid")
                .unwrap_or(None),
            organization_uuid: row
                .try_get::<Option<String>, _>("organization_uuid")
                .unwrap_or(None),
            subscription_type: row
                .try_get::<Option<String>, _>("subscription_type")
                .unwrap_or(None),
            concurrency: row.try_get::<i32, _>("concurrency").unwrap_or(3),
            priority: row.try_get::<i32, _>("priority").unwrap_or(50),
            rate_limited_at: Self::parse_optional_time(row, "rate_limited_at"),
            rate_limit_reset_at: Self::parse_optional_time(row, "rate_limit_reset_at"),
            disable_reason: row
                .try_get::<String, _>("disable_reason")
                .unwrap_or_default(),
            auto_telemetry: row.try_get::<i32, _>("auto_telemetry").unwrap_or(0) != 0,
            telemetry_count: row.try_get::<i64, _>("telemetry_count").unwrap_or(0),
            warmup_enabled: row.try_get::<i32, _>("warmup_enabled").unwrap_or(0) != 0,
            next_warmup_at: Self::parse_optional_time(row, "next_warmup_at"),
            last_warmup_at: Self::parse_optional_time(row, "last_warmup_at"),
            last_warmup_status: row
                .try_get::<String, _>("last_warmup_status")
                .unwrap_or_default(),
            last_warmup_message: row
                .try_get::<String, _>("last_warmup_message")
                .unwrap_or_default(),
            warmup_retry_count: row.try_get::<i32, _>("warmup_retry_count").unwrap_or(0),
            usage_data: Self::parse_json(row, "usage_data"),
            usage_fetched_at: Self::parse_optional_time(row, "usage_fetched_at"),
            created_at: Self::parse_time(row, "created_at"),
            updated_at: Self::parse_time(row, "updated_at"),
        }
    }

    pub async fn create(&self, a: &mut Account) -> Result<(), AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) as cnt FROM accounts WHERE email=$1")
            .bind(&a.email)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        if count > 0 {
            return Err(AppError::BadRequest(format!(
                "email {} already exists",
                a.email
            )));
        }

        let env_str = serde_json::to_string(&a.canonical_env).unwrap_or_else(|_| "{}".into());
        let prompt_str = serde_json::to_string(&a.canonical_prompt).unwrap_or_else(|_| "{}".into());
        let process_str =
            serde_json::to_string(&a.canonical_process).unwrap_or_else(|_| "{}".into());
        let expires_at = a.expires_at.map(|t| self.fmt_time(t));
        let oauth_refreshed_at = a.oauth_refreshed_at.map(|t| self.fmt_time(t));

        let auto_telemetry_int: i32 = if a.auto_telemetry { 1 } else { 0 };
        let q = format!(
            r#"INSERT INTO accounts (name, email, status, token, proxy_url,
                auth_type, access_token, refresh_token, oauth_expires_at, oauth_refreshed_at, auth_error,
                device_id, canonical_env, canonical_prompt_env, canonical_process,
                billing_mode, account_uuid, organization_uuid, subscription_type,
                concurrency, priority, auto_telemetry, warmup_enabled)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,{},{},{},$12,{},{},{},$16,{},{},{},$20,$21,$22,$23)"#,
            self.nullable_ts(9),
            self.nullable_ts(10),
            "$11",
            self.jsonb(13),
            self.jsonb(14),
            self.jsonb(15),
            self.nullable(17),
            self.nullable(18),
            self.nullable(19)
        );
        sqlx::query(&q)
            .bind(&a.name)
            .bind(&a.email)
            .bind(a.status.to_string())
            .bind(&a.setup_token)
            .bind(&a.proxy_url)
            .bind(a.auth_type.to_string())
            .bind(&a.access_token)
            .bind(&a.refresh_token)
            .bind(expires_at)
            .bind(oauth_refreshed_at)
            .bind(&a.auth_error)
            .bind(&a.device_id)
            .bind(&env_str)
            .bind(&prompt_str)
            .bind(&process_str)
            .bind(a.billing_mode.to_string())
            .bind(&a.account_uuid)
            .bind(&a.organization_uuid)
            .bind(&a.subscription_type)
            .bind(a.concurrency)
            .bind(a.priority)
            .bind(auto_telemetry_int)
            .bind(if a.warmup_enabled { 1 } else { 0 })
            .execute(&self.pool)
            .await?;

        let row: AnyRow = sqlx::query(&format!(
            "SELECT {} FROM accounts WHERE email=$1",
            self.select_account_cols()
        ))
        .bind(&a.email)
        .fetch_one(&self.pool)
        .await?;

        a.id = row.try_get::<i64, _>("id").unwrap_or_default();
        a.created_at = Self::parse_time(&row, "created_at");
        a.updated_at = Self::parse_time(&row, "updated_at");
        Ok(())
    }

    pub async fn update(&self, a: &Account) -> Result<(), AppError> {
        let expires_at = a.expires_at.map(|t| self.fmt_time(t));
        let oauth_refreshed_at = a.oauth_refreshed_at.map(|t| self.fmt_time(t));
        let auto_telemetry_int: i32 = if a.auto_telemetry { 1 } else { 0 };
        let q = format!(
            r#"UPDATE accounts SET name=$1, email=$2, status=$3, token=$4,
                auth_type=$5, access_token=$6, refresh_token=$7, oauth_expires_at={}, oauth_refreshed_at={},
                auth_error=$10, proxy_url=$11, billing_mode=$12,
                account_uuid={}, organization_uuid={}, subscription_type={},
                concurrency=$16, priority=$17, auto_telemetry=$18, warmup_enabled=$19, updated_at={}
            WHERE id=$20"#,
            self.nullable_ts(8),
            self.nullable_ts(9),
            self.nullable(13),
            self.nullable(14),
            self.nullable(15),
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(&a.name)
            .bind(&a.email)
            .bind(a.status.to_string())
            .bind(&a.setup_token)
            .bind(a.auth_type.to_string())
            .bind(&a.access_token)
            .bind(&a.refresh_token)
            .bind(expires_at)
            .bind(oauth_refreshed_at)
            .bind(&a.auth_error)
            .bind(&a.proxy_url)
            .bind(a.billing_mode.to_string())
            .bind(&a.account_uuid)
            .bind(&a.organization_uuid)
            .bind(&a.subscription_type)
            .bind(a.concurrency)
            .bind(a.priority)
            .bind(auto_telemetry_int)
            .bind(if a.warmup_enabled { 1 } else { 0 })
            .bind(a.id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_warmup_state(
        &self,
        id: i64,
        next_warmup_at: Option<DateTime<Utc>>,
        last_warmup_at: Option<DateTime<Utc>>,
        last_warmup_status: &str,
        last_warmup_message: &str,
        warmup_retry_count: i32,
    ) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET next_warmup_at={}, last_warmup_at={}, last_warmup_status=$3, \
             last_warmup_message=$4, warmup_retry_count=$5, updated_at={} WHERE id=$6",
            self.nullable_ts(1),
            self.nullable_ts(2),
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(next_warmup_at.map(|t| self.fmt_time(t)))
            .bind(last_warmup_at.map(|t| self.fmt_time(t)))
            .bind(last_warmup_status)
            .bind(last_warmup_message)
            .bind(warmup_retry_count)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_warmup_state(&self, id: i64) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET next_warmup_at=NULL, warmup_retry_count=0, updated_at={} WHERE id=$1",
            self.now_expr()
        );
        sqlx::query(&q).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_oauth_tokens(
        &self,
        id: i64,
        access_token: &str,
        refresh_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let q = format!(
            r#"UPDATE accounts SET access_token=$1, refresh_token=$2, oauth_expires_at={},
                oauth_refreshed_at={}, auth_error='', updated_at={}
            WHERE id=$5"#,
            self.nullable_ts(3),
            self.nullable_ts(4),
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(access_token)
            .bind(refresh_token)
            .bind(self.fmt_time(expires_at))
            .bind(self.fmt_time(Utc::now()))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_auth_error(&self, id: i64, auth_error: &str) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET auth_error=$1, updated_at={} WHERE id=$2",
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(auth_error)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_status(&self, id: i64, status: AccountStatus) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET status=$1, updated_at={} WHERE id=$2",
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(status.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_rate_limit(&self, id: i64, reset_at: DateTime<Utc>) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET rate_limited_at={}, rate_limit_reset_at={}, updated_at={} WHERE id=$3",
            self.nullable_ts(1),
            self.nullable_ts(2),
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(self.fmt_time(Utc::now()))
            .bind(self.fmt_time(reset_at))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn disable_account(
        &self,
        id: i64,
        status: AccountStatus,
        reason: &str,
        rate_limit_reset_at: Option<DateTime<Utc>>,
    ) -> Result<(), AppError> {
        let q = format!(
            r#"UPDATE accounts SET status=$1, disable_reason=$2,
                rate_limited_at={}, rate_limit_reset_at={}, updated_at={}
            WHERE id=$5"#,
            self.nullable_ts(3),
            self.nullable_ts(4),
            self.now_expr()
        );
        let limited_str = rate_limit_reset_at.map(|_| self.fmt_time(Utc::now()));
        let reset_str = rate_limit_reset_at.map(|t| self.fmt_time(t));
        sqlx::query(&q)
            .bind(status.to_string())
            .bind(reason)
            .bind(limited_str)
            .bind(reset_str)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn enable_account(&self, id: i64) -> Result<(), AppError> {
        let q = format!(
            r#"UPDATE accounts SET status='active', disable_reason='',
                rate_limited_at=NULL, rate_limit_reset_at=NULL, updated_at={}
            WHERE id=$1"#,
            self.now_expr()
        );
        sqlx::query(&q).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn clear_rate_limit(&self, id: i64) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET rate_limited_at=NULL, rate_limit_reset_at=NULL, updated_at={} WHERE id=$1",
            self.now_expr()
        );
        sqlx::query(&q).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<(), AppError> {
        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_by_id(&self, id: i64) -> Result<Account, AppError> {
        let row: AnyRow = sqlx::query(&format!(
            "SELECT {} FROM accounts WHERE id=$1",
            self.select_account_cols()
        ))
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(Self::row_to_account(&row))
    }

    pub async fn list(&self) -> Result<Vec<Account>, AppError> {
        let rows: Vec<AnyRow> = sqlx::query(&format!(
            "SELECT {} FROM accounts ORDER BY priority ASC, id ASC",
            self.select_account_cols()
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(Self::row_to_account).collect())
    }

    pub async fn count(&self) -> Result<i64, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
        Ok(count)
    }

    pub async fn list_paged(&self, page: i64, page_size: i64) -> Result<Vec<Account>, AppError> {
        let offset = (page - 1) * page_size;
        let q = format!(
            "SELECT {} FROM accounts ORDER BY priority ASC, id ASC LIMIT $1 OFFSET $2",
            self.select_account_cols()
        );
        let rows: Vec<AnyRow> = sqlx::query(&q)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::row_to_account).collect())
    }

    pub async fn update_usage(&self, id: i64, usage_data: &str) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET usage_data={}, usage_fetched_at={}, updated_at={} WHERE id=$3",
            self.jsonb(1),
            self.nullable_ts(2),
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(usage_data)
            .bind(self.fmt_time(Utc::now()))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn increment_telemetry_count(&self, id: i64, delta: i64) -> Result<(), AppError> {
        let q = format!(
            "UPDATE accounts SET telemetry_count = telemetry_count + $1, updated_at={} WHERE id=$2",
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_schedulable(&self) -> Result<Vec<Account>, AppError> {
        let q = format!(
            r#"SELECT {} FROM accounts
            WHERE status='active'
              AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at < {})
            ORDER BY priority ASC, id ASC"#,
            self.select_account_cols(),
            self.now_expr()
        );
        let rows: Vec<AnyRow> = sqlx::query(&q).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::row_to_account).collect())
    }
}

const ACCOUNT_COLS: &str = r#"id, name, email, status, token, auth_type, access_token, refresh_token,
    oauth_expires_at, oauth_refreshed_at, auth_error, proxy_url, device_id,
    canonical_env, canonical_prompt_env, canonical_process,
    billing_mode, account_uuid, organization_uuid, subscription_type,
    concurrency, priority, rate_limited_at, rate_limit_reset_at,
    disable_reason, auto_telemetry, telemetry_count,
    warmup_enabled, next_warmup_at, last_warmup_at, last_warmup_status,
    last_warmup_message, warmup_retry_count,
    usage_data, usage_fetched_at, created_at, updated_at"#;

const ACCOUNT_COLS_PG_TEXT: &str = r#"id, name, email, status, token, auth_type, access_token, refresh_token,
    oauth_expires_at::text AS oauth_expires_at, oauth_refreshed_at::text AS oauth_refreshed_at,
    auth_error, proxy_url, device_id,
    canonical_env::text AS canonical_env, canonical_prompt_env::text AS canonical_prompt_env,
    canonical_process::text AS canonical_process,
    billing_mode, account_uuid, organization_uuid, subscription_type,
    concurrency, priority, rate_limited_at::text AS rate_limited_at,
    rate_limit_reset_at::text AS rate_limit_reset_at,
    disable_reason, auto_telemetry, telemetry_count,
    warmup_enabled, next_warmup_at::text AS next_warmup_at,
    last_warmup_at::text AS last_warmup_at, last_warmup_status,
    last_warmup_message, warmup_retry_count,
    usage_data::text AS usage_data, usage_fetched_at::text AS usage_fetched_at,
    created_at::text AS created_at, updated_at::text AS updated_at"#;

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store(driver: &str) -> AccountStore {
        sqlx::any::install_default_drivers();
        let tmp = std::env::temp_dir().join(format!("ccgw_unit_{}.db", rand::random::<u64>()));
        let dsn = format!("sqlite:{}?mode=rwc", tmp.display());
        let pool = AnyPool::connect(&dsn).await.expect("pool");
        AccountStore {
            pool,
            driver: driver.to_string(),
        }
    }

    #[tokio::test]
    async fn test_is_pg() {
        assert!(make_store("postgres").await.is_pg());
        assert!(!make_store("sqlite").await.is_pg());
    }

    #[tokio::test]
    async fn test_now_expr_sqlite() {
        let store = make_store("sqlite").await;
        assert_eq!(store.now_expr(), "strftime('%Y-%m-%dT%H:%M:%SZ','now')");
    }

    #[tokio::test]
    async fn test_now_expr_postgres() {
        let store = make_store("postgres").await;
        assert_eq!(store.now_expr(), "NOW()");
    }

    #[tokio::test]
    async fn test_fmt_time_iso8601() {
        let store = make_store("sqlite").await;
        let t = chrono::NaiveDate::from_ymd_opt(2026, 4, 9)
            .unwrap()
            .and_hms_opt(12, 30, 45)
            .unwrap()
            .and_utc();
        assert_eq!(store.fmt_time(t), "2026-04-09T12:30:45Z");
    }

    #[test]
    fn test_parse_datetime_str_sqlite_iso8601() {
        let parsed = AccountStore::parse_datetime_str("2026-04-09T12:30:45Z").unwrap();
        let expected = chrono::NaiveDate::from_ymd_opt(2026, 4, 9)
            .unwrap()
            .and_hms_opt(12, 30, 45)
            .unwrap()
            .and_utc();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_parse_datetime_str_rfc3339_fractional() {
        let parsed = AccountStore::parse_datetime_str("2026-04-09T12:30:45.123456+00:00").unwrap();
        assert_eq!(parsed.timestamp(), 1775737845);
        assert_eq!(parsed.timestamp_subsec_micros(), 123456);
    }

    #[test]
    fn test_parse_datetime_str_postgres_text_format() {
        let parsed = AccountStore::parse_datetime_str("2026-04-09 12:30:45.123456+00:00").unwrap();
        assert_eq!(parsed.timestamp(), 1775737845);
        assert_eq!(parsed.timestamp_subsec_micros(), 123456);
    }

    // ─── nullable_ts() helper ───

    #[tokio::test]
    async fn test_nullable_ts_sqlite() {
        let store = make_store("sqlite").await;
        assert_eq!(store.nullable_ts(3), "$3");
    }

    #[tokio::test]
    async fn test_nullable_ts_postgres() {
        let store = make_store("postgres").await;
        assert_eq!(store.nullable_ts(3), "$3::TEXT::TIMESTAMPTZ");
    }

    // ─── jsonb() helper ───

    #[tokio::test]
    async fn test_jsonb_sqlite() {
        let store = make_store("sqlite").await;
        assert_eq!(store.jsonb(1), "$1");
    }

    #[tokio::test]
    async fn test_jsonb_postgres() {
        let store = make_store("postgres").await;
        assert_eq!(store.jsonb(1), "$1::JSONB");
    }

    // ─── nullable() helper ───

    #[tokio::test]
    async fn test_nullable_sqlite() {
        let store = make_store("sqlite").await;
        assert_eq!(store.nullable(5), "$5");
    }

    #[tokio::test]
    async fn test_nullable_postgres() {
        let store = make_store("postgres").await;
        assert_eq!(store.nullable(5), "$5::TEXT");
    }

    // ─── select_account_cols() ───

    #[tokio::test]
    async fn test_select_account_cols_sqlite() {
        let store = make_store("sqlite").await;
        assert_eq!(store.select_account_cols(), ACCOUNT_COLS);
    }

    #[tokio::test]
    async fn test_select_account_cols_postgres() {
        let store = make_store("postgres").await;
        assert_eq!(store.select_account_cols(), ACCOUNT_COLS_PG_TEXT);
    }
}
