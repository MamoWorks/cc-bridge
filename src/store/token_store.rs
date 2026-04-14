use chrono::{DateTime, Utc};
use sqlx::AnyPool;

use crate::error::AppError;
use crate::model::api_token::ApiToken;

pub struct TokenStore {
    pool: AnyPool,
    driver: String,
}

const TOKEN_COLS: &str =
    "id, name, token, allowed_accounts, blocked_accounts, status, created_at, updated_at";

const TOKEN_COLS_PG_TEXT: &str =
    "id, name, token, allowed_accounts, blocked_accounts, status, created_at::text AS created_at, updated_at::text AS updated_at";

impl TokenStore {
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

    fn select_token_cols(&self) -> &'static str {
        if self.is_pg() {
            TOKEN_COLS_PG_TEXT
        } else {
            TOKEN_COLS
        }
    }

    fn fmt_time(&self, t: DateTime<Utc>) -> String {
        t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn row_to_token(&self, row: &sqlx::any::AnyRow) -> ApiToken {
        use sqlx::Row;
        let parse_time = |col: &str| -> DateTime<Utc> {
            if let Ok(s) = row.try_get::<String, _>(col) {
                s.parse().unwrap_or_else(|_| Utc::now())
            } else {
                Utc::now()
            }
        };
        ApiToken {
            id: row.try_get::<i64, _>("id").unwrap_or_default(),
            name: row.try_get::<String, _>("name").unwrap_or_default(),
            token: row.try_get::<String, _>("token").unwrap_or_default(),
            allowed_accounts: row
                .try_get::<String, _>("allowed_accounts")
                .unwrap_or_default(),
            blocked_accounts: row
                .try_get::<String, _>("blocked_accounts")
                .unwrap_or_default(),
            status: row
                .try_get::<String, _>("status")
                .unwrap_or_else(|_| "active".into())
                .into(),
            created_at: parse_time("created_at"),
            updated_at: parse_time("updated_at"),
        }
    }

    /// 创建令牌
    pub async fn create(&self, t: &mut ApiToken) -> Result<(), AppError> {
        let q = format!(
            "INSERT INTO api_tokens (name, token, allowed_accounts, blocked_accounts, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, {now}, {now})",
            now = self.now_expr()
        );
        let result = sqlx::query(&q)
            .bind(&t.name)
            .bind(&t.token)
            .bind(&t.allowed_accounts)
            .bind(&t.blocked_accounts)
            .bind(t.status.to_string())
            .execute(&self.pool)
            .await?;
        t.id = result.last_insert_id().unwrap_or(0) as i64;
        Ok(())
    }

    /// 更新令牌
    pub async fn update(&self, t: &ApiToken) -> Result<(), AppError> {
        let q = format!(
            "UPDATE api_tokens SET name=$1, allowed_accounts=$2, blocked_accounts=$3, status=$4, updated_at={} WHERE id=$5",
            self.now_expr()
        );
        sqlx::query(&q)
            .bind(&t.name)
            .bind(&t.allowed_accounts)
            .bind(&t.blocked_accounts)
            .bind(t.status.to_string())
            .bind(t.id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 删除令牌
    pub async fn delete(&self, id: i64) -> Result<(), AppError> {
        sqlx::query("DELETE FROM api_tokens WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 按 ID 查询
    pub async fn get_by_id(&self, id: i64) -> Result<ApiToken, AppError> {
        let q = format!("SELECT {} FROM api_tokens WHERE id=$1", self.select_token_cols());
        let row = sqlx::query(&q)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AppError::NotFound)?;
        Ok(self.row_to_token(&row))
    }

    /// 按 token 值查询活跃令牌
    pub async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, AppError> {
        let q = format!(
            "SELECT {} FROM api_tokens WHERE token=$1 AND status='active'",
            self.select_token_cols()
        );
        let row = sqlx::query(&q)
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| self.row_to_token(&r)))
    }

    /// 列出所有令牌
    pub async fn list(&self) -> Result<Vec<ApiToken>, AppError> {
        let q = format!(
            "SELECT {} FROM api_tokens ORDER BY created_at DESC",
            self.select_token_cols()
        );
        let rows = sqlx::query(&q).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| self.row_to_token(r)).collect())
    }

    /// 分页列出令牌
    pub async fn list_paged(&self, page: i64, page_size: i64) -> Result<Vec<ApiToken>, AppError> {
        let offset = (page - 1) * page_size;
        let q = format!(
            "SELECT {} FROM api_tokens ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            self.select_token_cols()
        );
        let rows = sqlx::query(&q)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| self.row_to_token(r)).collect())
    }

    /// 计数
    pub async fn count(&self) -> Result<i64, AppError> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM api_tokens")
            .fetch_one(&self.pool)
            .await?;
        use sqlx::Row;
        Ok(row.get::<i64, _>("cnt"))
    }
}
