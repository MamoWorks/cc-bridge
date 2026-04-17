use sqlx::AnyPool;

use crate::error::AppError;

pub struct SettingsStore {
    pool: AnyPool,
}

impl SettingsStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        use sqlx::Row;

        let row = sqlx::query("SELECT value FROM settings WHERE key=$1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    pub async fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}
