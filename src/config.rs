use std::env;
use std::path::Path;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: Option<RedisConfig>,
    pub admin: AdminConfig,
    pub log_level: String,
    pub usage_poll_interval: Duration,
    pub warmup: WarmupConfig,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub driver: Option<String>,
    pub dsn: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

#[derive(Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub db: i64,
}

#[derive(Clone)]
pub struct AdminConfig {
    pub password: String,
}

#[derive(Clone)]
pub struct WarmupConfig {
    pub enabled: bool,
    pub base_utc_hour: u32,
    pub jitter_minutes: i64,
    pub max_retries: u32,
    pub retry_backoff_secs: u64,
    pub account_gap_secs: u64,
    pub poll_interval_secs: u64,
    pub greetings_file: String,
}

impl DatabaseConfig {
    pub fn driver(&self) -> String {
        self.driver.clone().unwrap_or_else(|| "sqlite".into())
    }

    pub fn has_explicit_dsn(&self) -> bool {
        self.dsn
            .as_ref()
            .map(|dsn| !dsn.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn dsn(&self) -> String {
        if let Some(dsn) = self.dsn.as_ref().filter(|dsn| !dsn.trim().is_empty()) {
            return dsn.clone();
        }
        if self.driver() == "sqlite" {
            return "data/claude-code-gateway.db".into();
        }
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode=disable",
            self.user, self.password, self.host, self.port, self.dbname
        )
    }

    pub fn admin_dsn(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/postgres?sslmode=disable",
            self.user, self.password, self.host, self.port
        )
    }
}

impl Config {
    pub fn load() -> Self {
        dotenvy::dotenv().ok();

        let redis = env::var("REDIS_HOST").ok().map(|host| RedisConfig {
            host,
            port: env::var("REDIS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6379),
            password: env::var("REDIS_PASSWORD").unwrap_or_default(),
            db: env::var("REDIS_DB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        });

        Config {
            server: ServerConfig {
                port: env::var("SERVER_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5674),
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
                tls_cert: env::var("TLS_CERT_FILE").ok(),
                tls_key: env::var("TLS_KEY_FILE").ok(),
            },
            database: DatabaseConfig {
                driver: env_var("DATABASE_DRIVER"),
                dsn: env_var("DATABASE_DSN").filter(|dsn| !dsn.trim().is_empty()),
                host: env_var("DATABASE_HOST").unwrap_or_else(default_postgres_host),
                port: env::var("DATABASE_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(5432),
                user: env_var("DATABASE_USER")
                    .or_else(|| env_var("POSTGRES_USER"))
                    .unwrap_or_else(|| "postgres".into()),
                password: env::var("DATABASE_PASSWORD")
                    .ok()
                    .or_else(|| env::var("POSTGRES_PASSWORD").ok())
                    .unwrap_or_default(),
                dbname: env_var("DATABASE_DBNAME")
                    .or_else(|| env_var("POSTGRES_DB"))
                    .unwrap_or_else(|| "claude_code_gateway".into()),
            },
            redis,
            admin: AdminConfig {
                password: env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".into()),
            },
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            usage_poll_interval: Duration::from_secs(
                env::var("USAGE_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300),
            ),
            warmup: WarmupConfig {
                enabled: env::var("WARMUP_ENABLED")
                    .ok()
                    .map(|v| v != "false")
                    .unwrap_or(false),
                base_utc_hour: env::var("WARMUP_UTC_HOUR")
                    .ok()
                    .and_then(|v| v.parse::<u32>().ok())
                    .map(|v| v.min(23))
                    .unwrap_or(23),
                jitter_minutes: env::var("WARMUP_JITTER_MINUTES")
                    .ok()
                    .and_then(|v| v.parse::<i64>().ok())
                    .map(|v| v.clamp(0, 720))
                    .unwrap_or(30),
                max_retries: env::var("WARMUP_MAX_RETRIES")
                    .ok()
                    .and_then(|v| v.parse::<u32>().ok())
                    .map(|v| v.min(10))
                    .unwrap_or(2),
                retry_backoff_secs: env::var("WARMUP_RETRY_BACKOFF_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(300),
                account_gap_secs: env::var("WARMUP_ACCOUNT_GAP_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(45),
                poll_interval_secs: env::var("WARMUP_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60),
                greetings_file: env::var("WARMUP_GREETINGS_FILE")
                    .unwrap_or_else(|_| "data/warmup_greetings.txt".into()),
            },
        }
    }
}

fn env_var(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn default_postgres_host() -> String {
    if Path::new("/.dockerenv").exists() {
        "postgres".into()
    } else {
        "127.0.0.1".into()
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseConfig;

    #[test]
    fn explicit_dsn_takes_priority() {
        let config = DatabaseConfig {
            driver: Some("postgres".into()),
            dsn: Some("postgres://db.example/app".into()),
            host: "127.0.0.1".into(),
            port: 5432,
            user: "postgres".into(),
            password: "secret".into(),
            dbname: "gateway".into(),
        };

        assert!(config.has_explicit_dsn());
        assert_eq!(config.dsn(), "postgres://db.example/app");
    }

    #[test]
    fn admin_dsn_targets_postgres_database() {
        let config = DatabaseConfig {
            driver: Some("postgres".into()),
            dsn: None,
            host: "127.0.0.1".into(),
            port: 5432,
            user: "postgres".into(),
            password: "secret".into(),
            dbname: "gateway".into(),
        };

        assert_eq!(
            config.admin_dsn(),
            "postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable"
        );
    }
}
