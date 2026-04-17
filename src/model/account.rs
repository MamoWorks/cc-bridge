use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod optional_timestamp_millis {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(dt) => serializer.serialize_i64(dt.timestamp_millis()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<i64>::deserialize(deserializer)?;
        value
            .map(|ms| {
                Utc.timestamp_millis_opt(ms)
                    .single()
                    .ok_or_else(|| serde::de::Error::custom("invalid timestamp millis"))
            })
            .transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Error,
    Disabled,
}

impl Default for AccountStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Error => write!(f, "error"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

impl From<String> for AccountStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            "active" => Self::Active,
            "error" => Self::Error,
            "disabled" => Self::Disabled,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BillingMode {
    Strip,
    Rewrite,
}

impl Default for BillingMode {
    fn default() -> Self {
        Self::Strip
    }
}

impl std::fmt::Display for BillingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strip => write!(f, "strip"),
            Self::Rewrite => write!(f, "rewrite"),
        }
    }
}

impl From<String> for BillingMode {
    fn from(s: String) -> Self {
        match s.as_str() {
            "rewrite" => Self::Rewrite,
            _ => Self::Strip,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccountAuthType {
    SetupToken,
    Oauth,
}

impl Default for AccountAuthType {
    fn default() -> Self {
        Self::SetupToken
    }
}

impl std::fmt::Display for AccountAuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetupToken => write!(f, "setup_token"),
            Self::Oauth => write!(f, "oauth"),
        }
    }
}

impl From<String> for AccountAuthType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "oauth" => Self::Oauth,
            _ => Self::SetupToken,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub status: AccountStatus,
    #[serde(default)]
    pub auth_type: AccountAuthType,
    #[serde(default)]
    pub setup_token: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default, with = "optional_timestamp_millis")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_refreshed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub auth_error: String,
    #[serde(default)]
    pub proxy_url: String,
    pub device_id: String,
    pub canonical_env: Value,
    #[serde(rename = "canonical_prompt_env")]
    pub canonical_prompt: Value,
    pub canonical_process: Value,
    pub billing_mode: BillingMode,
    /// OAuth account UUID（强烈推荐填写，用于遥测改写）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_uuid: Option<String>,
    /// OAuth organization UUID（强烈推荐填写，用于遥测改写）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_uuid: Option<String>,
    /// 订阅类型：max / pro / team / enterprise（强烈推荐填写，用于遥测改写）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_type: Option<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: i32,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limited_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_reset_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub disable_reason: String,
    /// 是否启用自动遥测。
    #[serde(default)]
    pub auto_telemetry: bool,
    /// 累计发送的遥测请求次数。
    #[serde(default)]
    pub telemetry_count: i64,
    #[serde(default)]
    pub warmup_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_warmup_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_warmup_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_warmup_status: String,
    #[serde(default)]
    pub last_warmup_message: String,
    #[serde(default)]
    pub warmup_retry_count: i32,
    #[serde(default)]
    pub usage_data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_fetched_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_concurrency() -> i32 {
    3
}
fn default_priority() -> i32 {
    50
}

impl Account {
    pub fn is_schedulable(&self) -> bool {
        if self.status != AccountStatus::Active {
            return false;
        }
        if let Some(reset) = self.rate_limit_reset_at {
            if Utc::now() < reset {
                return false;
            }
        }
        true
    }

    pub fn has_valid_oauth_access_token(&self, buffer_seconds: i64) -> bool {
        if self.auth_type != AccountAuthType::Oauth || self.access_token.is_empty() {
            return false;
        }
        self.expires_at
            .map(|expires_at| expires_at > Utc::now() + chrono::Duration::seconds(buffer_seconds))
            .unwrap_or(false)
    }
}

/// 存储 20+ 维度的环境指纹数据。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CanonicalEnvData {
    pub platform: String,
    pub platform_raw: String,
    pub arch: String,
    pub node_version: String,
    pub terminal: String,
    pub package_managers: String,
    pub runtimes: String,
    #[serde(default)]
    pub is_running_with_bun: bool,
    #[serde(default)]
    pub is_ci: bool,
    #[serde(default)]
    pub is_claubbit: bool,
    #[serde(default)]
    pub is_claude_code_remote: bool,
    #[serde(default)]
    pub is_local_agent_mode: bool,
    #[serde(default)]
    pub is_conductor: bool,
    #[serde(default)]
    pub is_github_action: bool,
    #[serde(default)]
    pub is_claude_code_action: bool,
    #[serde(default)]
    pub is_claude_ai_auth: bool,
    pub version: String,
    pub version_base: String,
    pub build_time: String,
    pub deployment_environment: String,
    pub vcs: String,
}

/// 系统提示词中的环境改写数据。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CanonicalPromptEnvData {
    pub platform: String,
    pub shell: String,
    pub os_version: String,
    pub working_dir: String,
}

/// 硬件指纹配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CanonicalProcessData {
    pub constrained_memory: i64,
    pub rss_range: [i64; 2],
    pub heap_total_range: [i64; 2],
    pub heap_used_range: [i64; 2],
    #[serde(default)]
    pub external_range: [i64; 2],
    #[serde(default)]
    pub array_buffers_range: [i64; 2],
}
