use crate::error::AppError;
use crate::model::account::CanonicalEnvData;
use crate::tlsfp::make_request_client;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

const OAUTH_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
];

#[derive(Debug, Clone)]
pub struct RefreshedOAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct OAuthRefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
}

/// 通过轻量级 API 调用验证 Setup Token。
pub struct TokenTester;

impl TokenTester {
    pub fn new() -> Self {
        Self
    }

    /// 通过发送最小消息请求验证 Setup Token 有效性。
    pub async fn test_token(
        &self,
        token: &str,
        proxy_url: &str,
        canonical_env: &Value,
    ) -> Result<(), AppError> {
        self.test_token_with_message(token, proxy_url, canonical_env, "hi")
            .await
    }

    pub async fn test_token_with_message(
        &self,
        token: &str,
        proxy_url: &str,
        canonical_env: &Value,
        message: &str,
    ) -> Result<(), AppError> {
        let env: CanonicalEnvData =
            serde_json::from_value(canonical_env.clone()).unwrap_or_default();
        let version = if env.version.is_empty() {
            "2.1.81"
        } else {
            &env.version
        };
        let stainless_os = match env.platform.as_str() {
            "darwin" => "Mac OS X",
            "win32" => "Windows",
            _ => "Linux",
        };

        let body = serde_json::json!({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": message}]
        });

        let client = make_request_client(proxy_url);

        let resp = client
            .post("https://api.anthropic.com/v1/messages?beta=true")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("anthropic-version", "2023-06-01")
            .header(
                "anthropic-beta",
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05",
            )
            .header("anthropic-dangerous-direct-browser-access", "true")
            .header(
                "User-Agent",
                format!("claude-cli/{} (external, cli)", version),
            )
            .header("x-app", "cli")
            .header("accept-encoding", "gzip, deflate, br, zstd")
            .header("X-Stainless-Lang", "js")
            .header("X-Stainless-Package-Version", "0.70.0")
            .header("X-Stainless-OS", stainless_os)
            .header("X-Stainless-Arch", &env.arch)
            .header("X-Stainless-Runtime", "node")
            .header("X-Stainless-Runtime-Version", &env.node_version)
            .header("X-Stainless-Retry-Count", "0")
            .header("X-Stainless-Timeout", "600")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("request failed: {:?}", e)))?;

        if resp.status() != 200 {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "token test failed: status {} {}",
                status, text
            )));
        }
        Ok(())
    }
}

/// 使用 refresh token 刷新 OAuth access token。
pub async fn refresh_oauth_token(
    refresh_token: &str,
    proxy_url: &str,
) -> Result<RefreshedOAuthTokens, AppError> {
    let client = make_request_client(proxy_url);
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "scope": OAUTH_SCOPES.join(" "),
    });

    let resp = client
        .post(OAUTH_TOKEN_URL)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("oauth refresh request failed: {}", e)))?;

    if resp.status() != 200 {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "oauth refresh failed: status {} {}",
            status, text
        )));
    }

    let data: OAuthRefreshResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("oauth refresh parse failed: {}", e)))?;

    let expires_in = if data.expires_in > 0 {
        data.expires_in
    } else {
        3600
    };
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in);

    Ok(RefreshedOAuthTokens {
        access_token: data.access_token,
        refresh_token: if data.refresh_token.is_empty() {
            refresh_token.to_string()
        } else {
            data.refresh_token
        },
        expires_at,
    })
}

/// 从 Anthropic OAuth API 获取账号用量数据。
pub async fn fetch_usage(token: &str, proxy_url: &str) -> Result<Value, AppError> {
    let client = make_request_client(proxy_url);

    let resp = client
        .get("https://api.anthropic.com/api/oauth/usage")
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("User-Agent", "claude-code/2.1.81")
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("usage request failed: {}", e)))?;

    let status = resp.status();
    if status != 200 {
        let text = resp.text().await.unwrap_or_default();
        return Err(match status.as_u16() {
            401 | 403 => AppError::BadRequest(format!(
                "usage fetch failed: status {} — token may be expired or invalid: {}",
                status, text
            )),
            429 => AppError::TooManyRequests(format!(
                "usage endpoint rate limited (429), try again later: {}",
                text
            )),
            _ => AppError::Internal(format!("usage fetch failed: status {} {}", status, text)),
        });
    }

    let data: Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("usage parse failed: {}", e)))?;
    Ok(data)
}
