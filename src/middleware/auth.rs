use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::store::token_store::TokenStore;

/// 从请求头提取 API Key（x-api-key 或 Authorization: Bearer）
pub fn extract_key(req: &Request) -> String {
    let headers = req.headers();
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

fn err_response(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

/// 管理后台密码认证
pub async fn admin_auth(
    password: String,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let key = extract_key(&req);
    if key.is_empty() || key.as_bytes().ct_eq(password.as_bytes()).unwrap_u8() != 1 {
        return Err(err_response("invalid password"));
    }
    Ok(next.run(req).await)
}

/// 网关令牌认证（从数据库查询）
/// 验证通过后将 ApiToken 存入请求扩展供后续 handler 使用。
pub async fn gateway_auth(
    token_store: Arc<TokenStore>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let key = extract_key(&req);
    if key.is_empty() {
        return Err(err_response("missing api key"));
    }

    let token = token_store
        .get_by_token(&key)
        .await
        .map_err(|_| err_response("authentication failed"))?
        .ok_or_else(|| err_response("invalid api key"))?;

    req.extensions_mut().insert(token);
    Ok(next.run(req).await)
}
