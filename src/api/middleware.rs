use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub struct ApiKeyValidator {
    api_key: String,
}

impl ApiKeyValidator {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }

    pub async fn validate(
        &self,
        headers: &HeaderMap,
    ) -> Result<(), StatusCode> {
        // Check X-API-Key header first
        if let Some(key) = headers.get("X-API-Key") {
            if let Ok(key_str) = key.to_str() {
                if key_str == self.api_key {
                    return Ok(());
                }
            }
        }

        // Check Authorization: Bearer header
        if let Some(auth) = headers.get("Authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    if token == self.api_key {
                        return Ok(());
                    }
                }
            }
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn api_key_middleware(
    validator: Arc<ApiKeyValidator>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    validator.validate(&headers).await?;
    Ok(next.run(request).await)
}
