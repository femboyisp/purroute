use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub bandwidth_limit: i64,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub username: String,
    pub account_id: i64,
    pub bandwidth_limit: Option<i64>,
    pub bandwidth_used: i64,
    pub registered: String,
}

#[derive(Debug, Serialize)]
pub struct UsersListResponse {
    pub users: Vec<UserResponse>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetBandwidthRequest {
    pub bandwidth_limit: i64,
}
