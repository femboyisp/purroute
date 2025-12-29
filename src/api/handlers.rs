use super::models::{CreateUserRequest, ErrorResponse, MessageResponse, ResetBandwidthRequest, UserResponse, UsersListResponse};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tokio_postgres::Client;

pub type DbClient = Arc<Client>;

pub async fn create_user(
    State(db): State<DbClient>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username and password cannot be empty".to_string(),
            }),
        ));
    }

    if payload.username.len() < 3 || payload.username.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username must be between 3 and 32 characters".to_string(),
            }),
        ));
    }

    if payload.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must be at least 8 characters".to_string(),
            }),
        ));
    }

    if payload.bandwidth_limit <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Bandwidth limit must be greater than 0".to_string(),
            }),
        ));
    }

    // Check if username already exists
    let check_query = "SELECT account FROM public.accounts WHERE username = $1";
    match db.query_opt(check_query, &[&payload.username]).await {
        Ok(Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Username already exists".to_string(),
                }),
            ));
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Database error checking username: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            ));
        }
    }

    // Insert user into accounts table
    let insert_query = "
        INSERT INTO public.accounts (username, password, bandwidth_limit)
        VALUES ($1, $2, $3)
        RETURNING account, registered
    ";

    let row = match db
        .query_one(
            insert_query,
            &[&payload.username, &payload.password, &payload.bandwidth_limit],
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Database error inserting user: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create user".to_string(),
                }),
            ));
        }
    };

    let account_id: i64 = row.get(0);
    let registered: chrono::NaiveDateTime = row.get(1);

    // Initialize user stats
    let stats_query = "
        INSERT INTO public.user_stats (id, total_connections, succeeded_connections, failed_connections, total_bytes_in, total_bytes_out)
        VALUES ($1, 0, 0, 0, 0, 0)
    ";

    if let Err(e) = db.execute(stats_query, &[&account_id]).await {
        eprintln!("Database error creating user stats: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to initialize user statistics".to_string(),
            }),
        ));
    }

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            username: payload.username,
            account_id,
            bandwidth_limit: Some(payload.bandwidth_limit),
            bandwidth_used: 0,
            registered: registered.format("%Y-%m-%dT%H:%M:%S").to_string(),
        }),
    ))
}

pub async fn delete_user(
    State(db): State<DbClient>,
    Path(username): Path<String>,
) -> Result<(StatusCode, Json<MessageResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Get account ID first
    let query = "SELECT account FROM public.accounts WHERE username = $1";
    let account_id: i64 = match db.query_opt(query, &[&username]).await {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            ));
        }
        Err(e) => {
            eprintln!("Database error finding user: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            ));
        }
    };

    // Delete user stats
    let delete_stats = "DELETE FROM public.user_stats WHERE id = $1";
    if let Err(e) = db.execute(delete_stats, &[&account_id]).await {
        eprintln!("Database error deleting user stats: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete user statistics".to_string(),
            }),
        ));
    }

    // Delete account
    let delete_account = "DELETE FROM public.accounts WHERE username = $1";
    if let Err(e) = db.execute(delete_account, &[&username]).await {
        eprintln!("Database error deleting account: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete user".to_string(),
            }),
        ));
    }

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "User deleted successfully".to_string(),
        }),
    ))
}

pub async fn get_user(
    State(db): State<DbClient>,
    Path(username): Path<String>,
) -> Result<Json<UserResponse>, (StatusCode, Json<ErrorResponse>)> {
    let query = "
        SELECT
            a.account,
            a.username,
            a.bandwidth_limit,
            a.registered,
            COALESCE(s.total_bytes_in, 0) + COALESCE(s.total_bytes_out, 0) AS bandwidth_used
        FROM public.accounts a
        LEFT JOIN public.user_stats s ON a.account = s.id
        WHERE a.username = $1
    ";

    match db.query_opt(query, &[&username]).await {
        Ok(Some(row)) => {
            let account_id: i64 = row.get(0);
            let username: String = row.get(1);
            let bandwidth_remaining: i64 = row.get(2);
            let registered: chrono::NaiveDateTime = row.get(3);
            let bandwidth_used: i64 = row.get(4);

            Ok(Json(UserResponse {
                username,
                account_id,
                bandwidth_limit: Some(bandwidth_remaining),
                bandwidth_used,
                registered: registered.format("%Y-%m-%dT%H:%M:%S").to_string(),
            }))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".to_string(),
            }),
        )),
        Err(e) => {
            eprintln!("Database error getting user: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            ))
        }
    }
}

pub async fn list_users(
    State(db): State<DbClient>,
) -> Result<Json<UsersListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let query = "
        SELECT
            a.account,
            a.username,
            a.bandwidth_limit,
            a.registered,
            COALESCE(s.total_bytes_in, 0) + COALESCE(s.total_bytes_out, 0) AS bandwidth_used
        FROM public.accounts a
        LEFT JOIN public.user_stats s ON a.account = s.id
        ORDER BY a.registered DESC
    ";

    match db.query(query, &[]).await {
        Ok(rows) => {
            let users: Vec<UserResponse> = rows
                .iter()
                .map(|row| {
                    let account_id: i64 = row.get(0);
                    let username: String = row.get(1);
                    let bandwidth_remaining: i64 = row.get(2);
                    let registered: chrono::NaiveDateTime = row.get(3);
                    let bandwidth_used: i64 = row.get(4);

                    UserResponse {
                        username,
                        account_id,
                        bandwidth_limit: Some(bandwidth_remaining),
                        bandwidth_used,
                        registered: registered.format("%Y-%m-%dT%H:%M:%S").to_string(),
                    }
                })
                .collect();

            Ok(Json(UsersListResponse { users }))
        }
        Err(e) => {
            eprintln!("Database error listing users: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            ))
        }
    }
}

pub async fn reset_user_bandwidth(
    State(db): State<DbClient>,
    Path(username): Path<String>,
    Json(payload): Json<ResetBandwidthRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if payload.bandwidth_limit <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Bandwidth limit must be greater than 0".to_string(),
            }),
        ));
    }

    // Check if user exists
    let check_query = "SELECT account FROM public.accounts WHERE username = $1";
    match db.query_opt(check_query, &[&username]).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            ));
        }
        Err(e) => {
            eprintln!("Database error finding user: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                }),
            ));
        }
    }

    // Set new bandwidth limit
    let reset_query = "
        UPDATE public.accounts
        SET bandwidth_limit = $1
        WHERE username = $2
    ";

    if let Err(e) = db.execute(reset_query, &[&payload.bandwidth_limit, &username]).await {
        eprintln!("Database error resetting bandwidth: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reset bandwidth".to_string(),
            }),
        ));
    }

    Ok(Json(MessageResponse {
        message: format!("Bandwidth set to {} bytes for user: {}", payload.bandwidth_limit, username),
    }))
}
