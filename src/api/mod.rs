pub mod handlers;
pub mod middleware;
pub mod models;

use crate::config::ApiConfig;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::Client;

use middleware::ApiKeyValidator;

pub async fn run_api_server(
    config: ApiConfig,
    db_client: Arc<Client>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create API key validator
    let validator = Arc::new(ApiKeyValidator::new(config.api_key.clone()));

    // Build router
    let app = Router::new()
        .route("/users", post(handlers::create_user))
        .route("/users", get(handlers::list_users))
        .route("/users/{username}", get(handlers::get_user))
        .route("/users/{username}", delete(handlers::delete_user))
        .route("/users/{username}/reset", post(handlers::reset_user_bandwidth))
        .layer(axum_middleware::from_fn(move |headers, request, next| {
            let validator = Arc::clone(&validator);
            middleware::api_key_middleware(validator, headers, request, next)
        }))
        .with_state(db_client);

    // Bind and serve
    let listener = TcpListener::bind(&config.listen).await?;
    println!("API server listening on: {}", config.listen);

    axum::serve(listener, app).await?;

    Ok(())
}
