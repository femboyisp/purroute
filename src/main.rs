//! Purroute — an auto-detecting proxy router.
//!
//! Listens on a local address, detects the inbound proxy protocol (SOCKS5,
//! SOCKS4/4a, HTTP, HTTPS-CONNECT) from the first bytes of each connection, and
//! forwards upstream through a single proxy or a multi-hop chain. Per-user auth
//! and bandwidth limits are backed by PostgreSQL. A local-only Prometheus
//! `/metrics` endpoint is exposed when `[router].metrics_listen` is set.

use std::sync::Arc;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Duration;
use tokio_postgres::{Config, NoTls};

mod auth;
mod config;
mod protocol;
mod protocols;
mod stats;

use crate::{
    auth::PostgresAuthBackend,
    config::load_config,
    protocols::ProxyServer,
    stats::{display::StatsDisplay, get_global_stats},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (router_config, proxy_chain, chains, db_config) = load_config("config.toml")?;
    let global_stats = get_global_stats();

    // Install the Prometheus recorder up front so counters exist immediately.
    let metrics_handle = PrometheusBuilder::new().install_recorder().ok();

    // Initialize the database connection.
    let db_config = db_config.ok_or("Database configuration is missing")?;
    let mut db_config_builder = Config::new();
    db_config_builder
        .host(&db_config.host)
        .port(db_config.port)
        .user(db_config.user.as_deref().unwrap_or(""))
        .dbname(&db_config.dbname)
        .password(db_config.password.as_deref().unwrap_or(""));

    let (db_client, db_connection) = db_config_builder.connect(NoTls).await?;

    let db_client = Arc::new(db_client);
    tokio::spawn(async move {
        if let Err(e) = db_connection.await {
            eprintln!("Database connection error: {e}");
        }
    });

    // Initialize the router's minimal schema (idempotent).
    PostgresAuthBackend::initialize_schema(&db_client).await?;

    // Load stats from the database if available.
    if let Err(e) = global_stats.load_from_db(&db_client).await {
        eprintln!("Failed to load stats from database: {e}");
    }

    let stats_display = Arc::new(StatsDisplay::new(
        Arc::clone(&global_stats),
        Duration::from_secs(2),
        Arc::clone(&db_client),
    ));

    let router_config_clone = router_config.clone();

    let auth_backend = Arc::new(PostgresAuthBackend::new(Arc::clone(&db_client)));

    let server = ProxyServer::new(
        proxy_chain,
        chains,
        Arc::clone(&stats_display),
        Arc::new(router_config.clone()),
        auth_backend,
    );

    // Run the stats display in a separate task.
    let display_handle = tokio::spawn({
        let display = StatsDisplay::new(
            Arc::clone(&global_stats),
            Duration::from_secs(2),
            Arc::clone(&db_client),
        );
        async move {
            if let Err(e) = display.run(Arc::new(router_config_clone)).await {
                eprintln!("Stats display error: {e}");
            }
        }
    });

    // Serve the local-only Prometheus endpoint if configured.
    if let (Some(addr), Some(handle)) = (router_config.metrics_listen.clone(), metrics_handle) {
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(&addr, handle).await {
                eprintln!("Metrics server error: {e}");
            }
        });
    }

    // Run the proxy server (blocks).
    server.run(router_config.listen.parse()?).await?;

    display_handle.await?;
    Ok(())
}

/// Minimal HTTP server that renders the Prometheus registry on any request.
///
/// Intentionally tiny (no web framework) and meant to be bound to a local-only
/// address such as `127.0.0.1:9100`.
async fn serve_metrics(
    addr: &str,
    handle: PrometheusHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut socket, _peer) = listener.accept().await?;
        let body = handle.render();
        tokio::spawn(async move {
            // Drain the request line/headers; we don't route on them.
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        });
    }
}
