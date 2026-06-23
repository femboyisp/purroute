//! Purroute — an auto-detecting proxy router.
//!
//! Listens on a local address, detects the inbound proxy protocol (SOCKS5,
//! SOCKS4/4a, HTTP, HTTPS-CONNECT) from the first bytes of each connection, and
//! forwards upstream through a single proxy or a multi-hop chain. Per-user auth
//! and bandwidth limits come from a pluggable backend: inline `[[user]]` blocks
//! (no database) or PostgreSQL. A local-only Prometheus `/metrics` endpoint is
//! exposed when `[router].metrics_listen` is set.

use std::sync::Arc;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Duration;
use tokio_postgres::{Client, Config as PgConfig, NoTls};

mod auth;
mod config;
mod protocol;
mod protocols;
mod stats;

use crate::{
    auth::{AuthBackend, PostgresAuthBackend, StaticAuthBackend},
    config::Config,
    protocols::ProxyServer,
    stats::{display::StatsDisplay, get_global_stats},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load("config.toml")?;
    let router_config = config.router;
    let proxies = config.proxy;
    let chains = config.chain;
    let global_stats = get_global_stats();

    // Install the Prometheus recorder up front so counters exist immediately.
    let metrics_handle = PrometheusBuilder::new().install_recorder().ok();

    // Pick the account backend. With a `[database]` section we use PostgreSQL;
    // otherwise we run database-less from inline `[[user]]` blocks.
    let auth_enabled = router_config.auth.unwrap_or(false);
    let (auth_backend, db_client): (Arc<dyn AuthBackend>, Option<Arc<Client>>) =
        if let Some(db_config) = config.database {
            let mut builder = PgConfig::new();
            builder
                .host(&db_config.host)
                .port(db_config.port)
                .user(db_config.user.as_deref().unwrap_or(""))
                .dbname(&db_config.dbname)
                .password(db_config.password.as_deref().unwrap_or(""));

            let (client, connection) = builder.connect(NoTls).await?;
            let client = Arc::new(client);
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Database connection error: {e}");
                }
            });

            PostgresAuthBackend::initialize_schema(&client).await?;
            if let Err(e) = global_stats.load_from_db(&client).await {
                eprintln!("Failed to load stats from database: {e}");
            }

            let backend = Arc::new(PostgresAuthBackend::new(Arc::clone(&client)));
            (backend, Some(client))
        } else {
            if auth_enabled && config.user.is_empty() {
                return Err(
                    "auth is enabled but no [database] section or [[user]] blocks are configured"
                        .into(),
                );
            }
            let backend = Arc::new(StaticAuthBackend::new(&config.user));
            (backend, None)
        };

    let stats_display = Arc::new(StatsDisplay::new(
        Arc::clone(&global_stats),
        Duration::from_secs(2),
        db_client.clone(),
    ));

    let router_config_clone = router_config.clone();

    let server = ProxyServer::new(
        proxies,
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
            db_client.clone(),
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
