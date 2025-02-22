use std::sync::Arc;
/// Purroute - A simple proxy server
/// This is a simple proxy server that supports HTTP, HTTPS, and SOCKS5 protocols.
/// It reads the configuration from a TOML file and listens on the specified address.
/// It forwards the requests to the proxy servers in the chain.
/// The proxy server supports basic authentication for SOCKS5 and HTTP proxies.
/// The proxy server also tracks the number of bytes transferred and the number of active connections.
// src/main.rs
use tokio::time::Duration;
use tokio_postgres::{Config, NoTls};

mod config;
mod protocols;
mod stats;

use crate::{
    config::load_config,
    protocols::{Proxy, ProxyError, ProxyServer},
    stats::{display::StatsDisplay, get_global_stats},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (router_config, proxy_chain, db_config) = load_config("config.toml")?;
    let global_stats = get_global_stats();

    // Initialize the database connection
    let db_config = db_config.ok_or("Database configuration is missing")?;
    let mut db_config_builder = Config::new();
    db_config_builder
        .host(&db_config.host)
        .port(db_config.port)
        .user(&db_config.user)
        .password(&db_config.password)
        .dbname(&db_config.dbname);

    let (db_client, db_connection) = if db_config.tls {
        db_config_builder.connect(tokio_postgres::NoTls).await?
    } else {
        db_config_builder.connect(NoTls).await?
    };

    let db_client = Arc::new(db_client);
    tokio::spawn(async move {
        if let Err(e) = db_connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    // Load stats from the database if configured
    if let Err(e) = global_stats.load_from_db(&db_client).await {
        eprintln!("Failed to load stats from database: {}", e);
    }

    // Create stats display for the server
    let stats_display = Arc::new(StatsDisplay::new(
        Arc::clone(&global_stats),
        Duration::from_millis(1),
        Arc::clone(&db_client),
    ));

    let router_config_clone = router_config.clone();

    // Create the proxy server with logger
    let server = ProxyServer::new(
        proxy_chain,
        Arc::clone(&stats_display),
        Arc::new(router_config.clone()).into(),
    );

    // Run stats display in a separate task
    let display_handle = tokio::spawn({
        // Create a new display instance for the display task
        let display = StatsDisplay::new(
            Arc::clone(&global_stats),
            Duration::from_millis(1),
            Arc::clone(&db_client),
        );
        async move {
            if let Err(e) = display.run(router_config_clone.into()).await {
                eprintln!("Stats display error: {}", e);
            }
        }
    });

    // Run the proxy server
    server.run(router_config.listen.parse()?).await?;

    // Wait for display to finish
    let _ = display_handle.await?;

    Ok(())
}
