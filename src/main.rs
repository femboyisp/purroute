use std::sync::Arc;
/// Purroute - A simple proxy server
/// This is a simple proxy server that supports HTTP, HTTPS, and SOCKS5 protocols.
/// It reads the configuration from a TOML file and listens on the specified address.
/// It forwards the requests to the proxy servers in the chain.
/// The proxy server supports basic authentication for SOCKS5 and HTTP proxies.
/// The proxy server also tracks the number of bytes transferred and the number of active connections.
// src/main.rs
use tokio::time::Duration;

mod config;
mod protocols;
mod stats;

use crate::{
    config::{load_config, ProxyConfig},
    protocols::{Proxy, ProxyError, ProxyServer},
    stats::{display::StatsDisplay, get_global_stats},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (listen_addr, proxy_chain) = load_config("config.toml")?;
    let global_stats = get_global_stats();

    // Create stats display for the server
    let stats_display = Arc::new(StatsDisplay::new(
        Arc::clone(&global_stats),
        Duration::from_millis(1),
    ));

    // Create the proxy server with logger
    let server = ProxyServer::new(proxy_chain, Arc::clone(&stats_display));

    // Run stats display in a separate task
    let display_handle = tokio::spawn({
        // Create a new display instance for the display task
        let display = StatsDisplay::new(Arc::clone(&global_stats), Duration::from_millis(1));
        async move {
            if let Err(e) = display.run().await {
                eprintln!("Stats display error: {}", e);
            }
        }
    });

    // Run the proxy server
    server.run(listen_addr.parse()?).await?;

    // Wait for display to finish
    let _ = display_handle.await;

    Ok(())
}
