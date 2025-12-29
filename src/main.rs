/// Purroute - A simple proxy server
/// This is a simple proxy server that supports HTTP, HTTPS, and SOCKS5 protocols.
/// It reads the configuration from a TOML file and listens on the specified address.
/// It forwards the requests to the proxy servers in the chain.
/// The proxy server supports basic authentication for SOCKS5 and HTTP proxies.
/// The proxy server also tracks the number of bytes transferred and the number of active connections.
// src/main.rs
use tokio::time::Duration;
use tokio_postgres::{Client, Config, Error, NoTls};

use std::sync::Arc;

mod api;
mod config;
mod protocols;
mod stats;

use crate::{
    config::load_config,
    protocols::ProxyServer,
    stats::{display::StatsDisplay, get_global_stats},
};

async fn initialize_database(client: &Client) -> Result<(), Error> {
    // Create sequence for account IDs if it doesn't exist
    client
        .execute(
            "
            CREATE SEQUENCE IF NOT EXISTS account_id_seq;
            ",
            &[],
        )
        .await?;

    // Create the global table if it does not exist
    client
        .execute(
            "
            CREATE TABLE IF NOT EXISTS public.global (
                total_connections BIGINT DEFAULT 0,
                succeeded_connections BIGINT DEFAULT 0,
                failed_connections BIGINT DEFAULT 0,
                total_bytes_in BIGINT DEFAULT 0,
                total_bytes_out BIGINT DEFAULT 0
            );
            ",
            &[],
        )
        .await?;

    // Create the accounts table if it does not exist
    client
        .execute(
            "
            CREATE TABLE IF NOT EXISTS public.accounts (
                account BIGINT PRIMARY KEY DEFAULT nextval('account_id_seq'),
                proxy BIGINT,
                feedback TEXT,
                registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                password TEXT
            );
            ",
            &[],
        )
        .await?;

    // Create the user_stats table if it does not exist
    client
        .execute(
            "
            CREATE TABLE IF NOT EXISTS public.user_stats (
                id BIGINT PRIMARY KEY,
                total_connections BIGINT DEFAULT 0,
                succeeded_connections BIGINT DEFAULT 0,
                failed_connections BIGINT DEFAULT 0,
                total_bytes_in BIGINT DEFAULT 0,
                total_bytes_out BIGINT DEFAULT 0,
                FOREIGN KEY (id) REFERENCES public.accounts (account)
            );
            ",
            &[],
        )
        .await?;

    // Initialize the global stats table if empty
    client
        .execute(
            "
            INSERT INTO public.global
            (total_connections, succeeded_connections, failed_connections, total_bytes_in, total_bytes_out)
            SELECT 0, 0, 0, 0, 0
            WHERE NOT EXISTS (SELECT 1 FROM public.global);
            ",
            &[],
        )
        .await?;

    // Add bandwidth_limit column to accounts table
    client
        .execute(
            "
            ALTER TABLE public.accounts
            ADD COLUMN IF NOT EXISTS bandwidth_limit BIGINT DEFAULT NULL;
            ",
            &[],
        )
        .await?;

    // Create indexes for performance
    client
        .execute(
            "
            CREATE INDEX IF NOT EXISTS idx_accounts_username
            ON public.accounts(username);
            ",
            &[],
        )
        .await?;

    client
        .execute(
            "
            CREATE INDEX IF NOT EXISTS idx_user_stats_id
            ON public.user_stats(id);
            ",
            &[],
        )
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (router_config, proxy_chain, chains, db_config, api_config) = load_config("config.toml")?;
    let global_stats = get_global_stats();

    // Initialize the database connection
    let db_config = db_config.ok_or("Database configuration is missing")?;
    let mut db_config_builder = Config::new();
    db_config_builder
        .host(&db_config.host)
        .port(db_config.port.try_into().unwrap())
        .user(db_config.user.as_deref().unwrap_or(""))
        .dbname(&db_config.dbname)
        .password(db_config.password.as_deref().unwrap_or(""));

    let (db_client, db_connection) = db_config_builder.connect(NoTls).await?;

    let db_client = Arc::new(db_client);
    tokio::spawn(async move {
        if let Err(e) = db_connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    // Initialize the database
    initialize_database(&db_client).await?;

    // Load stats from the database if configured
    if let Err(e) = global_stats.load_from_db(&db_client).await {
        eprintln!("Failed to load stats from database: {}", e);
    }

    // Create stats display for the server
    let stats_display = Arc::new(StatsDisplay::new(
        Arc::clone(&global_stats),
        Duration::from_secs(2), // Reduced frequency from 500ms to 2s
        Arc::clone(&db_client),
    ));

    let router_config_clone = router_config.clone();

    // Create the proxy server with logger
    let server = ProxyServer::new(
        proxy_chain,
        chains,
        Arc::clone(&stats_display),
        Arc::new(router_config.clone()),
        Arc::clone(&db_client),
    );

    // Run stats display in a separate task
    let display_handle = tokio::spawn({
        // Create a new display instance for the display task
        let display = StatsDisplay::new(
            Arc::clone(&global_stats),
            Duration::from_secs(2), // Reduced frequency from 500ms to 2s
            Arc::clone(&db_client),
        );
        async move {
            if let Err(e) = display.run(Arc::new(router_config_clone)).await {
                eprintln!("Stats display error: {}", e);
            }
        }
    });

    // Start API server if configured
    if let Some(api_config) = api_config {
        if api_config.enabled.unwrap_or(true) {
            let api_db_client = Arc::clone(&db_client);
            tokio::spawn(async move {
                if let Err(e) = crate::api::run_api_server(api_config, api_db_client).await {
                    eprintln!("API server error: {}", e);
                }
            });
        }
    }

    // Run the proxy server
    server.run(router_config.listen.parse()?).await?;

    // Wait for display to finish
    let _ = display_handle.await?;

    Ok(())
}
