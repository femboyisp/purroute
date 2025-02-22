// src/config.rs
use crate::protocols::Proxy;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub router: RouterConfig,
    pub proxy: Vec<ProxyConfig>,
    pub database: Option<DatabaseConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub tls: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterConfig {
    pub listen: String,
    pub log: Option<bool>,
    pub verbose: Option<bool>,
    pub debug: Option<bool>,
    pub auth: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub label: Option<String>,
    pub proxy_type: Proxy,
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn load_config(
    path: &str,
) -> Result<(RouterConfig, Vec<ProxyConfig>, Option<DatabaseConfig>), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;

    Ok((config.router, config.proxy, config.database))
}

pub fn encode_auth(username: &str, password: &str) -> String {
    STANDARD.encode(format!("{}:{}", username, password))
}
