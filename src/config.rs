use crate::protocols::Proxy;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub router: RouterConfig,
    pub proxy: Vec<ProxyConfig>,
    pub chain: Option<Vec<ChainConfig>>,
    pub database: Option<DatabaseConfig>,
    pub api: Option<ApiConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: i32,
    pub user: Option<String>,
    pub password: Option<String>,
    pub dbname: String,
    pub tls: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterConfig {
    pub listen: String,
    pub chain: Option<String>,
    pub log: Option<bool>,
    pub verbose: Option<bool>,
    pub debug: Option<bool>,
    pub auth: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    pub listen: String,
    pub api_key: String,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ChainMode {
    Strict,   // Use proxies in exact order
    Random,   // Pick random proxies from the list
}

impl Default for ChainMode {
    fn default() -> Self {
        ChainMode::Strict
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChainConfig {
    pub chain_id: String,
    pub proxies: Vec<String>,
    #[serde(default)]
    pub mode: ChainMode,
    pub count: Option<usize>, // For random mode: how many proxies to pick
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub label: Option<String>,
    pub proxy_type: Proxy,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn load_config(
    path: &str,
) -> Result<(RouterConfig, Vec<ProxyConfig>, Option<Vec<ChainConfig>>, Option<DatabaseConfig>, Option<ApiConfig>), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;

    Ok((config.router, config.proxy, config.chain, config.database, config.api))
}

pub fn encode_auth(username: &str, password: &str) -> String {
    STANDARD.encode(format!("{}:{}", username, password))
}

impl ProxyConfig {
    pub fn get_upstream_addr(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.address, port),
            None => self.address.clone(),
        }
    }
}
