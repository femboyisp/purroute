//! TOML configuration types for the router.
//!
//! purroute is self-contained: it parses its own config and knows nothing about
//! payments, reseller accounts, or pricing. A separate (private) backend may
//! extend the same database, but the router only ever reads what it needs.

use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use crate::protocol::Protocol;

/// Top-level `config.toml` shape. Unknown sections (e.g. a backend's
/// `[payments]`) are ignored, so the router and backend can share one file.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub router: RouterConfig,
    pub proxy: Vec<ProxyConfig>,
    pub chain: Option<Vec<ChainConfig>>,
    pub database: Option<DatabaseConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub dbname: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterConfig {
    pub listen: String,
    pub chain: Option<String>,
    pub log: Option<bool>,
    pub verbose: Option<bool>,
    pub debug: Option<bool>,
    pub auth: Option<bool>,
    /// Optional local-only address for the Prometheus `/metrics` endpoint.
    pub metrics_listen: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainMode {
    /// Use proxies in the exact order listed.
    #[default]
    Strict,
    /// Pick random proxies from the list.
    Random,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChainConfig {
    pub chain_id: String,
    pub proxies: Vec<String>,
    #[serde(default)]
    pub mode: ChainMode,
    /// For [`ChainMode::Random`]: how many proxies to pick.
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub label: Option<String>,
    pub proxy_type: Protocol,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// `host:port` string for the upstream, falling back to bare address when no
    /// port is configured.
    pub fn get_upstream_addr(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.address, port),
            None => self.address.clone(),
        }
    }
}

impl Config {
    /// Read and parse a config file from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_str = fs::read_to_string(path)?;
        let config = toml::from_str(&config_str)?;
        Ok(config)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// The router config, upstream proxies, optional chains, and optional database
/// config, as returned by [`load_config`].
pub type LoadedConfig = (
    RouterConfig,
    Vec<ProxyConfig>,
    Option<Vec<ChainConfig>>,
    Option<DatabaseConfig>,
);

/// Tuple loader used by `main`.
pub fn load_config(path: &str) -> Result<LoadedConfig, ConfigError> {
    let config = Config::load(path)?;
    Ok((config.router, config.proxy, config.chain, config.database))
}

/// Base64 `username:password` for HTTP Basic `Proxy-Authorization`.
pub fn encode_auth(username: &str, password: &str) -> String {
    STANDARD.encode(format!("{username}:{password}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            chain = "us"

            [[proxy]]
            label = "us"
            proxy_type = "Socks5"
            address = "10.0.0.1"
            port = 1080

            [database]
            host = "localhost"
            port = 5432
            dbname = "purroute"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.router.listen, "127.0.0.1:1080");
        assert_eq!(config.proxy.len(), 1);
        assert_eq!(config.proxy[0].proxy_type, Protocol::Socks5);
        assert_eq!(config.proxy[0].get_upstream_addr(), "10.0.0.1:1080");
        assert_eq!(config.database.unwrap().port, 5432);
    }

    #[test]
    fn ignores_unknown_sections() {
        // A backend's [payments] block must not break the router's parse.
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"

            [[proxy]]
            label = "us"
            proxy_type = "Http"
            address = "10.0.0.1"

            [payments]
            wallet_rpc_url = "http://localhost:18083"
            price_xmr_per_gb = 0.0005
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.proxy[0].proxy_type, Protocol::Http);
    }

    #[test]
    fn chain_mode_defaults_to_strict() {
        let toml = r#"
            chain_id = "triple"
            proxies = ["a", "b", "c"]
        "#;
        let chain: ChainConfig = toml::from_str(toml).unwrap();
        assert_eq!(chain.mode, ChainMode::Strict);
        assert_eq!(chain.proxies.len(), 3);
    }

    #[test]
    fn encode_auth_is_base64() {
        assert_eq!(encode_auth("user", "pass"), "dXNlcjpwYXNz");
    }
}
