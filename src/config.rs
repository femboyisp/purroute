//! TOML configuration types for the router.
//!
//! purroute is self-contained: it parses its own config and reads only what it
//! needs. Unknown sections are ignored, so an optional external system may share
//! the same file/database without the router caring.

use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use crate::protocol::Protocol;

/// Top-level `config.toml` shape. Unknown sections are ignored.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub router: RouterConfig,
    pub proxy: Vec<ProxyConfig>,
    pub chain: Option<Vec<ChainConfig>>,
    /// Optional PostgreSQL backend. When present, accounts live in the database.
    pub database: Option<DatabaseConfig>,
    /// Inline users for single-user / no-database operation. Used only when
    /// `[database]` is absent.
    #[serde(default)]
    pub user: Vec<UserConfig>,
}

/// An inline user for database-less operation (`[[user]]` blocks).
#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    /// Remaining traffic allowance in bytes. Omit for unlimited.
    pub bandwidth_limit: Option<i64>,
    /// Source IPs allowed to authenticate as this user without credentials.
    /// Exact addresses or CIDR ranges (e.g. `"10.0.0.0/24"`).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Default routing selection (username-token format) applied when a
    /// connection specifies none — e.g. `"country-us-isp-comcast"`.
    pub default_selection: Option<String>,
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
    /// How often (in seconds) to re-fetch upstreams from the database and
    /// merge them with the static config set. Defaults to 30 when a database
    /// is configured; ignored when running database-less.
    pub upstream_refresh_secs: Option<u64>,
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

/// Routing tags shared by upstreams and chains. All optional; an absent tag
/// matches only when a selection does not constrain that dimension.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Tags {
    pub country: Option<String>,
    pub state: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    /// `residential` | `mobile` | `datacenter`.
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub label: Option<String>,
    pub proxy_type: Protocol,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(flatten)]
    pub tags: Tags,
    /// Abstract metering rate: value units debited per relayed byte. `1.0`
    /// (the default) means one value unit per byte — i.e. plain byte metering.
    #[serde(default = "default_cost_per_byte")]
    #[allow(clippy::allow_attributes, dead_code)]
    pub cost_per_byte: f64,
    /// Optional per-connection username builder: routing dimension -> token
    /// prefix. When present, the outgoing username is the base `username` with
    /// the selected values appended (e.g. `base-country-us-city-nyc`). Absent =
    /// the static `username` is used unchanged.
    #[serde(default)]
    #[allow(clippy::allow_attributes, dead_code)]
    pub username_prefixes: Option<std::collections::BTreeMap<String, String>>,
}

fn default_cost_per_byte() -> f64 {
    1.0
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
        // An unrelated [extra] block must not break the router's parse.
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"

            [[proxy]]
            label = "us"
            proxy_type = "Http"
            address = "10.0.0.1"

            [extra]
            anything = "ignored"
            number = 42
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.proxy[0].proxy_type, Protocol::Http);
    }

    #[test]
    fn parses_inline_users() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            auth = true

            [[proxy]]
            label = "us"
            proxy_type = "Socks5"
            address = "10.0.0.1:1080"

            [[user]]
            username = "me"
            password = "hunter2"

            [[user]]
            username = "limited"
            password = "pw"
            bandwidth_limit = 1000
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.database.is_none());
        assert_eq!(config.user.len(), 2);
        assert_eq!(config.user[0].username, "me");
        assert_eq!(config.user[0].bandwidth_limit, None);
        assert_eq!(config.user[1].bandwidth_limit, Some(1000));
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

    #[test]
    fn proxy_cost_per_byte_defaults_to_one() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            [[proxy]]
            label = "a"
            proxy_type = "Socks5"
            address = "127.0.0.1:9000"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.proxy[0].cost_per_byte, 1.0);
    }

    #[test]
    fn proxy_cost_per_byte_parses_when_set() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            [[proxy]]
            label = "a"
            proxy_type = "Socks5"
            address = "127.0.0.1:9000"
            cost_per_byte = 0.5
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.proxy[0].cost_per_byte, 0.5);
    }

    /// `get_upstream_addr` returns `address` bare when `port` is `None`.
    #[test]
    fn get_upstream_addr_no_port() {
        let p = ProxyConfig {
            label: None,
            proxy_type: Protocol::Socks5,
            address: "proxy.example.com".into(),
            port: None,
            username: None,
            password: None,
            tags: Tags {
                country: None,
                state: None,
                city: None,
                isp: None,
                kind: None,
            },
            cost_per_byte: 1.0,
            username_prefixes: None,
        };
        assert_eq!(p.get_upstream_addr(), "proxy.example.com");
    }

    /// `Config::load` reads a TOML file from disk.
    #[test]
    fn load_reads_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("purroute-test-config.toml");
        std::fs::write(
            &path,
            r#"
[router]
listen = "127.0.0.1:1080"
chain = "a"
[[proxy]]
label = "a"
proxy_type = "Socks5"
address = "10.0.0.1"
port = 1080
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.proxy[0].address, "10.0.0.1");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn proxy_username_prefixes_parses() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            [[proxy]]
            label = "gw"
            proxy_type = "Socks5"
            address = "gw.example.com"
            port = 9000
            username = "base"
            username_prefixes = { country = "-country-", city = "-city-" }
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let p = &cfg.proxy[0];
        assert_eq!(
            p.username_prefixes
                .as_ref()
                .unwrap()
                .get("country")
                .unwrap(),
            "-country-"
        );
        assert_eq!(
            p.username_prefixes.as_ref().unwrap().get("city").unwrap(),
            "-city-"
        );
    }

    #[test]
    fn proxy_username_prefixes_defaults_none() {
        let toml = r#"
            [router]
            listen = "127.0.0.1:1080"
            [[proxy]]
            label = "a"
            proxy_type = "Socks5"
            address = "127.0.0.1:9000"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.proxy[0].username_prefixes.is_none());
    }
}
