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
    /// Optional `host:port`. When set, origin-form HTTP requests (a browser
    /// treating the proxy as a website, `GET /path`) are reverse-proxied here
    /// instead of being handled as forward-proxy requests. Unset disables it.
    pub web_backend: Option<String>,
    /// Optional `[[proxy]]` label or `[[chain]]` id to use whenever the routing
    /// selection carries a sticky `session` id. Rotating gateways ignore the
    /// session token, so sticky requests must be pinned to a sticky-capable
    /// upstream. Unset falls back to the normal tag/`chain` resolution.
    pub sticky_chain: Option<String>,
    /// Grace window (seconds) after paw-key rotation during which the previous
    /// life still verifies. Defaults to 86400.
    #[serde(default = "default_auth_grace_secs")]
    pub auth_grace_secs: u64,
    /// Tor (.onion) routing: optional local SOCKS hop + auto-prepend for onion targets.
    #[serde(default)]
    pub tor: HiddenHopConfig,
    /// I2P (.i2p) routing: optional local SOCKS hop + auto-prepend for I2P targets.
    #[serde(default)]
    pub i2p: HiddenHopConfig,
    /// Upstream health tracking and failover retry settings.
    #[serde(default)]
    pub upstream_health: UpstreamHealthConfig,
}

/// Upstream port health tracking, retries, and failover configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct UpstreamHealthConfig {
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_recovery_mode")]
    pub recovery_mode: String,
    #[serde(default = "default_active_probe_interval_secs")]
    pub active_probe_interval_secs: u64,
}

fn default_handshake_timeout_secs() -> u64 {
    3
}

fn default_max_retries() -> usize {
    2
}

fn default_failure_threshold() -> u32 {
    2
}

fn default_cooldown_secs() -> u64 {
    45
}

fn default_recovery_mode() -> String {
    "active".to_string()
}

fn default_active_probe_interval_secs() -> u64 {
    30
}

impl Default for UpstreamHealthConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: default_handshake_timeout_secs(),
            max_retries: default_max_retries(),
            failure_threshold: default_failure_threshold(),
            cooldown_secs: default_cooldown_secs(),
            recovery_mode: default_recovery_mode(),
            active_probe_interval_secs: default_active_probe_interval_secs(),
        }
    }
}

/// Local Tor/I2P SOCKS hop used to reach hidden-network destinations.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HiddenHopConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `[[proxy]]` label for the local SOCKS hop. Defaults to `Tor` / `I2p`.
    pub proxy_label: Option<String>,
    /// When true, prepend this hop for `.onion` / `.i2p` destinations.
    #[serde(default = "default_auto_prepend")]
    pub auto_prepend: bool,
}

fn default_auto_prepend() -> bool {
    true
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".into(),
            chain: None,
            log: None,
            verbose: None,
            debug: None,
            auth: None,
            metrics_listen: None,
            upstream_refresh_secs: None,
            web_backend: None,
            sticky_chain: None,
            auth_grace_secs: default_auth_grace_secs(),
            tor: HiddenHopConfig::default(),
            i2p: HiddenHopConfig::default(),
            upstream_health: UpstreamHealthConfig::default(),
        }
    }
}

fn default_auth_grace_secs() -> u64 {
    86400
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
    pub postal: Option<String>,
    pub asn: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub label: Option<String>,
    pub proxy_type: Protocol,
    pub address: String,
    pub port: Option<u16>,
    /// Inclusive port range for load-balancing (`11000-11010` in config). Cleared
    /// once a concrete port is materialised per connection.
    #[serde(default, skip)]
    pub port_range: Option<(u16, u16)>,
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
    pub username_prefixes: Option<std::collections::BTreeMap<String, String>>,
}

/// Parsed proxy endpoint: host, optional single port, optional inclusive port range.
pub type ParsedEndpoint = (String, Option<u16>, Option<(u16, u16)>);

/// Split `host`, `host:port`, or `host:start-end` out of a config `address`
/// field (when no separate `port` is set).
pub fn parse_endpoint_address(
    address: &str,
    explicit_port: Option<u16>,
) -> Result<ParsedEndpoint, ConfigError> {
    if explicit_port.is_some() {
        return Ok((address.to_owned(), explicit_port, None));
    }
    let Some((host, port_part)) = address.rsplit_once(':') else {
        return Ok((address.to_owned(), None, None));
    };
    if host.is_empty() {
        return Err(ConfigError::Endpoint(format!(
            "invalid proxy address '{address}': empty host"
        )));
    }
    if let Some((start, end)) = port_part.split_once('-') {
        let start: u16 = start.parse().map_err(|_| {
            ConfigError::Endpoint(format!("invalid port range start in '{address}'"))
        })?;
        let end: u16 = end
            .parse()
            .map_err(|_| ConfigError::Endpoint(format!("invalid port range end in '{address}'")))?;
        if start > end {
            return Err(ConfigError::Endpoint(format!(
                "invalid port range in '{address}': start > end"
            )));
        }
        return Ok((host.to_owned(), None, Some((start, end))));
    }
    let port: u16 = port_part
        .parse()
        .map_err(|_| ConfigError::Endpoint(format!("invalid port in '{address}'")))?;
    Ok((host.to_owned(), Some(port), None))
}

fn normalize_proxy_endpoints(proxies: &mut [ProxyConfig]) -> Result<(), ConfigError> {
    for p in proxies.iter_mut() {
        let port = p.port;
        let (host, single, range) = parse_endpoint_address(&p.address, port)?;
        p.address = host;
        p.port = single.or(p.port);
        p.port_range = range;
    }
    Ok(())
}

fn default_cost_per_byte() -> f64 {
    1.0
}

impl ProxyConfig {
    /// `host:port` string for the upstream, applying default port 80 for
    /// `.onion` / `.i2p` hosts when no port is configured.
    pub fn get_upstream_addr(&self) -> String {
        crate::hidden::socket_addr(&self.address, self.port)
    }
}

impl Config {
    /// Read and parse a config file from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_str = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_str)?;
        normalize_proxy_endpoints(&mut config.proxy)?;
        Ok(config)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid proxy endpoint: {0}")]
    Endpoint(String),
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
    fn parse_endpoint_address_single_port_and_range() {
        let (host, port, range) = parse_endpoint_address("gw.example.com:9000", None).unwrap();
        assert_eq!(host, "gw.example.com");
        assert_eq!(port, Some(9000));
        assert!(range.is_none());

        let (host, port, range) =
            parse_endpoint_address("gw.example.com:11000-11010", None).unwrap();
        assert_eq!(host, "gw.example.com");
        assert!(port.is_none());
        assert_eq!(range, Some((11000, 11010)));

        let (host, port, range) = parse_endpoint_address("bare.host", None).unwrap();
        assert_eq!(host, "bare.host");
        assert!(port.is_none());
        assert!(range.is_none());

        assert!(parse_endpoint_address("gw.example.com:11010-11000", None).is_err());
    }

    #[test]
    fn config_load_normalizes_port_range_in_address() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("purroute-range-test-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            r#"
[router]
listen = "127.0.0.1:1080"
[[proxy]]
label = "gw"
proxy_type = "Socks5"
address = "proxy.example.com:11000-11010"
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(cfg.proxy[0].address, "proxy.example.com");
        assert_eq!(cfg.proxy[0].port_range, Some((11000, 11010)));
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
            port_range: None,
            username: None,
            password: None,
            tags: Tags {
                country: None,
                state: None,
                city: None,
                isp: None,
                kind: None,
                postal: None,
                asn: None,
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

    #[test]
    fn web_backend_parses_and_defaults_none() {
        // Present: parsed into Some.
        let toml_with = r#"
[router]
listen = "127.0.0.1:1080"
web_backend = "127.0.0.1:8090"

[[proxy]]
label = "upstream"
proxy_type = "Socks5"
address = "10.0.0.1"
"#;
        let cfg: Config = toml::from_str(toml_with).unwrap();
        assert_eq!(cfg.router.web_backend.as_deref(), Some("127.0.0.1:8090"));

        // Absent: defaults to None.
        let toml_without = r#"
[router]
listen = "127.0.0.1:1080"

[[proxy]]
label = "upstream"
proxy_type = "Socks5"
address = "10.0.0.1"
"#;
        let cfg: Config = toml::from_str(toml_without).unwrap();
        assert_eq!(cfg.router.web_backend, None);
    }

    #[test]
    fn test_upstream_health_config_defaults() {
        let toml = r#"
            listen = "127.0.0.1:1080"
        "#;
        let router: RouterConfig = toml::from_str(toml).unwrap();
        assert_eq!(router.upstream_health.handshake_timeout_secs, 3);
        assert_eq!(router.upstream_health.max_retries, 2);
        assert_eq!(router.upstream_health.failure_threshold, 2);
        assert_eq!(router.upstream_health.cooldown_secs, 45);
        assert_eq!(router.upstream_health.recovery_mode, "active");
        assert_eq!(router.upstream_health.active_probe_interval_secs, 30);
    }

    #[test]
    fn test_upstream_health_config_custom() {
        let toml = r#"
            listen = "127.0.0.1:1080"
            [upstream_health]
            handshake_timeout_secs = 5
            max_retries = 3
            failure_threshold = 1
            cooldown_secs = 60
            recovery_mode = "passive"
            active_probe_interval_secs = 15
        "#;
        let router: RouterConfig = toml::from_str(toml).unwrap();
        assert_eq!(router.upstream_health.handshake_timeout_secs, 5);
        assert_eq!(router.upstream_health.max_retries, 3);
        assert_eq!(router.upstream_health.failure_threshold, 1);
        assert_eq!(router.upstream_health.cooldown_secs, 60);
        assert_eq!(router.upstream_health.recovery_mode, "passive");
        assert_eq!(router.upstream_health.active_probe_interval_secs, 15);
    }
}
