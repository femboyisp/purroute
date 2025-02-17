use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct Config {
    router: RouterConfig,
    proxy: Vec<ProxyConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RouterConfig {
    listen: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum ProxyType {
    Socks5,
    Http,
    Https,
}

impl ProxyConfig {
    fn to_proxy_config(&self) -> ProxyConfig {
        ProxyConfig {
            proxy_type: self.proxy_type.clone(),
            address: self.address.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

pub fn load_config(path: &str) -> Result<(String, Vec<ProxyConfig>), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;

    let proxy_chain = config
        .proxy
        .into_iter()
        .map(|p| p.to_proxy_config())
        .collect();

    Ok((config.router.listen, proxy_chain))
}

// Update base64 encoding function
pub fn encode_auth(username: &str, password: &str) -> String {
    STANDARD.encode(format!("{}:{}", username, password))
}
