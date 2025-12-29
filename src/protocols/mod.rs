// src/protocols/mod.rs
pub mod chain;
pub mod http;
pub mod https;
pub mod proxy;
pub mod socks4;
pub mod socks5;

pub use self::{
    chain::ChainConnector,
    http::Http,
    https::Https,
    proxy::{Proxy, ProxyError, ProxyServer},
    socks4::Socks4,
    socks5::Socks5,
};
