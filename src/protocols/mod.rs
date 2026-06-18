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
    proxy::{ProxyError, ProxyServer},
    socks4::Socks4,
    socks5::Socks5,
};
/// Re-export the crate's `Protocol` enum as `Proxy` for the existing
/// `crate::protocols::Proxy` paths used throughout this module.
pub use crate::protocol::Protocol as Proxy;
