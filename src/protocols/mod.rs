// src/protocols/mod.rs
pub mod http;
pub mod proxy;
pub mod socks5;

pub use self::{
    http::Http,
    proxy::{Proxy, ProxyError, ProxyServer},
    socks5::Socks5,
};
