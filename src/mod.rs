// src/mod.rs
use serde::Deserialize;
use std::sync::atomic::AtomicU64;
use thiserror::Error;

pub mod config;
pub mod protocols;
pub mod proxy;
pub mod stats;

pub use config::{encode_auth, load_config, Config, ProxyConfig, RouterConfig};
pub use protocols::{Http, ProxyError, ProxyProtocol, ProxyServer, ProxyType, Socks5};
pub use stats::{get_global_stats, GlobalStats, LogLevel, StatsDisplay};
