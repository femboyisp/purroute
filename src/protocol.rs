//! The proxy protocol enum, used for both the detected inbound protocol and a
//! configured upstream's `proxy_type`.

use serde::{Deserialize, Serialize};

/// A proxy protocol.
///
/// Variant names are kept stable because they are deserialised directly from the
/// `proxy_type` field of `[[proxy]]` blocks in `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Protocol {
    Http,
    Https,
    Socks4,
    Socks5,
}

impl Protocol {
    /// Lower-case identifier suitable for metrics labels and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Socks4 => "socks4",
            Protocol::Socks5 => "socks5",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
