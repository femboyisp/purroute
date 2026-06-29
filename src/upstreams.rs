//! Dynamic upstreams loaded from a database table (optional supplement to the
//! static `[[proxy]]` config). The router treats these exactly like configured
//! upstreams; an external system populates the table.

use crate::config::{ProxyConfig, Tags};
use crate::protocol::Protocol;
use tokio_postgres::{Client, Row};

/// Columns selected for an upstream row, in order. Keep in sync with `row_to_proxy`.
///
/// Index mapping:
///   0  label         — Option<String>
///   1  proxy_type    — String  → Protocol via `protocol_from_str`
///   2  address       — String
///   3  port          — Option<i32>  → Option<u16>
///   4  username      — Option<String>
///   5  password      — Option<String>
///   6  country       — Option<String>
///   7  city          — Option<String>
///   8  isp           — Option<String>
///   9  kind          — Option<String>
///  10  cost_per_byte — f64
#[allow(clippy::allow_attributes, dead_code)]
const UPSTREAM_SELECT: &str = "SELECT label, proxy_type, address, port, username, \
    password, country, city, isp, kind, cost_per_byte \
    FROM public.upstreams \
    WHERE enabled = true AND (expires_at IS NULL OR expires_at > now())";

#[allow(clippy::allow_attributes, dead_code)]
fn protocol_from_str(s: &str) -> Protocol {
    match s.to_ascii_lowercase().as_str() {
        "http" => Protocol::Http,
        "https" => Protocol::Https,
        "socks4" => Protocol::Socks4,
        _ => Protocol::Socks5,
    }
}

#[allow(clippy::allow_attributes, dead_code)]
fn row_to_proxy(row: &Row) -> ProxyConfig {
    let port: Option<i32> = row.get(3);
    ProxyConfig {
        label: row.get(0),
        proxy_type: protocol_from_str(&row.get::<_, String>(1)),
        address: row.get(2),
        port: port.and_then(|p| u16::try_from(p).ok()),
        username: row.get(4),
        password: row.get(5),
        tags: Tags {
            country: row.get(6),
            city: row.get(7),
            isp: row.get(8),
            kind: row.get(9),
        },
        cost_per_byte: row.get(10),
    }
}

/// Load all enabled, non-expired dynamic upstreams. Returns an empty vec when
/// the table is empty.
#[allow(clippy::allow_attributes, dead_code)]
pub async fn load_dynamic_upstreams(
    client: &Client,
) -> Result<Vec<ProxyConfig>, tokio_postgres::Error> {
    let rows = client.query(UPSTREAM_SELECT, &[]).await?;
    Ok(rows.iter().map(row_to_proxy).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_strings_map() {
        assert_eq!(protocol_from_str("http"), Protocol::Http);
        assert_eq!(protocol_from_str("SOCKS5"), Protocol::Socks5);
        assert_eq!(protocol_from_str("socks4"), Protocol::Socks4);
        assert_eq!(protocol_from_str("weird"), Protocol::Socks5);
    }
}
