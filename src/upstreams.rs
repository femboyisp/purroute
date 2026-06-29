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

/// Pure field-wiring for a proxy row — no database dependency.
/// Called by `row_to_proxy` with values extracted from a `tokio_postgres::Row`,
/// and directly by unit tests.
#[allow(clippy::allow_attributes, dead_code, clippy::too_many_arguments)]
fn build_proxy(
    label: Option<String>,
    proxy_type: &str,
    address: String,
    port: Option<i32>,
    username: Option<String>,
    password: Option<String>,
    country: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    kind: Option<String>,
    cost_per_byte: f64,
) -> ProxyConfig {
    ProxyConfig {
        label,
        proxy_type: protocol_from_str(proxy_type),
        address,
        port: port.and_then(|p| u16::try_from(p).ok()),
        username,
        password,
        tags: Tags {
            country,
            city,
            isp,
            kind,
        },
        cost_per_byte,
    }
}

#[allow(clippy::allow_attributes, dead_code)]
fn row_to_proxy(row: &Row) -> ProxyConfig {
    build_proxy(
        row.get(0),
        &row.get::<_, String>(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
        row.get(8),
        row.get(9),
        row.get(10),
    )
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
        assert_eq!(protocol_from_str("https"), Protocol::Https);
        assert_eq!(protocol_from_str("SOCKS5"), Protocol::Socks5);
        assert_eq!(protocol_from_str("socks4"), Protocol::Socks4);
        assert_eq!(protocol_from_str("weird"), Protocol::Socks5);
    }

    /// Hermetic: exercises `build_proxy` with all fields populated.
    #[test]
    fn build_proxy_full_row() {
        let p = build_proxy(
            Some("lab".into()),
            "socks5",
            "10.0.0.1".into(),
            Some(1080),
            Some("user".into()),
            Some("pass".into()),
            Some("us".into()),
            Some("nyc".into()),
            Some("comcast".into()),
            Some("residential".into()),
            2.5,
        );
        assert_eq!(p.label.as_deref(), Some("lab"));
        assert_eq!(p.proxy_type, Protocol::Socks5);
        assert_eq!(p.address, "10.0.0.1");
        assert_eq!(p.port, Some(1080));
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.tags.country.as_deref(), Some("us"));
        assert_eq!(p.tags.city.as_deref(), Some("nyc"));
        assert_eq!(p.tags.isp.as_deref(), Some("comcast"));
        assert_eq!(p.tags.kind.as_deref(), Some("residential"));
        assert!((p.cost_per_byte - 2.5).abs() < f64::EPSILON);
    }

    /// Hermetic: `build_proxy` with all optional fields absent.
    #[test]
    fn build_proxy_minimal_row() {
        let p = build_proxy(
            None,
            "http",
            "proxy.example.com".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            1.0,
        );
        assert_eq!(p.label, None);
        assert_eq!(p.proxy_type, Protocol::Http);
        assert_eq!(p.address, "proxy.example.com");
        assert_eq!(p.port, None);
        assert_eq!(p.username, None);
        assert_eq!(p.password, None);
        assert_eq!(p.tags.country, None);
        assert_eq!(p.tags.city, None);
        assert_eq!(p.tags.isp, None);
        assert_eq!(p.tags.kind, None);
    }

    /// Hermetic: port edge cases — valid, None, out-of-range, negative.
    #[test]
    fn build_proxy_port_conversion() {
        // valid port
        let p = build_proxy(
            None,
            "socks5",
            "h".into(),
            Some(8080),
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.port, Some(8080));

        // no port
        let p = build_proxy(
            None,
            "socks5",
            "h".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.port, None);

        // out-of-range (> u16::MAX)
        let p = build_proxy(
            None,
            "socks5",
            "h".into(),
            Some(70000),
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.port, None);

        // negative
        let p = build_proxy(
            None,
            "socks5",
            "h".into(),
            Some(-1),
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.port, None);
    }

    /// Hermetic: `protocol_from_str` arms exercised individually (socks4, https).
    #[test]
    fn build_proxy_protocol_arms() {
        let p = build_proxy(
            None,
            "socks4",
            "h".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.proxy_type, Protocol::Socks4);

        let p = build_proxy(
            None,
            "https",
            "h".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.proxy_type, Protocol::Https);

        // unknown → Socks5 fallback
        let p = build_proxy(
            None,
            "unknown",
            "h".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0.0,
        );
        assert_eq!(p.proxy_type, Protocol::Socks5);
    }

    /// Hermetic: cost_per_byte passes through unchanged.
    #[test]
    fn build_proxy_cost_passthrough() {
        let p = build_proxy(
            None,
            "socks5",
            "h".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            2.5,
        );
        assert!((p.cost_per_byte - 2.5).abs() < f64::EPSILON);
    }

    /// DB-gated: inserts one row and verifies `load_dynamic_upstreams` round-trips
    /// all fields. Skips cleanly when `TEST_DATABASE_URL` is absent.
    ///
    /// To run locally: `TEST_DATABASE_URL="host=localhost port=5432 user=purroute
    /// dbname=purroute password=purroute" cargo test -p purroute --bins`
    #[tokio::test]
    async fn load_dynamic_upstreams_roundtrip() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("load_dynamic_upstreams_roundtrip: no TEST_DATABASE_URL — skipping");
            return;
        };
        let Ok((client, conn)) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await else {
            eprintln!("load_dynamic_upstreams_roundtrip: DB unreachable — skipping");
            return;
        };
        tokio::spawn(async move { drop(conn.await) });
        crate::auth::PostgresAuthBackend::initialize_schema(&client)
            .await
            .expect("initialize_schema");
        let id: i64 = client
            .query_one(
                "INSERT INTO public.upstreams \
                 (label,proxy_type,address,port,username,password,\
                  country,city,isp,kind,cost_per_byte,enabled) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) RETURNING id",
                &[
                    &Some("test-label"),
                    &"socks5",
                    &"10.0.0.1",
                    &Some(1080_i32),
                    &Some("user"),
                    &Some("pass"),
                    &Some("us"),
                    &Some("nyc"),
                    &Some("comcast"),
                    &Some("residential"),
                    &2.5_f64,
                ],
            )
            .await
            .expect("INSERT")
            .get(0);
        let proxies = load_dynamic_upstreams(&client).await.expect("load");
        client
            .execute("DELETE FROM public.upstreams WHERE id=$1", &[&id])
            .await
            .expect("DELETE");
        let p = proxies
            .into_iter()
            .find(|p| p.label.as_deref() == Some("test-label"))
            .unwrap();
        assert_eq!(p.address, "10.0.0.1");
        assert_eq!(p.port, Some(1080));
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
        assert_eq!(p.proxy_type, Protocol::Socks5);
        assert_eq!(p.tags.country.as_deref(), Some("us"));
        assert_eq!(p.tags.city.as_deref(), Some("nyc"));
        assert_eq!(p.tags.isp.as_deref(), Some("comcast"));
        assert_eq!(p.tags.kind.as_deref(), Some("residential"));
        assert!((p.cost_per_byte - 2.5).abs() < f64::EPSILON);
    }
}
