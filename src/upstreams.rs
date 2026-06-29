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
        assert_eq!(protocol_from_str("https"), Protocol::Https);
        assert_eq!(protocol_from_str("SOCKS5"), Protocol::Socks5);
        assert_eq!(protocol_from_str("socks4"), Protocol::Socks4);
        assert_eq!(protocol_from_str("weird"), Protocol::Socks5);
    }

    /// DB-gated integration test: inserts one row into `public.upstreams` and
    /// asserts that `load_dynamic_upstreams` returns a `ProxyConfig` with the
    /// expected fields. Skips cleanly when `TEST_DATABASE_URL` is absent or when
    /// the database is unreachable.
    ///
    /// To run locally: `TEST_DATABASE_URL="host=localhost port=5432 user=purroute
    /// dbname=purroute password=purroute" cargo test -p purroute --bins`
    #[tokio::test]
    async fn load_dynamic_upstreams_roundtrip() {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("load_dynamic_upstreams_roundtrip: no TEST_DATABASE_URL — skipping");
                return;
            }
        };

        let (client, connection) = match tokio_postgres::connect(&url, tokio_postgres::NoTls).await
        {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("load_dynamic_upstreams_roundtrip: DB unreachable ({e}) — skipping");
                return;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("load_dynamic_upstreams_roundtrip: connection error: {e}");
            }
        });

        // Ensure the schema exists (idempotent).
        crate::auth::PostgresAuthBackend::initialize_schema(&client)
            .await
            .expect("initialize_schema failed");

        // Insert a test upstream row.
        let inserted: i64 = client
            .query_one(
                "INSERT INTO public.upstreams \
                     (label, proxy_type, address, port, username, password, \
                      country, city, isp, kind, cost_per_byte, enabled) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) \
                     RETURNING id",
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
            .expect("INSERT failed")
            .get(0);

        // Call the function under test.
        let proxies = load_dynamic_upstreams(&client)
            .await
            .expect("load_dynamic_upstreams failed");

        // Clean up before asserting so we don't leave rows on failure.
        client
            .execute("DELETE FROM public.upstreams WHERE id = $1", &[&inserted])
            .await
            .expect("cleanup DELETE failed");

        // Find our row (other tests may insert rows too).
        let proxy = proxies
            .into_iter()
            .find(|p| p.label.as_deref() == Some("test-label"))
            .expect("our upstream row was not returned by load_dynamic_upstreams");

        assert_eq!(proxy.address, "10.0.0.1");
        assert_eq!(proxy.port, Some(1080));
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
        assert_eq!(proxy.proxy_type, Protocol::Socks5);
        assert_eq!(proxy.tags.country.as_deref(), Some("us"));
        assert_eq!(proxy.tags.city.as_deref(), Some("nyc"));
        assert_eq!(proxy.tags.isp.as_deref(), Some("comcast"));
        assert_eq!(proxy.tags.kind.as_deref(), Some("residential"));
        assert!((proxy.cost_per_byte - 2.5).abs() < f64::EPSILON);
    }
}
