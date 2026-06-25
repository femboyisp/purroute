//! Authentication + usage-reporting backend for the router.
//!
//! The router does not care *how* a user came to exist or how their traffic
//! allowance is managed — only whether a `(username, secret)` is valid and how
//! many bytes they have left. That contract is the [`AuthBackend`] trait.
//!
//! Two implementations ship with the router:
//! - [`StaticAuthBackend`] — users defined inline in `config.toml` (`[[user]]`),
//!   for single-user / no-database operation.
//! - [`PostgresAuthBackend`] — an `accounts` table in PostgreSQL, with usage
//!   written to `user_stats`. An optional external system may extend the same
//!   schema; the router only ever touches the columns it defines here.
//!
//! Implement the trait yourself (e.g. against a remote API) to plug in any other
//! account source.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ipnet::IpNet;
use tokio_postgres::Client;

use crate::config::UserConfig;

/// A validated account: its id, remaining byte allowance (`None` = no limit), and
/// optional default routing selection (token format, applied when a connection
/// requests none).
#[derive(Debug, Clone)]
pub struct Account {
    pub id: i64,
    pub bandwidth_limit: Option<i64>,
    pub default_selection: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("auth backend error: {0}")]
    Backend(String),
}

/// The router's only dependency on user accounts.
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// Verify credentials. `Ok(None)` = no such user.
    async fn authenticate(
        &self,
        username: &str,
        secret: &str,
    ) -> Result<Option<Account>, AuthError>;

    /// Authorise a connection by its source IP (allowlist). `Ok(None)` = the IP
    /// is not authorised. Default: no IP auth.
    async fn authenticate_by_ip(&self, _peer: IpAddr) -> Result<Option<Account>, AuthError> {
        Ok(None)
    }

    /// Record relayed bytes for an account and decrement its allowance.
    async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64) -> Result<(), AuthError>;
}

/// Postgres-backed [`AuthBackend`] over a generic `accounts` / `user_stats`
/// schema. This is the default and what the standalone router ships with.
pub struct PostgresAuthBackend {
    client: Arc<Client>,
}

impl PostgresAuthBackend {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    /// Create the minimal schema the router needs, if absent. Idempotent.
    ///
    /// Only `accounts(username, password, bandwidth_limit)` + `user_stats` (and
    /// an operational `global` counters row). An optional external system may add
    /// its own columns/tables to the same database; the router ignores them.
    pub async fn initialize_schema(client: &Client) -> Result<(), tokio_postgres::Error> {
        client
            .batch_execute(
                "
                -- Serialise schema creation: CREATE ... IF NOT EXISTS is not
                -- race-safe, and the router + an external backend may initialise
                -- the same database concurrently. Session lock; released at end.
                SELECT pg_advisory_lock(4503599627370497);

                CREATE SEQUENCE IF NOT EXISTS account_id_seq;

                CREATE TABLE IF NOT EXISTS public.global (
                    total_connections BIGINT DEFAULT 0,
                    succeeded_connections BIGINT DEFAULT 0,
                    failed_connections BIGINT DEFAULT 0,
                    total_bytes_in BIGINT DEFAULT 0,
                    total_bytes_out BIGINT DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS public.accounts (
                    account BIGINT PRIMARY KEY DEFAULT nextval('account_id_seq'),
                    registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    password TEXT
                );

                ALTER TABLE public.accounts
                    ADD COLUMN IF NOT EXISTS bandwidth_limit BIGINT DEFAULT NULL;

                -- Default routing selection (username-token format), applied when
                -- a connection requests none (e.g. IP-auth users).
                ALTER TABLE public.accounts
                    ADD COLUMN IF NOT EXISTS default_selection TEXT;

                -- Source IPs / CIDRs allowed to authenticate by address.
                CREATE TABLE IF NOT EXISTS public.account_ips (
                    account BIGINT REFERENCES public.accounts(account),
                    cidr TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_account_ips_account
                    ON public.account_ips(account);

                CREATE TABLE IF NOT EXISTS public.user_stats (
                    id BIGINT PRIMARY KEY,
                    total_connections BIGINT DEFAULT 0,
                    succeeded_connections BIGINT DEFAULT 0,
                    failed_connections BIGINT DEFAULT 0,
                    total_bytes_in BIGINT DEFAULT 0,
                    total_bytes_out BIGINT DEFAULT 0,
                    FOREIGN KEY (id) REFERENCES public.accounts (account)
                );

                INSERT INTO public.global
                    (total_connections, succeeded_connections, failed_connections,
                     total_bytes_in, total_bytes_out)
                SELECT 0, 0, 0, 0, 0
                WHERE NOT EXISTS (SELECT 1 FROM public.global);

                CREATE INDEX IF NOT EXISTS idx_accounts_username ON public.accounts(username);
                CREATE INDEX IF NOT EXISTS idx_user_stats_id ON public.user_stats(id);

                SELECT pg_advisory_unlock(4503599627370497);
                ",
            )
            .await
    }
}

fn backend_err(e: tokio_postgres::Error) -> AuthError {
    AuthError::Backend(e.to_string())
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[async_trait]
impl AuthBackend for PostgresAuthBackend {
    async fn authenticate(
        &self,
        username: &str,
        secret: &str,
    ) -> Result<Option<Account>, AuthError> {
        let row = self
            .client
            .query_opt(
                "SELECT account, bandwidth_limit, default_selection FROM public.accounts \
                 WHERE username = $1 AND password = $2",
                &[&username, &secret],
            )
            .await
            .map_err(backend_err)?;
        Ok(row.map(|row| Account {
            id: row.get(0),
            bandwidth_limit: row.get(1),
            default_selection: row.get(2),
        }))
    }

    async fn authenticate_by_ip(&self, peer: IpAddr) -> Result<Option<Account>, AuthError> {
        let peer = peer.to_string();
        let row = self
            .client
            .query_opt(
                "SELECT a.account, a.bandwidth_limit, a.default_selection \
                 FROM public.account_ips i JOIN public.accounts a ON a.account = i.account \
                 WHERE $1::inet <<= i.cidr::cidr LIMIT 1",
                &[&peer],
            )
            .await
            .map_err(backend_err)?;
        Ok(row.map(|row| Account {
            id: row.get(0),
            bandwidth_limit: row.get(1),
            default_selection: row.get(2),
        }))
    }

    async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64) -> Result<(), AuthError> {
        let bin = to_i64(bytes_in);
        let bout = to_i64(bytes_out);
        self.client
            .execute(
                "UPDATE public.user_stats \
                 SET total_bytes_in = total_bytes_in + $1, \
                     total_bytes_out = total_bytes_out + $2 \
                 WHERE id = $3",
                &[&bin, &bout, &id],
            )
            .await
            .map_err(backend_err)?;
        self.client
            .execute(
                "UPDATE public.accounts \
                 SET bandwidth_limit = GREATEST(bandwidth_limit - $1, 0) WHERE account = $2",
                &[&(bin + bout), &id],
            )
            .await
            .map_err(backend_err)?;
        Ok(())
    }
}

/// An [`AuthBackend`] backed by users listed inline in `config.toml`
/// (`[[user]]`). No database — usage is tracked in memory. This is what makes
/// purroute usable as a personal, single-user proxy with zero infrastructure.
pub struct StaticAuthBackend {
    users: Vec<StaticUser>,
}

struct StaticUser {
    username: String,
    password: String,
    /// Remaining byte allowance; `None` = unlimited.
    remaining: Option<AtomicI64>,
    /// Source networks allowed to authenticate by IP.
    allowed_nets: Vec<IpNet>,
    default_selection: Option<String>,
}

impl StaticAuthBackend {
    /// Build from the `[[user]]` config blocks. Account ids are 1-based indices.
    /// Errors on a malformed `allowed_ips` entry.
    pub fn new(users: &[UserConfig]) -> Result<Self, AuthError> {
        let users = users
            .iter()
            .map(|u| {
                let allowed_nets = u
                    .allowed_ips
                    .iter()
                    .map(|s| parse_net(s))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(StaticUser {
                    username: u.username.clone(),
                    password: u.password.clone(),
                    remaining: u.bandwidth_limit.map(AtomicI64::new),
                    allowed_nets,
                    default_selection: u.default_selection.clone(),
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        Ok(Self { users })
    }

    fn account_for(&self, index: usize, user: &StaticUser) -> Account {
        Account {
            id: i64::try_from(index).unwrap_or(i64::MAX) + 1,
            bandwidth_limit: user.remaining.as_ref().map(|r| r.load(Ordering::Relaxed)),
            default_selection: user.default_selection.clone(),
        }
    }
}

/// Parse an `allowed_ips` entry: a bare IP (`1.2.3.4`) becomes a host network,
/// or a CIDR (`10.0.0.0/24`).
fn parse_net(s: &str) -> Result<IpNet, AuthError> {
    if let Ok(net) = IpNet::from_str(s) {
        return Ok(net);
    }
    let addr = IpAddr::from_str(s)
        .map_err(|_| AuthError::Backend(format!("invalid allowed_ips entry '{s}'")))?;
    Ok(IpNet::from(addr))
}

/// Length-independent constant-time string comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[async_trait]
impl AuthBackend for StaticAuthBackend {
    async fn authenticate(
        &self,
        username: &str,
        secret: &str,
    ) -> Result<Option<Account>, AuthError> {
        for (i, u) in self.users.iter().enumerate() {
            if u.username == username && constant_time_eq(&u.password, secret) {
                return Ok(Some(self.account_for(i, u)));
            }
        }
        Ok(None)
    }

    async fn authenticate_by_ip(&self, peer: IpAddr) -> Result<Option<Account>, AuthError> {
        for (i, u) in self.users.iter().enumerate() {
            if u.allowed_nets.iter().any(|net| net.contains(&peer)) {
                return Ok(Some(self.account_for(i, u)));
            }
        }
        Ok(None)
    }

    async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64) -> Result<(), AuthError> {
        let idx = usize::try_from(id - 1).ok();
        if let Some(user) = idx.and_then(|i| self.users.get(i)) {
            if let Some(rem) = &user.remaining {
                let total = to_i64(bytes_in) + to_i64(bytes_out);
                let mut cur = rem.load(Ordering::Relaxed);
                loop {
                    let next = (cur - total).max(0);
                    match rem.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
                    {
                        Ok(_) => break,
                        Err(observed) => cur = observed,
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, pw: &str, limit: Option<i64>) -> UserConfig {
        UserConfig {
            username: name.into(),
            password: pw.into(),
            bandwidth_limit: limit,
            allowed_ips: Vec::new(),
            default_selection: None,
        }
    }

    fn backend() -> StaticAuthBackend {
        StaticAuthBackend::new(&[
            user("me", "hunter2", None),
            user("limited", "pw", Some(1000)),
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn authenticates_known_user_unlimited() {
        let acct = backend().authenticate("me", "hunter2").await.unwrap();
        let acct = acct.expect("should authenticate");
        assert_eq!(acct.id, 1);
        assert_eq!(acct.bandwidth_limit, None);
    }

    #[tokio::test]
    async fn rejects_wrong_password_and_unknown_user() {
        let b = backend();
        assert!(b.authenticate("me", "wrong").await.unwrap().is_none());
        assert!(b.authenticate("ghost", "x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn report_usage_decrements_limit_and_floors_at_zero() {
        let b = backend();
        // user 2 starts at 1000
        b.report_usage(2, 300, 200).await.unwrap();
        let acct = b.authenticate("limited", "pw").await.unwrap().unwrap();
        assert_eq!(acct.bandwidth_limit, Some(500));
        // overshoot floors at 0
        b.report_usage(2, 10_000, 0).await.unwrap();
        let acct = b.authenticate("limited", "pw").await.unwrap().unwrap();
        assert_eq!(acct.bandwidth_limit, Some(0));
    }

    #[tokio::test]
    async fn unlimited_user_usage_is_noop() {
        let b = backend();
        b.report_usage(1, 9_999, 9_999).await.unwrap();
        let acct = b.authenticate("me", "hunter2").await.unwrap().unwrap();
        assert_eq!(acct.bandwidth_limit, None);
    }

    #[tokio::test]
    async fn ip_auth_matches_exact_and_cidr_with_default_selection() {
        let mut u = user("ipuser", "x", None);
        u.allowed_ips = vec!["1.2.3.4".into(), "10.0.0.0/24".into()];
        u.default_selection = Some("country-us".into());
        let b = StaticAuthBackend::new(&[u]).unwrap();

        // exact
        let a = b
            .authenticate_by_ip("1.2.3.4".parse().unwrap())
            .await
            .unwrap()
            .expect("exact ip authorised");
        assert_eq!(a.default_selection.as_deref(), Some("country-us"));
        // inside CIDR
        assert!(b
            .authenticate_by_ip("10.0.0.99".parse().unwrap())
            .await
            .unwrap()
            .is_some());
        // outside
        assert!(b
            .authenticate_by_ip("9.9.9.9".parse().unwrap())
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn malformed_allowed_ip_is_a_startup_error() {
        let mut u = user("bad", "x", None);
        u.allowed_ips = vec!["not-an-ip".into()];
        assert!(StaticAuthBackend::new(&[u]).is_err());
    }
}

#[cfg(test)]
mod auth_cov {
    use super::*;

    fn cfg(name: &str, pw: &str, limit: Option<i64>) -> UserConfig {
        UserConfig {
            username: name.into(),
            password: pw.into(),
            bandwidth_limit: limit,
            allowed_ips: Vec::new(),
            default_selection: None,
        }
    }

    #[tokio::test]
    async fn authenticate_hit_surfaces_default_selection_and_limit() {
        let mut u = cfg("me", "pw", Some(4096));
        u.default_selection = Some("country-de".into());
        let b = StaticAuthBackend::new(&[u]).unwrap();
        let a = b.authenticate("me", "pw").await.unwrap().expect("hit");
        assert_eq!(a.id, 1);
        assert_eq!(a.bandwidth_limit, Some(4096));
        assert_eq!(a.default_selection.as_deref(), Some("country-de"));
    }

    #[tokio::test]
    async fn authenticate_miss_unknown_and_wrong_password() {
        let b = StaticAuthBackend::new(&[cfg("me", "secret", None)]).unwrap();
        assert!(b.authenticate("nobody", "secret").await.unwrap().is_none());
        assert!(b.authenticate("me", "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn second_user_gets_id_two() {
        let b = StaticAuthBackend::new(&[cfg("a", "1", None), cfg("b", "2", None)]).unwrap();
        let a = b.authenticate("b", "2").await.unwrap().unwrap();
        assert_eq!(a.id, 2);
    }

    #[test]
    fn constant_time_eq_length_mismatch_and_content() {
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(constant_time_eq("abc", "abc"));
        assert!(constant_time_eq("", ""));
    }

    #[tokio::test]
    async fn ip_auth_exact_bare_ip_and_cidr_and_nonmatch() {
        let mut u = cfg("ip", "x", None);
        u.allowed_ips = vec!["10.0.0.0/24".into(), "1.2.3.4".into()];
        let b = StaticAuthBackend::new(&[u]).unwrap();

        assert!(b
            .authenticate_by_ip("1.2.3.4".parse().unwrap())
            .await
            .unwrap()
            .is_some());
        assert!(b
            .authenticate_by_ip("10.0.0.7".parse().unwrap())
            .await
            .unwrap()
            .is_some());
        // bare ip is a /32 host: a neighbour is not authorised
        assert!(b
            .authenticate_by_ip("1.2.3.5".parse().unwrap())
            .await
            .unwrap()
            .is_none());
        assert!(b
            .authenticate_by_ip("10.0.1.1".parse().unwrap())
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_net_accepts_cidr_bare_and_rejects_garbage() {
        assert!(parse_net("10.0.0.0/24").is_ok());
        assert!(parse_net("1.2.3.4").is_ok());
        // invalid CIDR prefix and non-ip both error gracefully (no panic)
        assert!(parse_net("10.0.0.0/99").is_err());
        assert!(parse_net("definitely not an ip").is_err());
    }

    #[test]
    fn invalid_cidr_in_allowed_ips_is_startup_error() {
        let mut u = cfg("bad", "x", None);
        u.allowed_ips = vec!["10.0.0.0/99".into()];
        assert!(StaticAuthBackend::new(&[u]).is_err());
    }

    #[tokio::test]
    async fn report_usage_accumulates_and_floors() {
        let b = StaticAuthBackend::new(&[cfg("u", "p", Some(1000))]).unwrap();
        b.report_usage(1, 100, 100).await.unwrap();
        let a = b.authenticate("u", "p").await.unwrap().unwrap();
        assert_eq!(a.bandwidth_limit, Some(800));
        b.report_usage(1, 300, 0).await.unwrap();
        let a = b.authenticate("u", "p").await.unwrap().unwrap();
        assert_eq!(a.bandwidth_limit, Some(500));
        b.report_usage(1, 10_000, 0).await.unwrap();
        let a = b.authenticate("u", "p").await.unwrap().unwrap();
        assert_eq!(a.bandwidth_limit, Some(0));
    }

    #[tokio::test]
    async fn report_usage_unlimited_is_noop() {
        let b = StaticAuthBackend::new(&[cfg("u", "p", None)]).unwrap();
        b.report_usage(1, 5, 5).await.unwrap();
        let a = b.authenticate("u", "p").await.unwrap().unwrap();
        assert_eq!(a.bandwidth_limit, None);
    }

    #[tokio::test]
    async fn report_usage_out_of_range_id_is_ignored() {
        let b = StaticAuthBackend::new(&[cfg("u", "p", Some(1000))]).unwrap();
        // id 0 -> idx underflow None; id 99 -> no such user
        b.report_usage(0, 10, 10).await.unwrap();
        b.report_usage(99, 10, 10).await.unwrap();
        let a = b.authenticate("u", "p").await.unwrap().unwrap();
        assert_eq!(a.bandwidth_limit, Some(1000));
    }
}
