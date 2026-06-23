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

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio_postgres::Client;

use crate::config::UserConfig;

/// A validated account: its id and remaining byte allowance (`None` = no limit).
#[derive(Debug, Clone, Copy)]
pub struct Account {
    pub id: i64,
    pub bandwidth_limit: Option<i64>,
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
                "SELECT account, bandwidth_limit FROM public.accounts \
                 WHERE username = $1 AND password = $2",
                &[&username, &secret],
            )
            .await
            .map_err(backend_err)?;
        Ok(row.map(|row| Account {
            id: row.get(0),
            bandwidth_limit: row.get(1),
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
}

impl StaticAuthBackend {
    /// Build from the `[[user]]` config blocks. Account ids are 1-based indices.
    pub fn new(users: &[UserConfig]) -> Self {
        let users = users
            .iter()
            .map(|u| StaticUser {
                username: u.username.clone(),
                password: u.password.clone(),
                remaining: u.bandwidth_limit.map(AtomicI64::new),
            })
            .collect();
        Self { users }
    }
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
                let id = i64::try_from(i).unwrap_or(i64::MAX) + 1;
                let bandwidth_limit = u.remaining.as_ref().map(|r| r.load(Ordering::Relaxed));
                return Ok(Some(Account {
                    id,
                    bandwidth_limit,
                }));
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

    fn backend() -> StaticAuthBackend {
        StaticAuthBackend::new(&[
            UserConfig {
                username: "me".into(),
                password: "hunter2".into(),
                bandwidth_limit: None,
            },
            UserConfig {
                username: "limited".into(),
                password: "pw".into(),
                bandwidth_limit: Some(1000),
            },
        ])
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
}
