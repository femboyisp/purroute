//! Authentication + usage-reporting backend for the router.
//!
//! The router does not care *how* a user came to exist or how their traffic
//! allowance was paid for — only whether a `(username, secret)` is valid and how
//! many bytes they have left. That contract is the [`AuthBackend`] trait.
//!
//! The default [`PostgresAuthBackend`] reads a generic `accounts` table and
//! writes usage to `user_stats`. A private backend can own a *superset* of this
//! schema (payments, subaddresses, …); the router only ever touches the columns
//! defined here. A future `HttpAuthBackend` could implement the same trait
//! against a remote API and drop the database dependency entirely.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_postgres::Client;

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
    /// an operational `global` counters row) — no business columns. A private
    /// backend layers its own columns/tables on top of the same database.
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
