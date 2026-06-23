# Auth backends

The router depends on accounts only through the `AuthBackend` trait
(`src/auth.rs`):

```rust
async fn authenticate(&self, username: &str, secret: &str)
    -> Result<Option<Account>, AuthError>;
async fn authenticate_by_ip(&self, ip: IpAddr)
    -> Result<Option<Account>, AuthError>;          // default: Ok(None)
async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64)
    -> Result<(), AuthError>;
```

An `Account` carries `{ id, bandwidth_limit: Option<i64>, default_selection:
Option<String> }`. `bandwidth_limit = None` means unlimited.

Two implementations ship; you can write your own (e.g. against an HTTP API).

## StaticAuthBackend — inline, no database

Users come from `[[user]]` blocks. Auth is a constant-time compare; usage is
in-memory counters. Perfect for a personal proxy.

```toml
[[user]]
username = "me"
password = "hunter2"
# bandwidth_limit = 1073741824       # optional bytes; omit = unlimited
# allowed_ips = ["10.0.0.0/24"]      # optional: these source IPs skip auth
# default_selection = "country-us"   # optional: route for credential-less conns
```

## PostgresAuthBackend — many accounts

Activated by a `[database]` section. Reads `(username, password,
bandwidth_limit, default_selection)` from `accounts` and the IP allowlist from
`account_ips` (`WHERE $1::inet <<= cidr`). The router creates a minimal subset of
the schema idempotently; a richer backend (such as socks.cat's) may own a
superset of the same tables.

## Authentication order

1. If the connection presents credentials, `authenticate(username, secret)` runs
   (the username may carry [routing tokens](Routing-tokens) — the base is used).
2. Otherwise `authenticate_by_ip(peer)` runs. An IP-authed connection has no
   username, so it routes via the account's `default_selection`.
3. Neither succeeds → the connection is rejected.
