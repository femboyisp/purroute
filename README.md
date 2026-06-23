# purroute

An auto-detecting proxy router/gateway. It listens on a local address,
**detects the inbound proxy protocol** (SOCKS5, SOCKS4/4a, HTTP, HTTPS-CONNECT)
from the first bytes of each connection, and forwards traffic upstream through a
single proxy or a multi-hop chain — translating between protocols as needed. It
enforces per-user auth and bandwidth limits through a pluggable `AuthBackend`.

purroute is self-contained: accounts come from a pluggable `AuthBackend`, so it
runs **with no database at all** (users listed in `config.toml`) or against
PostgreSQL for many users. It only ever reads `(username, secret,
bandwidth_limit)` and reports usage.

## Features

- Auto-detection of the inbound protocol — one endpoint serves every client type.
- Protocol translation across all inbound→upstream combinations.
- Multi-hop chaining (strict or random order) for every inbound protocol.
- Pluggable authentication (`AuthBackend`): inline users (no database) or PostgreSQL.
- Local-only Prometheus `/metrics` endpoint.

## Quick start (single user, no database)

```sh
cp config.toml.example config.toml      # main() reads "config.toml" from cwd
# config.toml: a [router], one [[proxy]], and one [[user]] — no [database] needed
cargo run --release
```

```toml
[router]
listen = "127.0.0.1:1080"
auth = true
chain = "exit"

[[user]]
username = "me"
password = "hunter2"
# bandwidth_limit = 1073741824   # optional, bytes; omit for unlimited

[[proxy]]
label = "exit"
proxy_type = "Socks5"
address = "10.0.0.1:1080"
```

Point any proxy client at `127.0.0.1:1080` with `me:hunter2`.

For many users, add a `[database]` section (and `docker-compose up --build` for a
local PostgreSQL) instead of `[[user]]` blocks. See `config.toml.example` for the
full model; `CLAUDE.md` documents the internals.

## Auth backend

The router depends only on the `AuthBackend` trait (`src/auth.rs`):

```rust
async fn authenticate(&self, username: &str, secret: &str) -> Result<Option<Account>, AuthError>;
async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64) -> Result<(), AuthError>;
```

It ships with `StaticAuthBackend` (inline users, no database) and
`PostgresAuthBackend`. Implement the trait against an HTTP API or any other store
to plug in your own account source.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
