# purroute

An auto-detecting proxy router/gateway. It listens on a local address,
**detects the inbound proxy protocol** (SOCKS5, SOCKS4/4a, HTTP, HTTPS-CONNECT)
from the first bytes of each connection, and forwards traffic upstream through a
single proxy or a multi-hop chain — translating between protocols as needed. It
enforces per-user auth and bandwidth limits through a pluggable `AuthBackend`.

purroute is self-contained: it has no account, billing, or payment code. A
separate system may manage users in the same database; purroute only ever reads
`(username, secret, bandwidth_limit)` and reports usage.

## Features

- Auto-detection of the inbound protocol — one endpoint serves every client type.
- Protocol translation across all inbound→upstream combinations.
- Multi-hop chaining (strict or random order) for every inbound protocol.
- Pluggable authentication (`AuthBackend`); ships with a PostgreSQL backend.
- Local-only Prometheus `/metrics` endpoint.

## Quick start

```sh
cp config.toml.example config.toml      # main() reads "config.toml" from cwd
docker-compose up --build               # PostgreSQL dependency
cargo run --release
```

See `config.toml.example` for the full configuration model (`[[proxy]]`,
`[[chain]]`, `[router]`, `[database]`). `CLAUDE.md` documents the internals.

## Auth backend

The router depends only on the `AuthBackend` trait (`src/auth.rs`):

```rust
async fn authenticate(&self, username: &str, secret: &str) -> Result<Option<Account>, AuthError>;
async fn report_usage(&self, id: i64, bytes_in: u64, bytes_out: u64) -> Result<(), AuthError>;
```

`PostgresAuthBackend` is the default. Implement the trait against an HTTP API or
any other store to drop the database dependency entirely.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
