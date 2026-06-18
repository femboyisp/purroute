# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`purroute` is a self-contained Rust proxy router/gateway. It listens on a local address, **auto-detects the inbound proxy protocol** (SOCKS5, SOCKS4/4a, HTTP, HTTPS-CONNECT) from the first bytes of each connection, then forwards the traffic upstream through a configured proxy or a multi-hop chain — translating between protocols as needed. It enforces per-user auth and bandwidth limits through a pluggable [`AuthBackend`], and exposes a local-only Prometheus `/metrics` endpoint.

It is **standalone**: it has no dependency on any business/billing code. A separate private backend may manage accounts and payments in the *same* database; purroute only ever reads `(username, secret, bandwidth_limit)` and writes usage.

## Commands

```sh
cp config.toml.example config.toml      # required; main() reads "config.toml" from cwd
docker-compose up --build               # start the PostgreSQL dependency (required to run)
cargo run --release                     # build + run the proxy
cargo build                             # debug build
cargo test                              # unit tests
cargo clippy --all-targets -- -D warnings
```

Integration tests live in `tests/integration/` and spin up real proxy containers — not hermetic:
```sh
cd tests/integration && docker-compose up -d   # SOCKS5:1080 SOCKS4:1081 HTTP/S:8888 target:8080
cargo test --test integration -- --nocapture
```
Targets are configurable via `TEST_TARGET_*` env vars (default to the local `target:8080`).

## Runtime topology (main.rs)

`main()` wires `tokio` tasks sharing `Arc`s:
1. Connects to Postgres and runs `PostgresAuthBackend::initialize_schema()` — the router's **minimal** schema source of truth (idempotent `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`). Tables: `global`, `accounts(account, username, password, bandwidth_limit)`, `user_stats`. No payments/business columns — a private backend layers those on the same DB.
2. Builds a `PostgresAuthBackend` and hands it to `ProxyServer` as `Arc<dyn AuthBackend>`.
3. Spawns the stats display task (`StatsDisplay::run`, crossterm TUI, flushes to DB every 2s).
4. Serves the local-only Prometheus endpoint if `[router].metrics_listen` is set.
5. Runs `ProxyServer::run()` on `router.listen` (blocks).

The DB is a hard dependency: `main` errors out if `[database]` config is missing.

## Module map

- `src/config.rs` — TOML config types + `load_config()` returning `(RouterConfig, Vec<ProxyConfig>, chains, db)`. Unknown sections (e.g. a backend's `[payments]`) are ignored so router + backend can share one `config.toml`.
- `src/protocol.rs` — the `Protocol` enum (`Http/Https/Socks4/Socks5`), re-exported as `Proxy` in `protocols::`.
- `src/auth.rs` — the [`AuthBackend`] trait (`authenticate`, `report_usage`) — the router's *only* dependency on user accounts — plus `PostgresAuthBackend` (default) and the minimal schema. A future `HttpAuthBackend` could implement the same trait against a remote API and drop the DB entirely.
- `src/protocols/` — the core. `proxy.rs` is the heart:
  - `ProxyServer::detect_protocol()` sniffs the first byte (`0x05`/`0x04`) or HTTP verb / `CONNECT`.
  - `resolve_proxy_chain()` turns `router.chain` into the upstream path: a single `[[proxy]]` by `label`, else a `[[chain]]` by `chain_id`, applying `ChainMode::Strict`/`Random`.
  - `handle_connection()` dispatches per detected protocol; multi-hop chains (>1 proxy) route through `handle_{socks5,socks4,https,http}_chain()` via `ChainConnector`, single-hop through the per-protocol handlers.
  - auth + usage go through `self.auth` (the `AuthBackend`), never raw SQL.
  - `chain.rs` (`ChainConnector::connect_chain`) tunnels hop-by-hop to the destination.
  - One file per inbound protocol: `http.rs`, `https.rs`, `socks4.rs`, `socks5.rs`.
- `src/stats/` — `global.rs` holds the process-wide `GlobalStats` singleton; `display.rs` is the crossterm dashboard + DB flush. Logging goes through `GlobalStats::log_*`, gated by `router.log/verbose/debug`.

## Configuration model

`config.toml` drives everything (see `config.toml.example`):
- `[router].chain` selects the upstream — a `[[proxy]].label` (single) or a `[[chain]].chain_id` (multi-hop).
- `[[proxy]]` blocks define upstreams (`proxy_type` ∈ `Http/Https/Socks4/Socks5`, address, optional auth). `[[chain]]` blocks reference proxies by label with a `mode` and optional `count`.
- `[router].auth` toggles user authentication against the `accounts` table via the `AuthBackend`.
- `[router].metrics_listen` (optional) exposes Prometheus metrics on a local address.
