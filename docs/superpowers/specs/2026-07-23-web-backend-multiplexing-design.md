# purroute web-backend multiplexing — design

**Date:** 2026-07-23
**Status:** approved, pre-implementation
**Repo:** purroute (OSS router)

## Goal

Let a single purroute inbound listener serve **both** proxy traffic and a plain-HTTP
web backend, distinguished by what the client sends. This lets one entry point — a
Tor onion, an I2P destination, or a clearnet address — front both the SOCKS/HTTP proxy
gateway and a co-located web app (e.g. socks.cat's dashboard) on one port, so a single
hidden-service address covers everything.

## Why

purroute already sniffs each inbound connection's first bytes and branches
SOCKS5/SOCKS4/HTTP-CONNECT/HTTP (`ProxyServer::detect_protocol`, `proxy.rs:889`).
Today an HTTP request is only ever treated as a **forward proxy**. But a browser
visiting purroute as if it were a website sends an **origin-form** request
(`GET /path HTTP/1.1` + `Host:`), which purroute can distinguish from a forward-proxy
**absolute-form** request (`GET http://host/path`). Routing origin-form requests to a
configured web backend turns purroute into a protocol multiplexer with no ambiguity.

Downstream (out of scope here) this is what lets socks.cat expose one vanity
`.onion` and one vanity `.b32.i2p` that each serve dashboard + gateway.

## The discriminator (core of the design)

After protocol detection yields HTTP (not SOCKS, not CONNECT), inspect the
request-target form of the first line:

- **absolute-form** — target begins `http://` or `https://` (e.g.
  `GET http://example.com/ HTTP/1.1`) → **forward proxy** (existing behavior).
- **origin-form** — target begins `/` (e.g. `GET /account HTTP/1.1`) → **reverse-proxy
  to the web backend** (new behavior), only when a backend is configured.

SOCKS5 (`0x05`), SOCKS4 (`0x04`), and HTTP `CONNECT` (authority-form) are untouched —
none can collide with origin-form, so the split is unambiguous.

## Components (all in purroute)

### 1. Config — `[router].web_backend`
- Add `pub web_backend: Option<String>` to `RouterConfig` (`src/config.rs`), a
  `host:port` string. `None` (unset) ⇒ feature entirely off; origin-form requests
  keep today's behavior (fall through to the forward-proxy path).
- Documented in `config.toml.example`.

### 2. Detection — request-target form
- A small pure helper, e.g. `fn is_origin_form_http(initial_request: &[u8]) -> bool`,
  that returns true when the first line is `<METHOD> /… HTTP/1.x` (target starts with
  `/`) and false for absolute-form / CONNECT. Unit-testable in isolation.
- In `handle_connection` (`proxy.rs`), when `detect_protocol` returns `Proxy::Http`
  **and** `web_backend` is `Some` **and** `is_origin_form_http(&initial_request)` ⇒
  take the web branch; otherwise unchanged.

### 3. Reverse proxy — `handle_web_backend`
- Connect a `TcpStream` to the configured `web_backend`.
- Write the already-read `initial_request` bytes to it verbatim (replay), then
  **bidirectionally relay** client ↔ backend using purroute's existing relay
  machinery (the same splice used by every proxy path). No HTTP parsing/rewriting
  beyond the first-line peek.
- **Raw relay is correct**: the browser's `Host:` header and relative links pass
  through untouched; keep-alive and pipelined requests work because after the
  first line it is a byte-for-byte TCP splice. The web app must render its own
  absolute references from its own config (socks.cat's does — it uses
  `gateway_host`, not the inbound `Host`), and use relative links.
- Plain HTTP (no TLS) is intentional: `.onion` / `.b32.i2p` provide their own
  transport encryption, and onion services conventionally serve plain HTTP.

## Behavior notes

- **Clearnet is affected too, by design.** Detection is per-connection, so any
  inbound to purroute (including the clearnet gateway port) serves the dashboard to
  browsers and proxies to SOCKS/forward-proxy clients on the same port. This is
  harmless (the web app is already public) and is the intended "one port does
  both" property. Not scoped to hidden networks — scoping would require a second
  listener and is explicitly not done.
- **Backend down / connect fails**: return a minimal `502`-class response (or close)
  and log via `GlobalStats`; do not hang. Exact shape decided in the plan, but it
  must not panic or leak the client connection.
- **OSS-safe**: no socks.cat specifics anywhere. Generic "reverse-proxy origin-form
  HTTP to a configured backend" — useful to any purroute user.

## Testing

- `is_origin_form_http`: true for `GET /`, `POST /x`, mixed methods; false for
  `GET http://x/`, `CONNECT x:443`, SOCKS byte prefixes, empty/garbage.
- `handle_web_backend`: origin-form request → bytes arrive at a fake backend and a
  reply relays back; multiple bytes / partial reads handled.
- Dispatch: with `web_backend` set, origin-form → web branch; absolute-form → still
  forward-proxy; CONNECT/SOCKS → unchanged. With `web_backend` unset, origin-form →
  existing behavior (no web branch).
- Config parse: `web_backend` present/absent both parse; absent ⇒ `None`.
- Keep purroute green: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
  `cargo test`, and the coverage gate as configured.

## Out of scope

- The hidden-service deployment (restoring the vanity Tor/I2P keys into the sockscat
  container, pointing tor + i2pd at purroute). That is a **separate spec** in the
  deploy repo that consumes this feature.
- TLS termination, HTTP header rewriting, path routing, load balancing — this is a
  single-backend transparent reverse proxy, nothing more.
