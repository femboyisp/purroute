# purroute wiki 🧶

purroute is an auto-detecting proxy router/gateway. It listens on one address,
sniffs the inbound protocol (SOCKS5, SOCKS4/4a, HTTP, HTTPS-CONNECT) from the
first bytes, and forwards upstream through a single proxy or a multi-hop chain —
translating between protocols as needed. Per-user auth, bandwidth limits, and
tag-based exit selection ride on a pluggable `AuthBackend`.

## Pages

- **[Configuration](Configuration)** — every config section, with examples.
- **[Routing tokens](Routing-tokens)** — choose an exit from the proxy username.
- **[Auth backends](Auth-backends)** — inline users, PostgreSQL, or your own.

## At a glance

```toml
[router]
listen = "127.0.0.1:1080"
auth = true
chain = "exit"

[[user]]
username = "me"
password = "hunter2"

[[proxy]]
label = "exit"
proxy_type = "Socks5"
address = "10.0.0.1:1080"
country = "us"
```

```sh
cargo run --release
curl -x socks5h://me-country-us:hunter2@127.0.0.1:1080 https://api.ipify.org
```

No database required — that config runs a personal proxy. Swap `[[user]]` for a
`[database]` section to serve many accounts from PostgreSQL.

GPL-3.0-or-later.
