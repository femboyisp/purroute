# Configuration

purroute reads `config.toml` from the working directory. `config.toml.example`
is the annotated reference; this page summarizes each section.

## `[router]`

| Key | Meaning |
|-----|---------|
| `listen` | address(es) to listen on — a string or an array (`["[::]:1337", "10.13.37.1:1337"]`) |
| `auth` | require per-connection authentication |
| `chain` | default route: a single proxy `label`, or a `chain_id` (strict/random) |
| `metrics_listen` | optional local-only Prometheus `/metrics` address |
| `log` / `verbose` / `debug` | logging verbosity |

`chain` is the **global** route; tagged upstreams + [routing tokens](Routing-tokens)
override it per connection.

## Accounts — pick one backend

- **`[[user]]`** — inline users, no database (see [Auth backends](Auth-backends)
  for `bandwidth_limit`, `allowed_ips`, `default_selection`).
- **`[database]`** — PostgreSQL for many accounts (`host`, `port`, `user`,
  `password`, `dbname`). Omit `[[user]]` when using it.

## `[[proxy]]` — upstreams

```toml
[[proxy]]
label = "us-comcast"
proxy_type = "Socks5"        # Http | Https | Socks4 | Socks5
address = "10.0.0.1:1080"
# username / password        # optional upstream auth
# country / city / isp / type  # optional exit tags for routing tokens
```

## `[[chain]]` — multi-hop

```toml
[[chain]]
chain_id = "strict-chain"
mode = "strict"              # exact order: Tor -> HttpProxy
proxies = ["Tor", "HttpProxy"]

[[chain]]
chain_id = "random-multi"
mode = "random"
count = 2                    # pick N at random and chain them
proxies = ["Tor", "HttpProxy", "Kitty"]
```

Reference a chain by its `chain_id` in `[router].chain`, or let clients select
tagged single-hop exits with routing tokens.
