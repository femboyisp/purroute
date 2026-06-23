# Routing tokens

When upstreams are tagged, clients pick an exit by appending `-key-value` tokens
to the proxy **username**. The base (everything before the first known key) still
authenticates; the tokens only select the exit.

```
me-country-us,de-city-nyc-isp-comcast-type-residential-session-ab12
└base┘└──────────────────── routing tokens ────────────────────────┘
```

## Keys

| Key | Matches the upstream tag | Notes |
|-----|--------------------------|-------|
| `country` | `country` | ISO code, e.g. `us` |
| `city` | `city` | |
| `isp` | `isp` | network / ISP name |
| `type` | `type` | exit kind, e.g. `residential`, `mobile` |
| `session` | — | sticky session id (see below) |

Parsing stops at the first **unknown** key (it's treated as part of the base), so
usernames that don't use tokens pass through untouched.

## Sets

Comma-separate values for "any of these". A connection matches an upstream when
**every** specified key matches; among matches, the gateway rotates (or sticks —
see below). No match → the connection is refused (fail closed).

```
me-country-us,de-type-residential   # any US or DE residential exit
```

## Sticky sessions

`session-<id>` pins one exit out of the matching set for as long as the id is
reused (selection is a stable FNV-1a hash of the id over the matching set).
Change the id to jump; omit it to rotate on every connection.

## Tagging upstreams

```toml
[[proxy]]
label = "us-comcast"
proxy_type = "Socks5"
address = "10.0.0.1:1080"
country = "us"
city = "nyc"
isp = "comcast"
type = "residential"
```

## Default selection

An account may carry a `default_selection` (a token string like
`country-us-isp-comcast`) applied when the username has no tokens — and for
IP-authenticated connections, which have no username to encode tokens into. See
[Auth backends](Auth-backends).
