# purroute Web-Backend Multiplexing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one purroute inbound port serve both proxy traffic and a plain-HTTP web backend — origin-form HTTP requests (`GET /path`) reverse-proxy to a configured `[router].web_backend`, while forward-proxy and SOCKS traffic are unchanged.

**Architecture:** After `detect_protocol` classifies an inbound connection as `Proxy::Http`, a new discriminator checks the request-target form. Origin-form (`GET /…`) + a configured `web_backend` short-circuits into a transparent TCP reverse proxy (`handle_web_backend`): connect to the backend, replay the already-read request bytes, then `copy_bidirectional`. Absolute-form (`GET http://…`), `CONNECT`, and SOCKS keep today's behavior.

**Tech Stack:** Rust, tokio (`TcpStream`, `tokio::io::copy_bidirectional`), serde/TOML config.

## Global Constraints

- Feature is **config-gated**: `[router].web_backend` is `Option<String>`; unset ⇒ behavior identical to today (origin-form falls through to the existing forward-proxy path).
- **OSS-safe**: no socks.cat specifics anywhere — generic "reverse-proxy origin-form HTTP to a configured backend".
- **Raw relay only**: replay the initial bytes, then bidirectional splice. No HTTP header rewriting, no TLS, no path routing.
- Keep purroute green: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --bins`, and `cargo llvm-cov --bins --fail-under-lines 90 --ignore-filename-regex '(main\.rs|stats/display\.rs)'` (proxy.rs and config.rs **are** counted — new code needs tests).
- The dispatch insertion sits **before** proxy-specific work (`selection_for`, `resolve_proxy_chain_for_target`) so a web request never runs upstream resolution.

## File Structure

- `src/config.rs` — add `web_backend: Option<String>` to `RouterConfig` + its `Default`.
- `config.toml.example` — document the new key.
- `src/protocols/proxy.rs` — add the pure `is_origin_form_http` helper, the `handle_web_backend` method, and the dispatch short-circuit in `handle_connection`. Tests live in the existing `#[cfg(test)] mod` in this file (reuses `fake_http_upstream`, `serve1`, `rcfg`, `client_to`).

---

### Task 1: `web_backend` config field

**Files:**
- Modify: `src/config.rs` (`RouterConfig` struct ~line 56; `impl Default for RouterConfig` ~line 97)
- Modify: `config.toml.example`

**Interfaces:**
- Produces: `RouterConfig.web_backend: Option<String>` — a `host:port` backend address; `None` when the key is absent.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `src/config.rs` (near the other `Config::load` / parse tests):

```rust
#[test]
fn web_backend_parses_and_defaults_none() {
    // Present: parsed into Some.
    let toml_with = r#"
[router]
listen = "127.0.0.1:1080"
web_backend = "127.0.0.1:8090"
"#;
    let cfg: Config = toml::from_str(toml_with).unwrap();
    assert_eq!(cfg.router.web_backend.as_deref(), Some("127.0.0.1:8090"));

    // Absent: defaults to None.
    let toml_without = r#"
[router]
listen = "127.0.0.1:1080"
"#;
    let cfg: Config = toml::from_str(toml_without).unwrap();
    assert_eq!(cfg.router.web_backend, None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bins web_backend_parses_and_defaults_none`
Expected: FAIL — compile error, `no field web_backend on RouterConfig`.

- [ ] **Step 3: Add the field + default**

In `src/config.rs`, add to `pub struct RouterConfig` (after `metrics_listen`):

```rust
    /// Optional `host:port`. When set, origin-form HTTP requests (a browser
    /// treating the proxy as a website, `GET /path`) are reverse-proxied here
    /// instead of being handled as forward-proxy requests. Unset disables it.
    pub web_backend: Option<String>,
```

And in `impl Default for RouterConfig` (add the field to the struct literal):

```rust
            web_backend: None,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bins web_backend_parses_and_defaults_none`
Expected: PASS.

- [ ] **Step 5: Document in `config.toml.example`**

In the `[router]` section, add:

```toml
# Optional. When set, a browser hitting this router (origin-form HTTP, `GET /path`)
# is reverse-proxied to this plain-HTTP backend, while SOCKS / forward-proxy traffic
# on the same port is proxied as usual. Lets one port (or one hidden-service address)
# serve both a proxy and a web app. Leave unset to disable.
#web_backend = "127.0.0.1:8090"
```

- [ ] **Step 6: Commit**

```bash
git add src/config.rs config.toml.example
git commit -m ":sparkles: config — add [router].web_backend (optional reverse-proxy target)"
```

---

### Task 2: `is_origin_form_http` detection helper

**Files:**
- Modify: `src/protocols/proxy.rs` (add a free function near `detect_protocol`; tests in the in-file `#[cfg(test)] mod`)

**Interfaces:**
- Produces: `fn is_origin_form_http(req: &[u8]) -> bool` — true iff the first line is `<METHOD> /… HTTP/1.x` (origin-form); false for absolute-form (`GET http://…`), `CONNECT`, SOCKS byte prefixes, and empty/garbage.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `src/protocols/proxy.rs`:

```rust
#[test]
fn origin_form_http_detection() {
    // Origin-form: browser hitting us as a website.
    assert!(is_origin_form_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    assert!(is_origin_form_http(b"GET /account HTTP/1.1\r\nHost: x\r\n\r\n"));
    assert!(is_origin_form_http(b"POST /signup HTTP/1.1\r\nHost: x\r\n\r\n"));
    // Absolute-form: forward-proxy request — NOT origin-form.
    assert!(!is_origin_form_http(b"GET http://example.com/ HTTP/1.1\r\n\r\n"));
    // CONNECT (authority-form) — NOT origin-form.
    assert!(!is_origin_form_http(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"));
    // SOCKS byte prefixes — NOT HTTP at all.
    assert!(!is_origin_form_http(&[0x05, 0x01, 0x00]));
    assert!(!is_origin_form_http(&[0x04, 0x01, 0x00, 0x50]));
    // Empty / garbage.
    assert!(!is_origin_form_http(b""));
    assert!(!is_origin_form_http(b"not http at all"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bins origin_form_http_detection`
Expected: FAIL — compile error, `cannot find function is_origin_form_http`.

- [ ] **Step 3: Implement the helper**

Add near `detect_protocol` in `src/protocols/proxy.rs` (module-level free function, not a method):

```rust
/// True when `req` is an **origin-form** HTTP request (`<METHOD> /path HTTP/1.x`) —
/// a client treating this router as an origin web server. This is distinct from a
/// forward-proxy request, which uses **absolute-form** (`GET http://host/…`) or
/// `CONNECT` (authority-form). Only the first ~64 bytes are inspected, which always
/// covers the method and the start of the request target.
fn is_origin_form_http(req: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&req[..req.len().min(64)]);
    let Some(first_line) = head.lines().next() else {
        return false;
    };
    let mut parts = first_line.split(' ');
    let method = parts.next().unwrap_or("");
    if !matches!(
        method,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE" | "PATCH"
    ) {
        return false;
    }
    // Origin-form targets start with '/'; absolute-form starts with the scheme.
    parts.next().unwrap_or("").starts_with('/')
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bins origin_form_http_detection`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/proxy.rs
git commit -m ":sparkles: proxy — is_origin_form_http (origin- vs absolute-form discriminator)"
```

---

### Task 3: `handle_web_backend` reverse proxy + dispatch wiring

**Files:**
- Modify: `src/protocols/proxy.rs` — add the `handle_web_backend` method on `impl ProxyServer`, wire the short-circuit into `handle_connection`, add a `mk_web` test helper + integration tests.

**Interfaces:**
- Consumes: `RouterConfig.web_backend` (Task 1); `is_origin_form_http` (Task 2); existing `Proxy::Http`, `self.config`, `GlobalStats`.
- Produces: `async fn handle_web_backend(&self, client: TcpStream, initial_request: Vec<u8>, backend: &str, global_stats: Arc<GlobalStats>) -> Result<(), ProxyError>`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `src/protocols/proxy.rs`. This reuses the existing `fake_http_upstream`, `serve1`, `client_to`, and `rcfg` helpers already in that module, and adds a `mk_web` helper:

```rust
/// A ProxyServer whose RouterConfig has `web_backend` set (no upstreams needed —
/// web requests short-circuit before upstream resolution).
fn mk_web(web_backend: &str) -> ProxyServer {
    let backend = Arc::new(StaticAuthBackend::new(&[]).unwrap());
    let display = Arc::new(StatsDisplay::new(
        get_global_stats(),
        Duration::from_secs(60),
        None,
    ));
    let cfg = Arc::new(RouterConfig {
        web_backend: Some(web_backend.to_owned()),
        ..RouterConfig::default()
    });
    ProxyServer::new(vec![], None, display, cfg, backend)
}

#[tokio::test]
async fn web_backend_relays_origin_form_request() {
    // Fake web backend captures what it receives and replies 200.
    let (backend_addr, rx) = fake_http_upstream().await;
    let srv = mk_web(&backend_addr.to_string());
    let front = serve1(srv).await;

    let mut c = client_to(front).await;
    c.write_all(b"GET /account HTTP/1.1\r\nHost: sockscat.onion\r\n\r\n")
        .await
        .unwrap();
    // Backend received the origin-form request verbatim (replayed initial bytes).
    let got = rx.await.unwrap();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("GET /account HTTP/1.1"), "got: {text}");
    // And the backend's reply relays back to the client.
    let mut reply = vec![0u8; 32];
    let n = c.read(&mut reply).await.unwrap();
    assert!(
        String::from_utf8_lossy(&reply[..n]).contains("200 OK"),
        "expected 200 relayed back"
    );
}

#[tokio::test]
async fn web_backend_unset_does_not_route_origin_form() {
    // With no web_backend, an origin-form request must NOT reach a web backend;
    // it falls through to the existing (forward-proxy) HTTP path. We assert the
    // fake backend never receives anything.
    let (backend_addr, rx) = fake_http_upstream().await;
    // Note: server built WITHOUT web_backend (default None), proxies empty.
    let srv = mk(vec![], None, None, vec![], false);
    let front = serve1(srv).await;
    let mut c = client_to(front).await;
    let _ = c
        .write_all(b"GET /account HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    // The backend must not have been contacted (nothing connected to backend_addr).
    let quick = tokio::time::timeout(Duration::from_millis(150), rx).await;
    assert!(quick.is_err(), "web backend must not be reached when unset");
    let _ = backend_addr; // backend intentionally unused
}

#[tokio::test]
async fn web_backend_down_returns_502() {
    // web_backend points at a closed port -> client gets a 502, no hang/panic.
    // 127.0.0.1:1 is reserved/unbound in practice.
    let srv = mk_web("127.0.0.1:1");
    let front = serve1(srv).await;
    let mut c = client_to(front).await;
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 64];
    let n = c.read(&mut reply).await.unwrap();
    assert!(
        String::from_utf8_lossy(&reply[..n]).contains("502"),
        "expected 502 when backend down"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bins web_backend_relays_origin_form_request web_backend_down_returns_502 web_backend_unset_does_not_route_origin_form`
Expected: FAIL — `cannot find function mk_web` / `handle_web_backend` not wired (origin-form currently takes the forward-proxy path, so the relay/502 assertions fail).

- [ ] **Step 3: Implement `handle_web_backend`**

Add this method inside `impl ProxyServer` in `src/protocols/proxy.rs` (near the other `handle_*` methods):

```rust
    /// Transparent reverse proxy to the configured web backend: replay the bytes
    /// already read from the client, then splice both directions. Used for
    /// origin-form HTTP requests when `[router].web_backend` is set. No HTTP
    /// rewriting — the client's Host header and relative links pass through.
    async fn handle_web_backend(
        &self,
        mut client: TcpStream,
        initial_request: Vec<u8>,
        backend: &str,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let mut upstream = match TcpStream::connect(backend).await {
            Ok(s) => s,
            Err(e) => {
                global_stats.log_info(
                    format!("web_backend {backend} unreachable: {e}"),
                    &self.config,
                );
                let _ = client
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                return Ok(());
            }
        };
        upstream.write_all(&initial_request).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }
```

- [ ] **Step 4: Wire the short-circuit into `handle_connection`**

In `src/protocols/proxy.rs`, in `handle_connection`, immediately **after** the `purroute_connections_total` counter increment and **before** the `let selection = server.selection_for(...)` line, insert:

```rust
                // Web-backend multiplexing: an origin-form HTTP request (a browser
                // treating us as a website, `GET /path`) is reverse-proxied to the
                // configured web backend — distinct from forward-proxy HTTP
                // (`GET http://host/…`). Only when `[router].web_backend` is set.
                if protocol == Proxy::Http {
                    if let Some(backend) = server.config.web_backend.clone() {
                        if is_origin_form_http(&initial_request) {
                            return server
                                .handle_web_backend(
                                    client,
                                    initial_request,
                                    &backend,
                                    global_stats.clone(),
                                )
                                .await;
                        }
                    }
                }
```

(`return` here exits the inner `async { … }` block whose value becomes `result`; the type is `Result<(), ProxyError>`, matching `handle_web_backend`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --bins web_backend`
Expected: PASS — all three (`web_backend_relays_origin_form_request`, `web_backend_unset_does_not_route_origin_form`, `web_backend_down_returns_502`).

- [ ] **Step 6: Full green gate**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --bins
cargo llvm-cov --bins --fail-under-lines 90 --ignore-filename-regex '(main\.rs|stats/display\.rs)'
```
Expected: fmt clean; clippy clean; all tests pass; coverage ≥ 90%.

- [ ] **Step 7: Commit**

```bash
git add src/protocols/proxy.rs
git commit -m ":sparkles: proxy — reverse-proxy origin-form HTTP to [router].web_backend (one port serves proxy + web)"
```

---

## Self-Review

**Spec coverage:**
- Config `[router].web_backend` optional, `None` = off → Task 1. ✓
- Discriminator (origin- vs absolute-form) → Task 2 (`is_origin_form_http`). ✓
- Dispatch short-circuit before upstream resolution → Task 3 Step 4. ✓
- `handle_web_backend` connect + replay + bidirectional relay, no rewriting → Task 3 Step 3. ✓
- Backend-down handling (502, no panic/leak) → Task 3 (`web_backend_down_returns_502`). ✓
- Unset = existing behavior → Task 3 (`web_backend_unset_does_not_route_origin_form`). ✓
- SOCKS/CONNECT/absolute-form unaffected → covered by `is_origin_form_http` false cases (Task 2) + the `protocol == Proxy::Http` guard (only HTTP is considered). ✓
- Clearnet-affected-by-design → inherent (per-connection detection); no code needed, documented in spec.
- Plain HTTP, no TLS → `handle_web_backend` is raw TCP. ✓
- OSS-safe naming → `web_backend`, no socks.cat strings. ✓

**Placeholder scan:** No TBD/TODO. All code blocks are complete and compile-ready. The 502 body is a concrete literal. Coverage command is the exact CI gate.

**Type consistency:** `web_backend: Option<String>` defined in Task 1, consumed as `server.config.web_backend.clone()` (Task 3) and `as_deref()` (Task 1 test). `is_origin_form_http(&[u8]) -> bool` defined Task 2, called `is_origin_form_http(&initial_request)` Task 3. `handle_web_backend(&self, TcpStream, Vec<u8>, &str, Arc<GlobalStats>)` defined + called consistently. `mk_web(&str) -> ProxyServer` defined + used in Task 3 tests. All match.
