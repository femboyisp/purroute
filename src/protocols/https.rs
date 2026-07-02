// src/protocols/https.rs
use crate::{
    config::{encode_auth, ProxyConfig},
    protocols::{Proxy, ProxyError},
    stats::{get_global_stats, GlobalStats},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct Https;

impl Https {
    pub async fn handle(
        client: TcpStream,
        upstream_addr: &str,
        request: Vec<u8>,
        target_proxy: &ProxyConfig,
        proxy_data: impl Fn(
            TcpStream,
            TcpStream,
            Arc<GlobalStats>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), ProxyError>> + Send>,
        >,
    ) -> Result<(), ProxyError> {
        let request_str = String::from_utf8_lossy(&request);
        let first_line = request_str
            .lines()
            .next()
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTPS request".to_string()))?;

        let mut client = client;
        let mut upstream = TcpStream::connect(upstream_addr).await?;
        upstream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency
        let stats = get_global_stats();

        match target_proxy.proxy_type {
            Proxy::Http | Proxy::Https => {
                let mut modified_request = Vec::new();
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                let target = parts
                    .get(1)
                    .ok_or_else(|| ProxyError::Protocol("Invalid CONNECT request".to_string()))?;

                modified_request
                    .extend_from_slice(format!("CONNECT {} HTTP/1.1\r\n", target).as_bytes());
                modified_request.extend_from_slice(format!("Host: {}\r\n", target).as_bytes());

                if let (Some(username), Some(password)) =
                    (&target_proxy.username, &target_proxy.password)
                {
                    let auth = encode_auth(username, password);
                    modified_request.extend_from_slice(b"Proxy-Authorization: Basic ");
                    modified_request.extend_from_slice(auth.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }

                modified_request.extend_from_slice(b"\r\n");

                // Track bytes before sending
                stats.add_bytes_out(modified_request.len() as u64);
                upstream.write_all(&modified_request).await?;

                let mut response = [0u8; 1024];
                let n = upstream.read(&mut response).await?;
                let response_str = String::from_utf8_lossy(&response[..n]);

                if !response_str.contains("200 Connection Established") {
                    return Err(ProxyError::Protocol("HTTPS tunnel failed".into()));
                }

                stats.add_bytes_in(n as u64);
                client.write_all(&response[..n]).await?;
            }
            Proxy::Socks4 => {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                let target = parts
                    .get(1)
                    .ok_or_else(|| ProxyError::Protocol("Invalid CONNECT request".to_string()))?;
                let mut target_parts = target.split(':');
                let host = target_parts.next().unwrap_or("");
                let port = target_parts
                    .next()
                    .unwrap_or("443")
                    .parse::<u16>()
                    .unwrap_or(443);

                // Create SOCKS4 request
                let mut socks_request = vec![0x04, 0x01]; // SOCKS4, CONNECT command
                socks_request.extend_from_slice(&port.to_be_bytes());
                socks_request.extend_from_slice(&[0, 0, 0, 1]); // IP (0.0.0.1 for SOCKS4a)
                socks_request.push(0); // Empty user ID
                socks_request.extend_from_slice(host.as_bytes()); // Domain name
                socks_request.push(0); // Null terminator

                upstream.write_all(&socks_request).await?;
                stats.add_bytes_out(socks_request.len() as u64);

                // Read response
                let mut response = [0u8; 8];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(8);

                if response[1] != 0x5A {
                    return Err(ProxyError::Protocol("SOCKS4 connection failed".into()));
                }

                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            Proxy::Socks5 => {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                let target = parts
                    .get(1)
                    .ok_or_else(|| ProxyError::Protocol("Invalid CONNECT request".to_string()))?;
                let mut target_parts = target.split(':');
                let host = target_parts.next().unwrap_or("");
                let port = target_parts
                    .next()
                    .unwrap_or("443")
                    .parse::<u16>()
                    .unwrap_or(443);

                // SOCKS5 handshake - offer both no auth and username/password auth
                let handshake =
                    if let (Some(_), Some(_)) = (&target_proxy.username, &target_proxy.password) {
                        // Offer both no auth and username/password auth
                        vec![0x05, 0x02, 0x00, 0x02]
                    } else {
                        // Only offer no auth
                        vec![0x05, 0x01, 0x00]
                    };
                upstream.write_all(&handshake).await?;
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;

                // Check if upstream selected username/password authentication
                if response[1] == 0x02 {
                    // Handle user authentication
                    if let (Some(username), Some(password)) =
                        (&target_proxy.username, &target_proxy.password)
                    {
                        // Send username/password authentication request
                        let mut auth_request = Vec::new();
                        auth_request.push(0x01); // Username/Password authentication version
                        auth_request.push(username.len() as u8); // Username length
                        auth_request.extend_from_slice(username.as_bytes()); // Username
                        auth_request.push(password.len() as u8); // Password length
                        auth_request.extend_from_slice(password.as_bytes()); // Password

                        upstream.write_all(&auth_request).await?;
                        stats.add_bytes_out(auth_request.len() as u64);

                        let mut auth_response = [0u8; 2];
                        upstream.read_exact(&mut auth_response).await?;
                        stats.add_bytes_in(2);

                        if auth_response[1] != 0x00 {
                            return Err(ProxyError::Protocol(
                                "SOCKS5 authentication failed".into(),
                            ));
                        }
                    } else {
                        return Err(ProxyError::Protocol(
                            "Username/password required but not provided".into(),
                        ));
                    }
                } else if response[1] != 0x00 {
                    return Err(ProxyError::Protocol(
                        "Upstream SOCKS5 handshake failed".into(),
                    ));
                }

                let mut socks_request = vec![0x05, 0x01, 0x00, 0x03];
                socks_request.push(host.len() as u8);
                socks_request.extend_from_slice(host.as_bytes());
                socks_request.extend_from_slice(&port.to_be_bytes());

                // Track bytes before sending
                stats.add_bytes_out(socks_request.len() as u64);
                upstream.write_all(&socks_request).await?;

                let mut response = [0u8; 4];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(4);

                if response[1] != 0x00 {
                    return Err(ProxyError::Protocol("Connection failed".into()));
                }

                let atyp = response[3];
                match atyp {
                    0x01 => {
                        let mut skip = [0u8; 6];
                        upstream.read_exact(&mut skip).await?;
                        stats.add_bytes_in(6);
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        upstream.read_exact(&mut len).await?;
                        stats.add_bytes_in(1);
                        let mut skip = vec![0u8; len[0] as usize + 2];
                        upstream.read_exact(&mut skip).await?;
                        stats.add_bytes_in((len[0] as u64) + 2);
                    }
                    0x04 => {
                        let mut skip = [0u8; 18];
                        upstream.read_exact(&mut skip).await?;
                        stats.add_bytes_in(18);
                    }
                    _ => return Err(ProxyError::Protocol("Invalid address type".into())),
                }

                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
        }

        proxy_data(client, upstream, stats).await
    }
}

#[cfg(test)]
mod https_cov {
    use super::*;
    use crate::config::Tags;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn cfg(kind: Proxy, addr: SocketAddr, user: Option<(&str, &str)>) -> ProxyConfig {
        ProxyConfig {
            label: Some("t".into()),
            proxy_type: kind,
            address: addr.ip().to_string(),
            port: Some(addr.port()),
            username: user.map(|(u, _)| u.to_owned()),
            password: user.map(|(_, p)| p.to_owned()),
            tags: Tags::default(),
            cost_per_byte: 1.0,
            username_prefixes: None,
        }
    }

    /// Build a connected pair of TcpStreams over loopback. The first is the
    /// "client" handed to `Https::handle`; the second is the in-test peer that
    /// receives whatever `handle` writes back to the client.
    async fn client_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = connect.await.unwrap();
        (client, server)
    }

    /// No-op relay: just succeed, dropping both sockets.
    fn noop_relay(
        _c: TcpStream,
        _u: TcpStream,
        _s: Arc<GlobalStats>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProxyError>> + Send>> {
        Box::pin(async { Ok(()) })
    }

    /// Spawn a one-shot fake upstream driven by `f`, return its address.
    fn spawn_upstream<F, Fut>(
        f: F,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SocketAddr>>>
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        Box::pin(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((s, _)) = listener.accept().await {
                    f(s).await;
                }
            });
            addr
        })
    }

    const CONNECT: &[u8] = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

    // ---- HTTP/HTTPS upstream: CONNECT injection ----

    #[tokio::test]
    async fn http_upstream_connect_success() {
        let up = spawn_upstream(|mut s| async move {
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(req.contains("Host: example.com:443\r\n"));
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Http, up, None);
        let (client, mut peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok());
        let mut buf = [0u8; 64];
        let n = peer.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"));
    }

    #[tokio::test]
    async fn http_upstream_with_auth_injects_header() {
        let up = spawn_upstream(|mut s| async move {
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("Proxy-Authorization: Basic "));
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Https, up, Some(("me", "pw")));
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn http_upstream_non_200_reply_errors() {
        let up = spawn_upstream(|mut s| async move {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Http, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("HTTPS tunnel failed")),
            other => panic!("expected tunnel failure, got {other:?}"),
        }
    }

    // ---- malformed CONNECT ----

    #[tokio::test]
    async fn empty_request_errors_before_connect() {
        // Empty request has no first line -> error, and no upstream needed,
        // but handle connects to upstream first. Point at a live acceptor.
        let up = spawn_upstream(|_s| async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Http, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(client, &up.to_string(), Vec::new(), &proxy, noop_relay).await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("Invalid HTTPS request")),
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_missing_target_errors() {
        let up = spawn_upstream(|_s| async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Http, up, None);
        let (client, _peer) = client_pair().await;
        // First line has only one token -> parts.get(1) is None.
        let r = Https::handle(
            client,
            &up.to_string(),
            b"CONNECT\r\n\r\n".to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("Invalid CONNECT request")),
            other => panic!("expected invalid connect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_connect_failure_errors() {
        // Bind then drop the listener so the address refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let proxy = cfg(Proxy::Http, addr, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &addr.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_err());
    }

    // ---- SOCKS4 upstream ----

    #[tokio::test]
    async fn socks4_upstream_grant_success() {
        let up = spawn_upstream(|mut s| async move {
            let mut head = [0u8; 8];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x04);
            assert_eq!(head[1], 0x01);
            // userid null
            let mut b = [0u8; 1];
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
            }
            // socks4a domain
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
            }
            s.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks4, up, None);
        let (client, mut peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok());
        let mut buf = [0u8; 64];
        let n = peer.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"));
    }

    #[tokio::test]
    async fn socks4_upstream_reject_errors() {
        let up = spawn_upstream(|mut s| async move {
            let mut head = [0u8; 8];
            s.read_exact(&mut head).await.unwrap();
            let mut b = [0u8; 1];
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
            }
            loop {
                s.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
            }
            // 0x5B = request rejected
            s.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks4, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("SOCKS4 connection failed")),
            other => panic!("expected socks4 failure, got {other:?}"),
        }
    }

    // ---- SOCKS5 upstream ----

    /// Drive a SOCKS5 upstream: no-auth handshake then a CONNECT reply with the
    /// given `atyp` and `rep` (0x00 success). Returns after replying.
    fn socks5_noauth(
        rep: u8,
        atyp: u8,
    ) -> impl FnOnce(TcpStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    {
        move |mut s| {
            Box::pin(async move {
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; g[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap();
                // CONNECT request: VER CMD RSV ATYP + addr
                let mut h = [0u8; 4];
                s.read_exact(&mut h).await.unwrap();
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                let mut d = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut d).await.unwrap();
                // reply
                let mut reply = vec![0x05, rep, 0x00, atyp];
                match atyp {
                    0x01 => reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]),
                    0x03 => {
                        reply.push(3);
                        reply.extend_from_slice(b"abc");
                        reply.extend_from_slice(&[0, 0]);
                    }
                    0x04 => reply.extend_from_slice(&[0u8; 18]),
                    _ => {}
                }
                s.write_all(&reply).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            })
        }
    }

    #[tokio::test]
    async fn socks5_upstream_ipv4_success() {
        let up = spawn_upstream(socks5_noauth(0x00, 0x01)).await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, mut peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "got {r:?}");
        let mut buf = [0u8; 64];
        let n = peer.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"));
    }

    #[tokio::test]
    async fn socks5_upstream_domain_atyp_success() {
        let up = spawn_upstream(socks5_noauth(0x00, 0x03)).await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "got {r:?}");
    }

    #[tokio::test]
    async fn socks5_upstream_ipv6_atyp_success() {
        let up = spawn_upstream(socks5_noauth(0x00, 0x04)).await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "got {r:?}");
    }

    #[tokio::test]
    async fn socks5_upstream_connect_failure_errors() {
        let up = spawn_upstream(socks5_noauth(0x05, 0x01)).await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("Connection failed")),
            other => panic!("expected connection failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn socks5_upstream_bad_handshake_method_errors() {
        // Upstream selects method 0xFF (no acceptable methods) -> handshake fail.
        let up = spawn_upstream(|mut s| async move {
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, 0xFF]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("Upstream SOCKS5 handshake failed")),
            other => panic!("expected handshake failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn socks5_upstream_userpass_auth_success() {
        let up = spawn_upstream(|mut s| async move {
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            // select username/password auth
            s.write_all(&[0x05, 0x02]).await.unwrap();
            // read auth: VER ULEN uname PLEN pass
            let mut ver_ulen = [0u8; 2];
            s.read_exact(&mut ver_ulen).await.unwrap();
            let mut uname = vec![0u8; ver_ulen[1] as usize];
            s.read_exact(&mut uname).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            assert_eq!(&uname, b"me");
            assert_eq!(&pass, b"pw");
            s.write_all(&[0x01, 0x00]).await.unwrap(); // auth ok
                                                       // CONNECT request
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut d = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut d).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks5, up, Some(("me", "pw")));
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "got {r:?}");
    }

    #[tokio::test]
    async fn socks5_upstream_userpass_auth_rejected_errors() {
        let up = spawn_upstream(|mut s| async move {
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, 0x02]).await.unwrap();
            let mut ver_ulen = [0u8; 2];
            s.read_exact(&mut ver_ulen).await.unwrap();
            let mut uname = vec![0u8; ver_ulen[1] as usize];
            s.read_exact(&mut uname).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[0x01, 0x01]).await.unwrap(); // auth failure
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks5, up, Some(("me", "pw")));
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("SOCKS5 authentication failed")),
            other => panic!("expected auth failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn socks5_upstream_auth_required_but_no_creds_errors() {
        // Upstream demands user/pass auth but proxy has no credentials.
        let up = spawn_upstream(|mut s| async move {
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, 0x02]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => {
                assert!(m.contains("Username/password required but not provided"))
            }
            other => panic!("expected creds-required failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn socks5_upstream_invalid_atyp_errors() {
        // Reply with success but an unknown atyp -> "Invalid address type".
        let up = spawn_upstream(|mut s| async move {
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut d = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut d).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x09]).await.unwrap(); // atyp 0x09
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        })
        .await;
        let proxy = cfg(Proxy::Socks5, up, None);
        let (client, _peer) = client_pair().await;
        let r = Https::handle(
            client,
            &up.to_string(),
            CONNECT.to_vec(),
            &proxy,
            noop_relay,
        )
        .await;
        match r {
            Err(ProxyError::Protocol(m)) => assert!(m.contains("Invalid address type")),
            other => panic!("expected invalid address type, got {other:?}"),
        }
    }
}
