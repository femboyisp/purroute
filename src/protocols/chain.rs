// src/protocols/chain.rs
use crate::{
    config::{encode_auth, ProxyConfig},
    protocols::{Proxy, ProxyError},
    stats::get_global_stats,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

pub struct ChainConnector;

impl ChainConnector {
    /// Connect through a chain of proxies to reach the final destination
    ///
    /// # Arguments
    /// * `chain` - Ordered list of proxies to traverse
    /// * `target_host` - Final destination hostname
    /// * `target_port` - Final destination port
    ///
    /// # Returns
    /// The TCP stream connected to the final destination through the chain
    pub async fn connect_chain(
        chain: &[ProxyConfig],
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, ProxyError> {
        if chain.is_empty() {
            return Err(ProxyError::Protocol("Empty proxy chain".to_string()));
        }

        let _stats = get_global_stats();

        // Connect to first proxy in chain
        let first_proxy = &chain[0];
        let mut stream = TcpStream::connect(&first_proxy.get_upstream_addr()).await?;
        stream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency

        // For each proxy in the chain, establish connection to the next hop
        for (i, current_proxy) in chain.iter().enumerate() {
            let is_last_hop = i == chain.len() - 1;

            let (next_host, next_port) = if is_last_hop {
                // Last hop: connect to final destination
                (target_host.to_string(), target_port)
            } else {
                // Intermediate hop: connect to next proxy in chain
                let next_proxy = &chain[i + 1];
                Self::parse_address(&next_proxy.get_upstream_addr())?
            };

            // Establish connection through current proxy to next hop
            stream =
                Self::connect_through_proxy(stream, current_proxy, &next_host, next_port).await?;
        }

        Ok(stream)
    }

    /// Connect through a single proxy to the next hop
    async fn connect_through_proxy(
        mut stream: TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, ProxyError> {
        match proxy.proxy_type {
            Proxy::Socks5 => {
                Self::socks5_connect(&mut stream, proxy, target_host, target_port).await?;
            }
            Proxy::Socks4 => {
                Self::socks4_connect(&mut stream, proxy, target_host, target_port).await?;
            }
            Proxy::Http | Proxy::Https => {
                Self::http_connect(&mut stream, proxy, target_host, target_port).await?;
            }
        }

        Ok(stream)
    }

    // SOCKS5 connection logic (extracted from socks5.rs)
    async fn socks5_connect(
        stream: &mut TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        // SOCKS5 handshake
        let handshake = if proxy.username.is_some() && proxy.password.is_some() {
            vec![0x05, 0x02, 0x00, 0x02] // Offer both no auth and username/password
        } else {
            vec![0x05, 0x01, 0x00] // Only no auth
        };
        stream.write_all(&handshake).await?;
        stats.add_bytes_out(handshake.len() as u64);

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        stats.add_bytes_in(2);

        // Handle authentication if selected
        if response[1] == 0x02 {
            if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
                let mut auth_request = Vec::new();
                auth_request.push(0x01);
                auth_request.push(username.len() as u8);
                auth_request.extend_from_slice(username.as_bytes());
                auth_request.push(password.len() as u8);
                auth_request.extend_from_slice(password.as_bytes());

                stream.write_all(&auth_request).await?;
                stats.add_bytes_out(auth_request.len() as u64);

                let mut auth_response = [0u8; 2];
                stream.read_exact(&mut auth_response).await?;
                stats.add_bytes_in(2);

                if auth_response[1] != 0x00 {
                    return Err(ProxyError::Protocol("SOCKS5 auth failed".into()));
                }
            } else {
                return Err(ProxyError::Protocol(
                    "Auth required but not provided".into(),
                ));
            }
        } else if response[1] != 0x00 {
            return Err(ProxyError::Protocol("SOCKS5 handshake failed".into()));
        }

        // Send CONNECT request
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
        request.extend_from_slice(&target_port.to_be_bytes());

        stream.write_all(&request).await?;
        stats.add_bytes_out(request.len() as u64);

        // Read response with timeout
        let mut response = [0u8; 4];
        match timeout(Duration::from_secs(30), stream.read_exact(&mut response)).await {
            Ok(Ok(_)) => {
                stats.add_bytes_in(4);
            }
            Ok(Err(e)) => {
                return Err(ProxyError::Io(e));
            }
            Err(_) => {
                return Err(ProxyError::Protocol(
                    "Timeout waiting for CONNECT response".into(),
                ));
            }
        }

        if response[1] != 0x00 {
            return Err(ProxyError::Protocol(format!(
                "SOCKS5 connect failed with code {}",
                response[1]
            )));
        }

        // Skip address in response
        let atyp = response[3];
        match atyp {
            0x01 => {
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
                stats.add_bytes_in(6);
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                stats.add_bytes_in(1);
                let mut domain = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut domain).await?;
                stats.add_bytes_in(domain.len() as u64);
            }
            0x04 => {
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
                stats.add_bytes_in(18);
            }
            _ => return Err(ProxyError::Protocol("Invalid address type".into())),
        }

        Ok(())
    }

    // SOCKS4 connection logic
    async fn socks4_connect(
        stream: &mut TcpStream,
        _proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        // SOCKS4a request: always use 0.0.0.x to indicate domain name follows
        let mut request = vec![
            0x04, // SOCKS version
            0x01, // CONNECT command
        ];
        request.extend_from_slice(&target_port.to_be_bytes());
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // IP 0.0.0.1 for SOCKS4a
        request.push(0x00); // Empty user ID
        request.extend_from_slice(target_host.as_bytes());
        request.push(0x00); // Null terminator for domain

        stream.write_all(&request).await?;
        stats.add_bytes_out(request.len() as u64);

        // Read response
        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await?;
        stats.add_bytes_in(8);

        if response[1] != 0x5A {
            return Err(ProxyError::Protocol("SOCKS4 connect failed".into()));
        }

        Ok(())
    }

    // HTTP/HTTPS CONNECT logic
    async fn http_connect(
        stream: &mut TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        let mut connect_request = Vec::new();
        connect_request.extend_from_slice(
            format!("CONNECT {}:{} HTTP/1.1\r\n", target_host, target_port).as_bytes(),
        );
        connect_request
            .extend_from_slice(format!("Host: {}:{}\r\n", target_host, target_port).as_bytes());

        if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
            let auth = encode_auth(username, password);
            connect_request.extend_from_slice(b"Proxy-Authorization: Basic ");
            connect_request.extend_from_slice(auth.as_bytes());
            connect_request.extend_from_slice(b"\r\n");
        }

        connect_request.extend_from_slice(b"\r\n");

        stream.write_all(&connect_request).await?;
        stats.add_bytes_out(connect_request.len() as u64);

        // Read HTTP response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await?;
        stats.add_bytes_in(n as u64);
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("200 Connection Established") {
            return Err(ProxyError::Protocol("HTTP tunnel failed".into()));
        }

        Ok(())
    }

    fn parse_address(addr: &str) -> Result<(String, u16), ProxyError> {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ProxyError::Protocol("Invalid address format".into()));
        }
        let port = parts[0]
            .parse()
            .map_err(|_| ProxyError::Protocol("Invalid port".into()))?;
        let host = parts[1].to_string();
        Ok((host, port))
    }
}

#[cfg(test)]
mod chain_cov {
    //! Hermetic, in-process tests for the multi-hop [`ChainConnector`]. Each
    //! fake upstream binds on loopback and, where it is an intermediate hop,
    //! dials the next address and splices bytes so a real chain reaches a real
    //! origin. No network, no sleeps beyond a few ms.
    use super::*;
    use crate::config::Tags;
    use crate::protocol::Protocol;
    use tokio::net::TcpListener;

    const BODY: &str = "ChainOK";

    fn cfg(kind: Protocol, addr: std::net::SocketAddr) -> ProxyConfig {
        ProxyConfig {
            label: Some("p".into()),
            proxy_type: kind,
            address: addr.ip().to_string(),
            port: Some(addr.port()),
            username: None,
            password: None,
            tags: Tags::default(),
            cost_per_byte: 1.0,
        }
    }

    fn cfg_auth(kind: Protocol, addr: std::net::SocketAddr) -> ProxyConfig {
        let mut c = cfg(kind, addr);
        c.username = Some("u".into());
        c.password = Some("pw".into());
        c
    }

    /// Read+discard a SOCKS5 CONNECT request header, returning the target
    /// `host:port` it asked for. Assumes the greeting was already consumed.
    async fn read_socks5_connect(s: &mut TcpStream) -> (String, u16) {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await.unwrap();
        let host = match h[3] {
            0x01 => {
                let mut a = [0u8; 4];
                s.read_exact(&mut a).await.unwrap();
                format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                let mut d = vec![0u8; l[0] as usize];
                s.read_exact(&mut d).await.unwrap();
                String::from_utf8_lossy(&d).into_owned()
            }
            _ => panic!("unsupported atyp"),
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        (host, u16::from_be_bytes(p))
    }

    /// Consume a SOCKS5 no-auth greeting.
    async fn read_socks5_greeting(s: &mut TcpStream) {
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        let mut m = vec![0u8; g[1] as usize];
        s.read_exact(&mut m).await.unwrap();
    }

    /// Fake SOCKS5 origin proxy: no-auth, accept CONNECT, reply success, then
    /// answer the tunnelled request as an HTTP origin.
    async fn fake_socks5_origin() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let _ = read_socks5_connect(&mut s).await;
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    BODY.len(),
                    BODY
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
            }
        });
        addr
    }

    /// Fake SOCKS5 *intermediate* hop: no-auth, accept CONNECT, dial the
    /// requested next hop and splice bytes both ways so the chain reaches the
    /// final origin.
    async fn fake_socks5_hop() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let (host, port) = read_socks5_connect(&mut s).await;
                let upstream = TcpStream::connect((host.as_str(), port)).await.unwrap();
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let (mut cr, mut cw) = s.into_split();
                let (mut ur, mut uw) = upstream.into_split();
                let a = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut uw).await });
                let b = tokio::spawn(async move { tokio::io::copy(&mut ur, &mut cw).await });
                let _ = a.await;
                let _ = b.await;
            }
        });
        addr
    }

    /// Drive an HTTP GET over the established chain stream and return the body.
    async fn fetch(mut stream: TcpStream, host: &str, port: u16) -> String {
        let req = format!("GET / HTTP/1.1\r\nHost: {}:{}\r\n\r\n", host, port);
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(BODY.len()).any(|w| w == BODY.as_bytes()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    // ---- connect_chain: empty chain ------------------------------------

    #[tokio::test]
    async fn empty_chain_errors() {
        let err = ChainConnector::connect_chain(&[], "example.com", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("Empty")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- connect_chain: 2-hop SOCKS5 -> SOCKS5 reaching an origin -------

    #[tokio::test]
    async fn two_hop_socks5_chain_reaches_origin() {
        let origin = fake_socks5_origin().await;
        let hop = fake_socks5_hop().await;
        // Chain: client -> hop(SOCKS5) -> origin(SOCKS5) -> final dest.
        // The final dest is whatever the origin proxy "connects" to; it just
        // answers HTTP regardless, so any target_host works.
        let chain = vec![cfg(Protocol::Socks5, hop), cfg(Protocol::Socks5, origin)];
        let stream = ChainConnector::connect_chain(&chain, "dest.invalid", 80)
            .await
            .unwrap();
        let body = fetch(stream, "dest.invalid", 80).await;
        assert!(body.contains(BODY), "got: {body}");
    }

    // ---- single-hop socks5 happy path ----------------------------------

    #[tokio::test]
    async fn single_socks5_happy() {
        let origin = fake_socks5_origin().await;
        let chain = vec![cfg(Protocol::Socks5, origin)];
        let stream = ChainConnector::connect_chain(&chain, "dest.invalid", 443)
            .await
            .unwrap();
        let body = fetch(stream, "dest.invalid", 443).await;
        assert!(body.contains(BODY), "got: {body}");
    }

    // ---- socks5: upstream rejects CONNECT ------------------------------

    #[tokio::test]
    async fn socks5_connect_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let _ = read_socks5_connect(&mut s).await;
                // reply code 0x05 (connection refused)
                s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("connect failed")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- socks5: auth required by upstream but config has none ----------

    #[tokio::test]
    async fn socks5_auth_required_but_missing() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                // demand username/password auth (0x02) although config offered none
                s.write_all(&[0x05, 0x02]).await.unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("Auth required")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- socks5: handshake method rejected (0xFF) ----------------------

    #[tokio::test]
    async fn socks5_handshake_failed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0xFF]).await.unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("handshake failed")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- socks5: auth offered and accepted -----------------------------

    #[tokio::test]
    async fn socks5_auth_accepted() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x02]).await.unwrap(); // pick user/pass
                                                           // read auth: ver, ulen, u, plen, p
                let mut hdr = [0u8; 2];
                s.read_exact(&mut hdr).await.unwrap();
                let mut u = vec![0u8; hdr[1] as usize];
                s.read_exact(&mut u).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut p = vec![0u8; pl[0] as usize];
                s.read_exact(&mut p).await.unwrap();
                s.write_all(&[0x01, 0x00]).await.unwrap(); // auth ok
                let _ = read_socks5_connect(&mut s).await;
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });
        let chain = vec![cfg_auth(Protocol::Socks5, addr)];
        ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap();
    }

    // ---- socks5: auth offered but rejected -----------------------------

    #[tokio::test]
    async fn socks5_auth_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x02]).await.unwrap();
                let mut hdr = [0u8; 2];
                s.read_exact(&mut hdr).await.unwrap();
                let mut u = vec![0u8; hdr[1] as usize];
                s.read_exact(&mut u).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut p = vec![0u8; pl[0] as usize];
                s.read_exact(&mut p).await.unwrap();
                s.write_all(&[0x01, 0x01]).await.unwrap(); // auth FAIL
            }
        });
        let chain = vec![cfg_auth(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("auth failed")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- socks5: invalid address type in success reply -----------------

    #[tokio::test]
    async fn socks5_invalid_reply_atyp() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                read_socks5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let _ = read_socks5_connect(&mut s).await;
                // success code 0x00 but atyp 0x09 is invalid
                s.write_all(&[0x05, 0x00, 0x00, 0x09]).await.unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("Invalid address type")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- socks4: happy path --------------------------------------------

    #[tokio::test]
    async fn socks4_connect_granted() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut head = [0u8; 8];
                s.read_exact(&mut head).await.unwrap();
                let mut b = [0u8; 1];
                loop {
                    s.read_exact(&mut b).await.unwrap();
                    if b[0] == 0 {
                        break;
                    }
                }
                // socks4a domain
                if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
                    loop {
                        s.read_exact(&mut b).await.unwrap();
                        if b[0] == 0 {
                            break;
                        }
                    }
                }
                s.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks4, addr)];
        ChainConnector::connect_chain(&chain, "dest.invalid", 80)
            .await
            .unwrap();
    }

    // ---- socks4: rejected ----------------------------------------------

    #[tokio::test]
    async fn socks4_connect_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf).await;
                // CD = 0x5B (request rejected)
                s.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await.unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Socks4, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("SOCKS4 connect failed")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- http CONNECT: happy path --------------------------------------

    #[tokio::test]
    async fn http_connect_ok() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Http, addr)];
        ChainConnector::connect_chain(&chain, "dest.invalid", 443)
            .await
            .unwrap();
    }

    // ---- http CONNECT: with proxy auth header --------------------------

    #[tokio::test]
    async fn http_connect_with_auth_header() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("Proxy-Authorization: Basic "));
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let chain = vec![cfg_auth(Protocol::Http, addr)];
        ChainConnector::connect_chain(&chain, "dest.invalid", 443)
            .await
            .unwrap();
    }

    // ---- http CONNECT: tunnel refused ----------------------------------

    #[tokio::test]
    async fn http_connect_refused() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let chain = vec![cfg(Protocol::Http, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("HTTP tunnel failed")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- connect_chain: first proxy unreachable ------------------------

    #[tokio::test]
    async fn first_hop_connect_refused() {
        // Bind then drop to obtain an address nothing is listening on.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let chain = vec![cfg(Protocol::Socks5, addr)];
        let err = ChainConnector::connect_chain(&chain, "x", 80)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Io(_)), "unexpected: {err:?}");
    }

    // ---- parse_address -------------------------------------------------

    #[tokio::test]
    async fn parse_address_ok() {
        let (h, p) = ChainConnector::parse_address("example.com:8080").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
    }

    #[tokio::test]
    async fn parse_address_ipv6ish_takes_last_colon() {
        // rsplitn(2, ':') splits on the final colon only.
        let (h, p) = ChainConnector::parse_address("a:b:1234").unwrap();
        assert_eq!(h, "a:b");
        assert_eq!(p, 1234);
    }

    #[tokio::test]
    async fn parse_address_no_colon() {
        let err = ChainConnector::parse_address("noport").unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("Invalid address format")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn parse_address_bad_port() {
        let err = ChainConnector::parse_address("host:notaport").unwrap_err();
        match err {
            ProxyError::Protocol(m) => assert!(m.contains("Invalid port")),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
