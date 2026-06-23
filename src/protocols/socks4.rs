/// SOCKS4 protocol
/// The SOCKS4 protocol is used to establish a connection between the client and the proxy server.
/// The client sends a connection request to the proxy server, which then forwards the request to the
/// destination server. The proxy server then establishes a connection with the destination server and
/// forwards the data between the client and the destination server.
/// The SOCKS4 protocol is simpler than SOCKS5 and only supports IPv4 addresses.
// src/protocols/socks4.rs
use crate::{
    config::ProxyConfig,
    protocols::{Proxy, ProxyError},
    stats::{get_global_stats, GlobalStats},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct Socks4;

impl Socks4 {
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
        if request[0] != 0x04 {
            return Err(ProxyError::Protocol("Invalid SOCKS4 version".into()));
        }

        let mut client = client;
        let stats = get_global_stats();

        // Track initial request bytes
        stats.add_bytes_in(request.len().try_into().unwrap());

        // Parse SOCKS4 request
        let command = request[1];
        if command != 0x01 {
            return Err(ProxyError::Protocol(
                "Only CONNECT command is supported".into(),
            ));
        }
        let port = u16::from_be_bytes([request[2], request[3]]);
        let ip = format!(
            "{}.{}.{}.{}",
            request[4], request[5], request[6], request[7]
        );

        // Find the end of the user ID string
        let mut user_id_end = 8;
        while user_id_end < request.len() && request[user_id_end] != 0 {
            user_id_end += 1;
        }

        // The SOCKS4 user ID field is parsed past but not used for auth.
        let _user_id = if user_id_end > 8 {
            String::from_utf8_lossy(&request[8..user_id_end]).to_string()
        } else {
            String::new()
        };

        // Check if this is a SOCKS4a request (domain name instead of IP)
        let target_host = if ip == "0.0.0.1" || ip == "0.0.0.0" {
            // SOCKS4a - domain name follows user ID
            let mut domain_end = user_id_end + 1;
            while domain_end < request.len() && request[domain_end] != 0 {
                domain_end += 1;
            }
            if domain_end <= user_id_end + 1 {
                return Err(ProxyError::Protocol(
                    "Invalid SOCKS4a request: missing domain".into(),
                ));
            }
            String::from_utf8_lossy(&request[user_id_end + 1..domain_end]).to_string()
        } else {
            ip
        };

        let mut upstream = TcpStream::connect(upstream_addr).await?;
        upstream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency

        match target_proxy.proxy_type {
            Proxy::Http | Proxy::Https => {
                // Convert SOCKS4 to HTTP CONNECT
                let mut connect_request = Vec::new();
                connect_request.extend_from_slice(
                    format!("CONNECT {}:{} HTTP/1.1\r\n", target_host, port).as_bytes(),
                );
                connect_request
                    .extend_from_slice(format!("Host: {}:{}\r\n", target_host, port).as_bytes());

                // Add authentication if provided
                if let (Some(username), Some(password)) =
                    (&target_proxy.username, &target_proxy.password)
                {
                    let auth = crate::config::encode_auth(username, password);
                    connect_request.extend_from_slice(b"Proxy-Authorization: Basic ");
                    connect_request.extend_from_slice(auth.as_bytes());
                    connect_request.extend_from_slice(b"\r\n");
                }

                connect_request.extend_from_slice(b"\r\n");

                // Send CONNECT request
                upstream.write_all(&connect_request).await?;
                stats.add_bytes_out(connect_request.len().try_into().unwrap());

                // Read HTTP response
                let mut response = [0u8; 1024];
                let n = upstream.read(&mut response).await?;
                stats.add_bytes_in(n.try_into().unwrap());
                let response_str = String::from_utf8_lossy(&response[..n]);

                if !response_str.contains("200 Connection Established") {
                    return Err(ProxyError::Protocol("HTTP tunnel failed".into()));
                }

                // Send SOCKS4 success response to client
                let response = [0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                client.write_all(&response).await?;
                stats.add_bytes_out(8);
            }
            Proxy::Socks4 => {
                // Forward SOCKS4 request directly
                upstream.write_all(&request).await?;
                stats.add_bytes_out(request.len().try_into().unwrap());

                // Read response
                let mut response = [0u8; 8];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(8);

                // Forward response to client
                client.write_all(&response).await?;
                stats.add_bytes_out(8);

                if response[1] != 0x5A {
                    return Err(ProxyError::Protocol("SOCKS4 connection failed".into()));
                }
            }
            Proxy::Socks5 => {
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

                // Create SOCKS5 connect request
                let mut socks_request = vec![0x05, 0x01, 0x00, 0x03];
                socks_request.push(target_host.len() as u8);
                socks_request.extend_from_slice(target_host.as_bytes());
                socks_request.extend_from_slice(&port.to_be_bytes());

                upstream.write_all(&socks_request).await?;

                // Read response
                let mut response = [0u8; 4];
                upstream.read_exact(&mut response).await?;

                if response[1] != 0x00 {
                    return Err(ProxyError::Protocol("Connection failed".into()));
                }

                // Skip address in response
                let atyp = response[3];
                match atyp {
                    0x01 => {
                        let mut skip = [0u8; 6];
                        upstream.read_exact(&mut skip).await?;
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        upstream.read_exact(&mut len).await?;
                        let mut skip = vec![0u8; len[0] as usize + 2];
                        upstream.read_exact(&mut skip).await?;
                    }
                    0x04 => {
                        let mut skip = [0u8; 18];
                        upstream.read_exact(&mut skip).await?;
                    }
                    _ => return Err(ProxyError::Protocol("Invalid address type".into())),
                }

                // Send SOCKS4 success response to client
                let response = [0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                client.write_all(&response).await?;
                stats.add_bytes_out(8);
            }
        }

        // Start bidirectional proxy
        proxy_data(client, upstream, stats).await
    }
}

#[cfg(test)]
mod socks4_cov {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    type RelayFut =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProxyError>> + Send>>;

    /// A no-op relay: reports success without real bidirectional IO, letting us
    /// assert the handler reached the relay stage.
    fn noop_relay(_c: TcpStream, _u: TcpStream, _s: Arc<GlobalStats>) -> RelayFut {
        Box::pin(async { Ok(()) })
    }

    fn socks4_proxy(addr: SocketAddr) -> ProxyConfig {
        ProxyConfig {
            label: Some("u".into()),
            proxy_type: Proxy::Socks4,
            address: addr.ip().to_string(),
            port: Some(addr.port()),
            username: None,
            password: None,
            tags: Default::default(),
        }
    }

    /// Fake SOCKS4 upstream: read the forwarded request and reply with the given
    /// CD code. Echoes back the captured target IP/domain via a oneshot.
    async fn fake_socks4_upstream(cd: u8) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut head = [0u8; 8];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut b = [0u8; 1];
                // consume userid until null
                loop {
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    if b[0] == 0 {
                        break;
                    }
                }
                // socks4a domain when IP is 0.0.0.x (x != 0)
                if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
                    loop {
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        if b[0] == 0 {
                            break;
                        }
                    }
                }
                let _ = s.write_all(&[0x00, cd, 0, 0, 0, 0, 0, 0]).await;
                let _ = s.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        addr
    }

    /// A client TcpStream connected to a throwaway loopback acceptor — gives the
    /// handler a real socket to write the SOCKS4 reply into.
    async fn fake_client() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        TcpStream::connect(addr).await.unwrap()
    }

    /// CONNECT request, IPv4 target.
    fn req_ipv4() -> Vec<u8> {
        vec![0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0]
    }

    /// SOCKS4a CONNECT request with a domain target.
    fn req_socks4a(domain: &str) -> Vec<u8> {
        let mut r = vec![0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0];
        r.extend_from_slice(domain.as_bytes());
        r.push(0);
        r
    }

    #[tokio::test]
    async fn granted_ipv4_reaches_relay() {
        let up = fake_socks4_upstream(0x5A).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req_ipv4(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "granted IPv4 should reach relay: {:?}", r);
    }

    #[tokio::test]
    async fn granted_socks4a_domain_reaches_relay() {
        let up = fake_socks4_upstream(0x5A).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req_socks4a("example.com"),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_ok(), "granted SOCKS4a should reach relay: {:?}", r);
    }

    #[tokio::test]
    async fn upstream_rejects_returns_error() {
        // CD != 0x5A means the upstream rejected the request.
        let up = fake_socks4_upstream(0x5B).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req_ipv4(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Protocol(_))));
    }

    #[tokio::test]
    async fn invalid_version_rejected() {
        let up = fake_socks4_upstream(0x5A).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        let mut req = req_ipv4();
        req[0] = 0x05; // not SOCKS4
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req,
            &proxy,
            noop_relay,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Protocol(m)) if m.contains("version")));
    }

    #[tokio::test]
    async fn non_connect_command_rejected() {
        let up = fake_socks4_upstream(0x5A).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        let mut req = req_ipv4();
        req[1] = 0x02; // BIND, unsupported
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req,
            &proxy,
            noop_relay,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Protocol(m)) if m.contains("CONNECT")));
    }

    #[tokio::test]
    async fn socks4a_missing_domain_rejected() {
        let up = fake_socks4_upstream(0x5A).await;
        let proxy = socks4_proxy(up);
        let client = fake_client().await;
        // SOCKS4a marker IP but the domain field is empty (just the trailing 0).
        let req = vec![0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0, 0];
        let r = Socks4::handle(
            client,
            &format!("{}:{}", up.ip(), up.port()),
            req,
            &proxy,
            noop_relay,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Protocol(m)) if m.contains("domain")));
    }

    #[tokio::test]
    async fn upstream_connect_failure_returns_error() {
        // Bind then drop the listener so the port is (almost certainly) closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);
        let proxy = socks4_proxy(dead);
        let client = fake_client().await;
        let r = Socks4::handle(
            client,
            &format!("{}:{}", dead.ip(), dead.port()),
            req_ipv4(),
            &proxy,
            noop_relay,
        )
        .await;
        assert!(r.is_err(), "connecting to a dead upstream should fail");
    }
}
