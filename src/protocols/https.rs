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
