/// SOCKS5 protocol
/// The SOCKS5 protocol is used to establish a connection between the client and the proxy server.
/// The client sends a connection request to the proxy server, which then forwards the request to the
/// destination server. The proxy server then establishes a connection with the destination server and
/// forwards the data between the client and the destination server.
/// The SOCKS5 protocol supports multiple authentication methods, including username/password and
/// no authentication. The proxy server can also support multiple proxy protocols, such as HTTP, HTTPS,
/// and SOCKS5.
// src/protocols/socks5.rs
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

pub struct Socks5;

impl Socks5 {
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
        if request[0] != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 version".into()));
        }

        let mut client = client;
        let stats = get_global_stats();

        // Track initial handshake bytes
        stats.add_bytes_in(request.len().try_into().unwrap());
        stats.add_bytes_out(2u64); // Track response bytes [0x05, 0x00]

        client.write_all(&[0x05, 0x00]).await?;

        let mut buf = Vec::new();
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;
        stats.add_bytes_in(4u64); // Track header bytes
        buf.extend_from_slice(&header);

        if header[0] != 0x05 {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 version in request".into(),
            ));
        }

        let (target_host, target_port) = match header[3] {
            0x01 => {
                let mut addr = [0u8; 6];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(6u64); // Track IPv4 address bytes
                buf.extend_from_slice(&addr);

                let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                (ip, port)
            }
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                stats.add_bytes_in(1u64); // Track domain length byte
                buf.extend_from_slice(&len);

                let domain_len = len[0] as usize;
                let mut domain = vec![0u8; domain_len + 2];
                client.read_exact(&mut domain).await?;
                stats.add_bytes_in((domain_len as u64) + 2u64); // Track domain bytes
                buf.extend_from_slice(&domain);

                let hostname = String::from_utf8_lossy(&domain[..domain_len]).to_string();
                let port = u16::from_be_bytes([domain[domain_len], domain[domain_len + 1]]);
                (hostname, port)
            }
            0x04 => {
                let mut addr = [0u8; 18];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(18u64); // Track IPv6 address bytes
                buf.extend_from_slice(&addr);

                let ip = format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    u16::from_be_bytes([addr[0], addr[1]]),
                    u16::from_be_bytes([addr[2], addr[3]]),
                    u16::from_be_bytes([addr[4], addr[5]]),
                    u16::from_be_bytes([addr[6], addr[7]]),
                    u16::from_be_bytes([addr[8], addr[9]]),
                    u16::from_be_bytes([addr[10], addr[11]]),
                    u16::from_be_bytes([addr[12], addr[13]]),
                    u16::from_be_bytes([addr[14], addr[15]])
                );
                let port = u16::from_be_bytes([addr[16], addr[17]]);
                (ip, port)
            }
            _ => return Err(ProxyError::Protocol("Unsupported address type".into())),
        };

        let mut upstream = TcpStream::connect(upstream_addr).await?;

        match target_proxy.proxy_type {
            Proxy::Http | Proxy::Https => {
                // Convert SOCKS5 to HTTP CONNECT
                let mut connect_request = Vec::new();

                // Construct CONNECT request
                connect_request.extend_from_slice(
                    format!("CONNECT {}:{} HTTP/1.1\r\n", target_host, target_port).as_bytes(),
                );
                connect_request.extend_from_slice(
                    format!("Host: {}:{}\r\n", target_host, target_port).as_bytes(),
                );

                // Add authentication if provided
                if let (Some(username), Some(password)) =
                    (&target_proxy.username, &target_proxy.password)
                {
                    let auth = encode_auth(username, password);
                    connect_request.extend_from_slice(b"Proxy-Authorization: Basic ");
                    connect_request.extend_from_slice(auth.as_bytes());
                    connect_request.extend_from_slice(b"\r\n");
                }

                connect_request.extend_from_slice(b"\r\n");

                // Send CONNECT request
                upstream.write_all(&connect_request).await?;
                stats.add_bytes_out(connect_request.len().try_into().unwrap()); // Track connect request bytes

                // Read HTTP response
                let mut response = [0u8; 1024];
                let n = upstream.read(&mut response).await?;
                stats.add_bytes_in(n.try_into().unwrap()); // Track response bytes
                let response_str = String::from_utf8_lossy(&response[..n]);

                if !response_str.contains("200 Connection Established") {
                    return Err(ProxyError::Protocol("HTTP tunnel failed".into()));
                }

                // Send success response to SOCKS5 client
                let response = [
                    0x05, // SOCKS version
                    0x00, // Success
                    0x00, // Reserved
                    0x01, // IPv4
                    0x00, 0x00, 0x00, 0x00, // IP (4 bytes)
                    0x00, 0x00, // Port (2 bytes)
                ];
                client.write_all(&response).await?;
                stats.add_bytes_out(response.len().try_into().unwrap()); // Track response bytes
            }
            Proxy::Socks4 => {
                // Convert SOCKS5 to SOCKS4 request
                let mut socks4_request = vec![0x04, 0x01]; // SOCKS4, CONNECT command
                socks4_request.extend_from_slice(&target_port.to_be_bytes());
                socks4_request.extend_from_slice(&[0, 0, 0, 1]); // IP (0.0.0.1 for SOCKS4a)
                socks4_request.push(0); // Empty user ID
                socks4_request.extend_from_slice(target_host.as_bytes()); // Domain name
                socks4_request.push(0); // Null terminator

                upstream.write_all(&socks4_request).await?;
                stats.add_bytes_out(socks4_request.len().try_into().unwrap());

                // Read SOCKS4 response
                let mut response = [0u8; 8];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(8);

                if response[1] != 0x5A {
                    return Err(ProxyError::Protocol("SOCKS4 connection failed".into()));
                }

                // Send SOCKS5 success response
                let response = [
                    0x05, // SOCKS version
                    0x00, // Success
                    0x00, // Reserved
                    0x01, // IPv4
                    0x00, 0x00, 0x00, 0x00, // IP (4 bytes)
                    0x00, 0x00, // Port (2 bytes)
                ];
                client.write_all(&response).await?;
                stats.add_bytes_out(response.len().try_into().unwrap());
            }
            Proxy::Socks5 => {
                // SOCKS5 handshake with upstream
                upstream.write_all(&[0x05, 0x01, 0x00]).await?;
                stats.add_bytes_out(3u64); // Track handshake bytes
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(2u64); // Track response bytes

                // handle user authentication
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
                    stats.add_bytes_out(auth_request.len() as u64); // Track auth request bytes

                    let mut auth_response = [0u8; 2];
                    upstream.read_exact(&mut auth_response).await?;
                    stats.add_bytes_in(2); // Track auth response bytes

                    if auth_response[1] != 0x00 {
                        return Err(ProxyError::Protocol("SOCKS5 authentication failed".into()));
                    }
                }

                upstream.write_all(&buf).await?;
                stats.add_bytes_out(buf.len().try_into().unwrap()); // Track request bytes

                let mut response = [0u8; 4];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(4u64); // Track response bytes
                client.write_all(&response).await?;
                stats.add_bytes_out(4u64); // Track response bytes

                let addr_type = response[3];
                match addr_type {
                    0x01 => {
                        let mut addr = [0u8; 6];
                        upstream.read_exact(&mut addr).await?;
                        stats.add_bytes_in(6u64); // Track IPv4 address bytes
                        client.write_all(&addr).await?;
                        stats.add_bytes_out(6u64); // Track IPv4 address bytes
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        upstream.read_exact(&mut len).await?;
                        stats.add_bytes_in(1u64); // Track domain length byte
                        client.write_all(&len).await?;
                        stats.add_bytes_out(1u64); // Track domain length byte
                        let mut domain = vec![0u8; len[0] as usize + 2];
                        upstream.read_exact(&mut domain).await?;
                        stats.add_bytes_in(domain.len().try_into().unwrap()); // Track domain bytes
                        client.write_all(&domain).await?;
                        stats.add_bytes_out(domain.len().try_into().unwrap()); // Track domain bytes
                    }
                    0x04 => {
                        let mut addr = [0u8; 18];
                        upstream.read_exact(&mut addr).await?;
                        stats.add_bytes_in(18u64); // Track IPv6 address bytes
                        client.write_all(&addr).await?;
                        stats.add_bytes_out(18u64); // Track IPv6 address bytes
                    }
                    _ => {
                        return Err(ProxyError::Protocol(
                            "Invalid address type in response".into(),
                        ));
                    }
                }
            }
        }

        proxy_data(client, upstream, stats).await
    }
}
