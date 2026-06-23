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
    stats::get_global_stats,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::config::RouterConfig;

pub struct Socks5;

impl Socks5 {
    pub async fn handle(
        client: TcpStream,
        upstream_addr: &str,
        request: Vec<u8>,
        target_proxy: &ProxyConfig,
        config: Arc<RouterConfig>,
        auth: &dyn crate::auth::AuthBackend,
    ) -> Result<(Option<i64>, TcpStream, TcpStream), ProxyError> {
        let mut client = client;
        let stats = get_global_stats();

        // Track initial handshake bytes
        stats.add_bytes_in(request.len().try_into().unwrap());

        // Parse the initial SOCKS5 greeting
        if request.len() < 3 {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 greeting length".into(),
            ));
        }

        let version = request[0];
        let nmethods = request[1];

        if version != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 version".into()));
        }

        // Check if we have enough bytes for the methods
        if request.len() < 2 + nmethods as usize {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 greeting: insufficient methods".into(),
            ));
        }

        // Check what methods client supports
        let methods = &request[2..2 + nmethods as usize];
        let supports_no_auth = methods.contains(&0x00);
        let supports_user_pass = methods.contains(&0x02);

        // Determine which method to use based on config
        let auth_enabled = config.auth.unwrap_or(false);
        let mut user_account: Option<i64> = None;

        if auth_enabled {
            // Auth is required - use username/password method (0x02)
            if !supports_user_pass {
                // Client doesn't support username/password auth
                client.write_all(&[0x05, 0xFF]).await?; // 0xFF = no acceptable methods
                stats.add_bytes_out(2u64);
                return Err(ProxyError::AuthFailed);
            }

            // Select method 0x02 (username/password)
            client.write_all(&[0x05, 0x02]).await?;
            stats.add_bytes_out(2u64);

            // Perform RFC 1929 username/password authentication
            let mut auth_request = [0u8; 513]; // Max size: 1 + 1 + 255 + 1 + 255
            let auth_len = client.read(&mut auth_request).await?;
            stats.add_bytes_in(auth_len as u64);

            if auth_len < 3 || auth_request[0] != 0x01 {
                return Err(ProxyError::Protocol("Invalid SOCKS5 auth request".into()));
            }

            let ulen = auth_request[1] as usize;
            if auth_len < 2 + ulen + 1 {
                return Err(ProxyError::Protocol(
                    "Invalid SOCKS5 auth username length".into(),
                ));
            }

            let username = String::from_utf8_lossy(&auth_request[2..2 + ulen]).to_string();
            let plen = auth_request[2 + ulen] as usize;

            if auth_len < 2 + ulen + 1 + plen {
                return Err(ProxyError::Protocol(
                    "Invalid SOCKS5 auth password length".into(),
                ));
            }

            let password =
                String::from_utf8_lossy(&auth_request[2 + ulen + 1..2 + ulen + 1 + plen])
                    .to_string();

            // Authenticate with the *base* username (routing tokens stripped).
            let username = crate::routing::parse_username(&username)
                .map(|(base, _sel)| base)
                .unwrap_or(username);

            // Authenticate via the pluggable auth backend.
            match auth.authenticate(&username, &password).await {
                Ok(Some(account)) => {
                    // Reject if a (non-null) bandwidth limit is exhausted.
                    if matches!(account.bandwidth_limit, Some(limit) if limit <= 0) {
                        stats.log_info(
                            format!("User {username} has no bandwidth remaining"),
                            &config,
                        );
                        client.write_all(&[0x01, 0x01]).await?; // Auth failed
                        stats.add_bytes_out(2u64);
                        return Err(ProxyError::BandwidthExceeded);
                    }

                    user_account = Some(account.id);
                    // Auth success
                    client.write_all(&[0x01, 0x00]).await?;
                    stats.add_bytes_out(2u64);
                }
                Ok(None) | Err(_) => {
                    // Auth failed
                    client.write_all(&[0x01, 0x01]).await?;
                    stats.add_bytes_out(2u64);
                    return Err(ProxyError::AuthFailed);
                }
            }
        } else {
            // No auth required - use method 0x00
            if !supports_no_auth {
                // Client doesn't support no auth
                client.write_all(&[0x05, 0xFF]).await?; // No acceptable methods
                stats.add_bytes_out(2u64);
                return Err(ProxyError::Protocol(
                    "Client does not support no authentication".into(),
                ));
            }

            // Select method 0x00 (no authentication)
            client.write_all(&[0x05, 0x00]).await?;
            stats.add_bytes_out(2u64);
        }

        // Now read the SOCKS5 request
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

        // Read address and port based on ATYP
        let (target_host, target_port) = match header[3] {
            0x01 => {
                // IPv4: 4 bytes address + 2 bytes port
                let mut addr = [0u8; 6];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(6u64);
                buf.extend_from_slice(&addr);
                let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                (ip, port)
            }
            0x03 => {
                // Domain: 1 byte len, N bytes domain, 2 bytes port
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                stats.add_bytes_in(1u64);
                buf.extend_from_slice(&len);
                let domain_len = len[0] as usize;
                let mut domain = vec![0u8; domain_len + 2];
                client.read_exact(&mut domain).await?;
                stats.add_bytes_in((domain_len as u64) + 2u64);
                buf.extend_from_slice(&domain);
                let hostname = String::from_utf8_lossy(&domain[..domain_len]).to_string();
                let port = u16::from_be_bytes([domain[domain_len], domain[domain_len + 1]]);
                (hostname, port)
            }
            0x04 => {
                // IPv6: 16 bytes address + 2 bytes port
                let mut addr = [0u8; 18];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(18u64);
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
        upstream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency

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
                // SOCKS5 handshake with upstream - offer both no auth and username/password auth
                let handshake =
                    if let (Some(_), Some(_)) = (&target_proxy.username, &target_proxy.password) {
                        // Offer both no auth and username/password auth
                        vec![0x05, 0x02, 0x00, 0x02]
                    } else {
                        // Only offer no auth
                        vec![0x05, 0x01, 0x00]
                    };
                upstream.write_all(&handshake).await?;
                stats.add_bytes_out(handshake.len().try_into().unwrap()); // Track handshake bytes
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(2u64); // Track response bytes

                // Check if upstream selected username/password authentication
                if response[1] == 0x02 {
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
                            return Err(ProxyError::Protocol(
                                "SOCKS5 authentication failed".into(),
                            ));
                        }
                    } else {
                        return Err(ProxyError::Protocol(
                            "Username/password required but not provided".into(),
                        ));
                    }
                } else if response[1] == 0x00 {
                } else {
                    return Err(ProxyError::Protocol(
                        "Upstream SOCKS5 handshake failed".into(),
                    ));
                }

                upstream.write_all(&buf).await?;
                stats.add_bytes_out(buf.len().try_into().unwrap()); // Track request bytes

                let mut response = [0u8; 4];
                upstream.read_exact(&mut response).await?;
                stats.add_bytes_in(4u64); // Track response bytes

                // Check if upstream connection was successful
                if response[1] != 0x00 {
                    // Send error response to client - use the same address type as the original request
                    let mut error_response = vec![
                        0x05,        // SOCKS version
                        response[1], // Error code from upstream
                        0x00,        // Reserved
                    ];

                    // Use the same address type as the original request
                    match header[3] {
                        0x01 => {
                            // IPv4
                            error_response.push(0x01); // IPv4
                            error_response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IP (4 bytes)
                            error_response.extend_from_slice(&[0x00, 0x00]); // Port (2 bytes)
                        }
                        0x03 => {
                            // Domain
                            error_response.push(0x03); // Domain
                            error_response.push(0x00); // Domain length
                            error_response.extend_from_slice(&[0x00, 0x00]); // Port (2 bytes)
                        }
                        0x04 => {
                            // IPv6
                            error_response.push(0x04); // IPv6
                            error_response.extend_from_slice(&[0x00; 16]); // IP (16 bytes)
                            error_response.extend_from_slice(&[0x00, 0x00]); // Port (2 bytes)
                        }
                        _ => {
                            return Err(ProxyError::Protocol("Invalid address type".into()));
                        }
                    }

                    client.write_all(&error_response).await?;
                    stats.add_bytes_out(error_response.len().try_into().unwrap());
                    return Err(ProxyError::Protocol(
                        "Upstream SOCKS5 connection failed".into(),
                    ));
                }

                // Forward successful response to client
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

        Ok((user_account, client, upstream))
    }
}
