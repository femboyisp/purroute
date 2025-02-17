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
    config::encode_auth, stats::get_global_stats, stats::global::GlobalStats, Proxy, ProxyConfig,
    ProxyError,
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
        // Verify SOCKS5 version
        if request[0] != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 version".into()));
        }

        let mut client = client;
        // Send auth method selection message
        client.write_all(&[0x05, 0x00]).await?;

        // Read client's connection request into a buffer
        let mut buf = Vec::new();
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;
        buf.extend_from_slice(&header);

        if header[0] != 0x05 {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 version in request".into(),
            ));
        }

        // Parse the SOCKS5 address
        let (target_host, target_port) = match header[3] {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 6]; // 4 for IPv4 + 2 for port
                client.read_exact(&mut addr).await?;
                buf.extend_from_slice(&addr);

                let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                (ip, port)
            }
            0x03 => {
                // Domain name
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                buf.extend_from_slice(&len);

                let domain_len = len[0] as usize;
                let mut domain = vec![0u8; domain_len + 2]; // +2 for port
                client.read_exact(&mut domain).await?;
                buf.extend_from_slice(&domain);

                let hostname = String::from_utf8_lossy(&domain[..domain_len]).to_string();
                let port = u16::from_be_bytes([domain[domain_len], domain[domain_len + 1]]);
                (hostname, port)
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 18]; // 16 for IPv6 + 2 for port
                client.read_exact(&mut addr).await?;
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
            _ => {
                return Err(ProxyError::Protocol("Unsupported address type".into()));
            }
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

                // Read HTTP response
                let mut response = [0u8; 1024];
                let n = upstream.read(&mut response).await?;
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
            }
            Proxy::Socks5 => {
                // SOCKS5 handshake with upstream
                upstream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;

                if response[0] != 0x05 || response[1] != 0x00 {
                    return Err(ProxyError::Protocol("Upstream handshake failed".into()));
                }

                upstream.write_all(&buf).await?;

                let mut response = [0u8; 4];
                upstream.read_exact(&mut response).await?;
                client.write_all(&response).await?;

                let addr_type = response[3];
                match addr_type {
                    0x01 => {
                        let mut addr = [0u8; 6];
                        upstream.read_exact(&mut addr).await?;
                        client.write_all(&addr).await?;
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        upstream.read_exact(&mut len).await?;
                        client.write_all(&len).await?;
                        let mut domain = vec![0u8; len[0] as usize + 2];
                        upstream.read_exact(&mut domain).await?;
                        client.write_all(&domain).await?;
                    }
                    0x04 => {
                        let mut addr = [0u8; 18];
                        upstream.read_exact(&mut addr).await?;
                        client.write_all(&addr).await?;
                    }
                    _ => {
                        return Err(ProxyError::Protocol(
                            "Invalid address type in response".into(),
                        ));
                    }
                }
            }
        }

        // Start bidirectional proxy
        proxy_data(client, upstream, get_global_stats()).await
    }
}
