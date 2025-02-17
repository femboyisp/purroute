/// HTTP proxy protocol
/// The HTTP proxy protocol is used to forward HTTP and HTTPS requests to an upstream proxy.
// src/protocols/http.rs
use crate::{
    config::encode_auth, stats::get_global_stats, stats::GlobalStats, Proxy, ProxyConfig,
    ProxyError,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct Http;

impl Http {
    pub async fn handle(
        client: TcpStream,
        upstream_addr: &str,
        request: Vec<u8>,
        is_https: bool,
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
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTP request".to_string()))?;

        let mut client = client;
        let mut upstream = TcpStream::connect(upstream_addr).await?;

        match target_proxy.proxy_type {
            Proxy::Http | Proxy::Https => {
                // For HTTP(S) proxies, modify the request to include authentication if needed
                let mut modified_request = Vec::new();

                if is_https {
                    // Handle CONNECT for HTTPS
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    let target = parts.get(1).ok_or_else(|| {
                        ProxyError::Protocol("Invalid CONNECT request".to_string())
                    })?;

                    // Construct CONNECT request
                    modified_request
                        .extend_from_slice(format!("CONNECT {} HTTP/1.1\r\n", target).as_bytes());
                } else {
                    // Keep the original request line for HTTP
                    modified_request.extend_from_slice(first_line.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }

                // Add Proxy-Authorization header if credentials are provided
                if let (Some(username), Some(password)) =
                    (&target_proxy.username, &target_proxy.password)
                {
                    let auth = encode_auth(username, password);
                    modified_request.extend_from_slice(b"Proxy-Authorization: Basic ");
                    modified_request.extend_from_slice(auth.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }

                // Add remaining headers
                let headers: Vec<&str> = request_str.lines().skip(1).collect();
                for header in headers {
                    modified_request.extend_from_slice(header.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }
                modified_request.extend_from_slice(b"\r\n");

                // Send the modified request to upstream proxy
                upstream.write_all(&modified_request).await?;

                if is_https {
                    // For HTTPS, wait for 200 response before starting tunnel
                    let mut response = [0u8; 1024];
                    let n = upstream.read(&mut response).await?;
                    let response_str = String::from_utf8_lossy(&response[..n]);

                    if !response_str.contains("200 Connection Established") {
                        return Err(ProxyError::Protocol("HTTPS tunnel failed".into()));
                    }

                    // Forward the 200 response to client
                    client.write_all(&response[..n]).await?;
                }
            }
            Proxy::Socks5 => {
                // SOCKS5 handshake with upstream
                upstream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;

                if response[0] != 0x05 || response[1] != 0x00 {
                    return Err(ProxyError::Protocol("Upstream handshake failed".into()));
                }

                // Extract target host and port
                let (host, port): (String, u16) = if is_https {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    let target = parts.get(1).ok_or_else(|| {
                        ProxyError::Protocol("Invalid CONNECT request".to_string())
                    })?;
                    let mut parts = target.split(':');
                    (
                        parts.next().unwrap_or("").to_string(),
                        parts.next().unwrap_or("443").parse().unwrap_or(443),
                    )
                } else {
                    // Extract from Host header
                    let host_header = request_str
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("host: "))
                        .ok_or_else(|| ProxyError::Protocol("No Host header found".to_string()))?;
                    let host_value = &host_header[6..];
                    let mut parts = host_value.trim().split(':');
                    (
                        parts.next().unwrap_or("").to_string(),
                        parts.next().unwrap_or("80").parse().unwrap_or(80),
                    )
                };

                // Create SOCKS5 connect request
                let mut socks_request = vec![0x05, 0x01, 0x00, 0x03];
                socks_request.push(host.len() as u8);
                socks_request.extend_from_slice(host.as_bytes());
                socks_request.extend_from_slice(&port.to_be_bytes());

                // Send SOCKS5 connect request
                upstream.write_all(&socks_request).await?;

                // Read SOCKS5 response
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

                if is_https {
                    // Send 200 Connection Established for HTTPS
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                } else {
                    // Forward the original HTTP request
                    upstream.write_all(&request).await?;
                }
            }
        }

        // Start bidirectional proxy
        proxy_data(client, upstream, get_global_stats()).await
    }
}
