/// HTTP proxy protocol
/// The HTTP proxy protocol is used to forward HTTP and HTTPS requests to an upstream proxy.
// src/protocols/http.rs
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

pub struct Http;

impl Http {
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
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTP request".to_string()))?;

        let mut upstream = TcpStream::connect(upstream_addr).await?;
        let stats = get_global_stats();

        match target_proxy.proxy_type {
            Proxy::Http | Proxy::Https => {
                // Track initial request bytes
                stats.add_bytes_out(request.len() as u64);

                // Forward HTTP request with optional authentication
                let mut modified_request = Vec::new();
                modified_request.extend_from_slice(first_line.as_bytes());
                modified_request.extend_from_slice(b"\r\n");

                if let (Some(username), Some(password)) =
                    (&target_proxy.username, &target_proxy.password)
                {
                    let auth = encode_auth(username, password);
                    modified_request.extend_from_slice(b"Proxy-Authorization: Basic ");
                    modified_request.extend_from_slice(auth.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }

                let headers: Vec<&str> = request_str.lines().skip(1).collect();
                for header in headers {
                    modified_request.extend_from_slice(header.as_bytes());
                    modified_request.extend_from_slice(b"\r\n");
                }
                modified_request.extend_from_slice(b"\r\n");

                // Track modified request bytes
                stats.add_bytes_out(modified_request.len() as u64);
                upstream.write_all(&modified_request).await?;
            }
            Proxy::Socks5 => {
                // Extract host and port from Host header
                let host_header = request_str
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("host: "))
                    .ok_or_else(|| ProxyError::Protocol("No Host header found".to_string()))?;
                let host_value = &host_header[6..];
                let mut parts = host_value.trim().split(':');
                let host = parts.next().unwrap_or("");
                let port = parts.next().unwrap_or("80").parse::<u16>().unwrap_or(80);

                // SOCKS5 handshake
                upstream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut response = [0u8; 2];
                upstream.read_exact(&mut response).await?;

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
                    stats.add_bytes_out(auth_request.len() as u64); // Track auth request bytes

                    let mut auth_response = [0u8; 2];
                    upstream.read_exact(&mut auth_response).await?;
                    stats.add_bytes_in(2); // Track auth response bytes

                    if auth_response[1] != 0x00 {
                        return Err(ProxyError::Protocol("SOCKS5 authentication failed".into()));
                    }
                }

                // Create SOCKS5 connect request
                let mut socks_request = vec![0x05, 0x01, 0x00, 0x03];
                socks_request.push(host.len() as u8);
                socks_request.extend_from_slice(host.as_bytes());
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

                // Track bytes before sending
                stats.add_bytes_out(request.len() as u64);
                upstream.write_all(&request).await?;
            }
        }

        // Start bidirectional proxy
        proxy_data(client, upstream, stats).await
    }
}
