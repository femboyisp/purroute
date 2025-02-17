use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod config;
use config::{encode_auth, load_config, ProxyConfig, ProxyType};

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Timeout error")]
    Timeout,
    #[error("Unsupported protocol")]
    UnsupportedProtocol,
}

#[derive(Debug)]
struct UserStats {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active_connections: AtomicU64,
}

#[derive(Debug, PartialEq)]
enum ProxyProtocol {
    Http,
    Https,
    Socks5,
}

struct ProxyServer {
    proxy_chain: Vec<ProxyConfig>,
}

impl ProxyServer {
    pub fn new(proxy_chain: Vec<ProxyConfig>) -> Self {
        Self { proxy_chain }
    }

    pub async fn run(self, addr: SocketAddr) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        println!("Proxy server listening on {}", addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            println!("New connection from {}", peer_addr);
            // Clone is not implemented, so we move self into the task
            let proxy_chain = self.proxy_chain.clone();
            let server = ProxyServer { proxy_chain };

            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket).await {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection(&self, mut client: TcpStream) -> Result<(), ProxyError> {
        let mut buf = vec![0u8; 8192];
        let n = client.read(&mut buf).await?;
        let initial_request = buf[..n].to_vec();

        let protocol = self.detect_protocol(&initial_request)?;
        println!("Detected protocol: {:?}", protocol);

        let target_proxy = self
            .proxy_chain
            .first()
            .ok_or_else(|| ProxyError::Protocol("No proxy configuration available".to_string()))?;

        match protocol {
            ProxyProtocol::Socks5 => {
                self.handle_socks5(client, &target_proxy.address, initial_request)
                    .await
            }
            ProxyProtocol::Http => {
                self.handle_http(client, &target_proxy.address, initial_request, false)
                    .await
            }
            ProxyProtocol::Https => {
                self.handle_http(client, &target_proxy.address, initial_request, true)
                    .await
            }
        }
    }

    async fn handle_socks5(
        &self,
        mut client: TcpStream,
        upstream_addr: &str,
        request: Vec<u8>,
    ) -> Result<(), ProxyError> {
        // Verify SOCKS5 version
        if request[0] != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 version".into()));
        }

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
                return Err(ProxyError::Protocol("IPv6 not supported".into()));
            }
            _ => {
                return Err(ProxyError::Protocol("Unsupported address type".into()));
            }
        };

        let mut upstream = TcpStream::connect(upstream_addr).await?;
        let target_proxy = self
            .proxy_chain
            .first()
            .ok_or_else(|| ProxyError::Protocol("No proxy configuration available".to_string()))?;

        match target_proxy.proxy_type {
            ProxyType::Http | ProxyType::Https => {
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
            ProxyType::Socks5 => {
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
        self.proxy_data(
            client,
            upstream,
            Arc::new(UserStats {
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                active_connections: AtomicU64::new(1),
            }),
        )
        .await
    }

    async fn handle_http(
        &self,
        mut client: TcpStream,
        upstream_addr: &str,
        request: Vec<u8>,
        is_https: bool,
    ) -> Result<(), ProxyError> {
        let request_str = String::from_utf8_lossy(&request);
        let first_line = request_str
            .lines()
            .next()
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTP request".to_string()))?;

        let mut upstream = TcpStream::connect(upstream_addr).await?;

        let target_proxy = self
            .proxy_chain
            .first()
            .ok_or_else(|| ProxyError::Protocol("No proxy configuration available".to_string()))?;

        match target_proxy.proxy_type {
            ProxyType::Http | ProxyType::Https => {
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
            ProxyType::Socks5 => {
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
        self.proxy_data(
            client,
            upstream,
            Arc::new(UserStats {
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                active_connections: AtomicU64::new(1),
            }),
        )
        .await
    }

    fn detect_protocol(&self, request: &[u8]) -> Result<ProxyProtocol, ProxyError> {
        if request.len() < 1 {
            return Err(ProxyError::Protocol("Request too short".into()));
        }

        if request[0] == 0x05 {
            return Ok(ProxyProtocol::Socks5);
        }

        let request_str = String::from_utf8_lossy(&request[..std::cmp::min(request.len(), 20)]);
        let first_line = request_str
            .lines()
            .next()
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTP request".to_string()))?;

        if first_line.starts_with("CONNECT") {
            Ok(ProxyProtocol::Https)
        } else if first_line.starts_with("GET")
            || first_line.starts_with("POST")
            || first_line.starts_with("HEAD")
            || first_line.starts_with("PUT")
            || first_line.starts_with("DELETE")
            || first_line.starts_with("OPTIONS")
            || first_line.starts_with("TRACE")
            || first_line.starts_with("PATCH")
        {
            Ok(ProxyProtocol::Http)
        } else {
            Err(ProxyError::Protocol("Unknown protocol".into()))
        }
    }

    async fn proxy_data(
        &self,
        mut client: TcpStream,
        mut upstream: TcpStream,
        user_stats: Arc<UserStats>,
    ) -> Result<(), ProxyError> {
        let (mut client_reader, mut client_writer) = client.split();
        let (mut upstream_reader, mut upstream_writer) = upstream.split();

        let client_to_upstream = async {
            let mut buf = [0u8; 8192];
            loop {
                match client_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        user_stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = upstream_writer.write_all(&buf[..n]).await {
                            eprintln!("Error writing to upstream: {}", e);
                            break;
                        }
                        if let Err(e) = upstream_writer.flush().await {
                            eprintln!("Error flushing upstream: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from client: {}", e);
                        break;
                    }
                }
            }
            Ok::<(), std::io::Error>(())
        };

        let upstream_to_client = async {
            let mut buf = [0u8; 8192];
            loop {
                match upstream_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        user_stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = client_writer.write_all(&buf[..n]).await {
                            eprintln!("Error writing to client: {}", e);
                            break;
                        }
                        if let Err(e) = client_writer.flush().await {
                            eprintln!("Error flushing client: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from upstream: {}", e);
                        break;
                    }
                }
            }
            Ok::<(), std::io::Error>(())
        };

        tokio::try_join!(client_to_upstream, upstream_to_client)?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from config.toml
    let (listen_addr, proxy_chain) = load_config("config.toml")?;

    let server = ProxyServer::new(proxy_chain);
    server.run(listen_addr.parse()?).await?;

    Ok(())
}
