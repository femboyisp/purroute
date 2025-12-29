/// PROXY Protocol
/// This module implements the PROXY protocol for the proxy server.
/// The PROXY protocol is a simple text-based protocol that is used to pass client connection information to the server.
/// The client sends a PROXY header to the server, which contains the client's IP address and port number.
/// The server reads the PROXY header and uses the client's IP address and port number to establish a connection to the client.
/// The server then forwards the client's request to the destination server.
// src/protocols/proxy.rs
use crate::{
    config::{ChainConfig, ProxyConfig, RouterConfig},
    protocols::{ChainConnector, Http, Https, Socks5, Socks4},
    stats::{get_global_stats, GlobalStats, StatsDisplay},
};
use base64::Engine;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_postgres::Client;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum Proxy {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Not enough bandwidth")]
    BandwidthExceeded,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Timeout error")]
    Timeout,
    #[error("Unsupported protocol")]
    UnsupportedProtocol,
}

#[derive(Clone)]
pub struct ProxyServer {
    proxy: Arc<Vec<ProxyConfig>>,
    chains: Arc<Option<Vec<ChainConfig>>>,
    config: Arc<RouterConfig>,
    db_client: Arc<Client>,
}

impl ProxyServer {
    pub fn new(
        proxy: Vec<ProxyConfig>,
        chains: Option<Vec<ChainConfig>>,
        _logger: Arc<StatsDisplay>,
        config: Arc<RouterConfig>,
        db_client: Arc<Client>,
    ) -> Self {
        Self {
            proxy: Arc::new(proxy),
            chains: Arc::new(chains),
            config,
            db_client,
        }
    }

    /// Resolve the chain to use for a connection
    fn resolve_proxy_chain(&self) -> Result<Vec<ProxyConfig>, ProxyError> {
        // If router.chain is specified, use that chain
        if let Some(chain_ref) = &self.config.chain {
            // First, try to find a single proxy by label (Single mode)
            if let Some(proxy) = self.proxy.iter().find(|p| p.label.as_deref() == Some(chain_ref)) {
                return Ok(vec![proxy.clone()]);
            }

            // If not a proxy label, look for a chain configuration
            if let Some(chains) = self.chains.as_ref() {
                let chain = chains
                    .iter()
                    .find(|c| &c.chain_id == chain_ref)
                    .ok_or_else(|| ProxyError::Protocol(format!("Chain or proxy '{}' not found", chain_ref)))?;

                // Collect all proxy configs from the chain
                let mut proxy_configs = Vec::new();
                for label in &chain.proxies {
                    let proxy = self.proxy
                        .iter()
                        .find(|p| p.label.as_deref() == Some(label))
                        .ok_or_else(|| ProxyError::Protocol(format!("Proxy '{}' not found in chain '{}'", label, chain_ref)))?
                        .clone();
                    proxy_configs.push(proxy);
                }

                // Apply chain mode
                use crate::config::ChainMode;
                let result = match chain.mode {
                    ChainMode::Strict => {
                        // Return proxies in order
                        proxy_configs
                    }
                    ChainMode::Random => {
                        // Randomly select proxies
                        use rand::seq::SliceRandom;
                        let mut rng = rand::rng();

                        if let Some(count) = chain.count {
                            // Pick 'count' random proxies
                            let count = count.min(proxy_configs.len());
                            proxy_configs.shuffle(&mut rng);
                            proxy_configs.truncate(count);
                            proxy_configs
                        } else {
                            // Pick one random proxy
                            proxy_configs.shuffle(&mut rng);
                            vec![proxy_configs.into_iter().next().unwrap()]
                        }
                    }
                };

                return Ok(result);
            }
        }

        // Fallback: use first proxy (backward compatibility)
        let proxy = self.proxy.first()
            .ok_or_else(|| ProxyError::Protocol("No proxy configuration available".to_string()))?
            .clone();

        Ok(vec![proxy])
    }

    /// Handle SOCKS5 connection with multi-hop chain
    async fn handle_socks5_chain(
        &self,
        mut client: TcpStream,
        initial_request: Vec<u8>,
        proxy_chain: Vec<ProxyConfig>,
        peer_addr: SocketAddr,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        // Parse SOCKS5 greeting (already received in initial_request)
        stats.add_bytes_in(initial_request.len() as u64);

        if initial_request.len() < 3 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 greeting length".into()));
        }

        let version = initial_request[0];
        let nmethods = initial_request[1];

        if version != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 version".into()));
        }

        if initial_request.len() < 2 + nmethods as usize {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 greeting: insufficient methods".into(),
            ));
        }

        let methods = &initial_request[2..2 + nmethods as usize];
        let supports_no_auth = methods.contains(&0x00);
        let supports_user_pass = methods.contains(&0x02);

        // Determine authentication method
        let auth_enabled = self.config.auth.unwrap_or(false);
        let mut user_account: Option<i64> = None;

        if auth_enabled {
            if !supports_user_pass {
                client.write_all(&[0x05, 0xFF]).await?;
                stats.add_bytes_out(2u64);
                return Err(ProxyError::AuthFailed);
            }

            client.write_all(&[0x05, 0x02]).await?;
            stats.add_bytes_out(2u64);

            // Perform username/password authentication
            let mut auth_request = [0u8; 513];
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

            // Verify credentials and check bandwidth
            let row = self
                .db_client
                .query_one(
                    "SELECT account, bandwidth_limit FROM public.accounts WHERE username = $1 AND password = $2",
                    &[&username, &password],
                )
                .await
                .map_err(|_| ProxyError::AuthFailed)?;

            let account_id: i64 = row.get(0);
            let bandwidth_limit: Option<i64> = row.get(1);

            if let Some(limit) = bandwidth_limit {
                if limit <= 0 {
                    return Err(ProxyError::BandwidthExceeded);
                }
            }

            user_account = Some(account_id);

            client.write_all(&[0x01, 0x00]).await?;
            stats.add_bytes_out(2u64);
        } else {
            if !supports_no_auth {
                client.write_all(&[0x05, 0xFF]).await?;
                stats.add_bytes_out(2u64);
                return Err(ProxyError::Protocol(
                    "Client does not support no authentication".into(),
                ));
            }

            client.write_all(&[0x05, 0x00]).await?;
            stats.add_bytes_out(2u64);
        }

        // Read SOCKS5 request
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;
        stats.add_bytes_in(4u64);

        if header[0] != 0x05 {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 version in request".into(),
            ));
        }

        // Extract target host and port
        let (target_host, target_port) = match header[3] {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 6];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(6u64);
                let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                (ip, port)
            }
            0x03 => {
                // Domain
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                stats.add_bytes_in(1u64);
                let domain_len = len[0] as usize;
                let mut domain = vec![0u8; domain_len + 2];
                client.read_exact(&mut domain).await?;
                stats.add_bytes_in((domain_len as u64) + 2u64);
                let hostname = String::from_utf8_lossy(&domain[..domain_len]).to_string();
                let port = u16::from_be_bytes([domain[domain_len], domain[domain_len + 1]]);
                (hostname, port)
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 18];
                client.read_exact(&mut addr).await?;
                stats.add_bytes_in(18u64);
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

        // Use ChainConnector to establish upstream connection through the chain
        let upstream = ChainConnector::connect_chain(&proxy_chain, &target_host, target_port).await?;

        // Send success response to client
        let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        client.write_all(&response).await?;
        stats.add_bytes_out(response.len() as u64);

        global_stats.record_connection_result(
            true,
            format!("SOCKS5 Chain Connection successful for {}", peer_addr),
            &self.config,
        );

        // Relay data between client and upstream
        self.proxy_data(client, upstream, peer_addr, global_stats, user_account)
            .await
    }

    pub async fn run(self, addr: SocketAddr) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        let global_stats = get_global_stats();
        global_stats.log_info(format!("Proxy server listening on {}", addr), &self.config);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let global_stats = global_stats.clone();

            // Increment active connections as soon as we accept a new connection
            global_stats.increment_active_connections();
            global_stats.log_info(format!("New connection from {}", peer_addr), &self.config);

            let server = self.clone();
            let label = server.proxy.first().and_then(|config| config.label.clone());
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket, peer_addr, label).await {
                    global_stats.record_connection_result(
                        false,
                        format!("Connection error from {}: {}", peer_addr, e),
                        &server.config,
                    );
                    // Ensure we decrement on error
                    global_stats.decrement_active_connections();
                }
            });
        }
    }

    pub async fn handle_connection(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
        label: Option<String>,
    ) -> Result<(), ProxyError> {
        let global_stats = get_global_stats();
        let server = self.clone();

        let handle = tokio::spawn(async move {
            let result = async {
                let mut buf = vec![0u8; 8192];
                let n = client.read(&mut buf).await?;
                let initial_request = buf[..n].to_vec();

                let protocol = server.detect_protocol(&initial_request)?;
                global_stats.log_info(
                    format!("Protocol {:?} detected from {}", protocol, peer_addr),
                    &server.config,
                );

                // Resolve the proxy chain to use
                let proxy_chain = server.resolve_proxy_chain()?;
                let target_proxy = &proxy_chain[0];

                if proxy_chain.len() > 1 {
                    let chain_desc: Vec<String> = proxy_chain
                        .iter()
                        .filter_map(|p| p.label.clone())
                        .collect();
                    global_stats.log_info(
                        format!("Using chain: {} ({} hops)", chain_desc.join(" -> "), proxy_chain.len()),
                        &server.config,
                    );
                } else if let Some(label) = &label {
                    global_stats.log_info(
                        format!("Using proxy '{}' for connection from {}", label, peer_addr),
                        &server.config,
                    );
                }

                match protocol {
                    Proxy::Socks5 => {
                        if proxy_chain.len() == 1 {
                            // Single proxy: use existing logic
                            let (user_account, client_stream, upstream_stream) = Socks5::handle(
                                client,
                                &target_proxy.get_upstream_addr(),
                                initial_request,
                                target_proxy,
                                server.config.clone(),
                                server.db_client.clone(),
                            )
                            .await?;

                            global_stats.record_connection_result(
                                true,
                                format!("Socks5 Connection successful for {}", peer_addr),
                                &server.config,
                            );

                            server
                                .proxy_data(client_stream, upstream_stream, peer_addr, global_stats.clone(), user_account)
                                .await
                        } else {
                            // Multi-hop chain: handle client SOCKS5 handshake and use ChainConnector
                            server.handle_socks5_chain(client, initial_request, proxy_chain, peer_addr, global_stats.clone()).await
                        }
                    }
                    Proxy::Socks4 => {
                        // Authenticate user for SOCKS4
                        let user_account = server.authenticate_user(&initial_request).await?;

                        Socks4::handle(
                            client,
                            &target_proxy.get_upstream_addr(),
                            initial_request,
                            target_proxy,
                            move |client, upstream, stats| {
                                let server = server.clone();
                                let peer = peer_addr;
                                Box::pin(async move {
                                    stats.record_connection_result(
                                        true,
                                        format!("Socks4 Connection successful for {}", peer_addr),
                                        &server.config,
                                    );
                                    server
                                        .proxy_data(client, upstream, peer, stats, user_account)
                                        .await
                                })
                            },
                        )
                        .await
                    }
                    Proxy::Http => {
                        // Authenticate user for HTTP
                        let user_account = server.authenticate_user(&initial_request).await?;

                        Http::handle(
                            client,
                            &target_proxy.get_upstream_addr(),
                            initial_request,
                            target_proxy,
                            move |client, upstream, stats| {
                                let server = server.clone();
                                let peer = peer_addr;
                                Box::pin(async move {
                                    stats.record_connection_result(
                                        true,
                                        format!("HTTP Connection successful for {}", peer_addr),
                                        &server.config,
                                    );
                                    server
                                        .proxy_data(client, upstream, peer, stats, user_account)
                                        .await
                                })
                            },
                        )
                        .await
                    }
                    Proxy::Https => {
                        // Authenticate user for HTTPS
                        let user_account = server.authenticate_user(&initial_request).await?;

                        Https::handle(
                            client,
                            &target_proxy.get_upstream_addr(),
                            initial_request,
                            target_proxy,
                            move |client, upstream, stats| {
                                let server = server.clone();
                                let peer = peer_addr;
                                Box::pin(async move {
                                    stats.record_connection_result(
                                        true,
                                        format!("HTTPS Connection successful for {}", peer_addr),
                                        &server.config,
                                    );
                                    server
                                        .proxy_data(client, upstream, peer, stats, user_account)
                                        .await
                                })
                            },
                        )
                        .await
                    }
                }
            }
            .await;

            result
        });

        // Wait for the handle and propagate any errors
        handle
            .await
            .unwrap_or_else(|e| Err(ProxyError::Protocol(e.to_string())))
    }

    pub fn detect_protocol(&self, request: &[u8]) -> Result<Proxy, ProxyError> {
        if request.len() < 1 {
            return Err(ProxyError::Protocol("Request too short".into()));
        }

        if request[0] == 0x05 {
            return Ok(Proxy::Socks5);
        }

        if request[0] == 0x04 {
            return Ok(Proxy::Socks4);
        }

        let request_str = String::from_utf8_lossy(&request[..std::cmp::min(request.len(), 20)]);
        let first_line = request_str
            .lines()
            .next()
            .ok_or_else(|| ProxyError::Protocol("Invalid HTTP request".to_string()))?;

        if first_line.starts_with("CONNECT") {
            Ok(Proxy::Https)
        } else if first_line.starts_with("GET")
            || first_line.starts_with("POST")
            || first_line.starts_with("HEAD")
            || first_line.starts_with("PUT")
            || first_line.starts_with("DELETE")
            || first_line.starts_with("OPTIONS")
            || first_line.starts_with("TRACE")
            || first_line.starts_with("PATCH")
        {
            Ok(Proxy::Http)
        } else {
            Err(ProxyError::UnsupportedProtocol)
        }
    }

    pub async fn authenticate_user(&self, request: &[u8]) -> Result<Option<i64>, ProxyError> {
        if let Some(auth) = self.config.auth {
            if auth {
                let request_str = String::from_utf8_lossy(request);
                let auth_header = request_str
                    .lines()
                    .find(|line| {
                        line.to_lowercase()
                            .starts_with("proxy-authorization: basic ")
                    })
                    .ok_or(ProxyError::AuthFailed)?;

                let encoded_credentials = auth_header[27..].trim();
                let decoded_credentials = base64::engine::general_purpose::STANDARD
                    .decode(encoded_credentials)
                    .map_err(|_| ProxyError::AuthFailed)?;
                let credentials =
                    String::from_utf8(decoded_credentials).map_err(|_| ProxyError::AuthFailed)?;
                let mut parts = credentials.split(':');
                let username = parts.next().ok_or(ProxyError::AuthFailed)?;
                let password = parts.next().ok_or(ProxyError::AuthFailed)?;

                let query = "
                       SELECT account, bandwidth_limit
                       FROM public.accounts
                       WHERE username = $1 AND password = $2
                   ";

                if let Some(row) = self
                    .db_client
                    .query_opt(query, &[&username, &password])
                    .await
                    .map_err(|_| ProxyError::AuthFailed)?
                {
                    let account_id: i64 = row.get(0);
                    let bandwidth_limit: i64 = row.get(1);

                    // Check if user has bandwidth remaining
                    if bandwidth_limit <= 0 {
                        get_global_stats().log_info(
                            format!("User {} has no bandwidth remaining ({})",
                                username, bandwidth_limit),
                            &self.config,
                        );
                        return Err(ProxyError::BandwidthExceeded);
                    }

                    return Ok(Some(account_id));
                }

                return Err(ProxyError::AuthFailed);
            }
        }

        Ok(None)
    }

    pub async fn proxy_data(
        &self,
        mut client: TcpStream,
        mut upstream: TcpStream,
        peer_addr: SocketAddr,
        stats: Arc<GlobalStats>,
        id: Option<i64>,
    ) -> Result<(), ProxyError> {
        let (mut client_reader, mut client_writer) = client.split();
        let (mut upstream_reader, mut upstream_writer) = upstream.split();

        // Create channels to signal when either stream ends
        let (tx1, rx1) = tokio::sync::oneshot::channel();
        let (tx2, rx2) = tokio::sync::oneshot::channel();

        let client_to_upstream = async {
            let mut buf = [0u8; 8192];
            let result = loop {
                match client_reader.read(&mut buf).await {
                    Ok(0) => break Ok(()), // Normal EOF
                    Ok(n) => {
                        stats.add_bytes_out(n.try_into().unwrap());
                        if let Some(id) = id {
                            self.add_user_bytes_out(id, n.try_into().unwrap()).await?;
                        }
                        if let Err(e) = upstream_writer.write_all(&buf[..n]).await {
                            stats.record_connection_result(
                                false,
                                format!("Error writing to upstream for {}: {}", peer_addr, e),
                                &self.config,
                            );
                            break Err(ProxyError::Io(e));
                        }
                        if let Err(e) = upstream_writer.flush().await {
                            stats.record_connection_result(
                                false,
                                format!("Error flushing upstream for {}: {}", peer_addr, e),
                                &self.config,
                            );
                            break Err(ProxyError::Io(e));
                        }
                    }
                    Err(e) => {
                        stats.record_connection_result(
                            false,
                            format!("Error reading from client {}: {}", peer_addr, e),
                            &self.config,
                        );
                        break Err(ProxyError::Io(e));
                    }
                }
            };
            let _ = tx1.send(()); // Signal that this stream has ended
            result
        };

        let upstream_to_client = async {
            let mut buf = [0u8; 8192];
            let result = loop {
                match upstream_reader.read(&mut buf).await {
                    Ok(0) => break Ok(()), // Normal EOF
                    Ok(n) => {
                        stats.add_bytes_in(n.try_into().unwrap());
                        if let Some(id) = id {
                            self.add_user_bytes_in(id, n.try_into().unwrap()).await?;
                        }
                        if let Err(e) = client_writer.write_all(&buf[..n]).await {
                            stats.record_connection_result(
                                false,
                                format!("Error writing to client {}: {}", peer_addr, e),
                                &self.config,
                            );
                            break Err(ProxyError::Io(e));
                        }
                        if let Err(e) = client_writer.flush().await {
                            stats.record_connection_result(
                                false,
                                format!("Error flushing client {}: {}", peer_addr, e),
                                &self.config,
                            );
                            break Err(ProxyError::Io(e));
                        }
                    }
                    Err(e) => {
                        stats.record_connection_result(
                            false,
                            format!("Error reading from upstream for {}: {}", peer_addr, e),
                            &self.config,
                        );
                        break Err(ProxyError::Io(e));
                    }
                }
            };
            let _ = tx2.send(()); // Signal that this stream has ended
            result
        };

        // Wait for either stream to end
        let result = tokio::select! {
            r1 = client_to_upstream => r1,
            r2 = upstream_to_client => r2,
            _ = rx1 => Ok(()),
            _ = rx2 => Ok(()),
        };

        // Always decrement active connections when connection ends
        stats.decrement_active_connections();
        stats.log_info(format!("Connection closed for {}", peer_addr), &self.config);

        result
    }

    async fn add_user_bytes_in(&self, id: i64, bytes: i64) -> Result<(), ProxyError> {
        // Update user stats
        let stats_query = "
                UPDATE public.user_stats
                SET total_bytes_in = total_bytes_in + $1
                WHERE id = $2
            ";

        self.db_client
            .execute(stats_query, &[&bytes, &id])
            .await
            .map_err(|e| {
                ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        // Decrement bandwidth_limit
        let limit_query = "
                UPDATE public.accounts
                SET bandwidth_limit = GREATEST(bandwidth_limit - $1, 0)
                WHERE account = $2
            ";

        self.db_client
            .execute(limit_query, &[&bytes, &id])
            .await
            .map_err(|e| {
                ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        Ok(())
    }

    async fn add_user_bytes_out(&self, id: i64, bytes: i64) -> Result<(), ProxyError> {
        // Update user stats
        let stats_query = "
                        UPDATE public.user_stats
                        SET total_bytes_out = total_bytes_out + $1
                        WHERE id = $2
                    ";

        self.db_client
            .execute(stats_query, &[&bytes, &id])
            .await
            .map_err(|e| {
                ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        // Decrement bandwidth_limit
        let limit_query = "
                UPDATE public.accounts
                SET bandwidth_limit = GREATEST(bandwidth_limit - $1, 0)
                WHERE account = $2
            ";

        self.db_client
            .execute(limit_query, &[&bytes, &id])
            .await
            .map_err(|e| {
                ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        Ok(())
    }
}
