use crate::auth::AuthBackend;
use crate::protocol::Protocol as Proxy;
/// PROXY Protocol
/// This module implements the PROXY protocol for the proxy server.
/// The PROXY protocol is a simple text-based protocol that is used to pass client connection information to the server.
/// The client sends a PROXY header to the server, which contains the client's IP address and port number.
/// The server reads the PROXY header and uses the client's IP address and port number to establish a connection to the client.
/// The server then forwards the client's request to the destination server.
// src/protocols/proxy.rs
use crate::{
    config::{ChainConfig, ProxyConfig, RouterConfig},
    protocols::{ChainConnector, Http, Https, Socks4},
    stats::{get_global_stats, GlobalStats, StatsDisplay},
};
use arc_swap::ArcSwap;
use base64::Engine;
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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
    #[error("No upstream matches the requested location/ISP selection")]
    NoMatchingUpstream,
}

#[derive(Clone)]
pub struct ProxyServer {
    proxy: Arc<ArcSwap<Vec<ProxyConfig>>>,
    chains: Arc<Option<Vec<ChainConfig>>>,
    config: Arc<RouterConfig>,
    auth: Arc<dyn AuthBackend>,
}

impl ProxyServer {
    pub fn new(
        proxy: Vec<ProxyConfig>,
        chains: Option<Vec<ChainConfig>>,
        _logger: Arc<StatsDisplay>,
        config: Arc<RouterConfig>,
        auth: Arc<dyn AuthBackend>,
    ) -> Self {
        Self {
            proxy: Arc::new(ArcSwap::from_pointee(proxy)),
            chains: Arc::new(chains),
            config,
            auth,
        }
    }

    /// Replace the live upstream set with `static_upstreams` followed by
    /// `dynamic`. Concurrent connections keep using the previous snapshot until
    /// they finish (lock-free via arc-swap).
    pub fn replace_upstreams(&self, static_upstreams: &[ProxyConfig], dynamic: Vec<ProxyConfig>) {
        let mut merged = static_upstreams.to_vec();
        merged.extend(dynamic);
        self.proxy.store(Arc::new(merged));
    }

    /// Resolve the upstream chain for a connection, honouring a routing
    /// [`Selection`] when it constrains location/ISP/type; otherwise the global
    /// `[router].chain`.
    fn resolve_proxy_chain(
        &self,
        selection: &crate::routing::Selection,
    ) -> Result<Vec<ProxyConfig>, ProxyError> {
        // An explicit `chain` selection names a `[[proxy]]` label or `[[chain]]`
        // id directly and takes precedence over the tag dimensions.
        if let Some(name) = &selection.chain {
            return self.resolve_ref(name);
        }
        if !selection.only_session() {
            // Filter upstreams by the selection's tags, then pick (sticky/rotate).
            let proxies = self.proxy.load();
            let candidates: Vec<ProxyConfig> = proxies
                .iter()
                .filter(|p| selection.matches(&p.tags))
                .cloned()
                .collect();
            let idx = crate::routing::pick_index(candidates.len(), selection.session.as_deref())
                .ok_or(ProxyError::NoMatchingUpstream)?;
            return Ok(vec![candidates[idx].clone()]);
        }
        self.resolve_global_chain()
    }

    /// The original global resolution: a single `[[proxy]]` by label or a
    /// `[[chain]]` by id, used when no location/ISP selection is given.
    fn resolve_global_chain(&self) -> Result<Vec<ProxyConfig>, ProxyError> {
        // If router.chain names a proxy/chain, resolve it; else fall back to the
        // first configured proxy (backward compatibility).
        if let Some(chain_ref) = &self.config.chain {
            return self.resolve_ref(chain_ref);
        }
        let proxies = self.proxy.load();
        let proxy = proxies
            .first()
            .ok_or_else(|| ProxyError::Protocol("No proxy configuration available".to_string()))?
            .clone();
        Ok(vec![proxy])
    }

    /// Resolve a name to an upstream path: a single `[[proxy]]` by label, else a
    /// `[[chain]]` by id (applying its `ChainMode`). Errors if neither matches.
    /// Shared by the global default and explicit `chain` selections.
    fn resolve_ref(&self, name: &str) -> Result<Vec<ProxyConfig>, ProxyError> {
        let proxies = self.proxy.load();
        // First, try a single proxy by label.
        if let Some(proxy) = proxies.iter().find(|p| p.label.as_deref() == Some(name)) {
            return Ok(vec![proxy.clone()]);
        }

        // Otherwise, look for a chain by id.
        if let Some(chains) = self.chains.as_ref() {
            if let Some(chain) = chains.iter().find(|c| c.chain_id == name) {
                // Collect the chain's proxies by label.
                let mut proxy_configs = Vec::new();
                for label in &chain.proxies {
                    let proxy = proxies
                        .iter()
                        .find(|p| p.label.as_deref() == Some(label))
                        .ok_or_else(|| {
                            ProxyError::Protocol(format!(
                                "Proxy '{}' not found in chain '{}'",
                                label, name
                            ))
                        })?
                        .clone();
                    proxy_configs.push(proxy);
                }

                // Apply chain mode.
                use crate::config::ChainMode;
                let result = match chain.mode {
                    ChainMode::Strict => proxy_configs,
                    ChainMode::Random => {
                        use rand::seq::SliceRandom;
                        let mut rng = rand::rng();
                        if let Some(count) = chain.count {
                            let count = count.min(proxy_configs.len());
                            proxy_configs.shuffle(&mut rng);
                            proxy_configs.truncate(count);
                            proxy_configs
                        } else {
                            proxy_configs.shuffle(&mut rng);
                            vec![proxy_configs.into_iter().next().unwrap()]
                        }
                    }
                };
                return Ok(result);
            }
        }

        Err(ProxyError::Protocol(format!(
            "Chain or proxy '{}' not found",
            name
        )))
    }

    /// Handle a SOCKS5 connection: greeting + auth (extracting any routing
    /// selection from the username), then resolve the upstream by that selection
    /// and tunnel through it (single- or multi-hop) via `ChainConnector`.
    async fn handle_socks5(
        &self,
        mut client: TcpStream,
        initial_request: Vec<u8>,
        peer_addr: SocketAddr,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();
        let mut selection = crate::routing::Selection::default();

        // Parse SOCKS5 greeting (already received in initial_request)
        stats.add_bytes_in(as_u64(initial_request.len()));

        if initial_request.len() < 3 {
            return Err(ProxyError::Protocol(
                "Invalid SOCKS5 greeting length".into(),
            ));
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
            stats.add_bytes_in(as_u64(auth_len));

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

            // Authenticate with the base username; keep the routing selection.
            let (username, sel) =
                crate::routing::parse_username(&username).map_err(|_| ProxyError::AuthFailed)?;
            selection = sel;
            let account = self
                .auth
                .authenticate(&username, &password)
                .await
                .map_err(|_| ProxyError::AuthFailed)?
                .ok_or(ProxyError::AuthFailed)?;

            check_bandwidth(account.bandwidth_limit, &username, &self.config)?;
            user_account = Some(account.id);

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
                stats.add_bytes_in(as_u64(domain_len) + 2);
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

        // No token selection: fall back to the account's stored default (by IP).
        if selection.is_empty() {
            if let Ok(Some(account)) = self.auth.authenticate_by_ip(peer_addr.ip()).await {
                if let Some(def) = account.default_selection {
                    if let Ok((_base, sel)) = crate::routing::parse_username(&def) {
                        selection = sel;
                    }
                }
            }
        }

        // Resolve the upstream by the selection (single- or multi-hop), then tunnel.
        let proxy_chain = self.resolve_proxy_chain(&selection)?;
        let cost_per_byte = proxy_chain.first().map(|p| p.cost_per_byte).unwrap_or(1.0);
        metrics::histogram!("purroute_chain_hops").record(proxy_chain.len() as f64);
        let upstream =
            ChainConnector::connect_chain(&proxy_chain, &target_host, target_port).await?;

        // Send success response to client
        let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        client.write_all(&response).await?;
        stats.add_bytes_out(as_u64(response.len()));

        global_stats.record_connection_result(
            true,
            format!("SOCKS5 Chain Connection successful for {}", peer_addr),
            &self.config,
        );

        // Relay data between client and upstream
        self.proxy_data(
            client,
            upstream,
            peer_addr,
            global_stats,
            user_account,
            cost_per_byte,
        )
        .await
    }

    /// Multi-hop SOCKS4/4a: parse the inbound CONNECT request, tunnel through
    /// the chain, then relay.
    async fn handle_socks4_chain(
        &self,
        mut client: TcpStream,
        initial_request: Vec<u8>,
        proxy_chain: Vec<ProxyConfig>,
        peer_addr: SocketAddr,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();
        stats.add_bytes_in(as_u64(initial_request.len()));

        let user_account = self.authenticate_user(&initial_request, peer_addr).await?;
        let (target_host, target_port) = parse_socks4_target(&initial_request)?;
        let cost_per_byte = proxy_chain.first().map(|p| p.cost_per_byte).unwrap_or(1.0);

        let upstream =
            ChainConnector::connect_chain(&proxy_chain, &target_host, target_port).await?;

        // SOCKS4 success reply: VN=0x00, CD=0x5A (granted), 6 bytes ignored.
        let response = [0x00, 0x5A, 0, 0, 0, 0, 0, 0];
        client.write_all(&response).await?;
        stats.add_bytes_out(as_u64(response.len()));

        global_stats.record_connection_result(
            true,
            format!("SOCKS4 chain connection successful for {peer_addr}"),
            &self.config,
        );
        self.proxy_data(
            client,
            upstream,
            peer_addr,
            global_stats,
            user_account,
            cost_per_byte,
        )
        .await
    }

    /// Multi-hop HTTPS (CONNECT) tunnel through the chain.
    async fn handle_https_chain(
        &self,
        mut client: TcpStream,
        initial_request: Vec<u8>,
        proxy_chain: Vec<ProxyConfig>,
        peer_addr: SocketAddr,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();
        stats.add_bytes_in(as_u64(initial_request.len()));

        let user_account = self.authenticate_user(&initial_request, peer_addr).await?;
        let (target_host, target_port) = parse_connect_target(&initial_request)?;
        let cost_per_byte = proxy_chain.first().map(|p| p.cost_per_byte).unwrap_or(1.0);

        let upstream =
            ChainConnector::connect_chain(&proxy_chain, &target_host, target_port).await?;

        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        client.write_all(response).await?;
        stats.add_bytes_out(as_u64(response.len()));

        global_stats.record_connection_result(
            true,
            format!("HTTPS chain connection successful for {peer_addr}"),
            &self.config,
        );
        self.proxy_data(
            client,
            upstream,
            peer_addr,
            global_stats,
            user_account,
            cost_per_byte,
        )
        .await
    }

    /// Multi-hop plain HTTP: tunnel to the origin through the chain, then
    /// forward the buffered request line + headers.
    async fn handle_http_chain(
        &self,
        client: TcpStream,
        initial_request: Vec<u8>,
        proxy_chain: Vec<ProxyConfig>,
        peer_addr: SocketAddr,
        global_stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();
        stats.add_bytes_in(as_u64(initial_request.len()));

        let user_account = self.authenticate_user(&initial_request, peer_addr).await?;
        let (target_host, target_port) = parse_http_target(&initial_request)?;
        let cost_per_byte = proxy_chain.first().map(|p| p.cost_per_byte).unwrap_or(1.0);

        let mut upstream =
            ChainConnector::connect_chain(&proxy_chain, &target_host, target_port).await?;

        // Forward the request to the origin server through the chain, rewriting
        // the absolute-form request line to origin-form so strict origins accept it.
        let forwarded = to_origin_form(&initial_request);
        upstream.write_all(&forwarded).await?;
        upstream.flush().await?;
        stats.add_bytes_out(as_u64(forwarded.len()));

        global_stats.record_connection_result(
            true,
            format!("HTTP chain connection successful for {peer_addr}"),
            &self.config,
        );
        self.proxy_data(
            client,
            upstream,
            peer_addr,
            global_stats,
            user_account,
            cost_per_byte,
        )
        .await
    }

    pub async fn run(&self, addr: SocketAddr) -> Result<(), ProxyError> {
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
            let label = server
                .proxy
                .load()
                .first()
                .and_then(|config| config.label.clone());
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
                // Bound the initial handshake read so stalled clients can't pin a task.
                let n =
                    tokio::time::timeout(std::time::Duration::from_secs(30), client.read(&mut buf))
                        .await
                        .map_err(|_| ProxyError::Timeout)??;
                let initial_request = buf[..n].to_vec();

                let protocol = server.detect_protocol(&initial_request)?;
                metrics::counter!(
                    "purroute_connections_total",
                    "protocol" => protocol.as_str(),
                )
                .increment(1);
                global_stats.log_info(
                    format!("Protocol {:?} detected from {}", protocol, peer_addr),
                    &server.config,
                );

                // Parse any location/ISP selection from the proxy username and
                // resolve the upstream accordingly (SOCKS5 carries its username
                // in a later handshake step, so its selection is empty here).
                let selection = server
                    .selection_for(&protocol, &initial_request, peer_addr)
                    .await;
                let proxy_chain = server.resolve_proxy_chain(&selection)?;
                let target_proxy = &proxy_chain[0];

                metrics::histogram!("purroute_chain_hops").record(proxy_chain.len() as f64);

                if proxy_chain.len() > 1 {
                    let chain_desc: Vec<String> =
                        proxy_chain.iter().filter_map(|p| p.label.clone()).collect();
                    global_stats.log_info(
                        format!(
                            "Using chain: {} ({} hops)",
                            chain_desc.join(" -> "),
                            proxy_chain.len()
                        ),
                        &server.config,
                    );
                } else if let Some(label) = &label {
                    global_stats.log_info(
                        format!("Using proxy '{}' for connection from {}", label, peer_addr),
                        &server.config,
                    );
                }

                // Multi-hop chains are handled by a protocol-agnostic path that
                // performs the inbound handshake, tunnels through every hop via
                // `ChainConnector`, then relays. Single-hop keeps the existing
                // per-protocol translation handlers.
                let multi_hop = proxy_chain.len() > 1;
                let cost_per_byte = proxy_chain.first().map(|p| p.cost_per_byte).unwrap_or(1.0);

                match protocol {
                    // SOCKS5 resolves its own upstream after auth (its username,
                    // and any routing tokens, arrive in the auth sub-negotiation).
                    Proxy::Socks5 => {
                        server
                            .handle_socks5(client, initial_request, peer_addr, global_stats.clone())
                            .await
                    }
                    Proxy::Socks4 if multi_hop => {
                        server
                            .handle_socks4_chain(
                                client,
                                initial_request,
                                proxy_chain,
                                peer_addr,
                                global_stats.clone(),
                            )
                            .await
                    }
                    Proxy::Https if multi_hop => {
                        server
                            .handle_https_chain(
                                client,
                                initial_request,
                                proxy_chain,
                                peer_addr,
                                global_stats.clone(),
                            )
                            .await
                    }
                    Proxy::Http if multi_hop => {
                        server
                            .handle_http_chain(
                                client,
                                initial_request,
                                proxy_chain,
                                peer_addr,
                                global_stats.clone(),
                            )
                            .await
                    }
                    Proxy::Socks4 => {
                        let user_account = server
                            .authenticate_user(&initial_request, peer_addr)
                            .await?;

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
                                        .proxy_data(
                                            client,
                                            upstream,
                                            peer,
                                            stats,
                                            user_account,
                                            cost_per_byte,
                                        )
                                        .await
                                })
                            },
                        )
                        .await
                    }
                    Proxy::Http => {
                        let user_account = server
                            .authenticate_user(&initial_request, peer_addr)
                            .await?;

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
                                        .proxy_data(
                                            client,
                                            upstream,
                                            peer,
                                            stats,
                                            user_account,
                                            cost_per_byte,
                                        )
                                        .await
                                })
                            },
                        )
                        .await
                    }
                    Proxy::Https => {
                        let user_account = server
                            .authenticate_user(&initial_request, peer_addr)
                            .await?;

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
                                        .proxy_data(
                                            client,
                                            upstream,
                                            peer,
                                            stats,
                                            user_account,
                                            cost_per_byte,
                                        )
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

    /// Determine the routing [`Selection`](crate::routing::Selection) for a
    /// connection: from the proxy username's tokens, else from the account's
    /// stored default (looked up by source IP for credential-less connections).
    /// SOCKS5 sends its username in a later step, so its token-selection is empty
    /// here (global routing).
    async fn selection_for(
        &self,
        protocol: &Proxy,
        request: &[u8],
        peer: SocketAddr,
    ) -> crate::routing::Selection {
        let username = match protocol {
            Proxy::Http | Proxy::Https => http_proxy_username(request),
            Proxy::Socks4 => socks4_userid(request),
            Proxy::Socks5 => None,
        };
        let from_tokens = username
            .and_then(|u| crate::routing::parse_username(&u).ok())
            .map(|(_base, sel)| sel)
            .unwrap_or_default();
        if !from_tokens.is_empty() {
            return from_tokens;
        }
        // No tokens: fall back to the account's stored default, found by IP.
        if let Ok(Some(account)) = self.auth.authenticate_by_ip(peer.ip()).await {
            if let Some(def) = account.default_selection {
                if let Ok((_base, sel)) = crate::routing::parse_username(&def) {
                    return sel;
                }
            }
        }
        from_tokens
    }

    pub fn detect_protocol(&self, request: &[u8]) -> Result<Proxy, ProxyError> {
        if request.is_empty() {
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

    pub async fn authenticate_user(
        &self,
        request: &[u8],
        peer: SocketAddr,
    ) -> Result<Option<i64>, ProxyError> {
        if let Some(auth) = self.config.auth {
            if auth {
                let request_str = String::from_utf8_lossy(request);
                let auth_header = request_str.lines().find(|line| {
                    line.to_lowercase()
                        .starts_with("proxy-authorization: basic ")
                });
                // No credentials: authorise by source IP if allowed.
                let Some(auth_header) = auth_header else {
                    let account = self
                        .auth
                        .authenticate_by_ip(peer.ip())
                        .await
                        .map_err(|_| ProxyError::AuthFailed)?
                        .ok_or(ProxyError::AuthFailed)?;
                    check_bandwidth(account.bandwidth_limit, "<ip>", &self.config)?;
                    return Ok(Some(account.id));
                };

                let encoded_credentials = auth_header[27..].trim();
                let decoded_credentials = base64::engine::general_purpose::STANDARD
                    .decode(encoded_credentials)
                    .map_err(|_| ProxyError::AuthFailed)?;
                let credentials =
                    String::from_utf8(decoded_credentials).map_err(|_| ProxyError::AuthFailed)?;
                let mut parts = credentials.split(':');
                let raw_username = parts.next().ok_or(ProxyError::AuthFailed)?;
                let password = parts.next().ok_or(ProxyError::AuthFailed)?;

                // Authenticate with the *base* username; routing tokens (e.g.
                // `-country-us`) are stripped off and used for upstream selection.
                let (username, _selection) = crate::routing::parse_username(raw_username)
                    .map_err(|_| ProxyError::AuthFailed)?;

                let account = self
                    .auth
                    .authenticate(&username, password)
                    .await
                    .map_err(|_| ProxyError::AuthFailed)?
                    .ok_or(ProxyError::AuthFailed)?;

                check_bandwidth(account.bandwidth_limit, &username, &self.config)?;
                return Ok(Some(account.id));
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
        cost_per_byte: f64,
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
                        stats.add_bytes_out(as_u64(n));
                        metrics::counter!("purroute_bytes_out_total").increment(as_u64(n));
                        if let Some(id) = id {
                            let remaining = self
                                .auth
                                .report_usage(id, 0, as_u64(n), cost_per_byte)
                                .await
                                .map_err(auth_io_error)?;
                            // Mid-stream cut-off: stop once the allowance is spent,
                            // bounding overage to the chunk already in flight.
                            if matches!(remaining, Some(r) if r <= 0) {
                                break Err(ProxyError::BandwidthExceeded);
                            }
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
                        stats.add_bytes_in(as_u64(n));
                        metrics::counter!("purroute_bytes_in_total").increment(as_u64(n));
                        if let Some(id) = id {
                            let remaining = self
                                .auth
                                .report_usage(id, as_u64(n), 0, cost_per_byte)
                                .await
                                .map_err(auth_io_error)?;
                            // Mid-stream cut-off: stop once the allowance is spent,
                            // bounding overage to the chunk already in flight.
                            if matches!(remaining, Some(r) if r <= 0) {
                                break Err(ProxyError::BandwidthExceeded);
                            }
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
}

/// Widen a buffer length to `u64` for byte counters (lengths never exceed u64).
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Map an auth-backend error into a [`ProxyError`] without panicking.
fn auth_io_error(e: crate::auth::AuthError) -> ProxyError {
    ProxyError::Io(std::io::Error::other(e.to_string()))
}

/// Enforce a (possibly absent) bandwidth limit. `None` ⇒ no limit configured;
/// `Some(n)` with `n <= 0` ⇒ the user is out of traffic.
fn check_bandwidth(
    limit: Option<i64>,
    username: &str,
    config: &RouterConfig,
) -> Result<(), ProxyError> {
    if let Some(limit) = limit {
        if limit <= 0 {
            get_global_stats().log_info(
                format!("User {username} has no bandwidth remaining ({limit})"),
                config,
            );
            return Err(ProxyError::BandwidthExceeded);
        }
    }
    Ok(())
}

/// Rewrite a buffered plain-HTTP proxy request so its request line is in
/// origin-form (`GET /path HTTP/1.1`) instead of the absolute-form
/// (`GET http://host/path HTTP/1.1`) a proxy receives. Headers are left intact.
///
/// If the request line is already origin-form (or can't be parsed), the input is
/// returned unchanged.
fn to_origin_form(request: &[u8]) -> Vec<u8> {
    // Only touch bytes up to the end of the first line; forward the rest verbatim
    // so we never corrupt a request body.
    let line_end = match request.windows(2).position(|w| w == b"\r\n") {
        Some(idx) => idx,
        None => return request.to_vec(),
    };
    let first_line = match std::str::from_utf8(&request[..line_end]) {
        Ok(line) => line,
        Err(_) => return request.to_vec(),
    };

    let mut parts = first_line.splitn(3, ' ');
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return request.to_vec();
    };

    let stripped = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"));
    let Some(rest) = stripped else {
        return request.to_vec(); // already origin-form
    };

    // Drop the authority; keep the absolute path (everything from the first '/').
    let path = match rest.find('/') {
        Some(idx) => &rest[idx..],
        None => "/",
    };

    let mut out = format!("{method} {path} {version}").into_bytes();
    out.extend_from_slice(&request[line_end..]);
    out
}

/// Split an `authority` (`host` or `host:port`) into host and port, using
/// `default_port` when none is present.
fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), ProxyError> {
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| ProxyError::Protocol("invalid port".into()))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// Extract the username from an HTTP `Proxy-Authorization: Basic` header.
fn http_proxy_username(request: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(request);
    let line = text
        .lines()
        .find(|l| l.to_lowercase().starts_with("proxy-authorization: basic "))?;
    let encoded = line[27..].trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    creds.split(':').next().map(str::to_owned)
}

/// Extract the user-id field from a SOCKS4/4a request.
fn socks4_userid(request: &[u8]) -> Option<String> {
    if request.len() < 9 || request[0] != 0x04 {
        return None;
    }
    let end = request[8..].iter().position(|&b| b == 0)? + 8;
    (end > 8).then(|| String::from_utf8_lossy(&request[8..end]).into_owned())
}

/// Parse the target `host:port` from an HTTP `CONNECT` request line.
fn parse_connect_target(request: &[u8]) -> Result<(String, u16), ProxyError> {
    let text = String::from_utf8_lossy(request);
    let first = text
        .lines()
        .next()
        .ok_or_else(|| ProxyError::Protocol("empty CONNECT request".into()))?;
    let target = first
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ProxyError::Protocol("malformed CONNECT line".into()))?;
    split_host_port(target, 443)
}

/// Parse the origin `host:port` from a plain HTTP proxy request (absolute-form
/// URI in the request line, falling back to the `Host` header).
fn parse_http_target(request: &[u8]) -> Result<(String, u16), ProxyError> {
    let text = String::from_utf8_lossy(request);
    let first = text
        .lines()
        .next()
        .ok_or_else(|| ProxyError::Protocol("empty HTTP request".into()))?;

    if let Some(uri) = first.split_whitespace().nth(1) {
        let stripped = uri
            .strip_prefix("http://")
            .or_else(|| uri.strip_prefix("https://"));
        if let Some(rest) = stripped {
            let authority = rest.split('/').next().unwrap_or(rest);
            if !authority.is_empty() {
                return split_host_port(authority, 80);
            }
        }
    }

    for line in text.lines() {
        let header = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"));
        if let Some(value) = header {
            return split_host_port(value.trim(), 80);
        }
    }
    Err(ProxyError::Protocol(
        "no target host in HTTP request".into(),
    ))
}

/// Parse the target `host:port` from a SOCKS4 or SOCKS4a CONNECT request.
fn parse_socks4_target(request: &[u8]) -> Result<(String, u16), ProxyError> {
    if request.len() < 9 || request[0] != 0x04 {
        return Err(ProxyError::Protocol("invalid SOCKS4 request".into()));
    }
    let port = u16::from_be_bytes([request[2], request[3]]);
    let ip = [request[4], request[5], request[6], request[7]];
    // SOCKS4a: 0.0.0.x (x != 0) signals a domain name follows the user id.
    let is_4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;

    // Skip the null-terminated user id starting at offset 8.
    let mut idx = 8;
    while idx < request.len() && request[idx] != 0 {
        idx += 1;
    }
    if idx >= request.len() {
        return Err(ProxyError::Protocol("unterminated SOCKS4 user id".into()));
    }
    idx += 1; // skip the null terminator

    if is_4a {
        let start = idx;
        while idx < request.len() && request[idx] != 0 {
            idx += 1;
        }
        let host = String::from_utf8_lossy(&request[start..idx]).to_string();
        Ok((host, port))
    } else {
        let host = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        Ok((host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_with_port() {
        assert_eq!(
            split_host_port("example.com:8443", 80).unwrap(),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn split_host_port_default() {
        assert_eq!(
            split_host_port("example.com", 80).unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn split_host_port_rejects_bad_port() {
        assert!(split_host_port("example.com:notaport", 80).is_err());
    }

    #[test]
    fn connect_target_parses_host_port() {
        let req =
            b"CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n";
        assert_eq!(
            parse_connect_target(req).unwrap(),
            ("secure.example.com".to_string(), 443)
        );
    }

    #[test]
    fn http_target_from_absolute_uri() {
        let req = b"GET http://example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(
            parse_http_target(req).unwrap(),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn http_target_from_host_header() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            parse_http_target(req).unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn socks4a_target_parses_domain() {
        // VN=4 CD=1 PORT=80 IP=0.0.0.1 USERID="" 0x00 DOMAIN 0x00
        let mut req = vec![0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00];
        req.extend_from_slice(b"example.com");
        req.push(0x00);
        assert_eq!(
            parse_socks4_target(&req).unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn origin_form_rewrites_absolute_uri() {
        let req =
            b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let out = to_origin_form(req);
        assert_eq!(
            out,
            b"GET /path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn origin_form_handles_authority_only() {
        let req = b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = to_origin_form(req);
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
    }

    #[test]
    fn origin_form_leaves_origin_form_unchanged() {
        let req = b"GET /already/origin HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = to_origin_form(req);
        assert_eq!(out, req.to_vec());
    }

    #[test]
    fn origin_form_preserves_body_bytes() {
        let req = b"POST http://h/x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
        let out = to_origin_form(req);
        assert_eq!(
            out,
            b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc".to_vec()
        );
    }

    #[test]
    fn socks4_target_parses_ipv4() {
        // VN=4 CD=1 PORT=443 IP=93.184.216.34 USERID="" 0x00
        let req = vec![0x04, 0x01, 0x01, 0xBB, 93, 184, 216, 34, 0x00];
        assert_eq!(
            parse_socks4_target(&req).unwrap(),
            ("93.184.216.34".to_string(), 443)
        );
    }
}

#[cfg(test)]
mod loopback {
    //! Hermetic, in-process integration tests. Each test stands up a fake
    //! upstream proxy on loopback, runs a real [`ProxyServer`] over an accepted
    //! TCP socket, and drives a client through the full handshake — no
    //! containers, no network. Exercises the protocol handlers, routing
    //! selection, auth and the relay path end to end.
    use super::*;
    use crate::auth::StaticAuthBackend;
    use crate::config::{Tags, UserConfig};
    use std::time::Duration;

    const BODY: &str = "Test Page";

    fn proxy(label: &str, kind: Proxy, addr: SocketAddr, tags: Tags) -> ProxyConfig {
        ProxyConfig {
            label: Some(label.to_owned()),
            proxy_type: kind,
            address: addr.ip().to_string(),
            port: Some(addr.port()),
            username: None,
            password: None,
            tags,
            cost_per_byte: 1.0,
        }
    }

    fn user(name: &str, pass: &str) -> UserConfig {
        UserConfig {
            username: name.to_owned(),
            password: pass.to_owned(),
            bandwidth_limit: None,
            allowed_ips: Vec::new(),
            default_selection: None,
        }
    }

    fn user_limited(name: &str, pass: &str, limit: i64) -> UserConfig {
        UserConfig {
            username: name.to_owned(),
            password: pass.to_owned(),
            bandwidth_limit: Some(limit),
            allowed_ips: Vec::new(),
            default_selection: None,
        }
    }

    fn router_cfg(chain: Option<&str>, auth: bool) -> Arc<RouterConfig> {
        Arc::new(RouterConfig {
            listen: "127.0.0.1:0".into(),
            chain: chain.map(str::to_owned),
            log: Some(false),
            verbose: Some(false),
            debug: Some(false),
            auth: Some(auth),
            metrics_listen: None,
            upstream_refresh_secs: None,
        })
    }

    fn build(
        proxies: Vec<ProxyConfig>,
        chains: Option<Vec<ChainConfig>>,
        chain: Option<&str>,
        users: Vec<UserConfig>,
    ) -> ProxyServer {
        let auth = Arc::new(StaticAuthBackend::new(&users).unwrap());
        let display = Arc::new(StatsDisplay::new(
            get_global_stats(),
            Duration::from_secs(60),
            None,
        ));
        ProxyServer::new(
            proxies,
            chains,
            display,
            router_cfg(chain, !users.is_empty()),
            auth,
        )
    }

    fn sel_chain(name: &str) -> crate::routing::Selection {
        crate::routing::Selection {
            chain: Some(name.to_owned()),
            ..Default::default()
        }
    }

    fn dummy(label: &str) -> ProxyConfig {
        proxy(
            label,
            Proxy::Socks5,
            "127.0.0.1:1".parse().unwrap(),
            Tags::default(),
        )
    }

    #[test]
    fn replace_upstreams_swaps_the_live_set() {
        let srv = build(vec![dummy("static-a")], None, None, vec![]);
        // Initially only the static upstream resolves.
        assert!(srv.resolve_proxy_chain(&sel_chain("static-a")).is_ok());
        assert!(srv.resolve_proxy_chain(&sel_chain("dyn-b")).is_err());
        // Swap in a dynamic upstream alongside the static one.
        srv.replace_upstreams(&[dummy("static-a")], vec![dummy("dyn-b")]);
        assert!(srv.resolve_proxy_chain(&sel_chain("static-a")).is_ok());
        assert!(srv.resolve_proxy_chain(&sel_chain("dyn-b")).is_ok());
    }

    #[test]
    fn chain_selection_resolves_a_proxy_label() {
        let srv = build(vec![dummy("a"), dummy("b")], None, None, vec![]);
        let got = srv.resolve_proxy_chain(&sel_chain("b")).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].label.as_deref(), Some("b"));
    }

    #[test]
    fn chain_selection_resolves_a_chain_id_in_order() {
        let chains = vec![ChainConfig {
            chain_id: "circuit".into(),
            proxies: vec!["a".into(), "b".into()],
            mode: crate::config::ChainMode::Strict,
            count: None,
        }];
        let srv = build(vec![dummy("a"), dummy("b")], Some(chains), None, vec![]);
        let got = srv.resolve_proxy_chain(&sel_chain("circuit")).unwrap();
        assert_eq!(
            got.iter()
                .map(|p| p.label.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn chain_selection_random_picks_count() {
        let chains = vec![ChainConfig {
            chain_id: "rnd".into(),
            proxies: vec!["a".into(), "b".into(), "c".into()],
            mode: crate::config::ChainMode::Random,
            count: Some(2),
        }];
        let srv = build(
            vec![dummy("a"), dummy("b"), dummy("c")],
            Some(chains),
            None,
            vec![],
        );
        let got = srv.resolve_proxy_chain(&sel_chain("rnd")).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn chain_selection_unknown_name_errors() {
        let srv = build(vec![dummy("a")], None, None, vec![]);
        assert!(srv.resolve_proxy_chain(&sel_chain("nope")).is_err());
    }

    /// Bind the router and serve exactly one accepted connection.
    async fn serve_once(srv: ProxyServer) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                let _ = srv.handle_connection(stream, peer, None).await;
            }
        });
        addr
    }

    /// Fake HTTP upstream proxy: read the forwarded request, reply with `body`.
    async fn fake_http_upstream(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        addr
    }

    /// Fake SOCKS5 upstream proxy: no-auth handshake, accept CONNECT, reply
    /// success, then serve an HTTP `body` as the origin.
    async fn fake_socks5_upstream(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                // greeting
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; g[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap(); // no-auth
                                                           // CONNECT request header
                let mut h = [0u8; 4];
                s.read_exact(&mut h).await.unwrap();
                match h[3] {
                    0x01 => {
                        let mut a = [0u8; 6];
                        s.read_exact(&mut a).await.unwrap();
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        s.read_exact(&mut l).await.unwrap();
                        let mut d = vec![0u8; l[0] as usize + 2];
                        s.read_exact(&mut d).await.unwrap();
                    }
                    _ => {}
                }
                // success reply, bound 0.0.0.0:0
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                // read tunnelled request, answer as origin
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        addr
    }

    /// Fake SOCKS4 upstream proxy: accept CONNECT, grant, then serve `body`.
    async fn fake_socks4_upstream(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                // VN CD PORT(2) IP(4) then userid\0 [domain\0]
                let mut head = [0u8; 8];
                s.read_exact(&mut head).await.unwrap();
                // consume userid until null
                let mut b = [0u8; 1];
                loop {
                    s.read_exact(&mut b).await.unwrap();
                    if b[0] == 0 {
                        break;
                    }
                }
                // socks4a domain (IP 0.0.0.x): consume domain until null
                if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
                    loop {
                        s.read_exact(&mut b).await.unwrap();
                        if b[0] == 0 {
                            break;
                        }
                    }
                }
                // granted: VN=0 CD=0x5A + 6 bytes
                s.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        addr
    }

    /// Fake HTTP upstream that honours a CONNECT tunnel: it replies
    /// `200 Connection Established`, then serves `body` over the tunnel.
    async fn fake_connect_upstream(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await; // CONNECT host:port ...
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = s.read(&mut buf).await; // tunnelled client request
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        addr
    }

    fn basic(creds: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(creds)
    }

    async fn read_body(s: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_secs(2), s.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(BODY.len()).any(|w| w == BODY.as_bytes())
                        || String::from_utf8_lossy(&buf).contains("EXIT")
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn http_inbound_through_http_upstream() {
        let up = fake_http_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Http, up, Tags::default())],
            None,
            Some("up"),
            vec![],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn socks5_inbound_through_socks5_upstream_with_auth() {
        let up = fake_socks5_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Socks5, up, Tags::default())],
            None,
            Some("up"),
            vec![user("me", "pw")],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // greeting: offer user/pass
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x02]);
        // auth
        c.write_all(&[0x01, 2, b'm', b'e', 2, b'p', b'w'])
            .await
            .unwrap();
        let mut ar = [0u8; 2];
        c.read_exact(&mut ar).await.unwrap();
        assert_eq!(ar, [0x01, 0x00]);
        // CONNECT example.com:80
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn socks5_inbound_rejects_bad_password() {
        let up = fake_socks5_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Socks5, up, Tags::default())],
            None,
            Some("up"),
            vec![user("me", "right")],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        c.write_all(&[0x01, 2, b'm', b'e', 5, b'w', b'r', b'o', b'n', b'g'])
            .await
            .unwrap();
        // server drops the connection on auth failure
        let mut ar = [0u8; 2];
        let r = c.read_exact(&mut ar).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn relay_stops_when_bandwidth_is_exhausted() {
        // A tiny allowance is spent on the first relayed chunk, so the request
        // never reaches the upstream and the body never comes back: the
        // connection is cut mid-stream rather than draining far past zero.
        let up = fake_socks5_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Socks5, up, Tags::default())],
            None,
            Some("up"),
            vec![user_limited("me", "pw", 5)],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        c.write_all(&[0x01, 2, b'm', b'e', 2, b'p', b'w'])
            .await
            .unwrap();
        let mut ar = [0u8; 2];
        c.read_exact(&mut ar).await.unwrap();
        assert_eq!(ar, [0x01, 0x00]);
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00); // CONNECT succeeded before the cut-off
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        // Allowance exhausted: the proxied body must not come through.
        assert!(!read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn metering_scales_by_upstream_cost() {
        // Upstream costs 1000 value-units/byte, so even a tiny transfer blows a
        // small allowance: the body must not come through.
        let up = fake_socks5_upstream(BODY).await;
        let mut p = proxy("up", Proxy::Socks5, up, Tags::default());
        p.cost_per_byte = 1000.0;
        let srv = build(
            vec![p],
            None,
            Some("up"),
            vec![user_limited("me", "pw", 50)],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        c.write_all(&[0x01, 2, b'm', b'e', 2, b'p', b'w'])
            .await
            .unwrap();
        let mut ar = [0u8; 2];
        c.read_exact(&mut ar).await.unwrap();
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(!read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn socks4_inbound_through_socks4_upstream() {
        let up = fake_socks4_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Socks4, up, Tags::default())],
            None,
            Some("up"),
            vec![],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // SOCKS4a CONNECT example.com:80, empty userid, domain
        let mut req = vec![0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00];
        req.extend_from_slice(b"example.com");
        req.push(0x00);
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 8];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x5A);
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn routing_token_selects_tagged_upstream() {
        let us = fake_http_upstream("US-EXIT").await;
        let de = fake_http_upstream("DE-EXIT").await;
        let tag = |cc: &str| Tags {
            country: Some(cc.to_owned()),
            ..Default::default()
        };
        let srv = build(
            vec![
                proxy("us", Proxy::Http, us, tag("us")),
                proxy("de", Proxy::Http, de, tag("de")),
            ],
            None,
            None,
            vec![user("me", "pw")],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        let auth = basic("me-country-de:pw");
        let reqs = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {}\r\n\r\n",
            auth
        );
        c.write_all(reqs.as_bytes()).await.unwrap();
        assert!(read_body(&mut c).await.contains("DE-EXIT"));
    }

    #[tokio::test]
    async fn routing_no_match_is_rejected() {
        let us = fake_http_upstream("US-EXIT").await;
        let srv = build(
            vec![proxy(
                "us",
                Proxy::Http,
                us,
                Tags {
                    country: Some("us".to_owned()),
                    ..Default::default()
                },
            )],
            None,
            None,
            vec![user("me", "pw")],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        let auth = basic("me-country-fr:pw");
        let reqs = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {}\r\n\r\n",
            auth
        );
        c.write_all(reqs.as_bytes()).await.unwrap();
        // no matching upstream -> connection closed with no body
        assert!(!read_body(&mut c).await.contains("EXIT"));
    }

    #[tokio::test]
    async fn https_connect_inbound_through_http_upstream() {
        let up = fake_connect_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Http, up, Tags::default())],
            None,
            Some("up"),
            vec![],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        // router replies 200 Connection Established, then tunnels
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert!(String::from_utf8_lossy(&head).contains("200"));
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(read_body(&mut c).await.contains(BODY));
    }

    #[tokio::test]
    async fn http_inbound_through_socks4_upstream() {
        let up = fake_socks4_upstream(BODY).await;
        let srv = build(
            vec![proxy("up", Proxy::Socks4, up, Tags::default())],
            None,
            Some("up"),
            vec![],
        );
        let router = serve_once(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(read_body(&mut c).await.contains(BODY));
    }
}

#[cfg(test)]
mod proxy_cov2 {
    //! Coverage for multi-hop chain handlers over non-SOCKS5 inbound, IP-based
    //! auth/default-selection, bandwidth refusal, and protocol-detection /
    //! malformed-greeting error paths. Hermetic: loopback only, no sleeps >100ms.
    use super::*;
    use crate::auth::StaticAuthBackend;
    use crate::config::{ChainConfig, ChainMode, Tags, UserConfig};
    use std::time::Duration;

    const BODY2: &str = "Cov2OK";

    fn px(label: &str, kind: Proxy, addr: SocketAddr) -> ProxyConfig {
        ProxyConfig {
            label: Some(label.to_owned()),
            proxy_type: kind,
            address: addr.ip().to_string(),
            port: Some(addr.port()),
            username: None,
            password: None,
            tags: Tags::default(),
            cost_per_byte: 1.0,
        }
    }

    fn usr(name: &str, pass: &str) -> UserConfig {
        UserConfig {
            username: name.to_owned(),
            password: pass.to_owned(),
            bandwidth_limit: None,
            allowed_ips: Vec::new(),
            default_selection: None,
        }
    }

    fn rcfg(chain: Option<&str>, auth: bool) -> Arc<RouterConfig> {
        Arc::new(RouterConfig {
            listen: "127.0.0.1:0".into(),
            chain: chain.map(str::to_owned),
            log: Some(false),
            verbose: Some(false),
            debug: Some(false),
            auth: Some(auth),
            metrics_listen: None,
            upstream_refresh_secs: None,
        })
    }

    fn mk(
        proxies: Vec<ProxyConfig>,
        chains: Option<Vec<ChainConfig>>,
        chain: Option<&str>,
        users: Vec<UserConfig>,
        auth: bool,
    ) -> ProxyServer {
        let backend = Arc::new(StaticAuthBackend::new(&users).unwrap());
        let display = Arc::new(StatsDisplay::new(
            get_global_stats(),
            Duration::from_secs(60),
            None,
        ));
        ProxyServer::new(proxies, chains, display, rcfg(chain, auth), backend)
    }

    async fn serve1(srv: ProxyServer) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                let _ = srv.handle_connection(stream, peer, None).await;
            }
        });
        addr
    }

    async fn s5_greeting(s: &mut TcpStream) {
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        let mut m = vec![0u8; g[1] as usize];
        s.read_exact(&mut m).await.unwrap();
    }

    async fn s5_connect(s: &mut TcpStream) -> (String, u16) {
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
            _ => panic!("atyp"),
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        (host, u16::from_be_bytes(p))
    }

    /// Intermediate SOCKS5 hop: dial onward and splice.
    async fn s5_hop() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                s5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let (host, port) = s5_connect(&mut s).await;
                let up = TcpStream::connect((host.as_str(), port)).await.unwrap();
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let (mut cr, mut cw) = s.into_split();
                let (mut ur, mut uw) = up.into_split();
                let a = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut uw).await });
                let b = tokio::spawn(async move { tokio::io::copy(&mut ur, &mut cw).await });
                let _ = a.await;
                let _ = b.await;
            }
        });
        addr
    }

    /// Origin SOCKS5 proxy that answers the tunnelled HTTP request with BODY2.
    async fn s5_origin() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                s5_greeting(&mut s).await;
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let _ = s5_connect(&mut s).await;
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    BODY2.len(),
                    BODY2
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        addr
    }

    async fn drain(s: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_secs(2), s.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(BODY2.len()).any(|w| w == BODY2.as_bytes()) {
                        break;
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn two_hop_chain(hop: SocketAddr, origin: SocketAddr) -> (Vec<ProxyConfig>, Vec<ChainConfig>) {
        let proxies = vec![
            px("h1", Proxy::Socks5, hop),
            px("h2", Proxy::Socks5, origin),
        ];
        let chains = vec![ChainConfig {
            chain_id: "dbl".into(),
            proxies: vec!["h1".into(), "h2".into()],
            mode: ChainMode::Strict,
            count: None,
        }];
        (proxies, chains)
    }

    // ---- (1) MULTI-HOP for non-SOCKS5 inbound ---------------------------

    #[tokio::test]
    async fn http_inbound_multi_hop_chain() {
        let origin = s5_origin().await;
        let hop = s5_hop().await;
        let (proxies, chains) = two_hop_chain(hop, origin);
        let srv = mk(proxies, Some(chains), Some("dbl"), vec![], false);
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(drain(&mut c).await.contains(BODY2));
    }

    #[tokio::test]
    async fn https_connect_inbound_multi_hop_chain() {
        let origin = s5_origin().await;
        let hop = s5_hop().await;
        let (proxies, chains) = two_hop_chain(hop, origin);
        let srv = mk(proxies, Some(chains), Some("dbl"), vec![], false);
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert!(String::from_utf8_lossy(&head).contains("200"));
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(drain(&mut c).await.contains(BODY2));
    }

    #[tokio::test]
    async fn socks4_inbound_multi_hop_chain() {
        let origin = s5_origin().await;
        let hop = s5_hop().await;
        let (proxies, chains) = two_hop_chain(hop, origin);
        let srv = mk(proxies, Some(chains), Some("dbl"), vec![], false);
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        let mut req = vec![0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00];
        req.extend_from_slice(b"example.com");
        req.push(0x00);
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 8];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x5A);
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(drain(&mut c).await.contains(BODY2));
    }

    // ---- (2) IP AUTH path ----------------------------------------------

    /// HTTP inbound, auth on, NO Proxy-Authorization header: authorised by
    /// source IP (127.0.0.1/32), default_selection drives upstream by IP.
    #[tokio::test]
    async fn http_ip_auth_with_default_selection() {
        let us = {
            // fake HTTP origin that echoes IP-SEL
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((mut s, _)) = l.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        BODY2.len(),
                        BODY2
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
            addr
        };
        let mut user = usr("ipme", "pw");
        user.allowed_ips = vec!["127.0.0.1/32".into()];
        user.default_selection = Some("ipme-country-us".into());
        let proxies = vec![ProxyConfig {
            label: Some("us".into()),
            proxy_type: Proxy::Http,
            address: us.ip().to_string(),
            port: Some(us.port()),
            username: None,
            password: None,
            tags: Tags {
                country: Some("us".into()),
                ..Default::default()
            },
            cost_per_byte: 1.0,
        }];
        let srv = mk(proxies, None, None, vec![user], true);
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // No Proxy-Authorization -> IP auth path.
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(drain(&mut c).await.contains(BODY2));
    }

    /// SOCKS5 inbound, no-auth offered, auth disabled, but the account's
    /// default_selection is resolved by source IP in handle_socks5.
    #[tokio::test]
    async fn socks5_ip_default_selection() {
        let origin = s5_origin().await;
        let mut user = usr("ipme", "pw");
        user.allowed_ips = vec!["127.0.0.1/32".into()];
        user.default_selection = Some("ipme-country-us".into());
        let proxies = vec![ProxyConfig {
            label: Some("us".into()),
            proxy_type: Proxy::Socks5,
            address: origin.ip().to_string(),
            port: Some(origin.port()),
            username: None,
            password: None,
            tags: Tags {
                country: Some("us".into()),
                ..Default::default()
            },
            cost_per_byte: 1.0,
        }];
        // auth disabled so SOCKS5 uses no-auth, but still hits IP default selection.
        let srv = mk(proxies, None, None, vec![user], false);
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);
        c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(drain(&mut c).await.contains(BODY2));
    }

    // ---- (3) bandwidth exceeded ----------------------------------------

    #[tokio::test]
    async fn http_bandwidth_exceeded_refused() {
        let up = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = l.accept().await;
            });
            addr
        };
        let mut user = usr("me", "pw");
        user.bandwidth_limit = Some(0);
        let srv = mk(
            vec![px("up", Proxy::Http, up)],
            None,
            Some("up"),
            vec![user],
            true,
        );
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        let creds = base64::engine::general_purpose::STANDARD.encode("me:pw");
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
        );
        c.write_all(req.as_bytes()).await.unwrap();
        // Refused -> no body, connection closed.
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        assert_eq!(n, 0, "expected closed connection on bandwidth refusal");
    }

    #[test]
    fn check_bandwidth_paths() {
        let cfg = rcfg(None, false);
        assert!(check_bandwidth(None, "u", &cfg).is_ok());
        assert!(check_bandwidth(Some(100), "u", &cfg).is_ok());
        assert!(matches!(
            check_bandwidth(Some(0), "u", &cfg),
            Err(ProxyError::BandwidthExceeded)
        ));
        assert!(matches!(
            check_bandwidth(Some(-5), "u", &cfg),
            Err(ProxyError::BandwidthExceeded)
        ));
    }

    // ---- (4) detect_protocol -------------------------------------------

    #[test]
    fn detect_protocol_all_and_errors() {
        let srv = mk(
            vec![px("x", Proxy::Http, "127.0.0.1:1".parse().unwrap())],
            None,
            None,
            vec![],
            false,
        );
        assert!(matches!(
            srv.detect_protocol(&[0x05, 0x01, 0x00]).unwrap(),
            Proxy::Socks5
        ));
        assert!(matches!(
            srv.detect_protocol(&[0x04, 0x01]).unwrap(),
            Proxy::Socks4
        ));
        assert!(matches!(
            srv.detect_protocol(b"CONNECT host:443 HTTP/1.1\r\n")
                .unwrap(),
            Proxy::Https
        ));
        for m in [
            "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH",
        ] {
            let line = format!("{m} / HTTP/1.1\r\n");
            assert!(matches!(
                srv.detect_protocol(line.as_bytes()).unwrap(),
                Proxy::Http
            ));
        }
        // empty -> error
        assert!(srv.detect_protocol(&[]).is_err());
        // unrecognised text -> unsupported
        assert!(matches!(
            srv.detect_protocol(b"BREW / HTCPCP/1.0\r\n"),
            Err(ProxyError::UnsupportedProtocol)
        ));
    }

    // ---- (5) malformed SOCKS5 greeting ---------------------------------

    /// Auth enabled but client offers only no-auth method -> server replies
    /// 0x05 0xFF and drops.
    #[tokio::test]
    async fn socks5_no_acceptable_method() {
        let srv = mk(
            vec![px("up", Proxy::Socks5, "127.0.0.1:1".parse().unwrap())],
            None,
            Some("up"),
            vec![usr("me", "pw")],
            true,
        );
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // offer only no-auth (0x00); auth requires user/pass (0x02)
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [0x05, 0xFF]);
    }

    /// Greeting too short for SOCKS5 -> detected as SOCKS5 then rejected.
    #[tokio::test]
    async fn socks5_greeting_too_short() {
        let srv = mk(
            vec![px("up", Proxy::Socks5, "127.0.0.1:1".parse().unwrap())],
            None,
            Some("up"),
            vec![],
            false,
        );
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // 2 bytes only: < 3 -> "Invalid SOCKS5 greeting length"
        c.write_all(&[0x05, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        assert!(c.read_exact(&mut r).await.is_err());
    }

    /// Bad SOCKS5 version in greeting (0x05 detected, but request[0] checked
    /// again as 0x05; here we send 0x05 with declared nmethods exceeding the
    /// buffer to hit the "insufficient methods" branch).
    #[tokio::test]
    async fn socks5_insufficient_methods() {
        let srv = mk(
            vec![px("up", Proxy::Socks5, "127.0.0.1:1".parse().unwrap())],
            None,
            Some("up"),
            vec![],
            false,
        );
        let router = serve1(srv).await;
        let mut c = TcpStream::connect(router).await.unwrap();
        // version=5, nmethods=5, but only 1 method byte present
        c.write_all(&[0x05, 0x05, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        assert!(c.read_exact(&mut r).await.is_err());
    }
}
