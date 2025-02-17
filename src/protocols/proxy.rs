/// PROXY Protocol
/// This module implements the PROXY protocol for the proxy server.
/// The PROXY protocol is a simple text-based protocol that is used to pass client connection information to the server.
/// The client sends a PROXY header to the server, which contains the client's IP address and port number.
/// The server reads the PROXY header and uses the client's IP address and port number to establish a connection to the client.
/// The server then forwards the client's request to the destination server.
// src/protocols/proxy.rs
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

use crate::{
    config::ProxyConfig,
    protocols::{Http, Socks5},
    stats::{get_global_stats, GlobalStats, StatsDisplay},
};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum Proxy {
    Http,
    Https,
    Socks5,
}

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

#[derive(Clone)]
pub struct ProxyServer {
    proxy: Arc<Vec<ProxyConfig>>,
    logger: Arc<StatsDisplay>,
}

impl ProxyServer {
    pub fn new(proxy: Vec<ProxyConfig>, logger: Arc<StatsDisplay>) -> Self {
        Self {
            proxy: Arc::new(proxy),
            logger,
        }
    }

    pub async fn run(self, addr: SocketAddr) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        let global_stats = get_global_stats();
        global_stats.log_info(format!("Proxy server listening on {}", addr));

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let global_stats = global_stats.clone();
            global_stats.log_info(format!("New connection from {}", peer_addr));

            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket, peer_addr).await {
                    global_stats.record_connection_result(
                        false,
                        format!("Connection error from {}: {}", peer_addr, e),
                    );
                }
            });
        }
    }

    pub async fn handle_connection(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        let global_stats = get_global_stats();
        global_stats.increment_active_connections();

        let result = async {
            let mut buf = vec![0u8; 8192];
            let n = client.read(&mut buf).await?;
            let initial_request = buf[..n].to_vec();

            let protocol = self.detect_protocol(&initial_request)?;
            global_stats.log_info(format!(
                "Protocol {:?} detected from {}",
                protocol, peer_addr
            ));

            let target_proxy = self.proxy.first().ok_or_else(|| {
                ProxyError::Protocol("No proxy configuration available".to_string())
            })?;

            // Create a notification channel with a larger buffer
            let (success_tx, mut success_rx) = mpsc::channel(32);

            // Spawn a task to handle the success notification
            let stats = global_stats.clone();
            let peer = peer_addr;
            let notification_task = tokio::spawn(async move {
                if success_rx.recv().await.is_some() {
                    stats.log_info(format!("Connection established successfully for {}", peer));
                }
            });

            let handle_result = match protocol {
                Proxy::Socks5 => {
                    let tx = success_tx.clone();
                    let stats = global_stats.clone();
                    Socks5::handle(
                        client,
                        &target_proxy.address,
                        initial_request,
                        target_proxy,
                        move |client, upstream, _| {
                            let server = self.clone();
                            let peer = peer_addr;
                            let stats = stats.clone();
                            Box::pin({
                                let tx = tx.clone();
                                async move {
                                    // Send success notification immediately after connection
                                    let _ = tx.send(()).await;
                                    server.proxy_data(client, upstream, peer, stats).await
                                }
                            })
                        },
                    )
                    .await
                }
                Proxy::Http | Proxy::Https => {
                    let tx = success_tx.clone();
                    let stats = global_stats.clone();
                    Http::handle(
                        client,
                        &target_proxy.address,
                        initial_request,
                        protocol == Proxy::Https,
                        target_proxy,
                        move |client, upstream, _| {
                            let server = self.clone();
                            let peer = peer_addr;
                            let stats = stats.clone();
                            Box::pin({
                                let tx = tx.clone();
                                async move {
                                    // Send success notification immediately after connection
                                    let _ = tx.send(()).await;
                                    server.proxy_data(client, upstream, peer, stats).await
                                }
                            })
                        },
                    )
                    .await
                }
            };

            // Wait for either an error or connection completion
            tokio::select! {
                res = notification_task => {
                    if let Err(e) = res {
                        global_stats.record_connection_result(
                            false,
                            format!("Notification error for {}: {}", peer_addr, e),
                        );
                    }
                }
                res = async { handle_result } => {
                    if let Err(e) = res {
                        global_stats.record_connection_result(
                            false,
                            format!("Connection failed for {}: {}", peer_addr, e),
                        );
                        return Err(e);
                    }
                }
            }

            Ok(())
        }
        .await;

        global_stats.decrement_active_connections();
        result
    }

    pub fn detect_protocol(&self, request: &[u8]) -> Result<Proxy, ProxyError> {
        if request.len() < 1 {
            return Err(ProxyError::Protocol("Request too short".into()));
        }

        if request[0] == 0x05 {
            return Ok(Proxy::Socks5);
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
            Err(ProxyError::Protocol("Unknown protocol".into()))
        }
    }

    pub async fn proxy_data(
        &self,
        mut client: TcpStream,
        mut upstream: TcpStream,
        peer_addr: SocketAddr,
        stats: Arc<GlobalStats>,
    ) -> Result<(), ProxyError> {
        let (mut client_reader, mut client_writer) = client.split();
        let (mut upstream_reader, mut upstream_writer) = upstream.split();

        let client_to_upstream = async {
            let mut buf = [0u8; 8192];
            loop {
                match client_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stats.add_bytes_out(n as u64);
                        if let Err(e) = upstream_writer.write_all(&buf[..n]).await {
                            stats.record_connection_result(
                                false,
                                format!("Error writing to upstream for {}: {}", peer_addr, e),
                            );
                            break;
                        }
                        if let Err(e) = upstream_writer.flush().await {
                            stats.record_connection_result(
                                false,
                                format!("Error flushing upstream for {}: {}", peer_addr, e),
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        stats.record_connection_result(
                            false,
                            format!("Error reading from client {}: {}", peer_addr, e),
                        );
                        break;
                    }
                }
            }
            Ok::<(), ProxyError>(())
        };

        let upstream_to_client = async {
            let mut buf = [0u8; 8192];
            loop {
                match upstream_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stats.add_bytes_in(n as u64);
                        if let Err(e) = client_writer.write_all(&buf[..n]).await {
                            stats.record_connection_result(
                                false,
                                format!("Error writing to client {}: {}", peer_addr, e),
                            );
                            break;
                        }
                        if let Err(e) = client_writer.flush().await {
                            stats.record_connection_result(
                                false,
                                format!("Error flushing client {}: {}", peer_addr, e),
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        stats.record_connection_result(
                            false,
                            format!("Error reading from upstream for {}: {}", peer_addr, e),
                        );
                        break;
                    }
                }
            }
            Ok::<(), ProxyError>(())
        };

        tokio::try_join!(client_to_upstream, upstream_to_client)?;
        Ok(())
    }
}
