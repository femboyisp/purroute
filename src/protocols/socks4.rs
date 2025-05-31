/// SOCKS4 protocol
/// The SOCKS4 protocol is used to establish a connection between the client and the proxy server.
/// The client sends a connection request to the proxy server, which then forwards the request to the
/// destination server. The proxy server then establishes a connection with the destination server and
/// forwards the data between the client and the destination server.
/// The SOCKS4 protocol is simpler than SOCKS5 and only supports IPv4 addresses.
// src/protocols/socks4.rs
use crate::{
    config::{ProxyConfig},
    protocols::{Proxy, ProxyError},
    stats::{get_global_stats, GlobalStats},
};
use base64::Engine;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct Socks4;

impl Socks4 {
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
        if request[0] != 0x04 {
            return Err(ProxyError::Protocol("Invalid SOCKS4 version".into()));
        }

        let mut client = client;
        let stats = get_global_stats();

        // Track initial request bytes
        stats.add_bytes_in(request.len().try_into().unwrap());

        // Parse SOCKS4 request
        let command = request[1];
        if command != 0x01 {
            return Err(ProxyError::Protocol("Only CONNECT command is supported".into()));
        }
        let port = u16::from_be_bytes([request[2], request[3]]);
        let ip = format!("{}.{}.{}.{}", request[4], request[5], request[6], request[7]);

        // Find the end of the user ID string
        let mut user_id_end = 8;
        while user_id_end < request.len() && request[user_id_end] != 0 {
            user_id_end += 1;
        }

        // Extract user ID if present
        let user_id = if user_id_end > 8 {
            String::from_utf8_lossy(&request[8..user_id_end]).to_string()
        } else {
            String::new()
        };

        // Check if this is a SOCKS4a request (domain name instead of IP)
        let target_host = if ip == "0.0.0.1" || ip == "0.0.0.0" {
            // SOCKS4a - domain name follows user ID
            let mut domain_end = user_id_end + 1;
            while domain_end < request.len() && request[domain_end] != 0 {
                domain_end += 1;
            }
            if domain_end <= user_id_end + 1 {
                return Err(ProxyError::Protocol("Invalid SOCKS4a request: missing domain".into()));
            }
            String::from_utf8_lossy(&request[user_id_end + 1..domain_end]).to_string()
        } else {
            ip
        };

        let mut upstream = TcpStream::connect(upstream_addr).await?;

        // Always forward the SOCKS4 request to the upstream, regardless of upstream type
        upstream.write_all(&request).await?;
        stats.add_bytes_out(request.len().try_into().unwrap());

        // Read response
        let mut response = [0u8; 8];
        upstream.read_exact(&mut response).await?;
        stats.add_bytes_in(8);

        // Forward response to client
        client.write_all(&response).await?;
        stats.add_bytes_out(8);

        if response[1] != 0x5A {
            return Err(ProxyError::Protocol("SOCKS4 connection failed".into()));
        }

        // Start bidirectional proxy
        proxy_data(client, upstream, stats).await
    }
}
