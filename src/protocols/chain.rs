// src/protocols/chain.rs
use crate::{
    config::{encode_auth, ProxyConfig},
    protocols::{Proxy, ProxyError},
    stats::get_global_stats,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

pub struct ChainConnector;

impl ChainConnector {
    /// Connect through a chain of proxies to reach the final destination
    ///
    /// # Arguments
    /// * `chain` - Ordered list of proxies to traverse
    /// * `target_host` - Final destination hostname
    /// * `target_port` - Final destination port
    ///
    /// # Returns
    /// The TCP stream connected to the final destination through the chain
    pub async fn connect_chain(
        chain: &[ProxyConfig],
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, ProxyError> {
        if chain.is_empty() {
            return Err(ProxyError::Protocol("Empty proxy chain".to_string()));
        }

        let _stats = get_global_stats();

        // Connect to first proxy in chain
        let first_proxy = &chain[0];
        let mut stream = TcpStream::connect(&first_proxy.get_upstream_addr()).await?;
        stream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency

        // For each proxy in the chain, establish connection to the next hop
        for (i, current_proxy) in chain.iter().enumerate() {
            let is_last_hop = i == chain.len() - 1;

            let (next_host, next_port) = if is_last_hop {
                // Last hop: connect to final destination
                (target_host.to_string(), target_port)
            } else {
                // Intermediate hop: connect to next proxy in chain
                let next_proxy = &chain[i + 1];
                Self::parse_address(&next_proxy.get_upstream_addr())?
            };

            // Establish connection through current proxy to next hop
            stream = Self::connect_through_proxy(stream, current_proxy, &next_host, next_port)
                .await?;
        }

        Ok(stream)
    }

    /// Connect through a single proxy to the next hop
    async fn connect_through_proxy(
        mut stream: TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, ProxyError> {
        match proxy.proxy_type {
            Proxy::Socks5 => {
                Self::socks5_connect(&mut stream, proxy, target_host, target_port).await?;
            }
            Proxy::Socks4 => {
                Self::socks4_connect(&mut stream, proxy, target_host, target_port).await?;
            }
            Proxy::Http | Proxy::Https => {
                Self::http_connect(&mut stream, proxy, target_host, target_port).await?;
            }
        }

        Ok(stream)
    }

    // SOCKS5 connection logic (extracted from socks5.rs)
    async fn socks5_connect(
        stream: &mut TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        // SOCKS5 handshake
        let handshake = if proxy.username.is_some() && proxy.password.is_some() {
            vec![0x05, 0x02, 0x00, 0x02] // Offer both no auth and username/password
        } else {
            vec![0x05, 0x01, 0x00] // Only no auth
        };
        stream.write_all(&handshake).await?;
        stats.add_bytes_out(handshake.len() as u64);

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        stats.add_bytes_in(2);

        // Handle authentication if selected
        if response[1] == 0x02 {
            if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
                let mut auth_request = Vec::new();
                auth_request.push(0x01);
                auth_request.push(username.len() as u8);
                auth_request.extend_from_slice(username.as_bytes());
                auth_request.push(password.len() as u8);
                auth_request.extend_from_slice(password.as_bytes());

                stream.write_all(&auth_request).await?;
                stats.add_bytes_out(auth_request.len() as u64);

                let mut auth_response = [0u8; 2];
                stream.read_exact(&mut auth_response).await?;
                stats.add_bytes_in(2);

                if auth_response[1] != 0x00 {
                    return Err(ProxyError::Protocol("SOCKS5 auth failed".into()));
                }
            } else {
                return Err(ProxyError::Protocol(
                    "Auth required but not provided".into(),
                ));
            }
        } else if response[1] != 0x00 {
            return Err(ProxyError::Protocol("SOCKS5 handshake failed".into()));
        }

        // Send CONNECT request
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
        request.extend_from_slice(&target_port.to_be_bytes());

        stream.write_all(&request).await?;
        stats.add_bytes_out(request.len() as u64);

        // Read response with timeout
        let mut response = [0u8; 4];
        match timeout(Duration::from_secs(30), stream.read_exact(&mut response)).await {
            Ok(Ok(_)) => {
                stats.add_bytes_in(4);
            }
            Ok(Err(e)) => {
                return Err(ProxyError::Io(e));
            }
            Err(_) => {
                return Err(ProxyError::Protocol("Timeout waiting for CONNECT response".into()));
            }
        }

        if response[1] != 0x00 {
            return Err(ProxyError::Protocol(format!("SOCKS5 connect failed with code {}", response[1])));
        }

        // Skip address in response
        let atyp = response[3];
        match atyp {
            0x01 => {
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
                stats.add_bytes_in(6);
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                stats.add_bytes_in(1);
                let mut domain = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut domain).await?;
                stats.add_bytes_in(domain.len() as u64);
            }
            0x04 => {
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
                stats.add_bytes_in(18);
            }
            _ => return Err(ProxyError::Protocol("Invalid address type".into())),
        }

        Ok(())
    }

    // SOCKS4 connection logic
    async fn socks4_connect(
        stream: &mut TcpStream,
        _proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        // SOCKS4a request: always use 0.0.0.x to indicate domain name follows
        let mut request = vec![
            0x04, // SOCKS version
            0x01, // CONNECT command
        ];
        request.extend_from_slice(&target_port.to_be_bytes());
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // IP 0.0.0.1 for SOCKS4a
        request.push(0x00); // Empty user ID
        request.extend_from_slice(target_host.as_bytes());
        request.push(0x00); // Null terminator for domain

        stream.write_all(&request).await?;
        stats.add_bytes_out(request.len() as u64);

        // Read response
        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await?;
        stats.add_bytes_in(8);

        if response[1] != 0x5A {
            return Err(ProxyError::Protocol("SOCKS4 connect failed".into()));
        }

        Ok(())
    }

    // HTTP/HTTPS CONNECT logic
    async fn http_connect(
        stream: &mut TcpStream,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<(), ProxyError> {
        let stats = get_global_stats();

        let mut connect_request = Vec::new();
        connect_request.extend_from_slice(
            format!("CONNECT {}:{} HTTP/1.1\r\n", target_host, target_port).as_bytes(),
        );
        connect_request.extend_from_slice(format!("Host: {}:{}\r\n", target_host, target_port).as_bytes());

        if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
            let auth = encode_auth(username, password);
            connect_request.extend_from_slice(b"Proxy-Authorization: Basic ");
            connect_request.extend_from_slice(auth.as_bytes());
            connect_request.extend_from_slice(b"\r\n");
        }

        connect_request.extend_from_slice(b"\r\n");

        stream.write_all(&connect_request).await?;
        stats.add_bytes_out(connect_request.len() as u64);

        // Read HTTP response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await?;
        stats.add_bytes_in(n as u64);
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("200 Connection Established") {
            return Err(ProxyError::Protocol("HTTP tunnel failed".into()));
        }

        Ok(())
    }

    fn parse_address(addr: &str) -> Result<(String, u16), ProxyError> {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ProxyError::Protocol("Invalid address format".into()));
        }
        let port = parts[0]
            .parse()
            .map_err(|_| ProxyError::Protocol("Invalid port".into()))?;
        let host = parts[1].to_string();
        Ok((host, port))
    }
}
