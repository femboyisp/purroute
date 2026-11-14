//! Upstream port health tracking, circuit breaking, and failover.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::RwLock;

use crate::config::UpstreamHealthConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortStatus {
    Healthy,
    Dead,
    Probing,
}

#[derive(Clone, Debug)]
pub struct PortHealthState {
    pub consecutive_failures: u32,
    pub status: PortStatus,
    pub dead_since: Option<Instant>,
    pub last_success: Option<Instant>,
}

impl Default for PortHealthState {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            status: PortStatus::Healthy,
            dead_since: None,
            last_success: None,
        }
    }
}

pub struct UpstreamHealthTracker {
    config: UpstreamHealthConfig,
    ports: RwLock<HashMap<(String, u16), PortHealthState>>,
}

impl UpstreamHealthTracker {
    pub fn new(config: UpstreamHealthConfig) -> Self {
        Self {
            config,
            ports: RwLock::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &UpstreamHealthConfig {
        &self.config
    }

    /// Record a successful connection / handshake through this upstream port.
    pub fn record_success(&self, host: &str, port: u16) {
        let mut map = self.ports.write();
        let state = map.entry((host.to_string(), port)).or_default();
        state.consecutive_failures = 0;
        state.status = PortStatus::Healthy;
        state.dead_since = None;
        state.last_success = Some(Instant::now());
    }

    /// Record a failed connection or handshake timeout.
    pub fn record_failure(&self, host: &str, port: u16) {
        let mut map = self.ports.write();
        let state = map.entry((host.to_string(), port)).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.config.failure_threshold {
            state.status = PortStatus::Dead;
            state.dead_since = Some(Instant::now());
        }
    }

    /// Check if a port is currently eligible to receive traffic.
    pub fn is_healthy(&self, host: &str, port: u16) -> bool {
        let mut map = self.ports.write();
        let state = match map.get_mut(&(host.to_string(), port)) {
            Some(s) => s,
            None => return true, // unvisited ports are healthy by default
        };

        match state.status {
            PortStatus::Healthy => true,
            PortStatus::Probing => true,
            PortStatus::Dead => {
                // In passive mode: check if cooldown elapsed, transition to Probing
                if self.config.recovery_mode == "passive" {
                    if let Some(since) = state.dead_since {
                        if since.elapsed() >= Duration::from_secs(self.config.cooldown_secs) {
                            state.status = PortStatus::Probing;
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    /// Get all healthy ports within an inclusive range `range.0..=range.1`.
    /// If all ports are marked dead, falls back to returning all ports so traffic
    /// is not unconditionally dropped.
    pub fn get_healthy_ports(&self, host: &str, range: (u16, u16)) -> Vec<u16> {
        let (start, end) = (range.0.min(range.1), range.0.max(range.1));
        let mut healthy = Vec::new();

        for port in start..=end {
            if self.is_healthy(host, port) {
                healthy.push(port);
            }
        }

        if healthy.is_empty() {
            // Emergency fallback: all ports appear dead, return full range
            (start..=end).collect()
        } else {
            healthy
        }
    }

    /// Retrieve all dead ports eligible for active background probing.
    pub fn get_dead_ports_for_probing(&self) -> Vec<(String, u16)> {
        let map = self.ports.read();
        let mut out = Vec::new();
        for ((host, port), state) in map.iter() {
            if state.status == PortStatus::Dead {
                if let Some(since) = state.dead_since {
                    if since.elapsed() >= Duration::from_secs(self.config.cooldown_secs) {
                        out.push((host.clone(), *port));
                    }
                }
            }
        }
        out
    }
}

/// Lightweight probe to check if a SOCKS5 upstream port is alive.
/// Performs TCP connect + SOCKS5 greeting + CONNECT to 127.0.0.1:0.
pub async fn probe_upstream_port(
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
    timeout_dur: Duration,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let probe_fut = async {
        let mut stream = TcpStream::connect((host, port)).await.ok()?;
        stream.set_nodelay(true).ok()?;

        let handshake = if auth.is_some() {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };
        stream.write_all(&handshake).await.ok()?;

        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.ok()?;
        if sel[0] != 0x05 {
            return None;
        }

        if sel[1] == 0x02 {
            if let Some((u, p)) = auth {
                let mut auth_req = Vec::with_capacity(3 + u.len() + p.len());
                auth_req.push(0x01);
                auth_req.push(u.len() as u8);
                auth_req.extend_from_slice(u.as_bytes());
                auth_req.push(p.len() as u8);
                auth_req.extend_from_slice(p.as_bytes());
                stream.write_all(&auth_req).await.ok()?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await.ok()?;
                if auth_resp[1] != 0x00 {
                    return None;
                }
            } else {
                return None;
            }
        } else if sel[1] != 0x00 {
            return None;
        }

        // Send a CONNECT request to 127.0.0.1:0
        let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0];
        stream.write_all(&req).await.ok()?;

        let mut rep = [0u8; 4];
        stream.read_exact(&mut rep).await.ok()?;
        if rep[0] != 0x05 {
            return None;
        }
        // As long as the proxy returned a valid SOCKS5 reply (even connection refused / unreachable 0x05),
        // the upstream port itself is responsive and alive!
        Some(())
    };

    timeout(timeout_dur, probe_fut)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Background loop that periodically probes dead upstream ports when `recovery_mode == "active"`.
pub async fn run_active_health_prober(
    tracker: std::sync::Arc<UpstreamHealthTracker>,
    proxies: Vec<crate::config::ProxyConfig>,
) {
    let interval_secs = tracker.config().active_probe_interval_secs.max(1);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        let dead_ports = tracker.get_dead_ports_for_probing();
        if dead_ports.is_empty() {
            continue;
        }

        for (host, port) in dead_ports {
            // Find any matching credentials from configured proxies
            let auth = proxies.iter().find_map(|p| {
                if p.address == host {
                    if let (Some(u), Some(pw)) = (&p.username, &p.password) {
                        return Some((u.as_str(), pw.as_str()));
                    }
                }
                None
            });

            let alive = probe_upstream_port(&host, port, auth, Duration::from_secs(2)).await;
            if alive {
                metrics::counter!("purroute_upstream_health_probes_total", "result" => "success")
                    .increment(1);
                tracker.record_success(&host, port);
            } else {
                metrics::counter!("purroute_upstream_health_probes_total", "result" => "failure")
                    .increment(1);
                // Reset cooldown timer
                let mut map = tracker.ports.write();
                if let Some(state) = map.get_mut(&(host, port)) {
                    state.dead_since = Some(Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unvisited_port_is_healthy() {
        let tracker = UpstreamHealthTracker::new(UpstreamHealthConfig::default());
        assert!(tracker.is_healthy("example.com", 11000));
    }

    #[test]
    fn failure_threshold_trips_to_dead() {
        let config = UpstreamHealthConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let tracker = UpstreamHealthTracker::new(config);

        // 1 failure: still healthy
        tracker.record_failure("example.com", 11000);
        assert!(tracker.is_healthy("example.com", 11000));

        // 2 failures: trips to dead
        tracker.record_failure("example.com", 11000);
        assert!(!tracker.is_healthy("example.com", 11000));

        // record_success revives it
        tracker.record_success("example.com", 11000);
        assert!(tracker.is_healthy("example.com", 11000));
    }

    #[test]
    fn passive_recovery_transitions_to_probing() {
        let config = UpstreamHealthConfig {
            failure_threshold: 1,
            cooldown_secs: 0, // instant cooldown for testing
            recovery_mode: "passive".to_string(),
            ..Default::default()
        };
        let tracker = UpstreamHealthTracker::new(config);

        tracker.record_failure("example.com", 11000);
        // cooldown elapsed immediately (0s), so is_healthy returns true and transitions to Probing
        assert!(tracker.is_healthy("example.com", 11000));
    }

    #[test]
    fn get_healthy_ports_filters_dead_and_emergency_fallback() {
        let config = UpstreamHealthConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let tracker = UpstreamHealthTracker::new(config);

        tracker.record_failure("example.com", 11001);
        let healthy = tracker.get_healthy_ports("example.com", (11000, 11002));
        assert_eq!(healthy, vec![11000, 11002]);

        // If all ports fail: emergency fallback returns all ports
        tracker.record_failure("example.com", 11000);
        tracker.record_failure("example.com", 11002);
        let fallback = tracker.get_healthy_ports("example.com", (11000, 11002));
        assert_eq!(fallback, vec![11000, 11001, 11002]);
    }

    #[tokio::test]
    async fn test_probe_upstream_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 128];
                // greeting
                let n = socket.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], &[0x05, 0x01, 0x00]);
                socket.write_all(&[0x05, 0x00]).await.unwrap();

                // connect
                let n = socket.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], &[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
                socket
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });

        let success = probe_upstream_port("127.0.0.1", port, None, Duration::from_secs(1)).await;
        assert!(success);

        // A dead port that drops connection
        let dead_success =
            probe_upstream_port("127.0.0.1", port + 9999, None, Duration::from_millis(50)).await;
        assert!(!dead_success);
    }

    #[tokio::test]
    async fn test_probe_upstream_port_with_auth() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 128];
                // greeting with auth offered (0x02)
                let n = socket.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], &[0x05, 0x02, 0x00, 0x02]);
                socket.write_all(&[0x05, 0x02]).await.unwrap();

                // read username/password auth
                let _ = socket.read(&mut buf).await.unwrap();
                assert_eq!(buf[0], 0x01); // version 1
                let ulen = buf[1] as usize;
                let user = std::str::from_utf8(&buf[2..2 + ulen]).unwrap();
                let plen = buf[2 + ulen] as usize;
                let pass = std::str::from_utf8(&buf[3 + ulen..3 + ulen + plen]).unwrap();
                assert_eq!(user, "testuser");
                assert_eq!(pass, "testpass");

                // auth success
                socket.write_all(&[0x01, 0x00]).await.unwrap();

                // connect request
                let _ = socket.read(&mut buf).await.unwrap();
                socket
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });

        let success = probe_upstream_port(
            "127.0.0.1",
            port,
            Some(("testuser", "testpass")),
            Duration::from_secs(1),
        )
        .await;
        assert!(success);
    }

    #[tokio::test]
    async fn test_active_health_prober_revives_dead_port() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 128];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(&[0x05, 0x00]).await;
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
            }
        });

        let config = UpstreamHealthConfig {
            failure_threshold: 1,
            cooldown_secs: 0,
            active_probe_interval_secs: 1,
            recovery_mode: "active".to_string(),
            ..Default::default()
        };
        let tracker = Arc::new(UpstreamHealthTracker::new(config));

        // Mark port as dead
        tracker.record_failure("127.0.0.1", port);
        assert!(!tracker.is_healthy("127.0.0.1", port));

        // Spawn prober in background
        let tracker_clone = Arc::clone(&tracker);
        let prober_handle = tokio::spawn(async move {
            run_active_health_prober(tracker_clone, vec![]).await;
        });

        // Wait up to 2 seconds for active prober to recover the port
        let mut recovered = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tracker.is_healthy("127.0.0.1", port) {
                recovered = true;
                break;
            }
        }
        prober_handle.abort();
        assert!(recovered, "Port should be recovered by active prober");
    }
}
