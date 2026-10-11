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
}
