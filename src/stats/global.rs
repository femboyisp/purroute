// src/stats/global.rs
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_postgres::Client;

use crate::config::RouterConfig;
use crate::stats::display::LogLevel;

#[derive(Debug)]
pub struct GlobalStats {
    pub current_bytes_in: AtomicU64,
    pub current_bytes_out: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub failed_connections: AtomicU64,
    pub succeeded_connections: AtomicU64,
    pub user_stats: Mutex<HashMap<String, UserStats>>,
    last_activity: Mutex<Instant>,
    log_tx: broadcast::Sender<(String, LogLevel)>,
}

#[derive(Debug)]
pub struct UserStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub connections: AtomicU64,
}

impl GlobalStats {
    pub fn new() -> Self {
        let (log_tx, _) = broadcast::channel(100);
        Self {
            current_bytes_in: AtomicU64::new(0),
            current_bytes_out: AtomicU64::new(0),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            succeeded_connections: AtomicU64::new(0),
            user_stats: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            log_tx,
        }
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        self.total_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn log_message(&self, message: String, level: LogLevel, config: &RouterConfig) {
        if let Some(log) = config.log {
            if log {
                match level {
                    LogLevel::Info => {
                        if config.verbose.unwrap_or(false) || config.debug.unwrap_or(false) {
                            self.log_tx.send((message.clone(), level)).unwrap_or(0);
                        }
                    }
                    LogLevel::Error => {
                        self.log_tx.send((message.clone(), level)).unwrap_or(0);
                    }
                    LogLevel::Success => {
                        if config.verbose.unwrap_or(false) {
                            self.log_tx.send((message.clone(), level)).unwrap_or(0);
                        }
                    }
                }
            }
        }
    }

    pub fn record_connection_result(&self, success: bool, message: String, config: &RouterConfig) {
        if success {
            self.succeeded_connections.fetch_add(1, Ordering::Release);
            self.log_message(message, LogLevel::Success, config);
        } else {
            self.failed_connections.fetch_add(1, Ordering::Release);
            self.log_message(message, LogLevel::Error, config);
        }
    }

    pub fn log_info(&self, message: String, config: &RouterConfig) {
        self.log_message(message, LogLevel::Info, config);
    }

    pub fn get_log_rx(&self) -> broadcast::Receiver<(String, LogLevel)> {
        self.log_tx.subscribe()
    }

    pub fn add_bytes_in(&self, bytes: u64) {
        *self.last_activity.lock() = Instant::now();
        self.current_bytes_in.fetch_add(bytes, Ordering::Release);
        self.total_bytes_in.fetch_add(bytes, Ordering::Release);
    }

    pub fn add_bytes_out(&self, bytes: u64) {
        *self.last_activity.lock() = Instant::now();
        self.current_bytes_out.fetch_add(bytes, Ordering::Release);
        self.total_bytes_out.fetch_add(bytes, Ordering::Release);
    }

    pub fn add_user_bytes_in(&self, user: &str, bytes: u64) {
        let mut user_stats = self.user_stats.lock();
        let stats = user_stats
            .entry(user.to_string())
            .or_insert_with(|| UserStats {
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                connections: AtomicU64::new(0),
            });
        stats.bytes_in.fetch_add(bytes, Ordering::Release);
    }

    pub fn add_user_bytes_out(&self, user: &str, bytes: u64) {
        let mut user_stats = self.user_stats.lock();
        let stats = user_stats
            .entry(user.to_string())
            .or_insert_with(|| UserStats {
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                connections: AtomicU64::new(0),
            });
        stats.bytes_out.fetch_add(bytes, Ordering::Release);
    }

    pub fn increment_user_connections(&self, user: &str) {
        let mut user_stats = self.user_stats.lock();
        let stats = user_stats
            .entry(user.to_string())
            .or_insert_with(|| UserStats {
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                connections: AtomicU64::new(0),
            });
        stats.connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn get_stats(&self) -> GlobalStatsSnapshot {
        let now = Instant::now();
        let last_activity = *self.last_activity.lock();
        let inactive_duration = now.duration_since(last_activity);

        // Only reset current bytes if there's been no activity for more than 1 second
        let (current_in, current_out) = if inactive_duration > Duration::from_secs(1) {
            (
                self.current_bytes_in.swap(0, Ordering::AcqRel),
                self.current_bytes_out.swap(0, Ordering::AcqRel),
            )
        } else {
            (
                self.current_bytes_in.load(Ordering::Acquire),
                self.current_bytes_out.load(Ordering::Acquire),
            )
        };

        GlobalStatsSnapshot {
            current_bytes_in: current_in,
            current_bytes_out: current_out,
            total_bytes_in: self.total_bytes_in.load(Ordering::Acquire),
            total_bytes_out: self.total_bytes_out.load(Ordering::Acquire),
            active_connections: self.active_connections.load(Ordering::Acquire),
            total_connections: self.total_connections.load(Ordering::Acquire),
            failed_connections: self.failed_connections.load(Ordering::Acquire),
            succeeded_connections: self.succeeded_connections.load(Ordering::Acquire),
        }
    }

    pub async fn load_from_db(&self, db_client: &Client) -> Result<(), Box<dyn std::error::Error>> {
        let query = "
                SELECT total_connections, succeeded_connections, failed_connections, total_bytes_in, total_bytes_out
                FROM public.global
                WHERE id = 1
            ";

        if let Some(row) = db_client.query_opt(query, &[]).await? {
            self.total_connections
                .store(row.get::<_, i64>(0) as u64, Ordering::SeqCst);
            self.succeeded_connections
                .store(row.get::<_, i64>(1) as u64, Ordering::SeqCst);
            self.failed_connections
                .store(row.get::<_, i64>(2) as u64, Ordering::SeqCst);
            self.total_bytes_in
                .store(row.get::<_, i64>(3) as u64, Ordering::SeqCst);
            self.total_bytes_out
                .store(row.get::<_, i64>(4) as u64, Ordering::SeqCst);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GlobalStatsSnapshot {
    pub current_bytes_in: u64,
    pub current_bytes_out: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub failed_connections: u64,
    pub succeeded_connections: u64,
}

pub static GLOBAL_STATS: Lazy<Arc<GlobalStats>> = Lazy::new(|| Arc::new(GlobalStats::new()));

pub fn get_global_stats() -> Arc<GlobalStats> {
    Arc::clone(&GLOBAL_STATS)
}
