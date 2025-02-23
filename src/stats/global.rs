// src/stats/global.rs
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_postgres::Client;

use crate::config::RouterConfig;
use crate::stats::display::LogLevel;

#[derive(Debug)]
pub struct GlobalStats {
    pub current_bytes_in: AtomicI64,
    pub current_bytes_out: AtomicI64,
    pub total_bytes_in: AtomicI64,
    pub total_bytes_out: AtomicI64,
    pub active_connections: AtomicI64,
    pub total_connections: AtomicI64,
    pub failed_connections: AtomicI64,
    pub succeeded_connections: AtomicI64,
    pub user_stats: Mutex<HashMap<u64, UserStats>>, // Changed to use user IDs
    last_activity: Mutex<Instant>,
    log_tx: broadcast::Sender<(String, LogLevel)>,
}

#[derive(Debug)]
pub struct UserStats {
    pub bytes_in: AtomicI64,
    pub bytes_out: AtomicI64,
    pub connections: AtomicI64,
}

impl GlobalStats {
    pub fn new() -> Self {
        let (log_tx, _) = broadcast::channel(100);
        Self {
            current_bytes_in: AtomicI64::new(0),
            current_bytes_out: AtomicI64::new(0),
            total_bytes_in: AtomicI64::new(0),
            total_bytes_out: AtomicI64::new(0),
            active_connections: AtomicI64::new(0),
            total_connections: AtomicI64::new(0),
            failed_connections: AtomicI64::new(0),
            succeeded_connections: AtomicI64::new(0),
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
                            let _ = self.log_tx.send((message.clone(), level));
                        }
                    }
                    LogLevel::Error => {
                        let _ = self.log_tx.send((message.clone(), level));
                    }
                    LogLevel::Success => {
                        if config.verbose.unwrap_or(false) {
                            let _ = self.log_tx.send((message.clone(), level));
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
        self.current_bytes_in
            .fetch_add(bytes.try_into().unwrap(), Ordering::Release);
        self.total_bytes_in
            .fetch_add(bytes.try_into().unwrap(), Ordering::Release);
    }

    pub fn add_bytes_out(&self, bytes: u64) {
        *self.last_activity.lock() = Instant::now();
        self.current_bytes_out
            .fetch_add(bytes.try_into().unwrap(), Ordering::Release);
        self.total_bytes_out
            .fetch_add(bytes.try_into().unwrap(), Ordering::Release);
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
                ";

        if let Some(row) = db_client.query_opt(query, &[]).await? {
            self.total_connections
                .store(row.get::<_, i64>(0), Ordering::SeqCst);
            self.succeeded_connections
                .store(row.get::<_, i64>(1), Ordering::SeqCst);
            self.failed_connections
                .store(row.get::<_, i64>(2), Ordering::SeqCst);
            self.total_bytes_in
                .store(row.get::<_, i64>(3), Ordering::SeqCst);
            self.total_bytes_out
                .store(row.get::<_, i64>(4), Ordering::SeqCst);
        }

        // Load user stats from the database
        let user_query = "
                    SELECT id, total_bytes_in, total_bytes_out, total_connections
                    FROM public.user_stats
                ";
        for row in db_client.query(user_query, &[]).await? {
            let id: i64 = row.get(0); // Changed i32 to i64
            let bytes_in: i64 = row.get(1); // Changed i32 to i64
            let bytes_out: i64 = row.get(2); // Changed i32 to i64
            let connections: i64 = row.get(3); // Changed i32 to i64

            let mut user_stats = self.user_stats.lock();
            let id_u64 = id.try_into().unwrap();
            user_stats
                .entry(id_u64)
                .or_insert_with(|| UserStats {
                    bytes_in: AtomicI64::new(0),
                    bytes_out: AtomicI64::new(0),
                    connections: AtomicI64::new(0),
                })
                .bytes_in
                .store(bytes_in, Ordering::SeqCst);
            user_stats
                .get_mut(&id_u64)
                .unwrap()
                .bytes_out
                .store(bytes_out, Ordering::SeqCst);
            user_stats
                .get_mut(&id_u64)
                .unwrap()
                .connections
                .store(connections, Ordering::SeqCst);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GlobalStatsSnapshot {
    pub current_bytes_in: i64,
    pub current_bytes_out: i64,
    pub total_bytes_in: i64,
    pub total_bytes_out: i64,
    pub active_connections: i64,
    pub total_connections: i64,
    pub failed_connections: i64,
    pub succeeded_connections: i64,
}

pub static GLOBAL_STATS: Lazy<Arc<GlobalStats>> = Lazy::new(|| Arc::new(GlobalStats::new()));

pub fn get_global_stats() -> Arc<GlobalStats> {
    Arc::clone(&GLOBAL_STATS)
}
