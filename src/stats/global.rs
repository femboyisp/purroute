// src/stats/global.rs
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

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
    last_activity: Mutex<Instant>,
    log_tx: broadcast::Sender<(String, LogLevel)>,
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
            last_activity: Mutex::new(Instant::now()),
            log_tx,
        }
    }
    pub fn increment_successful_connections(&self) {
        self.succeeded_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increment_failed_connections(&self) {
        self.failed_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        self.total_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn log_message(&self, message: String, level: LogLevel) {
        // Try send a few times in case of channel full
        for _ in 0..3 {
            if self.log_tx.send((message.clone(), level)).is_ok() {
                break;
            }
            std::thread::yield_now();
        }
    }

    pub fn record_connection_result(&self, success: bool, message: String) {
        if success {
            self.succeeded_connections.fetch_add(1, Ordering::Release);
            self.log_message(message, LogLevel::Success);
        } else {
            self.failed_connections.fetch_add(1, Ordering::Release);
            self.log_message(message, LogLevel::Error);
        }
    }

    pub fn log_info(&self, message: String) {
        self.log_message(message, LogLevel::Info);
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
