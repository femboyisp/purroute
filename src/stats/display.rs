// src/stats/display.rs
use chrono::DateTime;
use crossterm::{
    cursor,
    style::{Color, Print, SetForegroundColor},
    terminal::{Clear, ClearType},
    QueueableCommand,
};
use std::{
    collections::VecDeque,
    io::{stdout, Result, Stdout, Write},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    self,
    sync::broadcast,
    time::{interval, Duration, MissedTickBehavior},
};
use tokio_postgres::Client;

use crate::config::RouterConfig;
use crate::stats::{GlobalStats, GlobalStatsSnapshot};

const MAX_LOG_LINES: usize = 10;

#[derive(Clone)]
pub struct LogEntry {
    timestamp: u64,
    message: String,
    level: LogLevel,
}

#[derive(Clone, Copy)]
pub enum LogLevel {
    Info,
    Error,
    Success,
}

pub struct StatsDisplay {
    stats: Arc<GlobalStats>,
    update_interval: Duration,
    logs: Arc<Mutex<VecDeque<LogEntry>>>,
    log_rx: broadcast::Receiver<(String, LogLevel)>,
    db_client: Arc<Client>,
}

impl StatsDisplay {
    pub fn new(stats: Arc<GlobalStats>, update_interval: Duration, db_client: Arc<Client>) -> Self {
        Self {
            stats: stats.clone(),
            update_interval,
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES))),
            log_rx: stats.get_log_rx(),
            db_client,
        }
    }

    fn format_bytes(bytes: u64, is_rate: bool) -> String {
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut bytes = bytes as f64;
        let mut unit_index = 0;

        while bytes >= 1024.0 && unit_index < UNITS.len() - 1 {
            bytes /= 1024.0;
            unit_index += 1;
        }

        if is_rate {
            format!("{:.2} {}/s", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", bytes, UNITS[unit_index])
        }
    }

    fn print_stat(
        stdout: &mut Stdout,
        label: &str,
        value: String,
        color: Color,
    ) -> std::io::Result<()> {
        stdout
            .queue(SetForegroundColor(Color::Grey))?
            .queue(Print(format!("{:<25}", label)))?
            .queue(SetForegroundColor(color))?
            .queue(Print(value))?
            .queue(Print("\n"))?;
        Ok(())
    }

    fn print_log_entry(
        stdout: &mut Stdout,
        entry: &LogEntry,
        config: &RouterConfig,
    ) -> std::io::Result<()> {
        let color = match entry.level {
            LogLevel::Info => Color::Blue,
            LogLevel::Error => Color::Red,
            LogLevel::Success => Color::Green,
        };

        let timestamp = DateTime::from_timestamp(entry.timestamp as i64, 0)
            .map(|dt| dt.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "??:??:??".to_string());

        if let Some(log) = config.log {
            if log {
                match entry.level {
                    LogLevel::Info => {
                        if config.verbose.unwrap_or(false) || config.debug.unwrap_or(false) {
                            stdout
                                .queue(SetForegroundColor(Color::DarkGrey))?
                                .queue(Print(format!("[{}] ", timestamp)))?
                                .queue(SetForegroundColor(color))?
                                .queue(Print(&entry.message))?
                                .queue(Print("\n"))?;
                        }
                    }
                    LogLevel::Error => {
                        stdout
                            .queue(SetForegroundColor(Color::DarkGrey))?
                            .queue(Print(format!("[{}] ", timestamp)))?
                            .queue(SetForegroundColor(color))?
                            .queue(Print(&entry.message))?
                            .queue(Print("\n"))?;
                    }
                    LogLevel::Success => {
                        if config.verbose.unwrap_or(false) {
                            stdout
                                .queue(SetForegroundColor(Color::DarkGrey))?
                                .queue(Print(format!("[{}] ", timestamp)))?
                                .queue(SetForegroundColor(color))?
                                .queue(Print(&entry.message))?
                                .queue(Print("\n"))?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn refresh_display(
        &self,
        stats: &GlobalStatsSnapshot,
        config: &RouterConfig,
    ) -> std::io::Result<()> {
        let mut stdout = stdout();

        stdout
            .queue(cursor::MoveTo(0, 0))?
            .queue(Clear(ClearType::FromCursorDown))?;

        // Title
        stdout
            .queue(SetForegroundColor(Color::Cyan))?
            .queue(Print("=== Purroute Proxy Statistics ===\n\n"))?;

        // Connection stats
        Self::print_stat(
            &mut stdout,
            "Active Connections:",
            format!("{}", stats.active_connections),
            Color::Green,
        )?;
        Self::print_stat(
            &mut stdout,
            "Total Connections:",
            format!("{}", stats.total_connections),
            Color::Blue,
        )?;
        Self::print_stat(
            &mut stdout,
            "Succeeded Connections:",
            format!("{}", stats.succeeded_connections),
            Color::Green,
        )?;
        Self::print_stat(
            &mut stdout,
            "Failed Connections:",
            format!("{}", stats.failed_connections),
            Color::Red,
        )?;

        stdout.queue(Print("\n"))?;

        // Current bandwidth
        Self::print_stat(
            &mut stdout,
            "Current Download:",
            Self::format_bytes(stats.current_bytes_in, true),
            Color::Yellow,
        )?;
        Self::print_stat(
            &mut stdout,
            "Current Upload:",
            Self::format_bytes(stats.current_bytes_out, true),
            Color::Yellow,
        )?;

        stdout.queue(Print("\n"))?;

        // Total transfer
        Self::print_stat(
            &mut stdout,
            "Total Download:",
            Self::format_bytes(stats.total_bytes_in, false),
            Color::Magenta,
        )?;
        Self::print_stat(
            &mut stdout,
            "Total Upload:",
            Self::format_bytes(stats.total_bytes_out, false),
            Color::Magenta,
        )?;

        // Connection logs
        stdout
            .queue(Print("\n"))?
            .queue(SetForegroundColor(Color::Cyan))?
            .queue(Print("=== Connection Logs ===\n"))?;

        if let Ok(logs) = self.logs.lock() {
            for entry in logs.iter() {
                Self::print_log_entry(&mut stdout, entry, config)?;
            }
        }

        stdout
            .queue(Print("\n"))?
            .queue(SetForegroundColor(Color::Grey))?
            .queue(Print("Press Ctrl+C to exit"))?;

        stdout.flush()?;
        Ok(())
    }

    pub async fn run(mut self, config: Arc<RouterConfig>) -> Result<()> {
        let mut stdout = stdout();
        let mut interval = interval(self.update_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        stdout.queue(cursor::Hide)?;

        loop {
            interval.tick().await;

            // Process any new logs
            while let Ok((message, level)) = self.log_rx.try_recv() {
                if let Ok(mut logs) = self.logs.lock() {
                    if logs.len() >= MAX_LOG_LINES {
                        logs.pop_front();
                    }
                    logs.push_back(LogEntry {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        message,
                        level,
                    });
                }
            }

            let stats = self.stats.get_stats();

            // Update display
            self.refresh_display(&stats, &config)?;

            // Record statistics in the database
            self.record_stats_in_db(&stats).await?;
        }
    }

    async fn record_stats_in_db(&self, stats: &GlobalStatsSnapshot) -> Result<()> {
        let query = "
            UPDATE public.global
            SET
                total_connections = $1,
                succeeded_connections = $2,
                failed_connections = $3,
                total_bytes_in = $4,
                total_bytes_out = $5
            WHERE id = 1
        ";

        self.db_client
            .execute(
                query,
                &[
                    &(stats.total_connections as i64),
                    &(stats.succeeded_connections as i64),
                    &(stats.failed_connections as i64),
                    &(stats.total_bytes_in as i64),
                    &(stats.total_bytes_out as i64),
                ],
            )
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        Ok(())
    }
}

impl Drop for StatsDisplay {
    fn drop(&mut self) {
        let mut stdout = stdout();
        let _ = stdout.queue(cursor::Show);
        let _ = stdout.flush();
    }
}
