// src/stats/mod.rs
pub mod display;
pub mod global;

pub use self::display::StatsDisplay;
pub use self::global::{get_global_stats, GlobalStats, GlobalStatsSnapshot};
