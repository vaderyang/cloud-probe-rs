//! Logging. Port of `log.c`.
//!
//! Provides a C-like `log(level, msg)` entry point; formatting helpers are
//! available through the `log_info!`/`log_error!` macros.

use std::sync::atomic::{AtomicI32, Ordering};

use crate::config::{LOG_DEBUG, LOG_ERROR, LOG_FATAL, LOG_INFO, LOG_TRACE, LOG_WARN};

static LEVEL: AtomicI32 = AtomicI32::new(LOG_INFO);

pub fn log_level_string(level: i32) -> &'static str {
    match level {
        LOG_TRACE => "TRACE",
        LOG_DEBUG => "DEBUG",
        LOG_INFO => "INFO",
        LOG_WARN => "WARN",
        LOG_ERROR => "ERROR",
        LOG_FATAL => "FATAL",
        _ => "?????",
    }
}

pub fn set_level(level: i32) {
    LEVEL.store(level, Ordering::Relaxed);
}

pub fn level() -> i32 {
    LEVEL.load(Ordering::Relaxed)
}

/// Emit a pre-formatted message at `level`.
pub fn log(level: i32, msg: &str) {
    if level < LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let now = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    eprintln!("{now} {:<5} {msg}", log_level_string(level));
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_TRACE, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_DEBUG, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_INFO, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_WARN, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_ERROR, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_fatal {
    ($($arg:tt)*) => { $crate::log::log($crate::config::LOG_FATAL, &format!($($arg)*)) };
}
