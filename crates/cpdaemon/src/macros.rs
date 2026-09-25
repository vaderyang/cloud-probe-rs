//! Local logging macros for cpdaemon (mirrors the cpworker macros).

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { log::info!($($arg)*) };
}
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { log::warn!($($arg)*) };
}
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { log::error!($($arg)*) };
}
