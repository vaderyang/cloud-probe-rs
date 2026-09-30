//! Structured logging helpers. Rust port of `cpgolib/slogx`.
//!
//! The Go implementation wraps `log/slog` with attribute helpers and a
//! multi-handler. Here we build on `log`/`env_logger` and provide an
//! `error` attribute helper used across the CLI and daemon.

use std::io::Write;

/// Initialise the global logger at the given level. Safe to call multiple times.
pub fn init_default(level: log::LevelFilter) {
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level.as_str()))
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{ts} {level:<5} {target}: {args}",
                    ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
                    level = record.level(),
                    target = record.target(),
                    args = record.args()
                )
            })
            .try_init();
}

/// Format a `log`-style error attribute.
pub fn error_attr(err: &dyn std::error::Error) -> String {
    format!("error={err}")
}

#[macro_export]
macro_rules! log_error_attr {
    ($err:expr) => {
        log::error!("{}", $crate::slogx::error_attr(&$err))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_attr_formats_the_error() {
        let err = std::io::Error::other("boom");
        assert_eq!(error_attr(&err), "error=boom");
    }
}
