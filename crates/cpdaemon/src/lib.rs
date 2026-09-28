//! `cpdaemon` library.
//!
//! The Cloud Probe management daemon: configuration, the CPM syncer (register,
//! pull strategy, push metrics), worker lifecycle management and the HTTP
//! health endpoint. Port of `cpdaemon/main.go` + `cmd/server.go`.
//!
//! The `cpdaemon` binary is a thin wrapper around this crate; the library is
//! exposed separately so the end-to-end integration tests under `tests/` can
//! drive the syncer and the worker supervisor directly.
//!
//! The public modules below are the deliberate test/embedding surface:
//! `config`, `cpm`, `reslimit`, `tool`, `worker` and `worker_config`. The
//! remaining modules (`common`, `error`, `httpmix`, `macros`, `worker_log`) are
//! internal helpers.
//!
//! Note: because these modules are `pub`, `dead_code` can no longer flag their
//! unused items - the `#[allow(dead_code)] // not yet wired (PARITY.md §5)`
//! markers in them are now documentation, not an enforced lint. Review that
//! surface by hand rather than trusting the compiler.

pub mod config;
pub mod cpm;
pub mod error;
pub mod reslimit;
pub mod tool;
pub mod worker;
pub mod worker_config;

mod common;
mod httpmix;
mod macros;
mod worker_log;
