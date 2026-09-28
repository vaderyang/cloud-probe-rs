//! `cpdaemon` library.
//!
//! The Cloud Probe management daemon: configuration, the CPM syncer (register,
//! pull strategy, push metrics), worker lifecycle management and the HTTP
//! health endpoint. Port of `cpdaemon/main.go` + `cmd/server.go`.
//!
//! The `cpdaemon` binary is a thin wrapper around this crate; the library is
//! exposed separately so the end-to-end integration tests under `tests/` can
//! drive the syncer and the worker supervisor directly.

pub mod common;
pub mod config;
pub mod cpm;
pub mod error;
pub mod httpmix;
pub mod macros;
pub mod reslimit;
pub mod tool;
pub mod worker;
pub mod worker_config;
pub mod worker_log;
