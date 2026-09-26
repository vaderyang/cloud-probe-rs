//! Shared library for Cloud Probe clients.
//!
//! Rust port of the Go `cpgolib` module:
//! * `cpworker` — unix-socket JSON-RPC client and stats/info models
//! * `slogx`    — structured logging initialisation helpers
//! * `fingerprint` — FNV-1a fingerprint primitives (shared with cpdaemon)
//! * `worker_config` — worker configuration model (shared with cpdaemon)

pub mod cpworker;
pub mod fingerprint;
pub mod slogx;
pub mod worker_config;
pub mod worker_fingerprint;
