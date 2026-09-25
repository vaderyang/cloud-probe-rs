//! Shared library for Cloud Probe clients.
//!
//! Rust port of the Go `cpgolib` module:
//! * `cpworker` — unix-socket JSON-RPC client and stats/info models
//! * `slogx`    — structured logging initialisation helpers

pub mod cpworker;
pub mod slogx;
