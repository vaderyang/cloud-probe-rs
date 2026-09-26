//! Netis Cloud Probe — Rust port of the `cpworker` packet capture engine.
//!
//! Architecture mirrors the original C implementation:
//!
//! ```text
//!   Capturer  ->  Task  ->  Output(s)
//! ```

#![warn(missing_docs)]

pub mod affinity;
pub mod bpf;
pub mod capturer;
pub mod config;
pub mod error;
pub mod log;
pub mod netns;
pub mod netutil;
pub mod output;
pub mod packet;
pub mod packet_split;
pub mod ratelimit;
pub mod req_pattern;
pub mod ring_buffer;
pub mod sockopt;
pub mod stats;
pub mod task;
pub mod unix_manager;
pub mod zmtp;

pub use error::{Error, Result};
