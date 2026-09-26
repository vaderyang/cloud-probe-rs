//! ZMTP 3.x support (pure Rust, no libzmq).
//!
//! [`codec`] is the wire-format codec and [`client`] is the non-blocking
//! `PUSH` client used by the ZMQ output.

pub mod client;
pub mod codec;

pub use client::{tcp_connector, Connector, SendOutcome, Transport, ZmtpPush};
