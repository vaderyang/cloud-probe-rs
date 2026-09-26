//! ZMTP 3.x support (pure Rust, no libzmq).
//!
//! [`codec`] is the wire-format codec and [`client`] is the non-blocking
//! `PUSH` client used by the ZMQ output.

pub mod client;
pub mod codec;

pub use client::{
    tcp_connector, tcp_connector_with_resolver, Connector, Resolver, SendOutcome, SystemResolver,
    Transport, ZmtpPush, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_QUEUED_BYTES, RESOLVE_TTL,
    TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL, TCP_KEEPALIVE_RETRIES, TCP_USER_TIMEOUT,
};
