//! cpworker client + models. Port of `cpgolib/cpworker`.

pub mod client;
pub mod stats;

pub use client::{
    new_client, new_client_with_timeout, Client, Error, InfoSummary, PingResult, Result,
    UnixClient, DEFAULT_TIMEOUT,
};
pub use stats::{
    BytesStats, CaptureStats, OutputStats, PacketsStats, PipelineBufferStats, StatsSummary,
    EIB_IN_BYTES, PETA_IN_PACKETS,
};
