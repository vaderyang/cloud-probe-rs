//! Output pipeline. Port of `output*.c` with a Rust trait replacing the C
//! vtable (`output_base_t`).

pub mod file;
pub mod gre;
pub mod null;
pub mod pcap_writer;
pub mod rotating_file;
pub mod vxlan;
pub mod zmq;

use std::net::SocketAddr;
use std::sync::Arc;

use socket2::Socket;

use crate::config::{OutputConfig, OutputKind, TaskConfig};
use crate::error::Result;
use crate::stats::OutputStats;

/// Destination for an assembled datagram.
///
/// Abstracted from the raw socket so an output's send/retry/stats state machine
/// can be unit-tested without `CAP_NET_RAW`.
pub(crate) trait Egress: Send {
    fn send_to(&mut self, buf: &[u8]) -> std::io::Result<usize>;
}

/// The production [`Egress`]: a real socket sending to a fixed peer.
pub(crate) struct RawSocketEgress {
    pub(crate) socket: Socket,
    pub(crate) remote: SocketAddr,
}

impl Egress for RawSocketEgress {
    fn send_to(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(buf, &self.remote.into())
    }
}

/// Minimal packet metadata passed to outputs (replaces `struct pcap_pkthdr`).
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Capture timestamp, seconds.
    pub ts_sec: i64,
    /// Capture timestamp, microseconds.
    pub ts_usec: i64,
    /// Number of bytes captured.
    pub caplen: u32,
    /// Original packet length on the wire.
    pub len: u32,
}

impl PacketHeader {
    /// Capture timestamp as `(seconds, microseconds)`.
    #[must_use]
    pub fn ts(&self) -> (i64, i64) {
        (self.ts_sec, self.ts_usec)
    }
}

/// Common interface implemented by every output.
pub trait Output: Send {
    /// Forward one packet. `direct` is a `PKT_DIR_*` value; returns 0 on
    /// success or a negative value on drop.
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32;

    /// Periodic tick; outputs may emit heartbeats here.
    fn heartbeat(&mut self, _now: i64) {}

    /// Flush and release resources on shutdown.
    ///
    /// Called exactly once per output, by the single shutdown/reload call point
    /// [`crate::task::TaskManager::stop`]. Outputs must not rely on `Drop` for
    /// draining: `Box<dyn Output>` is released by the task manager, and the
    /// linger/flush semantics promised here only happen through this method.
    fn destroy(&mut self) {}
}

/// Construct an output from config. Mirrors `find_output_factory` dispatch in
/// `task.c`.
///
/// # Errors
/// Returns an error if the output type is unsupported or the output cannot be
/// created (e.g. socket bind or file open failure).
pub fn new_output(
    task: &TaskConfig,
    cfg: &OutputConfig,
    stats: Arc<OutputStats>,
) -> Result<Box<dyn Output>> {
    match &cfg.kind {
        OutputKind::Null => Ok(Box::new(null::NullOutput::new(cfg, stats))),
        OutputKind::File(c) => {
            file::FileOutput::new(c, &task.capturer.kind, stats).map(|o| Box::new(o) as _)
        }
        OutputKind::RotatingFile(c) => {
            rotating_file::RotatingFileOutput::new(c, &task.capturer.kind, stats)
                .map(|o| Box::new(o) as _)
        }
        OutputKind::Gre(c) => gre::GreOutput::new(c, cfg, stats).map(|o| Box::new(o) as _),
        OutputKind::Vxlan(c) => vxlan::VxlanOutput::new(c, cfg, stats).map(|o| Box::new(o) as _),
        OutputKind::Zmq(c) => zmq::ZmqOutput::new(c, cfg, stats).map(|o| Box::new(o) as _),
    }
}
