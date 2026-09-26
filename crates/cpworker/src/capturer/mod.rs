//! Capturer pipeline. Port of `capturer.h`, `libpcap.c`, `pcap_file.c`.

#[cfg(target_os = "linux")]
pub mod af_packet;
pub mod pcap_file;

use std::sync::Arc;

use crate::config::{CapturerKind, TaskConfig};
use crate::error::{Error, Result};
use crate::stats::CaptureStats;

pub use crate::output::PacketHeader;

/// Sink receiving captured packets and heartbeat ticks.
pub trait PacketSink {
    /// Deliver one captured packet. `direct` is a `PKT_DIR_*` value.
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32);
    /// Called periodically so the sink can emit heartbeats.
    fn on_heartbeat(&mut self);
}

/// A packet source. `capture_once` processes at most one packet / tick and
/// returns the number of packets delivered.
pub trait Capturer: Send {
    /// Capture at most one packet / tick, delivering it to `sink`.
    /// Returns the number of packets delivered.
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64;
}

/// Construct a capturer. Mirrors `find_capturer_factory` dispatch in `task.c`.
///
/// # Errors
/// Returns an error if the capturer type is unsupported or the underlying
/// capturer cannot be created (e.g. interface open failure).
pub fn new_capturer(
    tasks: &[TaskConfig],
    task: &TaskConfig,
    stats: Arc<CaptureStats>,
) -> Result<Box<dyn Capturer>> {
    match &task.capturer.kind {
        CapturerKind::Libpcap(c) => {
            #[cfg(target_os = "linux")]
            {
                af_packet::AfPacketCapturer::new(tasks, task, c, stats).map(|c| Box::new(c) as _)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (tasks, task, c, stats);
                Err(Error::new("live capture is not supported on this platform"))
            }
        }
        CapturerKind::PcapFile(c) => {
            pcap_file::PcapFileCapturer::new(tasks, task, c, stats).map(|c| Box::new(c) as _)
        }
        CapturerKind::DpdkPdump(_) => Err(Error::new(
            "dpdk_pdump capturer not supported: rebuild with the DPDK feature",
        )),
    }
}
