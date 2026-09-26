//! Capturer pipeline. Port of `capturer.h`, `libpcap.c`, `pcap_file.c`.

pub mod libpcap;
pub mod pcap_file;

use std::sync::Arc;

use crate::config::{CapturerKind, TaskConfig};
use crate::error::{Error, Result};
use crate::stats::CaptureStats;

pub use crate::output::PacketHeader;

/// Sink receiving captured packets and heartbeat ticks.
pub trait PacketSink {
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32);
    fn on_heartbeat(&mut self);
}

/// A packet source. `capture_once` processes at most one packet / tick and
/// returns the number of packets delivered.
pub trait Capturer: Send {
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
            libpcap::LibpcapCapturer::new(tasks, task, c, stats).map(|c| Box::new(c) as _)
        }
        CapturerKind::PcapFile(c) => {
            pcap_file::PcapFileCapturer::new(tasks, task, c, stats).map(|c| Box::new(c) as _)
        }
        CapturerKind::DpdkPdump(_) => Err(Error::new(
            "dpdk_pdump capturer not supported: rebuild with the DPDK feature",
        )),
    }
}
