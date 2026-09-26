//! Single-file pcap output. Port of `output_file.c`.

use std::sync::Arc;

use super::pcap_writer::PcapWriter;
use super::{Output, PacketHeader};
use crate::config::{CapturerKind, FileConfig};
use crate::error::Result;
use crate::packet::PKT_DIR_UNKNOWN;
use crate::stats::OutputStats;

pub struct FileOutput {
    stats: Arc<OutputStats>,
    writer: PcapWriter,
}

impl FileOutput {
    /// Create a pcap file output.
    ///
    /// # Errors
    /// Returns an error if the output file cannot be created.
    pub fn new(cfg: &FileConfig, capturer: &CapturerKind, stats: Arc<OutputStats>) -> Result<Self> {
        let snaplen = capturer.snaplen();
        let writer = PcapWriter::create(std::path::Path::new(&cfg.name), snaplen)?;
        Ok(FileOutput { stats, writer })
    }
}

impl Output for FileOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(hdr.caplen as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }
        self.writer.write(hdr, pkt);
        self.stats.fwd_bytes.add(hdr.caplen as u64);
        self.stats.fwd_packets.add(1);
        0
    }

    fn destroy(&mut self) {
        self.writer.flush();
    }
}
