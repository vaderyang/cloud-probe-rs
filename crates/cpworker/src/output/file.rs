//! Single-file pcap output. Port of `output_file.c`.

use std::sync::Arc;

use super::pcap_writer::PcapWriter;
use super::{Output, PacketHeader};
use crate::config::{CapturerKind, FileConfig, OutputConfig};
use crate::error::Result;
use crate::packet::PKT_DIR_UNKNOWN;
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

/// Single pcap file output.
pub struct FileOutput {
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,
    writer: PcapWriter,
}

impl FileOutput {
    /// Create a pcap file output.
    ///
    /// # Errors
    /// Returns an error if the output file cannot be created.
    pub fn new(
        cfg: &FileConfig,
        out: &OutputConfig,
        capturer: &CapturerKind,
        stats: Arc<OutputStats>,
    ) -> Result<Self> {
        let snaplen = file_output_snaplen(capturer.snaplen(), out.slice);
        let writer = PcapWriter::create(std::path::Path::new(&cfg.name), snaplen)?;
        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };
        Ok(FileOutput {
            stats,
            throttle,
            slice: out.slice,
            writer,
        })
    }
}

/// Port of `file_output_snaplen`: a positive `slice` smaller than the capturer
/// snaplen also shrinks the savefile's advertised snapshot length.
#[must_use]
pub fn file_output_snaplen(snaplen: i32, slice: i32) -> i32 {
    if slice > 0 && slice < snaplen {
        slice
    } else {
        snaplen
    }
}

impl Output for FileOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
        // A sliced record keeps the wire length in len, as pcap-savefile(5)
        // describes (port of the `hdr.caplen = output->slice` step).
        let mut caplen = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < caplen {
            caplen = self.slice as u32;
        }

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(caplen as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        if let Some(tb) = self.throttle.as_mut() {
            if !tb.consume(caplen as usize, hdr.ts()) {
                self.stats.ratelimit_drop_bytes.add(caplen as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        let out_hdr = PacketHeader { caplen, ..*hdr };
        if let Err(e) = self.writer.write(&out_hdr, pkt) {
            crate::log_error!("write pcap output failed: {e}");
        }
        self.stats.fwd_bytes.add(caplen as u64);
        self.stats.fwd_packets.add(1);
        0
    }

    fn destroy(&mut self) {
        if let Err(e) = self.writer.flush() {
            crate::log_error!("flush pcap output failed: {e}");
        }
    }
}
