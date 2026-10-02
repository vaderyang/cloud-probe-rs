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
    /// Packets the savefile refused. Non-zero latches the output: the failing
    /// write stays parked in [`PcapWriter`]'s buffer, so the file cannot be
    /// recovered by retrying, and per-packet retries produced 898 identical log
    /// lines for 1000 packets written to `/dev/full` (cloud-probe-rs-5bh).
    /// Counted, not just logged, so the loss is visible in `error_drop_*`.
    write_failures: u64,
    /// Bytes/packets handed to `writer` since the last successful flush. A
    /// failing flush at `destroy()` is the only chance to charge them back,
    /// because [`PcapWriter`] does not expose how much of it is still buffered.
    unflushed_bytes: u64,
    unflushed_packets: u64,
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
            write_failures: 0,
            unflushed_bytes: 0,
            unflushed_packets: 0,
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

        // Counting rule (cloud-probe-rs-5bh): `fwd_*` means "the record was
        // accepted by the writer", *not* "the record is on disk" - `PcapWriter`
        // buffers, so a counted packet can still be lost by a later flush
        // failure. That failure is charged to `error_drop_*` in `destroy()`, so
        // the two counters overlap for exactly the records that never made it
        // out, instead of one of them silently claiming success.
        if self.write_failures > 0 {
            // Latched: the file is gone as far as this run is concerned, so drop
            // without touching (or re-failing on) the writer, and without
            // re-logging the same error per packet.
            self.write_failures += 1;
            self.stats.error_drop_bytes.add(caplen as u64);
            self.stats.error_drop_packets.add(1);
            return -1;
        }

        let out_hdr = PacketHeader { caplen, ..*hdr };
        match self.writer.write(&out_hdr, pkt) {
            Ok(()) => {
                self.stats.fwd_bytes.add(caplen as u64);
                self.stats.fwd_packets.add(1);
                self.unflushed_bytes = self.unflushed_bytes.saturating_add(caplen as u64);
                self.unflushed_packets = self.unflushed_packets.saturating_add(1);
                0
            }
            Err(e) => {
                // The C oracle cannot do this: `pcap_dump()` is void, so
                // `output_file.c` counts every packet as forwarded no matter
                // what the dumper thought (this is a deliberate divergence).
                self.write_failures = 1;
                crate::log_error!(
                    "write pcap output failed, dropping this and every \
                                   further packet: {e}"
                );
                self.stats.error_drop_bytes.add(caplen as u64);
                self.stats.error_drop_packets.add(1);
                -1
            }
        }
    }

    fn destroy(&mut self) {
        // `BufWriter::drop` swallows a failing flush, so this call is the only
        // place the buffered tail can still be reported. The charge is an upper
        // bound on the loss (the buffer may already have spilled part of it to
        // the OS), which is still honest compared with the old behaviour where
        // a lost file left nothing behind but a log line.
        if let Err(e) = self.writer.flush() {
            crate::log_error!("flush pcap output failed: {e}");
            self.stats.error_drop_bytes.add(self.unflushed_bytes);
            self.stats.error_drop_packets.add(self.unflushed_packets);
            self.unflushed_bytes = 0;
            self.unflushed_packets = 0;
        }
        if self.write_failures > 0 {
            crate::log_error!(
                "pcap output: {} packets dropped because the savefile could not be written",
                self.write_failures
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OutputKind, PcapFileConfig};

    fn file_output(name: &str, stats: Arc<OutputStats>) -> FileOutput {
        let cfg = FileConfig { name: name.into() };
        let out = OutputConfig {
            kind: OutputKind::File(cfg.clone()),
            rate_limit_mbps: 0,
            slice: 0,
        };
        let capturer = CapturerKind::PcapFile(PcapFileConfig {
            file_name: String::new(),
            bpf: String::new(),
        });
        FileOutput::new(&cfg, &out, &capturer, stats).expect("create file output")
    }

    fn hdr(len: u32) -> PacketHeader {
        PacketHeader {
            ts_sec: 1_700_000_000,
            ts_usec: 0,
            caplen: len,
            len,
        }
    }

    fn packets(s: &crate::stats::PacketsStats) -> u64 {
        s.load().0
    }

    fn bytes(s: &crate::stats::BytesStats) -> u64 {
        s.load().0
    }

    /// cloud-probe-rs-5bh: a savefile that refuses every write used to be
    /// reported as a perfect run - 898 write errors in the log, and
    /// `fwd_packets=1000, error_drop_packets=0`. Every packet must land in
    /// exactly one of the two counters, and the error must be logged once.
    #[test]
    fn a_failing_savefile_is_counted_as_dropped_not_forwarded() {
        if !std::path::Path::new("/dev/full").exists() {
            return; // not a Linux dev box; nothing to fail the write against
        }
        let stats = Arc::new(OutputStats::default());
        let mut out = file_output("/dev/full", stats.clone());
        let body = vec![0xa5u8; 64];

        const N: u64 = 1000;
        let mut accepted = 0u64;
        for _ in 0..N {
            if out.send_packet(&hdr(body.len() as u32), &body, 1) == 0 {
                accepted += 1;
            }
        }

        // Some records fit the writer's buffer before the first error surfaces,
        // but not all of them: the whole point of the bug was "no error at all".
        assert!(accepted > 0, "the buffered records before the first error");
        assert!(accepted < N, "the write must fail for /dev/full");
        assert_eq!(
            packets(&stats.fwd_packets),
            accepted,
            "only the records the writer accepted may count as forwarded"
        );
        assert_eq!(
            packets(&stats.error_drop_packets),
            N - accepted,
            "a failed write is a drop, not a forward"
        );
        assert_eq!(bytes(&stats.error_drop_bytes), (N - accepted) * 64);
        assert_eq!(
            packets(&stats.fwd_packets) + packets(&stats.error_drop_packets),
            N,
            "every packet is either forwarded or dropped, never both-unaccounted"
        );
        // Latched: one log line for the first failure, not one per packet
        // (the repro printed 898).
        assert_eq!(
            out.write_failures,
            N - accepted,
            "the latch keeps counting after the first failure"
        );

        out.destroy();
        // The buffered records never reached /dev/full either, so destroy()
        // charges them too: 1000 packets forwarded into a file that holds
        // nothing must show up as 1000 packets lost.
        assert_eq!(packets(&stats.error_drop_packets), N);
        assert_eq!(bytes(&stats.error_drop_bytes), N * 64);
    }

    /// The latch must not be a lie in the other direction: a healthy file still
    /// counts every packet as forwarded and loses nothing.
    #[test]
    fn a_writable_file_still_forwards_every_packet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.pcap");
        let stats = Arc::new(OutputStats::default());
        let mut out = file_output(path.to_str().expect("utf-8 path"), stats.clone());

        let body = vec![0x5au8; 64];
        for i in 0..50u64 {
            let h = PacketHeader {
                ts_sec: 1_700_000_000 + i as i64,
                ..hdr(body.len() as u32)
            };
            assert_eq!(out.send_packet(&h, &body, 1), 0);
        }
        out.destroy();

        assert_eq!(packets(&stats.fwd_packets), 50);
        assert_eq!(bytes(&stats.fwd_bytes), 50 * 64);
        assert_eq!(packets(&stats.error_drop_packets), 0);
        assert_eq!(bytes(&stats.error_drop_bytes), 0);
        // destroy() flushed the buffered records instead of charging them.
        let on_disk = std::fs::metadata(&path).expect("stat").len();
        assert_eq!(on_disk, 24 + 50 * (16 + 64));
    }
}
