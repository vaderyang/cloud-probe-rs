//! Offline pcap-file capturer (pure Rust). Port of `pcap_file.c`.
//!
//! Reads the classic pcap format directly; no libpcap linkage. Both byte orders
//! and microsecond/nanosecond timestamp resolutions are supported.

use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;

use super::{Capturer, PacketHeader, PacketSink};
use crate::config::{bpf_filter_exclude_task_output_hosts, PcapFileConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::netutil::bpf_filter_replace_nic;
use crate::packet::PKT_DIR_NONCHECK;
use crate::req_pattern::ReqPattern;
use crate::stats::CaptureStats;

/// Upper bound on a single record's captured length, to bound allocations on a
/// corrupt file.
const MAX_CAPLEN: u32 = 256 * 1024 * 1024;

struct PcapReader {
    r: BufReader<File>,
    swap: bool,
    nanos: bool,
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
    data: Vec<u8>,
}

impl PcapReader {
    fn open(path: &str) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| Error::new(format!("could not load file {path}: {e}")))?;
        let mut r = BufReader::new(file);
        let mut ghdr = [0u8; 24];
        if r.read_exact(&mut ghdr).is_err() {
            return Err(Error::new(format!("{path}: truncated pcap global header")));
        }
        // The magic is written in the file's byte order.
        let (swap, nanos) = match [ghdr[0], ghdr[1], ghdr[2], ghdr[3]] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false), // little-endian, usec
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),  // big-endian, usec
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),  // little-endian, nsec
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),   // big-endian, nsec
            m => return Err(Error::new(format!("{path}: bad pcap magic {m:02x?}"))),
        };
        Ok(PcapReader {
            r,
            swap,
            nanos,
            ts_sec: 0,
            ts_usec: 0,
            caplen: 0,
            len: 0,
            data: Vec::new(),
        })
    }

    fn u32(&self, b: &[u8]) -> u32 {
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if self.swap {
            v.swap_bytes()
        } else {
            v
        }
    }

    /// Read the next record into `self.data`. Returns `false` at end of file.
    fn next(&mut self) -> bool {
        let mut rec = [0u8; 16];
        match self.r.read(&mut rec) {
            Ok(16) => {}
            _ => return false, // EOF or truncated header
        }
        self.ts_sec = self.u32(&rec[0..4]) as i64;
        let mut ts = self.u32(&rec[4..8]) as i64;
        if self.nanos {
            ts /= 1000;
        }
        self.ts_usec = ts;
        let incl = self.u32(&rec[8..12]);
        self.len = self.u32(&rec[12..16]);
        if incl > MAX_CAPLEN {
            crate::log_error!("pcap record caplen {incl} exceeds limit; stopping");
            return false;
        }
        self.caplen = incl;
        self.data.resize(incl as usize, 0);
        if self.r.read_exact(&mut self.data).is_err() {
            return false; // truncated record
        }
        true
    }
}

/// Offline replay of packets from a pcap file.
pub struct PcapFileCapturer {
    stats: Arc<CaptureStats>,
    req_pattern: Option<ReqPattern>,
    reader: PcapReader,
    eof: bool,
}

impl PcapFileCapturer {
    /// Open an offline pcap file for replay.
    ///
    /// # Errors
    /// Returns an error if the req_pattern cannot be built or the pcap file
    /// cannot be opened.
    pub fn new(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &PcapFileConfig,
        stats: Arc<CaptureStats>,
    ) -> Result<Self> {
        let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, "")
            .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

        let reader = PcapReader::open(&cfg.file_name)?;

        let bpf = bpf_filter_exclude_task_output_hosts(&cfg.bpf, tasks);
        if !bpf.is_empty() {
            let bpf = bpf_filter_replace_nic(&bpf)?;
            // TODO(P3): apply the pure-Rust BPF filter once the compiler lands.
            crate::log_warn!("pcap_file BPF filter not yet applied (pure-Rust migration): {bpf}");
        }

        Ok(PcapFileCapturer {
            stats,
            req_pattern: Some(req_pattern),
            reader,
            eof: false,
        })
    }
}

impl Capturer for PcapFileCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        if !self.reader.next() {
            sink.on_heartbeat();
            if !self.eof {
                crate::log_info!("end of file");
                self.eof = true;
            }
            return 0;
        }

        let hdr = PacketHeader {
            ts_sec: self.reader.ts_sec,
            ts_usec: self.reader.ts_usec,
            caplen: self.reader.caplen,
            len: self.reader.len,
        };
        let direction = match &self.req_pattern {
            None => PKT_DIR_NONCHECK,
            Some(rp) => rp.judge_pkt_direction(&self.reader.data),
        };
        self.stats.cap_bytes.add(hdr.caplen as u64);
        self.stats.cap_packets.add(1);
        sink.on_packet(&hdr, &self.reader.data, direction);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_roundtrip() {
        let path = std::env::temp_dir().join(format!("cp-pcap-{}.pcap", std::process::id()));
        {
            let mut w =
                crate::output::pcap_writer::PcapWriter::create(&path, 65535).expect("create");
            let hdr = PacketHeader {
                ts_sec: 1234,
                ts_usec: 5678,
                caplen: 4,
                len: 60,
            };
            w.write(&hdr, &[1, 2, 3, 4]).expect("write");
            w.flush().expect("flush");
        }
        let mut r = PcapReader::open(path.to_str().unwrap()).expect("open");
        assert!(r.next());
        assert_eq!(r.ts_sec, 1234);
        assert_eq!(r.ts_usec, 5678);
        assert_eq!(r.caplen, 4);
        assert_eq!(r.len, 60);
        assert_eq!(&r.data, &[1, 2, 3, 4]);
        assert!(!r.next());
        std::fs::remove_file(&path).ok();
    }
}
