//! Offline pcap-file capturer (pure Rust). Port of `pcap_file.c`.
//!
//! Reads the classic pcap format directly; no libpcap linkage. Both byte orders
//! and microsecond/nanosecond timestamp resolutions are supported.
//!
//! The reader is *validating*: a file whose global header or record headers are
//! not what a pcap savefile promises (wrong link type, `caplen > len`, a
//! caplen beyond the bound below, a pcap version we cannot interpret) is
//! rejected with an error instead of being replayed as garbage frames — see
//! AUDIT4 P5-20.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::sync::Arc;

use super::{Capturer, PacketHeader, PacketSink};
use crate::bpf::{self, Program};
use crate::config::{bpf_filter_exclude_task_output_hosts, PcapFileConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::netutil::bpf_filter_replace_nic;
use crate::output::pcap_writer::DLT_EN10MB;
use crate::packet::PKT_DIR_NONCHECK;
use crate::req_pattern::ReqPattern;
use crate::stats::CaptureStats;

/// Upper bound on a single record's captured length.
///
/// It is deliberately *not* `u32::MAX`-ish: a corrupt (or hostile) record
/// header used to be able to make the reader reserve 256 MiB in one `resize`
/// and keep it for the lifetime of the task, while a real frame never exceeds
/// one of these bounds:
///
/// * libpcap's own maximum snapshot length is 262144 bytes, which is also what
///   [`TaskConfig`] reports for offline replay ([`CapturerKind::snaplen`]);
/// * the largest frame any link layer we accept can put on the wire is far
///   below it.
///
/// Anything larger is treated as a corrupt file, not as a big packet.
pub const MAX_CAPLEN: u32 = 262_144;

/// One record must never be able to reserve an unreasonable amount of memory:
/// raising the bound above a megabyte would re-introduce AUDIT4 P5-20, so it is
/// checked at compile time as well as behaviourally in `bounds_one_record_allocation`.
const _: () = assert!(
    MAX_CAPLEN <= 1 << 20,
    "MAX_CAPLEN must stay far below 256 MiB"
);

/// Largest interpreted pcap `version_major`. libpcap refuses files above 2 as
/// well; 2.x covers every writer we have seen (2.4 being the common one).
const MAX_VERSION_MAJOR: u16 = 2;

/// Human-readable hint for the link types that most often show up in files
/// this reader refuses.
fn linktype_hint(linktype: u32) -> &'static str {
    match linktype {
        113 | 276 => " produced by `tcpdump -i any`; re-capture on a single interface",
        0 => " BSD loopback (`dbdump`/`lo` captures)",
        12 => " raw IPv4/IPv6 without an Ethernet header",
        105 | 104 => " 802.11 radiotap/prism captures",
        _ => "",
    }
}

/// Reader for the classic pcap savefile format: a 24-byte global header
/// followed by `16-byte record header + payload` blocks.
///
/// The reader is generic over the byte source on purpose: the same parsing code
/// that replays a [`File`] also drives the unit tests (from a [`std::io::Cursor`])
/// and the `pcap_reader` fuzz target, so malformed input can be exercised
/// without touching the filesystem (AUDIT4 P5-20).
#[derive(Debug)]
pub struct PcapReader<R> {
    r: R,
    /// Source name, used in diagnostics.
    src: String,
    swap: bool,
    nanos: bool,
    /// Link-layer header type of the file; always [`DLT_EN10MB`] after a
    /// successful [`PcapReader::open`] / [`PcapReader::from_reader`].
    pub linktype: u32,
    /// Timestamp (seconds part) of the record returned by the last
    /// successful [`PcapReader::next_record`].
    pub ts_sec: i64,
    /// Timestamp (microseconds part; a nanosecond file is scaled down) of the
    /// record returned by the last successful [`PcapReader::next`].
    pub ts_usec: i64,
    /// Captured length of the last record; `data.len() == caplen`.
    pub caplen: u32,
    /// Length the frame had on the wire (>= `caplen`).
    pub len: u32,
    /// Payload of the last record.
    pub data: Vec<u8>,
    /// `Some(caplen)` when the file stopped in the middle of a record, i.e. the
    /// record promised `caplen` bytes and the source ended earlier. `None` for a
    /// clean end of file. The *parser* stays silent; reporting is the
    /// capturer's job.
    pub truncated: Option<u32>,
}

impl PcapReader<BufReader<File>> {
    /// Open a pcap savefile for replay.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened, if the global header is
    /// truncated, if its version is not understood, or if its link type is not
    /// Ethernet.
    pub fn open(path: &str) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| Error::new(format!("could not load file {path}: {e}")))?;
        Self::from_reader(path, BufReader::new(file))
    }
}

impl<R: Read> PcapReader<R> {
    /// Read and validate the global header from a byte source.
    ///
    /// `src` only names the source in error messages (file path, "fuzz input",
    /// …).
    ///
    /// # Errors
    /// Returns an error if the global header is truncated, if its magic is not
    /// one of the four pcap magics, if `version_major` exceeds 2, or if
    /// `network` (the link type) is not [`DLT_EN10MB`].
    pub fn from_reader(src: impl Into<String>, mut r: R) -> Result<Self> {
        let src = src.into();
        let mut ghdr = [0u8; 24];
        if r.read_exact(&mut ghdr).is_err() {
            return Err(Error::new(format!("{src}: truncated pcap global header")));
        }
        // The magic is written in the file's byte order.
        let (swap, nanos) = match [ghdr[0], ghdr[1], ghdr[2], ghdr[3]] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false), // little-endian, usec
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),  // big-endian, usec
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),  // little-endian, nsec
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),   // big-endian, nsec
            m => return Err(Error::new(format!("{src}: bad pcap magic {m:02x?}"))),
        };
        let rd16 = |b: &[u8]| {
            let v = u16::from_le_bytes([b[0], b[1]]);
            if swap {
                v.swap_bytes()
            } else {
                v
            }
        };
        let rd32 = |b: &[u8]| {
            let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            if swap {
                v.swap_bytes()
            } else {
                v
            }
        };

        let version_major = rd16(&ghdr[4..6]);
        if version_major > MAX_VERSION_MAJOR {
            return Err(Error::new(format!(
                "{src}: unsupported pcap version {version_major}.{} (only 0..={MAX_VERSION_MAJOR} is understood)",
                rd16(&ghdr[6..8])
            )));
        }
        // `network` — the link-layer type. Replaying a file with any other
        // link type as Ethernet silently mis-parses every frame (a
        // `tcpdump -i any` capture is DLT_LINUX_SLL and would be forwarded
        // with a 4-byte offset), so refuse it up front.
        let linktype = rd32(&ghdr[20..24]);
        if linktype != DLT_EN10MB {
            return Err(Error::new(format!(
                "{src}: unsupported pcap linktype {linktype}: only Ethernet (DLT_EN10MB = {DLT_EN10MB}) can be replayed;{}",
                linktype_hint(linktype)
            )));
        }

        Ok(PcapReader {
            r,
            src,
            swap,
            nanos,
            linktype,
            ts_sec: 0,
            ts_usec: 0,
            caplen: 0,
            len: 0,
            data: Vec::new(),
            truncated: None,
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

    /// Read the next record into [`PcapReader::data`].
    ///
    /// Returns `Ok(false)` at a clean end of file (or when the last record is
    /// truncated by a file that stopped mid-frame), `Ok(true)` when a record
    /// was produced, and `Err` when the bytes are not a valid pcap record
    /// stream — a corrupt file must not be replayed as packets.
    ///
    /// # Errors
    /// Returns an error if the record header straddles a read that fails, if
    /// `caplen` exceeds [`MAX_CAPLEN`], or if `caplen` exceeds the record's
    /// `orig_len`.
    pub fn next_record(&mut self) -> Result<bool> {
        let mut rec = [0u8; 16];
        // `read_exact` is required here: a plain `read()` may return fewer than
        // 16 bytes when the record header straddles the BufReader's internal
        // buffer boundary, which loses those bytes and corrupts the file
        // position for every subsequent record.
        match self.r.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(Error::new(format!("{}: read pcap record: {e}", self.src))),
        }
        let ts_sec = self.u32(&rec[0..4]) as i64;
        let mut ts_usec = self.u32(&rec[4..8]) as i64;
        if self.nanos {
            ts_usec /= 1_000;
        }
        let caplen = self.u32(&rec[8..12]);
        let len = self.u32(&rec[12..16]);

        // A record may capture less than the frame, never more.
        if caplen > len {
            return Err(Error::new(format!(
                "{}: pcap record caplen {caplen} exceeds orig_len {len} (corrupt file)",
                self.src
            )));
        }
        // Bound the allocation before touching the buffer.
        if caplen > MAX_CAPLEN {
            return Err(Error::new(format!(
                "{}: pcap record caplen {caplen} exceeds the {MAX_CAPLEN} byte limit (corrupt file)",
                self.src
            )));
        }

        self.data.resize(caplen as usize, 0);
        match self.r.read_exact(&mut self.data) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Silent on purpose: `PcapFileCapturer::capture_once` reports it
                // once per file. A parser that logs cannot be fuzzed (the
                // `pcap_reader` target would emit one line per input).
                self.truncated = Some(caplen);
                self.data.clear();
                return Ok(false);
            }
            Err(e) => return Err(Error::new(format!("{}: read pcap record: {e}", self.src))),
        }

        // Publish the record only once every check above has passed.
        self.ts_sec = ts_sec;
        self.ts_usec = ts_usec;
        self.caplen = caplen;
        self.len = len;
        Ok(true)
    }
}

/// Offline replay of packets from a pcap file.
pub struct PcapFileCapturer {
    stats: Arc<CaptureStats>,
    req_pattern: Option<ReqPattern>,
    reader: PcapReader<BufReader<File>>,
    program: Option<Program>,
    /// Set once the file is exhausted *or* rejected as corrupt: the capturer
    /// then keeps ticking without touching the reader again.
    stopped: bool,
}

impl PcapFileCapturer {
    /// Open an offline pcap file for replay.
    ///
    /// # Errors
    /// Returns an error if the req_pattern cannot be built, the BPF filter
    /// cannot be compiled, or the pcap file cannot be opened / is not an
    /// Ethernet pcap savefile.
    pub fn new(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &PcapFileConfig,
        stats: Arc<CaptureStats>,
    ) -> Result<Self> {
        let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, "")
            .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

        let reader = PcapReader::open(&cfg.file_name)?;

        let bpf_expr = bpf_filter_exclude_task_output_hosts(&cfg.bpf, tasks);
        let program =
            if bpf_expr.is_empty() {
                None
            } else {
                let bpf_expr = bpf_filter_replace_nic(&bpf_expr)?;
                Some(bpf::compile(&bpf_expr).map_err(|e| {
                    Error::new(format!("compile bpf filter '{bpf_expr}' error: {e}"))
                })?)
            };

        Ok(PcapFileCapturer {
            stats,
            req_pattern: Some(req_pattern),
            reader,
            program,
            stopped: false,
        })
    }
}

impl Capturer for PcapFileCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        // Skip frames rejected by the BPF filter, like `pcap_next_ex` does.
        loop {
            if self.stopped {
                sink.on_heartbeat();
                return 0;
            }
            match self.reader.next_record() {
                Ok(true) => {}
                Ok(false) => {
                    sink.on_heartbeat();
                    self.stopped = true;
                    if let Some(caplen) = self.reader.truncated {
                        crate::log_error!(
                            "{}: truncated pcap record (caplen {caplen} extends past the end of the file); replay stopped",
                            self.reader.src
                        );
                    } else {
                        crate::log_info!("end of file");
                    }
                    return 0;
                }
                Err(e) => {
                    // A corrupt file must stop the replay *and say so*: the old
                    // code fell through and forwarded the garbage bytes.
                    crate::log_error!("{e}");
                    self.stopped = true;
                    sink.on_heartbeat();
                    return 0;
                }
            }
            if let Some(p) = &self.program {
                if !p.apply(&self.reader.data) {
                    continue;
                }
            }
            break;
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
    use std::io::Cursor;

    use super::*;
    use crate::config::CapturerKind;
    use crate::stats::CaptureStats;

    /// `global_header(linktype)` builds a valid LE/microsecond global header.
    fn global_header(linktype: u32) -> [u8; 24] {
        let mut v = [0u8; 24];
        v[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic (LE, usec)
        v[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
        v[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
        v[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
        v[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
        v[16..20].copy_from_slice(&262144u32.to_le_bytes()); // snaplen
        v[20..24].copy_from_slice(&linktype.to_le_bytes()); // network
        v
    }

    fn record(caplen: u32, len: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
        v.extend_from_slice(&2u32.to_le_bytes()); // ts_usec
        v.extend_from_slice(&caplen.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cp-{}-{}.pcap", name, std::process::id()))
    }

    #[derive(Default)]
    struct Collect {
        pkts: Vec<Vec<u8>>,
    }

    impl PacketSink for Collect {
        fn on_packet(&mut self, _hdr: &PacketHeader, pkt: &[u8], _direct: i32) {
            self.pkts.push(pkt.to_vec());
        }
        fn on_heartbeat(&mut self) {}
    }

    /// Drive a capturer built straight from a byte image of a pcap file.
    fn replay(bytes: &[u8], tag: &str) -> Result<(PcapFileCapturer, std::path::PathBuf)> {
        let path = tmp(tag);
        std::fs::write(&path, bytes).expect("write pcap");
        let cfg = PcapFileConfig {
            file_name: path.to_str().unwrap().to_owned(),
            bpf: String::new(),
        };
        let task = TaskConfig {
            fingerprint: None,
            req_pattern: crate::config::ReqPatternConfig::None,
            capturer: crate::config::CapturerConfig {
                kind: CapturerKind::PcapFile(cfg.clone()),
            },
            outputs: Vec::new(),
        };
        PcapFileCapturer::new(
            std::slice::from_ref(&task),
            &task,
            &cfg,
            Arc::new(CaptureStats::default()),
        )
        .map(|c| (c, path))
    }

    #[test]
    fn pcap_roundtrip() {
        let path = tmp("roundtrip");
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
        assert!(r.next_record().expect("valid record"));
        assert_eq!(r.ts_sec, 1234);
        assert_eq!(r.ts_usec, 5678);
        assert_eq!(r.caplen, 4);
        assert_eq!(r.len, 60);
        assert_eq!(&r.data, &[1, 2, 3, 4]);
        assert!(!r.next_record().expect("clean eof"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pcap_reader_large_file_no_position_drift() {
        // Regression: the record header must be read with `read_exact`. A plain
        // `read()` returns fewer than 16 bytes when a header straddles the
        // BufReader's internal buffer boundary, losing those bytes and
        // corrupting the file position for every subsequent record. Only
        // manifests on files larger than the 8 KiB buffer.
        let path = tmp("big");
        let n = 1000usize;
        {
            let mut w =
                crate::output::pcap_writer::PcapWriter::create(&path, 65535).expect("create");
            for i in 0..n {
                let caplen = 64 + (i % 961); // 64..1024, so headers straddle the buffer
                let data = vec![0xA5u8; caplen];
                let hdr = PacketHeader {
                    ts_sec: 1,
                    ts_usec: i as i64,
                    caplen: caplen as u32,
                    len: caplen as u32,
                };
                w.write(&hdr, &data).expect("write");
            }
            w.flush().expect("flush");
        }
        let mut r = PcapReader::open(path.to_str().unwrap()).expect("open");
        for i in 0..n {
            assert!(
                r.next_record().expect("valid record"),
                "record {i} failed to read"
            );
            assert_eq!(
                r.caplen as usize,
                64 + (i % 961),
                "record {i} caplen drifted"
            );
            assert_eq!(r.ts_usec, i as i64, "record {i} timestamp drifted");
        }
        assert!(!r.next_record().expect("clean eof"));
        std::fs::remove_file(&path).ok();
    }

    /// AUDIT4 P5-20: a `tcpdump -i any` capture is DLT_LINUX_SLL (113); reading
    /// it as Ethernet replays every frame with a 4-byte offset (silent data
    /// corruption), so the global header's link type must be checked.
    #[test]
    fn rejects_non_ethernet_linktype() {
        for (linktype, name) in [
            (113u32, "DLT_LINUX_SLL"),
            (276, "DLT_LINUX_SLL2"),
            (0, "DLT_NULL"),
            (12, "DLT_RAW"),
            (105, "DLT_IEEE802_11_RADIO"),
            (0xffff_ffff, "garbage"),
        ] {
            let mut img = global_header(linktype).to_vec();
            img.extend_from_slice(&record(4, 4, &[1, 2, 3, 4]));
            let e = PcapReader::from_reader("t.pcap", Cursor::new(&img))
                .unwrap_err()
                .to_string();
            assert!(e.contains("linktype"), "{name}: {e}");
            assert!(e.contains(&linktype.to_string()), "{name}: {e}");
            // ... and the same refusal through the capturer entry point.
            let err = match replay(&img, "badlink") {
                Ok((_, path)) => {
                    std::fs::remove_file(&path).ok();
                    panic!("{name}: a non-Ethernet file was opened");
                }
                Err(e) => e.to_string(),
            };
            assert!(err.contains("linktype"), "{name}: {err}");
        }
        // Ethernet still opens.
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(4, 4, &[1, 2, 3, 4]));
        assert!(PcapReader::from_reader("t.pcap", Cursor::new(&img)).is_ok());
    }

    /// AUDIT4 P5-20: `caplen > orig_len` is impossible in a real capture; it
    /// used to be replayed as a frame with a lying header.
    #[test]
    fn rejects_caplen_larger_than_orig_len() {
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(20, 10, &[0u8; 20]));
        let mut r = PcapReader::from_reader("t.pcap", Cursor::new(&img)).expect("global header ok");
        let e = r.next_record().unwrap_err().to_string();
        assert!(e.contains("caplen 20 exceeds orig_len 10"), "{e}");

        // Through the capturer: nothing is forwarded and the replay stops.
        let (mut cap, path) = replay(&img, "capgtlen").expect("capturer");
        let mut sink = Collect::default();
        assert_eq!(cap.capture_once(&mut sink), 0, "corrupt record forwarded");
        assert!(sink.pkts.is_empty(), "corrupt record forwarded");
        // A well-formed record *after* the corrupt one is not replayed either.
        assert_eq!(cap.capture_once(&mut sink), 0);
        std::fs::remove_file(&path).ok();
    }

    /// AUDIT4 P5-20: the single-record allocation used to be bounded by
    /// 256 MiB, so one corrupt header reserved 256 MiB per task. The bound is
    /// now libpcap's own maximum snapshot length.
    #[test]
    fn bounds_one_record_allocation() {
        // Just above the bound: refused, and the buffer never grows.
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(MAX_CAPLEN + 1, MAX_CAPLEN + 1, &[7u8; 8]));
        let mut r = PcapReader::from_reader("t.pcap", Cursor::new(&img)).expect("header ok");
        let e = r.next_record().unwrap_err().to_string();
        assert!(e.contains("exceeds the"), "{e}");
        assert!(e.contains(&MAX_CAPLEN.to_string()), "{e}");
        assert!(
            r.data.is_empty(),
            "the oversized record was resized for anyway"
        );

        // The bound itself is still accepted.
        let mut img = global_header(DLT_EN10MB).to_vec();
        let big = vec![0x5Au8; MAX_CAPLEN as usize];
        img.extend_from_slice(&record(MAX_CAPLEN, MAX_CAPLEN, &big));
        let mut r = PcapReader::from_reader("t.pcap", Cursor::new(&img)).expect("header ok");
        assert!(r.next_record().expect("in-bounds record"));
        assert_eq!(r.data.len(), MAX_CAPLEN as usize);

        // And through the capturer: a bogus 200 MiB caplen is not forwarded.
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(200 * 1024 * 1024, 200 * 1024 * 1024, &[9u8; 4]));
        let (mut cap, path) = replay(&img, "hugecaplen").expect("capturer");
        let mut sink = Collect::default();
        assert_eq!(cap.capture_once(&mut sink), 0, "huge caplen forwarded");
        assert!(sink.pkts.is_empty());
        std::fs::remove_file(&path).ok();
    }

    /// AUDIT4 P5-20: pcap versions we cannot interpret must be refused rather
    /// than parsed with guessed field widths.
    #[test]
    fn rejects_unknown_pcap_version() {
        for major in [3u16, 4, 255, 0xffff] {
            let mut g = global_header(DLT_EN10MB);
            g[4..6].copy_from_slice(&major.to_le_bytes());
            let e = PcapReader::from_reader("t.pcap", Cursor::new(g.to_vec()))
                .unwrap_err()
                .to_string();
            assert!(e.contains("version"), "{major}: {e}");
        }
        // v2.4 and the older v1.0 files libpcap still reads are accepted.
        for major in [0u16, 1, 2] {
            let mut g = global_header(DLT_EN10MB);
            g[4..6].copy_from_slice(&major.to_le_bytes());
            assert!(
                PcapReader::from_reader("t.pcap", Cursor::new(g.to_vec())).is_ok(),
                "version major {major} must be accepted"
            );
        }
    }

    /// Truncation anywhere must end the replay cleanly (no packet with a lying
    /// length, no panic) — for the header *and* the payload.
    #[test]
    fn truncated_files_stop_without_forwarding_garbage() {
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(4, 4, &[1, 2, 3, 4]));
        // Every possible truncation point.
        for cut in 0..img.len() {
            let mut r = PcapReader::from_reader("t.pcap", Cursor::new(img[..cut].to_vec()))
                .map(Some)
                .unwrap_or(None);
            if let Some(r) = r.as_mut() {
                let res = r.next_record();
                match res {
                    Ok(true) => assert_eq!(r.data.len(), r.caplen as usize),
                    Ok(false) => {}
                    Err(e) => panic!("truncation at {cut} reported as corrupt: {e}"),
                }
            }
        }
    }

    /// AUDIT4 §3.4: parsing must not depend on how the source chunks its bytes.
    /// A `BufReader` with a 1-byte buffer forces every multi-byte read across
    /// the source boundary, which is exactly where the old `read()` bug lived.
    #[test]
    fn parsing_is_independent_of_read_chunking() {
        let mut img = global_header(DLT_EN10MB).to_vec();
        for i in 0..50u32 {
            let data: Vec<u8> = (0..(i * 7 % 300)).map(|b| b as u8).collect();
            img.extend_from_slice(&record(data.len() as u32, data.len() as u32, &data));
        }
        let mut plain = PcapReader::from_reader("t.pcap", Cursor::new(img.clone())).expect("open");
        let mut dribble = PcapReader::from_reader(
            "t.pcap",
            BufReader::with_capacity(1, Cursor::new(img.clone())),
        )
        .expect("open dribble");
        let mut n = 0;
        loop {
            let a = plain.next_record().expect("valid");
            let b = dribble.next_record().expect("valid");
            assert_eq!(a, b, "record {n}: disagreement between readers");
            if !a {
                break;
            }
            assert_eq!(plain.data, dribble.data, "record {n}: payload differs");
            assert_eq!(plain.caplen, dribble.caplen);
            assert_eq!(plain.len, dribble.len);
            assert_eq!(plain.ts_sec, dribble.ts_sec);
            assert_eq!(plain.ts_usec, dribble.ts_usec);
            n += 1;
        }
        assert_eq!(n, 50, "not every record was replayed");
    }

    /// All four magics (and the byte order they imply) must still decode.
    #[test]
    fn all_byte_orders_and_timestamp_resolutions_decode() {
        // (magic bytes as written, file is big-endian, nanosecond timestamps)
        for (magic, swap, nanos) in [
            ([0xd4u8, 0xc3, 0xb2, 0xa1], false, false),
            ([0xa1, 0xb2, 0xc3, 0xd4], true, false),
            ([0x4d, 0x3c, 0xb2, 0xa1], false, true),
            ([0xa1, 0xb2, 0x3c, 0x4d], true, true),
        ] {
            let put16 = |v: &mut [u8], i: usize, x: u16| {
                let b = if swap {
                    x.to_be_bytes()
                } else {
                    x.to_le_bytes()
                };
                v[i..i + 2].copy_from_slice(&b);
            };
            let put32 = |v: &mut [u8], i: usize, x: u32| {
                let b = if swap {
                    x.to_be_bytes()
                } else {
                    x.to_le_bytes()
                };
                v[i..i + 4].copy_from_slice(&b);
            };
            let mut g = [0u8; 24];
            g[0..4].copy_from_slice(&magic);
            put16(&mut g, 4, 2);
            put16(&mut g, 6, 4);
            put32(&mut g, 16, 262144);
            put32(&mut g, 20, DLT_EN10MB);

            let mut rec = [0u8; 16];
            put32(&mut rec, 0, 7); // ts_sec
            put32(&mut rec, 4, if nanos { 5_000 } else { 5 }); // ts_{usec,nsec}
            put32(&mut rec, 8, 3); // caplen
            put32(&mut rec, 12, 9); // orig_len
            let mut img = g.to_vec();
            img.extend_from_slice(&rec);
            img.extend_from_slice(&[0xA1, 0xA2, 0xA3]);

            let mut r = PcapReader::from_reader("t.pcap", Cursor::new(img))
                .unwrap_or_else(|e| panic!("magic {magic:02x?}: {e}"));
            assert!(r.next_record().expect("record"), "magic {magic:02x?}");
            assert_eq!(r.ts_sec, 7);
            assert_eq!(r.ts_usec, 5, "magic {magic:02x?} (ns scales to us)");
            assert_eq!(r.caplen, 3);
            assert_eq!(r.len, 9);
            assert_eq!(&r.data, &[0xA1, 0xA2, 0xA3]);
        }
    }

    /// Reporting belongs to the capturer, the parser stays silent (a logging
    /// parser cannot be fuzzed) - and a truncated file must be distinguishable
    /// from a clean end of file.
    #[test]
    fn truncation_is_reported_once_by_the_capturer() {
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(1000, 1000, &[0x33u8; 5])); // 995 bytes missing
        let mut r = PcapReader::from_reader("t.pcap", Cursor::new(img.clone())).expect("header");
        assert_eq!(r.truncated, None);
        assert!(!r.next_record().expect("truncation is EOF, not corruption"));
        assert_eq!(
            r.truncated,
            Some(1000),
            "the parser must record the promised caplen it could not fill"
        );
        assert!(r.data.is_empty(), "no partial record may be handed out");

        let (mut cap, path) = replay(&img, "truncated").expect("capturer");
        let mut sink = Collect::default();
        assert_eq!(cap.capture_once(&mut sink), 0);
        assert!(sink.pkts.is_empty());
        std::fs::remove_file(&path).ok();

        // A whole file is a clean "end of file" instead.
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(2, 2, &[1, 2]));
        let (mut cap, path) = replay(&img, "clean").expect("capturer");
        let mut sink = Collect::default();
        assert_eq!(cap.capture_once(&mut sink), 1);
        assert_eq!(cap.capture_once(&mut sink), 0);
        assert_eq!(cap.reader.truncated, None, "clean end of file");
        std::fs::remove_file(&path).ok();
    }

    /// A record header whose bytes are pure garbage must never be published.
    #[test]
    fn corrupt_record_header_leaves_the_previous_record_intact() {
        let mut img = global_header(DLT_EN10MB).to_vec();
        img.extend_from_slice(&record(2, 2, &[0xDE, 0xAD]));
        img.extend_from_slice(&[0xffu8; 16]); // nonsense header
        let mut r = PcapReader::from_reader("t.pcap", Cursor::new(img)).expect("header");
        assert!(r.next_record().expect("first record"));
        assert_eq!(&r.data, &[0xDE, 0xAD]);
        assert!(r.next_record().is_err(), "garbage header was accepted");
        assert_eq!(
            &r.data,
            &[0xDE, 0xAD],
            "fields must not be overwritten by a rejected record"
        );
    }
}
