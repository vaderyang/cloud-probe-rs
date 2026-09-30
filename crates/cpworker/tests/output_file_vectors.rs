//! Ports of upstream `cpworker/tests/unit/output_file.c`.
//!
//! The C vectors construct a `file_output_t` / `rotating_file_output_t` directly
//! and drive `send_packet`, then reopen the produced savefile. The Rust port has
//! the same seam (`FileOutput` / `RotatingFileOutput`, reached through
//! [`new_output`]), so each `#[test]` below names its C counterpart and asserts
//! the same bytes, counters and file layout.
//!
//! These vectors pin production behaviour the initial port had dropped:
//! `slice` truncates the record (`caplen`, not `len`, and the advertised
//! savefile snaplen) and `rate_limit_mbps` drops frames through the token
//! bucket. `test_file_no_slice_keeps_capture_snaplen` and
//! `test_file_no_rate_limit_writes_everything` are the controls.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpworker::config::Config;
use cpworker::output::{new_output, Output, PacketHeader};
use cpworker::packet::PKT_DIR_NONCHECK;
use cpworker::stats::OutputStats;

/// C `SNAPLEN`.
const SNAPLEN: i32 = 65535;
/// Rate-limit scenario: 1000 x 1250-byte frames, 5 ms apart = 10 Mbit over 5 s.
const RL_FRAMES: usize = 1000;
const RL_FRAME_LEN: u32 = 1250;
const RL_GAP_USEC: i64 = 5000;
const RL_MBPS: u64 = 1;

/// `setUp()` fills the frame with `frame[i] = i as u8`.
fn frame_bytes() -> Vec<u8> {
    (0..1600u32).map(|i| i as u8).collect()
}

fn parse_config(capturer_snaplen: i32, output: serde_json::Value) -> Config {
    let cfg = serde_json::json!({
        "tasks": [{
            "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": capturer_snaplen}},
            "outputs": [output]
        }]
    });
    Config::parse_str(&cfg.to_string()).expect("parse config")
}

fn build(cfg: &Config, stats: Arc<OutputStats>) -> Box<dyn Output> {
    new_output(&cfg.tasks[0], &cfg.tasks[0].outputs[0], stats).expect("build output")
}

/// `new_file_output()`.
fn new_file_output(
    dir: &Path,
    slice: i32,
    rate_limit_mbps: u64,
) -> (Box<dyn Output>, PathBuf, Arc<OutputStats>) {
    let path = dir.join("out.pcap");
    let cfg = parse_config(
        SNAPLEN,
        serde_json::json!({
            "type": "file",
            "file": {"name": path.display().to_string()},
            "slice": slice,
            "rate_limit_mbps": rate_limit_mbps
        }),
    );
    let stats = Arc::new(OutputStats::default());
    let out = build(&cfg, stats.clone());
    (out, path, stats)
}

/// `new_rotating_output()` (the two `test_rotating_*` cases inside
/// `output_file.c`); interval 3600 so every packet lands in one dump.
fn new_rotating_output(
    dir: &Path,
    slice: i32,
    rate_limit_mbps: u64,
) -> (Box<dyn Output>, Arc<OutputStats>) {
    let cfg = parse_config(
        SNAPLEN,
        serde_json::json!({
            "type": "rotating_file",
            "rotating_file": {"file_root": dir.display().to_string(), "max_file_interval": 3600},
            "slice": slice,
            "rate_limit_mbps": rate_limit_mbps
        }),
    );
    let stats = Arc::new(OutputStats::default());
    let out = build(&cfg, stats.clone());
    (out, stats)
}

fn collect_pcaps(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_pcaps(&path, out);
        } else if path.extension().is_some_and(|x| x == "pcap") {
            out.push(path);
        }
    }
}

/// `rotating_file_path()`: the single `*/*.pcap` under `dir`.
fn rotating_file_path(dir: &Path) -> PathBuf {
    let mut found = Vec::new();
    collect_pcaps(dir, &mut found);
    assert_eq!(found.len(), 1, "expected one dump under {}", dir.display());
    found.pop().unwrap()
}

struct PcapSummary {
    snaplen: u32,
    count: usize,
    written_bits: u64,
    first: Option<(i64, i64, u32, u32, Vec<u8>)>,
}

/// `read_pcap()`: the parsed global header and every record, with no libpcap.
fn read_pcap(path: &Path) -> PcapSummary {
    let bytes = std::fs::read(path).expect("read pcap");
    assert!(bytes.len() >= 24, "truncated pcap global header");
    let snaplen = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let mut off = 24;
    let mut count = 0;
    let mut written_bits = 0u64;
    let mut first = None;
    while off + 16 <= bytes.len() {
        let ts_sec = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as i64;
        let ts_usec = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as i64;
        let caplen = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[off + 12..off + 16].try_into().unwrap());
        off += 16;
        let data = bytes[off..off + caplen as usize].to_vec();
        off += caplen as usize;
        if first.is_none() {
            first = Some((ts_sec, ts_usec, caplen, len, data));
        }
        count += 1;
        written_bits += caplen as u64 * 8;
    }
    PcapSummary {
        snaplen,
        count,
        written_bits,
        first,
    }
}

/// `make_hdr()`.
fn make_hdr(len: u32, usec_offset: i64) -> PacketHeader {
    PacketHeader {
        ts_sec: 1_700_000_000 + usec_offset / 1_000_000,
        ts_usec: usec_offset % 1_000_000,
        caplen: len,
        len,
    }
}

/// `send_one()`.
fn send_one(out: &mut dyn Output, len: u32) {
    let frame = frame_bytes();
    let hdr = make_hdr(len, 0);
    assert_eq!(out.send_packet(&hdr, &frame, PKT_DIR_NONCHECK), 0);
}

/// `send_rate_limit_burst()`.
fn send_rate_limit_burst(out: &mut dyn Output) {
    let frame = frame_bytes();
    for i in 0..RL_FRAMES {
        let hdr = make_hdr(RL_FRAME_LEN, i as i64 * RL_GAP_USEC);
        out.send_packet(&hdr, &frame, PKT_DIR_NONCHECK);
    }
}

/// `assert_sliced()`.
fn assert_sliced(sum: &PcapSummary, slice: u32, wire_len: u32, stats: &OutputStats) {
    assert_eq!(sum.count, 1);
    assert_eq!(sum.snaplen, slice);
    let (_, _, caplen, len, data) = sum.first.as_ref().expect("one record");
    assert_eq!(*caplen, slice);
    assert_eq!(*len, wire_len);
    assert_eq!(&data[..], &frame_bytes()[..slice as usize]);
    assert_eq!(stats.fwd_bytes.load().0, slice as u64);
}

/// `assert_rate_limited()`.
fn assert_rate_limited(sum: &PcapSummary, stats: &OutputStats) {
    let frame_bits = RL_FRAME_LEN as u64 * 8;
    assert!(
        sum.written_bits <= 6_000_000 + frame_bits,
        "wrote {} bits (over the 6 Mbit + one frame ceiling)",
        sum.written_bits
    );
    assert!(
        sum.written_bits >= 5_000_000,
        "wrote only {} bits (below the 5 Mbit floor)",
        sum.written_bits
    );
    assert_eq!(sum.count as u64, stats.fwd_packets.load().0);
    let dropped = RL_FRAMES as u64 - sum.count as u64;
    assert_eq!(dropped, stats.ratelimit_drop_packets.load().0);
    assert_eq!(
        dropped * RL_FRAME_LEN as u64,
        stats.ratelimit_drop_bytes.load().0
    );
}

// --- `test_file_slice_truncates_record` ------------------------------------

#[test]
fn test_file_slice_truncates_record() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, path, stats) = new_file_output(dir.path(), 64, 0);
    send_one(out.as_mut(), 200);
    out.destroy();

    assert_sliced(&read_pcap(&path), 64, 200, &stats);
}

// --- `test_file_slice_larger_than_packet_keeps_it_whole` -------------------

#[test]
fn test_file_slice_larger_than_packet_keeps_it_whole() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, path, _stats) = new_file_output(dir.path(), 1500, 0);
    send_one(out.as_mut(), 200);
    out.destroy();

    let sum = read_pcap(&path);
    assert_eq!(sum.count, 1);
    assert_eq!(sum.snaplen, 1500);
    let (_, _, caplen, len, _) = sum.first.as_ref().unwrap();
    assert_eq!(*caplen, 200);
    assert_eq!(*len, 200);
}

// --- `test_file_no_slice_keeps_capture_snaplen` ----------------------------

#[test]
fn test_file_no_slice_keeps_capture_snaplen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, path, _stats) = new_file_output(dir.path(), 0, 0);
    send_one(out.as_mut(), 200);
    out.destroy();

    let sum = read_pcap(&path);
    assert_eq!(sum.snaplen, SNAPLEN as u32);
    let (_, _, caplen, _, _) = sum.first.as_ref().unwrap();
    assert_eq!(*caplen, 200);
}

// --- `test_file_rate_limit_caps_output` ------------------------------------

#[test]
fn test_file_rate_limit_caps_output() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, path, stats) = new_file_output(dir.path(), 0, RL_MBPS);
    send_rate_limit_burst(out.as_mut());
    out.destroy();

    assert_rate_limited(&read_pcap(&path), &stats);
}

// --- `test_file_no_rate_limit_writes_everything` ---------------------------

#[test]
fn test_file_no_rate_limit_writes_everything() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, path, stats) = new_file_output(dir.path(), 0, 0);
    send_rate_limit_burst(out.as_mut());
    out.destroy();

    let sum = read_pcap(&path);
    assert_eq!(sum.count, RL_FRAMES);
    assert_eq!(stats.ratelimit_drop_packets.load().0, 0);
}

// --- `test_rotating_file_slice_truncates_record` ---------------------------

#[test]
fn test_rotating_file_slice_truncates_record() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, stats) = new_rotating_output(dir.path(), 64, 0);
    send_one(out.as_mut(), 200);
    out.destroy();

    let path = rotating_file_path(dir.path());
    assert_sliced(&read_pcap(&path), 64, 200, &stats);
}

// --- `test_rotating_file_rate_limit_caps_output` ---------------------------

#[test]
fn test_rotating_file_rate_limit_caps_output() {
    let dir = tempfile::tempdir().unwrap();
    let (mut out, stats) = new_rotating_output(dir.path(), 0, RL_MBPS);
    send_rate_limit_burst(out.as_mut());
    out.destroy();

    let path = rotating_file_path(dir.path());
    assert_rate_limited(&read_pcap(&path), &stats);
}
