//! Ports of upstream `cpworker/tests/unit/output_rotating_file.c`.
//!
//! `write_packets()` builds a rotating output, sends `count` packets and calls
//! `destroy()`; `count_files_and_packets()` then walks the generated
//! `<root>/<YYYYMMDDHH>/pktminerg_dump_<...>.pcap` tree. The two vectors pin
//! the interval semantics: `0` never rotates, and a positive interval keeps
//! every packet (no loss) while it is open.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpworker::config::Config;
use cpworker::output::{new_output, PacketHeader};
use cpworker::packet::PKT_DIR_NONCHECK;
use cpworker::stats::OutputStats;

/// `write_packets()`: snaplen 2048, slice 0, `count` 64-byte frames.
fn write_packets(root: &Path, max_file_interval: i32, count: usize) {
    let cfg = serde_json::json!({
        "tasks": [{
            "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048}},
            "outputs": [{
                "type": "rotating_file",
                "rotating_file": {"file_root": root.display().to_string(), "max_file_interval": max_file_interval},
                "slice": 0
            }]
        }]
    });
    let cfg = Config::parse_str(&cfg.to_string()).expect("parse config");
    let stats = Arc::new(OutputStats::default());
    let mut out =
        new_output(&cfg.tasks[0], &cfg.tasks[0].outputs[0], stats).expect("rotate output");

    let pkt = [0u8; 64];
    let hdr = PacketHeader {
        ts_sec: 0,
        ts_usec: 0,
        caplen: pkt.len() as u32,
        len: pkt.len() as u32,
    };
    for _ in 0..count {
        assert_eq!(out.send_packet(&hdr, &pkt, PKT_DIR_NONCHECK), 0);
    }
    out.destroy();
}

/// `count_packets_in_file()`: record count, without libpcap.
fn count_packets_in_file(path: &Path) -> usize {
    let bytes = std::fs::read(path).expect("read pcap");
    assert!(bytes.len() >= 24, "short pcap header");
    let mut off = 24;
    let mut n = 0;
    while off + 16 <= bytes.len() {
        let caplen = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16 + caplen;
        n += 1;
    }
    n
}

/// `count_files_and_packets()`.
fn count_files_and_packets(root: &Path) -> (usize, usize) {
    let mut files = 0;
    let mut packets = 0;
    let mut dirs: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                dirs.push(path);
            } else {
                files += 1;
                packets += count_packets_in_file(&path);
            }
        }
    }
    (files, packets)
}

// --- `test_interval_zero_never_rotates` ------------------------------------

/// `0` means never rotate: every packet goes to the one file.
#[test]
fn test_interval_zero_never_rotates() {
    let root = tempfile::tempdir().unwrap();
    write_packets(root.path(), 0, 5);

    let (files, packets) = count_files_and_packets(root.path());
    assert_eq!(files, 1);
    assert_eq!(packets, 5);
}

// --- `test_interval_keeps_packets_within_interval` -------------------------

#[test]
fn test_interval_keeps_packets_within_interval() {
    let root = tempfile::tempdir().unwrap();
    write_packets(root.path(), 60, 5);

    let (_files, packets) = count_files_and_packets(root.path());
    assert_eq!(packets, 5);
}
