//! End-to-end test of the offline pcap capturer with the pure-Rust BPF filter.
//!
//! Builds a small pcap in memory, replays it through `new_capturer` with a
//! `udp and port 53` filter plus the automatic output-host exclusion, and checks
//! that only the expected frames are delivered.

use std::sync::Arc;

use cpworker::capturer::{new_capturer, PacketSink};
use cpworker::config::Config;
use cpworker::output::PacketHeader;
use cpworker::stats::CaptureStats;

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

fn global_header() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic (LE, usec)
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0i32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&262144u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    v
}

fn record(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
    v.extend_from_slice(&2u32.to_le_bytes()); // ts_usec
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14];
    p[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    p.extend_from_slice(&ip);
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&udp);
    p
}

fn ipv4_tcp(dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14];
    p[12..14].copy_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[9] = 6;
    p.extend_from_slice(&ip);
    let mut tcp = vec![0u8; 20];
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&tcp);
    p
}

#[test]
fn pcap_file_applies_bpf_and_host_exclusion() {
    let dir = std::env::temp_dir().join(format!("cp-bpf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("in.pcap");

    // Records: (bytes, should_be_delivered)
    let dns = ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 40000, 53);
    let dns_to_output = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 9], 40000, 53);
    let tcp80 = ipv4_tcp(80);
    let udp80 = ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 40000, 80);

    let mut file = global_header();
    for pkt in [&dns, &dns_to_output, &tcp80, &udp80] {
        file.extend_from_slice(&record(pkt));
    }
    std::fs::write(&path, &file).unwrap();

    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "pcap_file", "pcap_file": {{
                    "file_name": {file_name:?},
                    "bpf": "udp and port 53"
                }} }},
                "outputs": [ {{ "type": "vxlan", "vxlan": {{ "host": "10.0.0.9", "vni1": 7 }} }} ]
            }}]
        }}"#,
        file_name = path.to_str().unwrap()
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats.clone()).expect("capturer");

    let mut sink = Collect::default();
    // Drive until EOF (capture_once returns 0 after the file is exhausted).
    for _ in 0..16 {
        let n = cap.capture_once(&mut sink);
        if n == 0 {
            break;
        }
    }

    // Only the DNS query to 8.8.8.8 matches: TCP/80 and UDP/80 are filtered out,
    // and the query to the vxlan output host 10.0.0.9 is excluded automatically.
    assert_eq!(
        sink.pkts.len(),
        1,
        "unexpected packets: {:?}",
        sink.pkts.len()
    );
    assert_eq!(sink.pkts[0], dns);
    assert_eq!(stats.cap_packets.load(), (1, 0));

    std::fs::remove_dir_all(&dir).ok();
}
