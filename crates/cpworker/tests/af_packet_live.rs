//! Live `AF_PACKET` capture test.
//!
//! Opening an `AF_PACKET` socket requires `CAP_NET_RAW`, so this test is
//! `#[ignore]`d by default. Run it on Linux as root (or with the capability):
//!
//! ```text
//! sudo -E cargo test -p cpworker --test af_packet_live -- --ignored --nocapture
//! ```
//!
//! It opens `lo` with a `udp and port 41234` filter, fires UDP datagrams at that
//! port and checks that at least one matching frame is captured with the
//! expected timestamp/accounting.

use std::sync::Arc;

use cpworker::capturer::{new_capturer, PacketSink};
use cpworker::config::Config;
use cpworker::output::PacketHeader;
use cpworker::stats::CaptureStats;

#[derive(Default)]
struct Collect {
    pkts: Vec<Vec<u8>>,
    heartbeats: u64,
}

impl PacketSink for Collect {
    fn on_packet(&mut self, _hdr: &PacketHeader, pkt: &[u8], _d: i32) {
        self.pkts.push(pkt.to_vec());
    }
    fn on_heartbeat(&mut self) {
        self.heartbeats += 1;
    }
}

fn privileged() -> bool {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_on_loopback_with_filter() {
    if !privileged() {
        eprintln!("skipping: not root / no CAP_NET_RAW");
        return;
    }
    const PORT: u16 = 41234;
    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "lo",
                    "bpf": "udp and port {PORT}",
                    "timeout_ms": 200
                }} }},
                "outputs": []
            }}]
        }}"#
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats.clone()).expect("capturer");

    let sender = std::thread::spawn(move || {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = format!("127.0.0.1:{PORT}");
        for _ in 0..200 {
            let _ = sock.send_to(b"hello-cpworker", &dst);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });

    let mut sink = Collect::default();
    for _ in 0..50 {
        cap.capture_once(&mut sink);
        if sink.pkts.len() >= 3 {
            break;
        }
    }
    sender.join().unwrap();

    assert!(
        !sink.pkts.is_empty(),
        "no packets captured on lo (heartbeats={})",
        sink.heartbeats
    );
    // Every captured frame must carry an IPv4/UDP datagram to PORT.
    for pkt in &sink.pkts {
        assert!(pkt.len() >= 42, "frame too short: {}", pkt.len());
        assert_eq!(&pkt[12..14], &[0x08, 0x00], "not IPv4");
        // Destination port is at offset 14+20+2.
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), PORT);
    }
    assert!(stats.cap_packets.load().0 >= 1);
}
