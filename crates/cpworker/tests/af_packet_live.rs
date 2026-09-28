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

fn run_ok(cmd: &str, args: &[&str]) {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {cmd}: {e}"));
    assert!(status.success(), "{cmd} {args:?} failed: {status}");
}

/// Send an 802.1Q-tagged Ethernet frame out of `ifname` via a raw socket.
fn send_tagged_frame(ifname: &str, tci: u16) {
    // SAFETY: raw AF_PACKET send with a fully initialized frame/sockaddr.
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            i32::from(0x0003u16.to_be()),
        );
        assert!(fd >= 0, "raw tx socket");
        let cname = std::ffi::CString::new(ifname).unwrap();
        let ifindex = libc::if_nametoindex(cname.as_ptr());
        assert!(ifindex > 0, "unknown interface {ifname}");
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = 0x0003u16.to_be();
        sll.sll_ifindex = ifindex as i32;
        let mut frame = [0u8; 60];
        for b in frame.iter_mut().take(6) {
            *b = 0xff;
        }
        for b in frame.iter_mut().take(12).skip(6) {
            *b = 0x11;
        }
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        frame[14..16].copy_from_slice(&tci.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        for (i, b) in frame.iter_mut().enumerate().skip(18) {
            *b = i as u8;
        }
        let n = libc::sendto(
            fd,
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            std::ptr::addr_of!(sll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        assert!(n > 0, "sendto failed");
        libc::close(fd);
    }
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

/// Create a veth pair and check that a stripped 802.1Q tag is re-inserted
/// (`PACKET_AUXDATA`), matching what libpcap does.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo); creates a veth pair"]
fn live_capture_reinserts_vlan_on_veth() {
    if !privileged() {
        eprintln!("skipping: not root / no CAP_NET_RAW");
        return;
    }
    const TCI: u16 = 100;

    // Best-effort cleanup of any stale pair, then create a fresh one.
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "veth0"])
        .status();
    run_ok(
        "ip",
        &[
            "link", "add", "veth0", "type", "veth", "peer", "name", "veth1",
        ],
    );
    run_ok("ip", &["link", "set", "veth0", "up"]);
    run_ok("ip", &["link", "set", "veth1", "up"]);

    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", "veth0"])
                .status();
        }
    }
    let _cleanup = Cleanup;
    std::thread::sleep(std::time::Duration::from_millis(300));

    let json = r#"{
        "log_level": "INFO",
        "execution_model": "rtc",
        "tasks": [{
            "capturer": { "type": "libpcap", "libpcap": {
                "interface": "veth0", "timeout_ms": 200
            } },
            "outputs": []
        }]
    }"#;
    let cfg = Config::parse_str(json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats).expect("capturer");

    for _ in 0..10 {
        send_tagged_frame("veth1", TCI);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let mut sink = Collect::default();
    let tagged = |p: &[u8]| {
        p.len() >= 18
            && p[12..14] == [0x81, 0x00]
            && p[14..16] == TCI.to_be_bytes()
            && p[16..18] == [0x08, 0x00]
    };
    for _ in 0..50 {
        cap.capture_once(&mut sink);
        if sink.pkts.iter().any(|p| tagged(p)) {
            break;
        }
    }

    let frame = sink
        .pkts
        .iter()
        .find(|p| tagged(p))
        .expect("no VLAN-tagged frame captured (AUXDATA not applied?)");
    // Payload that followed the original ethertype must still be intact.
    assert_eq!(frame[18], 0x12, "payload after reinserted VLAN tag shifted");
}

/// A filter too large for the kernel (or whose attach fails) must still capture,
/// by falling back to userspace filtering instead of failing the task.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_falls_back_to_userspace_filtering() {
    if !privileged() {
        eprintln!("skipping: not root / no CAP_NET_RAW");
        return;
    }
    const PORT: u16 = 41239;

    // >4096 instructions: SO_ATTACH_FILTER is refused (EINVAL), so the capturer
    // must filter in userspace and still deliver matching frames.
    let mut parts = vec![format!("port {PORT}")];
    for i in 0..150u32 {
        parts.push(format!("not host 10.9.{}.{}", i / 256, i % 256));
    }
    let bpf = parts.join(" and ");

    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "lo",
                    "bpf": {bpf:?},
                    "timeout_ms": 200
                }} }},
                "outputs": []
            }}]
        }}"#
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats).expect("capturer");

    let sender = std::thread::spawn(move || {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = format!("127.0.0.1:{PORT}");
        for _ in 0..200 {
            let _ = sock.send_to(b"fallback", &dst);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });

    let mut sink = Collect::default();
    for _ in 0..50 {
        cap.capture_once(&mut sink);
        if !sink.pkts.is_empty() {
            break;
        }
    }
    sender.join().unwrap();

    assert!(
        !sink.pkts.is_empty(),
        "userspace-filtered capture delivered nothing"
    );
    for pkt in &sink.pkts {
        assert!(pkt.len() >= 38, "frame too short: {}", pkt.len());
        // Destination port at 14 + 20 + 2.
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), PORT);
    }
}

/// On loopback the kernel taps every datagram twice (transmitted +
/// received); libpcap/tcpdump deliver only the received copy. The capturer must
/// match that, i.e. ~1 frame per datagram, not ~2.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_loopback_does_not_duplicate_frames() {
    if !privileged() {
        eprintln!("skipping: not root / no CAP_NET_RAW");
        return;
    }
    const PORT: u16 = 41241;
    const N: usize = 10_000;

    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "lo",
                    "bpf": "udp and dst port {PORT}",
                    "timeout_ms": 0
                }} }},
                "outputs": []
            }}]
        }}"#
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats.clone()).expect("capturer");

    // Bind a receiver so the datagrams are consumed (no ICMP noise) and send N.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dst = format!("127.0.0.1:{PORT}");
    let rx = std::net::UdpSocket::bind(("127.0.0.1", PORT)).unwrap();
    rx.set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .unwrap();
    let drainer = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while rx.recv_from(&mut buf).is_ok() {}
    });

    let sender = {
        let sock = sock.try_clone().unwrap();
        std::thread::spawn(move || {
            for _ in 0..N {
                let _ = sock.send_to(b"x", &dst);
            }
        })
    };

    let mut sink = Collect::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    while std::time::Instant::now() < deadline {
        cap.capture_once(&mut sink);
    }
    sender.join().unwrap();
    drop(sock);
    let _ = drainer.join();

    let got = sink.pkts.len();
    // The duplicate bug would deliver ~2N; allow generous loss but reject it.
    assert!(
        got <= N + N / 4,
        "loopback outgoing frames not suppressed: captured {got} for {N} datagrams (~2x expected without the fix)"
    );
    assert!(got >= N / 4, "captured too few frames: {got} for {N}");
}
