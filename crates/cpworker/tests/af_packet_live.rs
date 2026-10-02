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
//!
//! ## veth ordering (bead `cloud-probe-rs-h53`)
//!
//! `live_capture_veth_delivers_exactly_n_frames` asserts a **strict** order:
//! the injected sequence numbers `0..N` must come back in that order. That is
//! a property of the *surrounding kernel path*, not of the capturer:
//!
//! * the capturer reads one `AF_PACKET` socket queue and cannot reorder;
//! * a single-queue veth delivers a *single-threaded* sender's frames in order
//!   only while they all traverse one CPU. veth delivers a transmitted frame on
//!   the sending CPU (directly, or through that CPU's `netif_rx` backlog) and
//!   `packet_rcv` enqueues it into the capture socket under a lock, so frames
//!   processed concurrently on two CPUs are queued in lock-acquisition order,
//!   not send order (measured on this kernel with an 8-CPU raw-sender stress:
//!   adjacent inversions > 0, total exact);
//! * when the injecting thread migrates between CPUs (scheduler placement, or
//!   a softirq deferred to `ksoftirqd` under load) the high band can surface
//!   early - exactly the bead h53 symptom (a contiguous run of high sequence
//!   numbers delivered before a lower run, with the total still exact).
//!
//! The veth tests therefore pin the injecting thread to one CPU (the private
//! `CpuPin` guard) so the strict-order assertion stays deterministic. It is
//! **not** weakened to a set/sorted comparison. Two environment preconditions
//! matter as well: the process needs enough file descriptors for `ip`'s netlink
//! socket (a harness with `ulimit -n 4` fails at `ip link set ... up`, long
//! before the capture path runs), and the capturer needs a socket buffer large
//! enough for the burst (8 MiB here, well above `N * frame`).

use std::sync::Arc;

use cpworker::capturer::{new_capturer, Capturer, PacketSink};
use cpworker::config::Config;
use cpworker::output::PacketHeader;
use cpworker::stats::CaptureStats;

#[derive(Default)]
struct Collect {
    pkts: Vec<Vec<u8>>,
    /// (caplen, orig_len) as reported for each delivered frame.
    hdrs: Vec<(u32, u32)>,
    heartbeats: u64,
}

impl PacketSink for Collect {
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], _d: i32) {
        self.pkts.push(pkt.to_vec());
        self.hdrs.push((hdr.caplen, hdr.len));
    }
    fn on_heartbeat(&mut self) {
        self.heartbeats += 1;
    }
}

fn privileged() -> bool {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

/// These tests are `#[ignore]`d so that they only ever run in the privileged
/// job - which means a non-privileged run must be a **failure**, never a silent
/// pass. Returning early here used to report `test result: ok. 4 passed` while
/// nothing was opened, read or asserted, and `parity/all.sh`/CI stayed green on
/// it (AUDIT4 P2-2: "the live-capture job can be fully green while executing
/// nothing").
fn assert_privileged(what: &str) {
    if !privileged() {
        panic!(
            "{what} must run as root / with CAP_NET_RAW (it is #[ignore]d for exactly \
             that reason); run: sudo -E <af_packet_live binary> --ignored --nocapture"
        );
    }
}

fn run_ok(cmd: &str, args: &[&str]) {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {cmd}: {e}"));
    assert!(status.success(), "{cmd} {args:?} failed: {status}");
}

/// Like [`run_ok`] but returns `false` instead of panicking, so a caller can
/// retry with a different name or clean up.
fn try_run(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A fresh 16-bit name suffix for a veth pair. Mixes the pid, the nanosecond
/// clock and the retry counter so a harness that starts many processes in a
/// tight loop cannot have two of them pick the same pair name.
fn name_tag(attempt: u32) -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (std::process::id() ^ nanos ^ attempt.wrapping_mul(0x9e37_79b9)) & 0xFFFF
}

/// Pins the calling thread to a single allowed CPU and restores the previous
/// affinity on drop.
///
/// See the module doc ("veth ordering") for why the strict-order veth tests
/// need this: when veth delivers on more than one CPU, the single `AF_PACKET`
/// capture queue is filled in lock-acquisition order rather than send order.
struct CpuPin {
    prev: libc::cpu_set_t,
}

impl CpuPin {
    fn single() -> Self {
        // SAFETY: `sched_getaffinity`/`sched_setaffinity` with a `cpu_set_t`
        // of the size libc reports is the documented Linux ABI; pid 0 means the
        // calling thread.
        unsafe {
            let size = std::mem::size_of::<libc::cpu_set_t>();
            let mut prev: libc::cpu_set_t = std::mem::zeroed();
            assert_eq!(
                libc::sched_getaffinity(0, size, &mut prev),
                0,
                "sched_getaffinity failed: {}",
                std::io::Error::last_os_error()
            );
            let mut one: libc::cpu_set_t = std::mem::zeroed();
            let mut cpu = None;
            for c in 0..libc::CPU_SETSIZE as usize {
                if libc::CPU_ISSET(c, &prev) {
                    libc::CPU_SET(c, &mut one);
                    cpu = Some(c);
                    break;
                }
            }
            let cpu = cpu.expect("the current affinity mask contains no CPU");
            assert_eq!(
                libc::sched_setaffinity(0, size, &one),
                0,
                "sched_setaffinity to CPU {cpu} failed: {}; the strict-order veth \
                 contract requires the injecting thread on one CPU",
                std::io::Error::last_os_error()
            );
            CpuPin { prev }
        }
    }
}

impl Drop for CpuPin {
    fn drop(&mut self) {
        // SAFETY: `prev` was filled by a successful `sched_getaffinity` above.
        unsafe {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &self.prev);
        }
    }
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
    assert_privileged("live_capture_on_loopback_with_filter");
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

/// `libpcap.ring: false` must force the per-frame `recvmsg` fallback and still
/// capture. This keeps the fallback path exercised: the `TPACKET_V3` ring is the
/// default, so without this test the whole `recvmsg` path is dead in coverage.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_recvmsg_fallback_without_ring() {
    assert_privileged("live_capture_recvmsg_fallback_without_ring");
    const PORT: u16 = 41235;
    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "lo",
                    "bpf": "udp and port {PORT}",
                    "timeout_ms": 200,
                    "ring": false
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
        if !sink.pkts.is_empty() {
            break;
        }
    }
    sender.join().unwrap();

    assert!(
        !sink.pkts.is_empty(),
        "no packets captured on lo via the recvmsg fallback (heartbeats={})",
        sink.heartbeats
    );
    assert!(stats.cap_packets.load().0 >= 1);
}

/// Create a veth pair and check that a stripped 802.1Q tag is re-inserted
/// (`PACKET_AUXDATA`), matching what libpcap does.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo); creates a veth pair"]
fn live_capture_reinserts_vlan_on_veth() {
    assert_privileged("live_capture_reinserts_vlan_on_veth");
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

    // --- snaplen contract with a stripped tag (AUDIT4 P2-7) ---------------------
    // Reinserting 4 bytes into a frame that was truncated to `snaplen` used to
    // report `caplen == snaplen + 4`, breaking the per-packet contract the
    // configuration makes (`tcpdump -s 16` on the same frames reports 16). The
    // tag counts *inside* snaplen, like libpcap.
    let json16 = r#"{
        "log_level": "INFO",
        "execution_model": "rtc",
        "tasks": [{
            "capturer": { "type": "libpcap", "libpcap": {
                "interface": "veth0", "snaplen": 16, "timeout_ms": 200
            } },
            "outputs": []
        }]
    }"#;
    let cfg16 = Config::parse_str(json16).expect("parse snaplen config");
    let tasks16 = cfg16.tasks.clone();
    let mut cap16 = new_capturer(&tasks16, &tasks16[0], Arc::new(CaptureStats::default()))
        .expect("snaplen capturer");

    let mut sink16 = Collect::default();
    for _ in 0..10 {
        send_tagged_frame("veth1", TCI);
        std::thread::sleep(std::time::Duration::from_millis(5));
        for _ in 0..10 {
            cap16.capture_once(&mut sink16);
        }
        if !sink16.pkts.is_empty() {
            break;
        }
    }
    assert!(
        !sink16.pkts.is_empty(),
        "snaplen=16 capture delivered nothing on veth0"
    );
    // Only assert on the *tagged* frames we injected: the kernel's own IPv6/ND
    // traffic on the newly created veth (86-byte frames) is also visible to
    // AF_PACKET and would otherwise pollute the snaplen/orig_len invariants.
    let mut tagged = 0usize;
    let mut tagged_pkt: Option<&Vec<u8>> = None;
    for (i, ((cap_len, orig_len), pkt)) in sink16.hdrs.iter().zip(&sink16.pkts).enumerate() {
        let is_tagged = pkt.len() >= 14
            && pkt[..6] == [0xff; 6]
            && pkt[6..12] == [0x11; 6]
            && pkt[12..14] == [0x81, 0x00];
        if !is_tagged {
            continue;
        }
        tagged += 1;
        tagged_pkt = Some(pkt);
        assert!(
            *cap_len <= 16,
            "frame {i}: caplen {cap_len} exceeds the configured snaplen 16 (P2-7)"
        );
        assert_eq!(
            *cap_len, 16,
            "frame {i}: a 60-byte frame must be filled to exactly snaplen"
        );
        assert_eq!(
            *orig_len, 60,
            "frame {i}: orig_len must stay the on-wire length (tag included)"
        );
        assert_eq!(
            pkt.len(),
            *cap_len as usize,
            "frame {i}: delivered the buffer up to snaplen, not caplen"
        );
    }
    assert_eq!(
        tagged, 1,
        "expected exactly the one tagged frame to be captured, got {tagged}"
    );
    // What is reported is the first `snaplen` bytes of the *reinserted* frame.
    // Find it by predicate: the kernel's own IPv6/ND frames on the fresh veth
    // are visible to AF_PACKET too and may be captured before the injected one.
    let p = tagged_pkt.expect("the tagged frame was counted above");
    assert_eq!(
        p[12..14],
        [0x81, 0x00],
        "the tag must still be visible inside snaplen bytes"
    );
    assert_eq!(p[14..16], TCI.to_be_bytes(), "reinserted TCI mismatch");
}

/// A filter too large for the kernel (or whose attach fails) must still capture,
/// by falling back to userspace filtering instead of failing the task.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_falls_back_to_userspace_filtering() {
    assert_privileged("live_capture_falls_back_to_userspace_filtering");
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

/// Read a interface's MAC address from sysfs.
fn iface_mac(ifname: &str) -> [u8; 6] {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))
        .unwrap_or_else(|e| panic!("read MAC of {ifname}: {e}"));
    let mut mac = [0u8; 6];
    for (i, part) in raw.trim().split(':').take(6).enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .unwrap_or_else(|e| panic!("bad MAC '{raw}' on {ifname}: {e}"));
    }
    mac
}

/// Ones-complement 16-bit sum, as an IPv4 header carries it.
fn inet_csum(data: &[u8]) -> u16 {
    let mut total: u32 = 0;
    let mut d: Vec<u8> = data.to_vec();
    if !d.len().is_multiple_of(2) {
        d.push(0);
    }
    for pair in d.chunks(2) {
        total += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    total = (total >> 16) + (total & 0xFFFF);
    total += total >> 16;
    !(total as u16)
}

/// One Ethernet/IPv4/UDP frame carrying `seq` in its payload.
///
/// The sequence number is what lets the fidelity test assert *exactly* N distinct
/// frames rather than "N frames, some of them twice". UDP checksum 0 means "not
/// computed", which is legal for IPv4; the IP header checksum is computed because
/// a receiving host validates it.
fn udp_frame(
    seq: u32,
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    dst_ip: [u8; 4],
    port: u16,
) -> Vec<u8> {
    let mut payload = seq.to_be_bytes().to_vec();
    payload.resize(20, 0x5a);
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&50000u16.to_be_bytes()); // sport
    udp.extend_from_slice(&port.to_be_bytes()); // dport
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // length
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum: not computed
    udp.extend_from_slice(&payload);

    let total_len = 20 + udp.len() as u16;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0]);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.extend_from_slice(&[64, 17]); // ttl, proto=UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum
    ip.extend_from_slice(&[169, 254, 99, 2]); // src (not configured anywhere)
    ip.extend_from_slice(&dst_ip); // dst
    let csum = inet_csum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + ip.len() + udp.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&0x800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

/// Decode the injected sequence numbers from a [`Collect`] in delivery order.
fn delivered_seqs(sink: &Collect, port: u16) -> Vec<u32> {
    sink.pkts
        .iter()
        .map(|p| {
            let off = 14 + 20 + 8;
            assert_eq!(u16::from_be_bytes([p[off - 6], p[off - 5]]), port);
            u32::from_be_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]])
        })
        .collect()
}

/// A raw `AF_PACKET` transmitter bound to one interface.
struct RawTx {
    fd: std::os::fd::RawFd,
    ll: libc::sockaddr_ll,
}

impl RawTx {
    fn new(ifname: &str) -> Self {
        let cname = std::ffi::CString::new(ifname).unwrap();
        // SAFETY: socket()/if_nametoindex() with a valid C string.
        let (fd, ifindex) = unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(0x0003u16.to_be()),
            );
            let ifindex = libc::if_nametoindex(cname.as_ptr());
            (fd, ifindex)
        };
        assert!(fd >= 0, "raw tx socket on {ifname}");
        assert!(ifindex > 0, "unknown interface {ifname}");
        let mut ll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        ll.sll_family = libc::AF_PACKET as u16;
        ll.sll_protocol = 0x0003u16.to_be();
        ll.sll_ifindex = ifindex as i32;
        RawTx { fd, ll }
    }

    /// Send one raw frame; panics on any socket error (a failed injection is not a
    /// capture result, so it must never be counted as "the capturer missed it").
    fn send(&self, frame: &[u8]) {
        // SAFETY: valid fd, buffer and sockaddr_ll.
        let n = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                0,
                std::ptr::addr_of!(self.ll).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert!(n > 0, "injecting a {}-byte raw frame failed", frame.len());
    }
}

impl Drop for RawTx {
    fn drop(&mut self) {
        // SAFETY: this fd was created by `RawTx::new` and is owned by it.
        unsafe { libc::close(self.fd) };
    }
}

/// An exclusively named veth pair, deleted again on `Drop`.
///
/// The names embed the test process id: the CI job and any manual run must not be
/// able to collide with each other (or with the `veth0`/`veth1` pair the VLAN test
/// uses), and deleting one end deletes the whole pair.
struct VethPair {
    a: String,
    b: String,
}

impl VethPair {
    fn new() -> Self {
        // A fresh veth must not collide with a concurrent run (a harness may
        // start several processes from the same shell). Deriving the name from
        // the pid *and* the nanosecond clock, and retrying `ip link add`, keeps
        // the setup robust without ever reusing a live pair.
        let mut created = None;
        for attempt in 0..8u32 {
            let tag = name_tag(attempt);
            let a = format!("cplv{tag:04x}a");
            let b = format!("cplv{tag:04x}b");
            if try_run(
                "ip",
                &["link", "add", &a, "type", "veth", "peer", "name", &b],
            ) {
                created = Some((a, b));
                break;
            }
        }
        let (a, b) = created.expect("could not create a unique veth pair after 8 attempts");
        // Build the guard *before* bringing the pair up so a failed `ip` still
        // deletes both ends through `Drop`.
        let pair = VethPair { a, b };
        run_ok("ip", &["link", "set", &pair.a, "up"]);
        run_ok("ip", &["link", "set", &pair.b, "up"]);
        // A freshly created veth has no carrier until the peer is up; the first
        // frames sent without one are simply dropped by the driver.
        std::thread::sleep(std::time::Duration::from_millis(300));
        pair
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &self.a])
            .status();
    }
}

/// veth capture fidelity: injecting exactly N frames must deliver exactly those N
/// frames - no loss, no duplication, no reordering.
///
/// This is the hard gate behind `bench/live_bench.py`'s `frames/datagram == 1.0`
/// number, which was only ever produced by hand (AUDIT4 qwen §4-5/§4-7, "门禁盲
/// 区"). Two things make it a *fidelity* gate rather than a smoke test:
///
/// * the traffic is injected as **raw frames from the veth peer**, because a UDP
///   socket on the same host would be routed to `lo` by the kernel and would never
///   traverse the veth at all (measured: capturing `veth0` while sending to its own
///   address delivers 0 frames);
/// * every frame carries a sequence number, so `cap_packets == N` cannot be reached
///   by duplicating one frame N times.
///
/// A `drop_packets == 0` counter is *not* sufficient evidence of a lossless path
/// (AUDIT4 P5-02: `tp_drops` only counts socket-queue overflow), which is exactly
/// why the count itself is asserted.
#[test]
#[ignore = "requires CAP_NET_RAW + CAP_NET_ADMIN (run with sudo); creates a veth pair"]
fn live_capture_veth_delivers_exactly_n_frames() {
    assert_privileged("live_capture_veth_delivers_exactly_n_frames");
    const PORT: u16 = 41247;
    const N: u32 = 400;

    let veth = VethPair::new();
    // All N frames must traverse one CPU: see the module doc ("veth ordering").
    let _pin = CpuPin::single();
    let dst_mac = iface_mac(&veth.a);
    let src_mac = iface_mac(&veth.b);
    // Destination address: not configured on either end, so the frame is tapped by
    // AF_PACKET and then dropped by the IP layer - no socket, no ICMP reply, no
    // outgoing frame that could be tapped a second time on the capture end.
    let dst_ip = [198, 51, 100, 7];

    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "{ifname}",
                    "bpf": "udp and dst port {PORT}",
                    "buffer_size_mb": 8,
                    "timeout_ms": 50
                }} }},
                "outputs": []
            }}]
        }}"#,
        ifname = veth.a
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats.clone()).expect("capturer");

    let tx = RawTx::new(&veth.b);
    let frames: Vec<Vec<u8>> = (0..N)
        .map(|seq| udp_frame(seq, &dst_mac, &src_mac, dst_ip, PORT))
        .collect();
    // All N frames are injected before the first read: 400 * 70 B is far below the
    // 8 MB socket buffer, so a shortfall cannot be explained by ring pressure.
    for f in &frames {
        tx.send(f);
    }

    let mut sink = Collect::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while (sink.pkts.len() as u32) < N && std::time::Instant::now() < deadline {
        cap.capture_once(&mut sink);
    }

    let got = sink.pkts.len() as u32;
    assert_eq!(
        got, N,
        "capturer delivered {got} of {N} injected frames (loss or duplication)"
    );
    assert_eq!(
        stats.cap_packets.load().0,
        N as u64,
        "cap_packets does not match the {N} frames injected"
    );
    assert_eq!(
        stats.drop_packets.load().0,
        0,
        "the capturer reported drops while delivering {N} frames"
    );
    // Exactly the injected set, in order: no duplicate, no gap, no reordering.
    let seqs = delivered_seqs(&sink, PORT);
    assert_eq!(
        seqs,
        (0..N).collect::<Vec<u32>>(),
        "delivered frames are not the injected frames in order"
    );
}

/// `IFF_PROMISC` (`0x100`) as reported by `/sys/class/net/<if>/flags`.
///
/// The flag is refcounted by the kernel: joining `PACKET_MR_PROMISC` on a socket
/// sets it while the socket is alive and clears it again when the socket is
/// closed, so a before/after read on a freshly created, exclusively named veth
/// is a deterministic witness that the membership call really happened.
fn iface_promisc_flag(ifname: &str) -> bool {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{ifname}/flags"))
        .unwrap_or_else(|e| panic!("read flags of {ifname}: {e}"));
    let v = u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("parse flags '{raw}' of {ifname}: {e}"));
    v & 0x100 != 0
}

/// A physical NIC exposes a `device` symlink under sysfs; a veth does not.
/// Used to know whether the kernel actually models a hardware RX filter, which
/// is the only thing that can make the non-promiscuous negative assertion
/// meaningful (`FIELD_CONFIRMATION.md` §2).
fn is_hardware_nic(ifname: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{ifname}/device")).exists()
}

fn iface_capturer(ifname: &str, promisc: bool) -> Box<dyn Capturer> {
    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "{ifname}",
                    "promisc": {promisc},
                    "timeout_ms": 50
                }} }},
                "outputs": []
            }}]
        }}"#
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    new_capturer(&tasks, &tasks[0], Arc::new(CaptureStats::default())).expect("capturer")
}

/// `PACKET_MR_PROMISC` must be joined (and is observable as `IFF_PROMISC`), and
/// a frame whose destination MAC is **neither** the local MAC **nor** broadcast
/// must be captured when `promisc = true`.
///
/// The negative half - the same frame dropped when `promisc = false` - is only
/// asserted on a real NIC: a veth does not model the hardware RX filter, so it
/// delivers the foreign-MAC frame either way (`FIELD_CONFIRMATION.md` §2, and the
/// veth experiment recorded there). On a veth this test therefore proves the
/// setsockopt happened (the flag toggles) and does not pretend to prove the
/// filter semantics.
#[test]
#[ignore = "requires CAP_NET_RAW + CAP_NET_ADMIN (run with sudo); creates a veth pair"]
fn live_capture_promisc_joins_membership_and_takes_foreign_mac() {
    assert_privileged("live_capture_promisc_joins_membership_and_takes_foreign_mac");
    const PORT: u16 = 41249;
    // Locally administered, not the interface MAC, not broadcast/multicast.
    const FOREIGN_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

    let veth = VethPair::new();
    let src_mac = iface_mac(&veth.b);
    let tx = RawTx::new(&veth.b);

    // --- promisc = true (the default) -------------------------------------
    assert!(
        !iface_promisc_flag(&veth.a),
        "a fresh veth must start non-promiscuous"
    );
    let mut cap = iface_capturer(&veth.a, true);
    assert!(
        iface_promisc_flag(&veth.a),
        "promisc=true must join PACKET_MR_PROMISC (IFF_PROMISC is set while the socket lives)"
    );
    tx.send(&udp_frame(
        1,
        &FOREIGN_MAC,
        &src_mac,
        [198, 51, 100, 9],
        PORT,
    ));
    let mut sink = Collect::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sink.pkts.is_empty() && std::time::Instant::now() < deadline {
        cap.capture_once(&mut sink);
    }
    assert!(
        !sink.pkts.is_empty(),
        "promiscuous capture did not deliver a foreign-MAC frame on {}",
        veth.a
    );
    drop(cap);
    assert!(
        !iface_promisc_flag(&veth.a),
        "closing the capture socket must release PACKET_MR_PROMISC"
    );

    // --- promisc = false --------------------------------------------------
    let mut cap = iface_capturer(&veth.a, false);
    assert!(
        !iface_promisc_flag(&veth.a),
        "promisc=false must not set IFF_PROMISC"
    );
    tx.send(&udp_frame(
        2,
        &FOREIGN_MAC,
        &src_mac,
        [198, 51, 100, 9],
        PORT,
    ));
    let mut sink = Collect::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while sink.pkts.is_empty() && std::time::Instant::now() < deadline {
        cap.capture_once(&mut sink);
    }
    if is_hardware_nic(&veth.a) {
        assert!(
            sink.pkts.is_empty(),
            "a physical NIC must not deliver a foreign-MAC frame without promisc"
        );
    } else {
        eprintln!(
            "note: {} is a virtual device; it does not model the RX filter, so a \
             foreign-MAC frame may be delivered with promisc=false (FIELD_CONFIRMATION.md §2)",
            veth.a
        );
    }
}

/// Bounded repetition of the veth fidelity contract.
///
/// The single-shot test proves ordering for one burst; the reorder from bead
/// `cloud-probe-rs-h53` is a scheduling race, so one pass is weak evidence.
/// This repeats the inject/capture cycle `REPS` times on the same veth pair and
/// capturer and requires the strict `0..N` order every time. With the `CpuPin`
/// guard it is deterministic; the multi-CPU veth delivery path is what makes an
/// unpinned run flaky.
#[test]
#[ignore = "requires CAP_NET_RAW + CAP_NET_ADMIN (run with sudo); creates a veth pair"]
fn live_capture_veth_order_is_stable_under_repetition() {
    assert_privileged("live_capture_veth_order_is_stable_under_repetition");
    const PORT: u16 = 41249;
    const N: u32 = 128;
    const REPS: usize = 12;

    let veth = VethPair::new();
    // All N frames must traverse one CPU: see the module doc ("veth ordering").
    let _pin = CpuPin::single();
    let dst_mac = iface_mac(&veth.a);
    let src_mac = iface_mac(&veth.b);
    let dst_ip = [198, 51, 100, 8];

    let json = format!(
        r#"{{
            "log_level": "INFO",
            "execution_model": "rtc",
            "tasks": [{{
                "capturer": {{ "type": "libpcap", "libpcap": {{
                    "interface": "{ifname}",
                    "bpf": "udp and dst port {PORT}",
                    "buffer_size_mb": 8,
                    "timeout_ms": 50
                }} }},
                "outputs": []
            }}]
        }}"#,
        ifname = veth.a
    );
    let cfg = Config::parse_str(&json).expect("parse config");
    let tasks = cfg.tasks.clone();
    let stats = Arc::new(CaptureStats::default());
    let mut cap = new_capturer(&tasks, &tasks[0], stats).expect("capturer");

    let tx = RawTx::new(&veth.b);
    let frames: Vec<Vec<u8>> = (0..N)
        .map(|seq| udp_frame(seq, &dst_mac, &src_mac, dst_ip, PORT))
        .collect();

    for rep in 0..REPS {
        for f in &frames {
            tx.send(f);
        }
        // Drain until every frame arrived; only then assert. The previous
        // repetition is guaranteed to have emptied the queue (the BPF filter
        // matches nothing else), so there are never stale frames to account for.
        let mut sink = Collect::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while (sink.pkts.len() as u32) < N && std::time::Instant::now() < deadline {
            cap.capture_once(&mut sink);
        }
        assert_eq!(
            sink.pkts.len() as u32,
            N,
            "repetition {rep}: delivered {} of {N} frames",
            sink.pkts.len()
        );
        assert_eq!(
            delivered_seqs(&sink, PORT),
            (0..N).collect::<Vec<u32>>(),
            "repetition {rep}: delivered frames are not the injected frames in order"
        );
    }
}

/// On loopback the kernel taps every datagram twice (transmitted +
/// received); libpcap/tcpdump deliver only the received copy. The capturer must
/// match that, i.e. ~1 frame per datagram, not ~2.
#[test]
#[ignore = "requires CAP_NET_RAW (run with sudo) on lo"]
fn live_capture_loopback_does_not_duplicate_frames() {
    assert_privileged("live_capture_loopback_does_not_duplicate_frames");
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
