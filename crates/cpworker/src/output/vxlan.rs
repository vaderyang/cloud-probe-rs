//! VXLAN output. Port of `output_vxlan.c`, including packet splitting.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use super::{Egress, Output, PacketHeader, RawSocketEgress};
use crate::config::{OutputConfig, VxlanConfig};
use crate::error::{Error, Result};
use crate::packet::{parse_packet, ETH_HDR_LEN, PKT_DIR_NONCHECK, PKT_DIR_UNKNOWN, VXLAN_HDR_LEN};
use crate::packet_split::{build_fragment, calculate_fragment_count};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

const VXLAN_OUTPUT_BUFSIZE: usize = 65551;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;
const ENOBUFS: i32 = 105;

fn set_bind_device(socket: &Socket, device: &str) -> std::io::Result<()> {
    crate::sockopt::bind_to_device(socket, device)
}

fn set_pmtudisc(socket: &Socket, pmtudisc: i32) -> std::io::Result<()> {
    crate::sockopt::set_pmtudisc(socket, pmtudisc)
}

/// Port of `rte_raw_cksum` (with the 0x4a3b2d1c seed).
fn rte_raw_cksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0x4a3b2d1c;
    let (words, tail) = buf.split_at(buf.len() / 2 * 2);
    for w in words.as_chunks::<2>().0 {
        sum += u16::from_ne_bytes([w[0], w[1]]) as u32;
    }
    if let Some(&b) = tail.first() {
        sum += b as u32;
    }
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum as u16
}

/// Build a VXLAN-encapsulated frame into `buf`, returning the total length.
/// Single source of truth for the VXLAN wire format (also used by the parity
/// harness). `inner` is the Ethernet frame to encapsulate.
// Mirrors the C `vxlan_encapsulate` signature (used by the byte-for-byte parity
// harness), so the argument count is deliberate.
#[allow(clippy::too_many_arguments)]
pub fn vxlan_encapsulate(
    buf: &mut [u8],
    vni: u32,
    vni_version: u8,
    direct: i32,
    capture_time: bool,
    ts_sec: i64,
    ts_usec: i64,
    inner: &[u8],
) -> usize {
    let mut length = inner.len();
    buf[0..4].copy_from_slice(&0x0800_0000u32.to_be_bytes());
    buf[VXLAN_HDR_LEN..VXLAN_HDR_LEN + length].copy_from_slice(inner);

    if capture_time {
        let tv_sec = (ts_sec as u32).to_be_bytes();
        let tv_nsec = ((ts_usec as u32) * 1000).to_be_bytes();
        buf[VXLAN_HDR_LEN + length..VXLAN_HDR_LEN + length + 4].copy_from_slice(&tv_sec);
        length += 4;
        buf[VXLAN_HDR_LEN + length..VXLAN_HDR_LEN + length + 4].copy_from_slice(&tv_nsec);
        length += 4;
    }

    if vni_version == 1 {
        let mut vni_bytes = (vni << 8).to_be_bytes();
        if direct != PKT_DIR_NONCHECK {
            vni_bytes[0] = ((direct as u8) & 0x0f) << 4;
            vni_bytes[1] &= 0x0f;
            vni_bytes[3] = 0;
        }
        buf[4..8].copy_from_slice(&vni_bytes);
        // Checksum covering VXLAN + Ethernet + IPv4 headers.
        let check = rte_raw_cksum(&buf[..VXLAN_HDR_LEN + ETH_HDR_LEN + 20]);
        buf[7] = check as u8;
    } else {
        let v = vni.wrapping_add(direct as u32);
        buf[4..8].copy_from_slice(&v.to_be_bytes());
    }

    VXLAN_HDR_LEN + length
}

#[derive(Default)]
struct ErrorInfo {
    first_pktsec: i64,
    nb_nobufs_drops: u64,
    nb_partial_sends: u64,
    nb_other_send_error_drops: u64,
    other_send_error: String,
}

/// VXLAN tunnel output.
pub struct VxlanOutput {
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,
    vni_version: u8,
    vni: u32,
    capture_time: bool,
    egress: Box<dyn Egress>,
    buf: Vec<u8>,
    fragment_buf: Vec<u8>,
    max_payload_size: u16,
    recalculate_checksum: bool,
    error_info: ErrorInfo,
}

impl VxlanOutput {
    /// Create a VXLAN tunnel output.
    ///
    /// # Errors
    /// Returns an error if the host is invalid or the tunnel socket cannot be
    /// created or bound.
    pub fn new(cfg: &VxlanConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let addr: Ipv4Addr = cfg
            .host
            .parse()
            .map_err(|_| Error::new(format!("invalid vxlan host: {}", cfg.host)))?;
        let remote_addr = SocketAddrV4::new(addr, cfg.port);

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| Error::new(format!("create socket error: {e}")))?;

        if !cfg.bind_device.is_empty() {
            set_bind_device(&socket, &cfg.bind_device).map_err(|e| {
                Error::new(format!(
                    "set SO_BINDTODEVICE for device {} error: {e}",
                    cfg.bind_device
                ))
            })?;
        }
        if cfg.pmtudisc >= 0 {
            set_pmtudisc(&socket, cfg.pmtudisc)
                .map_err(|e| Error::new(format!("set IP_MTU_DISCOVER error: {e}")))?;
        }

        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };

        Ok(VxlanOutput {
            stats,
            throttle,
            slice: out.slice,
            vni_version: cfg.vni_version,
            vni: cfg.vni,
            capture_time: cfg.capture_time,
            egress: Box::new(RawSocketEgress {
                socket,
                remote: SocketAddr::V4(remote_addr),
            }),
            buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            fragment_buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            max_payload_size: cfg.split.max_payload_size,
            recalculate_checksum: cfg.split.recalculate_checksum,
            error_info: ErrorInfo::default(),
        })
    }

    fn flush_error_info(&mut self) {
        self.error_info.first_pktsec = 0;
        let e = &mut self.error_info;
        if e.nb_nobufs_drops > 0 || e.nb_partial_sends > 0 || e.nb_other_send_error_drops > 0 {
            crate::log_error!(
                "vxlan output error: nb_nobufs_drops={}, nb_partial_sends={}, nb_other_send_error_drops={}, detail: {}",
                e.nb_nobufs_drops,
                e.nb_partial_sends,
                e.nb_other_send_error_drops,
                e.other_send_error
            );
            e.nb_nobufs_drops = 0;
            e.nb_partial_sends = 0;
            e.nb_other_send_error_drops = 0;
            e.other_send_error.clear();
        }
    }

    fn do_send_packet(
        &mut self,
        hdr: &PacketHeader,
        pkt_data: &[u8],
        length: usize,
        direct: i32,
    ) -> i32 {
        let total = vxlan_encapsulate(
            &mut self.buf,
            self.vni,
            self.vni_version,
            direct,
            self.capture_time,
            hdr.ts_sec,
            hdr.ts_usec,
            &pkt_data[..length],
        );
        let mut retry = 0;
        loop {
            match self.egress.send_to(&self.buf[..total]) {
                Ok(sent) => {
                    if sent < total {
                        self.error_info.nb_partial_sends += 1;
                        self.stats.error_drop_bytes.add((total - sent) as u64);
                        self.stats.fwd_bytes.add(sent as u64);
                        self.stats.fwd_packets.add(1);
                        return -1;
                    }
                    self.stats.fwd_bytes.add(total as u64);
                    self.stats.fwd_packets.add(1);
                    return 0;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(ENOBUFS) && retry < 10 {
                        let duration = (100 + retry * 200).min(1000);
                        std::thread::sleep(std::time::Duration::from_micros(duration as u64));
                        retry += 1;
                        continue;
                    }
                    if e.raw_os_error() == Some(ENOBUFS) {
                        self.error_info.nb_nobufs_drops += 1;
                    } else {
                        if self.error_info.nb_other_send_error_drops == 0 {
                            self.error_info.other_send_error = e.to_string();
                        }
                        self.error_info.nb_other_send_error_drops += 1;
                    }
                    self.stats.error_drop_bytes.add(total as u64);
                    self.stats.error_drop_packets.add(1);
                    return -1;
                }
            }
        }
    }
}

impl Output for VxlanOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt_data: &[u8], direct: i32) -> i32 {
        let mut caplen = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < caplen {
            caplen = self.slice as u32;
        }
        let length = caplen.min(65535) as usize;

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(length as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        if let Some(tb) = self.throttle.as_mut() {
            if !tb.consume(VXLAN_HDR_LEN + length, hdr.ts()) {
                self.stats
                    .ratelimit_drop_bytes
                    .add((VXLAN_HDR_LEN + length) as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        if self.error_info.first_pktsec == 0 {
            self.error_info.first_pktsec = hdr.ts_sec;
        } else if hdr.ts_sec > self.error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC {
            self.flush_error_info();
            self.error_info.first_pktsec = hdr.ts_sec;
        }

        // Fast path: no split needed.
        if self.max_payload_size == 0 || length <= self.max_payload_size as usize {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        }

        let Some(parse) = parse_packet(pkt_data) else {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        };
        let count = calculate_fragment_count(&parse, self.max_payload_size as i32);
        if count == 1 {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        }

        for i in 0..count {
            let mut frag_buf = std::mem::take(&mut self.fragment_buf);
            let frag_len = build_fragment(
                &parse,
                pkt_data,
                i,
                self.max_payload_size as i32,
                self.recalculate_checksum,
                &mut frag_buf,
            );
            let ret = match frag_len {
                Some(frag_len) => self.do_send_packet(hdr, &frag_buf[..frag_len], frag_len, direct),
                None => 0,
            };
            self.fragment_buf = frag_buf;
            if ret != 0 {
                return ret;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ETHERTYPE_IP, IPPROTO_TCP, PKT_DIR_INCOMING, PKT_DIR_NONCHECK};
    use crate::stats::OutputStats;
    use std::sync::{Arc, Mutex};

    const VNI: u32 = 0x0012_3456;

    #[derive(Default)]
    struct MockState {
        responses: std::collections::VecDeque<std::io::Result<usize>>,
        sent: Vec<Vec<u8>>,
    }

    struct MockEgress(Arc<Mutex<MockState>>);

    impl Egress for MockEgress {
        fn send_to(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut s = self.0.lock().unwrap();
            s.sent.push(buf.to_vec());
            s.responses.pop_front().unwrap_or(Ok(buf.len()))
        }
    }

    struct Fixture {
        out: VxlanOutput,
        stats: Arc<OutputStats>,
    }

    fn fixture(
        state: Arc<Mutex<MockState>>,
        slice: i32,
        throttle: Option<TokenBucket>,
        max_payload_size: u16,
        recalculate_checksum: bool,
    ) -> Fixture {
        let stats = Arc::new(OutputStats::default());
        let out = VxlanOutput {
            stats: Arc::clone(&stats),
            throttle,
            slice,
            vni_version: 1,
            vni: VNI,
            capture_time: false,
            egress: Box::new(MockEgress(state)),
            buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            fragment_buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            max_payload_size,
            recalculate_checksum,
            error_info: ErrorInfo::default(),
        };
        Fixture { out, stats }
    }

    fn mock(responses: Vec<std::io::Result<usize>>) -> Arc<Mutex<MockState>> {
        Arc::new(Mutex::new(MockState {
            responses: responses.into(),
            sent: Vec::new(),
        }))
    }

    fn hdr(ts_sec: i64, caplen: u32) -> PacketHeader {
        PacketHeader {
            ts_sec,
            ts_usec: 0,
            caplen,
            len: caplen,
        }
    }

    fn sent(state: &Arc<Mutex<MockState>>) -> Vec<Vec<u8>> {
        state.lock().unwrap().sent.clone()
    }

    fn enobufs() -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(ENOBUFS))
    }

    /// Minimal Ethernet+IPv4+TCP frame with `payload`.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12..14].copy_from_slice(&ETHERTYPE_IP.to_be_bytes());
        p[14] = 0x45;
        let ip_total = 20 + 20 + payload.len();
        p[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
        p[14 + 9] = IPPROTO_TCP;
        p[14 + 20 + 12] = 0x50;
        p.extend_from_slice(payload);
        p
    }

    fn expect_encap(direct: i32, ts_sec: i64, ts_usec: i64, inner: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; VXLAN_OUTPUT_BUFSIZE];
        let n = vxlan_encapsulate(&mut b, VNI, 1, direct, false, ts_sec, ts_usec, inner);
        b[..n].to_vec()
    }

    #[test]
    fn unknown_direction_drops_before_sending() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0x11u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_UNKNOWN), -1);
        assert_eq!(f.stats.direction_drop_bytes.load(), (20, 0));
        assert_eq!(f.stats.direction_drop_packets.load(), (1, 0));
        assert!(sent(&state).is_empty());
    }

    #[test]
    fn fast_path_sends_the_encapsulated_frame() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0xABu8; 32];
        assert_eq!(f.out.send_packet(&hdr(1000, 32), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
        let s = sent(&state);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], expect_encap(PKT_DIR_INCOMING, 1000, 0, &pkt));
    }

    #[test]
    fn slice_truncates_the_inner_frame() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 12, None, 0, false);
        let pkt = [0xCDu8; 32];
        assert_eq!(f.out.send_packet(&hdr(1000, 32), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(
            sent(&state)[0],
            expect_encap(PKT_DIR_INCOMING, 1000, 0, &pkt[..12])
        );
    }

    #[test]
    fn slice_larger_than_caplen_is_ignored() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 100, None, 0, false);
        let pkt = [0xCDu8; 32];
        assert_eq!(f.out.send_packet(&hdr(1000, 32), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(
            sent(&state)[0],
            expect_encap(PKT_DIR_INCOMING, 1000, 0, &pkt)
        );
    }

    #[test]
    fn rate_limit_drop_reports_bytes_and_packets() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, Some(TokenBucket::new(1)), 0, false);
        let pkt = [0x22u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(
            f.stats.ratelimit_drop_bytes.load(),
            (VXLAN_HDR_LEN as u64 + 20, 0)
        );
        assert_eq!(f.stats.ratelimit_drop_packets.load(), (1, 0));
        assert!(sent(&state).is_empty());
    }

    #[test]
    fn partial_send_reports_dropped_bytes() {
        let total = VXLAN_HDR_LEN + 20;
        let state = mock(vec![Ok(7)]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0x33u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_partial_sends, 1);
        assert_eq!(f.stats.error_drop_bytes.load(), (total as u64 - 7, 0));
        assert_eq!(f.stats.fwd_bytes.load(), (7, 0));
        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
    }

    #[test]
    fn enobufs_is_retried_then_succeeds() {
        let state = mock(vec![enobufs(), Ok(VXLAN_HDR_LEN + 20)]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0x44u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(sent(&state).len(), 2);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
    }

    #[test]
    fn enobufs_after_max_retries_is_dropped() {
        let total = VXLAN_HDR_LEN + 20;
        let state = mock((0..11).map(|_| enobufs()).collect());
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0x55u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_nobufs_drops, 1);
        assert_eq!(f.stats.error_drop_bytes.load(), (total as u64, 0));
        assert_eq!(sent(&state).len(), 11);
    }

    #[test]
    fn other_send_error_records_the_first_detail_once() {
        let state = mock(vec![
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        ]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = [0x66u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        let first = f.out.error_info.other_send_error.clone();
        assert!(!first.is_empty());
        assert_eq!(
            f.out.send_packet(&hdr(1001, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_other_send_error_drops, 2);
        assert_eq!(f.out.error_info.other_send_error, first);
    }

    #[test]
    fn error_info_flushes_after_the_five_second_window() {
        let state = mock((0..11).map(|_| enobufs()).collect());
        let mut f = fixture(state, 0, None, 0, false);
        let pkt = [0x77u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.first_pktsec, 1000);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 1);
        assert_eq!(f.out.send_packet(&hdr(1006, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.out.error_info.first_pktsec, 1006);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
    }

    #[test]
    fn split_path_sends_each_fragment() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 30, false);
        let pkt = frame(&(0..100u8).collect::<Vec<_>>());
        let parse = parse_packet(&pkt).unwrap();
        let count = calculate_fragment_count(&parse, 30);
        assert_eq!(count, 4);
        assert_eq!(
            f.out
                .send_packet(&hdr(1000, pkt.len() as u32), &pkt, PKT_DIR_NONCHECK),
            0
        );
        let s = sent(&state);
        assert_eq!(s.len(), count as usize, "one datagram per fragment");
        assert_eq!(f.stats.fwd_packets.load(), (count as u64, 0));
        // First fragment carries the first 30 payload bytes.
        let mut out0 = vec![0u8; 2048];
        let n0 = build_fragment(&parse, &pkt, 0, 30, false, &mut out0).unwrap();
        assert_eq!(s[0], expect_encap(PKT_DIR_NONCHECK, 1000, 0, &out0[..n0]));
    }

    #[test]
    fn split_with_a_single_fragment_sends_the_whole_frame() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 30, false);
        let pkt = frame(&[1, 2, 3, 4, 5]);
        assert!(pkt.len() > 30);
        assert_eq!(
            f.out
                .send_packet(&hdr(1000, pkt.len() as u32), &pkt, PKT_DIR_NONCHECK),
            0
        );
        let s = sent(&state);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], expect_encap(PKT_DIR_NONCHECK, 1000, 0, &pkt));
    }

    #[test]
    fn unparseable_oversized_frame_falls_back_to_one_send() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 30, false);
        // ARP-looking Ethernet frame: parse_packet returns None.
        let mut pkt = vec![0u8; 60];
        pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(parse_packet(&pkt).is_none());
        assert_eq!(
            f.out
                .send_packet(&hdr(1000, pkt.len() as u32), &pkt, PKT_DIR_NONCHECK),
            0
        );
        let s = sent(&state);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], expect_encap(PKT_DIR_NONCHECK, 1000, 0, &pkt));
    }

    #[test]
    fn flush_error_info_resets_when_only_one_counter_is_set() {
        for which in 0..3 {
            let state = mock(vec![]);
            let mut f = fixture(state, 0, None, 0, false);
            match which {
                0 => f.out.error_info.nb_nobufs_drops = 1,
                1 => f.out.error_info.nb_partial_sends = 1,
                _ => f.out.error_info.nb_other_send_error_drops = 1,
            }
            f.out.flush_error_info();
            assert_eq!(f.out.error_info.nb_nobufs_drops, 0, "case {which}");
            assert_eq!(f.out.error_info.nb_partial_sends, 0, "case {which}");
            assert_eq!(
                f.out.error_info.nb_other_send_error_drops, 0,
                "case {which}"
            );
        }
    }

    #[test]
    fn new_rejects_an_invalid_host() {
        let cfg = VxlanConfig {
            host: "not-an-ip".into(),
            port: 4789,
            capture_time: false,
            vni_version: 1,
            vni: 1,
            bind_device: String::new(),
            pmtudisc: -1,
            split: crate::config::SplitConfig::default(),
        };
        let out = OutputConfig {
            kind: crate::config::OutputKind::Vxlan(cfg.clone()),
            rate_limit_mbps: 0,
            slice: 0,
        };
        match VxlanOutput::new(&cfg, &out, Arc::new(OutputStats::default())) {
            Ok(_) => panic!("expected an invalid-host error"),
            Err(e) => assert!(e.to_string().contains("invalid vxlan host"), "{e}"),
        }
    }

    #[test]
    fn vxlan_encapsulate_matches_golden_vectors() {
        // Byte-for-byte vectors (also checked against the C `vxlan_encapsulate`
        // by the parity harness); they pin the VNI/checksum/timestamp layout.
        let inner: Vec<u8> = (0..24u8).collect();
        let cases: [(u8, i32, bool, i64, i64, &str); 6] = [
            (
                1,
                0,
                false,
                0,
                0,
                "080000001234564c000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
            (
                1,
                1,
                false,
                0,
                0,
                "080000001004564a000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
            (
                1,
                2,
                false,
                0,
                0,
                "080000002004565a000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
            (
                1,
                1,
                true,
                1234,
                5678,
                "08000000100456f2000102030405060708090a0b0c0d0e0f1011121314151617000004d20056a3b0",
            ),
            (
                2,
                1,
                false,
                0,
                0,
                "0800000000123457000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
            (
                1,
                -1,
                false,
                0,
                0,
                "08000000f004562a000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
        ];
        for (vv, d, ct, s, u, hex) in cases {
            let mut b = vec![0u8; 4096];
            let n = vxlan_encapsulate(&mut b, 0x0012_3456, vv, d, ct, s, u, &inner);
            let got: String = b[..n].iter().map(|x| format!("{x:02x}")).collect();
            assert_eq!(got, hex, "vv={vv} d={d} ct={ct}");
        }
    }

    #[test]
    fn vxlan_checksum_covers_exactly_the_outer_header() {
        // The v1 VNI stores a checksum of VXLAN(8) + Ethernet(14) + IPv4(20) = 42
        // bytes in its last byte. Bytes past that must not contribute: callers
        // reuse one large buffer, so the tail is stale data from a previous
        // frame and folding it in would make the wire bytes depend on history.
        let inner = [0xAAu8; 24];
        let mut quiet = vec![0u8; 512];
        let n = vxlan_encapsulate(&mut quiet, 7, 1, PKT_DIR_NONCHECK, false, 0, 0, &inner);
        let mut noisy = vec![0u8; 512];
        for b in noisy.iter_mut().skip(42) {
            *b = 0xFF;
        }
        let m = vxlan_encapsulate(&mut noisy, 7, 1, PKT_DIR_NONCHECK, false, 0, 0, &inner);
        assert_eq!(n, m);
        assert_eq!(
            noisy[7], quiet[7],
            "the checksum must not read past byte 42"
        );
    }

    /// `rte_raw_cksum` is a port of the DPDK one-`s-complement sum: native-endian
    /// `u16` words, then at most one trailing odd byte, folded twice. The odd byte
    /// is invisible in production (the checksummed header is 42 B, even), so this
    /// exercises the function directly.
    #[cfg(target_endian = "little")]
    #[test]
    fn rte_raw_cksum_includes_a_trailing_odd_byte() {
        // 0x4a3b2d1c + 0x0100 = 0x4a3b2e1c -> 0x4a3b + 0x2e1c = 0x7857
        assert_eq!(rte_raw_cksum(&[0x00, 0x01]), 0x7857);
        // ... plus a trailing 0x00: no change.
        assert_eq!(rte_raw_cksum(&[0x00, 0x01, 0x00]), 0x7857);
        // ... plus a trailing 0x03: 0x4a3b2e1f -> 0x785a.
        assert_eq!(rte_raw_cksum(&[0x00, 0x01, 0x03]), 0x785a);
        // Two words: 0x0100 + 0x0302 -> 0x7b59.
        assert_eq!(rte_raw_cksum(&[0x00, 0x01, 0x02, 0x03]), 0x7b59);
    }

    #[test]
    fn zero_max_payload_size_always_takes_the_fast_path() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None, 0, false);
        let pkt = frame(&[1, 2, 3, 4, 5]);
        assert_eq!(
            f.out
                .send_packet(&hdr(1000, pkt.len() as u32), &pkt, PKT_DIR_NONCHECK),
            0
        );
        assert_eq!(sent(&state).len(), 1);
    }

    #[test]
    fn error_info_does_not_flush_at_the_window_edge() {
        let state = mock(vec![]);
        let mut f = fixture(state, 0, None, 0, false);
        let pkt = [0x88u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.out.send_packet(&hdr(1005, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(
            f.out.error_info.first_pktsec, 1000,
            "still inside the window"
        );
    }

    #[test]
    fn rate_limit_consumes_header_plus_payload_bytes() {
        // 300 tokens admits 28*8 = 224 but not 8*20*8 = 1280.
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, Some(TokenBucket::new(300)), 0, false);
        let pkt = [0x22u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.ratelimit_drop_packets.load(), (0, 0));
    }

    /// Same contract as the GRE output: `new_vxlan_output` propagates a
    /// `SO_BINDTODEVICE` / `IP_MTU_DISCOVER` failure instead of ignoring it
    /// (`PARITY.md`). The privileged part of that path lives in the live-capture
    /// job; argument validation and the kernel's rejection of a bad mode do not.
    #[cfg(target_os = "linux")]
    #[test]
    fn socket_option_wrappers_propagate_setsockopt_errors() {
        use crate::config::{IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_WANT};

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

        let e = set_bind_device(&sock, "vx\0lan").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);

        for mode in [IP_PMTUDISC_DONT, IP_PMTUDISC_WANT, IP_PMTUDISC_DO] {
            set_pmtudisc(&sock, mode).unwrap();
        }
        assert!(set_pmtudisc(&sock, 12345).is_err());
    }

    /// The constructor's non-privileged half: a real UDP socket, the pmtudisc
    /// wrapper and the rate-limit token bucket. `bind_device` needs CAP_NET_RAW,
    /// so its outcome is exercised but not asserted.
    #[test]
    fn new_builds_a_socket_and_honours_the_output_limits() {
        use crate::config::IP_PMTUDISC_DO;
        let out = |rate, slice| OutputConfig {
            kind: crate::config::OutputKind::Null,
            rate_limit_mbps: rate,
            slice,
        };
        let cfg = VxlanConfig {
            host: "127.0.0.1".to_string(),
            port: 4789,
            capture_time: false,
            vni_version: 1,
            vni: VNI,
            bind_device: String::new(),
            pmtudisc: -1,
            split: crate::config::SplitConfig::default(),
        };
        let stats = Arc::new(OutputStats::default());
        let plain = VxlanOutput::new(&cfg, &out(0, 0), Arc::clone(&stats)).expect("udp socket");
        assert!(plain.throttle.is_none());

        let cfg2 = VxlanConfig {
            pmtudisc: IP_PMTUDISC_DO,
            ..cfg
        };
        let limited = VxlanOutput::new(&cfg2, &out(10, 128), stats).expect("udp socket");
        assert!(
            limited.throttle.is_some(),
            "a positive rate limit is a bucket"
        );
    }

    #[test]
    fn new_rejects_a_bad_host_and_runs_the_bind_device_path() {
        let out = OutputConfig {
            kind: crate::config::OutputKind::Null,
            rate_limit_mbps: 0,
            slice: 0,
        };
        let stats = Arc::new(OutputStats::default());
        let mut cfg = VxlanConfig {
            host: "not-an-ip".to_string(),
            port: 4789,
            capture_time: false,
            vni_version: 1,
            vni: VNI,
            bind_device: String::new(),
            pmtudisc: -1,
            split: crate::config::SplitConfig::default(),
        };
        let e = match VxlanOutput::new(&cfg, &out, Arc::clone(&stats)) {
            Ok(_) => panic!("expected an invalid-host error"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("invalid vxlan host"), "{e}");
        cfg.host = "127.0.0.1".to_string();
        cfg.bind_device = "lo".to_string();
        // SO_BINDTODEVICE needs CAP_NET_RAW: Err unprivileged, Ok privileged.
        let _ = VxlanOutput::new(&cfg, &out, stats);
    }
}
