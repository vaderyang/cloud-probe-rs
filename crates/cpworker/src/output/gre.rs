//! GRE output. Port of `output_gre.c`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use super::{Output, PacketHeader};
use crate::config::{GreConfig, OutputConfig, IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_WANT};
use crate::error::{Error, Result};
use crate::packet::{GRE_HDR_LEN, PKT_DIR_UNKNOWN};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

const GRE_OUTPUT_BUFSIZE: usize = 65551;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;

/// Destination for an assembled GRE datagram.
///
/// Abstracted from the raw socket so the send/retry/stats state machine can be
/// exercised without `CAP_NET_RAW` (see the unit tests).
trait Egress: Send {
    fn send_to(&mut self, buf: &[u8]) -> std::io::Result<usize>;
}

struct RawSocketEgress {
    socket: Socket,
    remote: SocketAddr,
}

impl Egress for RawSocketEgress {
    fn send_to(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(buf, &self.remote.into())
    }
}

/// Wire-format GRE header used by the GRE output. This is the single source of
/// truth for the 8-byte header (also used by the protocol parity harness).
#[must_use]
pub fn gre_header(service_tag: u32, direct: i32) -> [u8; GRE_HDR_LEN] {
    let key = service_tag | ((direct as u32) << 28);
    let mut h = [0u8; GRE_HDR_LEN];
    h[0..2].copy_from_slice(&0x2000u16.to_be_bytes()); // flags: K=1
    h[2..4].copy_from_slice(&0x6558u16.to_be_bytes()); // protocol: Ethernet over GRE
    h[4..8].copy_from_slice(&key.to_be_bytes());
    h
}

#[derive(Default)]
struct ErrorInfo {
    first_pktsec: i64,
    nb_nobufs_drops: u64,
    nb_partial_sends: u64,
    nb_other_send_error_drops: u64,
    other_send_error: String,
}

/// GRE tunnel output.
pub struct GreOutput {
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,
    service_tag: u32,
    egress: Box<dyn Egress>,
    buf: Vec<u8>,
    error_info: ErrorInfo,
}

fn set_bind_device(socket: &Socket, device: &str) -> std::io::Result<()> {
    crate::sockopt::bind_to_device(socket, device)
}

fn set_pmtudisc(socket: &Socket, pmtudisc: i32) -> std::io::Result<()> {
    crate::sockopt::set_pmtudisc(socket, pmtudisc)
}

impl GreOutput {
    /// Create a GRE tunnel output.
    ///
    /// # Errors
    /// Returns an error if the host is invalid or the tunnel socket cannot be
    /// created or bound.
    pub fn new(cfg: &GreConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let addr: Ipv4Addr = cfg
            .host
            .parse()
            .map_err(|_| Error::new(format!("invalid gre host: {}", cfg.host)))?;
        let remote_addr = SocketAddrV4::new(addr, 0);

        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_GRE)),
        )
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

        Ok(GreOutput {
            stats,
            throttle,
            slice: out.slice,
            service_tag: cfg.service_tag,
            egress: Box::new(RawSocketEgress {
                socket,
                remote: SocketAddr::V4(remote_addr),
            }),
            buf: vec![0u8; GRE_OUTPUT_BUFSIZE],
            error_info: ErrorInfo::default(),
        })
    }

    fn flush_error_info(&mut self) {
        self.error_info.first_pktsec = 0;
        let e = &mut self.error_info;
        if e.nb_nobufs_drops > 0 || e.nb_partial_sends > 0 || e.nb_other_send_error_drops > 0 {
            crate::log_error!(
                "gre output error: nb_nobufs_drops={}, nb_partial_sends={}, nb_other_send_error_drops={}, detail: {}",
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
}

const ENOBUFS: i32 = 105;

impl Output for GreOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
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
            if !tb.consume(GRE_HDR_LEN + length, hdr.ts()) {
                self.stats
                    .ratelimit_drop_bytes
                    .add((GRE_HDR_LEN + length) as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        // GRE header: flags=0x2000 (K=1), protocol=0x6558 (Ethernet over GRE),
        // key = service_tag | (direct << 28), network byte order.
        self.buf[..GRE_HDR_LEN].copy_from_slice(&gre_header(self.service_tag, direct));
        self.buf[GRE_HDR_LEN..GRE_HDR_LEN + length].copy_from_slice(&pkt[..length]);

        if self.error_info.first_pktsec == 0 {
            self.error_info.first_pktsec = hdr.ts_sec;
        } else if hdr.ts_sec > self.error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC {
            self.flush_error_info();
            self.error_info.first_pktsec = hdr.ts_sec;
        }

        let total = GRE_HDR_LEN + length;
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

/// Ensure the unused constants are referenced (parity with `config.h` values).
#[allow(dead_code)]
fn _pmtudisc_consts() -> [i32; 3] {
    [IP_PMTUDISC_DONT, IP_PMTUDISC_WANT, IP_PMTUDISC_DO]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PKT_DIR_INCOMING, PKT_DIR_NONCHECK, PKT_DIR_OUTGOING};
    use crate::stats::OutputStats;
    use std::sync::{Arc, Mutex};

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
        out: GreOutput,
        stats: Arc<OutputStats>,
    }

    fn mock(responses: Vec<std::io::Result<usize>>) -> Arc<Mutex<MockState>> {
        Arc::new(Mutex::new(MockState {
            responses: responses.into(),
            sent: Vec::new(),
        }))
    }

    fn fixture(state: Arc<Mutex<MockState>>, slice: i32, throttle: Option<TokenBucket>) -> Fixture {
        let stats = Arc::new(OutputStats::default());
        let out = GreOutput {
            stats: Arc::clone(&stats),
            throttle,
            slice,
            service_tag: 0x0123_4567,
            egress: Box::new(MockEgress(Arc::clone(&state))),
            buf: vec![0u8; GRE_OUTPUT_BUFSIZE],
            error_info: ErrorInfo::default(),
        };
        Fixture { out, stats }
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

    #[test]
    fn gre_header_encodes_flags_protocol_and_key() {
        let h = gre_header(0x1234_5678, PKT_DIR_INCOMING);
        assert_eq!(&h[0..2], &[0x20, 0x00], "flags K=1");
        assert_eq!(&h[2..4], &[0x65, 0x58], "Ethernet over GRE");
        assert_eq!(
            u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            0x1234_5678 | (1 << 28)
        );
    }

    #[test]
    fn gre_header_key_high_nibble_is_the_direction() {
        assert_eq!(
            u32::from_be_bytes({
                let h = gre_header(0x0000_0001, PKT_DIR_OUTGOING);
                [h[4], h[5], h[6], h[7]]
            }),
            0x0000_0001 | (2 << 28)
        );
        assert_eq!(
            u32::from_be_bytes({
                let h = gre_header(0x0000_0001, PKT_DIR_NONCHECK);
                [h[4], h[5], h[6], h[7]]
            }),
            0x0000_0001
        );
    }

    #[test]
    fn _pmtudisc_consts_returns_config_values() {
        assert_eq!(
            _pmtudisc_consts(),
            [IP_PMTUDISC_DONT, IP_PMTUDISC_WANT, IP_PMTUDISC_DO]
        );
    }

    #[test]
    fn send_packet_forwards_header_and_payload() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None);
        let pkt = [0xAAu8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);

        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
        assert_eq!(f.stats.fwd_bytes.load(), (GRE_HDR_LEN as u64 + 20, 0));
        let s = sent(&state);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].len(), GRE_HDR_LEN + 20);
        assert_eq!(
            &s[0][..GRE_HDR_LEN],
            &gre_header(0x0123_4567, PKT_DIR_INCOMING)
        );
        assert_eq!(&s[0][GRE_HDR_LEN..], &pkt);
    }

    #[test]
    fn slice_truncates_the_payload() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 10, None);
        let pkt = [0x5Au8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.fwd_bytes.load(), (GRE_HDR_LEN as u64 + 10, 0));
        let s = sent(&state);
        assert_eq!(&s[0][GRE_HDR_LEN..], &pkt[..10]);
    }

    #[test]
    fn slice_larger_than_caplen_is_ignored() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 100, None);
        let pkt = [0x5Au8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(sent(&state)[0].len(), GRE_HDR_LEN + 20);
    }

    #[test]
    fn zero_caplen_forwards_a_bare_header() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None);
        assert_eq!(f.out.send_packet(&hdr(1000, 0), &[], PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.fwd_bytes.load(), (GRE_HDR_LEN as u64, 0));
        assert_eq!(sent(&state)[0].len(), GRE_HDR_LEN);
    }

    #[test]
    fn unknown_direction_drops_before_sending() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 10, None);
        let pkt = [0x11u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_UNKNOWN), -1);
        // The slice still bounds the counted length.
        assert_eq!(f.stats.direction_drop_bytes.load(), (10, 0));
        assert_eq!(f.stats.direction_drop_packets.load(), (1, 0));
        assert!(sent(&state).is_empty());
    }

    #[test]
    fn rate_limit_drop_reports_bytes_and_packets() {
        let state = mock(vec![]);
        // A 1-byte/second bucket cannot admit an 8+20 byte datagram.
        let mut f = fixture(state.clone(), 0, Some(TokenBucket::new(1)));
        let pkt = [0x22u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(
            f.stats.ratelimit_drop_bytes.load(),
            (GRE_HDR_LEN as u64 + 20, 0)
        );
        assert_eq!(f.stats.ratelimit_drop_packets.load(), (1, 0));
        assert_eq!(f.stats.fwd_packets.load(), (0, 0));
        assert!(sent(&state).is_empty());
    }

    #[test]
    fn rate_limit_consumes_header_plus_payload_bytes() {
        // Bucket admits 28*8 = 224 tokens but not 8*20*8 = 1280, so the
        // consumed amount must be GRE_HDR_LEN + length, not GRE_HDR_LEN * length.
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, Some(TokenBucket::new(1000)));
        let pkt = [0x22u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
        assert_eq!(f.stats.ratelimit_drop_packets.load(), (0, 0));
    }

    #[test]
    fn partial_send_reports_dropped_bytes() {
        let total = GRE_HDR_LEN + 20;
        let state = mock(vec![Ok(5)]);
        let mut f = fixture(state.clone(), 0, None);
        let pkt = [0x33u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_partial_sends, 1);
        assert_eq!(f.stats.error_drop_bytes.load(), (total as u64 - 5, 0));
        assert_eq!(f.stats.fwd_bytes.load(), (5, 0));
        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
    }

    #[test]
    fn enobufs_is_retried_then_succeeds() {
        let state = mock(vec![enobufs(), enobufs(), Ok(GRE_HDR_LEN + 20)]);
        let mut f = fixture(state.clone(), 0, None);
        let pkt = [0x44u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.stats.fwd_packets.load(), (1, 0));
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
        assert_eq!(sent(&state).len(), 3, "two retries then the success");
    }

    #[test]
    fn enobufs_after_max_retries_is_dropped() {
        let total = GRE_HDR_LEN + 20;
        let state = mock((0..11).map(|_| enobufs()).collect());
        let mut f = fixture(state.clone(), 0, None);
        let pkt = [0x55u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_nobufs_drops, 1);
        assert_eq!(f.stats.error_drop_bytes.load(), (total as u64, 0));
        assert_eq!(f.stats.error_drop_packets.load(), (1, 0));
        assert_eq!(sent(&state).len(), 11, "initial try + 10 retries");
    }

    #[test]
    fn other_send_error_records_the_first_detail_once() {
        let total = GRE_HDR_LEN + 20;
        let state = mock(vec![
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        ]);
        let mut f = fixture(state.clone(), 0, None);
        let pkt = [0x66u8; 20];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        let first = f.out.error_info.other_send_error.clone();
        assert!(!first.is_empty());
        assert_eq!(f.out.error_info.nb_other_send_error_drops, 1);
        assert_eq!(
            f.out.send_packet(&hdr(1001, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.nb_other_send_error_drops, 2);
        assert_eq!(
            f.out.error_info.other_send_error, first,
            "detail is not overwritten"
        );
        assert_eq!(f.stats.error_drop_bytes.load(), (2 * total as u64, 0));
    }

    #[test]
    fn flush_error_info_resets_state_and_counters() {
        let state = mock(vec![]);
        let mut f = fixture(state, 0, None);
        f.out.error_info.first_pktsec = 1000;
        f.out.error_info.nb_nobufs_drops = 3;
        f.out.error_info.nb_partial_sends = 1;
        f.out.error_info.nb_other_send_error_drops = 2;
        f.out.error_info.other_send_error = "boom".into();
        f.out.flush_error_info();
        assert_eq!(f.out.error_info.first_pktsec, 0);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
        assert_eq!(f.out.error_info.nb_partial_sends, 0);
        assert_eq!(f.out.error_info.nb_other_send_error_drops, 0);
        assert!(f.out.error_info.other_send_error.is_empty());
    }

    #[test]
    fn error_info_flushes_after_the_five_second_window() {
        let state = mock((0..11).map(|_| enobufs()).collect());
        let mut f = fixture(state, 0, None);
        let pkt = [0x77u8; 20];
        // First packet records first_pktsec=1000 and one drop.
        assert_eq!(
            f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING),
            -1
        );
        assert_eq!(f.out.error_info.first_pktsec, 1000);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 1);
        // A packet more than 5s later flushes the window.
        assert_eq!(f.out.send_packet(&hdr(1006, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.out.error_info.first_pktsec, 1006);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
    }

    #[test]
    fn flush_error_info_resets_when_only_one_counter_is_set() {
        for which in 0..3 {
            let state = mock(vec![]);
            let mut f = fixture(state, 0, None);
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
    fn flush_error_info_is_a_noop_with_no_counters() {
        let state = mock(vec![]);
        let mut f = fixture(state, 0, None);
        f.out.error_info.first_pktsec = 42;
        f.out.flush_error_info();
        assert_eq!(f.out.error_info.first_pktsec, 0);
        assert_eq!(f.out.error_info.nb_nobufs_drops, 0);
    }

    #[test]
    fn send_packet_handles_the_maximum_caplen() {
        let state = mock(vec![]);
        let mut f = fixture(state.clone(), 0, None);
        let pkt = vec![0xC7u8; 65535];
        assert_eq!(
            f.out.send_packet(&hdr(1000, 65535), &pkt, PKT_DIR_INCOMING),
            0
        );
        assert_eq!(f.stats.fwd_bytes.load(), (GRE_HDR_LEN as u64 + 65535, 0));
        assert_eq!(sent(&state)[0].len(), GRE_HDR_LEN + 65535);
        assert_eq!(&sent(&state)[0][GRE_HDR_LEN..], &pkt[..]);
    }

    #[test]
    fn error_info_does_not_flush_inside_the_window() {
        let state = mock(vec![]);
        let mut f = fixture(state, 0, None);
        let pkt = [0x88u8; 20];
        assert_eq!(f.out.send_packet(&hdr(1000, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.out.send_packet(&hdr(1005, 20), &pkt, PKT_DIR_INCOMING), 0);
        assert_eq!(f.out.error_info.first_pktsec, 1000);
    }

    #[test]
    fn new_rejects_an_invalid_host() {
        let gre = GreConfig {
            host: "not-an-ip".into(),
            service_tag: 0,
            bind_device: String::new(),
            pmtudisc: -1,
        };
        let out = OutputConfig {
            kind: crate::config::OutputKind::Gre(gre.clone()),
            rate_limit_mbps: 0,
            slice: 0,
        };
        let err = match GreOutput::new(&gre, &out, Arc::new(OutputStats::default())) {
            Ok(_) => panic!("expected an invalid-host error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("invalid gre host"),
            "unexpected error: {err}"
        );
    }
}
