//! Simulated probe: runs the real cpworker encapsulation / rate-limit /
//! fragmentation code and emits wire frames.

use cpworker::output::gre::gre_header;
use cpworker::output::vxlan::vxlan_encapsulate;
use cpworker::output::zmq::{uuid_to_bytes, BatchBuilder};
use cpworker::packet::{
    parse_packet, PKT_DIR_INCOMING, PKT_DIR_NONCHECK, PKT_DIR_OUTGOING, PKT_DIR_UNKNOWN,
};
use cpworker::packet_split::{build_fragment, calculate_fragment_count};
use cpworker::ratelimit::TokenBucket;

use crate::packet_gen::gen_frame;
use crate::{FrameKind, Message, Rng, TimeUs};

const VXLAN_BUFSIZE: usize = 65551;
const GRE_HDR_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Out {
    Gre,
    Vxlan,
    Zmq,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub out: Out,
    pub service_tag: u32,
    pub vni: u32,
    pub vni_version: u8,
    pub capture_time: bool,
    pub slice: i32,
    pub rate_limit_mbps: u64,
    pub max_payload_size: u16,
    pub recalculate_checksum: bool,
    pub heartbeat_ms: i32,
    pub uuid: String,
    pub frame_min: usize,
    pub frame_max: usize,
    pub seed: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            out: Out::Zmq,
            service_tag: 0x1234,
            vni: 100,
            vni_version: 1,
            capture_time: false,
            slice: 0,
            rate_limit_mbps: 0,
            max_payload_size: 0,
            recalculate_checksum: false,
            heartbeat_ms: 0,
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            frame_min: 18,
            frame_max: 1514,
            seed: 1,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProbeStats {
    pub ratelimit_dropped: u64,
    pub direction_dropped: u64,
    pub builder_dropped: u64,
}

pub struct Probe {
    pub cfg: ProbeConfig,
    pub heartbeat_ms: i32,
    pub last_direct: i32,
    pub packets_injected: usize,
    pub stats: ProbeStats,
    bucket: TokenBucket,
    builder: BatchBuilder,
    vxlan_buf: Vec<u8>,
    frag_buf: Vec<u8>,
    serial: u64,
}

impl Probe {
    pub fn new(cfg: ProbeConfig) -> Self {
        let uuid = uuid_to_bytes(&cfg.uuid).expect("sim uuid must be valid");
        // TokenBucket::new(0) is a no-op limiter; only use it when configured.
        let bucket = TokenBucket::new(cfg.rate_limit_mbps.saturating_mul(1_000_000).max(1));
        Probe {
            heartbeat_ms: cfg.heartbeat_ms,
            builder: BatchBuilder::new(cfg.service_tag, &uuid),
            vxlan_buf: vec![0u8; VXLAN_BUFSIZE],
            frag_buf: vec![0u8; VXLAN_BUFSIZE],
            bucket,
            serial: 0,
            last_direct: 0,
            packets_injected: 0,
            stats: ProbeStats::default(),
            cfg,
        }
    }

    fn mk(&mut self, kind: FrameKind, pkt_count: u16, bytes: Vec<u8>) -> Message {
        let serial = self.serial;
        self.serial += 1;
        Message {
            serial,
            kind,
            pkt_count,
            bytes,
        }
    }

    fn rate_ok(&mut self, bytes: usize, ts: (i64, i64)) -> bool {
        if self.cfg.rate_limit_mbps == 0 {
            return true;
        }
        self.bucket.consume(bytes, ts)
    }

    /// Inject packet `idx` at virtual time `now`.
    pub fn inject(
        &mut self,
        _idx: usize,
        now: TimeUs,
        rng: &mut Rng,
    ) -> (Vec<Message>, ProbeStats) {
        let mut delta = ProbeStats::default();
        let ts = ((now / 1_000_000) as i64, (now % 1_000_000) as i64);

        let frame = gen_frame(rng, self.cfg.frame_min, self.cfg.frame_max);
        let caplen_orig = frame.len() as u32;

        let roll = rng.below(100);
        let direct = if roll < 5 {
            PKT_DIR_UNKNOWN
        } else if roll < 8 {
            PKT_DIR_NONCHECK
        } else if roll < 50 {
            PKT_DIR_INCOMING
        } else {
            PKT_DIR_OUTGOING
        };
        self.last_direct = direct;
        self.packets_injected += 1;

        if direct == PKT_DIR_UNKNOWN {
            delta.direction_dropped += 1;
            self.stats.direction_dropped += 1;
            return (Vec::new(), delta);
        }

        let mut caplen = caplen_orig;
        if self.cfg.slice > 0 && (self.cfg.slice as u32) < caplen {
            caplen = self.cfg.slice as u32;
        }

        let msgs = match self.cfg.out {
            Out::Gre => self.encode_gre(&frame, caplen, direct, ts, &mut delta),
            Out::Vxlan => self.encode_vxlan(&frame, caplen, direct, ts, &mut delta),
            Out::Zmq => self.encode_zmq(&frame, caplen, direct, ts, &mut delta),
        };
        self.stats.ratelimit_dropped += delta.ratelimit_dropped;
        self.stats.direction_dropped += delta.direction_dropped;
        self.stats.builder_dropped += delta.builder_dropped;
        (msgs, delta)
    }

    fn encode_gre(
        &mut self,
        frame: &[u8],
        caplen: u32,
        direct: i32,
        ts: (i64, i64),
        delta: &mut ProbeStats,
    ) -> Vec<Message> {
        let len = caplen.min(65535) as usize;
        if !self.rate_ok(GRE_HDR_LEN + len, ts) {
            delta.ratelimit_dropped += 1;
            return Vec::new();
        }
        let hdr = gre_header(self.cfg.service_tag, direct);
        let mut bytes = Vec::with_capacity(GRE_HDR_LEN + len);
        bytes.extend_from_slice(&hdr);
        bytes.extend_from_slice(&frame[..len]);
        vec![self.mk(FrameKind::Gre, 1, bytes)]
    }

    fn encode_vxlan(
        &mut self,
        frame: &[u8],
        caplen: u32,
        direct: i32,
        ts: (i64, i64),
        delta: &mut ProbeStats,
    ) -> Vec<Message> {
        let len = caplen.min(65535) as usize;
        if !self.rate_ok(8 + len, ts) {
            delta.ratelimit_dropped += 1;
            return Vec::new();
        }

        let mut out = Vec::new();
        let needs_split = self.cfg.max_payload_size > 0
            && len > self.cfg.max_payload_size as usize
            && parse_packet(frame).is_some();
        if !needs_split {
            out.push(self.vxlan_one(frame, len, direct, ts));
            return out;
        }

        let parse = parse_packet(frame).unwrap();
        let count = calculate_fragment_count(&parse, self.cfg.max_payload_size as i32);
        if count <= 1 {
            out.push(self.vxlan_one(frame, len, direct, ts));
            return out;
        }
        for i in 0..count {
            let frag_len = match build_fragment(
                &parse,
                frame,
                i,
                self.cfg.max_payload_size as i32,
                self.cfg.recalculate_checksum,
                &mut self.frag_buf,
            ) {
                Some(n) => n,
                None => break,
            };
            let frag = self.frag_buf[..frag_len].to_vec();
            out.push(self.vxlan_one(&frag, frag_len, direct, ts));
        }
        out
    }

    fn vxlan_one(&mut self, inner: &[u8], len: usize, direct: i32, ts: (i64, i64)) -> Message {
        let total = vxlan_encapsulate(
            &mut self.vxlan_buf,
            self.cfg.vni,
            self.cfg.vni_version,
            direct,
            self.cfg.capture_time,
            ts.0,
            ts.1,
            &inner[..len],
        );
        let bytes = self.vxlan_buf[..total].to_vec();
        self.mk(FrameKind::Vxlan, 1, bytes)
    }

    fn encode_zmq(
        &mut self,
        frame: &[u8],
        caplen: u32,
        direct: i32,
        ts: (i64, i64),
        delta: &mut ProbeStats,
    ) -> Vec<Message> {
        if caplen < 18 {
            delta.builder_dropped += 1;
            return Vec::new();
        }
        let length = (caplen.min(65531) as usize) + 4;
        let wire_len = frame.len() as u32 + 4;
        if !self.rate_ok(length, ts) {
            delta.ratelimit_dropped += 1;
            return Vec::new();
        }

        let mut out = Vec::new();
        if self.builder.num() == 0 {
            self.builder.set_first_pktsec(ts.0);
        }
        if self.builder.should_flush(ts.0, length) {
            out.extend(self.flush());
            self.builder.set_first_pktsec(ts.0);
        }
        if self.builder.first_pktsec() == 0 {
            self.builder.set_first_pktsec(ts.0);
        }
        if !self
            .builder
            .append_packet(ts.0, ts.1, length as u16, wire_len, frame, direct)
        {
            delta.builder_dropped += 1;
        }
        out
    }

    /// Flush any pending ZMQ batch (0 or 1 message).
    pub fn flush(&mut self) -> Vec<Message> {
        self.flush_as(FrameKind::ZmqBatch)
    }

    fn flush_as(&mut self, kind: FrameKind) -> Vec<Message> {
        if self.builder.num() == 0 {
            return Vec::new();
        }
        let (num, len) = self.builder.begin_flush();
        let bytes = self.builder.buf[..len].to_vec();
        self.builder.end_flush();
        vec![self.mk(kind, num, bytes)]
    }

    fn flush_if_stale(&mut self, now: TimeUs) -> Vec<Message> {
        let now_sec = (now / 1_000_000) as i64;
        if self.builder.num() > 0
            && self.builder.first_pktsec() != 0
            && now_sec > self.builder.first_pktsec() + 1
        {
            self.flush()
        } else {
            Vec::new()
        }
    }

    /// Emit a heartbeat frame if enabled. Deterministic: a heartbeat is sent on
    /// every scheduled heartbeat tick.
    pub fn heartbeat(&mut self, now: TimeUs) -> Vec<Message> {
        let mut out = self.flush_if_stale(now);
        if self.heartbeat_ms <= 0 {
            return out;
        }
        let ts = ((now / 1_000_000) as i64, (now % 1_000_000) as i64);
        // Make room if needed.
        if self.builder.pos() + 2 + 16 + 14 > 1_048_576 {
            out.extend(self.flush());
        }
        if self.builder.num() == 0 {
            self.builder.set_first_pktsec(ts.0);
        }
        self.builder.append_heartbeat(ts.0, ts.1);
        out.extend(self.flush_as(FrameKind::ZmqHeartbeat));
        out
    }
}
