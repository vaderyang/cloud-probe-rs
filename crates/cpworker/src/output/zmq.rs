//! ZeroMQ batched output. Port of `output_zmq.c`.
//!
//! The batch buffer assembly is factored into [`BatchBuilder`], which is the
//! single source of truth for the ZMQ wire format (also exercised by the
//! protocol parity harness).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Output, PacketHeader};
use crate::config::{OutputConfig, ZmqConfig};
use crate::error::{Error, Result};
use crate::packet::{
    be16, ETHERTYPE_DOT1AD, ETHERTYPE_MPLS, ETHERTYPE_VLAN, ETHERTYPE_VLAN_9100,
    ETHERTYPE_VLAN_9200, ETH_HDR_LEN, PKT_DIR_UNKNOWN, VLAN_HDR_LEN,
};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

const ZMQ_MAX_BATCH_BUF_SIZE: usize = 1_048_576;
const ZMQ_PKTS_FLUSH_MAX_DUR_SEC: i64 = 1;
const ZMQ_PKTS_FLUSH_MAX_NUM: usize = 65535;
const ZMQ_BATCH_PKTS_VERSION: u16 = 2;
const ZMQ_HEARTBEAT_ETHER_TYPE: u16 = 0xFFFF;
const BATCH_HDR_SIZE: usize = 24; // version(2) + pkts_num(2) + keybit(4) + uuid(16)
const PKT_HDR_SIZE: usize = 16;
const MPLS_HDR_SIZE: usize = 4;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;

pub fn uuid_to_bytes(uuid: &str) -> Option<[u8; 16]> {
    let clean: Vec<u8> = uuid.bytes().filter(|&b| b != b'-').collect();
    if clean.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (clean[i * 2] as char).to_digit(16)?;
        let lo = (clean[i * 2 + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

pub fn make_mpls_hdr(direct: i32, service_tag: u32) -> u32 {
    let b0 = (1u8 << 7) | (((direct as u8) & 0x0f) << 3);
    let b1 = (service_tag >> 4) as u8;
    let b2 = (((service_tag as u8) & 0x0f) << 4) | 1;
    let b3 = 0xffu8;
    u32::from_ne_bytes([b0, b1, b2, b3])
}

/// ZMQ batch buffer builder. Single source of truth for the ZMQ wire format.
pub struct BatchBuilder {
    pub buf: Vec<u8>,
    pos: usize,
    num: u16,
    first_pktsec: i64,
    service_tag: u32,
}

impl BatchBuilder {
    pub fn new(service_tag: u32, uuid: &[u8; 16]) -> Self {
        let mut buf = vec![0u8; ZMQ_MAX_BATCH_BUF_SIZE];
        buf[0..2].copy_from_slice(&ZMQ_BATCH_PKTS_VERSION.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        buf[4..8].copy_from_slice(&service_tag.to_be_bytes());
        buf[8..24].copy_from_slice(uuid);
        BatchBuilder {
            buf,
            pos: BATCH_HDR_SIZE,
            num: 0,
            first_pktsec: 0,
            service_tag,
        }
    }

    pub fn num(&self) -> u16 {
        self.num
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn first_pktsec(&self) -> i64 {
        self.first_pktsec
    }
    pub fn set_first_pktsec(&mut self, t: i64) {
        self.first_pktsec = t;
    }

    /// Whether the pending batch must be flushed before adding a packet of the
    /// given wire length at the given timestamp.
    pub fn should_flush(&self, ts_sec: i64, length: usize) -> bool {
        self.num as usize >= ZMQ_PKTS_FLUSH_MAX_NUM
            || (self.first_pktsec != 0 && ts_sec > self.first_pktsec + ZMQ_PKTS_FLUSH_MAX_DUR_SEC)
            || self.pos + 2 + PKT_HDR_SIZE + length > ZMQ_MAX_BATCH_BUF_SIZE
    }

    /// Stamp `pkts_num` into the header and return `(num, len)`; does not reset.
    pub fn begin_flush(&mut self) -> (u16, usize) {
        self.buf[2..4].copy_from_slice(&self.num.to_be_bytes());
        (self.num, self.pos)
    }

    pub fn end_flush(&mut self) {
        self.first_pktsec = 0;
        self.pos = BATCH_HDR_SIZE;
        self.num = 0;
    }

    /// Append a captured packet. `length` is caplen(+MPLS) in wire terms;
    /// `wire_len` is the original wire length (+MPLS).
    pub fn append_packet(
        &mut self,
        ts_sec: i64,
        ts_usec: i64,
        length: u16,
        wire_len: u32,
        pkt_data: &[u8],
        direct: i32,
    ) -> bool {
        let length_usize = length as usize;
        if pkt_data.len() < ETH_HDR_LEN {
            return false;
        }

        // VLAN walk.
        let mut ether_type = be16(&pkt_data[12..14]);
        let mut vlan_total_size = 0usize;
        while matches!(
            ether_type,
            ETHERTYPE_VLAN | ETHERTYPE_DOT1AD | ETHERTYPE_VLAN_9100 | ETHERTYPE_VLAN_9200
        ) {
            let vlan_offset = ETH_HDR_LEN + vlan_total_size;
            if vlan_offset + VLAN_HDR_LEN > length_usize
                || pkt_data.len() < vlan_offset + VLAN_HDR_LEN
            {
                break;
            }
            ether_type = be16(&pkt_data[vlan_offset + 2..vlan_offset + 4]);
            vlan_total_size += VLAN_HDR_LEN;
        }
        let has_vlan = vlan_total_size > 0;

        // Safety guard: the C VLAN walk can over-count (its bound is
        // `caplen + MPLS_HDR_SIZE`, one tag past the captured data). When
        // `slice` truncates a VLAN frame this makes the C subtraction
        // `length - 14 - 4 - vlan_total_size` underflow to ~2^64 and perform a
        // wild out-of-bounds memcpy. That is undefined behaviour; drop the
        // packet instead (safe divergence from the original).
        if ETH_HDR_LEN + MPLS_HDR_SIZE + vlan_total_size > length_usize {
            return false;
        }

        let mut pos = self.pos;
        // pkt_data_len (network order)
        self.buf[pos..pos + 2].copy_from_slice(&length.to_be_bytes());
        pos += 2;
        // pkt_hdr: tv_sec, tv_usec, caplen(=length), len(=wire_len)
        self.buf[pos..pos + 4].copy_from_slice(&(ts_sec as u32).to_be_bytes());
        self.buf[pos + 4..pos + 8].copy_from_slice(&(ts_usec as u32).to_be_bytes());
        self.buf[pos + 8..pos + 12].copy_from_slice(&(length_usize as u32).to_be_bytes());
        self.buf[pos + 12..pos + 16].copy_from_slice(&wire_len.to_be_bytes());
        pos += PKT_HDR_SIZE;

        // Ethernet header (ether_type -> MPLS unless VLAN present).
        self.buf[pos..pos + ETH_HDR_LEN].copy_from_slice(&pkt_data[..ETH_HDR_LEN]);
        if !has_vlan {
            self.buf[pos + 12..pos + 14].copy_from_slice(&ETHERTYPE_MPLS.to_be_bytes());
        }
        pos += ETH_HDR_LEN;

        if has_vlan {
            self.buf[pos..pos + vlan_total_size]
                .copy_from_slice(&pkt_data[ETH_HDR_LEN..ETH_HDR_LEN + vlan_total_size]);
            let last_etype = pos + vlan_total_size - 2;
            self.buf[last_etype..last_etype + 2].copy_from_slice(&ETHERTYPE_MPLS.to_be_bytes());
            pos += vlan_total_size;
        }

        // MPLS header.
        let mpls = make_mpls_hdr(direct, self.service_tag);
        self.buf[pos..pos + MPLS_HDR_SIZE].copy_from_slice(&mpls.to_ne_bytes());
        pos += MPLS_HDR_SIZE;

        let payload_offset = ETH_HDR_LEN + vlan_total_size;
        let payload_copy_len = length_usize - ETH_HDR_LEN - MPLS_HDR_SIZE - vlan_total_size;
        self.buf[pos..pos + payload_copy_len]
            .copy_from_slice(&pkt_data[payload_offset..payload_offset + payload_copy_len]);
        pos += payload_copy_len;

        self.pos = pos;
        self.num += 1;
        true
    }

    /// Append a heartbeat frame (14-byte Ethernet with sentinel EtherType).
    pub fn append_heartbeat(&mut self, ts_sec: i64, ts_usec: i64) {
        let pkt_len = ETH_HDR_LEN;
        let mut pos = self.pos;
        self.buf[pos..pos + 2].copy_from_slice(&(pkt_len as u16).to_be_bytes());
        pos += 2;
        self.buf[pos..pos + 4].copy_from_slice(&(ts_sec as u32).to_be_bytes());
        self.buf[pos + 4..pos + 8].copy_from_slice(&(ts_usec as u32).to_be_bytes());
        self.buf[pos + 8..pos + 12].copy_from_slice(&(pkt_len as u32).to_be_bytes());
        self.buf[pos + 12..pos + 16].copy_from_slice(&(pkt_len as u32).to_be_bytes());
        pos += PKT_HDR_SIZE;
        for b in &mut self.buf[pos..pos + ETH_HDR_LEN] {
            *b = 0;
        }
        self.buf[pos + 12..pos + 14].copy_from_slice(&ZMQ_HEARTBEAT_ETHER_TYPE.to_be_bytes());
        pos += ETH_HDR_LEN;

        self.pos = pos;
        self.num += 1;
    }
}

#[derive(Default)]
struct ErrorInfo {
    first_pktsec: i64,
    nb_drop_packets: u64,
    nb_drop_batches: u64,
    nb_too_small_packets: u64,
    send_error: String,
}

pub struct ZmqOutput {
    stats: Arc<OutputStats>,
    rate_limit_mbps: u64,
    throttle: Option<TokenBucket>,
    slice: i32,

    context: zmq::Context,
    pusher: zmq::Socket,

    builder: BatchBuilder,

    heartbeat_ms: i32,
    last_pkt_ts: (i64, i64),
    error_info: ErrorInfo,
}

impl ZmqOutput {
    pub fn new(cfg: &ZmqConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let uuid = uuid_to_bytes(&cfg.uuid)
            .ok_or_else(|| Error::new(format!("invalid uuid: {}", cfg.uuid)))?;

        let context = zmq::Context::new();
        let pusher = context
            .socket(zmq::PUSH)
            .map_err(|e| Error::new(format!("zmq_socket() error: {e}")))?;
        pusher
            .set_sndhwm(cfg.hwm)
            .map_err(|e| Error::new(format!("set hwm error: {e}")))?;
        pusher
            .set_linger(5 * 1000)
            .map_err(|e| Error::new(format!("set linger error: {e}")))?;

        let address = format!("tcp://{}:{}", cfg.host, cfg.port);
        pusher
            .connect(&address)
            .map_err(|e| Error::new(format!("zmq connect address {address} error: {e}")))?;

        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };

        let now = now_ts();
        Ok(ZmqOutput {
            stats,
            rate_limit_mbps: out.rate_limit_mbps,
            throttle,
            slice: out.slice,
            context: context.clone(),
            pusher,
            builder: BatchBuilder::new(cfg.service_tag, &uuid),
            heartbeat_ms: cfg.heartbeat_ms,
            last_pkt_ts: now,
            error_info: ErrorInfo::default(),
        })
    }

    fn flush_error_info(&mut self) {
        self.error_info.first_pktsec = 0;
        if self.error_info.nb_too_small_packets > 0 {
            crate::log_warn!(
                "zmq output: nb_too_small_packets={} (dropped)",
                self.error_info.nb_too_small_packets
            );
            self.error_info.nb_too_small_packets = 0;
        }
        let e = &mut self.error_info;
        if e.nb_drop_batches > 0 || e.nb_drop_packets > 0 {
            crate::log_error!(
                "zmq output error: nb_drop_batches={}, nb_drop_packets={}, detail: {}",
                e.nb_drop_batches,
                e.nb_drop_packets,
                e.send_error
            );
            e.nb_drop_batches = 0;
            e.nb_drop_packets = 0;
            e.send_error.clear();
        }
    }

    /// Port of `zmq_flush_packet`.
    fn flush_packet(&mut self) {
        let (send_num, len) = self.builder.begin_flush();

        if self.error_info.first_pktsec == 0 {
            self.error_info.first_pktsec = self.builder.first_pktsec();
        } else if self.builder.first_pktsec()
            > self.error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC
        {
            self.flush_error_info();
            self.error_info.first_pktsec = self.builder.first_pktsec();
        }

        let sent = self.pusher.send(&self.builder.buf[..len], zmq::DONTWAIT);
        match sent {
            Ok(()) => {
                self.stats.fwd_bytes.add(len as u64);
                self.stats.fwd_packets.add(send_num as u64);
            }
            Err(e) => {
                if self.error_info.nb_drop_batches == 0 {
                    self.error_info.send_error = format!("zmq_send failed: {e}");
                }
                self.error_info.nb_drop_batches += 1;
                self.error_info.nb_drop_packets += send_num as u64;
                self.stats.error_drop_bytes.add(len as u64);
                self.stats.error_drop_packets.add(send_num as u64);
            }
        }

        self.builder.end_flush();
    }

    fn flush_if_stale(&mut self, now: i64) {
        if self.builder.num() > 0
            && self.builder.first_pktsec() != 0
            && now > self.builder.first_pktsec() + ZMQ_PKTS_FLUSH_MAX_DUR_SEC
        {
            self.flush_packet();
        }
    }

    fn send_heartbeat_packet(&mut self, ts: (i64, i64)) {
        let pkt_len = ETH_HDR_LEN;
        if self.builder.pos() + 2 + PKT_HDR_SIZE + pkt_len > ZMQ_MAX_BATCH_BUF_SIZE {
            self.flush_packet();
        }
        if self.builder.num() == 0 {
            self.builder.set_first_pktsec(ts.0);
        }

        self.builder.append_heartbeat(ts.0, ts.1);
        self.flush_packet();
        self.stats.heartbeat_packets.add(1);
        self.last_pkt_ts = ts;
    }
}

fn now_ts() -> (i64, i64) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_micros() as i64),
        Err(_) => (0, 0),
    }
}

impl Output for ZmqOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt_data: &[u8], direct: i32) -> i32 {
        let mut caplen = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < caplen {
            caplen = self.slice as u32;
        }

        // Ethernet header + one VLAN tag must fit.
        if caplen < (ETH_HDR_LEN + VLAN_HDR_LEN) as u32 {
            self.error_info.nb_too_small_packets += 1;
            return -1;
        }

        let length = (caplen.min(65531) as usize) + MPLS_HDR_SIZE;
        let wire_len = hdr.len + MPLS_HDR_SIZE as u32;

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(length as u64);
            self.stats.direction_drop_packets.add(1);
            self.flush_if_stale(hdr.ts_sec);
            return -1;
        }

        if self.rate_limit_mbps > 0 {
            let tb = self.throttle.as_mut().unwrap();
            if !tb.consume(length, hdr.ts()) {
                self.stats.ratelimit_drop_bytes.add(length as u64);
                self.stats.ratelimit_drop_packets.add(1);
                self.flush_if_stale(hdr.ts_sec);
                return -1;
            }
        }

        if self.builder.num() == 0 {
            self.builder.set_first_pktsec(hdr.ts_sec);
        }

        if self.builder.should_flush(hdr.ts_sec, length) {
            self.flush_packet();
            self.builder.set_first_pktsec(hdr.ts_sec);
        }
        if self.builder.first_pktsec() == 0 {
            self.builder.set_first_pktsec(hdr.ts_sec);
        }

        if !self.builder.append_packet(
            hdr.ts_sec,
            hdr.ts_usec,
            length as u16,
            wire_len,
            pkt_data,
            direct,
        ) {
            return -1;
        }
        self.last_pkt_ts = hdr.ts();
        0
    }

    fn heartbeat(&mut self, now: i64) {
        self.flush_if_stale(now);
        if self.heartbeat_ms <= 0 {
            return;
        }
        let coarse_elapsed_s = now - self.last_pkt_ts.0;
        if coarse_elapsed_s * 1000 < (self.heartbeat_ms - 1000) as i64 {
            return;
        }
        let now_tv = now_ts();
        let elapsed_ms =
            (now_tv.0 - self.last_pkt_ts.0) * 1000 + (now_tv.1 - self.last_pkt_ts.1) / 1000;
        if elapsed_ms >= self.heartbeat_ms as i64 {
            self.send_heartbeat_packet(now_tv);
        }
    }
}
