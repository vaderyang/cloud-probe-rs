//! ZeroMQ batched output. Port of `output_zmq.c`.
//!
//! The batch buffer assembly is factored into [`BatchBuilder`], which is the
//! single source of truth for the ZMQ wire format (also exercised by the
//! protocol parity harness).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Output, PacketHeader};
use crate::config::{OutputConfig, ZmqConfig};
use crate::error::{Error, Result};
use crate::packet::{
    be16, ETHERTYPE_DOT1AD, ETHERTYPE_MPLS, ETHERTYPE_VLAN, ETHERTYPE_VLAN_9100,
    ETHERTYPE_VLAN_9200, ETH_HDR_LEN, PKT_DIR_UNKNOWN, VLAN_HDR_LEN,
};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;
use crate::zmtp::client::MessageAccount;
use crate::zmtp::{self, SendOutcome, ZmtpPush};

const ZMQ_MAX_BATCH_BUF_SIZE: usize = 1_048_576;
const ZMQ_PKTS_FLUSH_MAX_DUR_SEC: i64 = 1;
const ZMQ_PKTS_FLUSH_MAX_NUM: usize = 65535;
const ZMQ_BATCH_PKTS_VERSION: u16 = 2;
const ZMQ_HEARTBEAT_ETHER_TYPE: u16 = 0xFFFF;
const BATCH_HDR_SIZE: usize = 24; // version(2) + pkts_num(2) + keybit(4) + uuid(16)
const PKT_HDR_SIZE: usize = 16;
const MPLS_HDR_SIZE: usize = 4;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;

#[must_use]
/// Parse a UUID string into its 16-byte representation, or `None` if invalid.
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

#[must_use]
/// Build the 32-bit MPLS label header carrying direction and service tag.
pub fn make_mpls_hdr(direct: i32, service_tag: u32) -> u32 {
    let b0 = (1u8 << 7) | (((direct as u8) & 0x0f) << 3);
    let b1 = (service_tag >> 4) as u8;
    let b2 = (((service_tag as u8) & 0x0f) << 4) | 1;
    let b3 = 0xffu8;
    u32::from_ne_bytes([b0, b1, b2, b3])
}

/// ZMQ batch buffer builder. Single source of truth for the ZMQ wire format.
pub struct BatchBuilder {
    /// The underlying batch buffer (header + packets).
    pub buf: Vec<u8>,
    pos: usize,
    num: u16,
    first_pktsec: i64,
    service_tag: u32,
}

impl BatchBuilder {
    /// Create a builder for `service_tag` and `uuid`, writing the batch header.
    #[must_use]
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

    /// Number of packets currently in the batch.
    #[must_use]
    pub fn num(&self) -> u16 {
        self.num
    }
    /// Current write position within the buffer.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }
    /// Timestamp (seconds) of the first packet in the batch, or 0 if empty.
    #[must_use]
    pub fn first_pktsec(&self) -> i64 {
        self.first_pktsec
    }
    /// Set the timestamp of the first packet in the batch.
    pub fn set_first_pktsec(&mut self, t: i64) {
        self.first_pktsec = t;
    }

    /// Whether the pending batch must be flushed before adding a packet of the
    /// given wire length at the given timestamp.
    #[must_use]
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

    /// Reset the builder after a flush has been sent.
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

        // VLAN walk, bounded by the *captured* payload (`data_len`), not the
        // on-wire `length` which already includes the MPLS header (#231 fix).
        let data_len = length_usize.saturating_sub(MPLS_HDR_SIZE);
        let mut ether_type = be16(&pkt_data[12..14]);
        let mut vlan_total_size = 0usize;
        while matches!(
            ether_type,
            ETHERTYPE_VLAN | ETHERTYPE_DOT1AD | ETHERTYPE_VLAN_9100 | ETHERTYPE_VLAN_9200
        ) {
            let vlan_offset = ETH_HDR_LEN + vlan_total_size;
            if vlan_offset + VLAN_HDR_LEN > data_len || pkt_data.len() < vlan_offset + VLAN_HDR_LEN
            {
                break;
            }
            ether_type = be16(&pkt_data[vlan_offset + 2..vlan_offset + 4]);
            vlan_total_size += VLAN_HDR_LEN;
        }
        let has_vlan = vlan_total_size > 0;

        // Safety guard: never let the (correctly bounded) walk produce a
        // negative payload length; drop rather than perform C's old
        // out-of-bounds `memcpy` (safe divergence, PARITY.md §2.2).
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

/// ZMQ batch output pushing to a collector.
pub struct ZmqOutput {
    /// Byte ceiling of the ZMTP send queue (see [`ZmqOutput::queue_budget_bytes`]).
    queue_budget_bytes: usize,
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,

    /// Pure-Rust ZMTP `PUSH` client (non-blocking, auto-reconnect).
    zmtp: ZmtpPush,

    builder: BatchBuilder,

    heartbeat_ms: i32,
    last_pkt_ts: (i64, i64),
    error_info: ErrorInfo,
}

impl ZmqOutput {
    /// Create a ZMQ output.
    ///
    /// # Errors
    /// Returns an error if the uuid is invalid or the ZMQ socket cannot be
    /// created or connected.
    pub fn new(cfg: &ZmqConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let uuid = if cfg.uuid.is_empty() {
            // uuid is optional (#249): when unset it stays all-zero on the wire.
            [0u8; 16]
        } else {
            uuid_to_bytes(&cfg.uuid)
                .ok_or_else(|| Error::new(format!("invalid uuid: {}", cfg.uuid)))?
        };

        let address = format!("tcp://{}:{}", cfg.host, cfg.port);
        let connector = zmtp::tcp_connector(&cfg.host, cfg.port)
            .map_err(|e| Error::new(format!("zmq connect address {address} error: {e}")))?;
        // Bound the backlog twice: `hwm` batches, and an absolute byte ceiling
        // so that a large hwm cannot turn the worker into an OOM candidate.
        let hwm = cfg.hwm.max(1) as usize;
        let max_queued_bytes =
            zmtp::DEFAULT_MAX_QUEUED_BYTES.min(hwm.saturating_mul(ZMQ_MAX_BATCH_BUF_SIZE));
        let zmtp = ZmtpPush::new(connector, hwm).with_queue_limits(hwm, max_queued_bytes);

        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };

        let now = now_ts();
        Ok(ZmqOutput {
            stats,
            throttle,
            slice: out.slice,
            zmtp,
            queue_budget_bytes: max_queued_bytes,
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

        // Accounting policy (AUDIT4 P5-11, deliberately unchanged): a batch counts
        // as forwarded when the transport *accepts* it, exactly like C's
        // `zmq_send(..., ZMQ_DONTWAIT)` returning 0 while libzmq buffers the
        // message. Backlog and loss stay visible through `error_drop_*` (batches
        // refused by the queue) and the `zmtp_queued_*` gauges (bytes currently
        // parked for the collector), so no C-facing number is redefined here.
        //
        // Acceptance is only half the truth, so the batch's own numbers travel
        // with it: the transport can still lose it after accepting it, and
        // `settle_transport_loss` charges that back (cloud-probe-rs-b7b).
        let sent = self.zmtp.send_with_account(
            &self.builder.buf[..len],
            MessageAccount {
                packets: u64::from(send_num),
                bytes: u64::try_from(len).unwrap_or(u64::MAX),
            },
        );
        match sent {
            SendOutcome::Queued => {
                self.stats.fwd_bytes.add(len as u64);
                self.stats.fwd_packets.add(send_num as u64);
            }
            SendOutcome::Dropped => {
                if self.error_info.nb_drop_batches == 0 {
                    self.error_info.send_error = format!(
                        "zmq_send failed: EAGAIN (queue full: {} batches / {} bytes queued)",
                        self.zmtp.queued(),
                        self.zmtp.queued_bytes()
                    );
                }
                self.error_info.nb_drop_batches += 1;
                self.error_info.nb_drop_packets += send_num as u64;
                self.stats.error_drop_bytes.add(len as u64);
                self.stats.error_drop_packets.add(send_num as u64);
            }
        }

        self.builder.end_flush();
        self.settle_transport_loss();
        self.publish_queue_gauges();
    }

    /// Charge what the transport lost *after* it accepted a batch
    /// (cloud-probe-rs-b7b).
    ///
    /// A frame that is half-written when the collector disconnects is
    /// unrecoverable, and an undelivered backlog is discarded when this output
    /// stops; both happen after the `fwd_*` counters already recorded the batch,
    /// and the `zmtp_queued_*` gauges go back to 0 either way. Without this the
    /// run looks clean while the peer never saw the data. The numbers ride out
    /// through the existing periodic error summary rather than one line per
    /// event, so a flapping collector cannot flood the log.
    fn settle_transport_loss(&mut self) {
        let lost = self.zmtp.take_loss_report();
        if lost.messages == 0 {
            return;
        }
        self.stats.error_drop_bytes.add(lost.bytes);
        self.stats.error_drop_packets.add(lost.packets);
        if self.error_info.nb_drop_batches == 0 {
            self.error_info.send_error =
                "connection lost after the batch was accepted (peer disconnected)".to_string();
        }
        self.error_info.nb_drop_batches = self
            .error_info
            .nb_drop_batches
            .saturating_add(lost.messages);
        self.error_info.nb_drop_packets =
            self.error_info.nb_drop_packets.saturating_add(lost.packets);
    }

    /// Publish the send-queue backlog as gauges (AUDIT4 P5-11).
    fn publish_queue_gauges(&self) {
        self.stats.zmtp_queued_batches.store(
            self.zmtp.queued() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.stats.zmtp_queued_bytes.store(
            self.zmtp.queued_bytes() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Ceiling on the bytes this output may park while the collector is slow:
    /// `hwm` batches, never more than [`zmtp::DEFAULT_MAX_QUEUED_BYTES`].
    #[must_use]
    pub fn queue_budget_bytes(&self) -> usize {
        self.queue_budget_bytes
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

        if let Some(tb) = self.throttle.as_mut() {
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
        // Progress reconnect / flush even when no packets are flowing.
        self.zmtp.poll();
        self.settle_transport_loss();
        self.publish_queue_gauges();
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

    fn destroy(&mut self) {
        // Send the pending batch first (#253); ZMQ_LINGER then keeps the
        // transport drain waiting until it is delivered.
        if self.builder.num() > 0 {
            self.flush_packet();
        }
        self.zmtp.drain_for(Duration::from_secs(5));
        // A linger that ran out is a drop: the backlog dies with this output, so
        // it must be charged before the queue gauges are allowed to read 0
        // (cloud-probe-rs-b7b).
        self.zmtp.discard_queued();
        self.settle_transport_loss();
        self.publish_queue_gauges();
        // Say it out loud while there is still somewhere to report to.
        self.flush_error_info();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OutputKind, ZmqConfig};
    use crate::packet::PKT_DIR_NONCHECK;
    use crate::zmtp::{Connector, Transport};
    use std::sync::Mutex;

    fn zmq_output(hwm: i32, stats: Arc<OutputStats>) -> ZmqOutput {
        let cfg = ZmqConfig {
            // Nothing listens here: the queue can only grow, which is what the
            // test wants to observe.
            host: "127.0.0.1".into(),
            port: 1,
            hwm,
            service_tag: 1,
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            heartbeat_ms: 0,
        };
        let out = OutputConfig {
            kind: OutputKind::Zmq(cfg.clone()),
            rate_limit_mbps: 0,
            slice: 0,
        };
        ZmqOutput::new(&cfg, &out, stats).expect("zmq output")
    }

    fn frame() -> Vec<u8> {
        let mut p = vec![0u8; 120];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        p
    }

    /// AUDIT4 P5-11: the backlog a slow collector leaves behind must be visible
    /// as `zmtp_queued_*` gauges, otherwise "stats look fine, data is not".
    #[test]
    fn queue_backlog_is_published_as_gauges() {
        let stats = Arc::new(OutputStats::default());
        let mut z = zmq_output(10, stats.clone());
        let body = frame();
        let hdr = PacketHeader {
            ts_sec: 1, // ancient, so the next heartbeat flushes it
            ts_usec: 0,
            caplen: body.len() as u32,
            len: body.len() as u32,
        };
        for _ in 0..20 {
            assert_eq!(z.send_packet(&hdr, &body, PKT_DIR_NONCHECK), 0);
        }
        assert_eq!(
            stats
                .zmtp_queued_batches
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing is queued before the first flush"
        );

        z.heartbeat(now_ts().0);

        let batches = stats
            .zmtp_queued_batches
            .load(std::sync::atomic::Ordering::Relaxed);
        let bytes = stats
            .zmtp_queued_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(batches, 1, "the stale batch must be queued");
        assert!(
            bytes >= 20 * 120,
            "queued bytes must reflect the batch size, got {bytes}"
        );
    }

    /// The byte budget must never exceed what `hwm` batches can hold, and must be
    /// capped for a large hwm.
    #[test]
    fn queue_budget_is_bounded_by_hwm_and_bytes() {
        let stats = Arc::new(OutputStats::default());
        let small = zmq_output(2, stats.clone());
        assert_eq!(small.queue_budget_bytes(), 2 * ZMQ_MAX_BATCH_BUF_SIZE);

        let huge = zmq_output(crate::config::ZMQ_HWM_MAX, stats);
        assert_eq!(huge.queue_budget_bytes(), zmtp::DEFAULT_MAX_QUEUED_BYTES);
    }

    /// A collector that finishes the ZMTP handshake and then dies in the middle
    /// of a business frame. That is the only way a batch accepted with
    /// `SendOutcome::Queued` can still never reach the peer.
    #[derive(Default)]
    struct MockPeer {
        state: Mutex<PeerState>,
    }

    #[derive(Default)]
    struct PeerState {
        /// What the peer still owes the client (its greeting and READY).
        to_client: Vec<u8>,
        /// Once armed, the socket accepts at most `budget` more bytes and then
        /// fails hard - a peer that dies mid-frame.
        armed: bool,
        budget: usize,
    }

    struct PeerTransport {
        peer: Arc<MockPeer>,
    }

    impl Transport for PeerTransport {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut st = self.peer.state.lock().expect("peer lock");
            if !st.armed {
                return Ok(buf.len());
            }
            if st.budget == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            let n = st.budget.min(buf.len());
            st.budget -= n;
            Ok(n)
        }

        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut st = self.peer.state.lock().expect("peer lock");
            if !st.to_client.is_empty() {
                let n = st.to_client.len().min(buf.len());
                buf[..n].copy_from_slice(&st.to_client[..n]);
                st.to_client.drain(..n);
                return Ok(n);
            }
            // Go silent rather than hang up: the *write* side has to be what dies,
            // otherwise the loss happens in the read path, not mid-frame.
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    }

    struct MockConnector {
        peer: Arc<MockPeer>,
    }

    impl Connector for MockConnector {
        fn start(&mut self) -> std::io::Result<Box<dyn Transport>> {
            Ok(Box::new(PeerTransport {
                peer: Arc::clone(&self.peer),
            }))
        }
    }

    fn mock_peer() -> Arc<MockPeer> {
        let mut to_client = zmtp::codec::greeting().to_vec();
        to_client.extend_from_slice(&zmtp::codec::ready_command("PULL"));
        Arc::new(MockPeer {
            state: Mutex::new(PeerState {
                to_client,
                ..Default::default()
            }),
        })
    }

    /// cloud-probe-rs-b7b: acceptance is not delivery. A batch still counts as
    /// forwarded when the transport takes it (AUDIT4 P5-11, unchanged), but a
    /// collector that dies mid-frame must have those same packets reappear in
    /// `error_drop_*`. Before the fix this run reported 5 forwarded / 0 dropped
    /// while the peer received nothing, and the queue gauge went back to 0.
    #[test]
    fn a_batch_lost_after_acceptance_shows_up_as_dropped() {
        let stats = Arc::new(OutputStats::default());
        let mut z = zmq_output(10, stats.clone());
        let peer = mock_peer();
        z.zmtp = ZmtpPush::new(
            Box::new(MockConnector {
                peer: Arc::clone(&peer),
            }),
            10,
        );
        for _ in 0..20 {
            z.zmtp.poll();
            if z.zmtp.is_connected() {
                break;
            }
        }
        assert!(
            z.zmtp.is_connected(),
            "the mock peer must complete the handshake"
        );
        // Only a few bytes of the next frame make it out before the peer dies.
        {
            let mut st = peer.state.lock().expect("peer lock");
            st.armed = true;
            st.budget = 8;
        }

        let body = frame();
        let hdr = PacketHeader {
            ts_sec: 1, // ancient, so the heartbeat flushes the batch
            ts_usec: 0,
            caplen: body.len() as u32,
            len: body.len() as u32,
        };
        for _ in 0..5 {
            assert_eq!(z.send_packet(&hdr, &body, PKT_DIR_NONCHECK), 0);
        }
        z.heartbeat(now_ts().0);

        assert_eq!(
            stats.fwd_packets.load().0,
            5,
            "acceptance still counts as forwarded (the P5-11 number is not redefined)"
        );
        assert_eq!(
            stats.error_drop_packets.load().0,
            5,
            "a batch the peer never received must not disappear from the counters"
        );
        assert_eq!(
            stats.error_drop_bytes.load().0,
            stats.fwd_bytes.load().0,
            "the whole batch is charged back"
        );
        assert_eq!(z.zmtp.queued(), 0, "a half-written frame is not retried");
        assert_eq!(
            z.zmtp.take_loss_report().messages,
            0,
            "the report is drained once, so nothing is double-counted"
        );
    }
}
