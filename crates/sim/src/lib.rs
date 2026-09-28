//! Deterministic Simulation Testing (DST) harness.
//!
//! Runs the Cloud Probe forwarding pipeline in a *single-threaded, purely
//! deterministic* simulation: a virtual clock, a seeded RNG, an event queue and
//! a simulated lossy network. Every decision (packet bytes, rate-limit outcome,
//! network loss/duplication/reordering/corruption, crash/reload points) derives
//! from the seed, so a failing run can be replayed exactly by re-running the
//! same seed.
//!
//! The probe side reuses the *real* cpworker code for encapsulation, rate
//! limiting and fragmentation:
//!   * `cpworker::output::gre::gre_header`
//!   * `cpworker::output::vxlan::vxlan_encapsulate`
//!   * `cpworker::output::zmq::BatchBuilder`
//!   * `cpworker::ratelimit::TokenBucket`
//!   * `cpworker::packet_split::{parse_packet, calculate_fragment_count, build_fragment}`

pub mod chaos;
pub mod collector;
pub mod packet_gen;
pub mod pcap_source;
pub mod probe;
pub mod zmtp_driver;

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use chaos::Chaos;
use collector::{Collector, Decode};
use probe::{Probe, ProbeConfig};

pub type TimeUs = u64;

/// Deterministic RNG wrapper (ChaCha8 is reproducible across platforms).
pub struct Rng(ChaCha8Rng);

impl Rng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Rng(ChaCha8Rng::seed_from_u64(seed))
    }
    pub fn u64(&mut self) -> u64 {
        use rand::Rng;
        self.0.next_u64()
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.u64() % n
        }
    }
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.below(hi - lo + 1)
        }
    }
    pub fn chance(&mut self, p: f64) -> bool {
        use rand::RngExt;
        self.0.random::<f64>() < p
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        use rand::Rng;
        self.0.fill_bytes(buf);
    }
}

/// FNV-1a trace of the whole run, used to assert determinism.
#[derive(Default, Clone)]
pub struct Trace {
    hash: u64,
    pub events: u64,
}

impl Trace {
    pub fn record(&mut self, tag: u8, bytes: &[u8]) {
        self.hash ^= tag as u64;
        self.hash = self.hash.wrapping_mul(0x100000001b3);
        for &b in bytes {
            self.hash ^= b as u64;
            self.hash = self.hash.wrapping_mul(0x100000001b3);
        }
        self.events += 1;
    }
    pub fn record_u64(&mut self, tag: u8, v: u64) {
        self.record(tag, &v.to_le_bytes());
    }
    #[must_use]
    pub fn digest(&self) -> u64 {
        self.hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Gre,
    Vxlan,
    ZmqBatch,
    ZmqHeartbeat,
}

/// A wire frame produced by the probe.
#[derive(Debug, Clone)]
pub struct Message {
    pub serial: u64,
    pub kind: FrameKind,
    /// Logical packets represented (1 for gre/vxlan, N for a zmq batch).
    pub pkt_count: u16,
    pub bytes: Vec<u8>,
    /// Whether the link flipped a bit in this frame (such frames may fail to
    /// decode; uncorrupted frames must always decode).
    pub corrupted: bool,
}

#[derive(Debug, Clone)]
enum Event {
    Inject { idx: usize },
    Heartbeat,
    FinalFlush,
    Deliver(Message),
}

#[derive(Debug, Clone)]
struct Queued {
    at: TimeUs,
    seq: u64,
    ev: Event,
}

impl PartialEq for Queued {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}
impl Eq for Queued {}
impl Ord for Queued {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for a min-heap ordered by (time, seq).
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}
impl PartialOrd for Queued {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Default)]
pub struct SimStats {
    pub sent_frames: u64,
    pub sent_packets: u64,
    pub ratelimit_dropped: u64,
    pub direction_dropped: u64,
    pub builder_dropped: u64,
    pub dropped: u64,
    pub duplicated: u64,
    pub corrupted: u64,
    pub delivered: u64,
    pub decode_errors: u64,
}

#[derive(Clone)]
pub struct SimConfig {
    pub probe: ProbeConfig,
    pub chaos: Chaos,
    pub num_packets: usize,
    pub seed: u64,
    /// Delay between injected packets (virtual microseconds), fixed for
    /// determinism plus a seeded jitter.
    pub inject_interval_us: u64,
    pub inject_jitter_us: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            probe: ProbeConfig::default(),
            chaos: Chaos::default(),
            num_packets: 500,
            seed: 1,
            inject_interval_us: 200,
            inject_jitter_us: 100,
        }
    }
}

pub struct Sim {
    pub cfg: SimConfig,
    pub rng: Rng,
    pub now: TimeUs,
    seq: u64,
    queue: BinaryHeap<Queued>,
    probe: Probe,
    collector: Collector,
    pub trace: Trace,
    pub stats: SimStats,
    /// pkt_count per serial, for end-to-end reconciliation.
    journal: Vec<u16>,
}

impl Sim {
    #[must_use]
    pub fn new(cfg: SimConfig) -> Self {
        let seed = cfg.seed;
        let probe = Probe::new(ProbeConfig {
            seed,
            ..cfg.probe.clone()
        });
        Sim {
            rng: Rng::new(seed),
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            probe,
            collector: Collector::default(),
            trace: Trace::default(),
            stats: SimStats::default(),
            journal: Vec::new(),
            cfg,
        }
    }

    fn schedule(&mut self, at: TimeUs, ev: Event) {
        self.seq += 1;
        let seq = self.seq;
        self.queue.push(Queued { at, seq, ev });
    }

    /// Run to completion and return the final deterministic state.
    #[must_use]
    pub fn run(mut self) -> SimResult {
        // Kick off the probe.
        self.schedule(0, Event::Inject { idx: 0 });
        if self.cfg.probe.heartbeat_ms > 0 {
            self.schedule(self.cfg.probe.heartbeat_ms as u64 * 1000, Event::Heartbeat);
        }

        while let Some(q) = self.queue.pop() {
            self.now = q.at;
            match q.ev {
                Event::Inject { idx } => {
                    if idx < self.cfg.num_packets {
                        self.probe_inject(idx);
                        let jitter = self.rng.below(self.cfg.inject_jitter_us + 1);
                        let next = self.now + self.cfg.inject_interval_us + jitter;
                        self.schedule(next, Event::Inject { idx: idx + 1 });
                    } else {
                        // One extra tick to flush any pending batch.
                        self.schedule(self.now, Event::FinalFlush);
                    }
                }
                Event::Heartbeat => {
                    self.probe_heartbeat();
                    if self.probe.heartbeat_ms > 0
                        && self.probe.packets_injected < self.cfg.num_packets
                    {
                        self.schedule(
                            self.now + self.probe.heartbeat_ms as u64 * 1000,
                            Event::Heartbeat,
                        );
                    }
                }
                Event::FinalFlush => {
                    self.probe_flush();
                    // Drain remaining deliveries.
                }
                Event::Deliver(msg) => {
                    self.deliver(msg);
                }
            }
        }

        SimResult {
            stats: self.stats,
            collector: self.collector,
            trace_digest: self.trace.digest(),
            trace_events: self.trace.events,
            journal: self.journal,
        }
    }

    fn probe_inject(&mut self, idx: usize) {
        let (msgs, stats) = self.probe.inject(idx, self.now, &mut self.rng);
        apply(&mut self.stats, &stats);
        self.trace.record_u64(1, idx as u64);
        self.trace.record_u64(2, self.probe.last_direct as u64);
        self.transmit_all(msgs);
    }

    fn probe_heartbeat(&mut self) {
        let msgs = self.probe.heartbeat(self.now);
        self.trace.record_u64(3, self.now);
        self.transmit_all(msgs);
    }

    fn probe_flush(&mut self) {
        let msgs = self.probe.flush();
        self.transmit_all(msgs);
    }

    fn transmit_all(&mut self, msgs: Vec<Message>) {
        for msg in msgs {
            self.transmit(msg);
        }
    }

    /// Simulated lossy network: loss, duplication, reordering, corruption.
    fn transmit(&mut self, mut msg: Message) {
        let serial = msg.serial;
        self.journal.push(msg.pkt_count);
        self.stats.sent_frames += 1;
        self.stats.sent_packets += msg.pkt_count as u64;
        self.trace.record_u64(10, serial);
        self.trace.record(11, &msg.bytes);

        if self.rng.chance(self.cfg.chaos.loss) {
            self.stats.dropped += 1;
            self.trace.record_u64(12, serial);
            return;
        }

        let base =
            self.now + self.cfg.chaos.base_delay_us + self.rng.below(self.cfg.chaos.jitter_us + 1);
        let delay = if self.rng.chance(self.cfg.chaos.reorder) {
            base + self.rng.below(self.cfg.chaos.reorder_delay_us + 1)
        } else {
            base
        };
        // Timing decisions are part of the trace, so a harsher network produces
        // a different digest (while remaining deterministic).
        self.trace.record_u64(15, delay);

        let mut corrupted = false;
        if self.rng.chance(self.cfg.chaos.corrupt) && !msg.bytes.is_empty() {
            let pos = self.rng.below(msg.bytes.len() as u64) as usize;
            let bit = 1u8 << (self.rng.below(8) as u8);
            msg.bytes[pos] ^= bit;
            corrupted = true;
            self.stats.corrupted += 1;
            self.trace.record_u64(13, serial);
        }

        self.schedule(
            delay,
            Event::Deliver(Message {
                serial,
                kind: msg.kind,
                pkt_count: msg.pkt_count,
                bytes: msg.bytes.clone(),
                corrupted,
            }),
        );
        if self.rng.chance(self.cfg.chaos.dup) {
            self.stats.duplicated += 1;
            self.trace.record_u64(14, serial);
            let extra = self.rng.below(50);
            self.schedule(
                delay + extra,
                Event::Deliver(Message {
                    serial,
                    kind: msg.kind,
                    pkt_count: msg.pkt_count,
                    bytes: msg.bytes,
                    corrupted,
                }),
            );
        }
    }

    fn deliver(&mut self, msg: Message) {
        self.stats.delivered += 1;
        self.trace.record_u64(20, msg.serial);
        self.trace.record(21, &msg.bytes);
        match self.collector.consume(&msg) {
            Ok(pkt_count) => {
                // Cross-check the decoded packet count against the journal.
                if let Some(&expected) = self.journal.get(msg.serial as usize) {
                    assert_eq!(
                        pkt_count,
                        expected,
                        "serial {serial} decoded {pkt_count} != journal {expected}",
                        serial = msg.serial
                    );
                }
            }
            Err(reason) => {
                self.stats.decode_errors += 1;
                // A frame the link did not corrupt must always decode.
                assert!(
                    msg.corrupted,
                    "uncorrupted frame {serial} failed to decode: {reason}",
                    serial = msg.serial
                );
            }
        }
    }
}

fn apply(dst: &mut SimStats, src: &probe::ProbeStats) {
    dst.ratelimit_dropped += src.ratelimit_dropped;
    dst.direction_dropped += src.direction_dropped;
    dst.builder_dropped += src.builder_dropped;
}

#[derive(Debug, Clone)]
pub struct SimResult {
    pub stats: SimStats,
    pub collector: Collector,
    pub trace_digest: u64,
    pub trace_events: u64,
    pub journal: Vec<u16>,
}

impl SimResult {
    /// Verify invariants that must hold for every seed.
    pub fn check(&self) {
        // Delivery accounting: every transmit schedules exactly one delivery,
        // unless dropped (0) or duplicated (+1).
        assert_eq!(
            self.stats.delivered,
            self.stats.sent_frames - self.stats.dropped + self.stats.duplicated,
            "delivery accounting mismatch: {:#?}",
            self.stats
        );
        // Only frames the link corrupted may fail to decode; every uncorrupted
        // frame is asserted to decode in `deliver`. (A corrupted frame that is
        // also duplicated produces two malformed deliveries, so the raw counts
        // are not directly comparable.)
        // Every delivered frame reconciles with the journal.
        for d in &self.collector.frames {
            if let Decode::Ok { pkt_count, .. } = &d.decode {
                let expected = self.journal.get(d.serial as usize).copied().unwrap_or(0);
                assert_eq!(
                    *pkt_count, expected,
                    "frame {} decoded pkt_count mismatch",
                    d.serial
                );
            }
        }
    }
}
