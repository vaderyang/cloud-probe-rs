//! Deterministic Simulation Tests.
//!
//! Every test iterates over a range of seeds. Because the whole simulation is
//! deterministic, a failure prints the offending seed and can be reproduced
//! exactly with:
//!
//! ```bash
//! DST_SEED=<seed> cargo test -p cpsim --test dst
//! ```

use cpsim::chaos::Chaos;
use cpsim::probe::{Out, ProbeConfig};
use cpsim::{Sim, SimConfig, SimResult};

fn base(seed: u64, out: Out) -> SimConfig {
    SimConfig {
        seed,
        probe: ProbeConfig {
            out,
            seed,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn run(cfg: SimConfig) -> SimResult {
    Sim::new(cfg).run()
}

fn seed_filter(default_lo: u64, default_hi: u64) -> std::ops::RangeInclusive<u64> {
    if let Ok(s) = std::env::var("DST_SEED") {
        let s: u64 = s.parse().expect("DST_SEED must be an integer");
        s..=s
    } else {
        default_lo..=default_hi
    }
}

/// Running the same seed twice must produce byte-for-byte identical decisions.
#[test]
fn determinism_same_seed() {
    for seed in seed_filter(1, 40) {
        for out in [Out::Gre, Out::Vxlan, Out::Zmq] {
            let a = run(base(seed, out));
            let b = run(base(seed, out));
            assert_eq!(
                a.trace_digest, b.trace_digest,
                "seed {seed} out {out:?} not deterministic"
            );
            assert!(a.trace_events > 0);
        }
    }
}

/// Different seeds should generally exercise different event sequences.
#[test]
fn different_seeds_diverge() {
    let a = run(base(1, Out::Zmq)).trace_digest;
    let b = run(base(2, Out::Zmq)).trace_digest;
    assert_ne!(a, b, "seeds 1 and 2 produced identical traces");
}

/// On a clean network nothing is dropped or corrupted; invariants hold.
#[test]
fn clean_network_all_outputs() {
    for seed in seed_filter(1, 60) {
        for out in [Out::Gre, Out::Vxlan, Out::Zmq] {
            let r = run(base(seed, out));
            r.check();
            assert_eq!(
                r.stats.dropped, 0,
                "seed {seed} out {out:?}: dropped on clean network"
            );
            assert_eq!(r.stats.decode_errors, 0, "seed {seed} out {out:?}");
            assert!(
                r.stats.sent_frames > 0,
                "seed {seed} out {out:?} sent nothing"
            );
        }
    }
}

/// Dropped/duplicated/reordered/corrupted networks still uphold the accounting
/// and decode invariants.
#[test]
fn harsh_network_invariants() {
    let mut total_delivered = 0u64;
    for seed in seed_filter(1, 120) {
        for out in [Out::Gre, Out::Vxlan, Out::Zmq] {
            let mut cfg = base(seed, out);
            cfg.chaos = Chaos::harsh();
            cfg.num_packets = 300;
            // Spread packets over virtual time so ZMQ time-based flushes emit
            // several batches rather than one.
            cfg.inject_interval_us = 20_000;
            let r = run(cfg);
            r.check();
            assert!(
                r.stats.sent_frames > 0,
                "seed {seed} out {out:?}: sent nothing"
            );
            total_delivered += r.stats.delivered;
        }
    }
    assert!(total_delivered > 0, "no frames were ever delivered");
}

/// A crash/reload of the probe (builder reset) mid-stream must not corrupt the
/// wire format: every delivered frame still decodes and reconciles.
#[test]
fn zmq_heartbeat_and_batch_invariants() {
    for seed in seed_filter(1, 60) {
        let mut cfg = base(seed, Out::Zmq);
        cfg.probe.heartbeat_ms = 50; // heartbeat every 50ms of virtual time
        cfg.probe.frame_min = 18;
        cfg.probe.frame_max = 200;
        cfg.inject_interval_us = 5_000; // 5ms between packets
        cfg.num_packets = 400;
        let r = run(cfg);
        r.check();
        let heartbeats = r
            .collector
            .frames
            .iter()
            .filter(|d| matches!(d.kind, cpsim::FrameKind::ZmqHeartbeat))
            .count();
        assert!(heartbeats > 0, "seed {seed}: no heartbeats delivered");
    }
}

/// Regression coverage for the C VLAN-walk overflow we reported upstream: a ZMQ
/// output with `slice` truncating VLAN frames must never corrupt the batch
/// buffer (the safe guard drops the packet instead).
#[test]
fn zmq_vlan_slice_never_corrupts() {
    for seed in seed_filter(1, 200) {
        let mut cfg = base(seed, Out::Zmq);
        cfg.probe.slice = 26;
        cfg.probe.frame_min = 64;
        cfg.probe.frame_max = 1514;
        cfg.num_packets = 400;
        let r = run(cfg);
        r.check();
        // Dropping via the safety guard is allowed; corrupting is not.
        assert_eq!(
            r.stats.decode_errors, 0,
            "seed {seed}: a non-corrupted delivered frame failed to decode"
        );
    }
}

/// VXLAN fragmentation must produce multiple valid frames and reconcile.
#[test]
fn vxlan_fragmentation() {
    for seed in seed_filter(1, 80) {
        let mut cfg = base(seed, Out::Vxlan);
        cfg.probe.max_payload_size = 128;
        cfg.probe.recalculate_checksum = true;
        cfg.probe.frame_min = 200;
        cfg.probe.frame_max = 1514;
        cfg.num_packets = 300;
        let r = run(cfg);
        r.check();
        assert!(r.stats.sent_frames > 0);
    }
}

/// VXLAN v1 with capture-time and endianness-sensitive checksums.
#[test]
fn vxlan_v1_capture_time() {
    for seed in seed_filter(1, 60) {
        let mut cfg = base(seed, Out::Vxlan);
        cfg.probe.vni_version = 1;
        cfg.probe.capture_time = true;
        cfg.probe.frame_min = 42;
        let r = run(cfg);
        r.check();
        assert_eq!(r.stats.decode_errors, 0);
    }
}

/// A very low rate limit must drop packets; a high one must not.
#[test]
fn ratelimit_drops_when_exceeded() {
    let mut slow = base(1, Out::Gre);
    slow.probe.rate_limit_mbps = 1; // ~1 MB/s
    slow.inject_interval_us = 1; // blast packets
    slow.num_packets = 2000;
    let r = run(slow);
    r.check();
    assert!(
        r.stats.ratelimit_dropped > 0,
        "expected rate limiting to drop packets"
    );

    let mut fast = base(1, Out::Gre);
    fast.probe.rate_limit_mbps = 0; // disabled
    fast.num_packets = 2000;
    let r = run(fast);
    assert_eq!(r.stats.ratelimit_dropped, 0);
}

/// The same simulation run twice under harsh chaos must be identical, proving
/// fault injection is deterministic too.
#[test]
fn harsh_network_determinism() {
    for seed in seed_filter(1, 50) {
        let mut cfg = base(seed, Out::Zmq);
        cfg.chaos = Chaos::harsh();
        cfg.num_packets = 500;
        let a = run(cfg.clone());
        let b = run(cfg);
        assert_eq!(a.trace_digest, b.trace_digest, "seed {seed}");
        assert_eq!(a.stats.dropped, b.stats.dropped);
        assert_eq!(a.stats.corrupted, b.stats.corrupted);
        assert_eq!(a.stats.duplicated, b.stats.duplicated);
    }
}

/// Regression: found by the `sim_dst` cargo-fuzz target
/// (`crash-3c54b0f6b077cbf73f5f64b1218f71bc22a91662`). A corrupted frame that
/// is also duplicated produces two malformed deliveries, so the old
/// `decode_errors <= corrupted` invariant was wrong; only *uncorrupted* frames
/// are required to decode.
#[test]
fn regression_corrupt_dup_decode_accounting() {
    let seed = 0xFFFF_FFFF_FFFF_202A;
    let mut cfg = base(seed, Out::Gre);
    cfg.chaos = Chaos::harsh();
    cfg.num_packets = 256;
    cfg.probe.slice = 1;
    let r = run(cfg);
    r.check();
}

/// DST for the pcap file reader: a clean large file whose record headers
/// straddle the reader's 8 KiB `BufReader` boundary must read back exactly —
/// no position drift. This is the regression test for the `read()` vs
/// `read_exact()` bug found by the P3 audit (AUDIT4).
#[test]
fn dst_pcap_reader_clean_file() {
    for seed in seed_filter(1, 30) {
        let mut rng = cpsim::Rng::new(seed);
        let gen = cpsim::pcap_source::generate(&mut rng, 1000);
        let out = cpsim::pcap_source::read_all(&gen).expect("clean file must read fully");
        assert_eq!(out.records, gen.sizes.len(), "seed {seed}: incomplete read");
    }
}

/// Truncated files must stop cleanly: at most the records that fit, no panic,
/// and no drift into garbage records.
#[test]
fn dst_pcap_reader_truncated() {
    for seed in seed_filter(1, 30) {
        let mut rng = cpsim::Rng::new(seed);
        let mut gen = cpsim::pcap_source::generate(&mut rng, 1000);
        // Keep the global header plus a seeded prefix of the record area.
        let keep = 24 + rng.below((gen.bytes.len() - 24) as u64) as usize;
        gen.bytes.truncate(keep);
        let out = cpsim::pcap_source::read_all(&gen).expect("truncated file must stop cleanly");
        assert!(
            out.records <= gen.sizes.len(),
            "seed {seed}: emitted more records than the schedule"
        );
    }
}

/// A record header corrupted to an oversized `incl_len` must make the reader
/// stop cleanly exactly at that record — no drift, no garbage records.
#[test]
fn dst_pcap_reader_corrupted_header() {
    for seed in seed_filter(1, 30) {
        let mut rng = cpsim::Rng::new(seed);
        let mut gen = cpsim::pcap_source::generate(&mut rng, 1000);
        let k = rng.below(gen.sizes.len() as u64) as usize;
        gen.corrupt_oversized(k);
        let out = cpsim::pcap_source::read_all(&gen).expect("clean prefix must read fully");
        assert_eq!(
            out.records, k,
            "seed {seed}: reader must stop exactly at the corrupted record"
        );
    }
}

/// The pcap reader and the ZMTP client state machine must be deterministic:
/// the same seed produces the same trace digest.
#[test]
fn dst_pcap_and_zmtp_deterministic() {
    for seed in seed_filter(1, 30) {
        let mut rng = cpsim::Rng::new(seed);
        let gen = cpsim::pcap_source::generate(&mut rng, 500);
        let a = cpsim::pcap_source::read_all(&gen).expect("clean file must read fully");
        let b = cpsim::pcap_source::read_all(&gen).expect("clean file must read fully");
        assert_eq!(
            a.digest, b.digest,
            "seed {seed}: pcap read not deterministic"
        );

        let za = cpsim::zmtp_driver::run(seed);
        let zb = cpsim::zmtp_driver::run(seed);
        assert_eq!(
            za.digest(),
            zb.digest(),
            "seed {seed}: zmtp not deterministic"
        );
        assert!(za.events > 0);
    }
}

/// DST for the ZMTP 3.x PUSH client state machine: scripted faults (write
/// failures, EOF, corrupt greeting, write budget) must never panic, never
/// exceed the high-water mark and never corrupt the wire stream.
#[test]
fn dst_zmtp_client_state_machine() {
    for seed in seed_filter(1, 40) {
        cpsim::zmtp_driver::run(seed);
    }
}
