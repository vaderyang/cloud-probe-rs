//! Print the deterministic trace digest for a given seed, so a run can be
//! reproduced across processes.
//!
//! Usage: cargo run -p cpsim --example trace -- [seed] [gre|vxlan|zmq] [harsh]

use cpsim::chaos::Chaos;
use cpsim::probe::{Out, ProbeConfig};
use cpsim::{Sim, SimConfig};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seed: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let out = match args.get(2).map(|s| s.as_str()) {
        Some("gre") => Out::Gre,
        Some("vxlan") => Out::Vxlan,
        _ => Out::Zmq,
    };
    let harsh = args.get(3).map(|s| s == "harsh").unwrap_or(false);

    let mut cfg = SimConfig {
        seed,
        probe: ProbeConfig {
            out,
            seed,
            ..Default::default()
        },
        ..Default::default()
    };
    if harsh {
        cfg.chaos = Chaos::harsh();
    }

    let r = Sim::new(cfg).run();
    r.check();
    println!(
        "seed={seed} out={out:?} harsh={harsh} digest={:016x} events={} \
         sent_frames={} sent_packets={} delivered={} dropped={} dup={} corrupt={} \
         decode_err={} ratelimit_drop={} builder_drop={}",
        r.trace_digest,
        r.trace_events,
        r.stats.sent_frames,
        r.stats.sent_packets,
        r.stats.delivered,
        r.stats.dropped,
        r.stats.duplicated,
        r.stats.corrupted,
        r.stats.decode_errors,
        r.stats.ratelimit_dropped,
        r.stats.builder_dropped,
    );
}
