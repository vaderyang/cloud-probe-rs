#![no_main]
//! Fuzz the deterministic simulator: arbitrary seeds/configs must uphold the
//! DST invariants and never panic.

use libfuzzer_sys::fuzz_target;

use cpsim::chaos::Chaos;
use cpsim::probe::{Out, ProbeConfig};
use cpsim::{Sim, SimConfig};

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let seed = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let out = match data[8] % 3 {
        0 => Out::Gre,
        1 => Out::Vxlan,
        _ => Out::Zmq,
    };

    let mut cfg = SimConfig {
        seed,
        probe: ProbeConfig {
            out,
            seed,
            ..Default::default()
        },
        num_packets: 1 + (data[9] as usize) % 300,
        ..Default::default()
    };
    cfg.probe.slice = data[10] as i32;
    cfg.probe.heartbeat_ms = (data[11] & 1) as i32 * 50;
    if data[8] & 0x80 != 0 {
        cfg.chaos = Chaos::harsh();
    }

    let r = Sim::new(cfg).run();
    r.check();
});
