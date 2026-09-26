#![no_main]
//! Fuzz the pure-Rust BPF parser/compiler/interpreter.
//!
//! Input is `expression '\n' packet`, where the packet is arbitrary bytes. The
//! compiler must never panic on any input, and the interpreter must be safe and
//! terminating for any compiled program.

use libfuzzer_sys::fuzz_target;

use cpworker::bpf;

fuzz_target!(|data: &[u8]| {
    let (expr_bytes, pkt) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let Ok(expr) = std::str::from_utf8(expr_bytes) else {
        return;
    };
    if let Ok(prog) = bpf::compile(expr) {
        let v = prog.evaluate(pkt);
        assert_eq!(prog.apply(pkt), v != 0);
    }
});
