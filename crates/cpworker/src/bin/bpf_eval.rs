//! Parity oracle entry point: compile tcpdump-subset filters and evaluate them
//! against a packet corpus, printing one `OK <bits>` line per expression.
//!
//! Used by `parity/verify_bpf.sh` to compare the pure-Rust compiler/interpreter
//! against libpcap. Not part of the runtime.

use std::fs;

use cpworker::bpf;

fn hex2bin(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16);
        let lo = (b[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => break,
        }
        i += 2;
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <exprs_file> <pkts_file>", args[0]);
        std::process::exit(2);
    }
    let exprs = fs::read_to_string(&args[1]).expect("read exprs");
    let pkts_raw = fs::read_to_string(&args[2]).expect("read pkts");
    let pkts: Vec<Vec<u8>> = pkts_raw
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(hex2bin)
        .collect();

    let mut out = String::new();
    for line in exprs
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match bpf::compile(line) {
            Ok(p) => {
                out.push_str("OK ");
                for pkt in &pkts {
                    out.push(if p.apply(pkt) { '1' } else { '0' });
                }
                out.push('\n');
            }
            Err(e) => out.push_str(&format!("ERR {e}\n")),
        }
    }
    print!("{out}");
}
