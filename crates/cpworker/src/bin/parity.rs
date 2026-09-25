//! Differential-test harness for the Rust packet_split implementation.
//!
//! Same stdin/stdout protocol as `c_harness.c` so outputs can be diffed.

use std::io::{self, BufRead, Write};

use cpworker::packet::parse_packet;
use cpworker::packet_split::{build_fragment, calculate_fragment_count};

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        match (hexval(b[i]), hexval(b[i + 1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => break,
        }
        i += 2;
    }
    out
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut buf = vec![0u8; 70000];

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let mut parts = line.split_whitespace();
        let maxp: i32 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        let recalc: i32 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        let hex = match parts.next() {
            Some(h) => h,
            None => continue,
        };

        let pkt = from_hex(hex);
        let Some(r) = parse_packet(&pkt) else {
            let _ = writeln!(out, "FAIL");
            continue;
        };

        let cnt = calculate_fragment_count(&r, maxp);
        let _ = writeln!(out, "{cnt}");
        for i in 0..cnt {
            match build_fragment(&r, &pkt, i, maxp, recalc != 0, &mut buf) {
                Some(len) => {
                    let mut s = String::with_capacity(len * 2);
                    for b in &buf[..len] {
                        s.push_str(&format!("{b:02x}"));
                    }
                    let _ = writeln!(out, "{s}");
                }
                None => {
                    let _ = writeln!(out, "ERR");
                }
            }
        }
    }
}
