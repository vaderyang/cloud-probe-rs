//! Differential harness for the Rust req_pattern custom matcher.
//! Same protocol as `c_req_pattern.c`.
//!
//! Default mode reads `<pattern>\t<ip>\t<port>` and prints the canonical match.
//! `--judge` reads `<pattern>\t<frame_hex>` and prints the direction returned by
//! `ReqPattern::judge_pkt_direction` — the packet-feeding entry point that also
//! exercises `extract_ipport` (including stacked VLAN descent).

use std::io::{self, BufRead, Write};

use cpworker::req_pattern::{canonical_eval, parse_pattern, ReqPattern};

/// Strict hex decoder matching `c_req_pattern.c`'s `hex_decode`: rejects odd
/// length, non-hex characters, and inputs larger than `MAX_FRAME_BYTES`.
const MAX_FRAME_BYTES: usize = 65536;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() & 1 != 0 || b.len() / 2 > MAX_FRAME_BYTES {
        return None;
    }
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((hv(pair[0])? << 4) | hv(pair[1])?);
    }
    Some(out)
}

fn main() {
    let judge = std::env::args().any(|a| a == "--judge");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        if judge {
            let Some((pattern, hex)) = line.split_once('\t') else {
                continue;
            };
            let Ok(ast) = parse_pattern(pattern) else {
                let _ = writeln!(out, "INIT_FAIL");
                continue;
            };
            let Some(frame) = hex_decode(hex) else {
                let _ = writeln!(out, "BAD_HEX");
                continue;
            };
            let rp = ReqPattern::Custom { ast: Box::new(ast) };
            let _ = writeln!(out, "{}", rp.judge_pkt_direction(&frame));
            continue;
        }

        let mut parts = line.splitn(3, '\t');
        let Some(pattern) = parts.next() else {
            continue;
        };
        let Some(ip_str) = parts.next() else { continue };
        let Some(port_str) = parts.next() else {
            continue;
        };
        if pattern.is_empty() && ip_str.is_empty() {
            continue;
        }
        let port: u16 = port_str.trim().parse().unwrap_or(0);
        let _ = writeln!(out, "{}", canonical_eval(pattern, ip_str, port));
    }
}
