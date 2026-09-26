//! Differential harness for the Rust req_pattern custom matcher.
//! Same protocol as `c_req_pattern.c`.

use std::io::{self, BufRead, Write};

use cpworker::req_pattern::canonical_eval;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
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
