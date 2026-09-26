//! Differential harness for the Rust req_pattern custom matcher.
//! Same protocol as `c_req_pattern.c`.

use std::io::{self, BufRead, Write};

use cpworker::packet::IpAddr;
use cpworker::req_pattern::{custom_match_by_ipport, parse_pattern};

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

        let ast = match parse_pattern(pattern) {
            Ok(a) => a,
            Err(_) => {
                let _ = writeln!(out, "INIT_FAIL");
                continue;
            }
        };

        let ip = if let Ok(v4) = ip_str.parse::<std::net::Ipv4Addr>() {
            IpAddr::V4(v4.octets())
        } else if let Ok(v6) = ip_str.parse::<std::net::Ipv6Addr>() {
            IpAddr::V6(v6.octets())
        } else {
            let _ = writeln!(out, "BAD_IP");
            continue;
        };

        let matched = custom_match_by_ipport(&ast, &ip, port);
        let _ = writeln!(out, "{}", if matched { 1 } else { 0 });
    }
}
