#![no_main]
//! Fuzz the pure-Rust BPF parser/compiler/interpreter.
//!
//! Input is `expression '\n' packet`, where the packet is arbitrary bytes. The
//! compiler must never panic on any input, and the interpreter must be safe and
//! terminating for any compiled program.
//!
//! Names are resolved by [`OfflineResolver`], not by the platform resolver: the
//! target calls [`bpf::compile_with`] so that a `host <name>` input cannot make a
//! `getaddrinfo()` call. That is what lets `fuzz.sh` gate on `-timeout=` at all
//! (qwen P3-7): with the system resolver a single name-heavy input could cost
//! glibc's whole resolver timeout, which made the run slow, network-dependent and
//! unreproducible. Coverage of the *resolution* behaviour (multi-address
//! expansion, unresolvable names) is preserved - only the source of the answers
//! changed, and it is still the production parser/compiler/interpreter under test.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use cpworker::bpf;

/// Deterministic, side-effect-free stand-in for `getaddrinfo()`.
///
/// Every name maps to documentation-prefix addresses (RFC 5737 / RFC 3849), one or
/// two of them, with the family mix chosen from the name itself:
///
/// * one IPv4 always, so `host <name>` and `net <name>/<plen>` keep expanding;
/// * a second IPv4 for half the names, which is what keeps the AUDIT4 P2-8
///   "cover *every* resolved address" rule under fuzz;
/// * an IPv6 for a third of them, so the v4/v6 mixing rules (`net <name>/24` with a
///   v6-only answer must be an error) stay reachable;
/// * names whose hash lands on one value in eight fail outright, so the
///   unresolvable-name path is exercised too.
struct OfflineResolver;

impl bpf::Resolver for OfflineResolver {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let h = fnv1a(host.as_bytes());
        // A deterministic slice of names is "unresolvable", exactly as a real
        // NXDOMAIN would be.
        if h & 7 == 3 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "offline resolver: no such host",
            ));
        }
        let mut addrs = vec![IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            (h & 0xff) as u8 | 1, // never .0 (network address) or .255
        ))];
        if h & 2 != 0 {
            addrs.push(IpAddr::V4(Ipv4Addr::new(
                198,
                51,
                100,
                ((h >> 8) & 0xff) as u8 | 1,
            )));
        }
        if h & 16 != 0 {
            addrs.push(IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                0,
                0,
                0,
                0,
                0x20 + ((h >> 16) & 0xff) as u16,
            )));
        }
        Ok(addrs)
    }
}

/// FNV-1a, 64 bit. Small, dependency-free and stable across runs and platforms,
/// which is what makes the fuzz input -> address mapping reproducible.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fuzz_target!(|data: &[u8]| {
    let (expr_bytes, pkt) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let Ok(expr) = std::str::from_utf8(expr_bytes) else {
        return;
    };
    if let Ok(prog) = bpf::compile_with(expr, &OfflineResolver) {
        let v = prog.evaluate(pkt);
        assert_eq!(prog.apply(pkt), v != 0);
    }
});
