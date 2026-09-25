//! Deterministic Ethernet frame generator for the simulation.
//!
//! Produces plain frames, stacked-VLAN frames (to exercise the VLAN walk and the
//! ZMQ MPLS rewrite) and valid IPv4/IPv6 UDP frames (to exercise the VXLAN
//! fragmenter).

use crate::Rng;

const VLAN_TYPES: [u16; 4] = [0x8100, 0x88a8, 0x9100, 0x9200];

fn put16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

/// Generate one Ethernet frame with length in `[min_len, max_len]`.
pub fn gen_frame(rng: &mut Rng, min_len: usize, max_len: usize) -> Vec<u8> {
    let lo = min_len.max(14);
    let hi = max_len.max(lo);
    let len = rng.range(lo as u64, hi as u64) as usize;
    let mut frame = vec![0u8; len];
    rng.fill(&mut frame[0..12]); // src/dst MACs

    match rng.below(100) {
        0..=29 => vlan_frame(rng, frame),
        30..=64 => ipv4_udp(rng, frame),
        65..=84 => ipv6_udp(rng, frame),
        _ => {
            put16(&mut frame, 12, rng.range(0x0600, 0xffff) as u16);
            frame
        }
    }
}

fn vlan_frame(rng: &mut Rng, mut frame: Vec<u8>) -> Vec<u8> {
    let caplen = frame.len();
    let max_tags = (caplen - 14) / 4;
    let want = rng.below(5) as usize; // 0..=4
    let n = want.min(max_tags);
    if n == 0 {
        put16(&mut frame, 12, rng.range(0x0600, 0xffff) as u16);
        return frame;
    }
    let tpid = VLAN_TYPES[rng.below(4) as usize];
    put16(&mut frame, 12, tpid);
    for i in 0..n {
        let off = 14 + 4 * i;
        put16(&mut frame, off, rng.u64() as u16);
        let etype = if i == n - 1 {
            // Terminate with a non-VLAN ethertype so the walk stops.
            [0x0800u16, 0x86DD, 0x8847][rng.below(3) as usize]
        } else {
            VLAN_TYPES[rng.below(4) as usize]
        };
        put16(&mut frame, off + 2, etype);
    }
    frame
}

fn ipv4_udp(rng: &mut Rng, frame: Vec<u8>) -> Vec<u8> {
    // Need at least eth(14) + ip(20) + udp(8).
    let mut frame = frame;
    if frame.len() < 42 {
        return frame;
    }
    put16(&mut frame, 12, 0x0800);
    let udp_payload = frame.len() - 42;
    let ip_total = 20 + 8 + udp_payload;
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 1] = 0;
    put16(&mut frame, ip + 2, ip_total as u16);
    put16(&mut frame, ip + 4, rng.u64() as u16);
    put16(&mut frame, ip + 6, 0);
    frame[ip + 8] = 64;
    frame[ip + 9] = 17; // UDP
    frame[ip + 10] = 0;
    frame[ip + 11] = 0;
    rng.fill(&mut frame[ip + 12..ip + 20]); // src/dst
    let udp = ip + 20;
    put16(&mut frame, udp, rng.range(1, 65535) as u16);
    put16(&mut frame, udp + 2, rng.range(1, 65535) as u16);
    put16(&mut frame, udp + 4, (8 + udp_payload) as u16);
    put16(&mut frame, udp + 6, 0);
    frame
}

fn ipv6_udp(rng: &mut Rng, frame: Vec<u8>) -> Vec<u8> {
    let mut frame = frame;
    if frame.len() < 62 {
        return frame;
    }
    put16(&mut frame, 12, 0x86DD);
    let udp_payload = frame.len() - 62;
    let ip = 14;
    frame[ip] = 0x60;
    frame[ip + 1] = 0;
    frame[ip + 2] = 0;
    frame[ip + 3] = 0;
    put16(&mut frame, ip + 4, (8 + udp_payload) as u16);
    frame[ip + 6] = 17; // UDP
    frame[ip + 7] = 64;
    rng.fill(&mut frame[ip + 8..ip + 40]); // src/dst
    let udp = ip + 40;
    put16(&mut frame, udp, rng.range(1, 65535) as u16);
    put16(&mut frame, udp + 2, rng.range(1, 65535) as u16);
    put16(&mut frame, udp + 4, (8 + udp_payload) as u16);
    put16(&mut frame, udp + 6, 0);
    frame
}
