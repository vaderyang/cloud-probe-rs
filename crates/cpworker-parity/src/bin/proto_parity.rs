//! Protocol parity harness (Rust side). Reads the same input format as
//! `parity/c_proto.c` and prints the captured wire bytes as hex, using the
//! extracted single-source-of-truth encapsulation functions.
//!
//! Usage: proto_parity <gre|vxlan|zmq> <input-file>

use std::io::Read;

use cpworker::output::gre::gre_header;
use cpworker::output::vxlan::vxlan_encapsulate;
use cpworker::output::zmq::BatchBuilder;

fn hex_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let hv = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    };
    let mut i = 0;
    while i + 1 < b.len() {
        out.push((hv(b[i]) << 4) | hv(b[i + 1]));
        i += 2;
    }
    out
}

fn print_hex(b: &[u8]) {
    let mut s = String::with_capacity(b.len() * 2 + 1);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    println!("{s}");
}

struct Packet {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
    direct: i32,
    data: Vec<u8>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <gre|vxlan|zmq> <input-file>", args[0]);
        std::process::exit(2);
    }
    let mut text = String::new();
    std::fs::File::open(&args[2])
        .and_then(|mut f| f.read_to_string(&mut text))
        .expect("read input");

    let mut it = text.split_whitespace();
    let mode = it.next().unwrap_or("");
    let next_u64 =
        |it: &mut std::str::SplitWhitespace| -> u64 { it.next().unwrap().parse().unwrap() };
    let next_i64 =
        |it: &mut std::str::SplitWhitespace| -> i64 { it.next().unwrap().parse().unwrap() };

    let mut packets: Vec<Packet> = Vec::new();

    match mode {
        "gre" => {
            let service_tag = next_u64(&mut it) as u32;
            let slice = next_i64(&mut it) as i32;
            collect(&mut it, &mut packets);
            for p in &packets {
                let mut caplen = p.caplen;
                if slice > 0 && (slice as u32) < caplen {
                    caplen = slice as u32;
                }
                let length = caplen.min(65535) as usize;
                if p.direct == -1 {
                    continue;
                }
                let header = gre_header(service_tag, p.direct);
                let mut out = Vec::with_capacity(8 + length);
                out.extend_from_slice(&header);
                out.extend_from_slice(&p.data[..length]);
                print_hex(&out);
            }
        }
        "vxlan" => {
            let vni = next_u64(&mut it) as u32;
            let vni_version = next_u64(&mut it) as u8;
            let capture_time = next_u64(&mut it) != 0;
            let slice = next_i64(&mut it) as i32;
            collect(&mut it, &mut packets);
            let mut buf = vec![0u8; 65551];
            for p in &packets {
                let mut caplen = p.caplen;
                if slice > 0 && (slice as u32) < caplen {
                    caplen = slice as u32;
                }
                let length = caplen.min(65535) as usize;
                if p.direct == -1 {
                    continue;
                }
                let total = vxlan_encapsulate(
                    &mut buf,
                    vni,
                    vni_version,
                    p.direct,
                    capture_time,
                    p.ts_sec,
                    p.ts_usec,
                    &p.data[..length],
                );
                print_hex(&buf[..total]);
            }
        }
        "zmq" => {
            let service_tag = next_u64(&mut it) as u32;
            let slice = next_i64(&mut it) as i32;
            let _heartbeat_ms = next_i64(&mut it);
            let uuid_str = it.next().unwrap();
            let uuid = uuid_parse(uuid_str);
            collect(&mut it, &mut packets);
            let mut b = BatchBuilder::new(service_tag, &uuid);
            for p in &packets {
                let mut caplen = p.caplen;
                if slice > 0 && (slice as u32) < caplen {
                    caplen = slice as u32;
                }
                if caplen < 18 {
                    continue;
                }
                let length = (caplen.min(65531) as usize) + 4;
                let wire_len = p.len + 4;
                if p.direct == -1 {
                    flush_if_stale(&mut b, p.ts_sec);
                    continue;
                }
                if b.num() == 0 {
                    b.set_first_pktsec(p.ts_sec);
                }
                if b.should_flush(p.ts_sec, length) {
                    flush(&mut b);
                    b.set_first_pktsec(p.ts_sec);
                }
                if b.first_pktsec() == 0 {
                    b.set_first_pktsec(p.ts_sec);
                }
                // Pass the full captured buffer, like production does (the
                // slice only shrinks the logical `length`, not the source).
                b.append_packet(
                    p.ts_sec,
                    p.ts_usec,
                    length as u16,
                    wire_len,
                    &p.data,
                    p.direct,
                );
            }
            flush(&mut b);
        }
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(2);
        }
    }
}

fn collect(it: &mut std::str::SplitWhitespace, out: &mut Vec<Packet>) {
    while let Some(tok) = it.next() {
        if tok != "pkt" {
            continue;
        }
        let ts_sec = it.next().unwrap().parse().unwrap();
        let ts_usec = it.next().unwrap().parse().unwrap();
        let caplen: u32 = it.next().unwrap().parse().unwrap();
        let len: u32 = it.next().unwrap().parse().unwrap();
        let direct: i32 = it.next().unwrap().parse().unwrap();
        let data = hex_decode(it.next().unwrap());
        out.push(Packet {
            ts_sec,
            ts_usec,
            caplen,
            len,
            direct,
            data,
        });
    }
}

fn flush(b: &mut BatchBuilder) {
    let (_num, len) = b.begin_flush();
    print_hex(&b.buf[..len]);
    b.end_flush();
}

fn flush_if_stale(b: &mut BatchBuilder, now: i64) {
    if b.num() > 0 && b.first_pktsec() != 0 && now > b.first_pktsec() + 1 {
        flush(b);
    }
}

fn uuid_parse(s: &str) -> [u8; 16] {
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'-').collect();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hv = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => 0,
            }
        };
        out[i] = (hv(clean[i * 2]) << 4) | hv(clean[i * 2 + 1]);
    }
    out
}
