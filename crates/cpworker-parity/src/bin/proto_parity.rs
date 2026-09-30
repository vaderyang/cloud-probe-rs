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

/// Lowercase hex of `b`, one line (the harness's only output format).
fn hex_line(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Packet {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
    direct: i32,
    data: Vec<u8>,
}

/// Parse and encode one input file body, appending each captured wire buffer as
/// a hex line to `out`. Returns the unrecognized mode when the leading token is
/// not `gre`/`vxlan`/`zmq`.
fn process(text: &str, out: &mut String) -> Result<(), String> {
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
                let mut buf = Vec::with_capacity(8 + length);
                buf.extend_from_slice(&header);
                buf.extend_from_slice(&p.data[..length]);
                out.push_str(&hex_line(&buf));
                out.push('\n');
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
                out.push_str(&hex_line(&buf[..total]));
                out.push('\n');
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
                    flush_if_stale(&mut b, p.ts_sec, out);
                    continue;
                }
                if b.num() == 0 {
                    b.set_first_pktsec(p.ts_sec);
                }
                if b.should_flush(p.ts_sec, length) {
                    flush(&mut b, out);
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
            flush(&mut b, out);
        }
        other => return Err(other.to_string()),
    }
    Ok(())
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

fn flush(b: &mut BatchBuilder, out: &mut String) {
    let (_num, len) = b.begin_flush();
    out.push_str(&hex_line(&b.buf[..len]));
    out.push('\n');
    b.end_flush();
}

fn flush_if_stale(b: &mut BatchBuilder, now: i64, out: &mut String) -> bool {
    if b.num() > 0 && b.first_pktsec() != 0 && now > b.first_pktsec() + 1 {
        flush(b, out);
        true
    } else {
        false
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

    let mut out = String::new();
    if let Err(mode) = process(&text, &mut out) {
        eprintln!("unknown mode {mode}");
        std::process::exit(2);
    }
    print!("{out}");
}

#[cfg(test)]
mod tests {
    use super::{hex_decode, hex_line, process, uuid_parse};
    use cpworker::output::gre::gre_header;
    use cpworker::output::vxlan::vxlan_encapsulate;

    #[test]
    fn hex_decode_decodes_mixed_case_and_folds_invalid_nibbles_to_zero() {
        assert_eq!(hex_decode("00ff10Ab"), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(hex_decode(""), Vec::<u8>::new());
        // A trailing odd nibble is ignored, matching the C scanner.
        assert_eq!(hex_decode("abc"), vec![0xab]);
        // The C harness zero-fills invalid nibbles rather than stopping.
        assert_eq!(hex_decode("zz"), vec![0x00]);
    }

    #[test]
    fn hex_line_lowercases_bytes() {
        assert_eq!(hex_line(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_line(&[]), "");
    }

    #[test]
    fn uuid_parse_ignores_dashes_and_decodes_hex() {
        assert_eq!(
            uuid_parse("00112233-4455-6677-8899-aabbccddeeff"),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }

    /// 60-byte frame with a non-VLAN ethertype at [12..14].
    fn frame(n: usize) -> Vec<u8> {
        let mut f: Vec<u8> = (0..n).map(|i| i as u8).collect();
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f
    }

    fn hex(b: &[u8]) -> String {
        hex_line(b)
    }

    #[test]
    fn process_rejects_unknown_mode() {
        let mut out = String::new();
        assert_eq!(process("bogus 1 2", &mut out), Err("bogus".to_string()));
        assert!(out.is_empty());
    }

    #[test]
    fn process_gre_emits_header_then_frame() {
        let pkt = frame(60);
        let input = format!("gre 305419896 0\npkt 100 200 60 60 1 {}\n", hex(&pkt));
        let mut out = String::new();
        process(&input, &mut out).unwrap();
        let expected = format!("{}{}\n", hex(&gre_header(305419896, 1)), hex(&pkt[..60]));
        assert_eq!(out, expected);
    }

    #[test]
    fn process_gre_honours_slice_and_skips_direct_minus_one() {
        let pkt = frame(60);
        let input = format!(
            "gre 1 10\npkt 1 0 60 60 1 {}\npkt 2 0 60 60 -1 {}\n",
            hex(&pkt),
            hex(&pkt)
        );
        let mut out = String::new();
        process(&input, &mut out).unwrap();
        // Exactly one line, sliced to 10 captured bytes.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), (8 + 10) * 2);
        assert!(lines[0].starts_with(&hex(&gre_header(1, 1))));
    }

    #[test]
    fn process_vxlan_matches_the_encapsulator() {
        let pkt = frame(60);
        let input = format!("vxlan 7 1 1 0\npkt 5 6 60 60 2 {}\n", hex(&pkt));
        let mut out = String::new();
        process(&input, &mut out).unwrap();
        let mut buf = vec![0u8; 65551];
        let total = vxlan_encapsulate(&mut buf, 7, 1, 2, true, 5, 6, &pkt[..60]);
        assert_eq!(out, format!("{}\n", hex(&buf[..total])));
    }

    #[test]
    fn process_zmq_writes_one_batch_with_packet_header() {
        let pkt = frame(18);
        let uuid = "00112233-4455-6677-8899-aabbccddeeff";
        let input = format!("zmq 4660 0 0 {uuid}\npkt 100 250 18 20 1 {}\n", hex(&pkt));
        let mut out = String::new();
        process(&input, &mut out).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "one flush line");
        let bytes = hex_decode(lines[0]);
        // batch hdr(24) + pkt len(2) + pkt hdr(16) + eth(14) + mpls(4) + payload(4)
        assert_eq!(bytes.len(), 24 + 2 + 16 + 14 + 4 + 4);
        assert_eq!(&bytes[0..2], &2u16.to_be_bytes(), "batch version");
        assert_eq!(&bytes[8..24], &uuid_parse(uuid), "uuid in batch header");
        assert_eq!(
            &bytes[24..26],
            &22u16.to_be_bytes(),
            "pkt_data_len = caplen+4"
        );
        assert_eq!(&bytes[26..30], &100u32.to_be_bytes(), "ts_sec");
        assert_eq!(&bytes[30..34], &250u32.to_be_bytes(), "ts_usec");
    }

    #[test]
    fn process_zmq_skips_frames_shorter_than_the_caplen_floor() {
        let pkt = frame(17);
        let input = format!(
            "zmq 1 0 0 00112233-4455-6677-8899-aabbccddeeff\npkt 1 0 17 17 1 {}\n",
            hex(&pkt)
        );
        let mut out = String::new();
        process(&input, &mut out).unwrap();
        // The only packet is skipped, so only the empty batch flush is emitted.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(hex_decode(lines[0]).len(), 24);
    }
}
