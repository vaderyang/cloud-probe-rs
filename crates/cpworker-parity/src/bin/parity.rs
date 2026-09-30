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

/// Process one `<maxp> <recalc> <packet_hex>` line, writing the fragment count
/// and hex-encoded fragments to `out`. Mirrors `c_harness.c`: a missing/empty
/// hex token is a zero-length frame, reported as `FAIL` (never silently skipped).
fn process_line<W: Write>(line: &str, out: &mut W, buf: &mut [u8]) {
    let mut parts = line.split_whitespace();
    let maxp: i32 = match parts.next().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return,
    };
    let recalc: i32 = match parts.next().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return,
    };
    let hex = parts.next().unwrap_or("");

    let pkt = from_hex(hex);
    let Some(r) = parse_packet(&pkt) else {
        let _ = writeln!(out, "FAIL");
        return;
    };

    let cnt = calculate_fragment_count(&r, maxp);
    let _ = writeln!(out, "{cnt}");
    for i in 0..cnt {
        match build_fragment(&r, &pkt, i, maxp, recalc != 0, buf) {
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
        process_line(&line, &mut out, &mut buf);
    }
}

#[cfg(test)]
mod tests {
    use super::{from_hex, hexval, process_line};
    use cpworker::packet_split::calculate_fragment_count;

    #[test]
    fn hexval_decodes_both_cases_and_rejects_non_hex() {
        assert_eq!(hexval(b'0'), Some(0));
        assert_eq!(hexval(b'9'), Some(9));
        assert_eq!(hexval(b'a'), Some(10));
        assert_eq!(hexval(b'F'), Some(15));
        assert_eq!(hexval(b'g'), None);
        assert_eq!(hexval(b' '), None);
    }

    #[test]
    fn from_hex_decodes_valid_pairs_and_stops_at_the_first_bad_pair() {
        assert_eq!(from_hex("00ff10Ab"), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(from_hex(""), Vec::<u8>::new());
        // A trailing odd nibble is ignored, like the original C scanner.
        assert_eq!(from_hex("abc"), vec![0xab]);
        // Decoding stops at the first non-hex character (no zero-filling).
        assert_eq!(from_hex("00zz11"), vec![0x00]);
    }

    /// Ethernet + IPv4/TCP carrying `payload`, matching `packet_split`'s tests.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        p[14] = 0x45;
        p[16..18].copy_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
        p[14 + 9] = 6; // IPPROTO_TCP
        p[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, 1]);
        p[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, 2]);
        p[14 + 20 + 12] = 0x50; // data offset 5
        p.extend_from_slice(payload);
        p
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn process_line_ignores_lines_without_two_numeric_fields() {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 70000];
        process_line("not-a-number 0 aa", &mut out, &mut buf);
        process_line("10 not-a-number aa", &mut out, &mut buf);
        process_line("", &mut out, &mut buf);
        assert!(out.is_empty(), "unparseable lines must produce no output");
    }

    #[test]
    fn process_line_reports_fail_for_an_unparseable_frame() {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 70000];
        // Missing hex token => zero-length frame => FAIL.
        process_line("10 0", &mut out, &mut buf);
        assert_eq!(String::from_utf8(out).unwrap(), "FAIL\n");
    }

    #[test]
    fn process_line_splits_and_emits_fragments() {
        let payload: Vec<u8> = (0..100u8).collect();
        let pkt = frame(&payload);
        // Sanity-check our golden frame against the real fragmenter first so a
        // change in the parser/fragmenter is caught here, not silently masked.
        let r = cpworker::packet::parse_packet(&pkt).expect("golden frame parses");
        let expected = calculate_fragment_count(&r, 30);
        assert_eq!(expected, 4);

        let input = format!("30 0 {}", to_hex(&pkt));
        let mut out = Vec::new();
        let mut buf = vec![0u8; 70000];
        process_line(&input, &mut out, &mut buf);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1 + expected as usize);
        assert_eq!(lines[0], "4");
        for frag in &lines[1..] {
            assert!(!frag.is_empty());
            assert!(frag.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // The first fragment reproduces the original L2/L3/L4 header prefix.
        assert!(lines[1].starts_with(&to_hex(&pkt[..14])));
    }

    #[test]
    fn process_line_recalc_flag_rewrites_checksums() {
        let pkt = frame(&[1, 2, 3, 4]);
        let run = |recalc: i32| {
            let mut out = Vec::new();
            let mut buf = vec![0u8; 70000];
            process_line(&format!("30 {recalc} {}", to_hex(&pkt)), &mut out, &mut buf);
            String::from_utf8(out).unwrap()
        };
        // recalc != 0 must change at least the IP/TCP checksum bytes.
        assert_ne!(run(0), run(1));
    }
}
