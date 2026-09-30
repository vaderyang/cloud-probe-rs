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

/// Handle one `--judge` input line: `<pattern>\t<frame_hex>`.
///
/// Returns the canonical output line, or `None` when the line has no tab
/// (malformed input is skipped, matching the matcher mode).
fn judge_line(line: &str) -> Option<String> {
    let (pattern, hex) = line.split_once('\t')?;
    let ast = match parse_pattern(pattern) {
        Ok(ast) => ast,
        Err(_) => return Some("INIT_FAIL".to_string()),
    };
    let frame = match hex_decode(hex) {
        Some(frame) => frame,
        None => return Some("BAD_HEX".to_string()),
    };
    let rp = ReqPattern::Custom { ast: Box::new(ast) };
    Some(rp.judge_pkt_direction(&frame).to_string())
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
            if let Some(o) = judge_line(line) {
                let _ = writeln!(out, "{o}");
            }
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

#[cfg(test)]
mod tests {
    use super::{hex_decode, judge_line, MAX_FRAME_BYTES};

    #[test]
    fn hex_decode_accepts_mixed_case_hex() {
        assert_eq!(hex_decode("00ff10Ab"), Some(vec![0x00, 0xff, 0x10, 0xab]));
        assert_eq!(hex_decode(""), Some(Vec::new()));
    }

    #[test]
    fn hex_decode_rejects_odd_length_non_hex_and_oversize() {
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode(&"00".repeat(MAX_FRAME_BYTES + 1)), None);
    }

    #[test]
    fn judge_line_skips_lines_without_a_tab() {
        assert_eq!(judge_line("host 1.2.3.4"), None);
    }

    #[test]
    fn judge_line_reports_bad_hex() {
        assert_eq!(judge_line("host 1.2.3.4\tzz"), Some("BAD_HEX".into()));
    }

    #[test]
    fn judge_line_reports_init_fail_for_a_bad_pattern() {
        // An unbalanced parenthesis cannot be parsed by `parse_pattern`.
        assert_eq!(judge_line("(\t00"), Some("INIT_FAIL".into()));
    }

    #[test]
    fn judge_line_returns_a_direction_for_a_valid_frame() {
        // 14-byte Ethernet (IPv4) + IPv4/UDP: src 1.2.3.4, dst 5.6.7.8, both port 53.
        let frame = concat!(
            "ffffffffffff0011223344550800",
            "4500001c00010000401100000102030405060708",
            "0035003500080000"
        );
        let out = judge_line(&format!("host 1.2.3.4\t{frame}")).expect("judge output");
        assert!(
            out.parse::<i32>().is_ok(),
            "direction must be an integer, got {out}"
        );
    }
}
