//! Parity oracle entry point: compile tcpdump-subset filters and evaluate them
//! against a packet corpus, printing one `OK <bits>` line per expression.
//!
//! Used by `parity/verify_bpf.sh` to compare the pure-Rust compiler/interpreter
//! against libpcap. Not part of the runtime.

use std::fs;

use cpworker::bpf;

fn hex2bin(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16);
        let lo = (b[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => break,
        }
        i += 2;
    }
    out
}

/// Parse a packet corpus: one raw hex frame per non-empty, non-`#` line.
fn parse_pkts(text: &str) -> Vec<Vec<u8>> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(hex2bin)
        .collect()
}

/// Compile each expression and emit `OK <bits>` (one bit per packet) or
/// `ERR <message>` for expressions the compiler rejects.
fn evaluate(exprs: &str, pkts: &[Vec<u8>]) -> String {
    let mut out = String::new();
    for line in exprs
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match bpf::compile(line) {
            Ok(p) => {
                out.push_str("OK ");
                for pkt in pkts {
                    out.push(if p.apply(pkt) { '1' } else { '0' });
                }
                out.push('\n');
            }
            Err(e) => out.push_str(&format!("ERR {e}\n")),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <exprs_file> <pkts_file>", args[0]);
        std::process::exit(2);
    }
    let exprs = fs::read_to_string(&args[1]).expect("read exprs");
    let pkts_raw = fs::read_to_string(&args[2]).expect("read pkts");
    let pkts = parse_pkts(&pkts_raw);

    print!("{}", evaluate(&exprs, &pkts));
}

#[cfg(test)]
mod tests {
    use super::{evaluate, hex2bin, parse_pkts};

    #[test]
    fn hex2bin_decodes_valid_hex_and_stops_at_the_first_bad_pair() {
        assert_eq!(hex2bin("00ff10Ab"), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(hex2bin(""), Vec::<u8>::new());
        assert_eq!(hex2bin("abc"), vec![0xab]); // trailing nibble ignored
        assert_eq!(hex2bin("00zz11"), vec![0x00]); // stops (does not zero-fill)
    }

    #[test]
    fn parse_pkts_skips_blank_and_comment_lines() {
        let pkts = parse_pkts("# comment\n\n0800\n\n# another\n0011\n");
        assert_eq!(pkts, vec![vec![0x08, 0x00], vec![0x00, 0x11]]);
    }

    /// Minimal Ethernet + IPv4/TCP frame: 14-byte L2, 20-byte IPv4 (proto 6).
    fn ipv4_tcp_hex() -> String {
        let mut f = [0u8; 14 + 20 + 20];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[14 + 9] = 6; // IPPROTO_TCP
        f.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Minimal Ethernet + IPv4/UDP frame (proto 17).
    fn ipv4_udp_hex() -> String {
        let mut f = [0u8; 14 + 20 + 8];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[14 + 9] = 17;
        f.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn evaluate_prints_one_bit_per_packet() {
        let tcp = hex2bin(&ipv4_tcp_hex());
        let udp = hex2bin(&ipv4_udp_hex());
        let out = evaluate("ip\ntcp\nudp\n", &[tcp, udp]);
        assert_eq!(out, "OK 11\nOK 10\nOK 01\n");
    }

    #[test]
    fn evaluate_reports_compiler_errors_without_stopping() {
        let pkt = hex2bin(&ipv4_tcp_hex());
        let out = evaluate("not a valid filter\nip\n", &[pkt]);
        let mut lines = out.lines();
        assert!(
            lines.next().unwrap().starts_with("ERR "),
            "first line must be an ERR for the bad expression"
        );
        assert_eq!(lines.next(), Some("OK 1"));
    }

    #[test]
    fn evaluate_ignores_blank_and_comment_expression_lines() {
        let pkt = hex2bin(&ipv4_tcp_hex());
        assert_eq!(evaluate("# c\n\nip\n", &[pkt]), "OK 1\n");
    }
}
