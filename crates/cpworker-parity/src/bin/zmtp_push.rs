//! Test helper: send one hex payload through the pure-Rust ZMTP `PUSH` client.
//!
//! Usage: zmtp_push <host> <port> <hex-payload>

use std::time::{Duration, Instant};

use cpworker::zmtp::{tcp_connector, ZmtpPush};

fn hex_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let hv = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        out.push((hv(b[i]) << 4) | hv(b[i + 1]));
        i += 2;
    }
    out
}

/// Resolve the payload argument: a hex string, or `@path` to read the hex from
/// a file (large payloads exceed the command-line length limit).
fn resolve_payload(arg: &str) -> std::io::Result<Vec<u8>> {
    if let Some(path) = arg.strip_prefix('@') {
        let s = std::fs::read_to_string(path)?;
        Ok(hex_decode(s.trim()))
    } else {
        Ok(hex_decode(arg))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} <host> <port> <hex-payload|@file>", args[0]);
        std::process::exit(2);
    }
    let host = &args[1];
    let port: u16 = args[2].parse().expect("port");
    let payload = resolve_payload(&args[3]).expect("read payload file");

    let connector = tcp_connector(host, port).expect("connector");
    let mut zmtp = ZmtpPush::new(connector, 1000);

    let deadline = Instant::now() + Duration::from_secs(3);
    while !zmtp.is_connected() {
        zmtp.poll();
        if Instant::now() >= deadline {
            eprintln!("connect/handshake timeout");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    zmtp.send(&payload);
    zmtp.drain_for(Duration::from_secs(3));
}

#[cfg(test)]
mod tests {
    use super::{hex_decode, resolve_payload};

    #[test]
    fn hex_decode_decodes_mixed_case_and_folds_invalid_nibbles_to_zero() {
        assert_eq!(hex_decode("00ff10Ab"), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(hex_decode(""), Vec::<u8>::new());
        // A trailing odd nibble is ignored, matching the C scanner.
        assert_eq!(hex_decode("abc"), vec![0xab]);
        // Invalid nibbles are zero-filled rather than aborting the decode.
        assert_eq!(hex_decode("zz"), vec![0x00]);
    }

    #[test]
    fn resolve_payload_decodes_an_inline_hex_argument() {
        assert_eq!(
            resolve_payload("deadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn resolve_payload_reads_and_trims_a_file() {
        let path = std::env::temp_dir().join(format!(
            "cpworker-parity-zmtp-payload-{}-{}.hex",
            std::process::id(),
            std::thread::current().name().unwrap_or("t")
        ));
        std::fs::write(&path, "010203\n").unwrap();
        let got = resolve_payload(&format!("@{}", path.display())).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(got, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn resolve_payload_reports_a_missing_file() {
        let err = resolve_payload("@/nonexistent/cprs/payload.hex").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
