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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} <host> <port> <hex-payload|@file>", args[0]);
        std::process::exit(2);
    }
    let host = &args[1];
    let port: u16 = args[2].parse().expect("port");
    // Payload is a hex string, or `@path` to read the hex from a file (large
    // payloads exceed the command-line length limit).
    let payload = if let Some(path) = args[3].strip_prefix('@') {
        let s = std::fs::read_to_string(path).expect("read payload file");
        hex_decode(s.trim())
    } else {
        hex_decode(&args[3])
    };

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
