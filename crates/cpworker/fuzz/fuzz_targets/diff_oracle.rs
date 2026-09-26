//! Coverage-guided differential fuzzing against the original C implementation.
//!
//! The Rust side runs in-process (so libFuzzer gets coverage feedback), while
//! the original C code runs as a *persistent* oracle subprocess built from the
//! upstream `netis/cloud-probe` sources. For every input we send the same
//! request to both and compare their canonical output; any divergence aborts
//! the fuzz run and libFuzzer saves the crashing input.
//!
//! Configuration (env):
//!   DIFF_MODE        packet_split | config | req_pattern   (default packet_split)
//!   DIFF_C_ORACLE    path to the compiled C oracle (see parity/difffuzz.sh)
//!
//! The oracle must support `--sentinel`: it prints each record's output then a
//! line containing `@@END@@` (see parity/c_harness.c etc.).

#![no_main]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;

use cpworker::packet::parse_packet;
use cpworker::packet_split::{build_fragment, calculate_fragment_count};

const SENTINEL: &str = "@@END@@";

// ---------------------------------------------------------------------------
// Persistent oracle subprocess
// ---------------------------------------------------------------------------

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn spawn(path: &str) -> Oracle {
        let mut child = Command::new(path)
            .arg("--sentinel")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn C oracle {path}: {e}"));
        let stdin = child.stdin.take().expect("oracle stdin");
        let stdout = BufReader::new(child.stdout.take().expect("oracle stdout"));
        Oracle {
            child,
            stdin,
            stdout,
        }
    }

    /// Send one request line; return the oracle's output lines. `Err` means the
    /// oracle died (e.g. crashed) before completing the record.
    fn request(&mut self, line: &str) -> Result<Vec<String>, ()> {
        if writeln!(self.stdin, "{line}").is_err() || self.stdin.flush().is_err() {
            return Err(());
        }
        let mut out = Vec::new();
        loop {
            let mut buf = String::new();
            match self.stdout.read_line(&mut buf) {
                Ok(0) => return Err(()), // EOF: oracle exited/crashed
                Ok(_) => {}
                Err(_) => return Err(()),
            }
            let l = buf.trim_end_matches(['\n', '\r']);
            if l == SENTINEL {
                return Ok(out);
            }
            out.push(l.to_string());
        }
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn oracle() -> &'static Mutex<Oracle> {
    static ORACLE: OnceLock<Mutex<Oracle>> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let path = std::env::var("DIFF_C_ORACLE")
            .expect("DIFF_C_ORACLE must point at the compiled C oracle (run parity/difffuzz.sh)");
        Mutex::new(Oracle::spawn(&path))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Keep printable ASCII, replace TAB/CR/LF (and other controls) with spaces so
/// the request stays a single line. Also avoids invalid UTF-8.
fn sanitize(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len());
    for &b in data {
        let c = if (0x20..=0x7e).contains(&b) { b as char } else { ' ' };
        s.push(c);
    }
    s
}

/// `PARSE_FAIL: <reason>` on the C side vs bare `PARSE_FAIL` on the Rust side.
fn normalize_c(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| {
            if l.starts_with("PARSE_FAIL") {
                "PARSE_FAIL".to_string()
            } else {
                l.clone()
            }
        })
        .collect()
}

fn written_artifact(line: &str, c_out: &[String], r_out: &[String], mode: &str) -> ! {
    let body = format!(
        "mode={mode}\nrequest={line}\n--- C (oracle) ---\n{}\n--- Rust ---\n{}\n",
        c_out.join("\n"),
        r_out.join("\n")
    );
    let _ = std::fs::write("/tmp/difffuzz_last.txt", &body);
    eprintln!("\n❌ DIFFERENTIAL MISMATCH ({mode})\n{body}");
    panic!("differential mismatch: Rust vs C ({mode}); see /tmp/difffuzz_last.txt");
}

/// Known, intentional divergence (PARITY.md §2.2): the Rust parser rejects
/// frames the C parser accepts solely because of its stricter IPv4 IHL / TCP
/// data-offset validation (`ihl < 5`, `tcp data offset < 5`). Used to filter
/// this documented class so the fuzzer keeps searching for *new* divergences.
fn known_strict_parse_divergence(pkt: &[u8]) -> bool {
    if pkt.len() < 14 {
        return false;
    }
    let mut ether_type = u16::from_be_bytes([pkt[12], pkt[13]]);
    let mut off = 14usize;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100 | 0x9200) {
        if pkt.len() < off + 4 {
            return false;
        }
        ether_type = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
        off += 4;
    }
    if ether_type != 0x0800 || pkt.len() < off + 20 {
        return false;
    }
    let ihl = (pkt[off] & 0x0f) as usize;
    if ihl < 5 {
        return true; // Rust rejects, C accepts
    }
    let ip_hdr_len = ihl * 4;
    if pkt.len() < off + ip_hdr_len {
        return false;
    }
    if pkt[off + 9] == 6 {
        // TCP
        let l4 = off + ip_hdr_len;
        if pkt.len() < l4 + 20 {
            return false;
        }
        let data_off = (pkt[l4 + 12] >> 4) as usize;
        if data_off < 5 {
            return true; // Rust rejects, C accepts
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Mode: packet_split  (parse + fragment count + fragment bytes)
// ---------------------------------------------------------------------------

fn build_packet_split(data: &[u8]) -> String {
    let (maxp, recalc, pkt) = if data.len() >= 3 {
        (
            u16::from_le_bytes([data[0], data[1]]) as i32,
            (data[2] & 1) as i32,
            &data[3..],
        )
    } else {
        (0, 0, &[][..])
    };
    format!("{maxp} {recalc} {}", to_hex(pkt))
}

fn rust_packet_split(data: &[u8]) -> Vec<String> {
    let (maxp, recalc, pkt) = if data.len() >= 3 {
        (
            u16::from_le_bytes([data[0], data[1]]) as i32,
            (data[2] & 1) != 0,
            &data[3..],
        )
    } else {
        (0, false, &[][..])
    };
    let mut out = Vec::new();
    let Some(r) = parse_packet(pkt) else {
        out.push("FAIL".to_string());
        return out;
    };
    let cnt = calculate_fragment_count(&r, maxp);
    out.push(cnt.to_string());
    let mut buf = vec![0u8; 70000];
    for i in 0..cnt {
        match build_fragment(&r, pkt, i, maxp, recalc, &mut buf) {
            Some(len) => out.push(to_hex(&buf[..len])),
            None => out.push("ERR".to_string()),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Mode: config  (JSON schema parse + bpf host exclusion)
// ---------------------------------------------------------------------------

fn build_config(data: &[u8]) -> String {
    let s = sanitize(data);
    if s.trim().is_empty() {
        "{}".to_string()
    } else {
        s
    }
}

fn rust_config(line: &str) -> Vec<String> {
    match cpworker::config::Config::parse_str(line) {
        Ok(c) => cpworker::config::canonical_dump(&c)
            .lines()
            .map(str::to_string)
            .collect(),
        Err(_) => vec!["PARSE_FAIL".to_string(), "---".to_string()],
    }
}

// ---------------------------------------------------------------------------
// Mode: req_pattern  (custom matcher mini-language)
// ---------------------------------------------------------------------------

fn build_req_pattern(data: &[u8]) -> String {
    // pattern = sanitized data; ip/port fixed so the pattern parser is the
    // primary surface under test.
    let pattern = sanitize(data);
    let port = u16::from_le_bytes([data.first().copied().unwrap_or(0), 0]);
    format!("{pattern}\t127.0.0.1\t{port}")
}

fn rust_req_pattern(line: &str) -> Vec<String> {
    let mut parts = line.splitn(3, '\t');
    let pattern = parts.next().unwrap_or("");
    let ip = parts.next().unwrap_or("");
    let port: u16 = parts.next().unwrap_or("0").trim().parse().unwrap_or(0);
    vec![cpworker::req_pattern::canonical_eval(pattern, ip, port).to_string()]
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

fn run(mode: &str, data: &[u8]) {
    let (request, rust_out) = match mode {
        "packet_split" => (build_packet_split(data), rust_packet_split(data)),
        "config" => {
            let line = build_config(data);
            let out = rust_config(&line);
            (line, out)
        }
        "req_pattern" => {
            let line = build_req_pattern(data);
            let out = rust_req_pattern(&line);
            (line, out)
        }
        other => panic!("unknown DIFF_MODE={other}"),
    };

    let mut guard = oracle().lock().unwrap();
    let c_raw = match guard.request(&request) {
        Ok(v) => v,
        Err(()) => {
            // The C oracle crashed/exited on this input. The Rust side did not.
            written_artifact(&request, &["<oracle crashed>".to_string()], &rust_out, mode);
        }
    };
    let c_out = normalize_c(&c_raw);
    if c_out == rust_out {
        return;
    }
    // Documented, intentional divergence: Rust's stricter header validation.
    if mode == "packet_split"
        && rust_out == ["FAIL".to_string()]
        && data.len() >= 3
        && known_strict_parse_divergence(&data[3..])
    {
        return;
    }
    written_artifact(&request, &c_out, &rust_out, mode);
}

fuzz_target!(|data: &[u8]| {
    let mode = std::env::var("DIFF_MODE").unwrap_or_else(|_| "packet_split".to_string());
    run(&mode, data);
});
