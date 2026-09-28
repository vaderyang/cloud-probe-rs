//! Coverage-guided differential fuzzing against the original C implementation.
//!
//! The Rust side runs in-process (so libFuzzer gets coverage feedback), while
//! the original C code runs as a *persistent* oracle subprocess built from the
//! upstream `netis/cloud-probe` sources. For every input we send the same
//! request to both and compare their canonical output; any divergence aborts
//! the fuzz run and libFuzzer saves the crashing input.
//!
//! Configuration (env):
//!   DIFF_MODE        packet_split | config | req_pattern | fingerprint |
//!                    task_fingerprint   (default packet_split)
//!   DIFF_ORACLE      path to the compiled oracle subprocess (see
//!                    parity/difffuzz.sh). `DIFF_C_ORACLE` is accepted as a
//!                    fallback for the C-only modes.
//!
//! The oracle must support `--sentinel`: it prints each record's output then a
//! line containing `@@END@@` (see parity/c_harness.c and
//! parity/difffuzz/go/oracle.go).

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
        let path = std::env::var("DIFF_ORACLE")
            .or_else(|_| std::env::var("DIFF_C_ORACLE"))
            .expect("DIFF_ORACLE must point at the compiled oracle (run parity/difffuzz.sh)");
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

/// Map the fuzz bytes to a config line, but only if it is **valid JSON**.
/// cJSON and serde disagree on how lenient to be with malformed input (trailing
/// bytes, invalid `\u` escapes, …); gating on valid JSON keeps the differential
/// comparison focused on config *semantics*. Malformed-input leniency is covered
/// by the fixed-seed `parity/verify_config.sh` generator.
fn build_config(data: &[u8]) -> Option<String> {
    let s = sanitize(data);
    let s = if s.trim().is_empty() {
        "{}".to_string()
    } else {
        s
    };
    serde_json::from_str::<serde_json::Value>(&s).ok()?;
    Some(s)
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
// Mode: fingerprint  (Rust cpgolib vs Go pkg/common)
// ---------------------------------------------------------------------------

/// Request tokens are `k\x1f v\x1f k\x1f v ...`; the fuzz input is split on NUL
/// bytes into key/value tokens. Both sides build a map (last write wins) and
/// hash the sorted labels, then print `Fingerprint.String()` and `.UUID()`.
fn build_fingerprint(data: &[u8]) -> (String, Vec<String>) {
    let tokens: Vec<String> = data.split(|&b| b == 0).map(sanitize).collect();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let k = tokens[i].clone();
        let v = tokens.get(i + 1).cloned().unwrap_or_default();
        pairs.push((k, v));
        i += 2;
    }
    let mut parts: Vec<String> = Vec::with_capacity(pairs.len() * 2);
    for (k, v) in &pairs {
        parts.push(k.clone());
        parts.push(v.clone());
    }
    let request = format!("L{}", parts.join("\u{1f}"));

    let mut map = std::collections::BTreeMap::new();
    for (k, v) in &pairs {
        map.insert(k.clone(), v.clone());
    }
    let f = cpgolib::fingerprint::labels_to_fingerprint(&map);
    let out = vec![
        cpgolib::fingerprint::fingerprint_string(f),
        cpgolib::fingerprint::fingerprint_uuid_string(f),
    ];
    (request, out)
}

// ---------------------------------------------------------------------------
// Mode: task_fingerprint  (Rust cpgolib vs Go worker.TaskConfig reflection)
// ---------------------------------------------------------------------------

/// Byte cursor that yields deterministic values (0 when exhausted).
struct Rng<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Rng<'a> {
    fn new(d: &'a [u8]) -> Self {
        Rng { d, i: 0 }
    }
    fn b(&mut self) -> u8 {
        let v = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    fn bit(&mut self) -> bool {
        self.b() & 1 == 1
    }
    fn num_i64(&mut self) -> i64 {
        let hi = self.b() as i64;
        let lo = self.b() as i64;
        (hi << 8) | lo
    }
    fn num_u64(&mut self) -> u64 {
        let hi = self.b() as u64;
        let lo = self.b() as u64;
        ((hi << 8) | lo) % 100_000
    }
    fn s(&mut self, max: usize) -> String {
        const CS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_";
        let n = (self.b() as usize % max) + 1;
        (0..n).map(|_| CS[(self.b() as usize) % CS.len()] as char).collect()
    }
}

fn build_output(r: &mut Rng) -> String {
    let rate = if r.bit() {
        format!(",\"rate_limit_mbps\":{}", r.num_u64())
    } else {
        String::new()
    };
    let slice = if r.bit() {
        format!(",\"slice\":{}", r.num_u64())
    } else {
        String::new()
    };
    match r.b() % 6 {
        0 => format!("{{\"type\":\"null\"{rate}{slice}}}"),
        1 => {
            let mut o = format!("{{\"type\":\"vxlan\",\"vxlan\":{{\"host\":\"{}\"", r.s(8));
            if r.bit() {
                o += &format!(",\"port\":{}", r.num_i64());
            }
            if r.bit() {
                o += &format!(",\"capture_time\":{}", r.bit());
            }
            if r.bit() {
                o += &format!(",\"vni1\":{}", r.num_u64());
            }
            if r.bit() {
                o += &format!(",\"vni2\":{}", r.num_u64());
            }
            if r.bit() {
                o += &format!(",\"bind_device\":\"{}\"", r.s(6));
            }
            if r.bit() {
                o += &format!(",\"pmtudisc\":\"{}\"", r.s(4));
            }
            if r.bit() {
                o += &format!(
                    ",\"split\":{{\"max_payload_size\":{},\"recalculate_checksum\":{}}}",
                    r.num_i64(),
                    r.bit()
                );
            }
            format!("{o}}}{rate}{slice}}}")
        }
        2 => {
            let mut o = format!("{{\"type\":\"gre\",\"gre\":{{\"host\":\"{}\"", r.s(8));
            if r.bit() {
                o += &format!(",\"service_tag\":{}", r.num_u64());
            }
            if r.bit() {
                o += &format!(",\"bind_device\":\"{}\"", r.s(6));
            }
            if r.bit() {
                o += &format!(",\"pmtudisc\":\"{}\"", r.s(4));
            }
            format!("{o}}}{rate}{slice}}}")
        }
        3 => {
            let mut o = format!(
                "{{\"type\":\"zmq\",\"zmq\":{{\"host\":\"{}\",\"port\":{},\"uuid\":\"{}\"",
                r.s(8),
                r.num_i64(),
                r.s(8)
            );
            if r.bit() {
                o += &format!(",\"hwm\":{}", r.num_i64());
            }
            if r.bit() {
                o += &format!(",\"service_tag\":{}", r.num_u64());
            }
            if r.bit() {
                o += &format!(",\"heartbeat_ms\":{}", r.num_i64());
            }
            format!("{o}}}{rate}{slice}}}")
        }
        4 => format!("{{\"type\":\"file\",\"file\":{{\"name\":\"{}\"}}{rate}{slice}}}", r.s(12)),
        _ => {
            let mut o = format!(
                "{{\"type\":\"rotating_file\",\"rotating_file\":{{\"file_root\":\"{}\"",
                r.s(12)
            );
            if r.bit() {
                o += &format!(",\"max_file_interval\":{}", r.num_i64());
            }
            format!("{o}}}{rate}{slice}}}")
        }
    }
}

/// Build a **well-formed** `TaskConfig` JSON with canonical field names,
/// varying only values and optional-field presence. This avoids Go/Rust JSON
/// decoder differences (case-insensitive keys, zero-fill of missing fields) so
/// the fuzzer compares the fingerprint *label extraction* itself.
fn build_task_json(data: &[u8]) -> String {
    let mut r = Rng::new(data);
    let iface = r.s(8);
    let mut lp = format!("{{\"interface\":\"{iface}\"");
    if r.bit() {
        lp += &format!(",\"snaplen\":{}", r.num_i64());
    }
    if r.bit() {
        lp += &format!(",\"netns\":\"{}\"", r.s(6));
    }
    if r.bit() {
        lp += &format!(",\"bpf\":\"{}\"", r.s(8));
    }
    if r.bit() {
        lp += &format!(",\"buffer_size_mb\":{}", r.num_u64());
    }
    if r.bit() {
        lp += &format!(",\"timeout_ms\":{}", r.num_i64());
    }
    if r.bit() {
        lp += &format!(",\"not_filter_output_hosts\":{}", r.bit());
    }
    lp += "}";

    let rp = match r.b() % 4 {
        0 => "{\"type\":\"auto\"}".to_string(),
        1 => "{\"type\":\"custom\"}".to_string(),
        2 => "{\"type\":\"custom\",\"custom\":{}}".to_string(),
        _ => format!(
            "{{\"type\":\"custom\",\"custom\":{{\"pattern\":\"{}\"}}}}",
            r.s(16)
        ),
    };

    let o1 = build_output(&mut r);
    let o2 = build_output(&mut r);
    format!(
        "{{\"req_pattern\":{rp},\"capturer\":{{\"type\":\"libpcap\",\"libpcap\":{lp}}},\"outputs\":[{o1},{o2}]}}"
    )
}

fn build_task_fingerprint(data: &[u8]) -> (String, Vec<String>) {
    let json = build_task_json(data);
    let request = format!("J{json}");
    let out = match serde_json::from_str::<cpgolib::worker_config::TaskConfig>(&json) {
        Ok(t) => {
            let labels = cpgolib::worker_fingerprint::task_fingerprint_labels(&t);
            let f = cpgolib::fingerprint::labels_to_fingerprint(&labels);
            vec![
                cpgolib::fingerprint::fingerprint_string(f),
                cpgolib::fingerprint::fingerprint_uuid_string(f),
            ]
        }
        Err(_) => vec!["PARSE_FAIL".to_string()],
    };
    (request, out)
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Detect duplicate JSON object keys in the raw text. Imprecise for nested
/// structures but sufficient as a filter for the documented duplicate-key
/// divergence (C first-wins vs serde's duplicate-field rejection).
fn has_duplicate_keys(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut keys: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != b'"' {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let mut k = j + 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k < bytes.len() && bytes[k] == b':' {
            keys.push(&s[start..j]);
        }
        i = j + 1;
    }
    let raw_len = keys.len();
    keys.sort_unstable();
    keys.dedup();
    raw_len != keys.len()
}

fn run(mode: &str, data: &[u8]) {
    let (request, rust_out) = match mode {
        "packet_split" => (build_packet_split(data), rust_packet_split(data)),
        "config" => match build_config(data) {
            Some(line) => {
                // Known benign divergence (PARITY.md Â§2.3): C (cJSON) keeps the
                // first occurrence of a duplicate JSON key while serde's
                // generated deserializer rejects duplicate fields. Skip that
                // documented class so the fuzzer searches for new divergences.
                if has_duplicate_keys(&line) {
                    return;
                }
                let out = rust_config(&line);
                (line, out)
            }
            None => return, // not valid JSON; skip
        },
        "req_pattern" => {
            let line = build_req_pattern(data);
            let out = rust_req_pattern(&line);
            (line, out)
        }
        "fingerprint" => build_fingerprint(data),
        "task_fingerprint" => build_task_fingerprint(data),
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
    // Known JSON-decoding difference (PARITY.md §2.3): Go's encoding/json
    // zero-fills missing struct fields, serde requires `capturer`/`outputs` (and
    // nested required fields). Only affects direct TaskConfig JSON decoding, not
    // a production input path. Classify one-sided PARSE_FAIL so the fuzzer keeps
    // comparing value-level fingerprint labels.
    if mode == "task_fingerprint" {
        let rust_fail = rust_out == ["PARSE_FAIL".to_string()];
        let oracle_fail = c_out == ["PARSE_FAIL".to_string()];
        if rust_fail != oracle_fail {
            return;
        }
    }
    written_artifact(&request, &c_out, &rust_out, mode);
}

fuzz_target!(|data: &[u8]| {
    let mode = std::env::var("DIFF_MODE").unwrap_or_else(|_| "packet_split".to_string());
    run(&mode, data);
});
