//! cpworker ping command. Port of `cpctl/cmd/ping.go`.

use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use cpgolib::cpworker::{self, Client};

use crate::cli::{Format, Globals};

#[derive(Debug, Default)]
struct PingSummary {
    sent: i32,
    received: i32,
    loss_pct: f64,
    min_ms: f64,
    avg_ms: f64,
    max_ms: f64,
    stddev_ms: f64,
    has_samples: bool,
}

fn compute_ping_summary(sent: i32, rtts: &[f64]) -> PingSummary {
    let mut s = PingSummary {
        sent,
        received: rtts.len() as i32,
        ..Default::default()
    };
    if sent > 0 {
        s.loss_pct = (sent - rtts.len() as i32) as f64 / sent as f64 * 100.0;
    }
    if rtts.is_empty() {
        return s;
    }
    s.has_samples = true;
    s.min_ms = rtts[0];
    s.max_ms = rtts[0];
    let mut sum = 0.0;
    for &v in rtts {
        if v < s.min_ms {
            s.min_ms = v;
        }
        if v > s.max_ms {
            s.max_ms = v;
        }
        sum += v;
    }
    s.avg_ms = sum / rtts.len() as f64;
    if rtts.len() > 1 {
        let mut sq = 0.0;
        for &v in rtts {
            let d = v - s.avg_ms;
            sq += d * d;
        }
        s.stddev_ms = (sq / rtts.len() as f64).sqrt();
    }
    s
}

fn write_sample<W: Write>(
    out: &mut W,
    format: Format,
    seq: i32,
    rtt_ms: f64,
    when: SystemTime,
) -> io::Result<()> {
    match format {
        Format::Jsonl => {
            let ts = chrono::DateTime::<chrono::Utc>::from(when).to_rfc3339();
            let rec = serde_json::json!({
                "kind": "sample", "ts": ts, "seq": seq, "rtt_ms": rtt_ms
            });
            writeln!(out, "{rec}")
        }
        Format::Text => writeln!(out, "seq={seq} time={rtt_ms:.2} ms"),
    }
}

fn write_error<W: Write>(
    out: &mut W,
    format: Format,
    seq: i32,
    err: &dyn std::error::Error,
    quiet: bool,
) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    match format {
        Format::Jsonl => {
            let rec = serde_json::json!({"kind": "error", "seq": seq, "err": err.to_string()});
            writeln!(out, "{rec}")
        }
        Format::Text => writeln!(out, "seq={seq} error: {err}"),
    }
}

fn write_summary<W: Write>(out: &mut W, format: Format, sent: i32, rtts: &[f64]) -> io::Result<()> {
    let s = compute_ping_summary(sent, rtts);
    match format {
        Format::Jsonl => {
            let mut rec = serde_json::json!({
                "kind": "summary",
                "sent": s.sent,
                "received": s.received,
                "loss_pct": s.loss_pct,
            });
            if s.has_samples {
                rec["min_ms"] = s.min_ms.into();
                rec["avg_ms"] = s.avg_ms.into();
                rec["max_ms"] = s.max_ms.into();
                rec["stddev_ms"] = s.stddev_ms.into();
            }
            writeln!(out, "{rec}")
        }
        Format::Text => {
            writeln!(out, "--- cpworker ping statistics ---")?;
            writeln!(
                out,
                "{} transmitted, {} received, {:.0}% loss",
                s.sent, s.received, s.loss_pct
            )?;
            if s.has_samples {
                writeln!(
                    out,
                    "rtt min/avg/max/stddev = {:.2}/{:.2}/{:.2}/{:.2} ms",
                    s.min_ms, s.avg_ms, s.max_ms, s.stddev_ms
                )?;
            }
            Ok(())
        }
    }
}

struct PingOptions<'a> {
    format: Format,
    count: i32,
    interval: Duration,
    quiet: bool,
    target: &'a str,
    timeout: Duration,
}

fn run_with_client<C: Client, W: Write>(
    client: &mut C,
    out: &mut W,
    opts: &PingOptions<'_>,
) -> anyhow::Result<()> {
    let PingOptions {
        format,
        count,
        interval,
        quiet,
        target,
        timeout,
    } = *opts;

    if format == Format::Text && !quiet {
        writeln!(out, "PING cpworker ({target})")?;
    }

    let mut rtts: Vec<f64> = Vec::new();
    let mut sent = 0i32;
    loop {
        let seq = sent;
        sent += 1;

        match client.ping(timeout) {
            Ok(r) => {
                let rtt_ms = r.rtt.as_secs_f64() * 1000.0;
                rtts.push(rtt_ms);
                if !quiet {
                    write_sample(out, format, seq, rtt_ms, r.when)?;
                }
            }
            Err(e) => write_error(out, format, seq, &e, quiet)?,
        }

        if count > 0 && sent >= count {
            write_summary(out, format, sent, &rtts)?;
            let _ = client.close();
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

pub fn run(globals: &Globals, count: i32, interval: Duration, quiet: bool) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;
    let target = globals.unix.clone().unwrap_or_default();

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    run_with_client(
        &mut client,
        &mut out,
        &PingOptions {
            format,
            count,
            interval,
            quiet,
            target: &target,
            timeout: globals.timeout,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use cpgolib::cpworker::Error;

    use super::*;

    /// A throwaway unix-socket server speaking the cpworker v1 control protocol:
    /// it answers the handshake, then answers each request with the next scripted
    /// reply. This lets the tests exercise the real `UnixClient` instead of a
    /// hand-rolled test double.
    struct MockServer {
        path: PathBuf,
        handle: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl MockServer {
        fn start(tag: &str, replies: Vec<String>) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cpctl-{tag}-{}-{:?}.sock",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind mock socket");
            let handle = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("handshake");
                assert!(line.contains("v1"), "handshake: {line}");
                stream
                    .write_all(b"{\"status\":\"OK\"}\n")
                    .expect("handshake ok");
                let mut seen = Vec::new();
                let mut replies = replies.into_iter();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            seen.push(line.trim().to_string());
                            let reply = replies.next().unwrap_or_else(|| {
                                "{\"status\":\"ERROR\",\"message\":\"exhausted\"}".to_string()
                            });
                            stream.write_all(reply.as_bytes()).expect("reply");
                            stream.write_all(b"\n").expect("newline");
                        }
                    }
                }
                seen
            });
            MockServer {
                path,
                handle: Some(handle),
            }
        }

        fn socket_url(&self) -> String {
            format!("unix://{}", self.path.display())
        }

        fn commands(mut self) -> Vec<String> {
            let handle = self.handle.take().expect("server handle");
            handle.join().expect("server thread")
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn ok_reply() -> String {
        "{\"status\":\"OK\"}".to_string()
    }

    fn error_reply(message: &str) -> String {
        serde_json::json!({"status": "ERROR", "message": message}).to_string()
    }

    /// Drive `run_with_client` against a real client connected to `server`.
    fn render(server: &MockServer, format: Format, count: i32, quiet: bool) -> String {
        let mut client =
            cpworker::UnixClient::with_timeout(&server.socket_url(), Duration::from_secs(2))
                .expect("client");
        let mut out = Vec::new();
        run_with_client(
            &mut client,
            &mut out,
            &PingOptions {
                format,
                count,
                interval: Duration::ZERO,
                quiet,
                target: "/tmp/cpworker.sock",
                timeout: Duration::from_secs(2),
            },
        )
        .expect("run_with_client");
        String::from_utf8(out).expect("utf8 output")
    }

    #[test]
    fn summary_without_samples_reports_full_loss() {
        let s = compute_ping_summary(4, &[]);
        assert_eq!(s.sent, 4);
        assert_eq!(s.received, 0);
        assert_eq!(s.loss_pct, 100.0);
        assert!(!s.has_samples);
    }

    #[test]
    fn summary_computes_min_avg_max_and_population_stddev() {
        let s = compute_ping_summary(3, &[10.0, 20.0, 30.0]);
        assert_eq!(s.received, 3);
        assert_eq!(s.loss_pct, 0.0);
        assert!(s.has_samples);
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 30.0);
        assert_eq!(s.avg_ms, 20.0);
        assert!((s.stddev_ms - (200.0f64 / 3.0).sqrt()).abs() < 1e-9);
    }

    #[test]
    fn summary_reports_partial_loss() {
        let s = compute_ping_summary(4, &[5.0, 5.0]);
        assert_eq!(s.received, 2);
        assert_eq!(s.loss_pct, 50.0);
        assert_eq!(s.stddev_ms, 0.0);
    }

    #[test]
    fn a_single_sample_has_no_stddev() {
        let s = compute_ping_summary(1, &[7.5]);
        assert_eq!(s.min_ms, 7.5);
        assert_eq!(s.avg_ms, 7.5);
        assert_eq!(s.stddev_ms, 0.0);
    }

    #[test]
    fn nothing_sent_does_not_divide_by_zero() {
        let s = compute_ping_summary(0, &[]);
        assert_eq!(s.loss_pct, 0.0);
    }

    #[test]
    fn write_sample_text_and_jsonl_are_stable() {
        let mut out = Vec::new();
        write_sample(&mut out, Format::Text, 3, 12.345, SystemTime::UNIX_EPOCH).expect("write");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "seq=3 time=12.35 ms\n"
        );

        let mut out = Vec::new();
        write_sample(&mut out, Format::Jsonl, 3, 12.3, SystemTime::UNIX_EPOCH).expect("write");
        let rec: serde_json::Value = serde_json::from_slice(&out).expect("json sample record");
        assert_eq!(rec["kind"], "sample");
        assert_eq!(rec["seq"], 3);
        assert_eq!(rec["rtt_ms"], 12.3);
        assert_eq!(rec["ts"], "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn write_error_honours_quiet_and_formats_both_modes() {
        let err = Error::NotOk("boom".into());

        let mut out = Vec::new();
        write_error(&mut out, Format::Text, 1, &err, false).expect("write");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "seq=1 error: no OK response: boom\n"
        );

        let mut out = Vec::new();
        write_error(&mut out, Format::Jsonl, 2, &err, false).expect("write");
        let rec: serde_json::Value = serde_json::from_slice(&out).expect("json error record");
        assert_eq!(rec["kind"], "error");
        assert_eq!(rec["seq"], 2);
        assert!(rec["err"].as_str().expect("err").contains("boom"));

        let mut out = Vec::new();
        write_error(&mut out, Format::Text, 3, &err, true).expect("write");
        assert!(out.is_empty(), "quiet must suppress the error line");
    }

    #[test]
    fn write_summary_text_is_exact_and_omits_rtt_when_empty() {
        let mut out = Vec::new();
        write_summary(&mut out, Format::Text, 3, &[10.0, 20.0, 30.0]).expect("write");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "--- cpworker ping statistics ---\n\
             3 transmitted, 3 received, 0% loss\n\
             rtt min/avg/max/stddev = 10.00/20.00/30.00/8.16 ms\n"
        );

        let mut out = Vec::new();
        write_summary(&mut out, Format::Text, 2, &[]).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(
            text.contains("2 transmitted, 0 received, 100% loss"),
            "{text}"
        );
        assert!(!text.contains("rtt min"), "{text}");
    }

    #[test]
    fn write_summary_jsonl_adds_rtt_fields_only_with_samples() {
        let mut out = Vec::new();
        write_summary(&mut out, Format::Jsonl, 2, &[4.0, 8.0]).expect("write");
        let rec: serde_json::Value = serde_json::from_slice(&out).expect("json summary");
        assert_eq!(rec["kind"], "summary");
        assert_eq!(rec["sent"], 2);
        assert_eq!(rec["received"], 2);
        assert_eq!(rec["min_ms"], 4.0);
        assert_eq!(rec["avg_ms"], 6.0);
        assert_eq!(rec["max_ms"], 8.0);
        assert_eq!(rec["stddev_ms"], 2.0);

        let mut out = Vec::new();
        write_summary(&mut out, Format::Jsonl, 1, &[]).expect("write");
        let rec: serde_json::Value = serde_json::from_slice(&out).expect("json summary");
        assert_eq!(rec["received"], 0);
        assert_eq!(rec["loss_pct"], 100.0);
        assert!(rec.get("min_ms").is_none(), "{rec}");
    }

    #[test]
    fn text_run_prints_banner_samples_and_summary_in_order() {
        let server = MockServer::start("ping-text", vec![ok_reply(), ok_reply()]);
        let text = render(&server, Format::Text, 2, false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "PING cpworker (/tmp/cpworker.sock)");
        assert!(lines[1].starts_with("seq=0 time="), "{text}");
        assert!(lines[1].ends_with(" ms"), "{text}");
        assert!(lines[2].starts_with("seq=1 time="), "{text}");
        assert_eq!(lines[3], "--- cpworker ping statistics ---");
        assert_eq!(lines[4], "2 transmitted, 2 received, 0% loss");
        assert!(lines[5].starts_with("rtt min/avg/max/stddev ="), "{text}");
        let commands = server.commands();
        assert_eq!(commands.len(), 2, "{commands:?}");
        assert!(commands[0].contains(r#""command":"ping""#), "{commands:?}");
    }

    #[test]
    fn text_quiet_suppresses_the_banner_and_samples_but_keeps_the_summary() {
        let server = MockServer::start("ping-quiet", vec![ok_reply()]);
        let text = render(&server, Format::Text, 1, true);
        assert!(!text.contains("PING"), "{text}");
        assert!(!text.contains("seq="), "{text}");
        assert!(
            text.contains("1 transmitted, 1 received, 0% loss"),
            "{text}"
        );
        assert!(text.contains("rtt min/avg/max/stddev ="), "{text}");
    }

    #[test]
    fn jsonl_run_names_every_record_kind() {
        let server = MockServer::start(
            "ping-jsonl",
            vec![ok_reply(), error_reply("boom"), ok_reply()],
        );
        let text = render(&server, Format::Jsonl, 3, false);
        let recs: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("json line"))
            .collect();
        assert_eq!(recs.len(), 4, "two samples, one error, one summary: {text}");
        assert_eq!(recs[0]["kind"], "sample");
        assert_eq!(recs[0]["seq"], 0);
        assert_eq!(recs[1]["kind"], "error");
        assert_eq!(recs[1]["seq"], 1);
        assert!(recs[1]["err"].as_str().expect("err").contains("boom"));
        assert_eq!(recs[2]["kind"], "sample");
        assert_eq!(recs[3]["kind"], "summary");
        assert_eq!(recs[3]["sent"], 3);
        assert_eq!(recs[3]["received"], 2);
        let loss = recs[3]["loss_pct"].as_f64().expect("loss");
        assert!((loss - 100.0 / 3.0).abs() < 1e-9, "loss={loss}");
    }

    #[test]
    fn quiet_jsonl_suppresses_error_and_sample_records() {
        let server = MockServer::start("ping-quiet-jsonl", vec![error_reply("secret"), ok_reply()]);
        let text = render(&server, Format::Jsonl, 2, true);
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("\"kind\":\"error\""), "{text}");
        assert!(!text.contains("\"kind\":\"sample\""), "{text}");
        let rec: serde_json::Value = serde_json::from_str(text.trim()).expect("json");
        assert_eq!(rec["kind"], "summary");
        assert_eq!(rec["sent"], 2);
        assert_eq!(rec["received"], 1);
        assert_eq!(rec["loss_pct"], 50.0);
    }

    /// Drive the real `run()` entrypoint against the mock socket: it must honor
    /// `--unix`, open the connection and put a `ping` command on the wire.
    #[test]
    fn run_connects_and_sends_the_ping_command() {
        let server = MockServer::start("ping-run", vec![ok_reply()]);
        let globals = Globals {
            unix: Some(server.path.to_string_lossy().into_owned()),
            format: "jsonl".into(),
            timeout: Duration::from_secs(2),
        };
        run(&globals, 1, Duration::ZERO, true).expect("run");
        let commands = server.commands();
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(commands[0].contains(r#""command":"ping""#), "{commands:?}");
    }
}
