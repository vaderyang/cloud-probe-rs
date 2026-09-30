//! cpworker stats command. Port of `cpctl/cmd/stats.go`.

use std::io::{self, Write};
use std::time::Duration;

use cpgolib::cpworker::{self, BytesStats, Client, PacketsStats, StatsSummary};

use crate::cli::{Format, Globals};
use crate::format::*;

fn bytes_as_json(b: &BytesStats) -> serde_json::Value {
    serde_json::json!({"bytes": b.bytes, "eib": b.eib})
}

fn packets_as_json(p: &PacketsStats) -> serde_json::Value {
    serde_json::json!({"packets": p.packets, "peta": p.peta})
}

fn counters_map(s: &StatsSummary) -> serde_json::Value {
    serde_json::json!({
        "cap_bytes": bytes_as_json(&s.capture.cap_bytes),
        "cap_packets": packets_as_json(&s.capture.cap_packets),
        "drop_packets": packets_as_json(&s.capture.drop_packets),
        "ifdrop_packets": packets_as_json(&s.capture.ifdrop_packets),
        "fwd_bytes": bytes_as_json(&s.output.fwd_bytes),
        "fwd_packets": packets_as_json(&s.output.fwd_packets),
        "direction_drop_bytes": bytes_as_json(&s.output.direction_drop_bytes),
        "direction_drop_packets": packets_as_json(&s.output.direction_drop_packets),
        "error_drop_bytes": bytes_as_json(&s.output.error_drop_bytes),
        "error_drop_packets": packets_as_json(&s.output.error_drop_packets),
        "ratelimit_drop_bytes": bytes_as_json(&s.output.ratelimit_drop_bytes),
        "ratelimit_drop_packets": packets_as_json(&s.output.ratelimit_drop_packets),
    })
}

fn rates_map(s: &StatsSummary, last: &StatsSummary, secs: f64) -> serde_json::Value {
    let mut m = serde_json::Map::new();

    macro_rules! add_bytes {
        ($name:literal, $cur:expr, $prev:expr) => {{
            let (diff, is_less) = $cur.sub(&$prev);
            m.insert(
                $name.into(),
                if is_less {
                    serde_json::Value::Null
                } else {
                    bytes_as_json(&bytes_per_sec(&diff, secs))
                },
            );
        }};
    }
    macro_rules! add_packets {
        ($name:literal, $cur:expr, $prev:expr) => {{
            let (diff, is_less) = $cur.sub(&$prev);
            m.insert(
                $name.into(),
                if is_less {
                    serde_json::Value::Null
                } else {
                    packets_as_json(&packets_per_sec(&diff, secs))
                },
            );
        }};
    }

    add_bytes!(
        "cap_bytes_per_sec",
        s.capture.cap_bytes,
        last.capture.cap_bytes
    );
    add_packets!(
        "cap_packets_per_sec",
        s.capture.cap_packets,
        last.capture.cap_packets
    );
    add_packets!(
        "drop_packets_per_sec",
        s.capture.drop_packets,
        last.capture.drop_packets
    );
    add_packets!(
        "ifdrop_packets_per_sec",
        s.capture.ifdrop_packets,
        last.capture.ifdrop_packets
    );
    add_bytes!(
        "fwd_bytes_per_sec",
        s.output.fwd_bytes,
        last.output.fwd_bytes
    );
    add_packets!(
        "fwd_packets_per_sec",
        s.output.fwd_packets,
        last.output.fwd_packets
    );
    add_bytes!(
        "direction_drop_bytes_per_sec",
        s.output.direction_drop_bytes,
        last.output.direction_drop_bytes
    );
    add_packets!(
        "direction_drop_packets_per_sec",
        s.output.direction_drop_packets,
        last.output.direction_drop_packets
    );
    add_bytes!(
        "error_drop_bytes_per_sec",
        s.output.error_drop_bytes,
        last.output.error_drop_bytes
    );
    add_packets!(
        "error_drop_packets_per_sec",
        s.output.error_drop_packets,
        last.output.error_drop_packets
    );
    add_bytes!(
        "ratelimit_drop_bytes_per_sec",
        s.output.ratelimit_drop_bytes,
        last.output.ratelimit_drop_bytes
    );
    add_packets!(
        "ratelimit_drop_packets_per_sec",
        s.output.ratelimit_drop_packets,
        last.output.ratelimit_drop_packets
    );

    serde_json::Value::Object(m)
}

fn ts_rfc3339(s: &StatsSummary) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(s.time.sec, s.time.nsec.max(0) as u32)
        .unwrap_or_default()
        .to_rfc3339()
}

fn write_raw_text<W: Write>(out: &mut W, s: &StatsSummary) -> io::Result<()> {
    let rows: Vec<(&str, String)> = vec![
        ("Cap Bytes", format_bytes_stats(&s.capture.cap_bytes)),
        ("Cap Packets", format_packets_stats(&s.capture.cap_packets)),
        (
            "Drop Packets",
            format_packets_stats(&s.capture.drop_packets),
        ),
        (
            "Ifdrop Packets",
            format_packets_stats(&s.capture.ifdrop_packets),
        ),
        ("Fwd Bytes", format_bytes_stats(&s.output.fwd_bytes)),
        ("Fwd Packets", format_packets_stats(&s.output.fwd_packets)),
        (
            "Direction Drop Bytes",
            format_bytes_stats(&s.output.direction_drop_bytes),
        ),
        (
            "Direction Drop Packets",
            format_packets_stats(&s.output.direction_drop_packets),
        ),
        (
            "Error Drop Bytes",
            format_bytes_stats(&s.output.error_drop_bytes),
        ),
        (
            "Error Drop Packets",
            format_packets_stats(&s.output.error_drop_packets),
        ),
        (
            "Ratelimit Drop Bytes",
            format_bytes_stats(&s.output.ratelimit_drop_bytes),
        ),
        (
            "Ratelimit Drop Packets",
            format_packets_stats(&s.output.ratelimit_drop_packets),
        ),
    ];
    let max_len = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (header, value) in rows {
        writeln!(out, "{header:<max_len$} : {value}")?;
    }
    Ok(())
}

fn write_summary_stats<W: Write>(
    out: &mut W,
    stats: &StatsSummary,
    last: &StatsSummary,
) -> io::Result<()> {
    let secs = stats.time.sec as f64 + stats.time.nsec as f64 / 1e9
        - (last.time.sec as f64 + last.time.nsec as f64 / 1e9);

    let mut headers: Vec<&str> = Vec::new();
    let mut row: Vec<String> = Vec::new();

    macro_rules! add_bytes {
        ($name:literal, $cur:expr, $prev:expr) => {{
            headers.push($name);
            let (diff, is_less) = $cur.sub(&$prev);
            row.push(if is_less {
                "-".into()
            } else {
                format_bytes_and_per_sec(&diff, secs)
            });
        }};
    }
    macro_rules! add_packets {
        ($name:literal, $cur:expr, $prev:expr) => {{
            headers.push($name);
            let (diff, is_less) = $cur.sub(&$prev);
            row.push(if is_less {
                "-".into()
            } else {
                format_packets_and_per_sec(&diff, secs)
            });
        }};
    }

    add_bytes!("Cap Bytes", stats.capture.cap_bytes, last.capture.cap_bytes);
    add_packets!(
        "Cap Packets",
        stats.capture.cap_packets,
        last.capture.cap_packets
    );
    add_packets!(
        "Drop Packets",
        stats.capture.drop_packets,
        last.capture.drop_packets
    );
    add_packets!(
        "Ifdrop Packets",
        stats.capture.ifdrop_packets,
        last.capture.ifdrop_packets
    );
    add_bytes!("Fwd Bytes", stats.output.fwd_bytes, last.output.fwd_bytes);
    add_packets!(
        "Fwd Packets",
        stats.output.fwd_packets,
        last.output.fwd_packets
    );
    add_bytes!(
        "Direction Drop Bytes",
        stats.output.direction_drop_bytes,
        last.output.direction_drop_bytes
    );
    add_packets!(
        "Direction Drop Packets",
        stats.output.direction_drop_packets,
        last.output.direction_drop_packets
    );
    add_bytes!(
        "Error Drop Bytes",
        stats.output.error_drop_bytes,
        last.output.error_drop_bytes
    );
    add_packets!(
        "Error Drop Packets",
        stats.output.error_drop_packets,
        last.output.error_drop_packets
    );
    add_bytes!(
        "Ratelimit Drop Bytes",
        stats.output.ratelimit_drop_bytes,
        last.output.ratelimit_drop_bytes
    );
    add_packets!(
        "Ratelimit Drop Packets",
        stats.output.ratelimit_drop_packets,
        last.output.ratelimit_drop_packets
    );

    let max_header = headers.iter().map(|h| h.len()).max().unwrap_or(0);
    for (i, h) in headers.iter().enumerate() {
        writeln!(out, "{h:<max_header$} : {}", row[i])?;
    }
    Ok(())
}

fn run_with_client<C: Client, W: Write>(
    client: &mut C,
    out: &mut W,
    format: Format,
    count: i32,
    interval: Duration,
    timeout: Duration,
) -> anyhow::Result<()> {
    let raw_only = count == 1;
    let mut last: Option<StatsSummary> = None;
    let mut emitted = 0i32;

    loop {
        let stats = client.collect_stats_summary(timeout)?;

        if raw_only {
            match format {
                Format::Jsonl => {
                    let rec = serde_json::json!({
                        "ts": ts_rfc3339(&stats),
                        "sample": "raw",
                        "counters": counters_map(&stats),
                    });
                    writeln!(out, "{rec}")?;
                }
                Format::Text => write_raw_text(out, &stats)?,
            }
            let _ = client.close();
            return Ok(());
        }

        if let Some(prev) = &last {
            let t1 = stats.time.sec as f64 + stats.time.nsec as f64 / 1e9;
            let t2 = prev.time.sec as f64 + prev.time.nsec as f64 / 1e9;
            if t1 > t2 {
                match format {
                    Format::Jsonl => {
                        let secs = t1 - t2;
                        let rec = serde_json::json!({
                            "ts": ts_rfc3339(&stats),
                            "sample": "rate",
                            "interval_sec": secs,
                            "counters": counters_map(&stats),
                            "rates": rates_map(&stats, prev, secs),
                        });
                        writeln!(out, "{rec}")?;
                    }
                    Format::Text => {
                        writeln!(out, "-------------------------------")?;
                        write_summary_stats(out, &stats, prev)?;
                    }
                }
                emitted += 1;
            }
        }
        last = Some(stats);

        if count > 0 && emitted >= count - 1 {
            let _ = client.close();
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

pub fn run(globals: &Globals, count: i32, interval: Duration) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    run_with_client(
        &mut client,
        &mut out,
        format,
        count,
        interval,
        globals.timeout,
    )
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::*;

    /// A throwaway unix-socket server speaking the cpworker v1 control protocol.
    /// Each request is answered with the next scripted reply so the tests drive
    /// the real `UnixClient` rather than a hand-rolled client double.
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

    fn stats_reply(v: serde_json::Value) -> String {
        let mut obj = v.as_object().cloned().unwrap_or_default();
        obj.insert("status".into(), serde_json::json!("OK"));
        serde_json::Value::Object(obj).to_string()
    }

    fn summary(v: serde_json::Value) -> StatsSummary {
        serde_json::from_value(v).expect("valid stats summary")
    }

    /// Drive `run_with_client` against a real client connected to `server`.
    fn render(server: &MockServer, format: Format, count: i32) -> String {
        let mut client =
            cpworker::UnixClient::with_timeout(&server.socket_url(), Duration::from_secs(2))
                .expect("client");
        let mut out = Vec::new();
        run_with_client(
            &mut client,
            &mut out,
            format,
            count,
            Duration::ZERO,
            Duration::from_secs(2),
        )
        .expect("run_with_client");
        String::from_utf8(out).expect("utf8 output")
    }

    #[test]
    fn counters_map_carries_all_twelve_counters() {
        let s = summary(serde_json::json!({
            "capture": {
                "cap_bytes": {"bytes": 11, "eib": 1},
                "cap_packets": {"packets": 22, "peta": 2},
                "drop_packets": {"packets": 33, "peta": 0},
                "ifdrop_packets": {"packets": 44, "peta": 0}
            },
            "output": {
                "fwd_bytes": {"bytes": 55, "eib": 5},
                "direction_drop_bytes": {"bytes": 66, "eib": 0},
                "error_drop_bytes": {"bytes": 77, "eib": 0},
                "ratelimit_drop_bytes": {"bytes": 88, "eib": 0}
            }
        }));
        let v = counters_map(&s);
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 12, "all counters must be present: {v}");
        assert_eq!(v["cap_bytes"], serde_json::json!({"bytes": 11, "eib": 1}));
        assert_eq!(
            v["cap_packets"],
            serde_json::json!({"packets": 22, "peta": 2})
        );
        assert_eq!(v["fwd_bytes"], serde_json::json!({"bytes": 55, "eib": 5}));
        assert_eq!(
            v["ratelimit_drop_bytes"],
            serde_json::json!({"bytes": 88, "eib": 0})
        );
    }

    #[test]
    fn rates_map_divides_the_delta_by_the_window() {
        let prev = summary(serde_json::json!({}));
        let cur = summary(serde_json::json!({
            "capture": {"cap_bytes": {"bytes": 1000}},
            "output": {"fwd_packets": {"packets": 8}}
        }));
        let v = rates_map(&cur, &prev, 2.0);
        assert_eq!(v["cap_bytes_per_sec"]["bytes"], 500);
        assert_eq!(v["fwd_packets_per_sec"]["packets"], 4);
        assert_eq!(v.as_object().expect("object").len(), 12);
    }

    #[test]
    fn rates_map_nulls_a_counter_that_went_backwards() {
        let prev = summary(serde_json::json!({"capture": {"cap_bytes": {"bytes": 1000}}}));
        let cur = summary(serde_json::json!({}));
        let v = rates_map(&cur, &prev, 2.0);
        assert!(v["cap_bytes_per_sec"].is_null());
        assert_eq!(v["cap_packets_per_sec"]["packets"], 0);
    }

    #[test]
    fn ts_rfc3339_formats_seconds_and_falls_back_for_out_of_range() {
        let epoch = summary(serde_json::json!({"time": {"sec": 0, "nsec": 0}}));
        assert_eq!(ts_rfc3339(&epoch), "1970-01-01T00:00:00+00:00");

        // A negative nsec is clamped rather than panicking.
        let clamped = summary(serde_json::json!({"time": {"sec": 0, "nsec": -5}}));
        assert_eq!(ts_rfc3339(&clamped), "1970-01-01T00:00:00+00:00");

        // Out-of-range seconds fall back to the default (epoch).
        let huge = summary(serde_json::json!({"time": {"sec": i64::MAX, "nsec": 0}}));
        assert_eq!(ts_rfc3339(&huge), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn raw_text_prints_every_row_aligned() {
        let s = summary(serde_json::json!({
            "capture": {"cap_bytes": {"bytes": 1536, "eib": 0}}
        }));
        let mut out = Vec::new();
        write_raw_text(&mut out, &s).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 12, "one line per counter: {text}");
        assert!(lines[0].starts_with("Cap Bytes"), "{}", lines[0]);
        assert!(lines[0].contains("1.5 KB"), "{}", lines[0]);
        // All labels are padded to the widest ("Ratelimit Drop Packets").
        assert!(lines[0].contains(" : 1.5 KB"), "{}", lines[0]);
    }

    #[test]
    fn summary_text_reports_values_and_per_second_rates() {
        let last = summary(serde_json::json!({"time": {"sec": 0, "nsec": 0}}));
        let cur = summary(serde_json::json!({
            "time": {"sec": 2, "nsec": 0},
            "capture": {"cap_bytes": {"bytes": 2048}}
        }));
        let mut out = Vec::new();
        write_summary_stats(&mut out, &cur, &last).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("Cap Bytes"), "{text}");
        assert!(text.contains("2.0 KB; (1.0 KB / s)"), "{text}");
    }

    #[test]
    fn summary_text_marks_a_counter_that_went_backwards_with_a_dash() {
        let last = summary(serde_json::json!({"capture": {"cap_bytes": {"bytes": 2048}}}));
        let cur = summary(serde_json::json!({}));
        let mut out = Vec::new();
        write_summary_stats(&mut out, &cur, &last).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        let cap = text
            .lines()
            .find(|l| l.starts_with("Cap Bytes"))
            .expect("cap bytes row");
        assert!(cap.ends_with(": -"), "{cap}");
    }

    #[test]
    fn raw_jsonl_emits_one_self_describing_sample() {
        let sample = stats_reply(serde_json::json!({
            "time": {"sec": 0, "nsec": 0},
            "capture": {"cap_bytes": {"bytes": 7}}
        }));
        let server = MockServer::start("stats-raw-jsonl", vec![sample]);
        let text = render(&server, Format::Jsonl, 1);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "{text}");
        let rec: serde_json::Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(rec["sample"], "raw");
        assert_eq!(rec["ts"], "1970-01-01T00:00:00+00:00");
        assert_eq!(rec["counters"]["cap_bytes"]["bytes"], 7);
        let commands = server.commands();
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(
            commands[0].contains(r#""command":"collect_stats_summary""#),
            "{commands:?}"
        );
    }

    #[test]
    fn raw_text_at_count_one_renders_the_counter_table() {
        let sample = stats_reply(serde_json::json!({
            "capture": {"cap_packets": {"packets": 42}}
        }));
        let server = MockServer::start("stats-raw-text", vec![sample]);
        let text = render(&server, Format::Text, 1);
        assert!(text.contains("Cap Packets"), "{text}");
        assert!(text.contains("42"), "{text}");
    }

    #[test]
    fn rate_jsonl_emits_the_delta_with_interval_and_rates() {
        let first = stats_reply(serde_json::json!({"time": {"sec": 0, "nsec": 0}}));
        let second = stats_reply(serde_json::json!({
            "time": {"sec": 2, "nsec": 0},
            "capture": {"cap_bytes": {"bytes": 2000}}
        }));
        let server = MockServer::start("stats-rate-jsonl", vec![first, second]);
        let text = render(&server, Format::Jsonl, 2);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "one rate sample: {text}");
        let rec: serde_json::Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(rec["sample"], "rate");
        assert_eq!(rec["interval_sec"], 2.0);
        assert_eq!(rec["counters"]["cap_bytes"]["bytes"], 2000);
        assert_eq!(rec["rates"]["cap_bytes_per_sec"]["bytes"], 1000);
    }

    #[test]
    fn rate_text_renders_a_separator_and_the_summary_row() {
        let first = stats_reply(serde_json::json!({"time": {"sec": 0, "nsec": 0}}));
        let second = stats_reply(serde_json::json!({
            "time": {"sec": 2, "nsec": 0},
            "capture": {"cap_bytes": {"bytes": 2048}}
        }));
        let server = MockServer::start("stats-rate-text", vec![first, second]);
        let text = render(&server, Format::Text, 2);
        assert!(text.contains("-------------------------------"), "{text}");
        assert!(text.contains("Cap Bytes"), "{text}");
    }

    #[test]
    fn a_non_monotonic_sample_is_skipped_and_the_next_one_is_emitted() {
        // The middle sample goes backwards, so it must not produce a rate; the
        // loop keeps going and emits the following sample instead.
        let server = MockServer::start(
            "stats-nonmonotonic",
            vec![
                stats_reply(serde_json::json!({"time": {"sec": 2, "nsec": 0}})),
                stats_reply(serde_json::json!({"time": {"sec": 1, "nsec": 0}})),
                stats_reply(serde_json::json!({"time": {"sec": 3, "nsec": 0}})),
            ],
        );
        let text = render(&server, Format::Jsonl, 2);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "only the increasing sample rates: {text}");
        let rec: serde_json::Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(rec["ts"], "1970-01-01T00:00:03+00:00");
    }

    #[test]
    fn collect_error_propagates_out_of_the_loop() {
        let server = MockServer::start(
            "stats-error",
            vec![serde_json::json!({"status": "ERROR", "message": "nope"}).to_string()],
        );
        let mut client =
            cpworker::UnixClient::with_timeout(&server.socket_url(), Duration::from_secs(2))
                .expect("client");
        let mut out = Vec::new();
        let err = run_with_client(
            &mut client,
            &mut out,
            Format::Text,
            2,
            Duration::ZERO,
            Duration::from_secs(2),
        )
        .expect_err("a failed collect must abort");
        assert!(err.to_string().contains("nope"), "{err}");
    }

    /// Drive the real `run()` entrypoint against the mock socket: it must honor
    /// `--unix`, open the connection and put a `collect_stats_summary` on the wire.
    #[test]
    fn run_connects_and_sends_the_stats_command() {
        let server = MockServer::start(
            "stats-run",
            vec![stats_reply(
                serde_json::json!({"capture": {"cap_bytes": {"bytes": 1}}}),
            )],
        );
        let globals = Globals {
            unix: Some(server.path.to_string_lossy().into_owned()),
            format: "text".into(),
            timeout: Duration::from_secs(2),
        };
        run(&globals, 1, Duration::ZERO).expect("run");
        let commands = server.commands();
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(
            commands[0].contains(r#""command":"collect_stats_summary""#),
            "{commands:?}"
        );
    }
}
