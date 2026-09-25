//! cpworker stats command. Port of `cpctl/cmd/stats.go`.

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

    add_bytes!("cap_bytes_per_sec", s.capture.cap_bytes, last.capture.cap_bytes);
    add_packets!("cap_packets_per_sec", s.capture.cap_packets, last.capture.cap_packets);
    add_packets!("drop_packets_per_sec", s.capture.drop_packets, last.capture.drop_packets);
    add_packets!("ifdrop_packets_per_sec", s.capture.ifdrop_packets, last.capture.ifdrop_packets);
    add_bytes!("fwd_bytes_per_sec", s.output.fwd_bytes, last.output.fwd_bytes);
    add_packets!("fwd_packets_per_sec", s.output.fwd_packets, last.output.fwd_packets);
    add_bytes!("direction_drop_bytes_per_sec", s.output.direction_drop_bytes, last.output.direction_drop_bytes);
    add_packets!("direction_drop_packets_per_sec", s.output.direction_drop_packets, last.output.direction_drop_packets);
    add_bytes!("error_drop_bytes_per_sec", s.output.error_drop_bytes, last.output.error_drop_bytes);
    add_packets!("error_drop_packets_per_sec", s.output.error_drop_packets, last.output.error_drop_packets);
    add_bytes!("ratelimit_drop_bytes_per_sec", s.output.ratelimit_drop_bytes, last.output.ratelimit_drop_bytes);
    add_packets!("ratelimit_drop_packets_per_sec", s.output.ratelimit_drop_packets, last.output.ratelimit_drop_packets);

    serde_json::Value::Object(m)
}

fn ts_rfc3339(s: &StatsSummary) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(s.time.sec, s.time.nsec.max(0) as u32)
        .unwrap_or_default()
        .to_rfc3339()
}

fn print_raw_text(s: &StatsSummary) {
    let rows: Vec<(&str, String)> = vec![
        ("Cap Bytes", format_bytes_stats(&s.capture.cap_bytes)),
        ("Cap Packets", format_packets_stats(&s.capture.cap_packets)),
        ("Drop Packets", format_packets_stats(&s.capture.drop_packets)),
        ("Ifdrop Packets", format_packets_stats(&s.capture.ifdrop_packets)),
        ("Fwd Bytes", format_bytes_stats(&s.output.fwd_bytes)),
        ("Fwd Packets", format_packets_stats(&s.output.fwd_packets)),
        ("Direction Drop Bytes", format_bytes_stats(&s.output.direction_drop_bytes)),
        ("Direction Drop Packets", format_packets_stats(&s.output.direction_drop_packets)),
        ("Error Drop Bytes", format_bytes_stats(&s.output.error_drop_bytes)),
        ("Error Drop Packets", format_packets_stats(&s.output.error_drop_packets)),
        ("Ratelimit Drop Bytes", format_bytes_stats(&s.output.ratelimit_drop_bytes)),
        ("Ratelimit Drop Packets", format_packets_stats(&s.output.ratelimit_drop_packets)),
    ];
    let max_len = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (header, value) in rows {
        println!("{header:<max_len$} : {value}");
    }
}

fn print_summary_stats(stats: &StatsSummary, last: &StatsSummary) {
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
    add_packets!("Cap Packets", stats.capture.cap_packets, last.capture.cap_packets);
    add_packets!("Drop Packets", stats.capture.drop_packets, last.capture.drop_packets);
    add_packets!("Ifdrop Packets", stats.capture.ifdrop_packets, last.capture.ifdrop_packets);
    add_bytes!("Fwd Bytes", stats.output.fwd_bytes, last.output.fwd_bytes);
    add_packets!("Fwd Packets", stats.output.fwd_packets, last.output.fwd_packets);
    add_bytes!("Direction Drop Bytes", stats.output.direction_drop_bytes, last.output.direction_drop_bytes);
    add_packets!("Direction Drop Packets", stats.output.direction_drop_packets, last.output.direction_drop_packets);
    add_bytes!("Error Drop Bytes", stats.output.error_drop_bytes, last.output.error_drop_bytes);
    add_packets!("Error Drop Packets", stats.output.error_drop_packets, last.output.error_drop_packets);
    add_bytes!("Ratelimit Drop Bytes", stats.output.ratelimit_drop_bytes, last.output.ratelimit_drop_bytes);
    add_packets!("Ratelimit Drop Packets", stats.output.ratelimit_drop_packets, last.output.ratelimit_drop_packets);

    let max_header = headers.iter().map(|h| h.len()).max().unwrap_or(0);
    for (i, h) in headers.iter().enumerate() {
        println!("{h:<max_header$} : {}", row[i]);
    }
}

pub fn run(globals: &Globals, count: i32, interval: Duration) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;
    let _ = &conn;

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;

    let raw_only = count == 1;
    let mut last: Option<StatsSummary> = None;
    let mut emitted = 0i32;

    loop {
        let stats = client.collect_stats_summary(globals.timeout)?;

        if raw_only {
            match format {
                Format::Jsonl => {
                    let rec = serde_json::json!({
                        "ts": ts_rfc3339(&stats),
                        "sample": "raw",
                        "counters": counters_map(&stats),
                    });
                    println!("{rec}");
                }
                Format::Text => print_raw_text(&stats),
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
                        println!("{rec}");
                    }
                    Format::Text => {
                        println!("-------------------------------");
                        print_summary_stats(&stats, prev);
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
