//! cpworker ping command. Port of `cpctl/cmd/ping.go`.

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

fn emit_sample(format: Format, seq: i32, rtt_ms: f64, when: SystemTime) {
    match format {
        Format::Jsonl => {
            let ts = chrono::DateTime::<chrono::Utc>::from(when).to_rfc3339();
            let rec = serde_json::json!({
                "kind": "sample", "ts": ts, "seq": seq, "rtt_ms": rtt_ms
            });
            println!("{rec}");
        }
        Format::Text => println!("seq={seq} time={rtt_ms:.2} ms"),
    }
}

fn emit_error(format: Format, seq: i32, err: &dyn std::error::Error, quiet: bool) {
    if quiet {
        return;
    }
    match format {
        Format::Jsonl => {
            let rec = serde_json::json!({"kind": "error", "seq": seq, "err": err.to_string()});
            println!("{rec}");
        }
        Format::Text => println!("seq={seq} error: {err}"),
    }
}

fn emit_summary(format: Format, sent: i32, rtts: &[f64]) {
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
            println!("{rec}");
        }
        Format::Text => {
            println!("--- cpworker ping statistics ---");
            println!(
                "{} transmitted, {} received, {:.0}% loss",
                s.sent, s.received, s.loss_pct
            );
            if s.has_samples {
                println!(
                    "rtt min/avg/max/stddev = {:.2}/{:.2}/{:.2}/{:.2} ms",
                    s.min_ms, s.avg_ms, s.max_ms, s.stddev_ms
                );
            }
        }
    }
}

pub fn run(globals: &Globals, count: i32, interval: Duration, quiet: bool) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;
    let target = globals.unix.clone().unwrap_or_default();

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;

    if format == Format::Text && !quiet {
        println!("PING cpworker ({target})");
    }

    let mut rtts: Vec<f64> = Vec::new();
    let mut sent = 0i32;
    loop {
        let seq = sent;
        sent += 1;

        match client.ping(globals.timeout) {
            Ok(r) => {
                let rtt_ms = r.rtt.as_secs_f64() * 1000.0;
                rtts.push(rtt_ms);
                if !quiet {
                    emit_sample(format, seq, rtt_ms, r.when);
                }
            }
            Err(e) => emit_error(format, seq, &e, quiet),
        }

        if count > 0 && sent >= count {
            emit_summary(format, sent, &rtts);
            let _ = client.close();
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
