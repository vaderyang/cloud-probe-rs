//! cpworker process info command. Port of `cpctl/cmd/info.go`.

use std::io::{self, Write};

use cpgolib::cpworker::{self, Client, InfoSummary};

use crate::cli::{Format, Globals};

fn write_info<W: Write>(out: &mut W, info: &InfoSummary, format: Format) -> anyhow::Result<()> {
    match format {
        Format::Jsonl => {
            writeln!(out, "{}", serde_json::to_string(info)?)?;
        }
        Format::Text => {
            writeln!(out, "version          : {}", info.version)?;
            writeln!(out, "pid              : {}", info.pid)?;
            writeln!(
                out,
                "uptime           : {}s ({} sec)",
                info.uptime_sec, info.uptime_sec
            )?;
            writeln!(
                out,
                "started_at       : {}",
                info.started_at().format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            writeln!(out, "config_path      : {}", info.config_path)?;
            writeln!(out, "working_dir      : {}", info.working_dir)?;
            writeln!(out, "log_destination  : {}", info.log_destination)?;
        }
    }
    Ok(())
}

fn run_with_client<C: Client, W: Write>(
    client: &mut C,
    out: &mut W,
    format: Format,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let info = client.info(timeout)?;
    let _ = client.close();
    write_info(out, &info, format)
}

pub fn run(globals: &Globals) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    run_with_client(&mut client, &mut out, format, globals.timeout)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    /// A throwaway unix-socket server speaking the cpworker v1 control protocol,
    /// so `run`/`run_with_client` are exercised through the real `UnixClient`.
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

    fn info_reply() -> String {
        serde_json::json!({
            "status": "OK",
            "version": "0.9.0",
            "pid": 4242,
            "uptime_sec": 3661,
            "config_path": "/etc/cloud-probe/cpworker.json",
            "working_dir": "/var/lib/cloud-probe",
            "log_destination": "/var/log/cloud-probe/worker.log",
            "started_at_sec": 1_700_000_000
        })
        .to_string()
    }

    #[test]
    fn text_format_prints_every_field_with_stable_labels() {
        let info: InfoSummary =
            serde_json::from_slice(info_reply().as_bytes()).expect("info summary");
        let mut out = Vec::new();
        write_info(&mut out, &info, Format::Text).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7, "{text}");
        assert_eq!(lines[0], "version          : 0.9.0");
        assert_eq!(lines[1], "pid              : 4242");
        assert_eq!(lines[2], "uptime           : 3661s (3661 sec)");
        assert_eq!(lines[3], "started_at       : 2023-11-14T22:13:20Z");
        assert_eq!(
            lines[4],
            "config_path      : /etc/cloud-probe/cpworker.json"
        );
        assert_eq!(lines[5], "working_dir      : /var/lib/cloud-probe");
        assert_eq!(
            lines[6],
            "log_destination  : /var/log/cloud-probe/worker.log"
        );
    }

    #[test]
    fn jsonl_format_round_trips_the_summary() {
        let info: InfoSummary =
            serde_json::from_slice(info_reply().as_bytes()).expect("info summary");
        let mut out = Vec::new();
        write_info(&mut out, &info, Format::Jsonl).expect("write");
        let rec: serde_json::Value = serde_json::from_slice(&out).expect("a single JSON object");
        assert_eq!(rec["version"], "0.9.0");
        assert_eq!(rec["pid"], 4242);
        assert_eq!(rec["uptime_sec"], 3661);
        assert_eq!(rec["started_at_sec"], 1_700_000_000);
    }

    #[test]
    fn run_with_client_reports_ok_and_sends_the_info_command() {
        let server = MockServer::start("info-rwc", vec![info_reply()]);
        let mut client =
            cpworker::UnixClient::with_timeout(&server.socket_url(), Duration::from_secs(2))
                .expect("client");
        let mut out = Vec::new();
        run_with_client(&mut client, &mut out, Format::Text, Duration::from_secs(2)).expect("info");
        assert!(String::from_utf8(out)
            .expect("utf8")
            .contains("pid              : 4242"));
        let commands = server.commands();
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(commands[0].contains(r#""command":"info""#), "{commands:?}");
    }

    #[test]
    fn a_worker_error_propagates_without_closing_early() {
        let server = MockServer::start(
            "info-error",
            vec![serde_json::json!({"status": "ERROR", "message": "worker said no"}).to_string()],
        );
        let mut client =
            cpworker::UnixClient::with_timeout(&server.socket_url(), Duration::from_secs(2))
                .expect("client");
        let mut out = Vec::new();
        let err = run_with_client(&mut client, &mut out, Format::Text, Duration::from_secs(2))
            .expect_err("info error");
        assert!(err.to_string().contains("worker said no"), "{err}");
        assert!(out.is_empty(), "no output on failure");
    }

    /// Drive the real `run()` entrypoint against the mock socket: it must honor
    /// `--unix`, open the connection and put an `info` command on the wire.
    #[test]
    fn run_connects_and_sends_the_info_command() {
        let server = MockServer::start("info-run", vec![info_reply()]);
        let globals = Globals {
            unix: Some(server.path.to_string_lossy().into_owned()),
            format: "jsonl".into(),
            timeout: Duration::from_secs(2),
        };
        run(&globals).expect("run must succeed against the mock");
        let commands = server.commands();
        assert_eq!(commands.len(), 1, "{commands:?}");
        assert!(commands[0].contains(r#""command":"info""#), "{commands:?}");
    }
}
