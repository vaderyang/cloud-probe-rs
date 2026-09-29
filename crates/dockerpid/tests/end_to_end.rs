//! End-to-end test for the `dockerpid` binary.
//!
//! Runs the real binary against a mock Docker Engine HTTP API over TCP
//! (`DOCKER_HOST=tcp://...`), covering API-version negotiation (`/_ping`),
//! `DOCKER_API_VERSION` short-circuiting it, inspect parsing and the failure
//! paths.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// A tiny HTTP server that answers `/_ping` and `containers/*/json`.
///
/// Requests are recorded (request line) so the tests can assert which paths the
/// binary actually hit.
fn spawn_mock_docker(pid: Option<i64>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_thread = seen.clone();

    std::thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            seen_thread.lock().unwrap().push(path.clone());

            let resp = if path == "/_ping" {
                "HTTP/1.1 200 OK\r\nApi-Version: 1.41\r\nContent-Length: 2\r\n\r\nOK".to_string()
            } else if path.contains("/containers/") {
                let body = match pid {
                    Some(p) => {
                        format!("{{\"Id\":\"abc\",\"State\":{{\"Running\":true,\"Pid\":{p}}}}}")
                    }
                    None => "{\"Id\":\"abc\",\"State\":{\"Running\":true}}".to_string(),
                };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });

    (addr, seen)
}

fn run(host: &str, api_version: Option<&str>, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dockerpid"));
    cmd.args(args).env("DOCKER_HOST", host);
    if let Some(v) = api_version {
        cmd.env("DOCKER_API_VERSION", v);
    } else {
        cmd.env_remove("DOCKER_API_VERSION");
    }
    cmd.output().expect("run dockerpid")
}

#[test]
fn negotiates_the_api_version_then_prints_the_host_pid() {
    let (addr, seen) = spawn_mock_docker(Some(4321));
    let out = run(&format!("tcp://{addr}"), None, &["abc123"]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "4321");

    let paths = seen.lock().unwrap().clone();
    assert!(paths.contains(&"/_ping".to_string()), "paths: {paths:?}");
    // The version advertised by `/_ping` must be used for the inspect call.
    assert!(
        paths.iter().any(|p| p == "/v1.41/containers/abc123/json"),
        "inspect must use the negotiated version; paths: {paths:?}"
    );
}

#[test]
fn docker_api_version_skips_the_ping_and_uses_the_unversioned_path() {
    let (addr, seen) = spawn_mock_docker(Some(99));
    let out = run(&format!("tcp://{addr}"), Some("1.41"), &["abc123"]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "99");

    let paths = seen.lock().unwrap().clone();
    assert!(
        !paths.contains(&"/_ping".to_string()),
        "DOCKER_API_VERSION must skip negotiation; paths: {paths:?}"
    );
    assert_eq!(paths, vec!["/containers/abc123/json".to_string()]);
}

#[test]
fn missing_pid_is_a_reported_failure() {
    let (addr, _seen) = spawn_mock_docker(None);
    let out = run(&format!("tcp://{addr}"), Some("1.41"), &["abc123"]);

    assert!(!out.status.success(), "must exit non-zero");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Failed to get container info"),
        "stderr: {err}"
    );
}

#[test]
fn missing_argument_prints_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_dockerpid"))
        .output()
        .expect("run dockerpid");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Usage:"), "stderr: {err}");
}
