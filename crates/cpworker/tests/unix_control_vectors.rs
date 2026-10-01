//! Ports of upstream `cpworker/tests/unit/unix_control.c`.
//!
//! The C file merges two seams:
//! * `unix_rpc_basic`: the `ping` / `info` command handlers, called directly
//!   with a response object. In the Rust port those handlers live in
//!   [`dispatch_command`], so the tests call that same seam.
//! * `unix-manager`: `SO_SNDTIMEO` hardening, tested through
//!   [`set_send_timeout`] and a stalled `send()`.
//!
//! `test_info_command_working_dir_updates_on_reset` has no Rust counterpart to
//! port: the C module keeps a mutable `g_working_dir` global with a setter,
//! whereas the Rust port stores `working_dir` once on `TaskManager` and a
//! reload rebuilds the manager. The observable RPC value is covered by
//! `test_info_command_handles_unset_config_path`.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{json, Value};

use cpworker::config::Config;
use cpworker::task::TaskManager;
use cpworker::unix_manager::{dispatch_command, set_send_timeout, UnixManager};

fn manager(config_path: &str, working_dir: &str) -> Arc<Mutex<TaskManager>> {
    let cfg = Config::parse_str(r#"{"tasks":[]}"#).expect("minimal config");
    let mgr = TaskManager::new(cfg, config_path.into(), working_dir.into()).expect("manager");
    Arc::new(Mutex::new(mgr))
}

// --- unix_rpc_basic: ping / info -------------------------------------------

// --- `test_ping_command_adds_ts_ms` ----------------------------------------

#[test]
fn test_ping_command_adds_ts_ms() {
    let mgr = manager("", "");
    let resp = dispatch_command(&json!({"command": "ping"}), &mgr);

    let ts = resp
        .get("ts_ms")
        .and_then(Value::as_i64)
        .expect("ts_ms must be a number");
    // A recent millisecond timestamp (> year 2020).
    assert!(ts > 1_577_836_800_000, "ts_ms {ts} is not after 2020");
}

// --- `test_info_command_returns_expected_fields` ---------------------------

#[test]
fn test_info_command_returns_expected_fields() {
    let fake_start = cpworker::task::now_sec() - 60; // 60s uptime
    let cfg = Config::parse_str(r#"{"tasks":[]}"#).expect("minimal config");
    let mut mgr = TaskManager::new(
        cfg,
        "/tmp/fake-cpworker.json".into(),
        "/opt/cpworker".into(),
    )
    .expect("manager");
    mgr.set_started_at(fake_start);
    let mgr = Arc::new(Mutex::new(mgr));

    let resp = dispatch_command(&json!({"command": "info"}), &mgr);

    assert!(resp.get("version").is_some_and(Value::is_string));
    assert_eq!(
        resp.get("pid").and_then(Value::as_u64),
        Some(u64::from(std::process::id()))
    );

    let uptime = resp
        .get("uptime_sec")
        .and_then(Value::as_i64)
        .expect("uptime_sec");
    assert!(
        (60..=65).contains(&uptime),
        "uptime should be ~60, got {uptime}"
    );
    assert_eq!(
        resp.get("started_at_sec").and_then(Value::as_i64),
        Some(fake_start)
    );
    assert_eq!(
        resp.get("config_path").and_then(Value::as_str),
        Some("/tmp/fake-cpworker.json")
    );
    assert_eq!(
        resp.get("working_dir").and_then(Value::as_str),
        Some("/opt/cpworker")
    );
    assert_eq!(
        resp.get("log_destination").and_then(Value::as_str),
        Some("stderr")
    );
}

// --- `test_info_command_handles_unset_config_path` -------------------------

#[test]
fn test_info_command_handles_unset_config_path() {
    let cfg = Config::parse_str(r#"{"tasks":[]}"#).expect("minimal config");
    let mut mgr = TaskManager::new(cfg, String::new(), String::new()).expect("manager");
    mgr.set_started_at(0);
    let mgr = Arc::new(Mutex::new(mgr));

    let resp = dispatch_command(&json!({"command": "info"}), &mgr);

    assert_eq!(resp.get("config_path").and_then(Value::as_str), Some(""));
    assert_eq!(resp.get("working_dir").and_then(Value::as_str), Some(""));
    assert_eq!(resp.get("uptime_sec").and_then(Value::as_i64), Some(0));
}

// --- unix-manager: SO_SNDTIMEO hardening -----------------------------------

fn get_sndtimeo(fd: RawFd) -> (i64, i64) {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: `tv`/`len` are valid out-parameters for this getsockopt call.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::addr_of_mut!(tv).cast(),
            &mut len,
        )
    };
    assert_eq!(ret, 0, "getsockopt(SO_SNDTIMEO) failed");
    (tv.tv_sec, tv.tv_usec)
}

// --- `test_set_send_timeout_readable_via_getsockopt` -----------------------

#[test]
fn test_set_send_timeout_readable_via_getsockopt() {
    let (a, _b) = UnixStream::pair().expect("socketpair");

    set_send_timeout(a.as_raw_fd(), 3).expect("set SO_SNDTIMEO");

    let (sec, _usec) = get_sndtimeo(a.as_raw_fd());
    assert_eq!(sec, 3);
}

// --- `test_send_timeout_fires_on_unread_peer` ------------------------------

#[test]
fn test_send_timeout_fires_on_unread_peer() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let fd = a.as_raw_fd();

    // Tight socket buffers so the test finishes well under a second.
    let small: libc::c_int = 4096;
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    // SAFETY: `small`/`tv` are valid socket-option values for this socket.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::addr_of!(small).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(small).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let payload = [b'A'; 8192];
    // We never read from `_b`, so `send()` must fail with EAGAIN/EWOULDBLOCK
    // once the buffer is full. The hard cap prevents an infinite loop if the
    // timeout ever breaks.
    let mut timed_out = false;
    for _ in 0..64 {
        // SAFETY: `payload` is a valid buffer of `payload.len()` bytes.
        let n = unsafe { libc::send(fd, payload.as_ptr().cast(), payload.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                timed_out = true;
            }
            break;
        }
    }
    assert!(
        timed_out,
        "send() should have returned EAGAIN once the buffer filled"
    );
}

// --- unix-manager: single-threaded poll() server semantics -------------------
//
// These drive a real [`UnixManager`] over a real `UnixStream` from test
// threads. They pin the C reference's observable behaviour: one event loop
// multiplexes every client, a newline-less command is abandoned after the
// 1.5s window, a genuinely idle client is *kept* (C only times out partial
// frames), and a client that stops draining its responses is dropped within
// the 5s `SO_SNDTIMEO` budget.

static SOCKET_SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_socket(tag: &str) -> PathBuf {
    let n = SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cpworker-test-{}-{tag}-{n}.sock",
        std::process::id()
    ));
    path
}

/// Read exactly one newline-terminated frame, without over-buffering (a
/// `BufReader` here could swallow the next reply).
fn read_line(stream: &mut UnixStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).expect("read reply");
        assert_ne!(n, 0, "unexpected EOF while reading a reply");
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
    }
    String::from_utf8(out).expect("utf8 reply")
}

fn read_reply(stream: &mut UnixStream) -> Value {
    serde_json::from_str(&read_line(stream)).expect("json reply")
}

fn assert_ok(reply: &Value) {
    assert_eq!(
        reply.get("status").and_then(Value::as_str),
        Some("OK"),
        "reply: {reply}"
    );
}

fn dial_and_handshake(path: &Path) -> UnixStream {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    stream
        .write_all(b"{\"version\":\"v1\"}\n")
        .expect("handshake write");
    assert_ok(&read_reply(&mut stream));
    stream
}

fn start_server(tag: &str) -> (PathBuf, UnixManager) {
    let path = temp_socket(tag);
    let mgr = manager("", "");
    let server = UnixManager::start(path.to_str().expect("utf8 path"), mgr).expect("start server");
    (path, server)
}

#[test]
fn test_server_serves_concurrent_clients() {
    let (path, server) = start_server("concurrent");

    let mut handles = Vec::new();
    for client in 0..8u32 {
        let path = path.clone();
        handles.push(std::thread::spawn(move || {
            let mut stream = dial_and_handshake(&path);
            // Split the command across two writes: the event loop must
            // reassemble it from its per-client buffer.
            stream
                .write_all(b"{\"command\":\"pi")
                .expect("partial write");
            std::thread::sleep(Duration::from_millis(20));
            stream.write_all(b"ng\"}\n").expect("rest write");
            let ping = read_reply(&mut stream);
            assert_ok(&ping);
            assert!(ping.get("ts_ms").is_some(), "client {client}");

            stream
                .write_all(b"{\"command\":\"info\"}\n")
                .expect("info write");
            assert_ok(&read_reply(&mut stream));
        }));
    }
    for handle in handles {
        handle.join().expect("client thread");
    }
    drop(server);
}

#[test]
fn test_server_disconnects_partial_frame_after_idle_timeout() {
    let (path, server) = start_server("partial");
    let mut stream = dial_and_handshake(&path);

    // A command without its terminating newline and then silence: C gives it
    // 3 x 500ms, then closes without a reply.
    stream
        .write_all(b"{\"command\":\"ping\"")
        .expect("partial command");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let start = Instant::now();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).expect("server must close, not hang");
    assert_eq!(n, 0, "a stalled partial frame must be closed",);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1400),
        "closed before the 1.5s window: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(3),
        "closed far after the 1.5s window: {elapsed:?}"
    );
    drop(server);
}

#[test]
fn test_server_keeps_idle_client_without_partial_frame() {
    let (path, server) = start_server("idle");
    let mut stream = dial_and_handshake(&path);

    // No bytes at all for longer than the partial-frame window. C does not
    // time out an idle client, and neither must the poll loop.
    std::thread::sleep(Duration::from_millis(1800));
    stream
        .write_all(b"{\"command\":\"ping\"}\n")
        .expect("ping write");
    assert_ok(&read_reply(&mut stream));
    drop(server);
}

#[test]
fn test_server_disconnects_overlong_command() {
    let (path, server) = start_server("overlong");
    let mut stream = dial_and_handshake(&path);

    // > `CLIENT_BUFFER_SIZE - 1` bytes with no newline. C disconnects rather
    // than growing the buffer without bound.
    let big = vec![b'A'; 5000];
    let _ = stream.write_all(&big);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");

    // Closing a socket with unread data makes Linux deliver ECONNRESET rather
    // than a clean EOF; either is the required disconnect.
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("over-long command must be closed, got {other:?}"),
    }
    drop(server);
}

#[test]
fn test_server_drops_client_that_stops_reading() {
    let (path, server) = start_server("send-timeout");
    let mut stream = dial_and_handshake(&path);

    // Shrink our receive buffer so the server's kernel send buffer fills long
    // before the flood ends; a single small reply would otherwise be absorbed
    // by the socket and never trip the write deadline.
    let small: libc::c_int = 2048;
    // SAFETY: `small` is a valid int socket option on `stream`.
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(small).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let mut writer = stream.try_clone().expect("clone");
    // Flood until the server gives up; 6s bounds the test if it never does.
    let flood = std::thread::spawn(move || {
        writer
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("write timeout");
        let cmd = b"{\"command\":\"ping\"}\n";
        let start = Instant::now();
        let mut sent = 0u64;
        while start.elapsed() < Duration::from_secs(6) {
            match writer.write_all(cmd) {
                Ok(()) => sent += 1,
                // EPIPE/ECONNRESET: the server retired us.
                Err(e) => return Some((sent, e)),
            }
        }
        None
    });

    let outcome = flood.join().expect("flood thread");
    assert!(
        outcome.is_some(),
        "server must drop a client that stops reading"
    );
    let (sent, err) = outcome.expect("checked above");
    assert!(sent > 0, "flood should have made progress: {err}");

    // The server is gone; drain the buffered replies until EOF.
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut buf = [0u8; 8192];
    let mut saw_eof = false;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => {
                saw_eof = true;
                break;
            }
            Ok(_) => {}
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => {
                saw_eof = true;
                break;
            }
        }
    }
    assert!(saw_eof, "server must have closed the connection");
    drop(server);
}
