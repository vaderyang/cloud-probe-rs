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

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Value};

use cpworker::config::Config;
use cpworker::task::TaskManager;
use cpworker::unix_manager::{dispatch_command, set_send_timeout};

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
