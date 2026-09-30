//! Unix-socket JSON-RPC control plane. Port of `unix-manager.c` +
//! `unix_rpc_basic.c`.
//!
//! Wire protocol (unchanged from the C implementation):
//! 1. client connects and sends `{"version":"v1"}\n`
//! 2. server replies `{"status":"OK"}\n`
//! 3. client sends one or more `{"command":"...", ...}\n` lines
//! 4. server replies with a JSON object (always containing `status`).

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::task::TaskManager;

/// Control protocol version string.
pub const PROTO_VERSION_V1: &str = "v1";

/// `SO_SNDTIMEO` applied to every accepted client (C: `CLIENT_SEND_TIMEOUT_SEC`).
const CLIENT_SEND_TIMEOUT_SEC: i32 = 5;

/// Apply `SO_SNDTIMEO` to `fd`. Port of `unix_manager_set_send_timeout`:
/// a slow reader must hit `EAGAIN` instead of stalling the writer forever.
///
/// # Errors
/// Returns the OS error if `setsockopt` fails.
pub fn set_send_timeout(fd: RawFd, seconds: i32) -> std::io::Result<()> {
    let tv = libc::timeval {
        tv_sec: seconds as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid `timeval` and `fd` a socket owned by the caller.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Unix-domain-socket control server owning its accept thread.
pub struct UnixManager {
    path: PathBuf,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UnixManager {
    /// Bind the socket and spawn the serving thread.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be bound.
    pub fn start(path: &str, mgr: Arc<Mutex<TaskManager>>) -> Result<Self> {
        let path = PathBuf::from(path);
        // Mirror `unlink(socket_file)` before bind.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)
            .map_err(|e| Error::new(format!("unix socket bind({}) error: {e}", path.display())))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::new(format!("set_nonblocking error: {e}")))?;

        let running = Arc::new(AtomicBool::new(true));
        let running_thread = running.clone();
        let thread = std::thread::Builder::new()
            .name("unix_manager".into())
            .spawn(move || {
                while running_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Harden each client against a slow reader (C applies
                            // SO_SNDTIMEO right after accept).
                            if let Err(e) =
                                set_send_timeout(stream.as_raw_fd(), CLIENT_SEND_TIMEOUT_SEC)
                            {
                                crate::log_warn!("unix socket: set SO_SNDTIMEO failed: {e}");
                            }
                            let mgr = mgr.clone();
                            // Serve each client on its own thread.
                            let _ = std::thread::Builder::new()
                                .name("unix_client".into())
                                .spawn(move || handle_client(stream, mgr));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        Err(e) => {
                            crate::log_error!("unix socket accept error: {e}");
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                    }
                }
            })
            .map_err(|e| Error::new(format!("spawn unix manager thread: {e}")))?;

        Ok(UnixManager {
            path,
            running,
            thread: Some(thread),
        })
    }

    /// Stop the accept thread and remove the socket file.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UnixManager {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn handle_client(stream: UnixStream, mgr: Arc<Mutex<TaskManager>>) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    // 1. Handshake.
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let hello: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            crate::log_error!("invalid handshake message: {e}");
            return;
        }
    };
    if hello.get("version").and_then(Value::as_str) != Some(PROTO_VERSION_V1) {
        crate::log_error!("invalid client version");
        return;
    }
    if write_msg(&mut writer, &json!({"status": "OK"})).is_err() {
        return;
    }

    // 2. Command loop. Match the C reference's ~1.5s timeout for an
    // incomplete (newline-less) command: set an overall read timeout.
    let _ = reader
        .get_ref()
        .set_read_timeout(Some(std::time::Duration::from_millis(1500)));
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                crate::log_error!("incomplete client message, closing connection");
                break;
            }
            Err(_) => break,
        }
        // The C reference requires a newline-terminated command; EOF without a
        // newline closes the connection without processing.
        if !line.ends_with('\n') {
            crate::log_error!("incomplete client message, closing connection");
            break;
        }
        let trimmed = line.trim();
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                // The C reference implementation drops the client on malformed
                // command JSON (no response). Match that.
                crate::log_error!("invalid command: {e}");
                break;
            }
        };
        if req.get("command").and_then(Value::as_str).is_none() {
            crate::log_error!("error: command is not a string");
            break;
        }
        let resp = dispatch_command(&req, &mgr);
        if write_msg(&mut writer, &resp).is_err() {
            break;
        }
    }
}

fn write_msg(writer: &mut UnixStream, msg: &Value) -> std::io::Result<()> {
    let mut s = serde_json::to_string(msg).unwrap_or_else(|_| "{\"status\":\"ERROR\"}".into());
    s.push('\n');
    writer.write_all(s.as_bytes())
}

/// Dispatch a single command. Mirrors `unix_command_execute` + registered
/// command handlers. Public so the RPC vectors can call the same seam the
/// C unit tests used (the command handlers directly).
pub fn dispatch_command(req: &Value, mgr: &Arc<Mutex<TaskManager>>) -> Value {
    let Some(cmd) = req.get("command").and_then(Value::as_str) else {
        return json!({"status": "ERROR", "message": "command is not a string"});
    };

    match cmd {
        "ping" => {
            let ts_ms = now_millis();
            json!({"ts_ms": ts_ms, "status": "OK"})
        }
        "info" => {
            let g = mgr.lock();
            let now = crate::task::now_sec();
            // C: started_at <= 0 means "unset" and reports uptime 0.
            let uptime = if g.started_at() > 0 {
                (now - g.started_at()).max(0)
            } else {
                0
            };
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
                "uptime_sec": uptime.max(0),
                "started_at_sec": g.started_at(),
                "config_path": g.config_path(),
                "working_dir": g.working_dir(),
                "log_destination": "stderr",
                "status": "OK",
            })
        }
        "collect_stats_summary" => {
            let g = mgr.lock();
            let mut v = g.collect_stats_summary();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("status".into(), Value::String("OK".into()));
            }
            v
        }
        "reload_config" => {
            // Resolution happens before the lock is taken (AUDIT4 P2-10): this
            // handler runs on the control thread, and holding `mgr` through
            // getaddrinfo() would stall the capture loop and `collect_stats_summary`.
            match crate::task::reload_from_file(mgr) {
                Ok(()) => json!({"status": "OK"}),
                Err(e) => json!({"status": "ERROR", "message": e.to_string()}),
            }
        }
        _ => json!({"status": "ERROR", "message": "unknown command"}),
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
