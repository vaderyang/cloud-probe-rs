//! Unix-socket JSON-RPC control plane. Port of `unix-manager.c` +
//! `unix_rpc_basic.c`.
//!
//! Wire protocol (unchanged from the C implementation):
//! 1. client connects and sends `{"version":"v1"}\n`
//! 2. server replies `{"status":"OK"}\n`
//! 3. client sends one or more `{"command":"...", ...}\n` lines
//! 4. server replies with a JSON object (always containing `status`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::task::TaskManager;

pub const PROTO_VERSION_V1: &str = "v1";

pub struct UnixManager {
    path: PathBuf,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UnixManager {
    /// Bind the socket and spawn the serving thread.
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
        let resp = dispatch(&req, &mgr);
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
/// command handlers.
fn dispatch(req: &Value, mgr: &Arc<Mutex<TaskManager>>) -> Value {
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
            let uptime = now - g.started_at();
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
            v.as_object_mut()
                .unwrap()
                .insert("status".into(), Value::String("OK".into()));
            v
        }
        "reload_config" => {
            let mut g = mgr.lock();
            match g.reload_from_file() {
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
