//! Unix-socket JSON-RPC control plane. Port of `unix-manager.c` +
//! `unix_rpc_basic.c`.
//!
//! Wire protocol (unchanged from the C implementation):
//! 1. client connects and sends `{"version":"v1"}\n`
//! 2. server replies `{"status":"OK"}\n`
//! 3. client sends one or more `{"command":"...", ...}\n` lines
//! 4. server replies with a JSON object (always containing `status`).
//!
//! Concurrency mirrors the C reference: one manager thread runs a single
//! `poll()` loop over the listening socket plus every accepted client. Clients
//! are serviced before new connections are accepted, exactly as
//! `unix_manager_main()` orders them. A client that sends a newline-less
//! command gets 3 x 500ms (1.5s) to finish before it is disconnected, and a
//! client that stops draining its responses is dropped after
//! `CLIENT_SEND_TIMEOUT_SEC` (5s) - the budget `SO_SNDTIMEO` gives the C
//! implementation.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::task::TaskManager;

/// Control protocol version string.
pub const PROTO_VERSION_V1: &str = "v1";

/// `SO_SNDTIMEO` applied to every accepted client (C: `CLIENT_SEND_TIMEOUT_SEC`).
const CLIENT_SEND_TIMEOUT_SEC: i32 = 5;

/// Per-client write budget, the userspace equivalent of `SO_SNDTIMEO`: once a
/// response is queued and the socket refuses it, the peer has this long to
/// drain before the connection is dropped.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// C waits 3 x 500ms for the rest of a newline-less command
/// (`unix_client_recv`). The deadline is refreshed whenever more of the frame
/// arrives, matching that per-event window.
const CLIENT_PARTIAL_TIMEOUT: Duration = Duration::from_millis(1500);

/// `select()` tick used by the C loop; also the maximum poll sleep.
const POLL_TICK_MS: i32 = 500;

/// C's `CLIENT_BUFFER_SIZE`; a single command longer than this disconnects.
const CLIENT_BUFFER_SIZE: usize = 4096;

/// Most bytes read from one client per poll event (bounds per-client work).
const CLIENT_READ_CHUNK: usize = CLIENT_BUFFER_SIZE;

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
            .spawn(move || serve(listener, mgr, running_thread))
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

/// One accepted connection and its pending read/write state.
struct Client {
    stream: UnixStream,
    /// Cached descriptor, so building the `pollfd` array needs no borrow of
    /// `stream`.
    fd: RawFd,
    /// Bytes received but not yet terminated by a newline.
    read_buf: Vec<u8>,
    /// Responses queued for a peer that has not drained them yet.
    write_buf: Vec<u8>,
    /// `false` until the `{"version":"v1"}` handshake has been accepted.
    handshake_done: bool,
    /// When a partial command must be completed by, or the connection drops.
    partial_deadline: Option<Instant>,
    /// When queued responses must be drained by, or the connection drops.
    write_deadline: Option<Instant>,
}

impl Client {
    fn new(stream: UnixStream) -> Self {
        let fd = stream.as_raw_fd();
        Client {
            stream,
            fd,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
            handshake_done: false,
            partial_deadline: None,
            write_deadline: None,
        }
    }
}

/// Single-threaded `select()`-equivalent loop: port of `unix_manager_run` +
/// `unix_manager_main`.
fn serve(listener: UnixListener, mgr: Arc<Mutex<TaskManager>>, running: Arc<AtomicBool>) {
    let listener_fd = listener.as_raw_fd();
    let mut clients: Vec<Client> = Vec::new();

    while running.load(Ordering::Acquire) {
        // Register the listening socket first, then every client. Client `i`
        // lives at `fds[i + 1]`.
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(clients.len() + 1);
        fds.push(libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        for c in &clients {
            let mut events = libc::POLLIN;
            if !c.write_buf.is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd: c.fd,
                events,
                revents: 0,
            });
        }

        let timeout = poll_timeout(&clients, Instant::now());
        // SAFETY: `fds` is a live, contiguous array of `pollfd`.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            crate::log_error!("unix socket: poll() fatal error: {err}");
            break;
        }

        let mut discard = vec![false; clients.len()];

        // 1. Service existing clients *before* accepting (`unix_manager_main`
        //    walks the client list first). Reading may queue responses, so
        //    flush immediately rather than waiting for a POLLOUT we never
        //    registered.
        for (i, dropped) in discard.iter_mut().enumerate() {
            let revents = fds[i + 1].revents;
            if revents == 0 {
                continue;
            }
            if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                *dropped = !client_readable(&mut clients[i], &mgr);
            }
            if !*dropped && !clients[i].write_buf.is_empty() {
                *dropped = !flush_client(&mut clients[i]);
            }
        }

        // 2. Accept new connections, after the clients (C order).
        if fds[0].revents & libc::POLLIN != 0 {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(e) = stream.set_nonblocking(true) {
                            crate::log_error!("unix socket: set_nonblocking error: {e}");
                            continue;
                        }
                        // Match C: harden every client against a slow reader.
                        if let Err(e) =
                            set_send_timeout(stream.as_raw_fd(), CLIENT_SEND_TIMEOUT_SEC)
                        {
                            crate::log_warn!("unix socket: set SO_SNDTIMEO failed: {e}");
                        }
                        clients.push(Client::new(stream));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        crate::log_error!("unix socket accept error: {e}");
                        break;
                    }
                }
            }
        }

        // 3. Retire clients whose partial-frame or write deadline has elapsed.
        //    Newly accepted clients start alive.
        discard.resize(clients.len(), false);
        let now = Instant::now();
        for (i, dropped) in discard.iter_mut().enumerate() {
            if !*dropped && client_expired(&clients[i], now) {
                *dropped = true;
            }
        }
        let mut kept = Vec::with_capacity(clients.len());
        for (client, dropped) in clients.into_iter().zip(discard) {
            if !dropped {
                kept.push(client);
            }
        }
        clients = kept;
    }
}

/// Read one chunk from `client` and act on it. Returns `false` when the
/// connection must be closed.
fn client_readable(client: &mut Client, mgr: &Arc<Mutex<TaskManager>>) -> bool {
    let mut buf = [0u8; CLIENT_READ_CHUNK];
    match client.stream.read(&mut buf) {
        // EOF, or a half-close with nothing left buffered.
        Ok(0) => false,
        Ok(n) => {
            client.read_buf.extend_from_slice(&buf[..n]);
            process_input(client, mgr)
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        // A signal interrupted the read; the fd is still open.
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => true,
        Err(_) => false,
    }
}

/// Split `read_buf` into newline-terminated frames, dispatching each. The
/// trailing, newline-less remainder starts (or refreshes) the 1.5s deadline.
fn process_input(client: &mut Client, mgr: &Arc<Mutex<TaskManager>>) -> bool {
    while let Some(pos) = client.read_buf.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = client.read_buf.drain(..=pos).collect();
        if !handle_message(client, &line, mgr) {
            return false;
        }
    }

    if client.read_buf.is_empty() {
        client.partial_deadline = None;
        return true;
    }
    // `unix_client_recv` disconnects a client whose single command outgrows the
    // 4 KiB buffer before a newline shows up.
    if client.read_buf.len() >= CLIENT_BUFFER_SIZE - 1 {
        crate::log_error!("command server: client command is too long, disconnect it.");
        return false;
    }
    client.partial_deadline = Some(Instant::now() + CLIENT_PARTIAL_TIMEOUT);
    true
}

/// Handle one newline-terminated frame: the version handshake first, then
/// commands. Returns `false` to drop the connection.
fn handle_message(client: &mut Client, line: &[u8], mgr: &Arc<Mutex<TaskManager>>) -> bool {
    let msg: Value = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => {
            // C drops the client on malformed JSON without sending a reply.
            if client.handshake_done {
                crate::log_error!("invalid command: {e}");
            } else {
                crate::log_error!("invalid handshake message: {e}");
            }
            return false;
        }
    };

    if !client.handshake_done {
        if msg.get("version").and_then(Value::as_str) != Some(PROTO_VERSION_V1) {
            crate::log_error!("invalid client version");
            return false;
        }
        client.handshake_done = true;
        queue_response(client, &json!({"status": "OK"}));
        return true;
    }

    if msg.get("command").and_then(Value::as_str).is_none() {
        crate::log_error!("error: command is not a string");
        return false;
    }
    let resp = dispatch_command(&msg, mgr);
    queue_response(client, &resp);
    true
}

/// Append a newline-terminated JSON response to the client's write buffer.
fn queue_response(client: &mut Client, msg: &Value) {
    match serde_json::to_vec(msg) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            client.write_buf.extend_from_slice(&bytes);
        }
        Err(e) => {
            crate::log_error!("json dumps error: {e}");
            client
                .write_buf
                .extend_from_slice(b"{\"status\":\"ERROR\"}\n");
        }
    }
}

/// Try to drain `client.write_buf`. Returns `false` when the connection must be
/// closed (hard error); a `WouldBlock` leaves the remaining bytes queued and
/// starts/keeps the write deadline.
fn flush_client(client: &mut Client) -> bool {
    while !client.write_buf.is_empty() {
        match client.stream.write(&client.write_buf) {
            Ok(0) => return false,
            Ok(n) => {
                client.write_buf.drain(..n);
                if client.write_buf.is_empty() {
                    client.write_deadline = None;
                } else {
                    // Progress was made, so restart the peer's budget.
                    client.write_deadline = Some(Instant::now() + CLIENT_WRITE_TIMEOUT);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                client
                    .write_deadline
                    .get_or_insert(Instant::now() + CLIENT_WRITE_TIMEOUT);
                return true;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// True when either the partial-frame or the write deadline has elapsed.
fn client_expired(client: &Client, now: Instant) -> bool {
    let partial = client.partial_deadline.is_some_and(|d| now >= d);
    let write = client.write_deadline.is_some_and(|d| now >= d);
    partial || write
}

/// Poll timeout: one tick, shortened to the nearest client deadline so an
/// expired client is retired promptly without spinning.
fn poll_timeout(clients: &[Client], now: Instant) -> libc::c_int {
    let mut ms = POLL_TICK_MS;
    for c in clients {
        for deadline in [c.partial_deadline, c.write_deadline].into_iter().flatten() {
            let remaining = deadline.saturating_duration_since(now).as_millis();
            let remaining = i32::try_from(remaining).unwrap_or(i32::MAX);
            ms = ms.min(remaining);
        }
    }
    ms
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
