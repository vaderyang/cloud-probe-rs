//! Minimal ZMTP 3.x `PUSH` client over TCP (pure Rust, no libzmq).
//!
//! A non-blocking state machine: it connects (non-blocking), exchanges the
//! greeting and `READY`, then writes framed messages. Messages are queued up to
//! a high-water mark (`hwm`) and dropped when the queue is full — matching
//! libzmq's `zmq_send(..., ZMQ_DONTWAIT)` behaviour. On any I/O or protocol
//! error the connection is torn down and reconnected with backoff.
//!
//! Robustness properties this client implements explicitly (AUDIT4 P5-10):
//!
//! * a peer that accepts the TCP connection but never completes the ZMTP
//!   handshake is given up on after [`DEFAULT_HANDSHAKE_TIMEOUT`]
//!   (configurable with [`ZmtpPush::with_handshake_timeout`]) and reconnected;
//! * every socket gets TCP keepalive plus `TCP_USER_TIMEOUT`, so a black-holed
//!   peer is noticed instead of lingering forever;
//! * the connector re-resolves the collector hostname on reconnect (rate limited
//!   to `RESOLVE_TTL`) and rotates over *all* returned addresses, so a DNS change
//!   or a multi-A/AAAA record is not pinned to the first answer;
//! * every byte we owe the peer goes through one FIFO (`Conn::out`), and business
//!   frames are only written once that FIFO is empty. A short write in the middle
//!   of the greeting/READY can therefore never misalign the wire stream.
//!
//! The transport, connector and resolver are traits so the state machine can be
//! driven by a scripted mock in tests and fuzz targets (malformed peer bytes,
//! truncation, disconnects, short writes, wrong socket types, …).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

use super::codec;

const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// How long a reconnect may re-use the previously resolved addresses before the
/// hostname is looked up again. Rate limits DNS during a reconnect storm.
pub const RESOLVE_TTL: Duration = Duration::from_secs(1);

/// Idle time before the first TCP keepalive probe is sent.
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
/// Interval between keepalive probes.
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// Keepalive probes lost before the connection is considered dead.
pub const TCP_KEEPALIVE_RETRIES: u32 = 3;
/// How long unacked data may stay unacked before the connection is failed
/// (`TCP_USER_TIMEOUT`). Bounds how long a stalled collector can hold our write
/// path open.
pub const TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Report (once per process) that the OS refused our TCP timeout options, so a
/// kernel that does not support them is visible rather than silent.
static TCP_TIMEOUTS_WARNED: AtomicBool = AtomicBool::new(false);

/// A byte-stream transport used by [`ZmtpPush`].
pub trait Transport: Send {
    /// Write bytes, returning the count written (may be short).
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    /// Read bytes, returning 0 on EOF. May return `WouldBlock`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Non-blocking check whether a pending connect has completed. Defaults to
    /// `true` for already-connected transports.
    fn check_connected(&mut self) -> io::Result<bool> {
        Ok(true)
    }
    /// Tear down the transport.
    fn shutdown(&mut self) {}
}

/// Creates transports for [`ZmtpPush`] (injectable for tests/fuzzing).
pub trait Connector: Send {
    /// Start a connection. The returned transport may still be connecting
    /// (see [`Transport::check_connected`]).
    ///
    /// # Errors
    /// Returns an error if a new transport cannot be created.
    fn start(&mut self) -> io::Result<Box<dyn Transport>>;
}

/// Outcome of a [`ZmtpPush::send`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Message accepted into the outgoing queue (libzmq `zmq_send` success).
    Queued,
    /// Dropped because the high-water mark is reached (libzmq `EAGAIN`).
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connecting,
    Greeting,
    Ready,
    Open,
}

struct Conn {
    t: Box<dyn Transport>,
    phase: Phase,
    /// Every byte we still owe the peer, in wire order: greeting, READY, PONG.
    /// `out_off` is the read position inside it (a short write leaves it
    /// mid-buffer). Business frames are written straight to the transport only
    /// once this FIFO is drained, so a partially written handshake frame can
    /// never be overwritten or interleaved.
    out: Vec<u8>,
    out_off: usize,
    inbuf: Vec<u8>,
    /// Instant by which the ZMTP handshake must have completed, otherwise the
    /// peer is treated as unreachable and we reconnect.
    deadline: Instant,
}

impl Conn {
    /// Append bytes to the outgoing FIFO, compacting what has already been
    /// written. Never replaces unwritten bytes: that would misalign the stream.
    fn queue_out(&mut self, bytes: &[u8]) {
        debug_assert!(
            self.out_off <= self.out.len(),
            "write cursor past the buffer"
        );
        if self.out_off > 0 {
            self.out.drain(..self.out_off);
            self.out_off = 0;
        }
        self.out.extend_from_slice(bytes);
    }

    /// Whether some of `out` has not reached the transport yet.
    fn out_pending(&self) -> bool {
        debug_assert!(
            self.out_off <= self.out.len(),
            "write cursor past the buffer"
        );
        self.out_off != self.out.len()
    }

    /// Safe to write a business frame? Only when the handshake is done *and* the
    /// outgoing FIFO is empty, otherwise our frame bytes would land in the middle
    /// of a half-written handshake frame.
    fn can_write_messages(&self) -> bool {
        self.phase == Phase::Open && !self.out_pending()
    }

    fn handshake_expired(&self, now: Instant) -> bool {
        self.phase != Phase::Open && now >= self.deadline
    }
}

impl Conn {
    fn advance(&mut self) -> Result<(), ()> {
        loop {
            match self.phase {
                Phase::Connecting => break,
                Phase::Greeting => {
                    if self.inbuf.len() < codec::GREETING_LEN {
                        break;
                    }
                    if codec::parse_greeting(&self.inbuf[..codec::GREETING_LEN]).is_err() {
                        return Err(());
                    }
                    self.inbuf.drain(..codec::GREETING_LEN);
                    self.queue_out(&codec::ready_command("PUSH"));
                    self.phase = Phase::Ready;
                }
                Phase::Ready => match codec::parse_frame(&self.inbuf) {
                    Ok(Some((frame, n))) => {
                        self.inbuf.drain(..n);
                        match codec::decode_command(&frame) {
                            Ok(codec::Command::Ready(md)) => {
                                let peer = md
                                    .get("Socket-Type")
                                    .and_then(|v| std::str::from_utf8(v).ok())
                                    .unwrap_or("");
                                if !codec::peer_type_compatible(peer) {
                                    return Err(());
                                }
                                self.phase = Phase::Open;
                            }
                            Ok(codec::Command::Error(_)) | Err(_) => return Err(()),
                            Ok(_) => {}
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Err(()),
                },
                Phase::Open => match codec::parse_frame(&self.inbuf) {
                    Ok(Some((frame, n))) => {
                        self.inbuf.drain(..n);
                        if frame.is_command() {
                            match codec::decode_command(&frame) {
                                Ok(codec::Command::Ping(data)) => {
                                    self.queue_out(&codec::pong_command(&data));
                                }
                                Ok(codec::Command::Error(_)) => return Err(()),
                                _ => {}
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Err(()),
                },
            }
        }
        Ok(())
    }
}

/// Ceiling on the bytes parked in the outgoing queue.
///
/// The queue is bounded twice over: by `hwm` messages *and* by this many bytes.
/// A ZMQ batch is at most 1 MiB, so a large `hwm` alone would let a slow or
/// missing collector make the worker hold `hwm x 1 MiB` in RAM — and the process
/// the OOM killer picks is the capture process. See also
/// [`ZmtpPush::with_queue_limits`].
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;

/// Default time allowed for the ZMTP handshake before the peer is considered
/// unreachable and the connection is re-established.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A non-blocking ZMTP `PUSH` client.
pub struct ZmtpPush {
    connector: Box<dyn Connector>,
    hwm: usize,
    conn: Option<Conn>,
    pending: VecDeque<Vec<u8>>,
    front_off: usize,
    next_attempt: Instant,
    backoff: Duration,
    handshake_timeout: Duration,
    handshakes_given_up: u64,
    max_queued_bytes: usize,
    pending_bytes: usize,
}

impl ZmtpPush {
    /// Create a client with the given outgoing high-water mark (messages).
    #[must_use]
    pub fn new(connector: Box<dyn Connector>, hwm: usize) -> Self {
        ZmtpPush {
            connector,
            hwm: hwm.max(1),
            conn: None,
            pending: VecDeque::new(),
            front_off: 0,
            next_attempt: Instant::now(),
            backoff: INITIAL_BACKOFF,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            handshakes_given_up: 0,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
            pending_bytes: 0,
        }
    }

    /// Bound the outgoing queue explicitly: `hwm` messages and `max_queued_bytes`
    /// bytes (a message that would cross either limit is dropped, like libzmq's
    /// `EAGAIN`).
    #[must_use]
    pub fn with_queue_limits(mut self, hwm: usize, max_queued_bytes: usize) -> Self {
        self.hwm = hwm.max(1);
        self.max_queued_bytes = max_queued_bytes.max(1);
        self
    }

    /// Byte ceiling of the outgoing queue.
    #[must_use]
    pub fn max_queued_bytes(&self) -> usize {
        self.max_queued_bytes
    }

    /// Override the handshake deadline.
    /// Tests and fuzzing use a short one; production keeps the default.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// How many handshakes were abandoned because the peer went silent.
    /// Non-zero means the collector is reachable at TCP level but not speaking
    /// ZMTP; see also [`Self::queued`] / [`Self::queued_bytes`].
    #[must_use]
    pub fn handshakes_given_up(&self) -> u64 {
        self.handshakes_given_up
    }

    /// Whether the ZMTP handshake has completed.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| c.phase == Phase::Open)
    }

    /// Number of messages queued waiting to be written.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.pending.len()
    }

    /// Outgoing high-water mark in messages.
    #[must_use]
    pub fn hwm(&self) -> usize {
        self.hwm
    }

    /// Whether a business frame may be written right now (handshake complete and
    /// nothing else outstanding on the wire).
    #[must_use]
    pub fn can_write_messages(&self) -> bool {
        self.conn.as_ref().is_some_and(Conn::can_write_messages)
    }

    /// Number of queued bytes waiting to be written (including frame headers,
    /// minus the part of the front message that already reached the transport).
    ///
    /// This is the observable memory cost of a slow or missing collector.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.pending_bytes.saturating_sub(self.front_off)
    }

    /// Enqueue a message, progressing the connection. Never blocks.
    pub fn send(&mut self, msg: &[u8]) -> SendOutcome {
        self.poll();
        // Exact wire size, so the budget accounting matches what is queued below.
        let framed = msg.len() + if msg.len() > 255 { 9 } else { 2 };
        if self.pending.len() >= self.hwm || self.pending_bytes + framed > self.max_queued_bytes {
            return SendOutcome::Dropped;
        }
        let frame = codec::frame(0, msg);
        self.pending_bytes += frame.len();
        self.pending.push_back(frame);
        self.poll();
        SendOutcome::Queued
    }

    /// Progress connection/reconnect and flush queued messages. Never blocks.
    pub fn poll(&mut self) {
        self.maybe_connect();
        if self.conn_pending_or_stalled() {
            self.abandon_handshake();
        } else if self.conn.is_some() {
            self.drive();
            // `advance()` can queue handshake bytes (READY, PONG) *after* the
            // write pass of a drive cycle. Give them one more pass so a peer is
            // never left waiting for bytes we already had ready — otherwise the
            // handshake (and everything gated on it) stalls until the next poll.
            if self.conn.as_ref().is_some_and(|c| c.out_pending()) {
                self.drive();
            }
        }
        self.flush_pending();
    }

    /// True when a connection exists, has not opened yet, and its handshake
    /// deadline has passed. Covers both a peer that accepts TCP and says nothing
    /// and a connect() that never completes.
    fn conn_pending_or_stalled(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.handshake_expired(Instant::now()))
    }

    /// Tear down a connection whose handshake timed out and back off.
    fn abandon_handshake(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.t.shutdown();
        }
        self.handshakes_given_up += 1;
        // Worth a log line only when data is piling up behind it: a missing
        // collector would otherwise emit one line per backoff step.
        if !self.pending.is_empty() {
            crate::log_warn!(
                "zmtp: handshake timed out after {:?}; reconnecting with {} queued batches",
                self.handshake_timeout,
                self.pending.len()
            );
        }
        self.schedule_reconnect();
    }

    /// Best-effort flush of queued messages for up to `timeout` (linger).
    pub fn drain_for(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.pending.is_empty() && Instant::now() < deadline {
            self.poll();
            if !self.pending.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn maybe_connect(&mut self) {
        if self.conn.is_some() || Instant::now() < self.next_attempt {
            return;
        }
        let mut transport = match self.connector.start() {
            Ok(t) => t,
            Err(_) => {
                self.schedule_reconnect();
                return;
            }
        };
        // A peer that refuses the connect outright should cost one backoff step,
        // not a full handshake deadline: surface that error here instead of
        // discovering it on the first write.
        let connecting = match transport.check_connected() {
            Ok(c) => c,
            Err(_) => {
                transport.shutdown();
                self.schedule_reconnect();
                return;
            }
        };
        let deadline = Instant::now() + self.handshake_timeout;
        self.conn = Some(Conn {
            t: transport,
            phase: if connecting {
                Phase::Connecting
            } else {
                Phase::Greeting
            },
            out: if connecting {
                Vec::new()
            } else {
                codec::greeting().to_vec()
            },
            out_off: 0,
            inbuf: Vec::new(),
            deadline,
        });
    }

    fn drive(&mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let was_open = conn.phase == Phase::Open;
        let result = self.drive_conn(&mut conn);
        match result {
            Ok(()) => {
                if !was_open && conn.phase == Phase::Open {
                    self.backoff = INITIAL_BACKOFF; // successful handshake
                }
                self.conn = Some(conn);
            }
            Err(()) => {
                conn.t.shutdown();
                self.schedule_reconnect();
            }
        }
    }

    fn drive_conn(&mut self, conn: &mut Conn) -> Result<(), ()> {
        if conn.phase == Phase::Connecting {
            match conn.t.check_connected() {
                Ok(true) => {
                    conn.phase = Phase::Greeting;
                    conn.queue_out(&codec::greeting());
                }
                Ok(false) => return Ok(()),
                Err(_) => return Err(()),
            }
        }

        while conn.out_off < conn.out.len() {
            match conn.t.write(&conn.out[conn.out_off..]) {
                Ok(0) => return Err(()),
                Ok(n) => conn.out_off += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }
        if conn.out_off == conn.out.len() {
            conn.out.clear();
            conn.out_off = 0;
        }

        let mut tmp = [0u8; 8192];
        loop {
            match conn.t.read(&mut tmp) {
                Ok(0) => return Err(()),
                Ok(n) => conn.inbuf.extend_from_slice(&tmp[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }

        conn.advance()
    }

    fn flush_pending(&mut self) {
        // Note the stricter-than-`is_connected()` gate: we must not start a
        // frame while handshake bytes are still owed to the transport.
        if !self.can_write_messages() {
            return;
        }
        // `can_write_messages()` is exactly
        // `conn.as_ref().is_some_and(Conn::can_write_messages)`, so a connection
        // exists here. Move it out for the duration of the drain instead of
        // `self.conn.as_mut().unwrap()`: with `panic = "abort"` in the release
        // profile that unwrap would abort the whole worker on a future
        // regression, and this is the message-forwarding hot path
        // (AUDIT4 P5-23).
        let mut conn = match self.conn.take() {
            Some(conn) => conn,
            // Cannot happen (see above); leave the queue untouched and let the
            // next poll re-establish the connection rather than dying here.
            None => return,
        };
        while let Some(msg) = self.pending.pop_front() {
            self.pending_bytes = self.pending_bytes.saturating_sub(msg.len());
            let mut off = self.front_off;
            self.front_off = 0;
            let mut disconnected = false;
            while off < msg.len() {
                debug_assert!(
                    !conn.out_pending(),
                    "single-FIFO invariant: handshake bytes must reach the wire first"
                );
                match conn.t.write(&msg[off..]) {
                    Ok(0) => {
                        disconnected = true;
                        break;
                    }
                    Ok(n) => off += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.front_off = off;
                        self.pending_bytes += msg.len();
                        self.pending.push_front(msg);
                        self.conn = Some(conn);
                        return;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                // A partially written frame is unrecoverable; drop it. The rest
                // of the queue is resent on the next connection.
                if off == 0 {
                    self.pending_bytes += msg.len();
                    self.pending.push_front(msg);
                }
                conn.t.shutdown();
                drop(conn);
                // schedule_reconnect() clears self.conn, which is already None
                // because we took it above.
                self.schedule_reconnect();
                return;
            }
        }
        self.conn = Some(conn);
    }

    fn schedule_reconnect(&mut self) {
        self.conn = None;
        self.next_attempt = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }
}

struct TcpTransport {
    stream: TcpStream,
    connecting: bool,
}

impl Transport for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
    fn check_connected(&mut self) -> io::Result<bool> {
        if !self.connecting {
            return Ok(true);
        }
        if let Some(e) = self.stream.take_error()? {
            return Err(e);
        }
        let ready = {
            let mut fds = [PollFd::new(self.stream.as_fd(), PollFlags::POLLOUT)];
            match poll(&mut fds, PollTimeout::ZERO) {
                Ok(0) => false,
                Ok(_) => {
                    let rev = fds[0].revents().unwrap_or(PollFlags::empty());
                    if rev.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                        // Surface the socket error (or a generic one).
                        match self.stream.take_error()? {
                            Some(e) => return Err(e),
                            None => return Err(io::Error::other("connect failed")),
                        }
                    }
                    true
                }
                Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        };
        if ready {
            if let Some(e) = self.stream.take_error()? {
                return Err(e);
            }
            self.connecting = false;
        }
        Ok(!self.connecting)
    }
    fn shutdown(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Resolves a collector hostname into candidate addresses (injectable).
pub trait Resolver: Send {
    /// Resolve `host` into every address usable for `port`.
    ///
    /// # Errors
    /// Returns an error if the name cannot be resolved right now. A transient
    /// failure is not fatal: [`Connector`]s keep using the previous answer.
    fn resolve(&mut self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The platform resolver (`getaddrinfo` through [`ToSocketAddrs`]).
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&mut self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Opens a non-blocking TCP connection to `addr`, with `TCP_NODELAY`,
/// `SO_KEEPALIVE` (+ probe tuning) and `TCP_USER_TIMEOUT` applied.
///
/// The returned stream may still be connecting; use
/// [`Transport::check_connected`].
///
/// # Errors
/// Returns an error if the socket cannot be created or `connect` fails
/// immediately (e.g. `ECONNREFUSED` on a loopback port with no listener).
fn connect_stream(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    if let Err(e) = set_tcp_timeouts(&socket) {
        // The connection still works without the timeouts; say so once, loudly
        // enough that an operator can see the degraded detection capability.
        if !TCP_TIMEOUTS_WARNED.swap(true, Ordering::Relaxed) {
            crate::log_warn!("zmtp: TCP keepalive/user-timeout unavailable: {e}");
        }
    }
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(ref e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(socket.into())
}

/// Enable `SO_KEEPALIVE` with tuned probes, plus `TCP_USER_TIMEOUT`.
///
/// Without these a black-holed collector (dropped SYN, expired NAT entry, peer
/// that stops ACKing) is never noticed: the client stays in its handshake phase
/// forever and, once open, keeps queueing batches into a dead socket.
///
/// # Errors
/// Returns an error if the platform refuses any of the options.
fn set_tcp_timeouts(socket: &Socket) -> io::Result<()> {
    socket.set_keepalive(true)?;
    socket.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_IDLE)
            .with_interval(TCP_KEEPALIVE_INTERVAL)
            .with_retries(TCP_KEEPALIVE_RETRIES),
    )?;
    crate::sockopt::set_tcp_user_timeout(socket, TCP_USER_TIMEOUT)
}

/// TCP connector for a `host:port` collector.
///
/// Re-resolves the hostname on (re)connect, at most once per [`RESOLVE_TTL`], and
/// rotates the starting index over all answers so a multi-address name is fully
/// covered and a dead address is stepped past.
struct TcpConnector {
    host: String,
    port: u16,
    resolver: Box<dyn Resolver>,
    addrs: Vec<SocketAddr>,
    next: usize,
    last_resolve: Option<Instant>,
}

impl TcpConnector {
    /// Refresh the candidate addresses, honouring the DNS cache interval.
    fn refresh_addresses(&mut self) {
        let stale = self.last_resolve.is_none_or(|t| t.elapsed() >= RESOLVE_TTL);
        if !stale {
            return;
        }
        match self.resolver.resolve(&self.host, self.port) {
            Ok(v) if !v.is_empty() => self.addrs = v,
            // A transient DNS failure (or a name that currently answers nothing)
            // must not stop reconnect attempts: keep the previous answer.
            _ => {}
        }
        self.last_resolve = Some(Instant::now());
    }
}

impl Connector for TcpConnector {
    fn start(&mut self) -> io::Result<Box<dyn Transport>> {
        self.refresh_addresses();
        if self.addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no address resolved for {}:{}", self.host, self.port),
            ));
        }
        let n = self.addrs.len();
        let mut last_err = None;
        for k in 0..n {
            let idx = (self.next + k) % n;
            match connect_stream(self.addrs[idx]) {
                Ok(stream) => {
                    // Start the next attempt after the address that just worked,
                    // so every answer gets its turn over time.
                    self.next = (idx + 1) % n;
                    return Ok(Box::new(TcpTransport {
                        stream,
                        connecting: true,
                    }));
                }
                Err(e) => last_err = Some(e),
            }
        }
        // All answers refused: move on so the next attempt starts elsewhere.
        self.next = (self.next + 1) % n;
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("connect to {}:{} failed", self.host, self.port),
            )
        }))
    }
}

/// Build a TCP connector for `host:port`, resolving the address now.
///
/// The name is resolved again on every (re)connect, so a collector whose address
/// record changes is picked up without restarting the process.
///
/// # Errors
/// Returns an error if the host cannot be resolved at startup.
pub fn tcp_connector(host: &str, port: u16) -> io::Result<Box<dyn Connector>> {
    let mut resolver = SystemResolver;
    let addrs = resolver.resolve(host, port)?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no address resolved for {host}:{port}"),
        ));
    }
    Ok(Box::new(TcpConnector {
        host: host.to_string(),
        port,
        resolver: Box::new(SystemResolver),
        addrs,
        next: 0,
        last_resolve: Some(Instant::now()),
    }))
}

/// Build a TCP connector with an injectable [`Resolver`] (tests, custom DNS).
///
/// Unlike [`tcp_connector`] this does not resolve eagerly; the first lookup
/// happens on the first connect attempt.
#[must_use]
pub fn tcp_connector_with_resolver(
    host: &str,
    port: u16,
    resolver: Box<dyn Resolver>,
) -> Box<dyn Connector> {
    Box::new(TcpConnector {
        host: host.to_string(),
        port,
        resolver,
        addrs: Vec::new(),
        next: 0,
        last_resolve: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Handles {
        peer: Arc<Mutex<Vec<u8>>>,
        written: Arc<Mutex<Vec<u8>>>,
        eof: Arc<AtomicBool>,
        fail_write: Arc<AtomicBool>,
        connects: Arc<AtomicU32>,
        /// Bytes the peer is still willing to accept before its receive window
        /// closes (`usize::MAX` = unlimited). Draining it makes writes return
        /// `WouldBlock`, i.e. a real socket send buffer that filled up.
        write_budget: Arc<AtomicUsize>,
    }

    struct MockTransport {
        h: Handles,
    }

    impl Transport for MockTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.h.fail_write.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let budget = self.h.write_budget.load(Ordering::Relaxed);
            if budget == 0 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let n = budget.min(buf.len());
            self.h.write_budget.fetch_sub(n, Ordering::Relaxed);
            self.h.written.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut peer = self.h.peer.lock().unwrap();
            if !peer.is_empty() {
                let n = peer.len().min(buf.len());
                buf[..n].copy_from_slice(&peer[..n]);
                peer.drain(..n);
                return Ok(n);
            }
            if self.h.eof.load(Ordering::Relaxed) {
                Ok(0)
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }
    }

    struct MockConnector {
        h: Handles,
    }

    impl Connector for MockConnector {
        fn start(&mut self) -> io::Result<Box<dyn Transport>> {
            self.h.connects.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(MockTransport { h: self.h.clone() }))
        }
    }

    /// Open the peer's receive window by `n` more bytes.
    fn topup(h: &Handles, n: usize) {
        h.write_budget.fetch_add(n, Ordering::Relaxed);
    }

    fn valid_peer() -> Vec<u8> {
        let mut p = codec::greeting().to_vec();
        p.extend_from_slice(&codec::ready_command("PULL"));
        p
    }

    fn setup(peer: Vec<u8>, hwm: usize) -> (ZmtpPush, Handles) {
        let h = Handles {
            peer: Arc::new(Mutex::new(peer)),
            ..Default::default()
        };
        let z = ZmtpPush::new(Box::new(MockConnector { h: h.clone() }), hwm);
        h.write_budget.store(usize::MAX / 4, Ordering::Relaxed);
        (z, h)
    }

    fn drive_until_open(z: &mut ZmtpPush) {
        for _ in 0..100 {
            z.poll();
            if z.is_connected() {
                return;
            }
        }
        panic!("handshake did not complete");
    }

    #[test]
    fn handshake_and_send() {
        let (mut z, h) = setup(valid_peer(), 10);
        drive_until_open(&mut z);
        assert_eq!(z.send(b"hello"), SendOutcome::Queued);
        z.poll();
        let w = h.written.lock().unwrap();
        let tail = &w[w.len() - 7..];
        assert_eq!(tail, &codec::frame(0, b"hello")[..]);
        // Greeting (64) + READY were written before the message.
        assert!(w.len() > 64 + 7);
    }

    #[test]
    fn garbage_peer_is_rejected_and_reconnects() {
        let (mut z, h) = setup(vec![0xff, 1, 2, 3, 4], 10);
        for _ in 0..5 {
            z.poll();
        }
        assert!(!z.is_connected());
        // A reconnection was attempted at least once.
        std::thread::sleep(Duration::from_millis(150));
        z.poll();
        assert!(h.connects.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn wrong_socket_type_is_rejected() {
        let mut peer = codec::greeting().to_vec();
        peer.extend_from_slice(&codec::ready_command("SUB"));
        let (mut z, _h) = setup(peer, 10);
        for _ in 0..10 {
            z.poll();
        }
        assert!(!z.is_connected());
    }

    #[test]
    fn truncated_frame_does_not_connect() {
        let mut peer = codec::greeting().to_vec();
        // READY frame header saying 100 bytes but only a few present.
        peer.extend_from_slice(&[codec::FLAG_COMMAND, 100, 1, 2, 3]);
        let (mut z, _h) = setup(peer, 10);
        for _ in 0..10 {
            z.poll();
        }
        assert!(!z.is_connected());
    }

    #[test]
    fn hwm_drops_when_socket_blocks() {
        let (mut z, h) = setup(valid_peer(), 3);
        drive_until_open(&mut z);
        // Make all writes fail so nothing drains and the queue fills.
        h.fail_write.store(true, Ordering::Relaxed);
        let mut dropped = 0;
        for _ in 0..10 {
            if z.send(b"x") == SendOutcome::Dropped {
                dropped += 1;
            }
        }
        assert!(dropped > 0);
        assert!(z.queued() <= 3);
    }

    #[test]
    fn ping_gets_pong() {
        let mut peer = valid_peer();
        let mut ping = vec![4];
        ping.extend_from_slice(b"PING");
        peer.extend_from_slice(&codec::frame(codec::FLAG_COMMAND, &ping));
        let (mut z, h) = setup(peer, 10);
        drive_until_open(&mut z);
        for _ in 0..5 {
            z.poll();
        }
        let w = h.written.lock().unwrap();
        assert!(
            w.windows(4).any(|x| x == b"PONG"),
            "written={:?}",
            String::from_utf8_lossy(&w)
        );
    }

    #[test]
    fn reconnect_after_eof() {
        let global: Handles = Default::default();
        // First connection: complete handshake then EOF on demand.
        *global.peer.lock().unwrap() = valid_peer();
        let mut z = ZmtpPush::new(Box::new(MockConnector { h: global.clone() }), 10);
        drive_until_open(&mut z);
        global.eof.store(true, Ordering::Relaxed);
        for _ in 0..3 {
            z.poll();
        }
        assert!(!z.is_connected());
        // Restore a valid peer for the next connection.
        global.eof.store(false, Ordering::Relaxed);
        *global.peer.lock().unwrap() = valid_peer();
        std::thread::sleep(Duration::from_millis(150));
        drive_until_open(&mut z);
        assert!(global.connects.load(Ordering::Relaxed) >= 2);
    }

    /// Parse what the client actually put on the wire: greeting, then frames.
    /// Any byte-level misalignment (a half-written greeting, a business frame
    /// interleaved into the READY tail) makes this fail.
    fn assert_wire_stream_is_well_formed(w: &[u8], expect_messages: &[&[u8]]) {
        assert!(
            w.len() >= codec::GREETING_LEN,
            "wire shorter than a greeting: {} bytes",
            w.len()
        );
        assert_eq!(
            &w[..codec::GREETING_LEN],
            &codec::greeting()[..],
            "the first 64 bytes on the wire must be exactly our greeting"
        );
        let mut off = codec::GREETING_LEN;
        let mut msgs = Vec::new();
        while off < w.len() {
            match codec::parse_frame(&w[off..]) {
                Ok(Some((frame, n))) => {
                    if !frame.is_command() {
                        msgs.push(frame.body.to_vec());
                    }
                    off += n;
                }
                Ok(None) => panic!("truncated frame at offset {off}: wire misaligned"),
                Err(e) => panic!("unparsable frame at offset {off}: {e:?} (wire misaligned)"),
            }
        }
        let got: Vec<Vec<u8>> = msgs.iter().map(|m| m.to_vec()).collect();
        let want: Vec<Vec<u8>> = expect_messages.iter().map(|m| m.to_vec()).collect();
        assert_eq!(got, want, "business frames on the wire");
    }

    /// A short write during the greeting must never be overwritten: the peer
    /// must see our 64 greeting bytes intact, then READY, then the message
    /// (AUDIT4 P2-2 / P5-10).
    #[test]
    fn short_write_during_greeting_keeps_the_wire_in_order() {
        let (mut z, h) = setup(valid_peer(), 10);
        // The peer's greeting+READY are already queued, but only 10 bytes of
        // our own greeting fit into the socket buffer.
        h.write_budget.store(10, Ordering::Relaxed);
        z.poll();
        assert!(z.is_connected(), "the peer spoke, so the handshake is done");

        topup(&h, 4096);
        z.send(b"hi");
        for _ in 0..10 {
            z.poll();
        }

        let w = h.written.lock().unwrap();
        assert_wire_stream_is_well_formed(&w, &[b"hi"]);
    }

    /// libzmq's PULL sends its READY without waiting for ours, so the client can
    /// reach `Open` while its own READY is still half-written. Business frames
    /// must wait for that tail (AUDIT4 P2-2 / P5-10).
    #[test]
    fn short_write_during_ready_does_not_interleave_messages() {
        // Peer greets first, and only later sends its READY.
        let (mut z, h) = setup(codec::greeting().to_vec(), 10);
        h.write_budget.store(64, Ordering::Relaxed);
        z.poll();
        assert!(
            !z.is_connected(),
            "we have sent the greeting, nothing more fits"
        );

        // Our READY frame now sits in the FIFO; the window is closed again.
        h.write_budget.store(0, Ordering::Relaxed);
        h.peer
            .lock()
            .unwrap()
            .extend_from_slice(&codec::ready_command("PULL"));
        z.poll();
        assert!(
            z.is_connected(),
            "the peer's READY opens the session even though ours is unwritten"
        );
        // The invariant itself: our READY tail has not reached the transport, so
        // no business frame may be written yet.
        assert!(
            !z.can_write_messages(),
            "handshake bytes are still owed to the transport"
        );

        z.send(b"early");
        z.send(b"frames");
        topup(&h, 4096);
        for _ in 0..10 {
            z.poll();
        }

        let w = h.written.lock().unwrap();
        assert_wire_stream_is_well_formed(&w, &[b"early", b"frames"]);
    }

    #[test]
    fn silent_peer_handshake_times_out_and_reconnects() {
        // A TCP peer that accepts but never greets must not wedge the client in
        // the handshake phase forever.
        let h = Handles {
            peer: Arc::new(Mutex::new(Vec::new())), // accepts the TCP socket, never greets
            ..Default::default()
        };
        let mut z = ZmtpPush::new(Box::new(MockConnector { h: h.clone() }), 10)
            .with_handshake_timeout(Duration::from_millis(50));
        z.poll();
        assert_eq!(h.connects.load(Ordering::Relaxed), 1);
        assert!(!z.is_connected());
        // Past the handshake deadline the state machine must give up on this
        // peer and reconnect, instead of sitting in Greeting forever.
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(20));
            z.poll();
            if h.connects.load(Ordering::Relaxed) >= 2 {
                break;
            }
        }
        assert!(
            h.connects.load(Ordering::Relaxed) >= 2,
            "a silent peer must trigger a reconnect (handshake deadline)"
        );
        assert!(z.handshakes_given_up() >= 1);
    }

    /// P5-11: the queue must be bounded in *bytes*, not only in message count.
    #[test]
    fn queue_is_bounded_in_bytes() {
        let (mut z, h) = setup(valid_peer(), 1000);
        z = z.with_queue_limits(1000, 4 * 1024 * 1024);
        drive_until_open(&mut z);
        // Nothing can drain: writes fail, so everything stays queued.
        h.fail_write.store(true, Ordering::Relaxed);

        let big = vec![0u8; 1024 * 1024];
        let mut queued = 0;
        for _ in 0..20 {
            if z.send(&big) == SendOutcome::Queued {
                queued += 1;
            }
        }
        assert!(queued > 0, "the first messages must be accepted");
        assert!(
            queued < 20,
            "the byte budget must start rejecting once it is reached (queued {queued})"
        );
        assert!(
            z.queued_bytes() <= 4 * 1024 * 1024,
            "queued bytes {} exceeded the 4 MiB budget",
            z.queued_bytes()
        );
        assert!(
            z.queued() < z.hwm(),
            "the byte budget must bind before the hwm"
        );
    }

    #[test]
    fn queued_bytes_tracks_the_queue() {
        let (mut z, h) = setup(valid_peer(), 10);
        // Queue three messages without letting anything drain.
        h.fail_write.store(true, Ordering::Relaxed);
        assert_eq!(z.queued_bytes(), 0);
        z.send(b"one");
        z.send(b"two");
        z.send(b"three");
        // frames of (2 header + body) bytes: 5 + 5 + 7.
        assert_eq!(z.queued_bytes(), 17, "queued bytes must include framing");

        // Let the writes succeed again and hand the peer a fresh handshake for
        // the connection it has to re-establish.
        h.fail_write.store(false, Ordering::Relaxed);
        *h.peer.lock().unwrap() = valid_peer();
        // Reconnection is backed off, so drive it on a deadline rather than a
        // fixed poll count.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !z.is_connected() && Instant::now() < deadline {
            z.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(z.is_connected(), "the client must reconnect and drain");
        assert_eq!(
            z.queued_bytes(),
            0,
            "a drained queue must report zero bytes"
        );
        assert_eq!(z.queued(), 0);
    }

    /// A zero linger must be a no-op, not a blocking drain (the fuzz target
    /// relies on this; a hang here would hang every CI run).
    #[test]
    fn zero_linger_does_not_touch_the_socket() {
        let (mut z, h) = setup(valid_peer(), 10);
        drive_until_open(&mut z);
        h.fail_write.store(true, Ordering::Relaxed);
        assert_eq!(z.send(b"stuck"), SendOutcome::Queued);
        assert!(z.queued() > 0);

        h.written.lock().unwrap().clear();
        z.drain_for(Duration::from_millis(0));
        assert!(
            h.written.lock().unwrap().is_empty(),
            "linger 0 must not write"
        );
    }

    #[test]
    fn queued_messages_survive_disconnect() {
        let (mut z, h) = setup(valid_peer(), 100);
        drive_until_open(&mut z);
        h.fail_write.store(true, Ordering::Relaxed);
        z.send(b"a");
        z.send(b"b");
        assert!(z.queued() >= 1);
        // After the connection is torn down the queue is retained for retry.
        z.poll();
        assert!(z.queued() >= 1);
    }
}

#[cfg(test)]
mod robustness_tests {
    //! P5-10: handshake deadline, TCP timeouts, DNS re-resolution.

    use super::*;
    use crate::zmtp::client::connect_stream;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// A resolver whose answers can be swapped while the client runs, standing
    /// in for a collector whose address record changes under DNS.
    #[derive(Clone)]
    struct ScriptedResolver {
        answers: Arc<Mutex<Vec<Vec<SocketAddr>>>>,
        calls: Arc<AtomicU32>,
    }

    impl ScriptedResolver {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            ScriptedResolver {
                answers: Arc::new(Mutex::new(answers)),
                calls: Arc::new(AtomicU32::new(0)),
            }
        }
        fn calls(&self) -> u32 {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&mut self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed) as usize;
            let answers = self.answers.lock().unwrap().clone();
            assert!(!answers.is_empty(), "script needs at least one answer");
            // Sticky: answer #0 for the first lookup, answer #1 from then on, so
            // the test does not depend on how often the client happens to retry.
            Ok(answers[n.min(answers.len() - 1)].clone())
        }
    }

    fn getsockopt_int(fd: i32, level: i32, opt: i32) -> io::Result<i32> {
        let mut val: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: standard getsockopt int query on a live socket fd.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                opt,
                std::ptr::addr_of_mut!(val).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(val)
    }

    fn wait_connected(z: &mut ZmtpPush, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            z.poll();
            if z.is_connected() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_transport_enables_keepalive_and_user_timeout() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = connect_stream(addr).expect("connect");
        let fd = stream.as_raw_fd();

        let keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap();
        let idle = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE).unwrap();
        let intvl = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL).unwrap();
        let cnt = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT).unwrap();
        let user_timeout = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT).unwrap();

        assert_eq!(
            keepalive, 1,
            "SO_KEEPALIVE must be on: a silently dead collector is otherwise \
             never noticed"
        );
        assert!(idle >= 1, "TCP_KEEPIDLE={idle}");
        assert!(intvl >= 1, "TCP_KEEPINTVL={intvl}");
        assert!(cnt >= 1, "TCP_KEEPCNT={cnt}");
        assert!(
            user_timeout > 0,
            "TCP_USER_TIMEOUT must be set so unacked data fails the connection"
        );
    }

    /// Complete one server-side NULL handshake and then **hold the socket open**
    /// until the caller joins (returning it). A server that finished reading and
    /// dropped the socket would tear the connection down right as the client
    /// reaches `Open`, which is a test artefact, not the behaviour under test.
    fn serve_one_handshake(listener: TcpListener) -> std::thread::JoinHandle<Option<TcpStream>> {
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().ok()?;
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.write_all(&codec::greeting());
            let _ = s.write_all(&codec::ready_command("PULL"));
            let mut g = [0u8; codec::GREETING_LEN];
            let _ = s.read_exact(&mut g);
            let mut hdr = [0u8; 2];
            let _ = s.read_exact(&mut hdr);
            let _ = s.read_exact(&mut vec![0u8; hdr[1] as usize]);
            Some(s)
        })
    }

    #[test]
    fn connector_covers_every_resolved_address() {
        // One hostname, two address records: the first is dead, the second is
        // the real collector. Pinning to the first answer (what the original
        // implementation did) means we never reach the live one.
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let good = listener.local_addr().unwrap();
        // A listener that accepts but never speaks ZMTP: deterministic version of
        // "collector process hung". It is held for the whole test, otherwise the
        // port could be recycled by another test and start answering.
        let dead_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let dead = dead_listener.local_addr().unwrap();
        let r = ScriptedResolver::new(vec![vec![dead, good]]);
        let mut z = ZmtpPush::new(
            tcp_connector_with_resolver("collector.example", good.port(), Box::new(r)),
            10,
        )
        // The hung peer only clears after the handshake deadline, which is what
        // rotates us onto the live address.
        .with_handshake_timeout(Duration::from_millis(200));
        let server = serve_one_handshake(listener);
        assert!(
            wait_connected(&mut z, Duration::from_secs(5)),
            "the client must rotate over the resolved addresses until one works"
        );
        let _peer = server.join().unwrap();
        drop(dead_listener);
    }

    #[test]
    fn connector_picks_up_a_dns_change_on_reconnect() {
        // The old collector is a hung (silent) peer that is kept alive so its port
        // cannot be recycled by a concurrent test.
        let old_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let old = old_listener.local_addr().unwrap();
        let new_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let new = new_listener.local_addr().unwrap();

        let r = ScriptedResolver::new(vec![vec![old], vec![new]]);
        let mut connector =
            tcp_connector_with_resolver("collector.example", new.port(), Box::new(r.clone()));
        // First connect resolves and uses the (now hung) old address.
        let _ = connector.start();
        assert_eq!(r.calls(), 1, "the connector must resolve on first use");

        let server = serve_one_handshake(new_listener);
        // Re-resolution is rate limited to keep a reconnect storm off DNS, so
        // wait past the cache interval.
        std::thread::sleep(RESOLVE_TTL + Duration::from_millis(200));
        let mut z = ZmtpPush::new(connector, 10).with_handshake_timeout(Duration::from_millis(500));
        assert!(
            wait_connected(&mut z, Duration::from_secs(5)),
            "after the address record changed the client must reconnect to the \
             new address (resolver calls: {})",
            r.calls()
        );
        assert!(
            r.calls() >= 2,
            "a reconnect must re-resolve the collector host"
        );
        let _peer = server.join().unwrap();
        drop(old_listener);
    }

    #[test]
    fn system_resolver_returns_every_address_for_localhost() {
        let addrs = SystemResolver
            .resolve("localhost", 5555)
            .expect("resolve localhost");
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 5555));
    }
}
