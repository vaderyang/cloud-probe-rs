//! Minimal ZMTP 3.x `PUSH` client over TCP (pure Rust, no libzmq).
//!
//! A non-blocking state machine: it connects (non-blocking), exchanges the
//! greeting and `READY`, then writes framed messages. Messages are queued up to
//! a high-water mark (`hwm`) and dropped when the queue is full — matching
//! libzmq's `zmq_send(..., ZMQ_DONTWAIT)` behaviour. On any I/O or protocol
//! error the connection is torn down and reconnected with backoff.
//!
//! The transport and connector are traits so the state machine can be driven by
//! a scripted mock in tests and fuzz targets (malformed peer bytes, truncation,
//! disconnects, wrong socket types, …).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use socket2::{Domain, Protocol, Socket, Type};

use super::codec;

const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

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
    out: Vec<u8>,
    out_off: usize,
    inbuf: Vec<u8>,
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
                    self.out = codec::ready_command("PUSH");
                    self.out_off = 0;
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
                                    self.out.extend_from_slice(&codec::pong_command(&data));
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

/// A non-blocking ZMTP `PUSH` client.
pub struct ZmtpPush {
    connector: Box<dyn Connector>,
    hwm: usize,
    conn: Option<Conn>,
    pending: VecDeque<Vec<u8>>,
    front_off: usize,
    next_attempt: Instant,
    backoff: Duration,
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
        }
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

    /// Enqueue a message, progressing the connection. Never blocks.
    pub fn send(&mut self, msg: &[u8]) -> SendOutcome {
        self.poll();
        if self.pending.len() >= self.hwm {
            return SendOutcome::Dropped;
        }
        self.pending.push_back(codec::frame(0, msg));
        self.poll();
        SendOutcome::Queued
    }

    /// Progress connection/reconnect and flush queued messages. Never blocks.
    pub fn poll(&mut self) {
        self.maybe_connect();
        if self.conn.is_some() {
            self.drive();
        }
        self.flush_pending();
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
        match self.connector.start() {
            Ok(t) => {
                let mut t = t;
                let connecting = t.check_connected().map(|c| !c).unwrap_or(false);
                self.conn = Some(Conn {
                    t,
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
                });
            }
            Err(_) => self.schedule_reconnect(),
        }
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
                    conn.out = codec::greeting().to_vec();
                    conn.out_off = 0;
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
        if !self.is_connected() {
            return;
        }
        while let Some(msg) = self.pending.pop_front() {
            let mut off = self.front_off;
            self.front_off = 0;
            let mut disconnected = false;
            while off < msg.len() {
                let conn = self.conn.as_mut().unwrap();
                match conn.t.write(&msg[off..]) {
                    Ok(0) => {
                        disconnected = true;
                        break;
                    }
                    Ok(n) => off += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.front_off = off;
                        self.pending.push_front(msg);
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
                    self.pending.push_front(msg);
                }
                if let Some(mut conn) = self.conn.take() {
                    conn.t.shutdown();
                }
                self.schedule_reconnect();
                return;
            }
        }
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

struct TcpConnector {
    addr: SocketAddr,
}

impl Connector for TcpConnector {
    fn start(&mut self) -> io::Result<Box<dyn Transport>> {
        let socket = Socket::new(
            Domain::for_address(self.addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        let connecting = match socket.connect(&self.addr.into()) {
            Ok(()) => false,
            Err(e)
                if e.raw_os_error() == Some(libc::EINPROGRESS)
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {
                true
            }
            Err(e) => return Err(e),
        };
        Ok(Box::new(TcpTransport {
            stream: socket.into(),
            connecting,
        }))
    }
}

/// Build a TCP connector for `host:port`, resolving the address now.
///
/// # Errors
/// Returns an error if the host cannot be resolved.
pub fn tcp_connector(host: &str, port: u16) -> io::Result<Box<dyn Connector>> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved"))?;
    Ok(Box::new(TcpConnector { addr }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Handles {
        peer: Arc<Mutex<Vec<u8>>>,
        written: Arc<Mutex<Vec<u8>>>,
        eof: Arc<AtomicBool>,
        fail_write: Arc<AtomicBool>,
        connects: Arc<AtomicU32>,
    }

    struct MockTransport {
        h: Handles,
    }

    impl Transport for MockTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.h.fail_write.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.h.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
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
