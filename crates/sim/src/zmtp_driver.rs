//! DST for the ZMTP 3.x PUSH client state machine
//! (`cpworker::zmtp::client::ZmtpPush`).
//!
//! Drives the real client against a deterministic scripted peer whose byte
//! stream, write failures, write budget (short writes / `EAGAIN`) and EOF all
//! derive from the seed. Invariants: no panic, the outgoing queue never
//! exceeds the high-water mark, and whatever reaches the wire is always a
//! well-formed ZMTP stream — 64-byte greeting first, then whole frames.

use std::io;
use std::sync::{Arc, Mutex};

use cpworker::zmtp::{codec, Connector, Transport, ZmtpPush};

use crate::Rng;

/// The deterministic fault/behaviour schedule for one run.
#[derive(Clone)]
struct Script {
    /// Writes fail with `BrokenPipe`.
    fail_write: bool,
    /// Peer closed the connection (`read` returns 0).
    eof: bool,
    /// Bytes the peer still accepts before `WouldBlock`.
    budget: usize,
    hwm: usize,
    n_msgs: usize,
}

struct ScriptedTransport {
    script: Script,
    peer: Vec<u8>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Transport for ScriptedTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.script.fail_write {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if self.script.budget == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = self.script.budget.min(buf.len());
        self.written
            .lock()
            .expect("written")
            .extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.script.eof {
            return Ok(0);
        }
        if self.peer.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = self.peer.len().min(buf.len());
        buf[..n].copy_from_slice(&self.peer[..n]);
        self.peer.drain(..n);
        Ok(n)
    }

    fn shutdown(&mut self) {}
}

/// Scripted connector: hands out a fresh transport per connection, all driven
/// by the same schedule; the last connection's wire bytes stay observable.
struct ScriptedConnector {
    script: Script,
    peer: Vec<u8>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Connector for ScriptedConnector {
    fn start(&mut self) -> io::Result<Box<dyn Transport>> {
        // Each connection is a single stream: start with an empty wire.
        self.written.lock().expect("written").clear();
        Ok(Box::new(ScriptedTransport {
            script: self.script.clone(),
            peer: self.peer.clone(),
            written: Arc::clone(&self.written),
        }))
    }
}

/// Build the schedule for `seed` and drive the client. Returns the FNV trace
/// of the send/poll schedule (for determinism assertions).
///
/// # Panics
/// Panics if an invariant is violated: the queue exceeds the high-water mark,
/// or the wire is not a well-formed ZMTP stream.
pub fn run(seed: u64) -> crate::Trace {
    let mut rng = Rng::new(seed);
    let valid_handshake = rng.chance(0.7);
    let corrupt_greeting = !valid_handshake && rng.chance(0.5);
    let fail_write = rng.chance(0.4);
    let eof = rng.chance(0.3);
    let budget = if rng.chance(0.3) {
        usize::MAX
    } else {
        1 + rng.below(300) as usize
    };
    let hwm = 1 + rng.below(16) as usize;
    let n_msgs = 4 + rng.below(9) as usize;

    let mut peer = Vec::new();
    if valid_handshake {
        peer.extend_from_slice(&codec::greeting());
        peer.extend_from_slice(&codec::ready_command("PULL"));
    } else if corrupt_greeting {
        let mut g = codec::greeting();
        g[0] ^= 0xFF;
        peer.extend_from_slice(&g);
    }
    peer.extend_from_slice(&[0u8; 8]); // post-handshake peer bytes

    let script = Script {
        fail_write,
        eof,
        budget,
        hwm,
        n_msgs,
    };
    let written = Arc::new(Mutex::new(Vec::new()));
    let mut z = ZmtpPush::new(
        Box::new(ScriptedConnector {
            script: script.clone(),
            peer: peer.clone(),
            written: Arc::clone(&written),
        }),
        script.hwm,
    )
    .with_queue_limits(script.hwm, 1024 * 1024);

    let mut trace = crate::Trace::default();
    for i in 0..script.n_msgs {
        z.poll();
        let msg = [i as u8; 64];
        let outcome = z.send(&msg);
        trace.record_u64(2, u64::from(outcome == cpworker::zmtp::SendOutcome::Queued));
        assert!(
            z.queued() <= hwm,
            "seed {seed}: queue {} exceeded hwm {hwm}",
            z.queued()
        );
    }
    // A large message must not grow the queue beyond the HWM either.
    let _ = z.send(&[0u8; 100_000]);
    assert!(
        z.queued() <= hwm,
        "seed {seed}: queue {} exceeded hwm {hwm} after a large message",
        z.queued()
    );
    z.poll();

    // Wire invariant: whatever reached the peer is a well-formed ZMTP stream —
    // 64-byte greeting first, then whole frames. A connection torn out while
    // the greeting is half-written legitimately leaves fewer than 64 bytes;
    // anything from a full greeting upwards must parse.
    let w = written.lock().expect("written");
    if w.len() >= codec::GREETING_LEN {
        assert_eq!(
            &w[..codec::GREETING_LEN],
            &codec::greeting()[..],
            "seed {seed}: the first bytes on the wire must be the complete greeting"
        );
        let mut off = codec::GREETING_LEN;
        while off < w.len() {
            match codec::parse_frame(&w[off..]) {
                Ok(Some((_, n))) => off += n,
                Ok(None) => break, // trailing partial frame is allowed
                Err(e) => panic!("seed {seed}: unparsable frame at {off}: {e:?} (misaligned wire)"),
            }
        }
    }
    trace
}
