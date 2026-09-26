//! Chaos fuzzing of the non-blocking ZMTP client state machine.
//!
//! Drives [`ZmtpPush`] against a scripted mock peer whose byte stream, write
//! failures, write-budget (short writes / `EAGAIN`) and EOF are all controlled by
//! the fuzz input. This exercises malformed/partial handshakes, unexpected
//! disconnects, oversized frames, socket buffers filling up mid-handshake and
//! interleaved send/poll calls. Invariants: no panic, the outgoing queue never
//! exceeds the high-water mark *or* the byte budget, nothing blocks, and the
//! bytes we put on the wire always parse as greeting + frames (the single-FIFO
//! phase invariant of AUDIT4 P2-2 / P5-10).

#![no_main]

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;

use cpworker::zmtp::{codec, Connector, Transport, ZmtpPush};

#[derive(Default)]
struct Handles {
    peer: Arc<Mutex<Vec<u8>>>,
    written: Arc<Mutex<Vec<u8>>>,
    eof: Arc<AtomicBool>,
    fail_write: Arc<AtomicBool>,
    connects: Arc<AtomicU32>,
    /// Bytes the peer still accepts before its window closes: models a full
    /// socket send buffer (short write then `WouldBlock`).
    write_budget: Arc<AtomicUsize>,
}

struct MockTransport {
    h: Arc<Handles>,
}

impl Transport for MockTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.h.fail_write.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let prev = self.h.write_budget.load(Ordering::Relaxed);
        if prev == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = prev.min(buf.len());
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
    h: Arc<Handles>,
}

impl Connector for MockConnector {
    fn start(&mut self) -> io::Result<Box<dyn Transport>> {
        self.h.connects.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(MockTransport { h: self.h.clone() }))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let hwm = (data[0] as usize % 16) + 1;
    let ctrl = data[1];
    // Byte budget: 0 = unlimited, otherwise a small, exhaustible window.
    let budget = if data[3] & 0x80 != 0 {
        usize::MAX / 8
    } else {
        (data[3] as usize) % 200 + 1
    };
    let body = &data[4..];
    let split = if body.is_empty() {
        0
    } else {
        (data[2] as usize) % body.len()
    };
    let (script, msg) = body.split_at(split);

    // Optionally prepend a valid handshake so the client reaches the open state
    // and then processes the fuzzed peer bytes.
    let mut peer = Vec::new();
    if ctrl & 1 != 0 {
        peer.extend_from_slice(&codec::greeting());
        peer.extend_from_slice(&codec::ready_command("PULL"));
    }
    peer.extend_from_slice(script);

    let h = Arc::new(Handles {
        peer: Arc::new(Mutex::new(peer)),
        fail_write: Arc::new(AtomicBool::new(ctrl & 0x04 != 0)),
        eof: Arc::new(AtomicBool::new(ctrl & 0x08 != 0)),
        write_budget: Arc::new(AtomicUsize::new(budget)),
        ..Default::default()
    });

    let max_bytes = 1024 * 1024 + (data[5] as usize) * 1024;
    let mut z = ZmtpPush::new(Box::new(MockConnector { h: h.clone() }), hwm)
        .with_queue_limits(hwm, max_bytes);

    for i in 0..8u8 {
        z.poll();
        let _ = z.send(msg);
        // Interleave state changes: sometimes start failing writes or close the
        // peer connection, to force reconnection paths.
        if i == 3 && ctrl & 0x10 != 0 {
            h.fail_write.store(true, Ordering::Relaxed);
        }
        if i == 5 && ctrl & 0x20 != 0 {
            h.eof.store(true, Ordering::Relaxed);
        }
        // Re-open the peer's window periodically so short writes alternate with
        // progress instead of wedging the run.
        if i % 3 == 2 {
            h.write_budget.fetch_add(budget, Ordering::Relaxed);
        }
        assert!(z.queued() <= hwm, "queue {} exceeded hwm {}", z.queued(), hwm);
        assert!(
            z.queued_bytes() <= max_bytes,
            "queue bytes {} exceeded budget {}",
            z.queued_bytes(),
            max_bytes
        );
    }

    // A large message must not grow the queue beyond the HWM either.
    let _ = z.send(&[0u8; 100_000]);
    assert!(z.queued() <= hwm);

    // Linger with zero timeout must return immediately (no blocking/hang).
    z.drain_for(Duration::from_millis(0));
    assert!(h.connects.load(Ordering::Relaxed) >= 1);

    // Wire-level invariant: whatever reached the peer must be a well-formed
    // ZMTP stream — 64-byte greeting first, then whole frames. A half-written
    // greeting overwritten by READY, or a business frame interleaved into the
    // READY tail, breaks this.
    let w = h.written.lock().unwrap();
    if !w.is_empty() {
        assert!(
            w.len() >= codec::GREETING_LEN,
            "wire shorter than one greeting ({} bytes)",
            w.len()
        );
        assert_eq!(
            &w[..codec::GREETING_LEN],
            &codec::greeting()[..],
            "the first bytes on the wire must be the complete greeting"
        );
        let mut off = codec::GREETING_LEN;
        while off < w.len() {
            match codec::parse_frame(&w[off..]) {
                Ok(Some((_, n))) => off += n,
                Ok(None) => break, // trailing partial frame is allowed
                Err(e) => panic!("unparsable frame at {off}: {e:?} (misaligned wire)"),
            }
        }
    }
});
