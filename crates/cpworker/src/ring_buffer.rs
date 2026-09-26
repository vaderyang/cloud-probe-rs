//! Pipeline ring buffer and byte allocator. Port of `ring_buffer.c`.
//!
//! The original used a lock-free SPSC ring / circular mempool. This port keeps
//! the same public behaviour (bounded SPSC queue + byte accounting) but uses
//! safe synchronisation primitives; the hot-path performance can be revisited
//! with a lock-free implementation if needed.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A message travelling through the pipeline ring.
pub enum RingMsg {
    /// A captured packet.
    Packet {
        /// Owning task index.
        task_index: usize,
        /// Packet direction (`PKT_DIR_*`).
        direction: i32,
        /// Capture timestamp, seconds.
        ts_sec: i64,
        /// Capture timestamp, microseconds.
        ts_usec: i64,
        /// Captured length in bytes.
        caplen: u32,
        /// Captured packet bytes.
        data: Vec<u8>,
    },
    /// A heartbeat tick for a task.
    Heartbeat {
        /// Owning task index.
        task_index: usize,
        /// Timestamp, seconds.
        ts: i64,
    },
}

impl RingMsg {
    /// Approximate memory footprint of this message in bytes.
    #[must_use]
    pub fn msg_len(&self) -> u64 {
        match self {
            RingMsg::Packet { caplen, .. } => {
                std::mem::size_of::<RingMsg>() as u64 + *caplen as u64
            }
            RingMsg::Heartbeat { .. } => std::mem::size_of::<RingMsg>() as u64,
        }
    }

    /// Index of the task that produced this message.
    #[must_use]
    pub fn task_index(&self) -> usize {
        match self {
            RingMsg::Packet { task_index, .. } => *task_index,
            RingMsg::Heartbeat { task_index, .. } => *task_index,
        }
    }
}

/// Bounded single-producer/single-consumer queue of `RingMsg`.
pub struct SpscRing {
    buf: Mutex<VecDeque<Box<RingMsg>>>,
    size: usize,
}

impl SpscRing {
    /// Create a ring holding at most `size` messages.
    #[must_use]
    pub fn new(size: usize) -> Self {
        SpscRing {
            buf: Mutex::new(VecDeque::with_capacity(size)),
            size,
        }
    }

    /// Configured ring capacity in messages.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Number of messages currently queued.
    pub fn used(&self) -> usize {
        self.buf.lock().len()
    }

    /// Returns `Err(msg)` (handing the message back) when full, mirroring
    /// the `spsc_ring_push` retry loop.
    ///
    /// # Errors
    /// Returns `Err(msg)` with the original message if the ring is full.
    pub fn push(&self, msg: Box<RingMsg>) -> std::result::Result<(), Box<RingMsg>> {
        let mut buf = self.buf.lock();
        // Reserve one slot so full is distinguishable from empty, as in C.
        if buf.len() + 1 >= self.size {
            return Err(msg);
        }
        buf.push_back(msg);
        Ok(())
    }

    /// Returns `false` when empty.
    /// Pop the oldest message, or `None` when empty.
    pub fn pop(&self) -> Option<Box<RingMsg>> {
        self.buf.lock().pop_front()
    }
}

/// Tracks an upper bound on bytes in flight across the pipeline.
#[derive(Debug)]
pub struct SimpleAllocator {
    capacity: AtomicU64,
    used: AtomicU64,
}

impl SimpleAllocator {
    /// Create an allocator with a `capacity`-byte budget.
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        SimpleAllocator {
            capacity: AtomicU64::new(capacity),
            used: AtomicU64::new(0),
        }
    }

    /// Current byte budget.
    pub fn capacity(&self) -> u64 {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Bytes currently reserved.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Change the byte budget.
    pub fn resize(&self, new_capacity: u64) {
        self.capacity.store(new_capacity, Ordering::Release);
    }

    /// Reserve `len` bytes; returns false if it would exceed capacity.
    fn reserve(&self, len: u64) -> bool {
        loop {
            let old = self.used.load(Ordering::Relaxed);
            if old + len > self.capacity.load(Ordering::Relaxed) {
                return false;
            }
            if self
                .used
                .compare_exchange_weak(old, old + len, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release(&self, len: u64) {
        let _ = self
            .used
            .fetch_update(Ordering::Release, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(len))
            });
    }

    /// Allocate a packet message, or `None` if the byte budget is exceeded.
    pub fn alloc_packet(
        &self,
        task_index: usize,
        direction: i32,
        ts_sec: i64,
        ts_usec: i64,
        pkt_data: &[u8],
    ) -> Option<Box<RingMsg>> {
        let msg = Box::new(RingMsg::Packet {
            task_index,
            direction,
            ts_sec,
            ts_usec,
            caplen: pkt_data.len() as u32,
            data: pkt_data.to_vec(),
        });
        if !self.reserve(msg.msg_len()) {
            return None;
        }
        Some(msg)
    }

    /// Allocate a heartbeat message, or `None` if the byte budget is exceeded.
    pub fn alloc_heartbeat(&self, task_index: usize) -> Option<Box<RingMsg>> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let msg = Box::new(RingMsg::Heartbeat { task_index, ts });
        if !self.reserve(msg.msg_len()) {
            return None;
        }
        Some(msg)
    }

    /// Release the bytes accounted for by `msg`.
    pub fn free(&self, msg: &RingMsg) {
        self.release(msg.msg_len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_capacity() {
        let r = SpscRing::new(2);
        assert!(r
            .push(Box::new(RingMsg::Heartbeat {
                task_index: 0,
                ts: 0
            }))
            .is_ok());
        assert!(r
            .push(Box::new(RingMsg::Heartbeat {
                task_index: 0,
                ts: 0
            }))
            .is_err());
        assert!(r.pop().is_some());
        assert!(r.pop().is_none());
    }

    #[test]
    fn allocator_bounds() {
        let a = SimpleAllocator::new(100);
        let m = a.alloc_heartbeat(0);
        assert!(m.is_some());
        let used = a.used();
        assert!(used > 0);
        a.free(m.as_ref().unwrap());
        assert_eq!(a.used(), 0);
    }
}
