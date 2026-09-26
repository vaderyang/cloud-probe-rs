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
pub enum RingMsg {
    Packet {
        task_index: usize,
        direction: i32,
        ts_sec: i64,
        ts_usec: i64,
        caplen: u32,
        data: Vec<u8>,
    },
    Heartbeat {
        task_index: usize,
        ts: i64,
    },
}

impl RingMsg {
    #[must_use]
    pub fn msg_len(&self) -> u64 {
        match self {
            RingMsg::Packet { caplen, .. } => {
                std::mem::size_of::<RingMsg>() as u64 + *caplen as u64
            }
            RingMsg::Heartbeat { .. } => std::mem::size_of::<RingMsg>() as u64,
        }
    }

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
    #[must_use]
    pub fn new(size: usize) -> Self {
        SpscRing {
            buf: Mutex::new(VecDeque::with_capacity(size)),
            size,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

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
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        SimpleAllocator {
            capacity: AtomicU64::new(capacity),
            used: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.capacity.load(Ordering::Relaxed)
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

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
