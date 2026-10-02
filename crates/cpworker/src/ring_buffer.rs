//! Pipeline ring buffer and byte allocator. Port of `ring_buffer.c`.
//!
//! The original C used a lock-free SPSC ring / circular mempool. This module
//! keeps the same public behaviour (bounded SPSC queue + byte accounting) and
//! implements the ring lock-free with atomics and explicit `Acquire`/`Release`
//! ordering, mirroring `spsc_ring_push` / `spsc_ring_pop`.
//!
//! The ring is configured for exactly one producer thread to call [`SpscRing::push`]
//! and one consumer thread to call [`SpscRing::pop`]. Because safe code must not be
//! able to obtain two producers, the concurrent API is expressed through
//! [`SpscRing::split`], which hands out one [`RingProducer`] and one [`RingConsumer`]
//! while borrowing the ring; the plain [`SpscRing::push`] / [`SpscRing::pop`] are for
//! serial use. [`SpscRing::into_split`] supplies unique owned endpoints for the
//! pipeline's long-lived threads without changing slot storage or sizing.

use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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

/// Shared storage for the lock-free SPSC ring.
///
/// `head` is written only by the producer, `tail` only by the consumer. A slot is
/// published by the producer's `Release` store to `head` and observed by the
/// consumer's `Acquire` load; the consumer's `Release` store to `tail` is observed
/// by the producer's `Acquire` load, which is what makes overwriting a
/// already-consumed slot race-free.
struct RingCore {
    slots: Box<[UnsafeCell<MaybeUninit<Box<RingMsg>>>]>,
    size: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

// SAFETY: `RingCore` is private and is only ever reachable through two safe
// wrappers:
//
//   * `SpscRing`, which owns it by value and is explicitly `!Sync`. Its
//     `push`/`pop` therefore cannot be called concurrently.
//   * The `RingProducer`/`RingConsumer` pair returned by `SpscRing::split`. The
//     `&mut self` borrow of `split` prevents any other access to the ring while
//     the pair is alive, `split` is the only constructor and returns exactly one
//     of each, and neither handle is `Clone`.
//   * The owned pair from `SpscRing::into_split`, which consumes the ring and
//     creates exactly one non-Clone producer and consumer. Their operations
//     require `&mut self`; the cloneable observer can only read atomic counters.
//
// So the only way `&RingCore` can be shared across threads is one producer and
// one consumer, exactly the contract the atomics implement.
unsafe impl Sync for RingCore {}

impl RingCore {
    fn new(size: usize) -> Self {
        let mut slots = Vec::with_capacity(size);
        for _ in 0..size {
            slots.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        RingCore {
            slots: slots.into_boxed_slice(),
            size,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Next index, wrapping to 0 at `size`. Only called when `size > 0`.
    #[inline]
    fn advance(&self, idx: usize) -> usize {
        let next = idx + 1;
        if next == self.size {
            0
        } else {
            next
        }
    }

    fn push(&self, msg: Box<RingMsg>) -> Result<(), Box<RingMsg>> {
        if self.size == 0 {
            return Err(msg);
        }
        // `head` is only written by the producer, so a relaxed load of our own
        // cursor is enough. `tail` is published by the consumer with `Release`;
        // the `Acquire` load makes the consumer's slot read happen-before any
        // overwrite of that slot below.
        let head = self.head.load(Ordering::Relaxed);
        let next = self.advance(head);
        if next == self.tail.load(Ordering::Acquire) {
            return Err(msg); // full, one slot is reserved to tell full from empty
        }
        // SAFETY: as the sole producer, no other thread reads or writes
        // `slots[head]` until the `Release` store to `head` below publishes it.
        // The consumer reaches `head` only through that store.
        unsafe {
            (*self.slots[head].get()).write(msg);
        }
        self.head.store(next, Ordering::Release);
        Ok(())
    }

    fn pop(&self) -> Option<Box<RingMsg>> {
        if self.size == 0 {
            return None;
        }
        // `tail` is only written by the consumer (relaxed load of our own
        // cursor); `head` is published by the producer with `Release`, and the
        // `Acquire` load makes the slot write happen-before the read below.
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None; // empty
        }
        // SAFETY: as the sole consumer we own `slots[tail]`; the producer
        // published it before advancing `head`, and no other slot maps to
        // `tail` while it is in `[tail, head)`.
        let msg = unsafe { (*self.slots[tail].get()).assume_init_read() };
        self.tail.store(self.advance(tail), Ordering::Release);
        Some(msg)
    }

    /// Number of messages currently queued. Mirrors `spsc_ring_used`: head and
    /// tail are read at different instants, so the value is a snapshot.
    fn used(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if tail <= head {
            head - tail
        } else {
            self.size - tail + head
        }
    }
}

impl Drop for RingCore {
    fn drop(&mut self) {
        // `&mut self` means no producer or consumer can be running, so the live
        // slots in `[tail, head)` can be dropped directly.
        let head = *self.head.get_mut();
        let mut tail = *self.tail.get_mut();
        while tail != head {
            // SAFETY: no concurrency (`&mut self`) and `[tail, head)` holds
            // initialised values.
            unsafe {
                (*self.slots[tail].get()).assume_init_drop();
            }
            tail = if tail + 1 == self.size { 0 } else { tail + 1 };
        }
    }
}

/// Bounded single-producer/single-consumer queue of `RingMsg`.
///
/// Holds `size - 1` messages at most (one slot is reserved so full and empty are
/// distinguishable), matching `spsc_ring_create`/`spsc_ring_push`.
/// The unsplit ring cannot be shared between threads:
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<cpworker::ring_buffer::SpscRing>();
/// ```
pub struct SpscRing {
    core: RingCore,
    // RingCore is Sync for its private endpoint APIs; the unsplit public ring
    // must remain !Sync so safe callers cannot create multiple writers/readers.
    _not_sync: PhantomData<Cell<()>>,
}

impl SpscRing {
    /// Create a ring holding at most `size` messages.
    #[must_use]
    pub fn new(size: usize) -> Self {
        SpscRing {
            core: RingCore::new(size),
            _not_sync: PhantomData,
        }
    }

    /// Configured ring capacity in messages.
    pub fn size(&self) -> usize {
        self.core.size
    }

    /// Number of messages currently queued.
    pub fn used(&self) -> usize {
        self.core.used()
    }

    /// Returns `Err(msg)` (handing the message back) when full, mirroring
    /// the `spsc_ring_push` retry loop.
    ///
    /// # Errors
    /// Returns `Err(msg)` with the original message if the ring is full.
    pub fn push(&self, msg: Box<RingMsg>) -> std::result::Result<(), Box<RingMsg>> {
        self.core.push(msg)
    }

    /// Returns `false` when empty.
    /// Pop the oldest message, or `None` when empty.
    pub fn pop(&self) -> Option<Box<RingMsg>> {
        self.core.pop()
    }

    /// Split the ring into one producer and one consumer handle for lock-free
    /// concurrent use.
    ///
    /// The `&mut self` borrow keeps any other access to the ring (including
    /// [`SpscRing::push`] / [`SpscRing::pop`]) out for as long as the handles
    /// live, so at most one producer and one consumer exist at a time.
    #[must_use]
    pub fn split(&mut self) -> (RingProducer<'_>, RingConsumer<'_>) {
        (
            RingProducer { core: &self.core },
            RingConsumer { core: &self.core },
        )
    }

    /// Consume the ring into uniquely owned endpoints suitable for long-lived
    /// threads, plus a read-only stats observer. Queued messages are preserved.
    #[must_use]
    pub fn into_split(self) -> (OwnedRingProducer, OwnedRingConsumer, RingObserver) {
        let core = Arc::new(self.core);
        (
            OwnedRingProducer { core: core.clone() },
            OwnedRingConsumer { core: core.clone() },
            RingObserver { core },
        )
    }
}

/// Unique producer of an owned SPSC ring; deliberately not Clone.
///
/// ```compile_fail
/// let (producer, _, _) = cpworker::ring_buffer::SpscRing::new(8).into_split();
/// let second_producer = producer.clone();
/// ```
pub struct OwnedRingProducer {
    core: Arc<RingCore>,
}

impl OwnedRingProducer {
    /// Push one message, returning it unchanged when the ring is full.
    ///
    /// # Errors
    /// Returns the original message if the ring is full.
    pub fn push(&mut self, msg: Box<RingMsg>) -> Result<(), Box<RingMsg>> {
        self.core.push(msg)
    }
}

/// Unique consumer of an owned SPSC ring; deliberately not Clone.
pub struct OwnedRingConsumer {
    core: Arc<RingCore>,
}

impl OwnedRingConsumer {
    /// Pop the oldest message, or None when the ring is empty.
    pub fn pop(&mut self) -> Option<Box<RingMsg>> {
        self.core.pop()
    }
}

/// Read-only atomic size/occupancy snapshots; cannot push or pop messages.
#[derive(Clone)]
pub struct RingObserver {
    core: Arc<RingCore>,
}

impl RingObserver {
    /// Configured ring capacity, including the reserved slot.
    #[must_use]
    pub fn size(&self) -> usize {
        self.core.size
    }

    /// Current occupancy snapshot, matching spsc_ring_used in the C oracle.
    #[must_use]
    pub fn used(&self) -> usize {
        self.core.used()
    }
}

/// Producer half of a split [`SpscRing`].
pub struct RingProducer<'a> {
    core: &'a RingCore,
}

impl RingProducer<'_> {
    /// Push a message, handing it back when the ring is full.
    ///
    /// # Errors
    /// Returns `Err(msg)` with the original message if the ring is full.
    pub fn push(&mut self, msg: Box<RingMsg>) -> std::result::Result<(), Box<RingMsg>> {
        self.core.push(msg)
    }

    /// Configured ring capacity in messages.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.core.size
    }

    /// Number of messages currently queued.
    #[must_use]
    pub fn used(&self) -> usize {
        self.core.used()
    }
}

/// Consumer half of a split [`SpscRing`].
pub struct RingConsumer<'a> {
    core: &'a RingCore,
}

impl RingConsumer<'_> {
    /// Pop the oldest message, or `None` when empty.
    pub fn pop(&mut self) -> Option<Box<RingMsg>> {
        self.core.pop()
    }

    /// Configured ring capacity in messages.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.core.size
    }

    /// Number of messages currently queued.
    #[must_use]
    pub fn used(&self) -> usize {
        self.core.used()
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
        // A CAS loop rather than `AtomicU64::fetch_update`: nightly renamed that
        // method (`try_update`), and the new name is not in our MSRV (1.88) yet,
        // so depending on either spelling means a fuzz/nightly build warning.
        // Saturating is the behaviour we want and the same loop `reserve` uses:
        // releasing more than was reserved is a bookkeeping bug, and it must not
        // wrap `used` into a huge number that then blocks every allocation.
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            match self.used.compare_exchange_weak(
                cur,
                cur.saturating_sub(len),
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(fresh) => cur = fresh,
            }
        }
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
    use std::collections::VecDeque;

    #[test]
    fn owned_spsc_endpoints_preserve_full_ring_and_fifo_across_threads() {
        let ring = SpscRing::new(17);
        for ts in 0..16 {
            ring.push(Box::new(RingMsg::Heartbeat { task_index: 3, ts }))
                .unwrap();
        }
        let (mut producer, mut consumer, observer) = ring.into_split();
        assert_eq!(observer.size(), 17);
        assert_eq!(observer.used(), 16);
        let returned = producer
            .push(Box::new(RingMsg::Heartbeat {
                task_index: 3,
                ts: 16,
            }))
            .unwrap_err();
        assert_eq!(
            *returned,
            RingMsg::Heartbeat {
                task_index: 3,
                ts: 16
            }
        );
        let writer = std::thread::spawn(move || {
            let mut msg = returned;
            for ts in 16..100_000 {
                loop {
                    match producer.push(msg) {
                        Ok(()) => break,
                        Err(m) => {
                            msg = m;
                            std::thread::yield_now();
                        }
                    }
                }
                msg = Box::new(RingMsg::Heartbeat {
                    task_index: 3,
                    ts: ts + 1,
                });
            }
        });
        for ts in 0..100_000 {
            let msg = loop {
                if let Some(msg) = consumer.pop() {
                    break msg;
                }
                std::thread::yield_now();
            };
            assert_eq!(*msg, RingMsg::Heartbeat { task_index: 3, ts });
        }
        writer.join().unwrap();
        assert!(consumer.pop().is_none());
        assert_eq!(observer.used(), 0);
    }

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

    /// `release` is saturating on purpose.
    ///
    /// A double free (or any bookkeeping bug that releases bytes that were never
    /// reserved) must not wrap `used` around to ~u64::MAX - that would make every
    /// later `reserve` fail and silently starve the pipeline. This pins the
    /// behaviour of the CAS-loop rewrite of `release` (AUDIT4 P5-27: nightly
    /// deprecated `AtomicU64::fetch_update`, and its replacement is newer than our
    /// MSRV, so the rewrite must not depend on either spelling).
    #[test]
    fn releasing_more_than_was_reserved_saturates_at_zero() {
        let a = SimpleAllocator::new(1000);
        let m = a
            .alloc_heartbeat(0)
            .expect("a heartbeat fits in 1000 bytes");
        assert!(a.used() > 0);
        a.free(&m);
        assert_eq!(a.used(), 0);
        for _ in 0..8 {
            a.free(&m);
            assert_eq!(a.used(), 0, "release wrapped instead of saturating");
        }
        // The budget is still usable afterwards.
        assert!(a.alloc_heartbeat(1).is_some());
    }

    /// Bounded model test: for a small ring, exhaustively interleave a fixed
    /// number of pushes and pops and compare every step against a `VecDeque`
    /// reference, including the one-slot reserve and the `full`/`empty` answers.
    ///
    /// This is deterministic (no threads), so it checks the *semantics* the
    /// lock-free implementation must preserve, independent of timing.
    #[test]
    fn bounded_interleavings_match_reference_model() {
        const OPS: usize = 4; // 4 pushes and 4 pops
        for cap in 1..=4usize {
            for mask in 0u32..(1u32 << (2 * OPS)) {
                if mask.count_ones() as usize != OPS {
                    continue;
                }
                let ring = SpscRing::new(cap);
                let mut reference: VecDeque<u64> = VecDeque::new();
                let mut next_push = 0u64;
                for step in 0..(2 * OPS) {
                    if (mask >> step) & 1 == 1 {
                        // Producer step.
                        let msg = Box::new(RingMsg::Heartbeat {
                            task_index: next_push as usize,
                            ts: next_push as i64,
                        });
                        let expect_full = reference.len() + 1 >= cap;
                        match ring.push(msg) {
                            Ok(()) => {
                                assert!(
                                    !expect_full,
                                    "cap={cap} mask={mask:08b} step={step}: accepted while full"
                                );
                                reference.push_back(next_push);
                            }
                            Err(_) => assert!(
                                expect_full,
                                "cap={cap} mask={mask:08b} step={step}: rejected while not full"
                            ),
                        }
                        next_push += 1;
                    } else {
                        // Consumer step.
                        let expected = reference.pop_front();
                        let got = ring.pop().map(|m| match *m {
                            RingMsg::Heartbeat { ts, .. } => ts as u64,
                            RingMsg::Packet { .. } => {
                                unreachable!("interleaving test only pushes heartbeats")
                            }
                        });
                        assert_eq!(got, expected, "cap={cap} mask={mask:08b} step={step}");
                    }
                    assert_eq!(
                        ring.used(),
                        reference.len(),
                        "cap={cap} mask={mask:08b} step={step}"
                    );
                }
            }
        }
    }

    /// True-concurrency stress: one producer and one consumer thread push/pop
    /// millions of sequence-tagged messages through a small ring. The consumer
    /// asserts strictly increasing, gap-free sequence numbers, which fails on
    /// any drop, duplicate or reordering.
    ///
    /// The handles come from `split`, so this exercises the lock-free paths
    /// without any external lock.
    #[test]
    fn spsc_stress_producer_consumer_fifo() {
        // Miri interprets the code (and explores many schedules via
        // `-Zmiri-many-seeds`), so it gets a smaller but still concurrent load.
        const ITEMS: u64 = if cfg!(miri) { 300 } else { 2_000_000 };
        const CAP: usize = 1024;

        let mut ring = SpscRing::new(CAP);
        let (mut producer, mut consumer) = ring.split();

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut next: u64 = 0;
                while next < ITEMS {
                    let mut pending = Box::new(RingMsg::Heartbeat {
                        task_index: next as usize,
                        ts: next as i64,
                    });
                    loop {
                        match producer.push(pending) {
                            Ok(()) => {
                                next += 1;
                                break;
                            }
                            Err(returned) => {
                                pending = returned;
                                std::thread::yield_now();
                            }
                        }
                    }
                }
            });
            scope.spawn(move || {
                let mut expected: u64 = 0;
                while expected < ITEMS {
                    match consumer.pop() {
                        Some(msg) => {
                            match *msg {
                                RingMsg::Heartbeat { task_index, ts } => {
                                    assert_eq!(task_index as u64, expected, "reordered or dropped");
                                    assert_eq!(ts as u64, expected, "reordered or dropped");
                                }
                                RingMsg::Packet { .. } => panic!("consumer saw a packet"),
                            }
                            expected += 1;
                        }
                        None => std::thread::yield_now(),
                    }
                }
            });
        });

        assert_eq!(
            ring.used(),
            0,
            "ring must be empty after the consumer drains it"
        );
        assert_eq!(ring.size(), CAP);
    }
}
