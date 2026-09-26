//! Statistics counters. Port of `stats.h`/`stats.c`.
//!
//! Counters use a "big unit + remainder" representation so individual counters
//! cannot overflow a `u64` on long-running (multi-year) captures.

use std::sync::atomic::{AtomicU64, Ordering};

/// 1 EiB = 2^60 bytes.
pub const EIB_IN_BYTES: u64 = 1024 * 1024 * 1024 * 1024 * 1024 * 1024;
/// 1 Peta = 10^16 packets.
pub const PETA_IN_PACKETS: u64 = 10_000_000_000_000_000;

#[derive(Debug, Default)]
/// Byte counter split into whole EiB plus a remainder below 1 EiB.
pub struct BytesStats {
    /// Remainder bytes (always below `EIB_IN_BYTES`).
    pub bytes: AtomicU64,
    /// Whole EiB units.
    pub eib: AtomicU64,
}

impl BytesStats {
    /// Add `bytes`, carrying into the EiB field as needed.
    pub fn add(&self, mut bytes: u64) {
        let mut new_eib = bytes / EIB_IN_BYTES;
        bytes %= EIB_IN_BYTES;

        let mut cur = self.bytes.load(Ordering::Relaxed) + bytes;
        if cur >= EIB_IN_BYTES {
            cur -= EIB_IN_BYTES;
            new_eib += 1;
        }
        self.bytes.store(cur, Ordering::Relaxed);
        self.eib.fetch_add(new_eib, Ordering::Relaxed);
    }

    /// Merge another counter into this one.
    pub fn merge(&self, src: &BytesStats) {
        let total = self.bytes.load(Ordering::Relaxed) + src.bytes.load(Ordering::Relaxed);
        let carry = total / EIB_IN_BYTES;
        self.bytes.store(total % EIB_IN_BYTES, Ordering::Relaxed);
        self.eib
            .fetch_add(src.eib.load(Ordering::Relaxed) + carry, Ordering::Relaxed);
    }

    /// Return `(remainder_bytes, eib)`.
    pub fn load(&self) -> (u64, u64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.eib.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Default)]
/// Packet counter split into whole Peta (10^16) plus a remainder.
pub struct PacketsStats {
    /// Remainder packets (always below `PETA_IN_PACKETS`).
    pub packets: AtomicU64,
    /// Whole Peta units.
    pub peta: AtomicU64,
}

impl PacketsStats {
    /// Add `packets`, carrying into the Peta field as needed.
    pub fn add(&self, mut packets: u64) {
        let mut new_peta = packets / PETA_IN_PACKETS;
        packets %= PETA_IN_PACKETS;

        let mut cur = self.packets.load(Ordering::Relaxed) + packets;
        if cur >= PETA_IN_PACKETS {
            cur -= PETA_IN_PACKETS;
            new_peta += 1;
        }
        self.packets.store(cur, Ordering::Relaxed);
        self.peta.fetch_add(new_peta, Ordering::Relaxed);
    }

    /// Merge another counter into this one.
    pub fn merge(&self, src: &PacketsStats) {
        let total = self.packets.load(Ordering::Relaxed) + src.packets.load(Ordering::Relaxed);
        let carry = total / PETA_IN_PACKETS;
        self.packets
            .store(total % PETA_IN_PACKETS, Ordering::Relaxed);
        self.peta
            .fetch_add(src.peta.load(Ordering::Relaxed) + carry, Ordering::Relaxed);
    }

    /// Return `(remainder_packets, peta)`.
    pub fn load(&self) -> (u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.peta.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Default)]
/// Capture-side counters.
pub struct CaptureStats {
    /// Bytes captured.
    pub cap_bytes: BytesStats,
    /// Packets captured.
    pub cap_packets: PacketsStats,
    /// Packets dropped by the capturer.
    pub drop_packets: PacketsStats,
    /// Packets dropped by the interface (ps_ifdrop).
    pub ifdrop_packets: PacketsStats,
}

#[derive(Debug, Default)]
/// Output-side counters.
pub struct OutputStats {
    /// Bytes forwarded.
    pub fwd_bytes: BytesStats,
    /// Packets forwarded.
    pub fwd_packets: PacketsStats,
    /// Bytes dropped for unknown direction.
    pub direction_drop_bytes: BytesStats,
    /// Packets dropped for unknown direction.
    pub direction_drop_packets: PacketsStats,
    /// Bytes dropped due to send errors.
    pub error_drop_bytes: BytesStats,
    /// Packets dropped due to send errors.
    pub error_drop_packets: PacketsStats,
    /// Bytes dropped by the rate limiter.
    pub ratelimit_drop_bytes: BytesStats,
    /// Packets dropped by the rate limiter.
    pub ratelimit_drop_packets: PacketsStats,
    /// Heartbeat frames sent.
    pub heartbeat_packets: PacketsStats,
}

#[derive(Debug, Default, Clone, Copy)]
/// Snapshot of pipeline ring-buffer usage.
pub struct PipelineBufferStats {
    /// Total ring capacity in messages.
    pub ring_total: u64,
    /// Ring slots currently used.
    pub ring_used: u64,
    /// Total pipeline buffer memory in bytes.
    pub mem_total: u64,
    /// Pipeline buffer memory currently used.
    pub mem_used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_rollover() {
        let s = BytesStats::default();
        s.add(EIB_IN_BYTES - 1);
        assert_eq!(s.load(), (EIB_IN_BYTES - 1, 0));
        s.add(2);
        assert_eq!(s.load(), (1, 1));
    }

    #[test]
    fn packets_rollover() {
        let s = PacketsStats::default();
        s.add(PETA_IN_PACKETS + 5);
        assert_eq!(s.load(), (5, 1));
    }
}
