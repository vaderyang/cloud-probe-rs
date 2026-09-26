//! Stats models. Port of `cpgolib/cpworker/stats.go`.

use serde::{Deserialize, Serialize};

pub const EIB_IN_BYTES: u64 = 1024 * 1024 * 1024 * 1024 * 1024 * 1024; // 2^60
pub const PETA_IN_PACKETS: u64 = 10_000_000_000_000_000; // 10^16

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsTime {
    #[serde(default)]
    pub sec: i64,
    #[serde(default)]
    pub nsec: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsSummary {
    #[serde(default)]
    pub time: StatsTime,
    #[serde(default)]
    pub capture: CaptureStats,
    #[serde(default)]
    pub output: OutputStats,
    #[serde(default)]
    pub pipeline_buffer: PipelineBufferStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineBufferStats {
    #[serde(default)]
    pub mem_total: u64,
    #[serde(default)]
    pub mem_used: u64,
    #[serde(default)]
    pub ring_total: u64,
    #[serde(default)]
    pub ring_used: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    #[serde(default)]
    pub cap_bytes: BytesStats,
    #[serde(default)]
    pub cap_packets: PacketsStats,
    #[serde(default)]
    pub drop_packets: PacketsStats,
    #[serde(default)]
    pub ifdrop_packets: PacketsStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutputStats {
    #[serde(default)]
    pub fwd_bytes: BytesStats,
    #[serde(default)]
    pub fwd_packets: PacketsStats,
    #[serde(default)]
    pub direction_drop_bytes: BytesStats,
    #[serde(default)]
    pub direction_drop_packets: PacketsStats,
    #[serde(default)]
    pub error_drop_bytes: BytesStats,
    #[serde(default)]
    pub error_drop_packets: PacketsStats,
    #[serde(default)]
    pub ratelimit_drop_bytes: BytesStats,
    #[serde(default)]
    pub ratelimit_drop_packets: PacketsStats,
    #[serde(default)]
    pub heartbeat_packets: PacketsStats,
    /// Batches a ZMQ output has queued for the collector right now (gauge).
    #[serde(default)]
    pub zmtp_queued_batches: u64,
    /// Bytes a ZMQ output has queued for the collector right now (gauge).
    #[serde(default)]
    pub zmtp_queued_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BytesStats {
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub eib: u64,
}

impl BytesStats {
    /// Returns Ordering-like i8: -1 less, 0 equal, 1 greater.
    #[must_use]
    pub fn compare(&self, other: &BytesStats) -> i8 {
        match self.eib.cmp(&other.eib) {
            std::cmp::Ordering::Equal => match self.bytes.cmp(&other.bytes) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            },
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// Difference `self - other`. Second value is true when `self < other`
    /// (the difference is then the absolute value).
    #[must_use]
    pub fn sub(&self, other: &BytesStats) -> (BytesStats, bool) {
        let is_less = self.compare(other) < 0;
        let (x, y) = if is_less {
            (other, self)
        } else {
            (self, other)
        };

        let mut eib = x.eib - y.eib;
        let bytes = if x.bytes < y.bytes {
            eib -= 1;
            EIB_IN_BYTES + x.bytes - y.bytes
        } else {
            x.bytes - y.bytes
        };
        (BytesStats { bytes, eib }, is_less)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PacketsStats {
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub peta: u64,
}

impl PacketsStats {
    #[must_use]
    pub fn compare(&self, other: &PacketsStats) -> i8 {
        match self.peta.cmp(&other.peta) {
            std::cmp::Ordering::Equal => match self.packets.cmp(&other.packets) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            },
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
        }
    }

    #[must_use]
    pub fn sub(&self, other: &PacketsStats) -> (PacketsStats, bool) {
        let is_less = self.compare(other) < 0;
        let (x, y) = if is_less {
            (other, self)
        } else {
            (self, other)
        };

        let mut peta = x.peta - y.peta;
        let packets = if x.packets < y.packets {
            peta -= 1;
            PETA_IN_PACKETS + x.packets - y.packets
        } else {
            x.packets - y.packets
        };
        (PacketsStats { packets, peta }, is_less)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_sub_simple() {
        let a = BytesStats { bytes: 100, eib: 0 };
        let b = BytesStats { bytes: 50, eib: 0 };
        let (d, less) = a.sub(&b);
        assert_eq!((d.bytes, d.eib, less), (50, 0, false));
    }

    #[test]
    fn bytes_sub_borrow() {
        let a = BytesStats { bytes: 5, eib: 0 };
        let b = BytesStats { bytes: 10, eib: 0 };
        let (d, less) = a.sub(&b);
        assert_eq!(d.bytes, 5);
        assert_eq!(d.eib, 0);
        assert!(less);
    }

    #[test]
    fn packets_sub_borrow() {
        let a = PacketsStats {
            packets: 1,
            peta: 0,
        };
        let b = PacketsStats {
            packets: 3,
            peta: 0,
        };
        let (d, less) = a.sub(&b);
        assert_eq!(d.packets, 2);
        assert_eq!(d.peta, 0);
        assert!(less);
    }
}
