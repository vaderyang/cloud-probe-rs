//! Human-readable formatting. Port of `cpctl/cmd/stats.go` helpers.

use cpgolib::cpworker::{BytesStats, EIB_IN_BYTES, PETA_IN_PACKETS, PacketsStats};

pub fn bytes_per_sec(stats: &BytesStats, secs: f64) -> BytesStats {
    if secs <= 0.0 {
        return *stats;
    }
    let mut bytes = (stats.bytes as f64 / secs) as u64;
    let eib = stats.eib as f64 / secs;
    let eib_int = eib.trunc();
    let eib_rem = eib - eib_int;
    bytes += (eib_rem * EIB_IN_BYTES as f64) as u64;
    BytesStats {
        bytes,
        eib: eib_int as u64,
    }
}

pub fn packets_per_sec(stats: &PacketsStats, secs: f64) -> PacketsStats {
    if secs <= 0.0 {
        return *stats;
    }
    let mut packets = (stats.packets as f64 / secs) as u64;
    let peta = stats.peta as f64 / secs;
    let peta_int = peta.trunc();
    let peta_rem = peta - peta_int;
    packets += (peta_rem * PETA_IN_PACKETS as f64) as u64;
    PacketsStats {
        packets,
        peta: peta_int as u64,
    }
}

pub fn format_packets_stats(stats: &PacketsStats) -> String {
    let v = format!("{}", stats.packets);
    if stats.peta != 0 {
        format!("{} Peta, {}", stats.peta, v)
    } else {
        v
    }
}

pub fn format_packets_and_per_sec(stats: &PacketsStats, secs: f64) -> String {
    let per_sec = packets_per_sec(stats, secs);
    format!(
        "{}; ({} / s)",
        format_packets_stats(stats),
        format_packets_stats(&per_sec)
    )
}

pub fn format_bytes_stats(stats: &BytesStats) -> String {
    let v = format_bytes(stats.bytes);
    if stats.eib != 0 {
        format!("{} EB, {}", stats.eib, v)
    } else {
        v
    }
}

pub fn format_bytes_and_per_sec(stats: &BytesStats, secs: f64) -> String {
    let per_sec = bytes_per_sec(stats, secs);
    format!(
        "{}; ({} / s)",
        format_bytes_stats(stats),
        format_bytes_stats(&per_sec)
    )
}

pub fn format_bytes(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT {
        return format!("{b} B");
    }
    let mut div: u64 = UNIT;
    let mut exp = 0usize;
    let mut n = b / UNIT;
    while n >= UNIT {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    let units = ["K", "M", "G", "T", "P", "E"];
    format!("{:.1} {}B", b as f64 / div as f64, units[exp.min(5)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn per_sec() {
        let b = BytesStats { bytes: 2000, eib: 0 };
        let r = bytes_per_sec(&b, 2.0);
        assert_eq!(r.bytes, 1000);
        assert_eq!(r.eib, 0);

        let p = PacketsStats { packets: 100, peta: 0 };
        let rp = packets_per_sec(&p, 2.0);
        assert_eq!(rp.packets, 50);
    }
}
