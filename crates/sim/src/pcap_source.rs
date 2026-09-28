//! DST for the pcap file reader (`cpworker::capturer::pcap_file::PcapReader`).
//!
//! Generates a deterministic pcap byte stream — seeded, with varying record
//! sizes so record headers straddle the reader's 8 KiB `BufReader` boundary —
//! and drives the real reader over it, verifying every record parses exactly.
//! Corrupted and truncated variants must fail cleanly: never panic, never
//! drift into garbage records.
//!
//! This closes the gap that let the `read()`/`read_exact()` position-drift
//! regression (AUDIT4) ship: the file reader had no simulation or differential
//! coverage on files larger than the 8 KiB buffer.

use std::io::{BufReader, Cursor};

use cpworker::capturer::pcap_file::PcapReader;

use crate::Rng;

/// Little-endian pcap global header: v2.4, snaplen 65535, Ethernet.
const GLOBAL: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

/// A deterministically generated pcap stream plus its record schedule.
pub struct Generated {
    pub bytes: Vec<u8>,
    pub sizes: Vec<u32>,
}

impl Generated {
    /// Byte offset of record `k`'s `incl_len` field.
    #[must_use]
    fn incl_offset(&self, k: usize) -> usize {
        let mut off = 24;
        for i in 0..k {
            off += 16 + self.sizes[i] as usize;
        }
        off + 8
    }

    /// Corrupt record `k`'s `incl_len` to an oversized value, so a correct
    /// reader stops cleanly exactly at record `k`.
    pub fn corrupt_oversized(&mut self, k: usize) {
        let off = self.incl_offset(k);
        self.bytes[off..off + 4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    }

    /// Truncate the stream to `keep` bytes (must keep the 24-byte global
    /// header).
    pub fn truncate_to(&mut self, keep: usize) {
        self.bytes.truncate(keep);
    }
}

/// Generate `n_records` records with seeded varying sizes (64..=1024), so
/// record headers straddle the reader's 8 KiB `BufReader` boundary. Record `i`
/// carries `ts_usec = i` and an all-`0xA5` payload of `size(i)` bytes.
#[must_use]
pub fn generate(rng: &mut Rng, n_records: usize) -> Generated {
    let mut bytes = GLOBAL.to_vec();
    let mut sizes = Vec::with_capacity(n_records);
    for i in 0..n_records {
        let size = 64 + rng.below(961) as u32;
        sizes.push(size);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        bytes.extend_from_slice(&(i as u32).to_le_bytes()); // ts_usec = i
        bytes.extend_from_slice(&size.to_le_bytes()); // incl_len
        bytes.extend_from_slice(&size.to_le_bytes()); // orig_len
        bytes.extend(std::iter::repeat_n(0xA5u8, size as usize));
    }
    Generated { bytes, sizes }
}

/// Outcome of a full read of a (possibly corrupted) stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    pub records: usize,
    pub digest: u64,
    /// Reader error (corrupt record, oversize `caplen`, …). `None` for a clean
    /// read of a clean file.
    pub stopped: Option<String>,
}

/// A hard failure of the reader that is not a position drift (e.g. an invalid
/// global header).
#[derive(Debug)]
pub struct DriftError(pub String);

impl DriftError {
    fn new(msg: impl Into<String>) -> Self {
        DriftError(msg.into())
    }
}

/// Read the whole stream with the real reader (8 KiB `BufReader`, exactly like
/// the file path). Verifies every record that comes back — `ts_usec = i`,
/// `caplen = size(i)`, payload all `0xA5` — and stops at the first clean EOF,
/// truncation or reader error.
///
/// # Panics
/// Panics if the reader drifts: emits a record whose `ts_usec`/`caplen`/payload
/// does not match the schedule, or emits a record beyond the schedule.
///
/// # Errors
/// Returns an error if the global header is invalid.
pub fn read_all(gen: &Generated) -> Result<ReadOutcome, DriftError> {
    let mut r = PcapReader::from_reader("dst-sim", BufReader::new(Cursor::new(gen.bytes.clone())))
        .map_err(|e| DriftError::new(format!("global header: {e}")))?;
    let mut trace = crate::Trace::default();
    let mut records = 0usize;
    let mut stopped = None;
    loop {
        match r.next_record() {
            Ok(true) => {}
            Ok(false) => break, // clean EOF
            Err(e) => {
                // Corrupt record / oversize caplen / truncated source: the
                // expected clean stop. Never a panic, never a garbage record.
                stopped = Some(e.to_string());
                break;
            }
        }
        assert!(
            records < gen.sizes.len(),
            "reader emitted record {records} beyond the schedule (position drift)"
        );
        let want = gen.sizes[records];
        assert_eq!(
            r.ts_usec, records as i64,
            "record {records}: ts_usec drifted (read()/read_exact() regression)"
        );
        assert_eq!(
            r.caplen, want,
            "record {records}: caplen drifted (read()/read_exact() regression)"
        );
        assert!(
            r.data.iter().all(|&b| b == 0xA5),
            "record {records}: payload drifted"
        );
        trace.record_u64(1, records as u64);
        records += 1;
    }
    Ok(ReadOutcome {
        records,
        digest: trace.digest(),
        stopped,
    })
}
