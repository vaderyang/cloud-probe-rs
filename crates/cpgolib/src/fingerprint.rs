//! FNV-1a fingerprint primitives.
//!
//! Port of `cpdaemon/pkg/common/{fnv,fingerprint,signature}.go`. These are the
//! pure hash/formatting primitives shared by `cpdaemon` and the differential
//! fuzz harness. The label *extraction* (walking a task config) lives in the
//! daemon; only the parts both sides can share live here.

use std::collections::BTreeMap;

const OFFSET64: u64 = 14695981039346656037;
const PRIME64: u64 = 1099511628211;
const SEPARATOR_BYTE: u8 = 255;

#[inline]
fn hash_add(mut h: u64, s: &str) -> u64 {
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME64);
    }
    h
}

#[inline]
fn hash_add_byte(mut h: u64, b: u8) -> u64 {
    h ^= b as u64;
    h.wrapping_mul(PRIME64)
}

/// Sorted-label FNV-1a fingerprint. Port of `LabelsToFingerprint`.
#[must_use]
pub fn labels_to_fingerprint(labels: &BTreeMap<String, String>) -> u64 {
    if labels.is_empty() {
        return OFFSET64;
    }
    let mut sum = OFFSET64;
    for (k, v) in labels {
        sum = hash_add(sum, k);
        sum = hash_add_byte(sum, SEPARATOR_BYTE);
        sum = hash_add(sum, v);
        sum = hash_add_byte(sum, SEPARATOR_BYTE);
    }
    sum
}

/// Port of `Fingerprint.String()`: 16 lowercase hex digits, zero padded.
#[must_use]
pub fn fingerprint_string(f: u64) -> String {
    format!("{f:016x}")
}

/// Port of `Fingerprint.UUID()` — note the quirk: the 16 ASCII characters of the
/// hex string are copied into the UUID bytes and then formatted as a UUID. This
/// is intentionally reproduced for byte-for-byte compatibility.
#[must_use]
pub fn fingerprint_uuid_string(f: u64) -> String {
    let hex = fingerprint_string(f);
    let b = hex.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_matches_go_offset() {
        assert_eq!(labels_to_fingerprint(&BTreeMap::new()), OFFSET64);
    }

    #[test]
    fn go_vector_round_trips() {
        // From parity/workerTaskBuilder Go test vectors: a->b, c->d.
        let mut l = BTreeMap::new();
        l.insert("a".to_string(), "b".to_string());
        l.insert("c".to_string(), "d".to_string());
        let f = labels_to_fingerprint(&l);
        assert_eq!(fingerprint_string(f), "53997eba86e1c7f5");
        assert_eq!(
            fingerprint_uuid_string(f),
            "35333939-3765-6261-3836-653163376635"
        );
    }

    #[test]
    fn ordering_is_key_sorted() {
        let mut a = BTreeMap::new();
        a.insert("z".to_string(), "1".to_string());
        a.insert("a".to_string(), "2".to_string());
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), "2".to_string());
        b.insert("z".to_string(), "1".to_string());
        assert_eq!(labels_to_fingerprint(&a), labels_to_fingerprint(&b));
    }
}
