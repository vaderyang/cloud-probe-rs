//! Fingerprint helpers. Port of `cpdaemon/pkg/common/{fnv,fingerprint,signature,fingerprint_reflect}.go`.
//!
//! Go used reflection over json tags to build a label map, then FNV-1a hashed
//! the sorted labels. Here we walk the worker `TaskConfig` explicitly with the
//! exact same label keys and ordering.

use std::collections::BTreeMap;

use crate::worker_config::{CapturerConfig, OutputConfig, ReqPatternConfig, TaskConfig};

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
pub fn fingerprint_string(f: u64) -> String {
    format!("{f:016x}")
}

/// Port of `Fingerprint.UUID()` — note the quirk: the 16 ASCII characters of the
/// hex string are copied into the UUID bytes and then formatted as a UUID. This
/// is intentionally reproduced for byte-for-byte compatibility.
pub fn fingerprint_uuid_string(f: u64) -> String {
    let hex = fingerprint_string(f);
    let b = hex.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn b(labels: &mut BTreeMap<String, String>, key: &str, value: &str) {
    labels.insert(key.to_string(), value.to_string());
}

fn opt_u64(labels: &mut BTreeMap<String, String>, key: &str, v: Option<u64>) {
    if let Some(v) = v {
        b(labels, key, &v.to_string());
    }
}

fn opt_i64(labels: &mut BTreeMap<String, String>, key: &str, v: Option<i64>) {
    if let Some(v) = v {
        b(labels, key, &v.to_string());
    }
}

fn opt_bool(labels: &mut BTreeMap<String, String>, key: &str, v: Option<bool>) {
    if let Some(v) = v {
        b(labels, key, if v { "true" } else { "false" });
    }
}

fn opt_str(labels: &mut BTreeMap<String, String>, key: &str, v: Option<&str>) {
    if let Some(v) = v {
        b(labels, key, v);
    }
}

/// Port of `TaskConfig.FingerPrintLables()` / `StructFingerprintLabels`.
/// `fingerprint` is excluded via the `fingerprint:"-"` tag.
pub fn task_fingerprint_labels(task: &TaskConfig) -> BTreeMap<String, String> {
    let mut l = BTreeMap::new();

    if let Some(rp) = &task.req_pattern {
        req_pattern_labels(&mut l, "req_pattern.", rp);
    }
    capturer_labels(&mut l, "capturer.", &task.capturer);
    for (i, o) in task.outputs.iter().enumerate() {
        output_labels(&mut l, &format!("outputs.{i}."), o);
    }
    l
}

fn req_pattern_labels(l: &mut BTreeMap<String, String>, prefix: &str, rp: &ReqPatternConfig) {
    b(l, &format!("{prefix}type"), &rp.ty);
    if let Some(c) = &rp.custom {
        opt_str(l, &format!("{prefix}custom.pattern"), c.pattern.as_deref());
    }
}

fn capturer_labels(l: &mut BTreeMap<String, String>, prefix: &str, c: &CapturerConfig) {
    b(l, &format!("{prefix}type"), &c.ty);
    if let Some(lp) = &c.libpcap {
        b(l, &format!("{prefix}libpcap.interface"), &lp.interface);
        opt_i64(
            l,
            &format!("{prefix}libpcap.snaplen"),
            lp.snaplen.map(|v| v as i64),
        );
        opt_str(l, &format!("{prefix}libpcap.netns"), lp.netns.as_deref());
        opt_str(l, &format!("{prefix}libpcap.bpf"), lp.bpf.as_deref());
        opt_u64(
            l,
            &format!("{prefix}libpcap.buffer_size_mb"),
            lp.buffer_size_mb,
        );
        opt_i64(
            l,
            &format!("{prefix}libpcap.timeout_ms"),
            lp.timeout_ms.map(|v| v as i64),
        );
        opt_bool(
            l,
            &format!("{prefix}libpcap.not_filter_output_hosts"),
            lp.not_filter_output_hosts,
        );
    }
}

fn output_labels(l: &mut BTreeMap<String, String>, prefix: &str, o: &OutputConfig) {
    b(l, &format!("{prefix}type"), &o.ty);
    opt_u64(l, &format!("{prefix}rate_limit_mbps"), o.rate_limit_mbps);
    opt_u64(l, &format!("{prefix}slice"), o.slice);
    if let Some(v) = &o.vxlan {
        let p = format!("{prefix}vxlan.");
        b(l, &format!("{p}host"), &v.host);
        opt_i64(l, &format!("{p}port"), v.port.map(|x| x as i64));
        opt_bool(l, &format!("{p}capture_time"), v.capture_time);
        if let Some(vni) = v.vni1 {
            b(l, &format!("{p}vni1"), &vni.to_string());
        }
        if let Some(vni) = v.vni2 {
            b(l, &format!("{p}vni2"), &vni.to_string());
        }
        opt_str(l, &format!("{p}bind_device"), v.bind_device.as_deref());
        opt_str(l, &format!("{p}pmtudisc"), v.pmtudisc.as_deref());
        if let Some(s) = &v.split {
            opt_i64(
                l,
                &format!("{p}split.max_payload_size"),
                s.max_payload_size.map(|x| x as i64),
            );
            opt_bool(
                l,
                &format!("{p}split.recalculate_checksum"),
                s.recalculate_checksum,
            );
        }
    }
    if let Some(v) = &o.gre {
        let p = format!("{prefix}gre.");
        b(l, &format!("{p}host"), &v.host);
        opt_u64(
            l,
            &format!("{p}service_tag"),
            v.service_tag.map(|x| x as u64),
        );
        opt_str(l, &format!("{p}bind_device"), v.bind_device.as_deref());
        opt_str(l, &format!("{p}pmtudisc"), v.pmtudisc.as_deref());
    }
    if let Some(v) = &o.zmq {
        let p = format!("{prefix}zmq.");
        b(l, &format!("{p}host"), &v.host);
        // Zmq.Port is a plain int in Go -> always emitted.
        b(l, &format!("{p}port"), &v.port.to_string());
        opt_i64(l, &format!("{p}hwm"), v.hwm.map(|x| x as i64));
        opt_u64(
            l,
            &format!("{p}service_tag"),
            v.service_tag.map(|x| x as u64),
        );
        // Uuid is a plain string -> always emitted.
        b(l, &format!("{p}uuid"), &v.uuid);
        opt_i64(
            l,
            &format!("{p}heartbeat_ms"),
            v.heartbeat_ms.map(|x| x as i64),
        );
    }
    if let Some(v) = &o.file {
        b(l, &format!("{prefix}file.name"), &v.name);
    }
    if let Some(v) = &o.rotating_file {
        let p = format!("{prefix}rotating_file.");
        b(l, &format!("{p}file_root"), &v.file_root);
        opt_i64(
            l,
            &format!("{p}max_file_interval"),
            v.max_file_interval.map(|x| x as i64),
        );
    }
}
