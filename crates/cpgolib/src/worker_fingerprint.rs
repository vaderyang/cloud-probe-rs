//! Task fingerprint label extraction. Port of `cpdaemon/pkg/common/fingerprint_reflect.go`
//! driven by the worker `TaskConfig` shape.
//!
//! Go used reflection over json tags to build a label map, then FNV-1a hashed
//! the sorted labels. Here we walk [`TaskConfig`] explicitly with the exact same
//! label keys and ordering. Shared with `cpdaemon` and the differential fuzz
//! harness so both can be compared against the Go reflection walk.

use std::collections::BTreeMap;

use crate::worker_config::{CapturerConfig, OutputConfig, ReqPatternConfig, TaskConfig};

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
#[must_use]
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

/// Full task fingerprint as the UUID string (`Fingerprint.UUID().String()`).
#[must_use]
pub fn task_fingerprint(task: &TaskConfig) -> String {
    let labels = task_fingerprint_labels(task);
    crate::fingerprint::fingerprint_uuid_string(crate::fingerprint::labels_to_fingerprint(&labels))
}

fn req_pattern_labels(l: &mut BTreeMap<String, String>, prefix: &str, rp: &ReqPatternConfig) {
    b(l, &format!("{prefix}type"), &rp.ty);
    if let Some(c) = &rp.custom {
        // Go's `CustomReqPatternConfig.Pattern` is a plain (non-pointer) string,
        // so reflection always emits it (empty when unset); `omitempty` only
        // affects JSON, not the fingerprint. Found by parity/difffuzz.sh
        // task_fingerprint.
        b(
            l,
            &format!("{prefix}custom.pattern"),
            c.pattern.as_deref().unwrap_or(""),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_pattern_absent_is_still_emitted() {
        // Go's Pattern is a non-pointer string, so the empty value still
        // contributes to the fingerprint. Vector generated by the Go
        // reflection walk (parity/difffuzz.sh task_fingerprint).
        let j = r#"{"req_pattern":{"type":"custom","custom":{}},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[]}"#;
        let t: TaskConfig = serde_json::from_str(j).unwrap();
        let labels = task_fingerprint_labels(&t);
        assert_eq!(
            labels.get("req_pattern.custom.pattern").map(String::as_str),
            Some("")
        );
        assert_eq!(task_fingerprint(&t), "38336539-3738-6433-6133-326337343139");
    }

    /// Every `opt_*` helper and every output/capturer branch must contribute its
    /// label; a dropped helper (or a whole dropped `output_labels`) would leave
    /// the fingerprint blind to that field.
    #[test]
    fn every_field_contributes_a_label() {
        let j = r#"{
          "req_pattern":{"type":"custom","custom":{"pattern":"GET /"}},
          "capturer":{"type":"libpcap","libpcap":{
            "interface":"eth0","snaplen":128,"netns":"ns1","bpf":"tcp",
            "buffer_size_mb":4,"timeout_ms":100,"not_filter_output_hosts":true}},
          "outputs":[
            {"type":"vxlan","rate_limit_mbps":10,"slice":2,"vxlan":{
              "host":"h1","port":4789,"capture_time":true,"vni1":1,"vni2":2,
              "bind_device":"eth0","pmtudisc":"do",
              "split":{"max_payload_size":1400,"recalculate_checksum":false}}},
            {"type":"gre","gre":{"host":"h2","service_tag":7,
              "bind_device":"eth1","pmtudisc":"dont"}},
            {"type":"zmq","zmq":{"host":"h3","port":5555,"hwm":1000,
              "service_tag":9,"uuid":"u","heartbeat_ms":500}},
            {"type":"file","file":{"name":"out.pcap"}},
            {"type":"rotating_file","rotating_file":{"file_root":"/root","max_file_interval":60}}
          ]
        }"#;
        let t: TaskConfig = serde_json::from_str(j).unwrap();
        let l = task_fingerprint_labels(&t);
        let get = |k: &str| l.get(k).map(String::as_str);

        assert_eq!(get("req_pattern.type"), Some("custom"));
        assert_eq!(get("req_pattern.custom.pattern"), Some("GET /"));
        assert_eq!(get("capturer.type"), Some("libpcap"));
        assert_eq!(get("capturer.libpcap.interface"), Some("eth0"));
        // opt_i64
        assert_eq!(get("capturer.libpcap.snaplen"), Some("128"));
        assert_eq!(get("capturer.libpcap.timeout_ms"), Some("100"));
        // opt_str
        assert_eq!(get("capturer.libpcap.netns"), Some("ns1"));
        assert_eq!(get("capturer.libpcap.bpf"), Some("tcp"));
        // opt_u64
        assert_eq!(get("capturer.libpcap.buffer_size_mb"), Some("4"));
        // opt_bool(true)
        assert_eq!(
            get("capturer.libpcap.not_filter_output_hosts"),
            Some("true")
        );

        // Outputs: index prefix + per-type helpers.
        assert_eq!(get("outputs.0.type"), Some("vxlan"));
        assert_eq!(get("outputs.0.rate_limit_mbps"), Some("10"));
        assert_eq!(get("outputs.0.slice"), Some("2"));
        assert_eq!(get("outputs.0.vxlan.port"), Some("4789"));
        assert_eq!(get("outputs.0.vxlan.capture_time"), Some("true"));
        assert_eq!(get("outputs.0.vxlan.vni1"), Some("1"));
        assert_eq!(get("outputs.0.vxlan.vni2"), Some("2"));
        assert_eq!(get("outputs.0.vxlan.bind_device"), Some("eth0"));
        assert_eq!(get("outputs.0.vxlan.pmtudisc"), Some("do"));
        assert_eq!(get("outputs.0.vxlan.split.max_payload_size"), Some("1400"));
        // opt_bool(false)
        assert_eq!(
            get("outputs.0.vxlan.split.recalculate_checksum"),
            Some("false")
        );

        assert_eq!(get("outputs.1.gre.host"), Some("h2"));
        assert_eq!(get("outputs.1.gre.service_tag"), Some("7"));
        assert_eq!(get("outputs.1.gre.bind_device"), Some("eth1"));
        assert_eq!(get("outputs.1.gre.pmtudisc"), Some("dont"));

        assert_eq!(get("outputs.2.zmq.host"), Some("h3"));
        assert_eq!(get("outputs.2.zmq.port"), Some("5555"));
        assert_eq!(get("outputs.2.zmq.hwm"), Some("1000"));
        assert_eq!(get("outputs.2.zmq.service_tag"), Some("9"));
        assert_eq!(get("outputs.2.zmq.uuid"), Some("u"));
        assert_eq!(get("outputs.2.zmq.heartbeat_ms"), Some("500"));

        assert_eq!(get("outputs.3.file.name"), Some("out.pcap"));
        assert_eq!(get("outputs.4.rotating_file.file_root"), Some("/root"));
        assert_eq!(get("outputs.4.rotating_file.max_file_interval"), Some("60"));
    }

    /// `None` options must not produce labels (so an unset field does not change
    /// the fingerprint), while non-pointer Go fields still do.
    #[test]
    fn absent_options_add_no_labels() {
        let j = r#"{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[]}"#;
        let t: TaskConfig = serde_json::from_str(j).unwrap();
        let l = task_fingerprint_labels(&t);
        assert!(!l.contains_key("capturer.libpcap.snaplen"));
        assert!(!l.contains_key("capturer.libpcap.netns"));
        assert!(
            !l.contains_key("capturer.libpcap.not_filter_output_hosts"),
            "an unset option must not contribute"
        );
        assert_eq!(
            l.get("capturer.libpcap.interface").map(String::as_str),
            Some("eth0")
        );
    }
}
