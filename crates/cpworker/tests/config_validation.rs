//! Ports of upstream `cpworker/tests/unit/config_validation.c`.
//!
//! Every `#[test]` below names the C test it was ported from. The C suite's
//! `assert_rejected()` checked both that the config was rejected *and* that the
//! `cJSONParseError` message contained a specific substring; this port words its
//! errors differently (field-range errors name the same field,
//! fractional/string errors are raised by serde and name the enclosing block),
//! so rejection vectors assert `is_err()` plus the most specific token the
//! message does carry. The exact C expectation is kept in the doc comment.
//! Accepted vectors assert the same normalised value the C test asserted.
//!
//! Already covered elsewhere (not duplicated here - see the bead status):
//! * `parity/verify_config.sh` (differential, C vs Rust) covers the
//!   out-of-range decision for every numeric field on a fixed vector grid.
//! * `crates/cpworker/src/config.rs` unit tests cover the generic
//!   `snaplen`/`buffer_size_mb`/`timeout_ms`/`slice`/`rate_limit_mbps`/`hwm`/
//!   `max_file_interval`/`pipeline` clamp rules and integral-float parsing.
//! * `crates/cpworker/tests/port_parity.rs` covers `misc.c`'s VNI fixture.

use cpworker::config::{
    CapturerKind, Config, OutputConfig, OutputKind, PIPELINE_BUFFER_MB_MAX, SNAPLEN_MAX,
};
use cpworker::output::vxlan::vxlan_encapsulate;
use cpworker::packet::PKT_DIR_NONCHECK;

// ---------------------------------------------------------------------------
// Helpers mirroring config_validation.c
// ---------------------------------------------------------------------------

/// `config_with_output()`: single-task libpcap config whose only output is
/// `output_json`.
fn with_output(output_json: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "libpcap", "libpcap": {{"interface": "eth0"}}}}, "outputs": [{output_json}]}}]}}"#
    )
}

fn parse(json: &str) -> Config {
    Config::parse_str(json).unwrap_or_else(|e| panic!("expected acceptance of {json}: {e}"))
}

/// `assert_rejected()` without the message check.
fn reject(json: &str) {
    assert!(
        Config::parse_str(json).is_err(),
        "expected rejection of {json}"
    );
}

/// `assert_rejected()` with an anchor the error message must contain. The anchor
/// is the field name for range errors and the enclosing block for errors raised
/// while deserialising a fractional/string value.
fn reject_naming(json: &str, anchor: &str) {
    match Config::parse_str(json) {
        Ok(_) => panic!("expected rejection of {json}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains(anchor),
                "error for {json} should mention {anchor:?}, got: {msg}"
            );
        }
    }
}

fn first_output(c: &Config) -> &OutputConfig {
    &c.tasks[0].outputs[0]
}

fn vxlan_output_with_port(port: &str) -> String {
    format!(r#"{{"type": "vxlan", "vxlan": {{"host": "10.0.0.1", "port": {port}, "vni1": 1}}}}"#)
}

fn zmq_output_with_port(port: &str) -> String {
    format!(r#"{{"type": "zmq", "zmq": {{"host": "10.0.0.1", "port": {port}}}}}"#)
}

fn pipeline_config_with_buffer_size(buffer_size_mb: &str) -> String {
    format!(
        r#"{{"execution_model": "pipeline", "pipeline": {{"buffer_size_mb": {buffer_size_mb}}}, "tasks": [{{"capturer": {{"type": "libpcap", "libpcap": {{"interface": "eth0"}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn libpcap_config_with_snaplen(snaplen: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "libpcap", "libpcap": {{"interface": "eth0", "snaplen": {snaplen}}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn dpdk_config_with_snaplen(snaplen: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "dpdk_pdump", "dpdk_pdump": {{"interface": "0000:00:00.0", "snaplen": {snaplen}}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn libpcap_config_with_buffer_size(buffer_size_mb: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "libpcap", "libpcap": {{"interface": "eth0", "buffer_size_mb": {buffer_size_mb}}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn null_output_with_slice(slice: &str) -> String {
    format!(r#"{{"type": "null", "slice": {slice}}}"#)
}

fn vxlan_output_with_vni(vni_fields: &str) -> String {
    format!(r#"{{"type": "vxlan", "vxlan": {{"host": "10.0.0.1", {vni_fields}}}}}"#)
}

fn vxlan_output_with_split(split_json: &str) -> String {
    format!(
        r#"{{"type": "vxlan", "vxlan": {{"host": "10.0.0.1", "vni1": 1, "split": {split_json}}}}}"#
    )
}

fn split_with_max_payload_size(max_payload_size: &str) -> String {
    vxlan_output_with_split(&format!(r#"{{"max_payload_size": {max_payload_size}}}"#))
}

fn zmq_output_with_service_tag(service_tag: &str) -> String {
    format!(
        r#"{{"type": "zmq", "zmq": {{"host": "10.0.0.1", "port": 5555, "service_tag": {service_tag}}}}}"#
    )
}

fn gre_output_with_service_tag(service_tag: &str) -> String {
    format!(r#"{{"type": "gre", "gre": {{"host": "10.0.0.1", "service_tag": {service_tag}}}}}"#)
}

fn zmq_output_with_hwm(hwm: &str) -> String {
    format!(r#"{{"type": "zmq", "zmq": {{"host": "10.0.0.1", "port": 5555, "hwm": {hwm}}}}}"#)
}

fn rotating_file_output_with_interval(interval: &str) -> String {
    format!(
        r#"{{"type": "rotating_file", "rotating_file": {{"file_root": "/tmp", "max_file_interval": {interval}}}}}"#
    )
}

fn dpdk_config_with_ring_size(ring_size: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "dpdk_pdump", "dpdk_pdump": {{"interface": "0000:00:00.0", "ring_size": {ring_size}}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn null_output_with_rate_limit(rate_limit_mbps: &str) -> String {
    format!(r#"{{"type": "null", "rate_limit_mbps": {rate_limit_mbps}}}"#)
}

fn libpcap_config_with_timeout(timeout_ms: &str) -> String {
    format!(
        r#"{{"tasks": [{{"capturer": {{"type": "libpcap", "libpcap": {{"interface": "eth0", "timeout_ms": {timeout_ms}}}}}, "outputs": [{{"type": "null"}}]}}]}}"#
    )
}

fn zmq_output_with_heartbeat(heartbeat_ms: &str) -> String {
    format!(
        r#"{{"type": "zmq", "zmq": {{"host": "10.0.0.1", "port": 5555, "heartbeat_ms": {heartbeat_ms}}}}}"#
    )
}

// ---------------------------------------------------------------------------
// vxlan.port
// ---------------------------------------------------------------------------

/// `test_vxlan_port_out_of_range_rejected`: C expects
/// `"invalid vxlan.port"` for every value.
#[test]
fn test_vxlan_port_out_of_range_rejected() {
    for bad in ["70000", "65536", "-1", "0", "1.5"] {
        reject_naming(&with_output(&vxlan_output_with_port(bad)), "vxlan");
    }
}

/// `test_vxlan_port_not_number_rejected`: C expects `"invalid vxlan.port"`.
#[test]
fn test_vxlan_port_not_number_rejected() {
    reject_naming(&with_output(&vxlan_output_with_port("\"4789\"")), "vxlan");
}

/// `test_vxlan_port_bounds_accepted`.
#[test]
fn test_vxlan_port_bounds_accepted() {
    let c = parse(&with_output(&vxlan_output_with_port("1")));
    match &first_output(&c).kind {
        OutputKind::Vxlan(v) => assert_eq!(v.port, 1),
        other => panic!("expected vxlan, got {other:?}"),
    }
    let c = parse(&with_output(&vxlan_output_with_port("65535")));
    match &first_output(&c).kind {
        OutputKind::Vxlan(v) => assert_eq!(v.port, 65535),
        other => panic!("expected vxlan, got {other:?}"),
    }
}

/// `test_vxlan_port_default`.
#[test]
fn test_vxlan_port_default() {
    let c = parse(&with_output(
        r#"{"type": "vxlan", "vxlan": {"host": "10.0.0.1", "vni1": 1}}"#,
    ));
    match &first_output(&c).kind {
        OutputKind::Vxlan(v) => assert_eq!(v.port, 4789),
        other => panic!("expected vxlan, got {other:?}"),
    }
}

/// `test_vxlan_port_error_message_names_range`: C's message is
/// `"invalid vxlan.port: 70000, must be an integer in [1, 65535]"`.
#[test]
fn test_vxlan_port_error_message_names_range() {
    let err = Config::parse_str(&with_output(&vxlan_output_with_port("70000")))
        .expect_err("70000 is out of range");
    let msg = err.to_string();
    assert!(msg.contains("vxlan.port"), "must name the field: {msg}");
    assert!(msg.contains("65535"), "must name the bound: {msg}");
}

// ---------------------------------------------------------------------------
// zmq.port
// ---------------------------------------------------------------------------

/// `test_zmq_port_out_of_range_rejected`: C expects `"invalid zmq.port"`.
#[test]
fn test_zmq_port_out_of_range_rejected() {
    for bad in ["70000", "65536", "-1", "0", "1.5"] {
        reject_naming(&with_output(&zmq_output_with_port(bad)), "zmq");
    }
}

/// `test_zmq_port_not_number_rejected`: C expects `"invalid zmq.port"`.
#[test]
fn test_zmq_port_not_number_rejected() {
    reject_naming(&with_output(&zmq_output_with_port("\"5555\"")), "zmq");
}

/// `test_zmq_port_bounds_accepted`.
#[test]
fn test_zmq_port_bounds_accepted() {
    let c = parse(&with_output(&zmq_output_with_port("1")));
    match &first_output(&c).kind {
        OutputKind::Zmq(z) => assert_eq!(z.port, 1),
        other => panic!("expected zmq, got {other:?}"),
    }
    let c = parse(&with_output(&zmq_output_with_port("65535")));
    match &first_output(&c).kind {
        OutputKind::Zmq(z) => assert_eq!(z.port, 65535),
        other => panic!("expected zmq, got {other:?}"),
    }
}

/// `test_zmq_port_missing_rejected`: C expects `"missing zmq.port"`.
#[test]
fn test_zmq_port_missing_rejected() {
    reject_naming(
        &with_output(r#"{"type": "zmq", "zmq": {"host": "10.0.0.1"}}"#),
        "missing zmq.port",
    );
}

// ---------------------------------------------------------------------------
// pipeline.buffer_size_mb
// ---------------------------------------------------------------------------

/// `test_pipeline_buffer_size_invalid_rejected`: C expects
/// `"invalid pipeline.buffer_size_mb"`. The last value is
/// `SIZE_MAX / 1 MiB + 1` on 64-bit platforms.
#[test]
fn test_pipeline_buffer_size_invalid_rejected() {
    for bad in ["0", "-1", "1.5", "17592186044416", "\"256\""] {
        reject_naming(&pipeline_config_with_buffer_size(bad), "pipeline");
    }
    // The value the C test singled out is exactly one past the port's bound.
    assert_eq!(PIPELINE_BUFFER_MB_MAX + 1, 17_592_186_044_416);
}

/// `test_pipeline_buffer_size_missing_rejected`: C expects
/// `"missing pipeline.buffer_size_mb"`.
#[test]
fn test_pipeline_buffer_size_missing_rejected() {
    reject_naming(
        r#"{"execution_model": "pipeline", "pipeline": {}, "tasks": [{"capturer": {"type": "libpcap", "libpcap": {"interface": "eth0"}}, "outputs": [{"type": "null"}]}]}"#,
        "missing pipeline.buffer_size_mb",
    );
}

/// `test_pipeline_buffer_size_large_value_in_bytes`: `buffer_size_mb * 1024 * 1024`
/// must not overflow.
#[test]
fn test_pipeline_buffer_size_large_value_in_bytes() {
    let c = parse(&pipeline_config_with_buffer_size("4096"));
    assert_eq!(c.pipeline_buffer_size_mb, 4096);
    assert_eq!(c.pipeline_buffer_size_mb * 1024 * 1024, 4_294_967_296);
}

// ---------------------------------------------------------------------------
// libpcap.snaplen
// ---------------------------------------------------------------------------

fn assert_libpcap_snaplen(configured: &str, expected: i32) {
    let c = parse(&libpcap_config_with_snaplen(configured));
    match &c.tasks[0].capturer.kind {
        CapturerKind::Libpcap(l) => {
            assert_eq!(l.snaplen, expected, "libpcap.snaplen {configured}")
        }
        other => panic!("expected libpcap capturer, got {other:?}"),
    }
}

/// `test_libpcap_snaplen_in_range_kept`.
#[test]
fn test_libpcap_snaplen_in_range_kept() {
    assert_libpcap_snaplen("1", 1);
    assert_libpcap_snaplen("2048", 2048);
    assert_libpcap_snaplen("262144", 262144);
}

/// `test_libpcap_snaplen_out_of_range_uses_maximum`: libpcap captures 0 bytes
/// for 0, fails for negatives, and hangs for INT_MAX.
#[test]
fn test_libpcap_snaplen_out_of_range_uses_maximum() {
    for bad in [
        "0",
        "-1",
        "-2147483649",
        "262145",
        "2147483647",
        "2147483648",
        "1e12",
    ] {
        assert_libpcap_snaplen(bad, SNAPLEN_MAX as i32);
    }
}

/// `test_libpcap_snaplen_default`.
#[test]
fn test_libpcap_snaplen_default() {
    let c = parse(
        r#"{"tasks": [{"capturer": {"type": "libpcap", "libpcap": {"interface": "eth0"}}, "outputs": [{"type": "null"}]}]}"#,
    );
    match &c.tasks[0].capturer.kind {
        CapturerKind::Libpcap(l) => assert_eq!(l.snaplen, 2048),
        other => panic!("expected libpcap capturer, got {other:?}"),
    }
}

/// `test_libpcap_snaplen_invalid_rejected`: C expects
/// `"invalid libpcap.snaplen: 1.5, must be an integer"` and
/// `"invalid libpcap.snaplen"`.
#[test]
fn test_libpcap_snaplen_invalid_rejected() {
    reject_naming(&libpcap_config_with_snaplen("1.5"), "libpcap");
    reject_naming(&libpcap_config_with_snaplen("\"2048\""), "libpcap");
}

// ---------------------------------------------------------------------------
// dpdk_pdump.snaplen
// ---------------------------------------------------------------------------

fn assert_dpdk_snaplen(configured: &str, expected: i32) {
    let c = parse(&dpdk_config_with_snaplen(configured));
    match &c.tasks[0].capturer.kind {
        CapturerKind::DpdkPdump(d) => {
            assert_eq!(d.snaplen, expected, "dpdk_pdump.snaplen {configured}")
        }
        other => panic!("expected dpdk_pdump capturer, got {other:?}"),
    }
}

/// `test_dpdk_snaplen`.
#[test]
fn test_dpdk_snaplen() {
    assert_dpdk_snaplen("1", 1);
    assert_dpdk_snaplen("262144", 262144);
    assert_dpdk_snaplen("262145", 262144);
    assert_dpdk_snaplen("2147483648", 262144);
}

/// `test_dpdk_snaplen_invalid_rejected`: C expects
/// `"invalid dpdk_pdump.snaplen"`.
#[test]
fn test_dpdk_snaplen_invalid_rejected() {
    for bad in ["0", "-1", "1.5", "\"2048\""] {
        reject_naming(&dpdk_config_with_snaplen(bad), "dpdk_pdump");
    }
}

// ---------------------------------------------------------------------------
// libpcap.buffer_size_mb
// ---------------------------------------------------------------------------

fn assert_libpcap_buffer_size(configured: &str, expected: i32) {
    let c = parse(&libpcap_config_with_buffer_size(configured));
    match &c.tasks[0].capturer.kind {
        CapturerKind::Libpcap(l) => {
            assert_eq!(l.buffer_size_mb, expected, "buffer_size_mb {configured}")
        }
        other => panic!("expected libpcap capturer, got {other:?}"),
    }
}

/// `test_libpcap_buffer_size_in_range_kept`.
#[test]
fn test_libpcap_buffer_size_in_range_kept() {
    assert_libpcap_buffer_size("1", 1);
    assert_libpcap_buffer_size("2047", 2047);
}

/// `test_libpcap_buffer_size_above_limit_uses_limit`: `pcap_set_buffer_size()`
/// takes an int byte count, so 2047 MB is the largest whole-MB value.
#[test]
fn test_libpcap_buffer_size_above_limit_uses_limit() {
    assert_libpcap_buffer_size("2048", 2047);
    assert_libpcap_buffer_size("8192", 2047);
    assert_libpcap_buffer_size("1e12", 2047);
}

/// `test_libpcap_buffer_size_default`.
#[test]
fn test_libpcap_buffer_size_default() {
    let c = parse(
        r#"{"tasks": [{"capturer": {"type": "libpcap", "libpcap": {"interface": "eth0"}}, "outputs": [{"type": "null"}]}]}"#,
    );
    match &c.tasks[0].capturer.kind {
        CapturerKind::Libpcap(l) => assert_eq!(l.buffer_size_mb, 256),
        other => panic!("expected libpcap capturer, got {other:?}"),
    }
}

/// `test_libpcap_buffer_size_invalid_rejected`: C expects
/// `"invalid libpcap.buffer_size_mb"`.
#[test]
fn test_libpcap_buffer_size_invalid_rejected() {
    for bad in ["0", "-1", "1.5", "\"256\""] {
        reject_naming(&libpcap_config_with_buffer_size(bad), "libpcap");
    }
}

// ---------------------------------------------------------------------------
// output slice
// ---------------------------------------------------------------------------

fn assert_slice(configured: &str, expected: i32) {
    let c = parse(&with_output(&null_output_with_slice(configured)));
    assert_eq!(first_output(&c).slice, expected, "slice {configured}");
}

/// `test_slice_non_negative_kept`.
#[test]
fn test_slice_non_negative_kept() {
    assert_slice("0", 0);
    assert_slice("1", 1);
    assert_slice("64", 64);
    assert_slice("262144", 262144);
}

/// `test_slice_above_int_stored_as_int_max`.
#[test]
fn test_slice_above_int_stored_as_int_max() {
    assert_slice("2147483648", i32::MAX);
}

/// `test_slice_default`.
#[test]
fn test_slice_default() {
    let c = parse(&with_output(r#"{"type": "null"}"#));
    assert_eq!(first_output(&c).slice, 0);
}

/// `test_slice_invalid_rejected`: C expects
/// `"invalid slice: -1, must be >= 0"` and `"invalid slice"`. The fractional
/// and string cases fail in serde before the field validator runs (`slice` is
/// a top-level output field, not a deferred sub-object), so they only need to
/// be rejected.
#[test]
fn test_slice_invalid_rejected() {
    reject_naming(&with_output(&null_output_with_slice("-1")), "slice");
    reject(&with_output(&null_output_with_slice("1.5")));
    reject(&with_output(&null_output_with_slice("\"64\"")));
}

// ---------------------------------------------------------------------------
// vxlan.vni1 / vxlan.vni2
// ---------------------------------------------------------------------------

fn assert_vni(vni_fields: &str, expected_version: u8, expected_vni: u32) {
    let c = parse(&with_output(&vxlan_output_with_vni(vni_fields)));
    match &first_output(&c).kind {
        OutputKind::Vxlan(v) => {
            assert_eq!(v.vni_version, expected_version, "{vni_fields}");
            assert_eq!(v.vni, expected_vni, "{vni_fields}");
        }
        other => panic!("expected vxlan, got {other:?}"),
    }
}

/// `test_vni1_in_range_kept`.
#[test]
fn test_vni1_in_range_kept() {
    assert_vni("\"vni1\": 0", 1, 0);
    assert_vni("\"vni1\": 16777215", 1, 0xFF_FFFF);
}

/// `test_vni1_above_24_bits_keeps_low_24_bits`: the wire only carries the low
/// 24 bits (`vni << 8`), but cpdaemon may send `uint32(serviceTag)` beyond that.
///
/// The C parser normalises `config->vxlan.vni` itself to the low 24 bits; this
/// port stores the full u32 and relies on the `<< 8` shift when the header is
/// built, so the *emitted* VNI is identical. Assert the effective, observable
/// value on the wire here (see the bead status for the representation gap).
#[test]
fn test_vni1_above_24_bits_keeps_low_24_bits() {
    for (input, low24) in [
        (16777216_i64, 0x00_0000_u32),
        (28036591, 0xAB_CDEF),
        (4294967295, 0xFF_FFFF),
    ] {
        let c = parse(&with_output(&vxlan_output_with_vni(&format!(
            "\"vni1\": {input}"
        ))));
        let (vni, version) = match &first_output(&c).kind {
            OutputKind::Vxlan(v) => (v.vni, v.vni_version),
            other => panic!("expected vxlan, got {other:?}"),
        };
        assert_eq!(version, 1);

        let mut buf = [0u8; 64];
        vxlan_encapsulate(&mut buf, vni, version, PKT_DIR_NONCHECK, false, 0, 0, &[]);
        assert_eq!(
            [buf[4], buf[5], buf[6]],
            [
                ((low24 >> 16) & 0xFF) as u8,
                ((low24 >> 8) & 0xFF) as u8,
                (low24 & 0xFF) as u8,
            ],
            "effective VNI for vni1={input}"
        );
    }
}

/// `test_vni1_invalid_rejected`: C expects `"invalid vxlan.vni1"`.
#[test]
fn test_vni1_invalid_rejected() {
    for bad in [
        "\"vni1\": -1",
        "\"vni1\": 4294967296",
        "\"vni1\": 1.5",
        "\"vni1\": \"1\"",
    ] {
        reject_naming(&with_output(&vxlan_output_with_vni(bad)), "vxlan");
    }
}

/// `test_vni2_in_range_kept`.
#[test]
fn test_vni2_in_range_kept() {
    assert_vni("\"vni2\": 0", 2, 0);
    assert_vni("\"vni2\": 4294967295", 2, 0xFFFF_FFFF);
}

/// `test_vni2_invalid_rejected`: C expects `"invalid vxlan.vni2"`.
#[test]
fn test_vni2_invalid_rejected() {
    for bad in [
        "\"vni2\": -1",
        "\"vni2\": 4294967296",
        "\"vni2\": 1.5",
        "\"vni2\": \"1\"",
    ] {
        reject_naming(&with_output(&vxlan_output_with_vni(bad)), "vxlan");
    }
}

/// `test_vni1_and_vni2_mutually_exclusive`: C expects
/// `"vxlan.vni1 and vxlan.vni2 are mutually exclusive"`.
#[test]
fn test_vni1_and_vni2_mutually_exclusive() {
    reject_naming(
        &with_output(&vxlan_output_with_vni("\"vni1\": 1, \"vni2\": 2")),
        "mutually exclusive",
    );
}

/// `test_vni_missing_rejected`: C expects `"require vxlan.vni1 or vxlan.vni2"`.
#[test]
fn test_vni_missing_rejected() {
    reject_naming(
        &with_output(r#"{"type": "vxlan", "vxlan": {"host": "10.0.0.1"}}"#),
        "require vxlan.vni1 or vxlan.vni2",
    );
}

// ---------------------------------------------------------------------------
// vxlan.split.max_payload_size
// ---------------------------------------------------------------------------

fn assert_max_payload_size(vxlan_output_json: &str, expected: u16) {
    let c = parse(&with_output(vxlan_output_json));
    match &first_output(&c).kind {
        OutputKind::Vxlan(v) => {
            assert_eq!(v.split.max_payload_size, expected, "{vxlan_output_json}")
        }
        other => panic!("expected vxlan, got {other:?}"),
    }
}

/// `test_split_max_payload_size_in_range_kept`.
#[test]
fn test_split_max_payload_size_in_range_kept() {
    assert_max_payload_size(&split_with_max_payload_size("0"), 0);
    assert_max_payload_size(&split_with_max_payload_size("1"), 1);
    assert_max_payload_size(&split_with_max_payload_size("65535"), 65535);
}

/// `test_split_max_payload_size_default`.
#[test]
fn test_split_max_payload_size_default() {
    assert_max_payload_size(&vxlan_output_with_vni("\"vni1\": 1"), 0);
    assert_max_payload_size(&vxlan_output_with_split("{}"), 0);
}

/// `test_split_max_payload_size_invalid_rejected`: C expects
/// `"invalid vxlan.split.max_payload_size"`.
#[test]
fn test_split_max_payload_size_invalid_rejected() {
    for bad in ["-1", "65536", "1.5", "-0.5", "1e20", "\"100\""] {
        reject_naming(
            &with_output(&split_with_max_payload_size(bad)),
            "vxlan.split",
        );
    }
}

// ---------------------------------------------------------------------------
// service_tag
// ---------------------------------------------------------------------------

/// `test_zmq_service_tag_uint32_kept`: 12 bits reach the per-packet MPLS label;
/// larger values are kept because the batch header's keybit carries all 32 bits.
#[test]
fn test_zmq_service_tag_uint32_kept() {
    let values = ["0", "4095", "4096", "4294967295"];
    let expected: [u32; 4] = [0, 4095, 4096, 0xFFFF_FFFF];
    for (value, want) in values.iter().zip(expected) {
        let c = parse(&with_output(&zmq_output_with_service_tag(value)));
        match &first_output(&c).kind {
            OutputKind::Zmq(z) => assert_eq!(z.service_tag, want, "zmq.service_tag {value}"),
            other => panic!("expected zmq, got {other:?}"),
        }
    }
}

/// `test_zmq_service_tag_default`.
#[test]
fn test_zmq_service_tag_default() {
    let c = parse(&with_output(&zmq_output_with_port("5555")));
    match &first_output(&c).kind {
        OutputKind::Zmq(z) => assert_eq!(z.service_tag, 0xFFFF_FFFF),
        other => panic!("expected zmq, got {other:?}"),
    }
}

/// `test_zmq_service_tag_invalid_rejected`: C expects
/// `"invalid zmq.service_tag"`.
#[test]
fn test_zmq_service_tag_invalid_rejected() {
    for bad in ["-1", "4294967296", "1.5", "\"1\""] {
        reject_naming(&with_output(&zmq_output_with_service_tag(bad)), "zmq");
    }
}

/// `test_gre_service_tag_uint32_kept`: the high 4 bits of the GRE key carry
/// the direction; larger tags are kept.
#[test]
fn test_gre_service_tag_uint32_kept() {
    let values = ["0", "268435455", "268435456", "4294967295"];
    let expected: [u32; 4] = [0, 0x0FFF_FFFF, 0x1000_0000, 0xFFFF_FFFF];
    for (value, want) in values.iter().zip(expected) {
        let c = parse(&with_output(&gre_output_with_service_tag(value)));
        match &first_output(&c).kind {
            OutputKind::Gre(g) => assert_eq!(g.service_tag, want, "gre.service_tag {value}"),
            other => panic!("expected gre, got {other:?}"),
        }
    }
}

/// `test_gre_service_tag_default`.
#[test]
fn test_gre_service_tag_default() {
    let c = parse(&with_output(
        r#"{"type": "gre", "gre": {"host": "10.0.0.1"}}"#,
    ));
    match &first_output(&c).kind {
        OutputKind::Gre(g) => assert_eq!(g.service_tag, 0xFFFF_FFFF),
        other => panic!("expected gre, got {other:?}"),
    }
}

/// `test_gre_service_tag_invalid_rejected`: C expects
/// `"invalid gre.service_tag"`.
#[test]
fn test_gre_service_tag_invalid_rejected() {
    for bad in ["-1", "4294967296", "1.5", "\"1\""] {
        reject_naming(&with_output(&gre_output_with_service_tag(bad)), "gre");
    }
}

// ---------------------------------------------------------------------------
// zmq.hwm
// ---------------------------------------------------------------------------

/// `test_zmq_hwm_non_negative_kept`: 0 is libzmq's "no limit"; values beyond
/// int are equally unbounded.
#[test]
fn test_zmq_hwm_non_negative_kept() {
    let cases = [("0", 0), ("1", 1), ("1000", 1000), ("2147483648", i32::MAX)];
    for (value, want) in cases {
        let c = parse(&with_output(&zmq_output_with_hwm(value)));
        match &first_output(&c).kind {
            OutputKind::Zmq(z) => assert_eq!(z.hwm, want, "zmq.hwm {value}"),
            other => panic!("expected zmq, got {other:?}"),
        }
    }
}

/// `test_zmq_hwm_default`.
#[test]
fn test_zmq_hwm_default() {
    let c = parse(&with_output(&zmq_output_with_port("5555")));
    match &first_output(&c).kind {
        OutputKind::Zmq(z) => assert_eq!(z.hwm, 100),
        other => panic!("expected zmq, got {other:?}"),
    }
}

/// `test_zmq_hwm_invalid_rejected`: C expects
/// `"invalid zmq.hwm: -1, must be >= 0"` and `"invalid zmq.hwm"`.
#[test]
fn test_zmq_hwm_invalid_rejected() {
    for bad in ["-1", "1.5", "\"100\""] {
        reject_naming(&with_output(&zmq_output_with_hwm(bad)), "zmq");
    }
}

// ---------------------------------------------------------------------------
// rotating_file.max_file_interval
// ---------------------------------------------------------------------------

/// `test_max_file_interval_non_negative_kept`: unset used to be -1, which
/// truncated the file on every packet.
#[test]
fn test_max_file_interval_non_negative_kept() {
    let cases = [("0", 0), ("1", 1), ("3600", 3600), ("2147483648", i32::MAX)];
    for (value, want) in cases {
        let c = parse(&with_output(&rotating_file_output_with_interval(value)));
        match &first_output(&c).kind {
            OutputKind::RotatingFile(r) => {
                assert_eq!(r.max_file_interval, want, "max_file_interval {value}")
            }
            other => panic!("expected rotating_file, got {other:?}"),
        }
    }
}

/// `test_max_file_interval_default`.
#[test]
fn test_max_file_interval_default() {
    let c = parse(&with_output(
        r#"{"type": "rotating_file", "rotating_file": {"file_root": "/tmp"}}"#,
    ));
    match &first_output(&c).kind {
        OutputKind::RotatingFile(r) => assert_eq!(r.max_file_interval, 60),
        other => panic!("expected rotating_file, got {other:?}"),
    }
}

/// `test_max_file_interval_invalid_rejected`: C expects
/// `"invalid rotating_file.max_file_interval: -1, must be >= 0"` and
/// `"invalid rotating_file.max_file_interval"`.
#[test]
fn test_max_file_interval_invalid_rejected() {
    for bad in ["-1", "1.5", "\"60\""] {
        reject_naming(
            &with_output(&rotating_file_output_with_interval(bad)),
            "rotating_file",
        );
    }
}

// ---------------------------------------------------------------------------
// dpdk_pdump.ring_size
// ---------------------------------------------------------------------------

/// `test_dpdk_ring_size_in_range_kept`: the ring is rounded up to a power of
/// two; 2^30 is the largest one `rte_ring_create()` accepts.
#[test]
fn test_dpdk_ring_size_in_range_kept() {
    for (value, want) in [("2", 2), ("1000", 1000), ("1073741824", 1 << 30)] {
        let c = parse(&dpdk_config_with_ring_size(value));
        match &c.tasks[0].capturer.kind {
            CapturerKind::DpdkPdump(d) => assert_eq!(d.ring_size, want, "ring_size {value}"),
            other => panic!("expected dpdk_pdump capturer, got {other:?}"),
        }
    }
}

/// `test_dpdk_ring_size_default`.
#[test]
fn test_dpdk_ring_size_default() {
    let c = parse(
        r#"{"tasks": [{"capturer": {"type": "dpdk_pdump", "dpdk_pdump": {"interface": "0000:00:00.0"}}, "outputs": [{"type": "null"}]}]}"#,
    );
    match &c.tasks[0].capturer.kind {
        CapturerKind::DpdkPdump(d) => assert_eq!(d.ring_size, 2048),
        other => panic!("expected dpdk_pdump capturer, got {other:?}"),
    }
}

/// `test_dpdk_ring_size_invalid_rejected`: C expects
/// `"invalid dpdk_pdump.ring_size"`.
#[test]
fn test_dpdk_ring_size_invalid_rejected() {
    for bad in ["0", "1", "-1", "1073741825", "1.5", "\"2048\""] {
        reject_naming(&dpdk_config_with_ring_size(bad), "dpdk_pdump");
    }
}

// ---------------------------------------------------------------------------
// output rate_limit_mbps
// ---------------------------------------------------------------------------

/// `test_rate_limit_non_negative_kept`: values beyond int are stored as INT_MAX
/// Mbps, which is unlimited in practice.
#[test]
fn test_rate_limit_non_negative_kept() {
    let cases = [
        ("0", 0_u64),
        ("1", 1),
        ("10000", 10000),
        ("2147483648", i32::MAX as u64),
    ];
    for (value, want) in cases {
        let c = parse(&with_output(&null_output_with_rate_limit(value)));
        assert_eq!(first_output(&c).rate_limit_mbps, want, "rate_limit {value}");
    }
}

/// `test_rate_limit_default`.
#[test]
fn test_rate_limit_default() {
    let c = parse(&with_output(r#"{"type": "null"}"#));
    assert_eq!(first_output(&c).rate_limit_mbps, 0);
}

/// `test_rate_limit_invalid_rejected`: C expects
/// `"invalid rate_limit_mbps: -1, must be >= 0"` and `"invalid rate_limit_mbps"`.
/// The fractional/string cases fail in serde before the field validator runs
/// (`rate_limit_mbps` is a top-level output field), so they only need to be
/// rejected.
#[test]
fn test_rate_limit_invalid_rejected() {
    reject_naming(
        &with_output(&null_output_with_rate_limit("-1")),
        "rate_limit_mbps",
    );
    for bad in ["1.5", "-0.5", "\"10\""] {
        reject(&with_output(&null_output_with_rate_limit(bad)));
    }
}

// ---------------------------------------------------------------------------
// libpcap.timeout_ms
// ---------------------------------------------------------------------------

/// `test_timeout_non_negative_kept`.
#[test]
fn test_timeout_non_negative_kept() {
    let cases = [("0", 0), ("10", 10), ("2147483648", i32::MAX)];
    for (value, want) in cases {
        let c = parse(&libpcap_config_with_timeout(value));
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.timeout_ms, want, "timeout_ms {value}"),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }
    }
}

/// `test_timeout_default`.
#[test]
fn test_timeout_default() {
    let c = parse(
        r#"{"tasks": [{"capturer": {"type": "libpcap", "libpcap": {"interface": "eth0"}}, "outputs": [{"type": "null"}]}]}"#,
    );
    match &c.tasks[0].capturer.kind {
        CapturerKind::Libpcap(l) => assert_eq!(l.timeout_ms, 0),
        other => panic!("expected libpcap capturer, got {other:?}"),
    }
}

/// `test_timeout_invalid_rejected`: C expects
/// `"invalid libpcap.timeout_ms: -1, must be >= 0"` and
/// `"invalid libpcap.timeout_ms"`.
#[test]
fn test_timeout_invalid_rejected() {
    for bad in ["-1", "1.5", "-0.5", "\"10\""] {
        reject_naming(&libpcap_config_with_timeout(bad), "libpcap");
    }
}

// ---------------------------------------------------------------------------
// zmq.heartbeat_ms
// ---------------------------------------------------------------------------

/// `test_heartbeat_in_range_kept`.
#[test]
fn test_heartbeat_in_range_kept() {
    for (value, want) in [("0", 0), ("2000", 2000), ("60000", 60000)] {
        let c = parse(&with_output(&zmq_output_with_heartbeat(value)));
        match &first_output(&c).kind {
            OutputKind::Zmq(z) => assert_eq!(z.heartbeat_ms, want, "heartbeat_ms {value}"),
            other => panic!("expected zmq, got {other:?}"),
        }
    }
}

/// `test_heartbeat_default`.
#[test]
fn test_heartbeat_default() {
    let c = parse(&with_output(&zmq_output_with_port("5555")));
    match &first_output(&c).kind {
        OutputKind::Zmq(z) => assert_eq!(z.heartbeat_ms, 0),
        other => panic!("expected zmq, got {other:?}"),
    }
}

/// `test_heartbeat_invalid_rejected`: C expects
/// `"invalid zmq.heartbeat_ms: 60001, must be an integer in [0, 60000]"`.
#[test]
fn test_heartbeat_invalid_rejected() {
    for bad in ["60001", "-1", "1.5", "-0.5", "2147483648", "\"2000\""] {
        reject_naming(&with_output(&zmq_output_with_heartbeat(bad)), "zmq");
    }
    let err = Config::parse_str(&with_output(&zmq_output_with_heartbeat("60001")))
        .expect_err("60001 is out of range");
    let msg = err.to_string();
    assert!(
        msg.contains("zmq.heartbeat_ms"),
        "must name the field: {msg}"
    );
    assert!(msg.contains("60000"), "must name the bound: {msg}");
}
