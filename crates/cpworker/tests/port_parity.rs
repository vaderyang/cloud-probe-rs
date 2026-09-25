//! Regression tests ported verbatim from the original C unit test suite.
//!
//! Sources:
//! * `cpworker/tests/unit/misc.c` (config, bpf filter, req_pattern, affinity)
//! * `cpworker/tests/unit/packet_split.c` (covered far more exhaustively by the
//!   C/Rust differential harness in `parity/`)
//!
//! These assert the exact values the C tests asserted, so passing them is
//! evidence of behavioural parity on those inputs.

use cpworker::affinity::{cpu_set_parse, set_cpu_affinity};
use cpworker::config::{bpf_filter_exclude_task_output_hosts, Config, OutputKind};
use cpworker::packet::IpAddr;
use cpworker::req_pattern::{custom_match_by_ipport, parse_pattern};

// ---------------------------------------------------------------------------
// Config fixtures (byte-identical to misc.c)
// ---------------------------------------------------------------------------

const CONFIG_LIBPCAP_GRE: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "gre", "rate_limit_mbps": 10, "gre": {"host": "172.16.1.201", "bind_device": "eth1"}}]}]}"#;

const CONFIG_LIBPCAP_GRE_VXLAN: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "gre", "rate_limit_mbps": 10, "gre": {"host": "172.16.1.201", "bind_device": "eth1"}}, {"type": "vxlan", "rate_limit_mbps": 10, "vxlan": {"host": "172.16.1.202", "port": 4789, "vni1": 2147483648, "bind_device": "eth1"}}]}]}"#;

const CONFIG_TWO_TASKS_VXLAN: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "ens192", "snaplen": 65535, "buffer_size_mb": 256}}, "outputs": [{"type": "vxlan", "vxlan": {"host": "172.16.206.40", "port": 4788, "vni1": 123}}]},{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "ens192", "snaplen": 65535, "buffer_size_mb": 256}}, "outputs": [{"type": "vxlan", "vxlan": {"host": "172.16.206.24", "port": 4788, "vni1": 234}}]}]}"#;

const CONFIG_TWO_TASKS_SHARED_HOST: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "gre", "gre": {"host": "172.16.1.201", "bind_device": "eth1"}}]},{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "gre", "gre": {"host": "172.16.1.201", "bind_device": "eth1"}}]}]}"#;

const CONFIG_ZMQ_HEARTBEAT: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "zmq", "zmq": {"host": "10.0.0.1", "port": 5555, "hwm": 100, "service_tag": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "heartbeat_ms": 2000}}]}]}"#;
const CONFIG_ZMQ_HEARTBEAT_DEFAULT: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "zmq", "zmq": {"host": "10.0.0.1", "port": 5555, "hwm": 100, "service_tag": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000"}}]}]}"#;
const CONFIG_ZMQ_HEARTBEAT_DISABLED: &str = r#"{"tasks": [{"req_pattern": {"type": "auto"}, "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0", "snaplen": 2048, "buffer_size_mb": 256}}, "outputs": [{"type": "zmq", "zmq": {"host": "10.0.0.1", "port": 5555, "hwm": 100, "service_tag": 1, "uuid": "550e8400-e29b-41d4-a716-446655440000", "heartbeat_ms": 0}}]}]}"#;

fn parse(json: &str) -> Config {
    Config::parse_str(json).expect("config should parse")
}

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<std::net::Ipv4Addr>().unwrap().octets())
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
}

fn matches(pattern: &str, ip: &IpAddr, port: u16) -> bool {
    let ast = parse_pattern(pattern).expect("pattern should parse");
    custom_match_by_ipport(&ast, ip, port)
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

#[test]
fn test_parse_config_data_for_libpcap_gre_vxlan() {
    let c = parse(CONFIG_LIBPCAP_GRE_VXLAN);
    match &c.tasks[0].outputs[1].kind {
        OutputKind::Vxlan(v) => assert_eq!(v.vni, 2147483648),
        _ => panic!("expected vxlan"),
    }
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_1() {
    let c = parse(CONFIG_LIBPCAP_GRE);
    let bpf = bpf_filter_exclude_task_output_hosts("", &c.tasks);
    assert_eq!(bpf, "not host 172.16.1.201");
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_2() {
    let c = parse(CONFIG_LIBPCAP_GRE);
    let bpf = bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", &c.tasks);
    assert_eq!(bpf, "(host 10.1.1.1 and port 8011) and not host 172.16.1.201");
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_3() {
    let c = parse(CONFIG_LIBPCAP_GRE_VXLAN);
    let bpf = bpf_filter_exclude_task_output_hosts("", &c.tasks);
    assert_eq!(bpf, "not host 172.16.1.201 and not host 172.16.1.202");
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_4() {
    let c = parse(CONFIG_LIBPCAP_GRE_VXLAN);
    let bpf = bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", &c.tasks);
    assert_eq!(
        bpf,
        "(host 10.1.1.1 and port 8011) and not host 172.16.1.201 and not host 172.16.1.202"
    );
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_5() {
    let c = parse(CONFIG_TWO_TASKS_VXLAN);
    let bpf = bpf_filter_exclude_task_output_hosts("", &c.tasks);
    assert_eq!(bpf, "not host 172.16.206.40 and not host 172.16.206.24");
}

#[test]
fn test_bpf_filter_exclude_task_output_hosts_6() {
    let c = parse(CONFIG_TWO_TASKS_SHARED_HOST);
    let bpf = bpf_filter_exclude_task_output_hosts("", &c.tasks);
    assert_eq!(bpf, "not host 172.16.1.201");
}

#[test]
fn test_parse_zmq_heartbeat_ms_explicit() {
    let c = parse(CONFIG_ZMQ_HEARTBEAT);
    match &c.tasks[0].outputs[0].kind {
        OutputKind::Zmq(z) => assert_eq!(z.heartbeat_ms, 2000),
        _ => panic!("expected zmq"),
    }
}

#[test]
fn test_parse_zmq_heartbeat_ms_default() {
    let c = parse(CONFIG_ZMQ_HEARTBEAT_DEFAULT);
    match &c.tasks[0].outputs[0].kind {
        OutputKind::Zmq(z) => assert_eq!(z.heartbeat_ms, 0),
        _ => panic!("expected zmq"),
    }
}

#[test]
fn test_parse_zmq_heartbeat_ms_disabled() {
    let c = parse(CONFIG_ZMQ_HEARTBEAT_DISABLED);
    match &c.tasks[0].outputs[0].kind {
        OutputKind::Zmq(z) => assert_eq!(z.heartbeat_ms, 0),
        _ => panic!("expected zmq"),
    }
}

// ---------------------------------------------------------------------------
// req_pattern
// ---------------------------------------------------------------------------

#[test]
fn test_req_pattern_custom_multi_host_and_one_port() {
    let p = "(host 172.16.1.1 or host 172.16.1.2) and port 8011";
    let (i1, i2, i3) = (v4("172.16.1.1"), v4("172.16.1.2"), v4("172.16.1.3"));
    assert!(matches(p, &i1, 8011));
    assert!(!matches(p, &i1, 8012));
    assert!(matches(p, &i2, 8011));
    assert!(!matches(p, &i2, 8012));
    assert!(!matches(p, &i3, 8011));
}

#[test]
fn test_req_pattern_custom_one_host_and_multi_port() {
    let p = "host 172.16.1.1 and (port 8011 or port 8012)";
    let (i1, i2) = (v4("172.16.1.1"), v4("172.16.1.2"));
    assert!(matches(p, &i1, 8011));
    assert!(matches(p, &i1, 8012));
    assert!(!matches(p, &i1, 8013));
    assert!(!matches(p, &i2, 8011));
    assert!(!matches(p, &i2, 8012));
}

#[test]
fn test_req_pattern_invalid() {
    assert!(parse_pattern("not host nic.eth0").is_err());
}

#[test]
fn test_req_pattern_custom_simple_host_only() {
    let p = "host 10.0.0.1";
    assert!(matches(p, &v4("10.0.0.1"), 0));
    assert!(matches(p, &v4("10.0.0.1"), 12345));
    assert!(!matches(p, &v4("10.0.0.2"), 0));
}

#[test]
fn test_req_pattern_custom_simple_port_only() {
    let p = "port 443";
    let ip = v4("1.2.3.4");
    assert!(matches(p, &ip, 443));
    assert!(!matches(p, &ip, 80));
    assert!(!matches(p, &ip, 0));
}

#[test]
fn test_req_pattern_custom_or_hosts() {
    let p = "host 10.0.0.1 or host 10.0.0.2";
    assert!(matches(p, &v4("10.0.0.1"), 0));
    assert!(matches(p, &v4("10.0.0.2"), 0));
    assert!(!matches(p, &v4("10.0.0.3"), 0));
}

#[test]
fn test_req_pattern_custom_or_ports() {
    let p = "port 80 or port 443";
    let ip = v4("1.2.3.4");
    assert!(matches(p, &ip, 80));
    assert!(matches(p, &ip, 443));
    assert!(!matches(p, &ip, 8080));
}

#[test]
fn test_req_pattern_custom_nested_parens() {
    let p = "((host 10.0.0.1 or host 10.0.0.2) and port 80) or port 443";
    let (i1, i2, i3) = (v4("10.0.0.1"), v4("10.0.0.2"), v4("10.0.0.3"));
    assert!(matches(p, &i1, 80));
    assert!(matches(p, &i2, 80));
    assert!(matches(p, &i1, 443));
    assert!(matches(p, &i3, 443));
    assert!(!matches(p, &i1, 8080));
    assert!(!matches(p, &i3, 80));
}

#[test]
fn test_req_pattern_custom_ipv6() {
    let p = "host ::1 and port 8080";
    assert!(matches(p, &v6("::1"), 8080));
    assert!(!matches(p, &v6("::1"), 80));
    assert!(!matches(p, &v6("::2"), 8080));
}

#[test]
fn test_req_pattern_custom_ipv6_full() {
    let p = "host 2001:db8::1 and port 443";
    assert!(matches(p, &v6("2001:db8::1"), 443));
    assert!(!matches(p, &v6("2001:db8::1"), 80));
}

#[test]
fn test_req_pattern_invalid_port_non_numeric() {
    assert!(parse_pattern("port abc").is_err());
}

#[test]
fn test_req_pattern_invalid_port_out_of_range() {
    assert!(parse_pattern("port 99999").is_err());
}

#[test]
fn test_req_pattern_invalid_port_negative() {
    assert!(parse_pattern("port -1").is_err());
}

#[test]
fn test_req_pattern_invalid_host() {
    assert!(parse_pattern("host not_an_ip").is_err());
}

#[test]
fn test_req_pattern_invalid_nic_not_exist() {
    assert!(parse_pattern("host nic.eth999").is_err());
}

#[test]
fn test_req_pattern_invalid_empty_pattern() {
    assert!(parse_pattern("").is_err());
}

#[test]
fn test_req_pattern_invalid_unmatched_paren() {
    assert!(parse_pattern("(host 10.0.0.1 and port 80").is_err());
}

#[test]
fn test_req_pattern_invalid_missing_value() {
    assert!(parse_pattern("host and port 80").is_err());
}

#[test]
fn test_req_pattern_custom_port_zero() {
    let p = "port 0";
    assert!(matches(p, &v4("1.2.3.4"), 0));
    assert!(!matches(p, &v4("1.2.3.4"), 1));
}

#[test]
fn test_req_pattern_custom_port_65535() {
    let p = "port 65535";
    assert!(matches(p, &v4("1.2.3.4"), 65535));
    assert!(!matches(p, &v4("1.2.3.4"), 65534));
}

#[test]
fn test_req_pattern_custom_and_precedence_over_or() {
    let p = "host 10.0.0.1 or host 10.0.0.2 and port 80";
    assert!(matches(p, &v4("10.0.0.1"), 0));
    assert!(matches(p, &v4("10.0.0.1"), 9999));
    assert!(matches(p, &v4("10.0.0.2"), 80));
    assert!(!matches(p, &v4("10.0.0.2"), 81));
    assert!(!matches(p, &v4("10.0.0.3"), 80));
}

#[test]
fn test_req_pattern_custom_extra_whitespace() {
    let p = "  host   10.0.0.1   and   port   80  ";
    assert!(matches(p, &v4("10.0.0.1"), 80));
    assert!(!matches(p, &v4("10.0.0.1"), 81));
}

// ---------------------------------------------------------------------------
// affinity (Linux)
// ---------------------------------------------------------------------------

#[test]
fn test_cpu_set_parse() {
    assert_eq!(cpu_set_parse("1").unwrap().len(), 1);
    assert_eq!(cpu_set_parse("0,1,2").unwrap().len(), 3);
    assert_eq!(cpu_set_parse("0-1").unwrap().len(), 2);
    assert_eq!(cpu_set_parse("0-1,2").unwrap().len(), 3);
    assert_eq!(cpu_set_parse("2,0-1").unwrap().len(), 3);

    assert!(cpu_set_parse(",").is_err());
    assert!(cpu_set_parse(",1").is_err());
    assert!(cpu_set_parse("1-,2").is_err());
    assert!(cpu_set_parse("1,,2").is_err());
    assert!(cpu_set_parse("-1").is_err());
    assert!(cpu_set_parse("abc").is_err());
    assert!(cpu_set_parse("3-1").is_err());
    assert!(cpu_set_parse("1,").is_err());

    assert_eq!(cpu_set_parse("").unwrap().len(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn test_set_cpu_affinity_out_of_range() {
    // CPU indices beyond `CPU_SETSIZE` must be rejected rather than reaching
    // libc's `CPU_SET`, which would panic on the fixed-size bitmask.
    let too_big = u32::MAX.to_string();
    assert!(set_cpu_affinity(&too_big).is_err());
}
