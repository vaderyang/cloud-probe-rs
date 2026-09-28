//! Configuration model and parser. Port of `config.c` (cJSON -> serde_json).
//!
//! The on-disk JSON schema is unchanged so existing config files keep working.

use serde::Deserialize;
use std::path::Path;

use crate::error::{Error, Result};
use crate::netutil::bpf_filter_replace_nic;

/// Capturer type string: DPDK pdump (not yet ported).
pub const CAPTURER_TYPE_DPDK_PDUMP: &str = "dpdk_pdump";
/// Capturer type string: libpcap live capture.
pub const CAPTURER_TYPE_LIBPCAP: &str = "libpcap";
/// Capturer type string: offline pcap file replay.
pub const CAPTURER_TYPE_PCAP_FILE: &str = "pcap_file";

/// Req-pattern type string: no direction matching.
pub const REQ_PATTERN_TYPE_NONE_STR: &str = "none";
/// Req-pattern type string: automatic MAC-based matching.
pub const REQ_PATTERN_TYPE_AUTO_STR: &str = "auto";
/// Req-pattern type string: custom expression matching.
pub const REQ_PATTERN_TYPE_CUSTOM_STR: &str = "custom";

/// Output type string: VXLAN tunnel.
pub const OUTPUT_TYPE_VXLAN: &str = "vxlan";
/// Output type string: GRE tunnel.
pub const OUTPUT_TYPE_GRE: &str = "gre";
/// Output type string: ZMQ batch push.
pub const OUTPUT_TYPE_ZMQ: &str = "zmq";
/// Output type string: single pcap file.
pub const OUTPUT_TYPE_FILE: &str = "file";
/// Output type string: rotating pcap files.
pub const OUTPUT_TYPE_ROTATING_FILE: &str = "rotating_file";
/// Output type string: discard (null sink).
pub const OUTPUT_TYPE_NULL: &str = "null";

/// Control channel type string: unix domain socket.
pub const CONTROL_TYPE_UNIX: &str = "unix";

/// `IP_MTU_DISCOVER` mode: never set DF.
pub const IP_PMTUDISC_DONT: i32 = 0;
/// `IP_MTU_DISCOVER` mode: kernel default / want DF.
pub const IP_PMTUDISC_WANT: i32 = 1;
/// `IP_MTU_DISCOVER` mode: always set DF.
pub const IP_PMTUDISC_DO: i32 = 2;
/// `IP_MTU_DISCOVER` mode: probe path MTU without sending.
pub const IP_PMTUDISC_PROBE: i32 = 3;

/// Log level: trace.
pub const LOG_TRACE: i32 = 0;
/// Log level: debug.
pub const LOG_DEBUG: i32 = 1;
/// Log level: info.
pub const LOG_INFO: i32 = 2;
/// Log level: warning.
pub const LOG_WARN: i32 = 3;
/// Log level: error.
pub const LOG_ERROR: i32 = 4;
/// Log level: fatal.
pub const LOG_FATAL: i32 = 5;

// --- Numeric configuration limits (AUDIT4 P5-15) ---------------------------
//
// `serde_json` hands every JSON number to us as `i64`, while the runtime
// structs use `i32`/`u16`/`u64`. Casting with `as` wraps silently, so the
// limits below are enforced at parse time and the values are converted with
// `TryFrom`. They are public because the C/Rust differential harness and the
// worker documentation both have to quote them.

/// Default `snaplen` when the key is absent (C: `config.c`).
pub const DEFAULT_SNAPLEN: i64 = 2_048;
/// Default `libpcap.buffer_size_mb` when the key is absent.
pub const DEFAULT_BUFFER_SIZE_MB: i64 = 256;
/// Default `libpcap.timeout_ms` when the key is absent (0 = no timeout).
pub const DEFAULT_TIMEOUT_MS: i64 = 0;
/// Default `dpdk_pdump.ring_size` when the key is absent.
pub const DEFAULT_RING_SIZE: i64 = 2_048;
/// Smallest accepted `snaplen`. `0` keeps the backend's own default (the C
/// parser accepted it too).
pub const SNAPLEN_MIN: i64 = 0;
/// Largest accepted `snaplen`: libpcap's own maximum snapshot length, which is
/// also the largest value a pcap savefile can record (see `CapturerKind::snaplen`
/// for the offline replay default).
pub const SNAPLEN_MAX: i64 = 262_144;
/// Smallest accepted `libpcap.buffer_size_mb` (0 = OS default).
pub const BUFFER_SIZE_MB_MIN: i64 = 0;
/// Largest accepted `libpcap.buffer_size_mb` (8 GiB). Far above any
/// `net.core.rmem_max`; larger values are a mistake, not a tuning request.
pub const BUFFER_SIZE_MB_MAX: i64 = 8_192;
/// Smallest accepted `libpcap.timeout_ms` (0 = non-blocking / no timeout).
pub const TIMEOUT_MS_MIN: i64 = 0;
/// Largest accepted `libpcap.timeout_ms` (10 minutes).
pub const TIMEOUT_MS_MAX: i64 = 600_000;
/// Smallest accepted `dpdk_pdump.ring_size`.
pub const RING_SIZE_MIN: i64 = 1;
/// Largest accepted `dpdk_pdump.ring_size` (2^20 descriptors).
pub const RING_SIZE_MAX: i64 = 1_048_576;
/// Smallest accepted `pipeline.buffer_size_mb` (must be positive).
pub const PIPELINE_BUFFER_MB_MIN: i64 = 1;
/// Largest accepted `pipeline.buffer_size_mb` (8 GiB).
pub const PIPELINE_BUFFER_MB_MAX: i64 = 8_192;
/// Smallest accepted output `slice` (0 = no truncation).
pub const SLICE_MIN: i64 = 0;
/// Largest accepted output `slice`: bigger than any frame, so it already means
/// "never truncate".
pub const SLICE_MAX: i64 = 65_535;
/// Smallest accepted `rate_limit_mbps` (0 = unlimited).
pub const RATE_LIMIT_MBPS_MIN: i64 = 0;
/// Largest accepted `rate_limit_mbps` (1 Tbps). Consumers multiply it by 1e6 to
/// get bytes/second, so an unbounded value overflows the token bucket.
pub const RATE_LIMIT_MBPS_MAX: i64 = 1_000_000;
/// Smallest accepted `rotating_file.max_file_interval` (-1 = rotate on error
/// only, which is also the C default).
pub const MAX_FILE_INTERVAL_MIN: i64 = -1;
/// Largest accepted `rotating_file.max_file_interval`, in seconds (1 year).
pub const MAX_FILE_INTERVAL_MAX: i64 = 31_536_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Task execution model.
pub enum ExecutionModel {
    /// Run-to-completion: each task forwards packets inline.
    Rtc,
    /// Pipeline: capturers enqueue into a shared ring; an output thread drains it.
    Pipeline,
}

#[derive(Debug, Clone, Default)]
/// VXLAN output fragmentation settings.
pub struct SplitConfig {
    /// Maximum payload size per fragment, in bytes.
    pub max_payload_size: u16,
    /// Recompute inner packet checksums after splitting.
    pub recalculate_checksum: bool,
}

#[derive(Debug, Clone)]
/// VXLAN output configuration.
pub struct VxlanConfig {
    /// Remote tunnel endpoint host.
    pub host: String,
    /// Remote tunnel endpoint UDP port.
    pub port: u16,
    /// Include a capture timestamp in the VXLAN header.
    pub capture_time: bool,
    /// VXLAN header version.
    pub vni_version: u8,
    /// VXLAN network identifier (VNI).
    pub vni: u32,
    /// Restrict the tunnel socket to this interface (`SO_BINDTODEVICE`).
    pub bind_device: String,
    /// Path-MTU-discovery mode (`IP_PMTUDISC_*`).
    pub pmtudisc: i32,
    /// Fragmentation settings.
    pub split: SplitConfig,
}

#[derive(Debug, Clone)]
/// GRE output configuration.
pub struct GreConfig {
    /// Remote tunnel endpoint host.
    pub host: String,
    /// Service tag written into the GRE header.
    pub service_tag: u32,
    /// Restrict the tunnel socket to this interface (`SO_BINDTODEVICE`).
    pub bind_device: String,
    /// Path-MTU-discovery mode (`IP_PMTUDISC_*`).
    pub pmtudisc: i32,
}

/// Default ZMQ high-water mark (queued batches).
pub const DEFAULT_ZMQ_HWM: i32 = 100;
/// Smallest accepted ZMQ high-water mark.
pub const ZMQ_HWM_MIN: i32 = 1;
/// Largest accepted ZMQ high-water mark. Each queued batch can be up to 1 MiB,
/// so this caps the message-count bound of the pending queue.
pub const ZMQ_HWM_MAX: i32 = 4096;

#[derive(Debug, Clone)]
/// ZMQ output configuration.
pub struct ZmqConfig {
    /// Collector host.
    pub host: String,
    /// Collector port.
    pub port: u16,
    /// ZMQ high-water mark, in queued batches.
    ///
    /// Validated against [`ZMQ_HWM_MIN`]..=[`ZMQ_HWM_MAX`]; each queued batch is
    /// at most 1 MiB, so this is also the memory bound of the output.
    pub hwm: i32,
    /// Service tag stamped into each batch.
    pub service_tag: u32,
    /// Probe UUID string.
    pub uuid: String,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_ms: i32,
}

#[derive(Debug, Clone)]
/// Single pcap file output configuration.
pub struct FileConfig {
    /// Destination file name.
    pub name: String,
}

#[derive(Debug, Clone)]
/// Rotating pcap file output configuration.
pub struct RotatingFileConfig {
    /// Root directory for the generated files.
    pub file_root: String,
    /// Maximum interval between file rotations, in seconds.
    pub max_file_interval: i32,
}

#[derive(Debug, Clone)]
/// Output backend selection and its configuration.
pub enum OutputKind {
    /// VXLAN tunnel output.
    Vxlan(VxlanConfig),
    /// GRE tunnel output.
    Gre(GreConfig),
    /// ZMQ batch output.
    Zmq(ZmqConfig),
    /// Single pcap file output.
    File(FileConfig),
    /// Rotating pcap file output.
    RotatingFile(RotatingFileConfig),
    /// Discard packets.
    Null,
}

#[derive(Debug, Clone)]
/// One task output (a backend plus per-output options).
pub struct OutputConfig {
    /// Backend kind and configuration.
    pub kind: OutputKind,
    /// Token-bucket rate limit in Mbps (0 = unlimited).
    pub rate_limit_mbps: u64,
    /// Truncate forwarded packets to this many bytes (0 = no truncation).
    pub slice: i32,
}

impl OutputConfig {
    /// The config string for this output's type.
    #[must_use]
    pub fn output_type(&self) -> &'static str {
        match self.kind {
            OutputKind::Vxlan(_) => OUTPUT_TYPE_VXLAN,
            OutputKind::Gre(_) => OUTPUT_TYPE_GRE,
            OutputKind::Zmq(_) => OUTPUT_TYPE_ZMQ,
            OutputKind::File(_) => OUTPUT_TYPE_FILE,
            OutputKind::RotatingFile(_) => OUTPUT_TYPE_ROTATING_FILE,
            OutputKind::Null => OUTPUT_TYPE_NULL,
        }
    }

    /// Host this output forwards frames to, if any. Mirrors `output_forward_host`.
    #[must_use]
    pub fn forward_host(&self) -> Option<&str> {
        match &self.kind {
            OutputKind::Vxlan(c) => Some(&c.host),
            OutputKind::Gre(c) => Some(&c.host),
            OutputKind::Zmq(c) => Some(&c.host),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
/// libpcap live-capture configuration.
pub struct LibpcapConfig {
    /// Capture interface name.
    pub interface: String,
    /// Snapshot length in bytes.
    pub snaplen: i32,
    /// Network namespace to enter before capture (empty = current).
    pub netns: String,
    /// BPF filter expression.
    pub bpf: String,
    /// libpcap capture buffer size in MB.
    pub buffer_size_mb: i32,
    /// Read timeout in milliseconds.
    pub timeout_ms: i32,
    /// Exclude task output hosts from the BPF filter.
    pub not_filter_output_hosts: bool,
}

impl LibpcapConfig {
    /// The filter expression this task will actually compile.
    ///
    /// Port of the two steps `libpcap_capturer_new()` performs before
    /// `pcap_compile()`: drop the task's own output hosts (unless disabled), then
    /// expand `nic.<ifname>` tokens. Exposed so a name can be resolved *ahead* of
    /// building the task (see `crate::task::reload_from_file`) without any second
    /// copy of this logic to drift out of sync with.
    ///
    /// # Errors
    /// Returns an error if a `nic.<ifname>` token names an interface without an
    /// address.
    pub fn effective_bpf(&self, tasks: &[TaskConfig]) -> Result<String> {
        let bpf = if self.not_filter_output_hosts {
            self.bpf.clone()
        } else {
            crate::log_info!("exclude task output hosts");
            bpf_filter_exclude_task_output_hosts(&self.bpf, tasks)
        };
        // The emptiness test is on the *result*: a task with no filter of its own
        // still has to exclude its output hosts (that is the whole point of the
        // feature - mirroring our own forwarded traffic back is the failure).
        if bpf.is_empty() {
            Ok(String::new())
        } else {
            bpf_filter_replace_nic(&bpf)
        }
    }
}

#[derive(Debug, Clone)]
/// Offline pcap file replay configuration.
pub struct PcapFileConfig {
    /// Source pcap file name.
    pub file_name: String,
    /// BPF filter expression.
    pub bpf: String,
}

#[derive(Debug, Clone)]
/// DPDK pdump capturer configuration (not yet ported).
pub struct DpdkPdumpConfig {
    /// Capture interface name.
    pub interface: String,
    /// Snapshot length in bytes.
    pub snaplen: i32,
    /// BPF filter expression.
    pub bpf: String,
    /// DPDK ring size.
    pub ring_size: i32,
}

#[derive(Debug, Clone)]
/// Capturer backend selection and its configuration.
pub enum CapturerKind {
    /// libpcap live capture.
    Libpcap(LibpcapConfig),
    /// Offline pcap file replay.
    PcapFile(PcapFileConfig),
    /// DPDK pdump capture (not yet ported).
    DpdkPdump(DpdkPdumpConfig),
}

impl CapturerKind {
    /// The config string for this capturer's type.
    #[must_use]
    pub fn capturer_type(&self) -> &'static str {
        match self {
            CapturerKind::Libpcap(_) => CAPTURER_TYPE_LIBPCAP,
            CapturerKind::PcapFile(_) => CAPTURER_TYPE_PCAP_FILE,
            CapturerKind::DpdkPdump(_) => CAPTURER_TYPE_DPDK_PDUMP,
        }
    }

    /// Effective snapshot length for this capturer.
    #[must_use]
    pub fn snaplen(&self) -> i32 {
        match self {
            CapturerKind::Libpcap(c) => c.snaplen,
            CapturerKind::PcapFile(_) => 262144,
            CapturerKind::DpdkPdump(c) => c.snaplen,
        }
    }

    /// Interface name, if this capturer is backed by a network interface.
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        match self {
            CapturerKind::Libpcap(c) => Some(&c.interface),
            CapturerKind::DpdkPdump(c) => Some(&c.interface),
            CapturerKind::PcapFile(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
/// Capturer selection for a task.
pub struct CapturerConfig {
    /// Capturer backend and its configuration.
    pub kind: CapturerKind,
}

#[derive(Debug, Clone)]
/// Direction-matching requirement for a task.
pub enum ReqPatternConfig {
    /// No direction matching.
    None,
    /// Automatic MAC-based matching.
    Auto,
    /// Custom pattern expression.
    Custom {
        /// The pattern expression string.
        pattern: String,
    },
}

#[derive(Debug, Clone)]
/// One capture/forward task.
pub struct TaskConfig {
    /// Stable fingerprint identifying the task (optional).
    pub fingerprint: Option<String>,
    /// Direction-matching requirement.
    pub req_pattern: ReqPatternConfig,
    /// Capturer for this task.
    pub capturer: CapturerConfig,
    /// Outputs for this task.
    pub outputs: Vec<OutputConfig>,
}

#[derive(Debug, Clone)]
/// Control-channel configuration.
pub enum ControlConfig {
    /// Unix domain socket control channel.
    UnixSocket {
        /// Socket path.
        path: String,
    },
}

#[derive(Debug, Clone)]
/// Top-level worker configuration (mirrors the on-disk JSON schema).
pub struct Config {
    /// Log level (`LOG_*`).
    pub log_level: i32,
    /// CPU affinity list (empty = no pinning).
    pub cpu_affinity: String,
    /// Task execution model.
    pub execution_model: ExecutionModel,
    /// Pipeline ring buffer size in MB.
    pub pipeline_buffer_size_mb: i32,
    /// Optional control channel.
    pub control: Option<ControlConfig>,
    /// Tasks to run.
    pub tasks: Vec<TaskConfig>,
}

impl Config {
    /// Parse a configuration from a JSON file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or the JSON is invalid.
    pub fn parse_file(path: impl AsRef<Path>) -> Result<Config> {
        let data = std::fs::read_to_string(path)?;
        Config::parse_str(&data)
    }

    /// Parse a configuration from a JSON string.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or fails semantic validation.
    pub fn parse_str(s: &str) -> Result<Config> {
        let raw: RawConfig =
            serde_json::from_str(s).map_err(|e| Error::new(format!("JSON parse error: {e}")))?;
        raw.build()
    }
}

/// Canonical, diffable description of a parsed config.
///
/// Produces exactly the lines printed by the C `c_config.c` harness (and by
/// `config_parity`), so the two can be compared line by line. Used by the
/// differential harness and the `diff_oracle` fuzz target.
#[must_use]
pub fn canonical_dump(c: &Config) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "log_level={}", c.log_level);
    let _ = writeln!(
        s,
        "exec_model={}",
        if c.execution_model == ExecutionModel::Pipeline {
            "pipeline"
        } else {
            "rtc"
        }
    );
    let _ = writeln!(s, "cpu={}", c.cpu_affinity);
    let _ = writeln!(s, "pipeline_mb={}", c.pipeline_buffer_size_mb);
    match &c.control {
        Some(ControlConfig::UnixSocket { path }) => {
            let _ = writeln!(s, "control type=unix path={path}");
        }
        None => {
            let _ = writeln!(s, "control none");
        }
    }
    let _ = writeln!(s, "tasks={}", c.tasks.len());
    for (i, t) in c.tasks.iter().enumerate() {
        let req = match t.req_pattern {
            ReqPatternConfig::None => "none",
            ReqPatternConfig::Auto => "auto",
            ReqPatternConfig::Custom { .. } => "custom",
        };
        let (cap_type, snaplen, bpf) = match &t.capturer.kind {
            CapturerKind::Libpcap(l) => (CAPTURER_TYPE_LIBPCAP, l.snaplen, l.bpf.as_str()),
            CapturerKind::PcapFile(p) => (CAPTURER_TYPE_PCAP_FILE, 262144, p.bpf.as_str()),
            CapturerKind::DpdkPdump(d) => (CAPTURER_TYPE_DPDK_PDUMP, d.snaplen, d.bpf.as_str()),
        };
        let _ = writeln!(
            s,
            " task idx={i} fp={} req={req} capturer={cap_type} snaplen={snaplen} bpf={bpf}",
            t.fingerprint.as_deref().unwrap_or("")
        );
        for o in &t.outputs {
            let host = o.forward_host().unwrap_or("");
            let _ = writeln!(
                s,
                "  output type={} rate={} slice={} host={host}",
                o.output_type(),
                o.rate_limit_mbps,
                o.slice
            );
        }
    }
    let base_bpf = c
        .tasks
        .first()
        .map(|t| match &t.capturer.kind {
            CapturerKind::Libpcap(l) => l.bpf.as_str(),
            _ => "",
        })
        .unwrap_or("");
    let bpf = bpf_filter_exclude_task_output_hosts(base_bpf, &c.tasks);
    let _ = writeln!(s, "exclude_bpf={bpf}");
    let _ = writeln!(s, "---");
    s
}

// ---------------------------------------------------------------------------
// Raw deserialization types
// ---------------------------------------------------------------------------

/// Deserialize an optional field, rejecting an explicit JSON `null`.
///
/// C's cJSON type checks (`cJSON_IsString` etc.) treat a present-but-null value
/// as a parse error, whereas serde maps `null` to `None`. This makes them agree.
fn de_nonnull<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    match Option::<T>::deserialize(d)? {
        Some(v) => Ok(Some(v)),
        None => Err(serde::de::Error::custom("null value not allowed")),
    }
}

/// Same as [`de_nonnull`] but for boolean fields with a default of `false`.
fn de_nonnull_bool<'de, D>(d: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<bool>::deserialize(d)? {
        Some(v) => Ok(v),
        None => Err(serde::de::Error::custom("null value not allowed")),
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default, deserialize_with = "de_nonnull")]
    log_level: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    cpu_affinity: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    execution_model: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pipeline: Option<RawPipeline>,
    #[serde(default, deserialize_with = "de_nonnull")]
    control: Option<RawControl>,
    // C requires the `tasks` key to be an array (empty is allowed).
    tasks: Vec<RawTask>,
}

#[derive(Debug, Deserialize)]
struct RawPipeline {
    buffer_size_mb: i64,
}

#[derive(Debug, Deserialize)]
struct RawControl {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    unix: Option<RawUnix>,
}

#[derive(Debug, Deserialize)]
struct RawUnix {
    path: String,
}

#[derive(Debug, Deserialize)]
struct RawTask {
    #[serde(default, deserialize_with = "de_nonnull")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    req_pattern: Option<RawReqPattern>,
    capturer: RawCapturer,
    // C requires the `outputs` key to be an array (empty is allowed).
    outputs: Vec<RawOutput>,
}

#[derive(Debug, Deserialize)]
struct RawReqPattern {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    custom: Option<RawCustom>,
}

#[derive(Debug, Deserialize)]
struct RawCustom {
    #[serde(default, deserialize_with = "de_nonnull")]
    pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCapturer {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    libpcap: Option<RawLibpcap>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pcap_file: Option<RawPcapFile>,
    #[serde(default, deserialize_with = "de_nonnull")]
    dpdk_pdump: Option<RawDpdk>,
}

#[derive(Debug, Deserialize)]
struct RawLibpcap {
    interface: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    netns: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    snaplen: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bpf: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    buffer_size_mb: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    not_filter_output_hosts: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawPcapFile {
    file_name: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    bpf: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDpdk {
    interface: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    snaplen: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bpf: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    ring_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawOutput {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    rate_limit_mbps: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    slice: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    vxlan: Option<RawVxlan>,
    #[serde(default, deserialize_with = "de_nonnull")]
    gre: Option<RawGre>,
    #[serde(default, deserialize_with = "de_nonnull")]
    zmq: Option<RawZmq>,
    #[serde(default, deserialize_with = "de_nonnull")]
    file: Option<RawFile>,
    #[serde(default, deserialize_with = "de_nonnull")]
    rotating_file: Option<RawRotatingFile>,
}

#[derive(Debug, Deserialize)]
struct RawVxlan {
    host: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "de_nonnull")]
    capture_time: Option<bool>,
    #[serde(default, deserialize_with = "de_nonnull")]
    vni1: Option<u32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    vni2: Option<u32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bind_device: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pmtudisc: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    split: Option<RawSplit>,
}

#[derive(Debug, Deserialize)]
struct RawGre {
    host: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    service_tag: Option<u32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bind_device: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pmtudisc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawZmq {
    host: String,
    port: u16,
    #[serde(default, deserialize_with = "de_nonnull")]
    hwm: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    service_tag: Option<u32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    uuid: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    heartbeat_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawRotatingFile {
    file_root: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    max_file_interval: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSplit {
    #[serde(default, deserialize_with = "de_nonnull")]
    max_payload_size: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull_bool")]
    recalculate_checksum: bool,
}

/// Range-check a JSON integer (`serde_json` gives us every number as `i64`).
///
/// The error message always names the offending field, because a config file is
/// shared between operators and the CPM control plane and "invalid number" is
/// not actionable.
fn int_in(field: &str, v: i64, min: i64, max: i64) -> Result<i64> {
    if !(min..=max).contains(&v) {
        return Err(Error::new(format!(
            "invalid {field} {v}: must be between {min} and {max}"
        )));
    }
    Ok(v)
}

/// [`int_in`] plus a lossless conversion to `i32` (AUDIT4 P5-15: never `as i32`).
fn i32_in(field: &str, v: i64, min: i64, max: i64) -> Result<i32> {
    let v = int_in(field, v, min, max)?;
    i32::try_from(v).map_err(|_| {
        Error::new(format!(
            "invalid {field} {v}: must be between {min} and {max}"
        ))
    })
}

/// [`int_in`] plus a lossless conversion to `u64`.
fn u64_in(field: &str, v: i64, min: i64, max: i64) -> Result<u64> {
    let v = int_in(field, v, min, max)?;
    u64::try_from(v).map_err(|_| {
        Error::new(format!(
            "invalid {field} {v}: must be between {min} and {max}"
        ))
    })
}

/// [`int_in`] plus a lossless conversion to `u16`.
fn u16_in(field: &str, v: i64, min: i64, max: i64) -> Result<u16> {
    let v = int_in(field, v, min, max)?;
    u16::try_from(v).map_err(|_| {
        Error::new(format!(
            "invalid {field} {v}: must be between {min} and {max}"
        ))
    })
}

fn parse_pmtudisc(s: &str) -> Result<i32> {
    match s {
        "do" => Ok(IP_PMTUDISC_DO),
        "dont" => Ok(IP_PMTUDISC_DONT),
        "want" => Ok(IP_PMTUDISC_WANT),
        other => Err(Error::new(format!("invalid pmtudisc {other}"))),
    }
}

impl RawSplit {
    fn build(self) -> Result<SplitConfig> {
        let max = match self.max_payload_size {
            None => 0,
            Some(v) => u16_in("vxlan.split.max_payload_size", v, 0, 65535)?,
        };
        Ok(SplitConfig {
            max_payload_size: max,
            recalculate_checksum: self.recalculate_checksum,
        })
    }
}

impl RawOutput {
    fn build(self) -> Result<OutputConfig> {
        // AUDIT4 P5-15: every numeric field is range-checked and converted
        // losslessly; `as` casts used to wrap into absurd running parameters.
        let rate_limit_mbps = u64_in(
            "rate_limit_mbps",
            self.rate_limit_mbps.unwrap_or(0),
            RATE_LIMIT_MBPS_MIN,
            RATE_LIMIT_MBPS_MAX,
        )?;
        let slice = i32_in("slice", self.slice.unwrap_or(0), SLICE_MIN, SLICE_MAX)?;

        let kind = match self.ty.as_str() {
            OUTPUT_TYPE_VXLAN => {
                let v = self
                    .vxlan
                    .ok_or_else(|| Error::new("missing vxlan config"))?;
                let (vni_version, vni) = if let Some(v1) = v.vni1 {
                    (1u8, v1)
                } else if let Some(v2) = v.vni2 {
                    (2u8, v2)
                } else {
                    return Err(Error::new("require vxlan.vni1 or vxlan.vni2"));
                };
                let pmtudisc = match v.pmtudisc.as_deref() {
                    None => -1,
                    Some(s) => parse_pmtudisc(s)?,
                };
                let split = v.split.map(|s| s.build()).transpose()?.unwrap_or_default();
                OutputKind::Vxlan(VxlanConfig {
                    host: v.host,
                    port: v.port.unwrap_or(4789),
                    capture_time: v.capture_time.unwrap_or(false),
                    vni_version,
                    vni,
                    bind_device: v.bind_device.unwrap_or_default(),
                    pmtudisc,
                    split,
                })
            }
            OUTPUT_TYPE_GRE => {
                let g = self.gre.ok_or_else(|| Error::new("missing gre config"))?;
                let pmtudisc = match g.pmtudisc.as_deref() {
                    None => -1,
                    Some(s) => parse_pmtudisc(s)?,
                };
                OutputKind::Gre(GreConfig {
                    host: g.host,
                    service_tag: g.service_tag.unwrap_or(0xffff_ffff),
                    bind_device: g.bind_device.unwrap_or_default(),
                    pmtudisc,
                })
            }
            OUTPUT_TYPE_ZMQ => {
                let z = self.zmq.ok_or_else(|| Error::new("missing zmq config"))?;
                let heartbeat_ms =
                    i32_in("zmq.heartbeat_ms", z.heartbeat_ms.unwrap_or(0), 0, 60_000)?;
                let hwm = i32_in(
                    "zmq.hwm",
                    z.hwm.unwrap_or(i64::from(DEFAULT_ZMQ_HWM)),
                    i64::from(ZMQ_HWM_MIN),
                    i64::from(ZMQ_HWM_MAX),
                )
                .map_err(|e| {
                    Error::new(format!(
                        "{e} (each queued batch is up to 1 MiB, so hwm bounds the output's memory)"
                    ))
                })?;
                // The pending queue is bounded by `hwm` messages of at most
                // ZMQ_MAX_BATCH_BUF_SIZE each, so an unbounded hwm is an
                // unbounded memory promise. Reject it here instead of letting
                // the worker get OOM-killed later.
                if !(ZMQ_HWM_MIN..=ZMQ_HWM_MAX).contains(&hwm) {
                    return Err(Error::new(format!(
                        "invalid zmq.hwm {hwm}: must be between {ZMQ_HWM_MIN} and                          {ZMQ_HWM_MAX} (each queued batch is up to 1 MiB)"
                    )));
                }
                OutputKind::Zmq(ZmqConfig {
                    host: z.host,
                    port: z.port,
                    hwm,
                    service_tag: z.service_tag.unwrap_or(0xffff_ffff),
                    uuid: z.uuid.unwrap_or_default(),
                    heartbeat_ms,
                })
            }
            OUTPUT_TYPE_FILE => {
                let f = self.file.ok_or_else(|| Error::new("missing file config"))?;
                OutputKind::File(FileConfig { name: f.name })
            }
            OUTPUT_TYPE_ROTATING_FILE => {
                let r = self
                    .rotating_file
                    .ok_or_else(|| Error::new("missing rotating_file config"))?;
                OutputKind::RotatingFile(RotatingFileConfig {
                    file_root: r.file_root,
                    max_file_interval: i32_in(
                        "rotating_file.max_file_interval",
                        r.max_file_interval.unwrap_or(-1),
                        MAX_FILE_INTERVAL_MIN,
                        MAX_FILE_INTERVAL_MAX,
                    )?,
                })
            }
            OUTPUT_TYPE_NULL => OutputKind::Null,
            other => return Err(Error::new(format!("unknown output type: {other}"))),
        };

        Ok(OutputConfig {
            kind,
            rate_limit_mbps,
            slice,
        })
    }
}

impl RawCapturer {
    fn build(self) -> Result<CapturerConfig> {
        let kind = match self.ty.as_str() {
            CAPTURER_TYPE_LIBPCAP => {
                let c = self
                    .libpcap
                    .ok_or_else(|| Error::new("missing libpcap config"))?;
                CapturerKind::Libpcap(LibpcapConfig {
                    interface: c.interface,
                    snaplen: i32_in(
                        "libpcap.snaplen",
                        c.snaplen.unwrap_or(DEFAULT_SNAPLEN),
                        SNAPLEN_MIN,
                        SNAPLEN_MAX,
                    )?,
                    netns: c.netns.unwrap_or_default(),
                    bpf: c.bpf.unwrap_or_default(),
                    buffer_size_mb: i32_in(
                        "libpcap.buffer_size_mb",
                        c.buffer_size_mb.unwrap_or(DEFAULT_BUFFER_SIZE_MB),
                        BUFFER_SIZE_MB_MIN,
                        BUFFER_SIZE_MB_MAX,
                    )?,
                    timeout_ms: i32_in(
                        "libpcap.timeout_ms",
                        c.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
                        TIMEOUT_MS_MIN,
                        TIMEOUT_MS_MAX,
                    )?,
                    not_filter_output_hosts: c.not_filter_output_hosts.unwrap_or(false),
                })
            }
            CAPTURER_TYPE_PCAP_FILE => {
                let c = self
                    .pcap_file
                    .ok_or_else(|| Error::new("missing pcap_file config"))?;
                CapturerKind::PcapFile(PcapFileConfig {
                    file_name: c.file_name,
                    bpf: c.bpf.unwrap_or_default(),
                })
            }
            CAPTURER_TYPE_DPDK_PDUMP => {
                let c = self
                    .dpdk_pdump
                    .ok_or_else(|| Error::new("missing dpdk_pdump config"))?;
                CapturerKind::DpdkPdump(DpdkPdumpConfig {
                    interface: c.interface,
                    snaplen: i32_in(
                        "dpdk_pdump.snaplen",
                        c.snaplen.unwrap_or(DEFAULT_SNAPLEN),
                        SNAPLEN_MIN,
                        SNAPLEN_MAX,
                    )?,
                    bpf: c.bpf.unwrap_or_default(),
                    ring_size: i32_in(
                        "dpdk_pdump.ring_size",
                        c.ring_size.unwrap_or(DEFAULT_RING_SIZE),
                        RING_SIZE_MIN,
                        RING_SIZE_MAX,
                    )?,
                })
            }
            other => return Err(Error::new(format!("unknown capturer type: {other}"))),
        };
        Ok(CapturerConfig { kind })
    }
}

impl RawReqPattern {
    fn build(self) -> Result<ReqPatternConfig> {
        match self.ty.as_str() {
            // NOTE: C only accepts "auto"/"custom" here; an explicit "none" is
            // rejected. "none" is the default used when req_pattern is absent.
            REQ_PATTERN_TYPE_AUTO_STR => Ok(ReqPatternConfig::Auto),
            REQ_PATTERN_TYPE_CUSTOM_STR => {
                let c = self
                    .custom
                    .ok_or_else(|| Error::new("custom is not an object"))?;
                Ok(ReqPatternConfig::Custom {
                    pattern: c.pattern.unwrap_or_default(),
                })
            }
            other => Err(Error::new(format!("unknown req_pattern type: {other}"))),
        }
    }
}

impl RawTask {
    fn build(self) -> Result<TaskConfig> {
        let req_pattern = match self.req_pattern {
            None => ReqPatternConfig::None,
            Some(r) => r.build()?,
        };
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for o in self.outputs {
            outputs.push(o.build()?);
        }
        Ok(TaskConfig {
            fingerprint: self.fingerprint.filter(|s| !s.is_empty()),
            req_pattern,
            capturer: self.capturer.build()?,
            outputs,
        })
    }
}

impl RawConfig {
    fn build(self) -> Result<Config> {
        let log_level = match self.log_level.as_deref() {
            None => LOG_INFO,
            // C only accepts DEBUG/INFO/WARN/ERROR here (not TRACE).
            Some(s) if s.eq_ignore_ascii_case("DEBUG") => LOG_DEBUG,
            Some(s) if s.eq_ignore_ascii_case("INFO") => LOG_INFO,
            Some(s) if s.eq_ignore_ascii_case("WARN") => LOG_WARN,
            Some(s) if s.eq_ignore_ascii_case("ERROR") => LOG_ERROR,
            Some(_) => return Err(Error::new("invalid log_level")),
        };

        let execution_model = match self.execution_model.as_deref() {
            None | Some("rtc") => ExecutionModel::Rtc,
            Some("pipeline") => ExecutionModel::Pipeline,
            Some(_) => return Err(Error::new("invalid execution_model")),
        };

        let pipeline_buffer_size_mb = if execution_model == ExecutionModel::Pipeline {
            let p = self
                .pipeline
                .ok_or_else(|| Error::new("missing pipeline config"))?;
            i32_in(
                "pipeline.buffer_size_mb",
                p.buffer_size_mb,
                PIPELINE_BUFFER_MB_MIN,
                PIPELINE_BUFFER_MB_MAX,
            )?
        } else {
            0
        };

        let control = match self.control {
            None => None,
            Some(c) => {
                if c.ty != CONTROL_TYPE_UNIX {
                    return Err(Error::new(format!("unknown control type: {}", c.ty)));
                }
                let u = c.unix.ok_or_else(|| Error::new("missing unix config"))?;
                Some(ControlConfig::UnixSocket { path: u.path })
            }
        };

        let mut tasks = Vec::with_capacity(self.tasks.len());
        for t in self.tasks {
            let task = t.build()?;
            // C rejects duplicate non-empty fingerprints.
            if let Some(fp) = &task.fingerprint {
                if tasks
                    .iter()
                    .any(|other: &TaskConfig| other.fingerprint.as_deref() == Some(fp.as_str()))
                {
                    return Err(Error::new(format!("duplicate fingerprint '{fp}'")));
                }
            }
            tasks.push(task);
        }

        Ok(Config {
            log_level,
            cpu_affinity: self.cpu_affinity.unwrap_or_default(),
            execution_model,
            pipeline_buffer_size_mb,
            control,
            tasks,
        })
    }
}

/// Build a BPF filter that excludes the forwarding hosts of every task.
/// Port of `bpf_filter_exclude_task_output_hosts`.
#[must_use]
pub fn bpf_filter_exclude_task_output_hosts(bpf: &str, tasks: &[TaskConfig]) -> String {
    let mut hosts: Vec<&str> = Vec::new();
    for task in tasks {
        for output in &task.outputs {
            if let Some(host) = output.forward_host() {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
    }

    let mut parts: Vec<String> = Vec::new();
    if !bpf.is_empty() {
        parts.push(format!("({bpf})"));
    }
    for host in hosts {
        parts.push(format!("not host {host}"));
    }
    parts.join(" and ")
}

/// Sane default snaplen for a task's capturer. Port of `task_capturer_snaplen`.
#[must_use]
pub fn task_capturer_snaplen(task: &TaskConfig) -> i32 {
    task.capturer.kind.snaplen()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "cpu_affinity": "1",
        "log_level": "DEBUG",
        "execution_model": "rtc",
        "control": { "type": "unix", "unix": { "path": "cpworker.sock" } },
        "tasks": [{
            "fingerprint": "fp1",
            "req_pattern": { "type": "auto" },
            "capturer": { "type": "libpcap", "libpcap": { "interface": "eth0" } },
            "outputs": [
                { "type": "vxlan", "vxlan": { "host": "10.0.0.9", "vni1": 7 } },
                { "type": "null" }
            ]
        }]
    }"#;

    #[test]
    fn parse_sample() {
        let c = Config::parse_str(SAMPLE).unwrap();
        assert_eq!(c.log_level, LOG_DEBUG);
        assert_eq!(c.tasks.len(), 1);
        assert_eq!(c.tasks[0].outputs.len(), 2);
        match &c.tasks[0].outputs[0].kind {
            OutputKind::Vxlan(v) => {
                assert_eq!(v.port, 4789);
                assert_eq!(v.vni, 7);
                assert_eq!(v.vni_version, 1);
            }
            _ => panic!("expected vxlan"),
        }
    }

    /// `libpcap.effective_bpf()` is what the capturer compiles, and it is now also
    /// what the reload path resolves ahead of the task-manager lock. It must keep
    /// the (inverted-looking) meaning of `not_filter_output_hosts` and the
    /// `nic.<ifname>` expansion in one place.
    #[test]
    fn effective_bpf_follows_the_exclusion_flag() {
        let cfg = Config::parse_str(SAMPLE).expect("parse sample");
        let mut l = match cfg.tasks[0].capturer.kind.clone() {
            CapturerKind::Libpcap(l) => l,
            other => panic!("expected libpcap, got {other:?}"),
        };
        l.bpf = "udp and port 53".to_string();

        l.not_filter_output_hosts = true;
        assert_eq!(
            l.effective_bpf(&cfg.tasks).expect("effective bpf"),
            "udp and port 53",
            "flag set means keep the expression exactly as written"
        );

        l.not_filter_output_hosts = false;
        let excluded = l.effective_bpf(&cfg.tasks).expect("effective bpf");
        assert!(
            excluded.starts_with("(udp and port 53) and not host "),
            "flag clear must append the output-host exclusion, got {excluded}"
        );

        // No filter of its own, flag clear: the exclusion alone is still a filter.
        l.bpf = String::new();
        assert_eq!(
            l.effective_bpf(&cfg.tasks).expect("exclusion only"),
            "not host 10.0.0.9",
            "a task without a bpf must still exclude its own output host"
        );
        l.not_filter_output_hosts = true;
        assert_eq!(
            l.effective_bpf(&cfg.tasks).expect("nothing"),
            "",
            "no filter and no exclusion means no filter program at all"
        );
    }

    #[test]
    fn exclude_hosts() {
        let c = Config::parse_str(SAMPLE).unwrap();
        let out = bpf_filter_exclude_task_output_hosts("port 80", &c.tasks);
        assert_eq!(out, "(port 80) and not host 10.0.0.9");
    }
    /// Build a one-task config whose libpcap capturer carries `kv`.
    fn with_libpcap(kv: &str) -> Result<Config> {
        Config::parse_str(&format!(
            r#"{{"tasks":[{{
            "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0",{kv}}}}},
            "outputs": []
        }}]}}"#
        ))
    }

    /// Build a one-task config whose dpdk_pdump capturer carries `kv`.
    fn with_dpdk(kv: &str) -> Result<Config> {
        Config::parse_str(&format!(
            r#"{{"tasks":[{{
            "capturer": {{"type":"dpdk_pdump","dpdk_pdump":{{"interface":"eth0",{kv}}}}},
            "outputs": []
        }}]}}"#
        ))
    }

    /// Build a config with a single `null` output carrying `kv`.
    fn with_output(kv: &str) -> Result<Config> {
        Config::parse_str(&format!(
            r#"{{"tasks":[{{
            "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},
            "outputs": [{{"type":"null"{kv}}}]
        }}]}}"#
        ))
    }

    /// Assert `res` is a rejection whose message names `field`.
    fn assert_rejects(field: &str, res: Result<Config>) {
        match res {
            Ok(c) => panic!(
                "{field}: out-of-range value was accepted ({:?})",
                c.execution_model
            ),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains(field),
                    "{field}: error should name the field, got: {msg}"
                );
            }
        }
    }

    /// AUDIT4 P5-15: JSON numbers arrive as `i64` while the runtime structs use
    /// `i32`. A bare `as i32` wraps silently and the capture plane turns the wrapped
    /// value into an absurd running parameter:
    ///
    /// * `snaplen: 2147483648` -> `i32::MIN` -> `snaplen.max(1)` -> **one byte per
    ///   packet**: every frame is truncated so hard that no BPF test matches and the
    ///   task captures nothing;
    /// * `buffer_size_mb: 4294967296` -> `0` -> `SO_RCVBUF=0` (massive loss);
    /// * `timeout_ms: 4294967396` -> `100` (not what anyone asked for);
    /// * `slice: 4294967296` -> `0` (= never truncate, the opposite of the request).
    ///
    /// Each of them must be a configuration error that names the field, while the
    /// in-range boundaries keep being accepted verbatim.
    #[test]
    fn numeric_fields_are_range_checked_not_truncated() {
        // --- libpcap.snaplen ---------------------------------------------------
        assert_rejects(
            "libpcap.snaplen",
            with_libpcap(r#""snaplen":4294967296"#), // wraps to 0 -> 1-byte captures
        );
        assert_rejects(
            "libpcap.snaplen",
            with_libpcap(r#""snaplen":2147483648"#), // wraps to i32::MIN
        );
        assert_rejects("libpcap.snaplen", with_libpcap(r#""snaplen":-1"#));
        for boundary in [0_i64, 2048, SNAPLEN_MAX] {
            let c = with_libpcap(&format!(r#""snaplen":{boundary}"#))
                .unwrap_or_else(|e| panic!("snaplen {boundary} is in range and must stay: {e}"));
            match &c.tasks[0].capturer.kind {
                CapturerKind::Libpcap(l) => assert_eq!(l.snaplen, boundary as i32),
                other => panic!("expected libpcap capturer, got {other:?}"),
            }
        }

        // --- libpcap.buffer_size_mb --------------------------------------------
        assert_rejects(
            "libpcap.buffer_size_mb",
            with_libpcap(r#""buffer_size_mb":4294967296"#), // wraps to 0
        );
        assert_rejects(
            "libpcap.buffer_size_mb",
            with_libpcap(&format!(r#""buffer_size_mb":{}"#, BUFFER_SIZE_MB_MAX + 1)),
        );
        let c =
            with_libpcap(&format!(r#""buffer_size_mb":{BUFFER_SIZE_MB_MAX}"#)).expect("in range");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.buffer_size_mb, BUFFER_SIZE_MB_MAX as i32),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }

        // --- libpcap.timeout_ms -------------------------------------------------
        assert_rejects(
            "libpcap.timeout_ms",
            with_libpcap(r#""timeout_ms":4294967396"#), // wraps to 100
        );
        assert_rejects("libpcap.timeout_ms", with_libpcap(r#""timeout_ms":-1"#));
        let c = with_libpcap(&format!(r#""timeout_ms":{TIMEOUT_MS_MAX}"#)).expect("in range");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.timeout_ms, TIMEOUT_MS_MAX as i32),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }

        // --- dpdk_pdump ---------------------------------------------------------
        assert_rejects("dpdk_pdump.snaplen", with_dpdk(r#""snaplen":2147483648"#));
        assert_rejects(
            "dpdk_pdump.ring_size",
            with_dpdk(r#""ring_size":4294967304"#), // wraps to 2048
        );
        assert_rejects("dpdk_pdump.ring_size", with_dpdk(r#""ring_size":0"#));
        let c = with_dpdk(&format!(
            r#""snaplen":{SNAPLEN_MAX},"ring_size":{RING_SIZE_MAX}"#
        ))
        .expect("in range");
        match &c.tasks[0].capturer.kind {
            CapturerKind::DpdkPdump(d) => {
                assert_eq!(d.snaplen, SNAPLEN_MAX as i32);
                assert_eq!(d.ring_size, RING_SIZE_MAX as i32);
            }
            other => panic!("expected dpdk_pdump capturer, got {other:?}"),
        }

        // --- output: slice / rate_limit_mbps ------------------------------------
        assert_rejects("slice", with_output(r#","slice":4294967296"#)); // wraps to 0
        assert_rejects("slice", with_output(r#","slice":-1"#));
        assert_rejects(
            "slice",
            with_output(&format!(r#","slice":{}"#, SLICE_MAX + 1)),
        );
        assert!(
            with_output(&format!(r#","slice":{SLICE_MAX}"#)).is_ok(),
            "SLICE_MAX is in range"
        );
        assert_rejects("rate_limit_mbps", with_output(r#","rate_limit_mbps":-1"#));
        assert_rejects(
            "rate_limit_mbps",
            with_output(&format!(
                r#","rate_limit_mbps":{}"#,
                RATE_LIMIT_MBPS_MAX + 1
            )),
        );
        assert!(
            with_output(&format!(r#","rate_limit_mbps":{RATE_LIMIT_MBPS_MAX}"#)).is_ok(),
            "the maximum rate limit must stay accepted (above it the token bucket overflows)"
        );

        // --- pipeline.buffer_size_mb --------------------------------------------
        let pipeline = |mb: i64| {
            Config::parse_str(&format!(
                r#"{{"execution_model":"pipeline","pipeline":{{"buffer_size_mb":{mb}}},"tasks":[]}}"#
            ))
        };
        assert_rejects("pipeline.buffer_size_mb", pipeline(4294967360)); // wraps to 64
        assert_rejects("pipeline.buffer_size_mb", pipeline(0));
        assert_rejects("pipeline.buffer_size_mb", pipeline(-1));
        assert_eq!(
            pipeline(256).expect("in range").pipeline_buffer_size_mb,
            256
        );

        // --- rotating_file.max_file_interval ------------------------------------
        let rotating = |kv: &str| {
            Config::parse_str(&format!(
                r#"{{"tasks":[{{
                "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},
                "outputs": [{{"type":"rotating_file","rotating_file":{{"file_root":"/tmp"{kv}}}}}]
            }}]}}"#
            ))
        };
        assert_rejects(
            "rotating_file.max_file_interval",
            rotating(r#","max_file_interval":4294967356"#), // wraps to 60
        );
        assert_rejects(
            "rotating_file.max_file_interval",
            rotating(r#","max_file_interval":-2"#),
        );
        assert!(
            rotating("").is_ok(),
            "the default max_file_interval (-1) must stay accepted"
        );
        assert!(rotating(r#","max_file_interval":-1"#).is_ok());

        // --- vxlan.split.max_payload_size ---------------------------------------
        // `frag` is appended inside the `vxlan` object.
        let vxlan = |frag: &str| {
            Config::parse_str(&format!(
                r#"{{"tasks":[{{
                "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},
                "outputs": [{{"type":"vxlan","vxlan":{{"host":"1.1.1.1","vni1":7{frag}}}}}
                ]}}]}}"#
            ))
        };
        let split = |v: i64| format!(",\"split\":{{\"max_payload_size\":{v}}}");
        assert_rejects("max_payload_size", vxlan(&split(65536)));
        assert_rejects("max_payload_size", vxlan(&split(4294967396))); // wraps to 100
        assert_rejects("max_payload_size", vxlan(&split(-1)));
        assert!(vxlan(&split(65535)).is_ok(), "65535 is in range");
    }

    /// AUDIT4 P5-11: `hwm` bounds the pending queue (hwm batches x <=1 MiB), so an
    /// unbounded value is an unbounded memory promise and must be rejected.
    #[test]
    fn zmq_hwm_is_range_checked() {
        let with_hwm = |hwm: i64| {
            Config::parse_str(&format!(
                r#"{{"tasks":[{{
                    "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},
                    "outputs": [{{"type":"zmq","zmq":{{
                        "host":"10.0.0.1","port":5555,"hwm":{hwm},
                        "uuid":"550e8400-e29b-41d4-a716-446655440000"
                    }}}}]
                }}]}}"#
            ))
        };
        assert!(
            with_hwm(100).is_ok(),
            "the default range must stay accepted"
        );
        assert!(with_hwm(i64::from(ZMQ_HWM_MAX)).is_ok());
        let big = with_hwm(i64::from(ZMQ_HWM_MAX) + 1)
            .unwrap_err()
            .to_string();
        assert!(
            big.contains("zmq.hwm"),
            "error should name the field: {big}"
        );
        assert!(
            with_hwm(0).is_err(),
            "hwm 0 (infinite in libzmq) must be rejected"
        );
        assert!(with_hwm(-1).is_err());
        assert!(
            with_hwm(2_147_483_647).is_err(),
            "i32::MAX hwm is an OOM request"
        );
        // Default when absent.
        let d = Config::parse_str(
            r#"{"tasks":[{
                "capturer": {"type":"libpcap","libpcap":{"interface":"eth0"}},
                "outputs": [{"type":"zmq","zmq":{
                    "host":"10.0.0.1","port":5555,
                    "uuid":"550e8400-e29b-41d4-a716-446655440000"
                }}]
            }]}"#,
        )
        .expect("default hwm config");
        match &d.tasks[0].outputs[0].kind {
            OutputKind::Zmq(c) => assert_eq!(c.hwm, DEFAULT_ZMQ_HWM),
            other => panic!("expected zmq output, got {other:?}"),
        }
    }
}
