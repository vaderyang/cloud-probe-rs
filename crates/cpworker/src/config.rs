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
/// Largest accepted `snaplen`: libpcap's own maximum snapshot length. `libpcap`
/// *normalises* out-of-range values to this instead of rejecting them (C:
/// `parse_snaplen`); `dpdk_pdump` rejects `<= 0` and then normalises above it.
pub const SNAPLEN_MAX: i64 = 262_144;
/// Largest accepted `libpcap.buffer_size_mb` (`INT_MAX / 1 MiB`); larger values
/// are normalised to it (C: `MAX_LIBPCAP_BUFFER_SIZE_MB`).
pub const BUFFER_SIZE_MB_MAX: i64 = 2_047;
/// Largest accepted `libpcap.timeout_ms` (`INT_MAX`); larger values are clamped.
pub const TIMEOUT_MS_MAX: i64 = 2_147_483_647;
/// Smallest accepted `dpdk_pdump.ring_size`.
pub const RING_SIZE_MIN: i64 = 2;
/// Largest accepted `dpdk_pdump.ring_size` (2^30 descriptors).
pub const RING_SIZE_MAX: i64 = 1 << 30;
/// Smallest accepted `pipeline.buffer_size_mb` (must be positive).
pub const PIPELINE_BUFFER_MB_MIN: i64 = 1;
/// Largest accepted `pipeline.buffer_size_mb`: keeps `buffer_size_mb * 1 MiB`
/// within `size_t` (C: `SIZE_MAX / (1024 * 1024)`).
pub const PIPELINE_BUFFER_MB_MAX: i64 = 17_592_186_044_415;
/// Smallest accepted output `slice` (0 = no truncation).
pub const SLICE_MIN: i64 = 0;
/// Largest accepted output `slice`: bigger than any frame, so it already means
/// "never truncate"; larger values are clamped to it (C clamps to `INT_MAX`).
pub const SLICE_MAX: i64 = 2_147_483_647;
/// Smallest accepted `rate_limit_mbps` (0 = unlimited).
pub const RATE_LIMIT_MBPS_MIN: i64 = 0;
/// Largest accepted `rate_limit_mbps`; larger values are clamped to it (C clamps
/// to `INT_MAX`, which is unlimited in practice and keeps the `* 1e6` byte rate
/// within `u64`).
pub const RATE_LIMIT_MBPS_MAX: i64 = 2_147_483_647;
/// Default `rotating_file.max_file_interval` when the key is absent (seconds).
pub const DEFAULT_MAX_FILE_INTERVAL: i64 = 60;
/// Smallest accepted `rotating_file.max_file_interval` (0 = size-triggered only).
pub const MAX_FILE_INTERVAL_MIN: i64 = 0;
/// Largest accepted `rotating_file.max_file_interval`, in seconds; larger values
/// are clamped to it (C clamps to `INT_MAX`).
pub const MAX_FILE_INTERVAL_MAX: i64 = 2_147_483_647;

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
/// Smallest accepted ZMQ high-water mark (0 = no limit).
pub const ZMQ_HWM_MIN: i32 = 0;
/// Largest accepted ZMQ high-water mark; larger values are clamped to it (C
/// clamps to `INT_MAX`).
pub const ZMQ_HWM_MAX: i32 = i32::MAX;

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
    /// Pipeline ring buffer size in MB (0 when not running the pipeline model).
    pub pipeline_buffer_size_mb: u64,
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

/// Same as [`de_nonnull`] but for numeric fields that must accept an integral
/// float, mirroring C's `cjson_get_integer`/`cjson_get_int64_range`: `2048.0`
/// and `1e3` mean 2048 and 1000, a fraction is rejected, and an explicit `null`
/// is an error (an absent key stays `None`). Values beyond `i64` saturate; every
/// field either clamps or range-rejects them, so the saturation is unobservable.
fn de_int<'de, D>(d: D) -> std::result::Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<f64>::deserialize(d)? {
        None => Err(serde::de::Error::custom("null value not allowed")),
        Some(f) => crate::num::integral_i64(f).map(Some).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid number {f}: must be an integer"))
        }),
    }
}

/// A sub-object whose validation C defers until a discriminator (`type`,
/// `execution_model`, ...) selects it. Keeping the raw [`serde_json::Value`]
/// means a malformed *sibling* - a `"zmq"` key on a `null` output, a `"libpcap"`
/// key on a `pcap_file` capturer - is ignored exactly as `cJSON` ignores it,
/// instead of failing serde eagerly.
type RawObject = serde_json::Value;

/// Parse a deferred sub-object: absent or `null` -> `None`; an object is parsed
/// strictly (so a bad field inside it still errors); any other type -> `None`,
/// which the caller turns into its "missing/invalid <x>" error. C walks a
/// non-object looking for fields, finds none and reports the first missing one,
/// so `None` here matches its accept/reject decision.
fn object_or_none<T: serde::de::DeserializeOwned>(
    field: &str,
    v: Option<RawObject>,
) -> Result<Option<T>> {
    match v {
        Some(v @ serde_json::Value::Object(_)) => serde_json::from_value(v)
            .map(Some)
            .map_err(|e| Error::new(format!("invalid {field}: {e}"))),
        _ => Ok(None),
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
    #[serde(default)]
    pipeline: Option<RawObject>,
    #[serde(default, deserialize_with = "de_nonnull")]
    control: Option<RawControl>,
    // C requires the `tasks` key to be an array (empty is allowed).
    tasks: Vec<RawTask>,
}

#[derive(Debug, Deserialize)]
struct RawPipeline {
    #[serde(default, deserialize_with = "de_int")]
    buffer_size_mb: Option<i64>,
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
    #[serde(default)]
    custom: Option<RawObject>,
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
    #[serde(default)]
    libpcap: Option<RawObject>,
    #[serde(default)]
    pcap_file: Option<RawObject>,
    #[serde(default)]
    dpdk_pdump: Option<RawObject>,
}

#[derive(Debug, Deserialize)]
struct RawLibpcap {
    interface: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    netns: Option<String>,
    #[serde(default, deserialize_with = "de_int")]
    snaplen: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bpf: Option<String>,
    #[serde(default, deserialize_with = "de_int")]
    buffer_size_mb: Option<i64>,
    #[serde(default, deserialize_with = "de_int")]
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
    #[serde(default, deserialize_with = "de_int")]
    snaplen: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bpf: Option<String>,
    #[serde(default, deserialize_with = "de_int")]
    ring_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawOutput {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, deserialize_with = "de_int")]
    rate_limit_mbps: Option<i64>,
    #[serde(default, deserialize_with = "de_int")]
    slice: Option<i64>,
    #[serde(default)]
    vxlan: Option<RawObject>,
    #[serde(default)]
    gre: Option<RawObject>,
    #[serde(default)]
    zmq: Option<RawObject>,
    #[serde(default)]
    file: Option<RawObject>,
    #[serde(default)]
    rotating_file: Option<RawObject>,
}

#[derive(Debug, Deserialize)]
struct RawVxlan {
    host: String,
    #[serde(default, deserialize_with = "de_int")]
    port: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    capture_time: Option<bool>,
    #[serde(default, deserialize_with = "de_int")]
    vni1: Option<i64>,
    #[serde(default, deserialize_with = "de_int")]
    vni2: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bind_device: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pmtudisc: Option<String>,
    #[serde(default)]
    split: Option<RawObject>,
}

#[derive(Debug, Deserialize)]
struct RawGre {
    host: String,
    #[serde(default, deserialize_with = "de_int")]
    service_tag: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    bind_device: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    pmtudisc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawZmq {
    host: String,
    #[serde(default, deserialize_with = "de_int")]
    port: Option<i64>,
    #[serde(default, deserialize_with = "de_int")]
    hwm: Option<i64>,
    #[serde(default, deserialize_with = "de_int")]
    service_tag: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull")]
    uuid: Option<String>,
    #[serde(default, deserialize_with = "de_int")]
    heartbeat_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawRotatingFile {
    file_root: String,
    #[serde(default, deserialize_with = "de_int")]
    max_file_interval: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSplit {
    #[serde(default, deserialize_with = "de_int")]
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

/// C `parse_snaplen`: absent -> [`DEFAULT_SNAPLEN`]; `0` -> max (libpcap only)
/// with an info log; `< 0` or `> max` -> max with a warning. `dpdk_pdump` passes
/// `non_positive_means_max = false`, so `<= 0` there is an error instead.
fn snaplen_in(field: &str, v: Option<i64>, non_positive_means_max: bool) -> Result<i32> {
    let v = v.unwrap_or(DEFAULT_SNAPLEN);
    if v <= 0 && !non_positive_means_max {
        return Err(Error::new(format!("invalid {field}: {v}, must be > 0")));
    }
    if v == 0 {
        crate::log_info!("{field} is 0, using the maximum {SNAPLEN_MAX}");
        return Ok(i32::try_from(SNAPLEN_MAX).unwrap_or(i32::MAX));
    }
    if !(0..=SNAPLEN_MAX).contains(&v) {
        crate::log_warn!("{field} {v} is out of range, using {SNAPLEN_MAX}");
        return Ok(i32::try_from(SNAPLEN_MAX).unwrap_or(i32::MAX));
    }
    Ok(i32::try_from(v).unwrap_or(i32::MAX))
}

/// C `libpcap.buffer_size_mb`: absent -> `default`; `<= 0` -> error; above `max`
/// -> warn + clamp; everything else as-is.
fn positive_clamped(field: &str, v: Option<i64>, default: i64, max: i64) -> Result<i32> {
    let v = v.unwrap_or(default);
    if v <= 0 {
        return Err(Error::new(format!("invalid {field}: {v}, must be > 0")));
    }
    if v > max {
        crate::log_warn!("{field} {v} is above {max}, using {max}");
        return Ok(i32::try_from(max).unwrap_or(i32::MAX));
    }
    Ok(i32::try_from(v).unwrap_or(i32::MAX))
}

/// C's `cjson_get_integer` + `value < 0` error + `value > INT_MAX` clamp, used by
/// output `slice`/`rate_limit_mbps`, `zmq.hwm`, `libpcap.timeout_ms` and
/// `rotating_file.max_file_interval`.
fn nonneg_clamped(field: &str, v: i64) -> Result<i32> {
    if v < 0 {
        return Err(Error::new(format!("invalid {field}: {v}, must be >= 0")));
    }
    Ok(i32::try_from(v).unwrap_or(i32::MAX))
}

/// [`int_in`] plus a lossless conversion to `u32`.
fn u32_in(field: &str, v: i64, min: i64, max: i64) -> Result<u32> {
    let v = int_in(field, v, min, max)?;
    u32::try_from(v).map_err(|_| {
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
        // C clamps `rate_limit_mbps`/`slice` to INT_MAX (beyond it they are
        // indistinguishable in practice) but rejects negative values.
        let rate_limit_mbps = u64::try_from(nonneg_clamped(
            "rate_limit_mbps",
            self.rate_limit_mbps.unwrap_or(0),
        )?)
        .unwrap_or(0);
        let slice = nonneg_clamped("slice", self.slice.unwrap_or(0))?;

        let kind = match self.ty.as_str() {
            OUTPUT_TYPE_VXLAN => {
                let v = object_or_none::<RawVxlan>("vxlan", self.vxlan)?
                    .ok_or_else(|| Error::new("missing vxlan config"))?;
                if v.vni1.is_some() && v.vni2.is_some() {
                    return Err(Error::new(
                        "vxlan.vni1 and vxlan.vni2 are mutually exclusive",
                    ));
                }
                let (vni_version, vni) = if let Some(v1) = v.vni1 {
                    let mut v1 = u32_in("vxlan.vni1", v1, 0, i64::from(u32::MAX))?;
                    // The wire carries `vni1 << 8`, so only the low 24 bits reach
                    // the VNI field. C keeps the full value only to warn, then
                    // masks it; cpdaemon may send uint32(serviceTag) beyond that
                    // (upstream #279).
                    if v1 > 0x00ff_ffff {
                        crate::log_warn!(
                            "vxlan.vni1 {v1} exceeds 24 bits and overlaps the reserved bits of the VXLAN header; using low 24 bits {low}",
                            low = v1 & 0x00ff_ffff
                        );
                        v1 &= 0x00ff_ffff;
                    }
                    (1u8, v1)
                } else if let Some(v2) = v.vni2 {
                    (2u8, u32_in("vxlan.vni2", v2, 0, i64::from(u32::MAX))?)
                } else {
                    return Err(Error::new("require vxlan.vni1 or vxlan.vni2"));
                };
                let pmtudisc = match v.pmtudisc.as_deref() {
                    None => -1,
                    Some(s) => parse_pmtudisc(s)?,
                };
                let split = object_or_none::<RawSplit>("vxlan.split", v.split)?
                    .map(|s| s.build())
                    .transpose()?
                    .unwrap_or_default();
                OutputKind::Vxlan(VxlanConfig {
                    host: v.host,
                    port: u16_in("vxlan.port", v.port.unwrap_or(4789), 1, i64::from(u16::MAX))?,
                    capture_time: v.capture_time.unwrap_or(false),
                    vni_version,
                    vni,
                    bind_device: v.bind_device.unwrap_or_default(),
                    pmtudisc,
                    split,
                })
            }
            OUTPUT_TYPE_GRE => {
                let g = object_or_none::<RawGre>("gre", self.gre)?
                    .ok_or_else(|| Error::new("missing gre config"))?;
                let pmtudisc = match g.pmtudisc.as_deref() {
                    None => -1,
                    Some(s) => parse_pmtudisc(s)?,
                };
                let service_tag = u32_in(
                    "gre.service_tag",
                    g.service_tag.unwrap_or(i64::from(u32::MAX)),
                    0,
                    i64::from(u32::MAX),
                )?;
                if service_tag > 0x0fff_ffff {
                    crate::log_warn!(
                        "gre.service_tag {service_tag} exceeds 28 bits and overlaps the direction bits of the GRE key"
                    );
                }
                OutputKind::Gre(GreConfig {
                    host: g.host,
                    service_tag,
                    bind_device: g.bind_device.unwrap_or_default(),
                    pmtudisc,
                })
            }
            OUTPUT_TYPE_ZMQ => {
                let z = object_or_none::<RawZmq>("zmq", self.zmq)?
                    .ok_or_else(|| Error::new("missing zmq config"))?;
                let port = u16_in(
                    "zmq.port",
                    z.port.ok_or_else(|| Error::new("missing zmq.port"))?,
                    1,
                    i64::from(u16::MAX),
                )?;
                let heartbeat_ms =
                    i32_in("zmq.heartbeat_ms", z.heartbeat_ms.unwrap_or(0), 0, 60_000)?;
                let service_tag = u32_in(
                    "zmq.service_tag",
                    z.service_tag.unwrap_or(i64::from(u32::MAX)),
                    0,
                    i64::from(u32::MAX),
                )?;
                if service_tag > 0x0fff {
                    crate::log_warn!(
                        "zmq.service_tag {service_tag} exceeds 12 bits: packet labels carry {}",
                        service_tag & 0x0fff
                    );
                }
                // 0 is libzmq's "no limit"; a negative value is rejected. A very
                // large hwm is clamped to INT_MAX rather than rejected.
                let hwm = nonneg_clamped("zmq.hwm", z.hwm.unwrap_or(i64::from(DEFAULT_ZMQ_HWM)))?;
                OutputKind::Zmq(ZmqConfig {
                    host: z.host,
                    port,
                    hwm,
                    service_tag,
                    uuid: z.uuid.unwrap_or_default(),
                    heartbeat_ms,
                })
            }
            OUTPUT_TYPE_FILE => {
                let f = object_or_none::<RawFile>("file", self.file)?
                    .ok_or_else(|| Error::new("missing file config"))?;
                OutputKind::File(FileConfig { name: f.name })
            }
            OUTPUT_TYPE_ROTATING_FILE => {
                let r = object_or_none::<RawRotatingFile>("rotating_file", self.rotating_file)?
                    .ok_or_else(|| Error::new("missing rotating_file config"))?;
                OutputKind::RotatingFile(RotatingFileConfig {
                    file_root: r.file_root,
                    max_file_interval: nonneg_clamped(
                        "rotating_file.max_file_interval",
                        r.max_file_interval.unwrap_or(DEFAULT_MAX_FILE_INTERVAL),
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
                let c = object_or_none::<RawLibpcap>("libpcap", self.libpcap)?
                    .ok_or_else(|| Error::new("missing libpcap config"))?;
                CapturerKind::Libpcap(LibpcapConfig {
                    interface: c.interface,
                    snaplen: snaplen_in("libpcap.snaplen", c.snaplen, true)?,
                    netns: c.netns.unwrap_or_default(),
                    bpf: c.bpf.unwrap_or_default(),
                    buffer_size_mb: positive_clamped(
                        "libpcap.buffer_size_mb",
                        c.buffer_size_mb,
                        DEFAULT_BUFFER_SIZE_MB,
                        BUFFER_SIZE_MB_MAX,
                    )?,
                    timeout_ms: nonneg_clamped(
                        "libpcap.timeout_ms",
                        c.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
                    )?,
                    not_filter_output_hosts: c.not_filter_output_hosts.unwrap_or(false),
                })
            }
            CAPTURER_TYPE_PCAP_FILE => {
                let c = object_or_none::<RawPcapFile>("pcap_file", self.pcap_file)?
                    .ok_or_else(|| Error::new("missing pcap_file config"))?;
                CapturerKind::PcapFile(PcapFileConfig {
                    file_name: c.file_name,
                    bpf: c.bpf.unwrap_or_default(),
                })
            }
            CAPTURER_TYPE_DPDK_PDUMP => {
                let c = object_or_none::<RawDpdk>("dpdk_pdump", self.dpdk_pdump)?
                    .ok_or_else(|| Error::new("missing dpdk_pdump config"))?;
                CapturerKind::DpdkPdump(DpdkPdumpConfig {
                    interface: c.interface,
                    snaplen: snaplen_in("dpdk_pdump.snaplen", c.snaplen, false)?,
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
                let c = object_or_none::<RawCustom>("custom", self.custom)?
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
            let p = object_or_none::<RawPipeline>("pipeline", self.pipeline)?
                .ok_or_else(|| Error::new("missing pipeline config"))?;
            u64_in(
                "pipeline.buffer_size_mb",
                p.buffer_size_mb
                    .ok_or_else(|| Error::new("missing pipeline.buffer_size_mb"))?,
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

    /// Upstream #279: `vxlan.vni1` above 24 bits is warned about and masked to
    /// its low 24 bits before being stored (the wire already shifted out the
    /// high bits). `vni2` is not masked. Mirrors
    /// `cpworker/tests/unit/config_validation.c`.
    #[test]
    fn vxlan_vni1_masked_to_low_24_bits() {
        let parse_vni =
            |json: &str| match &Config::parse_str(json).unwrap().tasks[0].outputs[0].kind {
                OutputKind::Vxlan(v) => (v.vni_version, v.vni),
                other => panic!("expected vxlan, got {other:?}"),
            };

        // in range: kept verbatim
        assert_eq!(
            parse_vni(
                r#"{"tasks":[{"req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"10.0.0.9","vni1":16777215}}]}]}"#
            ),
            (1, 0x00ff_ffff)
        );
        // above 24 bits: masked (0x1000000 -> 0)
        assert_eq!(
            parse_vni(
                r#"{"tasks":[{"req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"10.0.0.9","vni1":16777216}}]}]}"#
            ),
            (1, 0)
        );
        assert_eq!(
            parse_vni(
                r#"{"tasks":[{"req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"10.0.0.9","vni1":28036591}}]}]}"#
            ),
            (1, 0x00ab_cdef)
        );
        assert_eq!(
            parse_vni(
                r#"{"tasks":[{"req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"10.0.0.9","vni1":4294967295}}]}]}"#
            ),
            (1, 0x00ff_ffff)
        );
        // vni2 keeps the full u32 (no masking upstream)
        assert_eq!(
            parse_vni(
                r#"{"tasks":[{"req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"10.0.0.9","vni2":4294967295}}]}]}"#
            ),
            (2, u32::MAX)
        );
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

    /// Upstream `#279` ports C's numeric rules: out-of-range values *normalise*
    /// (or clamp) exactly like `parse_snaplen`/`cjson_get_integer`, while
    /// genuinely invalid values (negative where the wire requires non-negative,
    /// ports outside `[1, 65535]`, ...) still error and name the field. The
    /// differential harness (`parity/verify_config.sh`) is the acceptance test
    /// for these rules; this test only pins the boundary values.
    #[test]
    fn numeric_fields_normalise_out_of_range_values() {
        // --- libpcap.snaplen: <=0 or >MAX -> MAX ------------------------------
        for (given, want) in [
            (0_i64, SNAPLEN_MAX),
            (-1, SNAPLEN_MAX),
            (SNAPLEN_MAX + 1, SNAPLEN_MAX),
            (2048, 2048),
            (SNAPLEN_MAX, SNAPLEN_MAX),
        ] {
            let c = with_libpcap(&format!(r#""snaplen":{given}"#)).expect("accepted");
            match &c.tasks[0].capturer.kind {
                CapturerKind::Libpcap(l) => assert_eq!(l.snaplen, want as i32, "snaplen {given}"),
                other => panic!("expected libpcap capturer, got {other:?}"),
            }
        }
        let c = Config::parse_str(
            r#"{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[]}]}"#,
        )
        .expect("absent snaplen takes the default");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.snaplen, DEFAULT_SNAPLEN as i32),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }

        // --- libpcap.buffer_size_mb: <=0 rejected, >MAX -> MAX ----------------
        assert_rejects(
            "libpcap.buffer_size_mb",
            with_libpcap(r#""buffer_size_mb":0"#),
        );
        assert_rejects(
            "libpcap.buffer_size_mb",
            with_libpcap(r#""buffer_size_mb":-1"#),
        );
        let c = with_libpcap(&format!(r#""buffer_size_mb":{}"#, BUFFER_SIZE_MB_MAX + 1))
            .expect("clamped");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.buffer_size_mb, BUFFER_SIZE_MB_MAX as i32),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }

        // --- libpcap.timeout_ms: <0 rejected, >INT_MAX -> INT_MAX -------------
        assert_rejects("libpcap.timeout_ms", with_libpcap(r#""timeout_ms":-1"#));
        let c = with_libpcap(&format!(r#""timeout_ms":{}"#, TIMEOUT_MS_MAX + 1)).expect("clamped");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.timeout_ms, i32::MAX),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }

        // --- dpdk_pdump: snaplen <=0 rejected, >MAX -> MAX --------------------
        assert_rejects("dpdk_pdump.snaplen", with_dpdk(r#""snaplen":0"#));
        assert_rejects("dpdk_pdump.snaplen", with_dpdk(r#""snaplen":-1"#));
        let c = with_dpdk(&format!(r#""snaplen":{}"#, SNAPLEN_MAX + 1)).expect("clamped");
        match &c.tasks[0].capturer.kind {
            CapturerKind::DpdkPdump(d) => assert_eq!(d.snaplen, SNAPLEN_MAX as i32),
            other => panic!("expected dpdk_pdump capturer, got {other:?}"),
        }
        assert_rejects("dpdk_pdump.ring_size", with_dpdk(r#""ring_size":1"#));
        assert_rejects(
            "dpdk_pdump.ring_size",
            with_dpdk(&format!(r#""ring_size":{}"#, RING_SIZE_MAX + 1)),
        );
        let c = with_dpdk(&format!(r#""ring_size":{RING_SIZE_MAX}"#)).expect("in range");
        match &c.tasks[0].capturer.kind {
            CapturerKind::DpdkPdump(d) => assert_eq!(d.ring_size, RING_SIZE_MAX as i32),
            other => panic!("expected dpdk_pdump capturer, got {other:?}"),
        }

        // --- output slice / rate_limit_mbps: <0 rejected, >INT_MAX -> INT_MAX --
        assert_rejects("slice", with_output(r#","slice":-1"#));
        let c = with_output(&format!(r#","slice":{}"#, SLICE_MAX + 1)).expect("clamped");
        assert_eq!(c.tasks[0].outputs[0].slice, i32::MAX);
        assert_rejects("rate_limit_mbps", with_output(r#","rate_limit_mbps":-1"#));
        let c = with_output(&format!(
            r#","rate_limit_mbps":{}"#,
            RATE_LIMIT_MBPS_MAX + 1
        ))
        .expect("clamped");
        assert_eq!(c.tasks[0].outputs[0].rate_limit_mbps, i32::MAX as u64);

        // --- pipeline.buffer_size_mb: [1, SIZE_MAX/1MiB] ----------------------
        let pipeline = |mb: i64| {
            Config::parse_str(&format!(
                r#"{{"execution_model":"pipeline","pipeline":{{"buffer_size_mb":{mb}}},"tasks":[]}}"#
            ))
        };
        assert_rejects("pipeline.buffer_size_mb", pipeline(0));
        assert_rejects("pipeline.buffer_size_mb", pipeline(-1));
        assert_eq!(
            pipeline(256).expect("in range").pipeline_buffer_size_mb,
            256
        );
        assert_eq!(
            pipeline(PIPELINE_BUFFER_MB_MAX)
                .expect("the C bound is SIZE_MAX/1MiB")
                .pipeline_buffer_size_mb,
            PIPELINE_BUFFER_MB_MAX as u64
        );

        // --- rotating_file.max_file_interval: default 60, <0 rejected ---------
        let rotating = |kv: &str| {
            Config::parse_str(&format!(
                r#"{{"tasks":[{{
                "capturer": {{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},
                "outputs": [{{"type":"rotating_file","rotating_file":{{"file_root":"/tmp"{kv}}}}}]
            }}]}}"#
            ))
        };
        let interval = |c: &Config| match &c.tasks[0].outputs[0].kind {
            OutputKind::RotatingFile(r) => r.max_file_interval,
            other => panic!("expected rotating_file output, got {other:?}"),
        };
        assert_eq!(interval(&rotating("").expect("default")), 60);
        assert_rejects(
            "rotating_file.max_file_interval",
            rotating(r#","max_file_interval":-1"#),
        );
        assert_eq!(
            interval(
                &rotating(&format!(
                    r#","max_file_interval":{}"#,
                    MAX_FILE_INTERVAL_MAX + 1
                ))
                .expect("clamped")
            ),
            i32::MAX
        );

        // --- vxlan.split.max_payload_size: [0, 65535] -------------------------
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
        assert_rejects("max_payload_size", vxlan(&split(-1)));
        assert!(vxlan(&split(65535)).is_ok(), "65535 is in range");
    }

    /// C's `cjson_get_integer` uses `floor(value) == value`: an integral float is
    /// an integer (`2048.0`, `1e3`), a fraction is not, and an explicit `null` is
    /// an error (only an *absent* key takes the default).
    #[test]
    fn integral_floats_are_accepted_like_cjson() {
        let c = with_libpcap(r#""snaplen":2048.0"#).expect("2048.0 is an integer");
        match &c.tasks[0].capturer.kind {
            CapturerKind::Libpcap(l) => assert_eq!(l.snaplen, 2048),
            other => panic!("expected libpcap capturer, got {other:?}"),
        }
        let c = with_output(r#","slice":1e3"#).expect("1e3 is 1000");
        assert_eq!(c.tasks[0].outputs[0].slice, 1000);
        // The fraction/null errors come from the serde layer (before field
        // validation), so they need not name the field - only reject.
        assert!(with_libpcap(r#""snaplen":2048.5"#).is_err());
        assert!(with_libpcap(r#""snaplen":null"#).is_err());
    }

    /// `zmq.hwm` follows libzmq: `0` means "no limit" and is accepted, a negative
    /// value is rejected (naming the field, with a well-formed message), and a
    /// very large value is clamped to `INT_MAX` by the single gate.
    #[test]
    fn zmq_hwm_follows_libzmq() {
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
        let hwm_of = |c: &Config| match &c.tasks[0].outputs[0].kind {
            OutputKind::Zmq(z) => z.hwm,
            other => panic!("expected zmq output, got {other:?}"),
        };
        assert_eq!(hwm_of(&with_hwm(0).expect("0 = no limit")), 0);
        assert_eq!(hwm_of(&with_hwm(100).expect("in range")), 100);
        assert_eq!(
            hwm_of(&with_hwm(i64::from(i32::MAX) + 1).expect("clamped")),
            i32::MAX
        );
        let err = with_hwm(-1).expect_err("negative hwm must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("zmq.hwm"), "must name the field: {msg}");
        assert!(
            !msg.contains("  "),
            "the user-visible message must be well-formed: {msg}"
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

#[cfg(test)]
mod accessor_tests {
    use super::*;

    fn vxlan(host: &str) -> VxlanConfig {
        VxlanConfig {
            host: host.into(),
            port: 4789,
            capture_time: false,
            vni_version: 1,
            vni: 0,
            bind_device: String::new(),
            pmtudisc: -1,
            split: SplitConfig::default(),
        }
    }

    fn gre(host: &str) -> GreConfig {
        GreConfig {
            host: host.into(),
            service_tag: 0,
            bind_device: String::new(),
            pmtudisc: -1,
        }
    }

    fn zmq(host: &str) -> ZmqConfig {
        ZmqConfig {
            host: host.into(),
            port: 0,
            hwm: DEFAULT_ZMQ_HWM,
            service_tag: 0,
            uuid: String::new(),
            heartbeat_ms: 0,
        }
    }

    fn libpcap(iface: &str, snaplen: i32) -> LibpcapConfig {
        LibpcapConfig {
            interface: iface.into(),
            snaplen,
            netns: String::new(),
            bpf: String::new(),
            buffer_size_mb: 0,
            timeout_ms: 0,
            not_filter_output_hosts: false,
        }
    }

    fn oc(kind: OutputKind) -> OutputConfig {
        OutputConfig {
            kind,
            rate_limit_mbps: 0,
            slice: 0,
        }
    }

    #[test]
    fn output_type_strings() {
        assert_eq!(
            oc(OutputKind::Vxlan(vxlan("h"))).output_type(),
            OUTPUT_TYPE_VXLAN
        );
        assert_eq!(oc(OutputKind::Gre(gre("h"))).output_type(), OUTPUT_TYPE_GRE);
        assert_eq!(oc(OutputKind::Zmq(zmq("h"))).output_type(), OUTPUT_TYPE_ZMQ);
        assert_eq!(
            oc(OutputKind::File(FileConfig { name: "f".into() })).output_type(),
            OUTPUT_TYPE_FILE
        );
        assert_eq!(
            oc(OutputKind::RotatingFile(RotatingFileConfig {
                file_root: "/tmp".into(),
                max_file_interval: 60,
            }))
            .output_type(),
            OUTPUT_TYPE_ROTATING_FILE
        );
        assert_eq!(oc(OutputKind::Null).output_type(), OUTPUT_TYPE_NULL);
    }

    #[test]
    fn forward_host_only_for_network_outputs() {
        assert_eq!(
            oc(OutputKind::Vxlan(vxlan("10.0.0.1"))).forward_host(),
            Some("10.0.0.1")
        );
        assert_eq!(
            oc(OutputKind::Gre(gre("10.0.0.2"))).forward_host(),
            Some("10.0.0.2")
        );
        assert_eq!(
            oc(OutputKind::Zmq(zmq("10.0.0.3"))).forward_host(),
            Some("10.0.0.3")
        );
        assert_eq!(
            oc(OutputKind::File(FileConfig { name: "f".into() })).forward_host(),
            None
        );
        assert_eq!(oc(OutputKind::Null).forward_host(), None);
    }

    #[test]
    fn capturer_type_strings() {
        assert_eq!(
            CapturerKind::Libpcap(libpcap("eth0", 128)).capturer_type(),
            CAPTURER_TYPE_LIBPCAP
        );
        assert_eq!(
            CapturerKind::PcapFile(PcapFileConfig {
                file_name: "x.pcap".into(),
                bpf: String::new(),
            })
            .capturer_type(),
            CAPTURER_TYPE_PCAP_FILE
        );
        assert_eq!(
            CapturerKind::DpdkPdump(DpdkPdumpConfig {
                interface: "eth1".into(),
                snaplen: 64,
                bpf: String::new(),
                ring_size: 1024,
            })
            .capturer_type(),
            CAPTURER_TYPE_DPDK_PDUMP
        );
    }

    #[test]
    fn capturer_snaplen_and_interface() {
        let l = CapturerKind::Libpcap(libpcap("eth7", 128));
        assert_eq!(l.snaplen(), 128);
        assert_eq!(l.interface(), Some("eth7"));

        let p = CapturerKind::PcapFile(PcapFileConfig {
            file_name: "x.pcap".into(),
            bpf: String::new(),
        });
        assert_eq!(p.snaplen(), 262144);
        assert_eq!(p.interface(), None);

        let d = CapturerKind::DpdkPdump(DpdkPdumpConfig {
            interface: "eth9".into(),
            snaplen: 64,
            bpf: String::new(),
            ring_size: 1024,
        });
        assert_eq!(d.snaplen(), 64);
        assert_eq!(d.interface(), Some("eth9"));
    }

    #[derive(serde::Deserialize, Debug)]
    struct NonNull {
        #[serde(default, deserialize_with = "super::de_nonnull")]
        x: Option<String>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct NonNullBool {
        #[serde(default, deserialize_with = "super::de_nonnull_bool")]
        b: bool,
    }

    #[test]
    fn de_nonnull_allows_absent_and_value_but_rejects_null() {
        assert!(serde_json::from_str::<NonNull>("{}").unwrap().x.is_none());
        assert_eq!(
            serde_json::from_str::<NonNull>(r#"{"x":"v"}"#)
                .unwrap()
                .x
                .as_deref(),
            Some("v")
        );
        let e = serde_json::from_str::<NonNull>(r#"{"x":null}"#).unwrap_err();
        assert!(e.to_string().contains("null value not allowed"), "{e}");
    }

    #[test]
    fn de_nonnull_bool_allows_absent_and_value_but_rejects_null() {
        assert!(!serde_json::from_str::<NonNullBool>("{}").unwrap().b);
        assert!(
            serde_json::from_str::<NonNullBool>(r#"{"b":true}"#)
                .unwrap()
                .b
        );
        let e = serde_json::from_str::<NonNullBool>(r#"{"b":null}"#).unwrap_err();
        assert!(e.to_string().contains("null value not allowed"), "{e}");
    }

    const DUMP_JSON: &str = r#"{
        "tasks": [{
            "fingerprint": "fp1",
            "req_pattern": { "type": "auto" },
            "capturer": { "type": "libpcap", "libpcap": { "interface": "eth7", "bpf": "udp" } },
            "outputs": [
                { "type": "vxlan", "vxlan": { "host": "10.0.0.9", "vni1": 7 } },
                { "type": "gre", "gre": { "host": "10.0.0.10" } },
                { "type": "zmq", "zmq": { "host": "10.0.0.11", "port": 5555 } },
                { "type": "null" }
            ]
        }]
    }"#;

    #[test]
    fn canonical_dump_lists_every_output_and_the_libpcap_capturer() {
        let c = Config::parse_str(DUMP_JSON).expect("parse dump json");
        let d = canonical_dump(&c);
        assert!(d.contains("capturer=libpcap snaplen="), "{d}");
        assert!(d.contains("bpf=udp"), "{d}");
        assert!(
            d.contains("output type=vxlan") && d.contains("host=10.0.0.9"),
            "{d}"
        );
        assert!(
            d.contains("output type=gre") && d.contains("host=10.0.0.10"),
            "{d}"
        );
        assert!(
            d.contains("output type=zmq") && d.contains("host=10.0.0.11"),
            "{d}"
        );
        assert!(
            d.lines()
                .any(|l| l.starts_with("  output type=null") && l.ends_with("host=")),
            "null output has no forward host: {d}"
        );
        assert!(
            d.contains("exclude_bpf=(udp) and not host 10.0.0.9")
                && d.contains("not host 10.0.0.10"),
            "exclusion must keep the capturer bpf and list the output hosts: {d}"
        );
    }

    fn err_msg(json: &str) -> String {
        match Config::parse_str(json) {
            Ok(_) => panic!("expected an error for {json}"),
            Err(e) => e.to_string(),
        }
    }

    fn task_with(output: &str) -> String {
        format!(
            r#"{{"tasks":[{{"fingerprint":"a","req_pattern":{{"type":"auto"}},"capturer":{{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},"outputs":[{output}]}}]}}"#
        )
    }

    #[test]
    fn int_in_enforces_the_inclusive_bounds() {
        assert_eq!(int_in("f", 5, 0, 10).unwrap(), 5);
        assert_eq!(int_in("f", 0, 0, 10).unwrap(), 0);
        assert_eq!(int_in("f", 10, 0, 10).unwrap(), 10);
        assert!(int_in("f", -1, 0, 10).is_err());
        assert!(int_in("f", 11, 0, 10).is_err());
    }

    #[test]
    fn parse_pmtudisc_maps_the_three_keywords() {
        assert_eq!(parse_pmtudisc("do").unwrap(), IP_PMTUDISC_DO);
        assert_eq!(parse_pmtudisc("dont").unwrap(), IP_PMTUDISC_DONT);
        assert_eq!(parse_pmtudisc("want").unwrap(), IP_PMTUDISC_WANT);
        match parse_pmtudisc("maybe") {
            Ok(_) => panic!("expected an error"),
            Err(e) => assert!(e.to_string().contains("invalid pmtudisc"), "{e}"),
        }
    }

    #[test]
    fn omitted_pmtudisc_defaults_to_minus_one() {
        let v = Config::parse_str(&task_with(
            r#"{"type":"vxlan","vxlan":{"host":"1.2.3.4","vni1":1}}"#,
        ))
        .unwrap();
        match &v.tasks[0].outputs[0].kind {
            OutputKind::Vxlan(c) => assert_eq!(c.pmtudisc, -1),
            other => panic!("expected vxlan, got {other:?}"),
        }
        let g =
            Config::parse_str(&task_with(r#"{"type":"gre","gre":{"host":"1.2.3.4"}}"#)).unwrap();
        match &g.tasks[0].outputs[0].kind {
            OutputKind::Gre(c) => assert_eq!(c.pmtudisc, -1),
            other => panic!("expected gre, got {other:?}"),
        }
    }

    #[test]
    fn rotating_file_default_interval_is_sixty() {
        let c = Config::parse_str(&task_with(
            r#"{"type":"rotating_file","rotating_file":{"file_root":"/tmp"}}"#,
        ))
        .unwrap();
        match &c.tasks[0].outputs[0].kind {
            OutputKind::RotatingFile(r) => assert_eq!(r.max_file_interval, 60),
            other => panic!("expected rotating_file, got {other:?}"),
        }
    }

    #[test]
    fn task_capturer_snaplen_matches_the_capturer() {
        let c = Config::parse_str(
            r#"{"tasks":[{"fingerprint":"a","req_pattern":{"type":"auto"},"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":3000}},"outputs":[{"type":"null"}]}]}"#,
        )
        .unwrap();
        assert_eq!(task_capturer_snaplen(&c.tasks[0]), 3000);
    }

    #[test]
    fn log_levels_map_and_reject_unknown() {
        for (s, want) in [
            ("DEBUG", LOG_DEBUG),
            ("Info", LOG_INFO),
            ("warn", LOG_WARN),
            ("error", LOG_ERROR),
        ] {
            let c = Config::parse_str(&format!(r#"{{"log_level":"{s}","tasks":[]}}"#)).unwrap();
            assert_eq!(c.log_level, want, "log_level {s}");
        }
        assert_eq!(
            Config::parse_str(r#"{"tasks":[]}"#).unwrap().log_level,
            LOG_INFO
        );
        assert!(Config::parse_str(r#"{"log_level":"TRACE","tasks":[]}"#).is_err());
    }

    #[test]
    fn execution_model_pipeline_requires_and_reads_the_pipeline_block() {
        let m = err_msg(r#"{"execution_model":"pipeline","tasks":[]}"#);
        assert!(m.contains("missing pipeline config"), "{m}");
        let c = Config::parse_str(
            r#"{"execution_model":"pipeline","pipeline":{"buffer_size_mb":64},"tasks":[]}"#,
        )
        .unwrap();
        assert_eq!(c.execution_model, ExecutionModel::Pipeline);
        assert_eq!(c.pipeline_buffer_size_mb, 64);
    }

    #[test]
    fn empty_fingerprints_are_dropped_and_duplicates_rejected() {
        let two = |a: &str, b: &str| {
            format!(
                r#"{{"tasks":[
                    {{"fingerprint":"{a}","req_pattern":{{"type":"auto"}},"capturer":{{"type":"libpcap","libpcap":{{"interface":"eth0"}}}},"outputs":[{{"type":"null"}}]}},
                    {{"fingerprint":"{b}","req_pattern":{{"type":"auto"}},"capturer":{{"type":"libpcap","libpcap":{{"interface":"eth1"}}}},"outputs":[{{"type":"null"}}]}}
                ]}}"#
            )
        };
        let c = Config::parse_str(&two("", "a")).unwrap();
        assert!(c.tasks[0].fingerprint.is_none(), "empty string is dropped");
        assert_eq!(c.tasks[1].fingerprint.as_deref(), Some("a"));
        assert!(Config::parse_str(&two("dup", "dup")).is_err());
        assert!(Config::parse_str(&two("", "")).is_ok());
    }
}
