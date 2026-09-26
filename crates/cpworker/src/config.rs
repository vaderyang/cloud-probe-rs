//! Configuration model and parser. Port of `config.c` (cJSON -> serde_json).
//!
//! The on-disk JSON schema is unchanged so existing config files keep working.

use serde::Deserialize;
use std::path::Path;

use crate::error::{Error, Result};

pub const CAPTURER_TYPE_DPDK_PDUMP: &str = "dpdk_pdump";
pub const CAPTURER_TYPE_LIBPCAP: &str = "libpcap";
pub const CAPTURER_TYPE_PCAP_FILE: &str = "pcap_file";

pub const REQ_PATTERN_TYPE_NONE_STR: &str = "none";
pub const REQ_PATTERN_TYPE_AUTO_STR: &str = "auto";
pub const REQ_PATTERN_TYPE_CUSTOM_STR: &str = "custom";

pub const OUTPUT_TYPE_VXLAN: &str = "vxlan";
pub const OUTPUT_TYPE_GRE: &str = "gre";
pub const OUTPUT_TYPE_ZMQ: &str = "zmq";
pub const OUTPUT_TYPE_FILE: &str = "file";
pub const OUTPUT_TYPE_ROTATING_FILE: &str = "rotating_file";
pub const OUTPUT_TYPE_NULL: &str = "null";

pub const CONTROL_TYPE_UNIX: &str = "unix";

pub const IP_PMTUDISC_DONT: i32 = 0;
pub const IP_PMTUDISC_WANT: i32 = 1;
pub const IP_PMTUDISC_DO: i32 = 2;
pub const IP_PMTUDISC_PROBE: i32 = 3;

pub const LOG_TRACE: i32 = 0;
pub const LOG_DEBUG: i32 = 1;
pub const LOG_INFO: i32 = 2;
pub const LOG_WARN: i32 = 3;
pub const LOG_ERROR: i32 = 4;
pub const LOG_FATAL: i32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionModel {
    Rtc,
    Pipeline,
}

#[derive(Debug, Clone, Default)]
pub struct SplitConfig {
    pub max_payload_size: u16,
    pub recalculate_checksum: bool,
}

#[derive(Debug, Clone)]
pub struct VxlanConfig {
    pub host: String,
    pub port: u16,
    pub capture_time: bool,
    pub vni_version: u8,
    pub vni: u32,
    pub bind_device: String,
    pub pmtudisc: i32,
    pub split: SplitConfig,
}

#[derive(Debug, Clone)]
pub struct GreConfig {
    pub host: String,
    pub service_tag: u32,
    pub bind_device: String,
    pub pmtudisc: i32,
}

#[derive(Debug, Clone)]
pub struct ZmqConfig {
    pub host: String,
    pub port: u16,
    pub hwm: i32,
    pub service_tag: u32,
    pub uuid: String,
    pub heartbeat_ms: i32,
}

#[derive(Debug, Clone)]
pub struct FileConfig {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct RotatingFileConfig {
    pub file_root: String,
    pub max_file_interval: i32,
}

#[derive(Debug, Clone)]
pub enum OutputKind {
    Vxlan(VxlanConfig),
    Gre(GreConfig),
    Zmq(ZmqConfig),
    File(FileConfig),
    RotatingFile(RotatingFileConfig),
    Null,
}

#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub kind: OutputKind,
    pub rate_limit_mbps: u64,
    pub slice: i32,
}

impl OutputConfig {
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
pub struct LibpcapConfig {
    pub interface: String,
    pub snaplen: i32,
    pub netns: String,
    pub bpf: String,
    pub buffer_size_mb: i32,
    pub timeout_ms: i32,
    pub not_filter_output_hosts: bool,
}

#[derive(Debug, Clone)]
pub struct PcapFileConfig {
    pub file_name: String,
    pub bpf: String,
}

#[derive(Debug, Clone)]
pub struct DpdkPdumpConfig {
    pub interface: String,
    pub snaplen: i32,
    pub bpf: String,
    pub ring_size: i32,
}

#[derive(Debug, Clone)]
pub enum CapturerKind {
    Libpcap(LibpcapConfig),
    PcapFile(PcapFileConfig),
    DpdkPdump(DpdkPdumpConfig),
}

impl CapturerKind {
    #[must_use]
    pub fn capturer_type(&self) -> &'static str {
        match self {
            CapturerKind::Libpcap(_) => CAPTURER_TYPE_LIBPCAP,
            CapturerKind::PcapFile(_) => CAPTURER_TYPE_PCAP_FILE,
            CapturerKind::DpdkPdump(_) => CAPTURER_TYPE_DPDK_PDUMP,
        }
    }

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
pub struct CapturerConfig {
    pub kind: CapturerKind,
}

#[derive(Debug, Clone)]
pub enum ReqPatternConfig {
    None,
    Auto,
    Custom { pattern: String },
}

#[derive(Debug, Clone)]
pub struct TaskConfig {
    pub fingerprint: Option<String>,
    pub req_pattern: ReqPatternConfig,
    pub capturer: CapturerConfig,
    pub outputs: Vec<OutputConfig>,
}

#[derive(Debug, Clone)]
pub enum ControlConfig {
    UnixSocket { path: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: i32,
    pub cpu_affinity: String,
    pub execution_model: ExecutionModel,
    pub pipeline_buffer_size_mb: i32,
    pub control: Option<ControlConfig>,
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
    hwm: Option<i32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    service_tag: Option<u32>,
    #[serde(default, deserialize_with = "de_nonnull")]
    uuid: Option<String>,
    #[serde(default, deserialize_with = "de_nonnull")]
    heartbeat_ms: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawRotatingFile {
    file_root: String,
    #[serde(default, deserialize_with = "de_nonnull")]
    max_file_interval: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct RawSplit {
    #[serde(default, deserialize_with = "de_nonnull")]
    max_payload_size: Option<i64>,
    #[serde(default, deserialize_with = "de_nonnull_bool")]
    recalculate_checksum: bool,
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
            Some(v) if (0..=65535).contains(&v) => v as u16,
            _ => return Err(Error::new("invalid max_payload_size: must be 0-65535")),
        };
        Ok(SplitConfig {
            max_payload_size: max,
            recalculate_checksum: self.recalculate_checksum,
        })
    }
}

impl RawOutput {
    fn build(self) -> Result<OutputConfig> {
        let rate_limit_mbps = match self.rate_limit_mbps {
            None => 0,
            Some(v) if v >= 0 => v as u64,
            _ => return Err(Error::new("invalid rate_limit_mbps")),
        };
        let slice = self.slice.unwrap_or(0) as i32;

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
                let heartbeat_ms = match z.heartbeat_ms {
                    None => 0,
                    Some(v) if (0..=60000).contains(&v) => v,
                    _ => return Err(Error::new("invalid zmq.heartbeat_ms")),
                };
                OutputKind::Zmq(ZmqConfig {
                    host: z.host,
                    port: z.port,
                    hwm: z.hwm.unwrap_or(100),
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
                    max_file_interval: r.max_file_interval.unwrap_or(-1),
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
                let snaplen = c.snaplen.unwrap_or(2048);
                if snaplen < 0 {
                    return Err(Error::new("invalid libpcap.snaplen"));
                }
                let timeout_ms = c.timeout_ms.unwrap_or(0);
                if timeout_ms < 0 {
                    return Err(Error::new("invalid libpcap.timeout_ms"));
                }
                CapturerKind::Libpcap(LibpcapConfig {
                    interface: c.interface,
                    snaplen: snaplen as i32,
                    netns: c.netns.unwrap_or_default(),
                    bpf: c.bpf.unwrap_or_default(),
                    buffer_size_mb: c.buffer_size_mb.unwrap_or(256) as i32,
                    timeout_ms: timeout_ms as i32,
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
                    snaplen: c.snaplen.unwrap_or(2048) as i32,
                    bpf: c.bpf.unwrap_or_default(),
                    ring_size: c.ring_size.unwrap_or(2048) as i32,
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
            if p.buffer_size_mb <= 0 {
                return Err(Error::new("invalid pipeline.buffer_size_mb"));
            }
            p.buffer_size_mb as i32
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

    #[test]
    fn exclude_hosts() {
        let c = Config::parse_str(SAMPLE).unwrap();
        let out = bpf_filter_exclude_task_output_hosts("port 80", &c.tasks);
        assert_eq!(out, "(port 80) and not host 10.0.0.9");
    }
}
