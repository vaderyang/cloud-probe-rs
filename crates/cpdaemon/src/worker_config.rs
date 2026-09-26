//! cpworker worker configuration model. Port of `cpdaemon/pkg/worker/config.go`.
//!
//! These structures serialize to the exact JSON schema cpworker consumes.

use serde::{Deserialize, Serialize};

pub const CAPTURER_TYPE_LIBPCAP: &str = "libpcap";

pub const OUTPUT_TYPE_VXLAN: &str = "vxlan";
pub const OUTPUT_TYPE_GRE: &str = "gre";
pub const OUTPUT_TYPE_ZMQ: &str = "zmq";
#[allow(dead_code)] // ported constant, not yet wired (PARITY.md §5)
pub const OUTPUT_TYPE_FILE: &str = "file";
pub const OUTPUT_TYPE_ROTATING_FILE: &str = "rotating_file";

pub const REQ_PATTERN_TYPE_AUTO: &str = "auto";
pub const REQ_PATTERN_TYPE_CUSTOM: &str = "custom";

pub const EXECUTION_MODEL_RTC: &str = "rtc";
pub const EXECUTION_MODEL_PIPELINE: &str = "pipeline";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_affinity: Option<String>,
    pub log_level: String,
    pub execution_model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<PipelineConfig>,
    pub control: ControlConfig,
    pub tasks: Vec<TaskConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub buffer_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix: Option<ControlUnixConfig>,
}

impl ControlConfig {
    pub fn connect_string(&self) -> String {
        match self.ty.as_str() {
            "unix" => match &self.unix {
                Some(u) => format!("unix://{}", u.path),
                None => "unix://".to_string(),
            },
            _ => String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlUnixConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_pattern: Option<ReqPatternConfig>,
    pub capturer: CapturerConfig,
    pub outputs: Vec<OutputConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqPatternConfig {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomReqPatternConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomReqPatternConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturerConfig {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub libpcap: Option<LibpcapConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibpcapConfig {
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snaplen: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_size_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_filter_output_hosts: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_mbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slice: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vxlan: Option<VxlanOutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gre: Option<GreOutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zmq: Option<ZmqOutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileOutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotating_file: Option<RotatingFileOutputConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSplitConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_payload_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recalculate_checksum: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VxlanOutputConfig {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vni1: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vni2: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pmtudisc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<PacketSplitConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreOutputConfig {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pmtudisc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZmqOutputConfig {
    pub host: String,
    pub port: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tag: Option<u32>,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_ms: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOutputConfig {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatingFileOutputConfig {
    pub file_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_interval: Option<i32>,
}
