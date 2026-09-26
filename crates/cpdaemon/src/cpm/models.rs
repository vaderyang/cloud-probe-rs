//! CPM API models. Port of `cpdaemon/pkg/cpm/models.go`.

use serde::{Deserialize, Serialize};

pub const REQ_PATTERN_TYPE_AUTO: &str = "AUTO";
pub const REQ_PATTERN_TYPE_CUSTOM: &str = "CUSTOM";

pub const PACKET_CHANNEL_TYPE_GRE: &str = "GRE";
pub const PACKET_CHANNEL_TYPE_ZMQ: &str = "ZMQ";
pub const PACKET_CHANNEL_TYPE_VXLAN: &str = "VXLAN";
pub const PACKET_CHANNEL_TYPE_FILE: &str = "FILE";

pub const API_VERSION_V1: &str = "v1";

// Model constants mirroring the Go `pkg/cpm/models.go` exported values. Some are
// not yet referenced by the daemon; kept for parity (PARITY.md §5).
#[allow(dead_code)]
pub const STATUS_ACTIVE: &str = "active";
#[allow(dead_code)]
pub const STATUS_INACTIVE: &str = "inactive";
#[allow(dead_code)]
pub const STATUS_ERROR: &str = "error";

#[allow(dead_code)]
pub const SYNC_MODE_PULL: &str = "pull";
#[allow(dead_code)]
pub const SYNC_MODE_PUSH: &str = "push";

#[allow(dead_code)]
pub const DEPLOY_ENV_INSTANCE: &str = "INSTANCE";
#[allow(dead_code)]
pub const DEPLOY_ENV_HOST: &str = "HOST";

pub const SUPPORT_API_VERSIONS: &[&str] = &[API_VERSION_V1];
#[allow(dead_code)]
pub const SUPPORT_PACKET_CHANNEL_TYPES: &[&str] = &[
    PACKET_CHANNEL_TYPE_GRE,
    PACKET_CHANNEL_TYPE_ZMQ,
    PACKET_CHANNEL_TYPE_VXLAN,
    PACKET_CHANNEL_TYPE_FILE,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    #[serde(rename = "uuid", default)]
    pub uuid: String,
    #[serde(default)]
    pub service: String,
    #[serde(rename = "nodeName", default)]
    pub node_name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "podName", default)]
    pub pod_name: String,
    #[serde(rename = "platformId", default)]
    pub platform_id: String,
    #[serde(rename = "apiVersion", default)]
    pub api_version: String,
    #[serde(rename = "supportApiVersions", default)]
    pub support_api_versions: Vec<String>,
    #[serde(rename = "startTimestamp", default)]
    pub start_timestamp: i64,
    #[serde(rename = "startMicroTimestamp", default)]
    pub start_micro_timestamp: i64,
    #[serde(rename = "clientVersion", default)]
    pub client_version: String,
    #[serde(default)]
    pub labels: Vec<LabelEntry>,
    #[serde(rename = "networkInterfaces", default)]
    pub network_interfaces: Vec<NicEntry>,
    #[serde(rename = "deployEnv", default)]
    pub deploy_env: String,
    #[serde(rename = "paUUID", default)]
    pub pa_uuid: String,
}

impl RegisterRequest {
    pub fn fix_zero(&mut self) {
        // Labels / NetworkInterfaces must serialize as [] not null.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(default)]
    pub id: i64,
    #[serde(rename = "paUUID", default)]
    pub pa_uuid: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "registerRequestIpAddress", default)]
    pub register_request_ip_address: String,
    #[serde(rename = "nodeName", default)]
    pub node_name: String,
    #[serde(rename = "platformId", default)]
    pub platform_id: String,
    #[serde(rename = "startTimestamp", default)]
    pub start_timestamp: i64,
    #[serde(rename = "startMicroTimestamp", default)]
    pub start_micro_timestamp: i64,
    #[serde(rename = "syncInterval", default)]
    pub sync_interval: i32,
    #[serde(rename = "clientVersion", default)]
    pub client_version: String,
    #[serde(rename = "networkInterfaces", default)]
    pub network_interfaces: Vec<NicEntry>,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct SyncStrategyResult {
    pub changed: bool,
    pub response: Option<SyncStrategyResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStrategyResponse {
    #[serde(default)]
    pub id: i64,
    #[serde(rename = "daemonId", default)]
    pub daemon_id: i64,
    #[serde(default)]
    pub version: i32,
    #[serde(rename = "syncInterval", default)]
    pub sync_interval: i32,
    #[serde(rename = "cpuLimit", default)]
    pub cpu_limit: Option<f64>,
    #[serde(rename = "memLimit", default)]
    pub mem_limit: Option<i64>,
    #[serde(default)]
    pub strategy: Vec<StrategyEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StrategyEntry {
    #[serde(rename = "interfaceNames", default)]
    pub interface_names: Vec<String>,
    #[serde(rename = "instanceNames", default)]
    pub instance_names: Vec<String>,
    #[serde(rename = "containerIds", default)]
    pub container_ids: Vec<String>,
    #[serde(default)]
    pub bpf: Option<String>,
    #[serde(rename = "sliceLen", default)]
    pub slice_len: Option<i32>,
    #[serde(rename = "buffLimit", default)]
    pub buff_limit: Option<i64>,
    #[serde(rename = "capTime", default)]
    pub cap_time: Option<i32>,
    #[serde(rename = "forwardRateLimit", default)]
    pub forward_rate_limit: Option<i32>,
    #[serde(rename = "hasServiceTag", default)]
    pub has_service_tag: bool,
    #[serde(rename = "serviceTag", default)]
    pub service_tag: Option<i32>,
    #[serde(rename = "hasPacketSplit", default)]
    pub has_packet_split: bool,
    #[serde(rename = "packetSplitBytes", default)]
    pub packet_split_bytes: Option<i32>,
    #[serde(rename = "recalculateChecksum", default)]
    pub recalculate_checksum: bool,
    #[serde(rename = "hasReqPattern", default)]
    pub has_req_pattern: bool,
    #[serde(rename = "reqPattern", default)]
    pub req_pattern: Option<String>,
    #[serde(rename = "reqPatternType", default)]
    pub req_pattern_type: Option<String>,
    #[serde(rename = "apiVersion", default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub startup: Option<String>,
    #[serde(rename = "packetChannelType", default)]
    pub packet_channel_type: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(rename = "dumpDir", default)]
    pub dump_dir: Option<String>,
    #[serde(rename = "dumpInterval", default)]
    pub dump_interval: Option<i32>,
    #[serde(rename = "hasObservationTag", default)]
    pub has_observation_tag: bool,
    #[serde(rename = "observationDomainIds", default)]
    pub observation_domain_ids: Vec<u32>,
    #[serde(rename = "observationPointIds", default)]
    pub observation_point_ids: Vec<u8>,
    #[serde(rename = "hasExtensionFlag", default)]
    pub has_extension_flag: bool,
    #[serde(rename = "extensionFlag", default)]
    pub extension_flag: Option<i8>,
    #[serde(rename = "zmqHeartbeatMs", default)]
    pub zmq_heartbeat_ms: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncMetricsRequest {
    #[serde(default)]
    pub logs: Vec<LogEntry>,
    #[serde(default)]
    pub metrics: Option<MetricsEntry>,
    #[serde(default)]
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NicEntry {
    #[serde(default)]
    pub index: i32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub flags: i32,
    #[serde(default)]
    pub mtu: i32,
    #[serde(rename = "inetAddresses", default)]
    pub inet_addresses: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabelEntry {
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(rename = "logTimestamp", default)]
    pub timestamp: i64,
    #[serde(rename = "logMicroTimestamp", default)]
    pub micro_timestamp: i64,
    #[serde(rename = "logLevel", default)]
    pub level: String,
    #[serde(rename = "logDetails", default)]
    pub details: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsEntry {
    #[serde(rename = "samplingTimestamp", default)]
    pub sampling_timestamp: i64,
    #[serde(rename = "samplingMicroTimestamp", default)]
    pub sampling_micro_timestamp: i64,
    #[serde(rename = "startTime", default)]
    pub start_time: i64,
    #[serde(rename = "cpuLoad", default)]
    pub cpu_load: f64,
    #[serde(rename = "cpuLoadRate", default)]
    pub cpu_load_rate: f64,
    #[serde(rename = "memUse", default)]
    pub mem_use: u64,
    #[serde(rename = "memUseRate", default)]
    pub mem_use_rate: f64,
    #[serde(rename = "capBytes", default)]
    pub cap_bytes: u64,
    #[serde(rename = "capPackets", default)]
    pub cap_packets: u64,
    #[serde(rename = "capDrop", default)]
    pub cap_drop: u64,
    #[serde(rename = "fwdBytes", default)]
    pub fwd_bytes: u64,
    #[serde(rename = "fwdPackets", default)]
    pub fwd_packets: u64,
    #[serde(rename = "capBuff", default)]
    pub cap_buff: u64,
}

impl MetricsEntry {
    pub fn set_task_stats(&mut self, stats: &cpgolib::cpworker::StatsSummary) {
        self.cap_bytes += stats.capture.cap_bytes.bytes;
        self.cap_packets += stats.capture.cap_packets.packets;
        self.cap_drop += stats.capture.drop_packets.packets;
        self.fwd_bytes += stats.output.fwd_bytes.bytes;
        self.fwd_packets += stats.output.fwd_packets.packets;
    }
}
