//! cpdaemon configuration. Port of the viper key set in
//! `cpdaemon/cmd/internal/asm/key.go`, loaded from JSON.

use serde::Deserialize;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub listen: Listen,
    pub log: Log,
    pub tool: Tool,
    pub cgroup: Cgroup,
    pub cpm: Cpm,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Listen {
    pub http: HttpListen,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpListen {
    pub address: String,
    pub port: String,
}

impl Default for HttpListen {
    fn default() -> Self {
        HttpListen {
            address: String::new(),
            port: "9022".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Log {
    pub level: String,
    pub output: LogOutput,
}

impl Default for Log {
    fn default() -> Self {
        Log {
            level: "info".into(),
            output: LogOutput::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LogOutput {
    #[serde(rename = "type")]
    pub ty: String,
    pub rotating_file: RotatingFileLog,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RotatingFileLog {
    pub file_name: String,
    pub max_size: String,
    pub max_backups: String,
    pub max_age: String,
}

impl Default for RotatingFileLog {
    fn default() -> Self {
        RotatingFileLog {
            file_name: String::new(),
            max_size: "100".into(),
            max_backups: "3".into(),
            max_age: "30".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Tool {
    pub get_container_host_pid_script: String,
    pub get_kvm_instances_script: String,
    pub get_kvm_instance_nics_script: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Cgroup {
    pub version: String,
    pub root: String,
    pub hierarchy: String,
}

impl Default for Cgroup {
    fn default() -> Self {
        Cgroup {
            version: "auto".into(),
            root: "/sys/fs/cgroup".into(),
            hierarchy: "cloud-probe".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Cpm {
    pub base_url: String,
    pub client: CpmClient,
    pub syncer: CpmSyncer,
    pub reg: CpmReg,
    pub worker: CpmWorker,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpmClient {
    pub timeout: String,
    pub dial_timeout: String,
    pub response_header_timeout: String,
    pub max_idle_conns: String,
    pub max_idle_conns_per_host: String,
    pub tls: CpmClientTls,
}

impl Default for CpmClient {
    fn default() -> Self {
        CpmClient {
            timeout: "15s".into(),
            dial_timeout: "5s".into(),
            response_header_timeout: "15s".into(),
            max_idle_conns: "10".into(),
            max_idle_conns_per_host: "5".into(),
            tls: CpmClientTls::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CpmClientTls {
    pub pkcs12_cert_file: String,
    pub pkcs12_cert_password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpmSyncer {
    pub reg_retry_interval: String,
    pub sync_strategy_interval: String,
    pub sync_strategy_max_retries: String,
    pub sync_metric_interval: String,
    pub stop_worker_after_reg_fail_minutes: String,
    pub nic_change_detect_enable: String,
    pub nic_change_detect_interval: String,
}

impl Default for CpmSyncer {
    fn default() -> Self {
        CpmSyncer {
            reg_retry_interval: "5s".into(),
            sync_strategy_interval: "15s".into(),
            sync_strategy_max_retries: "3".into(),
            sync_metric_interval: "15s".into(),
            stop_worker_after_reg_fail_minutes: "30".into(),
            nic_change_detect_enable: String::new(),
            nic_change_detect_interval: "15s".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpmReg {
    pub name: String,
    pub platform_id: String,
    pub deploy_env: String,
    pub labels: Vec<String>,
    pub including_nics: Vec<String>,
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
    pub uuid_file: String,
    pub uuid_gen: UuidGen,
}

impl Default for CpmReg {
    fn default() -> Self {
        CpmReg {
            name: String::new(),
            platform_id: String::new(),
            deploy_env: String::new(),
            labels: Vec::new(),
            including_nics: Vec::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            uuid_file: "/usr/local/bin/uuid".into(),
            uuid_gen: UuidGen::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UuidGen {
    #[serde(rename = "type")]
    pub ty: String,
    pub env: UuidGenEnv,
}

impl Default for UuidGen {
    fn default() -> Self {
        UuidGen {
            ty: "random".into(),
            env: UuidGenEnv::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UuidGenEnv {
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpmWorker {
    pub pid_file: String,
    pub config_file: String,
    pub executable: String,
    pub log_level: String,
    pub update_policy: String,
    pub cpu_affinity: String,
    pub control: WorkerControl,
    pub execution_model: String,
    pub memory_policy: WorkerMemory,
}

impl Default for CpmWorker {
    fn default() -> Self {
        CpmWorker {
            pid_file: "cpm-worker.pid".into(),
            config_file: "cpm-worker.json".into(),
            executable: "cpworker".into(),
            log_level: "INFO".into(),
            update_policy: "reload".into(),
            cpu_affinity: String::new(),
            control: WorkerControl::default(),
            execution_model: "pipeline".into(),
            memory_policy: WorkerMemory::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WorkerControl {
    #[serde(rename = "type")]
    pub ty: String,
    pub unix: WorkerControlUnix,
}

impl Default for WorkerControl {
    fn default() -> Self {
        WorkerControl {
            ty: "unix".into(),
            unix: WorkerControlUnix::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WorkerControlUnix {
    pub path: String,
}

impl Default for WorkerControlUnix {
    fn default() -> Self {
        WorkerControlUnix {
            path: "cpm-worker.sock".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WorkerMemory {
    pub policy: String,
    pub default_limit_mb: String,
    pub libpcap: WorkerMemoryLibpcap,
    pub pipeline: WorkerMemoryPipeline,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WorkerMemoryLibpcap {
    pub fixed_buffer_size_mb: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WorkerMemoryPipeline {
    pub min_buffer_size_mb: String,
}

impl DaemonConfig {
    /// Load from a JSON file. A missing file yields defaults (matching viper's
    /// "config not found" behaviour).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(DaemonConfig::default());
        };
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| Error::new(format!("parse config {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DaemonConfig::default()),
            Err(e) => Err(Error::new(format!("read config {}: {e}", path.display()))),
        }
    }

    /// Duration getters with `humantime`-style parsing (falls back to defaults).
    pub fn parse_duration(s: &str, default: std::time::Duration) -> std::time::Duration {
        humantime_from_str(s).unwrap_or(default)
    }
}

fn humantime_from_str(s: &str) -> Option<std::time::Duration> {
    if s.is_empty() {
        return None;
    }
    // Reuse cpctl-style parsing via a tiny local implementation for common units.
    let s = s.trim();
    for (suffix, mult) in [("ms", 1u64), ("s", 1000), ("m", 60_000), ("h", 3_600_000)] {
        if let Some(num) = s.strip_suffix(suffix) {
            if let Ok(v) = num.trim().parse::<u64>() {
                return Some(std::time::Duration::from_millis(v * mult));
            }
        }
    }
    s.parse::<u64>().ok().map(std::time::Duration::from_secs)
}
