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
    #[serde(deserialize_with = "de_string_or_number")]
    pub port: String,
}

/// Accept either a JSON string or a JSON number for a string field.
///
/// The Go daemon reads `listen.http.port` through viper, whose *default* is the
/// number `9022`, and its shipped `examples/template.json` therefore writes
/// `"port": 9022` unquoted; operators routinely keep that form. serde would
/// reject it ("invalid type: integer"), so the port is normalised to a string
/// here and validated by [`crate::parse_http_port`] at startup.
fn de_string_or_number<'de, D>(d: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Port {
        Text(String),
        // u16, so an out-of-range number is refused here rather than turning
        // into a string that only fails later.
        Num(u16),
    }
    Ok(match Option::<Port>::deserialize(d)? {
        None => String::new(),
        Some(Port::Text(s)) => s,
        Some(Port::Num(n)) => n.to_string(),
    })
}

impl Default for HttpListen {
    fn default() -> Self {
        HttpListen {
            address: String::new(),
            port: DEFAULT_HTTP_PORT.to_string(),
        }
    }
}

/// Default HTTP listen port. Port of `vp.SetDefault(VKey.Listen.Http.Port, 9022)`
/// from `cpdaemon/cmd/internal/asm/key.go`.
pub const DEFAULT_HTTP_PORT: u16 = 9022;

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

/// `cpm.client.tls`. Port of the PKCS#12 key set in
/// `cpdaemon/cmd/internal/asm/key.go`, plus the safe-by-default
/// `insecure_skip_verify` switch (upstream #232; the Go daemon hard-codes
/// `InsecureSkipVerify: true` and has no such key).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CpmClientTls {
    pub pkcs12_cert_file: String,
    pub pkcs12_cert_password: String,
    /// Skip verifying the CPM server's TLS certificate.
    ///
    /// Defaults to `false`: the daemon verifies the server certificate, so a
    /// man-in-the-middle on the CPM channel cannot impersonate the control
    /// plane with a self-signed certificate. This deliberately diverges from
    /// the Go oracle, which always skips verification (see `PARITY.md` §2.7).
    /// Set it to `true` only for test/legacy deployments that cannot present a
    /// trusted certificate.
    pub insecure_skip_verify: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn http_port(json: &str) -> Result<String> {
        let cfg: DaemonConfig =
            serde_json::from_str(json).map_err(|e| Error::new(format!("parse: {e}")))?;
        Ok(cfg.listen.http.port.clone())
    }

    /// The Go daemon defaults `listen.http.port` to the *number* 9022 and its
    /// shipped template.json keeps that form; viper tolerated both, so the Rust
    /// port must not fail to even load a config because of it.
    #[test]
    fn http_port_accepts_strings_and_numbers() {
        assert_eq!(
            http_port(r#"{"listen":{"http":{"port":9022}}}"#).unwrap(),
            "9022"
        );
        assert_eq!(
            http_port(r#"{"listen":{"http":{"port":"8080"}}}"#).unwrap(),
            "8080"
        );
        // absent -> default
        assert_eq!(http_port(r#"{}"#).unwrap(), "9022");
        assert_eq!(http_port(r#"{"listen":{"http":{}}}"#).unwrap(), "9022");
        // explicit null -> empty, i.e. "use the default" (see parse_http_port)
        assert_eq!(
            http_port(r#"{"listen":{"http":{"port":null}}}"#).unwrap(),
            ""
        );
        assert_eq!(http_port(r#"{"listen":{"http":{"port":""}}}"#).unwrap(), "");
    }

    /// Upstream #232: server-certificate verification must be the default, and
    /// the `insecure_skip_verify` switch must be what turns it off.
    #[test]
    fn cpm_client_tls_verification_is_on_by_default() {
        let cfg: DaemonConfig = serde_json::from_str("{\"cpm\":{\"base_url\":\"https://cpm\"}}")
            .expect("parse minimal config");
        assert!(
            !cfg.cpm.client.tls.insecure_skip_verify,
            "default must verify the CPM server certificate"
        );

        let cfg: DaemonConfig = serde_json::from_str(
            "{\"cpm\":{\"client\":{\"tls\":{\"insecure_skip_verify\":true}}}}",
        )
        .expect("parse explicit skip");
        assert!(cfg.cpm.client.tls.insecure_skip_verify);

        // The existing PKCS#12 fields must keep parsing alongside the new key.
        let cfg: DaemonConfig = serde_json::from_str(
            "{\"cpm\":{\"client\":{\"tls\":{\"pkcs12_cert_file\":\"/c.p12\",\
             \"pkcs12_cert_password\":\"s3cret\",\"insecure_skip_verify\":false}}}}",
        )
        .expect("parse pkcs12 + skip");
        assert_eq!(cfg.cpm.client.tls.pkcs12_cert_file, "/c.p12");
        assert_eq!(cfg.cpm.client.tls.pkcs12_cert_password, "s3cret");
        assert!(!cfg.cpm.client.tls.insecure_skip_verify);
    }

    #[test]
    fn http_port_rejects_things_that_are_not_ports() {
        // A JSON bool/array/object is not a port at all.
        assert!(http_port(r#"{"listen":{"http":{"port":true}}}"#).is_err());
        assert!(http_port(r#"{"listen":{"http":{"port":[22]}}}"#).is_err());
        // A number outside u16 cannot be a port either.
        assert!(http_port(r#"{"listen":{"http":{"port":70000}}}"#).is_err());
    }
}
