//! CPM syncer: register, pull strategy, reconcile the worker, push metrics.
//! Port of `cpdaemon/pkg/cpm/syncer.go`.

use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::error::{Error, Result};
use crate::tool::Tool;

use super::client::HttpClient;
use super::models::*;
use super::synclog::{SharedSyncLogBuffer, SyncLogBuffer};
use super::worker_mgr::WorkerManager;

#[derive(Debug, Clone, Default)]
pub struct RegConfig {
    pub name: String,
    pub node_name: String,
    pub platform_id: String,
    pub deploy_env: String,
    pub labels: Vec<String>,
    pub including_nics: Vec<String>,
    pub pod_name: String,
    pub namespace: String,
    #[allow(dead_code)] // ported field, not yet wired (PARITY.md §5)
    pub uuid_file: String,
    pub uuid: String,
    pub client_version: String,
}

#[derive(Debug, Clone)]
pub struct SyncerConfig {
    pub reg_retry_interval: Duration,
    pub sync_strategy_interval: Duration,
    pub sync_metric_interval: Duration,
    pub stop_worker_after_reg_fail_minutes: i64,
}

impl Default for SyncerConfig {
    fn default() -> Self {
        SyncerConfig {
            reg_retry_interval: Duration::from_secs(5),
            sync_strategy_interval: Duration::from_secs(15),
            sync_metric_interval: Duration::from_secs(15),
            stop_worker_after_reg_fail_minutes: 30,
        }
    }
}

pub struct Syncer {
    client: HttpClient,
    worker_mgr: WorkerManager,
    tool: Tool,
    reg: RegConfig,
    cfg: SyncerConfig,
    daemon_id: AtomicI64,
    version: AtomicI32,
    sync_log: SharedSyncLogBuffer,
    reg_success: Mutex<bool>,
    first_reg_fail: Mutex<Option<Instant>>,
}

impl Syncer {
    pub fn new(
        client: HttpClient,
        worker_mgr: WorkerManager,
        tool: Tool,
        reg: RegConfig,
        cfg: SyncerConfig,
    ) -> Arc<Self> {
        Arc::new(Syncer {
            client,
            worker_mgr,
            tool,
            reg,
            cfg,
            daemon_id: AtomicI64::new(0),
            version: AtomicI32::new(-1),
            sync_log: Arc::new(Mutex::new(SyncLogBuffer::default())),
            reg_success: Mutex::new(false),
            first_reg_fail: Mutex::new(None),
        })
    }

    #[allow(dead_code)] // ported accessor, not yet wired (PARITY.md §5)
    pub fn sync_log(&self) -> SharedSyncLogBuffer {
        self.sync_log.clone()
    }

    pub fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        // 1. Register (with retry).
        loop {
            if *shutdown.borrow() {
                return;
            }
            match self.register() {
                Ok(resp) => {
                    self.daemon_id.store(resp.id, Ordering::SeqCst);
                    *self.reg_success.lock() = true;
                    *self.first_reg_fail.lock() = None;
                    crate::log_info!(
                        "registered with cpm daemon_id={} paUUID={}",
                        resp.id,
                        resp.pa_uuid
                    );
                    break;
                }
                Err(e) => {
                    crate::log_error!("register failed: {e}");
                    let mut first = self.first_reg_fail.lock();
                    let since = *first.get_or_insert_with(Instant::now);
                    drop(first);
                    if self.cfg.stop_worker_after_reg_fail_minutes > 0 {
                        let limit = Duration::from_secs(
                            self.cfg.stop_worker_after_reg_fail_minutes as u64 * 60,
                        );
                        if since.elapsed() >= limit && self.worker_mgr.is_alive() {
                            crate::log_error!(
                                "registration failed for {} minutes, stopping worker",
                                self.cfg.stop_worker_after_reg_fail_minutes
                            );
                            let _ = self.worker_mgr.stop();
                        }
                    }
                    if sleep_or_shutdown(&mut shutdown, self.cfg.reg_retry_interval) {
                        return;
                    }
                }
            }
        }

        // 2. Strategy + metrics loops until shutdown.
        let strategy_interval = self.cfg.sync_strategy_interval;
        let metric_interval = self.cfg.sync_metric_interval;
        let mut next_strategy = Instant::now();
        let mut next_metric = Instant::now();

        while !*shutdown.borrow() {
            let now = Instant::now();
            if now >= next_strategy {
                if let Err(e) = self.sync_strategy_once() {
                    crate::log_error!("sync strategy failed: {e}");
                }
                next_strategy = Instant::now() + strategy_interval;
            }
            if now >= next_metric {
                if let Err(e) = self.sync_metrics_once() {
                    crate::log_error!("sync metrics failed: {e}");
                }
                next_metric = Instant::now() + metric_interval;
            }
            if sleep_or_shutdown(&mut shutdown, Duration::from_millis(200)) {
                break;
            }
        }

        crate::log_info!("syncer stopping, stopping worker");
        let _ = self.worker_mgr.stop();
    }

    fn register(&self) -> Result<RegisterResponse> {
        let now = chrono::Utc::now();
        let req = RegisterRequest {
            name: self.reg.name.clone(),
            uuid: self.reg.uuid.clone(),
            service: String::new(),
            node_name: self.reg.node_name.clone(),
            namespace: self.reg.namespace.clone(),
            pod_name: self.reg.pod_name.clone(),
            platform_id: self.reg.platform_id.clone(),
            api_version: API_VERSION_V1.to_string(),
            support_api_versions: SUPPORT_API_VERSIONS.iter().map(|s| s.to_string()).collect(),
            start_timestamp: now.timestamp(),
            start_micro_timestamp: now.timestamp_micros(),
            client_version: self.reg.client_version.clone(),
            labels: self
                .reg
                .labels
                .iter()
                .map(|v| LabelEntry { value: v.clone() })
                .collect(),
            network_interfaces: enumerate_nics(&self.reg.including_nics),
            deploy_env: self.reg.deploy_env.clone(),
            pa_uuid: String::new(),
        };
        futures_block_on(self.client.register(req))
    }

    fn active_instances(&self) -> Vec<String> {
        self.tool.get_kvm_instances().unwrap_or_default()
    }

    fn sync_strategy_once(&self) -> Result<()> {
        let daemon_id = self.daemon_id.load(Ordering::SeqCst);
        if daemon_id == 0 {
            return Ok(());
        }
        let version = self.version.load(Ordering::SeqCst);
        let result = futures_block_on(self.client.sync_strategy(daemon_id, version))?;
        if !result.changed {
            return Ok(());
        }
        let Some(resp) = result.response else {
            return Ok(());
        };
        self.version.store(resp.version, Ordering::SeqCst);

        let active = self.active_instances();
        if self.worker_mgr.is_alive() {
            self.worker_mgr.update(&resp, &self.reg.uuid, &active)?;
        } else {
            self.worker_mgr
                .create_if_dead(&resp, &self.reg.uuid, &active)?;
        }
        Ok(())
    }

    fn sync_metrics_once(&self) -> Result<()> {
        let daemon_id = self.daemon_id.load(Ordering::SeqCst);
        if daemon_id == 0 {
            return Ok(());
        }

        let begin = Instant::now();
        let now = chrono::Utc::now();
        let mut metrics = MetricsEntry {
            sampling_timestamp: now.timestamp(),
            sampling_micro_timestamp: now.timestamp_micros(),
            start_time: self
                .worker_mgr
                .start_time()
                .map(|t| t.elapsed().as_secs() as i64)
                .unwrap_or(0),
            ..Default::default()
        };

        let worker_begin = Instant::now();
        if let Ok(stats) = self
            .worker_mgr
            .collect_stats_summary(Duration::from_secs(3))
        {
            metrics.set_task_stats(&stats);
        }
        let worker_dur = worker_begin.elapsed();

        let logs = self.sync_log.lock().clear();
        let log_count = logs.len();
        let req = SyncMetricsRequest {
            logs,
            metrics: Some(metrics),
            pid: Some(self.worker_mgr.pid()).filter(|p| *p > 0),
        };
        let sync_begin = Instant::now();
        let result = futures_block_on(self.client.sync_metrics(daemon_id, req));
        let sync_dur = sync_begin.elapsed();

        // Parity with upstream `syncMetric` (acb10f2): report the push timings
        // and how many buffered log lines were sent this round (`log_count`).
        // `system_dur` is omitted because `collectSysStats` is not ported
        // (PARITY.md §5).
        crate::log_info!(
            "sync metrics finished total_dur={:?} worker_dur={:?} sync_dur={:?} log_count={log_count}",
            begin.elapsed(),
            worker_dur,
            sync_dur
        );
        result
    }
}

/// Minimal block_on for the sync parts of the syncer. The syncer runs inside a
/// tokio runtime; `Handle::current().block_on` would panic there, so use
/// `block_in_place` on the multi-thread runtime.
fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

fn sleep_or_shutdown(shutdown: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if *shutdown.borrow() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Enumerate network interfaces (name, mac, mtu, inet addresses).
fn enumerate_nics(including: &[String]) -> Vec<NicEntry> {
    let mut out = Vec::new();
    let Ok(ifaddrs) = nix::ifaddrs::getifaddrs() else {
        return out;
    };
    use std::collections::BTreeMap;

    let mut map: BTreeMap<String, NicEntry> = BTreeMap::new();
    for ifa in ifaddrs {
        if !including.is_empty() && !including.contains(&ifa.interface_name) {
            continue;
        }
        let e = map
            .entry(ifa.interface_name.clone())
            .or_insert_with(|| NicEntry {
                name: ifa.interface_name.clone(),
                ..Default::default()
            });
        if let Some(addr) = ifa.address.as_ref() {
            if let Some(link) = addr.as_link_addr() {
                if let Some(mac) = link.addr() {
                    e.mac = mac
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                }
            } else if let Some(v4) = addr.as_sockaddr_in() {
                e.inet_addresses.push(v4.ip().to_string());
            } else if let Some(v6) = addr.as_sockaddr_in6() {
                e.inet_addresses.push(v6.ip().to_string());
            }
        }
    }
    out.extend(map.into_values());
    out
}

/// Generate a UUID from the configured environment keys, or random.
pub fn generate_uuid(uuid_file: &str, uuid_gen_type: &str, env_keys: &[String]) -> Result<String> {
    match uuid_gen_type {
        "env" => {
            if env_keys.is_empty() {
                return Err(Error::new(
                    "uuid_gen.env.keys is required when uuid_gen.type is 'env'",
                ));
            }
            let mut s = String::from("a1b2c3d4e5");
            for key in env_keys {
                let val = std::env::var(key)
                    .map_err(|_| Error::new(format!("environment variable {key:?} is not set")))?;
                if val.is_empty() {
                    return Err(Error::new(format!(
                        "environment variable {key:?} is not set"
                    )));
                }
                s.push_str(&val);
            }
            Ok(uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, s.as_bytes()).to_string())
        }
        _ => {
            if !uuid_file.is_empty() {
                if let Ok(s) = std::fs::read_to_string(uuid_file) {
                    let s = s.trim();
                    if !s.is_empty() {
                        return Ok(s.to_string());
                    }
                }
            }
            Ok(uuid::Uuid::new_v4().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpm::client::ClientConfig;
    use crate::cpm::worker_mgr::{MemoryConfig, PipelineConfig, WorkerConfig};
    use crate::reslimit::CgroupCfg;
    use crate::worker_config::{ControlConfig, ControlUnixConfig};

    fn dummy_syncer() -> Arc<Syncer> {
        let client =
            HttpClient::new("http://127.0.0.1:1/", ClientConfig::default()).expect("http client");
        let wc = WorkerConfig {
            pid_file: String::new(),
            config_file: String::new(),
            executable: String::new(),
            env: Default::default(),
            work_dir: None,
            cgroup_cfg: CgroupCfg::default(),
            cpu_affinity: String::new(),
            log_level: "INFO".into(),
            control: ControlConfig {
                ty: "unix".into(),
                unix: Some(ControlUnixConfig {
                    path: "/tmp/cpdaemon-syncer-test.sock".into(),
                }),
            },
            execution_model: "rtc".into(),
            pipeline: PipelineConfig::default(),
            update_policy: "restart".into(),
            memory: MemoryConfig::default(),
        };
        let mgr = WorkerManager::new(wc, Tool::default());
        Syncer::new(
            client,
            mgr,
            Tool::default(),
            RegConfig::default(),
            SyncerConfig::default(),
        )
    }

    #[test]
    fn config_defaults_match_upstream() {
        let c = SyncerConfig::default();
        assert_eq!(c.reg_retry_interval, Duration::from_secs(5));
        assert_eq!(c.sync_strategy_interval, Duration::from_secs(15));
        assert_eq!(c.sync_metric_interval, Duration::from_secs(15));
        assert_eq!(c.stop_worker_after_reg_fail_minutes, 30);
    }

    #[test]
    fn sync_once_is_inert_before_registration() {
        let s = dummy_syncer();
        // daemon_id starts at 0, so neither sync may touch the network.
        s.sync_strategy_once().expect("strategy before register");
        s.sync_metrics_once().expect("metrics before register");
    }

    #[test]
    fn sync_log_accessor_exposes_the_shared_buffer() {
        let s = dummy_syncer();
        let log = s.sync_log();
        log.lock().write(1, 0, "INFO", "hello".into());
        assert_eq!(log.lock().clear().len(), 1);
    }

    #[test]
    fn uuid_env_requires_keys_and_non_empty_values() {
        assert!(generate_uuid("", "env", &[]).is_err());

        let key = format!("CPDAEMON_UUID_ENV_{}", std::process::id());
        std::env::remove_var(&key);
        assert!(generate_uuid("", "env", std::slice::from_ref(&key)).is_err());

        std::env::set_var(&key, "value1");
        let a = generate_uuid("", "env", std::slice::from_ref(&key)).expect("env uuid");
        let b = generate_uuid("", "env", std::slice::from_ref(&key)).expect("env uuid");
        assert_eq!(a, b, "env-derived uuid must be deterministic");
        assert_eq!(a.len(), 36);

        std::env::set_var(&key, "");
        assert!(generate_uuid("", "env", std::slice::from_ref(&key)).is_err());
        std::env::remove_var(&key);
    }

    #[test]
    fn uuid_prefers_a_persisted_file_else_random() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("uuid");
        std::fs::write(&path, "  persisted-uuid\n").expect("write uuid file");
        assert_eq!(
            generate_uuid(path.to_str().unwrap(), "random", &[]).unwrap(),
            "persisted-uuid"
        );

        // A blank file falls back to a fresh random UUID.
        std::fs::write(&path, "   \n").expect("write blank");
        let random = generate_uuid(path.to_str().unwrap(), "random", &[]).unwrap();
        assert_eq!(random.len(), 36);
        assert_ne!(random, "persisted-uuid");

        // A missing file falls back too.
        let missing = generate_uuid("/nonexistent/uuid-file", "random", &[]).unwrap();
        assert_eq!(missing.len(), 36);
        assert_ne!(missing, random);
    }

    #[test]
    fn enumerate_nics_filters_by_name_and_reports_inet_addresses() {
        assert!(
            enumerate_nics(&["definitely-not-an-interface-xyz".to_string()]).is_empty(),
            "a non-matching filter must yield no interfaces"
        );
        let lo = enumerate_nics(&["lo".to_string()]);
        assert_eq!(lo.len(), 1);
        assert_eq!(lo[0].name, "lo");
        assert!(
            !lo[0].inet_addresses.is_empty(),
            "loopback must report an inet address"
        );
    }
}
