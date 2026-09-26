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

        if let Ok(stats) = self
            .worker_mgr
            .collect_stats_summary(Duration::from_secs(3))
        {
            metrics.set_task_stats(&stats);
        }

        let logs = self.sync_log.lock().clear();
        let req = SyncMetricsRequest {
            logs,
            metrics: Some(metrics),
            pid: Some(self.worker_mgr.pid()).filter(|p| *p > 0),
        };
        futures_block_on(self.client.sync_metrics(daemon_id, req))
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
