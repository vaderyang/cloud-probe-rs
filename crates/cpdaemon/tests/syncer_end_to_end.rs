//! Syncer end-to-end test against a mock CPM.
//!
//! Drives the real `Syncer::run` loop (register → pull strategy → push metrics)
//! against an axum mock of the CPM API, and asserts on what actually crossed the
//! wire: the register identity, the daemon id in the request path, the strategy
//! version round-trip (`-1` on the first pull, then the version the CPM answered
//! with) and the metrics body.
//!
//! `strategy: []` keeps the reconcile path from spawning a worker, so this test
//! needs no privileges. (The strategy → `WorkerManager` → cpworker spawn bridge
//! is covered separately by `worker_mgr` unit tests and the `Worker` supervision
//! test.)

mod common;

use std::time::Duration;

use cpdaemon::cpm::client::{ClientConfig, HttpClient};
use cpdaemon::cpm::syncer::{RegConfig, Syncer, SyncerConfig};
use cpdaemon::cpm::worker_mgr::{
    MemoryConfig, PipelineConfig, WorkerConfig as DaemonWorkerConfig, WorkerManager,
};
use cpdaemon::reslimit::CgroupCfg;
use cpdaemon::tool::Tool;
use cpdaemon::worker_config::{ControlConfig, ControlUnixConfig};
use serde_json::json;
use tokio::sync::watch;

use common::MockCpm;

const DAEMON_ID: i64 = 77;

/// Captures `log` records so tests can assert on the emitted log lines.
struct CaptureLogger;

static CAPTURED_LOGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static INSTALL_CAPTURE_LOGGER: std::sync::Once = std::sync::Once::new();

impl log::Log for CaptureLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if let Ok(mut logs) = CAPTURED_LOGS.lock() {
            logs.push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn install_capture_logger() {
    INSTALL_CAPTURE_LOGGER.call_once(|| {
        let _ = log::set_logger(&CaptureLogger);
        log::set_max_level(log::LevelFilter::Info);
    });
}

fn daemon_worker_config(socket_path: &str) -> DaemonWorkerConfig {
    DaemonWorkerConfig {
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
                path: socket_path.into(),
            }),
        },
        execution_model: "rtc".into(),
        pipeline: PipelineConfig::default(),
        update_policy: "restart".into(),
        memory: MemoryConfig::default(),
    }
}

/// Signal the syncer to stop even if the test panics before it asks nicely.
///
/// `Syncer::run` is a *synchronous* loop driven inside a spawned task (it uses
/// `block_in_place`), so a panic that skipped the shutdown would leave the task
/// mid-poll and deadlock `Runtime::drop` - the failure would hang CI instead of
/// turning it red.
struct ShutdownOnDrop(watch::Sender<bool>);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

async fn wait_async(pred: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    pred()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncer_registers_pulls_strategy_and_pushes_metrics() {
    // After the first `200` (version 1), the mock answers `304`, so the loop
    // also exercises "not changed → no reconcile" instead of reconciling forever.
    let mock = MockCpm::new()
        .register_body(json!({"id": DAEMON_ID, "paUUID": "pa-77", "syncInterval": 1}))
        .strategy_body(json!({
            "id": 3, "daemonId": DAEMON_ID, "version": 1, "syncInterval": 1, "strategy": [],
        }))
        .strategy_not_modified_at("1");
    let (url, rec) = mock.spawn().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ctl.sock");

    let tool = Tool {
        // Avoid shelling out to `virsh` on every strategy tick.
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr =
        WorkerManager::new(daemon_worker_config(&sock.to_string_lossy()), tool.clone());
    let reg = RegConfig {
        name: "probe-e2e".into(),
        client_version: "0.9.0".into(),
        ..Default::default()
    };
    let cfg = SyncerConfig {
        reg_retry_interval: Duration::from_millis(100),
        sync_strategy_interval: Duration::from_millis(100),
        sync_metric_interval: Duration::from_millis(100),
        stop_worker_after_reg_fail_minutes: 30,
    };
    let syncer = Syncer::new(client, worker_mgr, tool, reg, cfg);

    let (tx, rx) = watch::channel(false);
    let _guard = ShutdownOnDrop(tx.clone());
    let handle = tokio::spawn(async move { syncer.run(rx) });

    let ready = wait_async(
        || {
            let r = rec.lock().unwrap();
            !r.register_bodies.is_empty()
                && r.strategy_versions.contains(&"-1".to_string())
                && r.strategy_versions.contains(&"1".to_string())
                && !r.metrics_bodies.is_empty()
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(
        ready,
        "syncer did not complete a register + versioned strategy + metrics cycle in time"
    );

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("syncer did not stop within 5s")
        .expect("syncer task panicked");

    let r = rec.lock().unwrap();
    assert_eq!(r.register_bodies[0]["name"], "probe-e2e");
    assert_eq!(r.register_bodies[0]["clientVersion"], "0.9.0");
    assert_eq!(r.register_bodies[0]["apiVersion"], "v1");
    assert_eq!(r.register_bodies[0]["supportApiVersions"], json!(["v1"]));
    // The id returned by `register` must be the one used for every later call -
    // this pins the register→`daemon_id` flow, not just the bodies.
    assert!(
        r.strategy_ids.iter().all(|&id| id == DAEMON_ID) && !r.strategy_ids.is_empty(),
        "strategy requests must target the registered daemon id: {:?}",
        r.strategy_ids
    );
    assert!(
        r.metrics_ids.iter().all(|&id| id == DAEMON_ID) && !r.metrics_ids.is_empty(),
        "metrics requests must target the registered daemon id: {:?}",
        r.metrics_ids
    );
    assert!(
        r.metrics_bodies[0]["metrics"].is_object(),
        "metrics body must carry a metrics object: {}",
        r.metrics_bodies[0]
    );
}

/// Upstream `syncMetric` reports how many buffered log lines were drained and
/// sent on the metric push (`log_count`, commit acb10f2). Preload the ring
/// before the loop starts so the first push carries a known, non-zero count,
/// then assert the emitted log line is observable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncer_metric_log_reports_log_count() {
    install_capture_logger();
    CAPTURED_LOGS.lock().expect("logs lock").clear();

    let mock = MockCpm::new()
        .register_body(json!({"id": DAEMON_ID, "paUUID": "pa-77", "syncInterval": 1}))
        .strategy_body(json!({
            "id": 3, "daemonId": DAEMON_ID, "version": 1, "syncInterval": 1, "strategy": [],
        }))
        .strategy_not_modified_at("1");
    let (url, _rec) = mock.spawn().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ctl.sock");

    let tool = Tool {
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr =
        WorkerManager::new(daemon_worker_config(&sock.to_string_lossy()), tool.clone());
    let reg = RegConfig {
        name: "probe-logs".into(),
        ..Default::default()
    };
    let cfg = SyncerConfig {
        reg_retry_interval: Duration::from_millis(100),
        sync_strategy_interval: Duration::from_millis(100),
        sync_metric_interval: Duration::from_millis(100),
        stop_worker_after_reg_fail_minutes: 30,
    };
    let syncer = Syncer::new(client, worker_mgr, tool, reg, cfg);

    // Two buffered entries must be drained on the first metrics push.
    {
        let buf = syncer.sync_log();
        let mut buf = buf.lock();
        buf.write(1, 0, "INFO", "first".into());
        buf.write(2, 0, "INFO", "second".into());
    }

    let (tx, rx) = watch::channel(false);
    let _guard = ShutdownOnDrop(tx.clone());
    let handle = tokio::spawn(async move { syncer.run(rx) });

    let saw_log_count = wait_async(
        || {
            CAPTURED_LOGS
                .lock()
                .map(|logs| logs.iter().any(|line| line.contains("log_count=2")))
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    )
    .await;

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("syncer did not stop within 5s")
        .expect("syncer task panicked");

    assert!(
        saw_log_count,
        "metric log line must report log_count=2; captured: {:?}",
        CAPTURED_LOGS.lock().expect("logs lock")
    );
}

/// A registration outage must be retried, not fatal: the syncer keeps polling
/// the same endpoint until shutdown and never advances to strategy/metrics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncer_retries_register_until_shutdown() {
    let mock = MockCpm::new().register_status(500);
    let (url, rec) = mock.spawn().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ctl.sock");
    let tool = Tool {
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr =
        WorkerManager::new(daemon_worker_config(&sock.to_string_lossy()), tool.clone());
    let cfg = SyncerConfig {
        reg_retry_interval: Duration::from_millis(50),
        ..Default::default()
    };
    let syncer = Syncer::new(
        client,
        worker_mgr,
        tool,
        RegConfig {
            name: "probe-retry".into(),
            ..Default::default()
        },
        cfg,
    );

    let (tx, rx) = watch::channel(false);
    let _guard = ShutdownOnDrop(tx.clone());
    let handle = tokio::spawn(async move { syncer.run(rx) });

    let retried = wait_async(
        || rec.lock().unwrap().register_bodies.len() >= 3,
        Duration::from_secs(5),
    )
    .await;
    assert!(retried, "syncer must keep retrying a failed register");

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("syncer did not stop within 5s")
        .expect("syncer task panicked");

    let r = rec.lock().unwrap();
    assert!(r.register_bodies.len() >= 3);
    // No registration succeeded, so no daemon-id call may have been made.
    assert!(r.strategy_ids.is_empty());
    assert!(r.metrics_ids.is_empty());
}

/// Strategy and metric pushes can fail independently; a failure is logged and
/// the loop must keep running and retry, never unwinding the task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncer_survives_sync_strategy_and_metric_failures() {
    let mock = MockCpm::new()
        .register_body(json!({"id": DAEMON_ID, "paUUID": "pa-77", "syncInterval": 1}))
        .strategy_status(500)
        .metrics_status(500);
    let (url, rec) = mock.spawn().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ctl.sock");
    let tool = Tool {
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr =
        WorkerManager::new(daemon_worker_config(&sock.to_string_lossy()), tool.clone());
    let cfg = SyncerConfig {
        reg_retry_interval: Duration::from_millis(50),
        sync_strategy_interval: Duration::from_millis(50),
        sync_metric_interval: Duration::from_millis(50),
        ..Default::default()
    };
    let syncer = Syncer::new(
        client,
        worker_mgr,
        tool,
        RegConfig {
            name: "probe-errors".into(),
            ..Default::default()
        },
        cfg,
    );

    let (tx, rx) = watch::channel(false);
    let _guard = ShutdownOnDrop(tx.clone());
    let handle = tokio::spawn(async move { syncer.run(rx) });

    let saw_both = wait_async(
        || {
            let r = rec.lock().unwrap();
            r.strategy_versions.len() >= 2 && r.metrics_bodies.len() >= 2
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(saw_both, "the loops must keep retrying after HTTP errors");

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("syncer did not stop within 5s")
        .expect("syncer task panicked");

    let r = rec.lock().unwrap();
    assert!(
        r.strategy_ids.iter().all(|&id| id == DAEMON_ID) && !r.strategy_ids.is_empty(),
        "retried strategy calls must still target the registered daemon id"
    );
    assert!(
        r.metrics_ids.iter().all(|&id| id == DAEMON_ID) && !r.metrics_ids.is_empty(),
        "retried metric calls must still target the registered daemon id"
    );
}

/// A `304 Not Modified` on the very first strategy pull is the "version is
/// unchanged" path: the syncer must not reconcile and must keep the cached
/// version (`-1`) for the next poll rather than inventing a response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncer_strategy_not_modified_is_ignored() {
    let mock = MockCpm::new()
        .register_body(json!({"id": DAEMON_ID, "paUUID": "pa-77", "syncInterval": 1}))
        .strategy_not_modified_at("-1");
    let (url, rec) = mock.spawn().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ctl.sock");
    let tool = Tool {
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr =
        WorkerManager::new(daemon_worker_config(&sock.to_string_lossy()), tool.clone());
    let cfg = SyncerConfig {
        reg_retry_interval: Duration::from_millis(50),
        sync_strategy_interval: Duration::from_millis(50),
        sync_metric_interval: Duration::from_millis(50),
        ..Default::default()
    };
    let syncer = Syncer::new(
        client,
        worker_mgr,
        tool,
        RegConfig {
            name: "probe-304".into(),
            ..Default::default()
        },
        cfg,
    );

    let (tx, rx) = watch::channel(false);
    let _guard = ShutdownOnDrop(tx.clone());
    let handle = tokio::spawn(async move { syncer.run(rx) });

    let polled = wait_async(
        || rec.lock().unwrap().strategy_versions.len() >= 2,
        Duration::from_secs(5),
    )
    .await;
    assert!(polled, "strategy must keep polling after a 304");

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("syncer did not stop within 5s")
        .expect("syncer task panicked");

    let versions = rec.lock().unwrap().strategy_versions.clone();
    assert!(
        versions.iter().all(|v| v == "-1"),
        "a 304 must not advance the cached version: {versions:?}"
    );
}
