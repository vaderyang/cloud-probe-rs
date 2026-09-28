//! Syncer end-to-end test against a mock CPM.
//!
//! Drives the real `Syncer::run` loop (register → pull strategy → push metrics)
//! against an axum mock of the CPM API, and asserts on what actually crossed the
//! wire: the register identity, the strategy version round-trip (`-1` on the
//! first pull, then the version the CPM answered with) and the metrics body.

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

fn daemon_worker_config() -> DaemonWorkerConfig {
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
                path: "/tmp/cpdaemon-e2e.sock".into(),
            }),
        },
        execution_model: "rtc".into(),
        pipeline: PipelineConfig::default(),
        update_policy: "restart".into(),
        memory: MemoryConfig::default(),
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
    // `strategy: []` keeps the reconcile path from spawning a worker, so this
    // test needs no privileges: it exercises the control-plane loop itself.
    let mock = MockCpm::new()
        .register_body(json!({"id": 77, "paUUID": "pa-77", "syncInterval": 1}))
        .strategy_body(json!({
            "id": 3, "daemonId": 77, "version": 1, "syncInterval": 1, "strategy": [],
        }));
    let (url, rec) = mock.spawn().await;

    let tool = Tool {
        // Avoid shelling out to `virsh` on every strategy tick.
        get_kvm_instances_script: "true".into(),
        ..Default::default()
    };
    let client = HttpClient::new(&url, ClientConfig::default()).expect("http client");
    let worker_mgr = WorkerManager::new(daemon_worker_config(), tool.clone());
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
    assert!(
        r.metrics_bodies[0]["metrics"].is_object(),
        "metrics body must carry a metrics object: {}",
        r.metrics_bodies[0]
    );
}
