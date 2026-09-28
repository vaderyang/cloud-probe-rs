//! Worker supervision end-to-end.
//!
//! The daemon's job toward the worker is: serialize a config the worker accepts,
//! spawn it, track its pid/liveness, talk to it over the unix control socket,
//! reload it, and stop it cleanly. This test does all of that against the **real
//! `cpworker` binary** (not a stub).
//!
//! The task list is empty, so no capture is involved and the test runs
//! unprivileged in the normal `test` job.

mod common;

use std::sync::Arc;
use std::time::Duration;

use cpdaemon::cpm::models::SyncStrategyResponse;
use cpdaemon::cpm::worker_mgr::WorkerConfig as DaemonWorkerConfig;
use cpdaemon::cpm::worker_mgr::{MemoryConfig, PipelineConfig, WorkerManager};
use cpdaemon::reslimit::CgroupCfg;
use cpdaemon::tool::Tool;
use cpdaemon::worker::{ExecConfig, Worker};
use cpdaemon::worker_config::{Config, ControlConfig, ControlUnixConfig};
use cpgolib::cpworker::{Client, UnixClient};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use serde_json::json;

use common::{cpworker_binary, wait_until};

fn base_config(socket_path: &str, log_level: &str) -> Config {
    Config {
        cpu_affinity: None,
        log_level: log_level.into(),
        execution_model: "rtc".into(),
        pipeline: None,
        control: ControlConfig {
            ty: "unix".into(),
            unix: Some(ControlUnixConfig {
                path: socket_path.into(),
            }),
        },
        tasks: Vec::new(),
    }
}

/// True while `pid` still names a process (`kill(pid, 0)`).
fn os_process_exists(pid: i32) -> bool {
    match kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Stop the supervised worker even if the test panics mid-way; `Worker` itself
/// has no `Drop`, so an early `expect` would otherwise orphan a running cpworker.
struct WorkerGuard(Arc<Worker>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[test]
fn daemon_supervises_the_real_cpworker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("control.sock");
    let cfg_path = dir.path().join("worker.json");
    let pid_path = dir.path().join("worker.pid");
    let sock_str = sock.to_string_lossy().into_owned();

    let worker = Worker::new(
        "e2e",
        ExecConfig {
            pid_file: pid_path.to_string_lossy().into_owned(),
            executable: cpworker_binary().to_string_lossy().into_owned(),
            env: Default::default(),
            work_dir: None,
            config_file: cfg_path.to_string_lossy().into_owned(),
            cgroup_cfg: Default::default(),
        },
    );
    let _guard = WorkerGuard(worker.clone());

    worker
        .start(&base_config(&sock_str, "INFO"))
        .expect("start worker");
    let pid = worker.pid();
    assert!(pid > 0, "worker pid must be recorded");

    // The daemon writes the config the worker consumes; pin its shape so a
    // schema drift between the two crates is caught here.
    let written: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&cfg_path).expect("worker config file must be written"),
    )
    .expect("worker config must be valid JSON");
    assert_eq!(written["control"]["type"], "unix");
    assert_eq!(written["tasks"].as_array().map(Vec::len), Some(0));

    // The pid file is written by the *daemon* synchronously in `start()`, before
    // the child does anything; it only proves the daemon's bookkeeping.
    let recorded_pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("pid file must exist")
        .trim()
        .parse()
        .expect("pid file must hold a pid");
    assert_eq!(recorded_pid, pid, "pid file must record the worker pid");

    // Real evidence the child is up and using the daemon-written config: it can
    // only create the control socket at the path parsed from that file.
    assert!(
        wait_until(Duration::from_secs(5), || sock.exists()),
        "control socket must appear"
    );

    // Talk to the worker through the same client the daemon uses.
    let mut client =
        UnixClient::with_timeout(&format!("unix://{sock_str}"), Duration::from_secs(3))
            .expect("client");
    client.dial().expect("handshake");
    let info = client.info(Duration::from_secs(3)).expect("info");
    assert_eq!(info.pid, pid, "info.pid must match the supervised pid");
    assert!(!info.version.is_empty(), "info.version must be reported");
    client.ping(Duration::from_secs(3)).expect("ping");
    let stats = client
        .collect_stats_summary(Duration::from_secs(3))
        .expect("collect_stats_summary");
    assert_eq!(
        stats.capture.cap_packets.packets, 0,
        "no packets are captured in this test"
    );

    // Liveness is asserted *after* the handshake, where `is_alive()` (which is
    // satisfied by a zombie too) is corroborated by a responding control client.
    assert!(
        worker.is_alive(),
        "worker must be alive while serving control"
    );

    // Reload: the daemon rewrites the config and asks the worker to reload. The
    // worker replies OK only after parsing the rewritten file, so this pins
    // "the rewrite was accepted"; the process must also survive it.
    worker
        .update_config(&base_config(&sock_str, "DEBUG"))
        .expect("rewrite worker config");
    client
        .reload_config(Duration::from_secs(3))
        .expect("reload_config command");
    assert!(worker.is_alive(), "worker must survive a reload");

    // Stop: SIGINT, then the worker must be gone at the OS level. `is_alive()`
    // alone is tautological here (stop() sets pid=0), so check the captured pid.
    let _ = client.close();
    worker.stop();
    assert!(
        wait_until(Duration::from_secs(5), || !os_process_exists(pid)),
        "the worker process {pid} must actually be terminated by stop()"
    );
    assert!(!pid_path.exists(), "pid file must be removed on stop");
}

fn daemon_worker_config(
    executable: &str,
    config_file: &str,
    pid_file: &str,
    socket_path: &str,
) -> DaemonWorkerConfig {
    DaemonWorkerConfig {
        pid_file: pid_file.into(),
        config_file: config_file.into(),
        executable: executable.into(),
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

/// The full bridge the daemon actually uses: a CPM strategy → `build_tasks`
/// serialises a worker config → the real `cpworker` is spawned → the manager
/// talks to it over the unix socket → `stop()`.
///
/// The task captures on `lo` (the strategy always builds a libpcap capturer),
/// which needs `CAP_NET_RAW`, so this is `#[ignore]` and runs in the privileged
/// `live-capture` CI job via `--ignored`. It panics (does not skip) when it
/// cannot capture, so a lost privilege is a red test, not a green no-op.
#[test]
#[ignore = "requires root/CAP_NET_RAW: captures on lo"]
fn worker_manager_spawns_the_real_cpworker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("control.sock");
    let cfg_path = dir.path().join("worker.json");
    let pid_path = dir.path().join("worker.pid");
    let dump_dir = dir.path().join("dump");
    std::fs::create_dir_all(&dump_dir).expect("create dump dir");

    let mgr = WorkerManager::new(
        daemon_worker_config(
            &cpworker_binary().to_string_lossy(),
            &cfg_path.to_string_lossy(),
            &pid_path.to_string_lossy(),
            &sock.to_string_lossy(),
        ),
        Tool::default(),
    );

    let res: SyncStrategyResponse = serde_json::from_value(json!({
        "id": 1,
        "daemonId": 1,
        "version": 1,
        "syncInterval": 15,
        "strategy": [{
            "interfaceNames": ["lo"],
            "packetChannelType": "FILE",
            "dumpDir": dump_dir.to_string_lossy(),
            "dumpInterval": 60,
        }],
    }))
    .expect("strategy");

    let created = mgr
        .create_if_dead(&res, "daemon-uuid", &[])
        .expect("spawn worker");
    assert!(
        created.warnings.is_empty(),
        "unexpected task warnings: {:?}",
        created.warnings
    );
    let pid = mgr.pid();
    assert!(pid > 0, "the manager must record the spawned worker pid");
    assert!(wait_until(Duration::from_secs(5), || mgr.is_alive()));

    // Control plane through the manager (this is the client the syncer uses for
    // metrics).
    assert!(
        wait_until(Duration::from_secs(10), || mgr
            .collect_stats_summary(Duration::from_secs(1))
            .is_ok()),
        "the manager could not talk to the spawned worker"
    );

    // Generate loopback traffic and require the capture path to see it.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp socket");
    let addr = probe.local_addr().expect("local addr");
    for _ in 0..32 {
        let _ = probe.send_to(b"cloud-probe-e2e", addr);
    }
    let mut seen = 0u64;
    let captured = wait_until(Duration::from_secs(10), || {
        if let Ok(stats) = mgr.collect_stats_summary(Duration::from_secs(1)) {
            seen = stats.capture.cap_packets.packets;
        }
        seen > 0
    });
    assert!(captured, "expected captured loopback packets, saw {seen}");

    mgr.stop().expect("stop worker");
    assert!(
        wait_until(Duration::from_secs(5), || !os_process_exists(pid)),
        "the spawned worker {pid} must be terminated by stop()"
    );
}
