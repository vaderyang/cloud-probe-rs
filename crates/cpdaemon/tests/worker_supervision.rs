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

use std::time::Duration;

use cpdaemon::worker::{ExecConfig, Worker};
use cpdaemon::worker_config::{Config, ControlConfig, ControlUnixConfig};
use cpgolib::cpworker::{Client, UnixClient};

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

    worker
        .start(&base_config(&sock_str, "INFO"))
        .expect("start worker");
    let pid = worker.pid();
    assert!(pid > 0, "worker pid must be recorded");
    assert!(worker.is_alive(), "worker must be alive right after start");

    // The daemon writes the config the worker consumes; pin its shape so a
    // schema drift between the two crates is caught here.
    let written: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&cfg_path).expect("worker config file must be written"),
    )
    .expect("worker config must be valid JSON");
    assert_eq!(written["control"]["type"], "unix");
    assert_eq!(written["tasks"].as_array().map(Vec::len), Some(0));

    // PID file and control socket are created asynchronously by the child.
    assert!(
        wait_until(Duration::from_secs(5), || pid_path.exists()),
        "pid file must be written"
    );
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

    // Reload: the daemon rewrites the config and asks the worker to reload, and
    // the worker must survive it.
    worker
        .update_config(&base_config(&sock_str, "DEBUG"))
        .expect("rewrite worker config");
    client
        .reload_config(Duration::from_secs(3))
        .expect("reload_config command");
    std::thread::sleep(Duration::from_millis(300));
    assert!(worker.is_alive(), "worker must survive a reload");

    // Stop: SIGINT, then the pid file is removed and the process is gone.
    let _ = client.close();
    worker.stop();
    assert!(!worker.is_alive(), "worker must be stopped");
    assert!(!pid_path.exists(), "pid file must be removed on stop");
}
