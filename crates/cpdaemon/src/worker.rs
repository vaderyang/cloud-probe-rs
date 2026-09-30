//! Worker process supervision. Port of `cpdaemon/pkg/worker/worker.go`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::error::{Error, Result};
use crate::reslimit::{create_process_limit, CgroupCfg, ProcessLimit};
use crate::worker_config::Config;

#[derive(Debug, Clone, Default)]
pub struct ResLimit {
    pub cpu: Option<f64>,
    #[allow(dead_code)] // ported limit, not yet enforced (PARITY.md §5)
    pub mem: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ExecConfig {
    pub pid_file: String,
    pub executable: String,
    pub env: HashMap<String, String>,
    pub work_dir: Option<String>,
    pub config_file: String,
    pub cgroup_cfg: CgroupCfg,
}

struct Shared {
    done: Mutex<bool>,
    cv: Condvar,
}

impl Shared {
    fn new() -> Self {
        Shared {
            done: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    fn mark_done(&self) {
        *self.done.lock() = true;
        self.cv.notify_all();
    }

    fn wait_timeout(&self, dur: Duration) -> bool {
        let mut guard = self.done.lock();
        self.cv.wait_while_for(&mut guard, |d| !*d, dur);
        *guard
    }
}

struct State {
    pid: i32,
    start_time: Option<Instant>,
    res_limit: Option<ProcessLimit>,
    shared: Arc<Shared>,
}

pub struct Worker {
    name: String,
    cfg: ExecConfig,
    state: Mutex<State>,
}

impl Worker {
    pub fn new(name: impl Into<String>, cfg: ExecConfig) -> Arc<Self> {
        Arc::new(Worker {
            name: name.into(),
            cfg,
            state: Mutex::new(State {
                pid: 0,
                start_time: None,
                res_limit: None,
                shared: Arc::new(Shared::new()),
            }),
        })
    }

    #[allow(dead_code)] // ported accessor, not yet wired (PARITY.md §5)
    pub fn name(&self) -> &str {
        &self.name
    }

    #[allow(dead_code)] // ported accessor, not yet wired (PARITY.md §5)
    pub fn config_file(&self) -> &str {
        &self.cfg.config_file
    }

    pub fn pid(&self) -> i32 {
        self.state.lock().pid
    }

    pub fn start_time(&self) -> Option<Instant> {
        self.state.lock().start_time
    }

    pub fn is_alive(&self) -> bool {
        let pid = self.pid();
        if pid <= 0 {
            return false;
        }
        match kill(Pid::from_raw(pid), None) {
            Ok(()) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(_) => false,
        }
    }

    /// Start the worker process. Writes the config file first.
    pub fn start(&self, cfg: &Config) -> Result<()> {
        let mut st = self.state.lock();
        if st.pid != 0 {
            return Err(Error::new(format!(
                "worker {} is already running",
                self.name
            )));
        }

        self.write_config(cfg)?;

        let mut cmd = Command::new(&self.cfg.executable);
        cmd.arg("-c").arg(&self.cfg.config_file);
        for (k, v) in &self.cfg.env {
            cmd.env(k, v);
        }
        if let Some(dir) = &self.cfg.work_dir {
            cmd.current_dir(dir);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::new(format!("start worker {} failed: {e}", self.name)))?;
        let pid = child.id() as i32;

        if let Some(out) = child.stdout.take() {
            spawn_log_reader(out, self.name.clone(), "stdout");
        }
        if let Some(err) = child.stderr.take() {
            spawn_log_reader(err, self.name.clone(), "stderr");
        }
        // Do not reap via Child; the waiter thread uses waitpid.
        drop(child);

        crate::log_info!(
            "worker started pid={pid} command={} -c {}",
            self.cfg.executable,
            self.cfg.config_file
        );
        log_worker_config(cfg);

        st.pid = pid;
        st.start_time = Some(Instant::now());
        st.shared = Arc::new(Shared::new());
        let shared = st.shared.clone();

        if !self.cfg.pid_file.is_empty() {
            if let Err(e) = std::fs::write(&self.cfg.pid_file, pid.to_string()) {
                crate::log_error!("create pid file {} error: {e}", self.cfg.pid_file);
            } else {
                crate::log_info!("create pid file success file={}", self.cfg.pid_file);
            }
        }

        // Resource limit (if any was requested before start via update_res_limit).
        drop(st);
        let waiter_shared = shared;
        let name = self.name.clone();
        std::thread::spawn(move || {
            let _ = waitpid(Pid::from_raw(pid), None);
            waiter_shared.mark_done();
            crate::log_info!("worker exited name={name}");
        });
        Ok(())
    }

    /// Send SIGINT and wait up to 10s, then SIGKILL.
    pub fn stop(&self) {
        let (pid, shared) = {
            let st = self.state.lock();
            (st.pid, st.shared.clone())
        };
        if pid <= 0 {
            return;
        }

        crate::log_info!("stopping worker, send SIGINT pid={pid}");
        let _ = kill(Pid::from_raw(pid), Signal::SIGINT);

        if !shared.wait_timeout(Duration::from_secs(10)) {
            crate::log_info!("forcing kill after timeout");
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            if !shared.wait_timeout(Duration::from_secs(1)) {
                crate::log_error!("wait timeout after force kill");
            }
        }

        let mut st = self.state.lock();
        st.pid = 0;
        st.start_time = None;
        if let Some(limit) = st.res_limit.take() {
            if let Err(e) = limit.cleanup() {
                crate::log_error!("clean resource limit failed: {e}");
            } else {
                crate::log_info!("clean resource limit success");
            }
        }
        if !self.cfg.pid_file.is_empty() {
            let _ = std::fs::remove_file(&self.cfg.pid_file);
        }
    }

    /// Send SIGHUP so the worker reloads its config file.
    pub fn reload_config(&self) -> Result<()> {
        let pid = self.pid();
        if pid <= 0 {
            return Ok(());
        }
        crate::log_info!("reloading worker config, send SIGHUP pid={pid}");
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| Error::new(format!("send SIGHUP to worker failed, pid={pid}: {e}")))
    }

    /// Rewrite the config file (used before a reload / restart).
    pub fn update_config(&self, cfg: &Config) -> Result<()> {
        self.write_config(cfg)
    }

    pub fn update_res_limit(&self, limit: ResLimit) -> Result<()> {
        let mut st = self.state.lock();
        let cpu = limit.cpu.filter(|c| *c > 0.0);
        if cpu.is_none() {
            if let Some(prev) = st.res_limit.as_ref() {
                crate::log_info!("clearing previous cpu limit");
                prev.reset()?;
            }
            return Ok(());
        }
        let pid = st.pid;
        if pid <= 0 {
            return Ok(());
        }
        let handle = create_process_limit(pid, &self.cfg.cgroup_cfg, cpu)?;
        st.res_limit = handle;
        Ok(())
    }

    fn write_config(&self, cfg: &Config) -> Result<()> {
        let data = serde_json::to_vec_pretty(cfg)
            .map_err(|e| Error::new(format!("encode worker config: {e}")))?;
        std::fs::write(&self.cfg.config_file, data).map_err(|e| {
            Error::new(format!(
                "create worker config file {}: {e}",
                self.cfg.config_file
            ))
        })?;
        Ok(())
    }
}

fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    name: String,
    stream: &'static str,
) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            match line {
                Ok(l) => crate::log_info!("[worker {name} {stream}] {l}"),
                Err(_) => break,
            }
        }
    });
}

fn log_worker_config(cfg: &Config) {
    if let Ok(s) = serde_json::to_string(cfg) {
        crate::log_info!("worker config config={s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TEST_BODY: &str = r#"{"log_level":"info","execution_model":"rtc","control":{"type":"unix","unix":{"path":"/tmp/x.sock"}},"tasks":[]}"#;

    /// Write an executable shell script and return its path.
    ///
    /// `prewarm` makes the script exit immediately so the helper can force the
    /// inode to be executable without starting the long-lived process it is
    /// really meant to launch. This avoids the `ETXTBSY` race with forks from
    /// other tests while the freshly written descriptor is still held.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!("#!/bin/sh\n[ \"$1\" = prewarm ] && exit 0\n{body}\n"),
        )
        .expect("write script");
        let mut perms = std::fs::metadata(&p).expect("stat script").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).expect("chmod script");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match std::process::Command::new(&p).arg("prewarm").output() {
                Ok(_) => break,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("script {} not executable: {e}", p.display()),
            }
        }
        p.to_string_lossy().into_owned()
    }

    fn config() -> Config {
        serde_json::from_str(TEST_BODY).expect("parse config")
    }

    fn exec(dir: &std::path::Path, executable: String) -> ExecConfig {
        ExecConfig {
            pid_file: dir.join("worker.pid").to_string_lossy().into_owned(),
            executable,
            env: HashMap::new(),
            work_dir: None,
            config_file: dir.join("worker.json").to_string_lossy().into_owned(),
            cgroup_cfg: CgroupCfg::default(),
        }
    }

    #[test]
    fn accessors_report_initial_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w = Worker::new("n", exec(dir.path(), "/bin/true".into()));
        assert_eq!(w.name(), "n");
        assert_eq!(
            w.config_file(),
            dir.path().join("worker.json").to_str().unwrap()
        );
        assert_eq!(w.pid(), 0);
        assert!(w.start_time().is_none());
        // pid <= 0 is reported dead without probing the OS.
        assert!(!w.is_alive());
        // A SIGHUP without a worker is a no-op, not an error.
        w.reload_config().expect("reload without pid");
        // A cpu request without a running process is a no-op too.
        w.update_res_limit(ResLimit {
            cpu: Some(1.0),
            mem: Some(128),
        })
        .expect("limit without pid");
        w.update_res_limit(ResLimit {
            cpu: None,
            mem: None,
        })
        .expect("clear limit without pid");
    }

    #[test]
    fn start_fails_when_config_path_is_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let as_dir = dir.path().join("config-dir");
        std::fs::create_dir(&as_dir).expect("mkdir");
        let mut e = exec(dir.path(), "/bin/true".into());
        e.config_file = as_dir.to_string_lossy().into_owned();
        let w = Worker::new("n", e);
        let err = w.start(&config()).expect_err("write must fail");
        assert!(
            err.to_string().contains("create worker config file"),
            "unexpected error: {err}"
        );
        assert_eq!(w.pid(), 0, "a failed start must not record a pid");
    }

    #[test]
    fn start_records_process_and_stop_terminates_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Ignore SIGHUP so the reload probe cannot kill our stand-in worker.
        let exe = script(dir.path(), "fake.sh", "trap '' HUP\nexec sleep 30");
        let pid_path = dir.path().join("worker.pid");
        let mut e = exec(dir.path(), exe);
        e.pid_file = pid_path.to_string_lossy().into_owned();
        e.env = HashMap::from([("FAKE_ENV".to_string(), "1".to_string())]);
        e.work_dir = Some(dir.path().to_string_lossy().into_owned());
        let w = Worker::new("sup", e);

        w.start(&config()).expect("start");
        let pid = w.pid();
        assert!(pid > 0, "pid must be recorded");
        assert!(w.is_alive(), "the stand-in process must be alive");
        assert!(w.start_time().is_some(), "start time must be recorded");
        assert_eq!(
            std::fs::read_to_string(&pid_path)
                .expect("pid file")
                .trim()
                .parse::<i32>()
                .expect("pid int"),
            pid
        );

        // A second start is rejected rather than leaking a process.
        let err = w.start(&config()).expect_err("double start");
        assert!(
            err.to_string().contains("already running"),
            "unexpected error: {err}"
        );

        // Reload sends SIGHUP; the script ignores it, so the process survives.
        w.reload_config().expect("reload");
        assert!(w.is_alive(), "reload must not kill the worker");
        w.update_config(&config()).expect("rewrite config");

        w.stop();
        assert_eq!(w.pid(), 0);
        assert!(w.start_time().is_none());
        assert!(!pid_path.exists(), "pid file must be removed on stop");
    }

    #[test]
    fn start_survives_an_unwritable_pid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = script(dir.path(), "fake.sh", "exec sleep 30");
        let mut e = exec(dir.path(), exe);
        // Parent directory does not exist: the pid-file write fails but the
        // worker must still start (upstream logs and continues).
        e.pid_file = dir
            .path()
            .join("missing")
            .join("worker.pid")
            .to_string_lossy()
            .into_owned();
        let w = Worker::new("nopid", e);
        w.start(&config()).expect("start despite pid file error");
        assert!(w.pid() > 0);
        w.stop();
    }

    #[test]
    fn is_alive_reports_dead_after_the_process_exits() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `true` exits immediately; the waiter thread reaps it, then is_alive()
        // must observe the ESRCH from the OS.
        let w = Worker::new("short", exec(dir.path(), "/bin/true".into()));
        w.start(&config()).expect("start");
        assert!(w.pid() > 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while w.is_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !w.is_alive(),
            "an exited process must not be reported alive"
        );
        w.stop();
    }

    #[test]
    fn shared_wait_timeout_blocks_until_done() {
        let s = Shared::new();
        let began = Instant::now();
        assert!(!s.wait_timeout(Duration::from_millis(200)));
        assert!(began.elapsed() >= Duration::from_millis(150));
        s.mark_done();
        assert!(s.wait_timeout(Duration::from_millis(200)));
    }

    #[test]
    fn stop_force_kills_a_process_that_ignores_sigint() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No `exec`: the shell keeps ignoring SIGINT and stays alive until the
        // SIGKILL fallback fires after the 10s grace period.
        let exe = script(dir.path(), "stubborn.sh", "trap '' INT\nexec sleep 30");
        let w = Worker::new("stubborn", exec(dir.path(), exe));
        w.start(&config()).expect("start");
        assert!(w.is_alive());
        // Give the shell a moment to install its SIGINT trap before probing the
        // grace-period path; otherwise the default disposition would kill it.
        std::thread::sleep(Duration::from_millis(200));
        let began = Instant::now();
        w.stop();
        assert!(
            began.elapsed() >= Duration::from_secs(10),
            "stop must wait out the SIGINT grace period before SIGKILL"
        );
        assert_eq!(w.pid(), 0);
    }
}
