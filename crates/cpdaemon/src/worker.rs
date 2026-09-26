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
