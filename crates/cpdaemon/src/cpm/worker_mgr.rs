//! Worker lifecycle manager. Port of `cpdaemon/pkg/cpm/worker_mgr.go`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use cpgolib::cpworker::{Client, StatsSummary, UnixClient};

use crate::error::{Error, Result};
use crate::reslimit::CgroupCfg;
use crate::tool::Tool;
use crate::worker::{ExecConfig, ResLimit, Worker};
use crate::worker_config::{Config, ControlConfig, EXECUTION_MODEL_PIPELINE, EXECUTION_MODEL_RTC};

use super::models::SyncStrategyResponse;
use super::task_builder::WorkerTaskBuilder;

pub const UPDATE_POLICY_RESTART: &str = "restart";
pub const UPDATE_POLICY_RELOAD: &str = "reload";

pub const MEMORY_POLICY_AUTO_NIC_BUFFER: &str = "auto_nic_buffer";
pub const MEMORY_POLICY_FIXED_NIC_BUFFER: &str = "fixed_nic_buffer";

#[derive(Debug, Clone, Default)]
pub struct LibpcapMemConfig {
    pub fixed_buffer_size_mb: u64,
}

#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub policy: String,
    pub default_limit_mb: u64,
    pub libpcap: LibpcapMemConfig,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            policy: MEMORY_POLICY_FIXED_NIC_BUFFER.into(),
            default_limit_mb: 512,
            libpcap: LibpcapMemConfig {
                fixed_buffer_size_mb: 8,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub min_buffer_size_mb: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            min_buffer_size_mb: 128,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub pid_file: String,
    pub config_file: String,
    pub executable: String,
    pub env: std::collections::HashMap<String, String>,
    pub work_dir: Option<String>,
    pub cgroup_cfg: CgroupCfg,

    pub cpu_affinity: String,
    pub log_level: String,
    pub control: ControlConfig,

    pub execution_model: String,
    pub pipeline: PipelineConfig,

    pub update_policy: String,
    pub memory: MemoryConfig,
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<()> {
        let lv = self.log_level.to_uppercase();
        if !matches!(lv.as_str(), "DEBUG" | "INFO" | "WARN" | "ERROR") {
            return Err(Error::new(format!("invalid logLevel: {}", self.log_level)));
        }
        match self.control.ty.as_str() {
            "unix" => match &self.control.unix {
                Some(u) if !u.path.is_empty() => {}
                _ => return Err(Error::new("require control.unix.path")),
            },
            other => return Err(Error::new(format!("invalid control.type: {other}"))),
        }
        if !matches!(
            self.execution_model.as_str(),
            EXECUTION_MODEL_RTC | EXECUTION_MODEL_PIPELINE
        ) {
            return Err(Error::new(format!(
                "invalid execution_model: {}",
                self.execution_model
            )));
        }
        match self.memory.policy.as_str() {
            MEMORY_POLICY_FIXED_NIC_BUFFER => {
                if self.memory.libpcap.fixed_buffer_size_mb == 0 {
                    return Err(Error::new(format!(
                        "memoryPolicy.libpcap.bufferSizeMb must be greater than 0 when strategy is '{}'",
                        MEMORY_POLICY_FIXED_NIC_BUFFER
                    )));
                }
            }
            MEMORY_POLICY_AUTO_NIC_BUFFER => {}
            other => {
                return Err(Error::new(format!(
                    "invalid memoryPolicy.strategy: {other}"
                )))
            }
        }
        match self.update_policy.as_str() {
            UPDATE_POLICY_RELOAD | UPDATE_POLICY_RESTART => {}
            other => return Err(Error::new(format!("invalid updatePolicy: {other}"))),
        }
        self.cgroup_cfg.validate()?;
        Ok(())
    }
}

#[derive(Debug, Default)]
// Ported result type; some fields are not yet read by the daemon (PARITY.md §5).
#[allow(dead_code)]
pub struct WorkerCreateResult {
    pub warnings: Vec<Error>,
    pub buff_size_per_task: u64,
}

#[derive(Default)]
struct State {
    client: Option<UnixClient>,
    worker: Option<Arc<Worker>>,
}

fn stop_worker_locked(st: &mut State) {
    if let Some(w) = st.worker.take() {
        w.stop();
    }
    if let Some(mut c) = st.client.take() {
        let _ = c.close();
    }
}

pub struct WorkerManager {
    worker_cfg: WorkerConfig,
    tool: Tool,
    state: Mutex<State>,
}

impl WorkerManager {
    pub fn new(worker_cfg: WorkerConfig, tool: Tool) -> Self {
        WorkerManager {
            worker_cfg,
            tool,
            state: Mutex::new(State::default()),
        }
    }

    pub fn start_time(&self) -> Option<Instant> {
        self.state
            .lock()
            .worker
            .as_ref()
            .and_then(|w| w.start_time())
    }

    pub fn pid(&self) -> i32 {
        self.state
            .lock()
            .worker
            .as_ref()
            .map(|w| w.pid())
            .unwrap_or(0)
    }

    pub fn is_alive(&self) -> bool {
        self.state
            .lock()
            .worker
            .as_ref()
            .map(|w| w.is_alive())
            .unwrap_or(false)
    }

    pub fn stop(&self) -> Result<()> {
        let mut st = self.state.lock();
        stop_worker_locked(&mut st);
        Ok(())
    }

    pub fn collect_stats_summary(&self, timeout: Duration) -> Result<StatsSummary> {
        let mut st = self.state.lock();
        match st.client.as_mut() {
            Some(c) => c
                .collect_stats_summary(timeout)
                .map_err(|e| Error::new(e.to_string())),
            None => Ok(StatsSummary::default()),
        }
    }

    pub fn create_if_dead(
        &self,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        let mut st = self.state.lock();
        if let Some(w) = st.worker.as_ref() {
            if w.is_alive() {
                return Err(Error::new("worker is still running"));
            }
        }
        stop_worker_locked(&mut st);
        self.create_unlocked(&mut st, res, daemon_uuid, active_instances)
    }

    fn create_unlocked(
        &self,
        st: &mut State,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        if st.worker.is_some() {
            return Err(Error::new("worker is already exists"));
        }
        let (tasks, warnings, buff_size_per_task) =
            self.build_tasks(res, daemon_uuid, active_instances)?;
        for w in &warnings {
            crate::log_warn!("{w}");
        }
        if tasks.is_empty() {
            crate::log_warn!("no tasks");
            return Ok(WorkerCreateResult {
                warnings,
                buff_size_per_task,
            });
        }

        let exec_cfg = ExecConfig {
            pid_file: self.worker_cfg.pid_file.clone(),
            executable: self.worker_cfg.executable.clone(),
            env: self.worker_cfg.env.clone(),
            work_dir: self.worker_cfg.work_dir.clone(),
            config_file: self.worker_cfg.config_file.clone(),
            cgroup_cfg: self.worker_cfg.cgroup_cfg.clone(),
        };
        let w_cfg = self.new_worker_config(&tasks, res);
        let res_limit = ResLimit {
            cpu: res.cpu_limit,
            mem: res.mem_limit,
        };

        if self.worker_cfg.control.ty == "unix" {
            if let Some(u) = &self.worker_cfg.control.unix {
                let socket_path = u.path.clone();
                if let Some(dir) = Path::new(&socket_path).parent() {
                    if !dir.as_os_str().is_empty() {
                        std::fs::create_dir_all(dir).map_err(|e| {
                            Error::new(format!("create dir {} failed: {e}", dir.display()))
                        })?;
                    }
                }
            }
        }

        let conn = self.worker_cfg.control.connect_string();
        let mut client = cpgolib::cpworker::new_client(&conn)
            .map_err(|e| Error::new(format!("create worker client failed: {e}")))?;
        let worker = Worker::new("cpm", exec_cfg);

        if let Err(e) = worker.start(&w_cfg) {
            let _ = client.close();
            return Err(e);
        }
        if let Err(e) = worker.update_res_limit(res_limit) {
            crate::log_error!("update resource limit failed, stopping worker: {e}");
            worker.stop();
            return Err(e);
        }

        st.client = Some(client);
        st.worker = Some(worker);
        Ok(WorkerCreateResult {
            warnings,
            buff_size_per_task,
        })
    }

    pub fn update(
        &self,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        match self.worker_cfg.update_policy.as_str() {
            UPDATE_POLICY_RESTART => self.update_by_restart(res, daemon_uuid, active_instances),
            UPDATE_POLICY_RELOAD => self.update_by_reload(res, daemon_uuid, active_instances),
            other => Err(Error::new(format!("unknown update policy: {other}"))),
        }
    }

    fn update_by_restart(
        &self,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        let mut st = self.state.lock();
        stop_worker_locked(&mut st);
        self.create_unlocked(&mut st, res, daemon_uuid, active_instances)
    }

    fn update_by_reload(
        &self,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        let mut st = self.state.lock();
        if st.worker.is_none() {
            return self.create_unlocked(&mut st, res, daemon_uuid, active_instances);
        }
        self.reload_config(&mut st, res, daemon_uuid, active_instances)
    }

    fn reload_config(
        &self,
        st: &mut State,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<WorkerCreateResult> {
        let (tasks, warnings, buff_size_per_task) =
            self.build_tasks(res, daemon_uuid, active_instances)?;
        for w in &warnings {
            crate::log_warn!("{w}");
        }
        if tasks.is_empty() {
            crate::log_warn!("no tasks");
            stop_worker_locked(st);
            return Ok(WorkerCreateResult {
                warnings,
                buff_size_per_task,
            });
        }

        let w_cfg = self.new_worker_config(&tasks, res);
        let Some(worker) = st.worker.clone() else {
            return Err(Error::new("worker not found for reload"));
        };
        worker.update_config(&w_cfg)?;
        if let Some(client) = st.client.as_mut() {
            crate::log_info!("sending reload_config command to worker");
            client
                .reload_config(Duration::from_secs(3))
                .map_err(|e| Error::new(format!("send reload_config command failed: {e}")))?;
        } else {
            worker.reload_config()?;
        }

        let res_limit = ResLimit {
            cpu: res.cpu_limit,
            mem: res.mem_limit,
        };
        if let Err(e) = worker.update_res_limit(res_limit) {
            crate::log_error!("update resource limit failed, stopping worker: {e}");
            worker.stop();
            return Err(e);
        }

        Ok(WorkerCreateResult {
            warnings,
            buff_size_per_task,
        })
    }

    fn build_tasks(
        &self,
        res: &SyncStrategyResponse,
        daemon_uuid: &str,
        active_instances: &[String],
    ) -> Result<(Vec<crate::worker_config::TaskConfig>, Vec<Error>, u64)> {
        let num_items = num_items(res, active_instances);
        if num_items == 0 {
            return Ok((Vec::new(), Vec::new(), 0));
        }
        let buff = self.get_task_buffer_size_mb(res, active_instances)?;
        let mut tb = WorkerTaskBuilder::new(
            self.tool.clone(),
            daemon_uuid.to_string(),
            active_instances.to_vec(),
            buff,
        );
        for strategy in &res.strategy {
            tb.add_strategy(strategy);
        }
        let (tasks, warnings) = tb.build();
        Ok((tasks, warnings, buff))
    }

    fn new_worker_config(
        &self,
        tasks: &[crate::worker_config::TaskConfig],
        res: &SyncStrategyResponse,
    ) -> Config {
        let mut w_cfg = Config {
            cpu_affinity: if self.worker_cfg.cpu_affinity.is_empty() {
                None
            } else {
                Some(self.worker_cfg.cpu_affinity.clone())
            },
            log_level: self.worker_cfg.log_level.clone(),
            execution_model: self.worker_cfg.execution_model.clone(),
            pipeline: None,
            control: self.worker_cfg.control.clone(),
            tasks: tasks.to_vec(),
        };

        if self.worker_cfg.execution_model == EXECUTION_MODEL_PIPELINE {
            let task_mem: u64 = tasks
                .iter()
                .map(|t| {
                    if t.capturer.ty == crate::worker_config::CAPTURER_TYPE_LIBPCAP {
                        t.capturer
                            .libpcap
                            .as_ref()
                            .and_then(|l| l.buffer_size_mb)
                            .unwrap_or(256)
                    } else {
                        0
                    }
                })
                .sum();

            let mut mem_limit = self.worker_cfg.memory.default_limit_mb;
            if let Some(m) = res.mem_limit {
                if m > 0 {
                    mem_limit = m as u64;
                }
            }
            let mut buffer_size = self.worker_cfg.pipeline.min_buffer_size_mb;
            if mem_limit > task_mem && mem_limit - task_mem > buffer_size {
                buffer_size = mem_limit - task_mem;
            }
            w_cfg.pipeline = Some(crate::worker_config::PipelineConfig {
                buffer_size_mb: buffer_size,
            });
        }
        w_cfg
    }

    fn get_task_buffer_size_mb(
        &self,
        res: &SyncStrategyResponse,
        active_instances: &[String],
    ) -> Result<u64> {
        match self.worker_cfg.memory.policy.as_str() {
            MEMORY_POLICY_FIXED_NIC_BUFFER => {
                Ok(self.worker_cfg.memory.libpcap.fixed_buffer_size_mb)
            }
            MEMORY_POLICY_AUTO_NIC_BUFFER => {
                let n = num_items(res, active_instances);
                if n == 0 {
                    return Ok(0);
                }
                let mut mem_limit = self.worker_cfg.memory.default_limit_mb;
                if let Some(m) = res.mem_limit {
                    if m > 0 {
                        mem_limit = m as u64;
                    }
                }
                if mem_limit < n as u64 {
                    return Err(Error::new(format!(
                        "memory limit {mem_limit} MB is too small for {n} tasks"
                    )));
                }
                Ok(mem_limit / n as u64)
            }
            other => Err(Error::new(format!(
                "unknown memoryPolicy.strategy: {other}"
            ))),
        }
    }
}

/// Port of `SyncStrategyResponse.NumItems`.
fn num_items(res: &SyncStrategyResponse, active_instances: &[String]) -> usize {
    let mut n = 0usize;
    for s in &res.strategy {
        if !s.container_ids.is_empty() {
            n += s.container_ids.len();
        } else if !s.interface_names.is_empty() {
            n += s.interface_names.len();
        } else if !s.instance_names.is_empty() {
            for name in &s.instance_names {
                if active_instances.contains(name) {
                    n += 1;
                }
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpm::models::{StrategyEntry, PACKET_CHANNEL_TYPE_FILE};
    use crate::worker_config::ControlUnixConfig;

    fn base_worker_config() -> WorkerConfig {
        WorkerConfig {
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
                    path: "/tmp/cpdaemon-test.sock".into(),
                }),
            },
            execution_model: EXECUTION_MODEL_RTC.into(),
            pipeline: PipelineConfig::default(),
            update_policy: UPDATE_POLICY_RESTART.into(),
            memory: MemoryConfig {
                policy: MEMORY_POLICY_FIXED_NIC_BUFFER.into(),
                default_limit_mb: 512,
                libpcap: LibpcapMemConfig {
                    fixed_buffer_size_mb: 8,
                },
            },
        }
    }

    /// A FILE-channel strategy over the given interface/container/instance names.
    fn strategy(
        interfaces: &[&str],
        containers: &[&str],
        instances: &[&str],
    ) -> SyncStrategyResponse {
        SyncStrategyResponse {
            id: 1,
            daemon_id: 1,
            version: 1,
            sync_interval: 15,
            cpu_limit: None,
            mem_limit: None,
            strategy: vec![StrategyEntry {
                interface_names: interfaces.iter().map(|s| (*s).to_string()).collect(),
                container_ids: containers.iter().map(|s| (*s).to_string()).collect(),
                instance_names: instances.iter().map(|s| (*s).to_string()).collect(),
                packet_channel_type: PACKET_CHANNEL_TYPE_FILE.into(),
                dump_dir: Some("/tmp/probe".into()),
                dump_interval: Some(60),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn num_items_counts_containers_interfaces_and_live_instances() {
        assert_eq!(num_items(&strategy(&["eth0", "eth1"], &[], &[]), &[]), 2);
        assert_eq!(num_items(&strategy(&[], &["c1", "c2", "c3"], &[]), &[]), 3);
        // Instances only count when they are currently active.
        let active = vec!["vm1".to_string()];
        assert_eq!(num_items(&strategy(&[], &[], &["vm1", "vm2"]), &active), 1);
        assert_eq!(num_items(&strategy(&[], &[], &[]), &[]), 0);
    }

    /// The config bridge: a strategy becomes a serialised task with the expected
    /// capturer and output, with no warnings.
    #[test]
    fn build_tasks_serialises_a_file_channel_strategy() {
        let mgr = WorkerManager::new(base_worker_config(), Tool::default());
        let res = strategy(&["eth0"], &[], &[]);
        let (tasks, warnings, buff) = mgr.build_tasks(&res, "daemon-uuid", &[]).unwrap();
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(buff, 8, "fixed buffer policy");
        assert_eq!(tasks.len(), 1);
        let t = &tasks[0];
        assert_eq!(t.capturer.ty, crate::worker_config::CAPTURER_TYPE_LIBPCAP);
        assert_eq!(t.capturer.libpcap.as_ref().unwrap().interface, "eth0");
        assert_eq!(t.capturer.libpcap.as_ref().unwrap().buffer_size_mb, Some(8));
        assert!(
            t.outputs[0].rotating_file.is_some(),
            "FILE => rotating_file"
        );
    }

    #[test]
    fn build_tasks_is_empty_without_items() {
        let mgr = WorkerManager::new(base_worker_config(), Tool::default());
        let (tasks, warnings, buff) = mgr
            .build_tasks(&strategy(&[], &[], &[]), "daemon-uuid", &[])
            .unwrap();
        assert!(tasks.is_empty());
        assert!(warnings.is_empty());
        assert_eq!(buff, 0, "no items => no buffer budget");
    }

    #[test]
    fn task_buffer_size_follows_the_memory_policy() {
        let mut wc = base_worker_config();
        wc.memory.policy = MEMORY_POLICY_AUTO_NIC_BUFFER.into();
        wc.memory.default_limit_mb = 512;
        wc.memory.libpcap.fixed_buffer_size_mb = 0;
        let mgr = WorkerManager::new(wc, Tool::default());
        let res = strategy(&["eth0", "eth1"], &[], &[]);
        // 512 MB / 2 tasks.
        assert_eq!(mgr.get_task_buffer_size_mb(&res, &[]).unwrap(), 256);

        // Too small for the task count is an error, not a silent 0.
        let mut tiny = base_worker_config();
        tiny.memory.policy = MEMORY_POLICY_AUTO_NIC_BUFFER.into();
        tiny.memory.default_limit_mb = 1;
        let mgr = WorkerManager::new(tiny, Tool::default());
        assert!(mgr.get_task_buffer_size_mb(&res, &[]).is_err());
    }

    #[test]
    fn pipeline_buffer_subtracts_task_memory() {
        let mut wc = base_worker_config();
        wc.execution_model = EXECUTION_MODEL_PIPELINE.into();
        wc.memory.default_limit_mb = 512;
        wc.memory.libpcap.fixed_buffer_size_mb = 256;
        wc.pipeline.min_buffer_size_mb = 128;
        let mgr = WorkerManager::new(wc, Tool::default());
        let res = strategy(&["eth0"], &[], &[]);
        let tasks = mgr.build_tasks(&res, "daemon-uuid", &[]).unwrap().0;
        assert_eq!(tasks.len(), 1);
        let cfg = mgr.new_worker_config(&tasks, &res);
        // 512 (limit) - 256 (task capture buffer) = 256 > min 128.
        assert_eq!(cfg.pipeline.as_ref().unwrap().buffer_size_mb, 256);
    }

    fn valid_config() -> WorkerConfig {
        let mut wc = base_worker_config();
        wc.cgroup_cfg.version = "auto".into();
        wc
    }

    #[test]
    fn worker_config_validate_accepts_coherent_configs() {
        valid_config().validate().expect("fixed-buffer config");
        let mut wc = valid_config();
        wc.memory.policy = MEMORY_POLICY_AUTO_NIC_BUFFER.into();
        wc.validate().expect("auto-buffer config");
        let mut wc = valid_config();
        wc.update_policy = UPDATE_POLICY_RELOAD.into();
        wc.execution_model = EXECUTION_MODEL_PIPELINE.into();
        wc.validate().expect("pipeline/reload config");
    }

    #[test]
    fn worker_config_validate_rejects_each_invalid_field() {
        let mut wc = valid_config();
        wc.log_level = "TRACE".into();
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid logLevel"));

        let mut wc = valid_config();
        wc.control = ControlConfig {
            ty: "tcp".into(),
            unix: None,
        };
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid control.type"));

        let mut wc = valid_config();
        wc.control = ControlConfig {
            ty: "unix".into(),
            unix: None,
        };
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("require control.unix.path"));

        let mut wc = valid_config();
        wc.control = ControlConfig {
            ty: "unix".into(),
            unix: Some(ControlUnixConfig {
                path: String::new(),
            }),
        };
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("require control.unix.path"));

        let mut wc = valid_config();
        wc.execution_model = "threaded".into();
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid execution_model"));

        let mut wc = valid_config();
        wc.memory.libpcap.fixed_buffer_size_mb = 0;
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must be greater than 0"));

        let mut wc = valid_config();
        wc.memory.policy = "guess".into();
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid memoryPolicy.strategy"));

        let mut wc = valid_config();
        wc.update_policy = "sometimes".into();
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid updatePolicy"));

        let mut wc = valid_config();
        wc.cgroup_cfg.version = "v3".into();
        assert!(wc
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid cgroup.version"));
    }

    /// A stand-in for the real worker: a script that ignores HUP and sleeps, so
    /// the manager's process bookkeeping can be exercised unprivileged.
    fn fake_manager(dir: &std::path::Path, policy: &str) -> WorkerManager {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fake-worker.sh");
        // `prewarm` exits immediately; the real invocation (with `-c`) sleeps.
        std::fs::write(
            &p,
            "#!/bin/sh\n[ \"$1\" = prewarm ] && exit 0\ntrap '' HUP\nexec sleep 30\n",
        )
        .expect("write script");
        let mut perms = std::fs::metadata(&p).expect("stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).expect("chmod");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::process::Command::new(&p).arg("prewarm").output() {
                Ok(_) => break,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("script {} not executable: {e}", p.display()),
            }
        }

        let mut wc = base_worker_config();
        wc.executable = p.to_string_lossy().into_owned();
        wc.config_file = dir.join("worker.json").to_string_lossy().into_owned();
        wc.pid_file = dir.join("worker.pid").to_string_lossy().into_owned();
        wc.control = ControlConfig {
            ty: "unix".into(),
            unix: Some(ControlUnixConfig {
                path: dir.join("ctl.sock").to_string_lossy().into_owned(),
            }),
        };
        wc.update_policy = policy.into();
        WorkerManager::new(wc, Tool::default())
    }

    #[test]
    fn create_if_dead_spawns_then_stop_terminates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), UPDATE_POLICY_RESTART);
        let res = strategy(&["eth0"], &[], &[]);
        assert_eq!(mgr.pid(), 0);
        assert!(!mgr.is_alive());
        assert!(mgr.start_time().is_none());

        let created = mgr.create_if_dead(&res, "uuid", &[]).expect("create");
        assert!(created.warnings.is_empty(), "{:?}", created.warnings);
        assert_eq!(created.buff_size_per_task, 8);
        let pid = mgr.pid();
        assert!(pid > 0);
        assert!(mgr.is_alive());
        assert!(mgr.start_time().is_some());

        // Both files the manager promises to write exist and match.
        let recorded: i32 = std::fs::read_to_string(dir.path().join("worker.pid"))
            .expect("pid file")
            .trim()
            .parse()
            .expect("pid int");
        assert_eq!(recorded, pid);
        let cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("worker.json")).expect("config"))
                .expect("json");
        assert_eq!(cfg["tasks"].as_array().map(Vec::len), Some(1));

        // A live worker is not respawned.
        let err = mgr.create_if_dead(&res, "uuid", &[]).expect_err("alive");
        assert!(err.to_string().contains("worker is still running"));

        // The stand-in never listens on the control socket, so a stats request
        // is a transport error rather than a silent default.
        assert!(mgr
            .collect_stats_summary(Duration::from_millis(10))
            .is_err());

        mgr.stop().expect("stop");
        assert_eq!(mgr.pid(), 0);
        assert!(!mgr.is_alive());
        assert!(!dir.path().join("worker.pid").exists());
    }

    #[test]
    fn create_propagates_task_warnings_but_still_spawns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), UPDATE_POLICY_RESTART);
        // One valid interface task plus an inactive-instance strategy that only
        // produces a warning.
        let mut res = strategy(&["eth0"], &[], &[]);
        res.strategy.push(StrategyEntry {
            instance_names: vec!["ghost".into()],
            packet_channel_type: PACKET_CHANNEL_TYPE_FILE.into(),
            dump_dir: Some("/tmp/probe".into()),
            ..Default::default()
        });
        let created = mgr.create_if_dead(&res, "uuid", &[]).expect("create");
        assert_eq!(created.warnings.len(), 1);
        assert!(created.warnings[0]
            .to_string()
            .contains("instance name not found"));
        assert!(mgr.pid() > 0, "the valid task still spawns the worker");
        mgr.stop().expect("stop");
    }

    #[test]
    fn update_by_restart_replaces_the_running_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), UPDATE_POLICY_RESTART);
        let res = strategy(&["eth0"], &[], &[]);
        mgr.create_if_dead(&res, "uuid", &[]).expect("create");
        let first_pid = mgr.pid();
        let updated = mgr.update(&res, "uuid", &[]).expect("restart update");
        assert!(updated.warnings.is_empty(), "{:?}", updated.warnings);
        let second_pid = mgr.pid();
        assert!(second_pid > 0);
        assert_ne!(first_pid, second_pid, "restart must replace the process");
        assert!(mgr.is_alive());
        mgr.stop().expect("stop");
    }

    #[test]
    fn update_rejects_unknown_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), "sideways");
        let res = strategy(&["eth0"], &[], &[]);
        let err = mgr.update(&res, "uuid", &[]).expect_err("bad policy");
        assert!(err.to_string().contains("unknown update policy"));
    }

    #[test]
    fn update_by_reload_creates_then_reloads_or_errors_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), UPDATE_POLICY_RELOAD);
        let res = strategy(&["eth0"], &[], &[]);
        // No worker yet: reload policy must create one.
        let created = mgr.update(&res, "uuid", &[]).expect("create via reload");
        assert!(created.warnings.is_empty());
        assert!(mgr.pid() > 0);

        // With a worker present it rewrites the config (asserted by reading it
        // back) and then tries to talk to the control socket, which fails
        // because the stand-in has none.
        let err = mgr.update(&res, "uuid", &[]).expect_err("reload transport");
        assert!(
            err.to_string().contains("reload_config"),
            "unexpected: {err}"
        );
        let cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("worker.json")).expect("config"))
                .expect("json");
        assert_eq!(cfg["tasks"].as_array().map(Vec::len), Some(1));
        assert!(mgr.is_alive(), "a failed reload must not kill the worker");
        mgr.stop().expect("stop");
    }

    #[test]
    fn update_by_reload_with_empty_strategy_stops_the_worker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = fake_manager(dir.path(), UPDATE_POLICY_RELOAD);
        let res = strategy(&["eth0"], &[], &[]);
        mgr.update(&res, "uuid", &[]).expect("create via reload");
        assert!(mgr.pid() > 0);

        let empty = strategy(&[], &[], &[]);
        let out = mgr.update(&empty, "uuid", &[]).expect("empty reload");
        assert!(out.warnings.is_empty());
        assert_eq!(mgr.pid(), 0, "an empty strategy stops the worker");
    }

    #[test]
    fn pipeline_and_affinity_are_wired_into_the_worker_config() {
        let mut wc = base_worker_config();
        wc.execution_model = EXECUTION_MODEL_PIPELINE.into();
        wc.cpu_affinity = "0-1".into();
        wc.memory.default_limit_mb = 1024;
        wc.pipeline.min_buffer_size_mb = 128;
        let mgr = WorkerManager::new(wc, Tool::default());
        let mut res = strategy(&["eth0"], &[], &[]);
        res.mem_limit = Some(512);
        let tasks = mgr.build_tasks(&res, "uuid", &[]).unwrap().0;
        let cfg = mgr.new_worker_config(&tasks, &res);
        assert_eq!(cfg.cpu_affinity.as_deref(), Some("0-1"));
        // mem_limit 512 overrides the 1024 default; 512 - 8 capture = 504 > 128.
        assert_eq!(cfg.pipeline.as_ref().unwrap().buffer_size_mb, 504);
    }

    #[test]
    fn auto_buffer_uses_the_response_mem_limit_and_rejects_unknown_policy() {
        let mut wc = base_worker_config();
        wc.memory.policy = MEMORY_POLICY_AUTO_NIC_BUFFER.into();
        wc.memory.default_limit_mb = 100;
        let mgr = WorkerManager::new(wc, Tool::default());
        let mut res = strategy(&["eth0", "eth1"], &[], &[]);
        res.mem_limit = Some(400);
        // The response limit wins over the configured default: 400 / 2 tasks.
        assert_eq!(mgr.get_task_buffer_size_mb(&res, &[]).unwrap(), 200);

        let mut wc = base_worker_config();
        wc.memory.policy = "bogus".into();
        let mgr = WorkerManager::new(wc, Tool::default());
        assert!(mgr.get_task_buffer_size_mb(&res, &[]).is_err());
    }
}
