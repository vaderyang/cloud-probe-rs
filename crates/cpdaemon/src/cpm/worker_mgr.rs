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
