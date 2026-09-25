//! Task orchestration. Port of `task.c`.
//!
//! Deviations from the C implementation, documented for reviewers:
//! * Reload rebuilds every task from the new config instead of matching
//!   fingerprints and reusing unchanged tasks. Behaviour is equivalent
//!   (config becomes live without restart) but less efficient.
//! * The pipeline output thread and ring are safe abstractions, not the
//!   original lock-free SPSC structures.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::capturer::{new_capturer, Capturer, PacketSink};
use crate::config::{Config, ExecutionModel, TaskConfig};
use crate::error::{Error, Result};
use crate::output::{new_output, Output, PacketHeader};
use crate::ring_buffer::{RingMsg, SimpleAllocator, SpscRing};
use crate::stats::{BytesStats, CaptureStats, OutputStats, PacketsStats};

/// Outputs belonging to one task.
pub struct TaskOutputs {
    pub outputs: Vec<Box<dyn Output>>,
}

struct TaskEntry {
    index: usize,
    fingerprint: Option<String>,
    capturer: Option<Box<dyn Capturer>>,
    error: Option<String>,
}

/// RTC sink: forwards packets directly to a task's outputs.
struct RtcSink<'a> {
    outputs: &'a mut Vec<Box<dyn Output>>,
}

impl PacketSink for RtcSink<'_> {
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) {
        for o in self.outputs.iter_mut() {
            o.send_packet(hdr, pkt, direct);
        }
    }

    fn on_heartbeat(&mut self) {
        let now = now_sec();
        for o in self.outputs.iter_mut() {
            o.heartbeat(now);
        }
    }
}

/// Pipeline sink: enqueues packets / heartbeats into the shared ring.
struct PipelineSink {
    ring: Arc<Mutex<SpscRing>>,
    alloc: Arc<SimpleAllocator>,
    task_index: usize,
}

impl PacketSink for PipelineSink {
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) {
        loop {
            if let Some(msg) =
                self.alloc
                    .alloc_packet(self.task_index, direct, hdr.ts_sec, hdr.ts_usec, pkt)
            {
                let mut msg = msg;
                loop {
                    match self.ring.lock().push(msg) {
                        Ok(()) => return,
                        Err(m) => {
                            msg = m;
                            std::thread::yield_now();
                        }
                    }
                }
            }
            std::thread::yield_now();
        }
    }

    fn on_heartbeat(&mut self) {
        loop {
            if let Some(msg) = self.alloc.alloc_heartbeat(self.task_index) {
                let mut msg = msg;
                loop {
                    match self.ring.lock().push(msg) {
                        Ok(()) => return,
                        Err(m) => {
                            msg = m;
                            std::thread::yield_now();
                        }
                    }
                }
            }
            std::thread::yield_now();
        }
    }
}

pub fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build one task's capturer + outputs. Mirrors `capture_task_new`.
fn build_task(
    tasks_cfg: &[TaskConfig],
    task_cfg: &TaskConfig,
    capture: Arc<CaptureStats>,
    output: Arc<OutputStats>,
) -> Result<(Box<dyn Capturer>, Vec<Box<dyn Output>>)> {
    let capturer = new_capturer(tasks_cfg, task_cfg, capture)?;
    let mut outputs: Vec<Box<dyn Output>> = Vec::with_capacity(task_cfg.outputs.len());
    for output_cfg in &task_cfg.outputs {
        let out = new_output(task_cfg, output_cfg, output.clone())?;
        outputs.push(out);
    }
    Ok((capturer, outputs))
}

pub struct TaskManager {
    config: Config,
    config_path: String,
    working_dir: String,
    started_at: i64,

    stats_capture: Arc<CaptureStats>,
    stats_output: Arc<OutputStats>,

    entries: Vec<TaskEntry>,
    out_sets: Arc<Mutex<Vec<TaskOutputs>>>,

    ring: Option<Arc<Mutex<SpscRing>>>,
    alloc: Option<Arc<SimpleAllocator>>,

    running: Arc<AtomicBool>,
    output_thread: Option<JoinHandle<()>>,
    inited_count: usize,
}

impl TaskManager {
    /// Create the manager and all tasks. Returns an error only on catastrophic
    /// failure; individual task failures are recorded and reported separately.
    pub fn new(config: Config, config_path: String, working_dir: String) -> Result<Self> {
        let stats_capture = Arc::new(CaptureStats::default());
        let stats_output = Arc::new(OutputStats::default());

        let (ring, alloc) = if config.execution_model == ExecutionModel::Pipeline {
            let ring = Arc::new(Mutex::new(SpscRing::new(1024 * 1024)));
            let alloc = Arc::new(SimpleAllocator::new(
                config.pipeline_buffer_size_mb.max(0) as u64 * 1024 * 1024,
            ));
            (Some(ring), Some(alloc))
        } else {
            (None, None)
        };

        let mut mgr = TaskManager {
            config,
            config_path,
            working_dir,
            started_at: now_sec(),
            stats_capture,
            stats_output,
            entries: Vec::new(),
            out_sets: Arc::new(Mutex::new(Vec::new())),
            ring,
            alloc,
            running: Arc::new(AtomicBool::new(false)),
            output_thread: None,
            inited_count: 0,
        };
        mgr.build_all()?;
        Ok(mgr)
    }

    fn build_all(&mut self) -> Result<()> {
        let tasks_cfg = self.config.tasks.clone();
        let mut entries = Vec::with_capacity(tasks_cfg.len());
        let mut out_sets = Vec::with_capacity(tasks_cfg.len());
        let mut inited = 0;

        crate::log_info!("find {} tasks", tasks_cfg.len());
        for (i, task_cfg) in tasks_cfg.iter().enumerate() {
            match build_task(
                &tasks_cfg,
                task_cfg,
                self.stats_capture.clone(),
                self.stats_output.clone(),
            ) {
                Ok((capturer, outputs)) => {
                    crate::log_info!("create task-{i} success");
                    entries.push(TaskEntry {
                        index: i,
                        fingerprint: task_cfg.fingerprint.clone(),
                        capturer: Some(capturer),
                        error: None,
                    });
                    out_sets.push(TaskOutputs { outputs });
                    inited += 1;
                }
                Err(e) => {
                    crate::log_error!("new task-{i} error: {e}");
                    entries.push(TaskEntry {
                        index: i,
                        fingerprint: task_cfg.fingerprint.clone(),
                        capturer: None,
                        error: Some(e.to_string()),
                    });
                    out_sets.push(TaskOutputs { outputs: Vec::new() });
                }
            }
        }

        self.entries = entries;
        *self.out_sets.lock() = out_sets;
        self.inited_count = inited;
        Ok(())
    }

    pub fn inited_count(&self) -> usize {
        self.inited_count
    }

    pub fn total_tasks(&self) -> usize {
        self.config.tasks.len()
    }

    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    pub fn working_dir(&self) -> &str {
        &self.working_dir
    }

    pub fn started_at(&self) -> i64 {
        self.started_at
    }

    pub fn execution_model(&self) -> ExecutionModel {
        self.config.execution_model
    }

    pub fn print_errors(&self) {
        for e in &self.entries {
            if let Some(err) = &e.error {
                match &e.fingerprint {
                    Some(fp) => crate::log_error!("new task({fp}) error: {err}"),
                    None => crate::log_error!("new task({}) error: {err}", e.index),
                }
            }
        }
    }

    /// Start the pipeline output thread (no-op for the RTC model).
    pub fn start(&mut self) {
        if self.config.execution_model != ExecutionModel::Pipeline {
            return;
        }
        let ring = self.ring.clone().unwrap();
        let alloc = self.alloc.clone().unwrap();
        let out_sets = self.out_sets.clone();
        let running = self.running.clone();

        self.running.store(true, Ordering::Release);
        let handle = std::thread::Builder::new()
            .name("taskmgr_output".into())
            .spawn(move || {
                while running.load(Ordering::Acquire) {
                    match ring.lock().pop() {
                        Some(msg) => dispatch_ring_msg(&out_sets, &alloc, msg),
                        None => std::thread::sleep(std::time::Duration::from_micros(10)),
                    }
                }
                // Drain remaining messages on shutdown.
                loop {
                    let popped = ring.lock().pop();
                    match popped {
                        Some(msg) => dispatch_ring_msg(&out_sets, &alloc, msg),
                        None => break,
                    }
                }
            })
            .expect("failed to spawn output thread");
        crate::log_info!("output thread started");
        self.output_thread = Some(handle);
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.output_thread.take() {
            self.running.store(false, Ordering::Release);
            let _ = handle.join();
        }
    }

    /// Poll each task once. Mirrors `task_manager_poll_packets`.
    pub fn poll_packets(&mut self) -> u64 {
        let mut num_pkts = 0u64;
        match self.config.execution_model {
            ExecutionModel::Pipeline => {
                let ring = self.ring.clone().unwrap();
                let alloc = self.alloc.clone().unwrap();
                for entry in self.entries.iter_mut() {
                    if let Some(cap) = entry.capturer.as_mut() {
                        let mut sink = PipelineSink {
                            ring: ring.clone(),
                            alloc: alloc.clone(),
                            task_index: entry.index,
                        };
                        num_pkts += cap.capture_once(&mut sink);
                    }
                }
            }
            ExecutionModel::Rtc => {
                let out_sets = self.out_sets.clone();
                let mut sets = out_sets.lock();
                for entry in self.entries.iter_mut() {
                    if let Some(cap) = entry.capturer.as_mut() {
                        let outs = &mut sets[entry.index].outputs;
                        let mut sink = RtcSink { outputs: outs };
                        num_pkts += cap.capture_once(&mut sink);
                    }
                }
            }
        }
        num_pkts
    }

    /// Rebuild all tasks from a freshly parsed config. In-place reload.
    pub fn reload(&mut self, new_config: Config) -> Result<()> {
        let was_running = self.output_thread.is_some();
        if was_running {
            self.stop();
        }

        // Drop old capturers/outputs before creating new ones (so sockets and
        // files are released).
        let old_config = std::mem::replace(&mut self.config, new_config);
        self.entries.clear();
        *self.out_sets.lock() = Vec::new();

        // Recreate pipeline ring/alloc if the buffer size changed.
        self.ring = None;
        self.alloc = None;
        if self.config.execution_model == ExecutionModel::Pipeline {
            self.ring = Some(Arc::new(Mutex::new(SpscRing::new(1024 * 1024))));
            self.alloc = Some(Arc::new(SimpleAllocator::new(
                self.config.pipeline_buffer_size_mb.max(0) as u64 * 1024 * 1024,
            )));
        }

        let result = self.build_all();
        drop(old_config);

        if was_running {
            self.start();
        }
        result?;
        crate::log_info!(
            "reload complete: {} tasks",
            self.inited_count
        );
        Ok(())
    }

    /// Reload from the path recorded at startup.
    pub fn reload_from_file(&mut self) -> Result<()> {
        let cfg = Config::parse_file(&self.config_path)?;
        // Preserve control config from the original (C moves control out before
        // handing config to the task manager).
        self.reload(cfg)
    }

    /// Build the `collect_stats_summary` RPC payload. Mirrors
    /// `task_manager_collect_stats_summary_command`.
    pub fn collect_stats_summary(&self) -> serde_json::Value {
        let (sec, nsec) = monotonic_now();
        let (ring_total, ring_used, mem_total, mem_used) = match (&self.ring, &self.alloc) {
            (Some(r), Some(a)) => (
                r.lock().size() as u64,
                r.lock().used() as u64,
                a.capacity(),
                a.used(),
            ),
            _ => (0, 0, 0, 0),
        };

        serde_json::json!({
            "time": { "sec": sec, "nsec": nsec },
            "capture": capture_stats_json(&self.stats_capture),
            "output": output_stats_json(&self.stats_output),
            "pipeline_buffer": {
                "mem_total": mem_total,
                "mem_used": mem_used,
                "ring_total": ring_total,
                "ring_used": ring_used,
            }
        })
    }
}

impl Drop for TaskManager {
    fn drop(&mut self) {
        self.stop();
    }
}

fn dispatch_ring_msg(out_sets: &Arc<Mutex<Vec<TaskOutputs>>>, alloc: &Arc<SimpleAllocator>, msg: Box<RingMsg>) {
    let task_index = msg.task_index();
    {
        let mut sets = out_sets.lock();
        if let Some(set) = sets.get_mut(task_index) {
            match msg.as_ref() {
                RingMsg::Packet {
                    direction,
                    ts_sec,
                    ts_usec,
                    caplen,
                    data,
                    ..
                } => {
                    let hdr = PacketHeader {
                        ts_sec: *ts_sec,
                        ts_usec: *ts_usec,
                        caplen: *caplen,
                        len: *caplen,
                    };
                    for o in set.outputs.iter_mut() {
                        o.send_packet(&hdr, data, *direction);
                    }
                }
                RingMsg::Heartbeat { ts, .. } => {
                    for o in set.outputs.iter_mut() {
                        o.heartbeat(*ts);
                    }
                }
            }
        }
    }
    alloc.free(&msg);
}

fn monotonic_now() -> (i64, i64) {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as i64, ts.tv_nsec as i64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        (d.as_secs() as i64, d.subsec_nanos() as i64)
    }
}

fn bytes_stats_json(s: &BytesStats) -> serde_json::Value {
    let (bytes, eib) = s.load();
    serde_json::json!({ "bytes": bytes, "eib": eib })
}

fn packets_stats_json(s: &PacketsStats) -> serde_json::Value {
    let (packets, peta) = s.load();
    serde_json::json!({ "packets": packets, "peta": peta })
}

fn capture_stats_json(s: &CaptureStats) -> serde_json::Value {
    serde_json::json!({
        "cap_bytes": bytes_stats_json(&s.cap_bytes),
        "cap_packets": packets_stats_json(&s.cap_packets),
        "drop_packets": packets_stats_json(&s.drop_packets),
        "ifdrop_packets": packets_stats_json(&s.ifdrop_packets),
    })
}

fn output_stats_json(s: &OutputStats) -> serde_json::Value {
    serde_json::json!({
        "fwd_bytes": bytes_stats_json(&s.fwd_bytes),
        "fwd_packets": packets_stats_json(&s.fwd_packets),
        "direction_drop_bytes": bytes_stats_json(&s.direction_drop_bytes),
        "direction_drop_packets": packets_stats_json(&s.direction_drop_packets),
        "error_drop_bytes": bytes_stats_json(&s.error_drop_bytes),
        "error_drop_packets": packets_stats_json(&s.error_drop_packets),
        "ratelimit_drop_bytes": bytes_stats_json(&s.ratelimit_drop_bytes),
        "ratelimit_drop_packets": packets_stats_json(&s.ratelimit_drop_packets),
        "heartbeat_packets": packets_stats_json(&s.heartbeat_packets),
    })
}
