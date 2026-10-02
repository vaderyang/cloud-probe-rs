//! Task orchestration. Port of `task.c`.
//!
//! Deviations from the C implementation, documented for reviewers:
//! * Reload reuses a task's capturer and outputs when its config fingerprint is
//!   unchanged, matching `task.c`'s `find_task_by_fingerprint`; only added or
//!   changed tasks are rebuilt. The fingerprint is the daemon-computed task
//!   fingerprint (see `cpgolib::worker_fingerprint`), which changes whenever any
//!   field of the task config changes. A task without a fingerprint (the daemon
//!   always fills them in, but hand-written configs may omit it) is rebuilt,
//!   because it cannot be identified across configs. The C thread/mailbox
//!   protocol is collapsed into the polling and manager mutexes: the shared output
//!   thread is stopped for the swap, so no in-flight ring message can be
//!   delivered to a reordered task slot.
//! * The pipeline output thread and the ring are safe abstractions. The ring
//!   itself uses the lock-free SPSC structure from `ring_buffer`, with unique
//!   owned producer/consumer endpoints. Endpoint ownership is locked only when
//!   borrowing a capture batch or starting/stopping the output thread; queue
//!   operations and stats snapshots need no shared ring mutex.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::capturer::{new_capturer, Capturer, PacketSink};
use crate::config::{CapturerKind, Config, ExecutionModel, TaskConfig};
use crate::error::Result;
use crate::output::{new_output, Output, PacketHeader};
use crate::ring_buffer::{
    OwnedRingConsumer, OwnedRingProducer, RingMsg, RingObserver, SimpleAllocator, SpscRing,
};
use crate::stats::{BytesStats, CaptureStats, OutputStats, PacketsStats};

/// Outputs belonging to one task.
pub struct TaskOutputs {
    /// The task's configured outputs.
    ///
    /// These are taken (not merely borrowed) by [`TaskManager::stop`], which is
    /// the single call point for [`Output::destroy`]; see there.
    pub outputs: Vec<Box<dyn Output>>,
}

struct TaskEntry {
    index: usize,
    fingerprint: Option<String>,
    capturer: Option<Box<dyn Capturer>>,
    error: Option<String>,
    /// Reload generation in which this entry's capturer/outputs were built. The
    /// initial build is generation 0; an entry whose generation is older than
    /// the manager's current epoch was *reused* across a reload (not rebuilt).
    build_epoch: u64,
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
struct PipelineSink<'a> {
    ring: &'a mut OwnedRingProducer,
    alloc: &'a SimpleAllocator,
    task_index: usize,
}

impl PacketSink for PipelineSink<'_> {
    fn on_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) {
        loop {
            if let Some(msg) =
                self.alloc
                    .alloc_packet(self.task_index, direct, hdr.ts_sec, hdr.ts_usec, pkt)
            {
                let mut msg = msg;
                loop {
                    let pushed = self.ring.push(msg);
                    match pushed {
                        Ok(()) => return,
                        Err(m) => {
                            msg = m;
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_micros(10));
        }
    }

    fn on_heartbeat(&mut self) {
        loop {
            if let Some(msg) = self.alloc.alloc_heartbeat(self.task_index) {
                let mut msg = msg;
                loop {
                    let pushed = self.ring.push(msg);
                    match pushed {
                        Ok(()) => return,
                        Err(m) => {
                            msg = m;
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_micros(10));
        }
    }
}

#[must_use]
/// Current wall-clock time in seconds since the Unix epoch.
pub fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Ring + allocator for the pipeline execution model. Bundled into one struct
/// so the two are always constructed and dropped together, making a partial
/// (ring without alloc) state impossible.
#[derive(Clone)]
struct PipelineShared {
    ring: RingObserver,
    producer: Arc<Mutex<OwnedRingProducer>>,
    consumer: Arc<Mutex<Option<OwnedRingConsumer>>>,
    alloc: Arc<SimpleAllocator>,
}

impl PipelineShared {
    fn new(ring_size: usize, mem_size: u64) -> Self {
        let (producer, consumer, ring) = SpscRing::new(ring_size).into_split();
        Self {
            ring,
            producer: Arc::new(Mutex::new(producer)),
            consumer: Arc::new(Mutex::new(Some(consumer))),
            alloc: Arc::new(SimpleAllocator::new(mem_size)),
        }
    }
}

/// A task's capturer plus its configured outputs.
type BuiltTask = (Box<dyn Capturer>, Vec<Box<dyn Output>>);

/// Holds outputs that have been created but not yet handed to a task, and runs
/// `destroy()` on whatever it still holds when they are being thrown away.
///
/// `Output` deliberately has no `Drop` that drains (see `output::mod`), so the
/// single `destroy()` call point in `TaskManager::stop()` is the only place that
/// drains on the success path. A *partially built* task never reaches `stop()`:
/// the second output's creation failed, the first was dropped with the `Vec`, and
/// up to a BufWriter's worth of already-captured packets (and the ZMQ linger) went
/// with it (AUDIT4 P3-2).
struct PendingOutputs {
    outputs: Vec<Box<dyn Output>>,
}

impl PendingOutputs {
    fn new(capacity: usize) -> Self {
        PendingOutputs {
            outputs: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, out: Box<dyn Output>) {
        self.outputs.push(out);
    }

    /// Hand the outputs over to the task; the guard is left holding nothing, so
    /// its `Drop` is a no-op on the success path.
    fn finish(mut self) -> Vec<Box<dyn Output>> {
        std::mem::take(&mut self.outputs)
    }
}

impl Drop for PendingOutputs {
    fn drop(&mut self) {
        for o in self.outputs.iter_mut() {
            o.destroy();
        }
        self.outputs.clear();
    }
}

/// Build one task's capturer + outputs. Mirrors `capture_task_new`.
fn build_task(
    tasks_cfg: &[TaskConfig],
    task_cfg: &TaskConfig,
    capture: Arc<CaptureStats>,
    output: Arc<OutputStats>,
) -> Result<BuiltTask> {
    let capturer = new_capturer(tasks_cfg, task_cfg, capture)?;
    let mut pending = PendingOutputs::new(task_cfg.outputs.len());
    for output_cfg in &task_cfg.outputs {
        let out = new_output(task_cfg, output_cfg, output.clone())?;
        pending.push(out);
    }
    Ok((capturer, pending.finish()))
}

/// Find an old task that can satisfy `task_cfg` without being rebuilt: the same
/// non-empty config fingerprint, successfully built (a failed old task is retried),
/// and not already claimed by another new task.
fn find_reusable(entries: &[TaskEntry], reused: &[bool], task_cfg: &TaskConfig) -> Option<usize> {
    let fingerprint = task_cfg.fingerprint.as_deref()?;
    entries.iter().enumerate().find_map(|(j, old)| {
        (!reused.get(j).copied().unwrap_or(false)
            && old.capturer.is_some()
            && old.fingerprint.as_deref() == Some(fingerprint))
        .then_some(j)
    })
}

/// Owns all tasks, their capturers and outputs, and the execution threads.
pub struct TaskManager {
    config: Config,
    config_path: String,
    working_dir: String,
    started_at: i64,

    stats_capture: Arc<CaptureStats>,
    stats_output: Arc<OutputStats>,

    entries: Vec<TaskEntry>,
    out_sets: Arc<Mutex<Vec<TaskOutputs>>>,

    pipeline: Option<PipelineShared>,

    /// Serializes an off-manager pipeline capture batch with reload. Always
    /// acquired before the manager mutex; stats need only the manager mutex.
    polling: Arc<Mutex<()>>,

    running: Arc<AtomicBool>,
    output_thread: Option<JoinHandle<()>>,
    inited_count: usize,
    /// Incremented once per reload; new/rebuild task entries carry it as
    /// [`TaskEntry::build_epoch`], reused entries keep their old value.
    reload_epoch: u64,
}

impl TaskManager {
    /// Create the manager and all tasks. Returns an error only on catastrophic
    /// failure; individual task failures are recorded and reported separately.
    ///
    /// # Errors
    /// Returns an error if the task set cannot be built.
    pub fn new(config: Config, config_path: String, working_dir: String) -> Result<Self> {
        let stats_capture = Arc::new(CaptureStats::default());
        let stats_output = Arc::new(OutputStats::default());

        let pipeline = if config.execution_model == ExecutionModel::Pipeline {
            Some(PipelineShared::new(
                1024 * 1024,
                config.pipeline_buffer_size_mb * 1024 * 1024,
            ))
        } else {
            None
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
            pipeline,
            polling: Arc::new(Mutex::new(())),
            running: Arc::new(AtomicBool::new(false)),
            output_thread: None,
            inited_count: 0,
            reload_epoch: 0,
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
                        build_epoch: self.reload_epoch,
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
                        build_epoch: self.reload_epoch,
                    });
                    out_sets.push(TaskOutputs {
                        outputs: Vec::new(),
                    });
                }
            }
        }

        self.entries = entries;
        *self.out_sets.lock() = out_sets;
        self.inited_count = inited;
        Ok(())
    }

    #[must_use]
    /// Number of tasks successfully initialized.
    pub fn inited_count(&self) -> usize {
        self.inited_count
    }

    /// Total number of configured tasks.
    #[must_use]
    pub fn total_tasks(&self) -> usize {
        self.config.tasks.len()
    }

    /// Path of the config file this manager was created from.
    #[must_use]
    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    /// Working directory used when building tasks.
    #[must_use]
    pub fn working_dir(&self) -> &str {
        &self.working_dir
    }

    /// Unix timestamp (seconds) at which the manager was created.
    #[must_use]
    pub fn started_at(&self) -> i64 {
        self.started_at
    }

    /// Override the creation timestamp. Port of the RPC test seam
    /// `unix_rpc_basic_set_started_at`: the `info` command reports uptime
    /// relative to this value (0 means "unset", i.e. uptime 0).
    pub fn set_started_at(&mut self, t: i64) {
        self.started_at = t;
    }

    /// The configured task execution model.
    #[must_use]
    pub fn execution_model(&self) -> ExecutionModel {
        self.config.execution_model
    }

    /// Log per-task build errors recorded during construction.
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
        let Some(pipeline) = &self.pipeline else {
            crate::log_error!("pipeline model missing ring/alloc; output thread not started");
            return;
        };
        let consumer = pipeline.consumer.clone();
        let alloc = pipeline.alloc.clone();
        let out_sets = self.out_sets.clone();
        let running = self.running.clone();

        self.running.store(true, Ordering::Release);
        let handle = std::thread::Builder::new()
            .name("taskmgr_output".into())
            .spawn(move || {
                // Move the unique consumer out of its ownership slot. No
                // endpoint or manager mutex is held during queue operations,
                // output syscalls or idle waits.
                let Some(mut ring) = consumer.lock().take() else {
                    return;
                };
                loop {
                    match ring.pop() {
                        Some(msg) => dispatch_ring_msg(&out_sets, &alloc, msg),
                        None => {
                            // Drain before stop/reload, as in the C oracle.
                            if !running.load(Ordering::Acquire) {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        }
                    }
                }
                *consumer.lock() = Some(ring);
            });
        match handle {
            Ok(h) => {
                crate::log_info!("output thread started");
                self.output_thread = Some(h);
            }
            Err(e) => {
                self.running.store(false, Ordering::Release);
                crate::log_error!("failed to spawn output thread: {e}");
            }
        }
    }

    /// Stop the pipeline output thread (if running) and join it, *without*
    /// touching any task's outputs. Used by [`Self::reload`], which keeps the
    /// resources of unchanged tasks and only hands the replaced ones to
    /// `destroy()`. Every other shutdown path goes through [`Self::stop`].
    fn stop_output_thread(&mut self) {
        if let Some(handle) = self.output_thread.take() {
            self.running.store(false, Ordering::Release);
            let _ = handle.join();
        }
    }

    /// Stop the pipeline output thread (if running), join it, and run the one
    /// and only `Output::destroy()` call point for every live output.
    ///
    /// Shutdown (and `Drop`) and the fallback reload path funnel through here, so an
    /// output's linger / flush can never be skipped by an implicit
    /// `Box<dyn Output>` release. The outputs are *taken* out of the shared set
    /// before being destroyed, which makes repeat calls a no-op (destroy is
    /// never run twice) and keeps the shared lock held only for the O(n) swap,
    /// not for the multi-second linger wait.
    pub fn stop(&mut self) {
        self.stop_output_thread();
        let mut doomed: Vec<Box<dyn Output>> = {
            let mut sets = self.out_sets.lock();
            sets.iter_mut().flat_map(|s| s.outputs.drain(..)).collect()
        };
        for o in doomed.iter_mut() {
            o.destroy();
        }
        // Sockets / files are released here, after destroy() has drained them.
        drop(doomed);
    }

    /// Poll each task once. Mirrors `task_manager_poll_packets`.
    pub fn poll_packets(&mut self) -> u64 {
        self.poll_packets_batch(1)
    }

    /// Poll up to `max` packets, amortising the output-set lock (and the
    /// caller's TaskManager lock) across a batch instead of once per packet.
    /// Shared pipeline callers should use the free [`crate::task::poll_packets_batch`] to
    /// keep backpressure and capture waits outside the manager mutex.
    pub fn poll_packets_batch(&mut self, max: usize) -> u64 {
        let mut total = 0u64;
        match self.config.execution_model {
            ExecutionModel::Pipeline => {
                let pipeline = match &self.pipeline {
                    Some(p) => p,
                    None => {
                        crate::log_error!("pipeline model missing ring/alloc; no packets polled");
                        return total;
                    }
                };
                total = poll_pipeline(&mut self.entries, pipeline, max);
            }
            ExecutionModel::Rtc => {
                let mut sets = self.out_sets.lock();
                for _ in 0..max {
                    let mut n = 0u64;
                    for entry in self.entries.iter_mut() {
                        if let Some(cap) = entry.capturer.as_mut() {
                            let outs = &mut sets[entry.index].outputs;
                            let mut sink = RtcSink { outputs: outs };
                            n += cap.capture_once(&mut sink);
                        }
                    }
                    total += n;
                    if n == 0 {
                        break;
                    }
                }
            }
        }
        total
    }

    /// Reload in place from a freshly parsed config, reusing unchanged tasks.
    ///
    /// A task whose non-empty config fingerprint still appears in `new_config`
    /// and whose old build succeeded keeps its capturer and outputs: its live
    /// capture state (BPF program, socket, netns, open file) and its output
    /// connection are *not* recreated. Added and changed tasks are built fresh;
    /// tasks absent from the new config (or belonging to a changed fingerprint)
    /// have their outputs destroyed. This mirrors `task.c`'s
    /// `find_task_by_fingerprint` reuse without its three-phase mailbox dance,
    /// because the manager is already serialised by a single mutex.
    ///
    /// Shared-manager callers must use the free [`crate::task::reload`] or [`reload_from_file`]
    /// to serialize with off-manager pipeline capture. The latter parses and
    /// resolves host names *before* taking the lock: a BPF expression
    /// containing a name blocks there for as long as the resolver takes.
    ///
    /// Lock discipline: the shared output thread is joined *before* any old
    /// resource is moved, and `out_sets` is locked only in short, non-overlapping
    /// statements (never across a `self.start()` or a multi-second `destroy()`),
    /// so this cannot reproduce the double-lock deadlock that bit
    /// `collect_stats_summary`.
    ///
    /// # Errors
    /// Returns an error if the rebuilt task set cannot be constructed.
    pub fn reload(&mut self, new_config: Config) -> Result<()> {
        let was_running = self.output_thread.is_some();
        // Join the shared output thread but keep every task's resources so
        // unchanged tasks can be reused below. `stop()` would destroy them all.
        self.stop_output_thread();

        // Move the old task state aside. `out_sets` is left empty so a later
        // `stop()` / `Drop` cannot double-destroy anything we keep.
        let old_entries = std::mem::take(&mut self.entries);
        let old_out_sets = std::mem::take(&mut *self.out_sets.lock());

        // Drop old config after building new tasks (so filter names/sockets are
        // released only once the replacements exist, as before).
        let old_config = std::mem::replace(&mut self.config, new_config);

        // Recreate the shared ring/allocator after draining. Unchanged task
        // capturers and outputs are reused below.
        self.pipeline = None;
        if self.config.execution_model == ExecutionModel::Pipeline {
            self.pipeline = Some(PipelineShared::new(
                1024 * 1024,
                self.config.pipeline_buffer_size_mb * 1024 * 1024,
            ));
        }

        self.reload_epoch += 1;
        let result = self.rebuild_reusing(old_entries, old_out_sets);
        drop(old_config);

        if was_running {
            self.start();
        }
        result?;
        crate::log_info!("reload complete: {} tasks", self.inited_count);
        Ok(())
    }

    /// Build the new task set, moving the capturer and outputs of each old task
    /// whose non-empty fingerprint is unchanged into the new set untouched, and
    /// destroying the outputs of every old task that is not reused.
    ///
    /// `old_entries` and `old_out_sets` are parallel by position; both were moved
    /// out of the manager by [`Self::reload`], which already joined the output
    /// thread, so nothing polls them here.
    ///
    /// # Errors
    /// Reserved for a future fatal build failure; per-task build failures are
    /// recorded and reported like [`Self::build_all`] (`Ok`).
    fn rebuild_reusing(
        &mut self,
        mut old_entries: Vec<TaskEntry>,
        mut old_out_sets: Vec<TaskOutputs>,
    ) -> Result<()> {
        let tasks_cfg = self.config.tasks.clone();
        let mut entries = Vec::with_capacity(tasks_cfg.len());
        let mut out_sets = Vec::with_capacity(tasks_cfg.len());
        let mut inited = 0;
        let mut reused = vec![false; old_entries.len()];

        crate::log_info!("find {} tasks", tasks_cfg.len());
        for (i, task_cfg) in tasks_cfg.iter().enumerate() {
            if let Some(j) = find_reusable(&old_entries, &reused, task_cfg) {
                // `find_reusable` only returns built tasks; if that ever changed,
                // fall through and rebuild rather than leaving a hole.
                if let Some(capturer) = old_entries[j].capturer.take() {
                    reused[j] = true;
                    let outputs = std::mem::take(&mut old_out_sets[j].outputs);
                    crate::log_info!(
                        "existing task-{i}, fingerprint={}",
                        task_cfg.fingerprint.as_deref().unwrap_or("")
                    );
                    entries.push(TaskEntry {
                        index: i,
                        fingerprint: task_cfg.fingerprint.clone(),
                        capturer: Some(capturer),
                        error: None,
                        build_epoch: old_entries[j].build_epoch,
                    });
                    out_sets.push(TaskOutputs { outputs });
                    inited += 1;
                    continue;
                }
            }

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
                        build_epoch: self.reload_epoch,
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
                        build_epoch: self.reload_epoch,
                    });
                    out_sets.push(TaskOutputs {
                        outputs: Vec::new(),
                    });
                }
            }
        }

        // Only the outputs of old tasks that were not moved into the new set are
        // destroyed. This is the reload analogue of `stop()`'s single destroy()
        // call point; the shared output thread is already joined above, so the
        // doomed set is not polled.
        let mut doomed: Vec<Box<dyn Output>> = Vec::new();
        for (j, mut set) in old_out_sets.into_iter().enumerate() {
            if !reused.get(j).copied().unwrap_or(false) {
                doomed.append(&mut set.outputs);
            }
        }
        for o in doomed.iter_mut() {
            o.destroy();
        }
        drop(doomed);

        self.entries = entries;
        *self.out_sets.lock() = out_sets;
        self.inited_count = inited;
        Ok(())
    }

    #[cfg(test)]
    /// The reload generation in which task `index`'s capturer/outputs were last
    /// built (0 = initial build). An entry reused across a reload keeps its old
    /// value; a rebuilt/added one carries the new epoch. Tests use this to tell
    /// reuse from rebuild without relying only on destroy spies.
    #[must_use]
    pub(crate) fn task_build_epoch(&self, index: usize) -> Option<u64> {
        self.entries.get(index).map(|e| e.build_epoch)
    }

    /// Build the `collect_stats_summary` RPC payload. Mirrors
    /// `task_manager_collect_stats_summary_command`.
    #[must_use]
    /// Build the `collect_stats_summary` RPC payload. Mirrors
    /// `task_manager_collect_stats_summary_command`.
    pub fn collect_stats_summary(&self) -> serde_json::Value {
        let (sec, nsec) = monotonic_now();
        let (ring_total, ring_used, mem_total, mem_used) = match &self.pipeline {
            Some(p) => {
                let ring_total = u64::try_from(p.ring.size()).unwrap_or(u64::MAX);
                let ring_used = u64::try_from(p.ring.used()).unwrap_or(u64::MAX);
                (ring_total, ring_used, p.alloc.capacity(), p.alloc.used())
            }
            None => (0, 0, 0, 0),
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

/// Poll a shared manager, amortising locks over a batch. Pipeline capture owns
/// the entries for the duration of the batch, with the manager mutex released:
/// a full ring still backpressures capture without blocking control snapshots.
/// The polling lock prevents another batch or reload from changing task order,
/// outputs or buffers until the entries have been returned.
pub fn poll_packets_batch(mgr: &Mutex<TaskManager>, max: usize) -> u64 {
    let mut guard = mgr.lock();
    if guard.execution_model() == ExecutionModel::Rtc {
        return guard.poll_packets_batch(max);
    }
    let polling = guard.polling.clone();
    drop(guard);
    let _polling = polling.lock();
    let mut guard = mgr.lock();
    // A reload may have changed execution model while we waited for polling.
    if guard.execution_model() == ExecutionModel::Rtc {
        return guard.poll_packets_batch(max);
    }
    let Some(pipeline) = guard.pipeline.clone() else {
        return 0;
    };
    let mut entries = std::mem::take(&mut guard.entries);
    let total = parking_lot::MutexGuard::unlocked(&mut guard, || {
        poll_pipeline(&mut entries, &pipeline, max)
    });
    guard.entries = entries;
    total
}

fn poll_pipeline(entries: &mut [TaskEntry], pipeline: &PipelineShared, max: usize) -> u64 {
    // Borrow the unique producer once per batch, never per packet. The output
    // thread and stats observer do not use this ownership mutex.
    let mut producer = pipeline.producer.lock();
    let mut total = 0;
    for _ in 0..max {
        let mut n = 0;
        for entry in entries.iter_mut() {
            if let Some(cap) = entry.capturer.as_mut() {
                let mut sink = PipelineSink {
                    ring: &mut producer,
                    alloc: &pipeline.alloc,
                    task_index: entry.index,
                };
                n += cap.capture_once(&mut sink);
            }
        }
        total += n;
        if n == 0 {
            break;
        }
    }
    total
}

/// Apply a prepared reload to a shared manager. Wait for any pipeline capture
/// batch before taking the manager mutex, so stats remain available even when
/// a slow output is backpressuring that batch. The output thread still drains
/// all old messages before any task slot or pipeline buffer is replaced.
///
/// # Errors
/// Returns an error if the rebuilt task set cannot be constructed.
pub fn reload(mgr: &Mutex<TaskManager>, config: Config) -> Result<()> {
    let polling = mgr.lock().polling.clone();
    let _polling = polling.lock();
    mgr.lock().reload(config)
}

fn dispatch_ring_msg(
    out_sets: &Arc<Mutex<Vec<TaskOutputs>>>,
    alloc: &Arc<SimpleAllocator>,
    msg: Box<RingMsg>,
) {
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
        (ts.tv_sec, ts.tv_nsec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
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
        "zmtp_queued_batches": s.zmtp_queued_batches.load(Ordering::Relaxed),
        "zmtp_queued_bytes": s.zmtp_queued_bytes.load(Ordering::Relaxed),
    })
}

/// Resolve every host name that the live-capture filters of `config` need, and
/// validate those filters, while **no lock is held**.
///
/// Returns one message per filter that will not compile - the same error the task
/// build reports later, surfaced earlier and once per distinct expression. Tasks
/// with a `netns` are skipped on purpose: their filter is compiled inside that
/// namespace, where the answer may differ, and handing them the outer namespace's
/// addresses would silently change the filter's meaning (they are still covered by
/// the resolution budget).
#[must_use]
pub fn warm_task_names(config: &Config) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (i, task) in config.tasks.iter().enumerate() {
        let CapturerKind::Libpcap(l) = &task.capturer.kind else {
            continue;
        };
        if !l.netns.is_empty() {
            continue;
        }
        let expr = match l.effective_bpf(&config.tasks) {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!("task {i}: {e}"));
                continue;
            }
        };
        if expr.is_empty() || seen.contains(&expr) {
            continue;
        }
        if let Err(e) = crate::bpf::prewarm(&expr) {
            problems.push(format!("task {i}: compile bpf filter error: {e}"));
        }
        seen.push(expr);
    }
    problems
}

/// The result of preparing a reload: a parsed configuration, plus the filters that
/// will not compile (resolved and validated before any running task is touched).
#[derive(Debug)]
pub struct ReloadPlan {
    /// The freshly parsed configuration.
    pub config: Config,
    /// One message per filter that cannot compile. The task build reports the same
    /// errors per task; this is the early, once-per-expression view.
    pub problems: Vec<String>,
}

/// Read the configuration and resolve every name its filters need.
///
/// This is the part that can block for as long as the resolver takes, so it is kept
/// separate from the swap and is only ever called from a thread that is allowed to
/// wait - see [`reload_from_file`] (the RPC handler thread) and [`ReloadWorker`] (the
/// capture loop's thread, which is not allowed to wait at all).
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn prepare_reload(path: &str) -> Result<ReloadPlan> {
    let config = Config::parse_file(Path::new(path))?;
    let problems = warm_task_names(&config);
    Ok(ReloadPlan { config, problems })
}

/// Reload from the path recorded in the manager, preparing it (file read, parse,
/// name resolution) *before* the manager lock is taken (AUDIT4 P2-10).
///
/// `TaskManager::reload()` rebuilds every task, which compiles each BPF expression,
/// which may resolve a name - and `getaddrinfo()` is a blocking call whose timeout
/// the process does not control. Both callers used to write `mgr.lock()
/// .reload_from_file()`: the SIGHUP path (whose thread *is* the capture loop) and
/// the `reload_config` RPC (whose thread is not). Either way packet polling and
/// `cpctl stats` were frozen for as long as DNS took, with every drop counter still
/// reporting 0. Only the swap takes the mutex now.
///
/// This still blocks *its* caller, which is fine for the RPC handler and wrong for the
/// capture loop - use [`ReloadWorker`] there.
///
/// # Errors
/// Returns an error if the config file cannot be read or parsed, or if the rebuilt
/// task set cannot be constructed.
pub fn reload_from_file(mgr: &Arc<Mutex<TaskManager>>) -> Result<()> {
    let path = mgr.lock().config_path().to_string();
    let plan = prepare_reload(&path)?;
    for problem in plan.problems {
        crate::log_warn!("reload: {problem}");
    }
    // Preserve control config from the original (C moves control out before
    // handing config to the task manager).
    reload(mgr, plan.config)
}

/// A reload being prepared on a worker thread.
///
/// The SIGHUP flag is consumed by the capture loop itself, so a reload that resolved
/// names there stopped packet polling for the resolver's whole timeout. `start()`
/// moves that work away; the loop only ever calls [`ReloadWorker::is_done`], which
/// never blocks, and takes the manager lock once the names are already memoised - so
/// the swap is fast. While a name server is unreachable the reload simply stays
/// pending (and the worker keeps capturing) instead of freezing with it.
pub struct ReloadWorker {
    done: Arc<AtomicBool>,
    plan: Arc<Mutex<Option<Result<ReloadPlan>>>>,
    handle: Option<JoinHandle<()>>,
}

impl ReloadWorker {
    /// Start preparing a reload of `path` on a worker thread.
    #[must_use]
    pub fn start(path: &str) -> Self {
        let path = path.to_string();
        Self::start_with(move || prepare_reload(&path))
    }

    /// `start()` with the blocking work injected - how "the caller never waits" is
    /// tested without depending on a name server.
    #[must_use]
    fn start_with<F>(work: F) -> Self
    where
        F: FnOnce() -> Result<ReloadPlan> + Send + 'static,
    {
        let done = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<Result<ReloadPlan>>>> = Arc::new(Mutex::new(None));
        let (flag, result_slot) = (done.clone(), slot.clone());
        let handle = std::thread::Builder::new()
            .name("cp-reload".to_string())
            .spawn(move || {
                *result_slot.lock() = Some(work());
                flag.store(true, Ordering::Release);
            });
        if let Err(e) = handle {
            // No thread means no reload, reported. Falling back to resolving inline
            // would put the capture loop back on the critical path.
            *slot.lock() = Some(Err(crate::error::Error::new(format!(
                "spawn reload worker: {e}"
            ))));
            done.store(true, Ordering::Release);
            return ReloadWorker {
                done,
                plan: slot,
                handle: None,
            };
        }
        ReloadWorker {
            done,
            plan: slot,
            handle: handle.ok(),
        }
    }

    /// Whether the plan is ready. Never blocks.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Take the prepared plan. Call it once [`Self::is_done`] is true: the join must
    /// not become a wait on the resolver, which is the whole point.
    ///
    /// # Errors
    /// Propagated from reading/parsing the configuration, or from failing to spawn
    /// the worker.
    pub fn take(mut self) -> Result<ReloadPlan> {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.plan
            .lock()
            .take()
            .unwrap_or_else(|| Err(crate::error::Error::new("reload plan vanished")))
    }
}

impl Drop for ReloadWorker {
    fn drop(&mut self) {
        // Abandoned (e.g. the process quits while a lookup hangs): the thread is left
        // to finish on its own and holds no lock, so shutdown is not delayed. One
        // abandoned reload leaks at most one thread - deliberately not the
        // "spawn a thread per lookup" design `bpf::resolvers` documents.
        if let Some(handle) = self.handle.take() {
            drop(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::pcap_writer::PcapWriter;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// AUDIT4 P2-10: the SIGHUP handler runs on the capture loop's own thread, and
    /// the old code resolved every host name in every filter right there (and under
    /// `mgr.lock()`, which the loop also takes every batch). A reload must therefore
    /// be *prepared* somewhere else and only polled from the loop.
    ///
    /// The blocking work is injected, so this measures the property that matters -
    /// the caller never waits - rather than a name server's behaviour.
    #[test]
    fn reload_worker_does_not_block_the_capture_loop() {
        let slow = || {
            // Stands in for `getaddrinfo()` against an unreachable name server.
            std::thread::sleep(std::time::Duration::from_millis(250));
            Err(crate::error::Error::new("resolver unreachable"))
        };
        let start = std::time::Instant::now();
        let worker = ReloadWorker::start_with(slow);
        let polled = start.elapsed();
        assert!(
            polled < std::time::Duration::from_millis(50),
            "`start` + first poll took {polled:?}; the loop must not wait on the resolver"
        );
        assert!(!worker.is_done(), "the plan is not ready yet");

        // ... and a lock taken here stays free while the worker works, which is what
        // `cpctl stats` and the next batch of packets need.
        let other = std::sync::Arc::new(Mutex::new(0u32));
        assert!(
            other.try_lock().is_some(),
            "preparation must not hold any lock the loop needs"
        );

        while !worker.is_done() && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(worker.is_done(), "the worker must finish on its own");
        let err = worker
            .take()
            .expect_err("the injected resolver fails, and that must be reported");
        let msg = err.to_string();
        assert!(
            msg.contains("resolver unreachable"),
            "the plan's error must reach the caller: {msg}"
        );
    }

    /// A plan that succeeds is handed over intact, including the early report of
    /// filters that will not compile.
    #[test]
    fn reload_worker_delivers_the_plan_and_its_problems() {
        let worker = ReloadWorker::start_with(|| {
            let config = Config::parse_str(
                r#"{
                    "tasks": [{
                        "capturer": { "type": "libpcap", "libpcap": {
                            "interface": "lo", "bpf": "udp and port 53"
                        } },
                        "outputs": []
                    }]
                }"#,
            )
            .expect("parse");
            let problems = warm_task_names(&config);
            Ok(ReloadPlan { config, problems })
        });
        while !worker.is_done() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let plan = worker.take().expect("plan");
        assert_eq!(plan.config.tasks.len(), 1);
        assert!(
            plan.problems.is_empty(),
            "a valid filter reports nothing: {:?}",
            plan.problems
        );
    }

    /// `prepare_reload` is the part that can block on DNS, so it must not need the
    /// manager at all - and it must actually fill the shared compile cache.
    #[test]
    fn prepare_reload_resolves_into_the_shared_cache() {
        let dir = std::env::temp_dir().join(format!("cp-prepare-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("cfg.json");
        std::fs::write(
            &path,
            r#"{"tasks":[{"capturer":{"type":"libpcap","libpcap":{
                 "interface":"lo","bpf":"udp and not host localhost"}},"outputs":[]}]}"#,
        )
        .expect("write config");
        crate::bpf::clear_name_cache();
        let plan = prepare_reload(path.to_str().expect("utf8 path")).expect("prepare");
        assert_eq!(plan.config.tasks.len(), 1);
        assert!(
            crate::bpf::name_cache_len() >= 1,
            "preparing must have resolved the filter's names into the shared cache"
        );
        crate::bpf::clear_name_cache();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AUDIT4 P3-2: a task whose *second* output fails to be created used to drop
    /// the first output with the `Vec`, and `Output` has no draining `Drop` - the
    /// single `destroy()` call point is `TaskManager::stop()`, which a partially
    /// built task never reaches. `PendingOutputs` is what closes that bypass.
    ///
    /// (This is asserted on the guard itself with spies rather than end-to-end
    /// through `build_task`, because no output's `destroy()` is observable through
    /// a file: `PcapWriter` wraps a `BufWriter`, whose own `Drop` flushes, so the
    /// capture file looks identical either way. That "green by luck" is precisely
    /// what `parity/verify_liveness.sh` exists for - the gate there requires
    /// `build_task` to keep parking its outputs behind this guard.)
    #[test]
    fn pending_outputs_destroys_everything_it_throws_away() {
        let destroyed = Arc::new(AtomicUsize::new(0));
        let mut pending = PendingOutputs::new(2);
        for _ in 0..3 {
            pending.push(Box::new(SpyOutput {
                destroyed: destroyed.clone(),
            }));
        }
        assert_eq!(destroyed.load(Ordering::Relaxed), 0, "not yet");
        drop(pending); // the failure path: outputs are being discarded
        assert_eq!(
            destroyed.load(Ordering::Relaxed),
            3,
            "every output that was created must be destroyed, not just the first"
        );

        // The success path must *not* destroy: the task owns them now.
        let mut pending = PendingOutputs::new(1);
        pending.push(Box::new(SpyOutput {
            destroyed: destroyed.clone(),
        }));
        let handed_over = pending.finish();
        assert_eq!(handed_over.len(), 1);
        drop(handed_over);
        assert_eq!(
            destroyed.load(Ordering::Relaxed),
            3,
            "finish() must leave the guard empty so Drop is a no-op"
        );
    }

    /// `build_task` must keep its outputs behind that guard (see the gate in
    /// `parity/verify_liveness.sh`); this pins the observable part: a task whose
    /// second output cannot be created fails, and the error says why.
    #[test]
    fn build_task_fails_when_an_output_cannot_be_created() {
        let dir = std::env::temp_dir().join(format!("cp-partial-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let input = dir.join("input.pcap");
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
        hdr[20..24].copy_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
        std::fs::write(&input, hdr).expect("write input pcap");
        let bad = dir.join("no-such-dir").join("bad.pcap");

        let cfg = Config::parse_str(&format!(
            r#"{{
                "tasks": [{{
                    "capturer": {{ "type": "pcap_file", "pcap_file": {{ "file_name": "{}" }} }},
                    "outputs": [
                        {{ "type": "file", "file": {{ "name": "{}" }} }},
                        {{ "type": "file", "file": {{ "name": "{}" }} }}
                    ]
                }}]
            }}"#,
            input.display(),
            dir.join("good.pcap").display(),
            bad.display()
        ))
        .expect("parse config");
        let err = match build_task(
            &cfg.tasks,
            &cfg.tasks[0],
            Arc::new(CaptureStats::default()),
            Arc::new(OutputStats::default()),
        ) {
            Ok(_) => panic!("an uncreatable output path must fail the build"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("bad.pcap"), "unexpected error: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AUDIT4 P2-10: rebuilding tasks compiles every BPF expression, and compiling
    /// one may resolve a host name. That work has to be doable *before* the manager
    /// lock is taken, otherwise a slow resolver freezes packet polling and `cpctl
    /// stats` along with it.
    #[test]
    fn warm_task_names_resolves_names_and_reports_bad_filters() {
        let cfg = Config::parse_str(
            r#"{
                "tasks": [{
                    "capturer": { "type": "libpcap", "libpcap": {
                        "interface": "lo", "bpf": "udp and not host localhost"
                    } },
                    "outputs": []
                }]
            }"#,
        )
        .expect("parse good config");
        assert_eq!(
            warm_task_names(&cfg),
            Vec::<String>::new(),
            "a compilable filter must produce nothing to report"
        );

        // Same expression in two tasks: reported once, not twice.
        let bad = Config::parse_str(
            r#"{
                "tasks": [
                    { "capturer": { "type": "libpcap", "libpcap": {
                        "interface": "lo", "bpf": "vlan 5" } }, "outputs": [] },
                    { "capturer": { "type": "libpcap", "libpcap": {
                        "interface": "lo", "bpf": "vlan 5" } }, "outputs": [] }
                ]
            }"#,
        )
        .expect("parse bad config");
        let problems = warm_task_names(&bad);
        assert_eq!(
            problems.len(),
            1,
            "duplicate expressions must collapse, got {problems:?}"
        );
        let first = problems[0].clone();
        assert!(
            first.contains("vlan"),
            "the message must carry the reason: {first}"
        );

        // A netns task is left to its own build: warming it from outside could hand
        // it another namespace's addresses.
        let ns = Config::parse_str(
            r#"{
                "tasks": [{
                    "capturer": { "type": "libpcap", "libpcap": {
                        "interface": "lo", "netns": "/var/run/netns/nope", "bpf": "vlan 5"
                    } },
                    "outputs": []
                }]
            }"#,
        )
        .expect("parse netns config");
        assert_eq!(
            warm_task_names(&ns),
            Vec::<String>::new(),
            "netns tasks must not be warmed from the outer namespace"
        );
    }

    /// Output that records how many times `destroy()` was called on it.
    struct SpyOutput {
        destroyed: Arc<AtomicUsize>,
    }

    impl Output for SpyOutput {
        fn send_packet(&mut self, _hdr: &PacketHeader, _pkt: &[u8], _direct: i32) -> i32 {
            0
        }
        fn destroy(&mut self) {
            self.destroyed.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Create a tiny pcap file so the offline capturer can be built.
    fn scratch_pcap(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("in.pcap");
        {
            let mut w = PcapWriter::create(&path, 65535).expect("create pcap");
            let hdr = PacketHeader {
                ts_sec: 1,
                ts_usec: 0,
                caplen: 16,
                len: 16,
            };
            w.write(&hdr, &[0u8; 16]).expect("write");
        }
        path
    }

    /// A one-task RTC manager whose task also owns `n` spy outputs.
    fn manager_with_spies(dir: &std::path::Path, n: usize) -> (TaskManager, Vec<Arc<AtomicUsize>>) {
        let pcap = scratch_pcap(dir);
        let cfg = format!(
            r#"{{"execution_model":"rtc","tasks":[{{
                "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
                "outputs": [{{"type":"null"}}]
            }}]}}"#,
            pcap.display()
        );
        let mgr = TaskManager::new(
            Config::parse_str(&cfg).expect("parse config"),
            "test.json".into(),
            dir.display().to_string(),
        )
        .expect("manager");
        let mut counters = Vec::new();
        {
            let mut sets = mgr.out_sets.lock();
            for _ in 0..n {
                let c = Arc::new(AtomicUsize::new(0));
                counters.push(c.clone());
                sets[0].outputs.push(Box::new(SpyOutput { destroyed: c }));
            }
        }
        (mgr, counters)
    }

    #[test]
    fn stop_destroys_every_output_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let (mut mgr, counters) = manager_with_spies(dir.path(), 2);

        mgr.stop();
        for c in &counters {
            assert_eq!(
                c.load(Ordering::SeqCst),
                1,
                "Output::destroy() must be called exactly once by TaskManager::stop()"
            );
        }
        // The call point is idempotent: a second stop() must not destroy twice.
        mgr.stop();
        for c in &counters {
            assert_eq!(
                c.load(Ordering::SeqCst),
                1,
                "destroy() called more than once"
            );
        }
    }

    #[test]
    fn manager_drop_destroys_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, counters) = manager_with_spies(dir.path(), 1);
        drop(mgr);
        assert_eq!(
            counters[0].load(Ordering::SeqCst),
            1,
            "dropping the TaskManager must run the destroy() call point (Drop -> stop)"
        );
    }

    #[test]
    fn reload_destroys_replaced_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let (mut mgr, counters) = manager_with_spies(dir.path(), 1);
        let pcap = scratch_pcap(dir.path());
        let cfg = format!(
            r#"{{"execution_model":"rtc","tasks":[{{
                "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
                "outputs": [{{"type":"null"}}]
            }}]}}"#,
            pcap.display()
        );
        mgr.reload(Config::parse_str(&cfg).expect("parse config"))
            .expect("reload");
        assert_eq!(
            counters[0].load(Ordering::SeqCst),
            1,
            "reload() must destroy the outputs it replaces, otherwise their buffers \
             (ZMQ linger, pcap flush) are never drained"
        );
    }

    #[test]
    fn pipeline_stop_destroys_outputs_after_output_thread_joined() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let cfg = format!(
            r#"{{"execution_model":"pipeline","pipeline":{{"buffer_size_mb":1}},"tasks":[{{
                "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
                "outputs": [{{"type":"null"}}]
            }}]}}"#,
            pcap.display()
        );
        let mut mgr = TaskManager::new(
            Config::parse_str(&cfg).expect("parse config"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("manager");
        let c = Arc::new(AtomicUsize::new(0));
        mgr.out_sets.lock()[0].outputs.push(Box::new(SpyOutput {
            destroyed: c.clone(),
        }));
        mgr.start();
        assert!(mgr.output_thread.is_some());
        mgr.stop();
        assert_eq!(c.load(Ordering::SeqCst), 1);
    }

    // -----------------------------------------------------------------------
    // Tier 1 coverage: validation, output wiring and reload edge cases.
    // -----------------------------------------------------------------------

    /// Output that counts what the pipeline dispatch path delivers, so the
    /// forwarding can be asserted rather than merely executed.
    struct CountOutput {
        packets: Arc<AtomicUsize>,
        heartbeats: Arc<AtomicUsize>,
    }

    impl Output for CountOutput {
        fn send_packet(&mut self, _hdr: &PacketHeader, _pkt: &[u8], _direct: i32) -> i32 {
            self.packets.fetch_add(1, Ordering::SeqCst);
            0
        }
        fn heartbeat(&mut self, _now: i64) {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct BurstCapturer {
        base: u8,
        packets: u8,
        attempted: Arc<AtomicUsize>,
        wait_for_output: Option<Arc<AtomicBool>>,
    }

    impl Capturer for BurstCapturer {
        fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
            let hdr = PacketHeader {
                ts_sec: 1,
                ts_usec: 2,
                caplen: 1,
                len: 1,
            };
            for i in 0..self.packets {
                self.attempted.fetch_add(1, Ordering::SeqCst);
                sink.on_packet(&hdr, &[self.base + i], 7);
                if let Some(started) = self.wait_for_output.take() {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
                    while !started.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    assert!(
                        started.load(Ordering::Acquire),
                        "first output did not start"
                    );
                }
            }
            sink.on_heartbeat();
            u64::from(self.packets)
        }
    }

    struct BlockingOutput {
        base: u8,
        entered: Option<std::sync::mpsc::Sender<()>>,
        started: Arc<AtomicBool>,
        release: std::sync::mpsc::Receiver<()>,
        delivered: Arc<Mutex<Vec<u8>>>,
        destroyed: Arc<AtomicUsize>,
    }

    impl Output for BlockingOutput {
        fn send_packet(&mut self, _hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
            assert_eq!(direct, 7);
            if let Some(entered) = self.entered.take() {
                self.started.store(true, Ordering::Release);
                entered.send(()).unwrap();
                // A watchdog also lets failing versions join and drain instead
                // of leaving the suite stuck in the deliberately blocked output.
                let _ = self.release.recv_timeout(std::time::Duration::from_secs(5));
            }
            self.delivered.lock().push(pkt[0]);
            0
        }

        fn heartbeat(&mut self, _now: i64) {
            self.delivered.lock().push(self.base + 9);
        }

        fn destroy(&mut self) {
            self.destroyed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn blocked_pipeline_output_allows_enqueue_and_stop_drains_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = pipeline_manager(dir.path());
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let destroyed = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        manager.entries[0].capturer = Some(Box::new(BurstCapturer {
            base: 10,
            packets: 6,
            attempted: Arc::new(AtomicUsize::new(0)),
            wait_for_output: Some(started.clone()),
        }));
        manager.out_sets.lock()[0].outputs = vec![Box::new(BlockingOutput {
            base: 10,
            entered: Some(entered_tx),
            started,
            release: release_rx,
            delivered: delivered.clone(),
            destroyed: destroyed.clone(),
        })];
        manager.start();
        let mgr = Arc::new(Mutex::new(manager));
        let m = mgr.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let producer = std::thread::spawn(move || {
            done_tx.send(poll_packets_batch(&m, 1)).unwrap();
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let progress = done_rx.recv_timeout(std::time::Duration::from_secs(1));
        release_tx.send(()).unwrap();
        producer.join().unwrap();
        mgr.lock().stop();
        assert_eq!(
            progress.unwrap(),
            6,
            "output dispatch must not own the ring lock"
        );
        assert_eq!(*delivered.lock(), vec![10, 11, 12, 13, 14, 15, 19]);
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
        let summary = mgr.lock().collect_stats_summary();
        assert_eq!(summary["pipeline_buffer"]["ring_used"], 0);
        assert_eq!(summary["pipeline_buffer"]["mem_used"], 0);
    }

    #[test]
    fn full_pipeline_keeps_stats_responsive_and_reload_preserves_order() {
        // Exercise ring exhaustion and byte-budget exhaustion independently.
        for (ring_size, mem_size) in [(3, 4096), (16, (std::mem::size_of::<RingMsg>() + 1) * 3)] {
            let dir = tempfile::tempdir().unwrap();
            let pcap = scratch_pcap(dir.path());
            let config = fp_tasks_cfg(&pcap, &["a", "b"]).replace(
                "\"rtc\"",
                "\"pipeline\",\"pipeline\":{\"buffer_size_mb\":1}",
            );
            let mut manager = TaskManager::new(
                Config::parse_str(&config).unwrap(),
                "test.json".into(),
                dir.path().display().to_string(),
            )
            .unwrap();
            manager.pipeline = Some(PipelineShared::new(
                ring_size,
                u64::try_from(mem_size).unwrap(),
            ));
            let old_ring = manager.pipeline.as_ref().unwrap().producer.clone();
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let destroyed = Arc::new(AtomicUsize::new(0));
            let attempted = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(AtomicBool::new(false));
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (_, unused_rx) = std::sync::mpsc::channel();
            let mut entered = Some(entered_tx);
            let mut releases = [release_rx, unused_rx].into_iter();
            for (index, base) in [10, 20].into_iter().enumerate() {
                manager.entries[index].capturer = Some(Box::new(BurstCapturer {
                    base,
                    packets: 6,
                    attempted: attempted.clone(),
                    wait_for_output: (index == 0).then(|| started.clone()),
                }));
                manager.out_sets.lock()[index].outputs = vec![Box::new(BlockingOutput {
                    base,
                    entered: entered.take(),
                    started: started.clone(),
                    release: releases.next().unwrap(),
                    delivered: delivered.clone(),
                    destroyed: destroyed.clone(),
                })];
            }
            manager.start();
            let mgr = Arc::new(Mutex::new(manager));
            let m = mgr.clone();
            let producer = std::thread::spawn(move || poll_packets_batch(&m, 1));
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while attempted.load(Ordering::SeqCst) < 4 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            let m = mgr.clone();
            let replacement = fp_tasks_cfg(&pcap, &["b", "a"]).replace(
                "\"rtc\"",
                "\"pipeline\",\"pipeline\":{\"buffer_size_mb\":1}",
            );
            let (reload_tx, reload_rx) = std::sync::mpsc::channel();
            let reloader = std::thread::spawn(move || {
                reload(&m, Config::parse_str(&replacement).unwrap()).unwrap();
                reload_tx.send(()).unwrap();
            });
            let m = mgr.clone();
            let (stats_tx, stats_rx) = std::sync::mpsc::channel();
            let stats = std::thread::spawn(move || {
                stats_tx.send(m.lock().collect_stats_summary()).unwrap();
            });
            let snapshot = stats_rx.recv_timeout(std::time::Duration::from_secs(1));
            let still_waiting = reload_rx.try_recv().is_err();
            release_tx.send(()).unwrap();
            assert_eq!(producer.join().unwrap(), 12);
            reloader.join().unwrap();
            stats.join().unwrap();
            let summary = snapshot
                .expect("stats must not wait for full-ring capture or reload's polling lock");
            assert!(still_waiting, "reload must wait for the old capture batch");
            assert_eq!(summary["pipeline_buffer"]["ring_total"], ring_size);
            assert_eq!(summary["pipeline_buffer"]["mem_total"], mem_size);
            if ring_size == 3 {
                assert_eq!(summary["pipeline_buffer"]["ring_used"], 2);
            }
            assert!(
                serde_json::from_value::<u64>(summary["pipeline_buffer"]["mem_used"].clone())
                    .unwrap()
                    <= u64::try_from(mem_size).unwrap()
            );
            let mut manager = mgr.lock();
            assert!(!Arc::ptr_eq(
                &old_ring,
                &manager.pipeline.as_ref().unwrap().producer
            ));
            assert_eq!(manager.task_build_epoch(0), Some(0));
            assert_eq!(manager.task_build_epoch(1), Some(0));
            assert_eq!(
                destroyed.load(Ordering::SeqCst),
                0,
                "both outputs were reused"
            );
            manager.stop();
            assert_eq!(destroyed.load(Ordering::SeqCst), 2);
            assert_eq!(
                *delivered.lock(),
                vec![10, 11, 12, 13, 14, 15, 19, 20, 21, 22, 23, 24, 25, 29]
            );
            assert_eq!(
                manager.collect_stats_summary()["pipeline_buffer"]["mem_used"],
                0
            );
        }
    }

    fn pipeline_cfg_json(pcap: &std::path::Path) -> String {
        format!(
            r#"{{"execution_model":"pipeline","pipeline":{{"buffer_size_mb":1}},"tasks":[{{
                "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
                "outputs": [{{"type":"null"}}]
            }}]}}"#,
            pcap.display()
        )
    }

    fn pipeline_manager(dir: &std::path::Path) -> TaskManager {
        let pcap = scratch_pcap(dir);
        TaskManager::new(
            Config::parse_str(&pipeline_cfg_json(&pcap)).expect("parse config"),
            "test.json".into(),
            dir.display().to_string(),
        )
        .expect("manager")
    }

    /// Every accessor that the RPC surface and the docs expose must report the
    /// configuration the manager was built from.
    #[test]
    fn manager_accessors_report_the_built_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _) = manager_with_spies(dir.path(), 0);
        assert_eq!(mgr.total_tasks(), 1);
        assert_eq!(mgr.inited_count(), 1);
        assert_eq!(mgr.config_path(), "test.json");
        assert_eq!(mgr.working_dir(), dir.path().display().to_string());
        assert!(
            mgr.started_at() > 0,
            "started_at must be a real epoch stamp"
        );
        assert_eq!(mgr.execution_model(), ExecutionModel::Rtc);
    }

    /// `collect_stats_summary` must report the pipeline's ring/allocator sizes
    /// without deadlocking (the Pipeline arm used to lock the same
    /// `parking_lot::Mutex` twice in one statement).
    #[test]
    fn stats_summary_reports_zeroes_for_rtc() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _) = manager_with_spies(dir.path(), 0);
        assert_eq!(mgr.execution_model(), ExecutionModel::Rtc);
        let summary = mgr.collect_stats_summary();
        assert_eq!(summary["pipeline_buffer"]["ring_total"], 0);
        assert_eq!(summary["pipeline_buffer"]["mem_total"], 0);
        assert_eq!(summary["pipeline_buffer"]["ring_used"], 0);
        assert_eq!(summary["pipeline_buffer"]["mem_used"], 0);
    }

    /// The Pipeline arm must report the real ring/allocator sizes and, crucially,
    /// must not deadlock (regression for the double-lock bug).
    #[test]
    fn stats_summary_reports_pipeline_ring_and_alloc() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = pipeline_manager(dir.path());
        assert_eq!(mgr.execution_model(), ExecutionModel::Pipeline);
        let summary = mgr.collect_stats_summary();
        let ring_total: u64 =
            serde_json::from_value(summary["pipeline_buffer"]["ring_total"].clone()).unwrap();
        let mem_total: u64 =
            serde_json::from_value(summary["pipeline_buffer"]["mem_total"].clone()).unwrap();
        assert!(ring_total > 0, "pipeline ring size must be reported");
        assert!(
            mem_total > 0,
            "pipeline allocator capacity must be reported"
        );
        assert_eq!(summary["pipeline_buffer"]["ring_used"], 0);
        assert_eq!(summary["pipeline_buffer"]["mem_used"], 0);
    }

    /// Both execution models must drain the one-packet scratch pcap and stop when
    /// the source is exhausted; the single-packet `poll_packets` wrapper agrees.
    #[test]
    fn poll_packets_batch_drains_rtc_and_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let (mut rtc, _) = manager_with_spies(dir.path(), 0);
        assert_eq!(
            rtc.poll_packets(),
            1,
            "the scratch pcap holds exactly one packet"
        );
        assert_eq!(
            rtc.poll_packets(),
            0,
            "the source is exhausted after one poll"
        );

        let dir2 = tempfile::tempdir().unwrap();
        let mut pipe = pipeline_manager(dir2.path());
        assert_eq!(
            pipe.poll_packets_batch(4),
            1,
            "the pipeline path must drain the same single packet"
        );
    }

    /// A task that cannot be built is recorded (not fatal) and surfaced by
    /// `print_errors` for both the fingerprint-labelled and the anonymous form.
    #[test]
    fn failed_task_build_is_recorded_and_printable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.pcap");
        let cfg = format!(
            r#"{{"execution_model":"rtc","tasks":[
                {{"fingerprint":"fp1","capturer":{{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}},
                {{"capturer":{{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}}
            ]}}"#,
            missing.display(),
            missing.display()
        );
        let mgr = TaskManager::new(
            Config::parse_str(&cfg).expect("parse"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("a task build failure must not fail the whole manager");
        assert_eq!(mgr.inited_count(), 0);
        assert_eq!(mgr.total_tasks(), 2);
        mgr.print_errors(); // covers the Some(fp) and None arms
    }

    /// The pipeline sink is the only producer into the ring; both the packet and
    /// the heartbeat path must enqueue a message carrying the task index.
    #[test]
    fn pipeline_sink_enqueues_packets_and_heartbeats() {
        let (mut producer, mut consumer, ring) = SpscRing::new(16).into_split();
        let alloc = SimpleAllocator::new(4096);
        let mut sink = PipelineSink {
            ring: &mut producer,
            alloc: &alloc,
            task_index: 3,
        };
        let hdr = PacketHeader {
            ts_sec: 1,
            ts_usec: 2,
            caplen: 4,
            len: 4,
        };
        sink.on_packet(&hdr, &[1, 2, 3, 4], 7);
        match consumer.pop().expect("packet queued").as_ref() {
            RingMsg::Packet {
                task_index,
                direction,
                caplen,
                data,
                ..
            } => {
                assert_eq!(*task_index, 3);
                assert_eq!(*direction, 7);
                assert_eq!(*caplen, 4);
                assert_eq!(data, &[1, 2, 3, 4]);
            }
            other => panic!("expected packet, got {other:?}"),
        }
        sink.on_heartbeat();
        match consumer.pop().expect("heartbeat queued").as_ref() {
            RingMsg::Heartbeat { task_index, .. } => assert_eq!(*task_index, 3),
            other => panic!("expected heartbeat, got {other:?}"),
        }
        assert_eq!(ring.used(), 0);
        assert!(alloc.used() > 0, "both messages must hold allocator budget");
    }

    /// `dispatch_ring_msg` forwards to the owning task's outputs and always frees
    /// the message, including when no task owns it (otherwise the allocator would
    /// leak budget until the pipeline starves).
    #[test]
    fn dispatch_ring_msg_forwards_to_the_owning_task_and_frees() {
        let packets = Arc::new(AtomicUsize::new(0));
        let beats = Arc::new(AtomicUsize::new(0));
        let out_sets = Arc::new(Mutex::new(vec![TaskOutputs {
            outputs: vec![Box::new(CountOutput {
                packets: packets.clone(),
                heartbeats: beats.clone(),
            })],
        }]));
        let alloc = Arc::new(SimpleAllocator::new(4096));

        let msg = alloc
            .alloc_packet(0, 5, 1, 2, &[0u8; 8])
            .expect("alloc packet");
        dispatch_ring_msg(&out_sets, &alloc, msg);
        assert_eq!(packets.load(Ordering::SeqCst), 1);

        let beat = alloc.alloc_heartbeat(0).expect("alloc heartbeat");
        dispatch_ring_msg(&out_sets, &alloc, beat);
        assert_eq!(beats.load(Ordering::SeqCst), 1);

        let stray = alloc
            .alloc_packet(9, 0, 0, 0, &[0u8; 8])
            .expect("alloc stray");
        let used_before = alloc.used();
        dispatch_ring_msg(&out_sets, &alloc, stray);
        assert!(
            alloc.used() < used_before,
            "an orphan message's budget must still be released"
        );
    }

    /// `start` is a no-op for RTC and for the defensive pipeline-without-buffers
    /// state; neither may leave a thread handle behind.
    #[test]
    fn start_is_a_noop_for_rtc_and_without_a_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let (mut rtc, _) = manager_with_spies(dir.path(), 0);
        rtc.start();
        assert!(rtc.output_thread.is_none(), "RTC has no output thread");

        let mut pipe = pipeline_manager(dir.path());
        pipe.pipeline = None; // defensive state the constructor never makes
        pipe.start();
        assert!(
            pipe.output_thread.is_none(),
            "no ring/alloc means no thread"
        );
        assert_eq!(
            pipe.poll_packets_batch(1),
            0,
            "a pipeline without ring/alloc must poll nothing rather than panic"
        );
    }

    /// Reloading a running pipeline manager rebuilds the ring/allocator and
    /// restarts the output thread; a stopped manager must stay stopped.
    #[test]
    fn reload_recreates_pipeline_buffers_and_restarts_the_thread() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let cfg = pipeline_cfg_json(&pcap);
        let mut mgr = TaskManager::new(
            Config::parse_str(&cfg).expect("parse"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("manager");
        mgr.start();
        assert!(mgr.output_thread.is_some());
        mgr.reload(Config::parse_str(&cfg).expect("parse"))
            .expect("reload");
        assert!(mgr.pipeline.is_some(), "pipeline buffers must be rebuilt");
        assert!(
            mgr.output_thread.is_some(),
            "a running manager must stay started after reload"
        );
        mgr.stop();
    }

    /// `ReloadWorker::start` reads and parses off-thread; the plan reaches the
    /// caller intact.
    #[test]
    fn reload_worker_start_reads_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"execution_model":"rtc","tasks":[]}"#).expect("write");
        let worker = ReloadWorker::start(path.to_str().expect("utf8"));
        while !worker.is_done() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let plan = worker.take().expect("plan");
        assert!(plan.config.tasks.is_empty());
        assert!(plan.problems.is_empty());
    }

    /// `take` must report a missing plan rather than panic or return a default.
    #[test]
    fn reload_worker_take_reports_a_vanished_plan() {
        let worker = ReloadWorker {
            done: Arc::new(AtomicBool::new(true)),
            plan: Arc::new(Mutex::new(None)),
            handle: None,
        };
        let err = worker.take().expect_err("no plan stored");
        assert!(err.to_string().contains("vanished"), "got {err}");
    }

    /// Dropping a worker whose lookup is still running must detach, not join.
    #[test]
    fn reload_worker_drop_detaches_a_running_worker() {
        let worker = ReloadWorker::start_with(|| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            Err(crate::error::Error::new("late"))
        });
        drop(worker);
    }

    /// `reload_from_file` prepares off-lock and still swaps the tasks; a config
    /// whose filters cannot compile is reported as problems but is not fatal.
    #[test]
    fn reload_from_file_prepares_off_lock_and_reports_problems() {
        let dir = tempfile::tempdir().unwrap();
        let input = scratch_pcap(dir.path());
        let cfg_path = dir.path().join("cfg.json");
        let json = format!(
            r#"{{"execution_model":"rtc","tasks":[
                {{"capturer":{{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}},
                {{"capturer":{{"type":"libpcap","libpcap":{{"interface":"lo","bpf":"vlan 5"}}}},"outputs":[]}},
                {{"capturer":{{"type":"libpcap","libpcap":{{"interface":"lo","bpf":"host nic.definitely_not_real0"}}}},"outputs":[]}}
            ]}}"#,
            input.display()
        );
        std::fs::write(&cfg_path, &json).expect("write config");
        let mgr = TaskManager::new(
            Config::parse_str(&json).expect("parse"),
            cfg_path.display().to_string(),
            dir.path().display().to_string(),
        )
        .expect("manager");
        let mgr = Arc::new(Mutex::new(mgr));
        reload_from_file(&mgr).expect("a reload with task build errors still returns Ok");
        assert_eq!(
            mgr.lock().inited_count(),
            1,
            "only the pcap_file task can be rebuilt"
        );
    }

    /// Build the JSON for an RTC manager whose tasks all capture the same
    /// one-packet scratch pcap and carry the given config fingerprints.
    fn fp_tasks_cfg(pcap: &std::path::Path, fps: &[&str]) -> String {
        let tasks: Vec<String> = fps
            .iter()
            .map(|fp| {
                format!(
                    r#"{{"fingerprint":"{fp}","capturer":{{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}}"#,
                    pcap.display()
                )
            })
            .collect();
        format!(
            r#"{{"execution_model":"rtc","tasks":[{}]}}"#,
            tasks.join(",")
        )
    }

    /// The core of the efficiency change: in one reload, an unchanged fingerprint
    /// keeps its capturer and outputs untouched, a changed fingerprint (same task,
    /// new config) is rebuilt, an added task is built, and a removed one is
    /// destroyed. The generation counter makes reuse vs rebuild explicit, and the
    /// destroy spy proves the unchanged output was *not* recreated.
    #[test]
    fn reload_reuses_unchanged_tasks_and_rebuilds_only_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let mut mgr = TaskManager::new(
            Config::parse_str(&fp_tasks_cfg(&pcap, &["a", "b", "d"])).expect("parse"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("manager");

        // Attach one spy output to each initial task so a rebuild is observable.
        let spies: Vec<Arc<AtomicUsize>> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        {
            let mut sets = mgr.out_sets.lock();
            for (i, c) in spies.iter().enumerate() {
                sets[i].outputs.push(Box::new(SpyOutput {
                    destroyed: c.clone(),
                }));
            }
        }
        for i in 0..3 {
            assert_eq!(mgr.task_build_epoch(i), Some(0), "initial build is epoch 0");
        }

        // New order: a unchanged, b -> b2 (changed fingerprint), c added, d gone.
        mgr.reload(Config::parse_str(&fp_tasks_cfg(&pcap, &["a", "b2", "c"])).expect("parse"))
            .expect("reload");

        assert_eq!(mgr.inited_count(), 3);
        assert_eq!(mgr.total_tasks(), 3);
        assert_eq!(
            spies[0].load(Ordering::SeqCst),
            0,
            "unchanged task 'a' must be reused: its output must not be destroyed"
        );
        assert_eq!(
            spies[1].load(Ordering::SeqCst),
            1,
            "removed/changed task 'b' must be destroyed"
        );
        assert_eq!(
            spies[2].load(Ordering::SeqCst),
            1,
            "removed task 'd' must be destroyed"
        );
        assert_eq!(
            mgr.task_build_epoch(0),
            Some(0),
            "'a' keeps its old generation => reused"
        );
        assert_eq!(
            mgr.task_build_epoch(1),
            Some(1),
            "'b2' was rebuilt => new generation"
        );
        assert_eq!(
            mgr.task_build_epoch(2),
            Some(1),
            "'c' was added => new generation"
        );

        // The reused capturer still works: each of the three tasks drains its own
        // scratch-pcap packet (a was not left in a broken half-reloaded state).
        assert_eq!(mgr.poll_packets_batch(4), 3);
    }

    /// A non-empty fingerprint reused across two reloads is reused again (and its
    /// output survives both), while a fingerprint that disappears is destroyed once.
    #[test]
    fn repeated_reload_keeps_reusing_the_same_task() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let mut mgr = TaskManager::new(
            Config::parse_str(&fp_tasks_cfg(&pcap, &["keep"])).expect("parse"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("manager");
        let c = Arc::new(AtomicUsize::new(0));
        mgr.out_sets.lock()[0].outputs.push(Box::new(SpyOutput {
            destroyed: c.clone(),
        }));

        for _ in 0..3 {
            mgr.reload(Config::parse_str(&fp_tasks_cfg(&pcap, &["keep"])).expect("parse"))
                .expect("reload");
            assert_eq!(mgr.task_build_epoch(0), Some(0), "still the initial build");
        }
        assert_eq!(
            c.load(Ordering::SeqCst),
            0,
            "never destroyed while fingerprint holds"
        );

        // Drop the task: now its output must be destroyed exactly once.
        mgr.reload(Config::parse_str(&fp_tasks_cfg(&pcap, &[])).expect("parse"))
            .expect("reload");
        assert_eq!(mgr.inited_count(), 0);
        assert_eq!(c.load(Ordering::SeqCst), 1);
    }

    /// A task without a fingerprint cannot be identified across configs, so it is
    /// rebuilt even when the rest of its config is byte-identical. This preserves
    /// the pre-change behaviour for hand-written configs.
    #[test]
    fn reload_rebuilds_a_task_without_a_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let cfg = format!(
            r#"{{"execution_model":"rtc","tasks":[{{"capturer":{{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}}]}}"#,
            pcap.display()
        );
        let mut mgr = TaskManager::new(
            Config::parse_str(&cfg).expect("parse"),
            "test.json".into(),
            dir.path().display().to_string(),
        )
        .expect("manager");
        let c = Arc::new(AtomicUsize::new(0));
        mgr.out_sets.lock()[0].outputs.push(Box::new(SpyOutput {
            destroyed: c.clone(),
        }));
        mgr.reload(Config::parse_str(&cfg).expect("parse"))
            .expect("reload");
        assert_eq!(
            c.load(Ordering::SeqCst),
            1,
            "an anonymous task must be rebuilt (and its old output destroyed)"
        );
        assert_eq!(mgr.task_build_epoch(0), Some(1));
    }

    /// Lock-discipline regression: reload and `collect_stats_summary` run on
    /// separate threads against the same manager. If the new reload path nested
    /// the `out_sets`/ring locks (or held one across `start()`), the workers would
    /// park forever; the watchdog fails the test instead of hanging the suite.
    #[test]
    fn reload_and_stats_summary_run_without_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let pcap = scratch_pcap(dir.path());
        let cfg_path = dir.path().join("cfg.json");
        let json = format!(
            r#"{{"execution_model":"pipeline","pipeline":{{"buffer_size_mb":1}},"tasks":[
                {{"fingerprint":"a","capturer":{{"type":"pcap_file","pcap_file":{{ "file_name":"{}"}}}},"outputs":[{{"type":"null"}}]}}
            ]}}"#,
            pcap.display()
        );
        std::fs::write(&cfg_path, &json).expect("write config");
        let mgr = Arc::new(Mutex::new(
            TaskManager::new(
                Config::parse_str(&json).expect("parse"),
                cfg_path.display().to_string(),
                dir.path().display().to_string(),
            )
            .expect("manager"),
        ));
        mgr.lock().start();

        let (tx, rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..3 {
            let m = mgr.clone();
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..300 {
                    let s = m.lock().collect_stats_summary();
                    let ring_total: u64 =
                        serde_json::from_value(s["pipeline_buffer"]["ring_total"].clone())
                            .unwrap_or(0);
                    assert!(ring_total > 0);
                }
                tx.send(()).expect("send");
            }));
        }
        {
            let m = mgr.clone();
            let path = cfg_path.display().to_string();
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..20 {
                    let plan = prepare_reload(&path).expect("prepare");
                    m.lock().reload(plan.config).expect("reload");
                }
                tx.send(()).expect("send");
            }));
        }
        drop(tx);

        for _ in 0..handles.len() {
            rx.recv_timeout(std::time::Duration::from_secs(30))
                .expect("reload/stats deadlocked: a lock outlived its scope");
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
        mgr.lock().stop();
    }
}
