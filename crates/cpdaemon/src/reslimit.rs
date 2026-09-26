//! Process resource limiting via cgroup v2. Simplified port of
//! `cpdaemon/pkg/cgroup` + `pkg/worker/reslimit*.go`.
//!
//! Only the CPU quota path is implemented; on non-cgroup-v2 hosts limiting is
//! skipped (the worker still runs).

use std::path::PathBuf;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct CgroupCfg {
    pub version: String,
    pub root: String,
    pub hierarchy: String,
}

impl CgroupCfg {
    pub fn effective_root(&self) -> &str {
        if self.root.is_empty() {
            "/sys/fs/cgroup"
        } else {
            &self.root
        }
    }

    pub fn effective_hierarchy(&self) -> &str {
        if self.hierarchy.is_empty() {
            "cloud-probe"
        } else {
            &self.hierarchy
        }
    }

    /// Port of `CgroupCfg.Validate`: version must be auto/v1/v2.
    pub fn validate(&self) -> Result<()> {
        match self.version.as_str() {
            "auto" | "v1" | "v2" => Ok(()),
            other => Err(Error::new(format!(
                "invalid cgroup.version {other:?}: expected one of auto, v1, v2"
            ))),
        }
    }
}

/// A process placed in a cgroup with a CPU quota.
#[derive(Debug)]
pub struct ProcessLimit {
    path: PathBuf,
    active: bool,
}

fn is_cgroup_v2(root: &str) -> bool {
    std::path::Path::new(root)
        .join("cgroup.controllers")
        .exists()
}

/// Create (or reuse) a cgroup for `pid`, apply the CPU quota, and add the pid.
pub fn create_process_limit(
    pid: i32,
    cfg: &CgroupCfg,
    cpu_limit: Option<f64>,
) -> Result<Option<ProcessLimit>> {
    let Some(cpu) = cpu_limit.filter(|c| *c > 0.0) else {
        return Ok(None);
    };

    let root = cfg.effective_root();
    if cfg.version != "v2" && !is_cgroup_v2(root) {
        crate::log_warn!("cgroup v2 not detected at {root}; skipping cpu limit for pid {pid}");
        return Ok(None);
    }

    let dir = std::path::Path::new(root).join(cfg.effective_hierarchy());
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::new(format!("create cgroup {}: {e}", dir.display())))?;

    // period = 100ms, quota = cpu * period
    let period: u64 = 100_000;
    let quota = (cpu * period as f64).round() as u64;
    std::fs::write(dir.join("cpu.max"), format!("{quota} {period}"))
        .map_err(|e| Error::new(format!("write cpu.max: {e}")))?;

    // enable cpu controller in the parent if needed
    let _ = std::fs::write(dir.join("cgroup.subtree_control"), "+cpu");

    add_process(&dir, pid)?;
    crate::log_info!(
        "cpu limit applied: pid={pid}, cpu={cpu}, cgroup={}",
        dir.display()
    );
    Ok(Some(ProcessLimit {
        path: dir,
        active: true,
    }))
}

fn add_process(dir: &std::path::Path, pid: i32) -> Result<()> {
    std::fs::write(dir.join("cgroup.procs"), format!("{pid}"))
        .map_err(|e| Error::new(format!("add pid {pid} to cgroup {}: {e}", dir.display())))
}

impl ProcessLimit {
    /// Remove the cpu limit without deleting the cgroup (worker still attached).
    pub fn reset(&self) -> Result<()> {
        std::fs::write(self.path.join("cpu.max"), "max 100000")
            .map_err(|e| Error::new(format!("reset cpu.max: {e}")))
    }

    pub fn cleanup(mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        if let Err(e) = std::fs::remove_dir(&self.path) {
            return Err(Error::new(format!(
                "remove cgroup {}: {e}",
                self.path.display()
            )));
        }
        Ok(())
    }
}
