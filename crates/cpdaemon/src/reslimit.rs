//! Process resource limiting via cgroup v2. Simplified port of
//! `cpdaemon/pkg/cgroup` + `pkg/worker/reslimit*.go`.
//!
//! Only the CPU quota path is implemented; on non-cgroup-v2 hosts limiting is
//! skipped (the worker still runs).

use std::path::PathBuf;

use crate::error::{Error, Result};

/// CFS scheduling period written to `cpu.max` (100ms), matching upstream.
pub(crate) const CFS_PERIOD_US: u64 = 100_000;

/// Minimum CFS CPU quota accepted by the kernel (microseconds). The kernel
/// rejects `cpu.max` quotas below this value with `EINVAL`; upstream #284 adds
/// this floor.
pub(crate) const CFS_MIN_QUOTA_US: u64 = 1_000;

/// Compute the `cpu.max` quota (microseconds) for a fractional CPU limit.
///
/// `quota = round(cpu * period)`, clamped to `[CFS_MIN_QUOTA_US, period]` so a
/// tiny CPU share never yields a kernel-invalid quota and a share above one
/// full CPU never exceeds the period. `cpu` is expected to be finite and
/// positive; callers filter non-positive values before calling.
pub(crate) fn cpu_quota_us(cpu: f64, period_us: u64) -> u64 {
    let quota = (cpu * period_us as f64).round() as u64;
    quota.clamp(CFS_MIN_QUOTA_US, period_us)
}

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

    // period = 100ms, quota = cpu * period clamped to the kernel minimum
    let period = CFS_PERIOD_US;
    let quota = cpu_quota_us(cpu, period);
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
        std::fs::write(self.path.join("cpu.max"), format!("max {CFS_PERIOD_US}"))
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

#[cfg(test)]
mod tests {
    use super::{cpu_quota_us, CFS_MIN_QUOTA_US, CFS_PERIOD_US};

    #[test]
    fn quota_is_clamped_to_kernel_minimum_and_period() {
        for cpu in [0.001_f64, 0.005, 0.01, 0.5, 1.0] {
            let quota = cpu_quota_us(cpu, CFS_PERIOD_US);
            assert!(
                (CFS_MIN_QUOTA_US..=CFS_PERIOD_US).contains(&quota),
                "cpu={cpu}: quota={quota} out of [{CFS_MIN_QUOTA_US}, {CFS_PERIOD_US}]"
            );
        }
    }

    #[test]
    fn sub_millisecond_share_is_floored() {
        // 0.5% of 100ms is 500us, below the kernel minimum of 1000us.
        assert_eq!(cpu_quota_us(0.005, CFS_PERIOD_US), CFS_MIN_QUOTA_US);
        assert_eq!(cpu_quota_us(0.001, CFS_PERIOD_US), CFS_MIN_QUOTA_US);
    }

    #[test]
    fn full_and_oversized_shares_are_capped_at_period() {
        assert_eq!(cpu_quota_us(1.0, CFS_PERIOD_US), CFS_PERIOD_US);
        assert_eq!(cpu_quota_us(2.0, CFS_PERIOD_US), CFS_PERIOD_US);
        assert_eq!(cpu_quota_us(f64::INFINITY, CFS_PERIOD_US), CFS_PERIOD_US);
    }

    #[test]
    fn ordinary_shares_round_to_expected_quota() {
        assert_eq!(cpu_quota_us(0.01, CFS_PERIOD_US), 1_000);
        assert_eq!(cpu_quota_us(0.25, CFS_PERIOD_US), 25_000);
        assert_eq!(cpu_quota_us(0.5, CFS_PERIOD_US), 50_000);
    }

    #[test]
    fn period_constant_is_100ms() {
        assert_eq!(CFS_PERIOD_US, 100_000);
        const { assert!(CFS_MIN_QUOTA_US < CFS_PERIOD_US) };
    }
}
