//! Process resource limiting via cgroup v1 and v2. Simplified port of
//! `cpdaemon/pkg/cgroup` + `pkg/worker/reslimit*.go`.
//!
//! Only the CPU quota path is implemented. The cgroup version is taken from
//! [`CgroupCfg::version`] (`auto`/`v1`/`v2`); `auto` probes the host and picks
//! v2 when the unified `cgroup.controllers` file is present, otherwise v1.
//! Process membership is written to `tasks` on v1 and `cgroup.procs` on v2.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// CFS scheduling period written to `cpu.max` (v2) / `cpu.cfs_period_us` (v1),
/// 100ms, matching upstream.
pub(crate) const CFS_PERIOD_US: u64 = 100_000;

/// Minimum CFS CPU quota accepted by the kernel (microseconds). The kernel
/// rejects quotas below this value with `EINVAL`; upstream #284 adds this floor.
pub(crate) const CFS_MIN_QUOTA_US: u64 = 1_000;

/// Compute the CPU quota (microseconds) for a fractional CPU limit.
///
/// `quota = round(cpu * period)`, clamped to `[CFS_MIN_QUOTA_US, period]` so a
/// tiny CPU share never yields a kernel-invalid quota and a share above one
/// full CPU never exceeds the period. `cpu` is expected to be finite and
/// positive; callers filter non-positive values before calling.
pub(crate) fn cpu_quota_us(cpu: f64, period_us: u64) -> u64 {
    let quota = (cpu * period_us as f64).round() as u64;
    quota.clamp(CFS_MIN_QUOTA_US, period_us)
}

/// Resolved cgroup hierarchy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupVersion {
    V1,
    V2,
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
    version: CgroupVersion,
    active: bool,
}

/// Is `root` a cgroup v2 (unified) mount? The `cgroup.controllers` file only
/// exists on the v2 unified hierarchy.
fn is_cgroup_v2(root: &str) -> bool {
    Path::new(root).join("cgroup.controllers").exists()
}

/// Detect the host's cgroup version under `root`: v2 when the unified
/// `cgroup.controllers` file is present, otherwise v1 (legacy/hybrid hosts
/// expose the cpu controller under `cpu/`). A bare/unclassifiable root also
/// resolves to v1, matching Go `resolveVersion`'s fallback.
pub(crate) fn detect_version(root: &str) -> CgroupVersion {
    if is_cgroup_v2(root) {
        CgroupVersion::V2
    } else {
        CgroupVersion::V1
    }
}

/// Resolve the configured version: explicit `v1`/`v2` are pinned without
/// probing the host; `auto` (and any unset/empty value) probes it.
pub(crate) fn resolve_version(cfg: &CgroupCfg) -> CgroupVersion {
    match cfg.version.as_str() {
        "v1" => CgroupVersion::V1,
        "v2" => CgroupVersion::V2,
        _ => detect_version(cfg.effective_root()),
    }
}

/// Directory holding the process's cgroup for `version`:
/// `<root>/cpu/<hierarchy>` on v1, `<root>/<hierarchy>` on v2.
pub(crate) fn cgroup_dir(root: &str, version: CgroupVersion, hierarchy: &str) -> PathBuf {
    match version {
        CgroupVersion::V1 => Path::new(root).join("cpu").join(hierarchy),
        CgroupVersion::V2 => Path::new(root).join(hierarchy),
    }
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

    let version = resolve_version(cfg);
    let dir = cgroup_dir(cfg.effective_root(), version, cfg.effective_hierarchy());
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::new(format!("create cgroup {}: {e}", dir.display())))?;

    // period = 100ms, quota = cpu * period clamped to the kernel minimum
    let period = CFS_PERIOD_US;
    let quota = cpu_quota_us(cpu, period);

    match version {
        CgroupVersion::V2 => {
            std::fs::write(dir.join("cpu.max"), format!("{quota} {period}"))
                .map_err(|e| Error::new(format!("write cpu.max: {e}")))?;
            // enable cpu controller in the parent if needed
            let _ = std::fs::write(dir.join("cgroup.subtree_control"), "+cpu");
        }
        CgroupVersion::V1 => {
            std::fs::write(dir.join("cpu.cfs_period_us"), period.to_string())
                .map_err(|e| Error::new(format!("write cpu.cfs_period_us: {e}")))?;
            std::fs::write(dir.join("cpu.cfs_quota_us"), quota.to_string())
                .map_err(|e| Error::new(format!("write cpu.cfs_quota_us: {e}")))?;
        }
    }

    add_process(&dir, version, pid)?;
    crate::log_info!(
        "cpu limit applied: pid={pid}, cpu={cpu}, version={version:?}, cgroup={}",
        dir.display()
    );
    Ok(Some(ProcessLimit {
        path: dir,
        version,
        active: true,
    }))
}

fn add_process(dir: &Path, version: CgroupVersion, pid: i32) -> Result<()> {
    // v1 tracks threads in `tasks`; v2 tracks processes in `cgroup.procs`.
    let file = match version {
        CgroupVersion::V1 => "tasks",
        CgroupVersion::V2 => "cgroup.procs",
    };
    std::fs::write(dir.join(file), pid.to_string()).map_err(|e| {
        Error::new(format!(
            "add pid {pid} to cgroup {} ({file}): {e}",
            dir.display()
        ))
    })
}

impl ProcessLimit {
    /// Remove the cpu limit without deleting the cgroup (worker still attached).
    pub fn reset(&self) -> Result<()> {
        match self.version {
            CgroupVersion::V2 => {
                std::fs::write(self.path.join("cpu.max"), format!("max {CFS_PERIOD_US}"))
                    .map_err(|e| Error::new(format!("reset cpu.max: {e}")))
            }
            CgroupVersion::V1 => std::fs::write(self.path.join("cpu.cfs_quota_us"), "-1")
                .map_err(|e| Error::new(format!("reset cpu.cfs_quota_us: {e}"))),
        }
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
    use super::{
        cgroup_dir, cpu_quota_us, create_process_limit, detect_version, resolve_version, CgroupCfg,
        CgroupVersion, CFS_MIN_QUOTA_US, CFS_PERIOD_US,
    };

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

    // -- version selection ----------------------------------------------------

    #[test]
    fn detect_v2_from_unified_controllers_file() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("cgroup.controllers"), "cpu io\n").expect("write");
        assert_eq!(
            detect_version(root.path().to_str().unwrap()),
            CgroupVersion::V2
        );
    }

    #[test]
    fn detect_v1_without_unified_controllers_file() {
        // A bare root (no `cgroup.controllers`) is v1: legacy/hybrid hosts keep
        // the cpu controller under `cpu/`, and unclassifiable roots fall back
        // to v1 like Go `resolveVersion`.
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("cpu")).expect("create cpu dir");
        assert_eq!(
            detect_version(root.path().to_str().unwrap()),
            CgroupVersion::V1
        );

        let bare = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            detect_version(bare.path().to_str().unwrap()),
            CgroupVersion::V1
        );
    }

    #[test]
    fn explicit_version_pins_without_probing_host() {
        // A bogus root would classify as v1, so explicit v2 proves no probe ran.
        let cfg = CgroupCfg {
            version: "v2".into(),
            root: "/nonexistent-cgroup-root".into(),
            ..CgroupCfg::default()
        };
        assert_eq!(resolve_version(&cfg), CgroupVersion::V2);

        let cfg = CgroupCfg {
            version: "v1".into(),
            root: "/nonexistent-cgroup-root".into(),
            ..CgroupCfg::default()
        };
        assert_eq!(resolve_version(&cfg), CgroupVersion::V1);
    }

    #[test]
    fn auto_version_probes_the_root() {
        let v2_root = tempfile::tempdir().expect("tempdir");
        std::fs::write(v2_root.path().join("cgroup.controllers"), "cpu\n").expect("write");
        let cfg = CgroupCfg {
            version: "auto".into(),
            root: v2_root.path().to_str().unwrap().into(),
            ..CgroupCfg::default()
        };
        assert_eq!(resolve_version(&cfg), CgroupVersion::V2);

        let v1_root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(v1_root.path().join("cpu")).expect("create cpu dir");
        let cfg = CgroupCfg {
            version: "auto".into(),
            root: v1_root.path().to_str().unwrap().into(),
            ..CgroupCfg::default()
        };
        assert_eq!(resolve_version(&cfg), CgroupVersion::V1);

        // Empty/unset version behaves like auto (CreateProcessLimit may be
        // reached before Validate in unit tests / default configs).
        let cfg = CgroupCfg {
            version: String::new(),
            root: v1_root.path().to_str().unwrap().into(),
            ..CgroupCfg::default()
        };
        assert_eq!(resolve_version(&cfg), CgroupVersion::V1);
    }

    // -- path construction ----------------------------------------------------

    #[test]
    fn v1_path_adds_cpu_controller_mount() {
        assert_eq!(
            cgroup_dir("/sys/fs/cgroup", CgroupVersion::V1, "cloud-probe"),
            std::path::PathBuf::from("/sys/fs/cgroup/cpu/cloud-probe")
        );
    }

    #[test]
    fn v2_path_is_directly_under_root() {
        assert_eq!(
            cgroup_dir("/sys/fs/cgroup", CgroupVersion::V2, "cloud-probe"),
            std::path::PathBuf::from("/sys/fs/cgroup/cloud-probe")
        );
    }

    // -- end-to-end write path against a temp root ----------------------------

    /// Exercise the real create/quota/membership writes using a temp directory
    /// as the cgroup root. This does not apply a limit to a live process (that
    /// requires a real cgroup mount + CAP_SYS_ADMIN), but it verifies the exact
    /// file layout, names, and values for both versions.
    #[test]
    fn create_process_limit_v1_writes_period_quota_and_tasks() {
        let root = tempfile::tempdir().expect("tempdir");
        let cfg = CgroupCfg {
            version: "v1".into(),
            root: root.path().to_str().unwrap().into(),
            hierarchy: "cloud-probe-test".into(),
        };
        let pid = std::process::id() as i32;
        let limit = create_process_limit(pid, &cfg, Some(0.25))
            .expect("create v1 limit")
            .expect("limit present");
        let dir = root.path().join("cpu/cloud-probe-test");
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.cfs_period_us")).unwrap(),
            "100000"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.cfs_quota_us")).unwrap(),
            "25000"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("tasks")).unwrap(),
            pid.to_string()
        );
        assert!(!dir.join("cgroup.procs").exists());
        assert!(!dir.join("cpu.max").exists());

        limit.reset().expect("reset v1 quota");
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.cfs_quota_us")).unwrap(),
            "-1"
        );
        // `cleanup` is not asserted here: on a real cgroup mount the kernel
        // files vanish with the directory, but this temp-root harness wrote
        // real files, so rmdir would fail with ENOTEMPTY. Its rmdir path is
        // covered by `cleanup_removes_empty_cgroup_dir`.
    }

    #[test]
    fn create_process_limit_v1_floors_sub_millisecond_quota() {
        let root = tempfile::tempdir().expect("tempdir");
        let cfg = CgroupCfg {
            version: "v1".into(),
            root: root.path().to_str().unwrap().into(),
            hierarchy: "cloud-probe-test".into(),
        };
        let _limit = create_process_limit(7, &cfg, Some(0.001))
            .expect("create v1 limit")
            .expect("limit present");
        let dir = root.path().join("cpu/cloud-probe-test");
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.cfs_quota_us")).unwrap(),
            CFS_MIN_QUOTA_US.to_string()
        );
    }

    #[test]
    fn create_process_limit_v2_writes_cpu_max_and_procs() {
        let root = tempfile::tempdir().expect("tempdir");
        let cfg = CgroupCfg {
            version: "v2".into(),
            root: root.path().to_str().unwrap().into(),
            hierarchy: "cloud-probe-test".into(),
        };
        let _limit = create_process_limit(7, &cfg, Some(0.5))
            .expect("create v2 limit")
            .expect("limit present");
        let dir = root.path().join("cloud-probe-test");
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu.max")).unwrap(),
            "50000 100000"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
            "7"
        );
        assert!(!dir.join("tasks").exists());
    }

    /// `cleanup` removes an empty leaf cgroup directory, as it would on a real
    /// mount once the kernel's virtual files are gone. Membership writes are
    /// covered above; this isolates the rmdir path (which cannot be exercised
    /// on the temp-root harness because real files would remain).
    #[test]
    fn cleanup_removes_empty_cgroup_dir() {
        let root = tempfile::tempdir().expect("tempdir");
        let cfg = CgroupCfg {
            version: "v1".into(),
            root: root.path().to_str().expect("utf8 path").into(),
            hierarchy: "cloud-probe-test".into(),
        };
        // A limit with no cpu request creates no cgroup at all.
        assert!(create_process_limit(7, &cfg, None).expect("noop").is_none());

        // Simulate the kernel-owned (empty) leaf the daemon would remove.
        let dir = cgroup_dir(
            root.path().to_str().expect("utf8 path"),
            CgroupVersion::V1,
            "cloud-probe-test",
        );
        std::fs::create_dir_all(&dir).expect("create leaf");
        let limit = super::ProcessLimit {
            path: dir.clone(),
            version: CgroupVersion::V1,
            active: true,
        };
        limit.cleanup().expect("cleanup removes empty leaf");
        assert!(!dir.exists());
    }

    #[test]
    fn auto_version_writes_v1_layout_when_only_cpu_mount_present() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("cpu")).expect("create cpu dir");
        let cfg = CgroupCfg {
            version: "auto".into(),
            root: root.path().to_str().unwrap().into(),
            hierarchy: "cloud-probe-test".into(),
        };
        let _limit = create_process_limit(7, &cfg, Some(0.5))
            .expect("create auto limit")
            .expect("limit present");
        assert!(root
            .path()
            .join("cpu/cloud-probe-test/cpu.cfs_quota_us")
            .exists());
    }

    #[test]
    fn no_positive_limit_is_a_noop() {
        let root = tempfile::tempdir().expect("tempdir");
        let cfg = CgroupCfg {
            version: "v1".into(),
            root: root.path().to_str().unwrap().into(),
            hierarchy: "cloud-probe-test".into(),
        };
        assert!(create_process_limit(7, &cfg, None).unwrap().is_none());
        assert!(create_process_limit(7, &cfg, Some(0.0)).unwrap().is_none());
        assert!(create_process_limit(7, &cfg, Some(-1.0)).unwrap().is_none());
    }
}
