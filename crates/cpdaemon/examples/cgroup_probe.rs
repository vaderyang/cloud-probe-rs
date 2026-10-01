//! Field probe for the real cgroup mounts (not a temp-root harness).
//!
//! Unit tests exercise the file layout on a temporary root, but only a real
//! cgroup mount exercises the kernel: controller availability, the `tasks`
//! membership write, CFS quota enforcement and leaf removal. Run as root on a
//! host whose cgroup layout you want to validate:
//!
//! ```text
//! sudo ./cgroup_probe <auto|v1|v2> [root] [cpu]
//! ```
//!
//! Exits non-zero if any step fails, so it can gate a field run.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use cpdaemon::reslimit::{create_process_limit, CgroupCfg};

fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

fn resolved_dir(cfg: &CgroupCfg) -> PathBuf {
    let root = cfg.effective_root();
    let v1 = match cfg.version.as_str() {
        "v1" => true,
        "v2" => false,
        _ => !Path::new(root).join("cgroup.controllers").exists(),
    };
    if v1 {
        Path::new(root).join("cpu").join(cfg.effective_hierarchy())
    } else {
        Path::new(root).join(cfg.effective_hierarchy())
    }
}

fn cpu_seconds(pid: i32) -> f64 {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };
    // Fields 14/15 (1-based) are utime/stime, after the comm field which may
    // contain spaces; slice from the last ')' to stay robust.
    let rest = stat.rsplit_once(')').map(|(_, r)| r).unwrap_or(&stat);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let stime: u64 = f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    let hz = 100.0_f64; // USER_HZ
    (utime + stime) as f64 / hz
}

fn main() {
    let version = std::env::args().nth(1).unwrap_or_else(|| "auto".into());
    let root = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/sys/fs/cgroup".into());
    let cpu: f64 = std::env::args()
        .nth(3)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.5);

    if effective_uid() != 0 {
        eprintln!("cgroup_probe: must run as root (CAP_SYS_ADMIN)");
        std::process::exit(2);
    }

    let cfg = CgroupCfg {
        version: version.clone(),
        root: root.clone(),
        hierarchy: "cprs-cgprobe".into(),
    };
    cfg.validate().expect("cgroup config validates");

    // A single busy CPU burner we will constrain.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("while :; do :; done")
        .spawn()
        .expect("spawn burner");
    let pid = i32::try_from(child.id()).expect("pid fits i32");

    let start = Instant::now();
    let before = cpu_seconds(pid);
    let limit = create_process_limit(pid, &cfg, Some(cpu))
        .expect("create real process limit")
        .expect("limit present");
    let dir = resolved_dir(&cfg);
    println!("cgroup: {}", dir.display());
    for f in [
        "cpu.cfs_period_us",
        "cpu.cfs_quota_us",
        "tasks",
        "cpu.max",
        "cgroup.procs",
    ] {
        let p = dir.join(f);
        if p.exists() {
            let v = std::fs::read_to_string(&p).unwrap_or_default();
            println!("  {f} = {}", v.trim());
        }
    }

    std::thread::sleep(Duration::from_secs(3));
    let elapsed = start.elapsed().as_secs_f64();
    let used = cpu_seconds(pid) - before;
    let ratio = used / elapsed;
    println!("burner cpu={used:.3}s wall={elapsed:.3}s ratio={ratio:.2} (target {cpu})");

    let _ = child.kill();
    let _ = child.wait();
    limit.reset().expect("reset quota");
    limit.cleanup().expect("cleanup leaf");

    // Enforcement check only when we constrained below one full CPU: the ratio
    // should sit near the requested share, never near 1.0. On a v1 host a
    // sub-millisecond share is floored to 1ms, so allow generous slack.
    if cpu < 0.95 && ratio > cpu + 0.35 {
        eprintln!("FAIL: ratio {ratio:.2} exceeds requested {cpu} by >0.35");
        std::process::exit(1);
    }
    println!("OK: version={version} root={root} cpu={cpu}");
}
