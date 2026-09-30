//! External tool helpers. Port of `cpdaemon/pkg/tool/*.go`.

use std::process::Command;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Tool {
    pub get_container_host_pid_script: String,
    pub get_kvm_instances_script: String,
    pub get_kvm_instance_nics_script: String,
}

impl Tool {
    pub fn get_container_host_pid(&self, container_id: &str) -> Result<i32> {
        if let Ok(pid) = get_container_host_pid_by_docker(container_id) {
            return Ok(pid);
        }
        if let Ok(pid) = get_container_host_pid_by_cripid(container_id) {
            return Ok(pid);
        }
        if !self.get_container_host_pid_script.is_empty() {
            let out = run_shell_script(&self.get_container_host_pid_script, &[container_id])?;
            return parse_pid(&out);
        }
        Err(Error::new(format!(
            "failed to get host pid for container {container_id}"
        )))
    }

    pub fn get_kvm_instances(&self) -> Result<Vec<String>> {
        if !self.get_kvm_instances_script.is_empty() {
            let out = run_shell_script(&self.get_kvm_instances_script, &[])?;
            return Ok(parse_kvm_instances(&out));
        }
        get_kvm_instances_by_virsh()
    }

    pub fn get_kvm_instance_nics(&self, instance_name: &str) -> Result<Vec<String>> {
        if !self.get_kvm_instance_nics_script.is_empty() {
            let out = run_shell_script(&self.get_kvm_instance_nics_script, &[instance_name])?;
            return Ok(parse_kvm_instance_nics(&out));
        }
        get_kvm_instance_nics_by_virsh(instance_name)
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| Error::new(format!("{program} failed: {e}")))?;
    if !out.status.success() {
        return Err(Error::new(format!(
            "{program} failed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_shell_script(script: &str, args: &[&str]) -> Result<String> {
    run_cmd(script, args)
}

fn get_container_host_pid_by_docker(container_id: &str) -> Result<i32> {
    let out = run_cmd("dockerpid", &[container_id])?;
    parse_pid(&out)
}

fn get_container_host_pid_by_cripid(container_id: &str) -> Result<i32> {
    let out = run_cmd("cripid", &[container_id])?;
    parse_pid(&out)
}

pub fn parse_pid(output: &str) -> Result<i32> {
    let t = output.trim();
    match t.parse::<i32>() {
        Ok(pid) if pid > 0 => Ok(pid),
        _ => Err(Error::new(format!("invalid PID: {t}"))),
    }
}

fn get_kvm_instances_by_virsh() -> Result<Vec<String>> {
    let out = run_cmd("sh", &["-c", "virsh list | awk 'NR>2 {print $2}'"])?;
    Ok(parse_kvm_instances(&out))
}

fn get_kvm_instance_nics_by_virsh(instance_name: &str) -> Result<Vec<String>> {
    let cmd = format!("virsh domiflist {instance_name} | awk 'NR==3 {{print $1}}'");
    let out = run_cmd("sh", &["-c", &cmd])?;
    Ok(parse_kvm_instance_nics(&out))
}

pub fn parse_kvm_instances(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

pub fn parse_kvm_instance_nics(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "-")
        .map(|l| l.to_string())
        .collect()
}
#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::MutexGuard;

    use super::*;

    /// Every test here either writes an executable script or mutates the
    /// process-global `PATH`. Those operations must not overlap across threads:
    /// on Linux a `fork` racing a script `write` leaves the child holding the
    /// write fd so executing that script fails with ETXTBSY, and a fake helper on
    /// `PATH` must not be visible to other modules' tests. The shared crate-level
    /// lock serializes both effects; `PATH` is process-global anyway.
    fn lock() -> MutexGuard<'static, ()> {
        crate::test_support::path_lock()
    }

    struct FakePath {
        _dir: tempfile::TempDir,
        old: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for FakePath {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    fn write_executable(path: &Path, body: &str) {
        fs::write(path, body).expect("write script");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod");
    }

    /// Install `bins` (name -> shell body) in a temp dir and prepend it to PATH.
    fn fake_path(bins: &[(&str, &str)]) -> FakePath {
        let guard = lock();
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, body) in bins {
            write_executable(&dir.path().join(name), body);
        }
        let old = std::env::var_os("PATH");
        let mut new = dir.path().as_os_str().to_owned();
        if let Some(p) = &old {
            new.push(":");
            new.push(p);
        }
        std::env::set_var("PATH", &new);
        FakePath {
            _dir: dir,
            old,
            _lock: guard,
        }
    }

    fn script_tool(script: &str) -> (tempfile::TempDir, Tool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("helper.sh");
        write_executable(&path, script);
        let tool = Tool {
            get_container_host_pid_script: path.to_string_lossy().into_owned(),
            get_kvm_instances_script: path.to_string_lossy().into_owned(),
            get_kvm_instance_nics_script: path.to_string_lossy().into_owned(),
        };
        (dir, tool)
    }

    #[test]
    fn parse_pid_accepts_positive_pids_and_trims_whitespace() {
        assert_eq!(parse_pid(" 1234\n").expect("pid"), 1234);
        assert_eq!(parse_pid("1").expect("pid"), 1);
    }

    #[test]
    fn parse_pid_rejects_zero_negative_overflow_and_garbage() {
        assert!(parse_pid("0").is_err());
        assert!(parse_pid("-7").is_err());
        assert!(parse_pid("").is_err());
        assert!(parse_pid("not-a-pid").is_err());
        assert!(parse_pid("99999999999999999999").is_err());
        let err = parse_pid("abc").unwrap_err();
        assert!(err.to_string().contains("invalid PID"), "{err}");
    }

    #[test]
    fn parse_kvm_instances_trims_and_drops_blank_lines() {
        assert_eq!(parse_kvm_instances("vm1\n\n  vm2  \n"), vec!["vm1", "vm2"]);
        assert!(parse_kvm_instances("").is_empty());
    }

    #[test]
    fn parse_kvm_instance_nics_drops_dashes_and_blank_lines() {
        assert_eq!(
            parse_kvm_instance_nics("eth0\n-\n  eth1 \n\n"),
            vec!["eth0", "eth1"]
        );
        assert!(parse_kvm_instance_nics("-\n").is_empty());
    }

    #[test]
    fn run_cmd_returns_stdout_and_reports_both_failure_modes() {
        let _guard = lock();
        assert_eq!(run_cmd("echo", &["hello"]).expect("echo").trim(), "hello");

        let err = run_cmd("sh", &["-c", "echo oops >&2; exit 3"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed"), "{msg}");
        assert!(msg.contains("oops"), "{msg}");

        let missing = run_cmd("cprs-definitely-not-a-program", &[]).unwrap_err();
        assert!(missing.to_string().contains("failed"), "{missing}");
    }

    #[test]
    fn get_container_host_pid_prefers_the_docker_helper() {
        let _path = fake_path(&[("dockerpid", "#!/bin/sh\necho 4321\n")]);
        assert_eq!(
            Tool::default().get_container_host_pid("abc").expect("pid"),
            4321
        );
    }

    #[test]
    fn get_container_host_pid_falls_back_to_cripid_then_the_script_then_errors() {
        // dockerpid fails, cripid succeeds.
        let path = fake_path(&[
            ("dockerpid", "#!/bin/sh\nexit 1\n"),
            ("cripid", "#!/bin/sh\necho 777\n"),
        ]);
        assert_eq!(
            Tool::default().get_container_host_pid("c1").expect("pid"),
            777
        );
        drop(path);

        // Both helpers fail, so the configured script decides.
        let path = fake_path(&[
            ("dockerpid", "#!/bin/sh\nexit 1\n"),
            ("cripid", "#!/bin/sh\nexit 1\n"),
        ]);
        let (_dir, tool) = script_tool("#!/bin/sh\necho 9001\n");
        assert_eq!(tool.get_container_host_pid("c2").expect("pid"), 9001);
        drop(path);

        // Nothing works: the error names the container.
        let path = fake_path(&[
            ("dockerpid", "#!/bin/sh\nexit 1\n"),
            ("cripid", "#!/bin/sh\nexit 1\n"),
        ]);
        let err = Tool::default().get_container_host_pid("c3").unwrap_err();
        assert!(err.to_string().contains("c3"), "{err}");
        assert!(err.to_string().contains("failed to get host pid"), "{err}");
        drop(path);
    }

    #[test]
    fn get_kvm_instances_uses_the_configured_script_when_present() {
        let _guard = lock();
        let (_dir, tool) = script_tool("#!/bin/sh\nprintf 'vm-a\\n\\n vm-b \\n'\n");
        assert_eq!(
            tool.get_kvm_instances().expect("instances"),
            vec!["vm-a", "vm-b"]
        );
    }

    #[test]
    fn get_kvm_instances_falls_back_to_virsh() {
        let _path = fake_path(&[(
            "virsh",
            "#!/bin/sh\ncase \"$1\" in list) printf ' Id   Name\\n------------\\n 1    vm1\\n 2    vm2\\n';; esac\n",
        )]);
        assert_eq!(
            Tool::default().get_kvm_instances().expect("instances"),
            vec!["vm1", "vm2"]
        );
    }

    #[test]
    fn get_kvm_instance_nics_uses_the_configured_script_when_present() {
        let _guard = lock();
        let (_dir, tool) = script_tool("#!/bin/sh\nprintf 'eth0\\n-\\n eth1 \\n'\n");
        assert_eq!(
            tool.get_kvm_instance_nics("vm1").expect("nics"),
            vec!["eth0", "eth1"]
        );
    }

    #[test]
    fn get_kvm_instance_nics_falls_back_to_virsh() {
        let _path = fake_path(&[(
            "virsh",
            "#!/bin/sh\ncase \"$1\" in domiflist) printf 'Source Model\\n----\\nbr0 virtio\\n';; esac\n",
        )]);
        assert_eq!(
            Tool::default().get_kvm_instance_nics("vm1").expect("nics"),
            vec!["br0"]
        );
    }
}
