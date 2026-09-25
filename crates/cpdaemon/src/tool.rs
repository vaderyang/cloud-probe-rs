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
