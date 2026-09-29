//! `cripid` — print the host PID of a container served by a CRI runtime.
//!
//! Rust port of `cptools/cripid`. Uses a tonic client generated from the
//! upstream `k8s.io/cri-api` `api.proto` (vendored under `proto/`).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

// The generated gRPC types carry the upstream vendored proto comments, some of
// which trip clippy's `doc_lazy_continuation`; the generated code is not ours
// to edit.
#[allow(clippy::doc_lazy_continuation)]
pub mod runtime {
    tonic::include_proto!("runtime.v1");
}

use runtime::runtime_service_client::RuntimeServiceClient;
use runtime::ContainerStatusRequest;

const ENV_RUNTIME_ENDPOINT: &str = "CONTAINER_RUNTIME_ENDPOINT";

const DEFAULT_RUNTIME_ENDPOINTS: &[&str] = &[
    "unix:///run/containerd/containerd.sock",
    "unix:///run/crio/crio.sock",
    "unix:///var/run/cri-dockerd.sock",
];

/// Extract the host PID from a CRI `ContainerStatus` verbose Info map. Values
/// are runtime-specific JSON blobs; both containerd and CRI-O expose the host
/// PID as a top-level `"pid"` field. Every value is scanned rather than
/// hardcoding the `"info"` key so the same code works across runtimes.
fn parse_pid_from_info(info: &HashMap<String, String>) -> Result<i32> {
    for v in info.values() {
        if let Ok(ci) = serde_json::from_str::<serde_json::Value>(v) {
            // `i32::try_from`, never `as i32` (AUDIT4 P5-15/P2-3 ②): `pid` arrives
            // as a JSON `i64`, and `4294967296 as i32 == 0`, `2147483653 as i32 ==
            // -2147483643` - a truncated cast hands the caller a *plausible*
            // nonsense PID (0 or negative), which is worse than no answer. A value
            // that cannot be an `i32` PID is simply not a PID we found.
            let pid = ci
                .get("pid")
                .and_then(|p| p.as_i64())
                .and_then(|p| i32::try_from(p).ok());
            let Some(pid) = pid.filter(|p| *p > 0) else {
                continue;
            };
            return Ok(pid);
        }
    }
    bail!("no pid found in container info")
}

/// CRI endpoints to try, in priority order.
fn endpoints() -> Vec<String> {
    if let Ok(ep) = std::env::var(ENV_RUNTIME_ENDPOINT) {
        let ep = ep.trim();
        if !ep.is_empty() {
            return vec![ep.to_string()];
        }
    }
    DEFAULT_RUNTIME_ENDPOINTS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Whether a unix endpoint's socket file exists. Non-unix endpoints return true
/// so the dial attempt decides.
fn socket_exists(endpoint: &str) -> Result<bool> {
    let Some(path) = endpoint.strip_prefix("unix://") else {
        return Ok(true);
    };
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow!("stat {path}: {e}")),
    }
}

async fn get_container_pid(endpoint: &str, container_id: &str) -> Result<i32> {
    let path = endpoint
        .strip_prefix("unix://")
        .ok_or_else(|| anyhow!("unsupported endpoint (only unix:// supported): {endpoint}"))?
        .to_string();

    let channel = tonic::transport::Endpoint::try_from("http://localhost")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("dial {endpoint}"))?;

    let mut client = RuntimeServiceClient::new(channel);
    let resp = client
        .container_status(ContainerStatusRequest {
            container_id: container_id.to_string(),
            verbose: true,
        })
        .await
        .with_context(|| format!("ContainerStatus via {endpoint}"))?;

    parse_pid_from_info(&resp.into_inner().info)
}

/// Try each candidate endpoint in order; return the first successful lookup.
async fn resolve(container_id: &str) -> Result<i32> {
    let mut last_err: Option<anyhow::Error> = None;
    for ep in endpoints() {
        match socket_exists(&ep) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
        match tokio::time::timeout(
            Duration::from_secs(10),
            get_container_pid(&ep, container_id),
        )
        .await
        {
            Ok(Ok(pid)) => return Ok(pid),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some(anyhow!("timed out polling {ep}")),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Err(anyhow!("no CRI runtime endpoint available")),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        let prog = args.first().map(String::as_str).unwrap_or("cripid");
        eprintln!("Usage: {prog} <containerId>");
        eprintln!("Example: {prog} abc123def456");
        std::process::exit(1);
    }
    match resolve(&args[1]).await {
        Ok(pid) => println!("{pid}"),
        Err(e) => {
            eprintln!("Failed to get container info: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with(pid: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "info".to_string(),
            format!(r#"{{"pid":{pid},"runtimeSpec":{{}}}}"#),
        );
        m
    }

    #[test]
    fn pid_is_taken_from_the_json_number_when_it_fits() {
        assert_eq!(parse_pid_from_info(&info_with("4242")).unwrap(), 4242);
    }

    /// Regression for the `pid as i32` narrowing: a JSON number that does not fit
    /// an `i32` used to come back as a *different, plausible-looking* PID
    /// (`4294967296 as i32 == 0`, `2147483653 as i32 == -2147483643`), and the
    /// caller would then signal/read `/proc/<pid>` for a process that is not the
    /// container's.
    #[test]
    fn out_of_range_pid_is_an_error_not_a_truncated_pid() {
        for pid in ["4294967296", "2147483653", "9223372036854775807"] {
            let got = parse_pid_from_info(&info_with(pid));
            assert!(
                got.is_err(),
                "pid {pid} must not be reported as {:?} (truncating cast)",
                got.ok()
            );
        }
        // A zero / negative "pid" is not a pid either (as it was before).
        assert!(parse_pid_from_info(&info_with("0")).is_err());
        assert!(parse_pid_from_info(&info_with("-1")).is_err());
    }

    /// The function scans every info value, so a value without a usable pid
    /// (here `pid: 0`) must not stop it from finding one in another value.
    #[test]
    fn pid_is_found_when_another_info_value_has_no_usable_pid() {
        let mut m = HashMap::new();
        m.insert("runtimeSpec".to_string(), r#"{"pid":0}"#.to_string());
        m.insert("info".to_string(), r#"{"pid":4242}"#.to_string());
        assert_eq!(parse_pid_from_info(&m).unwrap(), 4242);
    }

    #[test]
    fn non_json_values_and_non_numeric_pids_are_skipped() {
        let mut m = HashMap::new();
        m.insert("a".to_string(), "not json".to_string());
        // `pid` as a JSON string is not the host pid.
        m.insert("b".to_string(), r#"{"pid":"4242"}"#.to_string());
        assert!(parse_pid_from_info(&m).is_err());
    }

    #[test]
    fn socket_exists_only_inspects_unix_paths() {
        let missing =
            std::env::temp_dir().join(format!("cripid-missing-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        assert!(!socket_exists(&format!("unix://{}", missing.display())).unwrap());

        let present =
            std::env::temp_dir().join(format!("cripid-present-{}.sock", std::process::id()));
        std::fs::write(&present, b"").unwrap();
        assert!(socket_exists(&format!("unix://{}", present.display())).unwrap());
        let _ = std::fs::remove_file(&present);

        // Non-unix endpoints are left to the dial attempt.
        assert!(socket_exists("tcp://127.0.0.1:1").unwrap());
    }
}
