//! `cpdaemon` entry point. Port of `cpdaemon/main.go` + `cmd/server.go`.

// `cpdaemon` is a partial port of the Go daemon: some ported API surface (HTTP
// helpers, model constants, log/synclog plumbing, accessors) is present for
// parity but not yet wired up. Those specific items carry `#[allow(dead_code)]`
// with a pointer to `PARITY.md` §5; do not add new unused code without a plan to
// wire it up or remove it.

mod common;
mod config;
mod cpm;
mod error;
mod httpmix;
mod macros;
mod reslimit;
mod tool;
mod worker;
mod worker_config;
mod worker_log;

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::sync::watch;

use config::{DaemonConfig, DEFAULT_HTTP_PORT};
use cpm::client::{ClientConfig, HttpClient};
use cpm::syncer::{generate_uuid, RegConfig, Syncer, SyncerConfig};
use cpm::worker_mgr::{MemoryConfig, PipelineConfig, WorkerConfig, WorkerManager};
use reslimit::CgroupCfg;
use tool::Tool;
use worker_config::{ControlConfig, ControlUnixConfig};

#[derive(Parser, Debug)]
#[command(name = "cpdaemon", version, about = "Cloud Probe management daemon")]
struct Cli {
    /// config file path
    #[arg(short = 'c', long, default_value = "config.json", global = true)]
    config: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Server,
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("version: {}", env!("CARGO_PKG_VERSION"));
        }
        Command::Server => {
            let cfg = match DaemonConfig::load(Some(Path::new(&cli.config))) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("fatal: {e}");
                    std::process::exit(1);
                }
            };
            let level = match cfg.log.level.to_ascii_lowercase().as_str() {
                "debug" => log::LevelFilter::Debug,
                "warn" => log::LevelFilter::Warn,
                "error" => log::LevelFilter::Error,
                _ => log::LevelFilter::Info,
            };
            cpgolib::slogx::init_default(level);

            if let Err(e) = run_server(cfg) {
                log::error!("fail error={e}");
                std::process::exit(1);
            }
        }
    }
}

/// Parse `listen.http.port` into a TCP port.
///
/// An absent/empty value means the default ([`DEFAULT_HTTP_PORT`], which is also
/// viper's default); anything that is not a `u16` is a fatal configuration
/// error rather than a silent fallback (AUDIT4 P5-22).
fn parse_http_port(s: &str) -> std::result::Result<u16, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_HTTP_PORT);
    }
    trimmed.parse::<u16>().map_err(|e| {
        format!(
            "{s:?} is not a valid port number ({e}); expected 0-65535, or an empty value for {DEFAULT_HTTP_PORT}"
        )
    })
}

fn parse_u64(s: &str, default: u64) -> u64 {
    if s.is_empty() {
        default
    } else {
        s.parse().unwrap_or(default)
    }
}

#[tokio::main]
async fn run_server(cfg: DaemonConfig) -> anyhow::Result<()> {
    if cfg.cpm.base_url.is_empty() {
        anyhow::bail!("cpm.base_url is missing");
    }

    let tool = Tool {
        get_container_host_pid_script: cfg.tool.get_container_host_pid_script.clone(),
        get_kvm_instances_script: cfg.tool.get_kvm_instances_script.clone(),
        get_kvm_instance_nics_script: cfg.tool.get_kvm_instance_nics_script.clone(),
    };

    let worker_cfg = WorkerConfig {
        pid_file: cfg.cpm.worker.pid_file.clone(),
        config_file: cfg.cpm.worker.config_file.clone(),
        executable: cfg.cpm.worker.executable.clone(),
        env: HashMap::new(),
        work_dir: None,
        cgroup_cfg: CgroupCfg {
            version: cfg.cgroup.version.clone(),
            root: cfg.cgroup.root.clone(),
            hierarchy: cfg.cgroup.hierarchy.clone(),
        },
        cpu_affinity: cfg.cpm.worker.cpu_affinity.clone(),
        log_level: cfg.cpm.worker.log_level.clone(),
        control: ControlConfig {
            ty: cfg.cpm.worker.control.ty.clone(),
            unix: Some(ControlUnixConfig {
                path: cfg.cpm.worker.control.unix.path.clone(),
            }),
        },
        execution_model: cfg.cpm.worker.execution_model.clone(),
        pipeline: PipelineConfig {
            min_buffer_size_mb: parse_u64(
                &cfg.cpm.worker.memory_policy.pipeline.min_buffer_size_mb,
                128,
            ),
        },
        update_policy: cfg.cpm.worker.update_policy.clone(),
        memory: MemoryConfig {
            policy: cfg.cpm.worker.memory_policy.policy.clone(),
            default_limit_mb: parse_u64(&cfg.cpm.worker.memory_policy.default_limit_mb, 512),
            libpcap: cpm::worker_mgr::LibpcapMemConfig {
                fixed_buffer_size_mb: parse_u64(
                    &cfg.cpm.worker.memory_policy.libpcap.fixed_buffer_size_mb,
                    8,
                ),
            },
        },
    };
    worker_cfg.validate()?;

    // Registration identity.
    let reg_name = if cfg.cpm.reg.name.is_empty() {
        nix::unistd::gethostname()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into())
    } else {
        cfg.cpm.reg.name.clone()
    };
    let uuid = generate_uuid(
        &cfg.cpm.reg.uuid_file,
        &cfg.cpm.reg.uuid_gen.ty,
        &cfg.cpm.reg.uuid_gen.env.keys,
    )
    .unwrap_or_default();

    let reg = RegConfig {
        name: reg_name,
        node_name: cfg.cpm.reg.node_name.clone(),
        platform_id: cfg.cpm.reg.platform_id.clone(),
        deploy_env: cfg.cpm.reg.deploy_env.clone(),
        labels: cfg.cpm.reg.labels.clone(),
        including_nics: cfg.cpm.reg.including_nics.clone(),
        pod_name: cfg.cpm.reg.pod_name.clone(),
        namespace: cfg.cpm.reg.namespace.clone(),
        uuid_file: cfg.cpm.reg.uuid_file.clone(),
        uuid,
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let syncer_cfg = SyncerConfig {
        reg_retry_interval: DaemonConfig::parse_duration(
            &cfg.cpm.syncer.reg_retry_interval,
            Duration::from_secs(5),
        ),
        sync_strategy_interval: DaemonConfig::parse_duration(
            &cfg.cpm.syncer.sync_strategy_interval,
            Duration::from_secs(15),
        ),
        sync_metric_interval: DaemonConfig::parse_duration(
            &cfg.cpm.syncer.sync_metric_interval,
            Duration::from_secs(15),
        ),
        stop_worker_after_reg_fail_minutes: cfg
            .cpm
            .syncer
            .stop_worker_after_reg_fail_minutes
            .parse()
            .unwrap_or(30),
    };

    let client = HttpClient::new(
        &cfg.cpm.base_url,
        ClientConfig {
            timeout: DaemonConfig::parse_duration(&cfg.cpm.client.timeout, Duration::from_secs(15)),
            insecure_skip_verify: true,
        },
    )?;

    let worker_mgr = WorkerManager::new(worker_cfg, tool.clone());
    let syncer = Syncer::new(client, worker_mgr, tool, reg, syncer_cfg);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // HTTP health endpoint.
    let addr = if cfg.listen.http.address.is_empty() {
        "0.0.0.0".to_string()
    } else {
        cfg.listen.http.address.clone()
    };
    // AUDIT4 P5-22: a bad port used to fall back to 9022 *silently*, moving the
    // health endpoint somewhere nobody was looking for it. Go handed the port
    // string straight to `net.Listen`, so an unparseable port failed startup;
    // do the same here.
    let port = parse_http_port(&cfg.listen.http.port)
        .map_err(|e| anyhow::anyhow!("invalid listen.http.port: {e}"))?;
    let listener = tokio::net::TcpListener::bind((addr.as_str(), port)).await?;
    let router = axum::Router::new().route("/", axum::routing::get(|| async { "OK" }));
    let http_shutdown = {
        let mut rx = shutdown_rx.clone();
        async move {
            let _ = rx.changed().await;
        }
    };
    log::info!("Listening and serving HTTP addr={addr}:{port}");
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(http_shutdown)
            .await
    });

    // Syncer.
    let sync_handle = {
        let syncer = syncer.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { syncer.run(rx) })
    };

    // Signal handling.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { log::info!("received signal SIGINT"); }
        _ = sigterm.recv() => { log::info!("received signal SIGTERM"); }
    }
    let _ = shutdown_tx.send(true);

    let _ = sync_handle.await;
    let _ = server.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_http_port;

    #[test]
    fn http_port_is_parsed_not_silently_defaulted() {
        assert_eq!(parse_http_port("8080").unwrap(), 8080);
        assert_eq!(parse_http_port("  9022 ").unwrap(), 9022);
        assert_eq!(parse_http_port("0").unwrap(), 0);
        assert_eq!(parse_http_port("65535").unwrap(), 65535);
        // empty / absent keeps viper's default (the field default is "9022")
        assert_eq!(
            parse_http_port("").unwrap(),
            crate::config::DEFAULT_HTTP_PORT
        );
    }

    /// The regression this guards: a typo used to bind 9022 and log nothing.
    #[test]
    fn bad_http_port_is_a_fatal_error() {
        for bad in [
            "http",
            "90222",
            "-1",
            "9022.5",
            "٩٩٩",
            "999999999999999999999",
        ] {
            let e = parse_http_port(bad).unwrap_err();
            assert!(e.contains("not a valid port number"), "{bad}: {e}");
            assert!(
                e.contains("65535"),
                "{bad}: message must say what is valid: {e}"
            );
        }
    }
}
