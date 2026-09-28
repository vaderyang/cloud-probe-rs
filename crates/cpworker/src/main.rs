//! `cpworker` entry point. Port of `main.c`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use parking_lot::Mutex;

use cpworker::config::{Config, ControlConfig};
use cpworker::task::TaskManager;
use cpworker::unix_manager::UnixManager;

#[derive(Parser, Debug)]
#[command(
    name = "cpworker",
    version,
    about = "Netis Cloud Probe packet capture engine"
)]
struct Args {
    /// Config file path
    #[arg(short = 'c', long = "config")]
    config: PathBuf,
}

fn main() {
    let args = Args::parse();

    let working_dir = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let config_path = args.config.display().to_string();

    let config = match Config::parse_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };

    cpworker::log::set_level(config.log_level);

    if !config.cpu_affinity.is_empty() {
        if let Err(e) = cpworker::affinity::set_cpu_affinity(&config.cpu_affinity) {
            cpworker::log_fatal!("{e}");
            std::process::exit(1);
        }
        cpworker::log_info!("set cpu affinity to '{}'", config.cpu_affinity);
    }

    let total_num_tasks = config.tasks.len();
    let control = config.control.clone();

    let mgr = match TaskManager::new(config, config_path, working_dir) {
        Ok(m) => Arc::new(Mutex::new(m)),
        Err(e) => {
            cpworker::log_fatal!("init tasks failed: {e}");
            std::process::exit(1);
        }
    };

    {
        let g = mgr.lock();
        cpworker::log_info!(
            "init {} tasks, total {} tasks",
            g.inited_count(),
            total_num_tasks
        );
    }

    let mut unix_manager = None;
    if let Some(ControlConfig::UnixSocket { path }) = &control {
        match UnixManager::start(path, mgr.clone()) {
            Ok(u) => {
                cpworker::log_info!("listen on unix socket {path}");
                unix_manager = Some(u);
            }
            Err(e) => {
                cpworker::log_fatal!("init unix socket failed: {e}");
                std::process::exit(1);
            }
        }
    }

    mgr.lock().start();

    // Signal handling.
    let quit = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, quit.clone());
    }
    let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, reload.clone());

    cpworker::log_info!("start poll packets");
    let stats_enabled = control.is_some();
    let mut last_reload_check = std::time::Instant::now();
    // Process packets in batches so the TaskManager / output-set locks and the
    // periodic clock check are amortised across many packets instead of once
    // per packet (matching the C loop's per-packet cost).
    const BATCH: usize = 256;

    while !quit.load(Ordering::Relaxed) {
        let num_pkts = mgr.lock().poll_packets_batch(BATCH);
        if num_pkts == 0 {
            std::thread::sleep(std::time::Duration::from_micros(10));
        }

        // Handle SIGHUP-driven reload at most once per second.
        if reload.swap(false, Ordering::Relaxed) {
            // Not `mgr.lock().reload_from_file()`: parsing and especially host-name
            // resolution must happen outside the lock this loop holds every batch
            // (AUDIT4 P2-10).
            if let Err(e) = cpworker::task::reload_from_file(&mgr) {
                cpworker::log_error!("reload failed: {e}");
            }
        }

        // Periodically print task errors (every 60s).
        if last_reload_check.elapsed().as_secs() >= 60 {
            mgr.lock().print_errors();
            last_reload_check = std::time::Instant::now();
        }

        let _ = stats_enabled;
    }

    cpworker::log_info!("quit");
    drop(unix_manager.take());
    mgr.lock().stop();
}
