// Rust side of the Unix JSON-RPC protocol parity harness.
// Usage: rpc_parity <socket-path> <config-path> <working-dir>
use std::sync::Arc;

use parking_lot::Mutex;

use cpworker::config::Config;
use cpworker::task::TaskManager;
use cpworker::unix_manager::UnixManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sock = args.get(1).cloned().unwrap_or_else(|| "/tmp/rpc.sock".into());
    let cfg_path = args.get(2).cloned().unwrap_or_else(|| "/tmp/config.json".into());
    let work_dir = args.get(3).cloned().unwrap_or_else(|| "/tmp".into());

    // Minimal config: an empty pipeline. Same shape as the C harness.
    let cfg = Config::parse_str(r#"{"log_level":"info","tasks":[]}"#)
        .expect("parse minimal config");
    let mgr = TaskManager::new(cfg, cfg_path, work_dir).expect("create task manager");
    let mgr = Arc::new(Mutex::new(mgr));

    let _um = UnixManager::start(&sock, mgr).expect("start unix manager");
    println!("READY");
    // Serve until killed.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
