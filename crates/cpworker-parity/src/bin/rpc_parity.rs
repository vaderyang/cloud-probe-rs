// Rust side of the Unix JSON-RPC protocol parity harness.
// Usage: rpc_parity <socket-path> <config-path> <working-dir>
use std::sync::Arc;

use parking_lot::Mutex;

use cpworker::config::Config;
use cpworker::task::TaskManager;
use cpworker::unix_manager::UnixManager;

/// Resolve the three positional arguments, keeping the historical defaults.
fn parse_args(args: &[String]) -> (String, String, String) {
    let sock = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/tmp/rpc.sock".into());
    let cfg_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "/tmp/config.json".into());
    let work_dir = args.get(3).cloned().unwrap_or_else(|| "/tmp".into());
    (sock, cfg_path, work_dir)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (sock, cfg_path, work_dir) = parse_args(&args);

    // Minimal config: an empty pipeline. Same shape as the C harness.
    let cfg =
        Config::parse_str(r#"{"log_level":"info","tasks":[]}"#).expect("parse minimal config");
    let mgr = TaskManager::new(cfg, cfg_path, work_dir).expect("create task manager");
    let mgr = Arc::new(Mutex::new(mgr));

    let _um = UnixManager::start(&sock, mgr).expect("start unix manager");
    println!("READY");
    // Serve until killed.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn parse_args_uses_defaults_when_positional_arguments_are_missing() {
        let none: Vec<String> = vec!["rpc_parity".into()];
        assert_eq!(
            parse_args(&none),
            (
                "/tmp/rpc.sock".to_string(),
                "/tmp/config.json".to_string(),
                "/tmp".to_string()
            )
        );
    }

    #[test]
    fn parse_args_forwards_explicit_paths() {
        let a: Vec<String> = vec![
            "rpc_parity".into(),
            "/run/x.sock".into(),
            "/etc/cfg.json".into(),
            "/var/work".into(),
        ];
        assert_eq!(
            parse_args(&a),
            (
                "/run/x.sock".to_string(),
                "/etc/cfg.json".to_string(),
                "/var/work".to_string()
            )
        );
    }

    #[test]
    fn parse_args_fills_only_the_leading_positions() {
        let a: Vec<String> = vec!["rpc_parity".into(), "/run/x.sock".into()];
        assert_eq!(
            parse_args(&a),
            (
                "/run/x.sock".to_string(),
                "/tmp/config.json".to_string(),
                "/tmp".to_string()
            )
        );
    }
}
