#![no_main]
//! Fuzz the JSON config parser and the BPF output-host exclusion helper.

use libfuzzer_sys::fuzz_target;

use cpworker::config::{bpf_filter_exclude_task_output_hosts, Config};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(cfg) = Config::parse_str(&s) {
        // Touch the parsed structure to ensure it is internally consistent.
        let _ = cfg.log_level;
        let _ = cfg.tasks.len();
        let _ = bpf_filter_exclude_task_output_hosts("host 1.2.3.4", &cfg.tasks);
    } else {
        let _ = bpf_filter_exclude_task_output_hosts(&s, &[]);
    }
});
