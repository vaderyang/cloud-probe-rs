//! Differential harness for the Rust config parser.
//! Same protocol as `c_config.c`.

use std::io::{self, BufRead, Write};

use cpworker::config::{
    bpf_filter_exclude_task_output_hosts, Config, ControlConfig, ExecutionModel, OutputKind,
    ReqPatternConfig, CAPTURER_TYPE_LIBPCAP, CAPTURER_TYPE_PCAP_FILE,
};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let c = match Config::parse_str(&line) {
            Ok(c) => c,
            Err(_) => {
                let _ = writeln!(out, "PARSE_FAIL");
                let _ = writeln!(out, "---");
                continue;
            }
        };

        let _ = writeln!(out, "log_level={}", c.log_level);
        let _ = writeln!(
            out,
            "exec_model={}",
            if c.execution_model == ExecutionModel::Pipeline {
                "pipeline"
            } else {
                "rtc"
            }
        );
        let _ = writeln!(out, "cpu={}", c.cpu_affinity);
        let _ = writeln!(out, "pipeline_mb={}", c.pipeline_buffer_size_mb);
        match &c.control {
            Some(ControlConfig::UnixSocket { path }) => {
                let _ = writeln!(out, "control type=unix path={path}");
            }
            None => {
                let _ = writeln!(out, "control none");
            }
        }

        let _ = writeln!(out, "tasks={}", c.tasks.len());
        for (i, t) in c.tasks.iter().enumerate() {
            let req = match t.req_pattern {
                ReqPatternConfig::None => "none",
                ReqPatternConfig::Auto => "auto",
                ReqPatternConfig::Custom { .. } => "custom",
            };
            let (cap_type, snaplen, bpf) = match &t.capturer.kind {
                cpworker::config::CapturerKind::Libpcap(l) => {
                    (CAPTURER_TYPE_LIBPCAP, l.snaplen, l.bpf.as_str())
                }
                cpworker::config::CapturerKind::PcapFile(p) => {
                    (CAPTURER_TYPE_PCAP_FILE, 262144, p.bpf.as_str())
                }
                cpworker::config::CapturerKind::DpdkPdump(d) => {
                    ("dpdk_pdump", d.snaplen, d.bpf.as_str())
                }
            };
            let _ = writeln!(
                out,
                " task idx={i} fp={} req={req} capturer={cap_type} snaplen={snaplen} bpf={bpf}",
                t.fingerprint.as_deref().unwrap_or("")
            );
            for o in &t.outputs {
                let host = o.forward_host().unwrap_or("");
                let _ = writeln!(
                    out,
                    "  output type={} rate={} slice={} host={host}",
                    o.output_type(),
                    o.rate_limit_mbps,
                    o.slice
                );
                let _ = &o.kind;
                let _: Option<&OutputKind> = None;
            }
        }

        let base_bpf = c
            .tasks
            .first()
            .map(|t| match &t.capturer.kind {
                cpworker::config::CapturerKind::Libpcap(l) => l.bpf.as_str(),
                _ => "",
            })
            .unwrap_or("");
        let bpf = bpf_filter_exclude_task_output_hosts(base_bpf, &c.tasks);
        let _ = writeln!(out, "exclude_bpf={bpf}");
        let _ = writeln!(out, "---");
    }
}
