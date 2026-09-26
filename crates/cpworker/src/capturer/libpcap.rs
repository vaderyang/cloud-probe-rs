//! libpcap live capturer. Port of `libpcap.c` (TPACKET_V3 nuance preserved).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pcap::Error as PcapError;

use super::{Capturer, PacketHeader, PacketSink};
use crate::config::{bpf_filter_exclude_task_output_hosts, LibpcapConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::netns;
use crate::netutil::bpf_filter_replace_nic;
use crate::packet::PKT_DIR_NONCHECK;
use crate::req_pattern::ReqPattern;
use crate::stats::CaptureStats;

const DROP_STAT_DUR_SEC: i64 = 2;

pub struct LibpcapCapturer {
    stats: Arc<CaptureStats>,
    interface: String,
    netns_path: String,
    req_pattern: Option<ReqPattern>,
    cap: pcap::Capture<pcap::Active>,

    drop_stat_started: bool,
    drop_stat_prev_time: i64,
    prev_ps_drop: u32,
    prev_ps_ifdrop: u32,
    pcap_next_error: Option<String>,
}

fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl LibpcapCapturer {
    pub fn new(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &LibpcapConfig,
        stats: Arc<CaptureStats>,
    ) -> Result<Self> {
        let has_netns = !cfg.netns.is_empty();
        let self_netns = if has_netns {
            Some(netns::open_self_netns()?)
        } else {
            None
        };
        let mut entered_netns = None;
        if has_netns {
            entered_netns = Some(netns::enter_netns_by_path(&cfg.netns)?);
        }

        // Build result with cleanup on any error path.
        let result = Self::open(
            tasks,
            task,
            cfg,
            stats.clone(),
            has_netns,
            self_netns.as_ref(),
        );

        // Restore original netns if we switched.
        if let Some(self_ns) = self_netns.as_ref() {
            if let Err(e) = netns::enter_netns_by_fd(self_ns) {
                crate::log_error!("restore netns fail: {e}");
            }
        }
        drop(entered_netns);

        result
    }

    fn open(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &LibpcapConfig,
        stats: Arc<CaptureStats>,
        has_netns: bool,
        _self_netns: Option<&std::os::fd::OwnedFd>,
    ) -> Result<Self> {
        let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, &cfg.interface)
            .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

        // BPF: unless disabled, exclude task output hosts.
        let bpf = if !cfg.not_filter_output_hosts {
            crate::log_info!("exclude task output hosts");
            bpf_filter_exclude_task_output_hosts(&cfg.bpf, tasks)
        } else {
            cfg.bpf.clone()
        };
        let bpf = if bpf.is_empty() {
            String::new()
        } else {
            bpf_filter_replace_nic(&bpf)?
        };

        let buffer_size = {
            let mb = cfg.buffer_size_mb as i64;
            if mb > (i32::MAX as i64) / 1024 / 1024 {
                crate::log_warn!("buffer_size is too large, set to {}", i32::MAX);
                i32::MAX
            } else {
                (mb * 1024 * 1024) as i32
            }
        };

        let inactive = pcap::Capture::from_device(cfg.interface.as_str())
            .map_err(|e| Error::new(format!("call pcap_create({}) error: {e}", cfg.interface)))?
            .snaplen(cfg.snaplen)
            .promisc(false)
            .buffer_size(buffer_size)
            .timeout(cfg.timeout_ms.max(1))
            .immediate_mode(cfg.timeout_ms == 0);

        let mut cap = inactive
            .open()
            .map_err(|e| Error::new(format!("call pcap_activate error: {e}")))?;

        if cfg.timeout_ms == 0 {
            cap = cap
                .setnonblock()
                .map_err(|e| Error::new(format!("pcap_setnonblock error: {e}")))?;
        }

        if !bpf.is_empty() {
            cap.filter(&bpf, true)
                .map_err(|e| Error::new(format!("compile bpf filter '{bpf}' error: {e}")))?;
        }

        let _ = has_netns;

        Ok(LibpcapCapturer {
            stats,
            interface: cfg.interface.clone(),
            netns_path: cfg.netns.clone(),
            req_pattern: Some(req_pattern),
            cap,
            drop_stat_started: false,
            drop_stat_prev_time: 0,
            prev_ps_drop: 0,
            prev_ps_ifdrop: 0,
            pcap_next_error: None,
        })
    }
}

impl Capturer for LibpcapCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        let mut num_pkts = 0u64;
        let mut now;

        match self.cap.next_packet() {
            Ok(packet) => {
                let hdr = PacketHeader {
                    ts_sec: packet.header.ts.tv_sec as i64,
                    ts_usec: packet.header.ts.tv_usec as i64,
                    caplen: packet.header.caplen,
                    len: packet.header.len,
                };
                let direction = match &self.req_pattern {
                    None => PKT_DIR_NONCHECK,
                    Some(rp) => rp.judge_pkt_direction(packet.data),
                };
                self.stats.cap_bytes.add(hdr.caplen as u64);
                self.stats.cap_packets.add(1);
                sink.on_packet(&hdr, packet.data, direction);
                num_pkts = 1;
                now = hdr.ts_sec;
            }
            Err(PcapError::TimeoutExpired) => {
                sink.on_heartbeat();
                now = now_sec();
            }
            Err(e) => {
                if self.pcap_next_error.is_none() {
                    self.pcap_next_error = Some(format!(
                        "interface={}, netns={}, pcap_next_ex error: {e}",
                        self.interface, self.netns_path
                    ));
                }
                now = now_sec();
            }
        }

        if !self.drop_stat_started {
            if let Ok(stat) = self.cap.stats() {
                self.drop_stat_started = true;
                self.prev_ps_drop = stat.dropped;
                self.prev_ps_ifdrop = stat.if_dropped;
                self.drop_stat_prev_time = now;
            }
            return num_pkts;
        }

        if now - self.drop_stat_prev_time < DROP_STAT_DUR_SEC {
            return num_pkts;
        }

        if let Ok(stat) = self.cap.stats() {
            let drop_diff = stat.dropped.wrapping_sub(self.prev_ps_drop);
            self.stats.drop_packets.add(drop_diff as u64);
            let ifdrop_diff = stat.if_dropped.wrapping_sub(self.prev_ps_ifdrop);
            self.stats.ifdrop_packets.add(ifdrop_diff as u64);
            self.prev_ps_drop = stat.dropped;
            self.prev_ps_ifdrop = stat.if_dropped;
            self.drop_stat_prev_time = now;
        }

        if let Some(err) = self.pcap_next_error.take() {
            crate::log_error!("{err}");
        }
        num_pkts
    }
}
