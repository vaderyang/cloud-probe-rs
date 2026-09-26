//! Offline pcap-file capturer. Port of `pcap_file.c`.

use std::sync::Arc;

use pcap::Error as PcapError;

use super::{Capturer, PacketHeader, PacketSink};
use crate::config::{bpf_filter_exclude_task_output_hosts, PcapFileConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::netutil::bpf_filter_replace_nic;
use crate::packet::PKT_DIR_NONCHECK;
use crate::req_pattern::ReqPattern;
use crate::stats::CaptureStats;

pub struct PcapFileCapturer {
    stats: Arc<CaptureStats>,
    req_pattern: Option<ReqPattern>,
    cap: pcap::Capture<pcap::Offline>,
    eof: bool,
}

impl PcapFileCapturer {
    /// Open an offline pcap file for replay.
    ///
    /// # Errors
    /// Returns an error if the req_pattern cannot be built or the pcap file
    /// cannot be opened.
    pub fn new(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &PcapFileConfig,
        stats: Arc<CaptureStats>,
    ) -> Result<Self> {
        let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, "")
            .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

        let mut cap = pcap::Capture::from_file(&cfg.file_name)
            .map_err(|e| Error::new(format!("could not load file {}: {e}", cfg.file_name)))?;

        let bpf = bpf_filter_exclude_task_output_hosts(&cfg.bpf, tasks);
        if !bpf.is_empty() {
            let bpf = bpf_filter_replace_nic(&bpf)?;
            cap.filter(&bpf, true)
                .map_err(|e| Error::new(format!("compile bpf filter '{bpf}' error: {e}")))?;
        }

        Ok(PcapFileCapturer {
            stats,
            req_pattern: Some(req_pattern),
            cap,
            eof: false,
        })
    }
}

impl Capturer for PcapFileCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        match self.cap.next_packet() {
            Ok(packet) => {
                let hdr = PacketHeader {
                    ts_sec: packet.header.ts.tv_sec,
                    ts_usec: packet.header.ts.tv_usec,
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
                1
            }
            Err(PcapError::NoMorePackets) => {
                sink.on_heartbeat();
                if !self.eof {
                    crate::log_info!("end of file");
                    self.eof = true;
                }
                0
            }
            Err(_) => 0,
        }
    }
}
