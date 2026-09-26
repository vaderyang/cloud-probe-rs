//! Rotating-file pcap output. Port of `output_rotating_file.c`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::pcap_writer::PcapWriter;
use super::{Output, PacketHeader};
use crate::config::{CapturerKind, RotatingFileConfig};
use crate::error::{Error, Result};
use crate::packet::PKT_DIR_UNKNOWN;
use crate::stats::OutputStats;

/// Rotating pcap file output.
pub struct RotatingFileOutput {
    stats: Arc<OutputStats>,
    file_root: String,
    max_file_interval: i64,
    snaplen: i32,
    writer: Option<PcapWriter>,
    file_time: i64,
    dumper_error: bool,
}

impl RotatingFileOutput {
    /// Create a rotating pcap file output.
    ///
    /// # Errors
    /// Returns an error if the root directory cannot be created or the first
    /// file cannot be opened.
    pub fn new(
        cfg: &RotatingFileConfig,
        capturer: &CapturerKind,
        stats: Arc<OutputStats>,
    ) -> Result<Self> {
        let root = PathBuf::from(&cfg.file_root);
        let meta = std::fs::metadata(&root)
            .map_err(|e| Error::new(format!("stat file_root {} error: {e}", cfg.file_root)))?;
        if !meta.is_dir() {
            return Err(Error::new(format!(
                "file_root {} is not a directory",
                cfg.file_root
            )));
        }
        Ok(RotatingFileOutput {
            stats,
            file_root: cfg.file_root.clone(),
            max_file_interval: cfg.max_file_interval.max(0) as i64,
            snaplen: capturer.snaplen(),
            writer: None,
            file_time: 0,
            dumper_error: false,
        })
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Port of `generate_path` + `create_dumper`.
    fn create_writer(&mut self) -> Result<()> {
        use chrono::{Datelike, TimeZone, Timelike};
        let dt = chrono::Local.timestamp_opt(self.file_time, 0).unwrap();
        let date = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        let sub_path = format!(
            "{:04}{:02}{:02}{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour()
        );
        let dir = PathBuf::from(&self.file_root).join(sub_path);
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .map_err(|e| Error::new(format!("create path {} error: {e}", dir.display())))?;
        }
        let file = dir.join(format!("pktminerg_dump_{date}.pcap"));
        let writer = PcapWriter::create(&file, self.snaplen)?;
        self.writer = Some(writer);
        Ok(())
    }
}

impl Output for RotatingFileOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(hdr.caplen as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        let now = Self::now();
        if self.dumper_error && now - self.file_time < self.max_file_interval {
            self.stats.error_drop_bytes.add(hdr.caplen as u64);
            self.stats.error_drop_packets.add(1);
            return -1;
        }

        match self.writer {
            None => {
                self.file_time = now;
                if let Err(e) = self.create_writer() {
                    crate::log_error!("{e}");
                    self.dumper_error = true;
                    self.stats.error_drop_bytes.add(hdr.caplen as u64);
                    self.stats.error_drop_packets.add(1);
                    return -1;
                }
                self.dumper_error = false;
            }
            Some(_) => {
                if self.max_file_interval > 0 && now - self.file_time >= self.max_file_interval {
                    self.writer = None;
                    self.file_time = now;
                    if let Err(e) = self.create_writer() {
                        crate::log_error!("{e}");
                        self.dumper_error = true;
                        self.stats.error_drop_bytes.add(hdr.caplen as u64);
                        self.stats.error_drop_packets.add(1);
                        return -1;
                    }
                    self.dumper_error = false;
                }
            }
        }

        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = w.write(hdr, pkt) {
                crate::log_error!("write pcap output failed: {e}");
            }
        }
        self.stats.fwd_bytes.add(hdr.caplen as u64);
        self.stats.fwd_packets.add(1);
        0
    }
}
