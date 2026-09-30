//! Rotating-file pcap output. Port of `output_rotating_file.c`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::pcap_writer::PcapWriter;
use super::{Output, PacketHeader};
use crate::config::{CapturerKind, OutputConfig, RotatingFileConfig};
use crate::error::{Error, Result};
use crate::packet::PKT_DIR_UNKNOWN;
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

/// Rotating pcap file output.
pub struct RotatingFileOutput {
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,
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
        out: &OutputConfig,
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
        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };
        Ok(RotatingFileOutput {
            stats,
            throttle,
            slice: out.slice,
            file_root: cfg.file_root.clone(),
            max_file_interval: cfg.max_file_interval.max(0) as i64,
            snaplen: super::file::file_output_snaplen(capturer.snaplen(), out.slice),
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
        // `timestamp_opt` is only `None` for a clock outside chrono's (or the
        // pcap name's) representable range, but an unreachable panic on a
        // machine with a broken RTC is still a dead worker under
        // `panic = "abort"` - report it as a dumper error, which send_packet()
        // already counts in error_drop_* (AUDIT4 P5-23).
        let dt = chrono::Local
            .timestamp_opt(self.file_time, 0)
            .single()
            .ok_or_else(|| {
                Error::new(format!(
                    "invalid file_time {}: out of range",
                    self.file_time
                ))
            })?;
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
        // A sliced record keeps the wire length in len, as pcap-savefile(5)
        // describes (port of the `hdr.caplen = output->slice` step).
        let mut caplen = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < caplen {
            caplen = self.slice as u32;
        }

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(caplen as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        if let Some(tb) = self.throttle.as_mut() {
            if !tb.consume(caplen as usize, hdr.ts()) {
                self.stats.ratelimit_drop_bytes.add(caplen as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        let now = Self::now();
        if self.dumper_error && now - self.file_time < self.max_file_interval {
            self.stats.error_drop_bytes.add(caplen as u64);
            self.stats.error_drop_packets.add(1);
            return -1;
        }

        match self.writer {
            None => {
                self.file_time = now;
                if let Err(e) = self.create_writer() {
                    crate::log_error!("{e}");
                    self.dumper_error = true;
                    self.stats.error_drop_bytes.add(caplen as u64);
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
                        self.stats.error_drop_bytes.add(caplen as u64);
                        self.stats.error_drop_packets.add(1);
                        return -1;
                    }
                    self.dumper_error = false;
                }
            }
        }

        let out_hdr = PacketHeader { caplen, ..*hdr };
        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = w.write(&out_hdr, pkt) {
                crate::log_error!("write pcap output failed: {e}");
            }
        }
        self.stats.fwd_bytes.add(caplen as u64);
        self.stats.fwd_packets.add(1);
        0
    }

    fn destroy(&mut self) {
        // Flush the current dump file explicitly so buffer errors are reported
        // (`BufWriter::drop` swallows them), then close it.
        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = w.flush() {
                crate::log_error!("flush rotating pcap output failed: {e}");
            }
        }
        self.writer = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PcapFileConfig;

    /// AUDIT4 P5-23: `create_writer` used to `unwrap()` chrono's LocalResult.
    /// A clock outside the representable range has to surface as a dumper error
    /// (the caller already has an error path for it), not abort the worker.
    #[test]
    fn out_of_range_file_time_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RotatingFileConfig {
            file_root: dir.path().display().to_string(),
            max_file_interval: -1,
        };
        let capturer = CapturerKind::PcapFile(PcapFileConfig {
            file_name: String::new(),
            bpf: String::new(),
        });
        let stats = Arc::new(OutputStats::default());
        let mut out = RotatingFileOutput::new(
            &cfg,
            &OutputConfig {
                kind: crate::config::OutputKind::RotatingFile(cfg.clone()),
                rate_limit_mbps: 0,
                slice: 0,
            },
            &capturer,
            stats,
        )
        .expect("create");

        for bad in [i64::MAX, -8_000_000_000_000_000] {
            out.file_time = bad;
            match out.create_writer() {
                Ok(_) => panic!("file_time {bad} was accepted"),
                Err(e) => assert!(e.to_string().contains("file_time"), "{e}"),
            }
        }
        out.file_time = 1_700_000_000;
        out.create_writer().expect("a sane clock still works");
    }

    /// `destroy()` must push the buffered packets out to the file: the writer
    /// is still alive here, so anything readable on disk has been flushed.
    #[test]
    fn destroy_flushes_buffered_packets() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RotatingFileConfig {
            file_root: dir.path().display().to_string(),
            max_file_interval: -1,
        };
        let stats = Arc::new(OutputStats::default());
        let mut out = RotatingFileOutput::new(
            &cfg,
            &OutputConfig {
                kind: crate::config::OutputKind::RotatingFile(cfg.clone()),
                rate_limit_mbps: 0,
                slice: 0,
            },
            &CapturerKind::PcapFile(PcapFileConfig {
                file_name: String::new(),
                bpf: String::new(),
            }),
            stats,
        )
        .expect("create rotating file output");

        // More than the BufWriter's 8 KiB capacity, so part of it is buffered.
        let body = vec![0xabu8; 4096];
        for i in 0..8u32 {
            let hdr = PacketHeader {
                ts_sec: 1_700_000_000 + i as i64,
                ts_usec: 0,
                caplen: body.len() as u32,
                len: body.len() as u32,
            };
            assert_eq!(out.send_packet(&hdr, &body, 1), 0);
        }

        out.destroy();

        let pcap = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .flat_map(|e| std::fs::read_dir(e.path()).ok())
            .flatten()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "pcap"))
            .expect("a dump pcap was created");
        let on_disk = std::fs::metadata(&pcap).expect("stat").len() as usize;
        let expected = 24 + 8 * (16 + body.len());
        assert_eq!(
            on_disk, expected,
            "destroy() must flush every buffered pcap record (wrote {expected} bytes, \
             only {on_disk} on disk)"
        );
    }
}
