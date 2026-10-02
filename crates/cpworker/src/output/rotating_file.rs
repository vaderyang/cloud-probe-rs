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
    /// When an output-layer failure last happened, or `None` while the output is
    /// healthy. This is the *one* "the dump file is broken" state: the old
    /// `dumper_error` covered only a failed open, so a failing *write* was logged
    /// once per packet and still counted as forwarded (cloud-probe-rs-3zs, the
    /// rotating twin of cloud-probe-rs-5bh). While it is set the packet is dropped
    /// without touching the writer, and a retry is allowed once per rotation
    /// interval - which is also what bounds the error log.
    failed_at: Option<i64>,
    /// Bytes/packets handed to the current writer since it last flushed
    /// successfully. Retiring that writer (rotation, write failure, shutdown) is
    /// the only chance to charge them back, because [`PcapWriter`] does not
    /// expose how much of it is still buffered.
    unflushed_bytes: u64,
    unflushed_packets: u64,
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
            failed_at: None,
            unflushed_bytes: 0,
            unflushed_packets: 0,
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

    /// Charge one packet to `error_drop_*` and report it as not forwarded.
    ///
    /// Every path that refuses a packet goes through here so that "the writer
    /// never took this record" and "the stats say it was dropped" cannot drift
    /// apart, which is exactly what the `-1` return value means.
    fn count_error(&mut self, caplen: u32) -> i32 {
        self.stats.error_drop_bytes.add(u64::from(caplen));
        self.stats.error_drop_packets.add(1);
        -1
    }

    /// Flush the current dump file and hand it back, charging whatever the flush
    /// could not publish to `error_drop_*`.
    ///
    /// `BufWriter::drop` swallows a failing flush, and this output drops the
    /// outgoing writer on every rotation as well as at shutdown, so without this
    /// call the records still parked in a *retired* file would leave nothing
    /// behind but a log line. The charge is an upper bound on the loss (the buffer
    /// may already have spilled part of it to the OS), which is still honest next
    /// to counting those packets as forwarded. `at` names the event in the log so
    /// an operator can tell a rotation loss from a shutdown loss.
    fn close_writer(&mut self, at: &str) {
        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = w.flush() {
                crate::log_error!("flush rotating pcap output failed ({at}): {e}");
                self.stats.error_drop_bytes.add(self.unflushed_bytes);
                self.stats.error_drop_packets.add(self.unflushed_packets);
            }
        }
        self.writer = None;
        self.unflushed_bytes = 0;
        self.unflushed_packets = 0;
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
        if let Some(failed_at) = self.failed_at {
            // Latched: drop without touching (or re-failing on) the writer, and
            // without re-logging the same error per packet. The retry window is
            // one rotation interval, at least one second, which is how the C
            // oracle bounds its own retries ("avoid frequent creation", see
            // `output_rotating_file.c`). Comparing against `max_file_interval`
            // alone - as this port did - leaves an output that never rotates
            // (`max_file_interval == 0`) re-failing and re-logging every packet.
            if now - failed_at < self.max_file_interval.max(1) {
                return self.count_error(caplen);
            }
        }

        match self.writer {
            None => {
                self.file_time = now;
                if let Err(e) = self.create_writer() {
                    crate::log_error!("{e}");
                    self.failed_at = Some(now);
                    return self.count_error(caplen);
                }
                self.failed_at = None;
            }
            Some(_) => {
                if self.max_file_interval > 0 && now - self.file_time >= self.max_file_interval {
                    // Retire the outgoing dump *through* close_writer(): simply
                    // dropping the writer here let `BufWriter::drop` swallow a
                    // failing flush, so a rotation could lose the tail of the old
                    // file without any counter noticing it.
                    self.close_writer("rotation");
                    self.file_time = now;
                    if let Err(e) = self.create_writer() {
                        crate::log_error!("{e}");
                        self.failed_at = Some(now);
                        return self.count_error(caplen);
                    }
                    self.failed_at = None;
                }
            }
        }

        let out_hdr = PacketHeader { caplen, ..*hdr };
        let write_err = match self.writer.as_mut() {
            Some(w) => w.write(&out_hdr, pkt).err(),
            // Both paths above install a writer or return; a counted drop beats
            // an `expect`, which is an abort here (P5-23).
            None => Some(Error::new("no dump file is open")),
        };
        let Some(e) = write_err else {
            // Counting rule, shared with `output/file.rs` (cloud-probe-rs-5bh):
            // `fwd_*` means "the record was accepted by the writer", *not* "the
            // record is on disk" - `PcapWriter` buffers, so a counted packet can
            // still be lost by a later flush failure, and that failure is charged
            // to `error_drop_*`. The two counters therefore overlap by exactly the
            // records that never made it out. The C oracle cannot say either way:
            // `pcap_dump()` is void, so `output_rotating_file.c` counts every
            // packet as forwarded no matter what the dumper thought (this is a
            // deliberate divergence).
            self.stats.fwd_bytes.add(u64::from(caplen));
            self.stats.fwd_packets.add(1);
            self.unflushed_bytes = self.unflushed_bytes.saturating_add(u64::from(caplen));
            self.unflushed_packets = self.unflushed_packets.saturating_add(1);
            return 0;
        };

        crate::log_error!("write rotating pcap output failed: {e}");
        // The dump file that refused a write is retired, not retried every packet:
        // close_writer() charges back what is still parked in its buffer, and the
        // latch keeps the next packets off the broken file (and off the log) until
        // the retry window opens a fresh one.
        self.failed_at = Some(now);
        self.close_writer("write failure");
        self.count_error(caplen)
    }

    fn destroy(&mut self) {
        // Flush the current dump file explicitly so buffer errors are reported
        // (`BufWriter::drop` swallows them), then close it.
        self.close_writer("shutdown");
        if self.failed_at.is_some() {
            crate::log_error!("rotating pcap output is closing with its dump files broken");
        }
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

    // --- cloud-probe-rs-3zs: a failed write is a drop, not a forward ----------

    fn rotating_output(
        root: &std::path::Path,
        max_file_interval: i32,
        stats: Arc<OutputStats>,
    ) -> RotatingFileOutput {
        let cfg = RotatingFileConfig {
            file_root: root.display().to_string(),
            max_file_interval,
        };
        RotatingFileOutput::new(
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
        .expect("create rotating file output")
    }

    fn hdr(len: u32, seq: u64) -> PacketHeader {
        PacketHeader {
            ts_sec: 1_700_000_000 + seq as i64,
            ts_usec: 0,
            caplen: len,
            len,
        }
    }

    fn packets(s: &crate::stats::PacketsStats) -> u64 {
        s.load().0
    }

    fn bytes(s: &crate::stats::BytesStats) -> u64 {
        s.load().0
    }

    /// A writer whose every eventual write fails: `/dev/full` takes the buffered
    /// header and records, then refuses the first flush the `BufWriter` attempts.
    /// Injected directly because the generated dump name cannot point at it.
    fn inject_failing_writer(out: &mut RotatingFileOutput) {
        let w = PcapWriter::create(std::path::Path::new("/dev/full"), out.snaplen)
            .expect("open /dev/full");
        out.writer = Some(w);
        out.file_time = RotatingFileOutput::now();
    }

    /// Make every *new* dump file un-openable, so the failing phase of a test stays
    /// failing and cannot silently recover when the retry window opens. `file_root`
    /// becomes a path through a regular file, which no `create_dir_all` can accept -
    /// not even root's.
    fn poison_file_root(out: &mut RotatingFileOutput, dir: &std::path::Path) {
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"x").expect("plant a regular file");
        out.file_root = blocker.display().to_string();
    }

    /// Every `*.pcap` below `root`, the way the upstream vector helper counts them.
    fn pcap_files(root: &std::path::Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "pcap") {
                    found.push(path);
                }
            }
        }
        found
    }

    /// The 5bh defect in its rotating shape: 1000 packets written to a dump file
    /// that refuses every write used to be reported as `fwd_packets=1000,
    /// error_drop_packets=0` while nothing reached the file. Each packet must land
    /// in exactly one of the two counters, and the error must not be logged or
    /// retried once per packet.
    #[test]
    fn a_failing_dump_file_is_counted_as_dropped_not_forwarded() {
        if !std::path::Path::new("/dev/full").exists() {
            return; // not a Linux dev box; nothing to fail the write against
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let stats = Arc::new(OutputStats::default());
        // interval 0 => never rotates, so every packet goes through the injected
        // writer instead of being rescued by a fresh dump file.
        let mut out = rotating_output(dir.path(), 0, stats.clone());
        inject_failing_writer(&mut out);
        poison_file_root(&mut out, dir.path());

        let body = vec![0x5au8; 64];
        const N: u64 = 1000;
        const CAP: u64 = 64;

        // Phase 1: the records that still fit the writer's buffer are accepted; the
        // first one that has to reach the file must fail.
        let mut accepted = 0u64;
        let mut sent = 0u64;
        while sent < N {
            let rc = out.send_packet(&hdr(CAP as u32, sent), &body, 1);
            sent += 1;
            if rc != 0 {
                break;
            }
            accepted += 1;
        }
        assert!(accepted > 0, "the records buffered before the first error");
        assert!(accepted < N, "the write must fail for /dev/full");
        assert_eq!(sent, accepted + 1, "exactly one packet has failed so far");
        assert_eq!(
            packets(&stats.fwd_packets),
            accepted,
            "only the records the writer accepted may count as forwarded"
        );
        assert_eq!(bytes(&stats.fwd_bytes), accepted * CAP);
        assert_eq!(
            packets(&stats.error_drop_packets),
            accepted + 1,
            "the refused packet, plus the records the retired file could not publish"
        );
        assert!(
            out.failed_at.is_some(),
            "one failed write latches the output"
        );
        assert!(
            out.writer.is_none(),
            "the file that refused a write is retired, not retried per packet"
        );

        // Phase 2: while latched nothing more is ever accepted (the retry would
        // find an un-openable root), so `fwd_*` cannot keep growing.
        for seq in sent..N {
            assert_eq!(out.send_packet(&hdr(CAP as u32, seq), &body, 1), -1);
        }
        assert_eq!(
            packets(&stats.fwd_packets),
            accepted,
            "a latched output must not hand out further forwards"
        );

        out.destroy();
        // All N packets now sit in `error_drop_*`: N-accepted because the writer
        // refused them, and the accepted ones because the file they were counted
        // into never published them. `fwd_*` keeps its `accepted` on top - the
        // overlap PARITY.md documents, and the reason a loss rate must not be
        // computed as error_drop/(fwd+error_drop).
        assert_eq!(packets(&stats.error_drop_packets), N);
        assert_eq!(bytes(&stats.error_drop_bytes), N * CAP);
    }

    /// The other direction: the latch and the charge-back must not become a habit of
    /// dropping healthy traffic. A writable root still forwards everything, loses
    /// nothing, and the frames are really in the dump file.
    #[test]
    fn a_writable_dump_file_still_forwards_every_packet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stats = Arc::new(OutputStats::default());
        // 3600 => one dump file for the whole test, like the upstream vectors.
        let mut out = rotating_output(dir.path(), 3600, stats.clone());

        let body = vec![0xa5u8; 64];
        const N: u64 = 50;
        for seq in 0..N {
            assert_eq!(out.send_packet(&hdr(body.len() as u32, seq), &body, 1), 0);
        }
        out.destroy();

        assert_eq!(packets(&stats.fwd_packets), N);
        assert_eq!(bytes(&stats.fwd_bytes), N * 64);
        assert_eq!(
            packets(&stats.error_drop_packets),
            0,
            "a healthy output charges nothing as dropped"
        );
        assert_eq!(bytes(&stats.error_drop_bytes), 0);

        let pcaps = pcap_files(dir.path());
        assert_eq!(pcaps.len(), 1, "interval 3600 => a single dump file");
        let on_disk = std::fs::read(&pcaps[0]).expect("read dump");
        assert_eq!(on_disk.len(), 24 + usize::try_from(N).unwrap() * (16 + 64));
        for rec in 0..usize::try_from(N).unwrap() {
            let off = 24 + rec * (16 + 64);
            assert_eq!(&on_disk[off + 16..off + 16 + 64], body.as_slice());
        }
    }

    /// Rotation path: a new dump file that cannot be opened drops the packet that
    /// triggered the rotation, and the file rotation retires must not lose its
    /// buffered tail silently.
    #[test]
    fn a_failed_rotation_is_counted_as_dropped_and_flushes_the_old_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stats = Arc::new(OutputStats::default());
        let mut out = rotating_output(dir.path(), 60, stats.clone());
        let body = vec![0x11u8; 64];

        assert_eq!(out.send_packet(&hdr(body.len() as u32, 0), &body, 1), 0);

        // Force the next packet into the rotation path, with no file to rotate into.
        out.file_time = 0;
        poison_file_root(&mut out, dir.path());
        assert_eq!(out.send_packet(&hdr(body.len() as u32, 1), &body, 1), -1);

        assert_eq!(
            packets(&stats.fwd_packets),
            1,
            "a packet the rotation could not write is not forwarded"
        );
        assert_eq!(packets(&stats.error_drop_packets), 1);
        assert_eq!(bytes(&stats.error_drop_bytes), 64);
        assert!(out.failed_at.is_some(), "the open failure latches");

        // The old dump file is complete on disk: close_writer flushed it instead of
        // letting `BufWriter::drop` swallow the buffered record.
        let pcaps = pcap_files(dir.path());
        assert_eq!(pcaps.len(), 1);
        assert_eq!(
            std::fs::metadata(&pcaps[0]).expect("stat").len(),
            24 + 16 + 64,
            "rotation must publish the outgoing file, not just unlink-and-forget it"
        );

        // Latched: the next packet is dropped without another open attempt, and
        // destroy() has nothing left to charge, so the retired file is not charged
        // twice.
        assert_eq!(out.send_packet(&hdr(body.len() as u32, 2), &body, 1), -1);
        assert_eq!(packets(&stats.error_drop_packets), 2);
        out.destroy();
        assert_eq!(
            packets(&stats.error_drop_packets),
            2,
            "destroy() must not charge the file rotation already closed"
        );
    }

    /// Rotation with a file that cannot publish its buffer: the records counted
    /// `fwd_*` against the old file are charged back, and the fresh file - which
    /// works - is not held against the output.
    #[test]
    fn a_failing_rotation_charges_the_records_that_never_reached_the_file() {
        if !std::path::Path::new("/dev/full").exists() {
            return; // see above
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let stats = Arc::new(OutputStats::default());
        let mut out = rotating_output(dir.path(), 60, stats.clone());
        inject_failing_writer(&mut out);

        let body = vec![0x22u8; 64];
        const N: u64 = 8; // fits the writer's buffer, so all of it is "accepted"
        for seq in 0..N {
            assert_eq!(out.send_packet(&hdr(body.len() as u32, seq), &body, 1), 0);
        }
        assert_eq!(packets(&stats.error_drop_packets), 0);

        out.file_time = 0;
        assert_eq!(
            out.send_packet(&hdr(body.len() as u32, N), &body, 1),
            0,
            "the fresh dump file takes the packet"
        );
        assert_eq!(
            packets(&stats.fwd_packets),
            N + 1,
            "the records the rotated-away file accepted stay counted as forwarded, \
             plus the one the fresh file took"
        );
        assert_eq!(
            packets(&stats.error_drop_packets),
            N,
            "the records the rotated-away file never published are a drop"
        );
        assert_eq!(bytes(&stats.error_drop_bytes), N * 64);
        assert!(
            out.failed_at.is_none(),
            "a rotation that produced a working file is healthy again"
        );

        out.destroy();
        assert_eq!(
            packets(&stats.error_drop_packets),
            N,
            "destroy() flushed the new file, so nothing more is charged"
        );
        let pcaps = pcap_files(dir.path());
        assert_eq!(pcaps.len(), 1);
        assert_eq!(
            std::fs::metadata(&pcaps[0]).expect("stat").len(),
            24 + 16 + 64
        );
    }
}
