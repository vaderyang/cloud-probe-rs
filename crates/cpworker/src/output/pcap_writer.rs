//! Pure-Rust libpcap savefile writer (no libpcap linkage).
//!
//! Writes the classic pcap format: a 24-byte global header followed by one
//! 16-byte record header per packet. Link type is Ethernet (`DLT_EN10MB`).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::output::PacketHeader;

/// Link-layer type for Ethernet, as used by libpcap savefiles.
pub const DLT_EN10MB: u32 = 1;

/// libpcap magic for microsecond-resolution timestamps, host byte order.
const PCAP_MAGIC_USEC: u32 = 0xa1b2_c3d4;
/// pcap format version 2.4.
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

/// A pcap savefile writer.
///
/// Writes are buffered in a [`BufWriter`]. [`PcapWriter::flush`] empties that
/// buffer into the file - this is what libpcap's `pcap_dump_flush()` does (an
/// `fflush`, never an `fsync`), so the C port's semantics are preserved and the
/// wording here matches them:
///
/// * after `flush()` the bytes **have reached the OS** and are visible to every
///   other reader of the file (this is what `Output::destroy()` relies on);
/// * they are **not** forced out of the OS page cache. A power loss can still
///   lose them, and nothing in the forwarding path calls `File::sync_all`: one
///   fsync per batch would dominate the forwarding loop. Callers that need
///   durability must sync the file themselves.
pub struct PcapWriter {
    w: BufWriter<File>,
}

impl PcapWriter {
    /// Create a new pcap file writing Ethernet frames with the given snaplen.
    ///
    /// # Errors
    /// Returns an error if the file cannot be created or written.
    pub fn create(path: &Path, snaplen: i32) -> Result<Self> {
        let file = File::create(path)
            .map_err(|e| Error::new(format!("open {} for writing: {e}", path.display())))?;
        let mut w = BufWriter::new(file);
        let snaplen = if snaplen <= 0 { 65535 } else { snaplen as u32 };
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&PCAP_MAGIC_USEC.to_le_bytes());
        hdr[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
        hdr[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
        hdr[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
        hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr[16..20].copy_from_slice(&snaplen.to_le_bytes());
        hdr[20..24].copy_from_slice(&DLT_EN10MB.to_le_bytes());
        w.write_all(&hdr)
            .map_err(|e| Error::new(format!("write pcap header: {e}")))?;
        Ok(PcapWriter { w })
    }

    /// Append one packet to the savefile.
    ///
    /// # Errors
    /// Returns an error if the write fails. `data` must be at least `caplen`
    /// bytes long (all current callers satisfy this).
    pub fn write(&mut self, hdr: &PacketHeader, data: &[u8]) -> Result<()> {
        let caplen = hdr.caplen.min(data.len() as u32);
        debug_assert!(
            data.len() >= hdr.caplen as usize,
            "pcap data buffer ({} bytes) shorter than caplen ({})",
            data.len(),
            hdr.caplen
        );
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&(hdr.ts_sec as u32).to_le_bytes());
        rec[4..8].copy_from_slice(&(hdr.ts_usec as u32).to_le_bytes());
        rec[8..12].copy_from_slice(&caplen.to_le_bytes());
        rec[12..16].copy_from_slice(&hdr.len.to_le_bytes());
        self.w
            .write_all(&rec)
            .map_err(|e| Error::new(format!("write pcap record header: {e}")))?;
        self.w
            .write_all(&data[..caplen as usize])
            .map_err(|e| Error::new(format!("write pcap record data: {e}")))?;
        Ok(())
    }

    /// Flush buffered packets to the OS.
    ///
    /// The buffered bytes are handed to the kernel (`write(2)`); this is **not**
    /// an `fsync` - see the type-level docs for the deliberate choice to match
    /// libpcap's `pcap_dump_flush()`.
    ///
    /// # Errors
    /// Returns an error if flushing fails.
    pub fn flush(&mut self) -> Result<()> {
        self.w
            .flush()
            .map_err(|e| Error::new(format!("flush pcap file: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What [`PcapWriter::flush`] actually promises: after it returns, the bytes
    /// are in the file (visible to another reader) even though the writer is
    /// still open. It does *not* fsync, and this test is the executable
    /// documentation of that boundary (AUDIT4 P5-22: the doc comment used to
    /// claim that this call fsynced the file).
    #[test]
    fn flush_publishes_the_buffer_without_waiting_for_the_writer() {
        let path =
            std::env::temp_dir().join(format!("cp-writer-flush-{}.pcap", std::process::id()));
        let mut w = PcapWriter::create(&path, 65535).expect("create");
        let hdr = PacketHeader {
            ts_sec: 1,
            ts_usec: 2,
            caplen: 3,
            len: 3,
        };
        for _ in 0..8 {
            w.write(&hdr, &[1, 2, 3]).expect("write");
        }
        // Everything still fits in BufWriter's 8 KiB buffer, so none of it has
        // reached the file yet...
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 0);
        // ...and one flush() publishes all of it while the writer is open.
        w.flush().expect("flush");
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").len(),
            24 + 8 * 19
        );
        std::fs::remove_file(&path).ok();
    }

    /// A non-positive snaplen is not written into the header as-is: 0 would be
    /// read back as "capture nothing".
    #[test]
    fn snaplen_falls_back_to_the_traditional_default() {
        for (snaplen, want) in [(0_i32, 65535_u32), (-1, 65535), (262144, 262144)] {
            let path = std::env::temp_dir().join(format!(
                "cp-writer-snaplen-{}-{}.pcap",
                snaplen,
                std::process::id()
            ));
            {
                let w = PcapWriter::create(&path, snaplen).expect("create");
                drop(w);
            }
            let hdr = std::fs::read(&path).expect("read");
            assert_eq!(&hdr[0..4], &0xa1b2_c3d4u32.to_le_bytes());
            assert_eq!(u32::from_le_bytes(hdr[16..20].try_into().unwrap()), want);
            assert_eq!(
                u32::from_le_bytes(hdr[20..24].try_into().unwrap()),
                DLT_EN10MB,
                "the writer must advertise Ethernet"
            );
            std::fs::remove_file(&path).ok();
        }
    }
}
