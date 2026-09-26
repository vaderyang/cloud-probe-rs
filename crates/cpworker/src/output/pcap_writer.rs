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

/// A pcap savefile writer. Buffered; call [`PcapWriter::flush`] to fsync.
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
    /// # Errors
    /// Returns an error if flushing fails.
    pub fn flush(&mut self) -> Result<()> {
        self.w
            .flush()
            .map_err(|e| Error::new(format!("flush pcap file: {e}")))
    }
}
