//! Raw libpcap savefile writer.
//!
//! The `pcap` crate does not expose `pcap_dump_open` for a "dead" handle, so we
//! declare the small FFI surface we need ourselves. Linking is provided by the
//! `pcap` crate's build script.

use std::ffi::CString;
use std::path::Path;

use crate::error::{Error, Result};
use crate::output::PacketHeader;

pub const DLT_EN10MB: libc::c_int = 1;

#[repr(C)]
struct PcapPkthdr {
    ts: libc::timeval,
    caplen: u32,
    len: u32,
}

extern "C" {
    fn pcap_open_dead(linktype: libc::c_int, snaplen: libc::c_int) -> *mut libc::c_void;
    fn pcap_dump_open(p: *mut libc::c_void, fname: *const libc::c_char) -> *mut libc::c_void;
    fn pcap_dump(user: *mut libc::c_uchar, h: *const PcapPkthdr, sp: *const libc::c_uchar);
    fn pcap_dump_flush(p: *mut libc::c_void) -> libc::c_int;
    fn pcap_dump_close(p: *mut libc::c_void);
    fn pcap_close(p: *mut libc::c_void);
}

pub struct PcapWriter {
    pcap: *mut libc::c_void,
    dumper: *mut libc::c_void,
}

// The writer owns its handles exclusively; libpcap dumpers are not thread-safe
// for concurrent access but are safe to move between threads.
unsafe impl Send for PcapWriter {}

impl PcapWriter {
    pub fn create(path: &Path, snaplen: i32) -> Result<Self> {
        let pcap = unsafe { pcap_open_dead(DLT_EN10MB, snaplen) };
        if pcap.is_null() {
            return Err(Error::new("pcap_open_dead failed"));
        }
        let cpath = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| Error::new("invalid output path"))?;
        let dumper = unsafe { pcap_dump_open(pcap, cpath.as_ptr()) };
        if dumper.is_null() {
            unsafe { pcap_close(pcap) };
            return Err(Error::new(format!(
                "pcap_dump_open failed for {}",
                path.display()
            )));
        }
        Ok(PcapWriter { pcap, dumper })
    }

    pub fn write(&mut self, hdr: &PacketHeader, data: &[u8]) {
        // `pcap_dump` writes `hdr.caplen` bytes from the data pointer, so the
        // caller must guarantee the buffer is at least that long. All current
        // callers take `data` from the ring buffer where `caplen == data.len()`.
        debug_assert!(
            data.len() >= hdr.caplen as usize,
            "pcap data buffer ({} bytes) shorter than caplen ({})",
            data.len(),
            hdr.caplen
        );
        let phdr = PcapPkthdr {
            ts: libc::timeval {
                tv_sec: hdr.ts_sec as libc::time_t,
                tv_usec: hdr.ts_usec as libc::suseconds_t,
            },
            caplen: hdr.caplen,
            len: hdr.len,
        };
        unsafe {
            pcap_dump(
                self.dumper as *mut libc::c_uchar,
                &phdr,
                data.as_ptr() as *const libc::c_uchar,
            );
        }
    }

    pub fn flush(&mut self) {
        unsafe {
            pcap_dump_flush(self.dumper);
        }
    }
}

impl Drop for PcapWriter {
    fn drop(&mut self) {
        unsafe {
            if !self.dumper.is_null() {
                pcap_dump_close(self.dumper);
            }
            if !self.pcap.is_null() {
                pcap_close(self.pcap);
            }
        }
    }
}
