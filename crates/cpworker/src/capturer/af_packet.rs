//! `AF_PACKET` live capturer (Linux). Replaces the libpcap live capturer.
//!
//! Uses a non-blocking `SOCK_RAW` `AF_PACKET` socket bound to the configured
//! interface, a large `SO_RCVBUF` (preferring `SO_RCVBUFFORCE`) with a read-back
//! warning, kernel `SO_TIMESTAMPNS` timestamps, `PACKET_AUXDATA` for 802.1Q VLAN
//! tags, a classic-BPF program attached with `SO_ATTACH_FILTER` *before* the
//! bind (to avoid an unfiltered startup window), and `PACKET_STATISTICS` for drop
//! counters. The bpf and netns plumbing live in platform-neutral/other modules
//! so a different OS backend could reuse them.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Capturer, PacketHeader, PacketSink};
use crate::bpf::{self, Program};
use crate::config::{bpf_filter_exclude_task_output_hosts, LibpcapConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::netns;
use crate::netutil::bpf_filter_replace_nic;
use crate::packet::PKT_DIR_NONCHECK;
use crate::req_pattern::ReqPattern;
use crate::stats::CaptureStats;

const DROP_STAT_DUR_SEC: i64 = 2;
/// Idle wait (ms) for `timeout_ms = 0`; see [`readability_wait_ms`].
const IDLE_POLL_MS: i32 = 1;
const ETH_P_ALL: u16 = 0x0003;
/// `SOL_PACKET` option (Linux >= 4.17) that makes the kernel drop outgoing
/// (`PACKET_OUTGOING`) copies.
const PACKET_IGNORE_OUTGOING: i32 = 23;
/// `sll_pkttype` value of a locally transmitted copy.
const PACKET_OUTGOING: u8 = 4;
const DEFAULT_VLAN_TPID: u16 = 0x8100;
/// Ethernet header (`dst` + `src` + ethertype) length; VLAN is inserted after
/// the 12 address bytes.
const ETH_HDR_MIN: usize = 14;
const VLAN_HDR_LEN: usize = 4;

#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

/// `struct tpacket_auxdata` (`linux/if_packet.h`).
#[repr(C)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

/// Control-message buffer aligned for `struct cmsghdr`: the kernel fills it with
/// `cmsghdr`s whose length/level/type fields are read through a reference, which
/// must be aligned (a plain `[u8; N]` on the stack is only 1-byte aligned).
#[repr(C, align(8))]
struct CmsgBuf([u8; 256]);

#[derive(Clone, Copy)]
struct VlanTag {
    tci: u16,
    tpid: u16,
}

struct RecvMeta {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
    /// A stripped 802.1Q tag to reinsert after filtering.
    vlan: Option<VlanTag>,
    /// `sockaddr_ll.sll_pkttype` (`PACKET_OUTGOING` for a transmitted copy).
    pkt_type: u8,
}

/// Accumulates `PACKET_STATISTICS` drops on the 2-second cadence.
///
/// Linux `getsockopt(PACKET_STATISTICS)` is **read-cleared**: it returns the
/// counters accumulated since the previous read and resets them. Each sample is
/// therefore a delta that must be added directly; the first read is discarded as
/// a baseline. (Treating it as a cumulative counter and subtracting produced
/// ~4.29e9 bogus drop counts whenever a window had fewer drops than the last.)
#[derive(Default)]
struct DropCounter {
    started: bool,
    prev_time: i64,
}

impl DropCounter {
    fn due(&self, now: i64) -> bool {
        !self.started || now - self.prev_time >= DROP_STAT_DUR_SEC
    }

    /// Feed one sample at time `now`, returning the packets to account.
    fn update(&mut self, now: i64, sample: Option<u32>) -> u64 {
        let baseline = !self.started;
        self.started = true;
        self.prev_time = now;
        if baseline {
            return 0;
        }
        sample.map_or(0, u64::from)
    }
}

/// Exponential backoff for *hard* `recvmsg` errors: 1ms, doubling, capped at 100ms.
///
/// A down interface makes `recvmsg` fail immediately (`ENETDOWN`, or `ENODEV` once
/// the device is gone) instead of returning `EAGAIN`, so there is nothing to wait
/// for - and with the default `timeout_ms = 0` there is no `poll` either. Measured
/// on a dedicated veth pair with the repository's default configuration: 0.65s of
/// CPU per 6s of wall clock (≈10.8% of one core) for a single idle task that
/// cannot possibly receive anything, scaling linearly with the number of tasks on
/// down interfaces. `Ok(..)` resets it, so a recovering interface goes back to full
/// speed on the first success.
#[derive(Default)]
struct ErrorBackoff {
    current: Option<Duration>,
}

impl ErrorBackoff {
    /// Smallest wait, taken on the first error.
    const MIN: Duration = Duration::from_millis(1);
    /// Largest wait; also the worst-case extra latency on shutdown for one task.
    const MAX: Duration = Duration::from_millis(100);

    /// Account one consecutive error and return how long to wait.
    fn on_error(&mut self) -> Duration {
        let wait = match self.current {
            None => Self::MIN,
            Some(cur) => (cur * 2).min(Self::MAX),
        };
        self.current = Some(wait);
        wait
    }

    /// A successful socket operation: drop out of backoff.
    fn reset(&mut self) {
        self.current = None;
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn interface_index(name: &str) -> Result<u32> {
    let cname = CString::new(name).map_err(|_| Error::new("invalid interface name"))?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(Error::new(format!(
            "unknown interface '{name}': {}",
            errno()
        )));
    }
    Ok(idx)
}

fn setsockopt_i32(fd: RawFd, level: i32, name: i32, val: i32) -> std::io::Result<()> {
    // SAFETY: `val` is a valid `i32` of the given size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(val).cast::<libc::c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Request `requested` bytes of receive buffer, preferring `SO_RCVBUFFORCE`
/// (needs `CAP_NET_ADMIN`), then read the value back and warn if the kernel
/// silently clamped it (to `net.core.rmem_max`).
fn set_rcvbuf(fd: RawFd, requested: i32) {
    let force = setsockopt_i32(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, requested);
    if force.is_err() {
        if let Err(e) = setsockopt_i32(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, requested) {
            crate::log_warn!("set SO_RCVBUF({requested}) error: {e}");
            return;
        }
    }
    let mut applied: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: valid pointer/size for SO_RCVBUF.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of_mut!(applied).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        crate::log_warn!("read back SO_RCVBUF error: {}", errno());
    } else if applied < requested {
        crate::log_warn!(
            "SO_RCVBUF applied {applied} < requested {requested} (limited by net.core.rmem_max; \
             SO_RCVBUFFORCE needs CAP_NET_ADMIN)"
        );
    } else {
        crate::log_info!("SO_RCVBUF={applied}");
    }
}

/// Create the capture socket with protocol 0. Packets only start flowing after
/// `bind(ETH_P_ALL, ifindex)`, which lets us attach the BPF filter first and
/// avoids an unfiltered window (P5-09).
fn create_socket() -> Result<OwnedFd> {
    // SAFETY: plain socket(2) call.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::new(format!("socket(AF_PACKET) error: {}", errno())));
    }
    // SAFETY: `raw` is a fresh fd we own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Whether `name` is a loopback interface (`IFF_LOOPBACK`).
fn interface_is_loopback(name: &str) -> bool {
    use nix::net::if_::InterfaceFlags;
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifa in addrs {
            if ifa.interface_name == name {
                return ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK);
            }
        }
    }
    false
}

/// Configure the socket receive buffer, timestamps, VLAN auxdata and the
/// loopback outgoing-frame policy. The BPF filter and the bind happen separately
/// so the filter is installed before the bind (no unfiltered startup window).
///
/// Returns `true` when outgoing (`PACKET_OUTGOING`) frames must still be dropped
/// in userspace (loopback with no `PACKET_IGNORE_OUTGOING` support).
fn configure_socket(fd: RawFd, buffer_size: i32, interface: &str) -> bool {
    set_rcvbuf(fd, buffer_size);
    if let Err(e) = setsockopt_i32(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1) {
        crate::log_warn!(
            "enable SO_TIMESTAMPNS failed: {e}; timestamps will fall back to wall clock"
        );
    }
    if let Err(e) = setsockopt_i32(fd, libc::SOL_PACKET, libc::PACKET_AUXDATA, 1) {
        crate::log_warn!("enable PACKET_AUXDATA failed: {e}; VLAN tags may be missing");
    }

    // On loopback the kernel delivers each frame twice: once as the transmitted
    // copy (`PACKET_OUTGOING`) and once as the received copy (`PACKET_HOST`).
    // libpcap/tcpdump deliver only the received copy there (measured: 1x), while
    // a plain `recvmsg` socket sees 2x, so request the kernel to drop outgoing
    // copies. On any other interface the outgoing copy is *not* a duplicate (it
    // is the only copy on the sending side and libpcap delivers it too), so it is
    // left intact.
    if interface_is_loopback(interface) {
        match setsockopt_i32(fd, libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, 1) {
            Ok(()) => {
                crate::log_info!(
                    "loopback interface: dropping duplicate outgoing frames (PACKET_IGNORE_OUTGOING)"
                );
                return false;
            }
            Err(e) => {
                crate::log_warn!(
                    "PACKET_IGNORE_OUTGOING unavailable ({e}); dropping outgoing frames in userspace"
                );
                return true;
            }
        }
    }
    false
}

/// How long `capture_once` may wait for readability after an empty read.
///
/// `timeout_ms > 0` is honoured as before. `timeout_ms == 0` - the repository
/// default - used to mean "return immediately", i.e. the main loop came back
/// ~100k times/s doing `recvmsg`+10µs sleep and burned ~22% of one core per
/// *idle or down* task (measured, see `PARITY.md §2.6`). Waiting up to
/// [`IDLE_POLL_MS`] changes no capture semantics: `poll` wakes the instant a
/// frame is queued, so there is no added latency and no throughput cost when
/// traffic flows (the wait is only entered after an empty read).
fn readability_wait_ms(timeout_ms: i32) -> i32 {
    if timeout_ms > 0 {
        timeout_ms
    } else {
        IDLE_POLL_MS
    }
}

/// The line logged when a filter program has to run here instead of in the kernel.
///
/// One stable, greppable token with the instruction count, because this fallback
/// is invisible to every counter the worker publishes: `drop_packets` stays 0 and
/// the task keeps capturing while the interpreter walks `insns` instructions per
/// frame (AUDIT4 P2-9 - a DNS name with many A/AAAA answers, a long config-supplied
/// filter or a CPM task update can all get here). Operators need something to alert
/// on, so the count is in the message twice: once as a field, once as prose.
fn userspace_fallback_warning(insns: usize) -> String {
    format!(
        "bpf_userspace_fallback insns={insns} limit={} kernel=BPF_MAXINSNS: filtering in \
         userspace, {insns} cBPF instructions are interpreted for every frame",
        bpf::BPF_MAXINSNS
    )
}

/// Bind the socket to `interface` with `ETH_P_ALL`.
fn bind_socket(fd: RawFd, interface: &str) -> Result<()> {
    let ifindex = i32::try_from(interface_index(interface)?).unwrap_or(i32::MAX);
    // SAFETY: zeroed sockaddr_ll is a valid initial state.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_ALL.to_be();
    sll.sll_ifindex = ifindex;
    // SAFETY: `sll` is fully initialized above.
    let rc = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(sll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::new(format!(
            "bind AF_PACKET to {interface} error: {}",
            errno()
        )));
    }
    Ok(())
}

/// Reinsert a stripped 802.1Q header after the 12 MAC bytes.
///
/// `snaplen` is the contract the configuration makes to the user ("never more
/// than `snaplen` bytes per packet") and, like libpcap, the reinserted tag
/// **counts towards** it: a frame that was truncated to `snaplen` on the wire
/// stays `snaplen` bytes long after the tag goes back, i.e. the last four bytes
/// that the tag pushes past the limit are not reported. (`tcpdump -s 16` on an
/// 802.1Q frame gives `caplen == 16`, not 20.)
///
/// Returns `Some(new_caplen)` (`<= snaplen`) when the tag was reinserted, or
/// `None` when it was not - because the captured prefix is too short to carry an
/// Ethernet header, or `buf` has no room. Callers must only grow `orig_len` for
/// the four tag bytes when this returns `Some`, since the wire frame did carry
/// the tag either way.
fn insert_vlan(buf: &mut [u8], caplen: usize, tag: VlanTag, snaplen: usize) -> Option<usize> {
    if caplen < ETH_HDR_MIN || buf.len() < caplen + VLAN_HDR_LEN {
        return None;
    }
    buf.copy_within(12..caplen, 12 + VLAN_HDR_LEN);
    buf[12..14].copy_from_slice(&tag.tpid.to_be_bytes());
    buf[14..16].copy_from_slice(&tag.tci.to_be_bytes());
    Some((caplen + VLAN_HDR_LEN).min(snaplen))
}

/// Walk the control messages of a filled `msghdr`, returning the
/// `SCM_TIMESTAMPNS` timestamp and any `PACKET_AUXDATA` VLAN tag.
///
/// # Safety
/// `msg` must come from a `recvmsg` call whose `msg_control` buffer is valid for
/// `msg_controllen` bytes.
unsafe fn parse_control(msg: &libc::msghdr) -> (Option<(i64, i64)>, Option<VlanTag>) {
    let mut ts = None;
    let mut vlan = None;
    let align = std::mem::align_of::<libc::cmsghdr>();
    let header = (std::mem::size_of::<libc::cmsghdr>() + align - 1) & !(align - 1);
    let start = msg.msg_control as *const u8;
    let end = start.add(msg.msg_controllen);
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() && (cmsg as *const u8) < end {
        let c = &*cmsg;
        let clen = c.cmsg_len;
        if clen < header {
            break;
        }
        let data = libc::CMSG_DATA(cmsg);
        let dlen = clen - header;
        if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SO_TIMESTAMPNS && dlen >= 16 {
            let t = std::ptr::read_unaligned(data as *const libc::timespec);
            ts = Some((t.tv_sec as i64, (t.tv_nsec / 1000) as i64));
        } else if c.cmsg_level == libc::SOL_PACKET
            && c.cmsg_type == libc::PACKET_AUXDATA
            && dlen >= std::mem::size_of::<TpacketAuxdata>()
        {
            let a = std::ptr::read_unaligned(data as *const TpacketAuxdata);
            if a.tp_status & libc::TP_STATUS_VLAN_VALID != 0 {
                let tpid = if a.tp_status & libc::TP_STATUS_VLAN_TPID_VALID != 0 {
                    a.tp_vlan_tpid
                } else {
                    DEFAULT_VLAN_TPID
                };
                vlan = Some(VlanTag {
                    tci: a.tp_vlan_tci,
                    tpid,
                });
            }
        }
        let step = (clen + align - 1) & !(align - 1);
        if step == 0 {
            break;
        }
        let next = (cmsg as *const u8).add(step) as *mut libc::cmsghdr;
        if next as *const u8 >= end {
            break;
        }
        cmsg = next;
    }
    (ts, vlan)
}

/// Live capture from a network interface via `AF_PACKET`.
pub struct AfPacketCapturer {
    stats: Arc<CaptureStats>,
    fd: OwnedFd,
    interface: String,
    netns_path: String,
    req_pattern: Option<ReqPattern>,
    snaplen: usize,
    timeout_ms: i32,
    /// Frame buffer; `snaplen` usable bytes plus 4 spare for VLAN reinsertion.
    buf: Vec<u8>,
    /// Set when the BPF program could not be installed in the kernel (program
    /// too long, or `SO_ATTACH_FILTER` failed); the frames are then filtered
    /// here instead. This mirrors libpcap's fallback to userspace filtering.
    userspace_filter: Option<Program>,
    /// Drop `PACKET_OUTGOING` frames in userspace (loopback without kernel
    /// `PACKET_IGNORE_OUTGOING` support).
    drop_outgoing: bool,

    drops: DropCounter,
    backoff: ErrorBackoff,
    next_error: Option<String>,
    last_error_log: i64,
}

impl AfPacketCapturer {
    /// Open the capture interface (optionally inside a netns).
    ///
    /// # Errors
    /// Returns an error if the netns cannot be entered, the socket cannot be
    /// opened/bound, or the BPF filter fails to compile or attach.
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
        if has_netns {
            netns::enter_netns_by_path(&cfg.netns)?;
        }

        let result = Self::open(tasks, task, cfg, stats);

        if let Some(ns) = self_netns.as_ref() {
            if let Err(e) = netns::enter_netns_by_fd(ns) {
                crate::log_error!("restore netns fail: {e}");
            }
        }
        result
    }

    fn open(
        tasks: &[TaskConfig],
        task: &TaskConfig,
        cfg: &LibpcapConfig,
        stats: Arc<CaptureStats>,
    ) -> Result<Self> {
        let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, &cfg.interface)
            .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

        let bpf_expr = if !cfg.not_filter_output_hosts {
            crate::log_info!("exclude task output hosts");
            bpf_filter_exclude_task_output_hosts(&cfg.bpf, tasks)
        } else {
            cfg.bpf.clone()
        };
        let bpf_expr = if bpf_expr.is_empty() {
            String::new()
        } else {
            bpf_filter_replace_nic(&bpf_expr)?
        };
        let program: Option<Program> =
            if bpf_expr.is_empty() {
                None
            } else {
                Some(bpf::compile(&bpf_expr).map_err(|e| {
                    Error::new(format!("compile bpf filter '{bpf_expr}' error: {e}"))
                })?)
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

        let fd = create_socket()?;
        let drop_outgoing = configure_socket(fd.as_raw_fd(), buffer_size, &cfg.interface);

        // Install the filter in the kernel when possible (before the bind, so no
        // unfiltered packet slips in). A program over the kernel's instruction
        // limit, or any attach failure (e.g. ENOMEM from optmem_max), falls back
        // to filtering in userspace so the task still captures correctly.
        let userspace_filter = match program {
            None => None,
            Some(p) if p.insns.len() <= bpf::BPF_MAXINSNS => {
                match bpf::attach_filter(fd.as_raw_fd(), &p) {
                    Ok(()) => None,
                    Err(e) => {
                        crate::log_warn!(
                            "attach bpf filter failed ({e}); {}",
                            userspace_fallback_warning(p.insns.len())
                        );
                        Some(p)
                    }
                }
            }
            Some(p) => {
                crate::log_warn!("{}", userspace_fallback_warning(p.insns.len()));
                Some(p)
            }
        };

        bind_socket(fd.as_raw_fd(), &cfg.interface)?;

        let snaplen = cfg.snaplen.max(1) as usize;
        Ok(AfPacketCapturer {
            stats,
            fd,
            interface: cfg.interface.clone(),
            netns_path: cfg.netns.clone(),
            req_pattern: Some(req_pattern),
            snaplen,
            timeout_ms: cfg.timeout_ms,
            buf: vec![0u8; snaplen + VLAN_HDR_LEN],
            userspace_filter,
            drop_outgoing,
            drops: DropCounter::default(),
            backoff: ErrorBackoff::default(),
            next_error: None,
            last_error_log: 0,
        })
    }

    /// Receive one frame into `self.buf`; `Ok(None)` means "would block".
    fn recv_into_buf(&mut self) -> std::io::Result<Option<RecvMeta>> {
        let mut iov = libc::iovec {
            iov_base: self.buf.as_mut_ptr().cast::<libc::c_void>(),
            // Never read more than `snaplen` from the wire; the extra 4 bytes of
            // `buf` are reserved for VLAN reinsertion.
            iov_len: self.snaplen,
        };
        let mut cmsg = CmsgBuf([0u8; 256]);
        // SAFETY: zeroed msghdr/sockaddr_ll are valid starting states.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = std::ptr::addr_of_mut!(sll).cast::<libc::c_void>();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.0.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg.0.len();
        // SAFETY: `msg` points at `iov`/`cmsg`, both alive for the call.
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_TRUNC) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => return Ok(None),
                _ => return Err(e),
            }
        }
        let len = n as u32;
        let caplen = len.min(self.snaplen as u32);

        // SAFETY: `msg` was filled by recvmsg above.
        let (ts, vlan) = unsafe { parse_control(&msg) };
        let pkt_type = if msg.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_ll>() {
            sll.sll_pkttype
        } else {
            0
        };
        let (ts_sec, ts_usec) = ts.unwrap_or_else(|| (now_sec(), 0));
        Ok(Some(RecvMeta {
            ts_sec,
            ts_usec,
            caplen,
            len,
            vlan,
            pkt_type,
        }))
    }

    /// Receive the next frame that passes the filter (kernel or userspace),
    /// reinserting any stripped VLAN tag. `Ok(None)` means "would block".
    fn recv_matching(&mut self) -> std::io::Result<Option<RecvMeta>> {
        loop {
            let Some(mut meta) = self.recv_into_buf()? else {
                return Ok(None);
            };
            // Userspace fallback for the loopback outgoing copy (when the kernel
            // has no PACKET_IGNORE_OUTGOING).
            if self.drop_outgoing && meta.pkt_type == PACKET_OUTGOING {
                continue;
            }
            // Userspace fallback: apply the compiled program to the frame the
            // way the kernel would have, i.e. *before* the VLAN tag is put back.
            let matched = self
                .userspace_filter
                .as_ref()
                .is_none_or(|p| p.apply(&self.buf[..meta.caplen as usize]));
            if !matched {
                continue;
            }
            if let Some(v) = meta.vlan {
                if let Some(new_caplen) =
                    insert_vlan(&mut self.buf, meta.caplen as usize, v, self.snaplen)
                {
                    meta.caplen = new_caplen as u32;
                    // The on-wire frame carried the tag, so the original length
                    // grows by it even when `caplen` was clamped to `snaplen`.
                    meta.len += VLAN_HDR_LEN as u32;
                }
            }
            return Ok(Some(meta));
        }
    }

    fn read_stats(&self) -> Option<u32> {
        let mut st = TpacketStats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        // SAFETY: valid pointer/size for PACKET_STATISTICS.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                std::ptr::addr_of_mut!(st).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc == 0 {
            Some(st.tp_drops)
        } else {
            None
        }
    }

    fn update_drop_stats(&mut self, now: i64) {
        if !self.drops.due(now) {
            return;
        }
        let sample = self.read_stats();
        let add = self.drops.update(now, sample);
        self.stats.drop_packets.add(add);
    }
}

impl Capturer for AfPacketCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        // Try to receive first (the socket is always non-blocking); only when it
        // would block do we wait for readability.
        let mut res = self.recv_matching();
        if matches!(res, Ok(None)) {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: single valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, readability_wait_ms(self.timeout_ms)) };
            if r > 0 && (pfd.revents & libc::POLLIN) != 0 {
                res = self.recv_matching();
            }
        }

        let mut num_pkts = 0u64;
        let now;
        match res {
            Ok(Some(meta)) => {
                self.backoff.reset();
                let hdr = PacketHeader {
                    ts_sec: meta.ts_sec,
                    ts_usec: meta.ts_usec,
                    caplen: meta.caplen,
                    len: meta.len,
                };
                let caplen = meta.caplen as usize;
                let direction = match &self.req_pattern {
                    None => PKT_DIR_NONCHECK,
                    Some(rp) => rp.judge_pkt_direction(&self.buf[..caplen]),
                };
                self.stats.cap_bytes.add(u64::from(meta.caplen));
                self.stats.cap_packets.add(1);
                sink.on_packet(&hdr, &self.buf[..caplen], direction);
                num_pkts = 1;
                now = meta.ts_sec;
            }
            Ok(None) => {
                // The socket works, it just has nothing: leave backoff (the
                // throughput-critical `timeout_ms = 0` path must not slow down).
                self.backoff.reset();
                sink.on_heartbeat();
                now = now_sec();
            }
            Err(e) => {
                if self.next_error.is_none() {
                    self.next_error = Some(format!(
                        "interface={}, netns={}, recvmsg error: {e}",
                        self.interface, self.netns_path
                    ));
                }
                // Hard errors return immediately; without this wait the task spins
                // a core for as long as the interface stays down (AUDIT4 P5-12 /
                // P2-6). C does not have this problem because `pcap_activate` fails
                // and the task is never created - see PARITY.md §2.6.
                std::thread::sleep(self.backoff.on_error());
                now = now_sec();
            }
        }

        self.update_drop_stats(now);

        // Rate-limit persistent errors to the drop-stat cadence (the C version
        // gates its logging the same way) to avoid a log flood / busy loop when
        // the interface goes away.
        if let Some(err) = self.next_error.take() {
            if now - self.last_error_log >= DROP_STAT_DUR_SEC {
                crate::log_error!("{err}");
                self.last_error_log = now;
            }
        }
        num_pkts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_counter_adds_read_cleared_samples() {
        // Regression for the read-cleared PACKET_STATISTICS semantics: a window
        // with fewer drops than the previous one must NOT wrap (the old code
        // subtracted and produced ~4.29e9).
        let mut c = DropCounter::default();
        assert_eq!(c.update(1000, Some(7)), 0); // baseline (clears kernel counter)
        assert_eq!(c.update(1002, Some(5)), 5);
        assert_eq!(c.update(1004, Some(0)), 0);
        assert_eq!(c.update(1006, Some(9)), 9);
    }

    /// AUDIT4 P2-9: the userspace filter fallback is invisible to every published
    /// counter (`drop_packets` stays 0 while the task slows down), so the only
    /// thing an operator can alert on is this line - it must carry the token and
    /// the per-frame instruction count.
    #[test]
    fn userspace_fallback_warning_carries_the_instruction_count() {
        let w = userspace_fallback_warning(4531);
        assert!(
            w.contains("bpf_userspace_fallback"),
            "must keep the stable alert token: {w}"
        );
        assert!(w.contains("insns=4531"), "must report the count: {w}");
        assert!(
            w.contains(&format!("limit={}", bpf::BPF_MAXINSNS)),
            "must report the kernel limit: {w}"
        );
    }

    #[test]
    fn loopback_interface_detection() {
        assert!(interface_is_loopback("lo"));
        assert!(!interface_is_loopback("definitely-not-a-real-iface0"));
    }

    /// AUDIT4 P5-12/P2-6: the acceptance criterion is "no busy loop while the
    /// interface is down". The backoff must start small (a flapping interface should
    /// not become sluggish), grow, saturate at 100ms, and reset on the first
    /// successful socket operation.
    /// AUDIT4 P2-6: the "no busy loop" acceptance criterion is about the *idle*
    /// socket too - `timeout_ms = 0` is the default, and returning immediately on
    /// an empty read spun a core (measured 22% with a down *or* an idle-up veth).
    #[test]
    fn empty_read_always_waits_for_readability() {
        assert_eq!(
            readability_wait_ms(0),
            IDLE_POLL_MS,
            "default must not spin"
        );
        assert_eq!(readability_wait_ms(200), 200, "configured timeout honoured");
        assert_eq!(
            readability_wait_ms(-1),
            IDLE_POLL_MS,
            "nonsense falls back to idle"
        );
        assert!(
            IDLE_POLL_MS <= 5,
            "the idle wait must stay well below packet-scale latency"
        );
    }

    #[test]
    fn hard_error_backoff_grows_saturates_and_resets() {
        let mut b = ErrorBackoff::default();
        assert_eq!(b.on_error(), Duration::from_millis(1));
        assert_eq!(b.on_error(), Duration::from_millis(2));
        assert_eq!(b.on_error(), Duration::from_millis(4));
        for _ in 0..12 {
            assert!(
                b.on_error() <= ErrorBackoff::MAX,
                "backoff must never exceed the cap"
            );
        }
        assert_eq!(b.on_error(), ErrorBackoff::MAX);
        b.reset();
        assert_eq!(b.on_error(), Duration::from_millis(1), "must start over");
    }

    #[test]
    fn drop_counter_cadence() {
        let mut c = DropCounter::default();
        assert!(c.due(1000));
        c.update(1000, Some(1));
        assert!(!c.due(1001));
        assert!(c.due(1002));
    }

    #[test]
    fn insert_vlan_reinserts_after_macs() {
        // dst(6) src(6) ethertype(2) payload(4)
        let mut buf = vec![0xaa; 18 + VLAN_HDR_LEN];
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        buf[14..18].copy_from_slice(&[1, 2, 3, 4]);
        let n = insert_vlan(
            &mut buf,
            18,
            VlanTag {
                tci: 0x0164,
                tpid: 0x8100,
            },
            65535,
        );
        assert_eq!(n, Some(22));
        assert_eq!(&buf[12..14], &[0x81, 0x00]);
        assert_eq!(&buf[14..16], &[0x01, 0x64]);
        assert_eq!(&buf[16..18], &[0x08, 0x00]);
        assert_eq!(&buf[18..22], &[1, 2, 3, 4]);
    }

    /// Regression for AUDIT4 P2-7 (independent review): with `snaplen: 16` and a
    /// 60-byte 802.1Q frame the capturer used to report `caplen = snaplen + 4`,
    /// breaking the per-packet contract the configuration makes (and making the
    /// capture file byte-incomparable with `tcpdump -s 16`, which reports 16).
    #[test]
    fn insert_vlan_truncated_frame_stays_within_snaplen() {
        let snaplen = 16usize;
        // `buf` is exactly what the capturer allocates: snaplen + 4 spare.
        let mut buf = vec![0u8; snaplen + VLAN_HDR_LEN];
        buf[12..14].copy_from_slice(&[0x08, 0x00]); // ethertype, as read off the wire
        buf[14..snaplen].copy_from_slice(&[1, 2]);
        let n = insert_vlan(
            &mut buf,
            snaplen,
            VlanTag {
                tci: 0x0164,
                tpid: 0x8100,
            },
            snaplen,
        )
        .expect("a snaplen-long prefix has room for the tag");
        assert!(
            n <= snaplen,
            "caplen {n} broke the 'never more than snaplen ({snaplen})' contract"
        );
        assert_eq!(n, snaplen, "must report exactly snaplen bytes");
        // What is reported is the *first `snaplen` bytes of the reinserted frame*.
        assert_eq!(&buf[12..14], &[0x81, 0x00]);
        assert_eq!(&buf[14..16], &[0x01, 0x64]);
        // The ethertype the wire put at offset 12 was pushed to 16, i.e. past the
        // reported prefix - that is the byte count libpcap drops, not reports.
        assert_eq!(&buf[16..18], &[0x08, 0x00]);
    }

    /// A prefix too short to hold an Ethernet header gets no tag, so the caller
    /// must not grow `orig_len` either.
    #[test]
    fn insert_vlan_refuses_prefix_without_ethernet_header() {
        let mut buf = vec![0u8; 8 + VLAN_HDR_LEN];
        assert_eq!(
            insert_vlan(
                &mut buf,
                8,
                VlanTag {
                    tci: 1,
                    tpid: 0x8100,
                },
                65535,
            ),
            None
        );
    }

    #[test]
    fn parse_control_reads_timestamp_and_vlan() {
        let header = (std::mem::size_of::<libc::cmsghdr>() + 7) & !7;
        let ts_len = header + 16;
        let aux_len = header + std::mem::size_of::<TpacketAuxdata>();
        let aux_off = ts_len;
        let total = aux_off + ((aux_len + 7) & !7);
        let mut cbuf = vec![0u8; total];

        // SCM_TIMESTAMPNS
        cbuf[0..8].copy_from_slice(&(ts_len as u64).to_ne_bytes());
        cbuf[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        cbuf[12..16].copy_from_slice(&libc::SO_TIMESTAMPNS.to_ne_bytes());
        cbuf[16..24].copy_from_slice(&1234i64.to_ne_bytes());
        cbuf[24..32].copy_from_slice(&500_000_000i64.to_ne_bytes());

        // PACKET_AUXDATA
        cbuf[aux_off..aux_off + 8].copy_from_slice(&(aux_len as u64).to_ne_bytes());
        cbuf[aux_off + 8..aux_off + 12].copy_from_slice(&libc::SOL_PACKET.to_ne_bytes());
        cbuf[aux_off + 12..aux_off + 16].copy_from_slice(&libc::PACKET_AUXDATA.to_ne_bytes());
        let d = aux_off + 16;
        let status = libc::TP_STATUS_VLAN_VALID | libc::TP_STATUS_VLAN_TPID_VALID;
        cbuf[d..d + 4].copy_from_slice(&status.to_ne_bytes());
        cbuf[d + 16..d + 18].copy_from_slice(&0x0164u16.to_ne_bytes()); // tci
        cbuf[d + 18..d + 20].copy_from_slice(&0x88a8u16.to_ne_bytes()); // tpid

        // SAFETY: cbuf is laid out as a well-formed control message buffer.
        let msg = unsafe {
            let mut m: libc::msghdr = std::mem::zeroed();
            m.msg_control = cbuf.as_mut_ptr().cast::<libc::c_void>();
            m.msg_controllen = total;
            m
        };
        // SAFETY: msg points at cbuf for `total` bytes.
        let (ts, vlan) = unsafe { parse_control(&msg) };
        assert_eq!(ts, Some((1234, 500_000)));
        let v = vlan.expect("vlan tag");
        assert_eq!(v.tci, 0x0164);
        assert_eq!(v.tpid, 0x88a8);
    }
}
