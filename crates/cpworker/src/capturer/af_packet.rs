//! `AF_PACKET` live capturer (Linux). Replaces the libpcap live capturer.
//!
//! Uses a `SOCK_RAW` `AF_PACKET` socket bound to the configured interface, a
//! large `SO_RCVBUF`, kernel `SO_TIMESTAMPNS` timestamps, a classic-BPF program
//! attached with `SO_ATTACH_FILTER`, and `PACKET_STATISTICS` for drop counters.
//! The bpf and netns plumbing live in platform-neutral/other modules so a
//! different OS backend could reuse them.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

struct RecvMeta {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
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

fn open_socket(interface: &str, buffer_size: i32, nonblock: bool) -> Result<OwnedFd> {
    let mut flags = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
    if nonblock {
        flags |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: plain socket(2) call.
    let raw = unsafe { libc::socket(libc::AF_PACKET, flags, i32::from(ETH_P_ALL.to_be())) };
    if raw < 0 {
        return Err(Error::new(format!("socket(AF_PACKET) error: {}", errno())));
    }
    // SAFETY: `raw` is a fresh fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let sz: i32 = buffer_size;
    // SAFETY: valid pointer/size for SO_RCVBUF.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(sz).cast::<libc::c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        crate::log_warn!("set SO_RCVBUF({buffer_size}) error: {}", errno());
    }

    let ifindex = i32::try_from(interface_index(interface)?).unwrap_or(i32::MAX);
    // SAFETY: zeroed sockaddr_ll is a valid initial state.
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_ALL.to_be();
    sll.sll_ifindex = ifindex;
    // SAFETY: `sll` is fully initialized above.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
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

    // Best-effort kernel timestamps; fall back to wall clock if unavailable.
    let one: i32 = 1;
    // SAFETY: valid pointer/size for SO_TIMESTAMPNS.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            std::ptr::addr_of!(one).cast::<libc::c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

/// Parse an `SCM_TIMESTAMPNS` control message, returning `(sec, usec)`.
fn parse_timestamp(cmsg: &[u8]) -> Option<(i64, i64)> {
    let mut off = 0usize;
    while off + 16 <= cmsg.len() {
        let len = u64::from_ne_bytes(cmsg[off..off + 8].try_into().ok()?) as usize;
        let level = i32::from_ne_bytes(cmsg[off + 8..off + 12].try_into().ok()?);
        let typ = i32::from_ne_bytes(cmsg[off + 12..off + 16].try_into().ok()?);
        if len < 16 || off + len > cmsg.len() {
            break;
        }
        if level == libc::SOL_SOCKET && typ == libc::SO_TIMESTAMPNS && len >= 32 {
            let sec = i64::from_ne_bytes(cmsg[off + 16..off + 24].try_into().ok()?);
            let nsec = i64::from_ne_bytes(cmsg[off + 24..off + 32].try_into().ok()?);
            return Some((sec, nsec / 1000));
        }
        let aligned = (len + 7) & !7;
        if aligned == 0 {
            break;
        }
        off += aligned;
    }
    None
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
    buf: Vec<u8>,

    drop_stat_started: bool,
    drop_stat_prev_time: i64,
    prev_ps_drop: u32,
    prev_ps_ifdrop: u32,
    next_error: Option<String>,
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

        let nonblock = cfg.timeout_ms <= 0;
        let fd = open_socket(&cfg.interface, buffer_size, nonblock)?;
        if let Some(p) = program.as_ref() {
            bpf::attach_filter(fd.as_raw_fd(), p)
                .map_err(|e| Error::new(format!("attach bpf filter error: {e}")))?;
        }

        let snaplen = cfg.snaplen.max(1) as usize;
        Ok(AfPacketCapturer {
            stats,
            fd,
            interface: cfg.interface.clone(),
            netns_path: cfg.netns.clone(),
            req_pattern: Some(req_pattern),
            snaplen,
            timeout_ms: cfg.timeout_ms,
            buf: vec![0u8; snaplen],
            drop_stat_started: false,
            drop_stat_prev_time: 0,
            prev_ps_drop: 0,
            prev_ps_ifdrop: 0,
            next_error: None,
        })
    }

    /// Receive one frame into `self.buf`; `Ok(None)` means "would block".
    fn recv_into_buf(&mut self) -> std::io::Result<Option<RecvMeta>> {
        let mut iov = libc::iovec {
            iov_base: self.buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: self.buf.len(),
        };
        let mut cmsg = [0u8; 64];
        // SAFETY: zeroed msghdr is a valid starting state.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg.len();
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
        let (ts_sec, ts_usec) = parse_timestamp(&cmsg[..msg.msg_controllen.min(cmsg.len())])
            .unwrap_or_else(|| (now_sec(), 0));
        Ok(Some(RecvMeta {
            ts_sec,
            ts_usec,
            caplen,
            len,
        }))
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
        if !self.drop_stat_started {
            if let Some(drop) = self.read_stats() {
                self.drop_stat_started = true;
                self.prev_ps_drop = drop;
                self.prev_ps_ifdrop = 0;
                self.drop_stat_prev_time = now;
            }
            return;
        }
        if now - self.drop_stat_prev_time < DROP_STAT_DUR_SEC {
            return;
        }
        if let Some(drop) = self.read_stats() {
            let drop_diff = drop.wrapping_sub(self.prev_ps_drop);
            self.stats.drop_packets.add(u64::from(drop_diff));
            // Linux does not report interface drops separately; libpcap also
            // returns ps_ifdrop = 0.
            let ifdrop_diff = 0u32.wrapping_sub(self.prev_ps_ifdrop);
            self.stats.ifdrop_packets.add(u64::from(ifdrop_diff));
            self.prev_ps_drop = drop;
            self.prev_ps_ifdrop = 0;
            self.drop_stat_prev_time = now;
        }
    }
}

impl Capturer for AfPacketCapturer {
    fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
        let mut num_pkts = 0u64;
        let now;

        if self.timeout_ms > 0 {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: single valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, self.timeout_ms) };
            if r <= 0 {
                sink.on_heartbeat();
                self.update_drop_stats(now_sec());
                return 0;
            }
        }

        match self.recv_into_buf() {
            Ok(Some(meta)) => {
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
                now = now_sec();
            }
        }

        self.update_drop_stats(now);

        if let Some(err) = self.next_error.take() {
            crate::log_error!("{err}");
        }
        num_pkts
    }
}
