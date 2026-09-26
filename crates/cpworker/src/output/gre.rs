//! GRE output. Port of `output_gre.c`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use super::{Output, PacketHeader};
use crate::config::{GreConfig, OutputConfig, IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_WANT};
use crate::error::{Error, Result};
use crate::packet::{GRE_HDR_LEN, PKT_DIR_UNKNOWN};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

const GRE_OUTPUT_BUFSIZE: usize = 65551;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;

/// Wire-format GRE header used by the GRE output. This is the single source of
/// truth for the 8-byte header (also used by the protocol parity harness).
pub fn gre_header(service_tag: u32, direct: i32) -> [u8; GRE_HDR_LEN] {
    let key = service_tag | ((direct as u32) << 28);
    let mut h = [0u8; GRE_HDR_LEN];
    h[0..2].copy_from_slice(&0x2000u16.to_be_bytes()); // flags: K=1
    h[2..4].copy_from_slice(&0x6558u16.to_be_bytes()); // protocol: Ethernet over GRE
    h[4..8].copy_from_slice(&key.to_be_bytes());
    h
}

#[derive(Default)]
struct ErrorInfo {
    first_pktsec: i64,
    nb_nobufs_drops: u64,
    nb_partial_sends: u64,
    nb_other_send_error_drops: u64,
    other_send_error: String,
}

pub struct GreOutput {
    stats: Arc<OutputStats>,
    rate_limit_mbps: u64,
    throttle: Option<TokenBucket>,
    slice: i32,
    service_tag: u32,
    remote_addr: SocketAddrV4,
    socket: Socket,
    buf: Vec<u8>,
    error_info: ErrorInfo,
}

fn set_bind_device(socket: &Socket, device: &str) -> std::io::Result<()> {
    // SO_BINDTODEVICE = 25 on Linux.
    let cdev = std::ffi::CString::new(device).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_device contains a NUL byte",
        )
    })?;
    let ret = unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            libc::SOL_SOCKET,
            25,
            cdev.as_ptr() as *const libc::c_void,
            (device.len() + 1) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_pmtudisc(socket: &Socket, pmtudisc: i32) -> std::io::Result<()> {
    // IP_MTU_DISCOVER = 10 on Linux.
    let ret = unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            libc::IPPROTO_IP,
            10,
            &pmtudisc as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl GreOutput {
    pub fn new(cfg: &GreConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let addr: Ipv4Addr = cfg
            .host
            .parse()
            .map_err(|_| Error::new(format!("invalid gre host: {}", cfg.host)))?;
        let remote_addr = SocketAddrV4::new(addr, 0);

        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_GRE)),
        )
        .map_err(|e| Error::new(format!("create socket error: {e}")))?;

        if !cfg.bind_device.is_empty() {
            set_bind_device(&socket, &cfg.bind_device).map_err(|e| {
                Error::new(format!(
                    "set SO_BINDTODEVICE for device {} error: {e}",
                    cfg.bind_device
                ))
            })?;
        }
        if cfg.pmtudisc >= 0 {
            set_pmtudisc(&socket, cfg.pmtudisc)
                .map_err(|e| Error::new(format!("set IP_MTU_DISCOVER error: {e}")))?;
        }

        let throttle = if out.rate_limit_mbps > 0 {
            Some(TokenBucket::new(out.rate_limit_mbps * 1_000_000))
        } else {
            None
        };

        Ok(GreOutput {
            stats,
            rate_limit_mbps: out.rate_limit_mbps,
            throttle,
            slice: out.slice,
            service_tag: cfg.service_tag,
            remote_addr,
            socket,
            buf: vec![0u8; GRE_OUTPUT_BUFSIZE],
            error_info: ErrorInfo::default(),
        })
    }

    fn flush_error_info(&mut self) {
        self.error_info.first_pktsec = 0;
        let e = &mut self.error_info;
        if e.nb_nobufs_drops > 0 || e.nb_partial_sends > 0 || e.nb_other_send_error_drops > 0 {
            crate::log_error!(
                "gre output error: nb_nobufs_drops={}, nb_partial_sends={}, nb_other_send_error_drops={}, detail: {}",
                e.nb_nobufs_drops,
                e.nb_partial_sends,
                e.nb_other_send_error_drops,
                e.other_send_error
            );
            e.nb_nobufs_drops = 0;
            e.nb_partial_sends = 0;
            e.nb_other_send_error_drops = 0;
            e.other_send_error.clear();
        }
    }
}

const ENOBUFS: i32 = 105;

impl Output for GreOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt: &[u8], direct: i32) -> i32 {
        let mut caplen = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < caplen {
            caplen = self.slice as u32;
        }
        let length = caplen.min(65535) as usize;

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(length as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        if self.rate_limit_mbps > 0 {
            let tb = self.throttle.as_mut().unwrap();
            if !tb.consume(GRE_HDR_LEN + length, hdr.ts()) {
                self.stats
                    .ratelimit_drop_bytes
                    .add((GRE_HDR_LEN + length) as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        // GRE header: flags=0x2000 (K=1), protocol=0x6558 (Ethernet over GRE),
        // key = service_tag | (direct << 28), network byte order.
        self.buf[..GRE_HDR_LEN].copy_from_slice(&gre_header(self.service_tag, direct));
        self.buf[GRE_HDR_LEN..GRE_HDR_LEN + length].copy_from_slice(&pkt[..length]);

        if self.error_info.first_pktsec == 0 {
            self.error_info.first_pktsec = hdr.ts_sec;
        } else if hdr.ts_sec > self.error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC {
            self.flush_error_info();
            self.error_info.first_pktsec = hdr.ts_sec;
        }

        let total = GRE_HDR_LEN + length;
        let mut retry = 0;
        loop {
            let addr: SocketAddr = SocketAddr::V4(self.remote_addr);
            match self.socket.send_to(&self.buf[..total], &addr.into()) {
                Ok(sent) => {
                    if sent < total {
                        self.error_info.nb_partial_sends += 1;
                        self.stats.error_drop_bytes.add((total - sent) as u64);
                        self.stats.fwd_bytes.add(sent as u64);
                        self.stats.fwd_packets.add(1);
                        return -1;
                    }
                    self.stats.fwd_bytes.add(total as u64);
                    self.stats.fwd_packets.add(1);
                    return 0;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(ENOBUFS) && retry < 10 {
                        let duration = (100 + retry * 200).min(1000);
                        std::thread::sleep(std::time::Duration::from_micros(duration as u64));
                        retry += 1;
                        continue;
                    }
                    if e.raw_os_error() == Some(ENOBUFS) {
                        self.error_info.nb_nobufs_drops += 1;
                    } else {
                        if self.error_info.nb_other_send_error_drops == 0 {
                            self.error_info.other_send_error = e.to_string();
                        }
                        self.error_info.nb_other_send_error_drops += 1;
                    }
                    self.stats.error_drop_bytes.add(total as u64);
                    self.stats.error_drop_packets.add(1);
                    return -1;
                }
            }
        }
    }
}

/// Ensure the unused constants are referenced (parity with `config.h` values).
#[allow(dead_code)]
fn _pmtudisc_consts() -> [i32; 3] {
    [IP_PMTUDISC_DONT, IP_PMTUDISC_WANT, IP_PMTUDISC_DO]
}
