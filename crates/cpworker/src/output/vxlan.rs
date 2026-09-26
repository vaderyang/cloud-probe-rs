//! VXLAN output. Port of `output_vxlan.c`, including packet splitting.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use super::{Output, PacketHeader};
use crate::config::{OutputConfig, VxlanConfig};
use crate::error::{Error, Result};
use crate::packet::{parse_packet, ETH_HDR_LEN, PKT_DIR_NONCHECK, PKT_DIR_UNKNOWN, VXLAN_HDR_LEN};
use crate::packet_split::{build_fragment, calculate_fragment_count};
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

const VXLAN_OUTPUT_BUFSIZE: usize = 65551;
const ERROR_INFO_FLUSH_MAX_DUR_SEC: i64 = 5;
const ENOBUFS: i32 = 105;

fn set_bind_device(socket: &Socket, device: &str) -> std::io::Result<()> {
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

/// Port of `rte_raw_cksum` (with the 0x4a3b2d1c seed).
fn rte_raw_cksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0x4a3b2d1c;
    let (words, tail) = buf.split_at(buf.len() / 2 * 2);
    for w in words.as_chunks::<2>().0 {
        sum += u16::from_ne_bytes([w[0], w[1]]) as u32;
    }
    if let Some(&b) = tail.first() {
        sum += b as u32;
    }
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum as u16
}

/// Build a VXLAN-encapsulated frame into `buf`, returning the total length.
/// Single source of truth for the VXLAN wire format (also used by the parity
/// harness). `inner` is the Ethernet frame to encapsulate.
pub fn vxlan_encapsulate(
    buf: &mut [u8],
    vni: u32,
    vni_version: u8,
    direct: i32,
    capture_time: bool,
    ts_sec: i64,
    ts_usec: i64,
    inner: &[u8],
) -> usize {
    let mut length = inner.len();
    buf[0..4].copy_from_slice(&0x0800_0000u32.to_be_bytes());
    buf[VXLAN_HDR_LEN..VXLAN_HDR_LEN + length].copy_from_slice(inner);

    if capture_time {
        let tv_sec = (ts_sec as u32).to_be_bytes();
        let tv_nsec = ((ts_usec as u32) * 1000).to_be_bytes();
        buf[VXLAN_HDR_LEN + length..VXLAN_HDR_LEN + length + 4].copy_from_slice(&tv_sec);
        length += 4;
        buf[VXLAN_HDR_LEN + length..VXLAN_HDR_LEN + length + 4].copy_from_slice(&tv_nsec);
        length += 4;
    }

    if vni_version == 1 {
        let mut vni_bytes = (vni << 8).to_be_bytes();
        if direct != PKT_DIR_NONCHECK {
            vni_bytes[0] = ((direct as u8) & 0x0f) << 4;
            vni_bytes[1] &= 0x0f;
            vni_bytes[3] = 0;
        }
        buf[4..8].copy_from_slice(&vni_bytes);
        // Checksum covering VXLAN + Ethernet + IPv4 headers.
        let check = rte_raw_cksum(&buf[..VXLAN_HDR_LEN + ETH_HDR_LEN + 20]);
        buf[7] = check as u8;
    } else {
        let v = vni.wrapping_add(direct as u32);
        buf[4..8].copy_from_slice(&v.to_be_bytes());
    }

    VXLAN_HDR_LEN + length
}

#[derive(Default)]
struct ErrorInfo {
    first_pktsec: i64,
    nb_nobufs_drops: u64,
    nb_partial_sends: u64,
    nb_other_send_error_drops: u64,
    other_send_error: String,
}

pub struct VxlanOutput {
    stats: Arc<OutputStats>,
    throttle: Option<TokenBucket>,
    slice: i32,
    vni_version: u8,
    vni: u32,
    capture_time: bool,
    remote_addr: SocketAddrV4,
    socket: Socket,
    buf: Vec<u8>,
    fragment_buf: Vec<u8>,
    max_payload_size: u16,
    recalculate_checksum: bool,
    error_info: ErrorInfo,
}

impl VxlanOutput {
    /// Create a VXLAN tunnel output.
    ///
    /// # Errors
    /// Returns an error if the host is invalid or the tunnel socket cannot be
    /// created or bound.
    pub fn new(cfg: &VxlanConfig, out: &OutputConfig, stats: Arc<OutputStats>) -> Result<Self> {
        let addr: Ipv4Addr = cfg
            .host
            .parse()
            .map_err(|_| Error::new(format!("invalid vxlan host: {}", cfg.host)))?;
        let remote_addr = SocketAddrV4::new(addr, cfg.port);

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
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

        Ok(VxlanOutput {
            stats,
            throttle,
            slice: out.slice,
            vni_version: cfg.vni_version,
            vni: cfg.vni,
            capture_time: cfg.capture_time,
            remote_addr,
            socket,
            buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            fragment_buf: vec![0u8; VXLAN_OUTPUT_BUFSIZE],
            max_payload_size: cfg.split.max_payload_size,
            recalculate_checksum: cfg.split.recalculate_checksum,
            error_info: ErrorInfo::default(),
        })
    }

    fn flush_error_info(&mut self) {
        self.error_info.first_pktsec = 0;
        let e = &mut self.error_info;
        if e.nb_nobufs_drops > 0 || e.nb_partial_sends > 0 || e.nb_other_send_error_drops > 0 {
            crate::log_error!(
                "vxlan output error: nb_nobufs_drops={}, nb_partial_sends={}, nb_other_send_error_drops={}, detail: {}",
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

    fn do_send_packet(
        &mut self,
        hdr: &PacketHeader,
        pkt_data: &[u8],
        length: usize,
        direct: i32,
    ) -> i32 {
        let total = vxlan_encapsulate(
            &mut self.buf,
            self.vni,
            self.vni_version,
            direct,
            self.capture_time,
            hdr.ts_sec,
            hdr.ts_usec,
            &pkt_data[..length],
        );
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

impl Output for VxlanOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, pkt_data: &[u8], direct: i32) -> i32 {
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

        if let Some(tb) = self.throttle.as_mut() {
            if !tb.consume(VXLAN_HDR_LEN + length, hdr.ts()) {
                self.stats
                    .ratelimit_drop_bytes
                    .add((VXLAN_HDR_LEN + length) as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }

        if self.error_info.first_pktsec == 0 {
            self.error_info.first_pktsec = hdr.ts_sec;
        } else if hdr.ts_sec > self.error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC {
            self.flush_error_info();
            self.error_info.first_pktsec = hdr.ts_sec;
        }

        // Fast path: no split needed.
        if self.max_payload_size == 0 || length <= self.max_payload_size as usize {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        }

        let Some(parse) = parse_packet(pkt_data) else {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        };
        let count = calculate_fragment_count(&parse, self.max_payload_size as i32);
        if count == 1 {
            return self.do_send_packet(hdr, pkt_data, length, direct);
        }

        for i in 0..count {
            let mut frag_buf = std::mem::take(&mut self.fragment_buf);
            let frag_len = build_fragment(
                &parse,
                pkt_data,
                i,
                self.max_payload_size as i32,
                self.recalculate_checksum,
                &mut frag_buf,
            );
            let ret = match frag_len {
                Some(frag_len) => self.do_send_packet(hdr, &frag_buf[..frag_len], frag_len, direct),
                None => 0,
            };
            self.fragment_buf = frag_buf;
            if ret != 0 {
                return ret;
            }
        }
        0
    }
}
