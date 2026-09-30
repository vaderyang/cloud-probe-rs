//! Experiment harness: what does the *kernel* put into a hand-written
//! `PACKET_RX_RING` (`TPACKET_V2`) on loopback - one frame per datagram, or two?
//!
//! This is the evidence behind `PARITY.md §4`'s explanation of why libpcap delivers
//! half of what `ps_recv` reports on `lo`. It touches no libpcap code: a plain
//! `AF_PACKET` socket, `PACKET_VERSION=TPACKET_V2`, `PACKET_RX_RING`, `mmap`, then
//! N loopback UDP datagrams, then a walk of the ring reporting the
//! `sockaddr_ll.sll_pkttype` of every frame the kernel placed there, plus
//! `PACKET_STATISTICS.tp_packets` (the number libpcap turns into `ps_recv`).
//!
//! Root is required (`CAP_NET_RAW`), and the interface should be idle apart from
//! this run. The numbers this reports on the development box, unchanged since the
//! A1 investigation:
//!
//! ```text
//! $ sudo target/debug/tpacket_ring_probe lo 3000 41267
//! ifname=lo sent=3000 ... ring_frames=6000 outgoing=3000 host=3000 ... tp_packets=6000
//! $ sudo target/debug/tpacket_ring_probe lo 3000 41266 ignore_outgoing
//! ifname=lo sent=3000 ... ring_frames=3000 outgoing=0    host=3000 ... tp_packets=3000
//! ```
//!
//! i.e. the kernel taps a loopback datagram twice and copies **both** into the ring
//! (and counts both in `tp_packets`); the second copy is discarded by whoever reads
//! it. libpcap discards it in userland (`linux_check_direction()` in
//! `pcap-linux.c`), `PACKET_IGNORE_OUTGOING` discards it in the kernel, and this
//! repository's capturer does the former on loopback - which is why the delivered
//! count matches `tcpdump` while the two implementations' "received" counters read
//! 2x apart.
//!
//! Not run by any CI job: it measures kernel/libpcap semantics, not this crate's,
//! and it needs `CAP_NET_RAW` plus an idle interface. `PARITY.md §4` quotes its
//! output.
//!
//! ```text
//! usage: tpacket_ring_probe [ifname] [n_datagrams] [port] [ignore_outgoing]
//! ```
use std::net::{Ipv4Addr, UdpSocket};
use std::{io, mem, ptr};

const TPACKET_ALIGNMENT: usize = 16;
const TPACKET_V2: i32 = 1; // enum tpacket_versions: V1=0, V2=1, V3=2
const TP_STATUS_USER: u32 = 1 << 0; // linux/if_packet.h: TP_STATUS_KERNEL = 0, USER = 1<<0
const TP_STATUS_LOSING: u32 = 1 << 2;
const ETH_P_ALL: u16 = 0x0003;
const PACKET_OUTGOING: u8 = 4;
const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const SNAPLEN: usize = 128;
/// `SOL_PACKET` option, Linux >= 4.17: drop the `PACKET_OUTGOING` copy in the kernel.
const PACKET_IGNORE_OUTGOING: i32 = 23;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TpacketHdr {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TpacketReq {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

const fn align(x: usize) -> usize {
    (x + (TPACKET_ALIGNMENT - 1)) & !(TPACKET_ALIGNMENT - 1)
}

fn hdrlen() -> usize {
    align(mem::size_of::<TpacketHdr>()) + mem::size_of::<libc::sockaddr_ll>()
}

/// Parse `[ifname] [n_datagrams] [port]` with the historical defaults.
fn parse_args(a: &[String]) -> (String, u32, u16) {
    let ifname = a.get(1).cloned().unwrap_or_else(|| "lo".to_string());
    let n: u32 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let port: u16 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(41255);
    (ifname, n, port)
}

/// Smallest power-of-two frame size that holds `need` bytes and divides `page`.
/// TPACKET_V1/V2 require an integer number of frames per page-sized block.
fn frame_size_for(page: usize, need: usize) -> usize {
    let mut frame_size = 64usize;
    while frame_size < need || !page.is_multiple_of(frame_size) {
        frame_size *= 2;
    }
    frame_size
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn setsockopt<T>(fd: i32, level: i32, optname: i32, val: &T) -> io::Result<()> {
    // SAFETY: `val` is a repr(C) value of the type the option expects.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            ptr::from_ref(val).cast::<libc::c_void>(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_err())
    }
}

fn main() -> io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let (ifname, n, port) = parse_args(&a);

    // SAFETY: plain socket() with a host-byte-order-converted protocol.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            i32::from(ETH_P_ALL.to_be()),
        )
    };
    if fd < 0 {
        return Err(last_err());
    }
    setsockopt(fd, libc::SOL_PACKET, libc::PACKET_VERSION, &TPACKET_V2)
        .expect("PACKET_VERSION=TPACKET_V2 (needs Linux >= 2.6)");
    // Control run: `... lo 3000 41255 ignore_outgoing` asks the kernel (>= 4.17) to
    // drop the transmitted copy before it reaches the ring.
    if a.iter().any(|x| x == "ignore_outgoing") {
        setsockopt(fd, libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, &1)
            .expect("PACKET_IGNORE_OUTGOING");
        eprintln!("control: PACKET_IGNORE_OUTGOING=1 set before bind()");
    }

    // TPACKET_V1/V2 require a block size that is a multiple of the page size.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).expect("page size");
    // ... and a block must hold an integer number of frames, so the frame size is
    // the smallest power of two that fits header + snaplen and divides a page.
    let need = hdrlen() + SNAPLEN;
    let frame_size = frame_size_for(page, need);
    let per_block = page / frame_size;
    let block_nr = 1024usize;
    let req = TpacketReq {
        block_size: page as u32,
        block_nr: block_nr as u32,
        frame_size: frame_size as u32,
        frame_nr: (per_block * block_nr) as u32,
    };
    setsockopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &req).expect("PACKET_RX_RING");
    let ring_len = req.block_size as usize * req.block_nr as usize;
    let nframes = (req.frame_nr as usize).max(1);

    // SAFETY: mmap of the ring the socket just allocated.
    let ring = unsafe {
        libc::mmap(
            ptr::null_mut(),
            ring_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ring == libc::MAP_FAILED {
        return Err(last_err());
    }

    let cname = std::ffi::CString::new(ifname.clone())?;
    // SAFETY: if_nametoindex with a valid C string.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(last_err());
    }
    let mut ll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    ll.sll_family = libc::AF_PACKET as u16;
    ll.sll_protocol = ETH_P_ALL.to_be();
    ll.sll_ifindex = ifindex as i32;
    // SAFETY: valid sockaddr_ll.
    let rc = unsafe {
        libc::bind(
            fd,
            ptr::from_ref(&ll).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err());
    }

    // Traffic: N loopback datagrams, with a receiver bound so nothing is refused.
    let rx = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))?;
    rx.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
    let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let dst = format!("127.0.0.1:{port}");
    let mut drained = 0u32;
    let mut sent = 0u32;
    for _ in 0..n {
        if tx.send_to(b"x", &dst).is_ok() {
            sent += 1;
        }
        if rx.recv(&mut [0u8; 2048]).is_ok() {
            drained += 1;
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Walk the ring, in order, handing each frame back to the kernel.
    let mut seen = 0u64;
    let mut outgoing = 0u64;
    let mut host = 0u64;
    let mut bcast = 0u64;
    let mut mcast = 0u64;
    let mut losing = 0u64;
    let mut idx = 0usize;
    let mut quiet = 0;
    while quiet < 100 {
        // SAFETY: base is inside the mmap and `frame_size`-aligned.
        let base = unsafe { (ring as *mut u8).add((idx % nframes) * frame_size) };
        // SAFETY: the header is at the start of the frame.
        let status = unsafe { (base as *const u32).read_unaligned() };
        if status & TP_STATUS_USER == 0 {
            quiet += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        quiet = 0;
        seen += 1;
        if status & TP_STATUS_LOSING != 0 {
            losing += 1;
        }
        // libpcap reads the copied sockaddr_ll from the end of the header area.
        let sll_off = hdrlen() - mem::size_of::<libc::sockaddr_ll>();
        // SAFETY: that is where the kernel puts it for TPACKET_V2.
        let sll = unsafe {
            (base.add(sll_off))
                .cast::<libc::sockaddr_ll>()
                .read_unaligned()
        };
        match sll.sll_pkttype {
            PACKET_OUTGOING => outgoing += 1,
            PACKET_HOST => host += 1,
            PACKET_BROADCAST => bcast += 1,
            PACKET_MULTICAST => mcast += 1,
            _ => {}
        }
        // SAFETY: releasing the frame back to the kernel.
        unsafe { (base as *mut u32).write_unaligned(0) };
        idx += 1;
    }

    let mut st = TpacketStats::default();
    let mut len = mem::size_of::<TpacketStats>() as libc::socklen_t;
    // SAFETY: valid out pointer/length for PACKET_STATISTICS.
    let stats_ok = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            ptr::addr_of_mut!(st).cast::<libc::c_void>(),
            &mut len,
        )
    } == 0;

    println!(
        "ifname={ifname} sent={sent} drained={drained} ring_frames={seen} \
         outgoing={outgoing} host={host} broadcast={bcast} multicast={mcast} \
         losing_frames={losing} tp_packets={} tp_drops={} stats_readable={stats_ok}",
        st.tp_packets, st.tp_drops
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{align, frame_size_for, hdrlen, parse_args, SNAPLEN, TPACKET_ALIGNMENT};

    #[test]
    fn align_rounds_up_to_the_tpacket_boundary() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), TPACKET_ALIGNMENT);
        assert_eq!(align(TPACKET_ALIGNMENT), TPACKET_ALIGNMENT);
        assert_eq!(align(TPACKET_ALIGNMENT + 1), 2 * TPACKET_ALIGNMENT);
        assert_eq!(align(33), 48);
    }

    #[test]
    fn hdrlen_is_the_aligned_v2_header_plus_sockaddr() {
        let hdr = std::mem::size_of::<super::TpacketHdr>();
        assert_eq!(align(hdr) % TPACKET_ALIGNMENT, 0);
        assert_eq!(
            hdrlen(),
            align(hdr) + std::mem::size_of::<libc::sockaddr_ll>()
        );
        // The copied sockaddr_ll sits at the end of the header area.
        assert!(hdrlen() >= hdr + std::mem::size_of::<libc::sockaddr_ll>());
    }

    #[test]
    fn parse_args_applies_documented_defaults() {
        let none: Vec<String> = vec!["probe".into()];
        assert_eq!(parse_args(&none), ("lo".to_string(), 2000, 41255));

        let full: Vec<String> = vec![
            "probe".into(),
            "eth0".into(),
            "3000".into(),
            "41266".into(),
            "ignore_outgoing".into(),
        ];
        assert_eq!(parse_args(&full), ("eth0".to_string(), 3000, 41266));
    }

    #[test]
    fn parse_args_falls_back_on_unparseable_numbers() {
        let a: Vec<String> = vec!["probe".into(), "lo".into(), "x".into(), "y".into()];
        assert_eq!(parse_args(&a), ("lo".to_string(), 2000, 41255));
    }

    #[test]
    fn frame_size_fits_the_header_snaplen_and_divides_the_page() {
        let need = hdrlen() + SNAPLEN;
        for page in [4096usize, 8192, 65536] {
            let fs = frame_size_for(page, need);
            assert!(fs >= need, "frame {fs} must hold {need} bytes");
            assert_eq!(page % fs, 0, "frame {fs} must divide page {page}");
            assert!(fs.is_power_of_two());
            // Minimal: halving it would either be too small or not divide.
            assert!(fs == 64 || fs / 2 < need || page % (fs / 2) != 0);
        }
        // A page-aligned block of 4096 with a 52+128-byte need yields 256.
        assert_eq!(frame_size_for(4096, need), 256);
    }
}
