//! Packet header definitions, address helpers and a zero-copy L2–L4 parser.
//!
//! Port of `ip.h`/`ip.c`, `ether.h`/`ether.c`, `tcp.h`, `udp.h`, `vlan.h`,
//! `vxlan.h`, `gre.h`, `mpls.h`, `pkt_dir.h` and the parsing bits of
//! `packet_split.c`.

use std::fmt;

/// Ethernet header length (no VLAN tag).
pub const ETH_HDR_LEN: usize = 14;
/// MAC address length in bytes.
pub const MAC_ADDR_LEN: usize = 6;
/// VLAN tag length in bytes.
pub const VLAN_HDR_LEN: usize = 4;
/// VXLAN header length in bytes.
pub const VXLAN_HDR_LEN: usize = 8;
/// GRE header length in bytes.
pub const GRE_HDR_LEN: usize = 8;

/// EtherType: IPv4.
pub const ETHERTYPE_IP: u16 = 0x0800;
/// EtherType: IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// EtherType: 802.1Q VLAN tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// EtherType: 802.1ad provider bridging VLAN tag.
pub const ETHERTYPE_DOT1AD: u16 = 0x88a8;
/// EtherType: legacy VLAN tag 0x9100.
pub const ETHERTYPE_VLAN_9100: u16 = 0x9100;
/// EtherType: legacy VLAN tag 0x9200.
pub const ETHERTYPE_VLAN_9200: u16 = 0x9200;
/// EtherType: MPLS unicast.
pub const ETHERTYPE_MPLS: u16 = 0x8847;

/// IPv6 extension header: hop-by-hop options.
pub const IPPROTO_HOPOPTS: u8 = 0;
/// IP protocol: TCP.
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol: UDP.
pub const IPPROTO_UDP: u8 = 17;
/// IPv6 extension header: routing.
pub const IPPROTO_ROUTING: u8 = 43;
/// IPv6 extension header: fragment.
pub const IPPROTO_FRAGMENT: u8 = 44;
/// IPv6 extension header: destination options.
pub const IPPROTO_DSTOPTS: u8 = 60;

/// Packet direction: unknown (dropped).
pub const PKT_DIR_UNKNOWN: i32 = -1;
/// Packet direction: not checked.
pub const PKT_DIR_NONCHECK: i32 = 0;
/// Packet direction: incoming.
pub const PKT_DIR_INCOMING: i32 = 1;
/// Packet direction: outgoing.
pub const PKT_DIR_OUTGOING: i32 = 2;

#[inline]
#[must_use]
/// Read a big-endian `u16` from the first two bytes of `b`.
pub fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
#[must_use]
/// Read a big-endian `u32` from the first four bytes of `b`.
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
/// Write `v` big-endian into the first two bytes of `b`.
pub fn put_be16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
/// Write `v` big-endian into the first four bytes of `b`.
pub fn put_be32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_be_bytes());
}

/// IPv4/IPv6 address union, matching `ip_addr_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    /// IPv4 address (4 bytes).
    V4([u8; 4]),
    /// IPv6 address (16 bytes).
    V6([u8; 16]),
}

impl IpAddr {
    /// Format the address in its canonical textual form.
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            IpAddr::V4(a) => std::net::Ipv4Addr::from(*a).to_string(),
            IpAddr::V6(a) => std::net::Ipv6Addr::from(*a).to_string(),
        }
    }

    /// The raw address bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            IpAddr::V4(a) => a,
            IpAddr::V6(a) => a,
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[must_use]
/// Format a MAC address as `aa:bb:cc:dd:ee:ff`.
pub fn format_mac_addr(mac: &[u8; MAC_ADDR_LEN]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Result of parsing an Ethernet frame up to (but excluding) the payload.
#[derive(Debug, Clone, Default)]
pub struct PacketParseResult {
    /// Frame carries IPv4.
    pub is_ipv4: bool,
    /// Frame carries IPv6.
    pub is_ipv6: bool,
    /// IPv4/IPv6 payload is TCP.
    pub is_tcp: bool,
    /// IPv4/IPv6 payload is UDP.
    pub is_udp: bool,
    /// Frame has at least one VLAN tag.
    pub has_vlan: bool,

    /// Offset of the Ethernet header.
    pub eth_offset: usize,
    /// Offset of the outermost VLAN tag (if any).
    pub vlan_offset: usize,
    /// Offset of the IP header.
    pub ip_offset: usize,
    /// Offset of the L4 (TCP/UDP) header.
    pub l4_offset: usize,
    /// Offset of the L4 payload.
    pub payload_offset: usize,

    /// IP header length in bytes.
    pub ip_hdr_len: usize,
    /// Total length of IPv6 extension headers in bytes.
    pub ipv6_ext_len: usize,
    /// L4 header length in bytes.
    pub l4_hdr_len: usize,
    /// L4 payload length in bytes.
    pub payload_len: usize,
}

/// Parse an Ethernet frame. Mirrors `parse_packet()` from `packet_split.c`.
#[must_use]
pub fn parse_packet(pkt_data: &[u8]) -> Option<PacketParseResult> {
    let caplen = pkt_data.len();
    let mut r = PacketParseResult::default();

    if caplen < ETH_HDR_LEN {
        return None;
    }

    r.eth_offset = 0;
    let mut ether_type = be16(&pkt_data[12..14]);
    let mut offset = ETH_HDR_LEN;

    while matches!(
        ether_type,
        ETHERTYPE_VLAN | ETHERTYPE_DOT1AD | ETHERTYPE_VLAN_9100 | ETHERTYPE_VLAN_9200
    ) {
        if caplen < offset + VLAN_HDR_LEN {
            return None;
        }
        if !r.has_vlan {
            r.has_vlan = true;
            r.vlan_offset = offset;
        }
        ether_type = be16(&pkt_data[offset + 2..offset + 4]);
        offset += VLAN_HDR_LEN;
    }

    r.ip_offset = offset;

    if ether_type == ETHERTYPE_IP {
        // IPv4
        if caplen < offset + 20 {
            return None;
        }
        r.is_ipv4 = true;
        let ihl = (pkt_data[offset] & 0x0f) as usize;
        r.ip_hdr_len = ihl * 4;
        if caplen < offset + r.ip_hdr_len || r.ip_hdr_len < 20 {
            return None;
        }
        let ip_proto = pkt_data[offset + 9];
        offset += r.ip_hdr_len;
        r.l4_offset = offset;

        if ip_proto == IPPROTO_TCP {
            if caplen < offset + 20 {
                return None;
            }
            r.is_tcp = true;
            r.l4_hdr_len = ((pkt_data[offset + 12] >> 4) as usize) * 4;
            if r.l4_hdr_len < 20 || caplen < offset + r.l4_hdr_len {
                return None;
            }
            offset += r.l4_hdr_len;
        } else if ip_proto == IPPROTO_UDP {
            if caplen < offset + 8 {
                return None;
            }
            r.is_udp = true;
            r.l4_hdr_len = 8;
            offset += r.l4_hdr_len;
        } else {
            return None;
        }

        r.payload_offset = offset;
        let ip_tot_len = be16(&pkt_data[r.ip_offset + 2..r.ip_offset + 4]) as usize;
        let headers_len = r.ip_hdr_len + r.l4_hdr_len;
        if ip_tot_len < headers_len {
            return None;
        }
        r.payload_len = ip_tot_len - headers_len;
    } else if ether_type == ETHERTYPE_IPV6 {
        if caplen < offset + 40 {
            return None;
        }
        r.is_ipv6 = true;
        r.ip_hdr_len = 40;
        r.ipv6_ext_len = 0;
        let mut nexthdr = pkt_data[offset + 6];
        offset += 40;

        while matches!(nexthdr, IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS) {
            if caplen < offset + 2 {
                return None;
            }
            let ext_nexthdr = pkt_data[offset];
            let ext_len = pkt_data[offset + 1] as usize;
            let ext_total = (ext_len + 1) * 8;
            if caplen < offset + ext_total {
                return None;
            }
            offset += ext_total;
            r.ipv6_ext_len += ext_total;
            nexthdr = ext_nexthdr;
        }

        // Fragment header cannot be split.
        if nexthdr == IPPROTO_FRAGMENT {
            return None;
        }

        r.l4_offset = offset;
        if nexthdr == IPPROTO_TCP {
            if caplen < offset + 20 {
                return None;
            }
            r.is_tcp = true;
            r.l4_hdr_len = ((pkt_data[offset + 12] >> 4) as usize) * 4;
            if r.l4_hdr_len < 20 || caplen < offset + r.l4_hdr_len {
                return None;
            }
            offset += r.l4_hdr_len;
        } else if nexthdr == IPPROTO_UDP {
            if caplen < offset + 8 {
                return None;
            }
            r.is_udp = true;
            r.l4_hdr_len = 8;
            offset += r.l4_hdr_len;
        } else {
            return None;
        }

        r.payload_offset = offset;
        let ipv6_payload_len = be16(&pkt_data[r.ip_offset + 4..r.ip_offset + 6]) as usize;
        if ipv6_payload_len < r.ipv6_ext_len + r.l4_hdr_len {
            return None;
        }
        r.payload_len = ipv6_payload_len - r.ipv6_ext_len - r.l4_hdr_len;
    } else {
        return None;
    }

    if r.payload_offset > caplen {
        return None;
    }

    let max_payload = caplen - r.payload_offset;
    if r.payload_len > max_payload {
        r.payload_len = max_payload;
    }

    Some(r)
}

/// Extract source/destination IP+port after descending through Ethernet, VLAN,
/// IPv4/IPv6 and (heuristically for VXLAN) inner frames.
pub struct IpPort {
    /// Source IP address.
    pub src: IpAddr,
    /// Source L4 port.
    pub sport: u16,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Destination L4 port.
    pub dport: u16,
    /// An IP layer was found.
    pub has_ip: bool,
    /// An L4 port pair was found.
    pub has_port: bool,
}

/// Mirrors `extract_ipport_from_ether_layer`.
#[must_use]
pub fn extract_ipport(pkt_data: &[u8], data_offset: usize) -> Option<IpPort> {
    if pkt_data.len() < data_offset + ETH_HDR_LEN {
        return None;
    }
    let ether_type = be16(&pkt_data[data_offset + 12..data_offset + 14]);
    let next = data_offset + ETH_HDR_LEN;

    match ether_type {
        ETHERTYPE_IP => extract_ipport_ipv4(pkt_data, next),
        ETHERTYPE_IPV6 => extract_ipport_ipv6(pkt_data, next),
        ETHERTYPE_VLAN | ETHERTYPE_DOT1AD | ETHERTYPE_VLAN_9100 | ETHERTYPE_VLAN_9200 => {
            if pkt_data.len() < next + VLAN_HDR_LEN {
                return None;
            }
            let inner = be16(&pkt_data[next + 2..next + 4]);
            let after_vlan = next + VLAN_HDR_LEN;
            match inner {
                ETHERTYPE_IP => extract_ipport_ipv4(pkt_data, after_vlan),
                ETHERTYPE_IPV6 => extract_ipport_ipv6(pkt_data, after_vlan),
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_ipport_ipv4(pkt_data: &[u8], off: usize) -> Option<IpPort> {
    if pkt_data.len() < off + 20 {
        return None;
    }
    let ihl = ((pkt_data[off] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt_data.len() < off + ihl {
        return None;
    }
    let mut out = IpPort {
        src: IpAddr::V4(pkt_data[off + 12..off + 16].try_into().unwrap()),
        sport: 0,
        dst: IpAddr::V4(pkt_data[off + 16..off + 20].try_into().unwrap()),
        dport: 0,
        has_ip: true,
        has_port: false,
    };
    match pkt_data[off + 9] {
        IPPROTO_TCP => fill_ports(pkt_data, off + ihl, &mut out, false),
        IPPROTO_UDP => fill_ports(pkt_data, off + ihl, &mut out, true),
        _ => {}
    }
    Some(out)
}

fn extract_ipport_ipv6(pkt_data: &[u8], off: usize) -> Option<IpPort> {
    if pkt_data.len() < off + 40 {
        return None;
    }
    let mut out = IpPort {
        src: IpAddr::V6(pkt_data[off + 8..off + 24].try_into().unwrap()),
        sport: 0,
        dst: IpAddr::V6(pkt_data[off + 24..off + 40].try_into().unwrap()),
        dport: 0,
        has_ip: true,
        has_port: false,
    };
    match pkt_data[off + 6] {
        IPPROTO_TCP => fill_ports(pkt_data, off + 40, &mut out, false),
        IPPROTO_UDP => fill_ports(pkt_data, off + 40, &mut out, true),
        _ => {}
    }
    Some(out)
}

fn fill_ports(pkt_data: &[u8], off: usize, out: &mut IpPort, udp: bool) {
    if pkt_data.len() < off + 8 {
        return;
    }
    out.sport = be16(&pkt_data[off..off + 2]);
    out.dport = be16(&pkt_data[off + 2..off + 4]);
    out.has_port = true;

    // Heuristic VXLAN detection (UDP port 4700-4799).
    if udp && (4700..4800).contains(&out.dport) {
        let inner_eth = off + 8 + VXLAN_HDR_LEN;
        if pkt_data.len() >= inner_eth + ETH_HDR_LEN + 20 {
            if let Some(inner) = extract_ipport(pkt_data, inner_eth) {
                out.src = inner.src;
                out.sport = inner.sport;
                out.dst = inner.dst;
                out.dport = inner.dport;
                out.has_ip = inner.has_ip;
                out.has_port = inner.has_port;
            }
        }
    }
}
