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
        // A fragment carries only part of an L4 datagram: a non-first fragment has
        // no L4 header at all, and splitting a first fragment at the L4 boundary
        // breaks reassembly of the rest (upstream #282 / #244). Send it unsplit.
        if be16(&pkt_data[offset + 6..offset + 8]) & 0x3fff != 0 {
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
    let mut ether_type = be16(&pkt_data[data_offset + 12..data_offset + 14]);
    let mut next = data_offset + ETH_HDR_LEN;

    // Descend through stacked VLAN tags (802.1Q/802.1ad and the legacy
    // 0x9100/0x9200 encapsulations). Each tag consumes four bytes and carries
    // the next EtherType, which may itself be a VLAN tag: real QinQ nests a
    // provider tag in front of a customer tag, and arbitrary stacking occurs on
    // some fabrics. The caplen bound is re-checked before every tag, so a
    // truncated inner layer yields `None` instead of reading past the captured
    // slice. Upstream 87cbaf6 (`extract_ipport_from_vlan_layer`) recurses the
    // same way; the loop here is the stack-safe equivalent.
    while matches!(
        ether_type,
        ETHERTYPE_VLAN | ETHERTYPE_DOT1AD | ETHERTYPE_VLAN_9100 | ETHERTYPE_VLAN_9200
    ) {
        if pkt_data.len() < next + VLAN_HDR_LEN {
            return None;
        }
        ether_type = be16(&pkt_data[next + 2..next + 4]);
        next += VLAN_HDR_LEN;
    }

    match ether_type {
        ETHERTYPE_IP => extract_ipport_ipv4(pkt_data, next),
        ETHERTYPE_IPV6 => extract_ipport_ipv6(pkt_data, next),
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
    // The 4/16-byte reads below are fixed-size by construction (the length
    // checks above guarantee it), so they are written as fallible slicing
    // helpers instead of `try_into().unwrap()`: an unreachable panic on
    // attacker-controlled frame bytes is exactly what AUDIT4 P5-23 removes.
    let a4 = |i: usize| <[u8; 4]>::try_from(&pkt_data[i..i + 4]).ok();
    let (Some(src), Some(dst)) = (a4(off + 12), a4(off + 16)) else {
        return None;
    };
    let mut out = IpPort {
        src: IpAddr::V4(src),
        sport: 0,
        dst: IpAddr::V4(dst),
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
    let a16 = |i: usize| <[u8; 16]>::try_from(&pkt_data[i..i + 16]).ok();
    let (Some(src), Some(dst)) = (a16(off + 8), a16(off + 24)) else {
        return None;
    };
    let mut out = IpPort {
        src: IpAddr::V6(src),
        sport: 0,
        dst: IpAddr::V6(dst),
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

#[cfg(test)]
mod tests {
    use super::*;

    const L4_SRC: [u8; 4] = [192, 168, 0, 1];
    const L4_DST: [u8; 4] = [203, 0, 113, 9];

    fn eth(ether_type: u16, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; ETH_HDR_LEN];
        v[12..14].copy_from_slice(&ether_type.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn ipv4_bytes(proto: u8, ihl_words: u8, tot_len: u16, options: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = 0x40 | (ihl_words & 0x0f);
        v[2..4].copy_from_slice(&tot_len.to_be_bytes());
        v[9] = proto;
        v[12..16].copy_from_slice(&L4_SRC);
        v[16..20].copy_from_slice(&L4_DST);
        v.extend_from_slice(options);
        v.extend_from_slice(body);
        v
    }

    fn tcp(sport: u16, dport: u16, data_off: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = data_off << 4;
        t.extend_from_slice(payload);
        t
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(payload);
        u
    }

    fn ipv4(proto: u8, l4: &[u8]) -> Vec<u8> {
        ipv4_bytes(proto, 5, (20 + l4.len()) as u16, &[], l4)
    }

    /// Ethernet + one 802.1Q tag wrapping `inner_ether_type` + `inner`.
    fn vlan(inner_ether_type: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = eth(ETHERTYPE_VLAN, &[0x00, 0x01]);
        v.extend_from_slice(&inner_ether_type.to_be_bytes());
        v.extend_from_slice(inner);
        v
    }

    /// Ethernet + `tpids.len()` stacked VLAN tags (outermost first) wrapping
    /// `inner_ether_type` + `inner`. With two or more tags this is QinQ.
    fn qinq(tpids: &[u16], inner_ether_type: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = eth(tpids[0], &[0x00, 0x01]);
        for (i, tpid) in tpids.iter().enumerate().skip(1) {
            v.extend_from_slice(&tpid.to_be_bytes());
            v.extend_from_slice(&[0x00, (i as u8) + 1]);
        }
        v.extend_from_slice(&inner_ether_type.to_be_bytes());
        v.extend_from_slice(inner);
        v
    }

    fn ipv6(nexthdr: u8, payload_len: u16, ext: &[u8], l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = nexthdr;
        ip[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip.extend_from_slice(ext);
        ip.extend_from_slice(l4);
        eth(ETHERTYPE_IPV6, &ip)
    }

    #[test]
    fn be_helpers_round_trip() {
        assert_eq!(be16(&[0x12, 0x34]), 0x1234);
        assert_eq!(be32(&[0x01, 0x02, 0x03, 0x04]), 0x0102_0304);
        let mut b = [0u8; 8];
        put_be16(&mut b, 0xabcd);
        assert_eq!(&b[..2], &[0xab, 0xcd]);
        put_be32(&mut b, 0xdead_beef);
        assert_eq!(&b[..4], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn mac_and_ip_formatting() {
        assert_eq!(
            format_mac_addr(&[0xaa, 0x0b, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:0b:cc:dd:ee:ff"
        );
        let v4 = IpAddr::V4([10, 0, 0, 1]);
        assert_eq!(v4.format(), "10.0.0.1");
        assert_eq!(v4.to_string(), "10.0.0.1");
        assert_eq!(v4.as_bytes(), &[10, 0, 0, 1]);
        let v6 = IpAddr::V6([0; 16]);
        assert_eq!(v6.format(), "::");
        assert_eq!(v6.as_bytes().len(), 16);
    }

    #[test]
    fn parse_rejects_short_and_non_ip() {
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[0u8; 13]).is_none());
        let arp = eth(0x0806, &[0u8; 40]);
        assert!(parse_packet(&arp).is_none());
    }

    #[test]
    fn parse_ipv4_tcp() {
        let payload = [0xAAu8; 10];
        let l4 = tcp(1234, 80, 5, &payload);
        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &l4));
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv4 && r.is_tcp && !r.is_udp && !r.has_vlan);
        assert_eq!(r.ip_offset, 14);
        assert_eq!(r.ip_hdr_len, 20);
        assert_eq!(r.l4_offset, 34);
        assert_eq!(r.l4_hdr_len, 20);
        assert_eq!(r.payload_offset, 54);
        assert_eq!(r.payload_len, 10);
    }

    #[test]
    fn parse_ipv4_udp() {
        let l4 = udp(53, 5353, &[0u8; 4]);
        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &l4));
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv4 && r.is_udp && !r.is_tcp);
        assert_eq!(r.l4_hdr_len, 8);
        assert_eq!(r.payload_offset, 14 + 20 + 8);
        assert_eq!(r.payload_len, 4);
    }

    #[test]
    fn parse_ipv4_with_options() {
        let l4 = tcp(1, 2, 5, &[]);
        let f = eth(
            ETHERTYPE_IP,
            &ipv4_bytes(IPPROTO_TCP, 6, 24 + 20, &[0u8; 4], &l4),
        );
        let r = parse_packet(&f).unwrap();
        assert_eq!(r.ip_hdr_len, 24);
        assert_eq!(r.l4_offset, 14 + 24);
    }

    #[test]
    fn parse_ipv4_rejects_bad_ihl_and_proto() {
        // ihl = 4 (< 5).
        let l4 = tcp(1, 2, 5, &[]);
        let bad_ihl = eth(ETHERTYPE_IP, &ipv4_bytes(IPPROTO_TCP, 4, 20 + 20, &[], &l4));
        assert!(parse_packet(&bad_ihl).is_none());
        // ICMP is not splittable.
        let f = eth(ETHERTYPE_IP, &ipv4(1, &[0u8; 8]));
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv4_rejects_tcp_data_offset_below_five() {
        let l4 = tcp(1, 2, 4, &[0u8; 4]);
        let f = eth(
            ETHERTYPE_IP,
            &[ipv4_bytes(IPPROTO_TCP, 5, 20 + l4.len() as u16, &[], &l4)].concat(),
        );
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv4_rejects_tot_len_smaller_than_headers() {
        let l4 = tcp(1, 2, 5, &[]);
        let f = eth(ETHERTYPE_IP, &ipv4_bytes(IPPROTO_TCP, 5, 30, &[], &l4));
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv4_clamps_payload_len_to_caplen() {
        // total length claims 1000 payload bytes but only 4 are captured.
        let l4 = tcp(1, 2, 5, &[1, 2, 3, 4]);
        let f = eth(
            ETHERTYPE_IP,
            &ipv4_bytes(IPPROTO_TCP, 5, 20 + 20 + 1000, &[], &l4),
        );
        let r = parse_packet(&f).unwrap();
        assert_eq!(r.payload_len, 4);
    }

    #[test]
    fn parse_single_and_double_vlan() {
        let l4 = udp(1, 2, &[0u8; 4]);
        let inner = ipv4(IPPROTO_UDP, &l4);
        let single = vlan(ETHERTYPE_IP, &inner);
        let r = parse_packet(&single).unwrap();
        assert!(r.has_vlan && r.is_udp);
        assert_eq!(r.vlan_offset, 14);
        assert_eq!(r.ip_offset, 18);
        assert_eq!(r.l4_offset, 18 + 20);

        // Outer 0x8100, inner tag 0x88a8.
        let mut dbl = eth(ETHERTYPE_VLAN, &[0x00, 0x01]);
        dbl.extend_from_slice(&ETHERTYPE_DOT1AD.to_be_bytes());
        dbl.extend_from_slice(&[0x00, 0x02, 0x08, 0x00]); // second tag TCI + IPv4 type
        dbl.extend_from_slice(&inner);
        let r = parse_packet(&dbl).unwrap();
        assert!(r.has_vlan && r.is_udp);
        assert_eq!(r.vlan_offset, 14, "outermost tag offset");
        assert_eq!(r.ip_offset, 22);
    }

    #[test]
    fn parse_rejects_truncated_vlan() {
        let mut f = eth(ETHERTYPE_VLAN, &[0x00, 0x01, 0x08]);
        f.truncate(16);
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv6_tcp_and_udp() {
        let l4 = tcp(1, 2, 5, &[0u8; 8]);
        let f = ipv6(IPPROTO_TCP, (20 + 8) as u16, &[], &l4);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv6 && r.is_tcp);
        assert_eq!(r.ip_hdr_len, 40);
        assert_eq!(r.ipv6_ext_len, 0);
        assert_eq!(r.l4_offset, 14 + 40);
        assert_eq!(r.payload_offset, 14 + 40 + 20);
        assert_eq!(r.payload_len, 8);

        let l4 = udp(1, 2, &[0u8; 6]);
        let f = ipv6(IPPROTO_UDP, (8 + 6) as u16, &[], &l4);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv6 && r.is_udp);
        assert_eq!(r.payload_offset, 14 + 40 + 8);
        assert_eq!(r.payload_len, 6);
    }

    #[test]
    fn parse_ipv6_with_extension_header() {
        // 8-byte hop-by-hop header whose next-header is UDP.
        let ext = [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        let l4 = udp(1, 2, &[0u8; 4]);
        let f = ipv6(IPPROTO_HOPOPTS, (8 + 8 + 4) as u16, &ext, &l4);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv6 && r.is_udp);
        assert_eq!(r.ipv6_ext_len, 8);
        assert_eq!(r.l4_offset, 14 + 40 + 8);
        assert_eq!(r.payload_len, 4);
    }

    #[test]
    fn parse_ipv6_fragment_header_is_rejected() {
        let f = ipv6(IPPROTO_FRAGMENT, 8, &[0u8; 8], &[0u8; 8]);
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv6_rejects_short_payload_len() {
        let l4 = udp(1, 2, &[0u8; 4]);
        // payload_len says 4 but ext+l4 headers alone need 8.
        let f = ipv6(IPPROTO_UDP, 4, &[], &l4);
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn extract_ipport_ipv4_tcp_and_udp() {
        let l4 = tcp(0x1234, 0x5678, 5, &[]);
        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &l4));
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!(p.src, IpAddr::V4(L4_SRC));
        assert_eq!(p.dst, IpAddr::V4(L4_DST));
        assert_eq!((p.sport, p.dport), (0x1234, 0x5678));
        assert!(p.has_ip && p.has_port);

        let l4 = udp(0x0102, 0x0304, &[]);
        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &l4));
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!((p.sport, p.dport), (0x0102, 0x0304));
    }

    #[test]
    fn extract_ipport_ipv4_without_ports() {
        // ICMP: IP found, no L4 ports.
        let f = eth(ETHERTYPE_IP, &ipv4(1, &[0u8; 8]));
        let p = extract_ipport(&f, 0).unwrap();
        assert!(p.has_ip && !p.has_port);
        assert_eq!((p.sport, p.dport), (0, 0));
    }

    #[test]
    fn extract_ipport_ipv4_short_l4() {
        // IP present but the L4 area is too short for ports.
        let f = eth(ETHERTYPE_IP, &ipv4_bytes(IPPROTO_UDP, 5, 20, &[], &[]));
        let p = extract_ipport(&f, 0).unwrap();
        assert!(p.has_ip && !p.has_port);
    }

    #[test]
    fn extract_ipport_ipv6() {
        let l4 = tcp(0xabcd, 0xef01, 5, &[]);
        let f = ipv6(IPPROTO_TCP, 20, &[], &l4);
        let p = extract_ipport(&f, 0).unwrap();
        assert!(matches!(p.src, IpAddr::V6(_)));
        assert_eq!((p.sport, p.dport), (0xabcd, 0xef01));
        assert!(p.has_ip && p.has_port);
    }

    #[test]
    fn extract_ipport_vlan_and_unknown() {
        let l4 = udp(1, 2, &[]);
        let f = vlan(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &l4));
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!((p.sport, p.dport), (1, 2));

        let f = vlan(0x0806, &[0u8; 40]);
        assert!(extract_ipport(&f, 0).is_none());
    }

    #[test]
    fn extract_ipport_two_level_qinq_ipv4() {
        // Outer 0x8100 + inner 0x88a8 around IPv4/UDP.
        let l4 = udp(0x1111, 0x2222, &[]);
        let f = qinq(
            &[ETHERTYPE_VLAN, ETHERTYPE_DOT1AD],
            ETHERTYPE_IP,
            &ipv4(IPPROTO_UDP, &l4),
        );
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!(p.src, IpAddr::V4(L4_SRC));
        assert_eq!(p.dst, IpAddr::V4(L4_DST));
        assert_eq!((p.sport, p.dport), (0x1111, 0x2222));
        assert!(p.has_ip && p.has_port);
    }

    #[test]
    fn extract_ipport_three_level_qinq_ipv4() {
        // 0x8100 / 0x9100 / 0x9200 around IPv4/TCP.
        let l4 = tcp(0x3333, 0x4444, 5, &[]);
        let f = qinq(
            &[ETHERTYPE_VLAN, ETHERTYPE_VLAN_9100, ETHERTYPE_VLAN_9200],
            ETHERTYPE_IP,
            &ipv4(IPPROTO_TCP, &l4),
        );
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!(p.src, IpAddr::V4(L4_SRC));
        assert_eq!(p.dst, IpAddr::V4(L4_DST));
        assert_eq!((p.sport, p.dport), (0x3333, 0x4444));
        assert!(p.has_ip && p.has_port);
    }

    #[test]
    fn extract_ipport_three_level_qinq_ipv6_inner() {
        let l4 = udp(0x5555, 0x6666, &[]);
        let f = qinq(
            &[ETHERTYPE_VLAN, ETHERTYPE_DOT1AD, ETHERTYPE_VLAN],
            ETHERTYPE_IPV6,
            &{
                let mut ip = vec![0u8; 40];
                ip[0] = 0x60;
                ip[6] = IPPROTO_UDP;
                ip[8..24].copy_from_slice(&[0x20; 16]);
                ip[24..40].copy_from_slice(&[0x21; 16]);
                ip.extend_from_slice(&l4);
                ip
            },
        );
        let p = extract_ipport(&f, 0).unwrap();
        assert!(matches!(p.src, IpAddr::V6(_)));
        assert_eq!((p.sport, p.dport), (0x5555, 0x6666));
        assert!(p.has_ip && p.has_port);
    }

    #[test]
    fn extract_ipport_qinq_rejects_a_truncated_layer() {
        let l4 = udp(1, 2, &[]);
        let f = qinq(
            &[ETHERTYPE_VLAN, ETHERTYPE_VLAN],
            ETHERTYPE_IP,
            &ipv4(IPPROTO_UDP, &l4),
        );
        // Complete frame parses.
        assert!(extract_ipport(&f, 0).is_some());
        // Cut inside the second VLAN tag: the inner (post-tag) EtherType cannot
        // be read, so the layer must fail closed rather than read past caplen.
        for cut in 18..22 {
            assert!(
                extract_ipport(&f[..cut], 0).is_none(),
                "cut to {cut} B (inside the inner tag) must be rejected"
            );
        }
        // Cut before the inner IPv4 header is complete.
        for cut in 22..42 {
            assert!(
                extract_ipport(&f[..cut], 0).is_none(),
                "cut to {cut} B (truncated inner IPv4) must be rejected"
            );
        }
    }

    #[test]
    fn extract_ipport_rejects_short_and_non_ip() {
        assert!(extract_ipport(&[0u8; 13], 0).is_none());
        let arp = eth(0x0806, &[0u8; 40]);
        assert!(extract_ipport(&arp, 0).is_none());
    }

    #[test]
    fn extract_ipport_offset_is_respected() {
        let l4 = udp(7, 8, &[]);
        let inner = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &l4));
        let mut buf = vec![0xFFu8; 32];
        buf.extend_from_slice(&inner);
        let p = extract_ipport(&buf, 32).unwrap();
        assert_eq!((p.sport, p.dport), (7, 8));
    }

    #[test]
    fn extract_ipport_descends_into_vxlan() {
        // outer UDP dport 4789 -> inner Ethernet/IPv4/TCP.
        let inner = eth(
            ETHERTYPE_IP,
            &ipv4(IPPROTO_TCP, &tcp(0x1111, 0x2222, 5, &[])),
        );
        let mut vxlan = vec![0u8; VXLAN_HDR_LEN];
        vxlan.extend_from_slice(&inner);
        let outer = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &udp(40000, 4789, &vxlan)));
        let p = extract_ipport(&outer, 0).unwrap();
        assert_eq!((p.sport, p.dport), (0x1111, 0x2222), "inner ports win");
    }

    #[test]
    fn extract_ipport_keeps_outer_ports_outside_vxlan_range() {
        let inner = eth(
            ETHERTYPE_IP,
            &ipv4(IPPROTO_TCP, &tcp(0x1111, 0x2222, 5, &[])),
        );
        let mut vxlan = vec![0u8; VXLAN_HDR_LEN];
        vxlan.extend_from_slice(&inner);
        let outer = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &udp(40000, 9999, &vxlan)));
        let p = extract_ipport(&outer, 0).unwrap();
        assert_eq!((p.sport, p.dport), (40000, 9999));
    }
    #[test]
    fn parse_minimal_ipv4_tcp_and_udp_without_payload() {
        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &tcp(1, 2, 5, &[])));
        assert_eq!(f.len(), 54);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_tcp);
        assert_eq!(r.payload_len, 0);

        let f = eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &udp(1, 2, &[])));
        assert_eq!(f.len(), 42);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_udp);
        assert_eq!(r.payload_len, 0);
    }

    #[test]
    fn parse_minimal_ipv6_tcp_and_udp_without_payload() {
        let f = ipv6(IPPROTO_TCP, 20, &[], &tcp(1, 2, 5, &[]));
        assert_eq!(f.len(), 74);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_tcp);
        assert_eq!(r.payload_len, 0);

        let f = ipv6(IPPROTO_UDP, 8, &[], &udp(1, 2, &[]));
        assert_eq!(f.len(), 62);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_udp);
        assert_eq!(r.payload_len, 0);
    }

    #[test]
    fn parse_payload_offset_equal_to_caplen_is_accepted() {
        // tot_len advertises 10 payload bytes but the capture stops right at
        // the payload offset; payload_len must clamp to zero, not fail.
        let f = {
            let l4 = tcp(1, 2, 5, &[]);
            let mut v = eth(
                ETHERTYPE_IP,
                &ipv4_bytes(IPPROTO_TCP, 5, 20 + 20 + 10, &[], &l4),
            );
            v.truncate(14 + 20 + 20);
            v
        };
        let r = parse_packet(&f).unwrap();
        assert_eq!(r.payload_offset, 54);
        assert_eq!(r.payload_len, 0);
    }

    #[test]
    fn parse_ipv6_extension_header_boundaries() {
        // Ext header present but truncated by one byte -> reject.
        let ext = [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        let mut f = ipv6(IPPROTO_HOPOPTS, 16, &ext, &udp(1, 2, &[0u8; 4]));
        f.truncate(14 + 40 + 7);
        assert!(parse_packet(&f).is_none());
        // No room even for the 2-byte extension header prefix -> reject.
        let mut f2 = ipv6(IPPROTO_HOPOPTS, 16, &ext, &udp(1, 2, &[0u8; 4]));
        f2.truncate(14 + 40 + 1);
        assert!(parse_packet(&f2).is_none());
    }

    #[test]
    fn extract_ipport_rejects_bad_ihl() {
        // ihl = 4 (< 5): the combined length guard must reject it.
        let l4 = tcp(1, 2, 5, &[]);
        let f = eth(ETHERTYPE_IP, &ipv4_bytes(IPPROTO_TCP, 4, 20 + 20, &[], &l4));
        assert!(extract_ipport(&f, 0).is_none());
    }

    #[test]
    fn extract_ipport_ipv6_header_only_and_udp() {
        // Exactly a 40-byte IPv6 header, no L4: IP found, no ports.
        let f = {
            let mut ip = vec![0u8; 40];
            ip[0] = 0x60;
            ip[6] = IPPROTO_TCP;
            ip[8..24].copy_from_slice(&[0x20; 16]);
            ip[24..40].copy_from_slice(&[0x21; 16]);
            eth(ETHERTYPE_IPV6, &ip)
        };
        let p = extract_ipport(&f, 0).unwrap();
        assert!(p.has_ip && !p.has_port);

        // IPv6 + UDP ports.
        let l4 = udp(0x0a0b, 0x0c0d, &[]);
        let f = ipv6(IPPROTO_UDP, 8, &[], &l4);
        let p = extract_ipport(&f, 0).unwrap();
        assert!(p.has_ip && p.has_port);
        assert_eq!((p.sport, p.dport), (0x0a0b, 0x0c0d));
    }
    #[test]
    fn parse_ipv6_tcp_data_offset_zero_is_rejected() {
        // data offset 0 -> l4_hdr_len 0 < 20, must reject without reading OOB.
        let f = ipv6(IPPROTO_TCP, 20, &[], &tcp(1, 2, 0, &[]));
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn parse_ipv4_short_ihl_is_rejected_even_when_the_rest_would_parse() {
        // ihl nibble = 4 (16 bytes) but a valid 20-byte TCP header follows, so a
        // broken length guard would wrongly accept the frame.
        let mut ip = vec![0u8; 16];
        ip[0] = 0x44;
        ip[2..4].copy_from_slice(&36u16.to_be_bytes()); // 16 (ip) + 20 (tcp)
        ip[9] = IPPROTO_TCP;
        let mut frame = eth(ETHERTYPE_IP, &ip);
        frame.extend_from_slice(&tcp(1, 2, 5, &[]));
        assert_eq!(frame.len(), 14 + 16 + 20);
        assert!(parse_packet(&frame).is_none());
    }
    #[test]
    fn extract_ipport_vlan_ipv6() {
        let l4 = udp(0x0a0b, 0x0c0d, &[]);
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[6] = IPPROTO_UDP;
        ip[8..24].copy_from_slice(&[0x20; 16]);
        ip[24..40].copy_from_slice(&[0x21; 16]);
        ip.extend_from_slice(&l4);
        let mut f = eth(ETHERTYPE_VLAN, &[0x00, 0x01]);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.extend_from_slice(&ip);
        let p = extract_ipport(&f, 0).unwrap();
        assert!(matches!(p.src, IpAddr::V6(_)));
        assert_eq!((p.sport, p.dport), (0x0a0b, 0x0c0d));
    }

    /// Every `caplen < offset + N` in `parse_packet` is a minimum capture length
    /// copied from `packet_split.c`: a frame shortened below it must be rejected,
    /// and the frame that is exactly long enough must be accepted. Sweeping every
    /// prefix of each minimal frame pins those comparisons from both sides, which
    /// is what lets an off-by-one (or a flipped `+`) hide otherwise.
    #[test]
    fn every_truncation_of_a_minimal_frame_is_rejected() {
        let ext8 = |next: u8| -> Vec<u8> {
            let mut e = vec![next, 0]; // (0 + 1) * 8 = 8 bytes
            e.resize(8, 0);
            e
        };
        let ext24 = |next: u8| -> Vec<u8> {
            let mut e = vec![next, 2]; // (2 + 1) * 8 = 24 bytes
            e.resize(24, 0);
            e
        };
        let dbl_vlan = |inner: &[u8]| -> Vec<u8> {
            let mut v = eth(ETHERTYPE_VLAN, &[0x00, 0x01]);
            v.extend_from_slice(&ETHERTYPE_DOT1AD.to_be_bytes());
            v.extend_from_slice(&[0x00, 0x02, 0x08, 0x00]); // second TCI + IPv4
            v.extend_from_slice(inner);
            v
        };

        let frames: Vec<(&str, Vec<u8>)> = vec![
            (
                "v4+tcp",
                eth(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &tcp(1, 2, 5, &[]))),
            ),
            (
                "v4+udp",
                eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &udp(1, 2, &[]))),
            ),
            (
                "v4 options + tcp",
                eth(
                    ETHERTYPE_IP,
                    &ipv4_bytes(IPPROTO_TCP, 6, 24 + 20, &[9; 4], &tcp(1, 2, 5, &[])),
                ),
            ),
            (
                "v4 + tcp with a 24 B header",
                eth(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &tcp(1, 2, 6, &[0u8; 4]))),
            ),
            (
                "vlan + v4 + tcp",
                vlan(ETHERTYPE_IP, &ipv4(IPPROTO_TCP, &tcp(1, 2, 5, &[]))),
            ),
            (
                "vlan + vlan + v4 + udp",
                dbl_vlan(&ipv4(IPPROTO_UDP, &udp(1, 2, &[]))),
            ),
            ("v6+tcp", ipv6(IPPROTO_TCP, 20, &[], &tcp(1, 2, 5, &[]))),
            ("v6+udp", ipv6(IPPROTO_UDP, 8, &[], &udp(1, 2, &[]))),
            (
                "v6 + hopopts + udp",
                ipv6(IPPROTO_HOPOPTS, 16, &ext8(IPPROTO_UDP), &udp(1, 2, &[])),
            ),
            (
                "v6 + routing + tcp",
                ipv6(IPPROTO_ROUTING, 44, &ext24(IPPROTO_TCP), &tcp(1, 2, 5, &[])),
            ),
            (
                "v6 + dstopts + udp",
                ipv6(IPPROTO_DSTOPTS, 16, &ext8(IPPROTO_UDP), &udp(1, 2, &[])),
            ),
        ];

        for (label, f) in frames {
            assert!(
                parse_packet(&f).is_some(),
                "{label}: the minimal frame ({} B) must parse",
                f.len()
            );
            for cut in 0..f.len() {
                assert!(
                    parse_packet(&f[..cut]).is_none(),
                    "{label}: {cut}/{} B must be rejected, not reported as a packet",
                    f.len()
                );
            }
        }
    }

    /// `payload_len` is what the *sender* declared, clamped to what was actually
    /// captured (`PARITY.md`, `packet_split.c`). Reported from the declared length
    /// means the subtractions that derive it are load-bearing, not decoration.
    #[test]
    fn ipv4_fragments_are_rejected() {
        // Upstream #282 / #244: a fragment has no complete L4 datagram (a
        // non-first one has no L4 header at all), so splitting it would rewrite
        // payload bytes as a sequence number/checksum. `parse_packet` rejects it
        // and the caller sends the packet unchanged.
        for frag in [0x2000u16, 0x0001, 0x2001, 0x3fff] {
            let mut ip = ipv4(IPPROTO_UDP, &udp(1, 2, &[]));
            ip[6..8].copy_from_slice(&frag.to_be_bytes());
            let frame = eth(ETHERTYPE_IP, &ip);
            assert!(
                parse_packet(&frame).is_none(),
                "frag_off {frag:#06x} must not parse (and must not be split)"
            );
        }
        // A packet with frag_off 0 still parses.
        assert!(parse_packet(&eth(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &udp(1, 2, &[])))).is_some());
    }

    #[test]
    fn ipv4_payload_len_follows_the_declared_total_length() {
        // 30 bytes of TCP on the wire, but tot_len says the datagram is 40 B
        // long, i.e. ip(20) + tcp(20) + no payload.
        let f = eth(
            ETHERTYPE_IP,
            &ipv4_bytes(IPPROTO_TCP, 5, 40, &[], &tcp(1, 2, 5, &[0u8; 10])),
        );
        assert_eq!(f.len(), 14 + 20 + 30);
        assert_eq!(parse_packet(&f).unwrap().payload_len, 0);

        // 45 - 40 = 5 declared payload bytes, still fewer than what was captured.
        let f = eth(
            ETHERTYPE_IP,
            &ipv4_bytes(IPPROTO_TCP, 5, 45, &[], &tcp(1, 2, 5, &[0u8; 10])),
        );
        assert_eq!(parse_packet(&f).unwrap().payload_len, 5);
    }

    #[test]
    fn ipv6_payload_len_subtracts_both_the_extension_and_the_l4_header() {
        // Declared payload 28 B = hopopts(8) + tcp(20), while the capture holds
        // 10 payload bytes more than that.
        let f = ipv6(
            IPPROTO_HOPOPTS,
            28,
            &[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0],
            &tcp(1, 2, 5, &[0u8; 10]),
        );
        assert_eq!(f.len(), 14 + 40 + 8 + 30);
        let r = parse_packet(&f).unwrap();
        assert_eq!(r.ipv6_ext_len, 8);
        assert_eq!(r.l4_hdr_len, 20);
        assert_eq!(r.payload_len, 0, "28 - 8 - 20");

        // Same frame, now declaring 5 extra payload bytes.
        let f = ipv6(
            IPPROTO_HOPOPTS,
            33,
            &[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0],
            &tcp(1, 2, 5, &[0u8; 10]),
        );
        assert_eq!(parse_packet(&f).unwrap().payload_len, 5, "33 - 8 - 20");
    }

    /// `extract_ipport` walks Ethernet, then an optional VLAN tag, then IP, then
    /// the port pair, so it has its own ladder of minimum lengths.
    #[test]
    fn extract_ipport_needs_a_complete_header_at_every_layer() {
        let l4 = udp(0x0a0b, 0x0c0d, &[]);
        let f = vlan(ETHERTYPE_IP, &ipv4(IPPROTO_UDP, &l4)); // 14 + 4 + 20 + 8
        assert_eq!(f.len(), 46);

        // The inner EtherType lives at 16..18; a shorter capture cannot even
        // read it, let alone the inner IPv4 header that follows at offset 18.
        for cut in 0..38 {
            assert!(
                extract_ipport(&f[..cut], 0).is_none(),
                "cut to {cut} B must be rejected"
            );
        }
        // Fixed IPv4 header (18 + 20 = 38) present, port pair (38 + 8) not yet.
        for cut in 38..46 {
            let p = extract_ipport(&f[..cut], 0)
                .unwrap_or_else(|| panic!("cut to {cut} B must report the addresses"));
            assert!(p.has_ip && !p.has_port, "cut to {cut} B");
        }
        let p = extract_ipport(&f, 0).unwrap();
        assert!(p.has_ip && p.has_port);
        assert_eq!((p.sport, p.dport), (0x0a0b, 0x0c0d));
    }

    #[test]
    fn extract_ipport_ipv6_reports_both_addresses_and_ports() {
        let f = ipv6(IPPROTO_TCP, 20, &[], &tcp(0xabcd, 0xef01, 5, &[]));
        let p = extract_ipport(&f, 0).unwrap();
        assert_eq!(
            p.src,
            IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "source must come from bytes 8..24"
        );
        assert_eq!(
            p.dst,
            IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            "destination must come from bytes 24..40"
        );
        assert_eq!((p.sport, p.dport), (0xabcd, 0xef01));

        // Truncated one byte before the destination address is complete.
        assert!(extract_ipport(&f[..14 + 40 - 1], 0).is_none());
    }

    /// The v4 TCP split point is `offset + l4_hdr_len`, so the guard is only
    /// load-bearing once the TCP header is longer than everything in front of it:
    /// with ihl = 5 that starts at doff = 9 (36 B > 14 + 20 B). Every other frame in
    /// this module uses doff <= 5, where `offset - l4_hdr_len` (what the 2026-10-02
    /// sweep mutant `packet.rs:220:53` computes) stays positive and the guard
    /// decides identically, which is why that mutant survived until this shape
    /// existed.
    #[test]
    fn parse_ipv4_tcp_with_a_header_longer_than_its_prefix() {
        for doff in 9..=15u8 {
            let hdr = usize::from(doff) * 4;
            // NOP padding for the option area, then 6 bytes that really are payload.
            let options = vec![0x01u8; hdr - 20 + 6];
            let l4 = tcp(1, 2, doff, &options);
            let tot_len = u16::try_from(20 + hdr + 6).expect("option frame fits u16");
            let f = eth(ETHERTYPE_IP, &ipv4_bytes(IPPROTO_TCP, 5, tot_len, &[], &l4));
            let r = parse_packet(&f)
                .unwrap_or_else(|| panic!("doff={doff} ({hdr} B TCP header) must parse"));
            assert_eq!(r.l4_hdr_len, hdr, "doff={doff}");
            assert_eq!(r.payload_offset, ETH_HDR_LEN + 20 + hdr, "doff={doff}");
            assert_eq!(r.payload_len, 6, "doff={doff}");
        }

        // The measured maximum: ihl = 5 + doff = 15 -> a 60 B header that ends
        // exactly at caplen (94 B), with tot_len advertising no payload. Equality
        // must be accepted (the guard is `<`), and one byte less must not be.
        let header_only = tcp(1, 2, 15, &[0x01u8; 40]);
        let f = eth(
            ETHERTYPE_IP,
            &ipv4_bytes(IPPROTO_TCP, 5, 80, &[], &header_only),
        );
        assert_eq!(f.len(), 94);
        let r = parse_packet(&f).expect("a 60 B TCP header ending at caplen must parse");
        assert_eq!(r.l4_hdr_len, 60);
        assert_eq!(r.payload_offset, 94);
        assert_eq!(r.payload_len, 0);
        assert!(
            parse_packet(&f[..93]).is_none(),
            "a capture one byte short of the advertised header cannot be split"
        );
    }

    /// The same guard on the IPv6 side (`packet.rs:279:53` in the sweep). Its
    /// prefix is 14 + 40 = 54 B, so the mutant only diverges from doff = 14
    /// (56 B) up - doff = 15 is the largest header TCP can advertise at all.
    #[test]
    fn parse_ipv6_tcp_with_a_header_longer_than_its_prefix() {
        for doff in 14..=15u8 {
            let hdr = usize::from(doff) * 4;
            let options = vec![0x01u8; hdr - 20 + 6];
            let l4 = tcp(1, 2, doff, &options);
            let f = ipv6(
                IPPROTO_TCP,
                u16::try_from(hdr + 6).expect("option frame fits u16"),
                &[],
                &l4,
            );
            let r =
                parse_packet(&f).unwrap_or_else(|| panic!("v6 doff={doff} ({hdr} B) must parse"));
            assert_eq!(r.l4_offset, ETH_HDR_LEN + 40, "doff={doff}");
            assert_eq!(r.l4_hdr_len, hdr, "doff={doff}");
            assert_eq!(r.payload_offset, ETH_HDR_LEN + 40 + hdr, "doff={doff}");
            assert_eq!(r.payload_len, 6, "doff={doff}");
        }

        // Boundary pair for doff = 15: the header ending exactly at caplen parses,
        // one byte short of it does not.
        let f = ipv6(IPPROTO_TCP, 60, &[], &tcp(1, 2, 15, &[0x01u8; 40]));
        assert_eq!(f.len(), 114);
        let r = parse_packet(&f).expect("a 60 B v6 TCP header ending at caplen must parse");
        assert_eq!(r.payload_offset, 114);
        assert_eq!(r.payload_len, 0);
        assert!(parse_packet(&f[..113]).is_none());
    }

    /// The extension-header guard is `caplen < offset + ext_total`, where offset
    /// is the 54 B IPv6 prefix. A header longer than that (hdr_ext_len = 7 -> 64 B)
    /// is the shape that tells `offset + ext_total` apart from the mutant's
    /// `offset - ext_total` (`packet.rs:259:32`); the 255 case pins the other half
    /// of the same guard, an advertised length far past the capture.
    #[test]
    fn parse_ipv6_extension_header_longer_than_its_prefix() {
        let mut ext = vec![0u8; 64];
        ext[0] = IPPROTO_TCP; // the header's own next-header
        ext[1] = 7; // (7 + 1) * 8 = 64 B
        let l4 = tcp(1, 2, 5, &[0u8; 6]);
        let f = ipv6(IPPROTO_HOPOPTS, 64 + 20 + 6, &ext, &l4);
        let r = parse_packet(&f).expect("a complete 64 B hopopts header must parse");
        assert_eq!(r.ipv6_ext_len, 64);
        assert_eq!(r.l4_offset, ETH_HDR_LEN + 40 + 64);
        assert_eq!(r.l4_hdr_len, 20);
        assert_eq!(r.payload_offset, ETH_HDR_LEN + 40 + 64 + 20);
        assert_eq!(r.payload_len, 6);

        // Truncated inside the advertised extension header: the parse must stop
        // there rather than carry the stale offset into the L4 guards.
        assert!(parse_packet(&f[..ETH_HDR_LEN + 40 + 63]).is_none());

        // hdr_ext_len = 255 advertises (255 + 1) * 8 = 2048 B, which the 144 B
        // capture cannot back; rejecting it is the whole point of the guard.
        let mut huge = vec![0u8; 64];
        huge[0] = IPPROTO_TCP;
        huge[1] = 255;
        let f = ipv6(IPPROTO_HOPOPTS, 64 + 20 + 6, &huge, &l4);
        assert!(parse_packet(&f).is_none(), "a 2048 B header cannot fit");
    }
}
