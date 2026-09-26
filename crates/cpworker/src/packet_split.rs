//! Packet checksumming and fragmentation. Port of `packet_split.c`.
//!
//! The C implementation used hand-rolled SSE2/8x-unrolled checksum code for
//! GCC 4.8 compatibility. In Rust we let the compiler auto-vectorize a clean
//! RFC 1071 implementation.

use crate::packet::{be32, put_be16, put_be32, PacketParseResult, IPPROTO_TCP, IPPROTO_UDP};

/// Fold a 32-bit partial one's-complement sum into a 16-bit result.
#[inline]
fn cksum_fold(mut sum: u32) -> u16 {
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    sum as u16
}

/// Accumulate the 16-bit one's-complement sum over `buf`, chaining `initial`.
///
/// Mirrors the C implementation exactly: 16-bit words are read in **native**
/// byte order (the C code casts to `const uint16_t *`), not network order.
#[inline]
fn cksum_accumulate(buf: &[u8], initial: u32) -> u32 {
    let mut sum = initial;
    let mut chunks = buf.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_ne_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += b as u32;
    }
    sum
}

#[inline]
fn cksum_finish(partial: u32) -> u16 {
    !cksum_fold(partial)
}

/// C `htons()`: on little-endian this byte-swaps the numeric value.
#[inline]
fn htons(x: u16) -> u16 {
    x.to_be()
}

/// IPv4 header checksum. `ip_hdr` must begin at the IPv4 header.
#[must_use]
pub fn calculate_ip_checksum(ip_hdr: &[u8]) -> u16 {
    let ihl = ((ip_hdr[0] & 0x0f) as usize) * 4;
    cksum_finish(cksum_accumulate(&ip_hdr[..ihl.min(ip_hdr.len())], 0))
}

fn pseudo_header_sum_v4(ip_hdr: &[u8], protocol: u8, l4_len: u16) -> u32 {
    // Native reads of the 4-byte addresses, exactly like the C `uint16_t *` cast.
    let s0 = u16::from_ne_bytes([ip_hdr[12], ip_hdr[13]]) as u32;
    let s1 = u16::from_ne_bytes([ip_hdr[14], ip_hdr[15]]) as u32;
    let d0 = u16::from_ne_bytes([ip_hdr[16], ip_hdr[17]]) as u32;
    let d1 = u16::from_ne_bytes([ip_hdr[18], ip_hdr[19]]) as u32;
    s0 + s1 + d0 + d1 + htons(protocol as u16) as u32 + htons(l4_len) as u32
}

fn pseudo_header_sum_v6(ip_hdr: &[u8], protocol: u8, l4_len: u16) -> u32 {
    let mut sum: u32 = 0;
    for i in (8..40).step_by(2) {
        sum += u16::from_ne_bytes([ip_hdr[i], ip_hdr[i + 1]]) as u32;
    }
    sum + htons(l4_len) as u32 + htons(protocol as u16) as u32
}

/// TCP checksum using the appropriate pseudo-header.
#[must_use]
pub fn calculate_tcp_checksum(
    ipv4: Option<&[u8]>,
    ipv6: Option<&[u8]>,
    tcp: &[u8],
    tcp_len: u16,
) -> u16 {
    let sum = if let Some(ip) = ipv4 {
        pseudo_header_sum_v4(ip, IPPROTO_TCP, tcp_len)
    } else if let Some(ip) = ipv6 {
        pseudo_header_sum_v6(ip, IPPROTO_TCP, tcp_len)
    } else {
        0
    };
    cksum_finish(cksum_accumulate(&tcp[..tcp_len as usize], sum))
}

/// UDP checksum using the appropriate pseudo-header.
#[must_use]
pub fn calculate_udp_checksum(
    ipv4: Option<&[u8]>,
    ipv6: Option<&[u8]>,
    udp: &[u8],
    udp_len: u16,
) -> u16 {
    let sum = if let Some(ip) = ipv4 {
        pseudo_header_sum_v4(ip, IPPROTO_UDP, udp_len)
    } else if let Some(ip) = ipv6 {
        pseudo_header_sum_v6(ip, IPPROTO_UDP, udp_len)
    } else {
        0
    };
    cksum_finish(cksum_accumulate(&udp[..udp_len as usize], sum))
}

// Native (host-order) 16-bit store, matching a C `uint16_t` assignment to a
// struct field such as `ip_hdr->check = ck`.
#[inline]
fn put_ne16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_ne_bytes());
}

/// Number of fragments needed; 1 means no split required.
#[must_use]
pub fn calculate_fragment_count(r: &PacketParseResult, max_payload_size: i32) -> i32 {
    if max_payload_size <= 0 || r.payload_len <= max_payload_size as usize {
        return 1;
    }
    r.payload_len.div_ceil(max_payload_size as usize) as i32
}

/// Build fragment `fragment_index` into `output_buf`, returning its length.
pub fn build_fragment(
    r: &PacketParseResult,
    pkt_data: &[u8],
    fragment_index: i32,
    max_payload_size: i32,
    recalculate_checksum: bool,
    output_buf: &mut [u8],
) -> Option<usize> {
    let max = max_payload_size as usize;
    let payload_offset = (fragment_index as usize).checked_mul(max)?;
    if payload_offset >= r.payload_len {
        return None;
    }
    let remaining = r.payload_len - payload_offset;
    let frag_payload_size = remaining.min(max);
    if frag_payload_size == 0 {
        return None;
    }

    let header_len = r.payload_offset;
    let total_len = header_len + frag_payload_size;
    if output_buf.len() < total_len || pkt_data.len() < header_len + frag_payload_size {
        return None;
    }

    output_buf[..header_len].copy_from_slice(&pkt_data[..header_len]);
    output_buf[header_len..total_len].copy_from_slice(
        &pkt_data[header_len + payload_offset..header_len + payload_offset + frag_payload_size],
    );

    if r.is_ipv4 {
        let new_total = (r.ip_hdr_len + r.l4_hdr_len + frag_payload_size) as u16;
        put_be16(&mut output_buf[r.ip_offset + 2..], new_total);
        if recalculate_checksum {
            output_buf[r.ip_offset + 10] = 0;
            output_buf[r.ip_offset + 11] = 0;
            let ck = calculate_ip_checksum(&output_buf[r.ip_offset..r.ip_offset + r.ip_hdr_len]);
            put_ne16(&mut output_buf[r.ip_offset + 10..], ck);
        }
    } else if r.is_ipv6 {
        let new_payload = (r.ipv6_ext_len + r.l4_hdr_len + frag_payload_size) as u16;
        put_be16(&mut output_buf[r.ip_offset + 4..], new_payload);
    }

    if r.is_tcp {
        let seq = be32(&output_buf[r.l4_offset + 4..]);
        put_be32(
            &mut output_buf[r.l4_offset + 4..],
            seq.wrapping_add(payload_offset as u32),
        );
        if recalculate_checksum {
            let tcp_len = (r.l4_hdr_len + frag_payload_size) as u16;
            output_buf[r.l4_offset + 16] = 0;
            output_buf[r.l4_offset + 17] = 0;
            let ck = if r.is_ipv4 {
                calculate_tcp_checksum(
                    Some(&output_buf[r.ip_offset..]),
                    None,
                    &output_buf[r.l4_offset..],
                    tcp_len,
                )
            } else {
                calculate_tcp_checksum(
                    None,
                    Some(&output_buf[r.ip_offset..]),
                    &output_buf[r.l4_offset..],
                    tcp_len,
                )
            };
            put_ne16(&mut output_buf[r.l4_offset + 16..], ck);
        }
    } else if r.is_udp {
        let udp_len = (r.l4_hdr_len + frag_payload_size) as u16;
        put_be16(&mut output_buf[r.l4_offset + 4..], udp_len);
        if recalculate_checksum {
            output_buf[r.l4_offset + 6] = 0;
            output_buf[r.l4_offset + 7] = 0;
            let ck = if r.is_ipv4 {
                calculate_udp_checksum(
                    Some(&output_buf[r.ip_offset..]),
                    None,
                    &output_buf[r.l4_offset..],
                    udp_len,
                )
            } else {
                calculate_udp_checksum(
                    None,
                    Some(&output_buf[r.ip_offset..]),
                    &output_buf[r.l4_offset..],
                    udp_len,
                )
            };
            put_ne16(&mut output_buf[r.l4_offset + 6..], ck);
        }
    }

    Some(total_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{parse_packet, ETHERTYPE_IP, IPPROTO_TCP};

    /// Build a minimal Ethernet+IPv4+TCP frame with `payload`.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12..14].copy_from_slice(&ETHERTYPE_IP.to_be_bytes());
        p[14] = 0x45;
        let ip_total = 20 + 20 + payload.len();
        p[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
        p[14 + 9] = IPPROTO_TCP;
        p[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, 1]);
        p[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, 2]);
        p[14 + 20 + 12] = 0x50; // data offset 5
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn parse_basic() {
        let f = frame(&[1, 2, 3, 4]);
        let r = parse_packet(&f).unwrap();
        assert!(r.is_ipv4 && r.is_tcp);
        assert_eq!(r.payload_len, 4);
        assert_eq!(r.payload_offset, 14 + 20 + 20);
    }

    #[test]
    fn split_payload() {
        let payload: Vec<u8> = (0..100u8).collect();
        let f = frame(&payload);
        let r = parse_packet(&f).unwrap();
        assert_eq!(calculate_fragment_count(&r, 30), 4);

        let mut out = vec![0u8; 2048];
        let n = build_fragment(&r, &f, 1, 30, false, &mut out).unwrap();
        assert_eq!(n, 14 + 20 + 20 + 30);
        // Second fragment starts at payload offset 30.
        assert_eq!(&out[n - 30..n], &payload[30..60]);
    }
}
