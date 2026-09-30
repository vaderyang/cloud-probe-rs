#!/usr/bin/env python3
"""Generate req_pattern direction-judge queries for the C/Rust differential.

Each output line is ``<pattern>\t<frame_hex>``.  The C harness runs the frame
through ``req_pattern_judge_pkt_direction`` and the Rust harness through the
equivalent ``ReqPattern::judge_pkt_direction``; the two judged directions must
be identical.  This is the only differential that reaches ``extract_ipport``
and therefore the QinQ (stacked-VLAN) descent under test.

The C ``req_pattern.c`` only descends a stacked VLAN when the tag's EtherType is
``ETHERTYPE_VLAN`` (0x8100) — 802.1ad / 0x9100 / 0x9200 tags are accepted by the
Rust port (mirroring ``packet_split.c``) but not by the C req-pattern matcher.
Vectors therefore only stack 0x8100 tags, the domain where the two are defined
to agree; the wider tag set is pinned by the Rust unit tests instead.
"""
import ipaddress
import random
import struct
import sys

random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 7)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

PROTO_TCP = 6
PROTO_UDP = 17


def mac():
    return bytes(random.randrange(256) for _ in range(6))


def eth_frame(ether_type, payload):
    return mac() + mac() + struct.pack("!H", ether_type) + payload


def eth_vlan_frame(tpids, inner_ether_type, payload):
    """Ethernet + len(tpids) 0x8100 tags (outermost first) + inner frame."""
    body = struct.pack("!H", inner_ether_type) + payload
    for i in range(len(tpids) - 1, -1, -1):
        tci = struct.pack("!H", 0x0001)
        if i > 0:
            tci = struct.pack("!H", tpids[i]) + tci
        body = tci + body
    return mac() + mac() + struct.pack("!H", tpids[0]) + body


def tcp(sport, dport):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 0, 0, 0)


def udp(sport, dport):
    return struct.pack("!HHHH", sport, dport, 8, 0)


def l4(proto, sport, dport):
    return tcp(sport, dport) if proto == PROTO_TCP else udp(sport, dport)


def ipv4(src, dst, proto, sport, dport):
    payload = l4(proto, sport, dport)
    tot = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, proto, 0, src, dst)
    return hdr + payload


def ipv6(src, dst, proto, sport, dport):
    payload = l4(proto, sport, dport)
    hdr = struct.pack("!IHBB16s16s", 0x60 << 24, len(payload), proto, 64, src, dst)
    return hdr + payload


def rand_ip4():
    return bytes(random.randrange(256) for _ in range(4))


def rand_ip6():
    return bytes(random.randrange(256) for _ in range(16))


def build():
    """Return (frame_bytes, (src_ip, sport, dst_ip, dport) or None)."""
    depth = random.choices([0, 1, 2, 3], weights=[2, 3, 5, 4])[0]
    tpids = [ETHERTYPE_VLAN] * depth
    proto = random.choice([PROTO_TCP, PROTO_UDP])
    sport = random.choice([0, 80, 443, 4789, 8011, random.randrange(65536)])
    dport = random.choice([0, 80, 443, 4789, 8011, random.randrange(65536)])
    kind = random.random()
    is_tcp = proto == PROTO_TCP
    if kind < 0.35:
        src, dst = rand_ip4(), rand_ip4()
        payload = ipv4(src, dst, proto, sport, dport)
        inner_type = ETHERTYPE_IP
        fields = (str(ipaddress.IPv4Address(src)), sport, str(ipaddress.IPv4Address(dst)), dport)
    elif kind < 0.7:
        src, dst = rand_ip6(), rand_ip6()
        payload = ipv6(src, dst, proto, sport, dport)
        inner_type = ETHERTYPE_IPV6
        fields = (str(ipaddress.IPv6Address(src)), sport, str(ipaddress.IPv6Address(dst)), dport)
    elif kind < 0.85:
        payload = bytes(random.randrange(256) for _ in range(20))
        inner_type = ETHERTYPE_ARP
        fields = None
        is_tcp = False
    else:
        payload = bytes(random.randrange(256) for _ in range(8))
        inner_type = random.choice([0x1234, ETHERTYPE_ARP, 0x8847])
        fields = None
        is_tcp = False

    if depth == 0:
        frame = eth_frame(inner_type, payload)
    else:
        frame = eth_vlan_frame(tpids, inner_type, payload)

    # Occasionally truncate, exercising every layer's caplen bound. TCP frames
    # are left whole: C's req_pattern requires the full 20-byte TCP header to
    # expose the ports while the Rust port also exposes them from a short
    # capture, a pre-existing, unrelated divergence. (UDP's 8-byte header is
    # required by both, so truncating a UDP frame is comparable.)
    if not is_tcp and random.random() < 0.3:
        frame = frame[: random.randrange(len(frame) + 1)]
    return frame, fields


def pattern(fields):
    r = random.random()
    if fields is None or r < 0.15:
        # Unrelated / invalid patterns still exercise the judge path.
        return random.choice(
            [
                "host 10.0.0.1",
                "port 12345",
                "host 10.0.0.1 and port 12345",
                "host",
                "(host 1.2.3.4",
                "port 99999",
            ]
        )
    sip, sport, dip, dport = fields
    target, port = random.choice([(sip, sport), (dip, dport)])
    forms = [
        f"host {target}",
        f"port {port}",
        f"host {target} and port {port}",
        f"host {sip} or host {dip}",
        f"port {sport} and port {dport}",
    ]
    return random.choice(forms)


for _ in range(N):
    frame, fields = build()
    print(f"{pattern(fields)}\t{frame.hex()}")
