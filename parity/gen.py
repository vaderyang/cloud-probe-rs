#!/usr/bin/env python3
"""Generate random Ethernet frames for the C/Rust packet_split differential test.

Each output line: <max_payload_size> <recalc 0|1> <packet_hex>
"""
import random
import struct
import sys

random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 1234)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000


def eth(etype):
    dst = bytes(random.randrange(256) for _ in range(6))
    src = bytes(random.randrange(256) for _ in range(6))
    return dst + src + struct.pack("!H", etype)


def ipv4(proto, payload, tot_len=None):
    total = 20 + len(payload) if tot_len is None else tot_len
    hdr = bytes([0x45, 0])
    hdr += struct.pack("!H", total)
    hdr += struct.pack("!H", random.randrange(65536))
    hdr += struct.pack("!H", 0)
    hdr += bytes([64, proto])
    hdr += struct.pack("!H", 0)
    hdr += bytes(random.randrange(256) for _ in range(4))
    hdr += bytes(random.randrange(256) for _ in range(4))
    return hdr + payload


def ipv6(nexthdr, payload, plen=None):
    plen = len(payload) if plen is None else plen
    hdr = bytes([0x60, 0, 0, 0]) + struct.pack("!H", plen) + bytes([nexthdr, 64])
    hdr += bytes(random.randrange(256) for _ in range(16))
    hdr += bytes(random.randrange(256) for _ in range(16))
    return hdr + payload


def tcp(payload):
    return struct.pack(
        "!HHIIBBHHH",
        random.randrange(65536),
        random.randrange(65536),
        random.randrange(2**32),
        0,
        0x50,
        0x02,
        8192,
        0,
        0,
    ) + payload


def udp(payload):
    return struct.pack(
        "!HHHH",
        random.randrange(65536),
        random.randrange(65536),
        8 + len(payload),
        0,
    ) + payload


def vlan_tags():
    tags = b""
    n = random.choice([0, 0, 0, 1, 1, 2])
    for _ in range(n):
        tags += struct.pack("!HH", random.randrange(65536), 0x8100)
    return tags, n


def payload():
    style = random.random()
    if style < 0.3:
        ln = random.randrange(0, 40)
    elif style < 0.8:
        ln = random.randrange(0, 1500)
    else:
        ln = random.randrange(1500, 4000)
    return bytes(random.randrange(256) for _ in range(ln))


def make_packet():
    pl = payload()
    l4 = random.choice([0, 1])
    if l4 == 0:
        trans = tcp(pl)
        proto = 6
    else:
        trans = udp(pl)
        proto = 17

    ipver = random.choice([4, 4, 4, 6, 6])
    if ipver == 4:
        tot = random.choice([None, None, 20 + len(trans), 20 + len(trans) + random.randrange(0, 32)])
        ip = ipv4(proto, trans, tot)
        et = 0x0800
    else:
        plen = random.choice([None, None, len(trans), len(trans) + random.randrange(0, 32)])
        ip = ipv6(proto, trans, plen)
        et = 0x86DD

    tags, n = vlan_tags()
    if n:
        # outer etype is the first VLAN tag; inner etype is the actual IP etype.
        frame = eth(0x8100) + tags[:-4] + struct.pack("!HH", struct.unpack("!H", tags[-4:-2])[0], et) + ip
    else:
        frame = eth(et) + ip

    # Occasionally truncate to exercise parse failures.
    if random.random() < 0.08:
        frame = frame[: random.randrange(0, max(1, len(frame)))]

    return frame


MAX = [0, 8, 16, 64, 200, 500, 1000, 1500, 65535]
for _ in range(N):
    frame = make_packet()
    maxp = random.choice(MAX)
    recalc = random.choice([0, 1])
    print(f"{maxp} {recalc} {frame.hex()}")
