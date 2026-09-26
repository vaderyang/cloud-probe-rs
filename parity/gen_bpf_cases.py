#!/usr/bin/env python3
"""Generate a deterministic (seed) corpus of filter expressions and Ethernet
frames for the libpcap<->pure-Rust BPF differential test.

Usage: gen_bpf_cases.py <seed> <n_pkts> <n_exprs> <exprs_out> <pkts_out>
"""
import ipaddress
import random
import sys


def mac(r):
    return ":".join("%02x" % r.randrange(256) for _ in range(6))


def gen_pkt(r, v4, v6, ports, macs):
    roll = r.random()
    eth = bytearray(14)
    eth[0:6] = r.randbytes(6)
    eth[6:12] = bytes.fromhex(macs[r.randrange(len(macs))].replace(":", ""))

    if roll < 0.48:  # IPv4
        eth[12:14] = b"\x08\x00"
        proto = r.choice([6, 6, 17, 17, 1, 132, 47, 0])
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = proto
        src = r.choice(v4) if r.random() < 0.8 else r.randbytes(4)
        dst = r.choice(v4) if r.random() < 0.8 else r.randbytes(4)
        ip[12:16] = src
        ip[16:20] = dst
        frag = r.choice([0, 0, 0, 0, 0, 1, 0x2000, 0x2001, 0x1fff])
        ip[6:8] = frag.to_bytes(2, "big")
        l4 = bytearray(r.randbytes(20))
        l4[0:2] = r.choice(ports).to_bytes(2, "big")
        l4[2:4] = r.choice(ports).to_bytes(2, "big")
        return bytes(eth + ip + l4)

    if roll < 0.78:  # IPv6
        eth[12:14] = b"\x86\xdd"
        nexth = r.choice([6, 6, 17, 17, 58, 0x2C, 0, 43])
        hdr = bytearray(40)
        hdr[0] = 0x60
        hdr[6] = nexth
        src = r.choice(v6) if r.random() < 0.8 else r.randbytes(16)
        dst = r.choice(v6) if r.random() < 0.8 else r.randbytes(16)
        hdr[8:24] = src
        hdr[24:40] = dst
        tail = bytearray()
        if nexth == 0x2C:
            fh = bytearray(8)
            fh[0] = r.choice([6, 17, 58])
            tail += fh
        l4 = bytearray(r.randbytes(8))
        l4[0:2] = r.choice(ports).to_bytes(2, "big")
        l4[2:4] = r.choice(ports).to_bytes(2, "big")
        return bytes(eth + hdr + tail + l4)

    if roll < 0.92:  # ARP / RARP
        eth[12:14] = b"\x08\x06" if r.random() < 0.7 else b"\x80\x35"
        arp = bytearray(28)
        arp[0:2] = (1).to_bytes(2, "big")
        arp[2:4] = b"\x08\x00"
        arp[4] = 6
        arp[5] = 4
        arp[6:8] = (1).to_bytes(2, "big")
        arp[8:14] = r.randbytes(6)
        arp[14:18] = r.choice(v4) if r.random() < 0.8 else r.randbytes(4)
        arp[18:24] = r.randbytes(6)
        arp[24:28] = r.choice(v4) if r.random() < 0.8 else r.randbytes(4)
        return bytes(eth + arp)

    # Random / truncated frames.
    n = r.randrange(0, 70)
    return bytes(r.randbytes(n))


def gen_exprs(r, v4s, v6s, ports, macs):
    a = ipaddress.IPv4Address(r.choice(v4s)).exploded
    b = ipaddress.IPv4Address(r.choice(v4s)).exploded
    a6 = str(ipaddress.IPv6Address(r.choice(v6s)))
    b6 = str(ipaddress.IPv6Address(r.choice(v6s)))
    p = r.choice(ports)
    p1, p2 = sorted(r.sample(ports, 2))
    m = r.choice(macs)
    n = ipaddress.IPv4Address(r.choice(v4s))
    plen = r.choice([8, 16, 24, 32])
    net = ipaddress.IPv4Network(f"{n}/{plen}", strict=False)

    templates = [
        f"host {a}",
        f"src host {a}",
        f"dst host {a}",
        f"ip host {a}",
        f"ip6 host {a6}",
        f"host {a6}",
        f"net {net}",
        f"host {a} and port {p}",
        f"(host {a}) and not host {b}",
        f"host {a} or host {b}",
        f"not host {a}",
        "udp",
        "tcp",
        "icmp",
        "icmp6",
        "ip",
        "ip6",
        "arp",
        "rarp",
        f"udp port {p}",
        f"tcp port {p}",
        f"port {p}",
        f"src port {p}",
        f"dst port {p}",
        f"portrange {p1}-{p2}",
        f"ether host {m}",
        f"udp and port {p}",
        f"tcp and (port {p1} or port {p2})",
        f"not (host {a} or host {b})",
        f"host {a} or udp",
        f"port {p1} or port {p2}",
        f"host {a6} and udp",
        f"udp and not host {b}",
        f"(net {net}) and not host {a}",
    ]
    return templates


def main():
    seed, npkts, nexprs, eo, po = (
        int(sys.argv[1]),
        int(sys.argv[2]),
        int(sys.argv[3]),
        sys.argv[4],
        sys.argv[5],
    )
    r = random.Random(seed)

    v4 = [bytes(r.randbytes(4)) for _ in range(5)]
    v4 += [bytes([10, 0, 0, 1]), bytes([10, 0, 0, 9]), bytes([192, 168, 1, 1])]
    v6 = [r.randbytes(16) for _ in range(3)]
    v6 += [bytes([0xFE, 0x80] + [0] * 13 + [1]), bytes(16)]
    ports = [53, 80, 443, 1234, 8080, 65535, 0, 100]
    macs = [mac(r) for _ in range(3)]
    macs += ["00:11:22:33:44:55"]

    exprs = gen_exprs(r, v4, v6, ports, macs)
    while len(exprs) < nexprs:
        exprs.extend(gen_exprs(r, v4, v6, ports, macs))
    exprs = exprs[:nexprs]

    pkts = [gen_pkt(r, v4, v6, ports, macs) for _ in range(npkts)]

    with open(eo, "w") as f:
        f.write("\n".join(exprs) + "\n")
    with open(po, "w") as f:
        f.write("\n".join(p.hex() for p in pkts) + "\n")


if __name__ == "__main__":
    main()
