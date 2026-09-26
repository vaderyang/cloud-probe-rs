#!/usr/bin/env python3
"""Generate a benchmark PCAP: N valid Ethernet/IPv4/UDP frames of mixed sizes.

Usage: gen_pcap.py <N> <out.pcap> [seed]

Prints "<packets> <bytes>" to stdout.
"""
import random
import struct
import sys

SIZES = [64, 64, 64, 128, 128, 256, 512, 1024, 1514]


def frame(rng, size):
    b = bytearray(size)
    b[0:6] = bytes.fromhex("001122334455")
    b[6:12] = bytes.fromhex("66778899aabb")
    b[12:14] = b"\x08\x00"
    if size >= 42:
        ip = 14
        b[ip] = 0x45
        b[ip + 1] = 0
        struct.pack_into(">H", b, ip + 2, size - 14)  # total length
        struct.pack_into(">H", b, ip + 4, rng.randrange(65536))  # id
        b[ip + 8] = 64  # ttl
        b[ip + 9] = 17  # UDP
        b[ip + 10] = 0
        b[ip + 11] = 0
        b[ip + 12 : ip + 16] = bytes([10, 0, 0, 1])
        b[ip + 16 : ip + 20] = bytes([10, 0, 0, 2])
        udp = ip + 20
        struct.pack_into(">H", b, udp, rng.randrange(1, 65535))
        struct.pack_into(">H", b, udp + 2, 53)
        struct.pack_into(">H", b, udp + 4, size - 14 - 20)
        struct.pack_into(">H", b, udp + 6, 0)
    # Random payload after the headers.
    for i in range(42, size):
        b[i] = rng.randrange(256)
    return bytes(b)


def main():
    n = int(sys.argv[1])
    out = sys.argv[2]
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    rng = random.Random(seed)
    total = 0
    with open(out, "wb") as f:
        # pcap global header: magic, v2.4, thiszone, sigfigs, snaplen, Ethernet
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for _ in range(n):
            pkt = frame(rng, rng.choice(SIZES))
            total += len(pkt)
            # Constant timestamp (0) so the capturer is never paced by time.
            f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
            f.write(pkt)
    print(n, total)


if __name__ == "__main__":
    main()
