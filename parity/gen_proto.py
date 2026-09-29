#!/usr/bin/env python3
"""Generate protocol-parity cases for gre/vxlan/zmq output encapsulators.

Each case is a file consumed by both `parity/c_proto.c` and
`cpworker-parity/src/bin/proto_parity.rs`. The generator is deliberately adversarial:
it emits stacked VLANs, boundary caplen values, timestamps that straddle the
1-second batch-flush window, and random directions.
"""
import os
import random
import sys

VLAN_TYPES = [0x8100, 0x88a8, 0x9100, 0x9200]


def rand_mac(r):
    return bytes(r.randrange(256) for _ in range(6))


def make_frame(r, caplen, force_vlan=None, max_tags=None):
    """Build a caplen-byte Ethernet frame, sometimes with stacked VLAN tags.

    NOTE: the C VLAN walk uses `caplen + MPLS_HDR_SIZE` as its bound, so it can
    over-count one VLAN header and (when `slice` truncates the frame) underflow
    `length - 14 - 4 - vlan_total_size`, performing an out-of-bounds memcpy.
    That is undefined behaviour in the original; the Rust port drops such
    packets instead. To keep the differential fuzz comparing defined behaviour
    we only emit VLAN stacks that fit in the *sliced* wire length
    (`max_tags`), terminated by a non-VLAN ethertype.
    """
    if caplen < 14:
        return bytes(r.randrange(256) for _ in range(caplen))
    frame = bytearray(r.randrange(256) for _ in range(caplen))
    frame[0:6] = rand_mac(r)
    frame[6:12] = rand_mac(r)
    limit = (caplen - 14) // 4
    if max_tags is not None:
        limit = min(limit, max_tags)
    want = force_vlan if force_vlan is not None else r.choice([0, 0, 1, 1, 2, 3, 4])
    n = max(0, min(want, limit))
    if n == 0:
        frame[12:14] = r.choice([0x0800, 0x86DD, 0x8847, 0x1234]).to_bytes(2, "big")
        return bytes(frame)
    frame[12:14] = r.choice(VLAN_TYPES).to_bytes(2, "big")
    for i in range(n):
        off = 14 + 4 * i
        frame[off:off + 2] = r.randrange(65536).to_bytes(2, "big")
        if i == n - 1:
            frame[off + 2:off + 4] = r.choice([0x0800, 0x86DD, 0x8847]).to_bytes(2, "big")
        else:
            frame[off + 2:off + 4] = r.choice(VLAN_TYPES).to_bytes(2, "big")
    return bytes(frame)


def gen_case(r):
    mode = r.choice(["gre", "vxlan", "zmq"])
    lines = [mode]
    if mode == "gre":
        service_tag = r.randrange(1 << 32)
        slice_ = r.choice([0, 0, 0, r.randrange(0, 200)])
        lines.append(f"{service_tag} {slice_}")
    elif mode == "vxlan":
        vni = r.randrange(1 << 24)
        vni_version = r.choice([0, 1])
        capture_time = r.choice([0, 1])
        slice_ = r.choice([0, 0, 0, r.randrange(0, 200)])
        lines.append(f"{vni} {vni_version} {capture_time} {slice_}")
    else:
        service_tag = r.randrange(1 << 16)
        slice_ = r.choice([0, 0, 0, r.randrange(0, 200)])
        heartbeat = 0  # avoid wall-clock-dependent heartbeats
        uuid = "-".join(
            [
                "%08x" % r.randrange(1 << 32),
                "%04x" % r.randrange(1 << 16),
                "%04x" % r.randrange(1 << 16),
                "%04x" % r.randrange(1 << 16),
                "%012x" % r.randrange(1 << 48),
            ]
        )
        lines.append(f"{service_tag} {slice_} {heartbeat} {uuid}")

    n = r.randrange(1, 400)
    ts_sec = r.randrange(1, 1 << 30)
    ts_usec = r.randrange(1_000_000)
    for _ in range(n):
        # Occasionally jump forward to trigger time-based flush.
        ts_sec += r.choice([0, 0, 0, 0, 1, 2])
        ts_usec = r.randrange(1_000_000)
        caplen = r.choice(
            [14, 18, 22, 34, 60, 64, 128, 512, 1500, 1514,
             r.randrange(19, 1600)]
        )
        if mode == "zmq" and caplen < 18:
            caplen = 18
        # Boundary: near the 65531 clamp / batch buffer.
        if r.random() < 0.01:
            caplen = r.choice([65531, 65535, 70000])
        caplen = min(caplen, 70000)
        wire_len = caplen + r.choice([0, 0, 0, r.randrange(0, 100)])
        direct = r.choice([0, 1, 2, 1, 2])
        # Limit VLAN tags so the C walk cannot over-count past the sliced length.
        eff = slice_ if (0 < slice_ < caplen) else caplen
        eff = min(eff, 65531)
        max_tags = max(0, (eff + 4 - 18) // 4)
        frame = make_frame(r, caplen, max_tags=max_tags)
        lines.append(f"pkt {ts_sec} {ts_usec} {caplen} {wire_len} {direct} {frame.hex()}")
    return "\n".join(lines) + "\n"


def main():
    nc = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    outdir = sys.argv[3] if len(sys.argv) > 3 else "."
    r = random.Random(seed)
    os.makedirs(outdir, exist_ok=True)
    for i in range(nc):
        with open(os.path.join(outdir, f"case_{i:05d}.txt"), "w") as f:
            f.write(gen_case(r))
    print(f"generated {nc} cases (seed={seed}) in {outdir}")


if __name__ == "__main__":
    main()
