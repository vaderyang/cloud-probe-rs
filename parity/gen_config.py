#!/usr/bin/env python3
"""Generate compact JSON configs for the C/Rust config differential test."""
import json
import random
import sys

random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 11)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000

LOG = [None, "DEBUG", "INFO", "WARN", "ERROR", "trace", "bad"]


def maybe(d, k, v, p=0.5):
    if random.random() < p:
        d[k] = v


def libpcap():
    c = {"interface": random.choice(["eth0", "eth1", "lo"])}
    maybe(c, "snaplen", random.choice([0, 96, 2048, 65535]), 0.6)
    maybe(c, "netns", "/proc/1/ns/net", 0.3)
    maybe(c, "bpf", random.choice(["", "port 80", "host 10.0.0.1", "tcp and port 443"]), 0.6)
    maybe(c, "buffer_size_mb", random.choice([1, 8, 256]), 0.5)
    maybe(c, "timeout_ms", random.choice([0, 3, 100]), 0.5)
    maybe(c, "not_filter_output_hosts", random.choice([True, False]), 0.4)
    return {"type": "libpcap", "libpcap": c}


def pcap_file():
    c = {"file_name": "a.pcap"}
    maybe(c, "bpf", "udp", 0.5)
    return {"type": "pcap_file", "pcap_file": c}


def output():
    t = random.choice(["null", "file", "rotating_file", "gre", "vxlan", "zmq", "bogus"])
    o = {"type": t}
    maybe(o, "rate_limit_mbps", random.choice([0, 1, 100]), 0.5)
    maybe(o, "slice", random.choice([0, 128, 1500]), 0.5)
    if t == "file":
        o["file"] = {"name": "out.pcap"}
    elif t == "rotating_file":
        c = {"file_root": "/tmp"}
        maybe(c, "max_file_interval", random.choice([-1, 60]), 0.6)
        o["rotating_file"] = c
    elif t == "gre":
        c = {"host": random.choice(["1.2.3.4", "10.0.0.1"])}
        maybe(c, "service_tag", 34, 0.5)
        maybe(c, "bind_device", "eth0", 0.3)
        maybe(c, "pmtudisc", random.choice(["do", "dont", "want"]), 0.5)
        o["gre"] = c
    elif t == "vxlan":
        c = {"host": "2.2.2.2"}
        maybe(c, "port", 4789, 0.5)
        maybe(c, "capture_time", True, 0.4)
        if random.random() < 0.5:
            c["vni1"] = random.randrange(1 << 24)
        else:
            c["vni2"] = random.randrange(1 << 24)
        maybe(c, "bind_device", "eth3", 0.3)
        maybe(c, "pmtudisc", "want", 0.4)
        if random.random() < 0.4:
            s = {}
            maybe(s, "max_payload_size", random.choice([0, 1400, 65535]), 0.6)
            maybe(s, "recalculate_checksum", True, 0.5)
            c["split"] = s
        o["vxlan"] = c
    elif t == "zmq":
        c = {"host": "2.2.2.2", "port": 1234, "uuid": "550e8400-e29b-41d4-a716-446655440000"}
        maybe(c, "hwm", 1000, 0.5)
        maybe(c, "service_tag", 3, 0.5)
        maybe(c, "heartbeat_ms", random.choice([0, 1000, 60000]), 0.5)
        o["zmq"] = c
    return o


def req_pattern():
    r = random.random()
    if r < 0.3:
        return {"type": "none"}
    if r < 0.6:
        return {"type": "auto"}
    o = {"type": "custom"}
    maybe(o, "custom", {"pattern": "host 1.2.3.4 and port 80"}, 0.8)
    return o


def task():
    t = {}
    maybe(t, "fingerprint", random.choice(["", "fp1", "fp2"]), 0.6)
    maybe(t, "req_pattern", req_pattern(), 0.7)
    t["capturer"] = random.choice([libpcap(), pcap_file()])
    t["outputs"] = [output() for _ in range(random.choice([0, 1, 1, 2]))]
    return t


for _ in range(N):
    cfg = {}
    maybe(cfg, "cpu_affinity", random.choice(["", "0", "1,2"]), 0.5)
    maybe(cfg, "log_level", random.choice(LOG), 0.7)
    em = random.choice([None, "rtc", "pipeline", "bad"])
    maybe(cfg, "execution_model", em, 0.7)
    if em == "pipeline" or (em is None and random.random() < 0.3):
        maybe(cfg, "pipeline", {"buffer_size_mb": random.choice([0, 64, 256])}, 0.8)
    if random.random() < 0.5:
        cfg["control"] = random.choice(
            [{"type": "unix", "unix": {"path": "cpworker.sock"}}, {"type": "bogus"}, {"type": "unix"}]
        )
    cfg["tasks"] = [task() for _ in range(random.choice([0, 1, 1, 2]))]
    print(json.dumps(cfg, separators=(",", ":")))
