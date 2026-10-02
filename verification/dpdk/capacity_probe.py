#!/usr/bin/env python3
"""Read-only remote counter snapshot for capacity_capture.py."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = "/home/vader/cprs-bench"
CG = Path("/sys/fs/cgroup/cprs-capacity")


def timed(fn):
    before = time.monotonic()
    value = fn()
    after = time.monotonic()
    return {"time": (before + after) / 2, "span": after - before, "value": value}


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def kv(path):
    value = read(path)
    return {k: int(v) for k, v in (line.split() for line in value.splitlines())} if value else {}


def nic(iface):
    out = subprocess.check_output(["ethtool", "-S", iface], text=True)
    result = {}
    for line in out.splitlines():
        match = re.match(r"\s*([^:]+):\s*(\d+)\s*$", line)
        if match and re.search(r"packets|bytes_phy|drop|discard|error|out_of_buffer", match[1]):
            result[match[1]] = int(match[2])
    result["sysfs_rx_packets"] = int(read(f"/sys/class/net/{iface}/statistics/rx_packets"))
    result["sysfs_tx_packets"] = int(read(f"/sys/class/net/{iface}/statistics/tx_packets"))
    return result


def procs():
    result = {}
    for name in ["cpworker", "dpdk_primary"]:
        pids = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True).stdout.split()
        for pid in pids:
            stat = read(f"/proc/{pid}/stat")
            if not stat:
                continue
            fields = stat[stat.rfind(")") + 2:].split()
            status = read(f"/proc/{pid}/status")
            status = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
            smaps = read(f"/proc/{pid}/smaps_rollup") or ""
            mem = {}
            for line in smaps.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    if re.match(r"\s*\d+ kB", v):
                        mem[k] = int(v.split()[0]) * 1024
            result[name] = {"pid": int(pid), "utime_ticks": int(fields[11]),
                            "stime_ticks": int(fields[12]), "hz": os.sysconf("SC_CLK_TCK"),
                            "threads": int(status["Threads"]),
                            "allowed": status["Cpus_allowed_list"].strip(),
                            "cgroup": read(f"/proc/{pid}/cgroup"), "memory": mem}
    return result


def cgroup():
    result = {k: kv(CG / k) for k in ["cpu.stat", "memory.events", "memory.stat", "hugetlb.2MB.events"]}
    for k in ["cpu.max", "memory.max", "memory.current", "memory.swap.max", "memory.peak",
              "hugetlb.2MB.max", "hugetlb.2MB.current", "cgroup.procs"]:
        result[k] = read(CG / k)
    return result


def capture():
    env = dict(os.environ, LD_LIBRARY_PATH="/home/vader/dpdk-inst/lib/x86_64-linux-gnu")
    result = subprocess.run([f"{ROOT}/target/release/cpctl", "-u", "/tmp/cpcap.sock",
                             "-W", "30s" if len(sys.argv)>2 and sys.argv[2]=="quiet" else "3s", "-f", "jsonl", "stats", "-n", "1"],
                            env=env, capture_output=True, text=True, timeout=35 if len(sys.argv)>2 and sys.argv[2]=="quiet" else 6)
    if result.returncode:
        return {"error": result.stderr, "rc": result.returncode}
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def system():
    stat = read("/proc/stat").splitlines()[0].split()[1:]
    softnet = [line.split() for line in read("/proc/net/softnet_stat").splitlines()]
    return {"cpu_ticks": list(map(int, stat)), "hz": os.sysconf("SC_CLK_TCK"),
            "softnet_processed": sum(int(v[0], 16) for v in softnet),
            "softnet_dropped": sum(int(v[1], 16) for v in softnet),
            "softnet_time_squeeze": sum(int(v[2], 16) for v in softnet)}


def huge():
    return {str(p): int(p.read_text()) for p in Path("/sys/devices/system/node").glob(
        "node*/hugepages/hugepages-2048kB/free_hugepages")}


def snapshot(host):
    out = {"wall": time.time(), "nic": timed(lambda: nic("ens72np0" if host == "laojun" else "ens8np0"))}
    if host == "yinjiao":
        if Path("/sys/class/net/ens8v0").exists():
            out["vf"] = timed(lambda: nic("ens8v0"))
        out["processes"] = timed(procs)
        out["cgroup"] = timed(cgroup)
        out["system"] = timed(system)
        out["huge_free"] = huge()
        primary = read("/tmp/cpcap-primary-stats.json")
        if primary:
            out["primary"] = json.loads(primary)
        if Path("/tmp/cpcap.sock").exists() and not (len(sys.argv) > 2 and sys.argv[2] == "series_no_capture"):
            out["capture"] = timed(capture)
    return out


host = sys.argv[1]
if len(sys.argv) > 2 and sys.argv[2].startswith("series"):
    Path("/tmp/cpcap-probe-ready").touch()
    while not Path("/tmp/cpcap-go").exists():
        time.sleep(0.02)
    begin = time.monotonic() + 1
    samples = []
    for i in range(3):
        time.sleep(max(begin + i * 2.5 - time.monotonic(), 0))
        samples.append(snapshot(host))
    Path("/tmp/cpcap-series.json").write_text(json.dumps(samples))
else:
    print(json.dumps(snapshot(host)))
