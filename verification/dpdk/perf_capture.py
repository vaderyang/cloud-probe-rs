#!/usr/bin/env python3
"""Serialized physical 100G experiments. Always restore VFs and PAUSE.

Run after building primary.c and perf_pool.c on yinjiao. Results include
separate counter timestamps; pdump rates use the primary snapshot interval.
No git operations, persistent NIC changes, or NFS writes are performed.
"""
import argparse
import json
from pathlib import Path
import shlex
import signal
import subprocess
import time

SSH = ["ssh", "-o", "BatchMode=yes"]
ROOT = "/home/vader/cprs-bench"
LD = "/home/vader/dpdk-inst/lib/x86_64-linux-gnu"
SOCK = "/tmp/cpperf.sock"
DST = "1a:ca:0a:26:a8:8c"


def ssh(host, cmd, timeout=45):
    result = subprocess.run(SSH + [host, cmd], capture_output=True, text=True,
                            timeout=timeout, check=True)
    return result.stdout.strip()


def stop():
    ssh("laojun", "sudo -n pkill -9 -x dpdk-testpmd || true")
    ssh("yinjiao", "sudo -n pkill -9 -x cpworker || true; "
        "sudo -n pkill -TERM -x dpdk_primary || true; "
        "sudo -n pkill -TERM -x pdump_perf || true; "
        "sudo -n pkill -9 -x dpdk-testpmd || true")
    time.sleep(1)
    ssh("yinjiao", "sudo -n pkill -9 -x dpdk_primary || true; "
        "sudo -n pkill -9 -x pdump_perf || true; "
        "sudo -n rm -rf /var/run/dpdk/rte; "
        "sudo -n rm -f /tmp/cpperf.sock /tmp/cpperf-stats.json /tmp/cpperf-drain.json")


def restore():
    stop()
    # mlx5 may retain a VF's scheduler setting across device recreation.
    ssh("laojun", "if [ \"$(cat /sys/class/net/ens72np0/device/sriov_numvfs)\" -gt 0 ]; then "
        "sudo -n ip link set ens72np0 vf 0 max_tx_rate 0; fi")
    for host, pf in [("yinjiao", "ens8np0"), ("laojun", "ens72np0")]:
        ssh(host, f"sudo -n sh -c 'echo 0 > /sys/class/net/{pf}/device/sriov_numvfs'; "
            f"sudo -n ethtool -A {pf} autoneg off rx on tx on; "
            # Expand root-owned directory globs inside the privileged shell.
            "sudo -n sh -c 'rm -rf /var/run/dpdk/*; rm -f /tmp/core.*'")


def setup():
    stop()
    for host, pf, vf, mac in [("yinjiao", "ens8np0", "ens8v0", DST),
                              ("laojun", "ens72np0", "ens72v0", "12:e9:4b:91:bd:e0")]:
        ssh(host, f"sudo -n sh -c 'echo 1 > /sys/class/net/{pf}/device/sriov_numvfs'; "
            f"sleep 3; sudo -n ip link set {vf} address {mac}; "
            f"sudo -n ip link set {vf} up; sudo -n ethtool -A {pf} autoneg off rx off tx off")


def wait_log(path, marker):
    for _ in range(30):
        out = ssh("yinjiao", f"sudo -n cat {path} 2>/dev/null || true")
        if marker in out:
            return
        time.sleep(0.5)
    raise RuntimeError(out)


def start(case):
    stop()
    env = {"PRIMARY_RXQ": case.get("rxq", 4), "PRIMARY_STATS": "/tmp/cpperf-stats.json",
           "LD_LIBRARY_PATH": LD}
    for key in ["PRIMARY_TOUCH", "PRIMARY_PCAP", "PRIMARY_MBUF", "PRIMARY_DESC", "PRIMARY_INSPECT"]:
        if key in case:
            env[key] = case[key]
    envstr = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in env.items())
    primary = case.get("primary_binary", f"{ROOT}/dpdk_primary")
    device = shlex.quote(case.get("device", "0000:b8:00.1"))
    ssh("yinjiao", f"sudo -n setsid nohup env {envstr} {primary} "
        f"-l 32-47,56 --log-level notice -a {device} >/tmp/cpperf-primary.log 2>&1 </dev/null &")
    wait_log("/tmp/cpperf-primary.log", "pdump_init=ok")
    if case.get("backend", "cpworker") == "none":
        return
    if case.get("backend") == "drain":
        envstr = f"LD_LIBRARY_PATH={LD} PERF_CONSUMERS={case['consumers']} "
        envstr += f"PERF_PER_QUEUE={case.get('per_queue', 0)} PERF_RING={case.get('ring', 2048)} "
        envstr += f"PERF_CACHE={case.get('cache', 32)}"
        ssh("yinjiao", f"sudo -n setsid nohup env {envstr} {ROOT}/pdump_perf "
            "--proc-type secondary -l 48-55 --log-level notice -a 0000:b8:00.1 "
            ">/tmp/cpperf-worker.log 2>&1 </dev/null &")
        wait_log("/tmp/cpperf-worker.log", "drain ready")
        return
    cfg = {"control": {"type": "unix", "unix": {"path": SOCK}},
           "tasks": [{"capturer": {"type": "dpdk_pdump", "dpdk_pdump": {
               "interface": "0000:b8:00.1", "snaplen": case.get("snap", 2048),
               "bpf": "", "ring_size": case.get("ring", 2048)}},
               "outputs": [{"type": "null", "rate_limit_mbps": 0}]}]}
    if case.get("tasks"):
        cfg["tasks"] = cfg["tasks"] * case["tasks"]
    if case.get("affinity"):
        cfg["cpu_affinity"] = case["affinity"]
    envstr = f"LD_LIBRARY_PATH={LD} LD_PRELOAD={ROOT}/perf_pool.so"
    if case.get("tasks"):
        envstr += " PERF_PDUMP_QUEUES=1"
    for key, field in [("PERF_POOL_CACHE", "cache"), ("PERF_POOL_FACTOR", "pool"),
                       ("PERF_POOL_SOCKET", "socket")]:
        if field in case:
            envstr += f" {key}={case[field]}"
    affinity = "taskset -c 48-55 " if case.get("pin") else ""
    binary = case.get("binary", f"{ROOT}/target/release/cpworker")
    for worker in range(case.get("workers", 1)):
        worker_env = envstr
        if case.get("workers"):
            cfg["control"]["unix"]["path"] = f"/tmp/cpperf-q{worker}.sock"
            worker_env += f" PERF_PDUMP_QUEUE={worker}"
            affinity = f"taskset -c {48 + worker} "
        path = f"/tmp/cpperf-q{worker}.json"
        log = f"/tmp/cpperf-worker{worker}.log"
        ssh("yinjiao", f"cat >{path} <<'JSON'\n" + json.dumps(cfg) + "\nJSON")
        ssh("yinjiao", f"sudo -n rm -f /tmp/cpperf-q{worker}.sock; "
            "sudo -n setsid nohup bash -c " + shlex.quote(
                f"ulimit -c unlimited; exec {affinity}env {worker_env} {binary} -c {path}") +
            f" >{log} 2>&1 </dev/null &")
        wait_log(log, "create task-0 success")


def snapshot(host, case):
    pf = "ens72np0" if host == "laojun" else "ens8np0"
    cmd = f"date +%s.%N; sudo -n ethtool -S {pf}; "
    if host == "yinjiao":
        cmd += "echo PRIMARY; sudo -n cat /tmp/cpperf-stats.json; "
        cmd += "echo CPU; for name in cpworker dpdk_primary pdump_perf; do "
        cmd += 'for pid in $(pgrep -x "$name"); do '
        cmd += 'echo "$name"; sudo -n cat /proc/"$pid"/stat; done; done; '
        cmd += "echo CAPTURE; "
        if case.get("backend", "cpworker") == "cpworker":
            for worker in range(case.get("workers", 1)):
                sock = f"/tmp/cpperf-q{worker}.sock" if case.get("workers") else SOCK
                cmd += f"sudo -n env LD_LIBRARY_PATH={LD} {ROOT}/target/release/cpctl "
                cmd += f"-u {sock} -W 3s -f jsonl stats -n 1 2>/dev/null; "
        elif case.get("backend") == "drain":
            cmd += "sudo -n cat /tmp/cpperf-drain.json"
        else:
            cmd += "true"
    lines = ssh(host, cmd).splitlines()
    result = {"time": float(lines[0]), "cpu": {}}
    for i, line in enumerate(lines[1:], 1):
        if "packets_phy:" in line or "bytes_phy:" in line:
            key, value = line.split(":")
            result[key.strip()] = int(value)
        elif line == "PRIMARY":
            result["primary"] = json.loads(lines[i + 1])
        elif line in ["cpworker", "dpdk_primary", "pdump_perf"]:
            stat = lines[i + 1].split()
            result["cpu"][line] = result["cpu"].get(line, 0) + (int(stat[13]) + int(stat[14])) / 100
        elif line == "CAPTURE" and i + 1 < len(lines):
            result["captured"] = 0
            for encoded in lines[i + 1:]:
                data = json.loads(encoded)
                result["captured"] += (data["counters"]["cap_packets"]["packets"]
                                       if "counters" in data else data["captured"])
                if "counters" in data:
                    for key, unit in [("cap_bytes", "bytes"), ("fwd_packets", "packets"),
                                      ("fwd_bytes", "bytes")]:
                        if key in data["counters"]:
                            result[key] = result.get(key, 0) + data["counters"][key][unit]
    return result


def measure(case):
    start(case)
    # The script returns after three seconds; stop is automatic after 11 more.
    nc = case.get("txcores", 4)
    generator = case.get("generator", "/tmp/lj_tx.sh")
    ssh("laojun", f"{generator} 8-{8 + nc} {nc} 11 {DST}")
    time.sleep(1)
    l0, y0 = snapshot("laojun", case), snapshot("yinjiao", case)
    time.sleep(5)
    l1, y1 = snapshot("laojun", case), snapshot("yinjiao", case)
    ssh("laojun", "sudo -n pkill -9 -x dpdk-testpmd || true")
    dtl, dty = l1["time"] - l0["time"], y1["time"] - y0["time"]
    pd0, pd1 = y0["primary"], y1["primary"]
    dtp = pd1["time"] - pd0["time"]
    result = dict(case, offered_mpps=(l1["tx_packets_phy"]-l0["tx_packets_phy"])/dtl/1e6,
                  wire_mpps=(y1["rx_packets_phy"]-y0["rx_packets_phy"])/dty/1e6,
                  primary_mpps=(pd1["rx"]-pd0["rx"])/dtp/1e6,
                  seconds=dty, primary_seconds=dtp, snapshots=[l0, y0, l1, y1])
    for key in ["accepted", "ringfull", "nombuf", "filtered", "imissed", "rx_nombuf"]:
        result[key + "_mpps"] = (pd1[key]-pd0[key])/dtp/1e6
    if "external" in pd0:
        result["external_fraction"] = ((pd1["external"]-pd0["external"])/
                                       max(pd1["rx"]-pd0["rx"], 1))
        result["scattered_packets"] = pd1["scattered"]-pd0["scattered"]
    if "captured" in y0:
        result["captured_mpps"] = (y1["captured"]-y0["captured"])/dty/1e6
        if "fwd_packets" in y0:
            result["counter_check"] = {
                "captured": y1["captured"]-y0["captured"],
                "forwarded": y1["fwd_packets"]-y0["fwd_packets"],
                "captured_bytes": y1["cap_bytes"]-y0["cap_bytes"],
                "forwarded_bytes": y1["fwd_bytes"]-y0["fwd_bytes"]}
    else:
        result["captured_mpps"] = result["primary_mpps"]
    result["cpu_cores"] = {name: (value-y0["cpu"][name])/dty
                           for name, value in y1["cpu"].items()}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", help="JSON array of cases")
    parser.add_argument("output", help="append-only JSONL evidence")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        setup()
        for case in json.loads(Path(args.cases).read_text()):
            print("START " + json.dumps(case), flush=True)
            try:
                result = measure(case)
            except RuntimeError as error:
                result = dict(case, error=str(error))
            with open(args.output, "a") as f:
                f.write(json.dumps(result) + "\n")
            print(json.dumps({k: v for k, v in result.items() if k != "snapshots"}), flush=True)
            ssh("yinjiao", "sudo -n tail -5 /tmp/cpperf-worker.log 2>/dev/null || true")
    finally:
        restore()
        print("RESTORED", flush=True)


if __name__ == "__main__":
    main()
