#!/usr/bin/env python3
"""Capture-backend benchmark: AF_PACKET vs DPDK pdump (cloud-probe-rs).

Orchestrates laojun (testpmd txonly, 100G) -> yinjiao (100G VF capture).
Metrics per case: offered (laojun tx_packets_phy), wire (yinjiao rx_packets_phy),
captured (cpworker cap_packets via cpctl), and cpworker/primary CPU.
"""

import json
import subprocess
import sys
import tempfile
import time

SSH = ["ssh", "-o", "BatchMode=yes"]
LJ = "laojun"
YJ = "yinjiao"
DST = "1a:ca:0a:26:a8:8c"
TMP = tempfile.gettempdir()
SOCK = f"{TMP}/cpbench.sock"
CFG = f"{TMP}/cpbench.json"
RUNLOG = f"{TMP}/cpbench_run.log"
PRILOG = f"{TMP}/cpbench_primary.log"
TXSH = f"{TMP}/lj_tx.sh"
BIN = "$HOME/cprs-bench/target/release"
LD = "LD_LIBRARY_PATH=$HOME/dpdk-inst/lib/x86_64-linux-gnu"
DPDK_BDF = "0000:b8:00.1"


def ssh(host, cmd, timeout=40):
    res = subprocess.run(SSH + [host, cmd], capture_output=True, text=True, timeout=timeout)
    return res.stdout.strip()


def sudo_yj(cmd):
    return ssh(YJ, "export " + LD + "; " + cmd)


def phy(host, iface, keys):
    out = ssh(host, f"sudo -n ethtool -S {iface}")
    d = {}
    for ln in out.splitlines():
        parts = ln.split(":")
        if len(parts) == 2 and parts[0].strip() in keys:
            d[parts[0].strip()] = int(parts[1].strip())
    return d


def tp():
    return phy(LJ, "ens72np0", {"tx_packets_phy", "tx_bytes_phy"})


def yp():
    return phy(YJ, "ens8np0", {"rx_packets_phy", "rx_bytes_phy"})


def cap():
    out = sudo_yj(f"sudo -n -E {BIN}/cpctl -u {SOCK} -W 5s -f jsonl stats -n 1 2>/dev/null | tail -1")
    try:
        counters = json.loads(out)["counters"]
        return counters["cap_packets"]["packets"], counters["cap_bytes"]["bytes"]
    except (KeyError, TypeError, ValueError):
        return None, None


def cpusecs(name):
    pid = ssh(YJ, f"pgrep -x {name} | head -1")
    if not pid:
        return None, None
    stat = ssh(YJ, f"sudo -n cat /proc/{pid}/stat").split()
    if len(stat) < 15:
        return pid, None
    return pid, (int(stat[13]) + int(stat[14])) / 100.0  # utime+stime (clock ticks, 100Hz)


def stop_all():
    ssh(YJ, "sudo -n pkill -9 cpworker 2>/dev/null; sudo -n pkill -9 dpdk_primary 2>/dev/null; "
            f"sudo -n pkill -9 dpdk-testpmd 2>/dev/null; sudo -n rm -f {SOCK}; true")
    ssh(LJ, "sudo -n pkill -9 dpdk-testpmd 2>/dev/null; true")


def write_cfg(cfg):
    ssh(YJ, f"cat > {CFG} <<'J'\n{cfg}\nJ")


def start_backend(kind, ring_size=2048):
    stop_all()
    time.sleep(4)
    ssh(YJ, "sudo -n rm -rf /var/run/dpdk/rte /var/run/dpdk/bench; true")
    control = {"control": {"type": "unix", "unix": {"path": SOCK}}}
    if kind == "af_packet":
        cfg = dict(control, tasks=[{"capturer": {"type": "libpcap",
                   "libpcap": {"interface": "ens8v0", "snaplen": 2048,
                               "buffer_size_mb": 256, "bpf": "", "timeout_ms": 1000}},
                   "outputs": [{"type": "null", "rate_limit_mbps": 0}]}])
        write_cfg(json.dumps(cfg))
        sudo_yj(f"sudo -n setsid nohup env {LD} {BIN}/cpworker -c {CFG} >{RUNLOG} 2>&1 &")
    else:
        cfg = dict(control, tasks=[{"capturer": {"type": "dpdk_pdump",
                   "dpdk_pdump": {"interface": DPDK_BDF, "snaplen": 2048,
                                  "bpf": "", "ring_size": ring_size}},
                   "outputs": [{"type": "null", "rate_limit_mbps": 0}]}])
        write_cfg(json.dumps(cfg))
        sudo_yj(f"sudo -n setsid nohup env {LD} $HOME/cprs-bench/dpdk_primary -l 32-35 "
                f"--log-level notice -a {DPDK_BDF} >{PRILOG} 2>&1 &")
        for _ in range(25):
            if "pdump_init=ok" in ssh(YJ, f"sudo -n cat {PRILOG} 2>/dev/null"):
                break
            time.sleep(1)
        sudo_yj(f"sudo -n setsid nohup env {LD} {BIN}/cpworker -c {CFG} >{RUNLOG} 2>&1 &")
    for _ in range(40):
        if "create task-0 success" in ssh(YJ, f"sudo -n cat {RUNLOG} 2>/dev/null"):
            return True
        time.sleep(0.5)
    print("  !! backend failed:", ssh(YJ, f"sudo -n tail -3 {RUNLOG}"))
    return False


def run_case(kind, cores, dur=8, ring_size=2048):
    ncores = int(cores.split("-")[1]) - int(cores.split("-")[0])
    if not start_backend(kind, ring_size):
        return None
    time.sleep(1)
    ssh(LJ, f"{TXSH} {cores} {ncores} {dur + 8} {DST}")
    time.sleep(4)  # ramp
    l0, y0 = tp(), yp()
    c0, _ = cap()
    _, cpu0 = cpusecs("cpworker")
    _, pri0 = cpusecs("dpdk_primary")
    t0 = time.time()
    time.sleep(dur)
    l1, y1 = tp(), yp()
    c1, _ = cap()
    _, cpu1 = cpusecs("cpworker")
    _, pri1 = cpusecs("dpdk_primary")
    t1 = time.time()
    offered = max(l1["tx_packets_phy"] - l0["tx_packets_phy"], 1)
    wire = max(y1["rx_packets_phy"] - y0["rx_packets_phy"], 0)
    got = (c1 - c0) if (c0 is not None and c1 is not None) else None
    secs = t1 - t0
    res = {"backend": kind, "cores": cores, "secs": round(secs, 2),
           "offered_pps": offered / secs, "wire_pps": wire / secs,
           "offered_Gbps": (l1["tx_bytes_phy"] - l0["tx_bytes_phy"]) * 8 / secs / 1e9,
           "cap_pps": (got / secs) if got is not None else None,
           "cap_pct_of_wire": (100 * got / wire) if (got is not None and wire) else None,
           "cpu_cpworker_s": (round(cpu1 - cpu0, 2) if (cpu0 is not None and cpu1 is not None) else None),
           "cpu_primary_s": (round(pri1 - pri0, 2) if (pri0 is not None and pri1 is not None) else None)}
    print("  " + json.dumps(res), flush=True)
    return res


def main():
    ring = int(sys.argv[1]) if len(sys.argv) > 1 else 2048
    results = []
    for kind in ["af_packet", "dpdk_pdump"]:
        for cores in ["8-9", "8-10", "8-12"]:
            print(f"== {kind} cores={cores} ==", flush=True)
            res = run_case(kind, cores, ring_size=ring)
            if res:
                results.append(res)
    print("\n==== SUMMARY ====")
    for res in results:
        print(json.dumps(res))
    stop_all()


if __name__ == "__main__":
    main()
