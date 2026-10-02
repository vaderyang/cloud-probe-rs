#!/usr/bin/env python3
"""Serialize short lab bursts under a cpworker-only 1 CPU / 512 MiB cgroup.

Reuses perf_capture.py's SSH/setup/restore helpers. Raw snapshots retain each
counter's own monotonic timestamp. DPDK hugepage footprint is recorded separately
from memory.current because shared allocations may be charged to the primary.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shlex
import signal
import select
import subprocess
import time

import perf_capture as perf

CG = "/sys/fs/cgroup/cprs-capacity"
perf.SSH += ["-o", "ControlMaster=auto", "-o", "ControlPersist=120", "-o", "ControlPath=/tmp/cpcap-ssh-%r@%h:%p"]
ROOT = perf.ROOT
LD = perf.LD
SOCK = "/tmp/cpcap.sock"


class Remote:
    def __init__(self, host):
        server = "import sys,json,subprocess\nfor line in sys.stdin:\n req=json.loads(line); p=subprocess.run(req['cmd'],shell=True,capture_output=True,text=True,timeout=req['timeout']); print(json.dumps({'stdout':p.stdout,'stderr':p.stderr,'rc':p.returncode}),flush=True)"
        self.proc = subprocess.Popen(perf.SSH + [host, "python3 -u -c " + shlex.quote(server)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def run(self, cmd, timeout):
        self.proc.stdin.write(json.dumps({'cmd':cmd,'timeout':timeout}) + "\n")
        self.proc.stdin.flush()
        if not select.select([self.proc.stdout], [], [], timeout + 5)[0]:
            raise TimeoutError(cmd)
        data = json.loads(self.proc.stdout.readline())
        if data['rc']:
            raise RuntimeError(data['stderr'] + data['stdout'])
        return data['stdout'].strip()


remotes = {}

def ssh(host, cmd, timeout=45):
    if host not in remotes:
        remotes[host] = Remote(host)
    return remotes[host].run(cmd, timeout)

perf.ssh = ssh


def deploy():
    subprocess.run(["scp", "-o", "BatchMode=yes", str(Path(__file__).with_name("capacity_tx.c")),
                    "laojun:/tmp/capacity_tx.c"], check=True, capture_output=True)
    perf.ssh("laojun", "export PKG_CONFIG_PATH=/home/vader/dpdk-inst/lib/x86_64-linux-gnu/pkgconfig; cc -O3 -Wall /tmp/capacity_tx.c -o /tmp/capacity_tx $(pkg-config --cflags --libs libdpdk)")
    subprocess.run(["scp", "-o", "BatchMode=yes", str(Path(__file__).with_name("capacity_probe.py")),
                    "yinjiao:/tmp/cpcap-probe.py"], check=True, capture_output=True)
    subprocess.run(["scp", "-o", "BatchMode=yes", str(Path(__file__).with_name("capacity_probe.py")),
                    "laojun:/tmp/cpcap-probe.py"], check=True, capture_output=True)


def stop():
    perf.ssh("laojun", "sudo -n pkill -TERM -x capacity_tx || true")
    for host in ["yinjiao", "laojun"]:
        perf.ssh(host, "sudo -n pkill -f '^python3 /tmp/cpcap-probe.py' || true")
    perf.stop()
    perf.ssh("yinjiao", "sudo -n rm -f /tmp/cpcap.sock /tmp/cpcap-primary-stats.json")


def budget():
    perf.ssh("yinjiao", f"sudo -n mkdir -p {CG}; sudo -n sh -c " + shlex.quote(
        f"echo '100000 100000' > {CG}/cpu.max; echo 536870912 > {CG}/memory.max; "
        f"echo 0 > {CG}/memory.swap.max; echo 536870912 > {CG}/hugetlb.2MB.max"))


def snap(host, quiet=False):
    return json.loads(perf.ssh(host, f"sudo -n python3 /tmp/cpcap-probe.py {host}" + (" quiet" if quiet else "")))


def launch(command, logfile, constrained=False):
    if constrained:
        command = f"echo $$ > {CG}/cgroup.procs; exec " + command
    else:
        command = "exec " + command
    perf.ssh("yinjiao", "sudo -n setsid nohup bash -c " + shlex.quote(command) +
             f" >{logfile} 2>&1 </dev/null &")


def start(case):
    stop()
    budget()
    backend = case["backend"]
    initial = snap("yinjiao")
    if backend != "af_packet":
        direct = backend.startswith("direct")
        cores = "32" if direct else "32-36"
        env = f"LD_LIBRARY_PATH={LD} PRIMARY_RXQ={1 if direct else 4} "
        env += "PRIMARY_MBUF=32768 PRIMARY_STATS=/tmp/cpcap-primary-stats.json"
        if backend == "direct_pcap":
            env += " PRIMARY_PCAP=/dev/null"
        device = case.get("device", "0000:b8:00.1")
        command = f"env {env} {ROOT}/dpdk_primary -l {cores} --log-level notice -a {shlex.quote(device)}"
        launch(command, "/tmp/cpcap-primary.log", constrained=direct)
        perf.wait_log("/tmp/cpcap-primary.log", "pdump_init=ok")
    primary_only = snap("yinjiao")
    if backend.startswith("direct"):
        return [initial, primary_only]
    capturer = {"type": "libpcap", "libpcap": {"interface": "ens8v0", "snaplen": 2048,
                "buffer_size_mb": case.get("ring_mb", 8), "bpf": "", "timeout_ms": 1000}} if backend == "af_packet" else {
                "type": "dpdk_pdump", "dpdk_pdump": {"interface": "0000:b8:00.1", "snaplen": 2048,
                                                        "bpf": "", "ring_size": case.get("ring", 65536)}}
    cfg = {"cpu_affinity": case.get("affinity", "48-49"), "control": {"type": "unix", "unix": {"path": SOCK}},
           "tasks": [{"capturer": capturer, "outputs": [{"type": "null", "rate_limit_mbps": 0}]}]}
    if case.get("pipeline"):
        cfg.update(execution_model="pipeline", pipeline={"buffer_size_mb": case["pipeline"]})
    perf.ssh("yinjiao", "cat >/tmp/cpcap.json <<'JSON'\n" + json.dumps(cfg) + "\nJSON")
    prefix = f"taskset -c {case.get('affinity', '48-49')} " if case.get("affinity", "48-49") else ""
    launch(prefix + f"env LD_LIBRARY_PATH={LD} {ROOT}/target/release/cpworker -c /tmp/cpcap.json",
           "/tmp/cpcap-worker.log", constrained=True)
    # Detect OOM/startup failure promptly, instead of polling for a whole minute.
    for _ in range(16):
        log = perf.ssh("yinjiao", "sudo -n cat /tmp/cpcap-worker.log; pgrep -x cpworker || true")
        if "create task-0 success" in log:
            return [initial, primary_only, snap("yinjiao")]
        if "error:" in log or "failed" in log or ("cpworker" in log and not log.splitlines()[-1].isdigit()):
            raise RuntimeError(log)
        time.sleep(0.5)
    raise RuntimeError(log)


def rate(a, b, key):
    return (b["value"][key] - a["value"][key]) / (b["time"] - a["time"]) / 1e6


def cap_counters(s):
    result = {}
    for task in s["capture"]["value"]:
        for k, v in task["counters"].items():
            if isinstance(v, dict) and "packets" in v:
                result[k] = result.get(k, 0) + v["packets"]
    return result


def calculate(case, samples, before=None, drain=None):
    l0, y0 = samples[0]
    l1, y1 = samples[-1]
    result = dict(case, offered_mpps=rate(l0["nic"], l1["nic"], "tx_packets_phy"),
                  wire_mpps=rate(y0["nic"], y1["nic"], "rx_packets_phy"))
    if "capture" in y1 or case.get("burst_capture"):
        csrc0, csrc1 = (before, drain) if case.get("burst_capture") else (y0, y1)
        c0, c1 = cap_counters(csrc0), cap_counters(csrc1)
        dt = csrc1["capture"]["time"] - csrc0["capture"]["time"]
        stamps = [y["capture"]["value"][0]["ts"] for y in [csrc0, csrc1]]
        dt = datetime.fromisoformat(stamps[1][:26] + stamps[1][-6:]).timestamp() - datetime.fromisoformat(stamps[0][:26] + stamps[0][-6:]).timestamp()
        result["capture_counter_seconds"] = dt
        if case.get("burst_capture"):
            dt = 14.0
            result["capture_window_mode"] = "whole-14s-burst"
        result["capture_seconds"] = dt
        result["cap_mpps"] = (c1["cap_packets"] - c0["cap_packets"]) / dt / 1e6
        result["cap_deltas"] = {k: c1[k] - c0[k] for k in c1}
        result["cap_drop_mpps"] = result["cap_deltas"]["drop_packets"] / dt / 1e6
    if "primary" in y1:
        p0, p1 = y0["primary"], y1["primary"]
        dt = p1["time"] - p0["time"]
        result["primary_seconds"] = dt
        for k in ["rx", "accepted", "ringfull", "nombuf", "filtered", "imissed", "rx_nombuf"]:
            result[f"primary_{k}_mpps"] = (p1[k] - p0[k]) / dt / 1e6
        if case["backend"].startswith("direct"):
            result["cap_mpps"] = result["primary_rx_mpps"]
    dt = y1["processes"]["time"] - y0["processes"]["time"]
    result["cpu_seconds"] = dt
    result["cpu_cores"] = {}
    for k, v1 in y1["processes"]["value"].items():
        v0 = y0["processes"]["value"][k]
        ticks = sum(v1[f"{t}time_ticks"] - v0[f"{t}time_ticks"] for t in ["u", "s"])
        result["cpu_cores"][k] = ticks / v1["hz"] / dt
    g0, g1 = y0["cgroup"]["value"], y1["cgroup"]["value"]
    result["cgroup_cpu_delta"] = {k: g1["cpu.stat"][k] - g0["cpu.stat"][k] for k in g1["cpu.stat"]}
    result["memory_current_mib"] = max(int(y["cgroup"]["value"]["memory.current"]) for _, y in samples) / 2**20
    result["memory_events_delta"] = {k: g1["memory.events"][k] - g0["memory.events"][k] for k in g1["memory.events"]}
    result["system_softirq_cores"] = (y1["system"]["value"]["cpu_ticks"][6] - y0["system"]["value"]["cpu_ticks"][6]) / 100 / (y1["system"]["time"] - y0["system"]["time"])
    result["vf_deltas"] = {k: y1["vf"]["value"][k] - y0["vf"]["value"][k] for k in y1.get("vf", {}).get("value", {}) if "drop" in k or "buffer" in k or k in ["rx_packets", "rx_packets_phy"]}
    result["samples"] = samples
    return result


def measure(case):
    startup = start(case)
    shape = 0
    perf.ssh("laojun", "sudo -n ip link set ens72np0 vf 0 max_tx_rate 0")
    before = [snap("laojun"), snap("yinjiao")]
    for host in ["yinjiao", "laojun"]:
        perf.ssh(host, "sudo -n rm -f /tmp/cpcap-go /tmp/cpcap-series.json /tmp/cpcap-probe-ready; sudo -n setsid nohup python3 /tmp/cpcap-probe.py " + host + (" series_no_capture" if case.get("burst_capture") and not case.get("live_stats") else " series") + " >/tmp/cpcap-series.log 2>&1 </dev/null &")
    for host in ["yinjiao", "laojun"]:
        perf.ssh(host, "for i in $(seq 1 120); do [ -f /tmp/cpcap-probe-ready ] && break; sleep 0.1; done; test -f /tmp/cpcap-probe-ready")
    if case.get("testpmd"):
        nc = case.get("txcores", 4)
        perf.ssh("laojun", f"/tmp/lj_tx.sh 8-{8 + nc} {nc} 14 {perf.DST}")
    else:
        command = f"env LD_LIBRARY_PATH={LD} CAP_TX_MPPS={case['target_mpps']} CAP_TX_SECONDS=14 CAP_TX_QUEUES=4 /tmp/capacity_tx --no-huge -m 512 -l 8-12 --log-level notice -a 0000:46:00.1"
        perf.ssh("laojun", "sudo -n rm -f /tmp/cpcap-tx.log; sudo -n setsid nohup " + command + " >/tmp/cpcap-tx.log 2>&1 </dev/null &")
        for _ in range(40):
            log = perf.ssh("laojun", "sudo -n cat /tmp/cpcap-tx.log")
            if "CAP_TX_READY" in log:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(log)
        time.sleep(2)
    for host in ["laojun", "yinjiao"]:
        perf.ssh(host, "sudo -n touch /tmp/cpcap-go")
    time.sleep(7.5)
    series = {}
    for host in ["laojun", "yinjiao"]:
        perf.ssh(host, "for i in $(seq 1 120); do [ -f /tmp/cpcap-series.json ] && break; sleep 0.1; done")
        series[host] = json.loads(perf.ssh(host, "sudo -n cat /tmp/cpcap-series.json"))
    samples = list(map(list, zip(series["laojun"], series["yinjiao"])))
    if case.get("burst_capture"):
        for _ in range(80):
            if "CAP_TX_DONE" in perf.ssh("laojun", "sudo -n cat /tmp/cpcap-tx.log"):
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("generator did not complete fixed 14-second burst")
    perf.ssh("laojun", "sudo -n pkill -TERM -x capacity_tx || true; sudo -n pkill -9 -x dpdk-testpmd || true")
    time.sleep(2.2)  # Include the last AF_PACKET drop publication, and ring drain.
    drain_l = snap("laojun")
    drain = snap("yinjiao", quiet=bool(case.get("burst_capture")))
    if case.get("pipeline"):
        for _ in range(6):
            c = cap_counters(drain)
            if c["cap_packets"] == c["fwd_packets"]:
                break
            time.sleep(2)
            drain = snap("yinjiao", quiet=bool(case.get("burst_capture")))
    result = calculate(case, samples, before[1], drain)
    if case.get("live_stats"):
        rpc = [y["capture"] for _, y in samples]
        result["live_stats_rpc"] = {"count": len(rpc), "max_seconds": max(s["span"] for s in rpc),
                                    "success": all(isinstance(s["value"], list) and bool(s["value"]) for s in rpc)}
    result.update(shape_mbps=shape, startup=startup, before=before, drained_l=drain_l, drained=drain,
                  tx_log=perf.ssh("laojun", "sudo -n cat /tmp/cpcap-tx.log 2>/dev/null || true"),
                  worker_log=perf.ssh("yinjiao", "sudo -n cat /tmp/cpcap-worker.log 2>/dev/null || true"),
                  primary_log=perf.ssh("yinjiao", "sudo -n tail -8 /tmp/cpcap-primary.log 2>/dev/null || true"))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases")
    parser.add_argument("output")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        deploy()
        perf.setup()
        for case in json.loads(Path(args.cases).read_text()):
            print("START " + json.dumps(case), flush=True)
            try:
                result = measure(case)
            except Exception as exc:
                result = dict(case, error=str(exc), failure_snapshot=snap("yinjiao"),
                              worker_log=perf.ssh("yinjiao", "sudo -n cat /tmp/cpcap-worker.log 2>/dev/null || true"))
            with open(args.output, "a") as f:
                f.write(json.dumps(result) + "\n")
            print(json.dumps({k: v for k, v in result.items() if k not in ["tx_log", "before", "drained_l", "vf_deltas", "samples", "startup", "drained", "worker_log", "primary_log", "failure_snapshot"]}), flush=True)
    finally:
        perf.ssh("laojun", "sudo -n pkill -TERM -x capacity_tx || true")
        perf.restore()
        perf.ssh("yinjiao", "sudo -n rm -f /tmp/cpcap.sock /tmp/cpcap-primary-stats.json")
        print("RESTORED", flush=True)


if __name__ == "__main__":
    main()
