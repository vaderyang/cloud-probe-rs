#!/usr/bin/env python3
"""Benchmark the C and Rust cpworker binaries and emit a Markdown report.

Scenarios (pcap_file capturer, all packets processed, then SIGTERM):
  * null         — parse + task pipeline + discard            (pure CPU)
  * file         — parse + pcap writer to tmpfs               (CPU + memcpy)
  * vxlan-split  — parse + VXLAN encap + checksum + splitting (CPU heavy)

Metrics: wall time until the capturer logs `end of file`, throughput
(packets/s, MB/s) and peak RSS (VmHWM).

Env:
  CP_C      path to the C cpworker      (default: the reference build)
  CP_RUST   path to the Rust cpworker   (default: target/release/cpworker)
  N         packets in the pcap         (default 1000000)
  REPEAT    measured runs (median used) (default 3)
  WORK      scratch dir (tmpfs ideal)   (default /dev/shm)
"""
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CP_C = os.environ.get(
    "CP_C", "/home/vader/cloud-probe/build/tmp/cpworker-linux-amd64/cpworker"
)
CP_RUST = os.environ.get("CP_RUST", os.path.join(ROOT, "target/release/cpworker"))
N = int(os.environ.get("N", "1000000"))
REPEAT = int(os.environ.get("REPEAT", "3"))
WORK = os.environ.get("WORK", "/dev/shm")


def sh(cmd):
    return subprocess.check_output(cmd, shell=True, text=True).strip()


def gen_pcap(path):
    out = sh(f"python3 {HERE}/gen_pcap.py {N} {path}")
    n, total = out.split()
    return int(n), int(total)


def write_cfg(path, body):
    with open(path, "w") as f:
        json.dump(body, f)


def run_once(binary, cfg):
    out = subprocess.check_output(
        ["python3", os.path.join(HERE, "measure.py"), binary, cfg], text=True
    )
    return json.loads(out)


def median_run(binary, cfg, repeat):
    runs = []
    # one warmup run, discarded
    run_once(binary, cfg)
    for _ in range(repeat):
        r = run_once(binary, cfg)
        if not r["ok"]:
            r["elapsed"] = None
        runs.append(r)
    times = [r["elapsed"] for r in runs if r["elapsed"]]
    rss = [r["rss_kb"] for r in runs if r["rss_kb"]]
    return statistics.median(times), max(rss) if rss else 0


def machine_info():
    cpu = sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip()
    return {
        "cpu": cpu,
        "cores": sh("nproc"),
        "mem": sh("grep MemTotal /proc/meminfo | awk '{print $2}'"),
        "kernel": sh("uname -sr"),
    }


class UdpDrainer:
    """Drains VXLAN output so sends don't hit a closed port (ICMP)."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop:
            try:
                self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    os.makedirs(WORK, exist_ok=True)
    pcap = os.path.join(WORK, "bench_input.pcap")
    print(f"==> generating {N} packets into {pcap}", file=sys.stderr)
    n, total = gen_pcap(pcap)
    print(f"    {n} packets, {total/1e6:.1f} MB on wire", file=sys.stderr)

    scenarios = {
        "null": lambda impl: {
            "tasks": [
                {
                    "capturer": {
                        "type": "pcap_file",
                        "pcap_file": {"file_name": pcap},
                    },
                    "outputs": [{"type": "null"}],
                }
            ]
        },
        "file": lambda impl: {
            "tasks": [
                {
                    "capturer": {
                        "type": "pcap_file",
                        "pcap_file": {"file_name": pcap},
                    },
                    "outputs": [
                        {
                            "type": "file",
                            "file": {"name": os.path.join(WORK, f"out-{impl}.pcap")},
                        }
                    ],
                }
            ]
        },
        "vxlan-split": lambda impl: {
            "tasks": [
                {
                    "capturer": {
                        "type": "pcap_file",
                        "pcap_file": {"file_name": pcap},
                    },
                    "outputs": [
                        {
                            "type": "vxlan",
                            "vxlan": {
                                "host": "127.0.0.1",
                                "port": 4791,
                                "vni1": 100,
                                "split": {"max_payload_size": 1200},
                            },
                        }
                    ],
                }
            ]
        },
    }

    impls = [("C", CP_C), ("Rust", CP_RUST)]
    drainer = UdpDrainer("127.0.0.1", 4791)
    results = {}
    for scen, mk in scenarios.items():
        for name, binary in impls:
            if not os.path.exists(binary):
                print(f"!! missing binary for {name}: {binary}", file=sys.stderr)
                continue
            cfg = os.path.join(WORK, f"cfg-{scen}-{name}.json")
            write_cfg(cfg, mk(name))
            print(f"==> {scen} / {name}", file=sys.stderr)
            elapsed, rss = median_run(binary, cfg, REPEAT)
            # clean output file to keep tmpfs free
            outp = os.path.join(WORK, f"out-{name}.pcap")
            if os.path.exists(outp):
                os.remove(outp)
            if elapsed and elapsed > 0:
                results[(scen, name)] = {
                    "pps": n / elapsed,
                    "mbps": total / elapsed / 1e6,
                    "rss_mb": rss / 1024.0,
                    "elapsed": elapsed,
                }
    drainer.close()

    mi = machine_info()
    lines = []
    lines.append("# cpworker: C vs Rust — benchmark results\n")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(
        f"Machine: {mi['cores']} cores, {mi['cpu']}, "
        f"{int(mi['mem'])/1024/1024:.1f} GiB RAM, {mi['kernel']}\n"
    )
    lines.append(
        f"Workload: {n} packets ({total/1e6:.1f} MB) replayed from a PCAP file; "
        f"median of {REPEAT} runs (after a warmup).\n"
    )
    lines.append("\n| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for scen in scenarios:
        for name, _ in impls:
            r = results.get((scen, name))
            if not r:
                continue
            lines.append(
                f"| {scen} | {name} | {r['pps']/1e6:.2f} M | {r['mbps']:.1f} | "
                f"{r['elapsed']:.3f} | {r['rss_mb']:.1f} |"
            )
    out = "\n".join(lines) + "\n"
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write(out)
    print(out)


if __name__ == "__main__":
    main()
