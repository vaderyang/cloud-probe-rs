#!/usr/bin/env python3
"""Benchmark the C and Rust cpworker binaries and emit a Markdown report.

Scenarios (pcap_file capturer, all packets processed, then SIGTERM):
  * null         — parse + task pipeline + discard            (pure CPU)
  * file         — parse + pcap writer to tmpfs               (CPU + memcpy)
  * vxlan-split  — parse + VXLAN encap + checksum + splitting (CPU heavy)

Metrics: wall time until the capturer logs `end of file`, throughput
(packets/s, MB/s) and peak RSS (VmHWM).

Every measured run is kept: the report shows the median *and* the spread
(min/max/stdev) of the `REPEAT` runs, and `RESULTS.md` is appended to, not
overwritten, so a quoted ratio can always be traced back to the raw rows that
produced it (qwen P3-6: "1.34-1.39x" quoted a precision this harness cannot
reproduce, and the second run behind it was never recorded).

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

RESULTS = os.path.join(HERE, "RESULTS.md")

# Fixed header of the append-only log. Everything after it is a recorded run.
RESULTS_HEAD = """# cpworker: C vs Rust — benchmark results

Append-only log: every `bench/bench.py` run appends a section, nothing is
overwritten. Read it bottom-up (newest run last). Each section carries its own
machine, `N`, `REPEAT` and the per-run raw rows, so any ratio quoted elsewhere
must be findable here with its spread.

**Absolute throughput is machine-specific and must not be compared across
machines or kernels.** Only the C/Rust ratio measured on one machine, in one
run, means anything. Two caveats in the measurement scope itself also move the
absolute numbers (neither changes the direction of a ratio):

* `elapsed` starts at `fork`/`exec`, so it includes process start-up, config
  parsing and capturer set-up (a fixed few tens of ms that matters most at small
  `N`);
* it stops at the capturer's `end of file` log line, which the capturer emits
  *before* the outputs are destroyed, i.e. before the pcap writer's last flush.
  The `file` scenario therefore under-measures the write path of both binaries by
  the same structural amount.

---
"""


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


def measure_runs(binary, cfg, repeat):
    """Run `repeat` times after one discarded warm-up; keep every run.

    Returns (list_of_elapsed_or_None, list_of_rss_kb). A failed run (no `end of
    file` marker) has `elapsed=None` and is excluded from the time statistics but
    still counted, because a silently dropped run is how a median lies.
    """
    runs = []
    run_once(binary, cfg)  # warm-up, discarded
    for _ in range(repeat):
        r = run_once(binary, cfg)
        runs.append(r if r["ok"] else {**r, "elapsed": None})
    times = [r["elapsed"] for r in runs if r["elapsed"]]
    rss = [r["rss_kb"] for r in runs if r["rss_kb"]]
    return runs, times, rss


def spread(values):
    """median, min, max, population stdev of a non-empty sample (else zeros)."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (
        statistics.median(values),
        min(values),
        max(values),
        statistics.pstdev(values) if len(values) > 1 else 0.0,
    )


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
    # results[(scenario, impl)] = {"runs": [...], "times": [...], "rss": [...]}
    results = {}
    for scen, mk in scenarios.items():
        for name, binary in impls:
            if not os.path.exists(binary):
                print(f"!! missing binary for {name}: {binary}", file=sys.stderr)
                continue
            cfg = os.path.join(WORK, f"cfg-{scen}-{name}.json")
            write_cfg(cfg, mk(name))
            print(f"==> {scen} / {name}", file=sys.stderr)
            runs, times, rss = measure_runs(binary, cfg, REPEAT)
            outp = os.path.join(WORK, f"out-{name}.pcap")
            if os.path.exists(outp):
                os.remove(outp)
            if times:
                results[(scen, name)] = {"runs": runs, "times": times, "rss": rss}
    drainer.close()

    mi = machine_info()
    lines = [
        f"## Run {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        f"Machine: {mi['cores']} cores, {mi['cpu']}, "
        f"{int(mi['mem'])/1024/1024:.1f} GiB RAM, {mi['kernel']}\n",
        f"Workload: {n} packets ({total/1e6:.1f} MB) replayed from a PCAP file; "
        f"N={n}, REPEAT={REPEAT} (plus one discarded warm-up per binary).\n",
        "",
        "| Scenario | Impl | Runs | Time med (s) | Time min–max (s) | stdev (ms) "
        "| pps med (M) | MB/s med | Peak RSS med (MB) |",
        "|---|---|---:|---:|---|---:|---:|---:|---:|",
    ]
    for scen in scenarios:
        for name, _ in impls:
            r = results.get((scen, name))
            if not r:
                continue
            med, lo, hi, sd = spread(r["times"])
            rmed, rlo, rhi, _ = spread(r["rss"])
            lines.append(
                f"| {scen} | {name} | {len(r['times'])}/{REPEAT} | {med:.3f} | "
                f"{lo:.3f}–{hi:.3f} | {sd*1000:.1f} | {n/med/1e6:.2f} | "
                f"{total/med/1e6:.1f} | {rmed/1024.0:.1f} ({rlo/1024.0:.1f}–"
                f"{rhi/1024.0:.1f}) |"
            )

    lines += [
        "",
        f"C/Rust time ratio (median; the range spans the min/max of both sides, "
        f"so it is the honest reading of the same {REPEAT}-run sample):\n",
        "| Scenario | ratio (med) | ratio range over min/max | spread of the ratio |",
        "|---|---:|---|---|",
    ]
    for scen in scenarios:
        c, r = results.get((scen, "C")), results.get((scen, "Rust"))
        if not c or not r:
            continue
        cmed, clo, chi, _ = spread(c["times"])
        rmed, rlo, rhi, _ = spread(r["times"])
        ratios = sorted([clo / rhi, cmed / rmed, chi / rlo])
        lines.append(
            f"| {scen} | {cmed/rmed:.2f}× | {ratios[0]:.2f}×–{ratios[-1]:.2f}× | "
            f"{ratios[-1]-ratios[0]:.2f} |"
        )

    lines += ["", "Raw per-run rows (the evidence behind every number above):\n"]
    for scen in scenarios:
        for name, _ in impls:
            r = results.get((scen, name))
            if not r:
                continue
            cells = []
            for i, run in enumerate(r["runs"], 1):
                if run["elapsed"] is None:
                    cells.append(f"run{i}: FAILED")
                else:
                    cells.append(f"run{i}: {run['elapsed']:.3f}s")
            rss = [f"{kb/1024.0:.1f}" for kb in [x["rss_kb"] for x in r["runs"]]]
            lines.append(f"* `{scen}` / {name}: " + ", ".join(cells) + f"; RSS MB: {', '.join(rss)}")

    section = "\n".join(lines) + "\n"

    # Append, never overwrite (qwen P3-6): the fixed preamble is rewritten
    # verbatim and every previously recorded run section is kept as it was.
    previous = ""
    if os.path.exists(RESULTS):
        with open(RESULTS, encoding="utf-8") as f:
            previous = f.read()
    body = previous.split("\n---\n", 1)[1] if "\n---\n" in previous else previous
    with open(RESULTS, "w", encoding="utf-8") as f:
        f.write(RESULTS_HEAD + body.rstrip() + "\n\n" + section)
    print(f"==> appended one run to {RESULTS}; previously recorded runs are kept")
    print(section)


if __name__ == "__main__":
    main()
