#!/usr/bin/env python3
"""Run one cpworker binary until it reports "end of file", then measure.

Usage: measure.py <binary> <config.json>

Watches stderr for the capturer's `end of file` marker (both the C and Rust
implementations log it after the last packet), records wall time until then and
the process peak RSS (VmHWM), then sends SIGTERM.

The reported `elapsed` is a *span between two observable events*, and both of its
ends are wider than "packet processing", which is why the numbers it feeds are
ratios rather than absolute throughput (qwen P3-6):

* it starts at `Popen`, so process start-up, config parsing and capturer set-up
  are inside it - quantified here as `startup_s`;
* it stops at the `end of file` line, which the capturer logs after the last
  packet but *before* its outputs are destroyed, i.e. before the pcap writer's
  final flush - quantified here as `flush_after_s` (marker to process exit).

Both add the same kind of overhead to both binaries, so the direction of a C/Rust
comparison is unaffected; the absolute values are not comparable to another
machine, kernel, or to `tcpdump`.

Prints one JSON line:
  {"elapsed": <s>, "rss_kb": <kb>, "ok": <bool>,
   "startup_s": <s>, "flush_after_s": <s>, "marker": "<line>", "binary": "<path>"}
"""
import json
import os
import signal
import subprocess
import sys
import time

MARKER = "end of file"
TIMEOUT = float(os.environ.get("BENCH_TIMEOUT", "300"))


def peak_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def main():
    binary, cfg = sys.argv[1], sys.argv[2]
    p = subprocess.Popen(
        [binary, "-c", cfg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    t0 = time.perf_counter()
    ok = False
    t_end = None
    t_first = None
    marker = ""
    deadline = t0 + TIMEOUT
    try:
        for line in p.stderr:
            if t_first is None:
                t_first = time.perf_counter()
            if MARKER in line:
                t_end = time.perf_counter()
                marker = line.strip()[:200]
                ok = True
                break
            if time.perf_counter() > deadline:
                break
    except Exception:
        pass
    if t_end is None:
        t_end = time.perf_counter()
    rss = peak_rss_kb(p.pid)
    try:
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=15)
    except Exception:
        p.kill()
        try:
            p.wait(timeout=5)
        except Exception:
            pass
    t_exit = time.perf_counter()
    print(
        json.dumps(
            {
                "elapsed": t_end - t0,
                "rss_kb": rss,
                "ok": ok,
                # spawn -> first stderr line: start-up, config parse, set-up.
                "startup_s": (t_first - t0) if t_first else None,
                # `end of file` -> process exit: everything the marker misses.
                "flush_after_s": t_exit - t_end,
                "marker": marker,
                "binary": binary,
            }
        )
    )


if __name__ == "__main__":
    main()
