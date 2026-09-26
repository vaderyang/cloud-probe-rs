#!/usr/bin/env python3
"""Run one cpworker binary until it reports "end of file", then measure.

Usage: measure.py <binary> <config.json>

Watches stderr for the capturer's `end of file` marker (both the C and Rust
implementations log it after the last packet), records wall time until then and
the process peak RSS (VmHWM), then sends SIGTERM. Prints a JSON line:
  {"elapsed": <s>, "rss_kb": <kb>, "ok": <bool>}
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
    deadline = t0 + TIMEOUT
    try:
        for line in p.stderr:
            if MARKER in line:
                t_end = time.perf_counter()
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
    print(json.dumps({"elapsed": t_end - t0, "rss_kb": rss, "ok": ok}))


if __name__ == "__main__":
    main()
