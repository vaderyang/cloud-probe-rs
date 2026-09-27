#!/usr/bin/env python3
"""Live-capture A/B: the C cpworker (libpcap) vs the Rust one (AF_PACKET).

Manual, root-only, and deliberately *not* wired into CI or into `bench.py`:
it needs a real interface and a traffic source, and the source is normally the
bottleneck, so this measures "did the capturer keep up, and at what CPU cost per
captured frame" rather than a ceiling. Offline throughput is `bench.py`'s job.

Usage (run as a user with passwordless sudo, or simply as root):
    bench/live_bench.py [seconds] [interface]
    CP_C=/path/to/cpworker CP_RUST=../target/release/cpworker bench/live_bench.py 20 wlp1s0

What it reports per implementation, over one window of a UDP flood on the
interface (the flood binds a receiver, so nothing is ICMP-refused):

    sent / drained   how many datagrams the sender pushed, how many were read back
    cap_packets      frames the capturer reported (cpctl stats, aggregate)
    drop_packets     the capture-side drop counter (PACKET_STATISTICS / pcap_stats)
    cpu_s            worker utime+stime burned during the window
    cpu_s_per_mpps   cpu_s / cap_packets * 1e6  <- the comparable number

Read `cap_packets` before trusting anything: on loopback a frame is delivered
twice (outbound + inbound), so "2 x sent" means "captured everything" and a
smaller number means the capturer missed frames. Both implementations report
`drop_packets == 0` in that situation, which is exactly why this prints counts
next to CPU instead of a single throughput figure (AUDIT4 P5-02: a zero drop
counter is not evidence of a lossless path).
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 10
IFACE = sys.argv[2] if len(sys.argv) > 2 else "lo"
PORT = int(os.environ.get("FLOOD_PORT", "15999"))
CP_C = os.environ.get(
    "CP_C", "/home/vader/cloud-probe/build/tmp/cpworker-linux-amd64/cpworker"
)
CP_RUST = os.environ.get("CP_RUST", os.path.join(ROOT, "target/release/cpworker"))
CPCTL = os.environ.get("CPCTL", os.path.join(ROOT, "target/debug/cpctl"))
SUDO = os.environ.get("SUDO", "sudo").split()


def cfg(name):
    """One task: live capture on IFACE, filtered to the flood, discarded."""
    return {
        "control": {"type": "unix", "unix": {"path": f"/tmp/live_bench-{name}.sock"}},
        "tasks": [{
            "capturer": {"type": "libpcap", "libpcap": {
                "interface": IFACE, "snaplen": 2048, "buffer_size_mb": 256,
                "bpf": f"udp and dst port {PORT}"}},
            "outputs": [{"type": "null"}],
        }],
    }


def stats(sock_path):
    """One raw `cpctl stats` sample. The worker runs as root and the control
    socket is bound 0755, so cpctl has to run with the same privileges."""
    out = subprocess.check_output(
        SUDO + [CPCTL, "-u", sock_path, "--format", "jsonl", "stats", "-n", "1"],
        text=True)
    return json.loads(out.strip().splitlines()[-1])["counters"]


def flood(stop_at):
    """Send UDP datagrams to a self-drained port until `stop_at`."""
    drained = [0]

    def drainer(sock):
        while time.time() < stop_at:
            try:
                sock.recvfrom(65535)
                drained[0] += 1
            except socket.timeout:
                break

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("127.0.0.1", PORT))
    rx.settimeout(0.2)
    threading.Thread(target=drainer, args=(rx,), daemon=True).start()

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = b"x" * 200
    sent = 0
    while time.time() < stop_at:
        try:
            tx.sendto(pkt, ("127.0.0.1", PORT))
            sent += 1
        except OSError:
            time.sleep(0.001)
    time.sleep(0.3)
    tx.close()
    rx.close()
    return sent, drained[0]


def worker_cpu(tag):
    """utime+stime (seconds) of every process whose cmdline contains `tag`.

    The launched pid is sudo's, so match on the config path instead of the pid.
    """
    ids = subprocess.check_output(
        SUDO + ["pgrep", "-f", "--", tag], text=True).split()
    hz = os.sysconf("SC_CLK_TCK")
    total = 0.0
    for pid in ids:
        try:
            fields = subprocess.check_output(
                SUDO + ["cat", f"/proc/{pid}/stat"], text=True
            ).rsplit(")", 1)[1].split()
        except subprocess.CalledProcessError:
            continue  # exited between pgrep and the read
        total += (int(fields[11]) + int(fields[12])) / hz
    return total


def measure(name, binary):
    if not os.path.exists(binary):
        print(f"!! missing binary for {name}: {binary}", file=sys.stderr)
        return None
    tag = f"live_bench-{name}.json"
    cfg_path = f"/tmp/{tag}"
    sock = f"/tmp/live_bench-{name}.sock"
    try:
        os.unlink(sock)
    except OSError:
        pass
    with open(cfg_path, "w") as f:
        json.dump(cfg(name), f)

    proc = subprocess.Popen(SUDO + [binary, "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.0)  # socket bind + capturer start
    cpu0 = worker_cpu(tag)
    t0 = time.time()
    sent, drained = flood(t0 + SECS)
    dt = time.time() - t0
    cpu = worker_cpu(tag) - cpu0
    c = stats(sock)
    subprocess.Popen(SUDO + ["kill", "-TERM", str(proc.pid)]).wait()
    proc.wait(timeout=10)

    cap = c["cap_packets"]["packets"]
    return {
        "sent": sent,
        "drained": drained,
        "wall_s": round(dt, 2),
        "cap_packets": cap,
        "fwd_packets": c["fwd_packets"]["packets"],
        "drop_packets": c["drop_packets"]["packets"],
        "ifdrop_packets": c["ifdrop_packets"]["packets"],
        "cpu_s": round(cpu, 2),
        "cpu_s_per_mpps": round(cpu / cap * 1e6, 3) if cap else None,
        "frames_captured_per_datagram_sent": round(cap / sent, 2) if sent else None,
    }


if __name__ == "__main__":
    print(f"iface={IFACE} window={SECS}s flood=udp/127.0.0.1:{PORT} (200 B datagrams)")
    out = {}
    for name, binary in (("C", CP_C), ("Rust", CP_RUST)):
        r = measure(name, binary)
        if r:
            out[name] = r
            print(f"{name}: {json.dumps(r)}")
    if "C" in out and "Rust" in out and out["C"]["cpu_s_per_mpps"] and out["Rust"]["cpu_s_per_mpps"]:
        print(f"cpu per captured million frames, C/Rust = "
              f"{out['C']['cpu_s_per_mpps'] / out['Rust']['cpu_s_per_mpps']:.2f}")
