#!/usr/bin/env python3
"""Live-capture A/B: the C cpworker (libpcap) vs the Rust one (AF_PACKET).

Manual, root-only, and deliberately *not* wired into CI or into `bench.py`:
it needs a real interface and a traffic source, and the source is normally the
bottleneck, so this measures "did the capturer keep up, and at what CPU cost per
captured frame" rather than a ceiling. Offline throughput is `bench.py`'s job.

Usage (run as a user with passwordless sudo, or simply as root):
    bench/live_bench.py [seconds] [interface]
    CP_C=/path/to/cpworker CP_RUST=../target/release/cpworker bench/live_bench.py 20 wlp1s0
    FLOOD_DST=10.99.0.1 bench/live_bench.py 20 vethq0     # flood through a veth
    bench/live_bench.py --selftest                        # no network needed

Where the flood goes (AUDIT4 P2-5): it used to be hard-coded to 127.0.0.1, so
`live_bench.py 20 vethq0` captured zero frames and the "use a veth" advice in the
documentation could not actually be followed. `FLOOD_DST` overrides; otherwise a
loopback capture floods loopback and any other interface is flooded through its own
IPv4 address (which must exist: `ip addr add 10.99.0.1/24 dev vethq0`).

Exit codes (AUDIT4 P2-4): 0 = measured, 2 = a worker captured nothing although
datagrams were sent (a broken task), 3 = a worker's counters could not be read (not
a measurement, and never to be printed as one).

What it reports per implementation, over one window of a UDP flood on the
interface (the flood binds a receiver, so nothing is ICMP-refused):

    sent / drained   how many datagrams the sender pushed, how many were read back
    cap_packets      frames the capturer reported (cpctl stats, aggregate)
    drop_packets     the capture-side drop counter (PACKET_STATISTICS / pcap_stats)
    cpu_s            worker utime+stime burned during the window
    cpu_s_per_mpps   cpu_s / cap_packets * 1e6  <- the comparable number

Read `cap_packets` before trusting anything. On loopback a datagram is tapped
**twice** by the kernel (the transmit `dev_queue_xmit_nit` copy and the receive
`__netif_receive_skb` copy); libpcap/tcpdump deliver only the received copy, and
the Rust capturer was fixed to match that (`PACKET_IGNORE_OUTGOING` on loopback),
so both now show `frames/datagram ~ 1` on `lo`. On a *non-loopback* interface a
ratio near `1` also means "captured everything". A smaller number means the
capturer missed frames, but note that **neither implementation reports those
losses as drops**: `tp_drops` only counts socket-queue overflows, and `ps_recv`
on loopback counts about twice what `pcap_next_ex` actually delivers. A zero drop
counter is therefore not evidence of a lossless path (AUDIT4 P5-02).

A1 note (AUDIT4 §5-6): the original read of "Rust x2.00 vs C x0.79" as a mere
measurement artifact was **wrong**. On loopback the kernel taps every datagram
twice; libpcap/tcpdump deliver only the received copy (1x) while a plain
`recvmsg` socket delivered both (2x). The Rust capturer was subsequently fixed to
match libpcap, so `lo` now yields ~1x too. The C `x0.79` was additionally
distorted by reading the C worker's stats through the *Rust* `cpctl` (a timing
race can yield `Connection reset by peer`; the Go `cpctl` from the C tree works).
Use a non-loopback interface (veth) for an unambiguous frames/datagram number.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

ARGS = sys.argv[1:]
if ARGS[:1] == ["--selftest"]:  # must be checked before the positional parse
    ARGS = []
    SELFTEST = True
else:
    SELFTEST = False
SECS = int(ARGS[0]) if len(ARGS) > 0 else 10
IFACE = ARGS[1] if len(ARGS) > 1 else "lo"
PORT = int(os.environ.get("FLOOD_PORT", "15999"))
CP_C = os.environ.get(
    "CP_C", "/home/vader/cloud-probe/build/tmp/cpworker-linux-amd64/cpworker"
)
CP_RUST = os.environ.get("CP_RUST", os.path.join(ROOT, "target/release/cpworker"))
CPCTL = os.environ.get("CPCTL", os.path.join(ROOT, "target/debug/cpctl"))
SUDO = os.environ.get("SUDO", "sudo").split()
FLOOD_DST = os.environ.get("FLOOD_DST", "")  # "a.b.c.d[:port]"; empty = derive from IFACE


def iface_ipv4(iface):
    """First IPv4 address configured on `iface`, or None."""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "dev", iface], text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        try:
            idx = parts.index("inet")
        except ValueError:
            continue
        return parts[idx + 1].split("/")[0]
    return None


def flood_target():
    """Where the UDP flood goes, and how to reach it from `IFACE`.

    Hard-coding 127.0.0.1 (as this script used to) meant the flood only ever
    traversed `lo`, so `live_bench.py 20 vethq0` captured 0 frames while the only
    warning printed was the one for `IFACE == "lo"` - the documentation said "use a
    veth for a meaningful ratio", the tool could not do it (AUDIT4 P2-5). An
    explicit FLOOD_DST always wins; otherwise a loopback capture floods loopback and
    any other interface is flooded through its own address.
    """
    host, port = FLOOD_DST.split(":")[0], int(FLOOD_DST.split(":")[1]) if ":" in FLOOD_DST else PORT
    if FLOOD_DST:
        return host, port
    if IFACE == "lo":
        return "127.0.0.1", PORT
    addr = iface_ipv4(IFACE)
    if addr is None:
        sys.exit(
            f"!! cannot flood '{IFACE}': it has no IPv4 address and FLOOD_DST is unset.\n"
            f"   either:  ip addr add 10.99.0.1/24 dev {IFACE}  (on both veth ends)\n"
            f"   or:      FLOOD_DST=10.99.0.1 bench/live_bench.py {SECS} {IFACE}"
        )
    return addr, PORT


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


def iface_mac(iface):
    """MAC of `iface`, or None."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except OSError:
        return None


def iface_peer(iface):
    """Peer of a veth pair, from `ip -o link` (`N: a@b: ...`), or None."""
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show", "dev", iface], text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    name = out.split(":", 2)[1] if out.count(":") >= 2 else ""
    return name.split("@", 1)[1] or None if "@" in name else None


def _inet_csum(data):
    """Ones-complement 16-bit sum, as the kernel checks it on ingress."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ipv4_header(src, dst, total_len, proto):
    """A checksummed IPv4 header (the receiving host validates it on ingress)."""
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, 1, 0, 64, proto, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
    )
    ip[10:12] = struct.pack("!H", _inet_csum(bytes(ip)))
    return bytes(ip)


def _mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def udp_frame(dst_mac, src_mac, src_ip, dst_ip, sport, dport, size):
    """One Ethernet/IPv4/UDP frame. UDP checksum 0 means "not computed" (legal)."""
    payload = b"x" * max(0, size - 42)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = ipv4_header(src_ip, dst_ip, 20 + len(udp), 17)
    return _mac_bytes(dst_mac) + _mac_bytes(src_mac) + b"\x08\x00" + ip + udp


def raw_flood(stop_at, iface, dst_ip, port):
    """Inject frames into `iface` from its veth peer; returns how many were sent.

    Flooding the interface's *own* address would not traverse it - the kernel routes
    a local address via `lo` - so a same-host veth pair has to be fed with raw frames
    from the other end. That is what makes `live_bench.py 20 vethq0` actually capture
    something (AUDIT4 P2-5), and it is the setup the manual veth measurements used.
    """
    peer = iface_peer(iface)
    if not peer:
        sys.exit(
            f"!! '{iface}' has no veth peer in this namespace, so frames cannot be "
            f"injected. Create a pair (`ip link add {iface} type veth peer name "
            f"{iface}p`) or set FLOOD_DST to a host reached through '{iface}'."
        )
    dst_mac, src_mac = iface_mac(iface), iface_mac(peer)
    if not dst_mac or not src_mac:
        sys.exit(f"!! could not read the MAC address of {iface} or its peer {peer}")
    frame = udp_frame(dst_mac, src_mac, "169.254.99.2", dst_ip, 50000, port, 242)
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sent = 0
    try:
        while time.time() < stop_at:
            try:
                tx.sendto(frame, (peer, 0x0003))
                sent += 1
            except OSError:
                time.sleep(0.001)
    finally:
        tx.close()
    return sent


def flood(stop_at, dst_addr, raw_iface=None):
    """Push datagrams at `dst_addr` until `stop_at`; returns (sent, drained).

    With `raw_iface` set the traffic is injected as frames from that interface's veth
    peer (see `raw_flood`); otherwise plain UDP is sent, with a receiver bound so
    nothing is ICMP-refused.
    """
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
    rx.bind((dst_addr, PORT))
    rx.settimeout(0.2)
    threading.Thread(target=drainer, args=(rx,), daemon=True).start()

    if raw_iface:
        sent = raw_flood(stop_at, raw_iface, dst_addr, PORT)
        time.sleep(0.3)
        rx.close()
        return sent, drained[0]

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt = b"x" * 200
    sent = 0
    while time.time() < stop_at:
        try:
            tx.sendto(pkt, (dst_addr, PORT))
            sent += 1
        except OSError:
            time.sleep(0.001)
    time.sleep(0.3)
    tx.close()
    rx.close()
    return sent, drained[0]


def worker_cpu(tag):
    """utime+stime (seconds) of every process whose cmdline contains `tag`.

    The launched pid is sudo's, so the config path in the cmdline is what identifies
    the worker. `/proc` is read directly rather than through `pgrep`+`cat`: the
    external pair raced (`pgrep` can list a pid that has already exited, and `cat`
    then prints an error into an otherwise clean run), and `pgrep -f` matched any
    command line containing the path - including the shell that started the bench
    (GLM observation). `/proc/<pid>/stat` is world-readable, so this works as root
    and as a plain user alike.
    """
    hz = os.sysconf("SC_CLK_TCK")
    total = 0.0
    me = os.getpid()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode(errors="replace")
            if tag not in cmdline:
                continue
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
        except OSError:
            continue  # exited between the two reads, or vanished
        total += (int(fields[11]) + int(fields[12])) / hz
    return total


def measure(name, binary):
    if not os.path.exists(binary):
        print(f"!! missing binary for {name}: {binary}", file=sys.stderr)
        return None
    dst_addr, _port = flood_target()
    # A veth (or any non-loopback interface we own the peer of) is fed with raw
    # frames; loopback and explicit remote targets use plain UDP.
    raw_iface = None if (IFACE == "lo" or FLOOD_DST) else IFACE
    if IFACE == "lo":
        print(
            "!! capturing on 'lo' and flooding 127.0.0.1: the kernel taps every "
            "datagram twice; libpcap and (since P1) the Rust capturer both deliver "
            "one frame per datagram, so 1.0 is the expected ratio here.",
            file=sys.stderr,
        )
    else:
        print(f"   flooding {dst_addr}:{PORT} through '{IFACE}'", file=sys.stderr)
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
    sent, drained = flood(t0 + SECS, dst_addr, raw_iface)
    dt = time.time() - t0
    cpu = worker_cpu(tag) - cpu0
    try:
        c = stats(sock)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, IndexError) as e:
        # Reading the worker stats can fail for environmental reasons (the C
        # worker's control socket is root-owned and the handshake has a narrow
        # timing race with a client that writes payload and `\n` separately). It
        # must never be reported the same way as "captured nothing" (AUDIT4 P2-4):
        # a P5-01 class failure - a task that captures zero frames - used to come
        # out of here as `cap_packets: 0, frames/...: null`, indistinguishable from
        # "not measured".
        print(f"!! {name}: stats unavailable on {sock}: {e}", file=sys.stderr)
        c = None
    subprocess.Popen(SUDO + ["kill", "-TERM", str(proc.pid)]).wait()
    proc.wait(timeout=10)

    return result(name, sent, drained, dt, cpu, c)


UNAVAILABLE = "unavailable"
EXIT_OK = 0
EXIT_CAPTURED_NOTHING = 2
EXIT_STATS_UNAVAILABLE = 3


def result(name, sent, drained, wall_s, cpu_s, c):
    """Build the sample, keeping "not measured" and "measured zero" distinguishable."""
    stats_ok = c is not None
    cap = c["cap_packets"]["packets"] if stats_ok else UNAVAILABLE
    out = {
        "sent": sent,
        "drained": drained,
        "wall_s": round(wall_s, 2),
        "cap_packets": cap,
        "stats_available": stats_ok,
        "fwd_packets": c["fwd_packets"]["packets"] if stats_ok else None,
        "drop_packets": c["drop_packets"]["packets"] if stats_ok else None,
        "ifdrop_packets": c["ifdrop_packets"]["packets"] if stats_ok else None,
        "cpu_s": round(cpu_s, 2),
        "cpu_s_per_mpps": round(cpu_s / cap * 1e6, 3) if stats_ok and cap else None,
        "frames_captured_per_datagram_sent": (
            round(cap / sent, 2) if stats_ok and sent else None
        ),
    }
    return out


def exit_code_for(sample):
    """Non-zero when a sample says something is wrong, not when it says "unknown"."""
    if not sample["stats_available"]:
        return EXIT_STATS_UNAVAILABLE
    if sample["cap_packets"] == 0 and sample["sent"] > 0:
        return EXIT_CAPTURED_NOTHING
    return EXIT_OK


def selftest():
    """The P2-4/P2-5 failure modes, without a network: a green run must be able to
    tell "not measured" from "captured nothing"."""
    ok = True

    def check(cond, what):
        nonlocal ok
        print(("  ok   " if cond else "  FAIL ") + what)
        ok = ok and cond

    no_stats = result("C", sent=1000, drained=1000, wall_s=1.0, cpu_s=0.1, c=None)
    check(no_stats["cap_packets"] == UNAVAILABLE, "unreadable stats say 'unavailable'")
    check(no_stats["cap_packets"] != 0, "unreadable stats must not look like a zero count")
    check(exit_code_for(no_stats) == EXIT_STATS_UNAVAILABLE, "unreadable stats exit non-zero")

    captured_nothing = result("Rust", sent=1000, drained=1000, wall_s=1.0, cpu_s=0.1,
                              c=counters(0, 0))
    check(captured_nothing["cap_packets"] == 0, "a real zero is a real zero")
    check(exit_code_for(captured_nothing) == EXIT_CAPTURED_NOTHING,
          "cap==0 with sent>0 exits 2")

    good = result("Rust", sent=1000, drained=1000, wall_s=1.0, cpu_s=0.1,
                  c=counters(1000, 1000))
    check(exit_code_for(good) == EXIT_OK, "a full capture exits 0")
    check(good["frames_captured_per_datagram_sent"] == 1.0, "ratio 1.0 for 1:1")

    idle = result("Rust", sent=0, drained=0, wall_s=1.0, cpu_s=0.0, c=counters(0, 0))
    check(exit_code_for(idle) == EXIT_OK, "nothing sent is not a failure")

    check(flood_target_says_what_it_means(), "FLOOD_DST overrides the interface")
    print("selftest:", "PASS" if ok else "FAIL")
    return EXIT_OK if ok else 1


def counters(packets, fwd):
    z = {"packets": packets}
    return {
        "cap_packets": z,
        "fwd_packets": {"packets": fwd},
        "drop_packets": {"packets": 0},
        "ifdrop_packets": {"packets": 0},
    }


def flood_target_says_what_it_means():
    global FLOOD_DST
    saved = FLOOD_DST
    FLOOD_DST = "10.99.0.7:16000"
    got = flood_target()
    FLOOD_DST = saved
    return got == ("10.99.0.7", 16000)


if __name__ == "__main__":
    if SELFTEST:
        sys.exit(selftest())
    dst_addr, _ = flood_target()
    print(f"iface={IFACE} window={SECS}s flood=udp/{dst_addr}:{PORT} (200 B datagrams)")
    out = {}
    code = EXIT_OK
    for name, binary in (("C", CP_C), ("Rust", CP_RUST)):
        r = measure(name, binary)
        if r:
            out[name] = r
            print(f"{name}: {json.dumps(r)}")
            c = exit_code_for(r)
            if c == EXIT_CAPTURED_NOTHING:
                print(
                    f"!! {name} captured NOTHING: {r['sent']} datagrams were sent and "
                    f"the worker reported cap_packets=0. That is a broken task, not a "
                    f"missing measurement.",
                    file=sys.stderr,
                )
            elif c == EXIT_STATS_UNAVAILABLE:
                print(f"!! {name}: no counters read; the numbers below are not a comparison",
                      file=sys.stderr)
            code = max(code, c)
    if "C" in out and "Rust" in out and out["C"]["cpu_s_per_mpps"] and out["Rust"]["cpu_s_per_mpps"]:
        print(f"cpu per captured million frames, C/Rust = "
              f"{out['C']['cpu_s_per_mpps'] / out['Rust']['cpu_s_per_mpps']:.2f}")
    sys.exit(code)
