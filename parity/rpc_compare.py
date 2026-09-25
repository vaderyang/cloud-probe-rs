#!/usr/bin/env python3
"""Compare two Unix JSON-RPC servers (C vs Rust) for protocol parity.

Usage: rpc_compare.py <c_socket> <rust_socket>

Each case opens a fresh connection, performs the handshake and a sequence of
commands, and records the raw response objects (or None if the server closed
the connection). Non-deterministic fields (timestamps, pid, uptime, version)
are normalised before comparison.
"""
import json
import socket
import sys
import time

GOOD = b'{"version":"v1"}\n'


def recv_reply(s):
    """Read one newline-terminated JSON reply; return (parsed_or_raw, closed)."""
    buf = b""
    s.settimeout(3.0)
    try:
        while True:
            ch = s.recv(1)
            if not ch:
                return (None, True) if buf == b"" else (buf.decode(errors="replace"), True)
            if ch == b"\n":
                return buf.decode(errors="replace"), False
            buf += ch
    except socket.timeout:
        return (("/TIMEOUT", buf.decode(errors="replace")), False)


def normalize(reply):
    if reply is None:
        return "__CLOSED__"
    if isinstance(reply, tuple):
        return repr(reply)
    try:
        o = json.loads(reply)
    except Exception:
        return reply
    if isinstance(o, dict):
        if o.get("status") == "OK" and "ts_ms" in o:
            o["ts_ms"] = 0
        if "pid" in o:
            o["pid"] = 0
        if "uptime_sec" in o:
            o["uptime_sec"] = 0
        if "started_at_sec" in o:
            o["started_at_sec"] = 0
        if "version" in o:
            o["version"] = "V"
    return json.dumps(o, sort_keys=True)


def session(path, messages, handshake=GOOD, shutdown_after_last=False):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    out = []
    try:
        s.sendall(handshake)
        out.append(recv_reply(s)[0])
        for i, m in enumerate(messages):
            try:
                s.sendall(m)
            except (BrokenPipeError, ConnectionResetError):
                out.append("__CLOSED__")
                break
            reply, closed = recv_reply(s)
            out.append(reply)
            if closed:
                break
            if shutdown_after_last and i == len(messages) - 1:
                s.shutdown(socket.SHUT_WR)
                out.append(recv_reply(s)[0])
    except (BrokenPipeError, ConnectionResetError):
        out.append("__CLOSED__")
    finally:
        try:
            s.close()
        except OSError:
            pass
    return [normalize(x) for x in out]


def cases():
    return [
        ("ping", GOOD, [b'{"command":"ping"}\n']),
        ("info", GOOD, [b'{"command":"info"}\n']),
        ("unknown", GOOD, [b'{"command":"nope"}\n']),
        ("empty-object", GOOD, [b"{}\n"]),
        ("command-int", GOOD, [b'{"command":123}\n']),
        ("command-extra", GOOD, [b'{"command":"ping","x":1}\n']),
        ("case-sensitive", GOOD, [b'{"command":"PING"}\n']),
        (
            "multi",
            GOOD,
            [b'{"command":"ping"}\n', b'{"command":"info"}\n', b'{"command":"nope"}\n'],
        ),
        ("nested", GOOD, [b'{"command":"ping","a":{"b":[1,2,3]}}\n']),
        ("ws", GOOD, [b'   {"command":"ping"}   \n']),
        ("empty-line", GOOD, [b"\n"]),
        ("malformed", GOOD, [b"{\n"]),
        ("bad-version", b'{"version":"v2"}\n', [b'{"command":"ping"}\n']),
        ("bad-json-handshake", b"notjson\n", [b'{"command":"ping"}\n']),
        ("handshake-extra", b'{"version":"v1","x":1}\n', [b'{"command":"ping"}\n']),
        ("no-newline", GOOD, [b'{"command":"ping"}']),
        ("unknown-then-ok", GOOD, [b'{"command":"nope"}\n', b'{"command":"ping"}\n']),
    ]


def run(path):
    res = []
    for name, hs, msgs in cases():
        res.append((name, session(path, msgs, hs, shutdown_after_last=(name == "no-newline"))))
    return res


def main():
    c_path, r_path = sys.argv[1], sys.argv[2]
    time.sleep(0.3)
    c_res = run(c_path)
    r_res = run(r_path)
    bad = 0
    for (n1, a), (n2, b) in zip(c_res, r_res):
        assert n1 == n2
        if a != b:
            bad += 1
            print(f"❌ MISMATCH case={n1}")
            print(f"   C   : {a}")
            print(f"   Rust: {b}")
    if bad == 0:
        print(f"✅ IDENTICAL: {len(c_res)} RPC cases")
    else:
        print(f"{bad} mismatches")
        sys.exit(1)


if __name__ == "__main__":
    main()
