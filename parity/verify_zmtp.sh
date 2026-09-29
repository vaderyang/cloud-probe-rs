#!/usr/bin/env bash
# ZMTP interop test: pure-Rust ZMTP PUSH  ->  real libzmq PULL.
#
# The Rust client performs the full ZMTP 3.x NULL handshake against a libzmq
# PULL endpoint; the received payload must be byte-identical to what was sent.
# Covers short frames, long frames (>255 bytes) and an empty message.
#
# Usage: parity/verify_zmtp.sh
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> compiling libzmq PULL harness"
gcc -O2 -w "$HERE/zmtp_pull.c" -lzmq -o "$TMP/zmtp_pull"

echo "==> building Rust ZMTP push helper"
( cd "$RUST_DIR" && cargo build -q --locked -p cpworker-parity --bin zmtp_push )
RUST_BIN="$RUST_DIR/target/debug/zmtp_push"

fail=0
check_case() {
    local name="$1" hex="$2"
    local expect="$hex"
    if [[ "$hex" == @* ]]; then expect="$(cat "${hex#@}")"; fi
    "$TMP/zmtp_pull" > "$TMP/out.txt" &
    local pid=$!
    # Wait for the endpoint line.
    for _ in $(seq 1 100); do
        [ -s "$TMP/out.txt" ] && break
        sleep 0.05
    done
    local ep port
    ep="$(head -1 "$TMP/out.txt")"
    port="${ep##*:}"
    if [ -z "$port" ]; then
        echo "❌ $name: could not read PULL endpoint"
        kill "$pid" 2>/dev/null || true
        fail=1
        return
    fi
    "$RUST_BIN" 127.0.0.1 "$port" "$hex"
    wait "$pid" || true
    local recv
    recv="$(tail -1 "$TMP/out.txt")"
    if [ "$recv" = "$expect" ]; then
        echo "  ✅ $name (${#expect} hex chars)"
    else
        echo "  ❌ $name: sent ${expect:0:40}... got ${recv:0:40}..."
        fail=1
    fi
}

# 1) small frame (short form)
check_case "small"  "$(python3 -c "print('deadbeef'*4)")"
# 2) empty message
check_case "empty"  ""
# 3) long frame (>255 bytes -> 8-byte length form)
check_case "long"   "$(python3 -c "print('01'*1000)")"
# 4) batch-sized (~64 KiB) via a file (too long for argv)
python3 -c "import sys; open('$TMP/payload.hex','w').write('ab'*65536)"
check_case "64k" "@$TMP/payload.hex"

if [ "$fail" -eq 0 ]; then
    echo "✅ IDENTICAL: pure-Rust ZMTP PUSH <-> libzmq PULL (4 payloads)"
else
    echo "❌ ZMTP interop failed"
    exit 1
fi
