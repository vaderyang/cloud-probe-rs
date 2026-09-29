#!/usr/bin/env bash
# Differential test: C packet_split vs Rust packet_split.
#
# Feeds identical random Ethernet frames to the original C implementation and
# the Rust port, then diffs the produced fragment bytes (including recalculated
# IP/TCP/UDP checksums) byte-for-byte.
#
# Usage: parity/run.sh [num_packets] [seed]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$HERE/.." && pwd)"
CLOUD_PROBE_SRC="${CLOUD_PROBE_SRC:-$(cd "$RUST_DIR/.." && pwd)/cloud-probe}"
PROJECT_ROOT="$CLOUD_PROBE_SRC"
if [ ! -d "$PROJECT_ROOT/cpworker" ]; then
    echo "error: cloud-probe sources not found at $PROJECT_ROOT (set CLOUD_PROBE_SRC)" >&2
    exit 1
fi

N="${1:-5000}"
SEED="${2:-42}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> compiling C harness (packet_split.c)"
gcc -O2 -I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim" \
    "$HERE/c_harness.c" "$PROJECT_ROOT/cpworker/src/packet_split.c" \
    -o "$TMP/c_harness"

echo "==> building Rust parity harness"
( cd "$RUST_DIR" && cargo build -q --locked -p cpworker-parity --bin parity )

echo "==> generating $N random packets (seed=$SEED)"
python3 "$HERE/gen.py" "$N" "$SEED" > "$TMP/vectors.txt"

"$TMP/c_harness" < "$TMP/vectors.txt" > "$TMP/out_c.txt"
"$RUST_DIR/target/debug/parity" < "$TMP/vectors.txt" > "$TMP/out_rust.txt"

if diff -q "$TMP/out_c.txt" "$TMP/out_rust.txt" >/dev/null; then
    echo "✅ IDENTICAL: $N packets, $(wc -l < "$TMP/out_c.txt") output lines"
else
    echo "❌ MISMATCH:"
    diff "$TMP/out_c.txt" "$TMP/out_rust.txt" | head -40
    exit 1
fi
