#!/usr/bin/env bash
# Protocol-level differential fuzz: GRE / VXLAN / ZMQ batch wire formats.
#
# Drives the real, unmodified C output code (with sendto/zmq_send intercepted
# via linker --wrap) and the Rust port against identical random inputs, then
# diffs the captured wire bytes.
#
# Usage: parity/fuzz_proto.sh [num_cases] [num_seeds] [pkts_per_case]
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

CASES="${1:-100}"
SEEDS="${2:-5}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> compiling C protocol harness"
gcc -O2 -w -I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim" \
    "$HERE/c_proto.c" \
    "$PROJECT_ROOT/cpworker/src/output_gre.c" \
    "$PROJECT_ROOT/cpworker/src/output_vxlan.c" \
    "$PROJECT_ROOT/cpworker/src/output_zmq.c" \
    "$PROJECT_ROOT/cpworker/src/stats.c" \
    "$PROJECT_ROOT/cpworker/src/errorf.c" \
    "$PROJECT_ROOT/cpworker/src/ratelimit.c" \
    "$PROJECT_ROOT/cpworker/src/packet_split.c" \
    -lpcap -lzmq -Wl,--wrap=sendto -Wl,--wrap=zmq_send \
    -o "$TMP/c_proto"

echo "==> building Rust protocol harness"
( cd "$RUST_DIR" && cargo build -q -p cpworker --bin proto_parity )
RUST_BIN="$RUST_DIR/target/debug/proto_parity"

total=0
for seed in $(seq 1 "$SEEDS"); do
    dir="$TMP/seed_$seed"
    python3 "$HERE/gen_proto.py" "$CASES" "$seed" "$dir" >/dev/null
    for f in "$dir"/case_*.txt; do
        mode="$(head -1 "$f" | awk '{print $1}')"
        "$TMP/c_proto" "$mode" "$f" > "$TMP/c.out" 2>/dev/null
        "$RUST_BIN" "$mode" "$f" > "$TMP/r.out" 2>/dev/null
        total=$((total + 1))
        if ! diff -q "$TMP/c.out" "$TMP/r.out" >/dev/null; then
            echo "❌ MISMATCH (seed=$seed case=$(basename "$f") mode=$mode)"
            cp "$f" /tmp/proto_mismatch.txt
            diff "$TMP/c.out" "$TMP/r.out" > /tmp/proto_mismatch.diff 2>&1 || true
            head -6 /tmp/proto_mismatch.diff
            echo "input saved at /tmp/proto_mismatch.txt, diff at /tmp/proto_mismatch.diff"
            exit 1
        fi
    done
    echo "  seed $seed: $CASES cases OK"
done

lines=$(wc -l < "$TMP/c.out" 2>/dev/null || echo 0)
echo "✅ IDENTICAL: $total cases across $SEEDS seeds (wire frames/batches compared byte-for-byte)"
