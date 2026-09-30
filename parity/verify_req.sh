#!/usr/bin/env bash
# Differential test: C req_pattern matcher vs Rust.
#
# Two comparisons:
#   1. matcher-only queries  <pattern>\t<ip>\t<port>  (gen_req.py)
#   2. full direction judge  <pattern>\t<frame_hex>   (gen_req_judge.py)
# The second feeds real Ethernet frames through
# `req_pattern_judge_pkt_direction` / `ReqPattern::judge_pkt_direction`, which
# reaches `extract_ipport` and covers stacked-VLAN (QinQ) descent.
#
# Usage: parity/verify_req.sh [num_queries] [seed]
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

N="${1:-3000}"
SEED="${2:-7}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> compiling C req_pattern harness"
gcc -O2 -w -I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim" \
    "$HERE/c_req_pattern.c" \
    "$PROJECT_ROOT/cpworker/src/req_pattern.c" \
    "$PROJECT_ROOT/cpworker/src/ip.c" \
    "$PROJECT_ROOT/cpworker/src/ether.c" \
    "$PROJECT_ROOT/cpworker/src/if_util.c" \
    "$PROJECT_ROOT/cpworker/src/log.c" \
    "$PROJECT_ROOT/cpworker/src/errorf.c" \
    -o "$TMP/c_req"

echo "==> building Rust req_pattern harness"
( cd "$RUST_DIR" && cargo build -q --locked -p cpworker-parity --bin req_parity )

echo "==> generating $N queries (seed=$SEED)"
python3 "$HERE/gen_req.py" "$N" "$SEED" > "$TMP/in.txt"

"$TMP/c_req" < "$TMP/in.txt" 2>/dev/null > "$TMP/c.out"
"$RUST_DIR/target/debug/req_parity" < "$TMP/in.txt" 2>/dev/null > "$TMP/r.out"

if diff -q "$TMP/c.out" "$TMP/r.out" >/dev/null; then
    echo "✅ IDENTICAL: $N queries (seed=$SEED)"
else
    echo "❌ MISMATCH"
    diff "$TMP/c.out" "$TMP/r.out" | head -30
    exit 1
fi

echo "==> generating $N direction-judge frames (seed=$SEED)"
python3 "$HERE/gen_req_judge.py" "$N" "$SEED" > "$TMP/judge_in.txt"

"$TMP/c_req" --judge < "$TMP/judge_in.txt" 2>/dev/null > "$TMP/c_judge.out"
"$RUST_DIR/target/debug/req_parity" --judge < "$TMP/judge_in.txt" 2>/dev/null > "$TMP/r_judge.out"

if diff -q "$TMP/c_judge.out" "$TMP/r_judge.out" >/dev/null; then
    echo "✅ IDENTICAL: $N direction-judge frames (seed=$SEED)"
else
    echo "❌ MISMATCH (direction judge)"
    diff "$TMP/c_judge.out" "$TMP/r_judge.out" | head -30
    exit 1
fi
