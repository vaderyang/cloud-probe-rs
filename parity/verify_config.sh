#!/usr/bin/env bash
# Differential test: C config parser vs Rust config parser.
# Usage: parity/verify_config.sh [num_configs] [seed]
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

N="${1:-2000}"
SEED="${2:-11}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> compiling C config harness"
gcc -O2 -w -I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim" \
    "$HERE/c_config.c" \
    "$PROJECT_ROOT/cpworker/src/config.c" \
    "$PROJECT_ROOT/cpworker/src/cjson_utils.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON_Utils.c" \
    "$PROJECT_ROOT/cpworker/src/bpf_util.c" \
    "$PROJECT_ROOT/cpworker/src/ip.c" \
    "$PROJECT_ROOT/cpworker/src/errorf.c" \
    "$PROJECT_ROOT/cpworker/src/log.c" \
    -o "$TMP/c_config"

echo "==> building Rust config harness"
( cd "$RUST_DIR" && cargo build -q -p cpworker --bin config_parity )

echo "==> generating $N configs (seed=$SEED)"
python3 "$HERE/gen_config.py" "$N" "$SEED" > "$TMP/in.txt"

# C includes a human-readable reason after PARSE_FAIL; the Rust side prints the
# bare marker. Normalise that (the success/failure decision is what matters).
"$TMP/c_config" < "$TMP/in.txt" 2>/dev/null | sed 's/^PARSE_FAIL.*/PARSE_FAIL/' > "$TMP/c.out"
"$RUST_DIR/target/debug/config_parity" < "$TMP/in.txt" 2>/dev/null | sed 's/^PARSE_FAIL.*/PARSE_FAIL/' > "$TMP/r.out"

if diff -q "$TMP/c.out" "$TMP/r.out" >/dev/null; then
    echo "✅ IDENTICAL: $N configs (seed=$SEED)"
else
    echo "❌ MISMATCH"
    diff "$TMP/c.out" "$TMP/r.out" | head -30
    exit 1
fi
