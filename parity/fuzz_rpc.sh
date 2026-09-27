#!/usr/bin/env bash
# Unix JSON-RPC protocol parity: C unix-manager vs Rust unix_manager.
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

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

echo "==> compiling C RPC server"
gcc -w -I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim" \
    "$HERE/c_rpc.c" \
    "$PROJECT_ROOT/cpworker/src/unix-manager.c" \
    "$PROJECT_ROOT/cpworker/src/unix_rpc_basic.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON_Utils.c" \
    -pthread -o "$TMP/c_rpc"

echo "==> building Rust RPC server"
( cd "$RUST_DIR" && cargo build -q --locked -p cpworker --bin rpc_parity )

"$TMP/c_rpc" "$TMP/c.sock" >"$TMP/c.log" 2>&1 &
PIDS+=($!)
"$RUST_DIR/target/debug/rpc_parity" "$TMP/r.sock" /tmp/config.json /tmp >"$TMP/r.log" 2>&1 &
PIDS+=($!)

for i in $(seq 1 50); do
    [ -S "$TMP/c.sock" ] && [ -S "$TMP/r.sock" ] && break
    sleep 0.1
done

python3 "$HERE/rpc_compare.py" "$TMP/c.sock" "$TMP/r.sock"
