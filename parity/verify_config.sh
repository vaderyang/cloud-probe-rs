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
( cd "$RUST_DIR" && cargo build -q --locked -p cpworker-parity --bin config_parity )

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

# --- AUDIT4 P5-15: numeric range checks --------------------------------------
# The generated vectors stay inside the documented ranges on purpose: cJSON
# clamps every out-of-range number to INT_MIN/INT_MAX and *accepts* it, so
# feeding those to the differential would only re-verify the clamp. The Rust
# port rejects them instead (PARITY.md §2.5). This fixed list of *valid JSON*
# out-of-range vectors guards that decision against a silently removed check.
echo "==> AUDIT4 P5-15: out-of-range numbers must be rejected"
cat > "$TMP/extreme.txt" <<'EOF'
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":2147483648}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":4294967296}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":262145}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":-1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":4294967296}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":8193}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":-1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","timeout_ms":4294967396}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","timeout_ms":600001}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","ring_size":4294967304}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","ring_size":1048577}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","snaplen":2147483648}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":4294967296}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":65536}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":-1}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","rate_limit_mbps":1000001}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","rate_limit_mbps":-1}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"rotating_file","rotating_file":{"file_root":"/tmp","max_file_interval":4294967356}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":7,"split":{"max_payload_size":4294967396}}}]}]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":4294967360},"tasks":[]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":8193},"tasks":[]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":0},"tasks":[]}
EOF
N_EXTREME=$(grep -c . "$TMP/extreme.txt")
N_ACCEPTED=$("$RUST_DIR/target/debug/config_parity" < "$TMP/extreme.txt" 2>/dev/null | grep -vc '^PARSE_FAIL$\|^---$' || true)
if [ "${N_ACCEPTED:-0}" -ne 0 ]; then
    echo "❌ $N_ACCEPTED of $N_EXTREME out-of-range configs were accepted (they must be rejected)"
    "$RUST_DIR/target/debug/config_parity" < "$TMP/extreme.txt" 2>/dev/null | grep -v '^PARSE_FAIL$\|^---$' | head -6
    exit 1
fi
echo "✅ OK: all $N_EXTREME out-of-range configs rejected (C clamps them, see PARITY.md §2.5)"
