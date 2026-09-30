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
# --- Upstream #279: numeric normalisation ------------------------------------
# Out-of-range numbers are *normalised* (snaplen, buffer_size_mb, timeout_ms,
# slice, rate_limit_mbps, hwm, service_tag, vni, ports) or rejected (negative
# where non-negative is required, out-of-range ports, fractional values) by
# *both* parsers - cJSON clamps/accepts, and C's own fields then normalise. The
# rule is not asserted here; whatever it is, C and Rust must agree, so compare
# their canonical outputs on a fixed grid of extreme, still-valid-JSON inputs.
echo "==> #279: out-of-range numbers must agree with C"
cat > "$TMP/extreme.txt" <<'EOF'
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":2147483648}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":4294967296}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":262145}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":-1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":0}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":2048.0}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":1e3}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","snaplen":2048.5}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":4294967296}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":8193}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":-1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","buffer_size_mb":0}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","timeout_ms":4294967396}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","timeout_ms":600001}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0","timeout_ms":-1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","ring_size":4294967304}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","ring_size":1048577}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","ring_size":1}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","snaplen":2147483648}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"dpdk_pdump","dpdk_pdump":{"interface":"eth0","snaplen":0}},"outputs":[]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":4294967296}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":65536}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","slice":-1}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","rate_limit_mbps":1000001}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"null","rate_limit_mbps":-1}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"rotating_file","rotating_file":{"file_root":"/tmp","max_file_interval":4294967356}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"rotating_file","rotating_file":{"file_root":"/tmp","max_file_interval":-1}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":7,"split":{"max_payload_size":4294967396}}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":7,"split":{"max_payload_size":65536}}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","port":0,"vni1":7}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","port":65536,"vni1":7}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":16777216}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":4294967296}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"vxlan","vxlan":{"host":"1.1.1.1","vni1":7,"vni2":8}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"gre","gre":{"host":"1.1.1.1","service_tag":4294967296}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"gre","gre":{"host":"1.1.1.1","service_tag":-1}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":0,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":65536,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":5555,"hwm":0,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":5555,"hwm":-1,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":5555,"hwm":4294967296,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"tasks":[{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[{"type":"zmq","zmq":{"host":"1.1.1.1","port":5555,"heartbeat_ms":60001,"uuid":"550e8400-e29b-41d4-a716-446655440000"}}]}]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":4294967360},"tasks":[]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":8193},"tasks":[]}
{"execution_model":"pipeline","pipeline":{"buffer_size_mb":0},"tasks":[]}
{"execution_model":"pipeline","pipeline":{},"tasks":[]}
EOF
N_EXTREME=$(grep -c . "$TMP/extreme.txt")
"$TMP/c_config" < "$TMP/extreme.txt" 2>/dev/null | sed 's/^PARSE_FAIL.*/PARSE_FAIL/' > "$TMP/c.extreme"
"$RUST_DIR/target/debug/config_parity" < "$TMP/extreme.txt" 2>/dev/null | sed 's/^PARSE_FAIL.*/PARSE_FAIL/' > "$TMP/r.extreme"
if diff -q "$TMP/c.extreme" "$TMP/r.extreme" >/dev/null; then
    echo "✅ IDENTICAL: $N_EXTREME out-of-range configs"
else
    echo "❌ MISMATCH on out-of-range configs"
    diff "$TMP/c.extreme" "$TMP/r.extreme" | head -30
    exit 1
fi
