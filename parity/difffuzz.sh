#!/usr/bin/env bash
# Coverage-guided *differential* fuzzing: the Rust port (in-process, so
# libFuzzer gets coverage feedback) vs the original C implementation running as
# a persistent oracle subprocess.
#
# Every fuzz input is mapped to the same request for both sides and their
# canonical output is compared; any divergence aborts the run and libFuzzer
# saves the crashing input. This finds semantic differences (not just crashes)
# that fixed-seed differential tests (`parity/*.sh`) miss.
#
# Usage:
#   parity/difffuzz.sh [seconds_per_mode] [mode|all]
#   parity/difffuzz.sh 120 packet_split
#   DFF_SEED=7 parity/difffuzz.sh 60 config
#
# Modes: packet_split config req_pattern
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$HERE/.." && pwd)"
CRATE="$RUST_DIR/crates/cpworker"
CLOUD_PROBE_SRC="${CLOUD_PROBE_SRC:-$(cd "$RUST_DIR/.." && pwd)/cloud-probe}"
PROJECT_ROOT="$CLOUD_PROBE_SRC"
if [ ! -d "$PROJECT_ROOT/cpworker" ]; then
    echo "error: cloud-probe sources not found at $PROJECT_ROOT (set CLOUD_PROBE_SRC)" >&2
    exit 1
fi

SECS="${1:-30}"
WHICH="${2:-all}"
ALL_MODES="packet_split config req_pattern"
[ "$WHICH" = "all" ] && WHICH="$ALL_MODES"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- toolchain -------------------------------------------------------------
if ! rustup toolchain list | grep -q '^nightly'; then
    echo "==> installing nightly toolchain (libFuzzer needs it)"
    rustup toolchain install nightly --profile minimal
fi
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "==> installing cargo-fuzz"
    cargo install cargo-fuzz
fi
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
[ -n "$HOST_TRIPLE" ] || HOST_TRIPLE="x86_64-unknown-linux-gnu"

# --- compile the C oracles -------------------------------------------------
CINC=(-I "$PROJECT_ROOT/cpworker/src" -I "$HERE/shim")
echo "==> compiling C oracles"
gcc -O2 -w "${CINC[@]}" "$HERE/c_harness.c" \
    "$PROJECT_ROOT/cpworker/src/packet_split.c" -o "$TMP/oracle_packet_split"
gcc -O2 -w "${CINC[@]}" "$HERE/c_config.c" \
    "$PROJECT_ROOT/cpworker/src/config.c" \
    "$PROJECT_ROOT/cpworker/src/cjson_utils.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON.c" \
    "$PROJECT_ROOT/cpworker/src/cJSON/cJSON_Utils.c" \
    "$PROJECT_ROOT/cpworker/src/bpf_util.c" \
    "$PROJECT_ROOT/cpworker/src/ip.c" \
    "$PROJECT_ROOT/cpworker/src/errorf.c" \
    "$PROJECT_ROOT/cpworker/src/log.c" -o "$TMP/oracle_config"
gcc -O2 -w "${CINC[@]}" "$HERE/c_req_pattern.c" \
    "$PROJECT_ROOT/cpworker/src/req_pattern.c" \
    "$PROJECT_ROOT/cpworker/src/ip.c" \
    "$PROJECT_ROOT/cpworker/src/ether.c" \
    "$PROJECT_ROOT/cpworker/src/if_util.c" \
    "$PROJECT_ROOT/cpworker/src/log.c" \
    "$PROJECT_ROOT/cpworker/src/errorf.c" -o "$TMP/oracle_req_pattern"

oracle_for() {
    case "$1" in
        packet_split) echo "$TMP/oracle_packet_split" ;;
        config)       echo "$TMP/oracle_config" ;;
        req_pattern)  echo "$TMP/oracle_req_pattern" ;;
    esac
}

# --- seed corpora ----------------------------------------------------------
seed() {
    local mode="$1" dir="$CRATE/fuzz/corpus/diff_$mode"
    mkdir -p "$dir"
    case "$mode" in
        packet_split)
            # data = maxp(LE u16) | recalc(u8) | frame
            python3 - "$dir/seed_tcp.bin" <<'PY'
import struct, sys
# minimal Ethernet/IPv4/TCP frame (54 bytes)
eth = bytes.fromhex("00112233445566778899aabb0800")
ip  = bytes.fromhex("4500002800010000400600000a0000010a000002")
tcp = bytes.fromhex("1f90005000000001000000005010000000000000")
open(sys.argv[1], "wb").write(struct.pack("<HB", 1500, 0) + eth + ip + tcp)
PY
            ;;
        config)
            printf '%s' '{"log_level":2,"execution_model":"rtc","tasks":[]}' > "$dir/seed_min.json"
            printf '%s' '{"log_level":2,"tasks":[{"capturer":{"type":"libpcap","interface":"eth0","snaplen":65535,"bpf":"udp"},"outputs":[{"type":"null"}]}]}' > "$dir/seed_task.json"
            ;;
        req_pattern)
            printf '%s' 'host 127.0.0.1 and port 80' > "$dir/seed_hostport"
            printf '%s' '(host 10.0.0.1 or host 10.0.0.2) and port 443' > "$dir/seed_or"
            ;;
    esac
}

cd "$CRATE"
echo "==> building diff_oracle"
cargo +nightly fuzz build --target "$HOST_TRIPLE" diff_oracle >/dev/null

fail=0
for mode in $WHICH; do
    seed "$mode"
    echo "=========================================================="
    echo " diff-fuzz: $mode vs C oracle (${SECS}s)"
    echo "=========================================================="
    args=(-max_total_time="$SECS" -rss_limit_mb=4096 -timeout=25 -max_len=4096 \
          -artifact_prefix="$TMP/${mode}-")
    [ -n "${DFF_SEED:-}" ] && args+=(-seed="$DFF_SEED")
    if DIFF_MODE="$mode" DIFF_C_ORACLE="$(oracle_for "$mode")" \
        cargo +nightly fuzz run --target "$HOST_TRIPLE" diff_oracle -- "${args[@]}"; then
        echo "  $mode: OK (no divergence)"
    else
        echo "  ❌ $mode: DIVERGENCE — see /tmp/difffuzz_last.txt and $TMP/${mode}-*"
        # Keep the artifact under the (gitignored) fuzz artifacts dir.
        mkdir -p "$CRATE/fuzz/artifacts/difffuzz"
        cp "$TMP/${mode}-"* "$CRATE/fuzz/artifacts/difffuzz/" 2>/dev/null || true
        fail=1
    fi
done
exit $fail
