#!/usr/bin/env bash
# Coverage-guided fuzzing for the Cloud Probe Rust port (cargo-fuzz + libFuzzer).
#
# Usage:
#   fuzz.sh [seconds] [target|all]      # fuzz (default: all, 30s each)
#   fuzz.sh --check [target|all]        # short smoke run (5s each)
#   FUZZ_SEED=123 fuzz.sh 60 zmq_batch  # fixed seed, longer run
#   fuzz.sh repro zmq_batch <artifact>  # reproduce a crash
#
# Targets: packet_split config vxlan zmq_batch sim_dst bpf zmtp_wire zmtp_client
#          pcap_reader diff_oracle(diff, see parity/difffuzz.sh)
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$HERE/crates/cpworker"
ALL_TARGETS="packet_split config vxlan zmq_batch sim_dst bpf zmtp_wire zmtp_client pcap_reader"

# Pinned (AUDIT4 P3-5): the smoke job must run the same fuzz driver on every commit.
# `cargo install cargo-fuzz` without a version resolved whatever was latest at that
# moment, so one commit could be fuzzed by two different drivers (different
# sanitiser flags, different corpus handling) and both would report "fuzz.sh --check"
# green.
CARGO_FUZZ_VERSION="0.13.2"

ensure_toolchain() {
    if ! rustup toolchain list | grep -q '^nightly'; then
        echo "==> installing nightly toolchain (libFuzzer needs it)"
        rustup toolchain install nightly --profile minimal
    fi
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        echo "==> installing cargo-fuzz $CARGO_FUZZ_VERSION"
        cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION"
    elif [ "$(cargo-fuzz --version | awk '{print $2}')" != "$CARGO_FUZZ_VERSION" ]; then
        echo "==> note: cargo-fuzz $(cargo-fuzz --version | awk '{print $2}') in PATH;" \
             "this script pins $CARGO_FUZZ_VERSION"
    fi
}

# Lockfile discipline (AUDIT4 P3-2, the fuzz half of P5-27): the fuzz workspace has
# its own Cargo.lock and `cargo fuzz` has no --locked to forward, so it would build
# with whatever it resolves. Asserting here that both lockfiles still match their
# manifests means a fuzz run cannot execute against a graph that differs from the
# one the `deny` job audited.
assert_lockfiles() {
    local m
    for m in "$HERE/Cargo.toml" "$CRATE/fuzz/Cargo.toml"; do
        if ! cargo metadata --locked --format-version 1 --manifest-path "$m" >/dev/null; then
            echo "::error::$m does not resolve with --locked"
            echo "   refresh that workspace's Cargo.lock and commit it"
            exit 1
        fi
    done
    echo "==> both workspaces resolve exactly to their committed lockfiles (--locked)"
}

ensure_toolchain
assert_lockfiles
cd "$CRATE"

# cargo-fuzz may otherwise default to a musl target (statically linked libc is
# incompatible with the address sanitizer). Pin the rustc host triple.
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
[ -n "$HOST_TRIPLE" ] || HOST_TRIPLE="x86_64-unknown-linux-gnu"

MODE="${1:-run}"
case "$MODE" in
    --check)
        TIME=5
        TARGETS="${2:-$ALL_TARGETS}"
        ARGS=(-max_total_time="$TIME" -rss_limit_mb=4096)
        ;;
    repro)
        TARGET="$2"
        shift 2
        exec cargo +nightly fuzz run --target "$HOST_TRIPLE" "$TARGET" "$@"
        ;;
    *)
        TIME="${1:-30}"
        TARGETS="${2:-$ALL_TARGETS}"
        ARGS=(-max_total_time="$TIME" -rss_limit_mb=4096)
        if [ -n "${FUZZ_SEED:-}" ]; then
            ARGS+=(-seed="$FUZZ_SEED")
        fi
        ;;
esac

[ "$TARGETS" = "all" ] && TARGETS="$ALL_TARGETS"

echo "==> building fuzz targets"
cargo +nightly fuzz build --target "$HOST_TRIPLE" >/dev/null

# Seed the corpora with the hand-written regression inputs.
for t in $TARGETS; do
    if [ -d "fuzz/seeds/$t" ]; then
        mkdir -p "fuzz/corpus/$t"
        cp -n fuzz/seeds/$t/* "fuzz/corpus/$t/" 2>/dev/null || true
    fi
done

fail=0
for t in $TARGETS; do
    echo "=========================================================="
    echo " fuzz: $t (max_total_time=${ARGS[0]#-max_total_time=}s)"
    echo "=========================================================="
    if cargo +nightly fuzz run --target "$HOST_TRIPLE" "$t" -- "${ARGS[@]}"; then
        echo "  $t: OK"
    else
        echo "  ❌ $t: CRASH — artifact under crates/cpworker/fuzz/artifacts/$t/"
        fail=1
    fi
done
exit $fail
