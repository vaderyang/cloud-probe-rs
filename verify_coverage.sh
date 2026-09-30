#!/usr/bin/env bash
# Verification-coverage entry point (see VERIFICATION_COVERAGE.md).
#
#   ./verify_coverage.sh                 # run the suite, fold the live tests, then gate
#   ./verify_coverage.sh --collect-only  # export lcov only (no gate, no sudo needed)
#   ./verify_coverage.sh --privileged-live  # collect-only incl. the live tests (CI)
#   ./verify_coverage.sh --no-run        # re-export lcov from existing profdata (fast)
#   ./verify_coverage.sh --diff          # also enforce changed-line coverage
#   ./verify_coverage.sh --update-baseline
#
# Folding the #[ignore]d AF_PACKET live tests needs sudo on Linux; use
# `--collect-only` for a partial report on a machine without it.
#
# Any other arguments are forwarded to verification/coverage_gate.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
LCOV="target/llvm-cov/lcov.info"
mkdir -p target/llvm-cov

run=1
collect_only=0
# On by default: the Tier 0 line floor (95%) is reached only once the root-only
# AF_PACKET path's coverage is folded in, so a plain un-privileged report would
# fail the ratchet.
privileged_live=1
args=()
for a in "$@"; do
    case "$a" in
        --no-run) run=0 ;;
        --collect-only) collect_only=1; privileged_live=0 ;;
        --privileged-live) collect_only=1; privileged_live=1 ;;
        *) args+=("$a") ;;
    esac
done

# The AF_PACKET capturer is exercised only by tests that are `#[ignore]`d because
# they need CAP_NET_RAW, so the ordinary report leaves it at ~44% line and Tier 0
# can never reach its 95% target. Run the instrumented suite once, then run the
# live test binary as root with `LLVM_PROFILE_FILE` pointed at the same profraw
# directory: the final `report` merges the privileged run into the unit-test
# profile. Only the live test needs privilege - running the whole suite as root
# would change the behaviour many tests assert (e.g. EPERM paths).
if [ "$run" = 1 ] && [ "$privileged_live" = 1 ]; then
    cargo llvm-cov clean --workspace
    cargo llvm-cov --workspace --locked --no-report
    BIN=$(find target/llvm-cov-target/debug/deps -maxdepth 1 -type f \
        -name 'af_packet_live-*' ! -name '*.d' | head -n1)
    if [ -z "$BIN" ]; then
        echo "error: no instrumented af_packet_live test binary was built" >&2
        exit 1
    fi
    sudo -E env "LLVM_PROFILE_FILE=$PWD/target/llvm-cov-target/af_live-%p.profraw" \
        "$BIN" --ignored
    cargo llvm-cov report --lcov --output-path "$LCOV"
elif [ "$run" = 1 ]; then
    cargo llvm-cov --workspace --locked --lcov --output-path "$LCOV"
else
    # Re-export from the last run's profdata without executing the tests again.
    cargo llvm-cov report --lcov --output-path "$LCOV"
fi
if [ "$collect_only" = 1 ]; then
    exit 0
fi

exec python3 verification/coverage_gate.py --lcov "$LCOV" ${args+"${args[@]}"}
