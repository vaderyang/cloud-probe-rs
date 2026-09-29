#!/usr/bin/env bash
# Verification-coverage entry point (see VERIFICATION_COVERAGE.md).
#
#   ./verify_coverage.sh                 # run the test suite under llvm-cov, then gate
#   ./verify_coverage.sh --no-run        # re-export lcov from existing profdata (fast)
#   ./verify_coverage.sh --diff          # also enforce changed-line coverage
#   ./verify_coverage.sh --update-baseline
#
# Any other arguments are forwarded to verification/coverage_gate.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
LCOV="target/llvm-cov/lcov.info"
mkdir -p target/llvm-cov

run=1
args=()
for a in "$@"; do
    case "$a" in
        --no-run) run=0 ;;
        *) args+=("$a") ;;
    esac
done

if [ "$run" = 1 ]; then
    cargo llvm-cov --workspace --locked --lcov --output-path "$LCOV"
else
    # Re-export from the last run's profdata without executing the tests again.
    cargo llvm-cov report --lcov --output-path "$LCOV"
fi

exec python3 verification/coverage_gate.py --lcov "$LCOV" ${args+"${args[@]}"}
