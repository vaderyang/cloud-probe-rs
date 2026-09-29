#!/usr/bin/env bash
# Mutation testing for the Tier 0/1 pure-logic scope (VERIFICATION_COVERAGE.md §7).
#
#   ./verify_mutation.sh                 # full run over verification/mutants.toml
#   ./verify_mutation.sh --in-diff [base]# only lines changed vs <base> (default origin/main)
#
# Requires cargo-mutants (`cargo install cargo-mutants` or CI install-action).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
CFG="verification/mutants.toml"

if [ "${1:-}" = "--in-diff" ]; then
    base="${2:-origin/main}"
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    git diff "$base...HEAD" > "$tmp"
    n="$(grep -c '^diff --git' "$tmp" || true)"
    echo "==> mutation testing only the $n changed file(s) vs $base"
    exec cargo mutants --workspace --config "$CFG" --in-diff "$tmp" --exit-code
fi

exec cargo mutants --workspace --config "$CFG" "$@"
