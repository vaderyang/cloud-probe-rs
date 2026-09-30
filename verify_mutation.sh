#!/usr/bin/env bash
# Mutation testing for the Tier 0/1 pure-logic scope (VERIFICATION_COVERAGE.md §7).
#
#   ./verify_mutation.sh                 # full run over verification/mutants.toml
#   ./verify_mutation.sh --in-diff [base]# only lines changed vs <base> (default origin/main)
#   ./verify_mutation.sh --shard 0/4     # one shard of the weekly matrix (0-based)
#
# Blocking since ADR-0001 stage 3/4: cargo-mutants exits non-zero when a mutant
# survives (2) or times out (3). Every surviving mutant in scope must therefore
# either be caught or be listed with a justification in `verification/mutants.toml`
# `exclude_re` (see verification/MUTATION_BASELINE.md). Do NOT pass `--exit-code`:
# it was removed in cargo-mutants v26, and a removed flag now aborts before any
# mutant runs, silently turning the gate into a no-op.
#
# Requires cargo-mutants (`cargo install cargo-mutants` or CI install-action).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
CFG="verification/mutants.toml"
GATE="verification/mutation_config_gate.py"

# The exemption list is the only way a surviving mutant can be tolerated, so it is
# validated before any mutant runs: every entry must still match a candidate
# mutant (no drift after a source edit), must carry a written reason, and must be
# a valid regex. Set SKIP_MUTATION_CONFIG_GATE=1 when a sibling job already did it.
if [ "${SKIP_MUTATION_CONFIG_GATE:-0}" != "1" ]; then
    echo "==> checking ${CFG} exemptions"
    python3 "$GATE" --config "$CFG"
fi

if [ "${1:-}" = "--in-diff" ]; then
    base="${2:-origin/main}"
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    git diff "$base...HEAD" > "$tmp"
    n="$(grep -c '^diff --git' "$tmp" || true)"
    echo "==> mutation testing only the $n changed file(s) vs $base"
    exec cargo mutants --workspace --config "$CFG" --in-diff "$tmp"
fi

exec cargo mutants --workspace --config "$CFG" "$@"
