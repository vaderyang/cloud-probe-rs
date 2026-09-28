#!/usr/bin/env bash
# AUDIT4 §3.1 gate: interfaces that are implemented but never *called*.
#
# rustc's dead_code lint cannot see a trait method that has a default
# implementation, and `clippy -D warnings` stays green on it. That is how P5-04
# survived three audits: `Output::destroy()` was implemented (ZMQ linger, pcap
# flush) and had exactly zero callers, so shutdown and reload silently threw
# away up to hwm x 1 MiB of already-queued batches. The same blind spot hides a
# metric that is computed but never published.
#
# Cheap, deterministic guard: one line per interface that must keep a *production*
# call site (test-only callers do not count).
#
# AUDIT4 P2-3 applies here too: "test code" used to mean "everything after the
# first `#[cfg(test)]` the file contains", so a single empty `#[cfg(test)] mod x {}`
# parked at the top of a file turned its whole production body into test code and
# the check went green with zero real callers. Test code is delimited per block now.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0

# --- test-code delimiting ----------------------------------------------------
# A *top-level* (column 0) `#[cfg(...test...)]` attribute or `mod *test*`
# declaration opens a test block; the first column-0 `}` closes it. rustfmt keeps
# items at column 0, so that brace is unambiguous, and a mis-parse (a raw string
# containing a column-0 `}`) ends the block *early*, which makes this check look
# at more code, never less.
declare -A TBLOCKS

in_test_block() {
    local file="$1" lineno="$2" s e blocks
    if [ -z "${TBLOCKS["$file"]+set}" ]; then
        TBLOCKS["$file"]=$(awk '
            !inblk && /^#\[cfg\(.*test.*\)\][[:space:]]*$/ { start = NR; inblk = 1; next }
            !inblk && /^(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]*test[A-Za-z0-9_]*[[:space:]]*\{/ {
                start = NR; inblk = 1; next
            }
            inblk && /^\}[[:space:]]*$/ { print start, NR; inblk = 0 }
            END { if (inblk) print start, NR }
        ' "$file")
    fi
    blocks=${TBLOCKS["$file"]}
    [ -n "$blocks" ] || return 1
    while read -r s e; do
        [ -n "${s:-}" ] || continue
        if [ "$lineno" -ge "$s" ] && [ "$lineno" -le "$e" ]; then
            return 0
        fi
    done <<<"$blocks"
    return 1
}

# check <label> <file-or-directory> <call-site regex>
#
# Lines inside a `#[cfg(test)]` module or an integration test are excluded, so a
# unit test calling the API cannot mask a missing production caller.
check() {
    local label="$1" scope="$2" pattern="$3" hits n
    hits=$(grep -rnH --include='*.rs' -E "$pattern" "$scope" \
        | grep -Ev '(^|/)tests/[a-z_0-9]+\.rs' || true)
    local filtered=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local file="${line%%:*}"
        local lineno="${line#*:}"; lineno="${lineno%%:*}"
        in_test_block "$file" "$lineno" && continue
        filtered+="$line"$'\n'
    done <<< "$hits"
    n=$(printf '%s' "$filtered" | grep -c . || true)
    if [ "${n:-0}" -eq 0 ]; then
        echo "❌ ${label}: no production call site — implemented but never invoked"
        echo "   scope=${scope} pattern=${pattern}"
        fail=1
    else
        echo "✅ ${label}: ${n} production call site(s)"
        printf '%s' "$filtered" | sed 's/^/     /'
    fi
}

# P5-04: Output::destroy() must be driven by the task lifecycle (stop/reload).
check "Output::destroy()" crates/cpworker/src/task.rs '\.destroy\(\)'
# P5-11: the ZMTP backlog gauges must be published in collect_stats_summary.
check "zmtp_queued_* metrics" crates/cpworker/src/task.rs 'zmtp_queued_'
# P5-10: the handshake deadline must be enforced from the polling loop.
check "ZMTP handshake deadline" crates/cpworker/src/zmtp/client.rs 'conn_pending_or_stalled\(\)'

if [ "$fail" -ne 0 ]; then
    echo
    echo "See IMPROVEMENT_PLAN_AUDIT4.md §3.1: 'implemented but never called' is a"
    echo "known blind spot of dead_code/clippy. Fix the caller — do not delete the check."
fi
exit "$fail"
