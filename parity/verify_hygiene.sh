#!/usr/bin/env bash
# AUDIT4 §3 gate for WP4 - "configuration and resource hygiene".
#
# All five M4 defects were invisible to the compiler and to the test suite, in
# exactly the way P5-04 was: a silently truncating cast, a fuzz target that
# exists but is never run, a doc comment promising more than the code does, an
# unwrap() on a path that "obviously" cannot fail. `clippy -D warnings` stays
# green through every one of them, and so did 138 tests.
#
# So each gets a cheap, deterministic grep here - one line per invariant, in the
# spirit of parity/verify_liveness.sh (which guards §3.1 only).
#
# Test code is excluded on purpose: a unit test unwrapping an Option is fine, a
# production path doing it is not (that is the P5-04 lesson).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0

# code_of <grep-hit>  -> the source text of the matched line
code_of() { printf '%s' "$1" | cut -d: -f3-; }

# in_test_code <file> <lineno> -> 0 if the line lives after `mod tests`
in_test_code() {
    local file="$1" lineno="$2" first
    first=$(grep -n '^[[:space:]]*\(pub \)\?mod tests\b\|^[[:space:]]*#\[cfg(test)\]' "$file" \
        | head -1 | cut -d: -f1)
    [ -n "${first:-}" ] && [ "$lineno" -ge "$first" ]
}

# forbid <label> <scope> <pattern> [<extra grep -v filter>]
#
# Fails when any non-comment, non-test line in <scope> matches <pattern>.
forbid() {
    local label="$1" scope="$2" pattern="$3" skip="${4:-}"
    local hits line file lineno body filtered="" n
    hits=$(grep -rnH --include='*.rs' -E "$pattern" "$scope" 2>/dev/null || true)
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        file=${line%%:*}
        lineno=${line#*:}
        lineno=${lineno%%:*}
        body=$(code_of "$line")
        # skip whole-line comments (incl. doc comments)
        if printf '%s' "$body" | grep -qE '^[[:space:]]*(//|/\*|\*)'; then
            continue
        fi
        if in_test_code "$file" "$lineno"; then
            continue
        fi
        if [ -n "$skip" ] && printf '%s' "$line" | grep -qE "$skip"; then
            continue
        fi
        filtered+="$line"$'\n'
    done <<<"$hits"
    n=$(printf '%s' "$filtered" | grep -c .)
    if [ "${n:-0}" -ne 0 ]; then
        echo "❌ ${label}: ${n} offending line(s)"
        printf '%s' "$filtered" | sed 's/^/     /'
        fail=1
    else
        echo "✅ ${label}"
    fi
}

# --- P5-15: configuration numbers must never be silently narrowed -----------
# serde_json hands every JSON number over as i64; `as i32` wraps, and
# `snaplen: 2147483648` became i32::MIN -> `.max(1)` -> a 1-byte snaplen, i.e. a
# task that captures nothing. Use the range-checked helpers (int_in/i32_in/
# u16_in/u64_in) in config.rs instead.
forbid "P5-15 config.rs contains no truncating 'as i32/u16/u8/usize' cast" \
    crates/cpworker/src/config.rs 'as +(i32|u16|u8|i16|usize)\b'

# --- P5-23: no panic constructors on library paths ---------------------------
# The release profile builds with panic="abort", so a single reachable unwrap()
# costs the whole worker and every task in it. src/bin/* are the parity/fuzz
# harnesses, where panicking *is* the reporting mechanism, so they are excluded.
forbid "P5-23 cpworker library has no unwrap()/expect()/panic!()/unreachable!()" \
    crates/cpworker/src \
    '\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|todo!\(|unimplemented!\(' \
    '/src/bin/'

# --- P5-22: the pcap writer must not promise an fsync it does not do --------
# "call [`PcapWriter::flush`] to fsync" was the exact false claim. The docs may
# of course *explain* that flush() is not an fsync, so lines that say so
# explicitly ("used to claim" / the AUDIT4 note) are allowed.
if awk '/flush[^ ]* to fsync/ && !/used to claim/ && !/AUDIT4/ { bad = 1 }
       END { exit !bad }' crates/cpworker/src/output/pcap_writer.rs; then
    echo '❌ P5-22 pcap_writer.rs again claims that flush() fsyncs'
    grep -n 'flush[^ ]* to fsync' crates/cpworker/src/output/pcap_writer.rs | sed 's/^/     /'
    fail=1
else
    echo '✅ P5-22 pcap_writer flush documentation matches what flush() actually does'
fi

# --- P5-20: a fuzz target must actually be run ------------------------------
# A target that is not in fuzz.sh's list never runs, not even in the CI smoke
# job (`fuzz.sh --check`). diff_oracle is the one documented exception: it needs
# the C/Go oracles and is driven by parity/difffuzz.sh instead.
declared=$(grep -A1 '^\[\[bin\]\]' crates/cpworker/fuzz/Cargo.toml |
    grep -oP '^name = "\K[^"]+' | sort -u)
listed=$(sed -n 's/^ALL_TARGETS="\(.*\)"/\1/p' fuzz.sh)
exempt="diff_oracle"
missing=""
for t in $declared; do
    if ! grep -qw -- "$t" <<<"$listed" && ! grep -qw -- "$t" <<<"$exempt"; then
        missing="$missing $t"
    fi
done
if [ -n "$missing" ]; then
    echo "❌ P5-20 fuzz target(s) declared but never run:$missing"
    echo "   add them to ALL_TARGETS in fuzz.sh, or document the exemption here"
    fail=1
else
    echo "✅ P5-20 all $(printf '%s\n' $declared | grep -c .) fuzz targets are registered in fuzz.sh"
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "See IMPROVEMENT_PLAN_AUDIT4.md §3: these are the failure modes that"
    echo "survived three audits plus 138 tests. Fix the code - do not weaken the"
    echo "check."
fi
exit "$fail"
