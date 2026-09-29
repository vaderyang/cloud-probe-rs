#!/usr/bin/env bash
# AUDIT4 §3 gate for WP4 - "configuration and resource hygiene".
#
# All five M4 defects were invisible to the compiler and to the test suite, in
# exactly the way P5-04 was: a silently truncating cast, a fuzz target that
# exists but is never run, a doc comment promising more than the code does, an
# unwrap() on a path that "obviously" cannot fail. `clippy -D warnings` stays
# green through every one of them, and so did 138 tests.
#
# So each gets a cheap, deterministic check here - one line per invariant, in the
# spirit of parity/verify_liveness.sh (which guards §3.1 only).
#
# ---------------------------------------------------------------------------
# AUDIT4 P2-3 (independent re-audit): every one of the four checks below could be
# passed by an *equivalent rewrite* of the violation rather than the original
# wording, which makes the gate worse than no gate because it is quoted as
# evidence. What was wrong, and what replaced it:
#
#   ① "after the first `#[cfg(test)]` in the file" was the definition of test
#      code, so one empty `#[cfg(test)] mod x {}` at the top classified the whole
#      file as tests. -> test code is now delimited per block (see blocks_of).
#   ② P5-15 matched `as (i32|u16|u8|i16|usize)` in one file, so `as libc::c_int`,
#      `as u32` or a cast in the next file over walked straight through. -> the
#      type list is exhaustive (incl. every `libc::c_*` spelling and `as _`), the
#      scope is every deserialising file, and a second rule covers JSON numbers
#      narrowed by `as` anywhere in the workspace.
#   ③ P5-20 read `[[bin]]` with `grep -A1`, so a target whose `path` line came
#      before its `name` line simply did not exist. -> the target list now comes
#      from `cargo metadata`, which is field-order independent, and the check is
#      bidirectional (declared-but-unrun *and* run-but-undeclared).
#   ④ P5-22 exempted lines by matching the very keywords a violator can type
#      ("AUDIT4", "used to claim"), i.e. the check certified its own exceptions.
#      -> replaced by implications that are checked against the code: a doc that
#      claims flush() fsyncs obliges flush() to actually call sync_all/sync_data.
#
# Each of those four has a reverse check that re-inserts the violation *in the
# rewritten form* - see parity/verify_hygiene_reverse.sh, which is what
# `parity/all.sh` runs after this script.
#
# Test code is excluded on purpose: a unit test unwrapping an Option is fine, a
# production path doing it is not (that is the P5-04 lesson).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0

# --- test-code delimiting (①) ------------------------------------------------
#
# A *top-level* (column 0) `#[cfg(...test...)]` attribute or `mod *test*`
# declaration opens a test block; the first column-0 `}` closes it. rustfmt keeps
# items at column 0, so that brace is unambiguous. If a raw string ever contains a
# column-0 `}` the block ends *early*, which makes the checks look at more code -
# never less, which is the only direction that can hide a defect.
declare -A BLOCKS

blocks_of() {
    local f="$1"
    if [ -z "${BLOCKS["$f"]+set}" ]; then
        BLOCKS["$f"]=$(awk '
            !inblk && /^#\[cfg\(.*test.*\)\][[:space:]]*$/ { start = NR; inblk = 1; next }
            !inblk && /^(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]*test[A-Za-z0-9_]*[[:space:]]*\{/ {
                start = NR; inblk = 1; next
            }
            inblk && /^\}[[:space:]]*$/ { print start, NR; inblk = 0 }
            END { if (inblk) print start, NR }
        ' "$f")
    fi
    printf '%s' "${BLOCKS[$f]}"
}

# in_test_code <file> <lineno> -> 0 if the line is inside a test block
in_test_code() {
    local file="$1" lineno="$2" s e
    local blocks
    blocks=$(blocks_of "$file")
    [ -n "$blocks" ] || return 1
    while read -r s e; do
        [ -n "${s:-}" ] || continue
        if [ "$lineno" -ge "$s" ] && [ "$lineno" -le "$e" ]; then
            return 0
        fi
    done <<<"$blocks"
    return 1
}

# code_of <grep-hit>  -> the source text of the matched line
code_of() { printf '%s' "$1" | cut -d: -f3-; }

# is_comment <code>  -> 0 for whole-line comments (incl. doc comments)
is_comment() { printf '%s' "$1" | grep -qE '^[[:space:]]*(//|/\*|\*)'; }

# is_use_alias <code> -> 0 for `use a::b as c;`, where `as` is an import alias and
# not a conversion at all. Structural, not keyword-based.
is_use_alias() { printf '%s' "$1" | grep -qE '^[[:space:]]*(pub[[:space:]]+)?use[[:space:]]'; }

# forbid <label> <scope...> -- <pattern> [<extra grep -v filter>]
#
# Fails when any non-comment, non-test line in <scope> matches <pattern>.
forbid() {
    local label="$1" scope pattern skip
    shift
    # scopes run until the "--" separator, then pattern, then optional skip
    local scopes=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do scopes+=("$1"); shift; done
    [ "$#" -gt 0 ] && shift
    pattern="${1:-}"; skip="${2:-}"
    local hits line file lineno body filtered="" n
    hits=$(grep -rnH --include='*.rs' -E "$pattern" "${scopes[@]}" 2>/dev/null || true)
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        file=${line%%:*}
        lineno=${line#*:}
        lineno=${lineno%%:*}
        body=$(code_of "$line")
        is_comment "$body" && continue
        is_use_alias "$body" && continue
        in_test_code "$file" "$lineno" && continue
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

# --- P5-15: configuration numbers must never be silently narrowed ------------
# serde_json hands every JSON number over as i64; `as i32` wraps, and
# `snaplen: 2147483648` became i32::MIN -> `.max(1)` -> a 1-byte snaplen, i.e. a
# task that captures nothing. Use the range-checked helpers (int_in/i32_in/
# u16_in/u64_in) instead.
#
# Scope is *every* file that turns untrusted text into typed configuration, not
# just the one file the defect was found in (②). The type list is every integer
# and float type name, the `libc::c_*`/`os::raw::c_*` spellings of them, the C
# names, and `as _` - i.e. no spelling of "narrow this number" is quieter than
# any other.
CAST_T='(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|f32|f64|int|uint|long|ulong|short|ushort|char|uchar|size_t|ssize_t|uintptr_t|intptr_t|uint8_t|uint16_t|uint32_t|uint64_t|c_int|c_uint|c_long|c_ulong|c_schar|c_uchar|c_short|c_ushort|c_char|c_void|_)'
CAST_RE="as +(([A-Za-z_][A-Za-z0-9_]*::)*${CAST_T})([^A-Za-z0-9_]|\$)"

CONFIG_SCOPE=(
    crates/cpworker/src/config.rs
    crates/cpworker/src/bpf/parser.rs
    crates/cpdaemon/src/config.rs
    crates/cpgolib/src/worker_config.rs
)
forbid "P5-15 no unrange-checked 'as <integer>' cast in the deserialising layer" \
    "${CONFIG_SCOPE[@]}" -- "$CAST_RE"

# Same conversion class, whole workspace, keyed on where the number came from: a
# file that pulls values out of a `serde_json::Value` may not narrow any of them
# with `as`. This is the half of ② that is not expressible as one grep: it looks
# at the *file*, so "resolve it and then cast three lines later" is caught too
# (`crates/cripid` was exactly that, and is why this rule exists).
json_files=$(grep -rlE --include='*.rs' '\.as_(i64|u64|i32|u32|f64|usize)\(' crates/ \
    | grep -v '/tests/' | grep -v '/fuzz/' | sort || true)
json_offenders=""
njson=$(printf '%s\n' ${json_files:-} | grep -c .)
for f in ${json_files:-}; do
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        lineno=${line#*:}; lineno=${lineno%%:*}
        body=$(code_of "$line")
        is_comment "$body" && continue
        is_use_alias "$body" && continue
        in_test_code "$f" "$lineno" && continue
        json_offenders+="$f: JSON number source + $line"$'\n'
    done < <(grep -nE "$CAST_RE" "$f" | sed "s|^|$f:|" || true)
done
if [ -n "$json_offenders" ]; then
    echo "❌ P5-15 file reads serde_json numbers and narrows something with 'as':"
    printf '%s' "$json_offenders" | sed 's/^/     /'
    fail=1
else
    echo "✅ P5-15 no serde_json number is narrowed by an 'as' cast ($njson file(s) read JSON numbers)"
fi

# --- P5-23: no panic constructors on library paths ---------------------------
# The release profile builds with panic="abort", so a single reachable unwrap()
# costs the whole worker and every task in it. src/bin/* are the parity/fuzz
# harnesses, where panicking *is* the reporting mechanism, so they are excluded.
forbid "P5-23 cpworker library has no unwrap()/expect()/panic!()/unreachable!()" \
    crates/cpworker/src -- \
    '\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|todo!\(|unimplemented!\(' \
    '/src/bin/'

# --- P5-29: parity/oracle tooling stays out of the library crate -------------
# `cargo build -p cpworker` used to compile the differential/fuzz harnesses
# alongside the product binary. They now live in the cpworker-parity crate; this
# gate catches a tool creeping back into the shipped library crate (which would
# also silently re-widen the P5-23 exclusion above).
nbin=$(grep -cE '^[[:space:]]*\[\[bin\]\]' crates/cpworker/Cargo.toml 2>/dev/null || true)
nbin=${nbin:-0}
tools=$(find crates/cpworker-parity/src/bin -maxdepth 1 -name '*.rs' 2>/dev/null | wc -l)
p529=""
if compgen -G "crates/cpworker/src/bin/*.rs" >/dev/null 2>&1; then
    p529+="     crates/cpworker/src/bin still contains tooling:"$'\n'
    p529+="$(ls crates/cpworker/src/bin/*.rs | sed 's/^/       /')"$'\n'
fi
if [ "$nbin" -gt 1 ]; then
    p529+="     cpworker/Cargo.toml declares $nbin [[bin]] targets (expected 1)"$'\n'
fi
if [ "$tools" -lt 1 ]; then
    p529+="     crates/cpworker-parity/src/bin has no tooling"$'\n'
fi
if [ -n "$p529" ]; then
    echo "❌ P5-29 parity/oracle tooling must live in cpworker-parity, not cpworker:"
    printf '%s' "$p529"
    fail=1
else
    echo "✅ P5-29 parity/oracle tooling lives in cpworker-parity ($tools binaries)"
fi

# Positive counterpart of ①: test code belongs at the end of the file. Without
# this, "test code" is only whatever the block tracker managed to see; with it, a
# `#[cfg(test)] mod early {}` marker placed at the top of a file to blind the
# checks above is itself a failure.
late_tests=""
for f in $(grep -rlE --include='*.rs' '^#\[cfg\(.*test.*\)\]|^(pub )?mod [A-Za-z0-9_]*test[A-Za-z0-9_]*[[:space:]]*\{' crates/); do
    blocks=$(blocks_of "$f")
    [ -n "$blocks" ] || continue
    # Everything after the *first* test block must still not be production code.
    first_end=$(printf '%s\n' "$blocks" | head -1 | awk '{print $2}')
    total=$(wc -l < "$f")
    [ "$first_end" -lt "$total" ] || continue
    bad=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        n=${line%%:*}
        # a second test module parked behind the first one is fine (zmtp/client.rs
        # has two); only items outside every test block are production code
        in_test_code "$f" "$n" && continue
        bad+="$line"$'\n'
    done < <(awk -v from="$((first_end + 1))" '
        NR < from { next }
        /^(pub(\([a-z_]+\))?[[:space:]]+)?(fn|struct|enum|trait|impl|const|static|type|union|mod|macro_rules!)/ {
            print NR ": " substr($0, 1, 80)
        }
    ' "$f")
    if [ -n "$bad" ]; then
        late_tests+="$f (first test block ends at line $first_end):"$'\n'
        late_tests+="$(printf '%s\n' "$bad" | sed 's/^/     /')"
    fi
done
if [ -n "$late_tests" ]; then
    echo "❌ P5-23 production items declared after a test block (a test marker parked"
    echo "   at the top of a file must not be able to reclassify the rest of it):"
    printf '%s' "$late_tests"
    fail=1
else
    echo "✅ P5-23 test modules are the last thing in every file"
fi

# --- P5-22: the pcap writer must not promise an fsync it does not do --------
# The original claim was "call [`PcapWriter::flush`] to fsync the file". The
# first gate allowed any line containing "AUDIT4" or "used to claim", which is
# self-certifying: writing those words into the new doc line exempted it (④).
# This is now an implication checked against the implementation:
#
#   IF  the documentation claims that a flush fsyncs (affirmative phrasing)
#   THEN flush() must actually force the file out (sync_all / sync_data / fsync)
#
# and the claim is searched for across the whole library, not just the one file
# that got it wrong. Honest wording ("this is *not* an fsync") matches no
# affirmative pattern and needs no exemption list.
FSYNC_CLAIM='to +fsync|will +fsync|fsyncs? +the +file|must +fsync|fsync +on +call|call[^[:cntrl:]]{0,40}to +fsync'
claims=$(grep -rnIE --include='*.rs' "$FSYNC_CLAIM" crates/cpworker/src 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)' || true)
doc_claims=$(grep -rnIE --include='*.rs' "$FSYNC_CLAIM" crates/cpworker/src 2>/dev/null \
    | grep -E '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)' || true)
# The body of `pub fn flush` in the pcap writer - what it really does.
flush_body=$(awk '/^[[:space:]]*pub fn flush\(/ { on = 1 }
                  on { print; if (/^[[:space:]]*\}/) exit }' \
    crates/cpworker/src/output/pcap_writer.rs)
forces_disk=$(printf '%s' "$flush_body" | grep -cE 'sync_all|sync_data|libc::fsync' || true)
if [ -n "$claims" ]; then
    echo "❌ P5-22 code (not a comment) claims an fsync:"
    printf '%s' "$claims" | sed 's/^/     /'
    fail=1
elif [ -n "$doc_claims" ] && [ "${forces_disk:-0}" -eq 0 ]; then
    echo "❌ P5-22 the docs claim that flush() forces data to disk, but flush() does not:"
    printf '%s' "$doc_claims" | sed 's/^/     /'
    echo "     body of pub fn flush in crates/cpworker/src/output/pcap_writer.rs:"
    printf '%s\n' "$flush_body" | sed 's/^/     /'
    echo "   either stop claiming it, or make flush() call sync_all/sync_data"
    fail=1
elif [ "${forces_disk:-0}" -gt 0 ] && [ -z "$doc_claims" ]; then
    echo "❌ P5-22 flush() does force data out but nothing documents that promise"
    echo "   (a capability the code has must be documented, P5-22 is a doc gate)"
    fail=1
else
    echo "✅ P5-22 flush documentation matches what flush() actually does"
fi

# --- P5-20: a fuzz target must actually be run ------------------------------
# A target that is not in fuzz.sh's list never runs, not even in the CI smoke
# job (`fuzz.sh --check`). diff_oracle is the one documented exception: it needs
# the C/Go oracles and is driven by parity/difffuzz.sh instead.
#
# The target list comes from cargo metadata, not from grep over the manifest: a
# `[[bin]]` whose `path` precedes its `name` used to be invisible to
# `grep -A1 '^\[\[bin\]\]' | grep -oP '^name = "'` (③). --no-deps keeps this
# offline and cheap, and it must not silently fall back to the old grep, so a
# failure to read metadata is itself a failure.
FUZZ_MANIFEST="crates/cpworker/fuzz/Cargo.toml"
meta=$(cargo metadata --no-deps --format-version 1 \
    --manifest-path "$FUZZ_MANIFEST" 2>/dev/null)
if [ -z "$meta" ]; then
    echo "❌ P5-20 \`cargo metadata --manifest-path $FUZZ_MANIFEST\` produced nothing;"
    echo "   the fuzz-target registration check cannot fall back to grepping the"
    echo "   manifest (field-order dependent, AUDIT4 P2-3 ③). Fix the manifest."
    fail=1
    declared=""
else
    declared=$(printf '%s' "$meta" | python3 -c '
import json, sys
meta = json.load(sys.stdin)
ws = set(str(p) for p in meta["workspace_members"])
names = []
for pkg in meta["packages"]:
    if pkg["manifest_path"] in ws or pkg["name"].endswith("-fuzz"):
        for t in pkg["targets"]:
            if "bin" in t["kind"]:
                names.append(t["name"])
print("\n".join(sorted(set(names))))
')
fi
listed=$(sed -n 's/^ALL_TARGETS="\(.*\)"/\1/p' fuzz.sh)
exempt="diff_oracle"
missing=""
for t in $declared; do
    if ! grep -qw -- "$t" <<<"$listed" && ! grep -qw -- "$t" <<<"$exempt"; then
        missing="$missing $t"
    fi
done
# The other direction: fuzz.sh naming a target that is not declared means the
# CI smoke job "runs all targets" while one of its names is a no-op.
stale=""
for t in $listed; do
    printf '%s\n' "$declared" | grep -qx -- "$t" || stale="$stale $t"
done
undirs=""
for t in $declared; do
    [ -f "crates/cpworker/fuzz/fuzz_targets/$t.rs" ] || undirs="$undirs $t"
done
if [ -n "$missing" ]; then
    echo "❌ P5-20 fuzz target(s) declared but never run:$missing"
    echo "   add them to ALL_TARGETS in fuzz.sh, or document the exemption here"
    fail=1
fi
if [ -n "$stale" ]; then
    echo "❌ P5-20 fuzz.sh ALL_TARGETS names target(s) that are not declared:$stale"
    echo "   that smoke run is a no-op, not coverage"
    fail=1
fi
if [ -n "$undirs" ]; then
    echo "❌ P5-20 declared target(s) with no source under fuzz_targets/:$undirs"
    fail=1
fi
ntargets=$(printf '%s\n' $declared | grep -c .)
if [ -z "$missing" ] && [ -z "$stale" ] && [ -z "$undirs" ] && [ "$ntargets" -ge 10 ]; then
    echo "✅ P5-20 all $ntargets fuzz targets are registered in fuzz.sh (cargo metadata)"
elif [ -z "$missing" ] && [ -z "$stale" ] && [ -z "$undirs" ]; then
    echo "❌ P5-20 only $ntargets fuzz targets are declared - the fuzz workspace has"
    echo "   10; a manifest that lost targets must not read as 'all registered'"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "See IMPROVEMENT_PLAN_AUDIT4.md §3: these are the failure modes that"
    echo "survived three audits plus 138 tests. Fix the code - do not weaken the"
    echo "check."
fi
exit "$fail"
