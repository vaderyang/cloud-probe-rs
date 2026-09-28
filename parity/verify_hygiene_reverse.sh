#!/usr/bin/env bash
# AUDIT4 P2-3 reverse check for parity/verify_hygiene.sh.
#
# "We added a gate" is only worth something if the *equivalent rewrite* of the
# violation also fails. An independent re-audit injected four violations into a
# copy of this repository - each written differently from the defect the gate was
# written against - and all four gates stayed ✅ with exit 0. That is what this
# script prevents: it re-inserts each violation in its rewritten form and requires
# the gate to go ❌.
#
# Everything happens in a throwaway copy under $TMPDIR; the work tree is never
# touched (verified with git status at the end). Run it after changing either
# verify_hygiene.sh or the code it inspects.
#
#   parity/verify_hygiene_reverse.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/hygiene-reverse.XXXXXX") || exit 1
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

before=$(git -C "$ROOT" status --porcelain | md5sum)
tar -C "$ROOT" --exclude=./target --exclude=./.git -cf - . 2>/dev/null \
    | tar -C "$WORK" -xf - || { echo "❌ could not copy the tree to $WORK"; exit 1; }

fail=0
declare -a RESULTS=()

# inject <label> <expected-❌-substring> <python-snippet>
#
# The snippet runs in $WORK and edits files there only. The gate must exit
# non-zero *and* name the check that is supposed to catch this violation, so a
# failure of some unrelated check cannot be counted as a pass.
inject() {
    local label="$1" expect="$2" script="$3" out rc
    if ! printf '%s' "$script" | (cd "$WORK" && python3 -) 2>/dev/null; then
        RESULTS+=("❌ $label: injection script failed")
        fail=1
        return
    fi
    out=$( (cd "$WORK" && bash parity/verify_hygiene.sh) 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ]; then
        RESULTS+=("❌ $label: verify_hygiene.sh still exited 0 (gate is bypassable)")
        printf '%s\n' "$out" | sed 's/^/       /'
        fail=1
    elif ! printf '%s' "$out" | grep -q "❌ $expect"; then
        RESULTS+=("❌ $label: gate failed but not the check that should catch it ('$expect')")
        printf '%s\n' "$out" | grep '❌' | sed 's/^/       /'
        fail=1
    else
        RESULTS+=("✅ $label")
    fi
    # restore the pristine tree for the next case
    tar -C "$ROOT" --exclude=./target --exclude=./.git -cf - . 2>/dev/null \
        | tar -C "$WORK" -xf -
}

# --- ① test-code classification ----------------------------------------------
# The original violation used the *first* `#[cfg(test)]` in the file as the
# definition of "test code". Rewritten: an empty cfg(test) module on one line at
# the top, with the production hazard appended after the file's real test module.
inject "① one-line #[cfg(test)] marker at the top reclassifies the file (P5-23)" \
    "P5-23" \
    '
p="crates/cpworker/src/netns.rs"
s=open(p).read()
s="#[cfg(test)]\nmod early_test_marker {}\n\n"+s
s+="\npub fn hole_demo(x: Option<u32>) -> u32 { x.unwrap() }\n"
open(p,"w").write(s)
'

# --- ② truncating cast, different spelling, different file ------------------
inject "② 'as libc::c_int' in config.rs (P5-15)" "P5-15" \
    '
p="crates/cpworker/src/config.rs"
s=open(p).read()
hole="fn p5_15_hole_demo(v: i64) -> libc::c_int { v as libc::c_int }\n\n"
i=s.index("#[cfg(test)]")
open(p,"w").write(s[:i]+hole+s[i:])
'

inject "② narrowing cast moved to another deserialising file (P5-15)" "P5-15" \
    '
p="crates/cpworker/src/bpf/parser.rs"
s=open(p).read()
hole="fn p5_15_hole_u32(v: i64) -> u32 {\n    v as u32\n}\n\n"
i=s.index("#[cfg(test)]")
open(p,"w").write(s[:i]+hole+s[i:])
'

inject "② serde_json number narrowed three lines later, outside config (P5-15)" "P5-15" \
    '
p="crates/cripid/src/main.rs"
s=open(p).read()
s=s.replace(".and_then(|p| i32::try_from(p).ok());", ".and_then(|p| Some(p));")
s=s.replace("let Some(pid) = pid.filter(|p| *p > 0) else {", "let Some(pid) = Some(pid).filter(|p| *p > 0) else {")
s=s.replace("return Ok(pid);", "return Ok(pid as i32);")
open(p,"w").write(s)
'

# --- ③ fuzz target registration, field order swapped ------------------------
inject "③ an 11th [[bin]] with path before name is invisible (P5-20)" "P5-20" \
    '
m="crates/cpworker/fuzz/Cargo.toml"
s=open(m).read()
s+=("\n[[bin]]\npath = \"fuzz_targets/hole_target.rs\"\nname = \"hole_target\"\n"
    "test = false\ndoc = false\nbench = false\n")
open(m,"w").write(s)
open("crates/cpworker/fuzz/fuzz_targets/hole_target.rs","w").write(
    "#![no_main]\nfn main() {}\n")
'

# --- ④ self-certifying doc exemption ----------------------------------------
inject "④ fsync claim that quotes the exemption keywords (P5-22)" "P5-22" \
    '
p="crates/cpworker/src/output/pcap_writer.rs"
s=open(p).read()
s=("//! AUDIT4 note: call [`PcapWriter::flush`] to fsync the file to disk.\n"+s)
open(p,"w").write(s)
'

inject "④ fsync claim in a file the old check never looked at (P5-22)" "P5-22" \
    '
p="crates/cpworker/src/output/rotating_file.rs"
s=open(p).read()
s=("/// RotatingFileOutput::destroy will fsync the file for you.\n"+s)
open(p,"w").write(s)
'

echo "=========================================================="
echo " verify_hygiene.sh reverse check (AUDIT4 P2-3)"
echo "=========================================================="
printf '%s\n' "${RESULTS[@]}"

after=$(git -C "$ROOT" status --porcelain | md5sum)
if [ "$before" != "$after" ]; then
    echo "❌ the work tree changed while this script ran - that must never happen"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "One of the gates in parity/verify_hygiene.sh can still be passed by an"
    echo "equivalent rewrite of the violation it exists to catch. Fix the gate."
fi
exit "$fail"
