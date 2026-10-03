#!/usr/bin/env bash
# mutation_resweep.sh - re-run the no-exclude sweep and diff it against the
# 2026-10-02 baseline.
#
# Why: cloud-probe-rs-ix9. The 2026-10-02 sweep reported 59 timeouts, but 45 of
# those mutants had *also* failed a test - they were only reported as timeouts
# because ReloadWorker never set `done` when its work panicked, so the harness
# hung and cargo-mutants could not call them killed. Every one of those was
# therefore carried in `exclude_re` as "runner timeout". Fixing that should turn
# them into real kills and shrink the exemption list; this script measures it.
#
# usage: mutation_resweep.sh [worktree]        (default: this checkout)
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

REPO=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
BASE_OUT=${BASE_OUT:-/tmp/mutout}
OUT="$BASE_OUT/resweep-$(date +%Y%m%d-%H%M)"
TAG=${TAG:-resweep}
JOBS=${JOBS:-12}

cd "$REPO"
mkdir -p "$OUT"

# Strip exclude_re into a scratch config: the sweep must see every mutant.
python3 - <<'PY'
t = open('verification/mutants.toml').read()
i = t.index('exclude_re = [')
h = t.rindex('\n', 0, i) + 1
e = t.index('\n]', i) + 2
open('/tmp/mut-noexcl.toml', 'w').write(t[:h] + t[e:])
PY

echo "[$TAG] sweeping $REPO with -j $JOBS (cold builds, expect ~20 min) ..."
cargo mutants --config /tmp/mut-noexcl.toml -j "$JOBS" --output "$OUT" --no-shuffle \
  > "$OUT/sweep.log" 2>&1 || true

D="$OUT/mutants.out"
tail -1 "$OUT/sweep.log"
printf '\n%-12s %8s\n' category count
for f in caught missed timeout unviable; do
  printf '%-12s %8s\n' "$f" "$(wc -l < "$D/$f.txt" 2>/dev/null || echo 0)"
done

# The number that matters: how many mutants are still timeouts, and of those how
# many also failed a test (i.e. are kills the harness could not report).
python3 - "$D" <<'PY'
import json, pathlib, sys, re
d = pathlib.Path(sys.argv[1])
try:
    outs = json.load(open(d / "outcomes.json"))["outcomes"]
except Exception as exc:
    print(f"(no outcomes.json: {exc})"); raise SystemExit
to, to_with_fail, killed = [], 0, 0
for e in outs:
    s = e.get("summary")
    if s == "CaughtMutant":
        killed += 1
    if s == "Timeout":
        name = e["scenario"]["Mutant"]["name"]
        to.append(name)
        lp = e.get("log_path")
        txt = ""
        if lp and (d / lp).exists():
            txt = (d / lp).read_text(errors="replace")
        # A killed-but-hanging run never prints the summary line, so look for the
        # per-test marker. Verified against the 2026-10-02 sweep: of its 59 timeouts,
        # 45 carry a "test ... FAILED" line and *also* a "has been running for over"
        # line - i.e. the suite did kill the mutant, the harness just could not say so.
        if re.search(r"test [^\n]*\.\.\. FAILED", txt):
            to_with_fail += 1
print(f"\ntimeouts: {len(to)}   of which the suite ALSO failed: {to_with_fail}")
print(f"killed: {killed}")
PY
echo "[$TAG] raw: $OUT"
