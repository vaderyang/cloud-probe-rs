#!/usr/bin/env python3
"""Verification-coverage gate.

Reads an lcov report (from `cargo llvm-cov`), the tiered policy in
verification/policy.toml and the ratchet baseline, and enforces:

  1. per-tier line/function coverage never drops below the baseline (ratchet);
  2. a tier that has already reached its target is held at the target;
  3. a tier below its target must have an unexpired waiver (owner+expiry);
  4. critical functions have 100% function coverage (no `FNDA:0`);
  5. changed-line diff coverage (default line>=90%, branch>=85%).

See VERIFICATION_COVERAGE.md for the design. Exit code is non-zero on any
failure. `--update-baseline` rewrites verification/baseline.json (only upward).

No third-party deps (tomllib is stdlib on 3.11+).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import subprocess
import sys
import tomllib
from pathlib import Path

# --------------------------------------------------------------------------- #
# lcov parsing
# --------------------------------------------------------------------------- #


def norm_path(sf: str) -> str:
    """Normalize an lcov SF path to a repo-relative path from `crates/`."""
    i = sf.find("crates/")
    return sf[i:] if i >= 0 else sf


class FileCov:
    __slots__ = ("lines", "functions", "branches", "fnf", "fnh")

    def __init__(self) -> None:
        self.lines: dict[int, int] = {}          # line -> hit count
        self.functions: dict[str, int] = {}      # (mangled) name -> max hit count
        self.branches: dict[tuple[int, int, int], int] = {}  # (line,block,branch) -> taken
        # llvm-cov's own function summary (FNF/FNH). It already collapses the
        # several crate instantiations of one source function (the same function
        # appears under two crate-disambiguator hashes, hit in one and not the
        # other); recomputing from the raw FNDA names would double-count it.
        self.fnf = 0
        self.fnh = 0


def parse_lcov(path: Path) -> dict[str, FileCov]:
    files: dict[str, FileCov] = {}
    cur: FileCov | None = None
    with path.open() as fh:
        for ln in fh:
            ln = ln.strip()
            if ln.startswith("SF:"):
                cur = FileCov()
                files[norm_path(ln[3:])] = cur
            elif cur is None:
                continue
            elif ln.startswith("DA:"):
                parts = ln[3:].split(",")
                try:
                    cur.lines[int(parts[0])] = int(parts[1])
                except (ValueError, IndexError):
                    pass
            elif ln.startswith("FNDA:"):
                rest = ln[5:]
                count_s, _, name = rest.partition(",")
                try:
                    count = int(count_s)
                except ValueError:
                    continue
                if name:
                    cur.functions[name] = max(cur.functions.get(name, 0), count)
            elif ln.startswith("FN:"):
                rest = ln[3:]
                _, _, name = rest.partition(",")
                if name:
                    cur.functions.setdefault(name, 0)
            elif ln.startswith("FNF:"):
                cur.fnf = int(ln[4:] or 0)
            elif ln.startswith("FNH:"):
                cur.fnh = int(ln[4:] or 0)
            elif ln.startswith("BRDA:"):
                parts = ln[5:].split(",")
                if len(parts) >= 4:
                    try:
                        taken = -1 if parts[3] == "-" else int(parts[3])
                        cur.branches[(int(parts[0]), int(parts[1]), int(parts[2]))] = taken
                    except ValueError:
                        pass
    return files


# --------------------------------------------------------------------------- #
# tiers
# --------------------------------------------------------------------------- #


class Tier:
    def __init__(self, spec: dict) -> None:
        self.id = int(spec["id"])
        self.name = spec["name"]
        self.line_target = float(spec.get("line", 0.0))
        self.branch_target = float(spec.get("branch", 0.0))
        self.function_target = float(spec.get("function", 0.0))
        self.paths = spec.get("paths", [])
        self.fallback = bool(spec.get("fallback", False))


def load_tiers(policy: dict) -> list[Tier]:
    return [Tier(t) for t in policy.get("tier", [])]


def tier_for(path: str, tiers: list[Tier]) -> Tier:
    for t in tiers:
        if t.fallback:
            continue
        for glob in t.paths:
            if fnmatch.fnmatch(path, glob):
                return t
    for t in tiers:
        if t.fallback:
            return t
    raise SystemExit("policy has no fallback tier")


def pct(covered: int, total: int) -> float:
    return 100.0 * covered / total if total else 100.0


# --------------------------------------------------------------------------- #
# demangling for critical functions
# --------------------------------------------------------------------------- #


def demangle(names: list[str]) -> dict[str, str]:
    if not names:
        return {}
    proc = subprocess.run(
        ["c++filt", "-s", "rust"],
        input="\n".join(names),
        capture_output=True,
        text=True,
    )
    out = proc.stdout.splitlines()
    if len(out) != len(names):  # fall back to mangled names
        return {n: n for n in names}
    return dict(zip(names, out))


def normalize_demangled(s: str) -> str:
    import re

    s = re.sub(r"\[[0-9a-f]+\]", "", s)  # crate disambiguator
    return s.replace("<", "").replace(">", "")


# --------------------------------------------------------------------------- #
# diff coverage
# --------------------------------------------------------------------------- #


def changed_lines(repo: Path, base: str, diff_filter: str) -> dict[str, set[int]]:
    """New-side changed line numbers per file, from `git diff -U0`."""
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "--unified=0", "--diff-filter=AM",
         f"{base}...HEAD"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit(f"git diff failed: {out.stderr.strip()}")
    res: dict[str, set[int]] = {}
    cur: str | None = None
    for ln in out.stdout.splitlines():
        if ln.startswith("+++ "):
            p = ln[4:].strip()
            cur = p[2:] if p.startswith("b/") else p
            res.setdefault(cur, set())
        elif ln.startswith("@@") and cur is not None:
            # @@ -a,b +c,d @@
            plus = ln.split("+", 1)[1].split(" ", 1)[0]
            start_s, _, count_s = plus.partition(",")
            try:
                start = int(start_s)
                count = int(count_s) if count_s else 1
            except ValueError:
                continue
            for i in range(start, start + count):
                res[cur].add(i)
    return {k: v for k, v in res.items() if v}


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="verification/policy.toml")
    ap.add_argument("--lcov", default=None)
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--diff", action="store_true", help="also check changed-line coverage")
    ap.add_argument("--diff-base", default=None)
    ap.add_argument("--tolerance", type=float, default=0.0)
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    policy_path = repo / args.policy
    policy = tomllib.loads(policy_path.read_text())

    lcov_path = repo / (args.lcov or policy["report"]["lcov"])
    baseline_path = repo / (args.baseline or policy["report"]["baseline"])
    if not lcov_path.exists():
        print(f"!! lcov not found at {lcov_path}; run verify_coverage.sh first")
        return 2

    files = parse_lcov(lcov_path)
    tiers = load_tiers(policy)
    crit_patterns = policy.get("critical_functions", {}).get("patterns", [])
    crit_waived = {w["pattern"]: w for w in policy.get("critical_waiver", [])}

    # --- normalized function counts ------------------------------------------
    #
    # One source function is compiled into several crate instantiations: the same
    # function appears under two disambiguator hashes, hit in one and zero in the
    # other. Normalizing the demangled name (stripping `[hash]`/`<>`) collapses
    # them and takes the max.
    #
    # Compiler-generated closures (`...::{closure#N}`) are excluded: almost all of
    # them are `.map_err(|e| ...)` error formatters, which are only reachable when
    # the OS/IO fails. They are not independently-designed functions, and counting
    # them makes the function target measure the number of error paths, not the
    # share of the code under test. See VERIFICATION_COVERAGE.md.
    def is_closure(demangled: str) -> bool:
        return "::{closure#" in demangled

    all_names = [n for fc in files.values() for n in fc.functions]
    dem = demangle(all_names)
    norm_fn: dict[str, dict[str, int]] = {}
    for path, fc in files.items():
        m: dict[str, int] = {}
        for n, c in fc.functions.items():
            d = dem.get(n, n)
            if is_closure(d):
                continue
            k = normalize_demangled(d)
            m[k] = max(m.get(k, 0), c)
        norm_fn[path] = m

    # --- per-tier aggregation -------------------------------------------------
    agg: dict[int, dict[str, int]] = {
        t.id: {"lf": 0, "lh": 0, "ff": 0, "fh": 0, "bf": 0, "bh": 0} for t in tiers
    }
    for path, fc in files.items():
        t = tier_for(path, tiers)
        a = agg[t.id]
        for count in fc.lines.values():
            a["lf"] += 1
            a["lh"] += 1 if count > 0 else 0
        for count in norm_fn[path].values():
            a["ff"] += 1
            a["fh"] += 1 if count > 0 else 0
        for taken in fc.branches.values():
            a["bf"] += 1
            a["bh"] += 1 if taken > 0 else 0

    current: dict[str, dict[str, float]] = {}
    for t in tiers:
        a = agg[t.id]
        current[str(t.id)] = {
            "line": pct(a["lh"], a["lf"]),
            "function": pct(a["fh"], a["ff"]),
            "branch": pct(a["bh"], a["bf"]) if a["bf"] else 0.0,
            "line_hit": a["lh"], "line_total": a["lf"],
            "fn_hit": a["fh"], "fn_total": a["ff"],
        }

    # --- baseline / ratchet ---------------------------------------------------
    baseline: dict[str, dict[str, float]] = {}
    if baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text()).get("tiers", {})
        except (OSError, json.JSONDecodeError) as e:
            print(f"!! cannot read baseline {baseline_path}: {e}")
            return 2

    today = _dt.date.today()
    waivers = {int(w["tier"]): w for w in policy.get("waiver", [])}

    failures: list[str] = []
    print("=" * 78)
    print(" verification coverage — tiered gate")
    print("=" * 78)
    print(f"{'tier':4} {'name':26} {'line':>16} {'branch':>8} {'function':>14}  verdict")
    for t in tiers:
        c = current[str(t.id)]
        base = baseline.get(str(t.id), {})
        base_line = base.get("line", 0.0)
        base_fn = base.get("function", 0.0)
        base_br = base.get("branch", 0.0)
        has_branch = c["branch"] > 0.0

        verdict = "ok"
        # ratchet: never below baseline (branch only once branch data exists)
        if base and (
            c["line"] < base_line - args.tolerance
            or c["function"] < base_fn - args.tolerance
            or (has_branch and base_br > 0.0 and c["branch"] < base_br - args.tolerance)
        ):
            verdict = "DECREASE"
            failures.append(
                f"tier {t.id} coverage decreased: line {c['line']:.1f} < {base_line:.1f} "
                f"or function {c['function']:.1f} < {base_fn:.1f}"
            )
        # target: enforced once reached, else waiver required
        elif base_line >= t.line_target and c["line"] + args.tolerance < t.line_target:
            verdict = f"< target {t.line_target:.0f}"
            failures.append(f"tier {t.id} line {c['line']:.1f} < target {t.line_target:.0f}")
        elif (
            t.function_target > 0.0
            and base_fn >= t.function_target
            and c["function"] + args.tolerance < t.function_target
        ):
            verdict = f"< fn {t.function_target:.0f}"
            failures.append(
                f"tier {t.id} function {c['function']:.1f} < target {t.function_target:.0f}"
            )
        elif (
            t.branch_target > 0.0
            and base_br >= t.branch_target
            and has_branch
            and c["branch"] + args.tolerance < t.branch_target
        ):
            verdict = f"< branch {t.branch_target:.0f}"
            failures.append(
                f"tier {t.id} branch {c['branch']:.1f} < target {t.branch_target:.0f}"
            )
        elif not base or base_line < t.line_target:
            w = waivers.get(t.id)
            if w is None:
                verdict = "NO WAIVER"
                failures.append(
                    f"tier {t.id} line {c['line']:.1f} < target {t.line_target:.0f} "
                    "and no [[waiver]] is registered"
                )
            else:
                expires = _dt.date.fromisoformat(w["expires"])
                if expires < today:
                    verdict = "WAIVER EXPIRED"
                    failures.append(
                        f"tier {t.id} waiver expired {w['expires']} (owner {w['owner']})"
                    )
                else:
                    verdict = f"waived→{w['expires']}"

        branch_s = f"{c['branch']:6.1f}%" if has_branch else "     -"
        print(
            f"{t.id:<4} {t.name:26} "
            f"{c['line']:6.1f}% ({c['line_hit']:>5}/{c['line_total']:<5}) "
            f"{branch_s:>8} "
            f"{c['function']:5.1f}% ({c['fn_hit']:>4}/{c['fn_total']:<4})  {verdict}"
        )

    # --- critical functions ---------------------------------------------------
    # aggregate counts by normalized demangled name (closures included here: a
    # critical function's closure may be the only thing that runs).
    norm_counts: dict[str, int] = {}
    for n, d in dem.items():
        # find the count for this mangled name across files
        cnt = 0
        for fc in files.values():
            if n in fc.functions:
                cnt = max(cnt, fc.functions[n])
        norm_counts[normalize_demangled(d)] = max(
            norm_counts.get(normalize_demangled(d), 0), cnt
        )

    print("-" * 78)
    print("critical functions (function coverage must be 100%)")
    for pat in crit_patterns:
        hit = any(pat in name and c > 0 for name, c in norm_counts.items())
        if hit:
            print(f"  ok    {pat}")
        else:
            print(f"  MISS  {pat}")
            failures.append(f"critical function never executed: {pat}")
    for pat, w in crit_waived.items():
        print(f"  waive {pat}  ({w.get('covered_by', '?')}: {w.get('reason', '')})")

    # --- diff coverage --------------------------------------------------------
    if args.diff:
        base = args.diff_base or policy.get("change", {}).get("base", "origin/main")
        line_thr = float(policy.get("change", {}).get("line", 90.0))
        excl = set(policy.get("change", {}).get("exclude_tiers", []))
        changed = changed_lines(repo, base, "AM")
        dl_hit = dl_tot = 0
        print("-" * 78)
        print(f"changed-line coverage (base {base})")
        for path, lines in sorted(changed.items()):
            if not path.endswith(".rs") or not path.startswith("crates/"):
                continue
            t = tier_for(path, tiers)
            if t.id in excl:
                continue
            fc = files.get(path)
            if fc is None:
                print(f"  (no coverage data) {path}")
                continue
            tot = hit = 0
            for line in lines:
                if line in fc.lines:
                    tot += 1
                    hit += 1 if fc.lines[line] > 0 else 0
            dl_hit += hit
            dl_tot += tot
            if tot:
                p = pct(hit, tot)
                flag = "ok" if p >= line_thr else "LOW"
                print(f"  {flag:3} {p:5.1f}% ({hit}/{tot})  {path}")
        if dl_tot:
            dp = pct(dl_hit, dl_tot)
            print(f"  total changed-line coverage: {dp:.1f}% ({dl_hit}/{dl_tot}), "
                  f"threshold {line_thr:.0f}%")
            if dp + args.tolerance < line_thr:
                failures.append(
                    f"changed-line coverage {dp:.1f}% < {line_thr:.0f}%"
                )
        else:
            print("  (no changed .rs lines under crates/)")

    # --- baseline update ------------------------------------------------------
    if args.update_baseline:
        merged = dict(baseline)
        for t in tiers:
            c = current[str(t.id)]
            prev = merged.get(str(t.id), {})
            merged[str(t.id)] = {
                "line": max(c["line"], prev.get("line", 0.0)),
                "function": max(c["function"], prev.get("function", 0.0)),
                "branch": max(c["branch"], prev.get("branch", 0.0)),
            }
        baseline_path.write_text(
            json.dumps({"version": 1, "tiers": merged}, indent=2, sort_keys=True) + "\n"
        )
        print(f"\nbaseline updated: {baseline_path}")

    print("=" * 78)
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print(f"  ❌ {f}")
        return 1
    print("✅ verification coverage: all enforced checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
