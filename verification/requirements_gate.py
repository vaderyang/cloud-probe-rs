#!/usr/bin/env python3
"""Behaviour-coverage gate (P0 scenario coverage = 100%).

Reads verification/requirements.toml and asserts, for every requirement:

  * P0 requirements map to at least one test;
  * every mapped test name exists as a real test function in the crate sources.

Scenario coverage for P0 must be 100% or the gate fails. Optional `--check-ignored`
also reports mapped tests that are `#[ignore]`d (they only run in the privileged
CI job), for visibility.

See VERIFICATION_COVERAGE.md §5.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

TEST_RE = re.compile(
    r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)
IGNORE_RE = re.compile(
    r"#\[(?:tokio::)?test[^\]]*\bignore\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)


def scan_tests(root: Path) -> tuple[set[str], set[str]]:
    found: set[str] = set()
    ignored: set[str] = set()
    for p in (root / "crates").rglob("*.rs"):
        s = p.read_text(errors="ignore")
        found.update(m.group(1) for m in TEST_RE.finditer(s))
        ignored.update(m.group(1) for m in IGNORE_RE.finditer(s))
    return found, ignored


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requirements", default="verification/requirements.toml")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--check-ignored", action="store_true")
    args = ap.parse_args()

    root = Path(args.repo).resolve()
    reqs = tomllib.loads((root / args.requirements).read_text()).get("requirement", [])
    found, ignored = scan_tests(root)

    failures: list[str] = []
    p0_total = p0_ok = 0

    print("=" * 78)
    print(" behaviour coverage — requirement/scenario/state-transition")
    print("=" * 78)
    for r in reqs:
        rid = r["id"]
        prio = r.get("priority", "P2")
        tests = r.get("tests", [])
        missing = [t for t in tests if t not in found]
        ok = not missing and (tests or prio != "P0")
        if prio == "P0":
            p0_total += 1
            if ok:
                p0_ok += 1
        state = r.get("state_transition", "")
        mark = "ok " if ok else "FAIL"
        state_note = f"  [{state}]" if state else ""
        print(f"  {mark} {prio} {rid:26} tests={len(tests):2}{state_note}")
        if not tests and prio == "P0":
            failures.append(f"{rid}: P0 requirement maps to no tests")
        for t in missing:
            failures.append(f"{rid}: mapped test does not exist: {t}")
        if args.check_ignored:
            for t in tests:
                if t in ignored:
                    print(f"        (ignored: {t} — runs in the privileged job)")

    cov = 100.0 * p0_ok / p0_total if p0_total else 100.0
    print("-" * 78)
    print(f"P0 scenario coverage: {cov:.1f}% ({p0_ok}/{p0_total}) — required 100%")
    if cov < 100.0:
        failures.append(f"P0 scenario coverage {cov:.1f}% < 100%")

    print("=" * 78)
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print(f"  ❌ {f}")
        return 1
    print("✅ behaviour coverage: every requirement maps to existing tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
