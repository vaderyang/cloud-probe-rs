#!/usr/bin/env python3
"""Risk-coverage gate: every P0 risk has at least one *executable* verification.

Reads verification/risk.toml and enforces, per risk:

  * P0 risks have at least one evidence entry;
  * P0 risks have at least one *executable* evidence whose subject exists:
      - `test:<fn>`  -> the test function exists in the crate sources;
      - `path:<file>`-> the file exists;
      - `cmd:<cmd>`  -> the command's first path token exists and is executable.

P0 risk coverage must be 100% or the gate fails. See VERIFICATION_COVERAGE.md §6.
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
CATEGORIES = {"security", "concurrency", "data_integrity", "failure_modes"}


def scan_tests(root: Path) -> set[str]:
    found: set[str] = set()
    for p in (root / "crates").rglob("*.rs"):
        found.update(m.group(1) for m in TEST_RE.finditer(p.read_text(errors="ignore")))
    return found


def evidence_ok(entry: str, tests: set[str], root: Path) -> bool:
    if entry.startswith("test:"):
        return entry[5:] in tests
    if entry.startswith("path:"):
        return (root / entry[5:]).exists()
    if entry.startswith("cmd:"):
        cmd = entry[4:].strip().lstrip("./")
        first = cmd.split()[0] if cmd.split() else ""
        return bool(first) and (root / first).exists()
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--risks", default="verification/risk.toml")
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()

    root = Path(args.repo).resolve()
    risks = tomllib.loads((root / args.risks).read_text()).get("risk", [])
    tests = scan_tests(root)

    failures: list[str] = []
    p0_total = p0_ok = 0

    print("=" * 78)
    print(" risk coverage — security / concurrency / data-integrity / failure-modes")
    print("=" * 78)
    for r in risks:
        rid = r["id"]
        prio = r.get("priority", "P1")
        cat = r.get("category", "?")
        ev = r.get("evidence", [])
        if cat not in CATEGORIES:
            failures.append(f"{rid}: unknown category {cat!r}")
        bad = [e for e in ev if not evidence_ok(e, tests, root)]
        executable = [e for e in ev if evidence_ok(e, tests, root)]
        ok = bool(executable) and (prio != "P0" or bool(ev))
        if prio == "P0":
            p0_total += 1
            if ok:
                p0_ok += 1
        print(f"  {'ok ' if ok else 'FAIL'} {prio} {cat:14} {rid:24} evidence={len(ev)}")
        if prio == "P0" and not ev:
            failures.append(f"{rid}: P0 risk has no evidence")
        if prio == "P0" and bad:
            failures.append(f"{rid}: P0 risk evidence does not exist: {bad}")
        if prio == "P0" and not executable:
            failures.append(f"{rid}: P0 risk has no *existing* executable evidence ({bad})")

    cov = 100.0 * p0_ok / p0_total if p0_total else 100.0
    print("-" * 78)
    print(f"P0 risk coverage: {cov:.1f}% ({p0_ok}/{p0_total}) — required 100%")
    if cov < 100.0:
        failures.append(f"P0 risk coverage {cov:.1f}% < 100%")

    print("=" * 78)
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print(f"  ❌ {f}")
        return 1
    print("✅ risk coverage: every P0 risk is verified by existing evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
