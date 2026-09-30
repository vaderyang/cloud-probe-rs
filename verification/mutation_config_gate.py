#!/usr/bin/env python3
"""Hygiene gate for `verification/mutants.toml` (ADR-0001 §2.1, §7).

Mutation testing is a blocking gate, and `exclude_re` is the only way a surviving
mutant can be tolerated. That makes the exemption list itself a attack surface for
silent decay, in four specific ways this script checks:

1. **Drift.** Most entries are pinned to a `file:line:col`. Editing the source
   shifts those lines, the regex stops matching anything, and the mutant it used
   to excuse becomes a *missed* mutant again -- or, worse, starts matching a
   different mutant. Every entry must match at least one candidate mutant.
2. **Over-exclusion.** An entry written loosely (e.g. `gre\\.rs:186:` to excuse a
   sleep duration) can also swallow mutants on the same line that the tests *do*
   kill, silently deleting real coverage. With `--outcomes` from a full run, every
   entry that matches a caught mutant is rejected.
3. **Incompleteness.** With `--outcomes`, every mutant the measured run reports as
   missed/timed-out must be covered by some entry.
4. **Unjustified exemption.** Every entry needs a written reason, either as a
   trailing comment on its own line or in the comment block directly above it.

Candidate mutants come from cargo-mutants itself, using a copy of the config with
`exclude_re` stripped so the globs (and therefore the scope) stay identical.

    ./verification/mutation_config_gate.py                  # drift + justification
    ./verification/mutation_config_gate.py --outcomes 'target/mutation/*/mutants.out/outcomes.json'

Exit codes: 0 ok, 1 violations, 2 could not run cargo-mutants.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

CONFIG = "verification/mutants.toml"
LIST_TIMEOUT = 1800
DESCRIPTION = "Check verification/mutants.toml exemptions"

# cargo-mutants colours the mutation description when CARGO_TERM_COLOR=always
# (which the verification workflow sets). The escapes land *inside* the name, so
# an entry pinned to `file:line:col: replace X with Y` stops matching while the
# bare `file:line:col` prefix still does - a confusing, environment-dependent
# failure. Ask for plain output and strip escapes anyway.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def read_text(path: str) -> str:
    """Read a text file, reporting a missing/unreadable file as a clean error."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise SystemExit(f"{path}: cannot read: {exc}") from exc


# `key = [` .. `\n]` for the exclude_re array, captured with its raw text.
def find_array(text: str, key: str):
    start = text.find(key + " = [")
    if start < 0:
        return None
    end = text.index("\n]", start)
    return start, text.index("[", start), end


def parse_entries(text: str, key: str):
    """Return [(pattern, line_no, justified, reason)] for a string-array key."""
    where = find_array(text, key)
    if where is None:
        return []
    _, open_bracket, end = where
    body = text[open_bracket + 1 : end]
    base_line = text[: open_bracket + 1].count("\n") + 1
    entries = []
    # Comment block seen so far, reset by every entry line that has no comment.
    pending: list[str] = []
    for offset, raw in enumerate(body.splitlines()):
        line = raw.strip()
        no = base_line + offset + 1
        if not line:
            continue
        if line.startswith("#"):
            pending.append(line.lstrip("# ").strip())
            continue
        m = re.match(r'"((?:[^"\\]|\\.)*)"\s*,?\s*(?:#\s*(.*))?$', line)
        if not m:
            # Trailing `[`/`,` or anything else we do not model; ignore.
            pending = []
            continue
        pattern = m.group(1).replace("\\\\", "\\").replace('\\"', '"')
        trailing = (m.group(2) or "").strip()
        justified = bool(trailing) or bool(pending)
        entries.append((pattern, no, justified, trailing or " / ".join(pending)))
        pending = []
    return entries


def candidate_names(config_path: str, quiet: bool) -> list[str]:
    """Mutant names in scope, ignoring `exclude_re` but keeping the globs."""
    text = read_text(config_path)
    where = find_array(text, "exclude_re")
    stripped = text
    if where is not None:
        start, _, end = where
        head = text.rindex("\n", 0, start) + 1
        stripped = text[:head] + text[end + 2 :]
    with tempfile.NamedTemporaryFile(
        "w", suffix=".toml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(stripped)
        tmp_path = tmp.name
    env = dict(os.environ, CARGO_TERM_COLOR="never", NO_COLOR="1")
    try:
        proc = subprocess.run(
            ["cargo", "mutants", "--config", tmp_path, "--list", "--no-times"],
            capture_output=True,
            text=True,
            env=env,
            timeout=LIST_TIMEOUT,
        )
    finally:
        os.unlink(tmp_path)
    if proc.returncode != 0:
        if not quiet:
            sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(2)
    names = [ANSI_RE.sub("", ln) for ln in proc.stdout.splitlines()]
    return [ln for ln in names if ln.strip()]


def read_candidates(path: str) -> list[str]:
    """Read a pre-generated candidate-name file."""
    return [ln.strip() for ln in read_text(path).splitlines() if ln.strip()]


def caught_names(pattern: str):
    """(all mutant names seen, survivors, killed) from previous run outcomes.

    `pattern` may be a comma-separated list of globs; later files override
    earlier ones per mutant, so a scoped re-run can be layered over a full sweep.
    """
    seen: dict[str, str] = {}
    for pat in pattern.split(","):
        for path in sorted(glob.glob(pat.strip())):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as exc:
                print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
                continue
            for rec in data.get("outcomes", []):
                scenario = rec.get("scenario", {})
                if "Mutant" in scenario:
                    seen[scenario["Mutant"]["name"]] = rec.get("summary") or ""
    survivors = [n for n, s in seen.items() if s in ("MissedMutant", "Timeout")]
    killed = {n for n, s in seen.items() if s == "CaughtMutant"}
    return list(seen), survivors, killed


def main() -> int:
    ap = argparse.ArgumentParser(description=DESCRIPTION)
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument(
        "--candidates",
        help="file of candidate mutant names (default: ask cargo-mutants)",
    )
    ap.add_argument(
        "--outcomes",
        help="comma-separated globs of outcomes.json from a no-exclude sweep (later "
        "files override earlier ones); rejects over-broad entries and checks that "
        "every survivor is covered",
    )
    args = ap.parse_args()

    entries = parse_entries(read_text(args.config), "exclude_re")
    if not entries:
        print(f"{args.config}: no exclude_re entries found", file=sys.stderr)
        return 1

    killed: set[str] = set()
    survivors: list[str] = []
    if args.outcomes:
        # A run with `exclude_re` stripped is the ground truth for what the test
        # suite really kills *and* the full candidate universe, so it replaces
        # both the cargo-mutants call and the name set.
        run_names, survivors, killed = caught_names(args.outcomes)
        names = run_names
    elif args.candidates:
        names = read_candidates(args.candidates)
    else:
        names = candidate_names(args.config, quiet=False)
    print(
        f"checking {len(entries)} exclude_re entries against {len(names)} candidates"
        + (
            f", {len(survivors)} survivors, {len(killed)} killed mutants"
            if killed
            else ""
        )
    )

    errors: list[str] = []
    for pattern, no, justified, _reason in entries:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            errors.append(f"{args.config}:{no}: invalid regex {pattern!r}: {exc}")
            continue
        matched = [n for n in names if rx.search(n)]
        if not matched:
            errors.append(
                f"{args.config}:{no}: {pattern!r} matches no candidate mutant -- it "
                "is stale (the source lines moved) or the mutant is gone. Re-measure "
                "and either delete it or re-pin it; do not leave it in place."
            )
        if not justified:
            errors.append(
                f"{args.config}:{no}: {pattern!r} has no written justification; every "
                "exemption needs a reason (equivalent / runner timeout / root only)."
            )
        if killed:
            silenced = sorted({n for n in matched if n in killed})
            if silenced:
                errors.append(
                    f"{args.config}:{no}: {pattern!r} also excludes "
                    f"{len(silenced)} mutant(s) that the tests already kill, e.g.\n"
                    + "\n".join(f"      {n}" for n in silenced[:5])
                    + "\n    Narrow the regex (add the column and the exact operation)."
                )

    if survivors:
        uncovered = sorted(
            n
            for n in survivors
            if not any(re.search(p, n) for p, _, _, _ in entries)
        )
        if uncovered:
            errors.append(
                f"{len(uncovered)} surviving mutant(s) from the measured run are not "
                "covered by any exemption (this is what the blocking gate will "
                "reject), e.g.\n" + "\n".join(f"      {n}" for n in uncovered[:10])
            )

    if errors:
        print(f"\n{len(errors)} problem(s) in {args.config}:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(
        f"ok: {len(entries)} exemptions, all live, all justified"
        + (", none over-broad, all survivors accounted for" if killed else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
