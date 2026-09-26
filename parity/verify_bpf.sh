#!/usr/bin/env bash
# Differential test: pure-Rust tcpdump-subset compiler/interpreter vs libpcap.
#
# Generates a seeded corpus of filter expressions and Ethernet frames, evaluates
# both implementations (libpcap `pcap_offline_filter` and the Rust interpreter)
# and requires identical per-packet decisions.
#
# Usage: verify_bpf.sh [seed] [n_pkts] [n_exprs]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SEED="${1:-$RANDOM}"
NPKTS="${2:-400}"
NEXPRS="${3:-80}"
CC="${CC:-cc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> building libpcap oracle"
"$CC" -O2 -o "$WORK/c_bpf" "$HERE/c_bpf.c" -lpcap

echo "==> building Rust evaluator"
cargo build -q --manifest-path "$ROOT/Cargo.toml" -p cpworker --bin bpf_eval

echo "==> generating corpus (seed=$SEED pkts=$NPKTS exprs=$NEXPRS)"
python3 "$HERE/gen_bpf_cases.py" "$SEED" "$NPKTS" "$NEXPRS" "$WORK/exprs.txt" "$WORK/pkts.txt"

"$WORK/c_bpf" "$WORK/exprs.txt" "$WORK/pkts.txt" > "$WORK/c.out"
"$ROOT/target/debug/bpf_eval" "$WORK/exprs.txt" "$WORK/pkts.txt" > "$WORK/rs.out"

python3 - "$WORK/exprs.txt" "$WORK/c.out" "$WORK/rs.out" <<'PY'
import sys

exprs = [l.rstrip("\n") for l in open(sys.argv[1]) if l.strip()]
c = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip()]
r = [l.rstrip("\n") for l in open(sys.argv[3]) if l.strip()]

if len(c) != len(r):
    print(f"line count differs: c={len(c)} rs={len(r)}")
    sys.exit(1)

def norm(s):
    # Error messages differ in wording; both rejecting the expression is a match.
    return "ERR" if s.startswith("ERR") else s

bad = 0
for i, (a, b) in enumerate(zip(c, r)):
    if norm(a) == norm(b):
        continue
    bad += 1
    expr = exprs[i] if i < len(exprs) else "?"
    if a.startswith("ERR") or b.startswith("ERR"):
        print(f"[{i}] expr={expr!r}\n    c={a}\n    rs={b}")
        continue
    # Find the first differing packet.
    ca, cb = a.split(" ", 1)[1], b.split(" ", 1)[1]
    for j, (x, y) in enumerate(zip(ca, cb)):
        if x != y:
            print(f"[{i}] expr={expr!r} pkt#{j}: c={x} rs={y}")
            break
    else:
        print(f"[{i}] expr={expr!r}: lines differ in length")
    if bad >= 15:
        print("... (truncated)")
        break

if bad:
    print(f"MISMATCH: {bad} expression(s) differ")
    sys.exit(1)
print(f"OK: {len(c)} expressions x {len(c[0].split(' ',1)[1]) if c else 0} packets identical")
PY
