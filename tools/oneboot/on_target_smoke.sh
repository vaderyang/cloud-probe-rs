#!/usr/bin/env bash
# on_target_smoke.sh - run a released cloud-probe-rs build on the OS that PXE
# installed it on, and write a machine-readable verdict.
#
# This is the payload that a OneBoot kickstart `%post` (or a manual run on an
# already-installed host) drops onto the target.  It is deliberately
# distro-tolerant: it must run on CentOS 7 (bash 4.2, glibc 2.17), RHEL 7-10,
# Kylin/UOS/OpenEuler/NeoKylin and Ubuntu, with only base + the packages the
# kickstart installs (iproute, python3).
#
# What it proves, per the release contract:
#   1. the archive extracts and its sha256 matches;
#   2. every shipped binary loads and answers --version/--help on this glibc
#      (a musl build or a too-new glibc baseline fails right here);
#   3. cpworker really starts, opens an AF_PACKET socket, serves its unix
#      control socket, and cpctl can talk to it;
#   4. a veth pair delivers exactly FRAMES raw UDP frames into the capturer.
#
# Exit status: 0 iff no check FAILED (SKIP is tolerated but recorded).
#
# Environment (all optional except ARTIFACT_URL):
#   ARTIFACT_URL      URL of cloud-probe-rs-<target>.tar.gz      (required)
#   ARTIFACT_SHA256   expected sha256 of the archive             (optional)
#   WORKDIR           scratch dir                    (default /root/cprs-smoke)
#   RESULT_FILE       where to write result.json    (default $WORKDIR/result.json)
#   CALLBACK_URL      POST the result JSON here                  (optional)
#   FRAMES            UDP frames to inject                    (default 2000)
#   BINARIES          space-separated list   (default the five release binaries)
#   SKIP_CAPTURE      1 = do not run the privileged capture check
# shellcheck disable=SC1091  # /etc/os-release is read from the live target
set -u

ARTIFACT_URL="${ARTIFACT_URL:?ARTIFACT_URL is required}"
ARTIFACT_SHA256="${ARTIFACT_SHA256:-}"
WORKDIR="${WORKDIR:-/root/cprs-smoke}"
RESULT_FILE="${RESULT_FILE:-$WORKDIR/result.json}"
CALLBACK_URL="${CALLBACK_URL:-}"
FRAMES="${FRAMES:-2000}"
BINARIES="${BINARIES:-cpworker cpctl cpdaemon dockerpid cripid}"
SKIP_CAPTURE="${SKIP_CAPTURE:-0}"

mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit 1

CHECKS_FILE="$WORKDIR/checks.tsv"
: > "$CHECKS_FILE"

# record <name> <PASS|FAIL|SKIP> <detail>
record() {
  # Collapse tabs/newlines so the TSV and the later JSON stay well-formed.
  local name="$1" status="$2" detail="${3:-}"
  detail="$(printf '%s' "$detail" | tr '\t\n' '  ' | cut -c1-400)"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$CHECKS_FILE"
  echo "[$status] $name: $detail"
}

# ---- emit result.json -------------------------------------------------
finalize() {
  local uname_m glibc os_pretty
  uname_m="$(uname -m 2>/dev/null || echo unknown)"
  glibc="$( (ldd --version 2>/dev/null || true) | head -n1 | tr -d '\n')"
  os_pretty="$( ( . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}" ) || echo unknown)"
  local failed skipped
  failed="$(awk -F'\t' '$2=="FAIL"' "$CHECKS_FILE" | wc -l | tr -d ' ')"
  skipped="$(awk -F'\t' '$2=="SKIP"' "$CHECKS_FILE" | wc -l | tr -d ' ')"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$CHECKS_FILE" "$RESULT_FILE" "$uname_m" "$glibc" "$os_pretty" <<'PY'
import json, sys
checks_file, out, arch, glibc, os_pretty = sys.argv[1:6]
checks = []
with open(checks_file) as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 3:
            checks.append({"name": parts[0], "status": parts[1], "detail": parts[2]})
failed = sum(1 for c in checks if c["status"] == "FAIL")
with open(out, "w") as fh:
    json.dump({"schema": "cprs-on-target-smoke-v1", "arch": arch,
               "glibc": glibc, "os": os_pretty, "ok": failed == 0,
               "failed": failed, "checks": checks}, fh, indent=2)
PY
  else
    # Fallback: a minimal, valid JSON (details omitted).
    {
      printf '{"schema":"cprs-on-target-smoke-v1","arch":"%s","glibc":"%s",' \
        "$uname_m" "$(printf '%s' "$glibc" | sed 's/"/\\\\"/g')"
      printf '"os":"%s","ok":%s,"failed":%s,"checks":[]}\n' \
        "$(printf '%s' "$os_pretty" | sed 's/"/\\\\"/g')" \
        "$([ "$failed" -eq 0 ] && echo true || echo false)" "$failed"
    } > "$RESULT_FILE"
  fi

  echo "----- result -----"
  cat "$RESULT_FILE" 2>/dev/null || true
  echo

  if [ -n "$CALLBACK_URL" ]; then
    if command -v curl >/dev/null 2>&1; then
      curl -fsS -m 20 -H 'Content-Type: application/json' \
        --data-binary "@$RESULT_FILE" "$CALLBACK_URL" >/dev/null 2>&1 \
        && echo "callback: posted to $CALLBACK_URL" \
        || echo "callback: POST to $CALLBACK_URL failed (result still at $RESULT_FILE)" >&2
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O /dev/null --header='Content-Type: application/json' \
        --post-file="$RESULT_FILE" "$CALLBACK_URL" 2>/dev/null \
        && echo "callback: posted to $CALLBACK_URL" \
        || echo "callback: POST to $CALLBACK_URL failed" >&2
    fi
  fi

  echo "failed=$failed skipped=$skipped"
  [ "$failed" -eq 0 ] && return 0 || return 1
}
# finalize's own status is the script's; the pre-trap status is preserved only
# to keep the failure loud when a check aborted before finalize could run.
trap 'rc=$?; trap - EXIT; finalize || rc=1; exit $rc' EXIT

# ---- 0. host identity -------------------------------------------------------
record host "PASS" "$(uname -a 2>/dev/null || echo 'uname failed')"

# ---- 1. fetch + verify ------------------------------------------------------
ARCHIVE="$WORKDIR/$(basename "$ARTIFACT_URL")"
if command -v curl >/dev/null 2>&1; then
  GET="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  GET="wget -q -O"
else
  record fetch FAIL "neither curl nor wget is installed"
  GET=""
fi
if [ -n "$GET" ]; then
  if $GET "$ARCHIVE" "$ARTIFACT_URL"; then
    record fetch PASS "downloaded $ARTIFACT_URL"
  else
    record fetch FAIL "download failed: $ARTIFACT_URL"
  fi
fi

if [ -s "$ARCHIVE" ]; then
  if [ -n "$ARTIFACT_SHA256" ]; then
    have="$(sha256sum "$ARCHIVE" 2>/dev/null | awk '{print $1}')"
    if [ "$have" = "$ARTIFACT_SHA256" ]; then
      record sha256 PASS "$have"
    else
      record sha256 FAIL "expected $ARTIFACT_SHA256 got $have"
    fi
  else
    record sha256 SKIP "no ARTIFACT_SHA256 provided"
  fi
else
  record sha256 FAIL "archive missing"
fi

# ---- 2. extract -------------------------------------------------------------
BIN=""
if [ -s "$ARCHIVE" ]; then
  rm -rf "$WORKDIR/opt"
  mkdir -p "$WORKDIR/opt"
  if tar -xzf "$ARCHIVE" -C "$WORKDIR/opt" 2>/dev/null; then
    BIN="$(dirname "$(find "$WORKDIR/opt" -type f -name cpworker -perm -u+x 2>/dev/null | head -n1)")"
  fi
  if [ -n "$BIN" ] && [ -d "$BIN" ]; then
    record extract PASS "binaries in $BIN"
  else
    record extract FAIL "no cpworker binary under the extracted archive"
    BIN=""
  fi
else
  record extract FAIL "archive missing"
fi

# ---- 3. every binary loads and answers on this glibc ------------------------
# cpworker/cpctl/cpdaemon are clap programs with --version.  dockerpid/cripid are
# bare positional-arg helpers with no --version, so for them (and as a fallback)
# the contract is "the dynamic loader resolves every symbol": an ABI mismatch
# fails *before* main() with exit 127 and 'GLIBC_x.y not found'.
loader_broken() {
  printf '%s' "$1" | grep -Eq 'GLIBC_[0-9.]+ not found|error while loading shared libraries|cannot execute|No such file'
}
if [ -n "$BIN" ]; then
  for b in $BINARIES; do
    if [ ! -x "$BIN/$b" ]; then
      record "bin:$b" FAIL "missing or not executable"
      continue
    fi
    if out="$(timeout 10 "$BIN/$b" --version 2>&1)" && [ -n "$out" ]; then
      record "bin:$b" PASS "$(printf '%s' "$out" | head -n1)"
      continue
    fi
    # No --version (or it failed): probe both the loader and a real run.
    lout="$(ldd "$BIN/$b" 2>&1 || true)"
    if loader_broken "$lout"; then
      record "bin:$b" FAIL "unresolved shared library: $(printf '%s' "$lout" | tr '\n' ' ')"
      continue
    fi
    rout="$(timeout 10 "$BIN/$b" __cprs_probe__ 2>&1)"; rc=$?
    if loader_broken "$rout" || [ "$rc" -eq 127 ]; then
      record "bin:$b" FAIL "loader/ABI failure: $(printf '%s' "$rout" | tr '\n' ' ')"
    else
      record "bin:$b" PASS "loads (exit $rc, no loader error)"
    fi
  done
fi

# ---- 4. AF_PACKET capture through a veth pair -------------------------------
if [ "$SKIP_CAPTURE" = "1" ]; then
  record capture SKIP "SKIP_CAPTURE=1"
elif [ "$(id -u)" != "0" ]; then
  record capture SKIP "not root"
elif [ -z "$BIN" ]; then
  record capture SKIP "no binaries extracted"
elif ! command -v ip >/dev/null 2>&1; then
  record capture SKIP "iproute2 not installed"
elif ! command -v python3 >/dev/null 2>&1; then
  record capture SKIP "python3 not installed (cannot inject frames)"
else
  V0=cprs-v0; V1=cprs-v1
  SOCK="$WORKDIR/cpworker.sock"
  SOCKET_PATH="$SOCK"
  cat > "$WORKDIR/cpworker.json" <<JSON
{
  "log_level": "info",
  "control": { "type": "unix", "unix": { "path": "$SOCKET_PATH" } },
  "tasks": [
    {
      "req_pattern": { "type": "auto" },
      "capturer": {
        "type": "libpcap",
        "libpcap": { "interface": "$V0", "snaplen": 2048,
                     "buffer_size_mb": 32, "bpf": "udp", "timeout_ms": 1000 }
      },
      "outputs": [ { "type": "null", "rate_limit_mbps": 1000 } ]
    }
  ]
}
JSON

  # Tear down any leftover pair, then create one.
  ip link del "$V0" 2>/dev/null
  ip link add "$V0" type veth peer name "$V1" 2>/dev/null
  ip link set "$V0" up 2>/dev/null
  ip link set "$V1" up 2>/dev/null
  sleep 1

  "$BIN/cpworker" -c "$WORKDIR/cpworker.json" > "$WORKDIR/cpworker.log" 2>&1 &
  CPW_PID=$!

  # Wait (up to 15 s) for the control socket to appear and answer.
  ready=0
  for _ in $(seq 1 30); do
    if [ -S "$SOCK" ] && "$BIN/cpctl" -u "$SOCK" -W 2s info >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 0.5
  done

  if [ "$ready" != "1" ]; then
    record capture FAIL "cpworker did not serve its control socket (log: $(tail -n2 "$WORKDIR/cpworker.log" 2>/dev/null))"
  else
    # cpctl info answered -> RPC path works.
    record "capture:rpc" PASS "cpctl info/ping over unix socket"

    python3 - "$V1" "$V0" "$FRAMES" <<'PY' || true
import socket, struct, sys
src_if, dst_if, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
def mac(ifname):
    with open(f"/sys/class/net/{ifname}/address") as fh:
        return bytes(int(x, 16) for x in fh.read().strip().split(":"))
dst = mac(dst_if); src = mac(src_if)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((src_if, 0))
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8, 1, 0, 64, 17, 0,
                 b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
udp = struct.pack("!HHHH", 1234, 4321, 8, 0)
payload = b"cprs" * 16
frame = dst + src + b"\x08\x00" + ip + udp + payload
for _ in range(n):
    s.send(frame)
s.close()
PY
    sleep 2
    "$BIN/cpctl" -u "$SOCK" -W 5s -f jsonl stats -n 1 > "$WORKDIR/stats.jsonl" 2>/dev/null
    cap="$(python3 - "$WORKDIR/stats.jsonl" <<'PY' 2>/dev/null || echo -1
import json, sys
try:
    rec = json.loads(open(sys.argv[1]).readline())
    c = rec["counters"]["cap_packets"]
    print(c["packets"] + c.get("peta", 0) * 1000**5)
except Exception:
    print(-1)
PY
)"
    if [ "$cap" -ge "$FRAMES" ] 2>/dev/null; then
      record "capture:fidelity" PASS "captured $cap >= injected $FRAMES UDP frames"
    else
      record "capture:fidelity" FAIL "captured ${cap:-?} < injected $FRAMES"
    fi
  fi

  kill "$CPW_PID" 2>/dev/null; wait "$CPW_PID" 2>/dev/null
  ip link del "$V0" 2>/dev/null
fi

record summary "PASS" "arch=$(uname -m) os=$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}")"
exit 0
