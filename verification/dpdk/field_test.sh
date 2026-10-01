#!/usr/bin/env bash
# Field test: validate the cpworker `dpdk` (pdump) capturer against a real DPDK
# port (cloud-probe-rs-1eu).
#
# It builds a minimal DPDK primary (./primary.c) and the cpworker secondary,
# starts the primary on PORT_BDF, lets the secondary enable pdump, optionally
# injects real frames at the port's MAC and asserts the captured count, then
# cleans up (including removing any SR-IOV VF it created).
#
# The DPDK the cpworker links and the DPDK the primary is built against MUST be
# the same (EAL rejects a primary/secondary version mismatch).
#
# Environment:
#   PORT_BDF        PCI BDF of the DPDK port, e.g. 0000:b8:00.1 (or set SRIOV_PF)
#   SRIOV_PF        kernel netdev of a PF to create one VF on, e.g. ens8np0.
#                   The script derives PORT_BDF/TARGET_MAC from that VF and
#                   removes it on exit. Use this to avoid disturbing PF traffic.
#   TRAFFIC_IFACE   kernel netdev to send frames from (e.g. the PF). When unset
#                   the script only validates EAL/port/pdump-enable, no frames.
#   TARGET_MAC      destination MAC for the injected frames (default: derived
#                   from SRIOV_PF's VF; required with TRAFFIC_IFACE otherwise)
#   FRAMES          frames to inject and expect (default 2000)
#   WARMUP          uncounted warm-up frames sent first to absorb pdump's
#                   fixed startup loss (default 256)
#   RING_SIZE       pdump ring size in descriptors (default 2048)
#   MIN_PCT         minimum capture ratio to pass, percent (default 95). pdump
#                   is best-effort: `rte_pdump_enable_bpf` drops a small fixed
#                   prefix at startup (the WARMUP batch absorbs most of it) and
#                   a little under sustained burst; 0 frames still fails.
#   EAL_EXTRA       extra EAL args for the primary, e.g. "--socket-mem 512,0"
#   HUGE_PAGES      hugepage count to request when 0 currently (default 1024)
#   DPDK_PKG_CONFIG directory holding libdpdk.pc, prepended to PKG_CONFIG_PATH
#   WORKDIR         scratch/build dir (default /tmp/cprs-dpdk-field)
#
# Usage:
#   sudo SRIOV_PF=ens8np0 TRAFFIC_IFACE=ens8np0 \
#        DPDK_PKG_CONFIG=$HOME/dpdk-inst/lib/x86_64-linux-gnu/pkgconfig \
#        verification/dpdk/field_test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PORT_BDF="${PORT_BDF:-}"
SRIOV_PF="${SRIOV_PF:-}"
TRAFFIC_IFACE="${TRAFFIC_IFACE:-}"
TARGET_MAC="${TARGET_MAC:-}"
FRAMES="${FRAMES:-2000}"
WARMUP="${WARMUP:-256}"
RING_SIZE="${RING_SIZE:-2048}"
MIN_PCT="${MIN_PCT:-95}"
HUGE_PAGES="${HUGE_PAGES:-1024}"
DPDK_PKG_CONFIG="${DPDK_PKG_CONFIG:-}"
WORKDIR="${WORKDIR:-/tmp/cprs-dpdk-field}"

PRIMARY_PID=""
SECONDARY_PID=""
VF_CREATED=0
VF_NETDEV=""

fail() { echo "FAIL: $*" >&2; exit 1; }
log()  { echo "[field] $*"; }

cleanup() {
  set +e
  [ -n "$SECONDARY_PID" ] && kill -9 "$SECONDARY_PID" 2>/dev/null
  [ -n "$PRIMARY_PID" ] && kill -9 "$PRIMARY_PID" 2>/dev/null
  if [ "$VF_CREATED" = 1 ] && [ -n "$SRIOV_PF" ]; then
    echo 0 > "/sys/class/net/$SRIOV_PF/device/sriov_numvfs" 2>/dev/null
    log "removed SR-IOV VF on $SRIOV_PF"
  fi
  rm -rf /var/run/dpdk/rte 2>/dev/null
}
trap cleanup EXIT

# ---- preconditions --------------------------------------------------------
[ "$(id -u)" = 0 ] || fail "run as root (sudo) — hugepages, DPDK and pdump need it"
for t in cc cargo python3 pkg-config; do
  command -v "$t" >/dev/null || fail "missing tool: $t"
done
[ -n "$DPDK_PKG_CONFIG" ] && export PKG_CONFIG_PATH="$DPDK_PKG_CONFIG:${PKG_CONFIG_PATH:-}"
pkg-config --exists libdpdk || fail "pkg-config cannot find libdpdk (set DPDK_PKG_CONFIG)"
DPDK_VER="$(pkg-config --modversion libdpdk)"
log "DPDK $DPDK_VER"

mkdir -p "$WORKDIR"

# ---- SR-IOV VF (optional) -------------------------------------------------
if [ -n "$SRIOV_PF" ]; then
  [ -e "/sys/class/net/$SRIOV_PF" ] || fail "SRIOV_PF $SRIOV_PF not found"
  log "creating 1 VF on $SRIOV_PF"
  echo 1 > "/sys/class/net/$SRIOV_PF/device/sriov_numvfs"
  VF_CREATED=1
  # The new VF netdev is the one whose device dir is under the PF's.
  sleep 3
  VF_NETDEV=""
  for d in /sys/class/net/*; do
    n="${d##*/}"
    if [[ "$n" =~ ^(ens|enp|eth).*v[0-9]+$ ]]; then VF_NETDEV="$n"; break; fi
  done
  [ -n "$VF_NETDEV" ] || fail "could not find the created VF netdev"
  [ -n "$PORT_BDF" ] || PORT_BDF="$(basename "$(readlink -f "/sys/class/net/$VF_NETDEV/device")")"
  [ -n "$TARGET_MAC" ] || TARGET_MAC="$(cat "/sys/class/net/$VF_NETDEV/address")"
  log "VF $VF_NETDEV  bdf=$PORT_BDF  mac=$TARGET_MAC"
fi

[ -n "$PORT_BDF" ] || fail "set PORT_BDF (or SRIOV_PF)"
if [ -n "$TRAFFIC_IFACE" ] && [ -z "$TARGET_MAC" ]; then
  fail "TRAFFIC_IFACE set but TARGET_MAC could not be derived (set TARGET_MAC)"
fi

# ---- hugepages ------------------------------------------------------------
# Reserve on the system-wide counter: EAL sizes its memory from the system
# hugepage pool, and with a device on one node it may also look at the other, so
# a single node's counter is not enough. Pass `EAL_EXTRA="--socket-mem M,0"` to
# pin EAL to one socket on memory-constrained hosts.
HP_FILE=/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
if [ "$(cat "$HP_FILE")" -lt "$HUGE_PAGES" ]; then
  log "reserving $HUGE_PAGES x 2MiB hugepages"
  echo "$HUGE_PAGES" > "$HP_FILE" || fail "could not write $HP_FILE"
fi

# ---- build ----------------------------------------------------------------
log "building primary and cpworker (--features dpdk)"
# shellcheck disable=SC2046  # pkg-config output must word-split into flags
cc -O2 "$HERE/primary.c" -o "$WORKDIR/dpdk_primary" $(pkg-config --cflags --libs libdpdk) \
  || fail "primary build failed"

export CARGO_TARGET_DIR="$WORKDIR/target"
export PATH="$HOME/.cargo/bin:$PATH"
( cd "$REPO_ROOT" && cargo build -p cpworker --features dpdk ) || fail "cpworker build failed"
CPWORKER="$CARGO_TARGET_DIR/debug/cpworker"
[ -x "$CPWORKER" ] || fail "cpworker binary not found at $CPWORKER"

# The cpworker only links DPDK if it was built against the same libdpdk.
CPWORKER_LIBDIR="$(pkg-config --variable=libdir libdpdk)"

CONFIG="$WORKDIR/task.json"
OUT="$WORKDIR/out.pcap"
rm -f "$OUT"
cat > "$CONFIG" <<JSON
{
  "tasks": [
    {
      "capturer": {"type":"dpdk_pdump","dpdk_pdump":{"interface":"$PORT_BDF","snaplen":2048,"bpf":"","ring_size":$RING_SIZE}},
      "outputs": [ {"type":"file","file":{"name":"$OUT"}} ]
    }
  ]
}
JSON

PRIMARY_LOG="$WORKDIR/primary.log"
SECONDARY_LOG="$WORKDIR/secondary.log"
: > "$PRIMARY_LOG"; : > "$SECONDARY_LOG"

# ---- run primary ----------------------------------------------------------
log "starting primary on $PORT_BDF"
LD_LIBRARY_PATH="$CPWORKER_LIBDIR:${LD_LIBRARY_PATH:-}" \
  "$WORKDIR/dpdk_primary" -l 4-7 -a "$PORT_BDF" ${EAL_EXTRA:-} >"$PRIMARY_LOG" 2>&1 &
PRIMARY_PID=$!

for _ in $(seq 1 20); do
  grep -q "pdump_init=ok" "$PRIMARY_LOG" && break
  kill -0 "$PRIMARY_PID" 2>/dev/null || fail "primary exited early: $(tail -3 "$PRIMARY_LOG")"
  sleep 1
done
grep -q "pdump_init=ok" "$PRIMARY_LOG" || fail "primary never enabled pdump: $(tail -5 "$PRIMARY_LOG")"
log "$(grep dpdk_primary: "$PRIMARY_LOG" | head -1)"

# ---- run secondary --------------------------------------------------------
log "starting cpworker pdump secondary"
LD_LIBRARY_PATH="$CPWORKER_LIBDIR:${LD_LIBRARY_PATH:-}" \
  "$CPWORKER" -c "$CONFIG" >"$SECONDARY_LOG" 2>&1 &
SECONDARY_PID=$!

for _ in $(seq 1 20); do
  grep -q "create task-0 success" "$SECONDARY_LOG" && break
  if grep -q "error" "$SECONDARY_LOG"; then
    fail "secondary failed to enable pdump: $(grep -i error "$SECONDARY_LOG" | tail -2)"
  fi
  kill -0 "$SECONDARY_PID" 2>/dev/null || fail "secondary exited early"
  sleep 1
done
grep -q "create task-0 success" "$SECONDARY_LOG" \
  || fail "secondary never created the task: $(tail -5 "$SECONDARY_LOG")"
log "secondary enabled pdump on $PORT_BDF"

# Warm-up: give the primary's rx callback a beat to start delivering before the
# counted frames (without this a small, fixed prefix can be missed).
sleep 2

# ---- traffic (optional) ---------------------------------------------------
if [ -n "$TRAFFIC_IFACE" ]; then
  log "injecting $FRAMES frames (+$WARMUP warm-up) via $TRAFFIC_IFACE -> $TARGET_MAC"
  python3 - "$TRAFFIC_IFACE" "$TARGET_MAC" "$FRAMES" "$WARMUP" <<'PY'
import socket, struct, sys, time
iface = sys.argv[1]
mac = bytes.fromhex(sys.argv[2].replace(":", ""))
n, warm = int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))

def frame(marker):
    return struct.pack("!6s6sH", mac, mac, 0x0800) + marker.ljust(60, b".")

# Warm-up absorbs pdump's fixed startup loss so the counted batch is exact.
for _ in range(warm):
    s.send(frame(b"CPRS-WARM"))
time.sleep(1)
for i in range(n):
    s.send(frame(b"CPRS-COUNT"))
    if (i & 0xFF) == 0xFF:
        time.sleep(0.002)
print(f"sent {n} (+{warm} warm-up)")
PY
  sleep 3   # let the ring drain into the output
else
  log "TRAFFIC_IFACE unset — validating pdump plumbing only (no frames)"
fi

sleep 2

# ---- verify ---------------------------------------------------------------
if [ ! -f "$OUT" ]; then
  fail "no output pcap written"
fi
CAPTURED="$(python3 - "$OUT" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
off, n = 24, 0
while off + 16 <= len(d):
    _, _, cl, _ = struct.unpack("<IIII", d[off:off + 16])
    body = d[off + 16:off + 16 + cl]
    off += 16 + cl
    if b"CPRS-COUNT" in body:
        n += 1
print(n)
PY
)"

if [ -n "$TRAFFIC_IFACE" ]; then
  MIN=$(( FRAMES * MIN_PCT / 100 ))
  if [ "$CAPTURED" -ge "$MIN" ]; then
    log "PASS: captured $CAPTURED/$FRAMES frames ($(( CAPTURED * 100 / FRAMES ))%) on $PORT_BDF (DPDK $DPDK_VER)"
  else
    fail "captured $CAPTURED/$FRAMES frames ($(( CAPTURED * 100 / FRAMES ))%), below MIN_PCT=$MIN_PCT"
  fi
else
  log "PASS: pdump enabled and secondary ran (captured $CAPTURED frames; no traffic injected)"
fi
