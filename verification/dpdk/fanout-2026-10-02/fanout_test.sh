#!/bin/bash
# fanout_test.sh - is the single AF_PACKET TPACKET_V3 socket ceiling a ring-lock
# limit that per-socket PACKET_FANOUT can lift? (cloud-probe-rs-f7x)
#
# Topology: laojun testpmd txonly (64B, line rate, --txonly-multi-flow) ->
# yinjiao VF ens8v0, captured by N fanout sockets (verification/dpdk/fanout_capture.c).
#
# Modes: `none` opens N sockets WITHOUT a fanout group, so every socket sees every
# packet - the control for "more sockets is not the same as more capacity".
# NIC counters are sampled around each trial so a capped capture can be told apart
# from NIC out-of-buffer drops.
#
# Serialized against every other physical test via /tmp/legacy-probe/physical.lock.
set -u
DST_MAC=1a:ca:0a:26:a8:8c
SECONDS_PER_TRIAL=14
# testpmd needs (lcores - 1) forward cores: `-l 46-49` with --nb-cores=4 aborts
# with "nb-cores should be > 0 and <= 3" and then generates nothing at all.
GEN_CORES=46-53
GEN_NCORES=7
BIN=/tmp/fanout_capture
OUT=${OUT:-/tmp/fanout_test_out}

# The capture process runs as root on yinjiao, so the log directory has to exist there.
ssh -o BatchMode=yes yinjiao "sudo -n mkdir -p $OUT; sudo -n chmod 777 $OUT"
mkdir -p "$OUT"

exec 9>/tmp/legacy-probe/physical.lock
flock -w 3600 9 || { echo "physical lock busy"; exit 1; }

yj() { ssh -o BatchMode=yes yinjiao "$@"; }
lj() { ssh -o BatchMode=yes laojun "$@"; }
# sysfs is the one counter that needs no privileges and no key-name guessing
# (`ip -s link` prints a header row before the values, so field indexing lies).
rc() { yj "cat /sys/class/net/ens8v0/statistics/rx_packets 2>/dev/null || echo 0"; }
rd() { yj "cat /sys/class/net/ens8v0/statistics/rx_dropped 2>/dev/null || echo 0"; }
oob() { yj "sudo -n ethtool -S ens8v0 2>/dev/null | awk '/rx_out_of_buffer/{s+=\$2} END{print s+0}'"; }

cleanup() {
  yj "sudo -n pkill -x fanout_capture 2>/dev/null; true" >/dev/null 2>&1
  lj "sudo -n pkill -9 dpdk-testpmd 2>/dev/null; true" >/dev/null 2>&1
  yj "sudo -n sh -c 'echo 0 > /sys/class/net/ens8np0/device/sriov_numvfs'; sudo -n ethtool -A ens8np0 autoneg off rx on tx on; sudo -n rm -rf /var/run/dpdk/rte" >/dev/null 2>&1
  lj "sudo -n sh -c 'echo 0 > /sys/class/net/ens72np0/device/sriov_numvfs'; sudo -n ethtool -A ens72np0 autoneg off rx on tx on; sudo -n rm -rf /var/run/dpdk/rte" >/dev/null 2>&1
  echo "[restore] VFs removed, PAUSE restored (autoneg off, rx on, tx on)"
}
trap cleanup EXIT

echo "=== setup VFs ==="
yj "sudo -n sh -c 'echo 1 > /sys/class/net/ens8np0/device/sriov_numvfs'; sleep 2; sudo -n sysctl -q -w net.ipv6.conf.ens8v0.disable_ipv6=1; sudo -n ip link set ens8v0 address $DST_MAC; sudo -n ip link set ens8v0 up; sudo -n ip link set ens8np0 vf 0 max_tx_rate 0; sudo -n ethtool -A ens8np0 autoneg off rx off tx off"
lj "sudo -n sh -c 'echo 1 > /sys/class/net/ens72np0/device/sriov_numvfs'; sleep 2; sudo -n sysctl -q -w net.ipv6.conf.ens72v0.disable_ipv6=1; sudo -n ip link set ens72v0 address 12:e9:4b:91:bd:e0; sudo -n ip link set ens72v0 up; sudo -n ip link set ens72np0 vf 0 max_tx_rate 0; sudo -n ethtool -A ens72np0 autoneg off rx off tx off"

printf '\n%-6s %-8s %-10s %-12s %-12s %s\n' NSOCKS MODE CAP_Mpps RX_PKTS NIC_OOB NOTE
for spec in "1 none" "2 none" "1 lb" "2 lb" "4 lb" "8 lb" "4 hash" "4 cpu"; do
  set -- $spec; N=$1; MODE=$2
  yj "sudo -n pkill -x fanout_capture 2>/dev/null; true" >/dev/null 2>&1
  before=$(rc); before_oob=$(oob)
  yj "sudo -n setsid sh -c 'nohup $BIN ens8v0 $N $MODE $SECONDS_PER_TRIAL > $OUT/n${N}_${MODE}.log 2>&1 < /dev/null &'"
  # wait for READY before generating, so the window is real traffic
  ready=0
  for _ in $(seq 1 40); do
    if yj "sudo -n grep -q FANOUT_READY $OUT/n${N}_${MODE}.log 2>/dev/null"; then ready=1; break; fi
    sleep 0.5
  done
  if [ "$ready" != 1 ]; then
    printf '%-6s %-8s %-10s %-12s %-12s %s\n' "$N" "$MODE" "NO_READY" "-" "-" "capture did not start"
    continue
  fi
  lj "sudo -n pkill -9 dpdk-testpmd 2>/dev/null; sudo -n rm -rf /var/run/dpdk/rte; timeout $((SECONDS_PER_TRIAL+4)) bash /tmp/lj_tx.sh $GEN_CORES $GEN_NCORES $SECONDS_PER_TRIAL $DST_MAC" >/dev/null 2>&1
  sleep $((SECONDS_PER_TRIAL+3))
  after=$(rc); after_oob=$(oob)
  mpps=$(yj "sudo -n grep -oE 'FANOUT_DONE.*mpps=[0-9.]+' $OUT/n${N}_${MODE}.log | grep -oE '[0-9.]+$'")
  printf '%-6s %-8s %-10s %-12s %-12s %s\n' "$N" "$MODE" "${mpps:-ERR}" "$(( after - before ))" "$(( after_oob - before_oob ))" "-"
  yj "sudo -n cat $OUT/n${N}_${MODE}.log | grep -E 'FANOUT_SOCK|FANOUT_DONE'" | sed 's/^/       /'
done
echo
echo "raw logs: $OUT/ (on yinjiao, root-owned)"
