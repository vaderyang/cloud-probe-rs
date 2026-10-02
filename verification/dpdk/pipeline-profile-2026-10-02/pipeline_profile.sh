#!/bin/bash
# pipeline_profile.sh - where does the pipeline execution model spend the one core?
#
# cloud-probe-rs-2kx. The 1 CPU / 512 MiB capacity record shows the RTC model
# reaching ~2.4 Mpps on AF_PACKET while the pipeline model passes only ~0.8 Mpps
# before losing packets. This runs both models at the same offered rates under the
# same worker-only cgroup and profiles them with `perf`, so the difference can be
# attributed instead of guessed. (The AF_PACKET kernel receive path is the ceiling
# on this port - see fanout-2026-10-02/ - so this measures the extra cost the
# pipeline adds on top of a path RTC already saturates.)
#
# Serialized against every other physical test via /tmp/legacy-probe/physical.lock.
set -u
DST_MAC=1a:ca:0a:26:a8:8c
CG=/sys/fs/cgroup/cprs-p2kx
SOCK=/tmp/p2kx.sock
RDIR=/tmp/p2kx-remote   # perf output must live on yinjiao, not here
ROOT=/home/vader/cprs-bench
LD=/home/vader/dpdk-inst/lib/x86_64-linux-gnu
GEN_SECONDS=14
OUT=${OUT:-/tmp/p2kx}
RATES=${RATES:-"0.8 1.6"}

exec 9>/tmp/legacy-probe/physical.lock
flock -w 3600 9 || { echo "physical lock busy"; exit 1; }
mkdir -p "$OUT"

yj() { ssh -o BatchMode=yes yinjiao "$@"; }
lj() { ssh -o BatchMode=yes laojun "$@"; }
rxp() { yj "cat /sys/class/net/ens8v0/statistics/rx_packets 2>/dev/null || echo 0"; }

cleanup() {
  yj "sudo -n pkill -x cpworker 2>/dev/null; sudo -n pkill -x perf 2>/dev/null; true" >/dev/null 2>&1
  lj "sudo -n pkill -TERM -x capacity_tx 2>/dev/null; true" >/dev/null 2>&1
  yj "sudo -n sh -c 'echo 0 > /sys/class/net/ens8np0/device/sriov_numvfs'; sudo -n ethtool -A ens8np0 autoneg off rx on tx on" >/dev/null 2>&1
  lj "sudo -n sh -c 'echo 0 > /sys/class/net/ens72np0/device/sriov_numvfs'; sudo -n ethtool -A ens72np0 autoneg off rx on tx on" >/dev/null 2>&1
  echo "[restore] VFs removed, PAUSE restored"
}
trap cleanup EXIT

echo "=== setup ==="
yj "sudo -n sh -c 'echo 1 > /sys/class/net/ens8np0/device/sriov_numvfs'; sleep 2; sudo -n ip link set ens8v0 address $DST_MAC; sudo -n ip link set ens8v0 up; sudo -n ip link set ens8np0 vf 0 max_tx_rate 0; sudo -n ethtool -A ens8np0 autoneg off rx off tx off"
lj "sudo -n sh -c 'echo 1 > /sys/class/net/ens72np0/device/sriov_numvfs'; sleep 2; sudo -n ip link set ens72v0 address 12:e9:4b:91:bd:e0; sudo -n ip link set ens72v0 up; sudo -n ip link set ens72np0 vf 0 max_tx_rate 0; sudo -n ethtool -A ens72np0 autoneg off rx off tx off"
# paced generator (same tool the capacity record used)
scp -q -o BatchMode=yes "$(dirname "$0")/capacity_tx.c" laojun:/tmp/capacity_tx.c
lj "export PKG_CONFIG_PATH=/home/vader/dpdk-inst/lib/x86_64-linux-gnu/pkgconfig; cc -O3 -w /tmp/capacity_tx.c -o /tmp/capacity_tx \$(pkg-config --cflags --libs libdpdk)" || { echo "capacity_tx build failed"; exit 1; }
yj "sudo -n mkdir -p $RDIR; sudo -n chmod 777 $RDIR"
yj "sudo -n mkdir -p $CG; sudo -n sh -c \"echo '100000 100000' > $CG/cpu.max; echo 536870912 > $CG/memory.max; echo 0 > $CG/memory.swap.max; echo 536870912 > $CG/hugetlb.2MB.max\""

printf '\n%-10s %-6s %-9s %-9s %-9s %-10s %s\n' MODEL OFFER CAP_Mpps CPU_CORES WORKER_DROP RX_PKTS PERF_TOP
for model in rtc pipeline; do
  for rate in $RATES; do
    yj "sudo -n pkill -x cpworker 2>/dev/null; true" >/dev/null 2>&1; sleep 1
    # config: AF_PACKET V3 capturer on the VF, null output, one task
    if [ "$model" = pipeline ]; then
      cfg="{\"execution_model\":\"pipeline\",\"pipeline\":{\"buffer_size_mb\":504},"
    else
      cfg="{\"execution_model\":\"rtc\","
    fi
    cfg+="\"cpu_affinity\":\"48-49\",\"control\":{\"type\":\"unix\",\"unix\":{\"path\":\"$SOCK\"}},\"tasks\":[{\"capturer\":{\"type\":\"libpcap\",\"libpcap\":{\"interface\":\"ens8v0\",\"snaplen\":2048,\"buffer_size_mb\":8,\"bpf\":\"\",\"timeout_ms\":1000}},\"outputs\":[{\"type\":\"null\",\"rate_limit_mbps\":0}]}]}"
    yj "cat >/tmp/p2kx.json <<'JSON'
$cfg
JSON"
    yj "sudo -n setsid nohup bash -c 'echo \$\$ > $CG/cgroup.procs; exec taskset -c 48-49 env LD_LIBRARY_PATH=$LD $ROOT/target/release/cpworker -c /tmp/p2kx.json' >/tmp/p2kx-worker.log 2>&1 </dev/null &"
    ok=0
    for _ in $(seq 1 20); do
      yj "sudo -n grep -q 'create task-0 success' /tmp/p2kx-worker.log" && { ok=1; break; }; sleep 0.5
    done
    if [ "$ok" != 1 ]; then printf '%-10s %-6s %s\n' "$model" "$rate" "START_FAILED"; yj "sudo -n tail -3 /tmp/p2kx-worker.log"; continue; fi
    pid=$(yj "pgrep -x cpworker | head -1")
    cpu0=$(yj "awk '/usage_usec/{print \$2}' $CG/cpu.stat")
    rx0=$(rxp)
    yj "sudo -n perf record -F 499 -g -p $pid -o $RDIR/perf_${model}_${rate}.data >/dev/null 2>&1 </dev/null &"
    sleep 2
    # mlx5 PMD needs root: without sudo the PMD fails with "Failed to load driver mlx5_eth".
    lj "sudo -n pkill -TERM -x capacity_tx 2>/dev/null; sudo -n sh -c \"env LD_LIBRARY_PATH=$LD CAP_TX_MPPS=$rate CAP_TX_SECONDS=$GEN_SECONDS CAP_TX_QUEUES=4 timeout $((GEN_SECONDS+8)) /tmp/capacity_tx --no-huge -m 512 -l 8-12 --log-level notice -a 0000:46:00.1\"" >"$OUT/gen_${model}_${rate}.log" 2>&1
    sleep 4
    yj "sudo -n $ROOT/target/release/cpctl stats -u $SOCK -f jsonl -n 2 -i 1sec" > "$OUT/stats_${model}_${rate}.jsonl" 2>&1
    stats=$(tail -1 "$OUT/stats_${model}_${rate}.jsonl")
    yj "sudo -n pkill -INT -x perf 2>/dev/null; true" >/dev/null 2>&1; sleep 2
    cpu1=$(yj "awk '/usage_usec/{print \$2}' $CG/cpu.stat")
    rx1=$(rxp)
    cap=$(echo "$stats" | python3 -c "import json,sys
try:
 d=json.loads(sys.stdin.read() or '{}')
 except Exception: d={}
 def g(o,*ks):
  for k in ks:
   if isinstance(o,dict) and k in o: o=o[k]
   else: return ''
  return o
 print(g(d,'task_0','capture','packets_per_sec') or d.get('capture_packets_per_sec',''))" 2>/dev/null)
    drop=$(echo "$stats" | python3 -c "import json,sys
try: d=json.loads(sys.stdin.read() or '{}')
except Exception: d={}
print(d.get('task_0',{}).get('capture',{}).get('drop_packets',''))" 2>/dev/null)
    cores=$(awk -v a="$cpu0" -v b="$cpu1" -v s="$(awk -v r=$rate 'BEGIN{print 1}')" 'BEGIN{d=b-a; printf "%.2f", d/1000000/(14+6)}')
    top=$(yj "sudo -n perf report -i $RDIR/perf_${model}_${rate}.data --stdio -g none --percent-limit 2 2>/dev/null | awk '\$1 ~ /%/ {print \$3}' | head -4 | tr '\n' ','" )
    printf '%-10s %-6s %-9s %-9s %-9s %-10s %s\n' "$model" "$rate" "${cap:-?}" "${cores:-?}" "${drop:-?}" "$((rx1-rx0))" "${top:-no-perf}"
    yj "sudo -n pkill -x cpworker 2>/dev/null; true" >/dev/null 2>&1
  done
done
echo
echo "perf data + logs: $OUT/ (on yinjiao)"
