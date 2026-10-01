#!/bin/bash
# usage: lj_tx.sh <lcores> <ncores> <duration_s> <dstmac>
CORES="$1"; NC="$2"; DUR="$3"; DST="$4"
export LD_LIBRARY_PATH=$HOME/dpdk-inst/lib/x86_64-linux-gnu
sudo -n pkill -9 dpdk-testpmd 2>/dev/null
sudo -n rm -rf /var/run/dpdk/rte
sudo -n rm -f /tmp/ljbench.log
sudo -n setsid bash -c "{ sleep 1; echo start; sleep $DUR; echo stop; } | env LD_LIBRARY_PATH=$LD_LIBRARY_PATH $HOME/dpdk-inst/bin/dpdk-testpmd --no-huge -m 4096 -l $CORES -a 0000:46:00.1 -- -i --forward-mode=txonly --txpkts=64 --eth-peer=0,$DST --tx-ip=10.2.0.12,10.2.0.11 --tx-udp=49000,49001 --rxq=$NC --txq=$NC --nb-cores=$NC --total-num-mbufs=131072 --txonly-multi-flow >/tmp/ljbench.log 2>&1" >/dev/null 2>&1 < /dev/null &
sleep 3
grep -E "txonly packet forwarding - ports|No cores|error" /tmp/ljbench.log | head -2
echo "launched"
