# DPDK pdump field test (`cloud-probe-rs-1eu`)

Reproduces the real-NIC validation of the feature-gated DPDK `pdump` capturer:
a minimal DPDK **primary** (`primary.c`) plus the cpworker **secondary** (the
actual capturer), on a real port. It is the field half of the DPDK work whose
pure layer is unit-tested in `crates/cpworker/src/capturer/dpdk_pdump.rs`.

## Why a real port is needed

The capturer is a DPDK *secondary*: it creates the shared ring/mempool, asks the
primary's `mp_pdump` server to mirror a port, and drains the ring. Two DPDK
properties decide whether it can run:

* The port's PMD **must support secondary processes**. The Nebulamatrix `nbl`
  PMD (the product's own NIC) does **not** — `nbl_pci_probe` prints
  `Secondary process is not supported.` — so `pdump` is impossible on `nbl`.
  Multi-process PMDs such as `mlx5`, `ixgbe` and `i40e` work.
* On DPDK **≥ 25.11** the enable handshake is two-way
  (`pdump_request_to_secondary`), so the secondary must call
  `rte_pdump_init()`; the capturer does (safe no-op on 21.11–24.11). The primary
  built here calls it too.

## Building DPDK

The primary and the cpworker secondary must be built against the **same** DPDK
(EAL rejects a version mismatch). If your distro's `libdpdk` has the PMD you
need, use it; otherwise build DPDK from source, e.g.:

```sh
curl -sL https://fast.dpdk.org/rel/dpdk-25.11.tar.xz | tar xJ
cd dpdk-25.11
meson setup build -Dprefix=$HOME/dpdk-inst -Dtests=false -Dexamples= \
  -Denable_apps=test-pmd \
  -Denable_drivers=net/mlx5,common/mlx5,bus/auxiliary,net/pcap,net/tap,net/ring
ninja -C build && ninja -C build install
```

`mlx5` additionally needs `libibverbs-dev librdmacm-dev libmlx5-dev`.

## Running

```sh
sudo SRIOV_PF=ens8np0 TRAFFIC_IFACE=ens8np0 \
     DPDK_PKG_CONFIG=$HOME/dpdk-inst/lib/x86_64-linux-gnu/pkgconfig \
     verification/dpdk/field_test.sh
```

`SRIOV_PF` makes the script create a single SR-IOV VF and hand that VF to DPDK,
so the PF (and any traffic it carries, e.g. NFS) is untouched. Omit it and pass
`PORT_BDF` to use a port directly. See the header of `field_test.sh` for all
variables.

On success the script asserts the captured marker-frame count is at least
`MIN_PCT`% of `FRAMES` (default 95%) and exits non-zero on any failure. `pdump`
is best-effort: it drops a small, fixed prefix at startup (the `WARMUP` batch
absorbs most of it) plus a little under sustained burst, so exact equality is
not guaranteed on every host. A genuine failure (PMD without secondary support,
pdump enable refused, zero frames) still fails hard.

## Recorded field result (yinjiao, 2026-10-01)

| NIC | result |
| --- | --- |
| Nebulamatrix `nbl` (25G, `3a:00.0/.1`) | PMD rejects secondary → **`pdump` unusable** |
| Mellanox ConnectX-6 Dx (100G) via SR-IOV VF | mlx5 primary + cpworker pdump secondary: **1927/2000 (96%)** typical, **2000/2000** on a quiet run |

See `FIELD_CONFIRMATION.md` §7 and `PARITY.md` §5.1.

## Serialized performance experiments

[BENCHMARK.md](BENCHMARK.md#architecture-investigation-2026-10-01) records the
2026-10-01 sweep, producer/consumer controls and hardware-mirroring results.
These helpers are specific to the yinjiao/laojun lab, its CPU numbering, paths
and destination MAC. Run one experiment at a time with exclusive use of the
test VFs; both PFs carry other traffic. SSH and passwordless sudo must work.

* `primary.c`: RSS RX, cumulative primary/pdump JSON counters, optional byte
  touch, external-buffer inspection and per-queue buffered pcap writers. See
  its header for `PRIMARY_*` variables. Pcap output must use local storage.
* `perf_pool.c`: laboratory `LD_PRELOAD` override for clone-pool multiplier,
  cache and NUMA socket; production defaults remain unchanged.
* `pdump_perf.c`: count/free-only secondary, with shared-ring or per-queue
  drain workers, for isolating transport overhead.
* `perf_multiqueue.patch`: optional queue-specific cpworker prototype. Apply
  only in a separate laboratory copy; it is not a production configuration or
  a claim that independent processes preserve global output semantics.
* `perf_capture.py`: JSON case array → append-only JSONL counter snapshots.
  Creates VFs, disables PAUSE, runs brief serialized windows, then restores
  VFs/PAUSE/processes/runtime state in `finally`, including on SIGTERM.
* `flow_mirror.c` / `perf_mirror.py`: isolated PF proxy plus two VF representors,
  transfer-domain SAMPLE mirror, and independent VF receivers. The script
  temporarily changes the eSwitch to switchdev and returns it to legacy.

Build C helpers on yinjiao against the same DPDK as cpworker:

```sh
cd /home/vader/cprs-bench
export PKG_CONFIG_PATH=/home/vader/dpdk-inst/lib/x86_64-linux-gnu/pkgconfig
cc -O3 -Wall verification/dpdk/primary.c -o dpdk_primary $(pkg-config --cflags --libs libdpdk)
cc -O3 -Wall verification/dpdk/pdump_perf.c -o pdump_perf $(pkg-config --cflags --libs libdpdk)
cc -O3 -Wall verification/dpdk/flow_mirror.c -o flow_mirror $(pkg-config --cflags --libs libdpdk)
cc -O3 -Wall -shared -fPIC verification/dpdk/perf_pool.c -o perf_pool.so $(pkg-config --cflags libdpdk) -ldl
PATH=/home/vader/.cargo/bin:$PATH cargo build --release -p cpworker -p cpctl --features cpworker/dpdk
```

The generator uses the existing `/tmp/lj_tx.sh` on laojun. A small case file can
compare the default, NUMA-local and direct primary paths:

```json
[
  {"name": "default"},
  {"name": "local", "affinity": "48", "pin": true, "ring": 65536},
  {"name": "local-cache256", "affinity": "48", "pin": true, "ring": 65536, "cache": 256},
  {"name": "direct-mprq", "backend": "none", "rxq": 8, "PRIMARY_INSPECT": 1,
   "device": "0000:b8:00.1,mprq_en=1,rxqs_min_mprq=4,mprq_max_memcpy_len=0,mprq_log_stride_num=6,mprq_log_stride_size=8"}
]
```

Run from this repository after synchronizing/building the helpers:

```sh
python3 verification/dpdk/perf_capture.py /tmp/cases.json /tmp/results.jsonl
```

Other case keys include `snap`, `rxq`, `pool`, `cache`, `socket`, `txcores`,
`PRIMARY_DESC`, `PRIMARY_MBUF`, `PRIMARY_TOUCH`, and `PRIMARY_PCAP`. `backend:
"drain"` additionally takes `consumers` and `per_queue`. The experimental
four-process cpworker run takes `workers: 4` and `binary` pointing to the
separately patched laboratory binary. Existing evidence includes the exact
case settings, counter intervals, CPU usage and failed allocations.

For an eight-queue mirror using MPRQ, with the diagnostic flow COUNT removed:

```sh
PERF_PRIMARY_DESC=1024 PERF_TX_CORES=6 PERF_FLOW_NO_COUNT=1 \
PERF_QUEUE_CASES='[[8,8]]' \
PERF_DEVICE_ARGS=',mprq_en=1,rxqs_min_mprq=4,mprq_max_memcpy_len=0,mprq_log_stride_num=6,mprq_log_stride_size=8' \
python3 verification/dpdk/perf_mirror.py
```

The mirror script writes `/tmp/cpperf-mirror-evidence.json`. It matches only the
laboratory destination MAC and checks kernel/NFS-link connectivity before,
during and after. It does not alter firmware or unbind the PF.

After an interrupted experiment, run restoration from the repository:

```sh
PYTHONPATH=verification/dpdk python3 -c 'import perf_capture; perf_capture.restore()'
```

For a mirror interruption, also stop `flow_mirror` and return the PF eSwitch to
legacy with only the test VFs unbound, before deleting the VFs. Verify both PFs
have `sriov_numvfs=0`, PAUSE RX/TX on, no test processes, empty DPDK runtime
directories and no `/tmp/core.*`. Explicitly restore any hugepage counts or
local pcap files changed outside the harness. The measured session restored
all of these; no persistent NIC/firmware changes were retained.
