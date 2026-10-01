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
