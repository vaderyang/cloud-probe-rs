# Forwarding and end-to-end measurement (2026-10-02)

`REPORT.md` is the full record; this is the summary. The question was what a
worker does once captured packets have to go *somewhere* — every earlier lab
number used a `null` (discard) output.

Testbed and budget as in [`../BENCHMARK.md`](../BENCHMARK.md): laojun → yinjiao
100 GbE, one worker under a worker-only cgroup (`cpu.max=100000 100000`,
`memory.max=536870912`), paced 64-byte frames (68 physical bytes with FCS),
serialized short bursts, no BPF and no rate limit. Capture backends: the Rust
`libpcap` capturer with the `TPACKET_V3` ring (default), its `ring:false`
(`recvmsg`) fallback, and — the "plain libpcap" reference — the unmodified
upstream C worker with real libpcap (`timeout_ms=1000` → V3, and its default
immediate mode → V2).

## Delivered throughput (captured / forwarded / delivered, Mpps)

| Output | Rust ring (V3) | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---|---|---|---|
| `null` | 2.4 at ~12% CPU | 2.4 at ~18% | 1.0 at ~100% |
| `pcap_file` (local disk) | **2.0 loss-free** | same order | same order |
| `pcap_file` (`/dev/shm`) | ~2.0 | — | — |
| `zmq` (PUSH → PULL receiver) | **2.0 loss-free** | — | — |
| `vxlan` | knee **0.125–0.15 Mpps** | — | — |

- **Forwarding does not cost much for the cheap sinks**: file and ZMQ both
  delivered 2.0 Mpps loss-free on the same one-core budget, i.e. the capture
  path still binds.
- **VXLAN is expensive**: the one-core knee is ~0.125–0.15 Mpps, and a strict
  delivered loss-free point could **not** be demonstrated — not because of
  cloud-probe, but because the host's egress policy
  (`table inet vibing_host_egress`) rate-limits/drops new unidirectional UDP to
  the 25 GbE peer and `sendto` returns **EPERM**, not ENOBUFS. Every such failure
  is accounted in `output error_drop_packets`. The throughput knee must therefore
  be read separately from those policy drops.
- `recvmsg` (`ring:false`) is CPU-bound: 0.5 Mpps at ~69% of a core with `null`,
  and its knee is not bracketed above that.
- DPDK `pdump` forwarding was **not** measured in this sweep.

End-to-end accounting was closed for the selected cases: generator accepted ==
captured == forwarded == receiver received, with all residual drops attributed.
**117/117 selected cases** pass the independent validation
([`continuation-validation.json`](continuation-validation.json),
[`selected-summary.json`](selected-summary.json)).

## Defects this found (filed, not fixed here)

1. **`pcap_file` counts failed writes as forwarded, and logs per packet**
   (`cloud-probe-rs-5bh`). `output/file.rs` logs a `PcapWriter::write` failure
   and then unconditionally increments `fwd_bytes`/`fwd_packets` and returns
   success; `destroy` only logs a failed flush. A controlled offline replay of
   1,000 64-byte packets into `/dev/full` produced **898 ENOSPC log lines** while
   reporting `cap_packets=1000`, `fwd_packets=1000`, `fwd_bytes=64000`,
   `error_drop_packets=0` — and stored nothing. Reproduced on the **exact**
   benchmark binary (SHA256 `0b43b5c6…`) after the physical sweeps stopped.
   The C upstream has the same shape (`output_file.c` calls void `pcap_dump` and
   counts forwarding unconditionally), so this is a parity bug too. Evidence:
   [`full-repro-exact-stats.json`](full-repro-exact-stats.json),
   [`full-repro-exact.log`](full-repro-exact.log).
2. **`zmq` counts a batch as forwarded when the peer never receives it**
   (`cloud-probe-rs-b7b`): a partially written frame is dropped on disconnect and
   `OutputStats` is not notified.
3. **RTC still holds `out_sets` across blocking output I/O**
   (`cloud-probe-rs-oim`): a follow-up to `cloud-probe-rs-brh`, which released the
   *manager* mutex; a slow disk or peer can still stall capture below quota.

No performance fix is included in this record, and none of these defects was
observed to cause loss in the successful sweeps — they are accounting and stall
hazards, plus one reproducible accounting defect.

## Reproduce

`run.py` drives the cases (it creates the VFs, disables PAUSE and restores both
hosts in `finally`), `sample.py` takes the counter snapshots, `receiver.c` is the
VXLAN/ZMQ receiver, `analyze.py`/`report.py`/`finalize.py` turn the raw JSONL
into the tables. `capacity_tx-reused.c` is the paced generator, reused from the
capacity work. Raw per-case JSONL and logs (767 MiB) stayed lab-local.

Both hosts were restored and independently re-audited afterwards: VFs 0, PAUSE
autoneg off / RX on / TX on, 100 GbE links up, no worker/transmitter/primary
processes, `/var/run/dpdk` empty, no cores, hugepage counts matching the original
baseline, NFS `statfs` and an NFS RPC NULL both passing. The egress firewall rules
were left unchanged. These are short-burst laboratory bounds, not sustained
durable-disk or line-rate claims.
