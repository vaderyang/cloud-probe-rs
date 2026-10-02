# Forwarding and end-to-end measurement (2026-10-02)

`REPORT.md` is the raw generated record, kept unedited — including the two
readings corrected below. This file is the summary. The question here was what a
worker does once captured packets have to go *somewhere*; every earlier lab number
used a `null` (discard) output.

Testbed and budget as in [`../BENCHMARK.md`](../BENCHMARK.md): laojun → yinjiao
100 GbE, one worker under a worker-only cgroup (`cpu.max=100000 100000`,
`memory.max=536870912`), paced 64-byte frames (68 physical bytes with FCS),
serialized short bursts, no rate limit. Capture backends: the Rust `libpcap`
capturer with the `TPACKET_V3` ring (default), its `ring:false` (`recvmsg`)
fallback, and the "plain libpcap" reference — the unmodified upstream C worker
with real libpcap (`timeout_ms=1000` → V3, and its shipped default immediate mode
→ V2). A peer exists on the output NIC, so the network-output rows explicitly set
`not_filter_output_hosts:true` for a genuinely empty filter; `null`/file rows have
no output hosts and are unaffected.

## Highest loss-free point per backend (captured Mpps @ worker CPU)

"Loss-free" means the worker counters show no capture/output drop **and** the
generator's frames were all captured (offered ≈ captured); the 2.4/3 Mpps rows are
offered targets, not loss-free points (at 2.4 Mpps the VF is already dropping out
of buffer: `rv3` captured 2.394175 with 23,298 OOB). Full per-target tables are in
`REPORT.md` ("Final aligned comparisons").

| Output | Rust ring (`rv3`) | C libpcap V3 (`cv3`) | C default/V2 (`cv2`) | Rust `recvmsg` |
|---|---|---|---|---|
| `null` | 2.0 @ 9.6% † | 2.0 @ 15.1% | 0.5 @ 28.7% † | 0.5 @ 68.6% † |
| `pcap_file` (disk) | 2.0 @ 31.4% † | 2.0 @ 36.3% | 0.5 @ 51.3% | 0.5 @ 70.4% † |
| `pcap_file` (`/dev/shm`) | 2.0 @ 19.8% † | 2.0 @ 30.7% | 0.5 @ 26.3% | 0.5 @ 62.8% † |
| `zmq` (PUSH → PULL receiver) | 2.0 @ 13.6% | 1.5 @ 25.4% | 1.0 @ 58.3% | — |
| `vxlan` | none (max 0.156 @ 100%) | none (max 0.149 @ 100%) | none (max 0.137 @ 100%) | — |

† This cell is from the first run of the same harness, not re-measured in the
continuation (the continuation re-ran `rv3` file_disk only to 1.5 Mpps and never
re-ran `cv2` null at 0.5): a reused saved run with the same capture options, not a
fresh point. The per-case configs for those rows are not shipped, so that equality
is not evidenced here. Everything else is a continuation row.

- **Forwarding barely costs anything for the cheap sinks.** File and ZMQ both held
  2.0 Mpps loss-free on the same one-core budget — the same rate as a `null`
  output — so capture, not forwarding, is the binding constraint there. What stops
  those columns above ~2.4 Mpps is the generator/VF running out of buffer (the
  `null` column plateaus at the same ~2.45 Mpps with only 11.9% CPU used), not the
  worker. The `file_disk` 2.0 row does sit at the 512 MiB `memory.max` ceiling
  (peak sampled cgroup usage 511.97 MiB — page cache, which is reclaimable), but
  this record does **not** show that the ceiling binds; `file_shm` reaches the same
  2.0 Mpps with a 306 MiB footprint, which argues against it.
- **`recvmsg` (`ring:false`) is CPU-bound**: 0.5 Mpps already costs ~69% of the
  allowed core; its knee is not bracketed above that.
- **VXLAN is expensive, and no loss-free point was demonstrated.** Its one-core
  knee is ~0.125–0.15 Mpps (all three backends plateau at ~100% CPU), so
  encapsulation plus `sendto` costs ~7 µs/packet. At every target the worker
  reported **1–2 `EPERM` packets** — except `rv3` at 1.5 Mpps, which reported none
  — so no strictly loss-free VXLAN point exists in this sweep. Those failures are
  booked in `output error_drop_packets`, and `forwarded == delivered` in every row,
  i.e. apart from those 1–2 packets the accounting closed.
  **The cause of the `EPERM` is not established by this record.** The host's egress
  policy is a measured candidate confound, not a proven one: the snapshot taken
  during the sweep ([`yinjiao-firewall.txt`](yinjiao-firewall.txt)) shows
  `10.0.0.10` — the VXLAN peer's address — outside that chain's allow set, and
  probes run afterwards ([`egress-eprem-probe-2026-10-02.txt`](egress-eprem-probe-2026-10-02.txt))
  show that packets to that address are dropped by that rule (the rule's counter
  advances by exactly the number of sends, twice) with `EPERM` returned
  intermittently (sometimes the first packet of a flow, sometimes not at all).
  But the sweep's own rows show the same destination **was being delivered** then,
  so the policy as captured cannot be the whole story, and the `EPERM` mechanism
  stays unexplained. The VXLAN CPU knee above is unaffected — it is a pure CPU
  measurement.
- **The ZMQ numbers say "forwarded", not "received".** The receiver is a separate
  process; the e2e term equals the worker's forwarded count for the selected rows,
  and the peer's UDP tail drops are invisible (`receiver.c`'s tail reader is
  UDP-only). Peer-side loss would appear only as `forwarded > delivered`.
- DPDK `pdump` forwarding was **not** measured in this sweep.

End-to-end accounting was closed for the selected cases: generator accepted ==
captured == forwarded == receiver received, with all residual drops attributed.
**117/117 selected cases** pass the independent validation
([`continuation-validation.json`](continuation-validation.json),
[`selected-summary.json`](selected-summary.json)). The older
[`validation.json`](validation.json) is the superseded earlier pass and still
carries one known failure (`cv3-gre-0.08m`, a GRE case: `downstream_gap 3`); GRE
was dropped from the selected set and is not part of any conclusion here.

## Defects this found (filed, not fixed here)

1. **`pcap_file` counts failed writes as forwarded, and logs per packet**
   (`cloud-probe-rs-5bh`). `output/file.rs` logs a `PcapWriter::write` failure and
   then unconditionally increments `fwd_bytes`/`fwd_packets` and returns success;
   `destroy` only logs a failed flush. A controlled offline replay of 1,000
   64-byte packets into `/dev/full` produced **898 write-failure log lines plus one
   flush failure** (so not one per packet — buffered writes surface per flush)
   while reporting `cap_packets=1000`, `fwd_packets=1000`, `fwd_bytes=64000`,
   `error_drop_packets=0` — and stored nothing. Reproduced on the **exact**
   benchmark binary (SHA256 `0b43b5c6…`) after the physical sweeps stopped.
   The C upstream has the same shape (`output_file.c` calls void `pcap_dump` and
   counts forwarding unconditionally), so this is a parity bug too. Evidence:
   [`full-repro-exact-stats.json`](full-repro-exact-stats.json),
   [`full-repro-exact.log`](full-repro-exact.log), and the earlier local run
   ([`full-repro-stats.json`](full-repro-stats.json),
   [`full-repro.log`](full-repro.log), [`full-repro-config.json`](full-repro-config.json)).
2. **`zmq` counts a batch as forwarded when the peer never receives it**
   (`cloud-probe-rs-b7b`): a partially written frame is dropped on disconnect and
   `OutputStats` is not notified.
3. **RTC blocking output I/O can stall capture** (`cloud-probe-rs-oim`). Note this
   is written against the source that was *benchmarked* (`a851e328`), where the
   RTC branch also held the manager mutex. The record's own tip (`06fc087`, the
   `cloud-probe-rs-brh` fix) releases that mutex, so at the tip only `out_sets` is
   held across the batch — a residual that cannot delay stats (which need only the
   manager lock) and is already serialized against reload by the polling lock. What
   remains, at both revisions, is the real hazard: `send_packet` does blocking I/O
   (file `write(2)`, `sendto`, VXLAN's ENOBUFS retry sleep) on the capture thread,
   so a slow disk or peer can stall capture below the worker's quota. Two
   qualifications that the `brh` fix does not cover: the inherent
   `TaskManager::poll_packets_batch`/`poll_packets` methods still hold the manager
   mutex for the whole batch, so "only `out_sets`" describes the `main.rs` path;
   and `stop()`/`Drop` takes `out_sets` **without** the polling lock, so shutdown
   can queue behind a full batch including a 1 s readability `poll()`
   (`cloud-probe-rs-fo7`).

No performance fix is included in this record, and none of these caused loss in
the successful sweeps — they are accounting and stall hazards, plus one
reproducible accounting defect.

## Corrections after independent review (2026-10-02)

Two independent models reviewed this record read-only (`qwen3.8-flash-next`,
`DeepSeek-V4.1-Flash`). Corrections applied here, with the finding that drove each:

- The `null` headline row reported the **offered** target (2.4 Mpps, and for C-V2
  a ~1.0 row at 42.8% CPU) as if delivered. Replaced with loss-free points. (Both
  reviewers; the six recomputed cells were then re-derived from
  `selected-summary.json` and all six check out.)
- The "plain libpcap" columns read "same order" where C V3 file is 1.5 and C V2
  0.5; they now carry the real values.
- The per-packet cost range `6.5–7 µs` (in `REPORT.md`) is really ~6.7–7.5 µs.
- The headline file/ZMQ rows that come from the earlier attempt are now marked †
  and the reuse is stated, without the earlier "no output hosts so unaffected"
  argument (the flag lives in a shared capture dict for every backend, and the
  per-case configs for those rows are not shipped).
- **The VXLAN attribution was downgraded from "host constraint, established" to
  "cause not established".** The first version rested on a firewall snapshot that
  was not shipped and on a mechanism asserted from the rules (`drop` ⇒ `sendto`
  fails); re-running the probe showed why that was wrong — packets to the peer
  address *are* dropped by that rule, and `EPERM` appears only intermittently,
  yet the sweep itself had `forwarded == delivered`. Both the snapshot and the full
  probe transcript, including that contradiction, are now shipped.
- Defect 3 was restated against the tip (only `out_sets`; stats are not delayed),
  and the two paths the fix does not cover (`TaskManager`'s inherent methods, and
  `stop()` taking `out_sets` without the polling lock) are noted.
- The `validation.json` GRE failure is disclosed.
- The ZMQ peer-side tail-drop blind spot is stated.
- The "512 MiB ceiling bounds the file 2.0 point" claim was dropped: the ~2.4 Mpps
  plateau is the generator/VF running out of buffer, and `file_shm` reaches 2.0
  Mpps at a 306 MiB footprint.
- The VXLAN sentence "at every target of 0.05 Mpps and above 1–2 packets failed"
  was wrong for `rv3` 1.5 Mpps (zero errors); corrected.
- `jinjiao-firewall.txt` is the peer host and has no `vibing_host_egress` chain;
  renamed `jinjiao-receiver-firewall.txt` to avoid an audit trap.
- `REPORT.md`'s file/line citations are off by one for several
  `write`/`drop`/`sleep` lines; it is kept unedited as the generated artifact.

Not changed, and left as open questions: the per-row `cpu_valid`/`cpu_method`
fields are not persisted in `selected-summary.json`, so the CPU-method claim cannot
be re-verified per row from the shipped JSON alone; the exact-binary identity is
asserted in prose rather than accompanied by a `sha256sum` manifest; and the
`error_drop_packets` increment is matched 1:1 to missing delivered packets by
identity rather than by per-packet ID, so compensating loss/duplication cannot be
excluded.

## Reproduce

`run.py` drives the cases (it creates the VFs, disables PAUSE and restores both
hosts in `finally`), `sample.py` takes the counter snapshots, `receiver.c` is the
VXLAN/ZMQ receiver, `analyze.py`/`report.py`/`finalize.py` turn the raw JSONL into
the tables. `capacity_tx-reused.c` is the paced generator, reused from the capacity
work. Raw per-case JSONL and logs (767 MiB) stayed lab-local.

Both hosts were restored and independently re-audited afterwards: VFs 0, PAUSE
autoneg off / RX on / TX on, 100 GbE links up, no worker/transmitter/primary
processes, `/var/run/dpdk` empty, no cores, hugepage counts matching the original
baseline, NFS `statfs` and an NFS RPC NULL both passing. The egress firewall rules
were left unchanged. These are short-burst laboratory bounds, not sustained
durable-disk or line-rate claims.
