# Legacy C reference — raw counters (2026-10-02)

Raw counter dumps behind the "Legacy C reference capture" section of
[`../BENCHMARK.md`](../BENCHMARK.md). The upstream worker is
`netis/cloud-probe` `0.9.x`, commit `d302572a`, built unmodified with the recipe
from its own CI (system libpcap plus a minimal static libzmq compiled with
`--disable-libbsd`).

Testbed and budget: the laojun → yinjiao 100 GbE link, one worker under a
worker-only cgroup (`cpu.max=100000 100000`, `memory.max=536870912`,
`memory.swap.max=0`), 14-second paced bursts of nominal 64-byte frames
(68 physical bytes including FCS, so 100 GbE is ≈142.05 Mpps for this shape),
`null` output, snaplen 2048, no BPF, no rate limit, tests serialized.

| File | What it is |
|---|---|
| `rtc-measurements.csv` | RTC runs: `timeout_ms=1000` (`TPACKET_V3`, 8 MiB) and the worker's compiled default `timeout_ms=0` (immediate mode, `TPACKET_V2`, 256 MiB). 26 rows. |
| `legacy-probe-validation.json` | Counter-consistency and completion checks for those rows. |
| `pipeline-measurements.csv` | Daemon-default pipeline runs: `timeout_ms` omitted → 0 ms (`TPACKET_V2`, 8 MiB libpcap buffer, 504 MiB pipeline) and the same with `timeout_ms=1000`. 31 valid bursts. |
| `pipeline-cases-sweep.json` | The case inputs for the pipeline sweep. |
| `pipeline-validation.json` | Counter consistency, cgroup membership, ring-version and restoration checks for the pipeline runs. |

Headline results (whole-burst, including drain):

| Configuration | Loss-free | Overload observed | Worker CPU |
|---|---:|---:|---:|
| RTC, `TPACKET_V3`, 8 MiB | ~2.4 Mpps | 2.455–2.508 Mpps | ~18% of one core |
| pipeline, `TPACKET_V2`, 8 MiB, 504 MiB buffer (shipped default) | 0.95–1.0 Mpps | 0.916–0.950 Mpps | ~100% |
| pipeline, `TPACKET_V3` | 2.1 Mpps | 1.20–2.05 Mpps | ~86% |

Caveats, so these are not over-read:

- **Short-burst laboratory bounds**, not endurance or line-rate guarantees.
- Counter windows are separate and close, not simultaneous; whole-burst loss is
  the qualifying number and includes startup/transient losses.
- The `2.1 Mpps` pipeline/V3 figure is the highest loss-free point, not a
  plateau (see `../BENCHMARK.md`).
- Worker CPU is the process's own user+system ticks inside the cgroup; kernel
  softirq work is outside it.
- **The C DPDK capturer cannot be measured at this commit**: `dpdk_init()` is
  never called, so EAL is never initialised (upstream issue #289). No pdump row
  exists here for that reason.
- The environment was restored and verified after every phase (VFs 0, PAUSE
  RX/TX on, no stray processes, `/var/run/dpdk` clean, hugepages unchanged,
  NFS healthy). Build logs, binary hashes and the audits remain lab-local under
  `/tmp/legacy-probe/`.
