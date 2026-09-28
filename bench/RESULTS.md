# cpworker: C vs Rust — benchmark results

Append-only log: every `bench/bench.py` run appends a section, nothing is
overwritten. Read it bottom-up (newest run last). Each section carries its own
machine, `N`, `REPEAT` and the per-run raw rows, so any ratio quoted elsewhere
must be findable here with its spread.

**Absolute throughput is machine-specific and must not be compared across
machines or kernels.** Only the C/Rust ratio measured on one machine, in one
run, means anything. Two caveats in the measurement scope itself also move the
absolute numbers (neither changes the direction of a ratio):

* `elapsed` starts at `fork`/`exec`, so it includes process start-up, config
  parsing and capturer set-up (a fixed few tens of ms that matters most at small
  `N`);
* it stops at the capturer's `end of file` log line, which the capturer emits
  *before* the outputs are destroyed, i.e. before the pcap writer's last flush.
  The `file` scenario therefore under-measures the write path of both binaries by
  the same structural amount.

---

## Run 2026-09-27 19:56:11 (historical, imported)

Imported from the run that produced the table in `README.md` at commit
`4c26564`. Kept because the plan (`IMPROVEMENT_PLAN.md` M5) quotes "two
consecutive runs agreed to within 2%" and this is the first of those two; until
now it existed only outside the repository (qwen P3-6).

Machine: 4 cores, Intel(R) Core(TM) M-5Y31 CPU @ 0.90GHz, 7.7 GiB RAM, Linux 7.0.0-34-generic

Workload: 1000000 packets (417.1 MB) replayed from a PCAP file; `N=1000000`,
`REPEAT=5` (median of 5 runs after a warm-up).

| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| null | C | 3.33 M | 1386.8 | 0.301 | 7.3 |
| null | Rust | 4.93 M | 2056.8 | 0.203 | 2.7 |
| file | C | 1.33 M | 553.3 | 0.754 | 7.3 |
| file | Rust | 1.84 M | 768.7 | 0.543 | 2.8 |
| vxlan-split | C | 0.10 M | 43.2 | 9.658 | 7.3 |
| vxlan-split | Rust | 0.11 M | 47.1 | 8.852 | 2.9 |

Dispersion: **not recorded.** The harness at that commit reported only the median
of the 5 runs, so this section cannot show a min/max/stdev — that is the gap
qwen P3-6 asked about, closed by the sections below.

## Run 2026-09-27 19:58:44 (historical, imported)

The second of the two runs, and the one `bench/RESULTS.md` used to be overwritten
with at every re-run. Same machine and workload as the section above.

| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| null | C | 3.30 M | 1374.8 | 0.303 | 7.3 |
| null | Rust | 4.98 M | 2077.0 | 0.201 | 2.8 |
| file | C | 1.36 M | 565.4 | 0.738 | 7.3 |
| file | Rust | 1.82 M | 759.1 | 0.549 | 2.8 |
| vxlan-split | C | 0.11 M | 44.5 | 9.373 | 7.3 |
| vxlan-split | Rust | 0.11 M | 46.4 | 8.995 | 2.9 |

Dispersion: not recorded (same harness limitation).

## Run 2026-09-28 14:35:17

Machine: 4 cores, Intel(R) Core(TM) M-5Y31 CPU @ 0.90GHz, 7.7 GiB RAM, Linux 7.0.0-34-generic

Workload: 1000000 packets (417.1 MB) replayed from a PCAP file; N=1000000, REPEAT=5 (plus one discarded warm-up per binary).


| Scenario | Impl | Runs | Time med (s) | Time min–max (s) | stdev (ms) | pps med (M) | MB/s med | Peak RSS med (MB) |
|---|---|---:|---:|---|---:|---:|---:|---:|
| null | C | 5/5 | 0.491 | 0.384–0.543 | 55.1 | 2.04 | 849.3 | 7.1 (7.0–7.2) |
| null | Rust | 5/5 | 0.357 | 0.303–0.385 | 34.5 | 2.80 | 1167.5 | 2.8 (2.7–2.8) |
| file | C | 5/5 | 1.366 | 1.050–1.629 | 202.9 | 0.73 | 305.4 | 7.1 (7.0–7.2) |
| file | Rust | 5/5 | 0.868 | 0.818–1.028 | 87.6 | 1.15 | 480.2 | 2.7 (2.7–2.8) |
| vxlan-split | C | 5/5 | 14.638 | 11.698–19.494 | 2924.6 | 0.07 | 28.5 | 7.1 (7.1–7.3) |
| vxlan-split | Rust | 5/5 | 15.885 | 15.648–16.786 | 412.1 | 0.06 | 26.3 | 2.9 (2.8–2.9) |

C/Rust time ratio (median; the range spans the min/max of both sides, so it is the honest reading of the same 5-run sample):

| Scenario | ratio (med) | ratio range over min/max | spread of the ratio |
|---|---:|---|---|
| null | 1.37× | 1.00×–1.79× | 0.79 |
| file | 1.57× | 1.02×–1.99× | 0.97 |
| vxlan-split | 0.92× | 0.70×–1.25× | 0.55 |

Raw per-run rows (the evidence behind every number above):

* `null` / C: run1: 0.384s, run2: 0.543s, run3: 0.526s, run4: 0.488s, run5: 0.491s; RSS MB: 7.0, 7.1, 7.2, 7.2, 7.0
* `null` / Rust: run1: 0.357s, run2: 0.385s, run3: 0.376s, run4: 0.306s, run5: 0.303s; RSS MB: 2.7, 2.8, 2.8, 2.7, 2.8
* `file` / C: run1: 1.629s, run2: 1.507s, run3: 1.366s, run4: 1.234s, run5: 1.050s; RSS MB: 7.2, 7.2, 7.1, 7.1, 7.0
* `file` / Rust: run1: 0.868s, run2: 1.028s, run3: 0.839s, run4: 0.818s, run5: 1.006s; RSS MB: 2.8, 2.7, 2.7, 2.7, 2.7
* `vxlan-split` / C: run1: 17.109s, run2: 11.698s, run3: 12.334s, run4: 14.638s, run5: 19.494s; RSS MB: 7.3, 7.1, 7.1, 7.1, 7.1
* `vxlan-split` / Rust: run1: 15.885s, run2: 15.926s, run3: 15.648s, run4: 15.702s, run5: 16.786s; RSS MB: 2.8, 2.9, 2.9, 2.8, 2.9
