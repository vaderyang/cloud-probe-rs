# Rejected candidate: recycle pipeline allocations and park the output thread (2026-10-03)

`cloud-probe-rs-10m`. The profile in
[`../pipeline-profile-2026-10-02/README.md`](../pipeline-profile-2026-10-02/README.md)
left two candidates for the pipeline model's fixed per-core cost and said so
explicitly: (a) the output thread's `thread::sleep(10 µs)` idle poll (~100 k
wake-ups/s) and (b) a per-packet allocation on the pipeline path (`taskmgr_output`
spent ~44 % of its self samples in `_int_malloc` + `_int_free`).

A candidate fix was written for both — allocation recycling along the ring plus a
spin-then-park idle wait — and then **measured and rejected**. It is recorded here
because it is the measurement, not the code, that is worth keeping: it removes both
of the original explanations without replacing them.

## What was measured

Same worker-only 1 CPU / 512 MiB cgroup, same probe, same rates, three samples per
cell (`run_probe.py`, `before.jsonl` / `after.jsonl`; `cores` is the cgroup
`cpu.stat` delta over the wall time). `after` is the candidate fix.

| model | offered pps | cores before | cores after | allocations before | allocations after | idle wakes before | idle wakes after |
|---|---|---|---|---|---|---|---|
| pipeline | idle | 0.0311 | **0.0001** | 0 | 0 | 77 566 | **1** |
| pipeline | 100 k | 0.0859 | **0.1089** | 1 000 000 | **400** | 76 043 | 6 711 |
| pipeline | 300 k | 0.2321 | **0.3686** | 3 000 000 | **1 800** | 71 474 | 15 629 |
| pipeline | 800 k | 0.5132 | **0.8151** | 8 000 000 | **8 172** | 62 536 | 34 722 |
| rtc | 100 k | 0.0110 | 0.0121 | 0 | 0 | 0 | 0 |
| rtc | 800 k | 0.0616 | 0.0664 | 0 | 0 | 0 | 0 |

## What the numbers say

- **The idle cost is real and this fixes it.** 77 566 wakes → **1**, and 0.0311 →
  **0.0001** cores while idle. That is a genuine win and the one part of the change
  worth keeping.
- **The loaded cost is not allocation volume.** Cutting allocations by ~1000×
  (8 000 000 → 8 172 at 800 k) did not reduce CPU; it went **up** by 59 %
  (0.5132 → 0.8151). If `_int_malloc`/`_int_free` were the loaded-path cost, this
  would have moved the other way.
- **The loaded cost is not the idle poll either.** The same change cut idle wakes
  by more than half at load (62 536 → 34 722) and still cost more CPU.
- So **both original candidates are now unsupported**, and the loaded-path fixed
  cost — the thing that actually stops the pipeline model near 0.8 Mpps in a 1 CPU
  budget — is still unexplained. The next plausible places are per-packet work the
  profile could not separate from the allocation signal: the copy through the ring,
  the `out_sets` lock, and the atomic accounting.

## Why the candidate was not merged

The loaded path is what `10m` is about, and this makes it worse. Even the part that
works (idle) cannot be merged on its own yet, because the change moved two things at
once and the worktree's ablation did **not** isolate which one produced the
regression — the spin-then-park is the prime suspect (the author's own comment
warns that parking on every gap "turns a fast producer into a per-packet futex wake
storm", and the 64-iteration spin burns CPU whenever the gap is short), but that is
an inference, not a measurement.

`rejected-candidate.patch` is the full diff as it stood; `run_probe.py`,
`before.jsonl` and `after.jsonl` reproduce the table; `baseline-instrumentation.patch`
is the diagnostic-only instrumentation that had to be applied to the baseline to
count allocations. Nothing here is on `main`.

## What to do next

Isolate first, then fix: apply the idle-wait change **alone** and the recycling
change **alone**, and treat the idle win as a separate, mergeable change of its own
(it is independent of the loaded-path question and already has a clean number).
