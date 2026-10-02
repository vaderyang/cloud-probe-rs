# Where does the pipeline execution model spend the one core? (2026-10-02)

`cloud-probe-rs-2kx`. The 1 CPU / 512 MiB capacity record has the RTC model
reaching ~2.4 Mpps on AF_PACKET while the pipeline model passes only ~0.8 Mpps
before losing. The bead asks to *profile allocation/free, atomic accounting,
scheduler/NUMA placement and the AF_PACKET kernel receive cost* **before**
choosing an optimisation. This is that profile; it does not select the
optimisation.

## Method

Same worker-only cgroup as the capacity record (`cpu.max = 100000 100000`,
`memory.max = 536870912`), same binary (`~/cprs-bench/target/release/cpworker`),
AF_PACKET `TPACKET_V3` capturer on the yinjiao VF, `null` output, one task,
`taskset -c 48-49`. Traffic from the paced DPDK generator the capacity record
used (`capacity_tx`, `CAP_TX_MPPS`/`CAP_TX_SECONDS`, 4 queues on laojun), 14 s per
point. `perf record -F 499 -g -p <pid>` over the steady window; worker CPU from
`cpu.stat usage_usec` across the burst. Runs serialized under the shared physical
lock; both hosts restored (VFs removed, PAUSE autoneg off / rx on / tx on).

## Worker CPU is the finding

| Model | Offered Mpps | Delivered (VF `rx_packets`) | **Worker cores** | CPU per Mpps |
|---|---|---|---|---|
| rtc | 0.8 | 11 198 850 | **0.04** | 0.05 |
| rtc | 2.4 | 33 240 401 | **0.19** | 0.08 |
| pipeline | 0.8 | 11 199 744 | **0.58** | 0.73 |
| pipeline | 2.4 | 33 595 506 | **0.72** | 0.30 |

- The generator's own pacing is exact: at 0.8 Mpps for 5 s it sent exactly
  4 000 000 frames and the VF received exactly 4 000 000, so the offered rate is a
  trustworthy denominator.
- **RTC scales with the traffic** (0.04 → 0.19 cores for a 3× rate rise).
- **The pipeline does not.** It costs **0.58 cores at 0.8 Mpps** — 14× the RTC cost
  for identical work — and only 0.72 at 2.4 Mpps. Almost all of it is *fixed*:
  ~0.55 of those cores are paid regardless of load. That single fact explains why
  the pipeline model stalls near 0.8 Mpps inside a 1 CPU budget: it spends over
  half the core before any of the traffic arrives.
- Delivered packets match the offer in every row, so these runs are not
  capture-limited; they measure what the model costs, not what it can carry.

## Where the pipeline's samples go (`perf report`, `-g none`, self %)

`pipeline` @ 0.8 Mpps — all top entries belong to the output thread
(`taskmgr_output`):

| self % | symbol |
|---|---|
| 30.28 % | `libc.so.6` `_int_malloc` |
| 13.84 % | `libc.so.6` `_int_free` |
| 9.27 % | `cpworker` `TaskManager::start::{closure#0}` |
| ~13 % | kernel softirq (`napi_poll` → `netif_receive_skb_list_internal`), i.e. the RX path charged to this thread's context |

`rtc` @ 0.8 Mpps — all top entries are per-packet work in the RTC loop:

| self % | symbol |
|---|---|
| 33.13 % | `AfPacketCapturer::deliver_matching` |
| 21.01 % | `NullOutput::send_packet` |
| 15.57 % | `AfPacketCapturer::capture_once` |

**Allocation dominates the pipeline output thread and is absent from RTC.**
`_int_malloc` + `_int_free` are ~44 % of that thread's self samples (57 % counting
both self and children). RTC passes a borrowed slice to the sink
(`send_packet(&hdr, data, ..)`) and never allocates per packet; the pipeline hands
a `Box<RingMsg>` through the ring and gets it back via `alloc.free(&msg)`.

## What is *not* established (do not over-read this)

- **The fixed ~0.55 cores are not explained by the allocation numbers.** Per-packet
  allocation should scale with the rate; the measured cost barely does. The output
  thread's idle path is a `thread::sleep(10 µs)` poll loop
  (`crates/cpworker/src/task.rs`, `start_output_thread`), i.e. ~100 k wake-ups per
  second; that is the shape a fixed cost would have, but this profile **does not**
  isolate it — the two candidates (the poll loop and a fixed allocation/accounting
  cost) were not separated, and no `sched`/trace data was taken.
- **The exact allocation site was not traced.** The per-packet path goes through
  `SimpleAllocator` and `Box<RingMsg>`; where glibc `_int_malloc` is actually
  reached (recycler miss, `Box::new` fallback, or the `out_sets` lock's
  bookkeeping) needs either a heap profiler or a counter on the allocator, and
  neither was run.
- **NUMA/scheduler placement was not measured.** Both models ran pinned to the
  same cores, so placement is controlled, but the bead's "scheduler/NUMA
  placement" question is unanswered.
- **The AF_PACKET kernel receive cost is bounded by something else entirely**, as
  [`fanout-2026-10-02/README.md`](../fanout-2026-10-02/README.md) shows: adding
  capture sockets does not lift it (~3.2 Mpps at 8 sockets). So the pipeline
  number here is *additional* cost on a path RTC already saturates, not a second
  bottleneck.
- One VF, one flow mix, 14 s bursts: laboratory bounds.

## Next step this obviously suggests

Write the follow-up optimisation bead from these two candidates — (a) remove or
bound the output thread's idle poll (park on the ring instead of sleeping in a
loop) and (b) find and remove the per-packet allocation on the pipeline path —
and require the *relative* CPU at a fixed rate to be the acceptance metric, with
RTC's cost as the floor. Reproduce with `pipeline_profile.sh` in this directory.
