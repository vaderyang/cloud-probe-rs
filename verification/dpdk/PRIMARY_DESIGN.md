# Primary capture and 100G acceptance contract

cloud-probe-rs-9jo (P2), design increment on fix/ws-9jo, base
8ac820611e882a393eabef4dcf42b550cad010cb, 2026-10-02.

**Status: design + tested offline numerical gate, not a production backend or a
100G pass.** No Rust/C runtime, configuration, dependency or RTC/pipeline behavior
is changed by this increment. The checker checks supplied normalized
measurements; it does not collect them or certify their authenticity. The bead
remains unfinished and its tracker state is unchanged.

## Evidence and scope

Read [BENCHMARK.md](BENCHMARK.md), including its pdump/MPRQ investigation,
capacity and pipeline fix history, and the new
[fanout experiment](fanout-2026-10-02/README.md). Source inspection of
[primary.c](primary.c) confirms explicit RSS, masked against PMD capabilities,
per-queue pollers and immediate bulk free of RX mbufs. The historical 33 Mpps
single-queue and 94.76 Mpps four-queue standard RX observations are consistent
with that implementation. They were not remeasured here. Its master polls spare
queues when lcores are insufficient: that convenience must not be copied into a
claimed one-worker-per-queue production configuration.

The fanout evidence localizes the ceiling before the socket: ring counts agree
with kernel rx_packets, eight sockets deliver only 3.19 Mpps, and changing
fanout modes scarcely changes throughput. That supports bypassing the kernel
VF RX path; it does not identify a specific mlx5/NAPI function. Absolute
rx_out_of_buffer counts are unreliable in that record. Adding an AF_PACKET
fanout backend is therefore outside this design.

The 139.31 Mpps MPRQ result is raw RX with 68-byte physical frames including
FCS, not telemetry. The later true-64B generator results still do not establish
sustained end-to-end loss-free telemetry. Four pdump workers were independent
processes; multiplying them would also multiply output limiter state.

This local host has no libdpdk pkg-config module and no provisioned 100G
experiment. Adding unexercised EAL/PMD/mbuf FFI, or an unused Rust queue-worker
abstraction, would leave the crucial lifetime and output ownership questions
untested. The useful executable increment is instead an offline acceptance
checker with adversarial synthetic fixtures. Its tests prove the rejection
rules, not a hardware throughput result.

## Backend placement and rollout boundary

Choose a **separate product-owned primary backend**, provisionally
capturer::dpdk_primary, built behind the existing dpdk feature. Keep
dpdk_pdump as the secondary compatibility backend. Do not promote the C
benchmark program into a product worker: it neither calls the Rust telemetry
outputs nor implements task/reload/limiter semantics.

The port/VF is explicitly exclusive to one process. A process-scoped owner
initializes EAL once as primary, validates port/queue/NUMA/RSS capability, sets
up pools/queues, and owns shutdown. Primary and pdump tasks cannot coexist in
the same process: the current pdump EAL singleton initializes secondary mode.
Reject such configuration before EAL or port side effects. Likewise reject two
owners for one port and insufficient dedicated worker cores. Never silently
fall back from primary to pdump/AF_PACKET, or bind a shared production VF.

For the first implementation require one capture task per exclusive port and
explicit RX-only coverage. Primary direct RX cannot reproduce pdump's RX+TX
coverage; deployments requiring local TX observation must retain pdump or
provide a separately designed TX tap. This is a declared backend capability,
not a reinterpretation of pdump flags. Multi-task packet fanout and integration
with an existing forwarding primary require separate ownership designs. A
future existing-primary adapter could borrow packets synchronously before that
primary frees/transmits them; retaining them would require explicit reference
transfer and forwarding isolation, not handing out raw pointers.

New config/daemon budget plumbing and runtime registration are deferred. Default
builds must continue returning before pkg-config/shim work in
[build.rs](../../crates/cpworker/build.rs); no default DPDK include/link/runtime
requirement. New inline mbuf/RX accessors belong in the header-compiled C shim,
with a tested ABI and checked conversions, rather than another handwritten
rte_mbuf layout. All library paths remain fallible (P5-23), with no added
integer as conversions (P5-15).

## RSS workers, outputs and semantic contract

One NUMA-local pinned worker exclusively polls each RX queue and owns its local
packet processing state. Configure RSS explicitly and validate the supported
hash fields/key/RETA before starting; merely allocating queues does not spread
traffic. Choose 8 or 16 queues only after PMD testing, rather than treating the
mlx5 benchmark devargs as universal defaults. Reverse directions of a flow
must map consistently when processing state needs them; ordinary RSS is not a
promise of symmetric hashing. Flow affinity, uneven RSS and single-flow
capacity are qualification cases, not reasons to migrate packets concurrently
between workers.

Start with synchronous per-queue processing of borrowed bytes: normalize the
frame, run the existing BPF semantics, construct the header, judge direction,
and call the existing output encoding/send logic. Bounded burst processing
amortizes accounting and output batching; it does not bypass parser/encoder,
filter, direction or limiter decisions. Each shard uses the existing output
batch size and flush/heartbeat rules. Publish once per complete burst, including
partial final bursts, rather than on every packet.

An ordinary Capturer is polled by the existing task manager, with mutable
PacketSink ownership. It cannot safely launch several threads all calling
that sink. The primary backend therefore needs its own opt-in task execution
adapter with unique queue-worker ownership; existing RTC and pipeline continue
using their current adapters. This increment does not implement that adapter.
It is a release blocker, not something solved by unsafe impl Send or by
sharing the existing SPSC producer across queues.

| Semantic | Required implementation and check |
| --- | --- |
| Global capture counters | Queue-local CaptureStats with one writer each; sum completed cumulative snapshots by task/epoch, including retired queues exactly once. Existing BytesStats::add/PacketsStats::add use load/store and lose concurrent additions; never share them between RX writers. Aggregate whole EiB + remainder (2^60) and packet units + remainder (10^16), with carry; do not repeatedly merge cumulative snapshots into a growing total. Test simultaneous publishing, rollover, queue retirement and reload without double counting. |
| Accounting boundary | cap_packets/cap_bytes count valid BPF-accepted sink deliveries, with bytes = caplen, excluding invalid mbufs. Keep PMD raw RX, filtered and delivery failures as separate diagnostics; raw RX is not cap_packets. Existing output stats retain their per-output meaning and aggregate across shards/outputs, so two outputs can legitimately forward twice the capture count. Acceptance below uses exactly one output. |
| Output ownership | One encoder/transport state per queue shard, with one logical task/output identity and aggregated stats. Single-writer pcap/rotating writers cannot be concurrently reused; initially funnel them to a bounded output owner preserving their framing/rotation, and qualify the capacity separately. Parallel network shards need collector support. Never advertise identical globally interleaved stream order; retain per-flow order and packet identity. |
| Global rate limit | One shared admission authority per logical task/output, independent of queue count. Reuse TokenBucket::consume under short serialization initially, preserving its packet timestamp, one-second capacity, actual bit debit (bytes * 8), and each output's current sliced/encapsulated debit length and decision order. No independent full-rate buckets and no preallocated leases that change admission outcomes. Batched credit distribution is deferred until equivalent ordering/refill/drop tests exist. This authority may limit throughput when enabled; unlimited qualification does not prove limited-path capacity. |
| Filter | Compile before starting RX, preserving the current dpdk_pdump expression semantics. Run BPF on the normalized original packet before truncation/direction/outputs, with original wire length available; snaplen affects delivery, not what BPF can inspect. Do not implicitly add AF_PACKET's output-host exclusion to pdump-equivalent config. Hardware steering is only an optimization after software-equivalence tests, including VLANs and non-IP traffic. |
| Direction | Reuse ReqPattern::judge_pkt_direction on captured bytes, None -> PKT_DIR_NONCHECK, and keep UNKNOWN output drops ahead of rate admission as today. Direct RX does not determine application request direction. Resolve NIC-based patterns before taking port ownership; retain required MAC/IP identity even if the VF netdev changes. |
| Timestamp | Preserve the pdump software convention: wall-clock UNIX sec/usec sampled once per nonempty burst and stored before asynchronous handoff. Do not substitute TSC/monotonic time, retimestamp at output, or claim hardware arrival accuracy. Packet delivery order is retained per queue, but even its clock can move backward; globally ordered arrival timestamps are not guaranteed. Use monotonic time only for benchmark intervals. Preserve current token bucket behavior for equal/backward packet timestamps; cross-queue admission has an explicit serialization order. |
| Header/slicing | Direct delivery preserves original len and min(len,snaplen) caplen. Output slices keep the current output-specific rules. Existing pipeline reconstructs len from caplen; this design does not change that legacy behavior or claim truncated RTC/pipeline headers are identical. FCS stripping/VLAN stripping/checksum offloads need explicit normalization and golden tests. |
| Heartbeat and backpressure | One coordinator schedules logical output heartbeats, serialized with each shard, including when RX is empty. Preserve flush/stop/drain order and explicit bounded buffering. A blocked output backpressures its queue; never retain unlimited external buffers. Control snapshots do not take output I/O locks. Stop/reload are generation barriers, not arbitrary cancellation with lost packets. |

The current Output API embeds private limiter and heartbeat state. Sharding
therefore needs an explicit opt-in admission hook at the existing decision
point and separate shard-flush versus logical-heartbeat operations; it cannot
be achieved by constructing N unchanged output objects. Tick/flush every shard,
but emit the logical heartbeat once, without multiplying its count by N.
Default RTC/pipeline outputs keep their current private state and API behavior.
Global limiter tests use one explicit cross-queue serialization trace; there
is no claim of identical packet selection under arbitrary thread interleavings.

Stats samples must contain a consistent packet/byte pair per completed queue
burst, then sum those snapshots without reading a torn unit/remainder carry.
Keep accumulation worker-private; publish/copy the completed snapshot under a
short per-queue snapshot lock, never held across RX or output calls. This is a
correctness baseline to measure before replacing it with a proven lock-free
publication scheme. Control reads take one such lock at a time, not a global
capture/output lock.
Live snapshots can include different completed bursts from different queues;
label the generation and sample time. They are not synchronized wire windows.
Final quiescent snapshots must be exact. Atomic types alone do not provide
multiwriter updates or a coherent multi-field snapshot.

For stop/reload: stop admitting new RX at a generation boundary; finish bursts;
drain bounded owned handoffs and flush outputs; publish final local counters;
join workers; then retire resources. Carry final totals once into the logical
task, including when fingerprinted tasks are reused/reordered. The existing
RTC/pipeline resource reuse and shared ring behavior stay unchanged. A primary
adapter needs its own regression tests for those same observable lifecycle
rules before release.

## Original RX mbufs and external buffers

The pdump path calls rte_pktmbuf_copy in primary callbacks and sends independent
copied mbufs through its clone pool/ring. The secondary frees those copies; the
primary can free original RX packets without waiting for it. Its ring_mp_mc
fix protects concurrent pool allocation. That is not direct RX ownership.

With mlx5 MPRQ, packet mbufs may reference strides in a PMD-owned shared buffer.
Preserve RTE_MBUF_F_EXTERNAL; return mbufs with the DPDK free API, which manages
the external buffer reference and callback. All application RX mbufs must be
freed before device close. These requirements and memcpy fallback are documented
in the [DPDK 25.11 mlx5 MPRQ guide](https://doc.dpdk.org/guides-25.11/nics/mlx5.html#multi-packet-rx-queue).
Retaining a stride can keep a larger shared buffer unavailable for RX.

Borrowed byte slices may exist only inside the owning mbuf's lifetime. Initially
finish synchronous sink calls before freeing each burst. For asynchronous
handoff, either copy the captured bytes into the existing owned message or
transfer a non-cloneable owned mbuf handle inside the same primary process.
Retaining bytes after free is invalid; shallow mbuf copies are invalid. Such a
handle needs chain-aware reads, external-reference-safe release and an explicit
thread-safety contract verified against the installed PMD. Multiple consumers
need separate valid references or owned bytes, never a raw pointer multicast.

Linearize/copy scattered frames safely; do not assume all packets are one
segment because the small-frame benchmark was. Keep extbuf flags intact when
rewriting headers. Reject malformed metadata with an error counter and free the
mbuf exactly once. Slow/error outputs, full queues, reload and partial startup
failures must release every outstanding handle while its pool/PMD is alive.
After workers join and references reach zero, stop/close the port, free pools, then
tear down EAL. An inability to drain must return an explicit failure and keep
resources alive until handles are released; freeing the PMD underneath them is
not recovery. Hardware tests must exercise MPRQ copy fallback, scatter,
allocation exhaustion and delayed consumers, beyond a mock RAII unit test.

## Full acceptance gate: primary-zmq-64b-v1

This is a proposed fixed release profile, not an executed benchmark. A full pass
requires **all** the physical, semantic and numerical conditions below. The
checker prints NUMERICAL_GATE_PASS, never a full acceptance verdict.

### Physical and instrumentation prerequisites

* An exclusive 100 GbE input port/VF, a generator independently calibrated at
  minimum-frame line rate, and separate collector egress with enough capacity
  for ZMQ framing/batching (provision at least 200G and measure actual overhead).
  A 100G input plus ZMQ overhead cannot simply fit onto another 100G link.
  PAUSE/PFC disabled on the whole path; no competing traffic, VF shaping,
  oversubscribed switch, sampled mirroring or unmeasured background traffic.
* Reserve dedicated CPU cores and NUMA-local ordinary/hugepage memory for **all**
  workers, EAL, transports and collectors. Record physical PCIe/link/firmware,
  PMD/DPDK versions, RSS key/RETA, queue/lcore map, devargs, pool/descriptor sizes,
  output config and git/binary hashes. Include every core/pool in the budget;
  this gate has no implied 1 CPU/512 MiB constraint. Qualify shipping nbl
  separately; mlx5/MPRQ results are not portable proof.
* Actual Ethernet frames are **64 bytes including 4-byte FCS**, without VLAN
  tags in this fixed profile. Check every generated frame's min/max length and
  calibrated physical byte counters, not just a mean or a txpkts=64 label.
  PMD TX generally takes 60 bytes without FCS; verify actual device behavior.
  Frame airtime is (64 + 8 preamble/SFD + 12 IFG) * 8 = 672 bits, giving
  100,000,000,000 / 672 = **148,809,523.8095 packets/s**. PCS/FEC encoding is not
  added again to the Ethernet 100G rate.
* Accepted TX packet count must exclude testpmd TX-dropped. Physical TX and RX
  are isolated workload counters, not kernel VF delivery counters. Record raw
  cumulative counters before/after, widths, counter clock timestamps and reset
  events. Reject resets/wraps or ambiguous nonmonotonic diagnostics; zero
  imissed alone is insufficient. Calibration must show physical byte counters
  include FCS; normalize other counter conventions explicitly.
* Use 10-second generator epochs and exact (run, epoch, flow, sequence) packet
  identities in valid UDP payloads. Receiver demultiplexes the **real cpworker
  ZMQ telemetry**, validates every encoded record's payload/header/direction and
  maintains exact sequence coverage per flow/epoch (bounded bitmap or equivalent,
  not a sampled hash). Heartbeats are decoded but excluded from data counts.
  Hash matches alone or aggregate receiver packet counts do not prove no
  duplicates compensated for losses.
* Logical packet counts refer to the same generated epoch, including receiver
  records that arrive at most one second late. Live physical counters have
  propagation/latch skew: use each endpoint's calibrated 10 s interval for
  rate, with uncertainty ≤0.01%, and quiet whole-run pre/post counters for exact
  conservation. Warm up, stop warmup traffic and drain, take the quiet baseline, then begin
  the uninterrupted 600 s measured stream; stop/drain before the final snapshot.
  No warmup/background packets may contaminate those whole-run counters.
  Do not combine old harness windows taken at different times. Use generation
  tags to reconcile logical batching, not arbitrary live cpctl deltas. Timing
  tolerance applies only to rate measurement; exact sequence/count equality
  has **zero packet tolerance**. A future collector/normalizer must implement
  these rules; existing short-burst harnesses do not yet do so.

### Semantic qualification, before capacity qualification

Run deterministic low-rate golden traces through the current backend and the
primary adapter, comparing decoded output content and counters, using controlled
packet timestamps for limiter comparisons. Cover no filter/accept/reject BPF,
VLAN/QinQ and scatter normalization, snaplen/output slicing, all direction values,
empty RX heartbeats, timestamp burst reuse, error writes/sends, limiter equal/
backward/refill timestamps and multiple competing queues. Two queues must share
one configured bit budget and one burst allowance with the output's existing
charge length. Do not silently fix legacy semantics during backend work.

Require queue-local counter carry and aggregation tests plus reload/stop tests
under busy RX, full handoffs and blocked/error outputs. Confirm per-flow order,
exactly-once disposal, no external references at PMD close, and no control stats
lock held over RX/output blocking work. Exercise packet retention with MPRQ on
hardware, including fallback copies and multi-segment frames. These tests are
requirements for the future implementation; none are claimed implemented by
the offline checker. Capacity cannot waive these requirements.

### Sustained capacity and numerical verdict

Use exactly one real zmq output per logical task, full original 60-byte
FCS-stripped data, no slicing, no BPF rejection, rate limit disabled and known
accepted direction. Set heartbeat_ms = 0 for this capacity profile; heartbeat
semantics are qualified separately above. Run **three independent restarts** of
the candidate binary,
each with at least **10 s warmup + 600 continuous measured seconds** (60 adjacent
10 s epochs). Freeze configuration for each run; disclose RSS flow count/mix.
A separate skewed/single-flow report states the envelope rather than claiming
RSS can parallelize a single flow. Require the following for every epoch, not
just the best run or a mean:

1. Generated and physical TX/RX rates lie within **±0.01% of 148.8095238095 Mpps**.
   This is the
   operational line-rate measurement tolerance, not a loss allowance. Lower
   offered load fails qualification; a rate above that range invalidates timing.
2. Per epoch: generator accepted TX = sum(queue capture) = global capture =
   output forwarded data = receiver unique data, exactly. Over the complete
   measured run, these totals also equal quiet-boundary physical TX/RX deltas,
   exactly; per-epoch physical samples need not equal tagged logical counts.
   Require physical bytes = 64 * physical packets, capture/receiver reconstructed
   original-frame bytes = 60 * packets, and queue byte sums equal global totals.
   ZMQ fwd_bytes retains its existing **message-byte** semantics: for this
   profile each record is 2 length + 16 header + 60 frame + 4 MPLS = 82 bytes,
   each data batch adds 24 bytes. Whole-run forwarded and receiver message
   bytes must both equal 82 * total_packets + 24 * data_batches, excluding ZMTP/
   TCP envelopes. Strip MPLS and validate the original frame when decoding;
   do not redefine cpctl fwd_bytes to make it equal capture bytes. Batch headers
   spanning epochs are reconciled at run scope, not attributed twice.
   Sequence coverage shows zero missing, duplicate or payload-corrupt records.
   Compare timestamp and direction with the profile's expected burst/ReqPattern
   convention; zero decoded timestamp/direction errors.
3. Every listed PMD/capture/pipeline/filter/direction/rate/error-drop delta is
   zero. Driver counters which are unsupported require independent audited loss
   evidence and a profile revision; silently mapping unavailable data to zero
   is forbidden. Software fwd counters mean output admission, not necessarily
   remote receipt/durability, so collector conservation remains mandatory.
4. Bounded output/hand-off backlog throughout, within a **predeclared physical
   memory and packet budget**, no OOM/crash/reset. Measure maxima continuously,
   including transport and collector queues and PMD-retained buffers. Maximum
   delivery latency ≤1 s; backlog zero at initial/final boundaries and final
   drain ≤1 s. A growing cache or oversized buffer must not turn an overloaded
   run into a pass. Record memory/CPU gauges and outstanding external references
   separately; their review is part of the full gate.

Raw RX only skips encoding/transport/receiver checks; byte touch skips actual
parsing/direction/output; null output discards the evidence; short buffered pcap
runs can borrow page-cache bandwidth and hide loss. None qualifies this profile.
Pcap storage is a separate profile requiring sustained writeback, explicit flush/
fsync and reopen/record validation after drain. A ZMQ pass says nothing about
that storage profile, VXLAN capacity or every possible output combination.

## Normalized report and executable numerical check

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s verification/dpdk -p 'test_validate_100g.py' -v
python3 verification/dpdk/validate_100g.py /path/to/normalized-report.json
~~~

The second command returns 0 for numerical consistency, 1 for missing, malformed
or failing evidence (2 for CLI misuse). Do not call a zero exit code a hardware
pass without the prerequisites and semantic qualification above. No passing
hardware report is included. The only passing fixtures are explicitly synthetic
and generated inside the unit tests. Historical artifacts are deliberately not
converted into passing evidence.

JSON schema (all counts and nanosecond fields are nonnegative integers; booleans,
strings/floats and absent counters are rejected):

| Object | Fields and interpretation |
| --- | --- |
| Root | schema_version: 1, profile: "primary-zmq-64b-v1", runs: [...]. At least three runs with distinct identities. |
| Run | Unique nonempty id; warmup_ns >= 10000000000; initial_backlog_packets = final_backlog_packets = 0; drain_ns <= 1000000000; backlog_limit_packets from the pre-run budget; windows: [...] of at least 60 consecutive epochs. Whole-run quiet-boundary tx_phy_packets/rx_phy_packets and tx_phy_bytes/rx_phy_bytes; zmq_data_batches, forwarded_bytes and receiver_message_bytes (ZMQ messages including headers/MPLS, excluding ZMTP framing). |
| Window times and frame sizes | start_ns, end_ns in one run's monotonic epoch clock, difference exactly 10000000000, next start = prior end; frame_min_bytes = frame_max_bytes = 64 including FCS. |
| Window packet deltas | generated_packets, capture_packets, forwarded_packets, receiver_unique_packets are same-epoch counts, exactly equal. tx_phy_packets/rx_phy_packets use each endpoint's calibrated 10 s sample for line-rate checking; exact physical conservation is at run scope. |
| Window byte deltas | tx_phy_bytes/rx_phy_bytes include FCS; capture_bytes/receiver_payload_bytes are original-frame bytes excluding FCS and telemetry envelope (60 per record). |
| Window zero deltas | nic_missed, nic_nombuf, capture_drop, pipeline_drop, filtered, direction_drop, ratelimit_drop, error_drop, receiver_missing, receiver_duplicate, receiver_payload_error, receiver_direction_error, receiver_timestamp_error. All required even when zero. |
| Window gauges | max_backlog_packets across all stages; max_delivery_latency_ns, measured with calibrated clocks (including receive/decode), not just the queue enqueue delay. |
| Window queues | queues: [{"id": 0, "capture_packets": ..., "capture_bytes": ...}, ...]. At least two active RSS queues, unique nonnegative IDs, same queue set within the run. Sum checked against global values; no balance requirement. |

Counter deltas must be normalized **after** validating raw widths/reset epochs
and sampled unit/remainder pairs. The script deliberately has no adapters for
cpctl formats, physical counters or ZMQ records. Retain the raw generator trace,
receiver sequence/validation summary, control/PMD/physical snapshots, calibrated
clock/length evidence, queue/backlog gauges, semantic test results, startup/
shutdown logs and restoration audit. A release reviewer must check provenance
and hashes and confirm they belong to the same binary/config/run. Invented or
incorrectly normalized JSON cannot become physical proof through this tool.

## Local validation and remaining decisions

Local validation exercises 19 synthetic gate tests: complete evidence, packet
loss/excess at every stage, each drop/semantic error, byte accounting, short
runs, gaps/overlaps, raw-RX profiles, 68B frames, underload/impossible rate,
malformed/missing counters, bad queue sums/IDs, buffering/latency, drain/warmup,
repeated IDs and CLI failures, plus exact whole-run physical conservation,
permitted live latch skew, and ZMQ message-byte accounting.

All of these passed on this host (with no DPDK installed):

~~~text
cargo build --workspace --locked
cargo test --workspace
cargo test -p cpworker --lib
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo clippy -p cpworker --all-targets
bash parity/verify_hygiene.sh
~~~

Normal cargo check -p cpworker --features dpdk exited 101 because libdpdk
development files are absent. The existing compile-only escape hatch passed:

~~~bash
CPRS_DPDK_ALLOW_MISSING=1 cargo check -p cpworker --features dpdk
~~~

That type-checks the Rust feature path only; no C shim/header compilation,
DPDK linkage or live EAL/PMD execution is validated. No feature code changed.
Validation logs are local under /tmp/ws-9jo-validation/; they are not hardware
artifacts or required dependencies of this design.

Unverified: a production primary backend/config, per-queue execution adapter,
shared limiter performance, live counter aggregation, header/FFI linkage,
MPRQ handle lifetimes, nbl support, calibrated generator/collector/normalizer,
semantic hardware tests and any sustained physical 100G run. The numerical gate
is the code increment; no per-queue Rust worker is claimed shipped.

Decisions before implementation: approve exclusive RX-only port/VF ownership
versus embedding inside the existing primary; agree the real output/profile
and collector capacity; allocate CPU/NUMA/memory budget and sustained exclusive
lab time. Changing the ±0.01%/600 s/three-run/one-second-latency profile requires
an explicit version change, not silently weakening a failed measurement.
