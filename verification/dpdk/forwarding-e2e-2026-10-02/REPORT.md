# cloud-probe forwarding and end-to-end measurement

**Final results — required sections 1–3 completed.** Final aligned tables and `selected-summary.json` supersede historical/interim rows. All 117 selected cases (including 9 recovered recvmsg rows) pass the applicable independent validation; all selected network-output accounting residuals are zero.

| Output | Rust AF_PACKET V3 highest loss-free Mpps | Plain C libpcap V3 | Plain C libpcap shipped immediate/V2 |
|---|---:|---:|---:|
| null (captured, no delivery) | ~2.0 | 2.0 | 0.5 |
| file, local ext4/NVMe (buffered) | 2.0 | 1.5 | 0.5 |
| file, tmpfs (bounded short file) | ~2.0 | ~2.0 | ~0.5 |
| ZMQ → jinjiao PULL | 2.0 | 1.5 | 1.0 |
| VXLAN → jinjiao UDP | not demonstrated: isolated EPERM host-policy drops | same limitation | same limitation |

VXLAN's capture/CPU knee is bracketed by 0.125 and 0.15 Mpps for all three backends; its cost is about 6.5–7 µs/captured packet, versus roughly 0.05 µs for Rust null. Fast Rust ring outputs hit capture/host RX loss near 2.0–2.4 Mpps with CPU below quota. Exact rates, individual CPU costs and nonmonotonic overload observations are below. No sustained durable disk or whole-system one-core capacity is claimed.

**Most valuable defect:** the exact benchmark Rust binary claims 1,000 packets forwarded with zero output drops when writing into /dev/full, despite 898 ENOSPC write-error logs. Blocking RTC I/O under locks and missing ZMTP partial-disconnect drop accounting are also source-evidenced. No source fixes are included.

**Restored and independently verified:** VFs=0, PF PAUSE rx/tx on, no benchmark processes/cores/DPDK runtime files, hugepages equal the original baseline, worker cgroup removed, NFS statfs/RPC pass. Checked-out branches/worktrees unchanged; an outside push advanced origin/main during the run, recorded in the audit and left intact. No commits, pushes, fetches or ref mutations were issued by this workflow; tools/oneboot was untouched.


Started continuation 2026-10-02 UTC. Results are appended after each completed output sweep. Raw cases/configs/packet-socket diagnostics are in `/tmp/forwarding-e2e/`; saved runs are reused, not regenerated silently.

Product worker limits: `cpu.max=100000 100000`, `memory.max=536870912`, `memory.swap.max=0`. Only cpworker is in this cgroup; generator and receiver are outside. Affinity 48–49 allows migration, but aggregate CPU quota is one core. Run-to-completion execution model, one capture task/output, 64-byte Ethernet frames (68 NIC physical bytes including FCS), no configured BPF/rate limit. Capture ring buffer configured 8 MiB (explicit bench size; shipped config default is 256 MiB). Rust shipped backend is `libpcap` with `ring:true`, implemented directly with AF_PACKET TPACKET_V3. Saved/new comparable ring rows set timeout_ms=1000; Rust ring retirement is 1 ms regardless (verify source/diag), whereas C libpcap uses V3 for this timeout. C timeout omitted means immediate/V2. Socket diagnostics prove backend selection.

Input: laojun ens72np0/VF 0000:46:00.1 → yinjiao ens8np0/ens8v0 (0000:b8:00.1, MAC 1a:ca:0a:26:a8:8c), paced `/tmp/capacity_tx`, four TX queues. Physical tests serialized with `/tmp/legacy-probe/physical.lock`; 100 GbE carries NFS. Output peer: yinjiao ens5f0 (10.0.0.11) → jinjiao ens5f0 (10.0.0.10), 25 GbE. Receiver counts validated inner frames using C libzmq PULL or UDP recvmmsg/SO_RXQ_OVFL. `pcap_file` is the descriptive output name; actual config is `type:file`, `file.name` (type:pcap_file is a capturer).

File destinations: `/dev/shm/fwdbench.pcap` is tmpfs; `/tmp/forwarding-e2e/out.pcap` is local ext4 on LVM backed by Samsung NVMe devices, not NFS. Buffered-write delivery is parsed complete pcap records after worker shutdown, independently cross-checked with repo pcap_file reader; post-run fsync time is separate. This is short-burst buffered file throughput, not sustained durable disk throughput. tmpfs tests are shortened to stay below 512 MiB because file pages are charged to the worker cgroup.

Counter windows: packet totals use quiet snapshots before generation and after drain/publication, divided by generator burst duration (normally 4 s). C publishes every 5 s: waits 5.2 s before, 5.8 s after; Rust waits 1.2/2.5 s. CPU uses cgroup usage deltas only across ~0.2 s sample intervals whose physical PF RX rate is within ±10% of burst offered rate. CPU window therefore differs from packet window. Rates near the boundary are short-burst observations, not a sustained certified limit. No CPU extrapolation from null proves real-output capacity. A disk, output device, peer, or capture path can bind before the worker quota.

Cells labelled not measured are genuinely absent; no counter-derived rate is substituted for a receiver count. Output fwd counters mean accepted by the output API/queue, not necessarily delivered. Closed e2e accounting uses observed drop counters, never the downstream gap itself as an invented drop counter. Final restore verification is appended at the end.

### 1. Recovered Rust ring results — null

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `rv3-null-2m` / 1.999920 | 1.999920 / 1.999920 / —; 9.6%; 0 | not measured | not measured |
| `rv3-null-2.4m` / 2.400000 | 2.394175 / 2.394175 / —; 11.5%; 0 | 2.359757 / 2.359757 / —; 17.7%; 0 | not measured |
| `rv3-null-3m` / 2.999944 | 2.447234 / 2.447234 / —; 11.9%; 0 | 2.450181 / 2.450181 / —; 18.5%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `rv3-null-2m` | 0 | 0 | 0 / 0 / 0 | 511,979,520 | n/a; ZMTP final queue=0 B | 1.4 | 3.66 |
| `rv3-null-2.4m` | 0 | 23,298 | 0 / 0 / 0 | 612,908,928 | n/a; ZMTP final queue=0 B | 1.5 | 3.68 |
| `rv3-null-3m` | 0 | 2,210,840 | 0 / 0 / 0 | 626,491,904 | n/a; ZMTP final queue=0 B | 1.5 | 3.67 |

Measured loss-free point: 1.999920 Mpps.
First measured non-loss-free offered load: 2.400000 Mpps (inspect startup/steady-state and drop attribution below).

### 1. Recovered Rust ring results — file_disk

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `rv3-file_disk-2m` / 2.000000 | 2.000000 / 2.000000 / 2.000000; 31.4%; 0 | not measured | not measured |
| `rv3-file_disk-2.4m` / 2.400000 | 2.385733 / 2.385733 / 2.385733; 31.5%; 0 | 2.397931 / 2.397931 / 2.397931; 41.2%; 0 | not measured |
| `rv3-file_disk-3m` / 3.000000 | 2.451375 / 2.451375 / 2.451375; 33.0%; 0 | 2.472119 / 2.472119 / 2.472119; 46.4%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `rv3-file_disk-2m` | 0 | 0 | 0 / 0 / 0 | 512,000,000 | 8,000,000 / file records / 0 / 0; file=640,000,024 B, fsync=0.000s; ZMTP final queue=0 B | 512.0 | 3.73 |
| `rv3-file_disk-2.4m` | 0 | 57,067 | 0 / 0 / 0 | 610,747,712 | 9,542,933 / file records / 0 / 0; file=763,434,664 B, fsync=0.000s; ZMTP final queue=0 B | 512.0 | 3.76 |
| `rv3-file_disk-3m` | 0 | 2,194,500 | 0 / 0 / 0 | 627,552,000 | 9,805,500 / file records / 0 / 0; file=784,440,024 B, fsync=0.000s; ZMTP final queue=0 B | 512.0 | 3.76 |

Measured loss-free point: 2.000000 Mpps.
First measured non-loss-free offered load: 2.400000 Mpps (inspect startup/steady-state and drop attribution below).

### 1. Recovered Rust ring results — file_shm

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `rv3-file_shm-2m` / 2.000034 | 2.000034 / 2.000034 / 2.000034; 19.8%; 0 | not measured | not measured |
| `rv3-file_shm-2.4m` / 2.400040 | 2.386871 / 2.386871 / 2.386871; 23.5%; 0 | 2.366019 / 2.366019 / 2.366019; 34.1%; 0 | not measured |
| `rv3-file_shm-3m` / 3.000000 | 2.563665 / 2.563665 / 2.563665; 24.4%; 0 | 2.488206 / 2.488206 / 2.488206; 36.0%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `rv3-file_shm-2m` | 0 | 0 | 0 / 0 / 0 | 243,204,096 | 3,800,064 / file records / 0 / 0; file=304,005,144 B, fsync=0.000s; ZMTP final queue=0 B | 292.0 | 1.55 |
| `rv3-file_shm-2.4m` | 0 | 20,852 | 0 / 0 / 0 | 241,869,568 | 3,779,212 / file records / 0 / 0; file=302,336,984 B, fsync=0.000s; ZMTP final queue=0 B | 290.4 | 1.40 |
| `rv3-file_shm-3m` | 0 | 552,691 | 0 / 0 / 0 | 207,827,776 | 3,247,309 / file records / 0 / 0; file=259,784,744 B, fsync=0.000s; ZMTP final queue=0 B | 249.8 | 1.10 |

Measured loss-free point: 2.000034 Mpps.
First measured non-loss-free offered load: 2.400040 Mpps (inspect startup/steady-state and drop attribution below).

### 1. Recovered Rust ring results — zmq

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `rv3-zmq-2m` / 2.000000 | 1.982443 / 1.982443 / 1.982443; 23.7%; 0 | not measured | not measured |
| `rv3-zmq-2.4m` / 2.400000 | 2.395452 / 2.395452 / 2.395452; 15.8%; 0 | 2.311310 / 2.311310 / 2.311310; 44.5%; 0 | not measured |
| `rv3-zmq-3m` / 3.000000 | 2.540662 / 2.540662 / 2.540662; 16.5%; 0 | 2.366964 / 2.366964 / 2.366964; 43.9%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `rv3-zmq-2m` | 70,227 | 0 | 0 / 0 / 0 | 681,976,102 | 7,929,773 / 651 / 0 / 0; ZMTP final queue=0 B | 49.8 | 3.77 |
| `rv3-zmq-2.4m` | 0 | 18,192 | 0 / 0 / 0 | 824,054,352 | 9,581,808 / 786 / 0 / 0; ZMTP final queue=0 B | 4.8 | 3.73 |
| `rv3-zmq-3m` | 0 | 1,837,350 | 0 / 0 / 0 | 874,007,916 | 10,162,650 / 834 / 0 / 0; ZMTP final queue=0 B | 4.7 | 3.87 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 2.000000 Mpps (inspect startup/steady-state and drop attribution below).

### 1. Recovered Rust ring results — vxlan

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `rv3-vxlan-0.08m` / 0.080000 | 0.080000 / 0.080000 / 0.080000; 52.9%; 2 | 0.080000 / 0.079999 / 0.079999; 50.6%; 3 | not measured |
| `rv3-vxlan-0.15m` / 0.150016 | 0.148896 / 0.148895 / 0.148895; 99.9%; 2 | 0.150016 / 0.150016 / 0.150016; 99.9%; 1 | not measured |
| `rv3-vxlan-0.3m` / 0.300000 | 0.153678 / 0.153678 / 0.153678; 99.8%; 1 | 0.154059 / 0.154058 / 0.154058; 100.0%; 2 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `rv3-vxlan-0.08m` | 0 | 0 | 2 / 0 / 0 | 23,039,856 | 319,998 / 319998 / 0 / 0; ZMTP final queue=0 B | 1.7 | 3.88 |
| `rv3-vxlan-0.15m` | 4,480 | 0 | 2 / 0 / 0 | 42,881,904 | 595,582 / 595582 / 0 / 0; ZMTP final queue=0 B | 1.7 | 3.61 |
| `rv3-vxlan-0.3m` | 585,288 | 0 | 1 / 0 / 0 | 44,259,192 | 614,711 / 614711 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.94 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 0.080000 Mpps (inspect startup/steady-state and drop attribution below).

### Continuation validity correction

Saved network-output rows left the default output-host exclusion enabled: empty configured BPF is not an empty effective filter when a peer exists (`config.rs:324–340`). They remain visible as historical data, but the continuation explicitly sets `not_filter_output_hosts:true` for a truly empty filter. Null/file saved rows have no output hosts and are unaffected. New network rows warm 20 kpps for 1 s, wait for drain, and subtract receiver warmup counters; measured points describe established forwarding. The first setup found orphan generator runtime files in laojun `/var/run/dpdk/rte` from the prior attempt; the restore path removed them and all restore checks passed before retrying.

### Completed continuation sweep — rv3 / null

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-null-0.25m` / 0.250016 | 0.250016 / 0.250016 / —; 1.2%; 0 | not measured | not measured |
| `cont-rv3-null-0.5m` / 0.500000 | 0.500000 / 0.500000 / —; 2.5%; 0 | not measured | 0.500000 / 0.500000 / —; 28.7%; 0 |
| `cont-rv3-null-1m` / 1.000000 | 1.000000 / 1.000000 / —; 5.7%; 0 | not measured | 0.999843 / 0.999843 / —; 42.8%; 0 |
| `cont-rv3-null-1.5m` / 1.500000 | 1.500000 / 1.500000 / —; 7.4%; 0 | 1.500000 / 1.500000 / —; 12.8%; 0 | 1.374329 / 1.374329 / —; 71.5%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-null-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | n/a; ZMTP final queue=0 B | 1.4 | 3.94 |
| `cont-rv3-null-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | n/a; ZMTP final queue=0 B | 1.4 | 3.91 |
| `cont-rv3-null-1m` | 0 | 0 | 0 / 0 / 0 | 256,000,000 | n/a; ZMTP final queue=0 B | 1.4 | 3.94 |
| `cont-rv3-null-1.5m` | 0 | 0 | 0 / 0 / 0 | 384,000,000 | n/a; ZMTP final queue=0 B | 1.4 | 3.73 |

Measured loss-free point: 1.500000 Mpps.
No knee bracketed by these rows.

### Source-evidenced output defects (written before remaining sweeps)

1. **File failures are counted as forwarded, with a per-packet error-log storm.** [Rust file.rs:83](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/output/file.rs:83) logs `PcapWriter::write` failure, then unconditionally increments fwd_bytes/fwd_packets and returns success. `destroy` also only logs failed flush. Controlled offline replay of 1,000 64-byte packets into `/dev/full` produced 898 ENOSPC write-error log lines, yet `cap_packets=1000`, `fwd_packets=1000`, `fwd_bytes=64000`, `error_drop_packets=0`; the sink stores no data. Evidence: `full-repro-config.json`, `full-repro-stats.json`, `full-repro.log`. Repro used local release binary SHA256 930bd05696dedce38819f81557abd2a5a7bf9453be6a70105d744320224aaced, separate from the physical benchmark binary. This proves the current source behavior, not a loss observed in successful disk runs. [C output_file.c:43](/home/vader/code/netis/cloud-probe-github/cpworker/src/output_file.c:43) likewise calls void pcap_dump and unconditionally counts forwarding without checking FILE errors. Proposed follow-up: latch file failure, correctly attribute uncommitted buffered packets, bound logging, and expose flush failure; do not claim per-packet durable delivery from buffered acceptance.

2. **RTC holds the manager and output-set locks across blocking output I/O.** [task.rs:740](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/task.rs:740) retains `mgr.lock()` in the RTC branch; [task.rs:506](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/task.rs:506) retains `out_sets.lock()` while capture invokes the sink. File BufWriter flushes synchronously into write(2); [output/mod.rs:37](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/output/mod.rs:37) calls socket.send_to; VXLAN's socket is blocking and ENOBUFS retry sleeps are inside that locked loop [vxlan.rs:214](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/output/vxlan.rs:214). A slow disk/egress can therefore halt capture, delay stats/reload, and cause upstream drops even below quota. This is a source-evidenced stall hazard; no deliberate peer/disk stall was injected in the throughput sweeps.

3. **ZMQ forwarded does not mean received; partial reconnect loss lacks a packet drop callback.** [zmq.rs:349](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/output/zmq.rs:349) counts a batch when accepted by ZMTP. [zmtp/client.rs:549](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/zmtp/client.rs:549) drops a partially written frame on disconnect, while OutputStats is not notified. Queue gauges can later reach zero with those counted packets missing at the receiver. Stable-peer sweeps validate equality independently; they do not test failure semantics.

Copy evidence: ZMQ copies payload into the ~1 MiB batch then into a framed owned queue buffer [zmtp/client.rs:338](/home/vader/code/netis/cloud-probe-rs/crates/cpworker/src/zmtp/client.rs:338); this is an extra full batch copy per send, not evidence of an O(n²) copy storm. VXLAN reuses a preallocated buffer, copies one frame, and makes one sendto syscall per packet. Its measured microsecond-level cost is consistent with per-packet kernel transmission; source alone cannot apportion CPU among kernel functions. No performance fix or repository edit is made here.

### Completed continuation sweep — rv3 / file_disk

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-file_disk-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 4.2%; 0 | not measured | not measured |
| `cont-rv3-file_disk-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 7.2%; 0 | not measured | not measured |
| `cont-rv3-file_disk-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 13.3%; 0 | not measured | not measured |
| `cont-rv3-file_disk-1.5m` / 1.500000 | 1.500000 / 1.500000 / 1.500000; 21.4%; 0 | 1.500000 / 1.500000 / 1.500000; 29.0%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-file_disk-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.007s; ZMTP final queue=0 B | 80.0 | 3.97 |
| `cont-rv3-file_disk-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | 2,000,000 / file records / 0 / 0; file=160,000,024 B, fsync=0.000s; ZMTP final queue=0 B | 158.4 | 3.93 |
| `cont-rv3-file_disk-1m` | 0 | 0 | 0 / 0 / 0 | 256,000,000 | 4,000,000 / file records / 0 / 0; file=320,000,024 B, fsync=0.008s; ZMTP final queue=0 B | 315.6 | 3.94 |
| `cont-rv3-file_disk-1.5m` | 0 | 0 | 0 / 0 / 0 | 384,000,000 | 6,000,000 / file records / 0 / 0; file=480,000,024 B, fsync=0.000s; ZMTP final queue=0 B | 472.5 | 3.77 |

Measured loss-free point: 1.500000 Mpps.
No knee bracketed by these rows.

### Completed continuation sweep — rv3 / file_shm

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-file_shm-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 2.6%; 0 | not measured | not measured |
| `cont-rv3-file_shm-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 5.2%; 0 | not measured | not measured |
| `cont-rv3-file_shm-1m` / 1.000017 | 1.000017 / 1.000017 / 1.000017; 10.2%; 0 | not measured | not measured |
| `cont-rv3-file_shm-1.5m` / 1.499861 | 1.499861 / 1.499861 / 1.499861; 20.8%; 0 | 1.500025 / 1.500025 / 1.500025; 23.1%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-file_shm-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.000s; ZMTP final queue=0 B | 77.8 | 3.90 |
| `cont-rv3-file_shm-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | 2,000,000 / file records / 0 / 0; file=160,000,024 B, fsync=0.000s; ZMTP final queue=0 B | 154.3 | 3.93 |
| `cont-rv3-file_shm-1m` | 0 | 0 | 0 / 0 / 0 | 243,204,096 | 3,800,064 / file records / 0 / 0; file=304,005,144 B, fsync=0.000s; ZMTP final queue=0 B | 292.0 | 3.74 |
| `cont-rv3-file_shm-1.5m` | 0 | 0 | 0 / 0 / 0 | 243,177,472 | 3,799,648 / file records / 0 / 0; file=303,971,864 B, fsync=0.000s; ZMTP final queue=0 B | 291.8 | 2.54 |

Measured loss-free point: 1.499861 Mpps.
No knee bracketed by these rows.

### Testbed identity and interpretation

Yinjiao: Intel Xeon Gold 6430, Linux 5.15.0-187; 128 logical CPUs. Benchmark Rust SHA256 `0b43b5c6e7a21a040af5b36cd0eaf01bacb5cbeee8c1061373be2547963d289e`; C SHA256 `1b7889a5f3e43fdd22c3e12e8a109f89560a85f9f0e6b7e679a6384e73a8f210`. C dynamically links real libpcap 1.10.1 (Ubuntu package 1.10.1-4ubuntu1.22.04.2); receiver uses libzmq 4.3.4. Source identities: Rust a851e328ba2492080defa7bce06a8d42a68edc89, C d302572a0a2ddcc7455a1e96a9d27e35559b4725. Full identity/environment files are retained in the harness directory.

The generator counts only mbufs accepted by rte_eth_tx_burst. Templates vary UDP source ports across pool indices and four TX queues, with fixed IPs and destination port 49001; yinjiao VF has 11 combined RX channels. Full worker cgroup limits are saved in every before/after/sample observation. These are worker-only results: IRQ/softirq processing and receiver/generator CPU outside the cgroup are not a complete-system one-core resource budget. VF RX out-of-buffer losses at high offered load with worker CPU well below 100% establish a capture/host-RX path ceiling, not a worker-quota ceiling. No narrower attribution to RSS, a specific CPU, or DMA is claimed without profiling.

End-to-end verification is count-based: receiver validates known Ethernet/IP/UDP template and length, but the reused generator has no unique per-packet sequence ID. Equal counts plus observed drop attribution close packet-count accounting; they do not independently rule out a exactly compensating duplication/loss pair. Receiver malformed counts must remain zero. Reported file delivery is after graceful flush and independent record parsing, not power-loss durability.

### ZMQ baseline correction

The first continuation warmup subtraction produced negative post-forward gaps (receiver > measured forward count), proving the baseline was not synchronized. Warmup counts were accepted/queued before the baseline but received afterward. Those first-attempt result files are preserved under `excluded-warmup-window/` and excluded from capacity/accounting conclusions. The harness now requires warmup captured == generator accepted, warmup forwarded + output drops == captured, independently received == forwarded, and Rust queue bytes == 0 before taking the actual burst baseline. This can take longer than a fixed 2.5 s drain because idle capture waits also slow ZMTP handshake progress. No throughput conclusion is drawn from the invalid subtraction rows.

### Completed continuation sweep — rv3 / zmq

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-zmq-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 2.0%; 0 | not measured | not measured |
| `cont-rv3-zmq-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 3.9%; 0 | not measured | not measured |
| `cont-rv3-zmq-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 7.3%; 0 | not measured | not measured |
| `cont-rv3-zmq-1.5m` / 1.499984 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.500000 / 1.500000; 19.0%; 0 | not measured |
| `cont-rv3-zmq-2m` / 2.000000 | 2.000000 / 2.000000 / 2.000000; 13.6%; 0 | not measured | not measured |
| `cont-rv3-zmq-2.4m` / 2.400000 | 2.383484 / 2.383484 / 2.383484; 16.2%; 0 | 2.311310 / 2.311310 / 2.311310; 44.5%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-zmq-0.25m` | 0 | 0 | 0 / 0 / 0 | 86,007,496 | 1,000,064 / 83 / 0 / 0; ZMTP final queue=0 B | 4.5 | 3.93 |
| `cont-rv3-zmq-0.5m` | 0 | 0 | 0 / 0 / 0 | 172,003,960 | 2,000,000 / 165 / 0 / 0; ZMTP final queue=0 B | 4.5 | 3.94 |
| `cont-rv3-zmq-1m` | 0 | 0 | 0 / 0 / 0 | 344,007,896 | 4,000,000 / 329 / 0 / 0; ZMTP final queue=0 B | 4.5 | 3.97 |
| `cont-rv3-zmq-1.5m` | 0 | 0 | 0 / 0 / 0 | 516,006,328 | 5,999,936 / 493 / 0 / 0; ZMTP final queue=0 B | 4.6 | 3.75 |
| `cont-rv3-zmq-2m` | 0 | 0 | 0 / 0 / 0 | 688,015,768 | 8,000,000 / 657 / 0 / 0; ZMTP final queue=0 B | 4.6 | 3.95 |
| `cont-rv3-zmq-2.4m` | 0 | 66,065 | 0 / 0 / 0 | 819,937,178 | 9,533,935 / 782 / 0 / 0; ZMTP final queue=0 B | 4.6 | 3.76 |

Measured loss-free point: 2.000000 Mpps.
First measured non-loss-free offered load: 2.400000 Mpps (inspect startup/steady-state and drop attribution below).

### Output-stat visibility

There is exactly one output per task and one task, so aggregate output fwd/error/rate/direction counters are that output's own counters. Rust ZMQ additionally exposes `zmtp_queued_batches/bytes`; C/libzmq has no equivalent queue-byte gauge in cpctl, so a plain-libpcap C queue-byte cell cannot be expressed. Receiver message count/payload bytes are independent sink stats, not inferred from fwd bytes. File fwd_bytes excludes each 16-byte pcap record header; file length includes those headers plus the 24-byte global header. VXLAN fwd_bytes includes its 8-byte header (72 bytes per transmitted packet), but excludes outer UDP/IP/Ethernet overhead.

### Why VXLAN has isolated send failures even at low load

The new logs identify `Operation not permitted (os error 1)` (EPERM), not ENOBUFS. Read-only firewall snapshots in `yinjiao-firewall.txt` show `table inet vibing_host_egress`, output hook priority -50: established/related traffic is accepted; explicit allowed IPv4 subnets omit 10.0.0.0/24; the terminal rule contains `counter log ... limit rate 6/minute drop` followed by a chain policy accept. Thus unidirectional new UDP to the 25 GbE peer can hit a rate-limited local drop and make sendto return EPERM. This is evidence for a host-egress policy constraint, not peer saturation or a cloud-probe encapsulation defect. Existing rules are retained; no firewall change or workaround is applied.

Warmup errors are subtracted only after receiver/forwarded counts close, but the same policy can reject another packet when the measured burst resumes. Consequently a strict delivered loss-free point may remain **not demonstrated under the current host policy**, even where capture is loss-free and CPU is far below quota. The throughput knee must be reported separately from these isolated EPERM events: rising capture-socket losses and ~100% worker CPU identify the one-core capacity knee. All EPERM failures appear in output error_drop_packets and close e2e accounting.

### Completed continuation sweep — rv3 / vxlan

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-vxlan-0.05m` / 0.050016 | 0.050016 / 0.050016 / 0.050016; 34.3%; 1 | not measured | not measured |
| `cont-rv3-vxlan-0.1m` / 0.100000 | 0.100000 / 0.100000 / 0.100000; 65.8%; 1 | not measured | not measured |
| `cont-rv3-vxlan-0.125m` / 0.125024 | 0.125024 / 0.125024 / 0.125024; 85.7%; 1 | not measured | not measured |
| `cont-rv3-vxlan-0.15m` / 0.150016 | 0.136253 / 0.136252 / 0.136252; 99.9%; 1 | 0.150016 / 0.150016 / 0.150016; 99.9%; 1 | not measured |
| `cont-rv3-vxlan-0.25m` / 0.250016 | 0.134577 / 0.134577 / 0.134577; 99.9%; 1 | not measured | not measured |
| `cont-rv3-vxlan-0.5m` / 0.500000 | 0.128281 / 0.128281 / 0.128281; 99.8%; 1 | not measured | not measured |
| `cont-rv3-vxlan-1m` / 0.999952 | 0.125102 / 0.125102 / 0.125077; 99.7%; 1 | not measured | not measured |
| `cont-rv3-vxlan-1.5m` / 1.500000 | 0.099079 / 0.099079 / 0.099079; 99.5%; 0 | not measured | not measured |
| `cont-rv3-vxlan-2m` / 1.999984 | 0.154090 / 0.154090 / 0.154090; 99.9%; 1 | not measured | not measured |
| `cont-rv3-vxlan-2.4m` / 2.400000 | 0.155882 / 0.155882 / 0.155882; 100.0%; 1 | not measured | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-vxlan-0.05m` | 0 | 0 | 1 / 0 / 0 | 14,404,536 | 200,063 / 200063 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.94 |
| `cont-rv3-vxlan-0.1m` | 0 | 0 | 1 / 0 / 0 | 28,799,928 | 399,999 / 399999 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.93 |
| `cont-rv3-vxlan-0.125m` | 0 | 0 | 1 / 0 / 0 | 36,006,840 | 500,095 / 500095 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.95 |
| `cont-rv3-vxlan-0.15m` | 55,053 | 0 | 1 / 0 / 0 | 39,240,720 | 545,010 / 545010 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.80 |
| `cont-rv3-vxlan-0.25m` | 461,756 | 0 | 1 / 0 / 0 | 38,758,104 | 538,307 / 538307 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.91 |
| `cont-rv3-vxlan-0.5m` | 1,486,874 | 0 | 1 / 0 / 0 | 36,945,000 | 513,125 / 513125 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.79 |
| `cont-rv3-vxlan-1m` | 3,499,401 | 0 | 1 / 0 / 0 | 36,029,232 | 500,309 / 500309 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.74 |
| `cont-rv3-vxlan-1.5m` | 5,603,684 | 0 | 0 / 0 / 0 | 28,534,752 | 396,316 / 396316 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.92 |
| `cont-rv3-vxlan-2m` | 7,383,574 | 0 | 1 / 0 / 0 | 44,377,992 | 616,361 / 616361 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.71 |
| `cont-rv3-vxlan-2.4m` | 8,976,254 | 217 | 1 / 0 / 0 | 44,894,016 | 623,528 / 623528 / 0 / 0; ZMTP final queue=0 B | 1.4 | 3.72 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 0.050016 Mpps (inspect startup/steady-state and drop attribution below).

### Completed continuation sweep — cv3 / null

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-null-0.25m` / 0.250016 | 0.250016 / 0.250016 / —; 1.2%; 0 | 0.250016 / 0.250016 / —; 11.9%; 0 | not measured |
| `cont-cv3-null-0.5m` / 0.500000 | 0.500000 / 0.500000 / —; 2.5%; 0 | 0.500000 / 0.500000 / —; 9.0%; 0 | 0.500000 / 0.500000 / —; 28.7%; 0 |
| `cont-cv3-null-1m` / 1.000000 | 1.000000 / 1.000000 / —; 5.7%; 0 | 1.000000 / 1.000000 / —; 10.8%; 0 | 0.999843 / 0.999843 / —; 42.8%; 0 |
| `cont-cv3-null-2m` / 2.000000 | 1.999920 / 1.999920 / —; 9.6%; 0 | 2.000000 / 2.000000 / —; 15.1%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-null-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | n/a | 0.7 | 3.74 |
| `cont-cv3-null-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | n/a | 0.7 | 3.70 |
| `cont-cv3-null-1m` | 0 | 0 | 0 / 0 / 0 | 256,000,000 | n/a | 0.6 | 3.74 |
| `cont-cv3-null-2m` | 0 | 0 | 0 / 0 / 0 | 512,000,000 | n/a | 0.8 | 3.96 |

Measured loss-free point: 2.000000 Mpps.
No knee bracketed by these rows.

### Receiver tail-drop visibility

One Rust VXLAN overload row (`cont-rv3-vxlan-1m`) received 97 fewer packets than forwarded, while SO_RXQ_OVFL ancillary count stayed zero. This is an unresolved original-run residual, not an attributed drop. SO_RXQ_OVFL only reports cumulative drops on a subsequently delivered datagram; it can miss drops at the end of a burst. The existing receiver is extended to read the matching UDP socket inode's final `/proc/net/udp` drop counter before close. Subsequent UDP runs include that tail count. The original row is retained pending a serialized repeat; no historical residual is retroactively attributed from a new run. Jinjiao receiver is rebuilt in /tmp; no host sysctl is changed.

### Completed continuation sweep — cv3 / file_disk

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-file_disk-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 4.2%; 0 | 0.250016 / 0.250016 / 0.250016; 10.5%; 0 | not measured |
| `cont-cv3-file_disk-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 7.2%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 | not measured |
| `cont-cv3-file_disk-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 13.3%; 0 | 1.000000 / 1.000000 / 1.000000; 21.1%; 0 | not measured |
| `cont-cv3-file_disk-2m` / 1.999984 | 2.000000 / 2.000000 / 2.000000; 31.4%; 0 | 1.999491 / 1.999491 / 1.999491; 36.3%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-file_disk-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.001s | 79.3 | 3.78 |
| `cont-cv3-file_disk-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | 2,000,000 / file records / 0 / 0; file=160,000,024 B, fsync=0.000s | 157.8 | 3.96 |
| `cont-cv3-file_disk-1m` | 0 | 0 | 0 / 0 / 0 | 256,000,000 | 4,000,000 / file records / 0 / 0; file=320,000,024 B, fsync=0.000s | 315.0 | 3.83 |
| `cont-cv3-file_disk-2m` | 0 | 1,974 | 0 / 0 / 0 | 511,869,568 | 7,997,962 / file records / 0 / 0; file=639,836,984 B, fsync=0.001s | 512.0 | 3.61 |

Measured loss-free point: 1.000000 Mpps.
First measured non-loss-free offered load: 1.999984 Mpps (inspect startup/steady-state and drop attribution below).

### Completed continuation sweep — cv3 / file_shm

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-file_shm-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 2.6%; 0 | 0.250016 / 0.250016 / 0.250016; 6.8%; 0 | not measured |
| `cont-cv3-file_shm-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 5.2%; 0 | 0.500000 / 0.500000 / 0.500000; 13.2%; 0 | not measured |
| `cont-cv3-file_shm-1m` / 1.000017 | 1.000017 / 1.000017 / 1.000017; 10.2%; 0 | 1.000017 / 1.000017 / 1.000017; 32.1%; 0 | not measured |
| `cont-cv3-file_shm-2m` / 2.000034 | 2.000034 / 2.000034 / 2.000034; 19.8%; 0 | 2.000034 / 2.000034 / 2.000034; 30.7%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-file_shm-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.000s | 77.1 | 3.74 |
| `cont-cv3-file_shm-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | 2,000,000 / file records / 0 / 0; file=160,000,024 B, fsync=0.000s | 153.6 | 3.99 |
| `cont-cv3-file_shm-1m` | 0 | 0 | 0 / 0 / 0 | 243,204,096 | 3,800,064 / file records / 0 / 0; file=304,005,144 B, fsync=0.000s | 291.4 | 3.74 |
| `cont-cv3-file_shm-2m` | 0 | 0 | 0 / 0 / 0 | 243,204,096 | 3,800,064 / file records / 0 / 0; file=304,005,144 B, fsync=0.000s | 291.4 | 1.74 |

Measured loss-free point: 2.000034 Mpps.
No knee bracketed by these rows.

## Interim Rust summary (C sweeps still in progress)

## Completed scope: delivered limits, knees and binding constraints

Highest loss-free means every generator-accepted packet was counted at the receiver (or capture for null), with zero drops and accounting residual, in the measured short burst. It is a measured point, not a sustained maximum guarantee. Historical filtered network runs are excluded. First strict loss includes isolated host-policy errors; the separate capture-capacity knee bracket ignores those output errors and brackets the onset of socket/VF capture loss.

| Backend | Output | Highest measured loss-free Mpps | First strict lossy load Mpps | Capture-capacity knee bracket Mpps | Peak delivered Mpps (null: captured) | Constraint evidenced at knee |
|---|---|---:|---:|---|---:|---|
| rv3 | null | 1.999920 | 2.400000 | (2.000, 2.400] | 2.447234 | capture / host RX path (VF OOB); worker below quota |
| rv3 | file_disk | 2.000000 | 2.400000 | (2.000, 2.400] | 2.451375 | capture / host RX path (VF OOB); worker below quota; page cache/reclaim at 512 MiB, durable disk not certified |
| rv3 | file_shm | 2.000034 | 2.400040 | (2.000, 2.400] | 2.563665 | capture / host RX path (VF OOB); worker below quota; short bounded file, not sustainable storage |
| rv3 | zmq | 2.000000 | 2.400000 | (2.000, 2.400] | 2.383484 | capture / host RX path (VF OOB); worker below quota |
| rv3 | vxlan | none | 0.050016 | (0.125, 0.150] | 0.155882 | worker quota / capture backpressure; strict LF also affected by local EPERM policy |

## Per-packet worker CPU cost relative to null

CPU µs/captured packet = loaded-window worker CPU fraction / whole-burst captured rate × 10⁶. This combines differing CPU and packet windows, so it is an approximate empirical average, not a cycle-exact isolated output benchmark. Only loss-free points with a valid CPU window are used. Incremental cost is output minus same-backend/same-offered-target null.

| Backend | Offered target Mpps | Output | Total µs/captured packet | Increment over null µs/packet |
|---|---:|---|---:|---:|
| rv3 | 0.25 | file_disk | 0.1672 | +0.1176 |
| rv3 | 0.25 | file_shm | 0.1026 | +0.0530 |
| rv3 | 0.25 | zmq | 0.0791 | +0.0296 |
| rv3 | 0.5 | file_disk | 0.1450 | +0.0956 |
| rv3 | 0.5 | file_shm | 0.1031 | +0.0537 |
| rv3 | 0.5 | zmq | 0.0772 | +0.0279 |
| rv3 | 1 | file_disk | 0.1327 | +0.0761 |
| rv3 | 1 | file_shm | 0.1017 | +0.0452 |
| rv3 | 1 | zmq | 0.0728 | +0.0162 |
| rv3 | 1.5 | file_disk | 0.1426 | +0.0930 |
| rv3 | 1.5 | file_shm | 0.1390 | +0.0894 |
| rv3 | 1.5 | zmq | 0.1260 | +0.0764 |
| rv3 | 2 | file_disk | 0.1568 | +0.1090 |
| rv3 | 2 | file_shm | 0.0991 | +0.0513 |
| rv3 | 2 | zmq | 0.0679 | +0.0201 |
| rv3 | 0.125 | VXLAN (capture loss-free; 1 output errors; null coefficient from 0.25 Mpps extrapolated) | 6.8517 | +6.8022 |

Receiver final-drop extension validated on jinjiao without physical link traffic: 180,000 valid VXLAN datagrams sent to its local address while receiver was paused; 174,763 received + 5,237 final UDP socket drops = 180,000, malformed=0. Evidence: `receiver-test.log`. The historical 97-packet residual remains unresolved until repeated; it is not relabelled as a socket drop.

### Completed continuation sweep — cv3 / zmq

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-zmq-0.25m` / 0.249992 | 0.250016 / 0.250016 / 0.250016; 2.0%; 0 | 0.249992 / 0.249992 / 0.249992; 9.6%; 0 | not measured |
| `cont-cv3-zmq-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 3.9%; 0 | 0.500000 / 0.500000 / 0.500000; 22.4%; 0 | not measured |
| `cont-cv3-zmq-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 7.3%; 0 | 1.000000 / 1.000000 / 1.000000; 22.4%; 0 | not measured |
| `cont-cv3-zmq-1.5m` / 1.500000 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.499616 / 1.500000; 34.5%; 0 | not measured |
| `cont-cv3-zmq-2m` / 2.000000 | 2.000000 / 2.000000 / 2.000000; 13.6%; 0 | 1.994398 / 1.994398 / 1.994398; 29.3%; 0 | not measured |
| `cont-cv3-zmq-2.4m` / 2.400000 | 2.383484 / 2.383484 / 2.383484; 16.2%; 0 | 2.306407 / 2.306407 / 2.306407; 54.2%; 0 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-zmq-0.25m` | 0 | 0 | 0 / 0 / 0 | 85,999,240 | 999,968 / 83 / 0 / 0 | 4.0 | 3.71 |
| `cont-cv3-zmq-0.5m` | 0 | 0 | 0 / 0 / 0 | 172,003,960 | 2,000,000 / 165 / 0 / 0 | 3.9 | 3.82 |
| `cont-cv3-zmq-1m` | 0 | 0 | 0 / 0 / 0 | 344,007,896 | 4,000,000 / 329 / 0 / 0 | 4.1 | 3.89 |
| `cont-cv3-zmq-1.5m` | 0 | 0 | 0 / 0 / 0 | 515,879,712 | 6,000,000 / 493 / 0 / 0 | 4.1 | 3.93 |
| `cont-cv3-zmq-2m` | 21,322 | 1,088 | 0 / 0 / 0 | 686,088,460 | 7,977,590 / 655 / 0 / 0 | 5.0 | 3.80 |
| `cont-cv3-zmq-2.4m` | 255,751 | 118,622 | 0 / 0 / 0 | 793,422,090 | 9,225,627 / 757 / 0 / 0 | 4.1 | 3.81 |

Measured loss-free point: 1.500000 Mpps.
First measured non-loss-free offered load: 2.000000 Mpps (inspect startup/steady-state and drop attribution below).

### C publication/tail-batch correction

`cont-cv3-zmq-1.5m` independently delivered all 6,000,000 measured packets, but the final published fwd counter was 1,536 packets short; the receiver counted the tail after shutdown. This is a counter/publication/flush-window mismatch, not a delivered loss. That original row is retained and flagged by output-accounting validation. The drain phase now waits for captured == published forwarded + output drops and an empty Rust queue before stopping a network-output worker; this can exceed the minimum 5.8 s C wait. A new serialized 1.5 Mpps C ZMQ repeat will verify the closed counter window.

### Completed continuation sweep — cv3 / vxlan

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-vxlan-0.05m` / 0.050016 | 0.050016 / 0.050016 / 0.050016; 34.3%; 1 | 0.050016 / 0.050016 / 0.050016; 37.3%; 1 | not measured |
| `cont-cv3-vxlan-0.1m` / 0.100000 | 0.100000 / 0.100000 / 0.100000; 65.8%; 1 | 0.100000 / 0.100000 / 0.100000; 65.0%; 2 | not measured |
| `cont-cv3-vxlan-0.125m` / 0.125024 | 0.125024 / 0.125024 / 0.125024; 85.7%; 1 | 0.125024 / 0.125024 / 0.125024; 93.3%; 1 | not measured |
| `cont-cv3-vxlan-0.15m` / 0.150016 | 0.136253 / 0.136252 / 0.136252; 99.9%; 1 | 0.149190 / 0.149190 / 0.149190; 100.1%; 1 | not measured |
| `cont-cv3-vxlan-0.25m` / 0.250016 | 0.134577 / 0.134577 / 0.134577; 99.9%; 1 | 0.139166 / 0.139165 / 0.139165; 99.6%; 2 | not measured |
| `cont-cv3-vxlan-0.5m` / 0.500000 | 0.128281 / 0.128281 / 0.128281; 99.8%; 1 | 0.144816 / 0.144816 / 0.144816; 99.8%; 1 | not measured |
| `cont-cv3-vxlan-1m` / 1.000000 | 0.125102 / 0.125102 / 0.125077; 99.7%; 1 | 0.156884 / 0.156884 / 0.156884; 100.0%; 1 | not measured |
| `cont-cv3-vxlan-1.5m` / 1.499800 | 0.099079 / 0.099079 / 0.099079; 99.5%; 0 | 0.103871 / 0.103871 / 0.103871; 99.2%; 1 | not measured |
| `cont-cv3-vxlan-2m` / 1.999984 | 0.154090 / 0.154090 / 0.154090; 99.9%; 1 | 0.127576 / 0.127576 / 0.127576; 100.0%; 1 | not measured |
| `cont-cv3-vxlan-2.4m` / 2.400000 | 0.155882 / 0.155882 / 0.155882; 100.0%; 1 | 0.081142 / 0.081142 / 0.081142; 98.8%; 1 | not measured |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-vxlan-0.05m` | 0 | 0 | 1 / 0 / 0 | 14,404,536 | 200,063 / 200063 / 0 / 0 | 0.8 | 3.74 |
| `cont-cv3-vxlan-0.1m` | 0 | 0 | 2 / 0 / 0 | 28,799,856 | 399,998 / 399998 / 0 / 0 | 0.7 | 3.70 |
| `cont-cv3-vxlan-0.125m` | 0 | 0 | 1 / 0 / 0 | 36,006,840 | 500,095 / 500095 / 0 / 0 | 0.8 | 3.88 |
| `cont-cv3-vxlan-0.15m` | 3,304 | 0 | 1 / 0 / 0 | 42,966,648 | 596,759 / 596759 / 0 / 0 | 0.8 | 3.57 |
| `cont-cv3-vxlan-0.25m` | 443,400 | 0 | 2 / 0 / 0 | 40,079,664 | 556,662 / 556662 / 0 / 0 | 0.8 | 3.68 |
| `cont-cv3-vxlan-0.5m` | 1,420,736 | 0 | 1 / 0 / 0 | 41,706,936 | 579,263 / 579263 / 0 / 0 | 1.1 | 3.65 |
| `cont-cv3-vxlan-1m` | 3,372,464 | 0 | 1 / 0 / 0 | 45,182,520 | 627,535 / 627535 / 0 / 0 | 1.5 | 3.75 |
| `cont-cv3-vxlan-1.5m` | 5,582,934 | 782 | 1 / 0 / 0 | 29,914,776 | 415,483 / 415483 / 0 / 0 | 1.4 | 3.75 |
| `cont-cv3-vxlan-2m` | 7,489,632 | 0 | 1 / 0 / 0 | 36,741,816 | 510,303 / 510303 / 0 / 0 | 1.4 | 3.82 |
| `cont-cv3-vxlan-2.4m` | 9,270,264 | 5,169 | 1 / 0 / 0 | 23,368,752 | 324,566 / 324566 / 0 / 0 | 1.5 | 3.86 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 0.050016 Mpps (inspect startup/steady-state and drop attribution below).

## Interim plain-libpcap V3 summary (immediate/V2 sweeps next)

## Completed scope: delivered limits, knees and binding constraints

Highest loss-free means every generator-accepted packet was counted at the receiver (or capture for null), with zero drops and accounting residual, in the measured short burst. It is a measured point, not a sustained maximum guarantee. Historical filtered network runs are excluded. First strict loss includes isolated host-policy errors; the separate capture-capacity knee bracket ignores those output errors and brackets the onset of socket/VF capture loss.

| Backend | Output | Highest measured loss-free Mpps | First strict lossy load Mpps | Capture-capacity knee bracket Mpps | Peak delivered Mpps (null: captured) | Constraint evidenced at knee |
|---|---|---:|---:|---|---:|---|
| cv3 | null | 2.000000 | 2.400000 | (2.000, 2.400] | 2.450181 | capture / host RX path (VF OOB); worker below quota |
| cv3 | file_disk | 1.500000 | 1.999984 | (1.500, 2.000] | 2.472119 | capture / host RX path (VF OOB); worker below quota; page cache/reclaim at 512 MiB, durable disk not certified |
| cv3 | file_shm | 2.000034 | 2.400040 | (2.000, 2.400] | 2.488206 | capture / host RX path (VF OOB); worker below quota; short bounded file, not sustainable storage |
| cv3 | zmq | 1.500000 | 2.000000 | (1.500, 2.000] | 2.306407 | capture / host RX path (VF OOB); worker below quota |
| cv3 | vxlan | none | 0.050016 | (0.125, 0.150] | 0.156884 | worker quota / capture backpressure; strict LF also affected by local EPERM policy |

## Per-packet worker CPU cost relative to null

CPU µs/captured packet = loaded-window worker CPU fraction / whole-burst captured rate × 10⁶. This combines differing CPU and packet windows, so it is an approximate empirical average, not a cycle-exact isolated output benchmark. Only loss-free points with a valid CPU window are used. Incremental cost is output minus same-backend/same-offered-target null.

| Backend | Offered target Mpps | Output | Total µs/captured packet | Increment over null µs/packet |
|---|---:|---|---:|---:|
| cv3 | 0.25 | file_disk | 0.4202 | -0.0572 |
| cv3 | 0.25 | file_shm | 0.2725 | -0.2049 |
| cv3 | 0.25 | zmq | 0.3828 | -0.0946 |
| cv3 | 0.5 | file_disk | 0.5875 | +0.4066 |
| cv3 | 0.5 | file_shm | 0.2638 | +0.0829 |
| cv3 | 0.5 | zmq | 0.4487 | +0.2678 |
| cv3 | 1 | file_disk | 0.2108 | +0.1025 |
| cv3 | 1 | file_shm | 0.3213 | +0.2130 |
| cv3 | 1 | zmq | 0.2240 | +0.1158 |
| cv3 | 1.5 | file_disk | 0.1935 | +0.1085 |
| cv3 | 1.5 | file_shm | 0.1539 | +0.0689 |
| cv3 | 1.5 | zmq | 0.2298 | +0.1448 |
| cv3 | 2 | file_shm | 0.1537 | +0.0782 |
| cv3 | 0.125 | VXLAN (capture loss-free; 1 output errors; null coefficient from 0.25 Mpps extrapolated) | 7.4656 | +6.9883 |

### Completed continuation sweep — cv2 / null

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv2-null-0.25m` / 0.250016 | 0.250016 / 0.250016 / —; 1.2%; 0 | 0.250016 / 0.250016 / —; 11.9%; 0 | 0.250016 / 0.250016 / —; 19.9%; 0 |
| `cont-cv2-null-2m` / 2.000000 | 1.999920 / 1.999920 / —; 9.6%; 0 | 2.000000 / 2.000000 / —; 15.1%; 0 | 1.168124 / 1.168124 / —; 93.4%; 0 |
| `cont-cv2-null-2.4m` / 2.399984 | 2.394175 / 2.394175 / —; 11.5%; 0 | 2.359757 / 2.359757 / —; 17.7%; 0 | 1.249673 / 1.249673 / —; 98.1%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv2-null-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | n/a | 1.5 | 3.89 |
| `cont-cv2-null-2m` | 864,558 | 2,462,948 | 0 / 0 / 0 | 299,039,616 | n/a | 1.4 | 3.81 |
| `cont-cv2-null-2.4m` | 0 | 4,601,244 | 0 / 0 / 0 | 319,916,288 | n/a | 1.6 | 3.89 |

Measured loss-free point: 0.250016 Mpps.
First measured non-loss-free offered load: 2.000000 Mpps (inspect startup/steady-state and drop attribution below).

File fsync_seconds is measured after the independent parser has traversed the file, so background writeback may already have made progress during parsing. A small fsync time is not evidence that the original 4 s write burst was durable at that rate. No O_DIRECT/per-record sync or sustained disk stress was measured.

### Completed continuation sweep — cv2 / file_disk

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv2-file_disk-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 4.2%; 0 | 0.250016 / 0.250016 / 0.250016; 10.5%; 0 | 0.250016 / 0.250016 / 0.250016; 20.8%; 0 |
| `cont-cv2-file_disk-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 7.2%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 | 0.500000 / 0.500000 / 0.500000; 51.3%; 0 |
| `cont-cv2-file_disk-1m` / 0.999928 | 1.000000 / 1.000000 / 1.000000; 13.3%; 0 | 1.000000 / 1.000000 / 1.000000; 21.1%; 0 | 0.682549 / 0.682549 / 0.682549; 99.0%; 0 |
| `cont-cv2-file_disk-1.5m` / 1.500000 | 1.500000 / 1.500000 / 1.500000; 21.4%; 0 | 1.500000 / 1.500000 / 1.500000; 29.0%; 0 | 1.204432 / 1.204432 / 1.204432; 95.0%; 0 |
| `cont-cv2-file_disk-2m` / 2.000000 | 2.000000 / 2.000000 / 2.000000; 31.4%; 0 | 1.999491 / 1.999491 / 1.999491; 36.3%; 0 | 1.177669 / 1.177669 / 1.177669; 98.6%; 0 |
| `cont-cv2-file_disk-2.4m` / 2.400000 | 2.385733 / 2.385733 / 2.385733; 31.5%; 0 | 2.397931 / 2.397931 / 2.397931; 41.2%; 0 | 1.111978 / 1.111978 / 1.111978; 97.6%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv2-file_disk-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.001s | 80.1 | 3.77 |
| `cont-cv2-file_disk-0.5m` | 0 | 0 | 0 / 0 / 0 | 128,000,000 | 2,000,000 / file records / 0 / 0; file=160,000,024 B, fsync=0.000s | 158.4 | 3.74 |
| `cont-cv2-file_disk-1m` | 1,269,515 | 0 | 0 / 0 / 0 | 174,732,608 | 2,730,197 / file records / 0 / 0; file=218,415,784 B, fsync=0.001s | 215.8 | 3.68 |
| `cont-cv2-file_disk-1.5m` | 1,256 | 1,181,016 | 0 / 0 / 0 | 308,334,592 | 4,817,728 / file records / 0 / 0; file=385,418,264 B, fsync=0.000s | 379.8 | 3.91 |
| `cont-cv2-file_disk-2m` | 695,571 | 2,593,754 | 0 / 0 / 0 | 301,483,200 | 4,710,675 / file records / 0 / 0; file=376,854,024 B, fsync=0.000s | 371.6 | 3.64 |
| `cont-cv2-file_disk-2.4m` | 1,827,118 | 3,324,970 | 0 / 0 / 0 | 284,666,368 | 4,447,912 / file records / 0 / 0; file=355,832,984 B, fsync=0.000s | 350.9 | 3.70 |

Measured loss-free point: 0.500000 Mpps.
First measured non-loss-free offered load: 0.999928 Mpps (inspect startup/steady-state and drop attribution below).

### Completed continuation sweep — cv2 / file_shm

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv2-file_shm-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 2.6%; 0 | 0.250016 / 0.250016 / 0.250016; 6.8%; 0 | 0.250016 / 0.250016 / 0.250016; 19.5%; 0 |
| `cont-cv2-file_shm-0.5m` / 0.499952 | 0.500000 / 0.500000 / 0.500000; 5.2%; 0 | 0.500000 / 0.500000 / 0.500000; 13.2%; 0 | 0.499952 / 0.499952 / 0.499952; 26.3%; 0 |
| `cont-cv2-file_shm-1m` / 1.000017 | 1.000017 / 1.000017 / 1.000017; 10.2%; 0 | 1.000017 / 1.000017 / 1.000017; 32.1%; 0 | 0.962878 / 0.962878 / 0.962878; 88.5%; 0 |
| `cont-cv2-file_shm-1.5m` / 1.500025 | 1.499861 / 1.499861 / 1.499861; 20.8%; 0 | 1.500025 / 1.500025 / 1.500025; 23.1%; 0 | 1.220031 / 1.220031 / 1.220031; 94.8%; 0 |
| `cont-cv2-file_shm-2m` / 2.000034 | 2.000034 / 2.000034 / 2.000034; 19.8%; 0 | 2.000034 / 2.000034 / 2.000034; 30.7%; 0 | 1.263818 / 1.263818 / 1.263818; 99.0%; 0 |
| `cont-cv2-file_shm-2.4m` / 2.400040 | 2.386871 / 2.386871 / 2.386871; 23.5%; 0 | 2.366019 / 2.366019 / 2.366019; 34.1%; 0 | 0.746780 / 0.746780 / 0.746780; 91.0%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv2-file_shm-0.25m` | 0 | 0 | 0 / 0 / 0 | 64,004,096 | 1,000,064 / file records / 0 / 0; file=80,005,144 B, fsync=0.000s | 77.9 | 3.87 |
| `cont-cv2-file_shm-0.5m` | 0 | 0 | 0 / 0 / 0 | 127,987,712 | 1,999,808 / file records / 0 / 0; file=159,984,664 B, fsync=0.000s | 154.5 | 3.81 |
| `cont-cv2-file_shm-1m` | 141,128 | 0 | 0 / 0 / 0 | 234,171,904 | 3,658,936 / file records / 0 / 0; file=292,714,904 B, fsync=0.000s | 281.3 | 3.49 |
| `cont-cv2-file_shm-1.5m` | 0 | 709,319 | 0 / 0 / 0 | 197,807,680 | 3,090,745 / file records / 0 / 0; file=247,259,624 B, fsync=0.000s | 237.8 | 2.52 |
| `cont-cv2-file_shm-2m` | 0 | 1,398,810 | 0 / 0 / 0 | 153,680,256 | 2,401,254 / file records / 0 / 0; file=192,100,344 B, fsync=0.000s | 185.1 | 1.64 |
| `cont-cv2-file_shm-2.4m` | 2,617,020 | 643 | 0 / 0 / 0 | 75,673,664 | 1,182,401 / file records / 0 / 0; file=94,592,104 B, fsync=0.000s | 91.9 | 1.41 |

Measured loss-free point: 0.499952 Mpps.
First measured non-loss-free offered load: 1.000017 Mpps (inspect startup/steady-state and drop attribution below).

### Immediate/V2 ZMQ preflight failure

The first 0.25 Mpps V2 ZMQ case was not measured: its 20,096-packet warmup was accepted and counted forwarded by C, but PULL received 0 within the fixed drain plus 25 s barrier. This is a failed startup/connection preflight, not a zero-capacity measurement. Exact error is in `cont-cv2-zmq-0.25m-error.txt`; the restore audit passed. A retry uses a longer barrier and read-only live connection diagnostics. Failed preflights will be recorded as unmeasured and will not abort the remaining serialized VXLAN/recheck work.

C ZMQ build identity correction: the upstream worker statically links libzmq from commit `46493370217ac135246617fa2f6ac819d8b61bfc` (headers/pkgconfig identify 4.3.6), rather than the peer system libzmq 4.3.4. The receiver is dynamically linked to system libzmq 4.3.4. Real libpcap remains dynamically linked at 1.10.1. Build evidence is retained in `/tmp/legacy-probe/zmq-*` and `build-versions.txt`; benchmark binaries are unchanged.

### Completed continuation sweep — cv2 / zmq

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv2-zmq-0.25m` / 0.250016 | 0.250016 / 0.250016 / 0.250016; 2.0%; 0 | 0.249992 / 0.249992 / 0.249992; 9.6%; 0 | 0.250016 / 0.250016 / 0.250016; 17.2%; 0 |
| `cont-cv2-zmq-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 3.9%; 0 | 0.500000 / 0.500000 / 0.500000; 22.4%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 |
| `cont-cv2-zmq-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 7.3%; 0 | 1.000000 / 1.000000 / 1.000000; 22.4%; 0 | 1.000000 / 1.000000 / 1.000000; 58.3%; 0 |
| `cont-cv2-zmq-1.5m` / 1.500000 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.499616 / 1.500000; 34.5%; 0 | 1.062958 / 1.062958 / 1.062958; 99.7%; 0 |
| `cont-cv2-zmq-2m` / 1.999968 | 2.000000 / 2.000000 / 2.000000; 13.6%; 0 | 1.994398 / 1.994398 / 1.994398; 29.3%; 0 | 1.304637 / 1.304637 / 1.304637; 99.1%; 0 |
| `cont-cv2-zmq-2.4m` / 2.399968 | 2.383484 / 2.383484 / 2.383484; 16.2%; 0 | 2.306407 / 2.306407 / 2.306407; 54.2%; 0 | 0.993698 / 0.993698 / 0.993698; 79.9%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv2-zmq-0.25m` | 0 | 0 | 0 / 0 / 0 | 86,007,496 | 1,000,064 / 83 / 0 / 0 | 4.1 | 3.71 |
| `cont-cv2-zmq-0.5m` | 0 | 0 | 0 / 0 / 0 | 172,003,960 | 2,000,000 / 165 / 0 / 0 | 4.1 | 3.76 |
| `cont-cv2-zmq-1m` | 0 | 0 | 0 / 0 / 0 | 344,007,896 | 4,000,000 / 329 / 0 / 0 | 4.1 | 3.78 |
| `cont-cv2-zmq-1.5m` | 1,748,166 | 0 | 0 / 0 / 0 | 365,666,100 | 4,251,834 / 349 / 0 / 0 | 4.0 | 3.80 |
| `cont-cv2-zmq-2m` | 0 | 2,781,322 | 0 / 0 / 0 | 448,805,596 | 5,218,550 / 429 / 0 / 0 | 4.0 | 3.76 |
| `cont-cv2-zmq-2.4m` | 4,217,437 | 1,407,645 | 0 / 0 / 0 | 341,839,788 | 3,974,790 / 327 / 0 / 0 | 4.0 | 3.78 |

Measured loss-free point: 1.000000 Mpps.
First measured non-loss-free offered load: 1.500000 Mpps (inspect startup/steady-state and drop attribution below).

### Live packet-socket diagnostics

| Property | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| tpacket | TPACKET_V3 | TPACKET_V3 | TPACKET_V2 |
| ring_bytes | 7626752 | 8388608 | 16150528 |
| block_size | 1089536 | 262144 | 4096 |
| block_nr | 7 | 32 | 3943 |
| frame_size | 2128 | 262144 | 2128 |
| frame_nr | 3584 | 32 | 3943 |
| retire_tmo | 1 | 1000 | 0 |

Backend diagnostics are live AF_PACKET socket/ring observations, not inferred from the libpcap compiled-feature version string. The same nominal 8 MiB buffer request produces different ring geometry in C V2; actual ring_bytes is reported above. Idle timeout/retirement differs between implementations even when the JSON timeout key matches.

### Completed continuation sweep — cv2 / vxlan

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv2-vxlan-0.05m` / 0.050016 | 0.050016 / 0.050016 / 0.050016; 34.3%; 1 | 0.050016 / 0.050016 / 0.050016; 37.3%; 1 | 0.050016 / 0.050016 / 0.050016; 35.2%; 1 |
| `cont-cv2-vxlan-0.1m` / 0.100000 | 0.100000 / 0.100000 / 0.100000; 65.8%; 1 | 0.100000 / 0.100000 / 0.100000; 65.0%; 2 | 0.100000 / 0.100000 / 0.100000; 68.0%; 1 |
| `cont-cv2-vxlan-0.125m` / 0.125024 | 0.125024 / 0.125024 / 0.125024; 85.7%; 1 | 0.125024 / 0.125024 / 0.125024; 93.3%; 1 | 0.125024 / 0.125024 / 0.125024; 83.3%; 2 |
| `cont-cv2-vxlan-0.15m` / 0.150016 | 0.136253 / 0.136252 / 0.136252; 99.9%; 1 | 0.149190 / 0.149190 / 0.149190; 100.1%; 1 | 0.136563 / 0.136563 / 0.136563; 100.0%; 1 |
| `cont-cv2-vxlan-0.25m` / 0.250016 | 0.134577 / 0.134577 / 0.134577; 99.9%; 1 | 0.139166 / 0.139165 / 0.139165; 99.6%; 2 | 0.121551 / 0.121551 / 0.121551; 99.9%; 1 |
| `cont-cv2-vxlan-0.5m` / 0.500000 | 0.128281 / 0.128281 / 0.128281; 99.8%; 1 | 0.144816 / 0.144816 / 0.144816; 99.8%; 1 | 0.124777 / 0.124777 / 0.124777; 99.8%; 1 |
| `cont-cv2-vxlan-1m` / 1.000000 | 0.125102 / 0.125102 / 0.125077; 99.7%; 1 | 0.156884 / 0.156884 / 0.156884; 100.0%; 1 | 0.143997 / 0.143997 / 0.143997; 99.9%; 1 |
| `cont-cv2-vxlan-1.5m` / 1.500000 | 0.099079 / 0.099079 / 0.099079; 99.5%; 0 | 0.103871 / 0.103871 / 0.103871; 99.2%; 1 | 0.090410 / 0.090410 / 0.090410; 99.6%; 2 |
| `cont-cv2-vxlan-2m` / 2.000000 | 0.154090 / 0.154090 / 0.154090; 99.9%; 1 | 0.127576 / 0.127576 / 0.127576; 100.0%; 1 | 0.062940 / 0.062940 / 0.062940; 100.0%; 2 |
| `cont-cv2-vxlan-2.4m` / 2.400000 | 0.155882 / 0.155882 / 0.155882; 100.0%; 1 | 0.081142 / 0.081142 / 0.081142; 98.8%; 1 | 0.066944 / 0.066944 / 0.066944; 100.0%; 1 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv2-vxlan-0.05m` | 0 | 0 | 1 / 0 / 0 | 14,404,536 | 200,063 / 200063 / 0 / 0 | 0.8 | 3.95 |
| `cont-cv2-vxlan-0.1m` | 0 | 0 | 1 / 0 / 0 | 28,799,928 | 399,999 / 399999 / 0 / 0 | 0.8 | 3.94 |
| `cont-cv2-vxlan-0.125m` | 0 | 0 | 2 / 0 / 0 | 36,006,768 | 500,094 / 500094 / 0 / 0 | 0.8 | 3.96 |
| `cont-cv2-vxlan-0.15m` | 53,813 | 0 | 1 / 0 / 0 | 39,330,000 | 546,250 / 546250 / 0 / 0 | 0.8 | 3.94 |
| `cont-cv2-vxlan-0.25m` | 513,860 | 0 | 1 / 0 / 0 | 35,006,616 | 486,203 / 486203 / 0 / 0 | 0.8 | 3.72 |
| `cont-cv2-vxlan-0.5m` | 1,500,892 | 0 | 1 / 0 / 0 | 35,935,704 | 499,107 / 499107 / 0 / 0 | 0.8 | 3.73 |
| `cont-cv2-vxlan-1m` | 3,424,011 | 0 | 1 / 0 / 0 | 41,471,136 | 575,988 / 575988 / 0 / 0 | 0.8 | 3.91 |
| `cont-cv2-vxlan-1.5m` | 5,638,359 | 0 | 2 / 0 / 0 | 26,038,008 | 361,639 / 361639 / 0 / 0 | 0.9 | 3.83 |
| `cont-cv2-vxlan-2m` | 7,748,239 | 0 | 2 / 0 / 0 | 18,126,648 | 251,759 / 251759 / 0 / 0 | 0.8 | 3.83 |
| `cont-cv2-vxlan-2.4m` | 9,332,083 | 142 | 1 / 0 / 0 | 19,279,728 | 267,774 / 267774 / 0 / 0 | 0.8 | 3.87 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 0.050016 Mpps (inspect startup/steady-state and drop attribution below).

### Completed continuation sweep — cv3 / zmq

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-cv3-zmq-0.25m` / 0.249992 | 0.250016 / 0.250016 / 0.250016; 2.0%; 0 | 0.249992 / 0.249992 / 0.249992; 9.6%; 0 | 0.250016 / 0.250016 / 0.250016; 17.2%; 0 |
| `cont-cv3-zmq-0.5m` / 0.500000 | 0.500000 / 0.500000 / 0.500000; 3.9%; 0 | 0.500000 / 0.500000 / 0.500000; 22.4%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 |
| `cont-cv3-zmq-1m` / 1.000000 | 1.000000 / 1.000000 / 1.000000; 7.3%; 0 | 1.000000 / 1.000000 / 1.000000; 22.4%; 0 | 1.000000 / 1.000000 / 1.000000; 58.3%; 0 |
| `cont-cv3-zmq-1.5m` / 1.500000 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.499616 / 1.500000; 34.5%; 0 | 1.062958 / 1.062958 / 1.062958; 99.7%; 0 |
| `cont-cv3-zmq-1.5m-recheck` / 1.500000 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.500000 / 1.500000; 25.4%; 0 | 1.062958 / 1.062958 / 1.062958; 99.7%; 0 |
| `cont-cv3-zmq-2m` / 2.000000 | 2.000000 / 2.000000 / 2.000000; 13.6%; 0 | 1.994398 / 1.994398 / 1.994398; 29.3%; 0 | 1.304637 / 1.304637 / 1.304637; 99.1%; 0 |
| `cont-cv3-zmq-2.4m` / 2.400000 | 2.383484 / 2.383484 / 2.383484; 16.2%; 0 | 2.306407 / 2.306407 / 2.306407; 54.2%; 0 | 0.993698 / 0.993698 / 0.993698; 79.9%; 0 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-cv3-zmq-0.25m` | 0 | 0 | 0 / 0 / 0 | 85,999,240 | 999,968 / 83 / 0 / 0 | 4.0 | 3.71 |
| `cont-cv3-zmq-0.5m` | 0 | 0 | 0 / 0 / 0 | 172,003,960 | 2,000,000 / 165 / 0 / 0 | 3.9 | 3.82 |
| `cont-cv3-zmq-1m` | 0 | 0 | 0 / 0 / 0 | 344,007,896 | 4,000,000 / 329 / 0 / 0 | 4.1 | 3.89 |
| `cont-cv3-zmq-1.5m` | 0 | 0 | 0 / 0 / 0 | 515,879,712 | 6,000,000 / 493 / 0 / 0 | 4.1 | 3.93 |
| `cont-cv3-zmq-1.5m-recheck` | 0 | 0 | 0 / 0 / 0 | 516,011,832 | 6,000,000 / 493 / 0 / 0 | 4.0 | 3.76 |
| `cont-cv3-zmq-2m` | 21,322 | 1,088 | 0 / 0 / 0 | 686,088,460 | 7,977,590 / 655 / 0 / 0 | 5.0 | 3.80 |
| `cont-cv3-zmq-2.4m` | 255,751 | 118,622 | 0 / 0 / 0 | 793,422,090 | 9,225,627 / 757 / 0 / 0 | 4.1 | 3.81 |

Measured loss-free point: 1.500000 Mpps.
First measured non-loss-free offered load: 2.000000 Mpps (inspect startup/steady-state and drop attribution below).

### Completed continuation sweep — rv3 / vxlan

Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.

| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |
|---|---|---|---|
| `cont-rv3-vxlan-0.05m` / 0.050016 | 0.050016 / 0.050016 / 0.050016; 34.3%; 1 | 0.050016 / 0.050016 / 0.050016; 37.3%; 1 | 0.050016 / 0.050016 / 0.050016; 35.2%; 1 |
| `cont-rv3-vxlan-0.1m` / 0.100000 | 0.100000 / 0.100000 / 0.100000; 65.8%; 1 | 0.100000 / 0.100000 / 0.100000; 65.0%; 2 | 0.100000 / 0.100000 / 0.100000; 68.0%; 1 |
| `cont-rv3-vxlan-0.125m` / 0.125024 | 0.125024 / 0.125024 / 0.125024; 85.7%; 1 | 0.125024 / 0.125024 / 0.125024; 93.3%; 1 | 0.125024 / 0.125024 / 0.125024; 83.3%; 2 |
| `cont-rv3-vxlan-0.15m` / 0.150016 | 0.136253 / 0.136252 / 0.136252; 99.9%; 1 | 0.149190 / 0.149190 / 0.149190; 100.1%; 1 | 0.136563 / 0.136563 / 0.136563; 100.0%; 1 |
| `cont-rv3-vxlan-0.25m` / 0.250016 | 0.134577 / 0.134577 / 0.134577; 99.9%; 1 | 0.139166 / 0.139165 / 0.139165; 99.6%; 2 | 0.121551 / 0.121551 / 0.121551; 99.9%; 1 |
| `cont-rv3-vxlan-0.5m` / 0.500000 | 0.128281 / 0.128281 / 0.128281; 99.8%; 1 | 0.144816 / 0.144816 / 0.144816; 99.8%; 1 | 0.124777 / 0.124777 / 0.124777; 99.8%; 1 |
| `cont-rv3-vxlan-1m` / 0.999952 | 0.125102 / 0.125102 / 0.125077; 99.7%; 1 | 0.156884 / 0.156884 / 0.156884; 100.0%; 1 | 0.143997 / 0.143997 / 0.143997; 99.9%; 1 |
| `cont-rv3-vxlan-1m-recheck` / 1.000000 | 0.119450 / 0.119450 / 0.119450; 99.8%; 1 | 0.156884 / 0.156884 / 0.156884; 100.0%; 1 | 0.143997 / 0.143997 / 0.143997; 99.9%; 1 |
| `cont-rv3-vxlan-1.5m` / 1.500000 | 0.099079 / 0.099079 / 0.099079; 99.5%; 0 | 0.103871 / 0.103871 / 0.103871; 99.2%; 1 | 0.090410 / 0.090410 / 0.090410; 99.6%; 2 |
| `cont-rv3-vxlan-2m` / 1.999984 | 0.154090 / 0.154090 / 0.154090; 99.9%; 1 | 0.127576 / 0.127576 / 0.127576; 100.0%; 1 | 0.062940 / 0.062940 / 0.062940; 100.0%; 2 |
| `cont-rv3-vxlan-2.4m` / 2.400000 | 0.155882 / 0.155882 / 0.155882; 100.0%; 1 | 0.081142 / 0.081142 / 0.081142; 98.8%; 1 | 0.066944 / 0.066944 / 0.066944; 100.0%; 1 |

| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |
|---|---:|---:|---|---:|---|---:|---:|
| `cont-rv3-vxlan-0.05m` | 0 | 0 | 1 / 0 / 0 | 14,404,536 | 200,063 / 200063 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.94 |
| `cont-rv3-vxlan-0.1m` | 0 | 0 | 1 / 0 / 0 | 28,799,928 | 399,999 / 399999 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.93 |
| `cont-rv3-vxlan-0.125m` | 0 | 0 | 1 / 0 / 0 | 36,006,840 | 500,095 / 500095 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.95 |
| `cont-rv3-vxlan-0.15m` | 55,053 | 0 | 1 / 0 / 0 | 39,240,720 | 545,010 / 545010 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.80 |
| `cont-rv3-vxlan-0.25m` | 461,756 | 0 | 1 / 0 / 0 | 38,758,104 | 538,307 / 538307 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.91 |
| `cont-rv3-vxlan-0.5m` | 1,486,874 | 0 | 1 / 0 / 0 | 36,945,000 | 513,125 / 513125 / 0 / 0; ZMTP final queue=0 B | 1.6 | 3.79 |
| `cont-rv3-vxlan-1m` | 3,499,401 | 0 | 1 / 0 / 0 | 36,029,232 | 500,309 / 500309 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.74 |
| `cont-rv3-vxlan-1m-recheck` | 3,522,199 | 0 | 1 / 0 / 0 | 34,401,600 | 477,800 / 477800 / 0 / 0; ZMTP final queue=0 B | 2.4 | 3.75 |
| `cont-rv3-vxlan-1.5m` | 5,603,684 | 0 | 0 / 0 / 0 | 28,534,752 | 396,316 / 396316 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.92 |
| `cont-rv3-vxlan-2m` | 7,383,574 | 0 | 1 / 0 / 0 | 44,377,992 | 616,361 / 616361 / 0 / 0; ZMTP final queue=0 B | 1.5 | 3.71 |
| `cont-rv3-vxlan-2.4m` | 8,976,254 | 217 | 1 / 0 / 0 | 44,894,016 | 623,528 / 623528 / 0 / 0; ZMTP final queue=0 B | 1.4 | 3.72 |

No strictly loss-free point in these rows.
First measured non-loss-free offered load: 0.050016 Mpps (inspect startup/steady-state and drop attribution below).

## Final aligned comparisons (supersede earlier interim tables)

One selected row per backend/output/offered target. New rechecks supersede the original ambiguous windows for conclusions; original raw records remain available. Each cell is captured / API-forwarded / independently delivered Mpps; loaded-window CPU; output drops. Null has no delivered rate. C V3 means real libpcap timeout_ms=1000; C V2 means real libpcap shipped timeout omitted/immediate mode. C is never relabelled AF_PACKET direct implementation.

### null

| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---:|---|---|---|
| 0.25 | 0.250016 / 0.250016 / —; 1.2%; 0 | 0.250016 / 0.250016 / —; 11.9%; 0 | 0.250016 / 0.250016 / —; 19.9%; 0 |
| 0.5 | 0.500000 / 0.500000 / —; 2.5%; 0 | 0.500000 / 0.500000 / —; 9.0%; 0 | 0.500000 / 0.500000 / —; 28.7%; 0 |
| 1 | 1.000000 / 1.000000 / —; 5.7%; 0 | 1.000000 / 1.000000 / —; 10.8%; 0 | 0.999843 / 0.999843 / —; 42.8%; 0 |
| 1.5 | 1.500000 / 1.500000 / —; 7.4%; 0 | 1.500000 / 1.500000 / —; 12.8%; 0 | 1.374329 / 1.374329 / —; 71.5%; 0 |
| 2 | 1.999920 / 1.999920 / —; 9.6%; 0 | 2.000000 / 2.000000 / —; 15.1%; 0 | 1.168124 / 1.168124 / —; 93.4%; 0 |
| 2.4 | 2.394175 / 2.394175 / —; 11.5%; 0 | 2.359757 / 2.359757 / —; 17.7%; 0 | 1.249673 / 1.249673 / —; 98.1%; 0 |
| 3 | 2.447234 / 2.447234 / —; 11.9%; 0 | 2.450181 / 2.450181 / —; 18.5%; 0 | not measured |

### file_disk

| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---:|---|---|---|
| 0.25 | 0.250016 / 0.250016 / 0.250016; 4.2%; 0 | 0.250016 / 0.250016 / 0.250016; 10.5%; 0 | 0.250016 / 0.250016 / 0.250016; 20.8%; 0 |
| 0.5 | 0.500000 / 0.500000 / 0.500000; 7.2%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 | 0.500000 / 0.500000 / 0.500000; 51.3%; 0 |
| 1 | 1.000000 / 1.000000 / 1.000000; 13.3%; 0 | 1.000000 / 1.000000 / 1.000000; 21.1%; 0 | 0.682549 / 0.682549 / 0.682549; 99.0%; 0 |
| 1.5 | 1.500000 / 1.500000 / 1.500000; 21.4%; 0 | 1.500000 / 1.500000 / 1.500000; 29.0%; 0 | 1.204432 / 1.204432 / 1.204432; 95.0%; 0 |
| 2 | 2.000000 / 2.000000 / 2.000000; 31.4%; 0 | 1.999491 / 1.999491 / 1.999491; 36.3%; 0 | 1.177669 / 1.177669 / 1.177669; 98.6%; 0 |
| 2.4 | 2.385733 / 2.385733 / 2.385733; 31.5%; 0 | 2.397931 / 2.397931 / 2.397931; 41.2%; 0 | 1.111978 / 1.111978 / 1.111978; 97.6%; 0 |
| 3 | 2.451375 / 2.451375 / 2.451375; 33.0%; 0 | 2.472119 / 2.472119 / 2.472119; 46.4%; 0 | not measured |

### file_shm

| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---:|---|---|---|
| 0.25 | 0.250016 / 0.250016 / 0.250016; 2.6%; 0 | 0.250016 / 0.250016 / 0.250016; 6.8%; 0 | 0.250016 / 0.250016 / 0.250016; 19.5%; 0 |
| 0.5 | 0.500000 / 0.500000 / 0.500000; 5.2%; 0 | 0.500000 / 0.500000 / 0.500000; 13.2%; 0 | 0.499952 / 0.499952 / 0.499952; 26.3%; 0 |
| 1 | 1.000017 / 1.000017 / 1.000017; 10.2%; 0 | 1.000017 / 1.000017 / 1.000017; 32.1%; 0 | 0.962878 / 0.962878 / 0.962878; 88.5%; 0 |
| 1.5 | 1.499861 / 1.499861 / 1.499861; 20.8%; 0 | 1.500025 / 1.500025 / 1.500025; 23.1%; 0 | 1.220031 / 1.220031 / 1.220031; 94.8%; 0 |
| 2 | 2.000034 / 2.000034 / 2.000034; 19.8%; 0 | 2.000034 / 2.000034 / 2.000034; 30.7%; 0 | 1.263818 / 1.263818 / 1.263818; 99.0%; 0 |
| 2.4 | 2.386871 / 2.386871 / 2.386871; 23.5%; 0 | 2.366019 / 2.366019 / 2.366019; 34.1%; 0 | 0.746780 / 0.746780 / 0.746780; 91.0%; 0 |
| 3 | 2.563665 / 2.563665 / 2.563665; 24.4%; 0 | 2.488206 / 2.488206 / 2.488206; 36.0%; 0 | not measured |

### zmq

| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---:|---|---|---|
| 0.25 | 0.250016 / 0.250016 / 0.250016; 2.0%; 0 | 0.249992 / 0.249992 / 0.249992; 9.6%; 0 | 0.250016 / 0.250016 / 0.250016; 17.2%; 0 |
| 0.5 | 0.500000 / 0.500000 / 0.500000; 3.9%; 0 | 0.500000 / 0.500000 / 0.500000; 22.4%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 |
| 1 | 1.000000 / 1.000000 / 1.000000; 7.3%; 0 | 1.000000 / 1.000000 / 1.000000; 22.4%; 0 | 1.000000 / 1.000000 / 1.000000; 58.3%; 0 |
| 1.5 | 1.499984 / 1.499984 / 1.499984; 18.9%; 0 | 1.500000 / 1.500000 / 1.500000; 25.4%; 0 | 1.062958 / 1.062958 / 1.062958; 99.7%; 0 |
| 2 | 2.000000 / 2.000000 / 2.000000; 13.6%; 0 | 1.994398 / 1.994398 / 1.994398; 29.3%; 0 | 1.304637 / 1.304637 / 1.304637; 99.1%; 0 |
| 2.4 | 2.383484 / 2.383484 / 2.383484; 16.2%; 0 | 2.306407 / 2.306407 / 2.306407; 54.2%; 0 | 0.993698 / 0.993698 / 0.993698; 79.9%; 0 |

### vxlan

| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---:|---|---|---|
| 0.05 | 0.050016 / 0.050016 / 0.050016; 34.3%; 1 | 0.050016 / 0.050016 / 0.050016; 37.3%; 1 | 0.050016 / 0.050016 / 0.050016; 35.2%; 1 |
| 0.1 | 0.100000 / 0.100000 / 0.100000; 65.8%; 1 | 0.100000 / 0.100000 / 0.100000; 65.0%; 2 | 0.100000 / 0.100000 / 0.100000; 68.0%; 1 |
| 0.125 | 0.125024 / 0.125024 / 0.125024; 85.7%; 1 | 0.125024 / 0.125024 / 0.125024; 93.3%; 1 | 0.125024 / 0.125024 / 0.125024; 83.3%; 2 |
| 0.15 | 0.136253 / 0.136252 / 0.136252; 99.9%; 1 | 0.149190 / 0.149190 / 0.149190; 100.1%; 1 | 0.136563 / 0.136563 / 0.136563; 100.0%; 1 |
| 0.25 | 0.134577 / 0.134577 / 0.134577; 99.9%; 1 | 0.139166 / 0.139165 / 0.139165; 99.6%; 2 | 0.121551 / 0.121551 / 0.121551; 99.9%; 1 |
| 0.5 | 0.128281 / 0.128281 / 0.128281; 99.8%; 1 | 0.144816 / 0.144816 / 0.144816; 99.8%; 1 | 0.124777 / 0.124777 / 0.124777; 99.8%; 1 |
| 1 | 0.119450 / 0.119450 / 0.119450; 99.8%; 1 | 0.156884 / 0.156884 / 0.156884; 100.0%; 1 | 0.143997 / 0.143997 / 0.143997; 99.9%; 1 |
| 1.5 | 0.099079 / 0.099079 / 0.099079; 99.5%; 0 | 0.103871 / 0.103871 / 0.103871; 99.2%; 1 | 0.090410 / 0.090410 / 0.090410; 99.6%; 2 |
| 2 | 0.154090 / 0.154090 / 0.154090; 99.9%; 1 | 0.127576 / 0.127576 / 0.127576; 100.0%; 1 | 0.062940 / 0.062940 / 0.062940; 100.0%; 2 |
| 2.4 | 0.155882 / 0.155882 / 0.155882; 100.0%; 1 | 0.081142 / 0.081142 / 0.081142; 98.8%; 1 | 0.066944 / 0.066944 / 0.066944; 100.0%; 1 |

## Completed scope: delivered limits, knees and binding constraints

Highest loss-free means every generator-accepted packet was counted at the receiver (or capture for null), with zero drops and accounting residual, in the measured short burst. It is a measured point, not a sustained maximum guarantee. Historical filtered network runs are excluded. First strict loss includes isolated host-policy errors; the separate capture-capacity knee bracket ignores those output errors and brackets the onset of socket/VF capture loss.

| Backend | Output | Highest measured loss-free Mpps | First strict lossy load Mpps | Capture-capacity knee bracket Mpps | Peak delivered Mpps (null: captured) | Constraint evidenced at knee |
|---|---|---:|---:|---|---:|---|
| rv3 | null | 1.999920 | 2.400000 | (2.000, 2.400] | 2.447234 | capture / host RX path (VF OOB); worker below quota |
| rv3 | file_disk | 2.000000 | 2.400000 | (2.000, 2.400] | 2.451375 | capture / host RX path (VF OOB); worker below quota; page cache/reclaim at 512 MiB, durable disk not certified |
| rv3 | file_shm | 2.000034 | 2.400040 | (2.000, 2.400] | 2.563665 | capture / host RX path (VF OOB); worker below quota; short bounded file, not sustainable storage |
| rv3 | zmq | 2.000000 | 2.400000 | (2.000, 2.400] | 2.383484 | capture / host RX path (VF OOB); worker below quota |
| rv3 | vxlan | none | 0.050016 | (0.125, 0.150] | 0.155882 | one-core CPU saturation at higher loads; capture/RX backpressure; strict LF also affected by local EPERM policy |
| cv3 | null | 2.000000 | 2.400000 | (2.000, 2.400] | 2.450181 | capture / host RX path (VF OOB); worker below quota |
| cv3 | file_disk | 1.500000 | 1.999984 | (1.500, 2.000] | 2.472119 | capture / host RX path (VF OOB); worker below quota; page cache/reclaim at 512 MiB, durable disk not certified |
| cv3 | file_shm | 2.000034 | 2.400040 | (2.000, 2.400] | 2.488206 | capture / host RX path (VF OOB); worker below quota; short bounded file, not sustainable storage |
| cv3 | zmq | 1.500000 | 2.000000 | (1.500, 2.000] | 2.306407 | capture / host RX path (VF OOB); worker below quota |
| cv3 | vxlan | none | 0.050016 | (0.125, 0.150] | 0.156884 | one-core CPU saturation at higher loads; capture/RX backpressure; strict LF also affected by local EPERM policy |
| cv2 | null | 0.500000 | 1.000000 | (0.500, 1.000] | 1.374329 | one-core CPU saturation at higher loads; capture/RX backpressure |
| cv2 | file_disk | 0.500000 | 0.999928 | (0.500, 1.000] | 1.204432 | one-core CPU saturation at higher loads; capture/RX backpressure; page cache/reclaim at 512 MiB, durable disk not certified |
| cv2 | file_shm | 0.499952 | 1.000017 | (0.500, 1.000] | 1.263818 | one-core CPU saturation at higher loads; capture/RX backpressure; short bounded file, not sustainable storage |
| cv2 | zmq | 1.000000 | 1.500000 | (1.000, 1.500] | 1.304637 | one-core CPU saturation at higher loads; capture/RX backpressure |
| cv2 | vxlan | none | 0.050016 | (0.125, 0.150] | 0.143997 | one-core CPU saturation at higher loads; capture/RX backpressure; strict LF also affected by local EPERM policy |
| rrecv | null | 0.500000 | not bracketed | > 0.500; not bracketed | 0.500000 | no measured capacity knee |
| rrecv | file_disk | 0.500000 | not bracketed | > 0.500; not bracketed | 0.500000 | no measured capacity knee; page cache/reclaim at 512 MiB, durable disk not certified |
| rrecv | file_shm | 0.500000 | not bracketed | > 0.500; not bracketed | 0.500000 | no measured capacity knee; short bounded file, not sustainable storage |

## Per-packet worker CPU cost relative to null

CPU µs/captured packet = loaded-window worker CPU fraction / whole-burst captured rate × 10⁶. This combines differing CPU and packet windows, so it is an approximate empirical average, not a cycle-exact isolated output benchmark. Output points are loss-free with a valid CPU window. Incremental cost is output minus same-backend/same-offered-target null; a null baseline with ≥99.9% captured and <90% worker CPU may be used if its tiny capture loss is explicitly labelled.

| Backend | Offered target Mpps | Output | Total µs/captured packet | Increment over null µs/packet |
|---|---:|---|---:|---:|
| rv3 | 0.25 | file_disk | 0.1672 | +0.1176 |
| rv3 | 0.25 | file_shm | 0.1026 | +0.0530 |
| rv3 | 0.25 | zmq | 0.0791 | +0.0296 |
| rv3 | 0.5 | file_disk | 0.1450 | +0.0956 |
| rv3 | 0.5 | file_shm | 0.1031 | +0.0537 |
| rv3 | 0.5 | zmq | 0.0772 | +0.0279 |
| rv3 | 1 | file_disk | 0.1327 | +0.0761 |
| rv3 | 1 | file_shm | 0.1017 | +0.0452 |
| rv3 | 1 | zmq | 0.0728 | +0.0162 |
| rv3 | 1.5 | file_disk | 0.1426 | +0.0930 |
| rv3 | 1.5 | file_shm | 0.1390 | +0.0894 |
| rv3 | 1.5 | zmq | 0.1260 | +0.0764 |
| rv3 | 2 | file_disk | 0.1568 | +0.1090 |
| rv3 | 2 | file_shm | 0.0991 | +0.0513 |
| rv3 | 2 | zmq | 0.0679 | +0.0201 |
| rv3 | 0.125 | VXLAN (capture loss-free; 1 output errors; null coefficient from 0.25 Mpps extrapolated) | 6.8517 | +6.8022 |
| cv3 | 0.25 | file_disk | 0.4202 | -0.0572 |
| cv3 | 0.25 | file_shm | 0.2725 | -0.2049 |
| cv3 | 0.25 | zmq | 0.3828 | -0.0946 |
| cv3 | 0.5 | file_disk | 0.5875 | +0.4066 |
| cv3 | 0.5 | file_shm | 0.2638 | +0.0829 |
| cv3 | 0.5 | zmq | 0.4487 | +0.2678 |
| cv3 | 1 | file_disk | 0.2108 | +0.1025 |
| cv3 | 1 | file_shm | 0.3213 | +0.2130 |
| cv3 | 1 | zmq | 0.2240 | +0.1158 |
| cv3 | 1.5 | file_disk | 0.1935 | +0.1085 |
| cv3 | 1.5 | file_shm | 0.1539 | +0.0689 |
| cv3 | 1.5 | zmq | 0.1695 | +0.0844 |
| cv3 | 2 | file_shm | 0.1537 | +0.0782 |
| cv3 | 0.125 | VXLAN (capture loss-free; 1 output errors; null coefficient from 0.25 Mpps extrapolated) | 7.4656 | +6.9883 |
| cv2 | 0.25 | file_disk | 0.8311 | +0.0352 |
| cv2 | 0.25 | file_shm | 0.7782 | -0.0177 |
| cv2 | 0.25 | zmq | 0.6868 | -0.1091 |
| cv2 | 0.5 | file_disk | 1.0251 | +0.4518 |
| cv2 | 0.5 | file_shm | 0.5263 | -0.0470 |
| cv2 | 0.5 | zmq | 0.5885 | +0.0153 |
| cv2 | 1 | zmq (null capture loss 0.0157%) | 0.5833 | +0.1554 |
| cv2 | 0.125 | VXLAN (capture loss-free; 2 output errors; null coefficient from 0.25 Mpps extrapolated) | 6.6654 | +5.8695 |
| rrecv | 0.2 | file_disk | 1.3856 | +0.1772 |
| rrecv | 0.2 | file_shm | 1.2894 | +0.0810 |
| rrecv | 0.35 | file_disk | 1.5658 | +0.2572 |
| rrecv | 0.35 | file_shm | 1.4019 | +0.0933 |
| rrecv | 0.5 | file_disk | 1.4078 | +0.0352 |
| rrecv | 0.5 | file_shm | 1.2570 | -0.1156 |

Single short bursts include CPU-frequency, scheduler and idle-poll variation; low-load C measurements vary materially, and some matched differences can be slightly negative. These are measurement differences, not negative physical output cost. Do not extrapolate a low-load coefficient to a certified capacity. VXLAN is several microseconds per captured packet; null/file/ZMQ are sub-microsecond in these ring rows. Source and the 100% CPU knee support that order of magnitude, while precise output-only CPU attribution would require repeated/profiled runs.

## 3. Generator → probe → jinjiao receiver: independent accounting

ZMQ PUSH connects to `tcp://10.0.0.10:19555`; jinjiao libzmq PULL parses the batch header and every MPLS-tagged inner record. VXLAN sends UDP to jinjiao `10.0.0.10:19556`; receiver.c uses recvmmsg and validates the inner frame, recording kernel SO_RXQ_OVFL separately. Receivers are outside worker quota. Measured warmup is excluded only after closed-count/empty-queue barrier.

The equation tested is **generator accepted = receiver received + capture-socket drops + VF OOB + output drops + receiver socket drops**. A nonzero residual is an unresolved gap, never counted as an attributed drop.

| Case | Generator accepted | Receiver received | Capture drops (socket + VF) | Output drops | Receiver socket drops | Unattributed residual |
|---|---:|---:|---:|---:|---:|---:|
| `cont-cv2-vxlan-0.05m` | 200,064 | 200,063 | 0 | 1 | 0 | 0 |
| `cont-cv2-vxlan-0.1m` | 400,000 | 399,999 | 0 | 1 | 0 | 0 |
| `cont-cv2-vxlan-0.125m` | 500,096 | 500,094 | 0 | 2 | 0 | 0 |
| `cont-cv2-vxlan-0.15m` | 600,064 | 546,250 | 53,813 | 1 | 0 | 0 |
| `cont-cv2-vxlan-0.25m` | 1,000,064 | 486,203 | 513,860 | 1 | 0 | 0 |
| `cont-cv2-vxlan-0.5m` | 2,000,000 | 499,107 | 1,500,892 | 1 | 0 | 0 |
| `cont-cv2-vxlan-1m` | 4,000,000 | 575,988 | 3,424,011 | 1 | 0 | 0 |
| `cont-cv2-vxlan-1.5m` | 6,000,000 | 361,639 | 5,638,359 | 2 | 0 | 0 |
| `cont-cv2-vxlan-2m` | 8,000,000 | 251,759 | 7,748,239 | 2 | 0 | 0 |
| `cont-cv2-vxlan-2.4m` | 9,600,000 | 267,774 | 9,332,225 | 1 | 0 | 0 |
| `cont-cv2-zmq-0.25m` | 1,000,064 | 1,000,064 | 0 | 0 | 0 | 0 |
| `cont-cv2-zmq-0.5m` | 2,000,000 | 2,000,000 | 0 | 0 | 0 | 0 |
| `cont-cv2-zmq-1m` | 4,000,000 | 4,000,000 | 0 | 0 | 0 | 0 |
| `cont-cv2-zmq-1.5m` | 6,000,000 | 4,251,834 | 1,748,166 | 0 | 0 | 0 |
| `cont-cv2-zmq-2m` | 7,999,872 | 5,218,550 | 2,781,322 | 0 | 0 | 0 |
| `cont-cv2-zmq-2.4m` | 9,599,872 | 3,974,790 | 5,625,082 | 0 | 0 | 0 |
| `cont-cv3-vxlan-0.05m` | 200,064 | 200,063 | 0 | 1 | 0 | 0 |
| `cont-cv3-vxlan-0.1m` | 400,000 | 399,998 | 0 | 2 | 0 | 0 |
| `cont-cv3-vxlan-0.125m` | 500,096 | 500,095 | 0 | 1 | 0 | 0 |
| `cont-cv3-vxlan-0.15m` | 600,064 | 596,759 | 3,304 | 1 | 0 | 0 |
| `cont-cv3-vxlan-0.25m` | 1,000,064 | 556,662 | 443,400 | 2 | 0 | 0 |
| `cont-cv3-vxlan-0.5m` | 2,000,000 | 579,263 | 1,420,736 | 1 | 0 | 0 |
| `cont-cv3-vxlan-1m` | 4,000,000 | 627,535 | 3,372,464 | 1 | 0 | 0 |
| `cont-cv3-vxlan-1.5m` | 5,999,200 | 415,483 | 5,583,716 | 1 | 0 | 0 |
| `cont-cv3-vxlan-2m` | 7,999,936 | 510,303 | 7,489,632 | 1 | 0 | 0 |
| `cont-cv3-vxlan-2.4m` | 9,600,000 | 324,566 | 9,275,433 | 1 | 0 | 0 |
| `cont-cv3-zmq-0.25m` | 999,968 | 999,968 | 0 | 0 | 0 | 0 |
| `cont-cv3-zmq-0.5m` | 2,000,000 | 2,000,000 | 0 | 0 | 0 | 0 |
| `cont-cv3-zmq-1m` | 4,000,000 | 4,000,000 | 0 | 0 | 0 | 0 |
| `cont-cv3-zmq-1.5m-recheck` | 6,000,000 | 6,000,000 | 0 | 0 | 0 | 0 |
| `cont-cv3-zmq-2m` | 8,000,000 | 7,977,590 | 22,410 | 0 | 0 | 0 |
| `cont-cv3-zmq-2.4m` | 9,600,000 | 9,225,627 | 374,373 | 0 | 0 | 0 |
| `cont-rv3-vxlan-0.05m` | 200,064 | 200,063 | 0 | 1 | 0 | 0 |
| `cont-rv3-vxlan-0.1m` | 400,000 | 399,999 | 0 | 1 | 0 | 0 |
| `cont-rv3-vxlan-0.125m` | 500,096 | 500,095 | 0 | 1 | 0 | 0 |
| `cont-rv3-vxlan-0.15m` | 600,064 | 545,010 | 55,053 | 1 | 0 | 0 |
| `cont-rv3-vxlan-0.25m` | 1,000,064 | 538,307 | 461,756 | 1 | 0 | 0 |
| `cont-rv3-vxlan-0.5m` | 2,000,000 | 513,125 | 1,486,874 | 1 | 0 | 0 |
| `cont-rv3-vxlan-1m-recheck` | 4,000,000 | 477,800 | 3,522,199 | 1 | 0 | 0 |
| `cont-rv3-vxlan-1.5m` | 6,000,000 | 396,316 | 5,603,684 | 0 | 0 | 0 |
| `cont-rv3-vxlan-2m` | 7,999,936 | 616,361 | 7,383,574 | 1 | 0 | 0 |
| `cont-rv3-vxlan-2.4m` | 9,600,000 | 623,528 | 8,976,471 | 1 | 0 | 0 |
| `cont-rv3-zmq-0.25m` | 1,000,064 | 1,000,064 | 0 | 0 | 0 | 0 |
| `cont-rv3-zmq-0.5m` | 2,000,000 | 2,000,000 | 0 | 0 | 0 | 0 |
| `cont-rv3-zmq-1m` | 4,000,000 | 4,000,000 | 0 | 0 | 0 | 0 |
| `cont-rv3-zmq-1.5m` | 5,999,936 | 5,999,936 | 0 | 0 | 0 | 0 |
| `cont-rv3-zmq-2m` | 8,000,000 | 8,000,000 | 0 | 0 | 0 | 0 |
| `cont-rv3-zmq-2.4m` | 9,600,000 | 9,533,935 | 66,065 | 0 | 0 | 0 |

Independent validation: 117/117 selected cases pass all applicable worker-budget, capture/output/e2e accounting, packet-format and file-parser checks. Details: `continuation-validation.json`.

### Exact benchmark-binary defect reproduction

After the physical sweeps stopped, the same 1,000-packet `/dev/full` replay was run on yinjiao using the exact measured Rust binary (SHA256 0b43b5c6e7a21a040af5b36cd0eaf01bacb5cbeee8c1061373be2547963d289e). Result was identical: 1,000 captured and claimed forwarded, zero error_drop_packets, 898 ENOSPC write logs, and no data can be stored by /dev/full. Evidence: `full-repro-exact-stats.json`, `full-repro-exact.log`, `full-repro-exact-output.txt`. This confirms that the defect is present in the benchmark binary, not merely a different local build. The replay used offline pcap input and did not send physical packets.

### Recheck outcomes and selection

The C V3 ZMQ 1.5 Mpps recheck has 6,000,000 generator-accepted == captured == published forwarded == receiver-received, zero drops. The Rust VXLAN 1 Mpps overload recheck has captured 477,801, forwarded/received 477,800, and one output error; capture losses account for the rest of 4,000,000 accepted input frames. Its independent downstream residual is zero. These rechecks supersede the two ambiguous original rows for conclusions. The original 97-packet residual remains preserved as unresolved historical evidence; no retrospective attribution was fabricated. The first V2 ZMQ preflight was retried successfully, and all six V2 ZMQ offered-load cells were measured.

## 4. Recovered recvmsg appendix; DPDK deferred

No additional physical recvmsg/DPDK sweep was run after the required ring/plain-libpcap/e2e work. Existing unfiltered recvmsg null/file rows are reused below; highest tested point 0.5 Mpps is loss-free, and its knee is not bracketed. Historical recvmsg network rows had default output-host BPF and are excluded from no-BPF conclusions. dpdk_pdump forwarding capacity is unmeasured in this continuation.

| Output / offered target Mpps | Rust recvmsg ring:false | Rust AF_PACKET ring:true | Plain libpcap C V3 | Plain libpcap C default/V2 |
|---|---|---|---|---|
| null / 0.2 | 0.200000 / 0.200000 / —; 24.2%; 0 | not measured | not measured | not measured |
| null / 0.35 | 0.350016 / 0.350016 / —; 45.8%; 0 | not measured | not measured | not measured |
| null / 0.5 | 0.500000 / 0.500000 / —; 68.6%; 0 | 0.500000 / 0.500000 / —; 2.5%; 0 | 0.500000 / 0.500000 / —; 9.0%; 0 | 0.500000 / 0.500000 / —; 28.7%; 0 |
| file_disk / 0.2 | 0.200000 / 0.200000 / 0.200000; 27.7%; 0 | not measured | not measured | not measured |
| file_disk / 0.35 | 0.350016 / 0.350016 / 0.350016; 54.8%; 0 | not measured | not measured | not measured |
| file_disk / 0.5 | 0.500000 / 0.500000 / 0.500000; 70.4%; 0 | 0.500000 / 0.500000 / 0.500000; 7.2%; 0 | 0.500000 / 0.500000 / 0.500000; 29.4%; 0 | 0.500000 / 0.500000 / 0.500000; 51.3%; 0 |
| file_shm / 0.2 | 0.199976 / 0.199976 / 0.199976; 25.8%; 0 | not measured | not measured | not measured |
| file_shm / 0.35 | 0.350016 / 0.350016 / 0.350016; 49.1%; 0 | not measured | not measured | not measured |
| file_shm / 0.5 | 0.500000 / 0.500000 / 0.500000; 62.8%; 0 | 0.500000 / 0.500000 / 0.500000; 5.2%; 0 | 0.500000 / 0.500000 / 0.500000; 13.2%; 0 | 0.499952 / 0.499952 / 0.499952; 26.3%; 0 |

## Restoration and final verification

Physical sweeps and offline reproductions have stopped. A fresh independent audit (`final-audit.json`) verifies **both hosts VFs=0; PF PAUSE autoneg off, rx on, tx on; 100 GbE links up; no cpworker/transmitter/DPDK primary; /var/run/dpdk empty or absent; no core files; hugepage configured/free/surplus counts exactly match the original saved baseline; jinjiao receiver stopped; NFS /cold statfs and NFS RPC NULL both pass**. Laojun hugepages remain node0=4/node1=27; yinjiao node0=628/node1=396. The worker cgroup and output files were removed. Firewall rules and persistent host sysctls were left intact; IPv6 was disabled only on the temporary VFs, which were removed.

Repository audit qualification: the all-refs equality check in the final harness restore failed because Rust `origin/main` advanced from 4f15bd5d806f6d07b5e88f245380a424d9a073cb to 4b37b29a06e591e69064105222383db7a6fe24a3. Reflog records `update by push` at 2026-10-02 11:25:34 UTC; symbolic origin/HEAD resolves to the new tracking tip. This workflow issued no commit/push/fetch/ref mutation commands and leaves that outside change intact. Checked-out Rust main/HEAD remains a851e328ba2492080defa7bce06a8d42a68edc89; C HEAD remains d302572a0a2ddcc7455a1e96a9d27e35559b4725; both source worktree status snapshots are unchanged. Rust's pre-existing untracked .beads/issues.jsonl remains. No branch changes or tools/oneboot edits were made.

117/117 selected cases pass fresh independent validation; all selected ZMQ/VXLAN end-to-end residuals are zero. Exact configs and diagnostics remain per case. `selected-summary.json` and `continuation-validation.json` are the selected data/validation, while cumulative results.jsonl also retains discarded first attempts. Harness Python syntax checks pass, receiver C was compiled and its tail-drop accounting tested, and the file defect was reproduced on the exact measured binary. Local /tmp Beads follow-ups: fwdbench-agh (file failure accounting/log storm), fwdbench-48l (RTC blocking I/O and ZMTP reconnect accounting). No source fix is included.

Null-output microbenchmarks are not real-output capacity. Under this worker-only budget, capture/host RX binds the fast ring outputs near 2 Mpps, VXLAN consumes roughly a core near 0.15 Mpps, and the current host egress policy prevents a demonstrated strict VXLAN loss-free point. Buffered disk throughput and the peer's capacity remain separate constraints; these short runs do not certify sustained durable disk throughput or a complete-system one-core budget.

