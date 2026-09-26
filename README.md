![CI](https://github.com/vaderyang/cloud-probe-rs/actions/workflows/ci.yml/badge.svg)

# cloud-probe-rs — Netis Cloud Probe (Rust port)

A standalone Rust port of Netis Cloud Probe. The original C + Go implementation lives in
a separate checkout; set `CLOUD_PROBE_SRC` when running the differential/fuzz harnesses in `parity/`.

## Crates

| Crate | Replaces | Notes |
|-------|----------|-------|
| `cpworker` | `cpworker/` (C, CMake) | Packet engine: capture → task → outputs |
| `cpgolib` | `cpgolib/` (Go) | cpworker unix-socket client + stats/info models + logging |
| `cpctl` | `cpctl/` (Go) | CLI: `version`, `info`, `ping`, `stats` |
| `cpdaemon` | `cpdaemon/` (Go) | Management daemon + CPM sync |
| `dockerpid` | `cptools/dockerpid/` (Go) | Docker container host PID |
| `cripid` | `cptools/cripid/` (Go) | CRI container host PID |

## Build

```bash
# from this directory
cargo build --workspace          # debug
cargo build --release --workspace
cargo test --workspace
```

Binaries land in `target/debug/` (or `target/release/`).

### System dependencies

* **libpcap** (development headers) — `cpworker` capture / savefiles
* **libzmq** (development headers) — `cpworker` ZMQ output
* **protoc** — only for `cripid` code generation (`proto/api.proto` is vendored)

On Debian/Ubuntu:

```bash
sudo apt-get install -y libpcap-dev libzmq3-dev protobuf-compiler
```

## Run

```bash
# cpworker
target/debug/cpworker -c ../cpworker/examples/libpcap_null.json

# cpctl (against a running cpworker)
target/debug/cpctl -u /path/to/cpworker.sock info
target/debug/cpctl -u /path/to/cpworker.sock stats -n 1

# cpdaemon
target/debug/cpdaemon -c config.json server

# container PID helpers
target/debug/dockerpid <containerId>
target/debug/cripid <containerId>
```

`cpworker` needs raw-socket capabilities for live capture:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/cpworker
```

## Migration status

Faithfully ported:

* **cpworker** — config model/parser (serde replaces cJSON), logging, stats,
  packet parsing/checksums/fragmentation, req_pattern mini-language,
  ring buffer, all outputs (`null`, `file`, `rotating_file`, `gre`, `vxlan`
  incl. splitting, `zmq` incl. heartbeat), libpcap + pcap-file capturers,
  task manager (RTC + pipeline), unix JSON-RPC control plane, signals/reload.
  The C unit tests that covered packet splitting, req_pattern, config and
  stats are ported (see `cargo test`).
* **cpgolib**, **cpctl**, **dockerpid**, **cripid** — full ports.

Reduced-scope port (`cpdaemon`):

* Worker lifecycle, cgroup-v2 CPU limiting, CPM HTTP client and models, and a
  functional register/strategy/metrics sync loop are ported.
* **Not** ported: the full `worker_task_builder` heuristics (container/VM
  resolution via dockerpid/cripid/virsh, memory-policy tuning), PKCS#12 client
  certificates, sync-log batching, and NIC-change detection.
  See `crates/cpdaemon/src/cpm/syncer.rs` for the documented simplifications.

## Layout

```
cloud-probe-rs/
├── Cargo.toml                 # workspace
├── parity/                    # C-vs-Rust differential + fuzz harnesses
├── bench/                     # C-vs-Rust benchmarks (throughput / RSS)
├── fuzz.sh                    # cargo-fuzz runner
├── deny.toml                  # cargo-deny policy
└── crates/
    ├── cpworker/
    │   └── src/
    │       ├── capturer/      # libpcap, pcap_file
    │       ├── output/        # null, file, rotating_file, gre, vxlan, zmq
    │       ├── config.rs      # JSON config (serde)
    │       ├── packet.rs      # L2–L4 parsing
    │       ├── packet_split.rs
    │       ├── req_pattern.rs
    │       ├── ring_buffer.rs
    │       ├── task.rs
    │       └── unix_manager.rs
    ├── cpgolib/
    ├── cpctl/
    ├── cpdaemon/
    ├── dockerpid/
    ├── cripid/
    └── sim/                   # Deterministic Simulation Testing (DST)
```

## Benchmarks: C vs Rust

Measured against the reference C `cpworker` from
[netis/cloud-probe](https://github.com/netis/cloud-probe) (`0.9.x`, built with
`CMAKE_BUILD_TYPE=Release`). Both binaries replay the **same 1,000,000-packet
PCAP** (417.5 MB, mixed Ethernet/IPv4/UDP frames) through a `pcap_file`
capturer. Timing stops when the capturer logs `end of file`; peak RSS is the
process `VmHWM`. Median of 3 runs after a warmup.

**Machine:** 4 cores, Intel Core M-5Y31 @ 0.90 GHz, 7.7 GiB RAM, Linux 6.14.

| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| `null` (parse + pipeline + discard) | C | 3.23 M | 1350 | 0.309 | 7.0 |
| `null` | Rust | 2.57 M | 1075 | 0.389 | 6.4 |
| `file` (parse + pcap writer) | C | 1.28 M | 536 | 0.779 | 7.0 |
| `file` | Rust | 1.23 M | 513 | 0.814 | 6.4 |
| `vxlan-split` (encap + checksum + split) | C | 0.13 M | 53.2 | 7.854 | 7.1 |
| `vxlan-split` | Rust | 0.12 M | 51.9 | 8.039 | 6.5 |

**Reading the numbers**

* **Pure pipeline (`null`)** — the Rust port reaches ~80% of C's packet rate.
  The remaining gap is mostly per-packet allocation in the Rust task/output
  path; it is the main tuning target.
* **PCAP writer (`file`)** — ~96% of C; both become memcpy/IO bound.
* **VXLAN encapsulation** — effectively at parity (~98%): the path is
  dominated by the `sendto(2)` syscall and the kernel, which both share. This
  confirms the encapsulation/checksum/split logic (the part most at risk of a
  porting bug) does not regress.
* **Memory** — the Rust binaries use ~9% less peak RSS (6.4 vs 7.0 MB here);
  `cpdaemon`/`cpctl` are separate processes and not included.

### Reproduce

```bash
# 1. reference C binary (Release build!)
cd cloud-probe/build
BUILD_MODE=local CPWORKER_LIBRARY_ROOT=/path/to/thirdparty/libs/linux-amd64 \
  CPWORKER_CMAKE_BUILD_TYPE=Release go run mage.go cpworker:linux

# 2. Rust binary
cd cloud-probe-rs
cargo build --release -p cpworker

# 3. run (writes bench/RESULTS.md)
CP_C=/path/to/cloud-probe/build/tmp/cpworker-linux-amd64/cpworker \
N=1000000 REPEAT=3 python3 bench/bench.py
```

`bench/bench.py` is self-contained: it generates the PCAP, writes the three
configs, runs each binary, and emits the table above. Thresholds/caveats:

* `pcap_file` capturer only — no live `libpcap` capture, no root needed. Both
  use the same libpcap read path.
* `vxlan-split` sends to a loopback UDP drainer to avoid ICMP back-pressure.
* Results are relative to this (slow, 4-core) machine. Absolute numbers will
  be much higher on server hardware; the C/Rust *ratios* are the meaningful
  output.
