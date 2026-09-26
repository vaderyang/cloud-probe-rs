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

Requires Rust **1.88+** (declared as `rust-version` in `Cargo.toml`).

```bash
# from this directory
cargo build --workspace          # debug
cargo build --release --workspace
cargo test --workspace
```

Binaries land in `target/debug/` (or `target/release/`).

### Coverage

Line coverage is collected in CI (advisory) with `cargo-llvm-cov` and uploaded
as an `lcov` artifact. To reproduce locally:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --lcov --output-path lcov.info
cargo llvm-cov report --summary-only
```

### System dependencies

The Rust build links **no C libraries**. `libc`/`nix` are used only for raw
syscall bindings (allowed). Optional tools for the differential test harnesses:

* **protoc** — only for `cripid` code generation (`proto/api.proto` is vendored)
* **libpcap** + **libzmq** — only to build the C oracles in `parity/`
  (`c_bpf.c`, `zmtp_pull.c`, ...); not needed for `cargo build`/`cargo test`

On Debian/Ubuntu:

```bash
sudo apt-get install -y protobuf-compiler
# optional, only for the parity harnesses:
# sudo apt-get install -y libpcap-dev libzmq3-dev
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
* **cpdaemon** — worker lifecycle, cgroup-v2 CPU limiting, CPM HTTP client and
  models, a functional register/strategy/metrics sync loop, and the
  `worker_task_builder` heuristics (startup-arg parsing, container-ID decoding,
  VNI→tag encoding) ported with the exact Go test vectors as unit tests
  (including fingerprint `64393037-6336-6262-3137-333739363234`).

Reduced-scope port (`cpdaemon`):

* **Not** ported: PKCS#12 client certificates, sync-log batching,
  NIC-change detection (config fields pass through, the detection loop does
  not), and memory-policy tuning.
  See `crates/cpdaemon/src/cpm/syncer.rs` for the documented simplifications.

Code-quality audits: baseline (unsafe inventory, lock strategy, dependency
hygiene, engineering baseline) in [AUDIT.md](AUDIT.md); review of the
remediation plan and its implementation in [AUDIT2.md](AUDIT2.md); closure of
the remediation findings in [AUDIT3.md](AUDIT3.md).

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

## Supply chain & licensing

* **License policy: permissive / non-GPL only.** `deny.toml` uses an explicit
  allow-list (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0,
  CC0-1.0, Unlicense, OpenSSL, BSL-1.0, CDLA-Permissive-2.0). cargo-deny is
  deny-by-default, so every GPL/AGPL/LGPL/SSPL-family license is rejected. CI
  additionally asserts that no GPL-family identifier is added to `deny.toml`.
* **CVE / advisory checks.** CI runs `cargo-deny check advisories` (RustSec DB,
  yanked crates denied) and `cargo audit` on every push. PRs also run GitHub's
  `dependency-review-action` (fails on high-severity advisories).
* **Automated updates.** Dependabot watches `Cargo.lock` and the GitHub Actions
  used by CI (`.github/dependabot.yml`).

## Benchmarks: C vs Rust

Measured against the reference C `cpworker` from
[netis/cloud-probe](https://github.com/netis/cloud-probe) (`0.9.x`, built with
`CMAKE_BUILD_TYPE=Release`). Both binaries replay the **same 1,000,000-packet
PCAP** (417 MB, mixed Ethernet/IPv4/UDP frames) through a `pcap_file` capturer.
Timing stops when the capturer logs `end of file`; peak RSS is the process
`VmHWM`. Median of 5 runs after a warmup.

**Machine:** 4 cores, Intel Core M-5Y31 @ 0.90 GHz, 7.7 GiB RAM, Linux 6.14.

| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| `null` (parse + pipeline + discard) | C | 2.83 M | 1181 | 0.353 | 7.1 |
| `null` | **Rust** | **3.05 M** | **1273** | **0.328** | **6.5** |
| `file` (parse + pcap writer) | C | 1.16 M | 485 | 0.860 | 7.1 |
| `file` | **Rust** | **1.27 M** | **532** | **0.784** | **6.4** |
| `vxlan-split` (encap + checksum + split) | C | 0.10 M | 43.0 | 9.69 | 7.1 |
| `vxlan-split` | Rust | 0.10 M | 41.1 | 10.16 | 6.6 |

**Findings**

* `null` and `file` — the Rust port is **~8–9% faster** than C.
* `vxlan-split` — within run-to-run noise (kernel `sendto` bound); the
  encapsulation/checksum/split logic (the most porting-sensitive part) does not
  regress.
* Memory — Rust uses **~9% less** peak RSS (6.5 vs 7.1 MB).

### Root cause of the original ~25% gap (and the fix)

An earlier revision was **~25% slower** on `null` (3M packets: Rust 1.41 s vs C
1.10 s). `perf record` showed the time was *not* in packet processing — the
per-packet work was essentially identical (`perf stat`: 3.24 B vs 3.13 B
instructions). The cost was in the Rust main loop:

* every packet went through `mgr.lock().poll_packets()`, and `poll_packets`
  acquired a **second** mutex (`out_sets`) and cloned an `Arc` — two lock/unlock
  pairs per packet;
* the loop also called `Instant::now()` (`elapsed()`) **once per packet** for
  the 60-second reload check;
* the C main loop does neither (no locks; a `difftime`, not on the per-packet
  path in the same way).

`perf` attributed ~11.6% of samples to `main` (vs ~4% for C) plus ~3.4% to
`clock_gettime`/`Timespec`. The fix batches the poll loop:
`TaskManager::poll_packets_batch(256)` now locks once per 256 packets and the
clock is read once per batch. On the same 3M-packet workload the Rust/C
wall-time ratio went **1.28 → 0.96** (Rust now faster).

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
N=1000000 REPEAT=5 python3 bench/bench.py
```

`bench/bench.py` is self-contained: it generates the PCAP, writes the three
configs, runs each binary, and emits the table above. Caveats:

* `pcap_file` capturer only — no live capture, no root. Both use libpcap.
* `vxlan-split` sends to a loopback UDP drainer to avoid ICMP back-pressure.
* Results are relative to this (slow, 4-core) machine; the C/Rust **ratios**
  are the meaningful output.
