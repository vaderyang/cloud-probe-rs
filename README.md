![CI](https://github.com/vaderyang/cloud-probe-rs/actions/workflows/ci.yml/badge.svg)

# cloud-probe-rs — Netis Cloud Probe (Rust port)

A standalone Rust port of Netis Cloud Probe. The original C + Go implementation lives in
a separate checkout; set `CLOUD_PROBE_SRC` when running the differential/fuzz harnesses in `parity/`.
That reference branch (`0.9.x`) floats on purpose, so upstream can turn the parity jobs red
without a change here — see [UPSTREAM_RUNBOOK.md](UPSTREAM_RUNBOOK.md) for the catch-up
procedure.

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

Requires Rust **1.88+** (`rust-version` in `Cargo.toml`). That floor is verified, not
aspirational: the CI `msrv` job builds the whole workspace on 1.88.0 - library,
binaries, tests and dev-dependencies (`--all-targets`).

```bash
# from this directory
cargo build --workspace --locked     # debug
cargo build --release --workspace --locked
cargo test --workspace
```

Binaries land in `target/debug/` (or `target/release/`). Contribution rules, the
gate list and the changelog: [CONTRIBUTING.md](CONTRIBUTING.md),
[CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md).

### Coverage

Verification coverage is a **blocking CI gate** (ADR-0001,
[VERIFICATION_COVERAGE.md](VERIFICATION_COVERAGE.md)): per-tier line/function
coverage with a must-not-decrease ratchet, 100% function coverage for a list of
critical safety/integrity functions, changed-line coverage (line 90% / branch
85%) and 100% P0 behaviour (requirement/scenario) coverage. Policy lives in
[`verification/policy.toml`](verification/policy.toml), the ratchet baseline in
`verification/baseline.json`. To reproduce locally:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
./verify_coverage.sh              # collect + gate (tiered, critical, diff)
./verify_coverage.sh --no-run     # re-export lcov from the last run, then gate
python3 verification/requirements_gate.py   # P0 scenario coverage
```

Branch coverage (nightly `cargo +nightly llvm-cov --branch`) and mutation
testing (`./verify_mutation.sh`) run in the weekly `.github/workflows/verification.yml`
workflow while their baselines are established.

### System dependencies

The Rust build links **no C libraries**. `libc`/`nix` are used only for raw
syscall bindings (allowed). Optional tools for the differential test harnesses:

* **protoc** — only for `cripid` code generation (`proto/api.proto` is vendored).
  It is a build-time generator, not a linked library; every CI job and the release
  matrix install it, and nothing else beyond `libpcap`/`libzmq` for the oracles.
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
# cpworker — live capture on `lo`, packets discarded (needs the capabilities below)
target/debug/cpworker -c crates/cpworker/examples/live_null.json

# cpworker — replay a pcap file through the BPF filter into /tmp/output.pcap
# (no privileges needed; edit file_name/bpf in the config first)
target/debug/cpworker -c crates/cpworker/examples/pcap_file_replay.json

# cpctl (against a running cpworker)
target/debug/cpctl -u /path/to/cpworker.sock info
target/debug/cpctl -u /path/to/cpworker.sock stats -n 1

# cpdaemon
target/debug/cpdaemon -c config.json server

# container PID helpers
target/debug/dockerpid <containerId>
target/debug/cripid <containerId>
```

The two example configs are the ones this repository ships; both were run against
the binary they document. `"type": "libpcap"` is the **configuration keyword** for
live capture, kept so that C/Go config files load unchanged — it is served by the
pure-Rust `AF_PACKET` capturer, not by libpcap. A replay run stays alive after
logging `end of file` (the capturer polls for the file to grow); stop it with
`Ctrl-C`/`SIGTERM`.

`cpworker` needs raw-socket capabilities for live capture:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/cpworker
```

## Migration status

Faithfully ported:

* **cpworker** — config model/parser (serde replaces cJSON), logging, stats,
  packet parsing/checksums/fragmentation, req_pattern mini-language,
  ring buffer, all outputs (`null`, `file`, `rotating_file`, `gre`, `vxlan`
  incl. splitting, `zmq` incl. heartbeat — pure-Rust ZMTP), the live
  (`AF_PACKET`) and pcap-file capturers, task manager (RTC + pipeline),
  unix JSON-RPC control plane, signals/reload.
  The C unit tests that covered packet splitting, req_pattern, config and
  stats are ported (see `cargo test`).
* **cpgolib**, **cpctl**, **dockerpid**, **cripid** — full ports.
* **cpdaemon** — worker lifecycle, cgroup-v1/v2 CPU limiting, CPM HTTP client and
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
the remediation findings in [AUDIT3.md](AUDIT3.md); the P3 (pure-Rust)
implementation audit — including a critical pcap-reader regression found and
fixed — in [AUDIT4GLM53f.md](AUDIT4GLM53f.md); the three-audit consolidation,
the P5-xx findings and their remediation status in
[IMPROVEMENT_PLAN_AUDIT4.md](IMPROVEMENT_PLAN_AUDIT4.md).

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
    │   ├── src/
    │   │   ├── capturer/      # af_packet (live), pcap_file (replay)
    │   │   ├── bpf/           # tcpdump-subset compiler + cBPF interpreter
    │   │   ├── zmtp/          # ZMTP 3.x PUSH client
    │   │   ├── output/        # null, file, rotating_file, gre, vxlan, zmq
    │   │   ├── config.rs      # JSON config (serde)
    │   │   ├── packet.rs      # L2–L4 parsing
    │   │   ├── packet_split.rs
    │   │   ├── req_pattern.rs
    │   │   ├── ring_buffer.rs
    │   │   ├── task.rs
    │   │   └── unix_manager.rs
    │   ├── examples/          # runnable worker configs (live_null, pcap_file_replay)
    │   └── fuzz/              # cargo-fuzz targets (standalone workspace)
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
  CC0-1.0, Unlicense, OpenSSL, BSL-1.0, CDLA-Permissive-2.0, NCSA). cargo-deny is
  deny-by-default, so every GPL/AGPL/LGPL/SSPL-family license is rejected. CI
  additionally asserts that no GPL-family identifier is added to `deny.toml`.
  NCSA is there for one dev-only crate (`libfuzzer-sys`, fuzz harness only; it is
  linked into no shipped binary) and is annotated as such in the file.
* **No floating sources.** `wildcards = "deny"` (no `dep = "*"` anywhere in the
  graph) and `unknown-registry`/`unknown-git` are denied too, so crates.io is the
  only source and a mirror or git dependency is a reviewed `deny.toml` edit rather
  than a warning line. Version-less path dependencies between the workspace crates
  stay legal because every member declares `publish = false`
  (`allow-wildcard-paths`).
* **Two lockfiles, both checked.** `crates/cpworker/fuzz` is a standalone
  workspace, so CI runs `cargo deny check` twice (root manifest and fuzz manifest)
  and asserts that neither `Cargo.lock` drifts from its manifest
  (`cargo metadata --locked`). Dependency changes must therefore refresh both.
* **CVE / advisory checks.** CI runs `cargo-deny check advisories` (RustSec DB,
  yanked crates denied) against both graphs and `cargo audit` against the workspace
  lockfile on every push. PRs also run GitHub's `dependency-review-action` (fails
  on high-severity advisories).
* **Reproducible builds.** Every cargo invocation in CI and in `parity/` uses
  `--locked`; the MSRV (1.88) is built in CI, not just declared.
* **Automated updates.** Dependabot watches **both** `Cargo.lock` files (the
  workspace and the standalone `crates/cpworker/fuzz` workspace) and the GitHub
  Actions used by CI (`.github/dependabot.yml`).

## Benchmarks: C vs Rust

Measured against the reference C `cpworker` from
[netis/cloud-probe](https://github.com/netis/cloud-probe) (`0.9.x`, built with
`CMAKE_BUILD_TYPE=Release`). Both binaries replay the **same 1,000,000-packet
PCAP** (417 MB, mixed Ethernet/IPv4/UDP frames) through a `pcap_file` capturer.
Timing stops when the capturer logs `end of file`; peak RSS is the process
`VmHWM`. Median of 5 runs after a warmup.

**Machine:** 4 cores, Intel Core M-5Y31 @ 0.90 GHz, 7.7 GiB RAM, Linux 7.0.0-34.
**Measured:** 2026-09-27, on the pure-Rust capture/forward path (the table that
lived here until now was taken while `cpworker` still used libpcap for reading the
replay file, so it is replaced rather than updated). Two consecutive runs
(`REPEAT=5` each) agreed to within 2% on every scenario; the spread is quoted
below, and `bench/RESULTS.md` holds the run that produced these numbers.

| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| `null` (parse + pipeline + discard) | C | 3.30 M | 1375 | 0.303 | 7.3 |
| `null` | **Rust** | **4.98 M** | **2077** | **0.201** | **2.8** |
| `file` (parse + pcap writer) | C | 1.36 M | 565 | 0.738 | 7.3 |
| `file` | **Rust** | **1.82 M** | **759** | **0.549** | **2.8** |
| `vxlan-split` (encap + checksum + split) | C | 0.11 M | 44.5 | 9.373 | 7.3 |
| `vxlan-split` | Rust | 0.11 M | 46.4 | 8.995 | 2.9 |

**Findings** (run-to-run spread in parentheses)

* `null` — Rust is **1.48–1.51× C** (0.203 s / 0.201 s vs 0.301 s / 0.303 s). This
  is the pure-Rust `PcapReader` replacing libpcap's `fread` path; the fourth
  audit measured 0.64 on a 3M-packet A/B, which brackets the same effect.
* `file` — Rust is **1.34–1.39× C** (0.549 s / 0.543 s vs 0.738 s / 0.754 s).
* `vxlan-split` — Rust is **1.04–1.09× C** (8.995 s / 8.852 s vs 9.373 s / 9.658 s):
  kernel `sendto` bound, so read it as "no regression" in the most
  porting-sensitive path (encapsulation, checksums, splitting), not as a win.
* Memory — peak RSS **2.8 MB vs 7.3 MB (~62% less)**. The Rust reader does not
  allocate libpcap's buffer, and one record is capped at 262144 bytes
  (AUDIT4 P5-20); the old table's 6.5 vs 7.1 MB was measured with libpcap linked in.

Absolute values are not comparable to other machines or kernels — the same C
binary here scores 3.30 M pps where an earlier Linux 6.14 run scored 2.83 M pps.
The C/Rust ratio on one machine is the meaningful output.

### Live capture is not benchmarked here

`bench/bench.py` replays a file: no root, no interface, no driver. The live
`AF_PACKET` path has functional coverage (the privileged CI job: loopback with a
filter, VLAN re-insertion on a veth, userspace-filter fallback) but **no
reproducible throughput number**. `bench/live_bench.py` is a manual A/B against
the C/libpcap capturer on a real interface and reports frames captured, drop
counters and CPU seconds per million captured frames — run it as root
(`bench/live_bench.py 20 wlp1s0`). On loopback it measured near-identical CPU per
captured frame (C 3.3 s / Rust 3.2 s per million) while the two implementations
reported different frame counts for the same traffic (2.00 vs 0.79 frames per
datagram sent, both with `drop_packets == 0`). That gap is **not root-caused and
is not a performance claim**; it is tracked as an open question in
[IMPROVEMENT_PLAN_AUDIT4.md §5](IMPROVEMENT_PLAN_AUDIT4.md), together with the
`recvmsg`-vs-`TPACKET_V3` trade-off recorded in [PARITY.md §4](PARITY.md).

### Root cause of the original ~25% gap (and the fix)

Historical record, from before the pure-Rust work: an earlier revision was **~25%
slower** on `null` (3M packets: Rust 1.41 s vs C
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
wall-time ratio went **1.28 → 0.96** (Rust now faster); the reader replacement
described above took it to ~0.66.

### Reproduce

```bash
# 1. reference C binary (Release build!)
cd cloud-probe/build
BUILD_MODE=local CPWORKER_LIBRARY_ROOT=/path/to/thirdparty/libs/linux-amd64 \
  CPWORKER_CMAKE_BUILD_TYPE=Release go run mage.go cpworker:linux

# 2. Rust binary
cd cloud-probe-rs
cargo build --release -p cpworker --locked

# 3. run (writes bench/RESULTS.md)
CP_C=/path/to/cloud-probe/build/tmp/cpworker-linux-amd64/cpworker \
N=1000000 REPEAT=5 python3 bench/bench.py
```

`bench/bench.py` is self-contained: it generates the PCAP, writes the three
configs, runs each binary, and emits the table above. Caveats:

* `pcap_file` capturer only — no live capture, no root. The C side reads the file
  with libpcap, the Rust side with its own reader (that difference *is* the
  subject of the `null`/`file` numbers); see "Live capture is not benchmarked
  here" for the capture plane.
* `vxlan-split` sends to a loopback UDP drainer to avoid ICMP back-pressure.
* Results are relative to this (slow, 4-core) machine; the C/Rust **ratios**
  are the meaningful output.
