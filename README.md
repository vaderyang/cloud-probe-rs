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
├── fuzz.sh                    # cargo-fuzz runner
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
