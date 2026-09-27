# Security Policy

Scope: this repository (the Rust port). The original C + Go implementation lives
in [netis/cloud-probe](https://github.com/netis/cloud-probe) and is not covered
here - report issues in that codebase upstream.

## Supported versions

| Version | Status |
|---|---|
| `0.9.x` (`main`, `version` in `Cargo.toml`) | Supported. Fixes land here first; there are no maintained release branches yet. |
| anything older | Not supported. There are no tags older than the current version, so "upgrade to `main`" is the only remediation. |

## Reporting a vulnerability

Open a **private vulnerability report** via
*Security → Report a vulnerability* on the repository (GitHub security advisory).
That keeps the issue non-public while a fix and a release are prepared. Use a
regular issue for hardening ideas, dependency bumps, or anything that is not
exploitable.

What makes a report actionable here (the more of this, the faster the fix):

* the affected binary (`cpworker`, `cpdaemon`, `cpctl`, `dockerpid`, `cripid`) and
  how it is launched (capabilities, config file, CPM URL);
* the input that triggers it - a pcap file, a BPF expression, a config JSON, bytes
  from a ZMTP collector, a container ID, a CPM HTTP response;
* the crash/leak evidence: ASAN output from `./fuzz.sh repro <target> <artifact>`,
  or the artifact under `crates/cpworker/fuzz/artifacts/<target>/`.

A reproducer that a fuzz target can consume is preferred: `crates/cpworker/fuzz/seeds/`
is where such inputs get committed as permanent regression seeds.

Expect: acknowledgement within a week, and no public disclosure of an unfixed issue
until a release containing the fix exists.

## Threat model (what actually parses untrusted bytes here)

| Input | Reached from | Parsed by |
|---|---|---|
| Ethernet frames | live `AF_PACKET` capture, or a pcap file | `packet.rs`, `packet_split.rs`, `bpf/interp.rs` |
| pcap files | `pcap_file` capturer (`-c` config) | `capturer/pcap_file.rs` |
| BPF filter text | config file, CPM task updates, SIGHUP reload | `bpf/parser.rs` → `bpf/compiler.rs` |
| ZMTP peer bytes | the collector side of a `zmq` output | `zmtp/codec.rs`, `zmtp/client.rs` |
| JSON config | `-c <file>` | `config.rs` (serde) |
| container IDs / CRI + Docker replies | `cpdaemon` task builder, `dockerpid`, `cripid` | `task_builder.rs`, those binaries |
| CPM HTTP responses | `cpdaemon` sync loop | `cpm/models.rs` |
| unix JSON-RPC | `cpctl` (local socket) | `unix_manager.rs` |

Everything above is exercised by the fuzz targets listed in
`crates/cpworker/fuzz/fuzz_targets/` (ASan + libFuzzer, run in CI as a smoke test
via `./fuzz.sh --check`), and the wire/format layers are additionally diffed
against the original C/Go implementations in `parity/`.

## Structural properties that are load-bearing

* **No C library is linked.** The pcap reader/writer, the BPF compiler/interpreter
  and the ZMTP client are Rust ([PARITY.md §4](PARITY.md)). The dependency graph
  contains no libpcap, no libzmq and no OpenSSL - TLS in
  `cpdaemon`/`reqwest` is rustls (whose crypto primitives come from the Rust
  `ring` crate). The `libc`/`nix` crates are syscall ABI declarations only, so the
  memory-corruption and parser-overflow history of the replaced C libraries is not
  inherited here.
* **Input-driven failure is never a panic.** `cpworker`'s release profile builds
  with `panic = "abort"`, so a reachable `unwrap()` is a whole-process outage; the
  library paths are kept free of panic constructors, and
  `parity/verify_hygiene.sh` greps for them because `clippy` cannot see the
  difference between "provably unreachable" and "reachable next quarter".
* **Untrusted input cannot make the process allocate freely.** Documented limits,
  all enforced in code: ZMTP frame body ≤ 16 MiB (`zmtp::codec::MAX_FRAME_BODY`);
  one pcap record ≤ 262 144 bytes and `caplen ≤ orig_len`, non-Ethernet linktypes
  rejected (`capturer/pcap_file.rs`); BPF expression ≤ 8 KiB, nesting ≤ 256,
  nodes ≤ 4096 (`bpf/`), and a compiled program that exceeds the kernel's
  `BPF_MAXINSNS` is never handed to `SO_ATTACH_FILTER` - the capturer falls back to
  userspace filtering with the same program (`capturer/af_packet.rs`);
  `zmq.hwm` must be `1..=4096` and the pending queue is capped at `min(hwm × 1 MiB, 64 MiB)`
  (`output/zmq.rs`). Config numbers are range-checked, never truncated
  (`config.rs`).
* **Memory-unsafe code is small and reviewed.** 34 `unsafe` blocks in the crates'
  `src/`, each expected to carry a `SAFETY:` note; they are concentrated in
  syscall boundaries (`capturer/af_packet.rs`, `netns.rs`, `affinity.rs`,
  `bpf/linux.rs`).
* **Supply chain.** `cargo deny` runs against **both** lockfiles (the workspace and
  the standalone `crates/cpworker/fuzz` workspace) with a permissive/non-GPL
  allow-list, yanked crates denied, wildcard (`"*"`) version requirements denied and
  unknown registries / git sources denied; `cargo audit` checks RustSec advisories;
  Dependabot opens the bumps and GitHub's dependency review flags high-severity
  ones. See the `deny` and `security` jobs in `.github/workflows/ci.yml`.

## Deployment guidance

`cpworker` is a privileged packet forwarder; treat these as part of the security
surface, not as tuning advice:

* Run it as a non-root user with only the capabilities it needs, as documented in
  the README: `sudo setcap cap_net_raw,cap_net_admin=eip target/release/cpworker`.
  `cap_net_admin` is only used for `SO_RCVBUFFORCE` and `SO_ATTACH_FILTER`; capture
  degrades to a warning (userspace filtering, clamped socket buffer) without it.
* The control socket is a **unix socket with no authentication** - anyone who can
  open it can list, reload and stop tasks. Its path comes from configuration, so
  keep it inside a directory the surrounding service owns, and check the file
  permissions after startup if the host is multi-tenant. There is no `cpctl`
  over TCP; do not export it with a socket proxy.
* `cpdaemon`'s health endpoint binds `0.0.0.0:<listen.http.port>` (default 9022)
  when `listen.http.address` is empty. Set it to a loopback or management address.
* **Known gap:** the CPM HTTP client sets `danger_accept_invalid_certs(true)`
  unconditionally (`crates/cpdaemon/src/main.rs`, `cpm/client.rs`), and the
  daemon's PKCS#12 client-certificate support is **not ported**. This mirrors the
  Go daemon, which builds `tls.Config{InsecureSkipVerify: true}`
  (`cmd/internal/asm/provider.go`). Until mutual TLS is implemented, restrict the
  CPM channel at the network layer: a dedicated management network/VLAN, or a
  local reverse proxy that validates the upstream certificate. Treat the CPM as an
  input source in your own threat model - its responses drive task creation and
  BPF expressions on the probe.
* `dockerpid`/`cripid` are invoked as helpers and parse container runtime state;
  they need read access to the Docker socket / CRI endpoint and nothing else.

## Scope notes

Not in scope: vulnerabilities in the upstream C/Go code, in the kernel's
`AF_PACKET`/BPF implementation, or behaviour that [PARITY.md §2.2](PARITY.md)
records as an intentional divergence from C's undefined behaviour (the port
refuses those inputs instead of reproducing them). The known trade-off in
`recvmsg`-based capture versus a `TPACKET_V3` ring is a *packet-loss*
characteristic, not a memory-safety one.
