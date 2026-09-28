# Changelog

Notable changes to this port. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows the version of the C/Go implementation it ports (`0.9.x`).

Two conventions worth knowing before reading:

* **Every behavioural entry names the check that proves it.** `parity/...` means a
  differential harness against the original C/Go; `P5-xx` refers to the finding in
  [IMPROVEMENT_PLAN_AUDIT4.md](IMPROVEMENT_PLAN_AUDIT4.md), which also records the
  red→green test written for it.
* **`[Unreleased]` is `main`.** No git tag exists yet; `version` in `Cargo.toml` is
  `0.9.0`, and `cargo build --workspace --locked` on `main` is the supported state.

## [Unreleased]

### Added

- Repository convention files: [CONTRIBUTING.md](CONTRIBUTING.md) (gates, the
  red→green rule, no-C-dependency policy, how to add a fuzz target or a parity
  case), [SECURITY.md](SECURITY.md) (threat model, capability guidance, the CPM
  TLS gap), [`.github/CODEOWNERS`](.github/CODEOWNERS), and this file (P5-30).
- CI `msrv` job: `cargo build --workspace --locked` on Rust 1.88, so the declared
  `rust-version` is actually verified instead of asserted (P5-26).
- `cargo deny` now also checks `crates/cpworker/fuzz/Cargo.lock` (a standalone
  workspace, previously invisible to the policy) and the `deny` job asserts that
  both lockfiles match their manifests (P5-28). Dependabot gained the matching
  second entry (`directory: /crates/cpworker/fuzz`), so that lockfile now gets
  update PRs instead of only being policed.
- `bench/live_bench.py`: manual, root-only live-capture A/B (C/libpcap vs the Rust
  `AF_PACKET` path) reporting frames captured, drop counters and CPU seconds per
  captured million frames. Not a CI gate and not a throughput ceiling - see its
  docstring for why `cap_packets` has to be read before the CPU number.

### Changed

- `--locked` on every dependency-resolving cargo command in CI, in the release
  build, and in the six `parity/` harness builds, so a build cannot silently
  resolve something other than the committed lockfiles (P5-27).
- Both workflows default to `permissions: contents: read`; only `dependency-review`
  (`pull-requests: write`) and `release.yml`'s publish job (`contents: write`)
  hold a write token (P5-27).
- `parity/verify_bpf.sh` uses a fixed default seed (`20260927`) instead of
  `$RANDOM`, keeps `BPF_SEED`/argument overrides, and prints the seed plus the
  exact replay command on every mismatch (P5-27). Two runs of one commit now
  exercise the same corpus.
- `deny.toml`: `[bans] wildcards` and `[sources] unknown-registry`/`unknown-git`
  raised to `deny`; `NCSA` added to the license allow-list because `libfuzzer-sys`
  (fuzz workspace only, no shipped binary) is `"(MIT OR Apache-2.0) AND NCSA"`.
  Every member crate now declares `publish = false`, which is what keeps the
  internal version-less path edges legal under `allow-wildcard-paths` (P5-28).
- Benchmarks re-measured with the pure-Rust capture/forward path; the previous
  table dated from the libpcap build (P5-19). See below and `bench/RESULTS.md`.

### Removed

- Zero-reference dependencies that had crept back in: `thiserror`, `env_logger`
  and `byteorder` from `cpworker`; `serde` and `env_logger` from `cpctl`;
  `anyhow` from `cpgolib`; `libc` from `cpdaemon` (P5-24). `byteorder` left
  `[workspace.dependencies]` as well; `axum`, `reqwest` and `rand` are now
  inherited from that table instead of being restated inline (nightly cargo
  reports the duplication as an unused workspace dependency).
- `brew install libpcap zeromq` from the macOS release matrix; the only system
  package any build needs is `protoc`, and only for `cripid`'s code generation
  (P5-25).

### Fixed

### Fixed

- `crates/cpworker/tests/af_packet_live.rs` no longer reports success when it could
  not capture (P2-2). Each test returned early without root, so an unprivileged
  `--ignored` run printed `test result: ok. 4 passed` while opening no socket at all,
  and the CI `live-capture` job could be green while executing nothing. The tests now
  panic when unprivileged (they are `#[ignore]`d exactly so that they only run in that
  job), and the job asserts that the number of ignored tests the binary advertises via
  `--ignored --list` is the number that actually executed.
- `SimpleAllocator::release` no longer calls `AtomicU64::fetch_update`, which
  current nightly deprecated (renamed `try_update`, not in the MSRV). It is the
  same CAS loop `reserve` uses, and the saturating behaviour it relies on - a
  double free must not wrap `used` around and starve the pipeline - is now pinned
  by `releasing_more_than_was_reserved_saturates_at_zero` (P5-27).
- Documentation that contradicted the code (P5-18): `PARITY.md` still described
  the pure-Rust work as "not finished / still links libpcap / ZMQ still uses
  libzmq" in its header, its coverage table and §5.1 while §4 said it was done;
  `IMPROVEMENT_PLAN.md` kept a "libpcap to be removed" bullet under a "libpcap
  removed" one. Test/vector counts in `PARITY.md §1.3` corrected (34 ported C
  vectors, 6 Go test functions → 8 Rust tests, 165 passing, 3 `#[ignore]`d live
  tests). README's quick start referenced a config file that does not exist in
  this repository; `crates/cpworker/examples/live_null.json` and
  `pcap_file_replay.json` are now committed and were run.

## [0.9.0] - 2026-09-27

The `0.9.x` feature set, plus four audit rounds (AUDIT.md → AUDIT4).

### Replaced (no C library is linked any more)

- libpcap → `capturer/af_packet.rs` (raw `AF_PACKET`), `bpf/` (tcpdump-subset
  compiler + cBPF interpreter, `SO_ATTACH_FILTER`), `capturer/pcap_file.rs` and
  `output/pcap_writer.rs` (`8eadeb0`, `9b6a1f2`, `00022ae`).
- libzmq → `zmtp/` (ZMTP 3.x `PUSH`, NULL mechanism, non-blocking state machine),
  verified byte-for-byte against a real libzmq `PULL` by `parity/verify_zmtp.sh`
  (`5984f67`). Wire-compatibility and the remaining semantic differences are tabulated
  in [PARITY.md §2.4](PARITY.md).

### Fixed (correctness; each with a regression test that failed before the change)

*Packet filtering*

- Jump distances over 255 instructions are bridged with `JA` trampolines, so long
  `not host` chains and multi-term `port`/`host` alternations compile instead of
  failing the task - the defect that made a task capture nothing at all (P5-01).
- Missing tcpdump syntax added: `tcp/udp src|dst port [range]`, `ether src|dst host`,
  `ip src host`, `ip/ip6 proto N`; the unsupported set is listed in
  [PARITY.md §4](PARITY.md) (P5-06).
- Deeply nested / oversized expressions return `Err` instead of overflowing the
  stack and aborting the process (`panic = "abort"`), bounded at 8 KiB text,
  depth 256, 4096 nodes (P5-07).
- `host <name>` OR-expands **every** resolved A/AAAA address rather than the first
  (`d9271b4`, P5-08); programs longer than `BPF_MAXINSNS`, and filters the kernel
  rejects (`ENOMEM` under `net.core.optmem_max`), fall back to userspace filtering
  with the same compiled program (`758ef9c`).

*Capture plane*

- `PACKET_STATISTICS` is read-and-reset, so `tp_drops` is accumulated as a
  per-window delta instead of subtracted from the previous sample; the old code
  reported ~4.29e9 phantom drops after any window with no traffic (P5-02).
- `PACKET_AUXDATA` enabled and the 802.1Q header re-inserted after the kernel
  stripped it, so captured frames keep VLAN tags (P5-03).
- `SO_RCVBUFFORCE` first, `SO_RCVBUF` fallback, the effective value read back with
  `getsockopt` and a warning when `net.core.rmem_max` clamps it (256 MiB requested
  became 8 MiB silently) (P5-05).
- No startup filtering window: the socket is created with protocol 0, the BPF
  program is attached, and only then `bind(ETH_P_ALL, ifindex)` (P5-09).
- Capture error paths are rate-limited like the C 2-second statistics window, counted
  in `error_drop_*`, and no longer busy-poll a `timeout_ms=0` task (P5-12/P5-13);
  `SO_TIMESTAMPNS` failure is reported instead of silently degrading to second
  resolution, and cmsg parsing uses the `CMSG_*` macros (P5-14).

*Output plane and lifecycle*

- `Output::destroy()` got a single call point (`TaskManager::stop()`, which
  `reload()` and `Drop` also go through). It had **zero** callers, so reload and
  shutdown discarded up to `hwm × 1 MiB` of already-queued ZMTP batches and
  unflushed pcap bytes (P5-04).
- ZMTP: 10 s handshake deadline, `SO_KEEPALIVE` + `TCP_USER_TIMEOUT`, DNS
  re-resolution on reconnect covering every address, single write FIFO so a short
  write cannot interleave frames, and re-resolution moved to a background thread
  so a stalled `getaddrinfo` cannot block capture (`8504fd5`, `55102a9`, `f7271fc`,
  P5-10).
- `zmq.hwm` range-checked (`1..=4096`), the pending queue capped by bytes as well
  as count, and `zmtp_queued_batches` / `zmtp_queued_bytes` published as gauges
  (`fwd_*` semantics deliberately unchanged, see [PARITY.md §2.4](PARITY.md))
  (P5-11).

*Configuration, parsing and resource hygiene*

- Every numeric config field is range-checked with its field name in the error
  instead of `as i32` - which had turned `snaplen: 2147483648` into a 1-byte
  snaplen (silent no-capture) and `buffer_size_mb: 4294967296` into `SO_RCVBUF=0`
  (P5-15).
- pcap reader validates magic, `version_major`, `linktype == DLT_EN10MB`,
  `caplen <= orig_len`, and caps one record at 262144 bytes; corrupt records stop
  the replay instead of being forwarded as packets, and `read_exact` fixed a
  position drift that silently truncated replays at the first 8 KiB boundary
  (`9ad3f22`, `7ca34a9`, P5-20).
- `bpf_filter_replace_nic` copies bytes verbatim instead of re-encoding each byte
  as a `char`, which mangled every non-ASCII filter (P5-21).
- `PcapWriter::flush()` documents what it does (publish to the OS, not fsync);
  `cpdaemon` fails startup on an unparseable `listen.http.port` instead of
  silently moving the health endpoint to 9022, and accepts an unquoted numeric
  port the way viper does (`18fbbf1`, P5-22).
- No panic constructors left in `cpworker`'s library paths (`bpf::or_all`,
  `zmtp::flush_pending`, rotating-file naming, `packet.rs` fixed-length slices);
  `panic = "abort"` is kept, with the boundary written down in `Cargo.toml` and
  [PARITY.md §4](PARITY.md) and enforced by `parity/verify_hygiene.sh`
  (`f3549b2`, P5-23).

### Testing and gates

- `parity/all.sh` runs 9 harnesses: packet_split, config, req_pattern,
  GRE/VXLAN/ZMQ wire bytes, unix JSON-RPC, ZMTP interop, BPF-vs-libpcap per-packet
  decisions, plus `verify_liveness.sh` (implemented-but-never-called guard, §3.1)
  and `verify_hygiene.sh` (truncating casts, panic surface, overstated docs,
  unregistered fuzz targets).
- Coverage-guided differential fuzzing against the original C and Go
  (`parity/difffuzz.sh`, `029a1af`, `1dbf44a`); it found the `req_pattern`
  `port -0` divergence and a fingerprint difference in Go's non-pointer string.
- 10 cargo-fuzz targets including `bpf`, `zmtp_wire`, `zmtp_client` and
  `pcap_reader`; `./fuzz.sh --check` runs in CI, and a declared target that is not
  in `fuzz.sh` fails the hygiene gate.
- Deterministic simulation harness (`crates/sim`), seeded and replayable.
- Privileged CI job for the real `AF_PACKET` path (loopback filter, VLAN re-insertion
  on a veth, userspace-filter fallback), which the ordinary jobs cannot reach.
- `cargo test --workspace`: 165 passing, 3 ignored (live capture).

### Performance

- `TaskManager::poll_packets_batch(256)` locks once per 256 packets and reads the
  clock once per batch: the Rust/C 3M-packet wall-time ratio went 1.28 → 0.96
  (`e9e1d13`).
- Re-measured offline (pure-Rust reader/writer, 1M packets, median of 5, same
  machine class): Rust is ~1.5× C on `null`, ~1.4× on `file`, ~1.07× on
  `vxlan-split`, with peak RSS 2.8 MB vs 7.3 MB. Numbers and provenance in
  [README.md](README.md#benchmarks-c-vs-rust) and `bench/RESULTS.md`.

### Known limitations

Unported modules and their triggers are tabulated in [PARITY.md §5](PARITY.md)
(DPDK capturer, reload fingerprint reuse, `unix-manager` select semantics,
lock-free ring buffer, cgroup v1; explicitly not planned: Wire DI, pprof, cJSON
first-key semantics, C's VLAN out-of-bounds UB). Reduced-scope `cpdaemon` items
and the CPM TLS gap are in README and [SECURITY.md](SECURITY.md). The
`recvmsg`-vs-`TPACKET_V3` capture trade-off, and an unexplained capture-plane
count difference the new live benchmark exposes, are in
[PARITY.md §4](PARITY.md).
