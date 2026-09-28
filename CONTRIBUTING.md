# Contributing

This is a Rust port of a C + Go packet-capture product. The bar for a change is
not "it compiles", it is "it behaves like the original where it claims to, and a
machine checks that claim". Almost every rule below exists because a specific
defect got past a specific check - the references (`P5-xx`, `§3.x`) point at
[IMPROVEMENT_PLAN_AUDIT4.md](IMPROVEMENT_PLAN_AUDIT4.md), which is where those
findings are recorded.

## 1. Get the toolchain right

| What | Version | Why |
|---|---|---|
| Rust | **1.88** (declared `rust-version`, verified by the CI `msrv` job with `--all-targets`) | Do not use a feature newer than 1.88 in a code path; if a dependency bump raises its own MSRV, that job fails - including for dev-dependencies and `tests/`, which plain `cargo build` never compiles. |
| Rust nightly | latest | Only for `cargo fuzz` (`./fuzz.sh`). |
| `protoc` | any recent | Only to build `cripid` (`build.rs` codegen from the vendored `proto/api.proto`). It is a build tool: nothing links a C library. |
| `libpcap` / `libzmq` | system | **Only** to compile the C oracles in `parity/`. `cargo build`/`cargo test` do not need them. |

Set `CLOUD_PROBE_SRC` to a checkout of the reference implementation
([netis/cloud-probe](https://github.com/netis/cloud-probe), branch `0.9.x`) to
run the differential harnesses; without it `parity/all.sh` skips nothing but
fails on the missing sources, which is intentional.

## 2. The loop

```bash
cargo build --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo deny --manifest-path crates/cpworker/fuzz/Cargo.toml check   # second lockfile
./parity/all.sh          # 10 differential + anti-regression harnesses
./fuzz.sh --check        # 5s smoke over every fuzz target (needs nightly)
```

CI runs all of that plus the privileged live-capture job, `cargo-audit`,
coverage (advisory) and the release matrix. `.github/workflows/*.yml` are linted
with `actionlint`; run it locally if you touch them.

## 3. Standing rules

**No C libraries.** The engine links no C library; `libc`/`nix` are syscall ABI
bindings and are the only exception. Adding `pcap`, `zmq`, `openssl`,
`ring`-style `-sys` crates or a `links = "..."` dependency needs an explicit
decision, not a `Cargo.toml` edit. Rationale and the current state:
[PARITY.md §4](PARITY.md).

**Dependencies.** `deny.toml` is a permissive/non-GPL allow-list (deny-by-default),
yanked crates are denied, `wildcards = "deny"` (a `dep = "*"` requirement leaves the
version to whoever resolves the graph) and `unknown-registry`/`unknown-git` are
denied, so registries and git sources other than crates.io are a policy change.
`crates/cpworker/fuzz/` is a **separate workspace with its own `Cargo.lock`**: any
dependency change must refresh both lockfiles, or `cargo metadata --locked` in the
`deny` job fails. `#![warn(missing_docs)]` is on for the `cpworker` public API -
document public items as you add them.

**`panic = "abort"` means no reachable panics in library code.** The release
profile aborts, so one `unwrap()` on an input-driven path costs the whole worker
and every task inside it. Any failure decided by data - config JSON, CPM task
updates, SIGHUP reload, BPF expressions, pcap files, ZMTP peer bytes, packet
frames - is a `Result` or an early return. Panics are reserved for violations of
the program's own invariants, expressed as `debug_assert!`.
`parity/verify_hygiene.sh` greps for the panic constructors instead of trusting
that discipline survives.

**Everything the kernel touches is read back.** `setsockopt` returning 0 does not
mean the OS took your value (`SO_RCVBUF` is silently clamped by `net.core.rmem_max`,
`PACKET_STATISTICS` is read-and-reset). Set, `getsockopt` back, warn or assert on
the difference - see `capturer/af_packet.rs` and `PARITY.md §4`.

**Tests and harnesses must be deterministic.** Fixed default seeds, no `$RANDOM`,
no wall-clock in assertions (use the monotonic clock or inject time), and any
harness that can fail prints the seed and the exact command to replay it. A green
run that cannot be re-created proves nothing.

**Docs are promises, so they are grepped too.** If a comment says a function
fsyncs, validates a linktype or bounds an allocation, either the code does it or a
gate fails. Do not write a capability into a doc comment that the code does not
have; do not leave a "not yet done" line behind after the work landed.

## 4. A fix needs a red→green test

Before changing behaviour, write the test that fails on `main`, confirm it fails,
then fix the code. Say in the commit message what the test looked like before. If
you cannot falsify the "unreachable"/"cannot happen" claim with a test, do not rely
on it - convert it to a `Result`, or add the grep gate that enforces it.

When a defect class is invisible to `clippy` and to the test suite, extend a gate
rather than only fixing the instance:

| Gate | Class it catches | Born from |
|---|---|---|
| `parity/verify_liveness.sh` | implemented but never *called* (test-only callers do not count) | P5-04, `Output::destroy()` |
| `parity/verify_hygiene.sh` | truncating casts in the deserialising layer (every spelling), panic constructors on library paths, docs overstating behaviour, fuzz targets that are declared but never run | P5-15/20/22/23 |
| `parity/verify_hygiene_reverse.sh` | a gate that can be passed by *rewriting* the violation (AUDIT4 P2-3: all four hygiene gates were ✅ against an injected copy) | P2-3 |

Add a line to one of those two scripts (and keep its reverse check honest: re-insert
the violation, confirm the line goes ❌ and the script exits 1). `verify_hygiene`'s
reverse checks live in `parity/verify_hygiene_reverse.sh`, and they inject the
violation *in a different spelling from the one the gate was written against* - the
original four reverse checks re-ran the literal defect and still passed when it was
written as `as libc::c_int`, as a `[[bin]]` with `path` before `name`, or as a doc
line quoting the exemption keywords (P2-3).

## 5. Differential parity (`parity/`)

Behavioural equivalence against the original C/Go is proven by `parity/all.sh`:
packet splitting, config parsing, `req_pattern`, GRE/VXLAN/ZMQ wire bytes, unix
JSON-RPC, ZMTP interop against real libzmq, and the BPF compiler against libpcap's
`pcap_offline_filter` - plus the two anti-regression gates above.

* Generators must exercise **deep shapes**, not just valid-looking ones. The BPF
  generator includes long `or` chains, `not host` chains of 11/50/200 and the
  direction-qualified syntax, because "≤ 2 operators" sampled green while
  `port A or port B or port C` failed to compile (P5-01). State the maximum size
  covered in the generator's own comments/report.
* Any input on which the two implementations are *defined* to differ (invalid
  JSON, C's undefined behaviour, out-of-range config numbers) is excluded from the
  generator and recorded in [PARITY.md §2.2/§2.3/§2.5](PARITY.md) instead -
  otherwise the harness just re-verifies the clamp.
* New `cpworker` behaviour that diverges from C goes into `PARITY.md §2` with the
  measured oracle output on both sides.

## 6. Fuzzing

To add a target: drop `fuzz_targets/<name>.rs`, declare the `[[bin]]` in
`crates/cpworker/fuzz/Cargo.toml`, **add the name to `ALL_TARGETS` in `fuzz.sh`**
(`verify_hygiene.sh` fails if you forget - a target nobody runs does not exist),
and put regression inputs in `crates/cpworker/fuzz/seeds/<name>/` (they are copied
into the corpus by `fuzz.sh`). Run `./fuzz.sh 60 <name>` before pushing.

C/Go differential fuzzing is `parity/difffuzz.sh <seconds> <mode|all>`; it needs
`CLOUD_PROBE_SRC`.

## 7. Live capture tests

`crates/cpworker/tests/af_packet_live.rs` is `#[ignore]`d: it needs `CAP_NET_RAW`
(plus `CAP_NET_ADMIN` for `SO_RCVBUFFORCE` and `SO_ATTACH_FILTER`) and, for the
VLAN case, `ip link` permissions. Run it with

```bash
cargo test -p cpworker --test af_packet_live --no-run
sudo -E "$(find target/debug/deps -type f -name 'af_packet_live-*' ! -name '*.d' | head -n1)" \
     --ignored --nocapture
```

CI's `live-capture` job does exactly this in a privileged runner, and it fails unless
every ignored test in that binary actually executed (`--ignored --list` count ==
`N passed`). A live test must therefore never `return` early when the environment is
not good enough - it `panic!`s. Silently skipping is what made that job report
`4 passed` while opening no socket (P2-2). Changes to
`capturer/af_packet.rs` (stats, auxdata/VLAN, buffer sizes, socket setup ordering,
filter attach/fallback) are only considered tested if this suite ran.

## 8. Commits, PRs, review

* Conventional commits, scoped: `fix(bpf):`, `fix(capturer):`, `ci:`, `docs:`,
  `chore(deps):`. The subject says *what changed*; the body says *why it was
  broken* and quotes the measurement (counts, timings, errno). Reference the plan
  id (`P5-11`) when there is one.
* One logical change per commit; a docs sync that records a behaviour change may
  be its own commit but must land in the same PR.
* `CHANGELOG.md` gets an entry under `[Unreleased]` for anything a user of the
  binaries or the behaviour would notice.
* [`.github/CODEOWNERS`](.github/CODEOWNERS) reviews every path; the supply-chain
  files (`deny.toml`, `.github/workflows/`, `Cargo.lock`) and `parity/` are the
  paths where a silent regression is cheapest to introduce and most expensive to
  discover, so expect closer review there.
* Do not push directly to `main`; do not mix an audit remediation with unrelated
  refactoring in one commit.

## 9. When a gate is wrong

Fix the code, not the gate. `parity/verify_hygiene.sh` ends with that sentence for
a reason: every check in `parity/` was written after something survived three
audits, four CI jobs and 138 tests. If a check is genuinely wrong, say so in the
PR and replace it with one that catches the real thing - do not widen a skip list.
