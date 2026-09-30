# Upstream Catch-Up Runbook — the floating 0.9.x oracle

We do **not** pin the reference implementation. Both differential CI jobs check out
`netis/cloud-probe@0.9.x` live:
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) job `parity` (`bash parity/all.sh`)
and job `fuzz` (`./fuzz.sh --check` + `./parity/difffuzz.sh 5 all`). An upstream commit can
therefore turn this repository red without one line changing here. That has happened three
times — **#279**, **#281**, **#282** — each converged by a follow-up commit (see
`git log --oneline --grep 'upstream #'`).

Contract (from `CONTRIBUTING.md` §5 and `PARITY.md`): the port must match the *current* tip
on every input where both sides are defined; any deliberate difference is recorded in
`PARITY.md` §2 and excluded from the generators. The oracle floats; the port converges.

## 1. Fetch and compare

The local reference checkout is `/tmp/cp-09x`. The harnesses read the **working tree**, not
a ref, so fast-forward the checkout itself — a stale tree quietly re-tests the old tip
(measured: the detached checkout sat at `3ff882c` while `origin/0.9.x` was already at
`d302572`).

```bash
git -C /tmp/cp-09x fetch --prune origin 0.9.x
git -C /tmp/cp-09x checkout 0.9.x
git -C /tmp/cp-09x merge --ff-only origin/0.9.x
git -C /tmp/cp-09x log --oneline -20   # subjects end in the upstream PR number, e.g. (#282)
```

Point the harnesses at that tree (unset, every script falls back to a sibling
`../cloud-probe` and fails with `set CLOUD_PROBE_SRC`):

```bash
export CLOUD_PROBE_SRC=/tmp/cp-09x
```

To list what is new since the last catch-up, diff against the upstream tip recorded in the
previous `port upstream #NNN` commit body (recent anchors: `#279` @ `e7bbc66`,
`#281` @ `b96d0de`, `#282` @ `3ff882c`):

```bash
git -C /tmp/cp-09x log --oneline <last-synced-sha>..origin/0.9.x
git -C /tmp/cp-09x show <sha>                    # one upstream fix at a time
git -C /tmp/cp-09x show --stat <sha>             # narrow the touched files first
```

`CLOUD_PROBE_SRC` may point at any tree (a fresh clone, a PR head); nothing requires
`/tmp/cp-09x` specifically.

## 2. Which gate goes red first

`bash parity/all.sh` runs ten steps in order and stops on the first failure. Steps 1–5
compare against the C/Go oracle sourced from `CLOUD_PROBE_SRC`; steps 6–7 compare against
an external reference (libzmq / libpcap); 8–10 are anti-regression gates that never
validate against upstream. Typical upstream edits land as:

| Upstream area | First red gate |
| --- | --- |
| `cpworker/src/packet_split.c` | `all.sh` 1/10 packet_split |
| `cpworker/src/config.c`, `cjson_utils.c` (and `bpf_util.c` exclusion) | `all.sh` 2/10 config |
| `cpworker/src/req_pattern.c` | `all.sh` 3/10 req_pattern |
| `cpworker/src/output_gre.c`, `output_vxlan.c`, `output_zmq.c` | `all.sh` 4/10 protocol |
| `cpworker/src/unix-manager.c`, `unix_rpc_basic.c` | `all.sh` 5/10 unix RPC |
| `cpgolib` fingerprint/common (Go) | diff-fuzz `fingerprint` |
| `cpdaemon/pkg/cpm/worker_task_builder.go` | diff-fuzz `task_fingerprint` |
| `cpworker/src/bpf_util.c` (BPF semantics) | step 2 for exclusion; else Rust test |

Replay one gate at the CI sizes (`CLOUD_PROBE_SRC` exported, §1):

```bash
parity/run.sh 2000 42                 # 1/10 packet_split   (PACKET_N / PACKET_SEED)
parity/verify_config.sh 1000 17       # 2/10 config         (CONFIG_N / CONFIG_SEED)
parity/verify_req.sh 1000 555         # 3/10 req_pattern    (REQ_N / REQ_SEED)
parity/fuzz_proto.sh 30 3             # 4/10 protocol       (PROTO_CASES / PROTO_SEEDS)
parity/fuzz_rpc.sh                    # 5/10 unix RPC
parity/difffuzz.sh 60 packet_split    # diff-fuzz, one mode (or 'all')
```

Two gates do **not** source the oracle from upstream and so never go red on an upstream
change by themselves:

* **6/10 ZMTP interop** (`parity/verify_zmtp.sh`) tests the Rust ZMTP PUSH against a real
  libzmq PULL — it catches Rust-side regressions, not `output_zmq.c` edits (those hit 4/10).
* **7/10 BPF filter** (`parity/verify_bpf.sh`) compares the Rust compiler against **system
  libpcap**, not `bpf_util.c`. A `bpf_util.c`-only semantic change (e.g. #281's
  `nic.<if>` tokenization) needs the differential fuzzer plus a Rust regression test and a
  `PARITY.md` note.

The `parity/fuzz` job adds the coverage-guided halves: `./fuzz.sh --check` (5 s per
in-process target) and `./parity/difffuzz.sh 5 all` (Rust in-process vs a C/Go oracle
subprocess; modes `packet_split config req_pattern fingerprint task_fingerprint`). A
divergence saves the input under `crates/cpworker/fuzz/artifacts/difffuzz/` and points at
`/tmp/difffuzz_last.txt`. The `diff_oracle` fuzz target is driven only by `difffuzz.sh`
(it is the one documented exemption in `parity/verify_hygiene.sh`).

By hand, at the larger local defaults:

```bash
bash parity/all.sh          # 10 steps; CI runs the same script at smaller sizes
./fuzz.sh --check           # cargo-fuzz smoke
./parity/difffuzz.sh 5 all  # differential-fuzz smoke
```

## 3. Convergence procedure

1. **Triage.** Note which gate failed on the PR/CI run and the exact parameters (every
   script names the seed it used; replay by re-running the same command with the same
   arguments).
2. **Refresh and locate the upstream commit(s).** §1. The failing gate tells you the file;
   `git -C /tmp/cp-09x log -p origin/0.9.x -- <upstream file>` shows just those commits.
3. **Map upstream change → Rust code.** Find the counterpart with `symbol_search`/`grep`
   (`PARITY.md` §1.1/§1.2 is the C/Go→Rust file map). Classify each hunk:
   * behaviour the port must match → port it;
   * UB / memory-unsafe in C (`PARITY.md` §2.2) or a benign invalid-input divergence
     (§2.3, §2.4, §2.5) → record it, exclude it from the generator;
   * fault-path/refactor with no observable wire/JSON change → port for semantics and add
     a Rust test, but expect no differential vector.
4. **Fix the Rust code** to match the new oracle. If the divergence is C UB (e.g. deep
   `req_pattern` recursion, a heap overflow), the fix is a bound on *both* sides — add the
   same guard to the C oracle harness in `parity/` and note it in `PARITY.md`.
5. **Add or adjust the differential vector.** Extend the generator (`parity/gen_*.py`) or
   freeze a boundary vector in the relevant `parity/verify_*.sh` (see the `#279` block in
   `verify_config.sh`). For a cargo-fuzz target, drop a regression seed under
   `crates/cpworker/fuzz/seeds/<target>/` (targets with seed dirs: `bpf`, `pcap_reader`,
   `sim_dst`, `zmq_batch`). The five differential modes (`packet_split config req_pattern
   fingerprint task_fingerprint`) have no seed dir; freeze the case in the generator or a
   boundary vector instead. Derive the case from the upstream commit and the
   spec (`PARITY.md`), not by reading the Rust implementation — spec-first (ADR-0001).
6. **Re-green everything:** `bash parity/all.sh`, `./fuzz.sh --check`,
   `./parity/difffuzz.sh 5 all`, `cargo test --workspace --locked`,
   `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets --locked -- -D warnings`.
7. **Record it.** Update the affected `PARITY.md` §2 subsection and add a `CHANGELOG.md`
   `[Unreleased]` entry for anything observable.
8. **Commit** `fix(parity): port upstream #NNN (<area>)`; the body names the oracle tip and
   the exact commands that were run (precedent: commit `1c93c37`).

## 4. Per-commit checklist

- [ ] `/tmp/cp-09x` fetched and fast-forwarded; `CLOUD_PROBE_SRC` points at the new tip.
- [ ] Every upstream commit since the last anchor triaged and mapped (or explicitly
      classified as no-parity-impact).
- [ ] Rust change has a red→green test that failed on the pre-fix tree (`CONTRIBUTING.md` §4).
- [ ] Differential generator / boundary vector added or adjusted for the new case.
- [ ] A regression input is seeded under `crates/cpworker/fuzz/seeds/<target>/` where one
      fits (cargo-fuzz targets only), or frozen in the generator / a `verify_*.sh` vector.
- [ ] `bash parity/all.sh` green at the CI sizes (`PACKET_N=2000 CONFIG_N=1000 REQ_N=1000
      PROTO_CASES=30 PROTO_SEEDS=3`).
- [ ] `./fuzz.sh --check` and `./parity/difffuzz.sh 5 all` green.
- [ ] `cargo test --workspace --locked`, `cargo fmt --all -- --check`, `cargo clippy
      --workspace --all-targets --locked -- -D warnings` green.
- [ ] `PARITY.md` updated (or an explicit note why the change is not observable there).
- [ ] `CHANGELOG.md` `[Unreleased]` updated.
- [ ] Commit message references the upstream PR number and records the new oracle tip.
