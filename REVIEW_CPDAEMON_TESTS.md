# Review: cpdaemon end-to-end tests (`cff352e`)

Two independent models adversarially reviewed the `cpdaemon` lib target + e2e
tests, each in its own git worktree (`review/glm-53`, `review/qwen38`). This file
keeps the findings and how each was resolved, so the triage is auditable.

- **GLM-5.3-Flash** (`netis/GLM-5.3-Flash`) — report below.
- **DeepSeek-V4.1-Flash** (`netis/DeepSeek-V4.1-Flash`) — report below.
- `netis/qwen3.8-flash-next` was dispatched twice but the provider returned
  `502 upstream provider connection failed` both times; no report.

Every finding was verified by hand before acting on it; the fixes are in the
follow-up commit and each non-obvious one has a red→green experiment recorded in
the triage table.

## Triage

| # | Finding | Verdict | Resolution |
|---|---|---|---|
| GLM-1 | Syncer e2e hangs (not fails) if the loop never reaches shutdown | real (HIGH) | `ShutdownOnDrop` guard; verified: forcing register to 500 makes the test **fail in ~10s**, not hang |
| DS-1 | `stop()` assertions are tautological (stop sets `pid=0`; `is_alive()` reads it) | real (BLOCKER) | capture the OS pid and assert `kill(pid, 0)` → gone; verified: removing the `kill()` calls makes the test fail |
| GLM-2, DS-2 | A panic mid-test orphans a real `cpworker` | real (HIGH) | `WorkerGuard` RAII + `Worker::stop()` on drop; verified: panic right after `start()` leaves **0** orphan processes |
| GLM-3 | Mock discards the `{id}` path segment, so the daemon-id flow is unpinned | real (MEDIUM) | `Recorded` now stores `strategy_ids`/`metrics_ids`; asserted in the contract and syncer tests |
| DS-3 | The commit claims the `syncer → WorkerManager → cpworker` path, but the syncer test uses `strategy: []` and never spawns | real (MEDIUM) | added `worker_mgr` unit tests for the config bridge (`num_items`, `build_tasks`, `new_worker_config`, `get_task_buffer_size_mb`); the full spawn path is now covered by `worker_manager_spawns_the_real_cpworker` (privileged `#[ignore]` in the `live-capture` job), which serializes a strategy, spawns the real `cpworker`, drives it and stops it |
| DS-4, GLM-7 | `cargo test -p cpdaemon` neither builds nor refreshes `cpworker` (stale-binary risk); blanket `dead_code` allow | real (MEDIUM/LOW) | documented the supported `--workspace` invocation + stale-binary caveat in the helper; kept the module allow with an explicit rationale (each test binary uses a subset) |
| GHM-4 | `is_alive()` right after start cannot see an instantly-crashed (zombie) worker | real (LOW) | liveness is now asserted *after* the socket + control handshake |
| GLM-5, DS-5 | The pid-file wait proved nothing (the daemon writes it synchronously) | real (LOW) | assert the pid file's *content* == `worker.pid()`, and fixed the comment |
| GLM-6, DS-6 | Reload only pinned "survives", not "applied" | partial (LOW) | the `reload_config` OK reply already implies cpworker parsed the rewrite; the test/comment now say exactly that (observing the *applied* log level needs a new `info` field) |
| GLM-9 | `pub` modules make `#[allow(dead_code)]` markers inert | real (NIT) | only `config`/`cpm`/`error`/`reslimit`/`tool`/`worker`/`worker_config` are `pub` now; the trade-off is documented in `lib.rs` |
| GLM-10, DS-10 | Hard-coded `/tmp` socket path in the syncer config | real (NIT) | uses a `tempfile::tempdir()` path |
| GLM-11 | The syncer test never exercises in-loop `304` | real (NIT) | mock answers `304` at version 1, so "not changed → no reconcile" is exercised |
| DS-7 | `sync_metrics` does not validate the body `{"code": >= 400}` envelope | **false positive** | confirmed against `cpdaemon/pkg/cpm/client.go:153-176`: Go's `SyncMetrics` does exactly `assert2xx` + discard. Added `sync_metrics_accepts_a_body_code_like_the_go_client` so a future "fix" cannot silently diverge |
| DS-8 | Strategy/metrics HTTP-level error paths untested | real (LOW) | added `sync_strategy_http_error_*` and `sync_metrics_http_error_*` |
| GLM-8 | Module-wide `dead_code` allow | accepted | justified in `tests/common/mod.rs`: the helper is shared by binaries that each use a subset |

## GLM-5.3-Flash report

All experiments are done and the worktree is clean. Here is the report.

---

# Adversarial review: cpdaemon lib target + end-to-end tests (`cff352e`)

**Verified environment:** `cargo test -p cpdaemon` passes once `target/debug/cpworker` is built (contract 6/6 in 0.04s, syncer 1/1 in ~0.3s, supervision 1/1 in ~0.6s, stable over 5+ runs); `cargo clippy -p cpdaemon --all-targets` is clean (CI runs it with `-D warnings`). MSRV 1.88 is not threatened: `tempfile` 3.x and the tokio `time` feature are both fine, and macOS is fine (tempdir socket paths are ~55 chars, well under the 104-char `sun_path` limit; `nix::ifaddrs` works there).

All three experiments cited below were run against a copy of the test setup; the worktree was left unmodified.

---

## 1. HIGH — `syncer_end_to_end.rs`: the failure path hangs forever instead of failing

**`crates/cpdaemon/tests/syncer_end_to_end.rs:93-107`** — the `assert!(ready, ...)` fires *before* `tx.send(true)` is ever reached, and there is no shutdown guard. If the syncer is broken (e.g. register never arrives), the test panics with a *hung process*, not a red test.

**Evidence (experiment):** I reproduced the exact pattern — a `#[tokio::test(flavor="multi_thread", worker_threads=2)]` equivalent whose spawned task runs `Syncer::run`'s shape (one long poll: `block_in_place` + blocking `sleep_or_shutdown` retry loop, shutdown never sent) while the main future panics. Result: the panic message prints, then the process **deadlocks in runtime shutdown** (killed by `timeout` with exit 124, no further output). Mechanism: `Syncer::run` is synchronous inside `tokio::spawn(async move { syncer.run(rx) })`, so the task's poll never completes; `Runtime::drop` waits for worker threads to park, and `sleep_or_shutdown` (syncer.rs:220-233) never returns because `tx` was dropped without sending (`*shutdown.borrow()` stays `false`). `handle.abort()` does not help — the task is mid-poll, and abort only takes effect at yield points.

**Impact:** a syncer regression manifests as a hung CI job (killed by the job timeout), not a failed test — the worst kind of false green.

**Fix:** install a drop guard before the wait so shutdown is always signalled:
```rust
struct ShutdownOnDrop<'a>(&'a watch::Sender<bool>);
impl Drop for ShutdownOnDrop<'_> { fn drop(&mut self) { let _ = self.0.send(true); } }
```
With the guard, `sleep_or_shutdown` returns within ~100 ms, the task's poll completes, and the runtime drops cleanly even when the assert fires.

---

## 2. MEDIUM — `worker_supervision.rs`: a panic mid-test leaks a running `cpworker`

**`crates/cpdaemon/tests/worker_supervision.rs:113`** — `worker.stop()` is only reached on the happy path; `Worker` has no `Drop`, so any panic between `start()` (line 46) and `stop()` (line 113) orphans the child.

**Evidence (experiment):** a test that spawns the real `cpworker` and panics immediately after `start()` leaves the process alive after the test binary exits:
```
thread 'experiment_panic_after_start' panicked at ...:49:5
2878193 /tmp/cp-review-glm/target/debug/cpworker -c /tmp/.tmp69SShr/worker.json
ORPHANED cpworker still running
```
The detached waiter thread only reaps the child *when it exits* — it never kills it. The tempdir is cleaned up during unwind, but the process (with a live unix control socket) persists beyond the test run and the machine.

**Fix:** wrap the worker in a guard whose `Drop` calls `worker.stop()` (SIGINT → 10s → SIGKILL is already bounded, so the guard is cheap and safe).

---

## 3. MEDIUM — `common/mod.rs`: the mock discards the `{id}` path segment, so the daemon-id part of the wire contract is unpinned

**`crates/cpdaemon/tests/common/mod.rs:177` and `:195`** — both handlers take `Path(_id): Path<i64>` and never record or validate it; `Recorded` has no field for it. The suites claim to pin "the wire contract" / "what actually crossed the wire" (syncer_end_to_end.rs header), but the daemon id in `/api/v1/daemons/{id}/sync/strategy` and `.../sync/metrics` is exactly what is *not* asserted.

**Precise argument:** if `HttpClient::sync_strategy`/`sync_metrics` built the URL with the wrong id (e.g. a hardcoded `0`, or swapped arguments), every test would still pass: the mock returns 200 regardless of the id, `sync_strategy_parses_a_changed_strategy` asserts only the body and the `version` query, and the syncer test asserts only bodies and versions. The client code is currently correct, so this is a coverage gap in the claimed pin, not a live bug.

**Fix:** record the path ids in `Recorded` (e.g. `strategy_ids: Vec<i64>`), and in the syncer test assert the strategy/metrics requests went to the registered id (`77`), which also pins the register→`daemon_id` flow end-to-end.

---

## 4. LOW — `worker_supervision.rs`: `is_alive()` right after start cannot detect a crashed worker (zombie)

**`crates/cpdaemon/tests/worker_supervision.rs:62`** — `assert!(worker.is_alive(), "worker must be alive right after start")`.

**Evidence (experiment):** `Worker::is_alive` (worker.rs:81-92) uses `kill(pid, None)`, which succeeds for a *zombie* — a child that already exited but has not been reaped by the waiter thread. I spawned `/bin/false` as the executable: `is_alive()` returned `true` even though the child was already dead. So this assertion is green even if the worker crashes instantly at spawn (e.g. because it rejects the written config) and cannot fail for the bug its message implies. The real liveness signal in this test is the socket wait + `UnixClient::dial`/`info` handshake.

**Fix:** reorder — wait for the control socket first, then assert `is_alive()` plus the handshake; or make `is_alive` zombie-aware (`waitpid(pid, WNOHANG)`) in production code.

---

## 5. LOW — `worker_supervision.rs`: the pid-file wait is a no-op and its comment is wrong

**`crates/cpdaemon/tests/worker_supervision.rs:73-77`** — the comment says "PID file and control socket are created asynchronously by the child", but the **daemon** writes the pid file synchronously inside `Worker::start` (worker.rs:167), before `start()` returns.

**Evidence (experiment, same run as #4):** `pid file exists immediately after start: true` — the `wait_until(5s, || pid_path.exists())` never waits and would pass even if the worker crashed instantly. Its only real value is catching the pid-write failure that `start()` swallows (worker.rs:167-170 logs but does not propagate the error). The socket wait (line 79) is what actually catches a config the worker rejects.

**Fix:** correct the comment ("the daemon writes the pid file in `start()`; the child creates the control socket"), and consider asserting on the pid file's *content* (`== worker.pid()`) so it pins something the wait cannot trivially satisfy.

---

## 6. LOW — `worker_supervision.rs`: reload is pinned only as "survival", not as "applied"

**`crates/cpdaemon/tests/worker_supervision.rs:104-109`** — the test rewrites the config with log level `DEBUG`, sends `reload_config`, sleeps 300 ms, and asserts the worker is alive.

**Precise argument:** the `reload_config` `expect` *does* pin that the rewritten config is accepted — cpworker's handler parses the file (`crates/cpworker/src/task.rs:696-700`) and replies `{"status":"ERROR"}` on a malformed rewrite, which becomes `Error::NotOk` and fails the test. But a cpworker that accepted the command and *ignored* the rewritten config would still pass: nothing observes the reloaded state (`info` has no log-level field, and the worker's stdout/stderr are piped to log readers the test never captures). The 300 ms sleep adds nothing because `reload_from_file` completes before the OK reply.

**Fix:** either extend cpworker's `info` command with the active log level and assert it after reload, or state in the doc comment that only survival is pinned.

---

## 7. LOW — `cargo test -p cpdaemon` hard-fails unless `cpworker` was built first

**`crates/cpdaemon/tests/common/mod.rs:38`** — demonstrated in this very worktree: a fresh checkout has no `target/debug/cpworker`, and `cargo test -p cpdaemon` fails at the assert (`cpworker binary not found at .../target/debug/cpworker`). This is deliberate per the comment (AUDIT4 P2-2: never silently skip), and the CI gate (`cargo test --workspace --locked`, ci.yml:59) builds cpworker, so the gate is green — but the plain `-p cpdaemon` invocation is not self-sufficient.

**Fix:** acceptable as-is given the helpful message; at minimum document the prerequisite, or have the test build cpworker on demand (`cargo build -p cpworker` spawned from a sync once-guard).

---

## 8. LOW — `common/mod.rs`: module-wide `#![allow(dead_code)]` masks genuinely dead helpers

**`crates/cpdaemon/tests/common/mod.rs:10`** — the blanket allow hides two items that are dead with no rationale: `impl Default for MockCpm` (lines 64-70, never used) and the `metrics_status` builder (lines 136-139, never called by any test — only `register_status` is).

**Fix:** delete the unused items, or drop the module allow and annotate individually.

---

## 9. NIT — `lib.rs` exposes all 11 internal modules, weakening the dead-code rationales

**`crates/cpdaemon/src/lib.rs:10-20`** — every module is now `pub`, but the tests only drive `config`, `cpm`, `worker`, `worker_config` (plus `reslimit`/`tool` transitively for construction). `common`, `httpmix`, `worker_log` and `macros` (`#[macro_export]` macros are root-exported regardless of module visibility) need not be public. More substantively: items annotated `#[allow(dead_code)] // not yet wired (PARITY.md §5)` (`Syncer::sync_log`, `Worker::name`/`config_file`, `RegConfig::uuid_file`, `ResLimit::mem`) were dead only because the bin's modules were private; as pub-in-lib items the lint can never fire on them again, so the documented "not yet wired" guard is now inert and future drift in this surface will be silent.

**Fix:** make `common`/`httpmix`/`worker_log`/`macros` non-pub, and treat the remaining pub surface as a deliberate API commitment.

---

## 10. NIT — `syncer_end_to_end.rs`: hardcoded `/tmp` socket path is dead config

**`crates/cpdaemon/tests/syncer_end_to_end.rs:33`** — `/tmp/cpdaemon-e2e.sock` is never used (empty strategy → `build_tasks` returns early → no socket dir creation, no worker), so it pins nothing. A fixed `/tmp` path would collide across concurrent CI jobs if it ever *were* used.

**Fix:** use a `tempfile::tempdir()` path like the supervision suite.

---

## 11. NIT — the syncer test never exercises 304 → "no reconcile" end-to-end

The syncer test leaves `strategy_not_modified_version` unset, so the mock returns 200 with the *same* version body every tick and the syncer reconciles every 100 ms — the test tolerates endless reconciliation and only the client-contract suite pins 304 handling. Adding a variant where the mock 304s at version 1 would pin `Syncer::sync_strategy_once`'s early return on `changed == false` (syncer.rs:156-158).

---

## Tests that are sound (stated explicitly)

- **`register_sends_the_request_and_parses_the_response`** — sound. Pins request shape (`name`/`apiVersion`/`supportApiVersions`) and response parsing; would fail on wire drift. (It does not assert `clientVersion` in the sent body, but `fix_zero` is currently an empty placeholder, so nothing is hidden.)
- **`sync_strategy_parses_a_changed_strategy`** — sound. The exact `["-1"]` match on the recorded query param pins both that the client sends the version and that the first pull is `-1`: removing the `append_pair` would make the mock record `""` and fail this test.
- **`sync_strategy_304_reports_not_changed`** — sound. Pins 304 → `changed=false`, `response=None`.
- **`register_body_error_code_is_rejected`** — sound. Pins the 200-OK-with-code envelope validation, including `msg` and the code in the error text.
- **`http_error_is_reported_with_status_and_body`** — sound. Pins the HTTP-level error path.
- **`sync_metrics_posts_the_metrics_body`** — sound modulo the unrecorded path id (finding 3).
- **`syncer_registers_pulls_strategy_and_pushes_metrics`** — sound on the happy path and the correct `#[tokio::test(flavor="multi_thread")]` flavor is *required* (`futures_block_on` uses `block_in_place`, which panics on the current-thread runtime). The version round-trip genuinely requires the client to send the version: a missing param records `""` (fails `contains("-1")`), a syncer starting at 0 records `"0"` and fails too. Its failure path hangs — that is finding 1, not the assertions themselves.
- **`daemon_supervises_the_real_cpworker`** — sound in its main thrust. It drives the real binary: a written config the worker rejects is caught (the socket never appears → `wait_until` fails → `dial` fails), `info.pid == worker.pid()` proves the supervised process is the actual worker, `reload_config` fails if the worker rejects the rewrite, and `stop()` asserts pid-file removal. Its weak spots are the trivially-green liveness and pid-file assertions (findings 4 and 5) and the orphan risk (finding 2).
- **`MockCpm` plumbing** — sound: `bind("127.0.0.1:0")` is ephemeral, handlers record before replying (happens-before via the HTTP response), and the per-test runtime teardown cancels the server task cleanly.

**Summary:** the commit's client-contract tests are genuinely pinning; the two end-to-end suites are real (no stubs) but each has one significant hygiene defect (hung failure path; orphaned process), and the supervision suite's liveness/pid-file assertions are weaker than their messages claim.


---

## DeepSeek-V4.1-Flash report

# Adversarial review: `test(cpdaemon): add a library target and end-to-end tests`

Scope: `cff352e`, all touched files, plus exercised production code. I ran `cargo test -p cpdaemon` (20/20 pass), `cargo clippy -p cpdaemon --all-targets` (clean), and `cargo +1.88.0 build -p cpdaemon --all-targets --locked` (clean). I also ran two throwaway experiments (reverted; `git status` clean).

---

## 1. blocker — the "clean stop" assertions are tautological; a `stop()` that never signals the child still passes

`crates/cpdaemon/tests/worker_supervision.rs:114-115`
```rust
assert!(!worker.is_alive(), "worker must be stopped");
assert!(!pid_path.exists(), "pid file must be removed on stop");
```
`Worker::stop()` unconditionally sets `st.pid = 0` (`crates/cpdaemon/src/worker.rs:208`) and removes the pid file (`worker.rs:218`) *after* the wait. `Worker::is_alive()` returns `false` when `pid <= 0` (`worker.rs:106-109`). So both assertions are computed from state `stop()` itself just fabricated; they cannot observe whether the OS process died. The comment at `worker_supervision.rs:111` ("then … the process is gone") is not verified — `client.close()` on line 112 is discarded.

Evidence (experiment): I removed the two `kill(...)` calls from `Worker::stop` and ran the test:
```
running 1 test
test daemon_supervises_the_real_cpworker ... ok
```
and the child was still running afterwards:
```
2908655 /tmp/cp-review-qwen/target/debug/cpworker -c /tmp/.tmpObViU8/worker.json
```
The test only catches a *completely deleted* `stop()`; it does not catch "stop fails to terminate the worker", which is the bug it exists to catch.

Fix: assert on the OS pid captured before `stop()`, e.g. `assert!(matches!(nix::sys::signal::kill(Pid::from_raw(pid), None), Err(Errno::ESRCH)))` (or `/proc/<pid>` absence), after `stop()`; keep `is_alive()` only as a daemon-state check.

## 2. high — a panic mid-test orphans the real `cpworker` process

`crates/cpdaemon/tests/worker_supervision.rs:39-58` (start) / `:113` (the only `stop`).
`Worker` has no `Drop` (confirmed: `grep -n "impl Drop" crates/cpdaemon/src/worker.rs` → none). Any failing `expect`/`assert` between `worker.start(...)` and `worker.stop()` (e.g. a flaky `client.info`, the socket timeout) unwinds the `#[test]`, drops `worker` without signalling, and leaves a polling `cpworker` behind. This was directly observed in experiment #1: removing the kill left an orphan that outlived the test binary, holding a unix socket in a `tempfile` directory the harness deleted.

Fix: wrap the worker in an RAII guard whose `Drop` calls `stop()` (or `catch_unwind`), and/or add a `Drop` for `Worker` that SIGKILLs a still-running child.

## 3. medium — the suite still does not exercise the path the commit claims to cover (`syncer → WorkerManager → cpworker`)

The syncer test deliberately uses `strategy: []` (`crates/cpdaemon/tests/syncer_end_to_end.rs:65-67`), so `WorkerManager::create_unlocked` returns at the empty-task early-out (`worker_mgr.rs:170-178`) and never spawns anything. `worker_supervision.rs` bypasses `WorkerManager` entirely and drives `Worker` + `cpgolib::cpworker::UnixClient` by hand (`worker_supervision.rs:45`, `:104-107`). `grep` shows no test calls `create_if_dead`/`update`/`update_by_reload` in a way that reaches the spawn/reload branch, and there are no unit tests for `worker_mgr.rs`. The commit message's "the whole CPM -> syncer -> worker path had no executable evidence" is therefore still not addressed; `new_worker_config`/`build_tasks`/`num_items` (the actual config-serialization bridge) remain unverified end-to-end.

Fix: give the syncer e2e one trivial strategy (e.g. `pcap_file` over a temp file, no privileges needed) and assert the syncer's `WorkerManager` spawned a live worker and pushed non-zero/at-least-present stats.

## 4. medium — `cargo test -p cpdaemon` neither builds nor freshness-checks the binary it depends on

`crates/cpdaemon/tests/common/mod.rs:32-40` locates `target/debug/cpworker`; `crates/cpdaemon/Cargo.toml` has no dev-dependency on `cpworker`. There is no build edge, so cargo will not rebuild cpworker for this package. Evidence (experiment): with `target/debug/cpworker` moved away, `cargo test -p cpdaemon --test worker_supervision` failed immediately with *"cpworker binary not found"*; cargo had not built it. Conversely, after editing cpworker sources, the cpdaemon test will happily run against a **stale** binary, so a broken cpworker can still yield a green supervision test. The locator doc comment ("or the `-p cpdaemon` case") overstates support.

Fix: obtain the path via a real build edge — e.g. make the test invoke `cargo build -p cpworker` first (or add a `build.rs`/`escargot`), or at minimum compare the binary mtime against `crates/cpworker/src` and fail loudly if stale. Document `cargo test --workspace` as required.

## 5. low — pid-file wait/assert does not involve the child at all

`crates/cpdaemon/tests/worker_supervision.rs:73-77` says "PID file and control socket are created asynchronously by the child" and waits on `pid_path.exists()`. In fact the **parent** writes the pid file synchronously in `Worker::start` (`worker.rs:166-168`) before the child has done anything. So the pid-file wait/`!pid_path.exists()` after stop prove nothing about cpworker. (The config-consumption claim *is* soundly covered: the worker can only create the unix socket at the path parsed from the daemon-written file, and `info.pid == worker.pid()` proves a live, responding child.)

Fix: drop the misleading `pid_path` liveness assert or read the pid file and assert it equals `info.pid`; the socket + `info` checks are the real evidence.

## 6. low — reload test uses a fixed sleep and never checks the new config took effect

`crates/cpdaemon/tests/worker_supervision.rs:107-109`: after `client.reload_config(...)` it does `std::thread::sleep(300ms)` then only asserts the process is alive. `reload_config` is dispatched **synchronously** on the worker's control thread (`crates/cpworker/src/unix_manager.rs:"reload_config"` → `reload_from_file`), returning `status: OK` only after applying; a crash after the reply is possible but 300ms is an arbitrary window. The test also never observes that `DEBUG` was applied, so a `reload_config` that replies OK without re-reading the file would pass.

Fix: replace the sleep with a poll on an observable effect (e.g. the new config's log level reflected in `info`/logs), or at least assert via the control channel rather than elapsed time.

## 7. low — `sync_metrics` never validates the `{"code": >= 400}` envelope, and no test notices

`crates/cpdaemon/src/cpm/client.rs:124-145` checks only the HTTP status; `check_body_error` is called for `register` (`:81`) and `sync_strategy` (`:115`) but not `sync_metrics`. `sync_metrics_posts_the_metrics_body` (`cpm_client_contract.rs:140-158`) only exercises 200-OK. If the Go contract treats a 200 body with `code >= 400` as failure for all three endpoints, this is an untested production divergence; if not, the asymmetry is still undocumented.

Fix: either add `check_body_error` to `sync_metrics` and a test, or add a comment/parity note explaining why metrics is exempt.

## 8. low — strategy/metrics HTTP-level error paths are claimed but not tested

`common/mod.rs` provides `strategy_status`/`metrics_status` builders (`:123`, `:136`) but no test ever uses them (`grep` in `tests/` shows only `register_status(503)`). Yet the commit message advertises "an HTTP-level error" as contract coverage and the mock implements both. The non-2xx branches at `client.rs:112-117` (strategy) and `:130-139` (metrics) are therefore uncovered.

Fix: add `strategy_status(500)` and `metrics_status(503)` cases asserting `status_code: …` in the message.

## 9. nit — shared mock module silences `dead_code`, hiding the unused builders

`crates/cpdaemon/tests/common/mod.rs:23` `#![allow(dead_code)]` is what makes finding 8's unused `metrics_status`/`strategy_status` invisible. Prefer per-item `#[allow(dead_code)]` (or just use them).

## 10. nit — hard-coded /tmp socket path in the syncer config

`crates/cpdaemon/tests/syncer_end_to_end.rs:32-34` sets `path: "/tmp/cpdaemon-e2e.sock"`. It is currently harmless (empty strategy ⇒ no worker spawned, so `create_unlocked`'s `create_dir_all`/bind never runs), but it is a cross-test collision hazard and will become one the moment finding 3 is fixed. Use a `tempfile::tempdir()` path.

---

## Tests that are actually sound

- `cpm_client_contract.rs`: `register_sends_the_request_and_parses_the_response`, `sync_strategy_parses_a_changed_strategy` (asserts the recorded `version=-1` query), `sync_strategy_304_reports_not_changed`, `register_body_error_code_is_rejected` (`boom`/`500` can only come from `check_body_error`; removing it yields an `unmarshal …` message and fails), `http_error_is_reported_with_status_and_body`, `sync_metrics_posts_the_metrics_body`. These pin real wire behavior against a real HTTP server on an ephemeral port (`bind 127.0.0.1:0`, `common/mod.rs:157`) — no fixed-port flakiness.
- `syncer_end_to_end.rs:97-98`: the `-1` then `1` pair does require the client to send a version. A client that never sends it records `""`; one that never updates records only `"-1"`; and since `SyncStrategyResponse.version` is `#[serde(default)]` (`models.rs:124-125`), a parsing regression yields `"0"` — all three fail. The only contrived escape is hard-coding `store(1)` in the syncer, which is not a realistic regression. Sound.
- Config consumption by the real cpworker: proven by the socket at the daemon-written path plus `info.pid == worker.pid()` (`worker_supervision.rs:79-88`). Schema drift makes cpworker exit before binding the socket, so it fails the test.
- MSRV/portability: `cargo +1.88.0 build -p cpdaemon --all-targets --locked` passes; `tempfile 3.27` declares `rust-version = "1.63"`. `nix::kill`, `UnixStream`, `tempfile`, and the binary locator are portable to macOS; no macOS-specific problem found.
- `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` is the correct flavor for the syncer test, since `Syncer::run` uses `block_in_place` (`syncer.rs:futures_block_on`); the single-threaded contract tests never call it. No `time`-feature MSRV issue (the added feature is only needed by the tests' `tokio::time` usage; moving it to a dev-dependency feature would be marginally cleaner).

No worktree modifications were left behind.
