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

- **混杂模式默认开启（`libpcap.promisc`，`cloud-probe-rs-sdt` / j36.2）**：新增可选
  `libpcap.promisc` 配置键，缺省 **`true`**。`AF_PACKET` 抓包器在 true 时
  `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC)`；失败只打 WARN 并按旧的非混杂行为
  降级（与 `SO_RCVBUFFORCE` 回退一致，不中止进程），显式 `false` 保持此前精确行为。真机 NIC 上
  `rx-vlan-filter: on` 时非混杂会丢未注册 VLAN 的 802.1Q/QinQ 帧（现场实测 `tcpdump` 900 帧、
  `tcpdump -p`/cpworker 300 帧），trunk/SPAN 场景下这是功能正确性修复而非 parity 细节。C 的 libpcap 路径
  `opts.promisc = 0` 为硬编码（`libpcap.c:340`），故相对 oracle 属**有意分歧**；DPDK pdump 本就默认开。
  `pcap_file`/`dpdk_pdump` 不接受也不使用该键。测试：配置解析单测
  `libpcap_promisc_defaults_to_true_and_is_configurable`（缺省/显式 false/显式 true）与
  `libpcap_promisc_rejects_null`；root-gated 实测
  `live_capture_promisc_joins_membership_and_takes_foreign_mac`（`IFF_PROMISC` 随 socket 建立/关闭置清，
  物理 NIC 上断言非本机 MAC 帧在非混杂下不被投递；veth 不建模 RX 过滤，已文档化）。见 `PARITY.md` §2.5、
  `FIELD_CONFIRMATION.md` §2/§4。
- **BPF `ether proto <ethertype>`**（`cloud-probe-rs-57d`，字段回归；`PARITY.md` §4 BPF 子集）：
  纯 Rust BPF 编译器现在接受 `ether proto 0x88b5` 这类 libpcap/`tcpdump` 语法，而不再以
  `expected 'host' after 'ether'` 拒绝整个任务（现场发现：`bpf='ether proto 0x88b5 or ...'`
  导致 init 0 tasks）。数字按 libpcap 规则解析为 base-0（`0x` 十六进制、前导 `0` 八进制、否则十进制，
  上限 `u32::MAX`），并接受 `\ip`/`\ip6`/`\arp`/`\rarp` 转义名。数值 > 1500 编译为
  `ldh [12]; jeq N`；≤ 1500 时与 libpcap 一致按 802.3 长度字段处理（先 `jgt 1500`，再比较偏移 14
  的 LLC 字节）。测试：`bpf::parser::tests::parses_ether_proto_numeric_and_named`、
  `ether_proto_number_base_zero`、`bpf::compiler::tests::ether_proto_matches_ethertype_and_8023_length`
  与 golden `golden_protocol_and_ethertype`；`parity/verify_bpf.sh` 生成器新增这些表达式/帧，
  与 libpcap `pcap_offline_filter` 逐包一致。

- **DPDK pdump capturer（bead 4mv.1，`PARITY.md` §5.1）**：`dpdk/pdump.c` 已移植到
  `crates/cpworker/src/capturer/dpdk_pdump.rs`，由 Cargo feature `dpdk` 门控。默认
  `cargo build` 完全不依赖 DPDK：`dpdk_pdump` 配置照常解析，但 `open()` 返回明确的
  「built without the `dpdk` feature」错误；`--features dpdk` 时 `build.rs` 用上游相同的
  `pkg-config libdpdk` 检查并给出安装提示。选项映射逐字段对齐
  `dpdk_capture_new_from_cfg`（`interface`/`snaplen`/`bpf`/`ring_size`、`pool_name`= `cpworker_capture_mbufs`、
  `ring_name` = `cpworker_capture_ring`、`num_mbufs = 2 * ring_size`），`promiscuous_mode = true`
  为上游硬编码（`pdump.c:386`，即 `FIELD_CONFIRMATION.md` §2 的 promisc 结论），因此**不新增
  配置键**。EAL 参数、ring 2 的幂次取整、pdump flags、默认值与错误路径有单测
  （`capturer::dpdk_pdump::tests`，含无 feature 的 gate 错误）。**残留边界**：本环境无 DPDK
  开发库，`rte_*` 运行时层按 DPDK 21.11/22.11 导出符号声明（仅 feature 编译，`cargo check` /
  `clippy --features dpdk` 通过），数据面未在真实设备上执行；上游从未调用的 `dpdk_init`
  在本 port 懒加载调用一次，primary 监控 alarm 为尽力而为移植。
- **CPM mTLS 客户端证书（PKCS#12）**（`cloud-probe-rs-ryg.2`，`PARITY.md` §2.7 / `SECURITY.md`）：
  当 `cpm.client.tls.pkcs12_cert_file` 非空时，用纯 Rust `p12` crate 解码 PKCS#12（仅
  `PBE-SHA1-RC2-40` / `PBE-SHA1-3DES`，与 oracle 的 `golang.org/x/crypto/pkcs12` 支持范围一致），
  校验 MAC 后把证书链与 PKCS#8 私钥 PEM 包装成 `reqwest::Identity` 并作为客户端身份发送；密码错误 /
  损坏档案 / 缺文件在启动时报错，不会静默回退成无客户端证书。未配置该键时行为不变（默认不发送客户端证书），
  ryg.1 的服务端证书默认校验也保持不变。测试：`crates/cpdaemon/tests/cpm_mtls.rs` 用**要求客户端证书的
  rustls 服务端**证明握手成功且服务端观察到该叶子证书，未配置时同一服务端拒绝握手；
  `client.rs` 单测覆盖解码、错误密码与 PEM 包装。
- **Verification Coverage 体系**（决策记录 [ADR-0001](docs/adr/0001-verification-coverage.md)，
  细节 [VERIFICATION_COVERAGE.md](VERIFICATION_COVERAGE.md)）：按风险分层的覆盖率策略
  （Tier 0/1/2/3 目标 line 95/90/80/60、关键函数 100% function coverage、变更行 line 90%/branch 85%、
  `coverage must not decrease` 棘轮），并落成机器可读的
  [`verification/policy.toml`](verification/policy.toml) + 基线 [`verification/baseline.json`](verification/baseline.json)
  + 门禁 [`verification/coverage_gate.py`](verification/coverage_gate.py) 与本地入口 [`verify_coverage.sh`](verify_coverage.sh)。
  测试必须先从 ADR/Spec 出发（spec-first）。mutation / behaviour / risk / system 维度按阶段的路线图
  在 VERIFICATION_COVERAGE.md §10 收敛。
- **Verification Coverage 阶段 2**：行为覆盖登记表 [`verification/requirements.toml`](verification/requirements.toml)
  （21 条 P0 requirement → scenario/state-transition → 236 个真实测试名）+ 门禁
  [`verification/requirements_gate.py`](verification/requirements_gate.py)（**P0 场景覆盖 = 100%**）。
  CI 的 `verify-coverage` job 改为**阻塞**（分层 line/function、关键函数 100%、no-decrease、
  变更行 line 90%/branch 85%、P0 requirements），并新增每周 `.github/workflows/verification.yml`
  （nightly `--branch` 分支覆盖 + `cargo-mutants`，暂 advisory）；mutation 配置
  [`verification/mutants.toml`](verification/mutants.toml) + 入口 [`verify_mutation.sh`](verify_mutation.sh)。
- **Verification Coverage 阶段 3**：风险覆盖登记 [`verification/risk.toml`](verification/risk.toml)
  （16 条 P0 风险，security/concurrency/data-integrity/failure-modes）+ 门禁
  [`verification/risk_gate.py`](verification/risk_gate.py)（**P0 风险 100% 有存在性验证**），纳入 CI `verify-coverage`。
  mutation 首次基线记录于 [`verification/MUTATION_BASELINE.md`](verification/MUTATION_BASELINE.md)：
  `output/gre.rs` 76/76 mutant 存活 → 已登记为待补测试缺口；每周 mutation 任务改为 4 shard 有界运行（advisory）。
- **mutation 缺口收敛**：`output::gre` 抽出 `Egress` 抽象后可单测，21 个新测试使其 mutation **50/50 caught**（原 76/76 存活）；
  `cpgolib::cpworker::stats` 补跨单位借位等测试达 **56/56**；`config` 访问器/反序列化补测后 **0 missed**。
  详见 [`verification/MUTATION_BASELINE.md`](verification/MUTATION_BASELINE.md)。
- **Verification Coverage 阶段 4**：系统层矩阵 [`verification/system.toml`](verification/system.toml)；
  weekly `verification.yml` 新增 `soak` job —— 用 `DST_SEED_RANGE` 在 `crates/sim` 的确定性仿真上扫 2000 个种子
  （ChaCha8 + 虚拟时钟 + 丢包/重复/乱序/位翻转），失败可 `DST_SEED=<seed>` 精确重放。
- `cpdaemon` now exposes a **library target** (`src/lib.rs`) and has end-to-end
  tests under `crates/cpdaemon/tests/`. This closes the largest remaining test
  gap in the port: `cpdaemon` previously had 14 unit tests and **no integration
  coverage**, so the whole "CPM pushes a strategy → daemon reconciles → worker
  runs" path had no executable evidence. The new suites are:
  - `cpm_client_contract.rs` - the CPM HTTP wire contract against an axum mock
    (register request/response, strategy pull, `304`, the `200 OK` +
    `{"code": >= 400}` envelope error, and an HTTP-level error), 6 tests.
  - `syncer_end_to_end.rs` - the real `Syncer::run` loop (register → versioned
    strategy pull → metrics push) against the mock CPM, asserting on the
    register identity, the `-1 → 1` strategy version round-trip and the metrics
    body.
  - `worker_supervision.rs` - the daemon's `Worker` supervisor driving the
    **real `cpworker` binary**: the written config is accepted by cpworker, the
    pid file / liveness / unix control socket work (`info`/`ping`/
    `collect_stats_summary`), a reload preserves the process, and `stop()`
    removes the pid file. Runs unprivileged (empty task list), so it is a normal
    gate rather than another `#[ignore]` live test.
- The new daemon tests were hardened after an independent adversarial review
  (GLM-5.3 and DeepSeek-V4.1): shutdown-on-drop and worker RAII guards so a
  mid-test failure can neither hang CI nor orphan a `cpworker`, an OS-level
  `kill(pid, 0)` assertion for `stop()` (the previous `is_alive()` check was
  tautological), daemon-id path assertions, in-loop `304` coverage, and a test
  pinning that `sync_metrics` ignores the body `code` envelope exactly like the
  Go client. Findings and triage: [REVIEW_CPDAEMON_TESTS.md](REVIEW_CPDAEMON_TESTS.md).
- The last gap from that review is now closed: `worker_manager_spawns_the_real_cpworker`
  (privileged `#[ignore]`) drives the full strategy → `WorkerManager` → real
  `cpworker` spawn bridge - config serialization, process spawn, unix control and
  captured loopback packets - and the `live-capture` CI job builds `cpworker` and
  asserts the test executed rather than silently skipping.
- `dockerpid` gained tests (it had none): unit tests for the chunked-transfer
  and inspect-JSON parsers, plus an end-to-end suite that drives the real binary
  against a mock Docker Engine API over TCP (negotiation via `/_ping`,
  `DOCKER_API_VERSION` short-circuiting it, inspect, and the usage/parse
  failures). Writing them exposed and fixed a panic: `decode_chunked` sliced out
  of bounds on a truncated chunk instead of returning an error.
- `cpctl` gained tests for `compute_ping_summary` (loss %, min/avg/max/
  population stddev, no-samples and single-sample cases) and for CLI
  `--format`/`--unix` parsing (2 → 9 tests).
- `cpgolib`'s `UnixClient` gained protocol-level unit tests (the `{"version":"v1"}`
  handshake bytes, command framing, non-OK status → error, invalid conn string,
  missing socket) on top of the daemon end-to-end coverage (7 → 12 tests).
- `cripid` gained tests for the info-map scan (the pid found in a later value,
  non-JSON and string pids skipped) and `socket_exists` (2 → 5 tests).
- [FIELD_CONFIRMATION.md](FIELD_CONFIRMATION.md): the `IMPROVEMENT_PLAN_AUDIT4.md`
  §5.1 items that need field or business input before sign-off, written as a
  checklist (what to collect, why it matters, what decision it unblocks) that can
  be handed to the teams that have the data.
- `release.yml` now also builds **aarch64-unknown-linux-gnu** (cross-compiling all
  five binaries, verified locally) so releases ship Linux ARM64 alongside x86_64
  and macOS.
- A minimal CPM mock (axum, ephemeral port, request recording) lives in
  `crates/cpdaemon/tests/common/mod.rs` for reuse by future daemon tests.

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
- `cpdaemon` now supports **cgroup v1 CPU limiting** alongside v2 (`reslimit.rs`),
  closing the last item in PARITY.md §5.1. Explicit `cgroup.version = v1` writes
  `cpu.cfs_period_us` (100ms) + `cpu.cfs_quota_us` (clamped to the 1000us kernel
  floor) and adds the pid to `tasks`; `v2` keeps `cpu.max` + `cgroup.procs`.
  `version = auto` detects v2 by `cgroup.controllers` and otherwise falls back to
  v1. `reset()` writes `-1` to the v1 quota and `max <period>` to `cpu.max`.
- `bench/live_bench.py`: manual, root-only live-capture A/B (C/libpcap vs the Rust
  `AF_PACKET` path) reporting frames captured, drop counters and CPU seconds per
  captured million frames. Not a CI gate and not a throughput ceiling - see its
  docstring for why `cap_packets` has to be read before the CPU number.

### Changed

- **Reload now reuses unchanged tasks (bead 4mv.2, PARITY.md §5.1).**
  `TaskManager::reload` used to rebuild every task, recompiling each BPF filter and
  recreating every capture socket / output connection. It now matches old tasks to
  the new config by their non-empty config fingerprint (`find_reusable`), moving an
  unchanged task's capturer and outputs into the new task set untouched; only added
  or changed tasks are built, and removed/changed ones have their outputs destroyed
  at the same single `destroy()` call point. Tasks without a fingerprint (hand-written
  configs; the daemon always computes one) are rebuilt as before, so no external
  behaviour changes. The C `task.c` thread/mailbox protocol is collapsed into the
  existing single manager mutex: the shared output thread is joined before the swap,
  so no in-flight ring message can be delivered to a reordered task slot and the
  reload path cannot nest the `out_sets`/ring locks. Proven by
  `reload_reuses_unchanged_tasks_and_rebuilds_only_the_rest` (add/remove/change/
  unchanged in one reload, with destroy spies and a per-task build generation),
  `repeated_reload_keeps_reusing_the_same_task`,
  `reload_rebuilds_a_task_without_a_fingerprint`, and the bounded
  `reload_and_stats_summary_run_without_deadlock` watchdog.

- **`unix-manager` 的 `select()` 单线程语义**（bead 4mv.3）：`unix_manager.rs` 不再采用
  “非阻塞 accept + 每客户端一个线程”，改为单线程 `poll()` 事件循环，把监听 socket 与所有客户端
  放在同一线程内多路复用，并先处理客户端再 accept（对齐 `unix_manager_main` 的顺序）。保留 1.5s
  不完整命令窗口、5s `SO_SNDTIMEO` 写预算和原有 JSON-RPC 分发；新增 5 个真实 `UnixStream` 测试
  （并发客户端、分片命令、部分帧超时断开、空闲客户端不被误断、停止读取的客户端在写预算内被丢弃），
  `parity/fuzz_rpc.sh` 继续与 C oracle **17/17 一致**。
- **无锁 SPSC ring buffer（bead 4mv.4，PARITY.md §5.1）**：`cpworker::ring_buffer::SpscRing`
  从内部 `Mutex<VecDeque>` 换成无锁单生产者/单消费者环（原子 `head`/`tail` + 显式
  `Acquire`/`Release`，对应 C `spsc_ring_push`/`spsc_ring_pop`）。公开语义不变：容量 `size` 但
  最多存 `size-1` 条、满时 `push` 返回 `Err`（消息原样退回）、`used`/`pop` FIFO，`SimpleAllocator`
  的预算记账不变。新增 `SpscRing::split` 返回一对 `RingProducer`/`RingConsumer` 句柄（`&mut self`
  借用期间不可能再构造第二个生产者），从而在安全 Rust 中表达“单生产/单消费”契约。验证：小环穷举
  交错对拍 `VecDeque` 参考模型（`bounded_interleavings_match_reference_model`）+ 200 万条单生产/
  单消费 FIFO 压力（`spsc_stress_producer_consumer_fifo`，无丢包/重复/乱序），并在 Miri
  `-Zmiri-many-seeds=0..32` 数据竞争检测下通过（把 `head` 的 `Release`/`Acquire` 改成 `Relaxed`
  时 Miri 会报数据竞争）。`verification/risk.toml` 的 `RISK-RING-CONCURRENCY` 证据同步登记。
- Parity/oracle tooling moved out of `cpworker/src/bin` into a new
  `cpworker-parity` crate (P5-29): `cargo build -p cpworker` no longer compiles
  the differential harnesses, the seven `parity/*.sh` callers now use
  `-p cpworker-parity`, and `verify_hygiene.sh` gained a P5-29 gate (plus a
  reverse-check injection) so the tooling cannot creep back into the library
  crate. The tools stay in the workspace, so `clippy --all-targets` still lints
  them.
- `cpworker`'s unimplemented `dpdk_pdump` capturer now reports "not implemented in
  this port (PARITY.md §5.1)" instead of "rebuild with the DPDK feature" - there
  is no such feature, so the old message pointed operators at a dead end.
- CI `msrv` job runs `cargo build --workspace --all-targets --locked`: plain `cargo
  build` never compiles dev-dependencies or `tests/`, so "MSRV 1.88 is verified"
  covered less than the README claimed (GLM P3-1). Verified locally on 1.88.0.
- `fuzz.sh` and `parity/difffuzz.sh` install a **pinned** `cargo-fuzz` (0.13.2) and
  assert with `cargo metadata --locked` that both workspace lockfiles still match
  their manifests before building - `cargo fuzz` has no `--locked` of its own to
  forward, so the fuzz jobs were the last place where a run could silently use a
  different dependency graph than the one `deny` audited (GLM P3-2/P3-5).
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

- **The veth capture-fidelity test is deterministic under repetition (bead
  `cloud-probe-rs-h53`).** Running
  `live_capture_veth_delivers_exactly_n_frames` in a tight loop failed
  occasionally with *"delivered frames are not the injected frames in order"*:
  a contiguous high band of sequence numbers surfaced early while the total
  stayed exact. The reorder is not in the capturer (it reads one `AF_PACKET`
  socket queue, a FIFO) but in the kernel path the test set up: veth delivers a
  transmitted frame on the sending CPU and `packet_rcv` fills the capture socket
  under a lock, so frames processed on two CPUs are queued in lock-acquisition
  order. The test now pins the injecting thread to a single
  CPU (so all frames traverse one CPU path), retries veth creation under a
  collision-resistant name, and keeps the **strict** `0..N` order assertion
  unchanged. A new bounded stress test
  (`live_capture_veth_order_is_stable_under_repetition`, 128 frames × 12
  repetitions on one pair) guards it; both passed 25/25 in a tight loop. The
  previously suspected `ulimit -n`-small harness failure is unrelated: it dies
  at `ip link set ... up` from fd exhaustion, not in the capture path.
- **P3 batch from the same two reviews.** Each item keeps its own regression test:
  * `zmq.hwm` was range-checked twice, and the second check was unreachable (the
    first `i32_in` had already enforced the same range), so its user-facing
    message - with a run of spaces in it - could never be shown. One gate now
    (`zmq_hwm_is_range_checked_by_a_single_wellformed_gate`).
  * `parse_control()` walked cmsgs with a hand-written iterator that bounded the
    *header* but not the *data*: a header claiming more than `msg_controllen`
    holds was read 16/20 bytes past the buffer (unreachable with the kernel
    filling it, but exactly the arithmetic M4 set out to remove). It now applies
    the `CMSG_OK` data bound (`parse_control_ignores_a_cmsg_that_overruns_the_buffer`,
    which before the fix reported a VLAN tag the kernel never sent).
  * A task whose second output fails to be created dropped the first output
    without ever calling `destroy()` - `Output` has no draining `Drop`, and the
    single call point is `TaskManager::stop()`, which a partially built task never
    reaches. Outputs are now parked behind `PendingOutputs`, whose `Drop` destroys
    them (`pending_outputs_destroys_everything_it_throws_away`, plus a
    `verify_liveness.sh` line, because no file output can reveal this end-to-end:
    `PcapWriter`'s `BufWriter` flushes on its own `Drop`).
  * A rejected BPF expression used to be quoted *in full* into `task.error`, which
    `print_errors()` re-logs every 60s per task (20KB lines were reproducible with
    an 8KiB filter). Errors now carry a bounded, UTF-8-safe prefix plus the length
    (`a_rejected_filter_is_quoted_with_a_bound_not_in_full`).
  * The 2-second `PACKET_STATISTICS` cadence compared packet timestamps with wall
    clock, so a fallback to second-resolution or zero timestamps could stall drop
    sampling; the cadence now uses one clock (`PARITY.md §4`).
- `bench/live_bench.py` can no longer report a broken task as "not measured", and it
  can actually do the thing its own documentation recommends (P2-4/P2-5). Unreadable
  counters are reported as `"cap_packets": "unavailable"` with exit code 3;
  `cap_packets == 0` with datagrams sent prints `!! <name> captured NOTHING` and
  exits 2 (verified live: flooding 127.0.0.1 while capturing on a veth now exits 2
  instead of printing `null`s). The flood target is parameterised: `FLOOD_DST`
  overrides, a non-loopback interface is fed with raw frames injected from its veth
  peer, and `bench/live_bench.py --selftest` covers the classification without a
  network. Measured with the veth path: 103 879 datagrams sent → 103 879 captured,
  ratio 1.0000, exit 0. `worker_cpu()` reads `/proc` directly instead of
  `pgrep -f` + `cat`, which raced and mis-matched other command lines.

- Name resolution while rebuilding tasks can no longer freeze the worker (P2-10).
  Compiling a filter that contains a host name calls `getaddrinfo()`, and both reload
  call sites were written `mgr.lock().reload_from_file()` - so with an unreachable name
  server the capture loop (same mutex, taken every batch) and `cpctl stats` were frozen
  for the resolver's own timeout while every drop counter kept reporting 0. Now: results
  are memoised process-wide for 60s (`bpf::CachedResolver`, at most 512 names, failures
  are *not* memoised so one bad answer cannot poison a name for the whole TTL), so a
  reload of an unchanged configuration resolves nothing at all; `task::prepare_reload()`
  splits "read + parse + resolve names" from "swap the tasks", and the `reload_config`
  RPC takes the lock only for the swap; the SIGHUP path goes further and prepares on a
  dedicated `task::ReloadWorker` thread, since its signal flag is consumed by the capture
  loop itself, which only polls `is_done()`. `netns` tasks are deliberately not
  pre-warmed (their filter compiles inside that namespace, where the answer may differ).
  The divergence from `pcap_compile()` - an answer can be up to 60s stale - is recorded
  in [PARITY.md §2.5](PARITY.md). The first draft of this fix bounded each lookup with a
  detached thread plus a 2s budget and the `bpf` fuzz target rejected it: LeakSanitizer
  found glibc's resolver buffer owned by a still-live detached thread at exit
  (`fuzz/artifacts/bpf/leak-592aa5…`) with `exec/s` at 0. Resolution is therefore
  *moved*, not raced (`bpf/resolvers.rs` module docs record why).
- A task capturing on an interface that is down - or simply idle - no longer spins a
  core (P2-6). Measured on a dedicated veth pair with the repository default
  `timeout_ms: 0`, 6s window, `utime+stime`: 4 tasks on a down interface cost
  30.2% of one core before and 3.2% after; two things were needed, because the
  `Err` branch alone was *not* the busy loop: the kernel returns `ENETDOWN` only for
  the frames still queued at the moment the link went down and `EAGAIN` afterwards.
  (a) `ErrorBackoff` on hard `recvmsg` errors - 1ms, doubling, capped at 100ms, reset
  by any successful socket operation; (b) after an empty read with `timeout_ms = 0`,
  `poll(POLLIN, 1)` instead of returning immediately - entered only when the queue
  was just drained, so throughput and latency are untouched (verified: 100,000
  datagrams -> 100,000 records, ratio 1.0000, before and after). C avoids the whole
  question by failing `pcap_activate` and not creating the task at all; that
  difference, and why `error_drop_*` is deliberately *not* touched, is in
  [PARITY.md §2.6](PARITY.md).
- `net <name>` now OR-expands **every** address the name resolves to, like
  `host <name>` already did (P2-8). P5-08 was only half applied: `parse_net()` went
  through `parse_addr()`, i.e. `to_socket_addrs().next()`, so a multi-homed name in
  a `net` filter left all but the first address unfiltered - the same
  loopback/mirror amplification the output-host exclusion is there to prevent.
  Answers inside one network collapse to a single leaf; with an explicit
  `mask`, answers of the other family are dropped, and if nothing is left the
  filter is refused instead of silently matching nothing. A `mask` must now be a
  numeric address (resolving a netmask would take "the first answer" again).
- A host name that resolves to more than 64 addresses is **refused by name**
  instead of compiled (P2-9). Each answer costs ~5-8 cBPF instructions, so unbounded
  DNS data decided the size of the program: past `BPF_MAXINSNS`(4096) the kernel
  refuses the program and the task degrades to interpreting thousands of
  instructions per frame - a throughput collapse with `drop == 0` and every gate
  green. The userspace fallback now also logs one stable, alertable line
  (`bpf_userspace_fallback insns=N limit=4096 kernel=BPF_MAXINSNS`) because no
  published counter moves when it happens. Name resolution in the parser went
  through a new `Resolver` seam (`parse_with`), which is what makes both bounds
  testable without a name server.
 gates could all be passed by writing the
  violation differently instead of not writing it (P2-3): test code meant
  "everything after the first `#[cfg(test)]` in the file", P5-15 matched
  `as (i32|u16|u8|i16|usize)` in one file, fuzz targets were read out of the
  manifest with `grep -A1 '^\[\[bin\]\]'`, and the P5-22 doc check exempted lines
  containing keywords a violator can type. Test code is now delimited per block,
  the cast list covers every integer/float/`libc::c_*`/`as _` spelling across all
  deserialising files (plus a second rule for JSON numbers narrowed anywhere in
  the workspace), the target list comes from `cargo metadata` and is checked in
  both directions, and P5-22 became an implication against the implementation
  (claim an fsync → `flush()` must call `sync_all`).
  `parity/verify_hygiene_reverse.sh` is the new gate on the gates: it re-injects
  each violation in its rewritten form (7 cases) into a temporary copy and fails
  unless the corresponding check goes ❌. `verify_liveness.sh` shares the per-block
  test-code logic.
- `cripid` cast a CRI `"pid"` with `pid as i32`: `4294967296` became PID `0` and
  `2147483653` became `-2147483643`, a plausible-looking PID for some other (or
  no) process. It now uses `i32::try_from` and reports "no pid found" - found by
  the broadened P5-15 rule, pinned by
  `out_of_range_pid_is_an_error_not_a_truncated_pid`.
- A reinserted 802.1Q tag now counts **inside** `snaplen`, so a truncated VLAN frame
  keeps reporting `caplen == snaplen` instead of `snaplen + 4` (P2-7). The old
  behaviour broke the per-packet contract the configuration makes (`slice`, ZMQ batch
  sizing and VXLAN fragmentation all consume `caplen`) and made capture files
  byte-incomparable with `tcpdump -s <snaplen>`, which reports `snaplen` on the same
  802.1Q frames. `orig_len` still reports the on-wire length, tag included.
  Regression: `insert_vlan_truncated_frame_stays_within_snaplen` plus the `snaplen: 16`
  phase of `live_capture_reinserts_vlan_on_veth` (measured on a real veth pair: caplen
  20 before the fix, 16 after).
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

### Security

- **CPM server-certificate verification is now on by default** (upstream
  [#232](https://github.com/Netis/cloud-probe/issues/232)). The Go daemon builds
  `tls.Config{InsecureSkipVerify: true}` unconditionally, so any MITM on the CPM
  channel could impersonate the control plane and drive task creation / BPF
  expressions. `cpdaemon` now verifies by default and only skips verification
  when `cpm.client.tls.insecure_skip_verify: true` is set explicitly
  (`config -> ClientConfig::from_cpm_client -> reqwest danger_accept_invalid_certs`).
  This is a deliberate divergence from the oracle, recorded in `PARITY.md` §2.7
  and `SECURITY.md`. Proven by `crates/cpdaemon/tests/cpm_tls_verify.rs`, which
  drives a real self-signed TLS server and asserts the default client fails the
  handshake while the opt-out succeeds. PKCS#12/mTLS remains a separate
  follow-up (`cloud-probe-rs-ryg.2`).

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
(DPDK capturer, reload fingerprint reuse, lock-free ring buffer, cgroup v1;
explicitly not planned: Wire DI, pprof, cJSON first-key semantics, C's VLAN
out-of-bounds UB). Reduced-scope `cpdaemon` items
and the CPM TLS gap are in README and [SECURITY.md](SECURITY.md). The
`recvmsg`-vs-`TPACKET_V3` capture trade-off, and an unexplained capture-plane
count difference the new live benchmark exposes, are in
[PARITY.md §4](PARITY.md).
