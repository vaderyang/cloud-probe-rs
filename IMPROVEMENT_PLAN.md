# cloud-probe-rs 改进计划

> 依据：`AUDIT.md`（2026-09-26，B+）。基线：`main@e04b035`（审计基于 `e9e1d13`）。
> 原则：低风险、可验证、每项有明确验收标准。按优先级分四个阶段，P1/P2 可在数小时内完成，
> P3（去 C 依赖）是最大独立工程项，P4 为可选质量提升。

## 进度总览

| 阶段 | 主题 | 项数 | 预估 | 风险 | 状态 |
|---|---|---|---|---|---|
| P1 | 快速清扫（锁策略、死依赖、脆弱 unwrap） | 3 | 0.5–1 天 | 低 | ✅ 已完成 |
| P2 | 可靠性加固（panic 面、可观测性） | 3 | 1–2 天 | 低 | ✅ 已完成 |
| P3 | 移除 C 依赖（纯 Rust） | 3 | 周级 | 高 | ⬜ 待开始 |
| P4 | 可选质量项（覆盖率、文档、基准） | 3 | 1–2 天 | 低 | 🟡 P4.2/P4.3 完成，P4.1 待硬件 |

### P1 完成记录（commits `0ff95d6` / `62597d9` / `3ba6813`）

- **P1.1**：`worker.rs` 已迁移到 `parking_lot`（`wait_while_for` 替代
  `std::sync` 的 `wait_timeout_while`），消除 21 处投毒 `.lock().unwrap()`。
- **P1.2**：删除 cpdaemon 的 `thiserror`/`env_logger` 与 workspace 的
  `tracing`/`tracing-subscriber`；tokio features 收窄为
  `rt-multi-thread/macros/net/signal/sync`。
- **P1.3**：`task.rs` 引入 `PipelineShared` 消除 ring/alloc 脆弱不变量；
  另修 `duration_since`、`as_object_mut`、`CString::new` 三处 unwrap。
- 验证：`cargo fmt --check` ✅ / `cargo clippy --workspace --all-targets` ✅ /
  `cargo test --workspace` **71 passed, 0 failed** ✅ / `cargo deny check`
  （advisories/bans/licenses/sources）✅

---

## P1 — 快速清扫（对应审计 §4.1–4.3）

### P1.1 统一锁策略：cpdaemon `std::sync::Mutex` → `parking_lot`

- **问题**：`crates/cpdaemon/src/worker.rs` 使用 `std::sync::{Mutex}` 并 21 处
  `.lock().unwrap()`，存在锁投毒风险；仓库其余部分统一用 `parking_lot`。
- **做法**：
  1. 第 6 行 `use std::sync::{Arc, Condvar, Mutex};` → `use std::sync::Arc;`
     加 `use parking_lot::{Condvar, Mutex};`（已依赖 `parking_lot.workspace = true`）。
  2. 将所有 `self.done.lock().unwrap()` / `self.state.lock().unwrap()` 改为 `.lock()`；
     `self.cv.wait_timeout_while(...).unwrap()` 改为直接返回。
  3. 保留谓词写法 `|d| !*d` 不变（parking_lot API 兼容）。
- **验收**：`grep -rn "std::sync" crates/cpdaemon/src` 无 `Mutex`；
  `cargo test -p cpdaemon` 通过；`cargo clippy -p cpdaemon --all-targets` 干净。
- **涉及文件**：`crates/cpdaemon/src/worker.rs`（34–256 行区段）。

### P1.2 清理死依赖

- **问题**：`crates/cpdaemon/Cargo.toml` 声明 `thiserror`、`env_logger` 但零引用；
  根 `Cargo.toml` 的 `tracing`、`tracing-subscriber` 在 workspace 内 0 成员引用；
  `tokio features = ["full"]` 偏重。
- **做法**：
  1. `cpdaemon/Cargo.toml` 删除 `thiserror.workspace = true`、`env_logger.workspace = true`
     （注意：cpdaemon 用 `log` crate + 需确认 main 是否初始化 env_logger —— 若实际用到
     `env_logger::init()` 则保留，见"注意事项"）。
  2. 根 `Cargo.toml` 删除 `tracing`、`tracing-subscriber`（若保留未来用途则加注释说明）。
  3. `tokio` 从 `features = ["full"]` 收窄为实际所需：
     `["rt-multi-thread", "macros", "net", "signal", "sync"]`
     （已核对：用到 `#[tokio::main]`、`block_in_place`(→rt-multi-thread)、
     `TcpListener`、`signal::unix/ctrl_c`、`sync::watch`；未见 `process`/`time`/`fs`/`io-util`）。
- **验收**：`cargo build --workspace` 通过；`cargo deny check` 四项 ok；
  `cargo tree -p cpdaemon | grep -E "thiserror|env_logger"` 无输出（若删）。
- **注意**：先 `grep -rn "env_logger::" crates/cpdaemon/src` 确认；`reqwest`/`axum` 可能
  通过 feature 间接启用 tokio 能力，收窄后以编译结果为准。

### P1.3 消除脆弱 unwrap

- **问题**：`panic = "abort"`（根 `Cargo.toml`）下，任何 unwrap panic 会直接终止进程，
  无栈回滚；`task.rs` 的 ring/alloc 属脆弱不变量。
- **做法**：
  1. `crates/cpworker/src/task.rs:269-270,316-317`：`self.ring.clone().unwrap()` /
     `self.alloc.clone().unwrap()`。改为在构造期建立不变量：新增私有 helper
     `fn pipeline_parts(&self) -> (&Ring, &Alloc)`，或在 `Pipeline` 分支用
     `expect("pipeline model requires ring/alloc")` 明确表达不变量；更优方案是用类型状态
     把 ring/alloc 收进 `ExecutionModel::Pipeline { ring, alloc }`，但改动较大，P1 先
     用 `Result`/`expect` 精确化。
  2. `crates/cpworker/src/task.rs:483`：`duration_since(UNIX_EPOCH).unwrap()` →
     `.unwrap_or_default()`。
  3. `crates/cpworker/src/unix_manager.rs:201`：`as_object_mut().unwrap()` →
     用 `if let Some(obj) = ... { obj.insert(...) }` 或 `match` 兜底。
  4. `crates/cpworker/src/netns.rs:33`：`CString::new(alt).unwrap()` →
     `.map_err(|_| Error::new("invalid netns alt path"))?`，与同文件 27 行风格一致。
- **验收**：`grep -rn "\.unwrap()" crates/cpworker/src/task.rs crates/cpworker/src/unix_manager.rs crates/cpworker/src/netns.rs`
  中不再有上述 4 处；`cargo test -p cpworker` 通过。

---

## P2 — 可靠性加固

### P2.1 全仓库 panic 面收敛

- **做法**：`cargo clippy --workspace --all-targets -- -W clippy::unwrap_used -W clippy::expect_used`
  生成清单，区分测试代码（允许）与生产代码（逐个评估）。对生产代码中无前置校验的
  `unwrap/expect` 加 `debug_assert!` 说明或用 `?` 上抛。可参考审计已确认的：
  `packet.rs:299-303` 有前置长度检查，属可保留。
- **验收**：产出一份 `unwrap` 处置清单并处理 P1 之外的合理项；CI 不新增告警。

### P2.2 补齐 clippy pedantic 文档段（低风险机械项）

- **做法**：
  1. 给返回 `Result` 的公共函数补 `/// # Errors`（报告称 82 处）。
  2. 给纯函数补 `#[must_use]`（~59 处）。
  3. `usize→u16` 等 13 处截断强转逐个加注释确认（多为 C 对齐）。
- **验收**：`cargo clippy --workspace --all-targets -- -W clippy::pedantic` 中
  `missing_errors_doc`/`must_use_candidate` 显著下降；不强求全绿（风格类）。
- **说明**：批次提交，避免一次巨型 diff。

### P2.3 覆盖率与 CI 补强

- **做法**：新增 `cargo-llvm-cov` 步骤（至少报告，不设硬门禁），
  产出覆盖率基线并写入 README。
- **验收**：CI 打印/上传 lcov；文档记录当前行覆盖率。

---

## P2 完成记录

- **P2.1 panic 面收敛**（生产代码）
  - `output/{null,gre,vxlan,zmq}.rs`：删除冗余 `rate_limit_mbps` 字段，
    用 `if let Some(tb) = self.throttle.as_mut()` 消除 4 处 `unwrap()`。
  - `task.rs`：输出线程 spawn 失败不再 `expect` 中止，改为复位 `running`
    并记录错误。
  - `cpdaemon/cpm/task_builder.rs`：3 处 `libpcap.as_mut().unwrap()` 改
    `if let`；短选项解析的 `chars().next().unwrap()` 改 `ok_or_else`。
  - `cpdaemon/cpm/worker_mgr.rs`：`worker.clone().unwrap()` 改为缺失时返回错误。
  - **保留**：`packet.rs` 4 处 `try_into().unwrap()`（有前置长度检查，
    审计已认可）；测试/差分 harness 中的 `unwrap/expect` 属预期。
  - `#[cfg(test)]`/`tests/`/`bin/*parity` 中的 unwrap 不处理（测试失败应中止）。
- **P2.2 pedantic 文档段**
  - `#[must_use]`：clippy `--fix` 全量应用（cpworker/cpgolib/cpsim），0 剩余。
  - `# Errors`：为 cpworker 公共 API（config/capturer/output/netns/netutil/
    task/unix_manager/affinity/req_pattern/ring_buffer）、cpgolib client、
    cpsim collector 补齐；`clippy::missing_errors_doc` 在 `--lib` 下 0 剩余。
- **P2.3 覆盖率**
  - `.github/workflows/ci.yml` 新增 `coverage (llvm-cov)` job（advisory，
    `continue-on-error`），产出并上传 `lcov.info`；README 增加本地复现步骤。

## P3 — 移除 C 依赖（审计 §4.4，最大工程项）

> 目标：去掉 `libpcap` / `libzmq`，实现"纯 Rust"。建议拆成独立里程碑，逐个可回退。

### P3.1 采集侧去 libpcap

- **现状**：`crates/cpworker/src/capturer/libpcap.rs` + `pcap_file.rs` 链接 libpcap。
- **做法**：
  1. 活跃采集用 `pnet_datalink`（AF_PACKET）或直接 `socket(AF_PACKET, SOCK_RAW)` +
     `nix`；对照 `libpcap.c` 的 fanout/ring 行为。
  2. 离线 pcap 文件读写改为纯 Rust reader/writer（`pcap_writer.rs` 已有封装，
     替换 FFI 层即可）。
  3. BPF 过滤：审计建议"自写 tcpdump BPF 子集编译器"。若项目只支持有限表达式，
     实现子集；否则可评估用 `pcap` 语法解析到 `BPF` 指令的现有 Rust crate。
- **验收**：`cargo tree -p cpworker | grep -E "^pcap"` 无输出；34 个 C 差分测试
  （`port_parity.rs`）全绿；fuzz `packet_split`/`config`/`vxlan` 全绿；
  采集吞吐基准不低于 C 基线 ±5%。

### P3.2 输出侧去 libzmq（纯 Rust ZMTP）

- **现状**：`crates/cpworker/src/output/zmq.rs` 使用 `zmq` crate（libzmq）。
- **做法**：实现 ZMTP 3.x 最小子集（或引入纯 Rust 实现），保持 wire 兼容，
  复用现有 `BatchBuilder`（`zmq_batch` fuzz target 已覆盖 VLAN/MPLS 边界）。
- **验收**：`cargo tree -p cpworker | grep -E "^zmq"` 无输出；
  与 collector 的端到端对拍通过；`zmq_vlan_slice_never_corrupts` 回归通过。

### P3.3 供应链/构建切换

- **做法**：移除 `pcap`/`zmq` 依赖后更新 `deny.toml`/`Cargo.lock`、CI 构建镜像
  （不再需要 `libpcap-dev`/`libzmq3-dev`）；更新 `PARITY.md §4` 状态为已完成。
- **验收**：`cargo deny check` 四项 ok；CI 在无 libpcap/libzmq 的镜像上构建通过。

---

## P4 完成记录

- **P4.2 rustdoc + `#![warn(missing_docs)]`**（已完成）
  - `cpworker` 公共 API 补齐 rustdoc：293 条初始告警 → 0（config/packet/
    stats/ring_buffer/req_pattern/task/output/capturer/netns 等全部公共类型、
    字段、枚举变体、常量、函数/方法）。
  - `crates/cpworker/src/lib.rs` 启用 `#![warn(missing_docs)]`，构建零告警。
- **P4.3 未移植项范围决策**（已完成）
  - `PARITY.md` §5 重写为两张表：**计划移植**（去 C 依赖、DPDK、reload
    复用、select 语义、无锁 ring、cgroup v1、单测）与**不计划移植**（Wire DI、
    pprof、重复 JSON key、C 的 VLAN UB），每项附触发条件/原因。
- **P4.1 `vxlan-split` 服务器硬件复测**（待办）
  - 需要固定 CPU/关闭频率调节的目标机器；本地无法完成。

## P4 — 可选质量项

- **P4.1** `vxlan-split` 基准在服务器硬件复测：审计指出负载下曾 2x 波动，
  建议固定 CPU、关闭频率调节、AB 复测，更新 README 基准表。
- **P4.2** 补充 `# Errors` 文档到 rustdoc 并 `#![warn(missing_docs)]`（cpworker 公共 API）。
- **P4.3** 未移植项跟踪：`PARITY.md` 中 dpdk/pdump、cgroup v1、`task.c` reload 语义
  差异，评估是否补齐或明确标注"不计划移植"。

---

## 执行顺序与提交策略

1. **P1 一次 PR**，按 P1.1 / P1.2 / P1.3 分 3 个 commit（便于二分）。
2. **P2** 分主题提交（panic 清单 / 文档段 / 覆盖率）。
3. **P3** 每子项独立 PR + feature flag 灰度，保持可回退；差分测试为门禁。
4. 每完成一项更新 `AUDIT.md` 的对应条目或新增 `CHANGELOG` 记录。

## 验收总命令

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo test -p cpworker --test port_parity
cargo test -p cpsim --test dst
./fuzz.sh            # smoke
```

## 注意事项

- 删除 `env_logger` 已复核：`cpdaemon/src/main.rs` 用 `cpgolib::slogx::init_default(level)`
  初始化日志，`env_logger` 与 `thiserror` 在 cpdaemon 中均**零引用**，可安全删除。
- 审计数据 `71 passed` 与 `PARITY.md` 的 `69` 有差异：当前实测为
  cpworker 差分 34 + DST 11 + 其他单元/集成若干（`cargo test --workspace` 汇总为准），
  执行前先跑基线记录准确数字。
- `tokio` feature 收窄后若 `axum`/`reqwest` 需要额外特性，以编译错误为准调整，
  不要为了"好看"牺牲可编译性。
