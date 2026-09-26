# cloud-probe-rs 改进方案实施审计报告（第二次审计）

- **审计日期**：2026-09-26
- **审计对象**：`IMPROVEMENT_PLAN.md`（基于第一次审计 `AUDIT.md` 的修理方案）及其已实施提交
  （`2a965ce` … `a41daaa`，基线 `e04b035`）
- **审计方法**：逐项对照方案声明与实际代码；关键改动人工核验（锁策略、unwrap 路径、
  spawn 失败处理、依赖树）；clippy 告警与基线（e04b035）worktree 对比；全量测试 + deny + CI 验证

## 总体评价：方案质量高，实施与声明一致

- 方案结构正确：分阶段、每项有验收标准、按二分友好切 commit、有"不要为好看牺牲可编译性"等务实告诫；
  P3 拆独立可回退里程碑并以差分测试为门禁。
- **P1.3 的实施优于原审计建议**：不是简单 `expect`，而是引入 `PipelineShared` 结构 +
  `start()` 用 let-else 大声 `log_error!`，stats/poll 路径显式 match——在"expect 精确化"与
  "全量类型状态"之间选了合理的中间点。
- P1.2 主动复核了 `env_logger` 零引用再删；P2.3 覆盖率设为 advisory 不设硬门禁——判断正确。

## 一、实施验证（逐项对照代码）

| 项 | 验证结果 |
|---|---|
| P1.1 锁统一 | ✅ `crates/cpdaemon/src/worker.rs` 全用 `parking_lot`（`use parking_lot::{Condvar, Mutex}`），零投毒 unwrap；Condvar API 正确适配（parking_lot 无 `Result` 包装，`.unwrap()` 已移除） |
| P1.2 死依赖 | ✅ cpdaemon 直接依赖已删（`thiserror`/`env_logger`）；workspace 已删 `tracing`/`tracing-subscriber`；tokio 收窄正确——实际只用 `#[tokio::main]` / `Handle::block_on` / `TcpListener` / `signal` / `sync::watch` / `spawn`，`time`/`process`/`fs`/`io` 确认未用 |
| P1.3 脆弱 unwrap | ✅ `task.rs` 引入 `PipelineShared`；`start()` let-else + `log_error!`（L296-300）；`duration_since`、`as_object_mut`、`CString::new` 三处已改 |
| P2.1 panic 面 | ✅ spawn 失败改 `Ok/Err` match + 复位 `running`（L322-330）；`rate_limit_mbps` 冗余字段删除正确（`throttle` 为 Some ⇔ `rate_limit>0`，无其他引用）；保留审计认可的 `packet.rs` 前置校验 unwrap（有前置长度检查） |
| P2.2 文档段 | ✅ `#[must_use]` clippy `--fix` 全量应用 0 剩余；`# Errors` 补齐且 `#![warn(missing_docs)]` 启用（293 条初始告警 → 0） |
| P2.3 覆盖率 | ✅ CI 新增 `coverage (llvm-cov)` job，advisory（`continue-on-error: true`），上传 `lcov.info` |
| P4.2/P4.3 | ✅ rustdoc 补齐 + `PARITY.md` §5 重写为"计划移植/不计划移植"两张表 |

**验收命令实测**：`cargo fmt --check` 干净 / `cargo test --workspace` **71 passed, 0 failed** /
`cargo deny check` 四项 ok / CI `a41daaa` 全绿。

## 二、发现的问题（按严重度）

### 中：56 条 clippy 告警未清零，CI 无告警门禁

- worktree 对比：基线 `e04b035` **68 条**告警 → 当前 HEAD **56 条**。P1/P2 修掉一部分但未清零。
- 分布：`cpdaemon/src/httpmix.rs`（9）、`cpdaemon/src/cpm/models.rs`（8）、`worker.rs`（3）、
  `cpm/syncer.rs`（3）、`config.rs`（3）、`cpm/mod.rs`（2），另零散在 cpworker
  （`task.rs`、`packet_split.rs`、`output/zmq.rs`、`output/vxlan.rs`）。
- 类型：`unused import`（`SockaddrLike`、`std::sync::Arc`、`models::*`）、
  "doc list item without indentation"（7）、"this impl can be derived"（3）等，多为机械项。
- **关键不一致**：方案"验收总命令"写的是 `cargo clippy --workspace --all-targets -- -D warnings`，
  按该标准**当前会失败**；而 CI 的 clippy job 未加 `-D warnings`，因此未被发现。
- **建议**：清理剩余告警（机械项为主）后，CI clippy job 加 `-D warnings` 锁住门禁，
  防止告警再次累积；否则应明确把验收标准降为"无 error"，避免虚假声明。

### 低：P1.2 验收标准写错（不可达成）

- 方案写"`cargo tree -p cpdaemon | grep thiserror|env_logger` 无输出"——**实际不可能达成**：
  两者是 cpgolib 的**传递依赖**（`slogx` 用 env_logger、`client.rs` 用 thiserror），
  删除 cpdaemon 的直接依赖后仍会出现在依赖树里。
- 正确标准应为"不在 cpdaemon 的**直接**依赖"（Cargo.toml）。删除本身正确。

### 低：一处静默路径不一致

- `crates/cpworker/src/task.rs` `poll_packets_batch` 的 `None => return total`（L355-358）
  是**静默跳过**，与 `start()` 的大声 `log_error!` 风格不一致。实际不可达（`start()` 拒绝启动
  输出线程；reload 在锁内重建），属防御一致性 nit，建议补一次 `log_error!`。

### 低：方案文档笔误（不影响结论）

- 方案 P1.2 说用到 `block_in_place`——实际是 `tokio::runtime::Handle::current().block_on(fut)`，
  同一 feature 要求（`rt` ⊆ `rt-multi-thread`），结论不变。
- P1 完成记录说 "`wait_while_for` 替代"——parking_lot API 实际同名 `wait_timeout_while`
  （差异是无 `Result` 包装），实现正确，措辞笔误。
- `PARITY.md` 测试数仍为 69，实测 71，未同步。

## 三、对 P3（去 C 依赖）的预审查

- **P3.1 采集侧**：BPF 编译器是最大的隐藏工作量——当前 `pcap_compile` 支持任意表达式，
  动手前应先审计用户配置中 BPF 表达式的分布再定"子集"范围；`pcap_writer.rs` 的 FFI 替换最简单
  （pcap 文件格式本身简单）。验收"吞吐不低于 C 基线 ±5%"合理。
- **P3.2 ZMTP**：纯 Rust 实现前需确认 collector 侧的具体 socket 语义（PUSH/PULL 还是 REQ/REP），
  以端到端对拍为门禁是对的；`zmq_batch` fuzz target 已覆盖 VLAN/MPLS 边界。
- **P3.3 构建切换**：验收 `cargo tree | grep -E "^pcap"` 无输出正确（直接依赖）；
  CI 镜像不再需要 `libpcap-dev`/`libzmq3-dev`。
- **补充**：P3 完成后 `libc` crate 仍在（netns/affinity/setsockopt 只是声明 crate，
  不含 C 代码），符合"纯 Rust = 无 C 库链接"的目标——建议在 `PARITY.md` 明确说明，
  避免"纯 Rust = 无 libc crate"的误解。

## 四、结论与建议

1. 方案可行、实施与声明一致、验证到位；P1/P2/P4 的工程质量良好。
2. 建议补一个小提交：
   - 清零 56 条 clippy 告警（unused import / doc list 缩进 / Derivable impls）；
   - CI clippy job 加 `-D warnings`（与方案验收总命令对齐）；
   - 修正 P1.2 验收标准（直接依赖）与 `block_in_place`/`wait_while_for` 两处措辞；
   - 同步 `PARITY.md` 测试数为 71。
3. P3（去 C 依赖）开工前先做两项调研：BPF 表达式分布审计、collector 侧 ZMTP socket 语义确认。
4. P4.1（服务器硬件复测 `vxlan-split`）仍需目标机器，本地无法完成。

## 审计时点的验证结果

- `cargo test --workspace`：**71 passed**，0 failed
- `cargo clippy --workspace --all-targets`：0 error，56 warning（基线 e04b035：68 warning）
- `cargo fmt --all -- --check`：干净
- `cargo deny check`：advisories ok / bans ok / licenses ok / sources ok
- CI `a41daaa`：8/8 job 全绿（coverage 为 advisory）
- clippy 告警 worktree 对比：e04b035 = 68 → HEAD = 56
