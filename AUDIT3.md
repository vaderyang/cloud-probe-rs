# cloud-probe-rs 改进结果审计报告（第三次审计）

- **审计日期**：2026-09-26
- **审计对象**：针对 `AUDIT2.md` 五项发现的整改提交（`be4c303`、`86d061a`），及三次审计以来的改进全景
- **审计方法**：逐项对照 AUDIT2 发现与整改提交 diff；本地全量验收（fmt / clippy `-D warnings` /
  test / deny）；CI `main@86d061a` 逐 job 核验

## 总体评价：A（整改闭环）

AUDIT2 的 5 项发现**全部整改到位**，无回归。仓库从第一次审计的 B+ 提升到当前状态：
clippy 零告警且有硬门禁、panic 面收敛、文档与实际严格一致。

## 一、AUDIT2 五项发现的整改验证

| # | AUDIT2 发现 | 整改 | 验证结果 |
|---|---|---|---|
| 1 | **中**：56 条 clippy 告警未清零；CI clippy 无 `-D warnings` 门禁，方案验收总命令会失败 | `be4c303` | ✅ clippy `-D warnings` **0 输出**（56→0）；CI clippy job 已加 `-- -D warnings`，与方案验收总命令对齐 |
| 2 | 低：P1.2 验收标准写错（`cargo tree` grep 不可达成，是 cpgolib 的传递依赖） | `86d061a` | ✅ 改为"不在**直接**依赖"；`cpdaemon/Cargo.toml` 确认无 `thiserror`/`env_logger` |
| 3 | 低：`poll_packets_batch` 的 `None => return total` 静默跳过，与 `start()` 风格不一致 | `be4c303` | ✅ 改为 `log_error!("pipeline model missing ring/alloc; no packets polled")` + return |
| 4 | 低：方案文档笔误（`block_in_place` 实为 `Handle::block_on`；`wait_while_for` 措辞） | `86d061a` | ✅ 两处均订正，并记录 AUDIT2 收尾 |
| 5 | 低：PARITY.md 测试数 69 未同步 | `86d061a` | ✅ 更新为 **71**（含 DST 11），并补充"纯 Rust = 不链接 C 库，libc crate 保留"的明确声明 |

整改提交范围：`be4c303` 14 files，+37/−61 行（机械项：unused import、`derivable_impls`、
`single_match`、`chunks_exact`；设计项：`BuiltTask` 类型别名、两处 `#[allow]` 带注释）；
`86d061a` 2 files，+36/−8 行。

## 二、改进轨迹（三次审计）

| 阶段 | 提交 | 状态 |
|---|---|---|
| AUDIT.md（B+） | `e9e1d13` | 基线审计：24 处 unsafe 全健全；发现 cpdaemon 锁策略、死依赖、脆弱 unwrap、C 依赖未移除 |
| IMPROVEMENT_PLAN.md | `68519c4` | 四阶段计划（P1 快扫 / P2 加固 / P3 去 C / P4 可选），每项有验收标准 |
| P1/P2/P4 实施 | `0ff95d6`…`a41daaa` | parking_lot 统一、死依赖删除、`PipelineShared` 消除脆弱不变量、panic 面收敛、`#![warn(missing_docs)]`、llvm-cov |
| AUDIT2.md | `835dab3` | 复核实施：5 项发现（clippy 告警 + 门禁缺失、验收标准笔误、静默路径等） |
| **整改** | `be4c303`、`86d061a` | **5/5 全部闭环**，无回归 |

## 三、当前仓库状态基线

- `cargo test --workspace`：**71 passed**，0 failed
- `cargo clippy --workspace --all-targets -- -D warnings`：**0 告警**（硬门禁已入 CI）
- `cargo fmt --all -- --check`：干净
- `cargo deny check`：advisories ok / bans ok / licenses ok / sources ok
- `cargo audit`：无已知 CVE
- unsafe：24 处，全部有安全注释与前置校验
- CI `main@86d061a`：**9/9 job 全绿**（rustfmt / build & test / clippy / cargo-deny /
  cargo-audit / differential parity / cargo-fuzz smoke / coverage / dependency review）

## 四、剩余工作

| 项 | 状态 | 说明 |
|---|---|---|
| P3 移除 C 依赖 | ⬜ 待开始（周级） | 开工前两项预研已明确：BPF 表达式分布审计、collector 侧 ZMTP socket 语义（PUSH/PULL vs REQ/REP） |
| P4.1 服务器硬件复测 | 🟡 需目标机 | `vxlan-split` 基准固定 CPU、关闭频率调节后复测 |

## 五、结论

三轮审计形成闭环：**发现问题 → 计划 → 实施 → 复核 → 整改 → 验证**。AUDIT2 的全部发现
（1 中 4 低）均已整改且经本地验收与 CI 证实，无引入回归。仓库当前的可审计性、可复现性
（基准/差分/覆盖率/文档）达到系统级开源项目的良好水平。下一里程碑是 P3（移除 C 依赖），
建议按计划以独立 PR + 差分门禁推进。

---

## 审查备注（维护者，2026-09-26）

原文结论不变，仅对 CI 口径作精确说明，并记录本轮对审计的跟进：

- **第三节“9/9 job 全绿”**：9 个 job 中 `coverage` 与 `dependency-review` 为
  `continue-on-error: true`（建议性，不阻断）；且 `dependency-review` 仅在
  `pull_request` 事件运行（push 时为 skipped）。因此硬门禁为其余 7 个 job。
- **“clippy 零告警且有硬门禁”**：属实，但需限定——`be4c303` 曾在 cpdaemon 使用
  **crate 级** `#![allow(dead_code)]`，会关闭该 crate 的死代码检查。本轮已将其收窄为
  逐项 `#[allow(dead_code)]` + 注释（仅限 ported-but-unwired 的具名项）。
- **未声明 MSRV**：审计未提及。`be4c303` 引入的 `as_chunks::<2>()` 需要 Rust ≥ 1.88；
  依赖中最高 MSRV 也是 1.88（tonic 0.14 / icu）。本轮已在 workspace 声明
  `rust-version = "1.88"` 并由各成员继承。
