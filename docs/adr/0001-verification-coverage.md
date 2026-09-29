# ADR-0001：采用 Verification Coverage 体系（分层覆盖 + 变更覆盖 + 有效性 + 系统覆盖）

- **状态**：Accepted
- **日期**：2026-09-29
- **决策者**：core（本移植维护方）
- **相关文档**：[`VERIFICATION_COVERAGE.md`](../../VERIFICATION_COVERAGE.md)（体系细节）、[`verification/policy.toml`](../../verification/policy.toml)（唯一事实来源）、
  [`PARITY.md`](../../PARITY.md)、[`SECURITY.md`](../../SECURITY.md)、[`IMPROVEMENT_PLAN_AUDIT4.md`](../../IMPROVEMENT_PLAN_AUDIT4.md)、[`REVIEW_CPDAEMON_TESTS.md`](../../REVIEW_CPDAEMON_TESTS.md)

---

## 1. 背景（Context）

本项目是 `netis/cloud-probe`（C + Go）到 Rust 的移植。移植的正确性必须**可证明**，而不是"看起来测了很多"。
过去几轮实践中反复暴露的事实：

1. **缺陷是真实且隐蔽的**：AUDIT 系列与两轮独立模型评审发现的缺陷（`decode_chunked` 截断越界、
   `Worker::stop()` 断言同义反复、e2e 失败时挂死而非变红、loopback 双份帧的采集语义分歧），
   全部通过了当时的 `cargo test` + `clippy -D warnings`。**测试通过 ≠ 验证充分**。
2. **"从实现倒推测试"会固化 bug**：由实现反推的用例只能证明"代码做了它现在做的事"，
   无法发现"实现 vs 原 C/Go 行为"的分歧——而后者正是本次移植的主要风险来源。
3. **单一覆盖率数字会被误用**：原始项目不统计覆盖率（CI 只 `go test`，无 `-cover`）；仅凭一个
   全局百分比既不能反映风险分布，也无法约束"新代码没测"或"关键路径没测"。
4. **上游交付形态要求可执行约束**：覆盖率若只写在文档里，会随迭代退化。必须落成 CI 门禁。

同时，覆盖率只是"验证充分性"的一个维度：它无法说明**测试是否有效**（mutation）、
**需求/场景是否覆盖**（behaviour）、**风险是否覆盖**（risk）、**系统级行为是否验证**（integration/e2e/性能/混沌）。

## 2. 决策（Decision）

采用 **Verification Coverage 体系**，并按以下要点执行：

### 2.1 第一原则：Spec-first
新增/补充测试**必须先从 ADR/Spec/需求/场景出发**，禁止以"读实现反推测试"作为提升覆盖率的手段。
规范来源优先级：原 C/Go 行为（`PARITY.md` / `parity/` 对拍）→ ADR/设计文档 → 需求登记表
（`verification/requirements.toml`）→ 最后才允许"实现即规范"且必须标注 `SPEC-MISSING`。

### 2.2 风险分层与阈值
按出问题的后果分为 Tier 0–3（Safety-Integrity-Critical / Core-Product-Logic / Normal / Glue-Low-Risk），
阈值（`verification/policy.toml` 为唯一事实来源）：

| Tier | line | branch | function | condition(MC/DC) | mutation |
|---|---:|---:|---:|---:|---:|
| 0 | **95%** | 90% | 95% | 90% | ≥85% |
| 1 | **90%** | 85% | 90% | 80% | ≥75% |
| 2 | **80%** | 75% | 80% | — | ≥60% |
| 3 | **60%** | — | — | — | — |

**关键功能（Tier 0 安全/完整性边界）必须 100% function coverage**（`FNDA:0` 即失败），
清单见 `policy.toml` 的 `critical_functions`。

### 2.3 变更覆盖与防退化（棘轮）
- **changed-code coverage**：变更行 line ≥ **90%**、branch ≥ **85**%（Tier 3 除外）。
- **coverage must not decrease**：每档 line/function 不得低于 `verification/baseline.json`；只升不降。
- **棘轮**：达 target 后 floor 永久抬到 target；未达 target 的档位须登记 `[[waiver]]`（owner+到期），到期未达标即失败。

### 2.4 四类非代码覆盖率维度
- **Behaviour**：`requirements.toml` 登记 requirement/scenario/state-transition → 测试映射；
  **P0 scenario 覆盖 = 100%**（映射的测试必须真实存在）。
- **Risk**：`risk.toml` 覆盖 security / concurrency / data integrity / failure modes；**P0 风险 100% 有验证**。
- **Test effectiveness**：`cargo-mutants`（Tier 0/1），并做 **poison/故障注入**（截断、短写、读后清零等）。
- **System**：integration / e2e / performance / soak / chaos-fault-DST，分即席与定时两层。

### 2.5 机制化（可执行门禁）
- 机器可读策略 `verification/policy.toml` + 基线 `verification/baseline.json` + 门禁
  `verification/coverage_gate.py`（分层/关键函数/no-decrease/diff）+ `verification/requirements_gate.py`；
  本地入口 `./verify_coverage.sh`。
- CI：`coverage-gate`（**阻塞**）、`p0-requirements`（阻塞）、`mutation`（Tier0/1，PR 限量 + 定时全量）、
  `system`（nightly：soak/chaos/DST）。
- **PR 评审清单**：测试须能指向规范来源；变更行须达标（否则逐条 `cov:ignore` 说明）；
  触及 Tier 0 须补状态迁移/失败模式用例；baseline 只升不降。

## 3. 理由（Rationale）

- **风险对齐**：阈值与关键函数清单对准"内存安全/线上字节/安全边界"，而不是平均用力，避免在粘合代码上刷分。
- **防止退化**：棘轮 + no-decrease 让"已建立的信心"成为不可回退的资产；这是纯文档做不到的。
- **防止自欺**：mutation + poison 检验"测试是否真的能失败"，直接针对"通过但无效"的测试。
- **可追溯**：spec-first + requirement/scenario 映射，把"为什么测这个"写下来，评审可核查。
- **可收敛**：目标（95/90/80/60）与当前差距用 waiver 显式登记，既有硬约束又有可执行路径。

## 4. 后果（Consequences）

### 正面
- 关键代码覆盖率与"关键函数 100%"成为**机器强制**，不再依赖自觉。
- 变更覆盖 + no-decrease 直接把"新代码没测"挡在合入前。
- 需求/风险/系统覆盖从一开始就进入流程，避免"只有行覆盖"的盲区。

### 代价 / 负面
- **CI 时间与成本上升**：mutation 与 soak/chaos 显著增加机时（用定时 job + PR `--in-diff` 限量缓解）。
- **维护成本**：`policy.toml`/`baseline.json`/`requirements.toml` 需随代码演进而维护。
- **初期常红风险**：当前 Tier0 75.8% / Tier1 72.6% / Tier2 53.7% / Tier3 49.9%（Regions）**均低于 target**；
  因此首轮只强制 **no-decrease + 关键函数 100% + 变更行 90/85**，绝对目标由 waiver 收敛（见 §5）。
- **function coverage 噪声**：闭包/泛型实例化会拉低"函数覆盖"数字；故函数阈值主要作为趋势，
  硬约束放在**关键函数**与 **line/branch**。

### 风险与缓解
| 风险 | 缓解 |
|---|---|
| 阈值过严导致 CI 长期红 | 棘轮 + waiver（owner/到期）；目标达成前不按绝对目标阻塞 |
| 为过门禁写"从实现出发"的测试 | spec-first 规则 + PR 清单；reviewer 可拒 |
| mutation 过慢 | 仅 Tier 0/1；PR 用 `--in-diff`；全量放定时 |
| 豁免滥用成盲区 | 豁免集中在 `policy.toml [exclude]`，hygiene 门禁核查其一致性 |
| baseline 被"上调即通过" | baseline 只允许向上；diff 需 review；CI 只接受上升 |

## 5. 落地状态与分阶段

- **阶段 1 ✅ 已完成**：`VERIFICATION_COVERAGE.md`、`verification/policy.toml`、
  `verification/coverage_gate.py`、`verification/baseline.json`、`verify_coverage.sh`。
- **阶段 2 ✅ 基本完成**：`verification/requirements.toml` + `requirements_gate.py`（P0 场景 100%）；
  CI `verify-coverage` 阻塞化（分层/关键函数/no-decrease/diff/requirements）；
  weekly `verification.yml` 跑 nightly `--branch`。待办：`--mcdc`、branch 纳入阻塞。
- **阶段 3（进行中）**：`cargo-mutants` 配置 + `verify_mutation.sh` + weekly mutation job（advisory）；
  待办：mutation 阈值基线化并纳阻塞；poison/DST harness。
- **阶段 4**：soak / chaos / fault-injection 定时 job；`risk.toml` P0 收敛到 100%。

## 6. 被否决的备选方案（Alternatives）

| 备选 | 否决理由 |
|---|---|
| **不设覆盖率门禁（仅文档/自觉）** | 会退化；无法约束新代码与关键路径；与"证据驱动移植"相悖 |
| **单一全局阈值（如整体 70%）** | 掩盖风险分布：可在粘合代码刷分而放过 Tier0；无法表达"关键函数必须 100%" |
| **只做 code coverage（不做 mutation/behaviour/risk/system）** | 无法回答"测试是否有效、需求是否覆盖、风险是否验证"；历史已证明会漏 |
| **从现有实现反推测试** | 固化 bug、无法发现实现与规范的偏差（§1.2） |
| **一次性按 95/90/80/60 立即阻塞** | 当前全部低于目标，会让 CI 立刻常红且无收敛路径；改用棘轮 + waiver |
| **云厂商 SaaS 覆盖服务（Codecov 等）** | 数据外发、与纯本地/自托管倾向不符；标准 lcov + 自研门禁已足够且可审计 |

## 7. 参考

- 体系细节与维度定义：[`VERIFICATION_COVERAGE.md`](../../VERIFICATION_COVERAGE.md)
- 阈值与关键函数的事实来源：[`verification/policy.toml`](../../verification/policy.toml)
- 原始行为对照：[`PARITY.md`](../../PARITY.md)；安全决策：[`SECURITY.md`](../../SECURITY.md)
