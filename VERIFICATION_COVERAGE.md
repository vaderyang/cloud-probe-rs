# 验证覆盖体系（Verification Coverage）

> 本文定义 cloud-probe-rs 的**验证覆盖体系**：覆盖的维度、分层阈值、关键功能清单、
> 变更覆盖、行为/风险/系统覆盖、测试有效性（mutation/poison），以及把这一切固化为
> **可执行门禁**的机制。它回答两个问题：*我们凭什么相信这个移植是对的*，以及
> *每次改动怎么保证这份信心不退化*。

## 0. 第一原则：Spec-first（从 ADR/Spec 出发，而不是从代码出发）

**新增/补充测试，必须先有需求/场景，再写测试；禁止"读实现反推测试"来刷覆盖率。**

理由：从实现倒推的测试只能证明"代码做了它现在做的事"，无法发现**实现与需求/原 C 行为
的分歧**——而这正是本移植最大的风险（见 `PARITY.md` 的逐条差分、AUDIT 系列发现的缺陷）。
从代码出发的测试会连同 bug 一起"固化"。

因此测试的规范来源是（按优先级）：

1. **原 C/Go 行为**（`PARITY.md` §2 差分约定、`parity/` 对拍、`CLOUD_PROBE_SRC`）；
2. **ADR / 设计文档**（本仓库的 `IMPROVEMENT_PLAN*.md`、`AUDIT*.md` 的决策与结论、`SECURITY.md`）；
3. **需求/场景登记表**（`verification/requirements.toml`，见 §5）；
4. 只有在以上都缺失时，才允许"实现即规范"，且必须在测试注释里显式标注 `SPEC-MISSING`
   并在下一轮补上规范。

**工作流**：`ADR/Spec → 场景（scenario）→ 状态迁移/边界 → 测试 → 与 C oracle 对拍（如适用）`。
PR 里若新增测试却无法指向其规范来源，视为不合格（见 §9 评审清单）。

## 1. 覆盖维度总览

| 维度 | 度量 | 工件 / 工具 | 门禁（见 §9） |
|---|---|---|---|
| **Code coverage** | line / branch / condition(MC-DC) / function，按 Tier | `cargo-llvm-cov`（line/function 稳定；branch 需 nightly `--branch`；MC/DC 需 `--mcdc`） | 分层阈值 + 关键函数 100% |
| **Change coverage** | 变更行 line≥90% / branch≥85%；**coverage 不得下降** | `git diff` × lcov；`verification/coverage_gate.py`；`verification/baseline.json` | 阻塞 |
| **Behaviour coverage** | requirement / scenario / state-transition 覆盖 | `verification/requirements.toml` + 测试名映射 | P0 场景 100% |
| **Risk coverage** | security / concurrency / data integrity / failure modes | `verification/risk.toml` 检查清单 + 专项测试 | P0 风险 100% |
| **Test effectiveness** | mutation score / poison（故障注入被检出率） | `cargo-mutants`；DST/混沌注入 | 分层 mutation 阈值 |
| **System coverage** | integration / e2e / performance / soak / chaos-fault-DST | `parity/`、`crates/cpdaemon/tests`、`bench/`、未来 soak/chaos | 场景矩阵 + 定期 job |

## 2. Tier 定义与阈值

分层依据**出问题的后果**（详见附录 A 的逐文件映射）：

- **Tier 0 — Safety / Integrity Critical**：解析不可信字节、`unsafe`/系统调用、线上字节
  正确性、安全边界。出错=内存不安全 / 转发伪造或损坏数据 / 过滤器或权限被绕过 / 被攻击输入整机崩溃。
- **Tier 1 — Core product logic**：采集流水线、task 生命周期、daemon reconcile、控制协议。
  出错=行为错误/丢数据/不可用，但不涉及内存安全或伪造线上数据。
- **Tier 2 — Normal**：支撑模块（stats 类型、fingerprint、CLI 子命令逻辑、错误装配）。
- **Tier 3 — Glue / Low risk**：入口装配、格式化、日志粘合、开发/差分工具（不随产品发布）。

### 阈值（`verification/policy.toml` 是唯一事实来源）

| Tier | line | branch | function | condition(MC/DC) | mutation | critical-fn |
|---|---:|---:|---:|---:|---:|---:|
| Tier 0 | **95%** | 90% | 95% | 90%（MC/DC，nightly） | ≥ 85% | **100%** |
| Tier 1 | **90%** | 85% | 90% | 80% | ≥ 75% | 100% |
| Tier 2 | **80%** | 75% | 80% | — | ≥ 60% | — |
| Tier 3 | **60%** | — | — | — | — | — |

阈值落地采用**棘轮（ratchet）**，避免"阈值一加、历史欠账直接让 CI 常红"：

- **floor（强制）**：每档覆盖不得低于 `baseline`（`verification/baseline.json`，随每次提升自动抬高）。
- **target（目标）**：上表的数字。某档达到 target 后，floor 永久抬到 target（不可回退）。
- 当前低于 target 的档位，必须在 `verification/policy.toml` 的 `[[waiver]]` 里登记 **owner + 计划 + 到期**；
  到期未达标 = 门禁失败。这样"目标"是硬约束，但给出可执行的收敛路径。

> **现状（2026-09，llvm-cov lines；四个 Tier 均已达 target 且绝对强制，无 waiver）**：
> Tier 0 **95.4% / 98.2%**、Tier 1 **92.0% / 93.4%**、Tier 2 **96.7% / 94.6%**、Tier 3 **74.0% / 84.1%**
> （target 分别为 95/95、90/90、80/80、60/—；`verification/baseline.json` 已抬到或高于 target，
> `[[waiver]]` 全部移除）。
> Tier 0 的 AF_PACKET 采集器覆盖来自 `verify_coverage.sh --privileged-live`：普通测试套件跑完后，
> 以 root 运行 `#[ignore]` 的 live 测试并把 profraw 合并进同一报告（仅有这条 root-only 路径需要提权；
> 整个套件用 root 跑会改变很多断言 EPERM 的用例）。函数覆盖按归一化 demangled 名去重并排除
> `::{closure#N}`（否则同源函数的多个 crate 实例与错误处理闭包会把分母抬高、把数字压低）。

## 3. 关键功能（100% function coverage）

以下功能一旦有函数从未被执行（`FNDA:0`）即门禁失败。清单在
`verification/policy.toml` 的 `critical_functions`，按**去 mangle 后的路径**匹配
（门禁用 `c++filt -s rust` 还原）。

按 §0 原则，这些是**安全/完整性边界**上的函数（示例，落地时在 policy 里精确到函数）：

- `cpworker::bpf::compiler`：`compile` / `Builder::finish`（跳转中继）/ `attach`
- `cpworker::bpf::interp`：`run`（cBPF 解释器，越界即终止）
- `cpworker::bpf::parser`：`parse`
- `cpworker::capturer::af_packet`：`open`（socket/BPF/bind 顺序，由 `--privileged-live` 合并覆盖）、
  ring 解析、方向过滤（`new`/内部函数随普通套件覆盖）
- `cpworker::packet::parse_packet`、`cpworker::packet_split::build_fragment`
- `cpworker::zmtp::codec`：帧解析/序列化；`cpworker::zmtp::client`：握手状态机
- `cpworker::output::vxlan::vxlan_encapsulate`、`output::gre::gre_header`（线上字节）
- `cpworker::config`：数值范围校验入口
- `cpgolib::cpworker::client`：handshake / run_command

## 4. Change coverage（变更覆盖 + 不得下降）

- **diff coverage**：本次变更命中的行（相对 `origin/main`）中，line 覆盖 ≥ **90%**、
  branch 覆盖 ≥ **85%**。允许在 PR 里对"不可测代码"打**显式豁免**（`// cov:ignore <理由>`），
  豁免需 reviewer 同意。
- **no-decrease**：每档 line/function 覆盖不得低于 `baseline.json`；提升后由 CI 自动更新 baseline
  （仅在同一 PR 内，且必须向上）。
- **baseline 更新流程**：`./verify_coverage.sh --update-baseline`（本地）→ PR 里 review baseline diff，
  只允许数值上升。

## 5. Behaviour coverage（行为覆盖）

`verification/requirements.toml` 是需求/场景登记表：每条需求有 `id`、`priority`(P0/P1/P2)、
`source`（ADR/PARITY 链接）、`scenario`、可选 `state_transition`、以及 `tests`（映射到具体测试名）。

- **P0 requirement 的 scenario coverage 必须 100%**：每条 P0 需求至少映射 1 个存在且通过的测试；
  门禁校验"映射的测试名在测试二进制里确实存在"（防止写了映射但测试被删/改名）。
- **状态迁移**：登记关键状态机及其迁移边（worker 生命周期、ZMTP 连接、采集 socket、reload、
  限速桶），每条边至少 1 个场景。首版种子见 `requirements.toml`。

## 6. Risk coverage（风险覆盖）

`verification/risk.toml` 按四类登记风险项与对应验证手段，P0 风险必须 100% 有验证：

- **Security**：CPM TLS（`SECURITY.md`）、不可信 BPF/配置解析、`unsafe` 内存安全、提权路径（`CAP_*`）。
- **Concurrency**：ring buffer SPSC、`TaskManager`/output 生命周期锁、ZMTP 单写 FIFO、reload 与采样并发。
- **Data integrity**：线上字节逐字节对拍（`parity/`）、VLAN/H3、分片与校验和、pcap 文件格式。
- **Failure modes**：接口 down、DNS 失败、collector 背压/断连、握手超时、磁盘满、cgroup 缺失。

## 7. Test effectiveness（mutation / poison）

- **mutation testing**：`cargo-mutants`（配置见 `verification/mutants.toml`；入口 `verify_mutation.sh`）。分层阈值见 §2。
  先对 **Tier 0/1** 运行；按 crate/文件限定范围、对已知等价 mutant 用 `exclude`。首次测量与缺口见
  [`verification/MUTATION_BASELINE.md`](verification/MUTATION_BASELINE.md)；每周 `verification.yml` 分 4 shard
  运行全量，PR 上 `ci.yml` 的 `mutation-diff` 只跑变更行，**两者均已阻塞**（详见 §10 阶段 3）：
  cargo-mutants 对存活 mutant 退出 2、超时退出 3，任何未被 `exclude_re` 登记理由的存活即判失败。
  豁免清单本身也是门禁对象：`verification/mutation_config_gate.py` 要求每条 `exclude_re` 仍命中候选
  （行号漂移即在第一条失效条目上判红）、只覆盖存活（不吞 caught）、覆盖全部存活且带书面理由。
  当前范围 no-exclude 基线：1519 candidates / 1305 caught（86.0%）/ 134 条逐条钉住的豁免 /
  0 未登记存活，分文件明细见 MUTATION_BASELINE.md。
- **poison / 故障注入**：向黄金路径注入可观测故障（截断 chunk、错误 checksum、延迟/丢包、
  半包写入、cgroup 失败），断言系统**检测并正确降级**而不是静默通过（DST 思想）。
  已有实例：`decode_chunked` 截断注入、ZMTP 短写、`P5-02` 读后清零注入。

## 8. System coverage（系统覆盖）

| 层 | 手段 | 现状 |
|---|---|---|
| Integration | `cpdaemon` mock-CPM + 真 `cpworker`；`cpgolib` 协议 | ✅ 已有 |
| E2E | mock CPM → syncer → 真 cpworker spawn（root，`live-capture` job） | ✅ 已有 |
| Differential | `parity/all.sh`（C/Go oracle，10 步） | ✅ 已有 |
| Performance | `bench/`（null/file/vxlan、live A/B） | ✅ 已有 |
| Soak | 长跑内存/句柄/丢包稳定性 | ✅ `DST_SEED_RANGE=1-20000`（weekly `soak`，~3 min，阻塞）+ 句柄泄漏 soak `fd_soak`（500 次重连/失败握手/失败 dial 后 socket 集合不变） |
| Chaos / Fault injection / DST | 接口抖动、DNS 抖动、依赖故障、时间/顺序扰动 | ✅ DST harness（`crates/sim`，ChaCha8+虚拟时钟+丢包/重复/乱序/位翻转）；weekly soak 跑 2000 seeds |

系统层矩阵登记于 [`verification/system.toml`](verification/system.toml)（`dst-soak`/`live-capture`/`worker-supervision`）。

## 9. 机制：把体系变成可执行门禁

工件：

```
verification/
  policy.toml          # 唯一事实来源：tier→路径、阈值、关键函数、diff 阈值、waiver
  baseline.json        # 覆盖率基线（ratchet）
  requirements.toml    # 需求/场景/状态迁移 → 测试映射
  risk.toml            # 风险清单 → 验证手段
  system.toml          # 系统层（soak/e2e/live）矩阵
  mutants.toml         # cargo-mutants 配置
  coverage_gate.py     # 读 lcov+policy+baseline → 分层/关键函数/变更/no-decrease 门禁
  requirements_gate.py # P0 场景/状态覆盖 100%
verify_coverage.sh     # 本地入口：跑 llvm-cov(lcov) → coverage_gate
```

CI 门禁（`.github/workflows/ci.yml`）：

| 规则 | 级别 | 内容 | 例 |
|---|---|---|---|
| `coverage_not_decrease` | **阻塞** | 每档 line/function ≥ baseline | `baseline.json` |
| `changed_code_coverage` | **阻塞** | 变更行 line≥90% / branch≥85% | `coverage_gate.py --diff` |
| `critical_functions` | **阻塞** | 清单内函数 function 覆盖 = 100% | §3 |
| `tier_targets` | 阻塞（达 target 后）/ waiver | Tier0/1/2/3 line 目标 | §2 |
| `p0_requirements` | **阻塞** | P0 scenario/state 覆盖 = 100% | §5 |
| `p0_risks` | 阻塞 | P0 风险均有验证 | §6 |
| `mutation` | **阻塞**（PR 变更行 + weekly 全量分片） | Tier0/1 范围零存活（超出 `exclude_re` 即失败） | §7 |
| `mutation_config` | **阻塞**（PR + weekly，无需构建） | 豁免清单不漂移/不过度/无遗漏/有理由 | §7 |
| `system` | 定时（nightly/weekly） | soak / chaos / DST | §8 |

> 当前落地：`.github/workflows/ci.yml` 的 `verify-coverage`（line/function、关键函数、no-decrease、
> diff、P0 requirements）与 `mutation-diff`（变更行零存活）已**阻塞**；branch 与 weekly soak 在
> `.github/workflows/verification.yml` 每周运行，仍为 advisory，待基线建立后纳入阻塞。

**PR 评审清单（新增）**：
1. 新测试能指向规范来源（ADR/PARITY/requirements id）？无则不合格。
2. 变更行是否达到 90/85？未达部分是否逐条 `cov:ignore` 并说明？
3. 触及 Tier 0 的改动是否补了状态迁移/失败模式用例？
4. 是否更新 `requirements.toml` / `risk.toml` 与 baseline（只升不降）？

**豁免与例外**：所有豁免集中登记在 `policy.toml` 的 `exclude`（路径+原因+owner），
不得用散落的 `#[cfg(not(test))]` 之类手段制造不可见盲区；hygiene 门禁会检查豁免清单的一致性。

## 10. 分阶段落地

- **阶段 1 ✅ 已完成**：框架文档 + `policy/baseline/gate`（line·function·关键函数·no-decrease·diff）
  + CI `verify-coverage`（阻塞）。
- **阶段 2 ✅ 基本完成**：`requirements.toml` + `requirements_gate.py`（P0 场景 100%，已阻塞进 `verify-coverage`）；
  nightly `verification.yml` 跑 `cargo +nightly llvm-cov --branch`（branch 数据 + 分层报告，advisory）。
  待办：`--mcdc`（condition 门禁）与把 branch 纳入阻塞（待基线建立）。
- **阶段 3 ✅ 已完成（mutation 已阻塞）**：`cargo-mutants` 配置 + `verify_mutation.sh`；
  已关闭 gre/vxlan/stats/config/packet/packet_split/zmtp-codec 及本轮 bpf parser·compiler·interp、
  zmtp client、cpgolib、bpf codes/resolvers/mod 的缺口（见 `verification/MUTATION_BASELINE.md`），
  所有存活均归零（剩余均为 `exclude_re` 登记的等价/死循环/时序边界）。
  PR `mutation-diff`（`--in-diff`，变更行零存活）与 weekly 全量分片 job 均已移除 `continue-on-error`，**阻塞**。
  DST/poison 已由 `crates/sim` 提供。
- **阶段 4 ✅ 已完成**：`verification/system.toml` + weekly `soak` job（`DST_SEED_RANGE=1-20000`，已**阻塞**）；
  新增句柄 soak `crates/cpgolib/tests/fd_soak.rs`（重连/失败握手/失败 dial 三类路径上 socket 集合不变，
  并对注入的 `mem::forget(conn)` 泄漏会失败），随 `cargo test -p cpgolib` 进 CI。
  待办：需 root/veth 的现场长时 soak（属 U3：只能按需触发，不进 PR 门禁）。
- **Tier 0 行覆盖收敛 ✅**：`verify_coverage.sh --privileged-live` 把 AF_PACKET live 测试（root）
  合并进 lcov，Tier 0 行 95.2% / 函数 98.1%，baseline 抬到 target、移除 Tier 0 waiver，
  `AfPacketCapturer::open` 从 critical_waiver 提升为 100% 强制关键函数。
  函数覆盖指标同时修正为「归一化去重 + 排除 `::{closure#N}`」（原指标把同源函数按 crate 实例重复计数）。
- **Tier 1/2/3 覆盖收敛 ✅**：Tier 1 91.99/93.45、Tier 2 96.68/94.64、Tier 3 73.98/84.09（line/function），
  均达或超 target；`baseline.json` 抬高、`policy.toml` 的三个 `[[waiver]]` 全部移除，
  四个 Tier 现在都是绝对强制（ADR-0001 的覆盖率收尾目标完成）。

---

## 附录 A：Tier 逐文件映射（当前）

见 `verification/policy.toml` 的 `[tiers.*].paths`（本表的机器可读版本）。要点：

- Tier 0：`cpworker` 的 `capturer/{af_packet,pcap_file}`、`packet`、`packet_split`、
  `bpf/*`、`zmtp/*`、`output/{vxlan,gre,zmq,pcap_writer}`、`config`、`sockopt`、`netns`。
- Tier 1：`cpworker` 的 `task`、`output/{mod,file,rotating_file,null}`、`ratelimit`、`ring_buffer`、
  `stats`、`unix_manager`、`req_pattern`、`netutil`、`capturer/mod`；`cpdaemon` 的
  `cpm/*`、`worker`、`config`、`reslimit`；`cpgolib` 的 `cpworker/client`、`worker_config`；
  `cripid`、`dockerpid`。
- Tier 2：其余 `cpworker`/`cpdaemon`/`cpgolib`/`cpctl` 支撑模块。
- Tier 3：`cpworker-parity/*`、`sim/*`、各 `main.rs`、`httpmix`、`slogx`、`cpctl/{cli,format}`。
