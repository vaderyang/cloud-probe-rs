# Mutation sweep 证据（2026-10-03，post-`ix9`）

`cloud-probe-rs-ix9` / `cloud-probe-rs-bg2`。这是**当前 main**（`ca2c1b6`：含 `ix9` 与 bg2 的 4 个缺口测试）
上的 no-exclude 全量 sweep，`exclude_re` 的 104 条就是从这一次的存活集重 pin 的。

工具 `cargo-mutants 27.1.0`，`-j 12`，配置 = `verification/mutants.toml` 去掉 `exclude_re`
（globs 与 timeout 预算 `timeout_multiplier = 3.0` / `minimum_test_timeout = 120.0` 原样保留 ——
预算属于豁免契约，换预算即换基线）。复现：`bash scripts/mutation_resweep.sh <worktree>`。

## 结果

| candidates | caught | missed | timeout | unviable | 存活 = missed+timeout |
|---:|---:|---:|---:|---:|---:|
| **1593** | **1384 (86.9%)** | 84 | 43 | 82 | **127** |

其中 **43 个 timeout 里有 29 个的 per-mutant 日志同时含逐条 `test ... FAILED`** ——
即套件其实杀掉了它们，只是同一次运行里**另一个测试挂住**，cargo-mutants 只能报 Timeout。
要找的标记是**逐条**的 `test X ... FAILED`，不是 summary 行：挂起的运行永远打不到 summary。
剩余挂起源见 `cloud-probe-rs-l81`。

## 与上一次（2026-10-02）的对照 —— 这就是 `ix9` 的收益

两次都是 1593 候选、都**不含** bg2 的 4 个缺口测试，因此是可比的干净对照：

| | 2026-10-02 | 2026-10-03 | 变化 |
|---|---:|---:|---:|
| caught | 1363 | **1383→1384** | **+20** |
| missed | 89 | 84 | −5 |
| **timeout** | **59** | **43** | **−16** |
| timeout 中「测试其实已失败」 | 45 | 29 | **−16** |

`ix9` 修的是 `ReloadWorker` 在 `work()` panic 时永不置位 `done`，使等待方永久自旋。
它把 **16 个「被报成 timeout 的真 kill」变回真 kill**（另加若干 missed 变 caught），
因此本轮可以从 `exclude_re` **删掉 15 条**已无必要的豁免：**119 → 104**。

## 权威产物

| 文件 | 内容 |
|---|---|
| `outcomes.json` | 逐条判定（1593 个 candidate，2.9 MB） |
| `caught.txt` / `missed.txt` / `timeout.txt` / `unviable.txt` | 分类清单，行数之和 = 1593 |
| `sweep.log` | 全量 sweep 的原始 stdout |

带豁免的正式运行（阻塞门禁）：见提交信息与 `MUTATION_BASELINE.md`；`mutation_config_gate.py` 对本
`outcomes.json` 的校验为 `104 exemptions, all live, all justified, none over-broad, all survivors
accounted for`。

## 一个必须知道的坑：并行假阳性（本轮又抓到 1 例）

`-j 12` 的全量 sweep 会偶发**假的 `Caught`**：同一次运行里某个不相关的测试挂了/失败了，
变异体就被记成 `Caught`；而这些变异体单独串行重测其实是 `Missed`。

本轮（2026-10-03）抓到 1 例：`cpworker/src/packet.rs:309:22: replace > with >=` —— 全量 sweep 记
`Caught`，但**串行（`-j 4`）重测 packet.rs 是 `Missed`**。代码本身也支持后者：
`if r.payload_len > max_payload { r.payload_len = max_payload }` 改成 `>=` 时，相等分支赋的是
同一个值，无输入可区分 —— 这是**等价变异体**。其串行原始结果随本目录
`recheck-packet-rs-outcomes.json` 一并入库，`mutation_config_gate.py` 以它覆盖全量结果。

上一轮（2026-10-02）同类问题有 3 例，都在 `output/vxlan.rs`（见上一目录的 `recheck-vxlan-rs-outcomes.json`）。
**结论：有争议的变异体一律以串行重测为准**；`scripts/mutation_resweep.sh` 的 `JOBS` 也建议在重 pin 时调低。
另一类（timeout 掩盖真 kill）见 `cloud-probe-rs-l81`。
