# Mutation baseline（mutation 基线记录）

`VERIFICATION_COVERAGE.md §7` 的 mutation 维度落地记录。工具 `cargo-mutants`
（`verification/mutants.toml`、`verify_mutation.sh`）；每周 `verification.yml` 分 4 shard 运行，
当前 **advisory**，待基线建立后纳阻塞。

## 怎么跑

```bash
cargo install cargo-mutants            # 或 CI 的 taiki-e/install-action
./verify_mutation.sh                   # 配置范围内全量（慢，本地/定时）
./verify_mutation.sh --in-diff         # 只变异相对 origin/main 的改动行（PR 用）
./verify_mutation.sh --shard 1/4       # 分片（周任务矩阵）
# 单文件快速采样：
cat > /tmp/mut-one.toml <<'EOF'
examine_globs = ["crates/cpworker/src/output/gre.rs"]
EOF
cargo mutants --config /tmp/mut-one.toml --no-times
```

## 首次测量（2026-09-29）

| 范围 | mutants | caught | missed | 结论 |
|---|---:|---:|---:|---|
| `crates/cpworker/src/output/gre.rs` | 76 | 0 | **76** | GRE 输出路径**几乎没有测试**（行覆盖 ~8%） |

`GreOutput::send_packet` 与 `_pmtudisc_consts` 的全部算术/比较/逻辑变异均**存活**，
说明该路径的行为没有被任何测试固定。这是 mutation 维度发现的第一个真实缺口
（行覆盖 8% 早已提示，mutation 给出了确定结论）。

## 策略

- 阈值（Tier 0 ≥85% / Tier 1 ≥75% / Tier 2 ≥60%，见 `policy.toml`）为**目标**；
  未基线化前 **不阻塞**，仅每周报告 + 记录缺口。
- PR 使用 `--in-diff`（只变异改动行）；待全量基线稳定后可对改动范围启用"零存活 mutant"硬门禁。
- 缺口清单（待补测试，随测量更新）：
  - `cpworker::output::gre::GreOutput::send_packet` / `_pmtudisc_consts`（GRE 输出）
  - `cpgolib::cpworker::stats::{BytesStats,PacketsStats}::sub`（减法/回绕）
  - `cpworker::bpf::mod::attach_filter`（需 root，归入 `live-capture` 覆盖）
  - `cpworker::config::{OutputConfig,CapturerKind}` 的访问器与 `canonical_dump`（部分）
