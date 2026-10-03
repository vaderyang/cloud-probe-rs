# Mutation sweep 证据（2026-10-02）

`verification/mutants.toml` 的 `exclude_re` 是从这里记录的 **no-exclude 全量 sweep**
测量出来的，不是手写的。本目录是那次测量的权威产物（commit
`test: kill the four mutation gaps left open by the 2026-10-02 sweep` 之后重跑）。

工具：`cargo-mutants 27.1.0`，stable toolchain，配置 = `verification/mutants.toml`
去掉 `exclude_re`（globs 与 timeout 预算 `timeout_multiplier = 3.0` /
`minimum_test_timeout = 120.0` 原样保留 —— 预算是豁免契约的一部分，换预算即换基线）。

## 产物

| 文件 | 内容 |
|---|---|
| `outcomes.json` | 权威结果（1593 个 candidate 的逐条判定；2.3 MB）。vxlan.rs 的 3 条判定被下面的 re-measure 覆盖 |
| `caught.txt` / `missed.txt` / `timeout.txt` / `unviable.txt` | 由 `outcomes.json` 导出的分类清单，行数之和 = 1593 |
| `recheck-vxlan-rs-outcomes.json` | `output/vxlan.rs` 单独重跑的原始 outcomes（overlay 的证据） |
| `sweep.log` | 全量 sweep 的**原始** stdout，末行汇总：`1593 mutants tested in 18m: 82 missed, 1370 caught, 82 unviable, 59 timeouts`。它比 `outcomes.json` 少 3 条 vxlan 存活 —— 那 3 条是下面「两个必须知道的坑」里的假阳性，已被 `-j 4` 重跑结果覆盖 |

结果分布：

| candidates | caught | missed | timeout | unviable | 存活 = missed+timeout |
|---:|---:|---:|---:|---:|---:|
| **1593** | **1367 (85.8%)** | 85 | 59 | 82 | **144** |

同一份配置在**补测试之前**（同日 16:58–17:16 UTC）跑的第一次是
`1593 / 1363 caught / 89 missed / 59 timeout / 82 unviable`，即 **148** 个存活；`exclude_re`
的 119 条就是按那一次的存活集钉的。补上 4 条测试（`packet.rs:220:53`、`:259:32`、`:279:53`、
`compiler.rs:521:24`）后存活降到 144，本目录存的是**补测试之后**的这一次，所以每条豁免都还能
命中自己的存活（drift=0），而 4 条缺口已经由 Caught 接管。

`exclude_re` 的 119 条逐条钉住这 144 个存活；带豁免的正式运行实测
`1448 mutants tested in 8m: 1367 caught, 81 unviable`（1448 = 1593 − 145：144 个存活 +
1 个同位本来就 unviable 的 mutant），missed/timeout 均为 0，退出码 0。

## 复现命令

```bash
export PATH="$HOME/.cargo/bin:$PATH"

# 1. 生成去掉 exclude_re 的临时配置（globs/预算不动）
python3.11 - <<'EOF'
t = open('verification/mutants.toml').read(); i = t.index('exclude_re = [')
h = t.rindex('\n', 0, i) + 1; e = t.index('\n]', i) + 2
open('/tmp/mut-noexcl.toml', 'w').write(t[:h] + t[e:])
EOF

# 2. 全量 sweep（-j 12，实测 18 min；-j 8 约 25 min，timeout 判定占大头）
cargo mutants --config /tmp/mut-noexcl.toml -j 12 --output /tmp/mutout/sweep

# 3. 校验豁免清单：drift / over-broad / incomplete / unjustified 四项全过才 exit 0
python3.11 verification/mutation_config_gate.py \
    --outcomes '/tmp/mutout/sweep/mutants.out/outcomes.json'
```

`mutation_config_gate.py --outcomes` 接受逗号分隔的多个 glob，**后者覆盖前者**；本目录
的 `outcomes.json` 就是按这个语义把两次运行合并后的结果，所以单文件即可复现校验：

```bash
python3.11 verification/mutation_config_gate.py \
    --outcomes 'verification/mutation-sweep-2026-10-02/outcomes.json'
```

## 两个必须知道的坑

1. **vxlan.rs 的 3 条 caught 是假阳性。** 全量 sweep（`-j 12`，机器负载 ~30）里
   `output/vxlan.rs:222:45 replace + with *` 与 `:222:53 replace * with +|/` 被判为
   Caught，唯一失败的测试是 `crates/cpworker/tests/unix_control_vectors.rs::
   test_server_drops_client_that_stops_reading`（一个 socket 时序测试，与本文件无关）。
   单独用 `-j 4` 重跑 `output/vxlan.rs`（131 个 candidate，4 min）后这 3 条回到 Missed，
   手工把变异打回源码跑 `cargo test -p cpworker --lib` 也全绿。因此 `outcomes.json` 里
   这 3 条取自重跑结果（见 `recheck-vxlan-rs-outcomes.json`）。**不要**为了迁就假阳性去
   收窄 `mutants.toml` 的 `vxlan\.rs:222:` 条目。
2. **59 条 timeout 不等于"测试测不出来"。** 用 sweep 自己的 per-mutant 日志统计：其中
   **46 条在同一次运行里已经有至少一个失败测试**，只是同一次运行里有别的测试挂住，
   整体被判成 Timeout。17 条挂住的是 `task::tests::reload_worker_*`：
   `crates/cpworker/src/task.rs:1246` 的 `while !worker.is_done()` 没有上限，reload
   worker 线程 panic 后自旋永不退出，把"已经报出来的失败"掩盖成 hang（跟进：
   bead `cloud-probe-rs-10m`）。剩下 13 条才是真死循环/死睡（解释器跳转算术、
   `Builder::finish()` 不收敛、`retry -= 1`、退避时长负值转 `u64` ≈ 208 天）。

## 与上一版基线的差异

上一版（2026-09-30）记的是 1519 candidates / 1305 caught / 134 存活 / 80 unviable。
本次候选数增加来自源码本身的增长（1593），caught 比例 85.8% 与 86.0% 同量级；数字全部
以本目录为准，见 `../MUTATION_BASELINE.md`。
