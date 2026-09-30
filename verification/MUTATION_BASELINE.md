# Mutation baseline（mutation 基线记录）

`VERIFICATION_COVERAGE.md §7` 的 mutation 维度落地记录。工具 `cargo-mutants`
（配置 `verification/mutants.toml`，入口 `verify_mutation.sh`，豁免卫生门禁
`verification/mutation_config_gate.py`）。

**自 ADR-0001 阶段 3 起 mutation 为阻塞门禁**：PR 跑 `--in-diff`（只变异改动行），
weekly `verification.yml` 分 4 shard 跑全量；cargo-mutants 对存活退出 2、超时退出 3，
两者都是失败。因此**范围内不允许出现未被登记的存活**。

## 怎么跑

```bash
cargo install cargo-mutants            # 或 CI 的 taiki-e/install-action
./verify_mutation.sh                   # 配置范围内全量（本地/定时）
./verify_mutation.sh --in-diff         # 只变异相对 origin/main 的改动行（PR 用）
./verify_mutation.sh --shard 1/4       # 分片（周任务矩阵）

# 豁免清单自检（不需要构建，~1 min）：
./verification/mutation_config_gate.py
```

### 怎样重新基线化（no-exclude sweep）

`exclude_re` 不是手写的，而是从一次「去掉豁免」的全量运行里**测量**出来的：

```bash
# 1. 生成去掉 exclude_re 的临时配置（globs 保持不变）
python3 - <<'EOF'
t = open('verification/mutants.toml').read(); i = t.index('exclude_re = [')
h = t.rindex('\n', 0, i) + 1; e = t.index('\n]', i) + 2
open('/tmp/mut-noexcl.toml', 'w').write(t[:h] + t[e:])
EOF
cargo mutants --config /tmp/mut-noexcl.toml -j 8 --output /tmp/mutout/sweep

# 2. 用 sweep 结果校验清单：每条豁免必须仍命中候选、必须只覆盖存活、覆盖所有存活、
#    且带书面理由。四项任一不满足即失败。
./verification/mutation_config_gate.py \
    --outcomes '/tmp/mutout/sweep/mutants.out/outcomes.json'

# 3. 按 sweep 的存活集刷新 mutants.toml（保留理由分类）。
```

第 2 步的 `--outcomes` 支持逗号分隔的多个 glob，**后者覆盖前者**，所以补测某几个文件后
可以只对这几个文件重跑 sweep，再叠在上一次全量结果之上：

```bash
./verification/mutation_config_gate.py \
    --outcomes '/tmp/mutout/full/mutants.out/outcomes.json,/tmp/mutout/scoped/mutants.out/outcomes.json'
```

> 为什么需要这道门禁：`exclude_re` 里大量条目钉在 `file:line:col` 上。改动被测文件后行号
> 漂移，正则就再也匹配不到任何 mutant（豁免静默失效，缺口重新出现）。本仓库上一版
> `gre.rs:33/70/74/133/154/205/207` 七条就是这样腐烂的：行号漂移后，GRE 的 9 个 mutant 又
> 变成 missed，而当时的整行豁免又把另外 30 个真实缺口（packet.rs 等）一起遮住了。
> `mutation_config_gate.py` 会在第一条失效条目上判红。

### 超时预算是豁免契约的一部分

标为 "runner timeout" 的豁免含义是「这个 mutant 让测试挂起至少这么久」，所以
`verification/mutants.toml` 显式固定了 `minimum_test_timeout = 120.0`（以及
`timeout_multiplier = 3.0`）。cargo-mutants 的默认下限（20 s）太紧：一些**慢但确实会被检测到**的
状态机 mutant 会被报成 Timeout（= 门禁失败），且随机器负载摇摆 —— 这在固定预算前真的发生了
（`zmtp/client.rs` 的 `write/queue_out/drive_conn` 共 5 例：20 s 下 timeout、60 s 下 caught）。
**重新基线化时必须用同一份预算。**

## 当前基线（2026-09-30，no-exclude 全量 sweep）

范围 = `verify_mutation.sh` 的 examine_globs。**no-exclude** 结果即"测试套件真实能杀多少"：

| 范围 | candidates | caught | 存活(missed+timeout) | unviable | 存活分类 |
|---|---:|---:|---:|---:|---|
| `cpworker/bpf/codes.rs` | 44 | 21 | 23 | 0 | `\|` vs `^`（位不相交）；`BPF_LD\|BPF_W` 是 `0\|0` |
| `cpworker/bpf/parser.rs` | 162 | 137 | 6 | 19 | runner timeout（计数变异死循环/栈溢出） |
| `cpworker/bpf/compiler.rs` | 136 | 106 | 17 | 13 | runner timeout（`finish` 不收敛）＋ 5 等价 |
| `cpworker/bpf/interp.rs` | 53 | 38 | 15 | 0 | runner timeout（跳转算术使 pc 不动/回退）＋ `\|`/`^` |
| `cpworker/bpf/resolvers.rs` | 25 | 17 | 1 | 7 | `Instant` 精确相等不可构造 |
| `cpworker/bpf/mod.rs` + `linux.rs` | 13 | 12 | 1 | 0 | 非 Linux `attach_filter` 桩 |
| `cpworker/packet.rs` | 284 | 262 | 19 | 3 | 精确边界帧无法完成解析 / 末段 `caplen` guard 兜住 |
| `cpworker/packet_split.rs` | 128 | 127 | 1 | 0 | 校验和只读 `ihl*4` 字节 |
| `cpworker/output/gre.rs` | 76 | 67 | 9 | 0 | 无符号计数日志门 + `slice==caplen` 等价 + 退避时长/`retry` 死循环 |
| `cpworker/output/vxlan.rs` | 131 | 118 | 12 | 1 | 同上；奇数尾字节分支不可达；`max==0` 仍是单片 |
| `cpworker/zmtp/client.rs` | 181 | 143 | 24 | 14 | runner timeout ＋ 压缩/日志/1ms/`Instant` 相等/POLLHUP/最佳努力 close |
| `cpworker/zmtp/codec.rs` | 101 | 95 | 0 | 6 | — |
| `cpworker/config.rs` | 70 | 59 | 3 | 8 | runner timeout |
| `cpgolib/cpworker/client.rs` | 24 | 13 | 2 | 9 | runner timeout（mock accept 阻塞） |
| `cpgolib/cpworker/stats.rs` | 56 | 56 | 0 | 0 | — |
| `cpgolib/{fingerprint,worker_config,worker_fingerprint}` | 32 | 32 | 0 | 0 | — |
| `cpgolib/slogx/mod.rs` | 3 | 2 | 1 | 0 | 进程级 logger 初始化的副作用 |
| **合计** | **1519** | **1305 (86.0%)** | **134** | **80** | 134 条全部逐条钉住并在 `exclude_re` 附理由 |

- **0 个未登记存活**：`cargo-mutants --config verification/mutants.toml` 只测 1385 个
  （1519 − 134 条精确豁免），missed/timeout 均为 0，退出码 0 —— 这就是阻塞门禁的验收条件。
- 134 条豁免按 `mutation_config_gate.py` 校验：全部仍命中候选、只覆盖存活（不吞 caught）、
  覆盖全部存活、且逐条带理由。
- Tier 阈值（`policy.toml`：Tier0 ≥85% / Tier1 ≥75%）作为**最低目标**；当前范围 86.0% caught，
  其余为上述分类的非等价项，而不是"未测量"。

### 本轮修正（诚实记录）

上一版基线在多个模块写「0 missed / 剩余为等价 guard」，但那些结论建立在**按整行**登记的
豁免之上。本轮做 no-exclude sweep 后发现并关闭了一批**真实缺口**：

| 文件 | sweep 暴露的存活 | 关闭方式 |
|---|---:|---|
| `packet.rs` | 30 | 新增"最小帧的**每个前缀截断都必须被拒**"表驱动测试（11 种帧：v4/v4+options/v4+tcp24/vlan/双 vlan/v6/v6+hopopts/routing/dstopts）+ `payload_len` 取自**声明**长度而非抓包长度（v4/v6 各两组）+ `extract_ipport` 逐层最小长度 + v6 源/目的地址断言 → 存活降到 19 |
| `vxlan.rs` | 6 | `vxlan_encapsulate` 的校验和只覆盖前 42 字节（用"42 字节之后填 0xFF 不改变校验和"的不变量测试钉住）+ 直接单测 `rte_raw_cksum` 的奇数尾字节分支 |
| `zmtp/codec.rs` | 3 | `parse_metadata` 三种截断的错误分类断言 + `frame()` 依 body 长度**规范化** long 标志（调用方传入也不被异或掉） |
| `zmtp/client.rs` | 5 | backoff **只在进入 `Phase::Open` 的迁移**上复位（已开连接/半握手均不复位）+ `TcpTransport` 完成 connect 后 `check_connected` 必须为 true + 空 DNS 结果不覆盖可用地址 |
| `bpf/compiler.rs` | 1 | 直接构造**后向跳转**并断言 `finish()` 报 "backward jump not supported" |

`socket_option_wrappers_propagate_setsockopt_errors`（gre/vxlan 各一）：`SO_BINDTODEVICE` 的
NUL 校验与 `IP_MTU_DISCOVER` 的非法值在内核里分别返回 `EINVAL`/`EINVAL`，无需 root 即可断言
"必须向上传播错误"，因此原先"root-only wrapper"的两条豁免被真测试取代。

### 已关闭的缺口

- `cpworker::output::gre` / `vxlan`：抽出共享 `Egress`（`RawSocketEgress` / 测试 `MockEgress`）后
  发送/重试/统计状态机完全单测化（slice/clamp、未知方向丢弃、令牌桶、部分发送、ENOBUFS 重试与耗尽、
  其它 errno、error-info 窗口、分片路径、golden wire 向量）。
- `cpworker::packet` / `packet_split`：见上表；分片侧另有校验和 golden、分片字节 golden、
  "重算后校验和归零"不变量、IPv6/UDP 长度修正。
- `cpworker::zmtp::{codec,client}`：常量/Display/greeting/命令帧/短长帧与 255·上限边界；
  状态机的 greeting/READY/PONG 分帧、255 字节边界与字节预算、backoff 倍增·复位·抑制、
  EINTR 重试、硬读写错误断开、Open 期 ERROR、WouldBlock 重排队记账、连接器地址轮转、
  DNS 空结果/TTL、拒绝连接、fd 复用。
- `cpworker::bpf::{parser,compiler,interp}`：tokenizer/布尔优先级/20+ 错误路径/掩码与
  `MAX_*` 精确边界；`Test` 变体语义矩阵与 golden 指令、`Builder::finish` 的 255 跳距与
  trampoline 细化循环、后向跳转拒绝；逐 opcode 手搓程序表驱动测试。
- `cpgolib::{stats,fingerprint,worker_config,worker_fingerprint}`：跨单位借位、单位常量、
  `compare` 排序、`ControlConfig::connect_string` 分支、`task_fingerprint` 全字段标签。

### 剩余的 134 条豁免（分类）

1. **runner timeout（52 条 timeout 判定 / 覆盖约 60 个 mutant）**：变异让代码**死循环或睡到天荒地老**
   （解释器跳转算术、`finish()` 的标签/细化循环不收敛、`retry -= 1`、退避时长负值转 `u64`、
   mock accept 阻塞、队列簿记停滞）。没有有限测试能“报错”，cargo-mutants 报 Timeout —— 对门禁而言
   仍是失败，故必须逐条登记。
   校验：把 52 个 timeout 判定单独用**提交预算（120 s）**重测一遍（反向排除其它 1467 个
   candidate），结果仍为 52/52 Timeout，证明这些标注不是“预算太短”造成的假 timeout。
2. **算术恒等（约 35 条）**：位不相交的 `|`/`^`；`slice == caplen` 时两分支赋同值；
   `payload_len` 在相等处 clamp 是空操作；trampoline 分支里 `p/tp - 1 == 0`；
   缩小的阈值仍被末尾 `payload_offset > caplen` guard 兜住；精确边界帧无法完成更深层解析。
3. **不可观测（约 20 条）**：只决定一行日志（无符号计数 `>= 0`、warn-once 闩、abandon 的 log、
   `init_default`）、1 ms sleep、`Instant::now()` 无法钉到相等瞬间、`POLLERR|POLLHUP` 在 TCP 上
   必然伴随 `take_error()`、连接关闭时的 best-effort `shutdown`、`queue_out` 的压缩只是内存优化。
4. **平台/无根（2 条）**：非 Linux 的 `attach_filter` 桩；`cpgolib` 的 logger 初始化。

### 未测范围

- `cpworker::bpf::mod::attach_filter` 的真 syscall 路径（需 `CAP_NET_RAW`）归 `live-capture` job；
  其错误分支已由 `bpf::tests` 覆盖。
- af_packet 抓包环路径同上（`live-capture`）。
