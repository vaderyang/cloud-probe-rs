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
./verify_mutation.sh --shard 0/4       # 分片（周任务矩阵；cargo-mutants 的 shard 是 0 基，0/4..3/4）

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

## 当前基线（2026-10-03，no-exclude 全量 sweep；post-`cloud-probe-rs-ix9`）

范围 = `verify_mutation.sh` 的 examine_globs。**no-exclude** 结果即"测试套件真实能杀多少"。
权威产物：`verification/mutation-sweep-2026-10-02/`（`outcomes.json` + 四个分类清单 +
`sweep.log`，命令/`-j`/耗时/两个坑见同目录 `README.md`）。工具 cargo-mutants 27.1.0，
`-j 12`，全量耗时 18 min；候选数从上一版的 1519 涨到 1593 是源码增长，不是范围变化。

| 范围 | candidates | caught | 存活(missed+timeout) | unviable | 存活分类 |
|---|---:|---:|---:|---:|---|
| `cpworker/bpf/codes.rs` | 44 | 21 | 23 | 0 | `\|` vs `^`（位不相交）；`BPF_LD\|BPF_W` 是 `0\|0` |
| `cpworker/bpf/parser.rs` | 179 | 154 | 6 | 19 | runner timeout（计数变异死循环/栈溢出） |
| `cpworker/bpf/compiler.rs` | 139 | 109 | 17 (6m/11t) | 13 | runner timeout（`finish` 不收敛）＋ 等价（含 `ether proto` 1500 边界，本轮已关） |
| `cpworker/bpf/interp.rs` | 53 | 36 | 17 (1m/16t) | 0 | runner timeout（跳转算术使 pc 不动/回退）＋ `\|`/`^` |
| `cpworker/bpf/resolvers.rs` | 25 | 17 | 1 | 7 | `Instant` 精确相等不可构造 |
| `cpworker/bpf/mod.rs` + `linux.rs` | 13 | 12 | 1 | 0 | 非 Linux `attach_filter` 桩 |
| `cpworker/packet.rs` | 288 | 269 | 16 (16m/0t) | 3 | 精确边界帧无法完成解析 / 末段 `caplen` guard 兜住（本轮关掉 3 条：doff=9..15、v6 60 B 扩展头） |
| `cpworker/packet_split.rs` | 131 | 130 | 1 | 0 | 校验和只读 `ihl*4` 字节 |
| `cpworker/output/gre.rs` | 76 | 67 | 9 (7m/2t) | 0 | 无符号计数日志门 + `slice==caplen` 等价 + 退避时长/`retry` 死循环 |
| `cpworker/output/vxlan.rs` | 131 | 120 | 10 (8m/2t) | 1 | 同上；奇数尾字节分支不可达；`max==0` 仍是单片 |
| `cpworker/zmtp/client.rs` | 188 | 149 | 24 (12m/12t) | 15 | runner timeout ＋ 压缩/日志/1ms/`Instant` 相等/POLLHUP/最佳努力 close |
| `cpworker/zmtp/codec.rs` | 101 | 95 | 0 | 6 | — |
| `cpworker/config.rs` | 110 | 85 | 16 (8m/8t) | 9 | runner timeout ＋ 只写日志的范围门 |
| `cpgolib/cpworker/client.rs` | 24 | 13 | 2 | 9 | runner timeout（mock accept 阻塞） |
| `cpgolib/cpworker/stats.rs` | 56 | 56 | 0 | 0 | — |
| `cpgolib/{fingerprint,worker_config,worker_fingerprint}` | 32 | 32 | 0 | 0 | — |
| `cpgolib/slogx/mod.rs` | 3 | 2 | 1 | 0 | 进程级 logger 初始化的副作用 |
| **合计** | **1593** | **1384 (86.9%)** | **127 (84m+43t)** | **82** | 127 个存活由 104 条 `exclude_re` 逐条钉住并附理由 |

- **0 个未登记存活**：`cargo-mutants --config verification/mutants.toml` 实测 1448 个
  （1593 − 145 个被豁免命中：144 个存活 + 1 个本来就 unviable 的同位 mutant），
  `1448 mutants tested in 8m: 1367 caught, 81 unviable`，missed/timeout 均为 0，退出码 0 —— 这就是阻塞门禁的验收条件。
- 119 条豁免按 `mutation_config_gate.py` 校验：全部仍命中候选、只覆盖存活（不吞 caught）、
  覆盖全部存活、且逐条带理由。
- Tier 阈值（`policy.toml`：Tier0 ≥85% / Tier1 ≥75%）作为**最低目标**；当前范围 85.8% caught，
  其余为上述分类的非等价项，而不是"未测量"。

### 本轮（2026-10-03）收口：`ix9` 之后重 pin，豁免 119 → 104

`cloud-probe-rs-ix9` 修掉了 `ReloadWorker` 的一个挂起：线程体把完成标志的置位放在 `work()` 之后，
`work()` panic 时那行永不执行，等待方永久自旋 —— 于是套件其实已经杀掉的变异被 cargo-mutants
报成 Timeout。影响是**可测的**（两次都是 1593 候选、都不含上轮那 4 个缺口测试，故为干净对照）：

| | 2026-10-02 | 2026-10-03 | 变化 |
|---|---:|---:|---:|
| caught | 1363 | 1384 | **+20** |
| **timeout** | 59 | **43** | **−16** |
| timeout 中「测试其实已失败」 | 45 | 29 | **−16** |

因此重 pin：**15 条豁免被删除**（它们覆盖的变异已由 Caught 接管），`exclude_re` **119 → 104**；
存活集 144 → 127。权威产物见 `verification/mutation-sweep-2026-10-03/`。
**剩下的 29 个 timeout 仍被另一个挂起源掩盖**，见 `cloud-probe-rs-l81` —— 修掉它预期还能再缩一截。

### 上一轮（2026-10-02）收口：4 条缺口用测试关闭

上一版把 129 条豁免重钉到本轮 sweep 的行号时，故意**不**豁免 4 个存活 —— 它们的等价性
无法从代码推出，探针显示是真缺口，用测试关闭而不是登记：

| 变异体 | 根因 | 新测试 |
|---|---|---|
| `packet.rs:220:53` `+`→`-`（v4 TCP 长度 guard） | 全套帧都是 doff≤5，`offset(34) - l4_hdr_len` 不下溢，guard 判定相同 | `parse_ipv4_tcp_with_a_header_longer_than_its_prefix`：doff=9..=15 断言 `l4_hdr_len`/`payload_offset`/`payload_len`，外加 ihl5+doff15（caplen=94、tot_len=80）的相等边界与截一字节必拒 |
| `packet.rs:279:53` 同一 guard 的 v6 侧 | prefix=54，需 doff≥14 | `parse_ipv6_tcp_with_a_header_longer_than_its_prefix`：doff=14..=15 + doff=15 的相等/截断边界 |
| `packet.rs:259:32` `+`→`-`（v6 扩展头 guard） | 现有 ext 帧只有 8 B（< prefix 54 B） | `parse_ipv6_extension_header_longer_than_its_prefix`：hdr_ext_len=7（64 B）完整帧 → `Some` + `ipv6_ext_len=64`；hdr_ext_len=255（声明 2048 B）短帧 → `None` |
| `compiler.rs:521:24` `>`→`>=`（`ether proto` 802.3 长度边界） | 现有 golden 用了 100 和 0x88b5，从没测 1500 | `ether_proto_length_boundary_is_exactly_the_8023_maximum`：1500 的 6 条指令 golden + 1501 的 4 条 golden + 携带 1500 的帧必须不匹配 |

四条都用手打补丁复验过：打回变异后 `cargo test -p cpworker --lib` 必红（三条是 mutate 路径
subtract-with-overflow，compiler 那条是 golden 指令序列不符），恢复后全绿。重跑 sweep 后
这 4 个变异体的判定为 `CaughtMutant`。

### timeout 判定不等于"测不出来"（重要修正）

本 sweep 自己的 per-mutant 日志显示：**59 条 timeout 里有 46 条在同一次运行里已经有测试失败**，
只是同一次运行里另有测试挂住，整体被报成 Timeout（= 门禁失败）。挂住的测试主要是
`task::tests::reload_worker_delivers_the_plan_and_its_problems`（17 条）与 `bpf::compiler::tests::*`
（20 条）：`crates/cpworker/src/task.rs:1246`（以及 2308）的 `while !worker.is_done()` **无上限**，
reload worker 线程 panic 后 `is_done()` 永远不为真，于是"已经被测出的失败"被掩盖成 hang。
跟进任务：bead **`cloud-probe-rs-10m`**（给这个自旋加上时间/次数上限并在超限时明确报 panic）。
剩下 13 条才是真·死循环/死睡（解释器跳转算术让 pc 不动、`Builder::finish()` 不收敛、
`retry -= 1` 永远 < 10、退避时长负值转 `u64` ≈ 208 天 sleep）。

> 也就是说：这些 mutant 的豁免理由写 "runner timeout" 是对的（harness 确实只能看到 Timeout），
> 但**不要**把它读成"测试无覆盖"。修掉 `cloud-probe-rs-10m` 之后重跑 sweep，这批判定会大幅
> 转成 Caught，`exclude_re` 也应随之缩短。

### 另一个假阳性：flaky 的 `unix_control_vectors` 测试

全量 sweep（`-j 12`、机器负载 ~30）把 `output/vxlan.rs:222:45 replace + with *` 和
`:222:53 replace * with +|/` 判成 Caught，唯一失败测试是
`crates/cpworker/tests/unix_control_vectors.rs::test_server_drops_client_that_stops_reading`
（与本文件无关的 socket 时序测试）。用 `-j 4` 单独重跑 `output/vxlan.rs` 的 131 个候选后这 3 条回到
Missed，手工打回变异跑 `cargo test -p cpworker --lib` 也全绿。因此入库的 `outcomes.json` 里这 3 条
取自重跑（`recheck-vxlan-rs-outcomes.json` 是证据），**没有**为了迁就假阳性去收窄豁免。
这暴露了一个门禁风险：flaky 测试会把真实存活伪装成 Caught（本例就差点触发一条"收窄豁免"的
错误修改）。修它需要给该测试加显式等待而不是固定 sleep，未在本轮范围内。

### 上一轮（2026-09-30）的诚实记录

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

### 剩余的 119 条豁免（覆盖 144 个存活，分类）

1. **runner timeout（47 条 / 57 个存活）**：变异让代码**死循环或睡到天荒地老**
   （解释器跳转算术、`finish()` 的标签/细化循环不收敛、`retry -= 1`、退避时长负值转 `u64`、
   mock accept 阻塞、队列簿记停滞）。cargo-mutants 报 Timeout —— 对门禁而言仍是失败，故必须
   逐条登记。注意：这 59 条 timeout 判定里 46 条同一次运行已有失败测试（见上一节，
   bead `cloud-probe-rs-10m`），"runner timeout" 描述的是 harness 的可见性，不是测试无覆盖。
   校验：本 sweep 用的就是提交预算（`minimum_test_timeout = 120.0`、`timeout_multiplier = 3.0`），
   59 条判定全部在 120 s 下复现，不是预算太短造成的假 timeout。
2. **算术/结构等价（52 条 / 55 个存活）**：位不相交的 `|`/`^`；`slice == caplen` 时两分支赋同值；
   `payload_len` 在相等处 clamp 是空操作；trampoline 分支里 `p/tp - 1 == 0`；
   缩小的阈值仍被末尾 `payload_offset > caplen` guard 兜住；精确边界帧无法完成更深层解析。
3. **不可观测（18 条 / 30 个存活）**：只决定一行日志（无符号计数 `>= 0`、warn-once 闩、abandon 的 log、
   只喂 `log_warn!` 的 service_tag 范围门）、1 ms sleep、`Instant::now()` 无法钉到相等瞬间、
   `POLLERR|POLLHUP` 在 TCP 上必然伴随 `take_error()`、连接关闭时的 best-effort `shutdown`、
   `queue_out` 的压缩只是内存优化。
4. **平台（2 条 / 2 个存活）**：非 Linux `attach_filter` 桩（测试主机上被 cfg 掉，二进制与基线逐字节相同）；
   `cpgolib` 的进程级 logger 初始化（结果被丢弃，调用方都在 examine_globs 之外）。

### 未测范围

- `cpworker::bpf::mod::attach_filter` 的真 syscall 路径（需 `CAP_NET_RAW`）归 `live-capture` job；
  其错误分支已由 `bpf::tests` 覆盖。
- af_packet 抓包环路径同上（`live-capture`）。
