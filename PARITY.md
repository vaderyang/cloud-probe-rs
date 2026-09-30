# 迁移一致性与覆盖报告

> 结论：**核心引擎与工具已高度完整；cpdaemon 已补齐主要模块。一致性通过差分对拍
> 与测试向量移植来证明，而非阅读代码。**
>
> “纯 Rust”（去除 libpcap/libzmq）**已完成**：`cargo build`/`cargo test` 不链接任何
> C 库，实现与取舍见 §4。
>
> 上游 `netis/cloud-probe@0.9.x` 是**浮动 oracle**（CI 每次实时拉取），上游前进可能在
> 本仓库无改动时让差分/模糊门变红（先例 #279、#281、#282）。追平流程与逐提交检查清单见
> [UPSTREAM_RUNBOOK.md](UPSTREAM_RUNBOOK.md)。

## 1. 覆盖状态

### 1.1 cpworker（C → Rust）

| 原 C 文件 | Rust | 状态 |
|---|---|---|
| `config.c` / `cjson_utils.c` | `config.rs`（serde） | ✅ 差分验证 |
| `packet_split.c` | `packet_split.rs` | ✅ 差分验证（逐字节） |
| `req_pattern.c` | `req_pattern.rs` | ✅ 差分验证 |
| `bpf_util.c` / `if_util.c` / `ether.c` / `ip.c` | `netutil.rs` / `packet.rs` | ✅ |
| `stats.c` / `log.c` / `errorf.c` / `ratelimit.c` | 同名 | ✅ |
| `affinity_linux.c` | `affinity.rs` | ✅ 测试向量移植 |
| `netns_linux.c` | `netns.rs` | ✅ |
| `output_*.c`（6） | `output/*.rs` | ✅ 纯 Rust（含 ZMTP 3.x PUSH，替代 libzmq；差异见 §2.4） |
| `libpcap.c` / `pcap_file.c` | `capturer/*.rs` | ✅ 纯 Rust（裸 `AF_PACKET` + 自研 BPF + pcap 读写；配置键 `libpcap` 保留以兼容 C 配置文件） |
| `ring_buffer.c` | `ring_buffer.rs` | ⚠️ 语义等价，非无锁 |
| `task.c` | `task.rs` | ⚠️ reload 简化为重建 |
| `unix-manager.c` / `unix_rpc_basic.c` | `unix_manager.rs` | ✅ |
| `dpdk/pdump.c` | — | ❌ 未 port |

### 1.2 cpdaemon（Go → Rust）

| 原 Go 文件 | Rust | 状态 |
|---|---|---|
| `pkg/worker/config.go` | `worker_config.rs` | ✅ |
| `pkg/worker/worker.go` | `worker.rs` | ✅ |
| `pkg/worker/log.go` | `worker_log.rs` | ✅ |
| `pkg/worker/reslimit*.go` | `reslimit.rs` | ✅（cgroup v1/v2 CPU 限额） |
| `pkg/cgroup/*` | `reslimit.rs` | ⚠️ v1/v2 CPU 配额；写后校验未移植 |
| `pkg/common/{fnv,fingerprint,signature,fingerprint_reflect}.go` | `common.rs` | ✅ 测试向量验证 |
| `pkg/cpm/client.go` / `models.go` | `cpm/client.rs` / `models.rs` | ✅ |
| `pkg/cpm/syncer.go` | `cpm/syncer.rs` | ✅ |
| `pkg/cpm/worker_mgr.go` | `cpm/worker_mgr.rs` | ✅ |
| `pkg/cpm/worker_task_builder.go` | `cpm/task_builder.rs` | ✅ 测试向量验证 |
| `pkg/cpm/synclog.go` | `cpm/synclog.rs` | ✅ |
| `pkg/cpm/utils.go` / `uuid.go` | `cpm/utils.rs` / `syncer.rs` | ✅ |
| `pkg/tool/*.go` | `tool.rs` | ✅ |
| `pkg/httpmix/*.go` | `httpmix.rs` | ✅（路由仅 `/` 与 pprof，后者 Go 特有） |
| `cmd/internal/asm/*`（Wire DI） | `main.rs`（手工装配） | ⚠️ 机制不同 |

### 1.3 测试

| 来源 | 状态 |
|---|---|
| C 单测向量（`misc.c` 等） | ✅ 34 个移植到 `cpworker/tests/port_parity.rs` |
| Go `worker_task_builder_test.go` 向量 | ✅ 6 个 Go 测试函数全都移植到 `cpdaemon/src/cpm/task_builder.rs`（展开为 8 个 Rust 测试） |
| cpgolib / cpctl 纯函数测试 | ✅ 7 + 2 |
| 其余 C/Go 测试文件 | ⚠️ 部分未移植 |

当前 `cargo test --workspace`：**165 个测试全部通过**（含 `cpsim` 的 DST 测试），另有 3 个需要 `CAP_NET_RAW`（其中两个还需要 `CAP_NET_ADMIN` / 创建 veth）的
实时抓包测试标记为 `#[ignore]`，由 CI 的 privileged job 运行：`live_capture_on_loopback_with_filter`、
`live_capture_reinserts_vlan_on_veth`、`live_capture_falls_back_to_userspace_filtering`。

### 1.4 Deterministic Simulation Testing（`crates/sim`）

`cpsim` 是单线程、种子驱动的确定性仿真框架：虚拟时钟 + ChaCha8 + 事件队列 +
可注入故障（丢包/重复/乱序/位翻转/延迟），复用 cpworker 真实封装、限速、分片代码，
collector 解码并对账。同一 seed 跨进程 trace 摘要一致，可精确复现失败。

P3 之后新增两个 DST 驱动（回应 AUDIT4 指出的覆盖缺口）：

* `pcap_source`：以可变大小的确定性 record 序列驱动真实 `PcapReader`（8 KiB `BufReader`
  边界跨界），逐条验证 ts/caplen/payload；并覆盖截断与 oversized-incl 的干净停止。
  回归：`read()` vs `read_exact()` 位置漂移 bug 即由此路径暴露。
* `zmtp_driver`：以种子化的脚本 peer（短写/EAGAIN/EOF/畸形 greeting/写预算）驱动真实
  `ZmtpPush` 状态机，不变量：队列不超 HWM、wire 必须为 greeting + 整帧（单 FIFO）。

* 测试：`cargo test -p cpsim --test dst`；复现某个 seed：`DST_SEED=7 cargo test -p cpsim --test dst`
* trace：`cargo run -p cpsim --example trace -- 7 zmq harsh`
* 详解见 `crates/sim/README.md`
* 已把上游 ZMQ VLAN 溢出（issue #231）做成回归用例 `zmq_vlan_slice_never_corrupts`。

### 1.5 覆盖率引导的 Fuzz（cargo-fuzz / libFuzzer）

`crates/cpworker/fuzz/` 下有 10 个 fuzz target（nightly + ASAN + libFuzzer）：

| target | 对象 |
|---|---|
| `packet_split` | `parse_packet` / `calculate_fragment_count` / `build_fragment` |
| `config` | JSON 配置解析 + BPF 排除主机 |
| `vxlan` | `vxlan_encapsulate`（校验和/capture_time） |
| `zmq_batch` | `BatchBuilder`（VLAN/MPLS，issue #231 回归） |
| `sim_dst` | 整个确定性仿真 + 不变量 |
| `bpf` | BPF 解析/编译/解释（任意表达式 + 任意报文） |
| `zmtp_wire` | ZMTP greeting/帧/命令编解码（含长度上限） |
| `zmtp_client` | 非阻塞 ZMTP 客户端状态机（模拟垃圾握手/截断/中断/HWM 的混沌驱动） |
| `diff_oracle` | C/Go 差分（见 §1.6，由 `parity/difffuzz.sh` 驱动） |

* 运行：`fuzz.sh [秒数] [target|all]`；CI 烟雾：`fuzz.sh --check`
* **门禁**：`parity/verify_hygiene.sh` 要求 `fuzz/Cargo.toml` 里声明的每个 target 都必须出现在 `fuzz.sh` 的执行列表中（`diff_oracle` 是唯一显式豁免）——"写了但从不运行"的 fuzz target 等于没有（AUDIT4 §3.2 的又一形态）
* 复现：`fuzz.sh repro zmq_batch <artifact>`
* 详见 `crates/cpworker/fuzz/README.md`

二者互补：Python 差分 fuzz 证明“C 与 Rust 行为一致”，cargo-fuzz 在 Rust 内部搜索崩溃/不变量
违例并给出可复现输入。

### 1.6 覆盖引导的差分 Fuzz（Rust ↔ 原 C/Go）

`parity/difffuzz.sh` 把两者结合：Rust 侧**在进程内**跑（libFuzzer 获得覆盖率反馈），
原 C 代码作为**常驻 oracle 子进程**（`--sentinel` 行帧）；每个输入映射成同一请求喂给两侧，
逐行比较规范化输出，一旦分歧即 panic，libFuzzer 保存触发输入。这能发现固定种子的差分测试
（`parity/*.sh`，只覆盖“生成器能想到的”输入）遗漏的语义差异。

| 模式 | 对象 | oracle |
|---|---|---|
| `packet_split` | `parse_packet` + 分片 + 校验和 | C `c_harness.c` |
| `config` | JSON 解析 + bpf 排除主机 | C `c_config.c` |
| `req_pattern` | 自定义模式匹配器 + 整包方向判定（`judge_pkt_direction`） | C `c_req_pattern.c` |
| `fingerprint` | `labels_to_fingerprint` + `String`/`UUID` | Go `difffuzz/go/oracle.go` |
| `task_fingerprint` | `TaskConfig` → 反射 label → 指纹 | Go `difffuzz/go/oracle.go` |

```bash
parity/difffuzz.sh 60 packet_split   # 一个模式 60s
parity/difffuzz.sh 120 all           # 全部模式各 120s
```

Go oracle 由 `difffuzz.sh` 现场用临时 module（`replace` 到参考仓库的 `cpdaemon`/`cpgolib`）
编译；`task_fingerprint` 的输入是**固定字段名的模板 JSON**（只 fuzz 值与可选字段存在性），
避免 Go/serde 在 JSON 解码宽容度上的差异淹没指纹逻辑。

已知的有意分歧（§2.2 的 IPv4/TCP 严格校验；§2.3 的 JSON 解码宽容度）在 target 内被分类过滤，
以便继续搜索**新**分歧。**本框架已发现并修复**：

1. `req_pattern` 的端口解析。C 早期用 `strtol(..., 10)`，接受 `-0`/`+80`，Rust 用 `u16`
   拒绝；对齐后上游又把规则收紧为**纯十进制**（`req_pattern.c` 的 `plain_decimal` 守卫：
   无符号、无前导零 —— BPF 会把 `010` 读作八进制），两侧现已一致。
2. `TaskConfig` 指纹：Go 的 `CustomReqPatternConfig.Pattern` 是非指针 string（始终参与指纹，
   即使为空），Rust 曾用 `Option` 跳过——已修正并对齐 Go 向量。

差分/模糊测试（`parity/`）：

| 脚本 | 对象 |
|---|---|
| `run.sh` | packet_split（解析/分片/校验和） |
| `verify_config.sh` | config JSON 解析 + bpf 排除主机 |
| `verify_req.sh` | req_pattern 匹配器 + 整包方向判定（含 QinQ） |
| `fuzz_proto.sh` | GRE / VXLAN / ZMQ batch 线格式 |
| `fuzz_rpc.sh` | Unix JSON-RPC 协议 |
| `all.sh` | 一键全部 |

## 2. 差分对拍（一致性硬证据）

```bash
parity/run.sh 5000 42     # packet_split: C vs Rust
```

| 模块 | 方法 | 规模 | 结果 |
|---|---|---|---|
| `packet_split`（解析/切片/IP·TCP·UDP 校验和） | C harness vs Rust，逐字节 diff | 5 种子 × 20000 报文 | ✅ 完全一致 |
| `req_pattern`（mini-language 解析+匹配） | C matcher vs Rust，逐答案 diff | 5 种子 × 4000 查询 | ✅ 完全一致 |
| `req_pattern` 方向判定（整包 `extract_ipport`，含堆叠 VLAN/QinQ） | C `req_pattern_judge_pkt_direction` vs Rust `judge_pkt_direction`，逐帧 diff | 多种子 × 2000 帧（单/双/三层 0x8100、IPv4·IPv6·TCP·UDP、截断、非 IP） | ✅ 完全一致 |
| `config`（JSON 解析 + bpf 排除主机） | C parser vs Rust，规范化输出 diff | 5 种子 × 2500 配置 | ✅ 完全一致 |
| **协议：GRE/VXLAN/ZMQ batch 线格式** | C 真实输出代码（`--wrap=sendto/zmq_send` 拦截）vs Rust | 8 种子 × 150 用例（每用例最多 400 包，含分片/翻页/flush 边界/VLAN/MPLS） | ✅ 逐字节一致 |
| **协议：Unix JSON-RPC** | 真实 C `unix-manager.c` 服务器 vs Rust 服务器，真实 socket | 17 个用例（握手/命令/错误/超时） | ✅ 一致（JSON 归一化后） |

复现：`parity/all.sh`（10 项，含 `verify_liveness.sh`（§3.1）、`verify_hygiene.sh`（§3/§3.2/§3.4）与
`verify_hygiene_reverse.sh`（P2-3：把四条防复发门禁的**等价改写违例**重新注入一份临时副本，要求它们
仍然变红）三个防复发门禁；也可单独跑 `run.sh`、`verify_config.sh`、`verify_req.sh`、`fuzz_proto.sh`、
`fuzz_rpc.sh`）。

### 2.1 协议 fuzz 方法

* **GRE / VXLAN / ZMQ**：链接**未修改的** `output_*.c`，用 linker `--wrap=sendto` 与
  `--wrap=zmq_send` 拦截真实发送，捕获即将上线的字节；Rust 侧把封装逻辑提为唯一实现
  （`gre_header`、`vxlan_encapsulate`、`BatchBuilder`）后对拍。无需 root、无需网络。
* **Unix RPC**：同时启动 C 与 Rust 服务器，Python 客户端发送相同握手/命令序列，
  对返回 JSON 做字段归一化（时间戳/pid/uptime/version）后比较，并比较连接是否被关闭。

**对拍发现的真实不一致（均已修复）：**
1. TCP/UDP 伪首部校验和：Rust 用 big-endian 累加，C 用 native-endian + `htons()`。
2. 空 `tasks:[]`：C 接受，Rust 曾报错。
3. 显式 `null` 字段：C 一律报错，serde 把 null 当缺省。
4. `req_pattern` 显式 `"none"`：C 拒绝（只接受 auto/custom）。
5. `log_level` 的 `TRACE`：C 不接受。
6. 重复 fingerprint：C 报错，Rust 曾漏检。
7. **Unix RPC 空行/无换行命令**：C 视为不完整命令并断开；Rust 曾跳过或直接执行。已改为
   要求换行 + 1.5s 超时断开，与 C 一致。

## 2.2 有意的安全分歧（C 的未定义行为）

对拍还暴露了原 C 代码的内存安全问题。Rust 端口选择**安全行为**而非复刻 UB：

1. **ZMQ VLAN 遍历越界写**（`output_zmq.c`）：VLAN 遍历的边界用 `caplen + 4`（把合成的
   MPLS 区当成 VLAN 标签），当 `slice` 截断 VLAN 帧时会算出 `vlan_total_size > length-18`，
   使 `payload_copy_len` 下溢为约 2^64，触发越界 `memcpy`（可破坏 batch 头/堆）。Rust 在
   `BatchBuilder::append_packet` 中检测该条件并丢弃该包。
2. **ZMQ VLAN 遍历越界读**：同一遍历在数据不足时读取 `caplen` 之后的 4 字节。Rust 增加了
   `pkt_data.len()` 边界保护。
3. **`req_pattern` 超长表达式的递归深度**：C 的 `req_pattern.c` 与 Rust 端口都是递归下降
   解析器（`parse_expression → parse_term → parse_factor → parse_expression`），且 AST 的求值/
   析构也递归。数千层嵌套 `(` 或数千个 `and`/`or` 会耗尽栈。Rust 现在在
   `parse_pattern` 以 `MAX_PATTERN_LEN = 512` 拒绝（`INIT_FAIL`，不会崩溃），C 侧的同一边界
   写在 `parity/c_req_pattern.c`；真实 pattern 只有几十字节，C 的深递归本就是 UB（它只是
   栈帧更小、撑得久一点）。由 `parity/difffuzz.sh req_pattern` 发现（ASan 在 ~3300 层嵌套处
   报 stack-overflow），两侧现在返回相同的 accept/reject。
4. **IPv4 IHL / TCP data offset 最小长度校验**（`packet_split.c` ↔ `packet.rs`）：Rust 端口
   原本就额外要求两者至少 20 字节，会拒绝 C 曾经接受的畸形头部（IHL=1、TCP data offset=0）。
   上游 #282 现已同样拒绝，**分歧已收敛**；Rust 只是更早做了这项硬化。

以上输入在生成器中已规避，或由双方同一边界拒绝，以保证差分对拍比较的是**有定义的行为**；
其余全部输入逐字节一致。

**堆叠 VLAN（QinQ）与 VLAN 标签类型集合**：上游 `87cbaf6` 让 `req_pattern.c` 的
`extract_ipport_from_vlan_layer` 在标签内 EtherType 仍是 VLAN 时递归，Rust 端口以等价的
循环实现同一深层下降（`packet.rs::extract_ipport`，每层都做 `caplen` 边界检查）。差异在于
标签类型集合：C 的 req-pattern 匹配器只认 `ETHERTYPE_VLAN`（0x8100），而 Rust 端口（与
`packet_split.c`/`parse_packet` 一致）在**每一层**都接受 0x8100 / 0x88a8 / 0x9100 /
0x9200。因此在 0x88a8 等外层标签上 Rust 会判定方向、C 返回 `PKT_DIR_UNKNOWN`——这是
Rust 更宽的、有意保留的接受面；`parity/gen_req_judge.py` 只在双方都有定义的 0x8100
堆叠域内生成向量，四种标签的深层下降由 Rust 单元测试（
`extract_ipport_{two,three}_level_qinq_*`、`extract_ipport_qinq_rejects_a_truncated_layer`）固定。

> **上游 #281 / #282 的记忆安全同步**：#281 的 `bpf_filter_replace_nic` 堆溢出在 Rust 里
> 不存在（`String` 增长无越界），但**语义**已同步——`nic.` 只在行首或定界符（空白、`(`、`)`）
> 之后开始、在下一个定界符结束，名字为空或长度 ≥ `IF_NAMESIZE` 报错，因此 `panic.example.com`
> 不再被误认，`(host nic.eth0)` 也能正确替换。#282 同步了 `parse_packet` 对 IPv4 分片
> （MF 或 offset ≠ 0）的拒绝（不分片，原样发送）、`build_fragment` 在 UDP 校验和算得 0 时
> 发送 `0xFFFF`（RFC 768），以及 IPv6 扩展头循环去重；`parity/run.sh` 与 `parity/verify_bpf.sh`
> 对新 tip 全绿。

> **由差分 fuzzing 发现并修复（同一处两次）**：`req_pattern` 的端口解析先是补齐了 C 的
> `strtol(..., 10)` 语义（接受 `-0`、`+80`）；上游随后把规则收紧为**纯十进制**
> （`req_pattern.c` 的 `plain_decimal` 守卫，因为 BPF 把 `010` 当八进制），Rust 未同步，
> 差分 fuzzer 立刻以 `port-0` 报出（C `INIT_FAIL` / Rust `0`）。现在两侧一致：端口必须是
> `0`–`65535` 的纯十进制，`-0`/`+80`/`010`/`00` 等一律 `INIT_FAIL`。见
> `parity/difffuzz.sh req_pattern` 与 `req_pattern.rs::tests::port_parsing_requires_plain_decimal`。
> 注意 CI 的 C oracle 按上游浮动分支 `0.9.x` 现场编译，因此上游收紧一次规则，这里就会
> 由 fuzz job 报红一次。

## 2.3 已知的良性分歧

* **重复 JSON key**（如 `{"command":"a","command":"b"}`）：cJSON 取**首个**，serde_json 取
  **末个**。属无效/歧义 JSON，实际客户端不会产生，未复刻。
* **JSON 解码宽容度**（差分 fuzzer 发现）：
  * cJSON 忽略首个 JSON 值之后的尾部垃圾（`{...},`），serde 拒绝——属非法 JSON。
  * 非法 `\uXXXX` 转义：cJSON 宽容接受，serde 拒绝。
  * **超长数字 token**（≥ 64 字节，如 70 位整数）：cJSON 把数字复制进
    `char number_c_string[64]`，整体报 JSON 解析错误；serde_json 接受（回退为 `f64`）。
    实测 63 位可解析、64 位报错（`PARITY.md` 记录于本次差分 fuzz 发现）。
    差分 fuzzer 的 `config` 模式据此收紧合法 JSON 闸门（`number_tokens_fit_cjson`），
    使比较仍聚焦于语义层。
  * Go `encoding/json` **大小写不敏感**匹配字段（`snAplen` → `snaplen`）且对缺失字段
    零值填充（缺 `outputs`/`capturer` 不报错）；serde 大小写敏感且要求必填字段。
  以上均仅在**非法/含糊 JSON**上分歧，且 `TaskConfig` 的直接 JSON 解码不是生产输入路径
  （Rust 侧由代码构造）。差分 fuzzer 对 `config` 模式只喂**合法 JSON**（按 cJSON 的词法
  严格度，见上条数字长度限制）、对
  `task_fingerprint` 用固定字段名模板并分类单侧 `PARSE_FAIL`，以聚焦语义层差异。

## 2.4 输出面与生命周期的有意分歧（AUDIT4 M3：P5-04 / P5-10 / P5-11）

ZMQ 输出用纯 Rust ZMTP 客户端替代 libzmq，因此"C 的行为"= **libzmq 的行为**。下表逐项
说明 Rust 侧在何处**刻意不同**（其余保持逐字节一致的 wire 格式，见 `parity/verify_zmtp.sh`）：

| 行为 | C（libzmq） | Rust（`zmtp/`、`output/zmq.rs`） | 性质 |
|---|---|---|---|
| 退出/reload 排空在途批次 | `zmq_close` + `ZMQ_LINGER=5s` 尽量发完 | `TaskManager::stop()` 是 `Output::destroy()` 的**唯一调用点**：先 join 输出线程，再把所有 `Box<dyn Output>` 从共享集合中取出并逐个 `destroy()`（ZMQ：`drain_for(5s)`；pcap：显式 `flush()` 并上报错误）。`reload()` 也经过 `stop()` | 语义与 C 一致（此前 `destroy()` **无任何调用方**，reload/退出会静默丢弃最多 hwm×1 MiB 已入队批次，属回归，已修复） |
| ZMTP 握手超时 | 默认无限（仅受 OS connect 超时约束） | 每条连接 10s deadline（`DEFAULT_HANDSHAKE_TIMEOUT`，可 `with_handshake_timeout` 覆盖），超时即断开重连并计数 `handshakes_given_up()` | **有意增强**：对端只接受 TCP 却不发 greeting 时不再永久停在握手相位 |
| TCP keepalive / `TCP_USER_TIMEOUT` | keepalive 默认关闭 | 建 socket 时即设 `SO_KEEPALIVE`（idle 15s / interval 5s / 3 次探测）+ `TCP_USER_TIMEOUT=30s`；OS 拒绝时一次性告警 | **有意增强**：黑洞/NAT 老化导致的静默死链会在 ~30s 内被发现 |
| 重连时重新解析 DNS | 每次 connect 重新 `getaddrinfo` | 与 libzmq 对齐：每次重连重新解析（`RESOLVE_TTL=1s` 限速），并**轮转全部**解析结果；解析暂时失败时沿用上一次结果 | 修复原实现"只解析一次、只取首个地址"的偏差（多 A/AAAA 记录、collector 换 IP 场景） |
| 写缓冲相位 | libzmq 内部单一 pipe | 握手字节（greeting/READY/PONG）一律**追加**到 `Conn::out` FIFO；业务帧只有在 FIFO 空时才允许写（`can_write_messages()`）。`debug_assert` + 单测 + fuzz 不变式覆盖 | 协议正确性硬化：短写（`EAGAIN`）时不得覆盖未写尾部或与业务帧交错导致线序错位 |
| `zmq.hwm` 取值 | 任意 `int`；**0 表示无限队列** | 配置期校验 `1..=4096`，越界**报错**（消息含字段名与"每批次 ≤1 MiB"换算） | **有意分歧**：hwm 直接决定队列内存上限，不再接受隐式的无限队列 |
| 待发队列上限 | 仅按消息数（hwm） | 双重上限：`hwm` 条 **且** `min(hwm × 1 MiB, 64 MiB)` 字节（`DEFAULT_MAX_QUEUED_BYTES`）；超限按 libzmq `EAGAIN` 语义丢弃并计入 `error_drop_*` | **有意分歧**：慢/失联 collector 不能把 RSS 撑到 OOM（被 OOM killer 杀掉的是采集进程本身） |
| `fwd_bytes` / `fwd_packets` 口径 | `zmq_send(ZMQ_DONTWAIT)` 返回 0（=进入 libzmq pipe）即计数 | **保持不变**：批次被 transport 接收即计数 | 与 C 一致（不静默改变对外数字）。积压与丢弃改由新指标观测：`output.zmtp_queued_batches` / `output.zmtp_queued_bytes`（gauge，见 `collect_stats_summary` 与 `cpctl stats`）+ `error_drop_*` |

## 2.5 配置与输入校验的有意分歧（AUDIT4 M4：P5-15 / P5-20 / P5-21 / P5-22）

M4 的问题大多不是"移植错了"，而是"移植得比原实现更宽松、更沉默"。下面每一项都**用 oracle
实测确认了原实现的行为**（C harness / 系统 libpcap 1.10 探针），分歧处按上表说明：

> **配置数值越界已收敛（上游 #279，2026-09-30）**：本题曾列为"有意分歧（更严）"——Rust 报错、
> C 钳位后继续跑。上游 `0.9.x` 的 #279 把数值校验统一为"归一化 / 钳位 + 明确拒绝非法值"，
> Rust 已 1:1 移植：`libpcap.snaplen` 越界归一化到 262144（`<=0` 也等价最大值、打 info 日志）、
> `dpdk_pdump.snaplen` `<=0` 报错、越界归一化，`libpcap.buffer_size_mb` `>2047` 归一化、`<=0`
> 报错，`timeout_ms`/`slice`/`rate_limit_mbps`/`hwm`/`max_file_interval` 负值报错、超过
> `INT_MAX` 钳位，端口类字段拒绝 `[1,65535]` 之外，`service_tag`/`vni2` 保留完整值并告警、
> `vni1` 超过 24 位时按 oracle 掩码到低 24 位（`value &= 0xFFFFFF`），
> `pipeline.buffer_size_mb` 在 pipeline 模型下必填且上界为 `SIZE_MAX/1MiB`；且**所有整数字段都
> 接受整值浮点**（`2048.0`、`1e3`，与 cJSON 的 `floor(v)==v` 一致）。对拍由
> `parity/verify_config.sh` 的 46 条边界向量（C/Rust 逐字节比较）与 5000 条随机配置覆盖。

| 项 | C / libpcap 实测行为 | Rust 行为 | 性质 |
|---|---|---|---|
| pcap 文件 linktype 非 EN10MB（`tcpdump -i any` 的 DLT_LINUX_SLL 113 / SLL2 276、DLT_NULL、DLT_RAW、radiotap） | `pcap_open_offline` **照常打开**（实测 `datalink=113` 成功），`pcap_compile` 按该 DLT 编译，`pcap_next_ex` 正常返回记录 | **明确拒绝**：`unsupported pcap linktype 113: only Ethernet (DLT_EN10MB = 1) can be replayed; produced by tcpdump -i any; re-capture on a single interface` | **有意分歧**：本项目 BPF 后端只实现 Ethernet 布局，把 SLL 帧按 Ethernet 解析会让每一帧错位 4 字节后转发进 GRE/VXLAN/ZMQ —— 静默的数据破坏，宁缺勿错 |
| pcap 记录 `caplen > orig_len` | libpcap **不校验**：实测返回 `caplen=20 origlen=10` 并交出 20 字节 | **报错** `caplen 20 exceeds orig_len 10 (corrupt file)`，该记录不进入输出 | **有意分歧**：真实抓包不可能出现该组合，出现即文件损坏 |
| pcap `version_major > 2` | libpcap 拒绝：`unsupported pcap savefile version 3.4` | 同样拒绝并打印版本号 | **一致**（对齐 libpcap） |
| BPF 编译期的主机名解析（`host <name>` / `net <name>`） | `pcap_compile()` 每次都同步调用 `getaddrinfo()`：DNS 不可达时一次 reload 就阻塞数十秒；移植后的 Rust 同样同步，**且**发生在 `TaskManager::reload()` 持 mgr 锁期间 → 抓包循环（同一把锁）与 `cpctl stats` 一起冻结，而 `drop_packets` 一直是 0 | ① 结果进程内缓存 `DEFAULT_TTL=60s`（`bpf::CachedResolver`，≤512 个名字，失败不入表）→ 配置未变的重载**一次解析都不做**；② `task::prepare_reload()` 把"读文件+解析+解析名字"与"换装 task"分开，`reload_config` RPC 只在换装时取锁；③ SIGHUP 更进一步放到 `task::ReloadWorker` 的专用线程（它的信号标志正是抓包循环自己消费的，循环只轮询 `is_done()`，永不阻塞） | **有意分歧（更有界）**：代价是 collector 换 IP 后最多 60s 内，自动排除过滤器可能仍用旧地址。`netns` task 不在锁外预热（命名空间内答案可能不同），仍走构建期解析。**刻意不做**"每次解析起一个线程 + 超时放弃"：libFuzzer 实测把它判为 CRASH（detached 线程在进程退出时仍持有 glibc 解析缓冲 → LeakSanitizer 报 leak-592aa5…，且 exec/s 归零），那等于把一次阻塞换成无界线程数 |
| 单条记录 caplen 上限 | 受文件实际长度约束 | `MAX_CAPLEN = 262144`（libpcap 自身的最大 snaplen），超限按损坏处理；另有 `const _ = assert!` 编译期约束 | **有意收敛**：原上限 256 MiB，一条畸形记录就能让 reader 一次 `resize` 预留 256 MB 并长期持有（进程基线 RSS 仅 6.5 MB） |
| `nic.<ifname>` 过滤器替换（`bpf_filter_replace_nic`） | C 按 `char *` 逐字节处理，UTF-8 序列**原样透传** | 曾用 `bytes[i] as char` 逐字节重编码，非 ASCII 过滤器被改成 Latin-1 乱码；现按**字节切片复制**，非 ASCII 空白（U+3000）也能正确结束接口名 | **修复回归**（现在与 C 一致） |
| `PcapWriter::flush()` | libpcap `pcap_dump_flush()` 就是 `fflush`：到 OS，不 fsync | 行为**不变**；文档改为如实描述（flush 后字节已到 OS、可被其他读者看到；不保证掉电持久） | **文档修复**：原注释"call flush to fsync"是空头承诺，现在有 grep 门禁 |
| `cpdaemon` HTTP 端口解析 | Go 把端口字符串直接交给 `net.Listen` / `http.Server.Addr`，端口非法 → **启动失败** | 原来 `parse::<u16>().unwrap_or(9022)` 静默换端口；现返回错误并指明键名与合法范围；空值仍表示默认 9022 | **修复回归**（现在与 Go 一致）。同时接受不带引号的 `"port": 9022`：viper 默认值就是数字、官方 template.json 也这么写，serde 原本会直接拒绝该配置文件 |

差分向量分配：`parity/gen_config.py` 产生范围内的随机数值；越界与整值浮点等 46 条边界向量固化在
`parity/verify_config.sh` 的 "#279" 段，**直接比较 C 与 Rust 的规范化输出**（不再是"断言 Rust 拒绝"）。

## 2.6 采集错误路径、down 接口与空转的有意分歧（AUDIT4 P5-12 / 复核 P2-6）

C 走 libpcap 的 `pcap_activate()`，Rust 走裸 `AF_PACKET` 的 `socket()+bind()`，两者对"接口存在但没
UP"的反应**不是一回事**。独占 veth 对（`p2spin0/p2spin1`，实验后已删除）、debug 构建、6 秒窗口内取
`/proc/<pid>/stat` 的 utime+stime、`timeout_ms` 取仓库默认 **0**：

| 场景 | 修复前 | 修复后 | 说明 |
|---|---|---|---|
| 4 个 task，抓包口 down | **30.2%** 单核 | **3.2%** 单核 | 每 task 约 3.6% 的空转被消除，且不再随 task 数线性放大 |
| 4 个 task，口 UP 但无流量 | 30.3% | 3.2% | 同上：空转主体是"读不到包就立刻返回"的紧循环 |
| 1 个 task，口 down | 18.5–22.0% | 3.8–4.3% | |
| 0 个 task（进程基线） | 15.8% | 15.3% | **未改**：主循环 `num_pkts==0 → sleep(10µs)` 自身的开销；C 同样有（审查实测 C 侧 0 task 时 13.2%），属既有平价而非回归 |
| 采集保真度（lo，10 万 UDP 报文，`timeout_ms=0`） | records/sent = 1.0000 | 1.0000（caplen 直方图单一、无尾部残帧） | 1ms 空闲等待不引入丢包/延迟：`poll` 在帧入队的那一刻就醒 |

行为差异与做法：

* **task 存活 vs 创建失败**：C 的 `pcap_activate` 在 down 口上失败 → **task 创建失败**（worker 以 0 个
  task 继续）；Rust 的 `socket()+bind()` 在 down 口上成功，task **存活**并持续失败（按 2s 窗口打一条错误
  日志）。保留 Rust 语义（接口随后 UP 即可立刻恢复采集，不必重载配置），代价是必须自带退避。
* **`Err` 分支退避**（P5-12 验收原文）：`ErrorBackoff` 1ms 起、倍增、100ms 封顶，任何一次成功的 socket
  操作（含 `EAGAIN`）立即复位；实测硬错误风暴（例如拔卡式 `ENODEV`）下 CPU 由紧循环降到 ~0。
* **`timeout_ms = 0` 的空闲等待**（新发现，实测才是这里的主体）：接口 down 时内核只在"链路断开瞬间还有
  排队帧"的那一次返回 `ENETDOWN`，之后一律 `EAGAIN`，因此单靠 `Err` 退避**并不能**满足"CPU 不空转"。
  现在空读之后最多 `poll(POLLIN, 1ms)`；这只在"刚读空"时进入，流量持续时永不进入，故对吞吐与延迟无影响
  （上表保真度行即为此断言的证据），心跳频率由 ~10 万次/s 降到 ~1 千次/s（`Output::heartbeat(now)` 以**秒**
  为参数，无精度损失）。
* **不把 recvmsg 硬错误计入 `error_drop_*`**：`error_drop_*` 在 C 里是**输出侧**计数
  （`output->base.stats`，见 `output_gre.c:114`、`output_rotating_file.c:103`），采集侧 schema 只有
  `cap_bytes`/`cap_packets`/`drop_packets`/`ifdrop_packets`；把"读失败"记成"丢包"会破坏 §2.4 已声明的对外
  口径并让运维把观测错误当成本征损失。原计划 P5-12 的这句话已按 C 的 schema 在 `IMPROVEMENT_PLAN_AUDIT4.md`
  中改写并说明理由。
* **netns 恢复失败 → 终止 worker（上游 #285）**：进入目标 netns 抓包前会先保存当前线程的
  netns fd；抓包器创建结束后必须切回原 netns。旧实现恢复失败时只 `log_error!` 后继续，调用线程
  （即抓包 worker）会**停留在目标 netns 里**：其后所有依赖“原命名空间”的操作（重新打开接口、
  其它 task、诊断路径）都会在错误的名字空间里静默执行。上游 #285 把该失败提升为不可忽略的错误；
  Rust 侧现在把它并入 `AfPacketCapturer::new` 的返回：`Ok` 的抓包器被丢弃（RAII 关闭 fd），
  worker 按既有的“创建失败”路径终止。代价是偶发的 `setns` 失败会让该次 task 创建失败并等待重载，
  而不是带病继续；收益是不再存在“worker 在错误命名空间继续跑”的静默错误。

`drop_packets` 仍只来自 `getsockopt(PACKET_STATISTICS)` 的 `tp_drops`（§4 采集面语义），退避与空闲等待不改变
任何计数口径。

## 2.7 CPM 客户端 TLS 校验的有意分歧（上游 #232）

上游 `cpdaemon/cmd/internal/asm/provider.go` 无条件构造
`tls.Config{InsecureSkipVerify: true}`，且没有任何配置开关（上游 issue #232）。
Go 版因此**永远不校验 CPM 的服务端证书**：能对 CPM 通道做中间人的一方可以用任意自签证书
冒充 CPM，返回的 JSON 会驱动探针建任务、下发 BPF/转发主机/输出目标。

Rust 移植**有意偏离**该行为，改为安全默认：

| 项 | Go oracle | Rust（本仓库） | 性质 |
|---|---|---|---|
| CPM 服务端证书校验 | 硬编码 `InsecureSkipVerify: true`，无开关 | **默认校验**；`cpm.client.tls.insecure_skip_verify: true` 才显式关闭（映射到 reqwest `danger_accept_invalid_certs`） | **有意分歧（安全修复）**：默认即安全；需要连接不受信证书的测试/遗留环境可显式降级 |
| mTLS 客户端证书（PKCS#12） | 配置了 `cpm.client.tls.pkcs12_cert_file` 时用 PKCS#12 做客户端证书（`provider.go:116`） | 键仍可解析但**尚未接线**（reqwest/rustls 无内建 PKCS#12 解码器），列为独立后续 `cloud-probe-rs-ryg.2` | 未移植项（见 §5.1） |

行为由 `crates/cpdaemon/tests/cpm_tls_verify.rs` 用**真实自签 TLS 服务端**固定：默认客户端
握手失败（服务端未完成握手），`insecure_skip_verify = true` 时同一请求成功。

## 3. 关键一致性向量（已通过）

* `workerTaskBuilder` 产出的 task fingerprint（含 Go 反射标签算法的怪异 `UUID()`
  行为）：`64393037-6336-6262-3137-333739363234` 等，与 Go 测试逐字一致。
* `Vni2Tag.Encode`：`23,1,6,0 → 6040`；`3568,0,9,0 → 913444`。
* `parseStartup`：pflag 短/长/`=`/未知标志各形态。
* `decodeContainerId`：含 `docker://`、`containerd://`、多 NIC。
* `cpu_set_parse`：C 的全部边界用例（`,`、`1,`、`1-,2`、`3-1`、`""`…）。

## 4. "纯 Rust" 现状（已完成）

**`cargo build` / `cargo test` 不再链接任何 C 库。**

| 原 C 依赖 | 替代 |
|---|---|
| **libpcap**（实时抓包） | ✅ 裸 `AF_PACKET`（`capturer/af_packet.rs`）：`SOCK_RAW` + `SO_RCVBUF`/`SO_RCVBUFFORCE`（回读+告警）+ `SO_TIMESTAMPNS` + `PACKET_AUXDATA`（VLAN）+ `PACKET_STATISTICS`；**先挂 BPF 再 bind** |
| **libpcap**（BPF 编译/挂载） | ✅ 自研 tcpdump 子集编译器（`bpf/`），Linux 用 `SO_ATTACH_FILTER` |
| **libpcap**（pcap 文件读/写） | ✅ 纯 Rust（`capturer/pcap_file.rs`、`output/pcap_writer.rs`）；reader 泛化到 `impl Read`，畸形输入可在无文件系统的条件下 fuzz/单测 |
| **libzmq**（ZMQ 输出） | ✅ 纯 Rust ZMTP 3.x `PUSH`（`zmtp/`）|
| libc / nix（syscall 绑定） | 保留（不是任务 C 代码）|

采集面语义（AUDIT4 P5-02/03/05/09）：

* **丢包统计**：`getsockopt(PACKET_STATISTICS)` 是**读后清零**，每个样本是"自上次读取以来的增量"，
  直接累加；首次读取作基线。`ps_ifdrop` 在 Linux 恒为 0（与 libpcap 一致）。
* **VLAN**：启用 `PACKET_AUXDATA`，内核剥离标签后由 `TP_STATUS_VLAN_VALID`/`tp_vlan_tci`
  在 MAC 后重插 4 字节 802.1Q 头（TPID 取 `tp_vlan_tpid`，缺省 0x8100）。重插的 4 字节
  **计入 `snaplen`**（与 libpcap 一致）：被截断到 `snaplen` 的帧重插后仍报告 `caplen == snaplen`，
  被 tag 推过上限的尾部字节不报告；`orig_len` 仍是线上长度（含 tag，+4）。
  （AUDIT4 P2-7 回归：修复前 `snaplen:16` + 802.1Q 会报告 `caplen == 20`，而 `tcpdump -s 16`
  在同一批帧上报告 16，违反「每包 ≤ snaplen」的配置契约，并使抓包文件与 C 版不可比。）
* **loopback 重复帧**：仅对 loopback 接口设 `PACKET_IGNORE_OUTGOING`（否则用户态按
  `PACKET_OUTGOING` 丢弃），与 libpcap 一致；非 loopback 不丢出站。
* **接收缓冲**：优先 `SO_RCVBUFFORCE`（需 `CAP_NET_ADMIN`），失败回退 `SO_RCVBUF`，
  并用 `getsockopt` 回读实际值，被 `net.core.rmem_max` 截断时告警。
* **启动无空窗**：socket 以协议 0 创建 → 挂 BPF → 再 `bind(ETH_P_ALL, ifindex)`，
  避免 bind/挂过滤器之前收到未过滤流量。
* **编译期名字解析不阻塞抓包**（AUDIT4 P2-10）：`bpf::CachedResolver` 给 `parse()` 加进程内 60s
  结果缓存（≤512 个名字；解析失败不入表，所以一次抖动不会把某个名字"毒化"整个 TTL）；reload 的准备
  阶段（读文件/解析/解析名字）与换装分离，`reload_config` 只在换装时取锁，SIGHUP 则整段放到
  `task::ReloadWorker` 的专用线程上（抓包循环只轮询 `is_done()`）；与 ZMTP 侧的 `BackgroundResolver`
  （下文 ZMTP 一节）配对，覆盖"DNS 挂了就把 worker 冻住"的两条路径。
* **过滤器回退**：内核 `SO_ATTACH_FILTER` 有 4096 条指令上限（`BPF_MAXINSNS`），
  且受 `net.core.optmem_max` 限制（超限返回 `ENOMEM`/`EINVAL`）。挂载失败或程序过长时，
  capturer **回退到用户态过滤**（用同一编译结果在收到帧后判定，丢弃不匹配帧），与 libpcap 一致，
  且用户态过滤在 VLAN 标签重插**之前**执行，保持与内核过滤相同的匹配语义。
  该回退对所有已发布计数器是**不可见的**（`drop_packets` 仍为 0，只是每帧多跑 N 条指令），
  因此回退时打印带稳定告警字段的一行 `bpf_userspace_fallback insns=N limit=4096 kernel=BPF_MAXINSNS`
  （AUDIT4 P2-9：需要有“每包指令数”可告警，而不是静默退化）。

### pcap 文件读取（AUDIT4 P5-20）

`capturer/pcap_file.rs` 的 `PcapReader<R: Read>` 是**校验型**读取器，四条硬规则：

* magic 必须是四种已知变体（LE/BE × µs/ns）之一；
* `version_major <= 2`（与 libpcap 实测行为一致）；
* `linktype` 必须是 `DLT_EN10MB`，否则报错并提示常见来源（`tcpdump -i any` 的 SLL/SLL2）；
* 每条记录满足 `caplen <= orig_len` 且 `caplen <= MAX_CAPLEN = 262144`。

记录字段只在全部检查通过后发布（被拒绝的记录不会覆盖上一次结果）；截断只意味着 EOF，
绝不会交出"长度说谎"的包；文件损坏时 `log_error!` 一次并停止回放，不再把 payload 当报文继续转发。
解析与"源如何分块"无关：单测与 `pcap_reader` fuzz target 都会再用 1 字节 `BufReader` 跑一遍并要求
逐记录一致——这正是 `read_exact` 失步教训的固化（IMPROVEMENT_PLAN_AUDIT4 §3.4）。

### 崩溃面与 `panic = "abort"`（AUDIT4 P5-23）

release profile 用 `panic = "abort"`：**panic 是致命事件，不是可恢复错误**——一个线程里的 panic 会带走
整个 worker 及其所有 task。边界因此这样划：

* 凡由**输入**决定的失败一律是 `Result` 或提前返回：配置 JSON、CPM 任务下发、SIGHUP 重载、BPF 表达式、
  pcap 文件、ZMTP 对端字节、报文帧；
* panic 只留给**程序自身的不变量违例**，用 `debug_assert!` 表达（写缓冲单一 FIFO 相位、ring buffer 记账），
  测试/debug 会炸、release 编译掉；
* 原先那几处"可证不可达"的 `expect`/`unwrap`（`bpf::or_all`、`zmtp::flush_pending`、`rotating_file`
  的时间戳、`packet.rs` 的定长切片）已全部消除——"可证"依赖调用点纪律，纪律会随改动流失，而 abort 不可恢复；
* `cargo test` 走 `test` profile（`panic = unwind`），`#[should_panic]` 与断言报告不受影响；
* 回归网：`parity/verify_hygiene.sh` 直接 grep 掉 cpworker 库代码（对拍工具已移入 `cpworker-parity`，不在扫描范围）中的 panic
  构造——这是 clippy 与单测都看不见的盲区。

### BPF 子集（`crates/cpworker/src/bpf/`）

* **支持**：`host`/`net`/`port`/`portrange`/`ether host`；`src`/`dst`（含 `tcp dst port 80`、
  `udp src port 53`、`ip src host X`、`ether src host MAC`）；
  `ip`/`ip6`/`arp`/`rarp`/`tcp`/`udp`/`icmp`/`icmp6`；`ip proto N`/`ip6 proto N`；
  `and`/`or`/`not`/括号。
* **语义对齐 tcpdump**：IPv6 分片头 `0x2c`、IPv4 分片偏移、bare `port` 含 SCTP、`net` 掩码；
  `host <name>` **与 `net <name>`** 解析出多个 A/AAAA 时按 **OR 展开全部地址**（不以首个为准；
  AUDIT4 P2-8 补齐 `net`，此前 P5-08 只做了 `host`，多宿主主机名仍会漏排除）。
  选择“展开全部”而不是“拒绝主机名”的理由：`net <name>` 现在可用，拒绝会让今天能工作的过滤器
  变成 task 创建失败；展开规模由下面的解析上限约束。同一网络内的多个答案去重为一个叶子。
* **限制**：表达式 ≤ 8 KiB、嵌套 ≤ 256、节点 ≤ 4096；超限**明确报错**（不会栈溢出）。
  单个主机名的**解析结果数量 ≤ 64**（`MAX_RESOLVED_ADDRS`）：超过则**报错并给出主机名与两个数量**，
  而不是静默生成一个超出内核 4096 条指令上限、只能在用户态逐帧解释的程序（AUDIT4 P2-9）。
* **`net ... mask` 的掩码必须是数字地址**，不做主机名解析（掩码是位模式，解析出的“第一个答案”必然语义错误）。
* **长跳转**：条件跳转仅 255 指令距离，超出时由 `JA` 跳转中继（jump-around，32 位 k）
  自动处理，因此 `not host` 长链 / 多项 `port`/`host` 或链不再受此限制。
* **不支持（明确报错）**：`vlan`/`mpls`/`pppoes`、`greater`/`less`/`len`、`protochain`、算术、
  原始偏移（`byte`/`ether proto` 之外的偏移）、以及方向作用于 proto 之前的写法（`src tcp`）。
* **对拍**：`parity/verify_bpf.sh` 用 libpcap `pcap_offline_filter` 在同一批随机
  表达式/报文上逐包比较决策（`parity/c_bpf.c` + `bpf_eval`），生成器包含长链/方向语法用例。

### ZMTP（`crates/cpworker/src/zmtp/`）

* `codec.rs`：ZMTP 3.x greeting / `READY` / 帧编解码（纯函数）。
* `client.rs`：非阻塞 `PUSH` 状态机（非阻塞 connect、NULL 握手、HWM/字节双重上限
  排队/丢弃、自动重连退避、握手 deadline、`PING`→`PONG`、单一写 FIFO；
  transport/connector/resolver 均可注入）。
* 健壮性（AUDIT4 P5-10/11，均有回归测试）：握手 10s deadline、`SO_KEEPALIVE` +
  `TCP_USER_TIMEOUT`、重连时重新解析 DNS 并轮转全部地址、队列字节上限 64 MiB、
  `zmtp_queued_*` 指标。与 libzmq 的差异见 §2.4。
* **重连 DNS 不阻塞抓包线程**：`getaddrinfo` 在后台线程执行（`BackgroundResolver`），
  `Resolver::resolve` 立即返回缓存答案并只在过期时*请求*刷新，因此在 DNS 不可用导致
  `getaddrinfo` 阻塞数十秒时也不会卡住 `send()/poll()`（首次解析在任务装配阶段完成）。
* 对拍：`parity/verify_zmtp.sh` 用**真实 libzmq PULL** 验证 wire 逐字节一致。
* fuzz：`zmtp_wire` + `zmtp_client`；真实 TCP 集成测试（并发/断开重连）。

### Windows 延展性

编译器、pcap 文件 I/O、ZMTP 均为平台无关；平台相关代码集中在
`capturer/af_packet.rs`（`#[cfg(target_os = "linux")]`）与 `bpf/linux.rs` 的 attach。
未来 Windows 支持只需新增后端（实时抓包需 Npcap 或驱动 + 对应 attach），不影响共享代码。

> **实现差异（已知取舍）**：`AF_PACKET` 抓包用 `recvmsg` 而非 libpcap 的 TPACKET_V3
> mmap 环形缓冲，因此**高吞吐下的丢包特征可能与 libpcap 不同**；`PACKET_STATISTICS` 是
> **读后清零**，实现按“本窗口增量直接累加”处理（详见上文采集面语义）。若需要与
> libpcap 完全一致的吞吐/丢包曲线，可后续在 `af_packet.rs` 内加 mmap ring（不影响其他模块）。

> **实时抓取面的重复帧（A1，已定根因并修复）**：loopback 上内核把每个报文 tap **两次**
> （出站 `dev_queue_xmit_nit` + 入站 `__netif_receive_skb`），并把**两份都**拷进 `PACKET_RX_RING`
> （也都在 `tp_packets` 里计数，即 libpcap 的 `ps_recv`）。libpcap 在**用户态**丢弃出站那份
> （`linux_check_direction()`，`pcap-linux.c`），`PACKET_IGNORE_OUTGOING` 则在内核丢弃。因此
> tcpdump 在 lo 上交付 **1×**，而裸 `recvmsg` socket 交付 **2×**。机制由
> `crates/cpworker-parity/src/bin/tpacket_ring_probe.rs` 实测确认
> （`sudo target/debug/tpacket_ring_probe lo 3000 41267` → `ring_frames=6000 outgoing=3000 host=3000`；
> 加 `ignore_outgoing` → `3000/0/3000`）。Rust capturer 现对 **loopback 接口**设置 `PACKET_IGNORE_OUTGOING`
> （内核 <4.17 时在用户态按 `sll_pkttype==PACKET_OUTGOING` 丢弃），从而与 libpcap 一致；
> 回归测试 `live_capture_loopback_does_not_duplicate_frames`（1 万报文交付 ~1×，修复前为 2×）；
> veth 上的采集保真度硬门禁 `live_capture_veth_delivers_exactly_n_frames`（发 N 帧 ⇒ 交付恰 N）已进入
> `live-capture` CI job。**非 loopback 接口不丢出站**（libpcap 在 veth 发送侧同样能看到）。
>
> 另：M5 记录的 “C ×0.79” 不可全信——`bench/live_bench.py` 用 **Rust `cpctl`** 读 C worker 统计时
> 存在**时序竞态**（Rust 客户端把 payload 与 `\n` 分两次 write，而 C 服务端握手是单次 recv，可能漏掉 `\n`，
> 残留空行被当命令 → `Connection reset by peer`）；用 Go/源码 `cpctl` 或对齐后的时序可正常读取。
> 详见 `IMPROVEMENT_PLAN_AUDIT4.md §5-6`。

> **”纯 Rust”的定义**：不链接任何 C 库（`libc`/`nix` 仅声明 syscall ABI，保留）。
> 去 C 依赖对应改进计划 P3，**已完成**。离线 `pcap_file` 过滤也已接入纯 Rust BPF。

## 5. 剩余工作与范围决策

下面的未移植项已明确区分“**计划移植**”与“**不计划移植**”，避免范围漂移。

### 5.1 计划移植（有明确目标）

> **已完成（bead 4mv.4）**：`ring_buffer.c` 的无锁 SPSC ring 已移植。实现用原子 `head`/`tail`
> 与显式 `Acquire`/`Release` 排序（`SpscRing::split` 给出一对单生产/单消费者句柄，使得安全代码
> 不可能拿到两个生产者）；满时 `push` 返回 `Err`、容量为 `size-1`、`used` 取值方式与 C 的
> `spsc_ring_push`/`spsc_ring_pop`/`spsc_ring_used` 逐项对齐。并发正确性由 200 万条 FIFO 压测 +
> 小环穷举交错模型测试覆盖，并在 Miri（`-Zmiri-many-seeds`，数据竞争检测）下通过。
>
> **已完成（bead 4mv.5）**：cgroup v1 CPU 限额（`cpu.cfs_period_us` / `cpu.cfs_quota_us` / `tasks`）已随 v2
> 一同 port 到 `reslimit.rs`；`version=auto` 按 `cgroup.controllers` 探测 v2，否则回退 v1。Go
> `verifyProcessCgroup` 的写后校验仍未移植（不影响限额生效，只是缺一条观测日志）。

| 项 | 来源 | 现状 | 决策 / 触发条件 |
| --- | --- | --- | --- |
| DPDK capturer（`dpdk/pdump.c`） | C | 未 port，按类型返回不支持 | **计划移植**，仅在目标部署需要 `dpdk_pdump` 时实现；否则维持显式错误 |
| task reload 的 fingerprint 复用 / mailbox 协议 | `task.c` | 简化为重建全部 task | **计划移植**：行为等价但效率低；仅在 reload 抖动成为实际问题时实现 |
| `unix-manager` select 单线程语义 | `unix-manager.c` | 用“非阻塞 accept + 独立线程” | **计划移植**（可选）：当前与 C 行为对齐（1.5s 超时断开），仅在并发语义差异暴露时改 |
| 其余 C/Go 单测移植 | 上游测试 | 部分已移植 | **持续**：随功能补齐同步移植向量 |

### 5.2 不计划移植（明确排除）

| 项 | 来源 | 原因 |
|---|---|---|
| Wire-DI 依赖注入框架 | Go `cmd/internal/asm` | 编译期注入在 Rust 中无收益；`main.rs` 手工装配已等价 |
| Go `net/http/pprof` 端点 | Go `httpmix` | Go 运行时特有；Rust 侧用其他 profiling 手段 |
| 重复 JSON key 的 cJSON“取首个”语义 | cJSON | 无效/歧义输入，见 §2.3；不复刻 |
| C 的 ZMQ VLAN 越界读写 UB | `output_zmq.c` | 内存安全问题，Rust 选择安全行为并丢弃该包，见 §2.2 |

### 5.3 去 C 依赖（纯 Rust）

**已完成**（对应改进计划 P3 与 AUDIT4 整改）：实现、验收与已知取舍见 §4，与 libzmq 的输出面
差异见 §2.4。本节不再跟踪该项；本表 5.1 只保留尚未移植的模块。
