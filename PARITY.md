# 迁移一致性与覆盖报告

> 结论：**核心引擎与工具已高度完整；cpdaemon 已补齐主要模块。一致性通过差分对拍
> 与测试向量移植来证明，而非阅读代码。**
>
> "纯 Rust"（去除 libpcap/libzmq）**尚未完成**，见 §4。

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
| `output_*.c`（6） | `output/*.rs` | ✅（ZMQ 仍用 libzmq） |
| `libpcap.c` / `pcap_file.c` | `capturer/*.rs` | ⚠️ 仍链接 libpcap |
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
| `pkg/worker/reslimit*.go` | `reslimit.rs` | ⚠️ 仅 cgroup v2 CPU |
| `pkg/cgroup/*` | `reslimit.rs` | ⚠️ 无 cgroup v1 |
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
| C 单测向量（`misc.c` 等） | ✅ 33 个移植到 `cpworker/tests/port_parity.rs` |
| Go `worker_task_builder_test.go` 向量 | ✅ 10 个移植到 `cpm/task_builder.rs` |
| cpgolib / cpctl 纯函数测试 | ✅ |
| 其余 C/Go 测试文件 | ⚠️ 部分未移植 |

当前 `cargo test --workspace`：**71 个测试全部通过**（含 `cpsim` 的 11 个 DST 测试）。

### 1.4 Deterministic Simulation Testing（`crates/sim`）

`cpsim` 是单线程、种子驱动的确定性仿真框架：虚拟时钟 + ChaCha8 + 事件队列 +
可注入故障（丢包/重复/乱序/位翻转/延迟），复用 cpworker 真实封装、限速、分片代码，
collector 解码并对账。同一 seed 跨进程 trace 摘要一致，可精确复现失败。

* 测试：`cargo test -p cpsim --test dst`；复现某个 seed：`DST_SEED=7 cargo test -p cpsim --test dst`
* trace：`cargo run -p cpsim --example trace -- 7 zmq harsh`
* 详解见 `crates/sim/README.md`
* 已把上游 ZMQ VLAN 溢出（issue #231）做成回归用例 `zmq_vlan_slice_never_corrupts`。

### 1.5 覆盖率引导的 Fuzz（cargo-fuzz / libFuzzer）

`crates/cpworker/fuzz/` 下有 9 个 fuzz target（nightly + ASAN + libFuzzer）：

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
| `req_pattern` | 自定义模式匹配器 | C `c_req_pattern.c` |
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

1. `req_pattern` 对 `port -0` 的负零解析不兼容（C `strtol` 接受，Rust `u16` 拒绝）。
2. `TaskConfig` 指纹：Go 的 `CustomReqPatternConfig.Pattern` 是非指针 string（始终参与指纹，
   即使为空），Rust 曾用 `Option` 跳过——已修正并对齐 Go 向量。

差分/模糊测试（`parity/`）：

| 脚本 | 对象 |
|---|---|
| `run.sh` | packet_split（解析/分片/校验和） |
| `verify_config.sh` | config JSON 解析 + bpf 排除主机 |
| `verify_req.sh` | req_pattern 匹配器 |
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
| `config`（JSON 解析 + bpf 排除主机） | C parser vs Rust，规范化输出 diff | 5 种子 × 2500 配置 | ✅ 完全一致 |
| **协议：GRE/VXLAN/ZMQ batch 线格式** | C 真实输出代码（`--wrap=sendto/zmq_send` 拦截）vs Rust | 8 种子 × 150 用例（每用例最多 400 包，含分片/翻页/flush 边界/VLAN/MPLS） | ✅ 逐字节一致 |
| **协议：Unix JSON-RPC** | 真实 C `unix-manager.c` 服务器 vs Rust 服务器，真实 socket | 17 个用例（握手/命令/错误/超时） | ✅ 一致（JSON 归一化后） |

复现：`parity/all.sh`（或单独的 `run.sh`、`verify_config.sh`、
`verify_req.sh`、`fuzz_proto.sh`、`fuzz_rpc.sh`）。

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

对拍还暴露了原 C 代码的两个内存安全问题。Rust 端口选择**安全行为**而非复刻 UB：

1. **ZMQ VLAN 遍历越界写**（`output_zmq.c`）：VLAN 遍历的边界用 `caplen + 4`（把合成的
   MPLS 区当成 VLAN 标签），当 `slice` 截断 VLAN 帧时会算出 `vlan_total_size > length-18`，
   使 `payload_copy_len` 下溢为约 2^64，触发越界 `memcpy`（可破坏 batch 头/堆）。Rust 在
   `BatchBuilder::append_packet` 中检测该条件并丢弃该包。
2. **ZMQ VLAN 遍历越界读**：同一遍历在数据不足时读取 `caplen` 之后的 4 字节。Rust 增加了
   `pkt_data.len()` 边界保护。
3. **IPv4 IHL / TCP data offset 最小长度校验**（`packet_split.c` ↔ `packet.rs`）：C 只检查
   `caplen >= ihl*4`（不要求 `ihl >= 5`），且不要求 TCP data offset `>= 5`；Rust 额外要求
   两者至少 20 字节，因此会**拒绝** C 会接受的一类畸形头部（例如 IHL=1 或 TCP data offset=0）。
   这是 Rust 有意的输入校验硬化（避免把重叠的头部当合法分片），由差分 fuzzer
   （`parity/difffuzz.sh packet_split`）发现；其余输入逐字节一致。

以上三类输入在生成器中已规避，以保证差分对拍比较的是**有定义的行为**；其余全部输入逐字节一致。

> **由差分 fuzzing 发现并修复**：`req_pattern` 的端口解析曾用 `u16::parse`，拒绝 C 用
> `strtol` 接受的负零（`port -0` / `port -000`）；已改为 `i64` 解析 + `0..=65535` 范围校验。
> 见 `parity/difffuzz.sh req_pattern` 与 `req_pattern.rs` 的回归测试。

## 2.3 已知的良性分歧

* **重复 JSON key**（如 `{"command":"a","command":"b"}`）：cJSON 取**首个**，serde_json 取
  **末个**。属无效/歧义 JSON，实际客户端不会产生，未复刻。
* **JSON 解码宽容度**（差分 fuzzer 发现）：
  * cJSON 忽略首个 JSON 值之后的尾部垃圾（`{...},`），serde 拒绝——属非法 JSON。
  * 非法 `\uXXXX` 转义：cJSON 宽容接受，serde 拒绝。
  * Go `encoding/json` **大小写不敏感**匹配字段（`snAplen` → `snaplen`）且对缺失字段
    零值填充（缺 `outputs`/`capturer` 不报错）；serde 大小写敏感且要求必填字段。
  以上均仅在**非法/含糊 JSON**上分歧，且 `TaskConfig` 的直接 JSON 解码不是生产输入路径
  （Rust 侧由代码构造）。差分 fuzzer 对 `config` 模式只喂**合法 JSON**、对
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
| **libpcap**（pcap 文件读/写） | ✅ 纯 Rust（`capturer/pcap_file.rs`、`output/pcap_writer.rs`）|
| **libzmq**（ZMQ 输出） | ✅ 纯 Rust ZMTP 3.x `PUSH`（`zmtp/`）|
| libc / nix（syscall 绑定） | 保留（不是任务 C 代码）|

采集面语义（AUDIT4 P5-02/03/05/09）：

* **丢包统计**：`getsockopt(PACKET_STATISTICS)` 是**读后清零**，每个样本是"自上次读取以来的增量"，
  直接累加；首次读取作基线。`ps_ifdrop` 在 Linux 恒为 0（与 libpcap 一致）。
* **VLAN**：启用 `PACKET_AUXDATA`，内核剥离标签后由 `TP_STATUS_VLAN_VALID`/`tp_vlan_tci`
  在 MAC 后重插 4 字节 802.1Q 头（TPID 取 `tp_vlan_tpid`，缺省 0x8100）。
* **接收缓冲**：优先 `SO_RCVBUFFORCE`（需 `CAP_NET_ADMIN`），失败回退 `SO_RCVBUF`，
  并用 `getsockopt` 回读实际值，被 `net.core.rmem_max` 截断时告警。
* **启动无空窗**：socket 以协议 0 创建 → 挂 BPF → 再 `bind(ETH_P_ALL, ifindex)`，
  避免 bind/挂过滤器之前收到未过滤流量。

### BPF 子集（`crates/cpworker/src/bpf/`）

* **支持**：`host`/`net`/`port`/`portrange`/`ether host`；`src`/`dst`（含 `tcp dst port 80`、
  `udp src port 53`、`ip src host X`、`ether src host MAC`）；
  `ip`/`ip6`/`arp`/`rarp`/`tcp`/`udp`/`icmp`/`icmp6`；`ip proto N`/`ip6 proto N`；
  `and`/`or`/`not`/括号。
* **语义对齐 tcpdump**：IPv6 分片头 `0x2c`、IPv4 分片偏移、bare `port` 含 SCTP、`net` 掩码。
* **限制**：表达式 ≤ 8 KiB、嵌套 ≤ 256、节点 ≤ 4096；超限**明确报错**（不会栈溢出）。
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
* 对拍：`parity/verify_zmtp.sh` 用**真实 libzmq PULL** 验证 wire 逐字节一致。
* fuzz：`zmtp_wire` + `zmtp_client`；真实 TCP 集成测试（并发/断开重连）。

### Windows 延展性

编译器、pcap 文件 I/O、ZMTP 均为平台无关；平台相关代码集中在
`capturer/af_packet.rs`（`#[cfg(target_os = "linux")]`）与 `bpf/linux.rs` 的 attach。
未来 Windows 支持只需新增后端（实时抓包需 Npcap 或驱动 + 对应 attach），不影响共享代码。

> **实现差异（已知取舍）**：`AF_PACKET` 抓包用 `recvmsg` 而非 libpcap 的 TPACKET_V3
> mmap 环形缓冲，因此**高吞吐下的丢包特征可能与 libpcap 不同**；`PACKET_STATISTICS` 是
> **读后清零**，实现按"本窗口增量直接累加"处理（详见上文采集面语义）。若需要与
> libpcap 完全一致的吞吐/丢包曲线，可后续在 `af_packet.rs` 内加 mmap ring（不影响其他模块）。

> **”纯 Rust”的定义**：不链接任何 C 库（`libc`/`nix` 仅声明 syscall ABI，保留）。
> 去 C 依赖对应改进计划 P3，**已完成**。离线 `pcap_file` 过滤也已接入纯 Rust BPF。

## 5. 剩余工作与范围决策

下面的未移植项已明确区分“**计划移植**”与“**不计划移植**”，避免范围漂移。

### 5.1 计划移植（有明确目标）

| 项 | 来源 | 现状 | 决策 / 触发条件 |
|---|---|---|---|
| 去 libpcap / libzmq（纯 Rust） | §4 | 未完成 | **计划移植**（P3，最大工程项）：AF_PACKET + 纯 Rust pcap I/O + BPF 子集；纯 Rust ZMTP |
| DPDK capturer（`dpdk/pdump.c`） | C | 未 port，按类型返回不支持 | **计划移植**，仅在目标部署需要 `dpdk_pdump` 时实现；否则维持显式错误 |
| task reload 的 fingerprint 复用 / mailbox 协议 | `task.c` | 简化为重建全部 task | **计划移植**：行为等价但效率低；仅在 reload 抖动成为实际问题时实现 |
| `unix-manager` select 单线程语义 | `unix-manager.c` | 用“非阻塞 accept + 独立线程” | **计划移植**（可选）：当前与 C 行为对齐（1.5s 超时断开），仅在并发语义差异暴露时改 |
| 无锁 ring buffer | `ring_buffer.c` | 语义等价的加锁实现 | **计划移植**（可选）：仅在 P3/性能复测显示锁成为瓶颈时实现 lock-free SPSC |
| cgroup v1 支持 | Go `pkg/cgroup` | 仅 cgroup v2 CPU 限额 | **计划移植**：仅在仍需 cgroup v1 的宿主（老内核/容器）上实现 |
| 其余 C/Go 单测移植 | 上游测试 | 部分已移植 | **持续**：随功能补齐同步移植向量 |

### 5.2 不计划移植（明确排除）

| 项 | 来源 | 原因 |
|---|---|---|
| Wire-DI 依赖注入框架 | Go `cmd/internal/asm` | 编译期注入在 Rust 中无收益；`main.rs` 手工装配已等价 |
| Go `net/http/pprof` 端点 | Go `httpmix` | Go 运行时特有；Rust 侧用其他 profiling 手段 |
| 重复 JSON key 的 cJSON“取首个”语义 | cJSON | 无效/歧义输入，见 §2.3；不复刻 |
| C 的 ZMQ VLAN 越界读写 UB | `output_zmq.c` | 内存安全问题，Rust 选择安全行为并丢弃该包，见 §2.2 |

### 5.3 去 C 依赖（纯 Rust）

见 §4，对应改进计划 P3。完成后本文件 §4 状态更新为“已完成”，并从本表 5.1 移除前两行。
