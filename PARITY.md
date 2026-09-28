# 迁移一致性与覆盖报告

> 结论：**核心引擎与工具已高度完整；cpdaemon 已补齐主要模块。一致性通过差分对拍
> 与测试向量移植来证明，而非阅读代码。**
>
> “纯 Rust”（去除 libpcap/libzmq）**已完成**：`cargo build`/`cargo test` 不链接任何
> C 库，实现与取舍见 §4。

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

## 2.5 配置与输入校验的有意分歧（AUDIT4 M4：P5-15 / P5-20 / P5-21 / P5-22）

M4 的问题大多不是"移植错了"，而是"移植得比原实现更宽松、更沉默"。下面每一项都**用 oracle
实测确认了原实现的行为**（C harness / 系统 libpcap 1.10 探针），分歧处按上表说明：

| 项 | C / libpcap 实测行为 | Rust 行为 | 性质 |
|---|---|---|---|
| 配置数值越界（`snaplen` / `buffer_size_mb` / `timeout_ms` / `ring_size` / `slice` / `pipeline.buffer_size_mb` / `max_payload_size`） | cJSON 把数字**钳位**到 `INT_MIN/INT_MAX` 后接受：实测 C harness 对 `snaplen:2147483648` 输出 `snaplen=2147483647`，对 `slice:4294967296` 输出 `slice=2147483647` | **报错**并给出字段名与允许范围，如 `invalid libpcap.snaplen 2147483648: must be between 0 and 262144` | **有意分歧（更严）**：Rust 原来是 `as i32` 截断，`2147483648` 变成 `i32::MIN`，再被 `snaplen.max(1)` 变成**每包 1 字节**——任务静默抓不到任何包；`buffer_size_mb:4294967296` 变成 `SO_RCVBUF=0`。钳位后的 C 仍带着荒谬参数继续跑 |
| pcap 文件 linktype 非 EN10MB（`tcpdump -i any` 的 DLT_LINUX_SLL 113 / SLL2 276、DLT_NULL、DLT_RAW、radiotap） | `pcap_open_offline` **照常打开**（实测 `datalink=113` 成功），`pcap_compile` 按该 DLT 编译，`pcap_next_ex` 正常返回记录 | **明确拒绝**：`unsupported pcap linktype 113: only Ethernet (DLT_EN10MB = 1) can be replayed; produced by tcpdump -i any; re-capture on a single interface` | **有意分歧**：本项目 BPF 后端只实现 Ethernet 布局，把 SLL 帧按 Ethernet 解析会让每一帧错位 4 字节后转发进 GRE/VXLAN/ZMQ —— 静默的数据破坏，宁缺勿错 |
| pcap 记录 `caplen > orig_len` | libpcap **不校验**：实测返回 `caplen=20 origlen=10` 并交出 20 字节 | **报错** `caplen 20 exceeds orig_len 10 (corrupt file)`，该记录不进入输出 | **有意分歧**：真实抓包不可能出现该组合，出现即文件损坏 |
| pcap `version_major > 2` | libpcap 拒绝：`unsupported pcap savefile version 3.4` | 同样拒绝并打印版本号 | **一致**（对齐 libpcap） |
| 单条记录 caplen 上限 | 受文件实际长度约束 | `MAX_CAPLEN = 262144`（libpcap 自身的最大 snaplen），超限按损坏处理；另有 `const _ = assert!` 编译期约束 | **有意收敛**：原上限 256 MiB，一条畸形记录就能让 reader 一次 `resize` 预留 256 MB 并长期持有（进程基线 RSS 仅 6.5 MB） |
| `nic.<ifname>` 过滤器替换（`bpf_filter_replace_nic`） | C 按 `char *` 逐字节处理，UTF-8 序列**原样透传** | 曾用 `bytes[i] as char` 逐字节重编码，非 ASCII 过滤器被改成 Latin-1 乱码；现按**字节切片复制**，非 ASCII 空白（U+3000）也能正确结束接口名 | **修复回归**（现在与 C 一致） |
| `PcapWriter::flush()` | libpcap `pcap_dump_flush()` 就是 `fflush`：到 OS，不 fsync | 行为**不变**；文档改为如实描述（flush 后字节已到 OS、可被其他读者看到；不保证掉电持久） | **文档修复**：原注释"call flush to fsync"是空头承诺，现在有 grep 门禁 |
| `cpdaemon` HTTP 端口解析 | Go 把端口字符串直接交给 `net.Listen` / `http.Server.Addr`，端口非法 → **启动失败** | 原来 `parse::<u16>().unwrap_or(9022)` 静默换端口；现返回错误并指明键名与合法范围；空值仍表示默认 9022 | **修复回归**（现在与 Go 一致）。同时接受不带引号的 `"port": 9022`：viper 默认值就是数字、官方 template.json 也这么写，serde 原本会直接拒绝该配置文件 |

差分向量分配：`parity/gen_config.py` **只产生范围内的数值**——范围外两侧定义上就分歧，比较它只会重复验证
钳位；22 条越界的合法 JSON 向量固化在 `parity/verify_config.sh` 的 "AUDIT4 P5-15" 段，断言 Rust 侧全部拒绝。

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
* 回归网：`parity/verify_hygiene.sh` 直接 grep 掉 cpworker 库代码（`src/bin/` 对拍工具除外）中的 panic
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
> （出站 `dev_queue_xmit_nit` + 入站 `__netif_receive_skb`），libpcap/tcpdump 只交付**收到**的那一份
> （实测 1×），而裸 `recvmsg` socket 会交付 2×。Rust capturer 现对 **loopback 接口**设置
> `PACKET_IGNORE_OUTGOING`（内核 <4.17 时在用户态按 `sll_pkttype==PACKET_OUTGOING` 丢弃），
> 从而与 libpcap 一致；回归测试 `live_capture_loopback_does_not_duplicate_frames`（1 万报文交付 ~1×，
> 修复前为 2×）。**非 loopback 接口不丢出站**（libpcap 在 veth 发送侧同样能看到出站帧，实测 tcpdump 抓到 5000）。
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

| 项 | 来源 | 现状 | 决策 / 触发条件 |
|---|---|---|---|
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

**已完成**（对应改进计划 P3 与 AUDIT4 整改）：实现、验收与已知取舍见 §4，与 libzmq 的输出面
差异见 §2.4。本节不再跟踪该项；本表 5.1 只保留尚未移植的模块。
