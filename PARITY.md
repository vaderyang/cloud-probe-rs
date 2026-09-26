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

`crates/cpworker/fuzz/` 下有 5 个 fuzz target（nightly + ASAN + libFuzzer）：

| target | 对象 |
|---|---|
| `packet_split` | `parse_packet` / `calculate_fragment_count` / `build_fragment` |
| `config` | JSON 配置解析 + BPF 排除主机 |
| `vxlan` | `vxlan_encapsulate`（校验和/capture_time） |
| `zmq_batch` | `BatchBuilder`（VLAN/MPLS，issue #231 回归） |
| `sim_dst` | 整个确定性仿真 + 不变量 |

* 运行：`fuzz.sh [秒数] [target|all]`；CI 烟雾：`fuzz.sh --check`
* 复现：`fuzz.sh repro zmq_batch <artifact>`
* 详见 `crates/cpworker/fuzz/README.md`

二者互补：Python 差分 fuzz 证明“C 与 Rust 行为一致”，cargo-fuzz 在 Rust 内部搜索崩溃/不变量
违例并给出可复现输入。

### 1.6 覆盖引导的差分 Fuzz（Rust ↔ 原 C）

`parity/difffuzz.sh` 把两者结合：Rust 侧**在进程内**跑（libFuzzer 获得覆盖率反馈），
原 C 代码作为**常驻 oracle 子进程**（`--sentinel` 行帧）；每个输入映射成同一请求喂给两侧，
逐行比较规范化输出，一旦分歧即 panic，libFuzzer 保存触发输入。这能发现固定种子的差分测试
（`parity/*.sh`，只覆盖“生成器能想到的”输入）遗漏的语义差异。

| 模式 | 对象 | C oracle |
|---|---|---|
| `packet_split` | `parse_packet` + 分片 + 校验和 | `c_harness.c` |
| `config` | JSON 解析 + bpf 排除主机 | `c_config.c` |
| `req_pattern` | 自定义模式匹配器 | `c_req_pattern.c` |

```bash
parity/difffuzz.sh 60 packet_split   # 一个模式 60s
parity/difffuzz.sh 120 all           # 全部模式各 120s
```

已知的有意分歧（如 §2.2 的 IPv4/TCP 严格校验）在 target 内被分类过滤，
以便继续搜索**新**分歧。**本框架已发现并修复**：`req_pattern` 对 `port -0` 的负零解析不兼容。

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

## 3. 关键一致性向量（已通过）

* `workerTaskBuilder` 产出的 task fingerprint（含 Go 反射标签算法的怪异 `UUID()`
  行为）：`64393037-6336-6262-3137-333739363234` 等，与 Go 测试逐字一致。
* `Vni2Tag.Encode`：`23,1,6,0 → 6040`；`3568,0,9,0 → 913444`。
* `parseStartup`：pflag 短/长/`=`/未知标志各形态。
* `decodeContainerId`：含 `docker://`、`containerd://`、多 NIC。
* `cpu_set_parse`：C 的全部边界用例（`,`、`1,`、`1-,2`、`3-1`、`""`…）。

## 4. "纯 Rust" 现状（未完成）

| C 依赖 | 现状 | 计划替代 |
|---|---|---|
| **libpcap** | `pcap` crate 绑定 + 少量 FFI | AF_PACKET（`pnet_datalink`）+ `pcap-file` + 自研 tcpdump BPF 子集编译器 |
| **libzmq** | `zmq` crate 绑定 | `tmq`（纯 Rust） |
| libc（raw socket/syscall） | `libc` crate | 系统调用，非第三方 C 库 |

> **“纯 Rust”的定义**：本项目的目标是**不链接任何 C 库**（去除 libpcap / libzmq）。
> `libc` 只是一个声明系统调用与常量 ABI 的 crate（不是任务 C 代码），移除 libpcap/libzmq
> 后仍会保留，这是预期且符合目标的。
>
> 去 C 依赖对应改进计划 P3；开工前需先完成两项调研：用户配置中 BPF 表达式的分布审计、
> collector 侧 ZMTP socket 语义确认。

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
