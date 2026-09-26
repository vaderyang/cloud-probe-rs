# P5 — AUDIT4 整改计划（纯 Rust 采集/输出 + 工程质量）

- **来源**：`AUDIT4GLM53f.md`、`AUDIT4-qwenfn.md`、`AUDIT4Opus5.md`（三篇去重合并）
- **对应阶段**：P3（去 C 依赖）的缺陷整改 + 门禁强化
- **制定日期**：2026-09-26
- **已完成**：`read()`→`read_exact()` 失步修复（`9ad3f22`，含跨 8 KiB 边界回归测试）

## 0. 目标与验收总则

1. 优先修复会导致**数据错误 / 数据丢失 / 完全不抓包**的 P0/P1。
2. **每条修复必须先有"修复前失败"的回归测试**（红→绿），否则不算完成。
3. 修复与**门禁强化同批交付**：本轮 5 个缺陷全部落在现有门禁盲区（见 §3），只修不补门禁必然复发。
4. 每个工作包完成后必须通过：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --locked`、`cargo deny check`、`parity/all.sh`。
5. 独立提交、可回退；涉及行为变更的在 `PARITY.md` §2 记录。

## 1. 分级总览

| ID | 级别 | 问题 | 来源 | 工作包 |
|---|---|---|---|---|
| P5-01 | **P0** | BPF 缺跳转中继，生产 `not host` 链 ≥11 / `port A or B or C` 即编译失败 → 该 task 完全不抓包 | Opus H4 / qwen P1-1 | WP1 |
| P5-02 | **P1** | `PACKET_STATISTICS` 读后清零，`wrapping_sub` 产生 ~4.29e9 假丢包 | **Opus H2**（已实测确认） | WP2 |
| P5-03 | **P1** | 未启用 `PACKET_AUXDATA` → 实时抓包丢失 802.1Q VLAN 标签 | **Opus H3** | WP2 |
| P5-04 | **P1** | `Output::destroy()` 从无调用方 → ZMQ linger / 文件 flush 从未生效，reload/退出丢最多 hwm×1 MiB | **qwen P1-3** | WP3 |
| P5-05 | **P1** | `SO_RCVBUF` 被 `rmem_max` 静默截断（实测 256 MiB→8 MiB），无 `SO_RCVBUFFORCE`、无回读、无告警 | qwen P1-4 / Opus M2 | WP2 |
| P5-06 | **P1** | BPF 子集缺合法语法（`tcp dst port`、`udp src port`、`ether src host`、`ip proto`、`greater`…）且文档未声明 | qwen P1-2 | WP1 |
| P5-07 | **P1** | 深嵌套/超长 BPF 表达式触发**栈溢出 abort**（`panic="abort"` 下整进程消失） | **qwen P2-1** | WP1 |
| P5-08 | P2 | 主机名只取首个解析地址（多 A/AAAA 漏排除 → 回环放大风险） | Opus M1 | WP1 |
| P5-09 | P2 | 启动过滤空窗：socket 以 `ETH_P_ALL` + 未 bind/未挂 filter 期间收包 | Opus M4 | WP2 |
| P5-10 | P2 | ZMTP 无握手超时 / keepalive / DNS 重解析；写缓冲相位不变量缺失 | Opus M5 / qwen P2-2/P2-7 | WP3 |
| P5-11 | P2 | ZMQ `pending` = hwm×1 MiB，`hwm` 无上限校验；`fwd_*` 入队即计数（统计虚高） | qwen P2-8 | WP3 |
| P5-12 | P2 | 采集错误路径日志洪泛 + CPU 空转；错误仍计入成功 | Opus M3 / qwen P2-3 | WP2 |
| P5-13 | P2 | `timeout_ms=0` 非阻塞忙轮询（~10 万 recvmsg/s）；无批量化 | qwen P2-4 / Opus M6 | WP2 |
| P5-14 | P2 | `SO_TIMESTAMPNS` 返回值被忽略，失败时静默退化为秒级时间戳；cmsg 按 64 位布局硬编码 | qwen P2-5 / Opus low | WP2 |
| P5-15 | P2 | 配置数值 `i64→i32` 静默截断，可产生荒谬运行参数 | qwen P2-6 | WP4 |
| P5-16 | P2 | 实时采集路径 CI 零覆盖（`af_packet_live` 为 `#[ignore]`） | Opus 3.2 / qwen P2-9 | WP5 |
| P5-17 | P2 | BPF 差分生成器算子≤2 项 → 门禁对 P5-01/P5-06 盲区 | qwen P2-10 / Opus H4 | WP5 |
| P5-18 | P2 | 文档与代码 11 处矛盾（PARITY"未完成"、README libpcap 描述、IMPROVEMENT_PLAN 状态等） | Opus 3.2 / qwen P2-11 | WP5 |
| P5-19 | P2 | 基准未重跑（README 仍是 libpcap 时代数字）+ 补实时抓包基准 | GLM §4 / Opus M6 | WP5 |
| P5-20 | P2 | pcap reader 无 fuzz；无 linktype/`len>=caplen` 校验；单条 256 MiB `resize` | Opus low / qwen P3-12 | WP4 |
| P5-21 | P3 | `netutil.rs:68` 逐字节 `as char` 重编码 → 非 ASCII 过滤器被破坏 | qwen P3-13 | WP4 |
| P5-22 | P3 | `PcapWriter` 文档称 fsync 实为 flush；HTTP 端口解析失败静默回退 9022 | Opus low | WP4 |
| P5-23 | P3 | panic 面：2 处 `expect`/`unwrap`（可证不可达）+ `panic="abort"` | qwen §3 | WP4 |
| P5-24 | P3 | 零引用依赖复现（cpworker `thiserror`/`env_logger`/`byteorder` 等） | Opus low | WP5 |
| P5-25 | P3 | release.yml macOS 仍 `brew install libpcap zeromq` | Opus 3.2 | WP5 |
| P5-26 | P3 | MSRV（1.88）无验证 job | Opus 3.2 | WP5 |
| P5-27 | P3 | CI 非确定（`verify_bpf.sh` 用 `$RANDOM`）；缺 `--locked`、缺 workflow `permissions` | Opus 3.2 / qwen §7 | WP5 |
| P5-28 | P3 | `deny.toml` 的 `wildcards`/`unknown-registry` 未 deny、未覆盖 fuzz workspace | qwen §7 | WP5 |
| P5-29 | P3 | parity/oracle 工具位于 `src/bin/` 随默认构建编译；根目录审计文档堆积 | Opus 3.2 | WP5 |
| P5-30 | P3 | 缺 `CONTRIBUTING`/`CHANGELOG`/`CODEOWNERS`/`SECURITY` 等仓库约定文件 | qwen P2-12 | WP5 |

## 2. 工作包

### WP1 — BPF 完备性与鲁棒性（P0/P1）

**P5-01 跳转中继（JA trampoline）** —— 最高优先
- 【证据】`bpf/compiler.rs` `Builder::finish()`（`jt`/`jf` >255 直接 `Err`）；`bpf/codes.rs` 的 `JMP_JA` **从未被发射**；生产过滤器由 `config.rs:931` `bpf_filter_exclude_task_output_hosts` 生成 `(bpf) and not host H1…HN`。
- 【复现】`port 1000 or port 1001 or port 1002` → `bpf: filter too complex (jt > 255)`；`not host` ×10 OK、×11 ERR。
- 【修复】`finish()` 中当 `jt`/`jf` 距离 >255 时，插入 `JMP_JA`（k 为 32 位，可长跳）中继；同步放宽/保留显式长度上限报错。
- 【验收】新回归：`not host` ×{11,50,200}、`port` 或链 ×{3,20}、`host` 或链 ×{12,64} 均编译通过，且与 libpcap 判定逐包一致；`parity/gen_bpf_cases.py` 增加长链模板（见 P5-17）。

**P5-06 补齐 tcpdump 子集语法 + 文档**
- 【证据】`bpf/parser.rs::parse_proto_qualified` 仅支持 `tcp/udp + host/net/port`，不支持方向限定；libpcap=OK / Rust=ERR 集合：`tcp dst port 80`、`udp src port 53`、`ether src host`、`ether dst`、`ip proto 6`、`greater`、`len greater`。
- 【修复】支持 `[src|dst] PROTO port/portrange`、`ether src|dst host`；`PARITY.md §4` 列**完整**不支持清单（`vlan`、`greater`、`len`、算术等）。
- 【验收】上述语法进入 `verify_bpf.sh` 用例并与 libpcap 一致；文档清单与实现一致。

**P5-07 表达式长度/递归深度上限（消除可达 abort）**
- 【证据】`parser.rs:236`（`parse_unary` 自递归）、`compiler.rs:105`（`lower`）、`compiler.rs:608`（`Builder::compile`）；实测 `not`×5000 / `(`×5000 / 扁平 `and`×6000 → `stack overflow, aborting`。BPF 串经 config/CPM/SIGHUP 属**可远程影响输入**。
- 【修复】`parse()` 入口加字节长度上限（如 8 KiB）与递归深度计数（如 256，超限 `Err`）；`lower`/`compile` 复用同一深度预算或改迭代。
- 【验收】`not`×5000 等返回 `Err` 而非 abort；`bpf` fuzz target 增加结构型种子（重复 `not `/`(`）。

**P5-08 主机名多地址**
- 【证据】`bpf/parser.rs:468-470` `to_socket_addrs().next()` 只取首个。
- 【修复】保留全部 V4/V6 结果并 OR 展开（对齐 libpcap `host <name>`）。
- 【验收】多 A/AAAA 记录的主机名生成覆盖全部地址的过滤器；与 libpcap 一致。

### WP2 — 采集面语义等价（P1/P2）

**P5-02 `PACKET_STATISTICS` 增量语义**
- 【证据】`af_packet.rs` `update_drop_stats`（`drop.wrapping_sub(self.prev_ps_drop)`）；**实测**连续两次 `getsockopt` 无流量 → `tp_packets=0, tp_drops=0`（读后清零）。
- 【修复】直接累加本窗口增量 `st.tp_drops`；首次读取建立基线；删除 `ifdrop` 恒 0 的死码。
- 【验收】新回归/mock：两窗口 drop=5 再 0 → 累计仍为 5（修复前会跳 ~4.29e9）；`PACKET_STATISTICS` 语义在 `PARITY.md` 更正。

**P5-03 VLAN / `PACKET_AUXDATA`**
- 【证据】`af_packet.rs` 未设 `SOL_PACKET/PACKET_AUXDATA`；内核在投递前已 untag。
- 【修复】`setsockopt(PACKET_AUXDATA, 1)`，解析 `tpacket_auxdata`，`TP_STATUS_VLAN_VALID` 时在 MAC 后插回 4 字节 VLAN 头（TPID 取 `tp_vlan_tpid`，缺省 0x8100）。
- 【验收】带 VLAN 的 veth 上实测抓到的帧含 VLAN 头；与 libpcap 一致；`PARITY.md` 记录。

**P5-05 `SO_RCVBUF` 强制 + 回读 + 告警**
- 【证据】`af_packet.rs:77-90`；实测请求 256 MiB → 生效 8 MiB（`rmem_max=4 MiB`×2）。
- 【修复】优先 `SO_RCVBUFFORCE`（`README` 的 `setcap` 已给 `CAP_NET_ADMIN`），失败回退 `SO_RCVBUF`；`getsockopt` 回读实际值，缩水则 `log_warn`。
- 【验收】日志打印实际生效值；有 `CAP_NET_ADMIN` 时达到配置量级。

**P5-09 启动过滤空窗**
- 【证据】`af_packet.rs:70`（`socket(..., ETH_P_ALL)`）→ `:99`（bind）→ `:244`（attach filter）。
- 【修复】`socket(AF_PACKET, SOCK_RAW, 0)` → 挂 filter → `bind(ETH_P_ALL, ifindex)`；或先挂 reject-all 并清空队列。
- 【验收】启动首批包不含非目标接口/不匹配过滤器的帧。

**P5-12 错误路径限速 + 正确计数**
- 【证据】`af_packet.rs:393-408` 每次 `capture_once` 都打日志（C 版受 2s 窗口门控）；错误未计入 `error_drop_*`。
- 【修复】错误日志与 `DROP_STAT_DUR_SEC` 对齐或限速；持续错误退避；错误计入 `error_drop_*`。
- 【验收】接口 down 场景下不刷屏、CPU 不空转；统计可观测。

**P5-13 忙轮询 / 批量化**
- 【证据】`timeout_ms=0` → 非阻塞 `recvmsg` 紧循环（~10 万/s）；`timeout_ms>0` 每包 `poll`+`recvmsg`。
- 【修复】先非阻塞 `recvmsg`，`EAGAIN` 后再 `poll`；评估 `recvmmsg` 批量。
- 【验收】空闲 CPU 占用显著下降；实时抓包基准补齐（见 P5-19）。

**P5-14 时间戳健壮性**
- 【证据】`af_packet.rs` `parse_timestamp` 忽略 `SO_TIMESTAMPNS` 的 `setsockopt` 返回值，失败即静默秒级时间戳；cmsg 按 64 位 `cmsghdr` 硬编码。
- 【修复】检查 `setsockopt` 返回值并在失败时告警；改用 `libc::CMSG_FIRSTHDR/CMSG_NXTHDR/CMSG_DATA`。
- 【验收】无控制消息时降级可见；cmsg 解析用宏。

### WP3 — 输出与生命周期（P1/P2）

**P5-04 `destroy()` 调用点**
- 【证据】`output/mod.rs:49`（trait 默认实现）、`file.rs:45`、`zmq.rs:460`；`grep -rn "\.destroy()" crates/` 为空。`task.rs:417/485` 的 reload/`Drop` 直接释放 `Box<dyn Output>`。
- 【修复】在 `TaskManager::stop()` / reload 替换 outputs 前显式 `for o in outputs { o.destroy() }`（或为持有者实现 `Drop`）。
- 【验收】新回归：ZMQ 输出在 `send` 未 flush 时走 `stop()`，mock peer 仍收到队列中的批次；文件输出 flush。

**P5-10 ZMTP 健壮性**
- 【证据】`zmtp/client.rs:400-426`（仅 nonblocking+nodelay）、`:355-380`（`check_connected` 仅探一次，永不停）、`:429-434`（`to_socket_addrs().next()` 解析一次）、`output/zmq.rs:271`（不重解析）；写缓冲相位不变量（qwen P2-2）。
- 【修复】`TCP_USER_TIMEOUT` + keepalive；`Connector::start()` 内 DNS 重解析；`Conn` 加握手 deadline（如 10s）超时 `schedule_reconnect()`；补写缓冲相位不变量与断言测试。
- 【验收】不发 greeting 的 peer 会在超时后重连；DNS 变更后重连到新地址；相位不变量单测通过。

**P5-11 `pending` 内存上限 + 统计口径**
- 【证据】`output/zmq.rs` `pending` 上限 = hwm×1 MiB；`hwm` 无范围校验；`fwd_*` 入队即计数。
- 【修复】`hwm` 范围校验；新增 `queued_bytes` 指标；评估把 `fwd_*` 移到"写入 transport 成功后"或明确文档说明口径。
- 【验收】极端 `hwm` 被拒绝/钳制；指标可观测。

### WP4 — 配置与资源卫生（P2/P3）

- **P5-15** `config.rs:779-792` i64→i32 统一 `try_into` + 范围校验（snaplen/buffer_size_mb/timeout_ms 等）。
- **P5-20** pcap reader：校验 linktype（非 EN10MB 明确报错）、`len >= caplen`、单条 `resize` 上限收敛；新增 `pcap_reader` fuzz target（畸形头/截断/错误字节序/跨边界）。
- **P5-21** `netutil.rs:68` 改为按字节切片复制/push_str，避免非 ASCII 破坏。
- **P5-22** `PcapWriter` 文档改为 flush（或真的 fsync）；HTTP 端口解析失败改为显式报错/告警，不静默回退。
- **P5-23** 消除 2 处可达性存疑的 panic 构造（或加 `debug_assert` + 明确不变量）；评估 `panic="abort"` 与"可恢复错误"的边界。
- 【验收】各自配单测；clippy/deny/test 全绿。

### WP5 — 工程质量与供应链（P2/P3）

- **P5-16 实时采集进 CI**：privileged 容器（`--cap-add=NET_ADMIN,NET_RAW`）或 `unshare -n`+veth 脚本跑 `af_packet_live`；覆盖 VLAN（P5-03）、丢包统计（P5-02）、启动空窗（P5-09）。
- **P5-17 差分门禁加深**：`gen_bpf_cases.py` 增加算子 3/10/50 项、`not host` 长链、方向语法；`verify_bpf.sh` 失败时打印种子。
- **P5-18 文档同步**：一次改齐 PARITY/README/IMPROVEMENT_PLAN/release 的 11 处矛盾（测试数、libpcap 描述、P3 状态、bench）。
- **P5-19 基准重跑**：修复后重跑离线三场景 + **新增实时抓包**基准；更新 README（现数据为 libpcap 时代）。
- **P5-24** 删除零引用依赖（cpworker `thiserror`/`env_logger`/`byteorder`；cpctl `serde`/`env_logger`；cpgolib `anyhow`；cpdaemon `libc`）。
- **P5-25** `release.yml:43` 删除 macOS `brew install libpcap zeromq`；核对纯 Rust 构建矩阵。
- **P5-26** 新增 MSRV（1.88）CI job。
- **P5-27** 所有 CI 命令加 `--locked`；workflow 级 `permissions: contents: read`；固定 `verify_bpf.sh` 种子（失败时打印）。
- **P5-28** `deny.toml`：`wildcards`/`unknown-registry` 提到 `deny`；覆盖 fuzz workspace。
- **P5-29** parity/oracle 工具移入 `examples/` 或 feature 门控；根目录审计/计划文档移入 `docs/`。
- **P5-30** 补 `CONTRIBUTING.md`/`CHANGELOG.md`/`CODEOWNERS`/`SECURITY.md`。

## 3. 门禁强化（防复发的系统措施）

本轮三篇审计暴露的**三层共同盲区**，必须固化为固定检查项：

1. **接口有无调用方**（P5-04 类）：trait 默认方法不参与 `dead_code`。→ 引入 `cargo-mutants`/自定义脚本或 CI grep 检查"公开 API 无调用点"。
2. **测试生成器的组合深度**（P5-01/P5-06/P5-17 类）：小样本差分全绿≠语义等价。→ 对每个差分生成器设"最小组合深度/规模"下限，并在报告中显式声明覆盖的最大规模。
3. **OS 对参数的静默修正**（P5-02/P5-05/P5-14 类）：`setsockopt`/`getsockopt` 返回 0 但语义被改。→ 所有内核参数"设置即回读 + 断言/告警"；关键 syscall 记入 `PARITY.md`。
4. **端到端大文件差分**（已由 `read_exact` 教训得出）：所有"替换库"的路径都要有大输入/跨边界端到端对拍。

## 4. 里程碑与排期（建议）

| 里程碑 | 内容 | 依赖 | 出口标准 |
|---|---|---|---|
| **M1（阻塞）** | WP1：P5-01/06/07 + P5-17 门禁 | — | 长链/方向语法与 libpcap 一致；无 abort；`all.sh` 绿 |
| **M2（数据正确）** | WP2：P5-02/03/05/09 + P5-16 live CI | M1 | 丢包/VLAN/RXBUF 与 libpcap 对齐；live job 入 CI |
| **M3（数据不丢）** | WP3：P5-04/10/11 | — | reload 不丢批次；握手超时/重解析有测试 |
| **M4（卫生）** | WP4 + WP5 的 P3 项 | M1–M3 | clippy/deny/test 全绿；文档一致；MSRV job |
| **M5（收尾）** | P5-19 基准 + P5-18 文档 + P5-30 流程 | M1–M4 | README/基准更新；流程文件齐备 |

WP2 与 WP3 可并行；M1 必须最先（唯一可能"完全无数据"的缺陷）。

## 5. 暂不处理 / 需业务确认

1. **BPF 表达式现场分布**（AUDIT2 早已要求的预研）：决定 P5-01/P5-06 是"发布阻塞"还是"文档说明即可"。仓库内无该调研记录，需业务数据。
2. **混杂模式（promisc）**：需确认原 C 是否有意设置；影响采集面等价性（三篇均未定论）。
3. **`af_packet_live` 在 root 下是否真通过**：需在带 `CAP_NET_RAW` 环境实测并在 CI 固化。
4. **libpcap TPACKET ring 相对 `SO_RCVBUF` 的真实容量优势**：核心结论（256 MiB→8 MiB）已实测；"ring 可用 MB 级"需高负载实测。
5. **VLAN/H3 的现场影响**：需在 trunk/镜像口实测确认严重度。

## 6. 执行进度

### M1 已完成

- ✅ **P5-01 跳转中继（JA jump-around）**：`bpf/compiler.rs` 改为反向汇编器，
  条件分支距离 >255 时插入 `JMP_JA`（32 位 k）。`not host` ×{11,50,200}、
  `port` 或链 ×{3,20}、`host` 或链 ×{12,64} 均编译通过，且与 libpcap 逐包一致。
- ✅ **P5-06 语法补齐**：`tcp dst port`、`udp src port`、`tcp dst portrange`、
  `ether src|dst host`、`ip proto N`、`ip6 proto N`、`ip src host`；
  `PARITY.md §4` 列出完整不支持清单（`vlan`/`greater`/`len`/算术/`src tcp` 等）。
- ✅ **P5-07 上限**：表达式 ≤8 KiB、嵌套 ≤256、节点 ≤4096；
  `not`×5000 / `(`×5000 / `and`×3000 均返回 `Err`，不再栈溢出 abort。
- ✅ **P5-17 门禁加深**：`gen_bpf_cases.py` 增加长链/方向语法/`ip proto` 用例及
  10.8/10.9 地址池；新增 `crates/cpworker/fuzz/seeds/bpf/` 结构型种子。
- 验证：`cargo test --workspace` **112 passed**；clippy `-D warnings` 0；`cargo deny check` 四项 ok；
  `parity/all.sh` **7/7 绿**；`bpf` fuzz 30s 覆盖 840（无崩溃）。

### 下一步

- **M2**：采集面语义等价（P5-02 `PACKET_STATISTICS`、P5-03 VLAN、P5-05 `SO_RCVBUF`、P5-09 启动空窗 + P5-16 live CI）。
