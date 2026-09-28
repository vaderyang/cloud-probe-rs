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

**P5-12 错误路径限速 + 持续错误退避**
- 【证据】`af_packet.rs:393-408` 每次 `capture_once` 都打日志（C 版受 2s 窗口门控）；~~错误未计入 `error_drop_*`~~。
- 【修复】错误日志与 `DROP_STAT_DUR_SEC` 对齐限速 ✅；持续错误退避 ✅（M6：1ms→100ms 封顶，收包/socket 恢复即复位）；
  ~~错误计入 `error_drop_*`~~ **【修正的验收标准】**：`error_drop_*` 在 C 里是**输出侧**计数
  （`output->base.stats`，见 `output_gre.c:114`、`output_rotating_file.c:103`），采集侧 schema 里根本没有这两个计数器；
  把"recvmsg 读失败"记成"丢包"既改口径又把观测错误伪装成本征损失。见 `PARITY.md §2.6`。
- 【验收】接口 down 场景下不刷屏 ✅、CPU 不空转 ✅（实测修复前 10.8% 单核/task，修复后见 §8 M6）；统计口径不变。

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

### WP4 — 配置与资源卫生（P2/P3）  ✅ **已完成（M4，见 §6）**

- **P5-15** `config.rs:779-792` i64→i32 统一 `try_into` + 范围校验（snaplen/buffer_size_mb/timeout_ms 等）。
- **P5-20** pcap reader：校验 linktype（非 EN10MB 明确报错）、`len >= caplen`、单条 `resize` 上限收敛；新增 `pcap_reader` fuzz target（畸形头/截断/错误字节序/跨边界）。
- **P5-21** `netutil.rs:68` 改为按字节切片复制/push_str，避免非 ASCII 破坏。
- **P5-22** `PcapWriter` 文档改为 flush（或真的 fsync）；HTTP 端口解析失败改为显式报错/告警，不静默回退。
- **P5-23** 消除 2 处可达性存疑的 panic 构造（或加 `debug_assert` + 明确不变量）；评估 `panic="abort"` 与"可恢复错误"的边界。
- 【验收】各自配单测；clippy/deny/test 全绿。

### WP5 — 工程质量与供应链（P2/P3）  ✅ **已完成（M5，见 §6）**

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

1. **接口有无调用方**（P5-04 类）：trait 默认方法不参与 `dead_code`。
   ✅ **已落地（M3）**：`parity/verify_liveness.sh`（并加入 `parity/all.sh` 第 8 项与 CI `test` job）
   对"必须有生产调用点"的接口逐条 grep：`Output::destroy()`、`zmtp_queued_*` 指标、
   ZMTP 握手 deadline。测试内调用不算数——正是 P5-04 的失效形态。
2. **测试生成器的组合深度**（P5-01/P5-06/P5-17 类）：小样本差分全绿≠语义等价。→ 对每个差分生成器设"最小组合深度/规模"下限，并在报告中显式声明覆盖的最大规模。
3. **OS 对参数的静默修正**（P5-02/P5-05/P5-14 类）：`setsockopt`/`getsockopt` 返回 0 但语义被改。→ 所有内核参数"设置即回读 + 断言/告警"；关键 syscall 记入 `PARITY.md`。
4. **端到端大文件差分**（已由 `read_exact` 教训得出）：所有"替换库"的路径都要有大输入/跨边界端到端对拍。
   ✅ **强化（M4）**：`pcap_reader` fuzz target 对**同一输入**用 `Cursor` 与 1 字节 `BufReader` 各跑一遍，
   要求逐记录（时间戳/两个长度字段/payload）完全一致——"解析与源如何分块无关"从口头教训变成机器约束。
5. **文档承诺也是门禁**（P5-20/P5-22 类）：注释里写的"call flush to fsync"、"校验 linktype"、
   "上限 256 MiB"同样是接口承诺，只有 grep 能防止它再次变成空头承诺。
   ✅ **已落地（M4）**：`parity/verify_hygiene.sh` 四条——配置层不得再有截断 `as` 转换（P5-15）、
   cpworker 库代码不得有 panic 构造（P5-23，`src/bin/` 对拍工具除外）、`pcap_writer` 文档不得再声称
   flush 会 fsync（P5-22）、`fuzz/Cargo.toml` 声明的 target 必须出现在 `fuzz.sh`（P5-20：写了不跑等于没写）。
   这四类 `clippy`/`cargo test` 全部看不见；已做反向验证（重新插入违例 → 对应行变 ❌ 且退出码非 0）。

## 4. 里程碑与排期（建议）

| 里程碑 | 内容 | 依赖 | 出口标准 |
|---|---|---|---|
| **M1（阻塞）** | WP1：P5-01/06/07 + P5-17 门禁 | — | 长链/方向语法与 libpcap 一致；无 abort；`all.sh` 绿 |
| **M2（数据正确）** | WP2：P5-02/03/05/09 + P5-16 live CI | M1 | 丢包/VLAN/RXBUF 与 libpcap 对齐；live job 入 CI |
| **M3（数据不丢）** ✅ | WP3：P5-04/10/11 | — | reload 不丢批次；握手超时/重解析有测试 |
| **M4（卫生）** ✅ | WP4（P5-15/20/21/22/23 + §3 门禁扩展）已完成；WP5 的 P3 项（P5-24..28）随 M5 | M1–M3 | clippy/deny/test 全绿；MSRV job 已入 CI |
| **M5（收尾）** ✅ | WP5 全部（P5-18/19/24..30） | M1–M4 | 基准重测并更新 README；流程文件齐备；CI/parity 全部 --locked + 最小权限 + MSRV job |

WP2 与 WP3 可并行；M1 必须最先（唯一可能"完全无数据"的缺陷）。

## 5. 暂不处理 / 需业务确认

1. **BPF 表达式现场分布**（AUDIT2 早已要求的预研）：决定 P5-01/P5-06 是"发布阻塞"还是"文档说明即可"。仓库内无该调研记录，需业务数据。
2. **混杂模式（promisc）**：需确认原 C 是否有意设置；影响采集面等价性（三篇均未定论）。
3. **`af_packet_live` 在 root 下是否真通过**：✅ 已闭环（M6/P2-2）。本机 root 实测 4 个 live 测试全部执行并通过；
   测试在非特权时改为 **panic 而不是 skip**（此前 `--ignored` 在非 root 下打印 `ok. 4 passed` 而什么都没做），
   CI `live-capture` job 断言"`--ignored --list` 声明的条数 == 实际 executed 条数"。
4. **libpcap TPACKET ring 相对 `SO_RCVBUF` 的真实容量优势**：核心结论（256 MiB→8 MiB）已实测；"ring 可用 MB 级"需高负载实测。
5. **VLAN/H3 的现场影响**：需在 trunk/镜像口实测确认严重度。
6. **实时抓取面的“同流不同包数”（A1，结论已修正并修复，P1）**：
   - **初版结论（本计划 b60c8a6）是错的**：它把 loopback 上 Rust 交付 2× 当成“全抓的正确行为”。经
     GLM-5.3 与 Qwen3.8 两份独立审查证伪：C/libpcap 在 lo 上只交付 **1×**（用能从源码构建的 Go `cpctl`
     + 延迟读、以及 tcpdump 都复现），Rust 交付 **2×** ——这是**真实的 R/C 采集语义分歧**，
     会导致下游 GRE/VXLAN/ZMQ 收到双份、`cap_bytes` 翻倍（实测 71,957,732 vs 35,978,866）。
   - **已修**：对**loopback 接口**设 `PACKET_IGNORE_OUTGOING`（内核 <4.17 时用户态按
     `sll_pkttype==PACKET_OUTGOING` 丢弃）；非 loopback 保留出站（libpcap 在 veth 发送侧也能看到出站，
     实测 tcpdump 抓到 5000）。回归测试 `live_capture_loopback_does_not_duplicate_frames`（红→绿：
     无修复时 1 万报文交付 20000，修复后 ~10000）。`PARITY.md §4` 已登记。
   - `lo` 上每个报文被 tap **两次**（出站 `dev_queue_xmit_nit` + 入站 `__netif_receive_skb`）；
     libpcap 的 `ps_recv ≈ 2 × pcap_next_ex 交付`（计数口径）解释了为何容易误判。
   - “C ×0.79”另有时序竞态因素：`bench/live_bench.py` 用 **Rust `cpctl`** 读 C worker 统计时，
     Rust 客户端把 payload 与 `\n` 分两次 write、C 服务端握手单次 recv，可能漏掉 `\n`（残留空行被当命令）
     → `Connection reset by peer`；**并非协议不兼容**（Go `cpctl` 与重试的 Rust `cpctl` 都能成功）。
   - `drop_packets == 0` 不能作为“无丢失”的证据（只有 socket 队列溢出才计入 `tp_drops`）。
   - **顺带修了一个 UB**：`parse_control` 的 cmsg 缓冲区 `[u8; 256]` 未按 `cmsghdr` 对齐，
     `&*cmsg` 会 misaligned deref（调试构建下 abort）；改用 `#[repr(align(8))] CmsgBuf`。
7. **实时抓包吞吐门禁**：`live_bench.py` 是手工工具（需 root、需真实接口、发送端通常是瓶颈），不进 CI。
   若要固化成回归网，需要 veth + 可控注入速率与丢包断言，属独立工程项。

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

### M2 已完成

- ✅ **P5-02 `PACKET_STATISTICS`**：实测确认它是**读后清零**（连续两次读取无流量 → 0），
  改为按“本窗口增量直接累加”；`DropCounter` 纯逻辑单测覆盖“上窗口 5 → 本窗口 0 不再产生
  ~4.29e9 假值”。
- ✅ **P5-03 VLAN/AUXDATA**：启用 `PACKET_AUXDATA`，解析 `tpacket_auxdata`，
  `TP_STATUS_VLAN_VALID` 时在 MAC 后重插 802.1Q 头；veth 端到端测试验证
  （内核确实剥离标签：`auxdata_vlan=1 tci=100`）。
- ✅ **P5-05 `SO_RCVBUF`**：优先 `SO_RCVBUFFORCE`（需 `CAP_NET_ADMIN`），失败回退；
  `getsockopt` 回读实际值，被 `net.core.rmem_max` 截断时告警。root 下实测 `SO_RCVBUF=512MiB`。
- ✅ **P5-09 启动空窗**：socket 以协议 0 创建 → 挂 BPF → 再 `bind(ETH_P_ALL, ifindex)`。
- ✅（顺带）**P5-12 错误日志限速**、**P5-13 recv-first + 常驻非阻塞**、
  **P5-14 cmsg 用 libc 宏 + 时间戳启用失败告警**。
- ✅ **P5-16 live CI job**：`.github/workflows/ci.yml` 新增 privileged `live-capture` job。
- 验证：`cargo test --workspace` **116 passed**；clippy/deny ok；root 下 2 个 `#[ignore]`
  live 测试通过（lo 过滤 + veth VLAN 重插）。

### M3 已完成

- ✅ **P5-04 `Output::destroy()` 调用点**：`TaskManager::stop()` 成为**唯一**调用点
  （先 join 输出线程，再把 outputs 从共享集合取出后逐个 `destroy()`，锁内不做 5s linger，
  重复调用为 no-op）；`reload()` 与 `Drop` 都经过它。`RotatingFileOutput` 补上 `destroy()`。
  - 红→绿：`tests/output_lifecycle.rs`（对端只握手不读取时，**修复前 mock peer 只收到 508/6000
    个包**，修复后 stop()/reload() 全部送达）；`task::tests` 4 个 spy 单测（修复前 destroy 次数=0）；
    `output::rotating_file::tests::destroy_flushes_buffered_packets`（修复前磁盘上只有 28824/32920 字节）。
- ✅ **P5-10 ZMTP 健壮性**：握手 deadline（默认 10s，超时→重连并计数）；
  `SO_KEEPALIVE`(15s/5s/3) + `TCP_USER_TIMEOUT`(30s)，OS 拒绝时一次性告警；
  `TcpConnector` 保存 host/port 并在重连时**重新解析**（`RESOLVE_TTL=1s` 限速）且
  **轮转全部**解析结果（新增可注入 `Resolver`）；写缓冲改为**单一 FIFO**
  （握手字节只追加不覆盖，业务帧需 `can_write_messages()` 才允许写）+ `debug_assert`。
  - 红→绿：`silent_peer_handshake_times_out_and_reconnects`、
    `tcp_transport_enables_keepalive_and_user_timeout`（getsockopt 回读）、
    `connector_covers_every_resolved_address`、`connector_picks_up_a_dns_change_on_reconnect`、
    `short_write_during_greeting_keeps_the_wire_in_order`、
    `short_write_during_ready_does_not_interleave_messages`、
    `tests/zmtp_interop.rs::real_tcp_silent_peer_is_given_up_on`；
    `zmtp_client` fuzz 加入"对端窗口有界（短写→EAGAIN）"分支与"上线字节必须能按
    greeting+整帧解析"不变式。
- ✅ **P5-11 队列内存与指标**：`zmq.hwm` 配置期校验 `1..=4096`（0/负数/超大报错并说明
  hwm×1 MiB 换算）；队列除条数外再受字节上限 `min(hwm×1 MiB, 64 MiB)` 约束；
  新增 gauge `zmtp_queued_batches` / `zmtp_queued_bytes`（`collect_stats_summary` 与
  `cpctl stats` 均可见）。`fwd_*` 口径**保持不变**（与 C 的 `zmq_send(DONTWAIT)` 一致），
  已在代码与 `PARITY.md §2.4` 明确记录。
  - 红→绿：`config::tests::zmq_hwm_is_range_checked`、
    `zmtp::client::tests::queue_is_bounded_in_bytes`、`queued_bytes_tracks_the_queue`、
    `output::zmq::tests::{queue_backlog_is_published_as_gauges,queue_budget_is_bounded_by_hwm_and_bytes}`。
- ✅ 新增 `PARITY.md §2.4`：libzmq 与 Rust ZMTP 的输出面差异表（linger 调用点、握手超时、
  keepalive/`TCP_USER_TIMEOUT`、DNS 重解析、hwm 校验、队列字节上限、`fwd_*` 口径）。
- ✅ **门禁强化 §3.1 落地**：新增 `parity/verify_liveness.sh`（"实现了却没人调用"的接口
  grep 门禁，测试内调用不计入），已接入 `parity/all.sh`（第 8 项）与 CI `test` job。
- 验证：`cargo test --workspace` **138 passed / 0 failed**（另有 2 个 live 测试 `#[ignore]`，由 privileged job 跑）；clippy `-D warnings` 0；
  `cargo fmt --all -- --check` 通过；`cargo deny check` 四项 ok；`parity/all.sh` **8/8 绿**；
  `zmtp_client` fuzz 120s / 1.04M runs 无崩溃。

### M4 已完成

- ✅ **P5-15 配置数值 `i64→i32` 静默截断**：所有 "JSON 数字 → 运行时整数" 的转换统一走
  `int_in()/i32_in()/u16_in()/u64_in()`（显式范围 + 无损 `TryFrom`），越界返回**含字段名**的错误
  （`invalid libpcap.snaplen 2147483648: must be between 0 and 262144`）。范围以公开常量形式给出
  （`SNAPLEN_MIN/MAX`、`BUFFER_SIZE_MB_MIN/MAX`、`TIMEOUT_MS_MIN/MAX`、`RING_SIZE_MIN/MAX`、
  `PIPELINE_BUFFER_MB_MIN/MAX`、`SLICE_MIN/MAX`、`RATE_LIMIT_MBPS_MIN/MAX`、`MAX_FILE_INTERVAL_*`），
  `zmq.hwm`/`heartbeat_ms`/`rotating_file.max_file_interval` 改用 `i64` 反序列化以便由同一段代码报错。
  关闭的实际故障：`snaplen:2147483648 → i32::MIN → snaplen.max(1)` = **每包只截 1 字节**（BPF 全不命中，
  任务静默无数据）、`buffer_size_mb:4294967296 → SO_RCVBUF=0`、`timeout_ms:4294967396 → 100`、
  `slice:4294967296 → 0`（变成"不截断"，与请求相反）、`ring_size:4294967304 → 2048`；
  `rate_limit_mbps` 的上限顺带保证 `×1_000_000` 的 token bucket 不再可能溢出。
  - 红→绿：`config::tests::numeric_fields_are_range_checked_not_truncated`
    （修复前：`libpcap.snaplen: out-of-range value was accepted`）；边界值（0 / 2048 / 262144 / 8192 /
    65535 / 1e6）必须被**接受且数值不变**。
  - 与差分门禁的关系：实测 cJSON 会把越界数字**钳位**到 `INT_MIN/INT_MAX` 后接受，而 Rust 选择报错，
    因此 `parity/gen_config.py` 仍只产生范围内数值（否则对拍只是在重复验证钳位）；越界判定固化成
    `parity/verify_config.sh` 的 "AUDIT4 P5-15" 段（22 条合法 JSON 越界向量必须全被拒）。分歧见 `PARITY.md §2.5`。
- ✅ **P5-20 pcap reader 校验 + fuzz**：`PcapReader` 泛化为 `PcapReader<R: Read>`（新增
  `from_reader()` 纯字节流入口），补四条硬校验——`linktype == DLT_EN10MB`（错误消息含具体编号与
  `tcpdump -i any`/SLL2/radiotap 提示）、`version_major <= 2`、`caplen <= orig_len`、
  `caplen <= MAX_CAPLEN`；`MAX_CAPLEN` 由 **256 MiB 收敛到 262144**（libpcap 自身最大 snaplen），
  并加 `const _ = assert!` 编译期约束防止回调。记录字段只在检查全部通过后发布；截断 = EOF（不交出说谎的
  长度）；文件损坏时 `log_error!` 一次并停止回放（原实现会把 payload 当报文继续转发）。
  - 红→绿（逐个关掉检查，同一批测试即失败）：`rejects_non_ethernet_linktype`、
    `rejects_caplen_larger_than_orig_len`（修复前损坏记录被投递到 sink）、`bounds_one_record_allocation`
    （修复前 262145 字节的记录被正常接受、200 MiB 记录会触发同量级 `resize`）、
    `rejects_unknown_pcap_version`、`truncated_files_stop_without_forwarding_garbage`、
    `parsing_is_independent_of_read_chunking`、`all_byte_orders_and_timestamp_resolutions_decode`、
    `corrupt_record_header_leaves_the_previous_record_intact`。
  - 新增 fuzz target `pcap_reader`（注册进 `fuzz/Cargo.toml` + `fuzz.sh` 的 ALL_TARGETS）：
    同一输入跑两遍（`Cursor` 与 1 字节 `BufReader`），要求逐记录一致 + 不变量 `data.len() == caplen <= len <= MAX_CAPLEN`；
    15 条手写种子覆盖畸形全局头/记录头、截断、错误字节序、跨 BufReader 边界、超大 caplen。
    `./fuzz.sh 30 pcap_reader` → 996 656 runs，无崩溃。
- ✅ **P5-21 netutil 非 ASCII 破坏**：`bpf_filter_replace_nic` 不再用 `bytes[i] as char` 逐字节重编码
  （那会把 `网络` 变成 `ç½‘ç»œ`，过滤器再也编译不过），改为字节切片复制 + `find(char::is_whitespace)`
  结束接口名；解析器抽成可注入 resolver 的 `replace_nic`，回归测试不需要真实网卡。
  - 红→绿：`non_ascii_text_survives_unchanged`、`non_ascii_around_a_token_is_preserved`、
    `unicode_whitespace_terminates_the_interface_name`（三条修复前均失败，见 §6 记录）。
- ✅ **P5-22 文档与静默回退**：
  - `PcapWriter`：选择**保持 flush 语义**（libpcap `pcap_dump_flush()` 本身就是 `fflush`；每批次一次
    fsync 会主导转发循环），把"call flush to fsync"的空头承诺改成精确边界：flush 后字节已到 OS、可被其他
    读者看到（`Output::destroy()` 依赖这一点），但不保证掉电持久。新增
    `flush_publishes_the_buffer_without_waiting_for_the_writer` 把该边界钉住（flush 前 0 字节、flush 后全量、
    writer 仍打开），另加 `snaplen_falls_back_to_the_traditional_default`。
  - `cpdaemon`：`listen.http.port` 解析失败不再静默回退 9022，而是启动失败并指出键名与合法范围
    （Go 侧把端口字符串直接交给 `net.Listen`，非法端口本来就是致命错误）；空值仍表示默认。
    顺带接受不带引号的 `"port": 9022`——viper 默认值是数字、官方 `template.json` 也这么写，
    serde 原本会直接拒绝整个配置文件。
  - 红→绿：`cpdaemon tests::bad_http_port_is_a_fatal_error`、`config::tests::http_port_accepts_strings_and_numbers`
    （修复前分别失败：静默回退 / 配置文件根本加载不了）。
- ✅ **P5-23 panic 面**：消除库代码里全部 panic 构造 —— `bpf::or_all` 的 `expect`（改为 `Result`，
  `lower_port` 随之返回 `Result`：过滤器编译路径由配置文件/CPM 下发/SIGHUP 重载驱动，abort 会带走整个 worker）、
  `zmtp::flush_pending` 的 `self.conn.as_mut().unwrap()`（改为一次性 `take()` 出连接，保留旁边的单一 FIFO
  `debug_assert!`）、`rotating_file` 命名文件时的 `timestamp_opt(..).unwrap()`（改为 dumper 错误，
  调用方已有 `error_drop_*` 计数路径）、`packet.rs` 四处定长切片 `try_into().unwrap()`（改为可失败切片辅助）。
  `panic = "abort"` **保留**，边界写进根 `Cargo.toml` 与 `PARITY.md §4`：由输入决定的失败一律是 `Result`，
  panic 只留给 `debug_assert!` 表达的程序自身不变量违例；`cargo test` 走 unwind 的 `test` profile 不受影响。
  - 红→绿：`bpf::compiler::tests::or_all_rejects_an_empty_alternative_list_without_panicking`、
    `output::rotating_file::tests::out_of_range_file_time_is_an_error_not_a_panic`（修复前均 panic）。
    `zmtp` 那处的"不可达"无法用测试证伪，故改由下面的 grep 门禁守着。
- ✅ **门禁强化 §3 扩展**：新增 `parity/verify_hygiene.sh`（4 条，已接入 `parity/all.sh` 第 9 项与 CI `test` job）：
  config.rs 不得再有截断 `as` 转换；cpworker 库代码不得有 panic 构造（`src/bin/` 对拍工具除外）；
  `pcap_writer` 文档不得再声称 flush 会 fsync；`fuzz/Cargo.toml` 声明的每个 target 必须出现在 `fuzz.sh`。
  四条都已做反向验证：把对应违例重新插入一处，该行即变 ❌ 且脚本退出 1。

### M5 已完成（WP5：工程质量与供应链）

- ✅ **P5-24 零引用依赖**：逐条用 `grep -w` 扫全 crate 的 `*.rs`（src / bin / tests / fuzz）核实后再删 ——
  cpworker `thiserror`（error.rs 为手写）、`env_logger`（日志走 `cpgolib::slogx`）、`byteorder`
  （字节序用 from_be_bytes/to_be_bytes）；cpctl `serde`（只用 serde_json，全 crate 无 Serialize/Deserialize
  derive）、`env_logger`；cpgolib `anyhow`；cpdaemon `libc`（syscall 走 nix）。`byteorder` 删完已无任何成员
  引用 → 连 `[workspace.dependencies]` 条目一并删；`axum`/`reqwest`/`rand` 是反向症状（表里声明、成员内又
  内联一份），改为 `.workspace = true` 继承，顺带消掉 nightly cargo 新增的 unused-workspace-dependency 告警。
  两份 lockfile 同步刷新（根 -13 行、fuzz -10 行，均为被删的包/依赖边）。
- ✅ **P5-25 release 矩阵**：删除 macOS 的 `brew install libpcap zeromq`。矩阵核对结论：**protoc 必须保留**
  —— 把 PATH 里的 protoc 换成失败桩后 `cargo build -p cripid` 即在 build.rs 报 "protoc failed"（release 产物
  含 cripid）；它是构建期代码生成工具，不链接任何 C 库，README 的 System dependencies 段早已如此描述。
- ✅ **P5-26 MSRV 1.88 job**：CI 新增 `msrv` job（`dtolnay/rust-toolchain@1.88.0` +
  `cargo build --workspace --locked`，rust-cache 用独立 key，避免与 stable 产物互串）。本地用 rustc 1.88.0
  实跑全 workspace build 通过（4 核 2m18s），故按计划用 build 而非 check。
- ✅ **P5-27 CI 确定性 + 最小权限**：ci.yml 的 build/test/live-capture/clippy/coverage、release.yml 的 build、
  `parity/` 六个 harness 的 `cargo build` 全部加 `--locked`；两份 workflow 顶层
  `permissions: contents: read`，仅 dependency-review（`pull-requests: write`）与 release.yml 的 publish job
  （`contents: write`）自行放宽。`parity/verify_bpf.sh` 默认种子由 `$RANDOM` 改为固定 `20260927`（位置参数与
  `BPF_SEED` 仍可覆盖），不匹配时打印 seed/pkts/exprs 与可直接粘贴的重放命令；`all.sh` 只把规模放进环境
  （800×96），避免默认种子在两处各存一份。反向验证：伪造一次 rs.out 差异 → 输出
  `MISMATCH ... seed=20260927 ... reproduce with: parity/verify_bpf.sh 20260927 400 80` 且退出 1。
  顺带修掉 fuzz 构建（nightly）唯一告警：`AtomicU64::fetch_update` 被改名 `try_update`（1.88 尚无新名），
  `ring_buffer.rs::release` 改为与 `reserve` 同形的 CAS 环，并加
  `releasing_more_than_was_reserved_saturates_at_zero` 钉住“重复释放不得把 used 回绕成天文数字”。
  actionlint 1.7.12 对两份 workflow 零告警。
- ✅ **P5-28 deny 收紧 + 覆盖 fuzz workspace**：`wildcards` 与 `unknown-registry`/`unknown-git` 提到 `deny`。
  为让 workspace 内部无版本 path 依赖合法，7 个成员显式声明 `publish = false`（事实成立：path 依赖无版本、
  `repository` 指向上游 C/Go 树，本就不可发布）并配 `allow-wildcard-paths = true`；
  `[licenses.private] ignore` 保持 false，私有 crate 的许可证照旧检查。fuzz 独立 workspace 采用
  **“CI 里对该目录再跑一次”**（`cargo deny --manifest-path crates/cpworker/fuzz/Cargo.toml check`，复用根
  deny.toml），而不是把 fuzz 并入主 workspace —— 后者会让 nightly + libfuzzer 依赖污染 stable 依赖图，且
  `cargo fuzz` 本身就要求 publish=false 的独立 workspace。前置 `cargo metadata --locked` 断言两份 lockfile
  不漂移。首次覆盖即抓到真问题：`libfuzzer-sys 0.4.13` 许可证为 `(MIT OR Apache-2.0) AND NCSA` →
  白名单补 `NCSA`（注明仅 fuzz 开发依赖、不进任何发布产物）；`cpworker-fuzz` 缺 `license` 字段（cargo-deny
  视为硬错误）→ 补 BSD-3-Clause。反向验证：插入 `byteorder = "*"` → `error[wildcard]`；
  `allow-registry = []` → 多条 `error[source-not-allowed]`；人为让 Cargo.lock 过期 → `cargo metadata --locked`
  退出 101；CI 的 GPL grep 断言仍为空。
  Dependabot 同步补了 `directory: /crates/cpworker/fuzz` 条目，让这份 lockfile 也能收到升级 PR
  （此前只有检查、没有更新渠道）。
- ✅ **P5-30 仓库约定文件**：`CONTRIBUTING.md`（门禁清单 + 每条门禁对应哪个历史缺陷、red→绿 纪律、无 C 库
  政策、加 fuzz target / 加对拍用例 / 跑 live 测试的具体步骤、提交与评审约定）、`CHANGELOG.md`
  （Keep-a-Changelog：`[Unreleased]` = M5 全部改动，`[0.9.0]` 按 WP1–WP4 归类并附 commit 与实测证据）、
  `.github/CODEOWNERS`、`SECURITY.md`（输入面表、结构性防护、能力/监听端口部署指引、**CPM
  `danger_accept_invalid_certs(true)` 已知 TLS 缺口与缓解措施**、上报通道与响应预期）。
- ✅ **P5-18 文档矛盾清零**：`PARITY.md` 头部“纯 Rust 尚未完成”→ 已完成；§1.1 的“ZMQ 仍用 libzmq”、
  “⚠️ 仍链接 libpcap”→ 纯 Rust（并注明配置键 `libpcap` 为兼容 C/Go 配置文件而保留）；§5.1 首行
  “去 libpcap/libzmq：未完成”整条删除、§5.3 改为“已完成、不再在此跟踪”；§1.3 计数一次改齐
  （C 向量 34、Go 6 个测试函数 → 8 个 Rust 测试、165 passed / 3 ignored、cpgolib+cpctl 7+2）；
  `IMPROVEMENT_PLAN.md` 删除与“✅ libpcap 已移除”并存的“⬜ libpcap 待移除”，并把 BPF 语法与 AF_PACKET
  描述同步到 M1/M2 之后的现状；README 快速上手不再指向仓库里不存在的
  `../cpworker/examples/libpcap_null.json`，改用仓库内新增、且实际运行过的
  `crates/cpworker/examples/live_null.json` 与 `pcap_file_replay.json`（后者 200 包进 / 200 包出且 tcpdump
  可读；前者 root 下在 lo 建任务成功并写出 pcap）；目录树 `capturer/ # libpcap, pcap_file` 更正为
  af_packet/pcap_file，并补 bpf/、zmtp/、examples/、fuzz/。
- ✅ **P5-19 基准重跑（离线三场景）**：纯 Rust reader 上线后重测（1M 包 / 417 MB、median of 5、连续两次独立
  运行）：`null` Rust 0.201/0.203 s vs C 0.303/0.301 s（**1.48–1.51×**）、`file` 0.549/0.543 vs 0.738/0.754
  （**1.34–1.39×**）、`vxlan-split` 8.995/8.852 vs 9.373/9.658（1.04–1.09×，kernel `sendto` 受限 → 读作
  “无回归”）、峰值 RSS **2.8 vs 7.3 MB（约 -62%）**。README 表格整体替换并标注来源与环境（旧表是 libpcap
  时代数字；本机内核已从 6.14 变为 7.0.0-34，绝对值不可跨机比较，只看比值）。新增 `bench/live_bench.py`：
  手工、需 root 的实时抓包 A/B，报“每百万捕获帧 CPU 秒”，并把 `cap_packets` 与发包数并列以便判断是否真的
  收全 —— 该测量暴露的“同流不同包数”已登记到 §5-6，**未据此下任何性能或一致性结论**。
- ⚠️ **P5-29 保守处理，未做**：`crates/cpworker/src/bin/` 的 7 个 parity/oracle 工具仍随默认 `cargo build`
  编译。原因：`run.sh / verify_config.sh / verify_req.sh / fuzz_proto.sh / fuzz_rpc.sh / verify_zmtp.sh /
  verify_bpf.sh` 全部按 `cargo build -p cpworker --bin X` + `target/debug/X` 调用；加 `required-features` 或
  移入 `examples/` 需同步改 7 处脚本与 CI `parity` job，而且这些 bin 会因此**退出
  `cargo clippy --workspace --all-targets` 的 lint 覆盖**（静默变差）。若要动，建议：新建 bin-only crate
  `crates/cpworker-parity`（留在 workspace 但不属于发布产物集合），脚本改为 `-p cpworker-parity`，并在
  `verify_hygiene.sh` 补一条“每个 oracle bin 必须被某个脚本引用”的门禁。根目录审计/计划文档保持原位。
- 验证：`cargo build --workspace --locked` ok；`cargo fmt --all -- --check` ok；
  `cargo clippy --workspace --all-targets -- -D warnings` 0 告警；`cargo test --workspace`
  **165 passed / 0 failed（3 个 live 测试 `#[ignore]`）**；`cargo deny check`（根 + fuzz workspace）四项 ok；
  `./parity/all.sh` **9/9 绿**；`./fuzz.sh --check` 9 个 target 无崩溃；actionlint 零告警。

### 下一步

- ✅ **§5-6 已定根因**（A1）：veth 上 Rust `frames/datagram == 1.0000`，无缺陷；
  diff 来自 loopback 双 tap + `ps_recv` 计数口径 + bench 的 C 侧控制协议不兼容。
  可选的后续：把“veth + 可控注入 + 帧数断言”做成采集保真度门禁（见下）。
- **P4.1**（IMPROVEMENT_PLAN）：`vxlan-split` 在服务器硬件上复测（需固定 CPU、关频率调节）。
- 可选加固：把 `actionlint` 固化成 CI job；给 coverage 设阈值（目前仅 advisory artifact）；
  新增基于 veth 的采集保真度门禁（每帧断言 `frames/datagram == 1.0`，需 privileged job）。


## 7. 补充修复（三篇 AUDIT4 + 用户复核）

- ✅ **P5-08 主机名多地址**（M1 漏项）：`bpf/parser.rs` 的 `host <name>` 现按 OR 展开**全部**
  A/AAAA 地址（此前只取首个，回环放大的风险仍在）；BPF 差分生成器新增 `host localhost` 用例
  （本应能捕获此缺陷）。
- ✅ **H4 剩余部分（挂载规模）**：实测 N=100 → `ENOMEM`（`net.core.optmem_max`）、
  N≥150 → `EINVAL`（>4096 指令）。capturer 在 `SO_ATTACH_FILTER` 失败或程序 >
  `bpf::BPF_MAXINSNS`(4096) 时**回退用户态过滤**（在 VLAN 重插前判定，语义与内核过滤一致），
  live 测试验证 4531 条指令仍能正常抓包。
- ✅ **M3 引入的回归（DNS 阻塞抓包线程）**：`zmtp` 重连时的 DNS 重解析改为后台线程
  （`BackgroundResolver`），`resolve()` 立即返回缓存并异步刷新；首次解析在任务装配阶段完成。
  新增回归测试"worker 阻塞时 `resolve()` 不阻塞调用方"。


## 8. M6 — 两篇独立审查（GLM-5.3 / qwen3.8）P2 批次整改

审查基线 `b60c8a6`（其后的 `3755f95`/`628b5bc` 已处理 P1 loopback 重复采集）。本节按优先级逐条登记，
每条都有"修复前会失败"的回归测试与红→绿实测输出。

| # | 缺陷（审查编号） | 修复 | 红→绿证据 |
|---|---|---|---|
| P2-7 | VLAN 重插突破 snaplen：`caplen` 可达 `snaplen+4`，违反"每包 ≤ snaplen"契约（同条件 tcpdump 给 `caplen==snaplen`） | `insert_vlan()` 改为 `Some((caplen+4).min(snaplen))`（tag 计入 snaplen，被推过上限的尾部字节不报告），返回 `Option` 让调用方知道"是否真的重插"，`orig_len` 仍 +4 | 单测 `insert_vlan_truncated_frame_stays_within_snaplen`：`caplen 20 broke the 'never more than snaplen (16)' contract` → ok；live `live_capture_reinserts_vlan_on_veth` 增加 `snaplen:16` 阶段：`frame 0: caplen 20 exceeds the configured snaplen 16 (P2-7)` → ok（真 veth 实测） |
| P2-3 | `verify_hygiene.sh` 四条门禁全部可被**等价改写**绕过（注入后 4 条仍 ✅、EXIT=0） | ① 逐块判定测试代码 + 新增"测试块之后不得再有生产条目"门禁（`verify_liveness.sh` 同步）；② 覆盖 `as libc::c_int`/`as u32`/`as _` 全部写法并把范围扩到所有反序列化文件 + 新增"读 serde_json 数字的文件不得用 `as` 窄化"整文件规则；③ `[[bin]]` 改用 `cargo metadata --no-deps` 且双向校验；④ P5-22 改成"正向断言"（文档声称 fsync ⇒ flush() 必须真的 `sync_all`） | 新增 `parity/verify_hygiene_reverse.sh`（7 个等价改写注入，全部要求变红）。同一份注入树对照：旧门禁 4 ✅/EXIT=0，新门禁 6 ❌/EXIT=1。副产物：抓到并修复 `cripid` 的 `pid as i32`（4294967296→PID 0） |
| P2-2 | `af_packet_live` 非 root 时打印 `ok. 4 passed`（CI 特权 job 可全绿零执行） | `!privileged()` → `assert_privileged()` **panic**；CI 断言 `--ignored --list` 条数（≥4）== `test result: ok. N passed; 0 failed` | uid=1000：修复前 `ok. 4 passed`（exit 0）→ 修复后 `FAILED. 0 passed; 4 failed`（exit 101）；root：`ok. 4 passed`（exit 0） |
| P2-10 | BPF 编译期 DNS 同步阻塞于持锁 reload（`mgr.lock().reload_from_file()`） | 新增 `bpf::GuardedResolver`：进程内 60s 结果缓存（≤512 名字）+ 单名 2s 预算（超时→带名字的 `TimedOut`，只让该 task 建不出来）；`task::reload_from_file(&Arc<Mutex<TaskManager>>)` 把"读文件+解析+名字解析"移出 mgr 锁（SIGHUP 与 `reload_config` RPC 两个调用点都改），`config.rs` 抽出 `effective_bpf()` 单一实现；`netns` task 不锁外预热 | 单测 `a_slow_lookup_is_given_up_on_within_the_budget`（400ms 解析 + 20ms 预算 → TimedOut，实际 <300ms）、`cached_names_are_reused_without_calling_the_resolver`、`the_cache_is_shared_between_clones`、`prewarming_resolves_what_the_compile_needs`、`warm_task_names_resolves_names_and_reports_bad_filters`；差异写进 `PARITY.md §2.5/§4` |
| P2-6 | down 接口忙轮询（4 个 down task = 30.2% 单核）+ 与 C 的 down-interface 差异未登记 | `ErrorBackoff`（1ms→100ms 封顶，成功即复位）**加**空读后 `poll(POLLIN,1ms)`（实测证明单靠 `Err` 退避不满足"CPU 不空转"：down 口只在断链瞬间返回一次 ENETDOWN，之后都是 EAGAIN）；`PARITY.md §2.6` 登记与 C 的三点差异 | 独占 veth 实测：4 down task 30.2%→3.2%、4 idle-up task 30.3%→3.2%、1 down task 18.5–22%→3.8–4.3%；保真度不变（10 万报文→10 万记录，ratio 1.0000）；单测 `hard_error_backoff_grows_saturates_and_resets`、`empty_read_always_waits_for_readability` |
| P2-8 | `net <name>` 仍只取首个解析地址（P5-08 只做了一半） | 选定"**全部地址 OR 展开**"（非拒绝主机名）：`net_expr()` + 纯函数 `net_masks()`（同网络去重；`mask` 形式只保留同族地址，全被滤掉则报错）；`mask` 不再做主机名解析。理由：拒绝会把现在能工作的过滤器变成 task 失败，而展开规模被 P2-9 的上限约束 | `net_name_expands_to_every_resolved_address`：`left: [(192.0.2.0, 255.255.255.0)] right: [192.0.2.0/24, 198.51.100.0/24]` → ok；`net_mask_without_matching_family_is_an_error` |
| P2-9 | 解析结果数量无上限 → DNS 数据可把程序推过 4096 指令而**静默退化**为用户态逐帧解释 | 新增 `MAX_RESOLVED_ADDRS=64`（越界报错含主机名 + 两个数量）；用户态回退打印可告警的 `bpf_userspace_fallback insns=N limit=4096 kernel=BPF_MAXINSNS`；解析改走可注入的 `Resolver` seam（`parse_with`），使上限与 OR 展开可离线测试 | `oversized_resolution_is_refused_by_name_not_silently_expand`（去掉上限即失败）；`userspace_fallback_warning_carries_the_instruction_count` |
### 低优先项（同批完成）

- ✅ **P2-4/P2-5 `bench/live_bench.py`**：统计读取失败输出 `"cap_packets": "unavailable"` + `stats_available:false`
  并以退出码 3 结束；`cap==0 && sent>0` 打印 `!! <name> captured NOTHING` 并退出 2（真实验证：在 veth 上抓包、
  却向 127.0.0.1 注流 → 退出码 2，而修复前只会输出 `null`）；灼流目标参数化：`FLOOD_DST` 优先，非 lo 接口改为
  **从其 veth peer 注入原始帧**（本机同侧 UDP 会被内核走 lo，这正是"请用 veth"做不到的根因）；
  `bench/live_bench.py --selftest` 覆盖分类逻辑（旧逻辑下 4 项 FAIL）；`worker_cpu()` 改为直读 `/proc`，
  不再 `pgrep -f` + `cat`（GLM 观察项：会误匹配、且 pid 竞态会往 stdout 吐错误）。
  veth 实测：103 879 报文 → cap_packets 103 879，ratio 1.0000，EXIT=0。
- ✅ **P3（qwen P3-1）`zmq.hwm` 重复校验死码**：删除恒假的第二道检查，只留 `i32_in`；回归断言"用户可见消息里不得有连续空格"。
- ✅ **P3（qwen P3-3）`parse_control()` cmsg 数据上界**：补 `CMSG_OK` 等价检查；回归构造"头部谎报长度 + 越界区放一条合法 AUXDATA"，
  修复前会读出内核从未发出的 VLAN tag（`Some(VlanTag { tci: 356, tpid: 33024 })`）。
- ✅ **P3（qwen P3-2）`build_task()` 部分失败绕过 `destroy()`**：新增 `PendingOutputs`（其 `Drop` 逐个 `destroy()`，
  成功路径 `finish()` 移交后为空操作）；单元测试钉住"三个 output 全部被 destroy"与"finish() 后 Drop 不动作"，
  并在 `verify_liveness.sh` 加一条门禁（文件型 output 端到端看不出来：`BufWriter` 自身 `Drop` 会 flush）。
- ✅ **P3（qwen P3-8）BPF 编译失败时整条表达式落盘**：`expr_preview()` 限长 120B（按 UTF-8 边界回退）并标注原长度。
- ✅ **P3（qwen P3-4）`PACKET_STATISTICS` 节拍混用包时间戳与墙钟**：收包分支改用 `now_sec()`，节拍只有一个时钟源。
- ✅ **P3（GLM P3-1）MSRV job 覆盖 dev-deps/测试**：`cargo build --workspace --all-targets --locked`（本机 1.88.0 实测通过），
  README/CONTRIBUTING 措辞同步。
- ✅ **P3（GLM P3-2/P3-5）fuzz 入口的 lockfile 与工具版本**：`fuzz.sh`/`parity/difffuzz.sh` 固定 `cargo-fuzz 0.13.2`，
  并在入口对**两份** lockfile 跑 `cargo metadata --locked`（cargo-fuzz 0.13.2 无 `--locked` 可转发，已核实其 `--help`）。

### 明确未完成 / 待决

- **qwen P3-6（基准精度夸大）**：本轮未改 README/`bench/RESULTS.md` 的数字呈现（补 `REPEAT/N/min-max`、改为追加而非覆盖）。
  属文档/流程项，与本轮缺陷无因果关系，建议单独一批。
- **qwen P3-7 的 fuzz 超时**：`fuzz.sh` smoke 仍只有 `-rss_limit_mb`，未加 `-timeout=`，所以"构造输入导致的近挂死"
  （例如超大用户态过滤）仍不会被 smoke 发现。加 `-timeout=10` 是一行改动，但它会让既有 corpus 中的慢用例变成红灯，
  需要一次实际的 corpus 评估，未纳入本轮。
- **qwen §4-5 / §4-7（门禁盲区：整文件输出对拍、veth 保真度硬门禁）**：`live_bench.py` 现在真的能在 veth 上跑出
  ratio 1.0000，但把它固化成 privileged job 的硬断言（发 N 帧 ⇒ `cap_packets == N`）仍未做——需要 CI 里的 veth/注流权限与速率上限，
  属独立工程项（`§5-7` 原判断不变）。
- **qwen §5-1（libpcap 为何只交付 lo 的一半副本）**：仍未做源码级确认；本轮只对齐了**可观测行为**（`PACKET_IGNORE_OUTGOING`）。
- **GLM P3-3（cargo-audit 只审计根 lockfile）**：未加 `--file crates/cpworker/fuzz/Cargo.lock`；fuzz 侧 advisories 目前由 cargo-deny 覆盖。

