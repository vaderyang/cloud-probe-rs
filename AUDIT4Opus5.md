# cloud-probe-rs 代码与工程质量审计报告（第四次审计）

- **审计日期**：2026-09-26
- **审计对象**：`cloud-probe-rs` @ `main`（`95e56fb`）
- **审计重点**：P3（去 C 依赖）新增的纯 Rust 代码——`capturer/pcap_file.rs`、
  `capturer/af_packet.rs`、`bpf/`、`zmtp/`、`output/pcap_writer.rs`；前三次审计均早于 P3
- **审计方法**：逐文件人工审查并对照原 C 实现（`netis/cloud-probe` `cpworker/src/libpcap.c`、
  `output_zmq.c`）；本地全量验收（fmt / clippy `-D warnings` / test / deny）；
  对可疑点编写独立复现程序实测（pcap 失步、BPF 跳转上限）

## 总体评价：B+

工程体系仍是 A 级水准，但 P3 新写的纯 Rust 代码存在数处**真实缺陷**，且现有测试均未覆盖
（小输入单测、实时抓包测试 `#[ignore]`、差分对拍表达式过短）。

---

## 一、基线验证（本地实测）

| 项 | 结果 |
|---|---|
| `cargo fmt --all --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ 0 告警 |
| `cargo test --workspace` | ✅ **106 passed**，1 ignored（`af_packet_live`，需 root） |
| `cargo deny check` | ✅ advisories / bans / licenses / sources 四项 ok |
| unsafe | 28 处，均有 SAFETY 注释；平台相关代码均 `cfg(target_os = "linux")` 隔离 |

测试分布：cpworker 77 / cpsim 11 / cpdaemon 10 / cpgolib 7 / cpctl 2 / cripid 0 / dockerpid 0。

---

## 二、代码质量问题（按严重度）

### 🔴 高

#### H1. pcap 文件回放失步并产出垃圾包

- **位置**：`crates/cpworker/src/capturer/pcap_file.rs:75`
- **问题**：16 字节记录头用 `self.r.read(&mut rec)` 读取并要求 `Ok(16)`。当记录头跨越
  `BufReader` 缓冲区边界时，`read` 合法地返回短读，被误判为 EOF 并打印 `end of file`；
  但已读字节已被消费，后续调用从错位偏移继续解析，**持续输出垃圾记录**。
- **实测复现**：写入 1000 个 100 字节包 → 第 141 个包后全部错乱（`ts_sec`/`caplen` 失真），
  共读出 1011 个包。复现程序：scratchpad `pcapchk/`（以 path 依赖 cpworker，调用
  `capturer::new_capturer` 回放自生成的 pcap）。
- **为何未被发现**：`pcap_roundtrip` 单测只写 1 个包；`tests/pcap_file_filter.rs` 文件很小。
- **连带影响**：README 基准依赖 `pcap_file` 回放且以 `end of file` 为计时终点，现有数据是
  libpcap 时代测得（README:226 "Both use libpcap"），纯 Rust 读取器上线后未重跑。
- **修复**：改用 `read_exact`，区分 `UnexpectedEof`（正常结束 / 截断）；加跨 8 KiB 边界的
  回归测试（≥1000 包）。

#### H2. AF_PACKET 丢包统计语义错误

- **位置**：`crates/cpworker/src/capturer/af_packet.rs:336-338`
- **问题**：Linux `getsockopt(PACKET_STATISTICS)` **读后清零**，返回的是自上次读取以来的增量
  （libpcap 在 `pcap_stats_linux` 中累加这些增量）。Rust 沿用了 C 的"累计值相减"写法
  `drop.wrapping_sub(self.prev_ps_drop)`。
- **后果**：当本窗口丢包数小于上窗口（如上窗口 5、本窗口 0）时，`drop_packets` 一次性加上
  约 **4.29×10⁹**；其余情况也是错误值。
- PARITY.md §4 声称 "`tp_drops` 语义已对齐"——与实际不符。
- **修复**：直接累加 `st.tp_drops`（首次读取仅用于清零基线）；`ifdrop` 恒为 0 的死代码一并删除。

#### H3. 抓包丢失 802.1Q VLAN 标签

- **位置**：`af_packet.rs`（未启用 `PACKET_AUXDATA`）
- **问题**：内核在 `__netif_receive_skb_core` 中先 `skb_vlan_untag` 再投递给 `ptype_all`，
  AF_PACKET 收到的帧不含 VLAN 头，TCI 仅通过 `PACKET_AUXDATA` 控制消息提供。libpcap
  （`pcap-linux.c`）据此把 VLAN 标签重新插回帧中；Rust 实现未做。
- **后果**：trunk / 镜像口上转发的 GRE/VXLAN/ZMQ 包缺失 VLAN 信息；ZMQ 输出中的 VLAN 处理
  逻辑在实时抓包路径上成为死代码。与 C 版行为不一致且无文档记录。
- **置信度**：依据内核行为推断，建议在带 VLAN 的接口上实测确认。
- **修复**：`setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)`，解析 `tpacket_auxdata`，
  `TP_STATUS_VLAN_VALID` 时在 MAC 地址后插入 4 字节 VLAN 头（TPID 取 `tp_vlan_tpid`，缺省 0x8100）。

#### H4. 输出主机较多时 BPF 编译失败，worker 无法启动

- **位置**：`crates/cpworker/src/bpf/compiler.rs` `Builder::finish()`
- **问题**：跳转偏移超过 255 直接报错，未实现 libpcap 的长跳转（`JA` 跳板）。而
  `config.rs` 的 `bpf_filter_exclude_task_output_hosts` **默认开启**，会把全部 task 的输出主机
  拼成 `and not host X`。
- **实测**：`port 80` + 12 个 `not host 10.0.0.N` → `bpf: filter too complex (jf > 255)`，
  capturer 创建失败；10 个时仍可编译。同配置在 C 版正常。
- **为何未被发现**：`parity/gen_bpf_cases.py` 生成的表达式都很短。
- **修复**：偏移超限时插入 `JMP_JA` 跳板（k 为 32 位）；在 BPF 对拍中加入长表达式用例
  （20+ 主机排除）。

### 🟠 中

#### M1. 主机名只取第一个解析地址

- **位置**：`crates/cpworker/src/bpf/parser.rs:468-472`
- libpcap 的 `host <name>` 对所有 A/AAAA 结果生成 OR；Rust 仅取 `.next()`。输出主机名解析为
  多个 IP 时，自动排除规则漏掉部分地址，探针可能抓到自身发出的镜像流量，形成**回环放大**。

#### M2. 接收缓冲区被 `rmem_max` 静默截断

- **位置**：`af_packet.rs:77-90`
- `SO_RCVBUF` 受 `net.core.rmem_max`（默认约 208 KB）限制，配置的 `buffer_size_mb`（如 64 MB）
  实际只生效几百 KB，且 setsockopt 不报错、日志无提示。libpcap 使用 buffer_size 大小的
  TPACKET mmap 环形缓冲。突发流量下丢包会显著多于 C 版。
- **修复**：优先 `SO_RCVBUFFORCE`（README 的 setcap 已授予 `CAP_NET_ADMIN`），失败回退
  `SO_RCVBUF`；用 `getsockopt` 读取实际值并记录日志。

#### M3. 持续错误时日志刷屏 + CPU 空转

- **位置**：`af_packet.rs:393-408`
- C 版（`libpcap.c`）的错误日志位于 2 秒统计窗口门控之后，最多每 2 秒一次；Rust 每次
  `capture_once` 都 `take()` 并打印。接口被删除 / down（容器场景常见）时，`poll` 立即返回
  POLLERR → `recvmsg` 失败 → 紧循环 + 日志洪泛。
- **修复**：错误日志与 `DROP_STAT_DUR_SEC` 窗口对齐，或做速率限制；持续错误时退避。

#### M4. 启动时的过滤空窗

- **位置**：`af_packet.rs:70`（`socket(..., ETH_P_ALL)`）→ `:99`（bind）→ `:244`（attach BPF）
- socket 创建即以 `ETH_P_ALL` 接收**所有接口**的流量，直到 bind 与挂载过滤器之前，未过滤的包
  已进入接收队列，首批包可能来自其他接口或不匹配过滤器。
- **修复**：`socket(AF_PACKET, SOCK_RAW, 0)` → 挂载过滤器 → `bind(ETH_P_ALL, ifindex)`；
  或参照 libpcap 先挂 reject-all 过滤器并清空队列。

#### M5. ZMTP 握手无超时

- **位置**：`crates/cpworker/src/zmtp/client.rs`
- 对端接受 TCP 但不发送 greeting / READY 时，连接永久停留在 `Greeting`/`Ready` 阶段，消息攒满
  HWM 后被静默丢弃。libzmq 默认 `ZMQ_HANDSHAKE_IVL = 30s`。
- **修复**：记录连接建立时刻，握手超时即 `schedule_reconnect()`。

#### M6. 实时抓包路径无性能数据

- `timeout_ms > 0` 时每包 `poll` + `recvmsg` 两次系统调用；PARITY.md 已记录 recvmsg vs
  mmap ring 的取舍，但 README 基准只覆盖离线回放，AF_PACKET 吞吐 / 丢包从未测量。
- **修复**：先非阻塞 `recvmsg`，EAGAIN 后再 `poll`（或 `recvmmsg` 批量）；补实时抓包基准。

### 🟢 低

| 问题 | 位置 |
|---|---|
| 零引用依赖（P3 后重新出现）：cpworker `thiserror`/`env_logger`/`byteorder`；cpctl `serde`/`env_logger`；cpgolib `anyhow`；cpdaemon `libc` | 各 `Cargo.toml` |
| `parse_timestamp` 按 64 位 `cmsghdr` 布局硬编码，应使用 `libc::CMSG_FIRSTHDR/CMSG_NXTHDR/CMSG_DATA` | `af_packet.rs:129` |
| pcap 读取不校验 linktype（默认按 Ethernet）、不校验 `len >= caplen` | `pcap_file.rs` |
| `PcapWriter` 文档称 "call flush to fsync"，实际只 flush 到 OS，无 fsync | `output/pcap_writer.rs:22` |
| HTTP 端口解析失败静默回退到 9022 | `cpdaemon/src/main.rs:211` |

---

## 三、工程质量

### 3.1 优点（保持）

- C / Go 差分对拍（7 类 harness）+ 覆盖引导差分 fuzz + DST 确定性仿真 + 9 个 fuzz target，全部进 CI。
- 供应链：cargo-deny（宽松许可证白名单 + GPL 防护断言）、cargo-audit、dependabot、dependency-review。
- 基准方法论严谨（同输入 / 中位数 / perf 根因分析）。
- 审计 → 计划 → 实施 → 复核 → 整改的闭环文化。

### 3.2 问题

| 问题 | 说明 |
|---|---|
| **文档自相矛盾** | PARITY.md 第 6 行"纯 Rust **尚未完成**"、第 21-22 行"ZMQ 仍用 libzmq / ⚠️ 仍链接 libpcap"、第 268 行"未完成"，与 §4"已完成"矛盾；IMPROVEMENT_PLAN.md 同时存在"⬜ libpcap 待移除"与"✅ 已移除"；README 第 92、127、226 行仍描述 libpcap capturer |
| **Release 流水线过时** | `.github/workflows/release.yml:43` macOS 仍 `brew install libpcap zeromq` |
| **MSRV 未验证** | 声明 `rust-version = 1.88`，但所有 CI job 使用 stable，无 1.88 工具链 job |
| **CI 非确定** | `parity/all.sh` 中 `verify_bpf.sh` 种子为 `$RANDOM`，同一 commit 两次运行用例不同 |
| **测试盲区** | 实时抓包在 CI 中零覆盖（唯一测试 `#[ignore]`）；pcap 读取仅 1 包单测；`output/*`、`task.rs`、`unix_manager.rs` 无单元测试；cripid / dockerpid 0 测试。**本次 H1–H4 全部落在这些盲区** |
| **产物混杂** | 7 个 parity / oracle 工具位于 `crates/cpworker/src/bin/`，随 `cargo build` 编译（release 通过 `--bin` 规避）；建议移到 `examples/` 或放在 feature 后。根目录 4 份审计 / 计划文档建议移入 `docs/` |

---

## 四、建议优先级

1. **立即修复 H1 / H2 / H4**：改动均很小，各配一个回归测试
   （≥1000 包跨缓冲区 pcap 回放；PACKET_STATISTICS 增量累加；20+ 主机排除表达式编译）。
2. **重跑基准**：H1 修复后重新执行 `bench/bench.py`，更新 README（现有数据来自 libpcap 版本）。
3. **补齐 libpcap 行为对齐**：H3（VLAN / AUXDATA）、M1（多地址）、M2（缓冲区）、M4（启动空窗）；
   CI 新增带 `CAP_NET_RAW` 的实时抓包 job（GitHub runner 可 sudo），覆盖 VLAN 与丢包统计。
4. **健壮性**：M3（错误日志限速）、M5（握手超时）、M6（抓包批量化 + 实时基准）。
5. **清理**：同步 PARITY / README / IMPROVEMENT_PLAN；修正 release.yml；删除零引用依赖；
   新增 MSRV job；固定 BPF 对拍种子（或在失败时打印种子）。

## 五、审计时点的验证结果

- `cargo fmt --all --check`：干净
- `cargo clippy --workspace --all-targets -- -D warnings`：0 告警
- `cargo test --workspace`：**106 passed**，0 failed，1 ignored
- `cargo deny check`：advisories ok / bans ok / licenses ok / sources ok
- H1 复现：1000 包写入 → 第 141 包起失步，读出 1011 包
- H4 复现：`port 80` + 12 × `not host` → `bpf: filter too complex (jf > 255)`
