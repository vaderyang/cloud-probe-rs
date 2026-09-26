# cloud-probe-rs P3（去 C 依赖）实现审计报告

- **审计日期**：2026-09-26
- **审计对象**：P3 里程碑的 9 个提交（`1dbf44a` … `95e56fb`）：纯 Rust pcap 读写、BPF 子集
  编译器 + cBPF 解释器、ZMTP 3.x PUSH 客户端、AF_PACKET 实时采集、覆盖引导的 C/Go 差分 fuzz
- **审计方法**：逐组件人工审查（FFI 移除、字节序、unsafe、wire 格式）+ 差分对拍实测 + fuzz
  smoke + 全量测试 + 3M 包 A/B 吞吐验证

## 总体评价：A-（实现质量高，但存在一个未被发现的关键 bug，已修复）

P3 的架构决策与实现质量整体优秀：**`pcap`/`zmq` 依赖彻底移除**（Cargo.lock 无 libpcap/libzmq，
无 FFI 残留），测试 71→106，unsafe 仅 +4（28 处全部有安全注释）。但审计发现 **P3.1 采集侧
存在一个关键回归**（`read()` vs `read_exact()`，见 §2.1），该 bug 在 3M 包重放中导致 reader
提前停止——差分测试与 fuzz 均未覆盖此路径，由基准 A/B 暴露。**已修复并验证**（`9ad3f22`）。

## 1. 各组件审计

### 1.1 纯 Rust pcap 文件读写（`8eadeb0`）

- `output/pcap_writer.rs`：**0 unsafe**，直接写经典 pcap 格式（24 字节全局头 + 16 字节记录头），
  替换了原 libpcap `pcap_dump_*` FFI 层。质量良好。
- `capturer/pcap_file.rs`：字节序检测正确（4 种 magic 变体全覆盖：LE/BE × usec/nsec）。
  **但发现关键 bug，见 §2.1。**

### 1.2 BPF 子集编译器 + cBPF 解释器（`9b6a1f2`）

- `bpf/` 模块：`parse`（tcpdump 子集 AST）→ `compile`（cBPF 指令）→ `attach_filter`
  （`SO_ATTACH_FILTER`）或内置解释器（离线回放）分离清晰；平台中立（仅 attach 是 OS 特定）。
- **差分对拍实测通过**：`parity/verify_bpf.sh` 以 libpcap `pcap_compile`/`pcap_offline_filter`
  为 oracle，80 表达式 × 400 包**逐包判定一致**。
- 仅 1 处 unsafe（`SO_ATTACH_FILTER` setsockopt，带 SAFETY 注释）。

### 1.3 ZMTP 3.x PUSH 客户端（`5984f67`、`5b58058`）

- `zmtp/` 模块：**0 unsafe**；wire 格式正确（64 字节 greeting、NULL mechanism、v3.1、
  `READY` + Socket-Type 元数据、帧化消息）。
- 设计优秀：`Transport`/`Connector` trait 使状态机可由脚本化 mock 驱动（测试与 fuzz：
  畸形 peer 字节、截断、断连、错误 socket 类型）。
- HWM 行为对齐 libzmq `zmq_send(..., ZMQ_DONTWAIT)`（队列满即丢弃）。
- fuzz smoke 实测：`zmtp_wire` 896k runs / `zmtp_client` 113k runs，无崩溃。

### 1.4 AF_PACKET 实时采集（`00022ae`）

- 11 处 unsafe 全部健全（`if_nametoindex` 判空、`OwnedFd`、`sockaddr_ll` zeroed、errno 检查）。
- **已知取舍诚实记录**（PARITY.md §4）：`recvmsg` 而非 libpcap 的 TPACKET_V3 mmap 环形缓冲，
  高吞吐下丢包特征可能不同；`PACKET_STATISTICS` 的 `tp_drops` 语义已对齐。
- `af_packet_live.rs` 集成测试需 root + 真实接口（CI 跳过，合理）。

## 2. 🔴 发现的关键 bug（已修复，`9ad3f22`）

### 2.1 `read()` vs `read_exact()`：位置漂移 + 垃圾包转发

- **位置**：`crates/cpworker/src/capturer/pcap_file.rs` `PcapReader::next()`
- **问题**：16 字节 record 头用 `self.r.read()` 读取。当 record 头**跨越 BufReader 8KB 内部
  缓冲边界**时，`read()` 返回 `Ok(k<16)`，这 k 个字节被消费并**丢失**——文件位置漂移，后续
  record 全部错位解析。
- **触发条件**：文件 > 8KB 且 record 头恰好跨界（随机大小下概率约 0.2%/record）。
  3M 包重放在 record 155846（~67MB，首个跨界点）停止。
- **危害**（两层）：
  1. reader 提前停止（EOF 误判），重放不完整；
  2. EOF 误判后主循环继续轮询（`capture_once` 无 eof 前置守卫），reader 在文件尾游走，
     把 payload 字节当 packet **转发到输出**——对 null 无害，对 GRE/VXLAN/ZMQ 是垃圾上线路。
- **为何未被发现**：单测用小 pcap（<8KB 不触发）；fuzz 目标不含 file reader；
  差分对拍覆盖 config/协议而非文件读取端到端；基准只测吞吐不校验正确性。
- **证据链**：C（libpcap）读同一 3M 文件正常（1.10s）；Rust reader 报垃圾 caplen
  （1749737517 等）后停止；Python 独立扫描确认 3M 条记录全部合法；垃圾值定位到
  offset 67452952（record 155846 内部 114 字节处）。
- **修复**：`read_exact`（clean EOF = `UnexpectedEof`）+ 大文件回归测试
  （`pcap_reader_large_file_no_position_drift`，1000 条可变大小 record，头部必然跨界）。
- **修复后验证**：错误 0；3M 包 null 重放 **Rust 0.70–0.73s vs C 1.10–1.13s（Rust/C = 0.64，
  ~35% 快于 libpcap fread 路径）**。

## 3. 验证结果（审计时点）

- `cargo test --workspace`：**107 passed**（含新回归测试），0 failed
- `cargo clippy --workspace --all-targets -- -D warnings`：0 告警
- `cargo fmt --all -- --check`：干净
- `cargo deny check`：四项 ok；**Cargo.lock 无 libpcap/libzmq**
- BPF 差分对拍：80 表达式 × 400 包与 libpcap 逐包一致
- fuzz smoke：`zmtp_wire` 896k / `zmtp_client` 113k / `bpf` 141k runs，无崩溃
- 3M 包 A/B（null，纯 Rust reader 修复后）：Rust **0.70s** vs C 1.10s（快 ~35%）
- CI `main@95e56fb`：全绿（修复提交 `9ad3f22` 的 CI 同样通过）

## 4. 遗留问题与建议

| 级别 | 问题 | 建议 |
|---|---|---|
| 中 | README/RESULTS.md 基准表仍是 libpcap 时代的数字，未反映纯 Rust reader | 重跑三个场景基准并更新表格（含新的 ±35% null 结果） |
| 中 | file reader 无 fuzz 目标 | 增加 pcap reader fuzz（畸形 record 头、截断、错误字节序、跨边界） |
| 低 | AF_PACKET 路径无 C 差分对拍（需真实接口） | 在有 root 的环境跑 `af_packet_live.rs` 并对拍 libpcap 抓包 |
| 低 | PARITY.md §4 已记录 recvmsg 取舍，但未记录 `read_exact` bug 的教训 | 在 PARITY.md 增补：端到端大文件差分是必要门禁 |
| 低 | Windows 延展性（§4）仅在文档层面 | 维持现状即可 |

## 5. 结论

P3 实现质量整体优秀：依赖彻底移除、模块设计清晰（trait 化状态机、平台中立 BPF）、
测试从 71 增至 106、unsafe 纪律严格、文档诚实记录已知取舍。审计发现的
`read()` vs `read_exact()` 关键回归已修复并验证——修复后纯 Rust reader **比 libpcap 快 ~35%**，
这也证明了"纯 Rust"路线在性能上不仅可行而且有优势。教训明确：**端到端大文件差分测试是
移植类工作的必要门禁**，仅靠小样本单测与吞吐基准会漏掉这类只在真实文件上暴露的 bug。
