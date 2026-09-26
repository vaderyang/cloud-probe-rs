# cloud-probe-rs 第四次审计：P3（纯 Rust 化）代码质量 + 工程质量独立审计

- **审计模型**：`netis/qwen3.8-flash-next`（pi 独立子进程，high thinking，无先前会话上下文）
- **审计日期**：2026-09-26
- **审计对象**：`main` @ `f838a0a`（含 P3 里程碑 8 个提交 `8eadeb0`…`95e56fb`，以及审计窗口内并发落入的 `9ad3f22`（pcap `read_exact` 修复）与 `f838a0a`（上一版 AUDIT4））
- **审计范围**：`crates/cpworker/src/bpf/`（1 631 行）、`capturer/af_packet.rs`、`capturer/pcap_file.rs`、`zmtp/`、`output/pcap_writer.rs`、`sockopt.rs`，以及工程质量面（CI/测试/依赖/文档/流程）
- **审计方法**：只读证据审计。逐文件人工审查 + 可执行验证：
  `cargo clippy --workspace --all-targets -- -D warnings`（**0 告警**）、`cargo test --workspace --locked`（**107 passed / 0 failed / 1 ignored**）、`cargo deny check`（**四项 ok**）、
  **本地实测 libpcap 与纯 Rust BPF 编译器的判定差异**（`parity/c_bpf.c` 编译为 `/tmp/c_bpf`，与 `target/debug/bpf_eval` 逐表达式对比）、
  实测 BPF 表达式嵌套深度导致的进程栈溢出、实测 `SO_RCVBUF` 内核截断行为、复核 AUDIT/AUDIT2/AUDIT3 全部历史结论。
- **说明**：仓库根另有一份维护者自审版 `AUDIT4.md`（提交 `f838a0a`）。本报告为独立复审，**单独存放为 `AUDIT4-qwenfn.md`**，不覆盖 `AUDIT4.md`；自审版仍可用 `git show f838a0a:AUDIT4.md` 取回。本次审计**推翻**了自审版"总体 A-"的结论（见 §5、§6）。
- **约定文件核查**：仓库**不存在** `CLAUDE.md` / `AGENTS.md` / `.cursorrules` / `CONTRIBUTING*` / `CODEOWNERS` / `SECURITY.md` / `CHANGELOG` / `rust-toolchain.toml`（`find` 全仓库确认）。因此该项无法判定"是否被遵守"，但缺失本身是工程发现（见 P2-12）。

---

## 1. 执行摘要

P3 的**架构决策是正确的，也是这批改动最有价值的部分**：`pcap`/`zmq` 两个 C 依赖被彻底移除（`Cargo.lock` 241 项中无任何 C 库，`cargo tree --workspace | grep -E "pcap|zmq"` 无输出），新增约 1 600 行 BPF、约 1 000 行 ZMTP、约 700 行 AF_PACKET/pcap 读写；新增代码共 **12 处 `unsafe`**（`capturer/af_packet.rs` 11 + `bpf/linux.rs` 1），**全部带 SAFETY 注释并逐项论证成立**；`zmtp/` 与 pcap 读写为 **0 unsafe**。cBPF 跳转偏移计算、`SO_ATTACH_FILTER` 的 `sock_fprog`/`sock_filter` 内存布局、ARP/IPv4/IPv6 头部偏移、ZMTP 3.x greeting 64 字节布局、帧长短/长格式、`read_exact` 修复——逐项核对**均正确**。测试从 71 增至 107，差分对拍新增 BPF/ZMTP 两路，fuzz 新增 3 个 target，DST 保留。

但**"移植完成度"与"文档声明"之间存在实质性缺口，且缺口落在产品主路径上**：

1. **自研 BPF 编译器在极常见的合法表达式上硬失败**。实测：`port 1000 or port 1001 or port 1002`（3 项）即报 `bpf: filter too complex (jt > 255)`；`not host` 链 ≥11 项失败；`host` 链 ≥12 项失败——而 libpcap 全部编译通过。原因：编译器未实现 tcpdump/libpcap 的 **"jump around"（JA 中继）跳转扩展**，`Builder::finish()` 只会报错（`bpf/compiler.rs:628-647`，`JMP_JA` 在 `codes.rs:44` 定义并已在解释器实现，却从未被发射）。而生产过滤器由 `config.rs:931-951` 自动生成 `(用户bpf) and not host H1 and … and not host HN`，**N 由所有 task 的转发目的主机数决定**——即"≥11 个 collector 端点"这一完全正常的部署规模会让该 task 静默地完全不抓包。
2. **BPF 子集缺失 tcpdump 核心语法**，且未在文档中声明。实测 libpcap=OK / Rust=ERR 的集合包括 `tcp dst port 80`、`udp src port 53`、`ether src host <mac>`、`ether dst <mac>`、`ip proto 6`、`greater 100`、`len greater 100`（`vlan 5` 是文档明确声明的唯一例外）。PARITY.md §4 只写"不支持的关键字（`vlan` 等）明确报错"，读者无法得知 `tcp dst port` 也不可用。
3. **`Output::destroy()` 全仓库从未被调用**（`output/mod.rs:49`、`file.rs:45`、`zmq.rs:460`；`grep -rn "destroy()" crates/` 无任何调用点）。因此 `zmq.rs:460-462` 承诺的 "mirrors ZMQ_LINGER=5s" **从未生效**：热重载（SIGHUP/RPC）与退出时，`pending` 队列里最多 `hwm`（默认 100）条 ×1 MiB 的批次被直接丢弃——相对 C（`zmq_close` 会 linger 阻塞发送）是**数据回归**。
4. **AF_PACKET 的 `SO_RCVBUF` 被内核静默降级，且无回读/告警**。实测本机：请求 256 MiB（`config.rs:792` 默认 `buffer_size_mb=256`）→ 内核实际应用 **8 MiB**（`net.core.rmem_max=4194304`；内核在 `SO_RCVBUF` 上按 rmem_max 截断）。未使用 `SO_RCVBUFFORCE`（部署已具备 `cap_net_admin`，`README.md:82`），未 `getsockopt` 回读，日志仍打印"成功"。对以"丢包测量"为核心功能的探针，这是静默的量级性容量缩水。
5. **`parity/verify_bpf.sh` 门禁当前是绿的**（本地实测：`OK: 96 expressions x 300 packets identical`），而上面 1/2 两项就在同一时刻失败。原因：`parity/gen_bpf_cases.py:93-110` 的模板每个布尔算子**最多 2 项**，`not host` 只出现 1 项，永远不触及跳转距离上限，也不覆盖生产形态的长排除链。差分门禁因此对"子集完备性/复杂度上限"完全盲区。

除此之外，**未发现任何内存安全缺陷**：无越界、无 unwrap panic 可达路径（新模块非测试代码里只有 2 个 panic 构造，均可证不可达）、`parse_frame`/`parse_metadata`/pcap 读取的长度校验完备、cmsg 解析有 `len<16`/`off+len>len` 双重守卫、fd 全部 `OwnedFd`。

**结论一句话**：设计优秀、纪律严格、但**功能完备性未达"可替换 libpcap"的声明标准**，且现有门禁（clippy/fuzz/差分/文档）都看不到这些缺口。P3 在补齐 §7 前 4 项之前不应作为发布里程碑。

---

## 2. 评分

| 维度 | 评级 | 一句话理由 |
|---|---|---|
| **代码质量** | **B-** | 结构与 unsafe 纪律达 A（新增约 3 300 行、共 12 处 unsafe 且论证均成立、无 UB、边界校验完备），但主路径存在实质性功能缺陷：BPF 子集与跳转上限使常见合法过滤器编译失败、`destroy()` 生命周期钩子从未被调用导致 ZMQ 优雅退出丢数据、`SO_RCVBUF` 静默降级、深嵌套表达式可栈溢出 abort。 |
| **工程质量** | **B** | CI/差分对拍/DST/覆盖引导 fuzz/deny/审计闭环属同类项目最佳梯队；但新采集路径在 CI 中零覆盖（`#[ignore]`）、BPF 差分生成器组合深度≤2 导致门禁假绿、文档（PARITY/README/IMPROVEMENT_PLAN/bench）与代码存在 11 处矛盾、MSRV 声明无验证、P3 自订的"独立 PR + feature flag 灰度"流程未执行。 |
| **综合** | **B（良好，未达"完成"）** | 移植方向与工程骨架无可挑剔，且已证明纯 Rust 可以更快；但"去 C 依赖"的**语义等价性尚未被证明**——被证明的是"被测试到的那部分等价"。当前状态适合灰度，不适合默认切换。 |

---

## 3. 逐维度检查表

### 3.1 代码质量

| 检查项 | 结论 | 关键证据 |
|---|---|---|
| BPF 跳转偏移（u8 / 255）计算正确性 | ✅ 算术正确、❌ 无溢出中继 | `compiler.rs:628-647` `off = target - (idx+1)` 符合 cBPF"相对下一条指令"语义；`u8::try_from` 拦截 >255 并报错（不会静默截断）；但未实现 tcpdump 的 JA 中继 → 见 P1-1 |
| cBPF 语义与 tcpdump/libpcap 对齐（两侧均可编译的子集内） | ✅ | 本地实测 19 组表达式 × 7 类报文（IPv4/IPv6/ARP/RARP/分片/短帧/随机帧）与 libpcap `pcap_offline_filter` 判定逐位一致（另 5 组为单侧拒绝，见 P1-2）；头部偏移 26/30（v4）、22/38（v6）、28/38（ARP SPA/TPA）见 `compiler.rs:259-345`；`4*([14]&0xf)` IHL、`jset #0x1fff` 分片偏移、IPv6 `0x2c` 后继头、`ret #0x40000` 等码生成见 `compiler.rs:565-604` 与 `:18/:107`，均与 tcpdump 生成码一致 |
| 子集完备性 / 不支持表达式的报错策略 | ❌ | `tcp dst port 80`、`ether src host`、`ip proto`、`greater`、`len` 实测被拒（`parser.rs:296-321`、`parser.rs:335-360`），文档只声明 `vlan`；报错文案清晰（"unsupported filter keyword 'vlan'"）✅ |
| 解释器越界/终止性 | ⚠️ | `interp.rs:11-16` `checked_add`+`get` → 越界 load 返回 0（与内核/libpcap `bpf_filter` 一致 ✅）；未实现 opcode → drop ✅；但 `JMP_JA` 用 `wrapping_add`（`interp.rs:56`）且**无执行步数上限**：构造一个含后向跳转的 `Program`（`Program.insns` 是 `pub`）可让 `evaluate()` 永久循环 → P3-6 |
| `SO_ATTACH_FILTER` unsafe 安全论证 | ✅ | `linux.rs:16-20` `SockFprog{u16,*const Insn}` + `Insn{u16,u8,u8,u32}` 均 `#[repr(C)]`，与 `struct sock_fprog`/`struct sock_filter` 布局与对齐一致（64/32 位皆同）；`linux.rs:34-36` SAFETY 注释成立（`prog` 借用在调用期内有效，内核同步拷贝）；`u16::try_from(len)` 防长度截断 ✅。缺口：>4096 条（`BPF_MAXINSNS`）只能在 attach 时得到 EINVAL；空程序静默 `Ok(())` 且不摘除旧过滤器（`linux.rs:26-28`）→ P3-8 |
| 内存安全与 `unsafe` 使用（整体） | ✅ | 全仓 28 处 unsafe 逐处人工核：均为 libc 直接调用 + `OwnedFd` 接管 + rc/errno 判定；无指针对外存活，`mem::zeroed` 只用于 POD 结构且随后完整初始化；`affinity.rs:102-112` 对 `CPU_SET` 索引做了 `CPU_SETSIZE` 前置拦截（避免 OOB 写）。新增代码中 `zmtp/`、pcap 读写、bpf 编译与解释为 **0 unsafe**，`af_packet.rs` 11 处与 `bpf/linux.rs` 1 处均带 SAFETY 注释。未发现可达越界/UB。仅 13 处存量 unsafe（netns 8、affinity 4、task.rs:537 1）缺 SAFETY 注释 → P3-19 |
| 边界 / 整数溢出 | ⚠️ | 正向用例完备：`interp.rs:11` `checked_add`、`codec.rs:260-264` 分配前判长、`zmq.rs:167` VLAN 下溢守卫、`caplen.min(65531)` 保 `u16` 不溢出、`linux.rs:29-30` `u16::try_from`。但**配置侧 i64→i32 静默截断未拦**（`config.rs:779-792`）→ P2-6；`pcap_file.rs:95` 单条 256 MiB `resize` → P3-12；32 位平台 `n as usize` 可绕过帧长上限（`codec.rs:262`）→ P3-11 |
| AF_PACKET recvmsg / cmsg 解析 | ✅ | `af_packet.rs:129-146`：`cmsghdr` 16 字节头、`len<16`、`off+len>len`、`(len+7)&!7` 对齐、`len>=32` 才取 `timespec`，越界一律 `None` → 回落，无 unsafe ✅。假设 64 位 `time_t`/`size_t` → P3-9 |
| 时间戳正确性 | ⚠️ | `nsec/1000` → `ts_usec` 换算正确 ✅；`SO_TIMESTAMPNS` 的 `setsockopt` **返回值被丢弃**（`af_packet.rs:115-122`），失败时静默回落到 `(now_sec(), 0)`（`af_packet.rs:290-291`）→ 全部包 usec=0，pcap/rotating_file 输出退化为秒级时间戳且无任何告警 → P2-5 |
| snaplen 语义 | ⚠️ | `MSG_TRUNC` 用法正确（`n`=线上长度，`caplen=min(n,snaplen)`，`af_packet.rs:281-288`）✅；但 `cfg.snaplen.max(1)`（`:248`）与 i64→i32 截断（`config.rs:779-792`）组合可把 `snaplen: 2147483648` 变成 **1 字节捕获** → P2-6 |
| `PACKET_STATISTICS` | ⚠️ | 读 `tp_drops` 累计值并取 `wrapping_sub` 差值 ✅（与 u32 环绕兼容）；`ifdrop` 计算写成 `0u32.wrapping_sub(prev)`（`af_packet.rs:341`）——语义恒 0 但形式是"0 减非 0"的死码/陷阱码 → P3-1；以 packet 时间戳做 2s 节流（`af_packet.rs:396`）在时钟阶跃回拨时会长期停算 → P3-2 |
| netns 进入/恢复 | ✅ | `af_packet.rs:182-198`：`open_self_netns()` → enter target → `Self::open()` → **两条路径（Ok/Err）都恢复**原 netns；失败路径 `log_error!` 不吞；恢复 fd 由 `OwnedFd` 关闭；`netns.rs:60-66` `setns` 失败显式 `close` 后再返回错误 → 无 fd 泄漏；`if_nametoindex`/`getifaddrs` 都在目标 ns 内调用 ✅ |
| 文件描述符泄漏 | ✅ | 全链路 `OwnedFd`（`af_packet.rs:75`、`netns.rs:26/65`）；`open_socket` 各失败点均有 OwnedFd 接管或无 fd 状态 |
| 无权限时的错误路径 | ⚠️ | 行为正确（`socket(AF_PACKET)` → `Err` → `build_task` 记录 → 其余 task 继续），但消息形如 `socket(AF_PACKET) error: 1`（`af_packet.rs:40-42` 只打印裸 errno，无 `strerror`），运维看不出"缺 cap_net_raw" → P3-10 |
| 忙轮询 / CPU | ⚠️ | `timeout_ms` 默认 0 → `nonblock=true`（`af_packet.rs:241`）→ `capture_once` 完全跳过 poll（`:355`）→ EAGAIN + `main.rs:107` 10 µs sleep ⇒ **~10 万次 recvmsg/秒 + 等量 heartbeat 回调**常驻 CPU（C 侧 libpcap `to_ms=0` 是阻塞读）→ P2-4 |
| recvmsg 错误风暴抑制 | ❌ | `af_packet.rs:394-407`：`next_error` 先 set 后 `take()`，每轮都清空 → 守卫形同不存在；接口 down（ENETDOWN）时按主循环频率（~10 万次/秒）刷 `log_error!` → P2-3。`file.rs:38-42`/`rotating_file.rs:139-145` 同类：写失败仅记日志，**仍 `fwd_bytes/fwd_packets += 1` 并返回 0**（ENOSPC 时统计虚高 + 日志洪泛） |
| ZMTP 握手状态机健壮性（乱序/半包/错误握手） | ✅ | `client.rs:84-141` 逐阶段严格：greeting 不足 64 字节 → break 等待；`READY` 半包 → `Ok(None)` → 等待；非命令帧在 Ready 阶段 → 断开；`Socket-Type` 不兼容 → 断开；`ERROR` → 断开；EOF(Ok(0)) → 断开重连。8 个单测 + `zmtp_client` 混沌 fuzz 覆盖，本地全绿 |
| ZMTP 写缓冲相位不变量（线序） | ❌ | 两处未检查 `out_off == out.len()` 就改写/绕过 `out`：`client.rs:88-91`（Greeting→Ready 直接 `self.out = ready_command(...)`，若本地 greeting 因 `WouldBlock` 只写出一半即被覆盖，线上字节流永久错位）；`client.rs:296-302`（`is_connected()` 即开始写业务帧，不等 READY 尾部落线）→ P2-2 |
| ZMTP HWM / 无限缓冲风险 | ⚠️ | `pending` 长度受 `hwm` 严格约束（fuzz 不变式 `queued() <= hwm` 通过 ✅），但**单条 = 整批拷贝 ≤1 MiB**（`zmq.rs:330` → `client.rs:181`），`hwm` 来自配置且**无上限校验**（`config.rs:741`，i32 可到 2^31-1）→ 最坏 hwm×1 MiB 常驻；默认 100 已可让 RSS 从宣称的 6.5 MB 涨到 ~100 MB → P2-8 |
| ZMTP 重连退避 / keepalive | ⚠️ | 退避 100 ms→5 s 指数、握手成功即复位（`client.rs:243,338-342`）✅；但 **无握手超时、无 TCP keepalive、无 `TCP_USER_TIMEOUT`**（`client.rs:400-425`），黑洞 peer 会让状态机永久停在 `Connecting`；且 `fwd_bytes/fwd_packets` 在"入队"时即计数（`zmq.rs:344-347`），黑洞期统计与实际上线量脱节 → P2-7 |
| ZMTP 帧长上限 / 解析 | ✅ | `codec.rs:25` 16 MiB 上限，`parse_frame` 在**分配前**判定（`codec.rs:260-264`），`consumed <= len` 由 fuzz 断言覆盖；`parse_metadata` 逐字段有界（`codec.rs:154-186`）。仅 32 位平台 `n as usize` 截断可绕过上限（`codec.rs:262`）→ P3-11 |
| pcap 读/写正确性 | ✅/⚠️ | 4 种 magic（LE/BE × µs/ns）全覆盖、`read_exact` 修复正确（`pcap_file.rs:75-97`）、写侧恒小端且读侧兼容双向 ✅；但**未校验 global header 的 linktype**（`ghdr[20..24]` 从未读取）→ `tcpdump -i any`（DLT_LINUX_SLL）文件被当作 Ethernet 静默错位解析 → P3-12；`MAX_CAPLEN=256 MiB` 单条 → 一次 `resize` 即可预留 256 MB → P3-12 |
| 错误处理一致性 | ✅ | `Error(String)` 统一、`Result` 全覆盖、`# Errors` 文档 + `#![warn(missing_docs)]`（`lib.rs:9`）且 clippy `-D warnings` 全绿；资源回滚路径（`netns`、`setns` 失败 close）正确 |
| panic 面 | ⚠️ | 新模块非测试代码仅 2 个 panic 构造：`compiler.rs:91 expect`、`client.rs:304 unwrap`，两者均可证不可达（`or_all` 入参恒非空；`is_connected()` 前置保证 `conn` 为 Some），但 `panic="abort"`（`Cargo.toml:44`）下任何回归即整进程消失；而**可达的 abort 路径是栈溢出**（P2-1） |
| 并发与不变量 | ⚠️ | `parking_lot` 全线（cpdaemon 已无 `std::sync::Mutex` ✅）；但 `BytesStats/PacketsStats::add` 是 `load→store` 非原子 RMW（`stats.rs:24-35,66-77`），类型是 `Sync` 且被 RPC 线程并发读，单写者不变量未文档化/未强制 → P3-14；`poll_packets_batch` 持锁时间上界 = `BATCH × max(timeout_ms)` = 256×timeout_ms（多 capturer 时任一活跃者会把批拉满）→ RPC 可被阻塞数十秒 → P3-15 |
| API / 模块设计 | ✅/⚠️ | `bpf`（parser/compiler/interp/codes/linux）、`zmtp`（纯函数 codec + 可注入 Transport/Connector 状态机）、`sockopt`（平台翻译点）、`Capturer`/`Output` trait 分层干净、平台相关代码被 `cfg` 收敛到 2 个文件——可测试性与 Windows 延展性都好 ⚠️；缺陷是 `Output::destroy` 是**没有调用方的接口承诺**（P1-3），`netutil.rs:68` 用 `bytes[i] as char` 逐字节重编码 UTF-8（非 ASCII 过滤器会被破坏）→ P3-13 |
| 可读性 / 注释质量 | ✅ | 新代码注释密度与信息量高（模块级 doc 说明设计取舍、`compiler.rs` 说明"每个原子测试自包含"的码生成策略、`codec.rs` 说明 libzmq 字节兼容理由、`pcap_file.rs:75-78` 把 `read_exact` 的坑写成不变量）；零 TODO/FIXME；命名一致 |
| 与 C 的 UB 分歧处理 | ✅ | `zmq.rs:161-169` 对 C 的 VLAN 越界 memcpy 选择丢包并在 PARITY §2.2 记录，判定与实现一致 |

### 3.2 工程质量

| 检查项 | 结论 | 证据 |
|---|---|---|
| 单元测试 | ✅ | cpworker lib 39（bpf 10、zmtp codec 7 + client 8、pcap_file 2 含大文件回归）、cpdaemon 10、cpgolib 7、cpctl 2；共 107 passed |
| 集成测试 | ⚠️ | `zmtp_interop.rs` 3（真实 TCP：投递/断开重连/并发慢读，CI 可跑 ✅）；`pcap_file_filter.rs` 1（离线过滤+主机排除端到端 ✅）；**`af_packet_live.rs` 是 `#[ignore]`（需 CAP_NET_RAW）→ 新实时采集路径在 CI 中 0 覆盖**（cmsg/时间戳/snaplen/PACKET_STATISTICS/netns 全部未进回归网）→ P2-9 |
| 差分（对拍）测试 | ⚠️ | 5 类差分 + ZMTP↔libzmq 4 载荷 + BPF↔libpcap 逐包判定，方法学一流；但 `gen_bpf_cases.py` 模板算子**最多 2 项、`not host` 恒 1 项**，实测在门禁全绿的同时 `port A or B or C` 编译失败 → 门禁对 P1-1/P1-2 盲区（P2-10） |
| Fuzz | ✅/⚠️ | 9 个 target（新增 bpf / zmtp_wire / zmtp_client 混沌状态机），`fuzz.sh --check` 进 CI；`diff_oracle` 覆盖 C/Go 差分。**缺 pcap reader fuzz**（畸形记录头/截断/错字节序/跨缓冲边界——正是 `9ad3f22` 那类 bug 的猎场）；`bpf` target 只在 `compile` 成功时断言，不覆盖深度嵌套导致的 abort（P2-1 未触发即因输入形态受限） |
| DST（确定性仿真） | ⚠️ | 11 个 DST 全绿、种子可精确复现；但 `grep -rn "zmtp\|bpf" crates/sim/` **无命中** → DST 不覆盖新增的 ZMTP 客户端与 BPF 过滤路径（P2-11） |
| CI 配置 | ✅/⚠️ | 8 job：fmt / build&test / clippy `-D warnings` / cargo-deny（+GPL 断言）/ cargo-audit / dependency-review（advisory）/ differential parity / cargo-fuzz smoke，另 coverage advisory；parity+diff fuzz 进 CI 属同类项目顶级 ⚠️：无 `--locked`/`--frozen`（lockfile 漂移不会被发现）、**无 MSRV job**（声明 1.88 却只在 stable 上验证）、无 workflow 级 `permissions:` 最小化、无 `cargo doc` 门禁 |
| 依赖与供应链 | ✅/⚠️ | 241 lock 项、无 C 库、BSD-3-Clause；`deny.toml` 许可证白名单 + `yanked=deny` + registry 白名单，CI 还断言不得出现 GPL 家族 ⚠️：`bans.wildcards = "allow"`、`sources.unknown-registry/unknown-git = "warn"`（git/通配依赖可通过 CI）；`crates/cpworker/fuzz/` 是**独立 workspace**，其 `Cargo.lock` 不在 `cargo deny`/`cargo audit` 覆盖范围 |
| 构建可复现性 | ⚠️ | `Cargo.lock` 与 fuzz `Cargo.lock` 均已提交 ✅、release profile（lto + codegen-units=1）✅；但无 `rust-toolchain.toml`、CI 不用 `--locked`、release 无 `-C strip`/无 SBOM、`release.yml` macOS 步骤仍在 `brew install libpcap zeromq`（P3 后已不需要，属遗留） |
| MSRV | ⚠️ | `Cargo.toml:12 rust-version="1.88"` 且 7 个成员继承 ✅；**没有任何 CI job 用 1.88 构建**（只有 `@stable`），"Requires Rust 1.88+" 是无验证声明 |
| 文档（README/PARITY/IMPROVEMENT_PLAN/bench） | ❌ | 11 处与代码矛盾（P2-11）：`PARITY.md:6` 说纯 Rust"尚未完成"而 §4 说"已完成"；`PARITY.md:21,22` 说 ZMQ"仍用 libzmq"、capturer"仍链接 libpcap"；`PARITY.md:57` 测试数 71（实际 107）；`PARITY.md:268` §5.1 又把去 C 依赖列为"未完成/计划移植"；`README.md:92,129` 仍称 libpcap capturer；`README.md:228` 基准注仍写"Both use libpcap"；`README.md:65` 快速上手命令引用仓库内不存在的 `../cpworker/examples/libpcap_null.json`；`IMPROVEMENT_PLAN.md:171` 在"✅ 已移除"之后又留"⬜ libpcap 待移除"；`bench/RESULTS.md`（09:58）与 README 基准表仍是 libpcap 时代数字 |
| 提交与流程 | ⚠️ | 提交信息规范（conventional commits、正文含根因与量化证据）优秀 ✅；但 `git log --merges` **为空**——P3 8 个提交全部直推 main，`IMPROVEMENT_PLAN.md:224` 自订的"P3 每子项独立 PR + feature flag 灰度，保持可回退"未执行（仓库无任何 `[features]`）；AUDIT2 要求的两项开工预研（**BPF 表达式分布审计**、collector socket 语义确认）在仓库内**找不到任何产出痕迹**；无 CHANGELOG / CODEOWNERS / SECURITY.md |
| 运维 / 可观测性 | ⚠️ | `collect_stats_summary` 字段与 C 逐字对齐（drop/ifdrop/ratelimit/direction/error/heartbeat/pipeline_buffer）✅；错误经 `print_errors()` **每 60 s 才打印一次**（`main.rs:118-122`）→ task 静默不抓包最长 60 s 不可见，且 `inited_count < total` 无指标/退出码体现；errno 不转文本；无 socket/文件写错误的专用计数器（复用 fwd_*）；reload 期间在主线程内做 DNS 解析（`parser.rs:463-472`）可长时间阻塞采集与 RPC |

---

## 4. 分级发现

### P0（阻断 / 内存安全 / 数据破坏）——**0 项**

未发现可达的越界读写、可解引用野指针的 unsafe、可被报文触发的 panic、或会破坏落盘/上线数据的缺陷。这一点在两轮"去 C 依赖"重写后仍然成立，是本项目最值得肯定的工程质量。

### P1（必须在"默认替换 libpcap/libzmq"之前修复）——4 项

#### P1-1 BPF 编译器缺少跳转中继，11 项 `not host` 链 / 3 项 `port` 或链即编译失败，而生产过滤器正是这一形态

- **证据**
  - 代码：`crates/cpworker/src/bpf/compiler.rs:628-647`（`finish()` 对 `off>255` 只能 `Err`）；`crates/cpworker/src/bpf/codes.rs:44` 定义了 `JMP_JA`、`interp.rs:55-58` 已能执行 JA，但**编译器全篇从未发射 JA**（`grep -n "JMP_JA" bpf/compiler.rs` 无命中）→ 没有 tcpdump/libpcap 的 "jump around" 距离扩展。
  - 生产形态：`config.rs:931-951` `bpf_filter_exclude_task_output_hosts` 生成 `(bpf) and not host H1 and not host H2 …`，`capturer/af_packet.rs:212-217` 默认调用（`not_filter_output_hosts=false`）；`ipv4()`+`arp()`×2+`src/dst` 使**每个 `not host` 展开约 26 条指令**。
  - 实测（本机 libpcap 1.10.4 作 oracle，`parity/c_bpf.c` 编译为 `/tmp/c_bpf`）：
    ```
    not host ×10   libpcap=OK   rust=OK 0001100
    not host ×11   libpcap=OK   rust=ERR bpf: filter too complex (jt > 255)
    port 1000 or port 1001            libpcap=OK   rust=OK
    port 1000 or 1001 or 1002         libpcap=OK   rust=ERR bpf: filter too complex (jt > 255)
    host ×8 or-chain                  libpcap=OK   rust=OK
    host ×12 or-chain                 libpcap=OK   rust=ERR ... (jt > 255)
    ```
  - 失败后果链：`bpf::compile` Err → `open()` Err（`af_packet.rs:226-229`）→ `new_capturer` Err → `build_task` Err → `build_all` **仅记 error**（`task.rs:225-233`）→ 该 task 永不抓包；主循环照常运行；错误要等 `print_errors()` 的 60 s 周期才见（`main.rs:118-122`）。
- **影响**：≥11 个不同转发主机（vxlan/gre/zmq 目的端去重后的总数，跨所有 task）即触发；或用户 bpf 里出现 3 项 `port` 或链 / 12 项 `host` 或链。**症状是"探针活着但没有数据"**，且管理面（CPM 下发的 strategy.bpf，见 `cpdaemon/src/cpm/task_builder.rs:228-229`）可远程造成该状态。与 `PARITY.md §4`"语义对齐 tcpdump"、`README.md` 的完成声明冲突。
- **建议**：在 `Builder::finish()` 里实现标准长跳中继：对 `off>255` 的跳转，插入 `ja #off-1`（`JMP_JA`，k 为 u32 距离，可达 ~4 k 条）作为中继——即 `jt` 指向新插入的 JA，JA 再跳到目标；或以"每条指令的可用后继窗口"重排 label 绑定。补 3 类回归：11/50/200 项 `not host` 链、`port`×N、`host`×N，并在 `gen_bpf_cases.py` 中加入"N 项算子链"模板，让门禁本身能发现它。同时在 `compile()` 显式检查 `insns.len() > 4096` 并给出人类可读错误（现在是 attach 时 EINVAL）。

#### P1-2 BPF 子集缺失 tcpdump 常用合法语法，文档未声明（"文档说已做，代码没做"）

- **证据**：`parity/gen_bpf_cases.py` 之外的自由表达式实测：
  | 表达式 | libpcap | 纯 Rust | 代码位置 |
  |---|---|---|---|
  | `tcp dst port 80` | OK（可编译可判定） | **ERR unexpected token 'dst' in filter** | `parser.rs:335-360`（`parse_proto_qualified` 只接受紧跟 proto 的 `port`；`src/dst` 只能出现在最前，而 `parse_predicate:313-319` 对 `src/dst` 后接协议关键字直接报错） |
  | `udp src port 53` | OK | ERR 同上 | 同上 |
  | `ether src host 00:11:22:33:44:55` | OK | **ERR expected 'host' after 'ether'** | `parser.rs:303-312`（只支持 `ether host`） |
  | `ether dst 00:11:22:33:44:55` | OK | ERR 同上 | 同上 |
  | `ip proto 6` | OK | **ERR unexpected token 'proto'** | `parser.rs:317` |
  | `greater 100` / `len greater 100` | OK | **ERR unsupported filter keyword** | `parser.rs:317` |
  | `vlan 5` | OK | ERR（**已在 PARITY §4 声明**） | — |
  - 文档侧：`PARITY.md §4` 只写"不支持的关键字（`vlan` 等）明确报错"；`parser.rs:1-20` 的文法注释虽然隐含了 `[src|dst]` 不能与 PROTO 组合，但 README/PARITY 面向用户的"已完成/语义对齐 tcpdump"表述覆盖了这一点。
- **影响**：从 C 升级到 Rust 的现场，任何使用 `tcp dst port 443` 之类过滤的 task 会**从"能抓"变成"静默不抓"**（同 P1-1 的失败链）。这是可升级性/回退风险，不是纯粹的功能缺失。
- **建议**：（1）文法补齐 `[src|dst] PROTO port/portrange`（tcpdump 的 `tcp dst port` ≡ `dst port` + tcp 限定，AST 已有 `Dir`+`L4`，只需在 `parse_proto_qualified` 前接受方向词）与 `ether src|dst [host]`；（2）在 PARITY §4 明确列出**完整**不支持清单（vlan/gre 内部字段/`ip proto`/`len`/`greater`/`multicast`/`broadcast`/算术/`[k]:n` 原始偏移等）；（3）升级前置检查：在 `cpdaemon` 下发或 `cpworker` 启动时把"编译失败的原始表达式 + 建议改写"写入 stats（`collect_stats_summary` 增一个 `bpf_errors` 字段），而不是只进日志。

#### P1-3 `Output::destroy()` 从未被调用 → ZMQ 的 5 秒 linger 与文件 flush 全是死代码，热重载/退出丢数据

- **证据**：`grep -rn "destroy" --include=*.rs crates/` 仅 3 处命中：`output/mod.rs:49`（trait 默认实现，文档写 "Flush and release resources on shutdown"）、`output/file.rs:45-49`、`output/zmq.rs:460-463`。**无任何调用点**。而 task 生命周期是纯 Drop 驱动：`task.rs:417-420`（`reload()` 里 `self.entries.clear(); *self.out_sets.lock() = Vec::new();`）、`task.rs:485`（`impl Drop for TaskManager → stop()`）。`Box<dyn Output>` 被 drop 时 `ZmtpPush`（含 `pending: VecDeque<Vec<u8>>`）直接释放。
- **影响**：
  1. **数据回归（相对 C）**：C 的 `output_zmq.c` 在 destroy 路径 `zmq_close` + `ZMQ_LINGER=5s` 会尽量把在途批次发完；Rust 侧丢弃最多 `hwm×1 MiB`（默认 100 MiB）批次。每次 SIGHUP reload / cpctl `reload_config` / 正常退出都会丢一批在线流量，且 `fwd_packets/fwd_bytes` 已按"入队即计数"（`zmq.rs:332-335`）报成"已转发"→ **静默丢包 + 统计虚高**。
  2. `file.rs:45` 的显式 flush 不生效，落盘尾部依赖 `BufWriter::drop`（其错误被 std 吞掉）→ ENOSPC/超限时 pcap 尾部静默截断且无错误上报。
  3. 该类缺陷对 `clippy::dead_code` **不可见**（trait 方法有默认实现，不参与死代码分析），因此 `-D warnings` 门禁和 AUDIT1/2/3 的"死代码收窄"都没抓到它。
- **建议**：给 `TaskOutputs`/持有者实现显式 `Drop`（或在 `TaskManager::stop()`/`build_all()` 替换前统一 `for o in outputs { o.destroy() }`），让 `destroy()` 有唯一确定的调用点；并加一个回归测试：ZMQ 输出在 `send` 未 flush 状态下走 `stop()`，断言 mock peer 收到了入队批次（`zmtp_interop.rs` 已有脚手架）。长期建议：把 `fwd_*` 计数移到"确认写入 transport 之后"，或额外引入 `queued_bytes` 指标。

#### P1-4 AF_PACKET `SO_RCVBUF` 被内核静默截断，无回读、无 `SO_RCVBUFFORCE`

- **证据**
  - 代码：`capturer/af_packet.rs:77-91`——只做一次 `setsockopt(SOL_SOCKET, SO_RCVBUF, &sz)`，失败仅 `log_warn!`；**无 `getsockopt` 回读**，未用 `SO_RCVBUFFORCE`。buffer_size 来源 `config.rs:792 buffer_size_mb.unwrap_or(256) as i32`（默认 256 MB）。
  - 实测（本机非 root，`/tmp/rcvbuf.c`）：
    ```
    net.core.rmem_max = 4194304
    AF_INET/DGRAM: setsockopt rc=0 want=268435456 applied=8388608   # 32× 缩水，且 rc=0（"成功"）
    AF_PACKET socket: Operation not permitted (errno=1)             # 无特权路径，见 P3-10
    ```
    即：`setsockopt` 返回 0、代码认为配置生效，实际生效值是请求值的 1/32；在 `rmem_max` 为发行版默认 212992 的机器上，256 MB 会变成 **416 KB**。
  - 对照：部署文档已要求 `cap_net_admin`（`README.md:82`），而带 `CAP_NET_ADMIN` 的 `packet_set_ring()`（libpcap TPACKET 路径）不受该上限约束——因此这不仅是"绝对容量小"，还是**相对 libpcap 的能力回归**；PARITY §4 只记录了 `recvmsg` vs mmap ring 的取舍，未记录缓冲容量这一实际后果。
- **影响**：突发流量下 RX 环形缓冲溢出 → `PACKET_STATISTICS.tp_drops` 上升 → 用户看到的"网络丢包"里混入了探针自身容量不足造成的丢包（对以丢包测量为卖点的产品是致命的），且没有任何告警。
- **建议**：（1）`setsockopt(SO_RCVBUFFORCE)`（有 CAP_NET_ADMIN 时）失败再退 `SO_RCVBUF`；（2）**总是** `getsockopt` 回读实际值，若 `< 请求值的 1/2` 则 `log_warn!` 并写入一个可观测计数；（3）中期：按 PARITY §4 的计划实现 `PACKET_RX_VERSION`/TPACKET_V3 mmap ring，把 `recvmsg` 保留为 fallback；（4）文档在 PARITY §4 的"已知取舍"里补上缓冲语义差异。

### P2（重要，应在下一个里程碑内闭环）——12 项

#### P2-1 深度嵌套或超长 BPF 表达式导致进程**栈溢出 abort**（无表达式长度/递归深度上限）
- **证据**：实测（debug 构建、8 MB 主栈）：`not`×3000 → `OK`；`not`×5000 → `thread 'main' has overflowed its stack / fatal runtime error: stack overflow, aborting`；`(`×5000 嵌套 → 同样 abort；扁平 `and` 链 ×1000/×3000 → 优雅 `ERR bpf: filter too complex`，但 ×6000 → abort。递归点：`parser.rs:236-241`（`parse_unary` 自递归）、`compiler.rs:105-118`（`lower`）、`compiler.rs:608-626`（`Builder::compile`）。
- **影响**：BPF 字符串来自配置文件，而该文件由 `cpdaemon` 依据 **CPM 下发的 strategy** 写出（`cpdaemon/src/cpm/task_builder.rs:228-229` → `worker.rs:257 write_config` → `:229 SIGHUP`）。一条畸形/恶意的长表达式使 cpworker **不可捕获地 abort**，被 cpdaemon 反复拉起 → 崩溃循环。`panic="abort"`（`Cargo.toml:44`）+ 递归无深度限制 = 无兜底。libpcap 的 yacc 解析器在同类输入上报 "filter too complex"，不会 crash。
- **建议**：`parse()` 入口加表达式字节长度上限（如 8 KB）与显式递归深度计数（如 256，超限 `Err`）；`lower`/`compile` 改迭代或复用同一深度预算；给 `bpf` fuzz target 增加"纯结构输入"（重复 `not `/`(`）的种子，使 stack-overflow sanitizer 能被触发（当前 target 输入形态很难自然生成 5 000 层嵌套，这就是它没被发现的原因）。

#### P2-2 ZMTP 客户端写缓冲的相位不变量缺失 → 线序损坏风险（握手后字节错位 → 重连风暴）
- **证据**：`zmtp/client.rs:88-91`：`Phase::Greeting` 收到对端 greeting 后**无条件**执行 `self.out = codec::ready_command("PUSH"); self.out_off = 0;`——若我方 64 字节 greeting 因 `WouldBlock` 只写出一半（`drive_conn:267-275` 会保留 `out_off`），这里直接丢弃未写尾部并改写缓冲，对端将收到"半 greeting + READY 字节"。`client.rs:295-304`：`flush_pending()` 只以 `is_connected()`（`phase==Open`）为闸门，而 `phase→Open` 是在 `advance()` 内由**对端 READY** 触发的（libzmq 的 PULL 不等我们发完 READY 就发自己的 READY），因此 `conn.out` 仍有未写尾巴时就可能开始交织写业务帧。两处都缺 `out_off == out.len()` 守卫。
- **影响**：触发需要"发送缓冲刚好在握手期间写满"，概率低但非零（内存压力、`SO_SNDBUF` 被压缩、对端不读）；一旦触发是**协议级不可恢复**：libzmq 解出畸形帧→断连→我们重连→再次可能卡在同一相位 → 采集数据全部堆积到 HWM 后被丢弃（且 `fwd_*` 已计数）。`zmtp_client` 混沌 fuzz 未覆盖"greeting 写一半"（其 mock 的 `write` 要么全成功要么 `BrokenPipe`，见 `fuzz_targets/zmtp_client.rs:35-42`）。
- **建议**：把"待写字节"合并成单一 FIFO（`out: VecDeque<u8>` 或在 `advance()` 里禁止覆盖 `out`，直到 `out_off==out.len()`）；`is_connected()` 之外再加 `can_write_messages() = phase==Open && out_off==out.len()`；mock `write` 增加"短写（Ok(k<len)）"分支，并在 `zmtp_client` fuzz 里暴露。

#### P2-3 采集/输出错误路径的日志洪泛与"错误仍计成功"
- **证据**：`capturer/af_packet.rs:393-408`：`Err(e)` 分支里 `if self.next_error.is_none()` 设置消息，随后**同一函数末尾 `self.next_error.take()` 打印并清空** → 守卫永不生效，recvmsg 持续失败（接口 down → ENETDOWN；主循环 10 µs 一轮）时以每秒上万条的频率写 stderr。同类：`output/file.rs:37-42`、`output/rotating_file.rs:138-145`（写失败仅 `log_error!`，随后仍 `fwd_bytes/fwd_packets.add()` 并 `return 0`，ENOSPC 时逐包刷日志且统计虚高）。
- **影响**：磁盘/日志管道被打满（次要 DoS），且"错误丢弃"没有计入 `error_drop_*`，运维看到的增长全是成功计数。
- **建议**：`next_error` 语义改为"距上次打印 ≥N 秒才打印"（保存 `last_error_log: i64`）；文件写错误累加到 `stats.error_drop_*` 并让 `send_packet` 返回 -1；对 `BufWriter` 错误设置 sticky 降级标志（`rotating_file` 已有 `dumper_error`，`file.rs` 没有）。

#### P2-4 `timeout_ms` 默认 0 → 非阻塞忙轮询（约 10 万次 recvmsg/秒）
- **证据**：`config.rs:783 timeout_ms.unwrap_or(0)`；`af_packet.rs:241 let nonblock = cfg.timeout_ms <= 0;`；`af_packet.rs:355 if self.timeout_ms > 0 { poll(...) }`（默认路径完全不等内核）；`main.rs:105-108`：批量返回 0 时只 `sleep(10µs)`。空闲时每轮 = 1×recvmsg(EAGAIN) + `on_heartbeat()`（`zmq.rs:441-443` 里再做一次 read(EAGAIN)）≈ 2 syscall / 10 µs ⇒ **~2×10⁵ syscall/s 常驻**，并阻止 CPU 进入深度 idle。C 侧 `pcap_open_live(..., to_ms=0)` 是阻塞读，空闲 CPU≈0（SIGHUP 会以 EINTR 打断，reload 语义不受影响）。
- **影响**：单核占用与功耗显著上升、与其他同机租户争抢；`bench/` 全用 `pcap_file`，所以这条路径没有基准数据。
- **建议**：`timeout_ms<=0` 时用 `poll(fd, timeout=-1)`（或 `timeout=100ms`）代替忙轮询；或把默认 `timeout_ms` 从 0 改成 100~200 并更新 PARITY；在 bench 里加一个"空载 live capturer CPU/pps"场景防回归。

#### P2-5 `SO_TIMESTAMPNS` 返回值被忽略，失败时静默退化为秒级时间戳
- **证据**：`af_packet.rs:115-122`（`unsafe { setsockopt(...) }` 无返回值检查）；回落 `af_packet.rs:290-291 .unwrap_or_else(|| (now_sec(), 0))` → `ts_usec` 恒 0。
- **影响**：`file`/`rotating_file` 输出的 pcap 每条记录 `ts_usec=0`（Wireshark 里所有包同一秒），ZMQ 批次的 `tv_usec`、VXLAN `capture_time` 附加字段、`TokenBucket::consume(.., hdr.ts())` 的限速时间轴全部退化到 1 秒粒度；无任何告警。
- **建议**：检查返回值并 `log_warn!`；回落到 `Instant`/`clock_gettime(CLOCK_MONOTONIC)` 派生的 µs（或至少记录"本 capturer 已降级"计数），使降级可见。

#### P2-6 配置数值 i64→i32 静默截断可产生荒谬运行参数
- **证据**：`config.rs:779-792`：`snaplen: Option<i64>` 只校验 `<0`，随后 `snaplen: snaplen as i32`、`buffer_size_mb.unwrap_or(256) as i32`、`timeout_ms as i32`；消费端 `af_packet.rs:248 cfg.snaplen.max(1) as usize`。
- **影响**（可实测复算）：`snaplen: 2147483648` → `as i32` = −2147483648 → `.max(1)` = **1** → 每包只截获 1 字节，BPF 全部判定为不匹配（越界 load → drop），采集静默为空；`buffer_size_mb: 4294967296` → `as i32` = 0 → `SO_RCVBUF=0` → 内核抬到最小值 → 极端丢包；`timeout_ms: 4294967396` → 100。C 侧 cJSON 的 `valueint` 会被钳到 INT_MAX，不会产生这类"变号/变 1"的值，属**行为分歧**。
- **建议**：统一用 `i64::try_into()` + 显式范围校验（snaplen 1..=262144、buffer_size_mb 1..=8192、timeout_ms 0..=60000），越界返回带字段名的 `Err`；顺手把这几项的范围写进 PARITY 的差分向量（`gen_config.py` 已可加极值用例）。

#### P2-7 ZMTP 无握手超时、无 TCP keepalive、DNS 只解析一次
- **证据**：`zmtp/client.rs:400-426`（`TcpConnector::start` 只设 nonblocking + nodelay）；`check_connected:355-380` 仅 `PollTimeout::ZERO` 探一次，永不错误即一直 `Ok(false)` → `drive_conn:262 return Ok(())`，状态机停在 `Connecting`，无超时、无退避推进；`tcp_connector:429-434` 启动时 `to_socket_addrs()?.next()` 解析**一次**并只取**首个**地址；`output/zmq.rs:271-273` 之后永不重解析。
- **影响**：（a）collector IP 变化（K8s Service / DNS 轮转 / 主机迁移）后进程只能靠重启恢复，而 libzmq 的重连会重新解析；（b）黑洞 peer（SYN 被 drop / NAT 表项老化导致静默失联）下：连接停在 `Connecting` 直到 OS 的 connect 超时（数十秒至 2 分钟），已建立的静默死链则**永远不会被发现**，期间每批 `fwd_bytes/fwd_packets` 持续累加（`zmq.rs:332-335`）→ 监控显示"一切正常"而 collector 早已收不到数据。
- **建议**：`socket2::Socket::set_tcp_keepalive`（feature `all` 已启用，`Cargo.toml:36`）+ `TCP_USER_TIMEOUT`；`Connector::start()` 内做 DNS 重解析（把 `TcpConnector{addr}` 改成 `{host,port,resolved,ttl}`）；`Conn` 增加 `handshake_deadline`（如 10 s），超时走 `schedule_reconnect()`；`check_connected` 的失败计数接入 `error_drop_*` 使降级可观测。

#### P2-8 ZMQ `pending` 队列 = hwm × 1 MiB，hwm 无上限校验
- **证据**：`zmq.rs:330 self.zmtp.send(&self.builder.buf[..len])`（len ≤ `ZMQ_MAX_BATCH_BUF_SIZE = 1 048 576`）→ `client.rs:181 pending.push_back(codec::frame(0,msg))`（**整批 1 MiB 深拷贝**）；队列长度受 `hwm` 约束（`client.rs:178-181`）；`config.rs:741 hwm: z.hwm.unwrap_or(100)` 无范围校验（`Option<i32>` 可到 2^31−1）。
- **影响**：collector 慢/不可达时，默认配置即可让 RSS 从 README 宣称的 6.5 MB 涨到 ~100 MB；配置写大 hwm（"防丢包"的常见调优直觉）会把 cpworker 变成 OOM 候选，OOM killer 杀掉的是**采集进程本身**。另外 happy path 每批多一次 1 MiB memcpy（libzmq 走 zerocopy 的 `zmq_send` 也拷贝进 pipe，量级相当，可不算回归）。
- **建议**：`hwm` 加范围校验（如 1..=1024）并在文档给出"字节上限 = hwm × 1 MiB"的换算；额外提供 `pending_bytes` 指标（`collect_stats_summary` 增字段）；可选：把 pending 元素改为 `Arc<[u8]>` 引用以支持"多输出共享同一批"。

#### P2-9 新增实时采集路径在 CI 中零覆盖
- **证据**：`crates/cpworker/tests/af_packet_live.rs:41-43` `#[test] #[ignore = "requires CAP_NET_RAW"]`；`.github/workflows/ci.yml` 的 `test` job 只跑 `cargo test --workspace`（不含 `-- --ignored`），也没有任何 privileged/capability 容器步骤。`IMPROVEMENT_PLAN.md:180` 声称"真实 `AF_PACKET` 抓包测试通过（root）"（本地一次性、无门禁化；同一文件 `:160` 如实标注了 `#[ignore]`）。
- **影响**：P1-4/P2-4/P2-5/P2-6、cmsg 解析、netns 恢复这些最危险的代码路径**没有任何自动化回归**。P3 的 5 个 bug（本轮 P1-4、P2-3、P2-4、P2-5、P2-6）全落在这一块。
- **建议**：CI 增加一个 `live capture (privileged)` job：GitHub-hosted runner 上做不了 → 用 `container: { options: "--privileged --cap-add=NET_ADMIN --cap-add=NET_RAW" }`（自建 runner）或"在 unshare -n + veth 里跑"的脚本；最低成本替代：把 `recv_into_buf`/`parse_timestamp`/`update_drop_stats` 拆成可用 `socketpair`/临时文件驱动的纯函数 + 单测，并加 `PACKET_STATISTICS`/cmsg 的 golden 向量单测。

#### P2-10 BPF 差分门禁的生成器组合深度不足，"门禁绿 = 语义正确"不成立
- **证据**：实测 `bash parity/verify_bpf.sh 7 300 96` → `OK: 96 expressions x 300 packets identical`；而同一时刻 `port A or B or C`、`tcp dst port 80`、`ether src host` 全部编译失败。根因：`parity/gen_bpf_cases.py:93-110` 的模板中每个 `and`/`or` **最多 2 项**、`not host` 恒 1 项；`parity/all.sh:39` 以固定的 `BPF_EXPRS=96` 跑的就是这批模板（CI 调 `parity/all.sh`）。
- **影响**：这是**方法论级**问题（AUDIT2 曾预警"先审计 BPF 表达式分布再定子集"，未做 → 正是它预测的风险落地）。
- **建议**：生成器加入 (a) N 项算子链（N∈1..40，含生产形态 `(bpf) and not host H1..HN`）、(b) `src/dst` 与协议关键字的各种合法组合、(c) 明确的"预期双方都 ERR"清单（`vlan`、`greater`、`ip proto`），使"Rust 单侧 ERR"必然被 diff 捕获；同时把 `parity/verify_bpf.sh` 从固定模板换成"表达式 + 决策"双轨（对同一表达式集随机抽报文与随机抽表达式组合）。

#### P2-11 文档与代码 11 处矛盾（含"文档说已完成而代码未完成"）
- **证据**：见 §3.2 文档行的逐条清单（`PARITY.md:6,21,22,57,268`、`README.md:65,92,129,228`、`IMPROVEMENT_PLAN.md:171`、`bench/RESULTS.md` 全表 + `README.md:180-190` 基准表）。
- **影响**：`PARITY.md` 是本项目的**一致性契约文件**，同一文档内 §1/§4/§5.1 互相否证（既"仍链接 libpcap"又"已移除"），会让评审与下游用户无法判断事实；`README.md:65` 的快速上手命令在独立仓库里必然失败（无 `crates/cpworker/examples/`）；基准表仍是 libpcap 时代数字，而 P3 提交说明已给出不同的新数字 → 无法复现的公开声明。
- **建议**：一个"文档一致性"提交（把 PARITY §1.1 两行、§5.1 第一行、§3 测试数、README 4 处、IMPROVEMENT_PLAN 1 处一次改齐），并加一个 CI 步骤做机械校验：`cargo test --workspace` 的通过数与 `PARITY.md` 声明数比对、`grep -c "仍链接 libpcap" PARITY.md == 0`、README 里引用的相对路径存在性检查。基准数字按 P4.1 一并重跑。

#### P2-12 自订流程要求未执行（PR 灰度 / 开工预研 / 仓库约定文件）
- **证据**：`git log --merges` 空 → P3 的 8 个提交全部直推 `main`；`IMPROVEMENT_PLAN.md:224` 要求"P3 每子项独立 PR + feature flag 灰度，保持可回退"，仓库内 `grep -rn "\[features\]"` 无命中 → 无 feature flag，回退只能 revert 整模块；`AUDIT2.md` 结尾要求的两项开工预研（BPF 表达式分布审计、collector 的 ZMTP socket 语义确认）在 IMPROVEMENT_PLAN/PARITY/仓库中找不到任何记录；无 `CLAUDE.md`/`AGENTS.md`/`CONTRIBUTING.md`/`CODEOWNERS.md`/`SECURITY.md`/`CHANGELOG.md`（`find` 确认）。
- **影响**：本仓库的**风险最高的一次改动**恰好落在"无 review、无灰度、无回退开关"的流程条件下，直接后果是 P1-1/P1-2 这类"只有真实配置才会暴露"的缺陷没有任何拦截层。前三轮审计的流程红利（发现→计划→实施→复核→整改）在这里出现了断裂。
- **建议**：为 P3 补 feature flag（如 `cpworker = { features = ["af-packet","pure-zmtp"] }`，默认保留旧实现一个发布周期）或在 config 层加 `capturer.type = "af_packet" | "libpcap"` 的显式选择以便现场回退；补 `CONTRIBUTING.md`（列验收总命令）+ `CHANGELOG.md`；`CODEOWNERS`/branch protection 禁止直推 main。

### P3（次要 / 一致性 / 硬化建议）——19 项

| # | 位置 | 问题 | 建议 |
|---|---|---|---|
| P3-1 | `capturer/af_packet.rs:341` | `let ifdrop_diff = 0u32.wrapping_sub(self.prev_ps_ifdrop);` 形式上是"0 减历史值"，语义恒 0（`prev_ps_ifdrop` 只在 `:261/:328/:344` 被写 0）。当前无害但是陷阱码：任何"以后补上真 ifdrop"的改动都会把它变成巨大伪计数 | 直接写 `// Linux 不单独报告 ifdrop，与 libpcap 一致保持 0`，删掉减法 |
| P3-2 | `af_packet.rs:326-345` | 丢包统计 2 s 节流用**报文时间戳**（`now = meta.ts_sec`）；NTP 回拨或回放历史 pcap 时 `now - prev < 2` 长期成立 → 计数器停摆 | 节流用单调钟（`task::monotonic_now`），报文时间只用于业务 |
| P3-3 | `capturer/af_packet.rs:280-288` | `recvmsg` 返回 0 被当作合法零长帧下发到 sink（`caplen=0,len=0`）；AF_PACKET 上这通常意味着 socket 状态异常 | `n==0` 时视作 EOF/错误并按 P2-3 限频告警 |
| P3-4 | `zmtp/client.rs:304` | `self.conn.as_mut().unwrap()`（`panic="abort"` 下即整进程消失）；当前由 `is_connected()` 前置可证不可达 | 改 `let Some(conn)=self.conn.as_mut() else { return; }` 或引入 `OpenConn` 类型状态（与 P1.3 的 `PipelineShared` 同风格） |
| P3-5 | `bpf/compiler.rs:91` | `or_all([]).expect(...)`；当前调用点恒非空 | 改返回 `Option<NExpr>` 或在文档写明前置条件（同 P3-4） |
| P3-6 | `bpf/interp.rs:20-81` | 解释器无步数上限；`JMP_JA` 用 `wrapping_add`（`:56`）。`Program.insns` 为 `pub`，外部构造含后向跳转的程序可让 `evaluate()` 永久循环（内核靠 verifier 禁后跳，这里没有等价保护） | `run()` 加 `steps <= 4*insns.len()+64` 上限；`JMP_JA` 用 `checked_add` |
| P3-7 | `bpf/mod.rs:77-79` / `linux.rs:26-28` | `compile()` 不检查 `BPF_MAXINSNS(4096)`；`attach_filter` 对空程序静默 `Ok(())`（若 socket 上已有过滤则**不会摘除**） | `compile()` 显式判 `>4096` 并报错；空程序走 `SO_DETACH_FILTER` 或在 doc 里写清"no-op" |
| P3-8 | `capturer/pcap_file.rs:36-56` | 全局头 `network`(linktype, `ghdr[20..24]`) 从不校验；`DLT_LINUX_SLL`(113/276，`tcpdump -i any` 的常见产物) 会被按 Ethernet 静默错位解析 | 校验 `network==1`，否则 `Err("unsupported linktype N")`；顺手校验 `version_major<=2` |
| P3-9 | `capturer/af_packet.rs:129-146` | cmsg 解析硬编码 64 位假设（头 16 B、`len>=32` 才算 `timespec`、`(len+7)&!7` 对齐）→ 32 位 `time_t` 平台（armv7 等嵌入式目标）上时间戳会被静默忽略并退化为秒 | 用 `std::mem::size_of::<libc::timespec>()` 推导；或显式声明"仅支持 64 位平台"并写进 README |
| P3-10 | `capturer/af_packet.rs:40-42,89` | 错误消息只带裸 errno 数字（`socket(AF_PACKET) error: 1`、`bind ... error: 13`），不给 `strerror`，运维无法定位"缺 cap_net_raw / 缺 cap_net_admin / ns 不可达" | `std::io::Error::from_raw_os_error(e).to_string()`（给出 "Operation not permitted"）并附提示文案；README 的 setcap 段引用它 |
| P3-11 | `zmtp/codec.rs:262` | `if n as usize > MAX_FRAME_BODY` 在 32 位目标上先截断再比较，16 MiB 上限可被绕过（当前只发 64 位产物，风险理论性） | `usize::try_from(n).map_err(...)` |
| P3-12 | `capturer/pcap_file.rs:21,95` | `MAX_CAPLEN = 256 MiB`：一条畸形记录即可让 reader `resize` 预留 256 MB 且此后长期持有（进程基线 RSS 才 6.5 MB） | 上限降到 64 KiB（pcap snaplen 实际最大 262144，65535 已覆盖全部真实链路），超限按"文件损坏"报错 |
| P3-13 | `netutil.rs:68,74` | `bpf_filter_replace_nic` 逐字节 `out.push(bytes[i] as char)` 重编码 UTF-8：任何非 ASCII（如全角空格、中文注释）都会变成 Latin-1 乱码；ASCII 路径无碍但属潜在错误 | 用 `char_indices()` 或直接对 `&str` 切片拼接（`&bpf[..i]`） |
| P3-14 | `stats.rs:24-35,66-77` | `add()` 为 `load → store` 非原子 RMW，且 `eib` 与 `bytes` 分两步；类型是 `Sync`、被 RPC 线程 `load()` 并发读。当前依赖"每个 stats 只有一个写者"的隐式不变量 | 用 `fetch_add(rem, AcqRel)` + 进位 CAS 环；或在结构体 doc 明确"单写多读"契约并加 `debug_assert` |
| P3-15 | `task.rs:384-401` | RTC 批处理在**多 capturer** 时持 `out_sets`/`TaskManager` 锁上界为 `BATCH × max(timeout_ms)`（256×timeout_ms，`timeout_ms=200` → 最坏 51 s），期间 `cpctl stats`/`info` RPC 与 `reload_config` 全阻塞 | 每 capturer 的 poll 超时取 `min(timeout_ms, 剩余预算/BATCH)`，或每轮只 poll 一次活跃 fd（epoll 化） |
| P3-16 | `deny.toml` | `bans.wildcards="allow"`、`sources.unknown-registry/unknown-git="warn"`：通配版本或第三方 git 源可静默通过 CI；`crates/cpworker/fuzz/` 独立 workspace 不在 deny/audit 覆盖内 | 两项提到 `deny`；CI 对 fuzz lockfile 再跑一次 `cargo deny check --manifest-path crates/cpworker/fuzz/Cargo.toml` |
| P3-17 | `.github/workflows/ci.yml` | 无 `--locked`；无 MSRV(1.88) job；无 workflow 级 `permissions:`（仅 release.yml 有）；`coverage` 无阈值只有 artifact | 构建/测试统一 `--locked`；加一个 `dtolnay/rust-toolchain@1.88` 的 check job；顶层加 `permissions: {contents: read}` |
| P3-18 | `fuzz.sh:11` 头注释 | "Targets: packet_split config vxlan zmq_batch sim_dst" 已过期（实际 8 个 + diff_oracle）；`ALL_TARGETS` 未含 `diff_oracle`（由 difffuzz.sh 驱动，但注释没写） | 注释与实际列表对齐，避免"以为漏跑了 target"的误判 |
| P3-19 | unsafe 注释覆盖 | 全仓 28 处 `unsafe`、仅 15 条 `SAFETY:` 注释：`netns.rs` 8 处、`affinity.rs` 4 处、`task.rs:537`（`clock_gettime` 返回值也未判）无注释 | 与 AUDIT3 的声明对齐（补齐注释，或把 `unsafe-op-in-unsafe-fn` / `missing_safety_doc` 纳入门禁） |

---

## 5. 与 AUDIT / AUDIT2 / AUDIT3（及现存 AUDIT4）的对比

### 5.1 历史发现 —— 已修复（本轮复核确认）

| 来源 | 发现 | 本轮复核证据 |
|---|---|---|
| AUDIT §1.2 中 | cpdaemon `std::sync::Mutex` 投毒风险 | `grep -rn "std::sync::Mutex" crates/cpdaemon` → **无命中**；仅 `parking_lot` |
| AUDIT §1.2 中 | 死依赖 `thiserror`/`env_logger`（cpdaemon）、workspace `tracing*`、`tokio features=full` | `crates/cpdaemon/Cargo.toml` 直接依赖已无这三者；`tokio` 收窄为 `rt-multi-thread,macros,net,signal,sync`；`grep -rn tracing --include=Cargo.toml .` 无命中 |
| AUDIT §1.2 低 | `task.rs` ring/alloc 脆弱 unwrap | `PipelineShared`（`task.rs:107-111`）+ `start()` let-else（`:299-302`）+ `poll_packets_batch` 显式 match（`:358-364`）；非测试代码 unwrap 计数已核实 |
| AUDIT2 中 | 56 条 clippy 告警 + 无 `-D warnings` 门禁 | `cargo clippy --workspace --all-targets -- -D warnings` → **0 输出**；`ci.yml:56` 已带 `-D warnings` |
| AUDIT3 复核 | MSRV 未声明 | `Cargo.toml:12 rust-version="1.88"`，7 成员继承 ✅（但见 5.2 的"未验证"） |
| AUDIT §2.2 中 / AUDIT1 建议 4 | **C 依赖仍在（libpcap/libzmq）** | ✅ 已移除：`cargo tree --workspace \| grep -E "pcap\|zmq"` 无输出；`Cargo.lock` 241 项无 C 库；CI `test/clippy/coverage/release` 只装 protobuf-compiler |
| （现存 AUDIT4 §2.1） | `PcapReader::next()` 用 `read()` 造成位置漂移 | ✅ `9ad3f22` 已修（`pcap_file.rs:79` 用 `read_exact`）并附 1 000 条可变长 record 的大文件回归测试（`:217-255`）；本轮另外确认 EOF 后不再"游走转发垃圾包"（`capture_once` 的 `self.eof` 语义 + `next()` 恒 false） |

### 5.2 历史发现 —— 仍存在

| 来源 | 状态 |
|---|---|
| AUDIT1 §4.4 / AUDIT3 第五节 **P4.1 服务器硬件复测 `vxlan-split`** | 🟡 仍未做：`bench/RESULTS.md`（生成于 09:58）与 README 基准表（`README.md:168-178`）仍是旧机器（4 核 M-5Y31）数字，且是 **libpcap 时代**的 |
| PARITY §1.1 `dpdk/pdump.c` | ⬜ 未 port（`capturer/mod.rs:53-55` 显式报不支持），与文档一致 ✅ |
| PARITY §5.1 task reload 指纹复用 / mailbox | ⬜ 仍"重建全部 task"（`task.rs:410-437`），文档一致 ✅ |
| PARITY §5.1 无锁 ring | ⬜ 仍是 `Mutex<VecDeque>`（`ring_buffer.rs:64-66`），文档一致 ✅ |
| PARITY §5.1 cgroup v1 | ⬜ 仅 v2；`#[allow(dead_code)]` 的"ported 未接线"面仍较大（`models.rs` 9 处、`httpmix.rs` **整模块**） |
| AUDIT §1.2 低（pedantic 文档段） | ✅ `#![warn(missing_docs)]` 保留（`lib.rs:9`）；但只有 cpworker 启用，cpgolib/cpdaemon/cpsim 未启用 |
| AUDIT3 "clippy 零告警"的**限定说明** | ⚠️ **本轮推翻其一半**：AUDIT3 备注称 crate 级 `#![allow(dead_code)]` 已"收窄为逐项 allow + 注释（仅限具名项）"，但 `crates/cpdaemon/src/httpmix.rs:4` 仍是 **`#![allow(dead_code)]`（整个模块级）**，且该模块被 `grep -rn "httpmix::"` 证实**完全未被使用**。属于"有文档解释的整块豁免"，但 AUDIT3 的措辞（"仅限具名项"）与事实不符 |
| AUDIT3 "unsafe：24 处，全部有安全注释" | ⚠️ 现况：28 处 unsafe / 15 条 SAFETY 注释（见 P3-19），"全部有安全注释"已不成立 |

### 5.3 本轮**新发现**（前三轮 + 现存 AUDIT4 均未提及）

**P1：P1-1 BPF 跳转上限（11 项 not-host / 3 项 port-or 即失败）、P1-2 子集缺 tcp 方向语法、P1-3 `Output::destroy()` 无调用方（ZMQ linger 从未生效）、P1-4 `SO_RCVBUF` 静默降级（实测 32×）。**
**P2：P2-1 栈溢出 abort、P2-2 ZMTP 写缓冲相位、P2-3 日志洪泛+错误计成功、P2-4 忙轮询、P2-5 时间戳降级不可见、P2-6 i64→i32 截断、P2-7 ZMTP 无 keepalive/超时/重解析、P2-8 pending 内存上限、P2-9 AF_PACKET CI 零覆盖、P2-10 差分生成器组合深度盲区、P2-11 文档 11 处矛盾、P2-12 流程未执行。**
**P3：15 项（见上表）。**

与现存 `AUDIT4.md`（维护者自审，结论 A-）的关系：其 §2.1 关于 `read()`/`read_exact()` 的分析与修复验证**正确且可复现**（本轮已在 `pcap_file.rs:79` 与 `:216` 回归测试中确认）；但它的总体评级忽略了本报告的 P1-1/P1-2/P1-3/P1-4——其中 P1-1 恰落在它 §1.2 判定为"差分对拍实测通过"的同一模块，说明**它的"BPF 差分通过"结论建立在生成器深度不足的门禁之上**（P2-10）。因此本报告的结论是 **B / 未完成**，而非 A-。

**方法论提示（三轮审计的共同盲区）**：`clippy -D warnings` + `fuzz 不崩溃` + `小样本差分` 这三层都看不见（a）**接口被实现但没有调用方**（P1-3，trait 默认方法不参与 dead_code 分析）；（b）**测试生成器的组合深度上限**（P1-1/P1-2/P2-10）；（c）**OS 对参数的静默修正**（P1-4，`setsockopt` 返回 0 但值被改）。建议把这三类作为后续审计的固定检查项。

---

## 6. 不确定与需人工确认项

1. **混杂模式缺失的实际影响**（潜在 P1）：全仓 `grep -rni "promisc|PACKET_ADD_MEMBERSHIP|MR_PROMISC"` **无命中** → Rust 侧确定不开混杂。影响取决于原 C `libpcap.c` 里 `pcap_open_live(dev, snaplen, promisc, ...)` 第三参数是否为 1（本地无 `CLOUD_PROBE_SRC` 参考树，无法核实）。若现场依赖 SPAN/TAP 镜像口或需要抓非本机 MAC 的帧，则这是 **P1 级"抓不到包"**；若原实现是 `promisc=0`，则完全对齐。**请对照参考仓库确认并在 PARITY §4 记录结论。**
2. **`af_packet_live.rs` 是否真在 root 下通过**：`IMPROVEMENT_PLAN.md:157` 与现存 AUDIT4 §3 均声称本地通过，但该测试 `#[ignore]`，本环境无 `CAP_NET_RAW`（实测 `socket(AF_PACKET) → EPERM`）→ 无法复现验证。CI 亦不运行（P2-9）。
3. **libpcap TPACKET ring 相对 `SO_RCVBUF` 的真实容量优势**：P1-4 中"libpcap 在 CAP_NET_ADMIN 下可用 MB 级 ring"是基于内核 `packet_set_ring()` 的授权路径的推理，未在目标机实测（需 root + 高负载打流）。**核心结论（256 MB 请求 → 实测 8 MB 生效、无回读无告警）已由 `/tmp/rcvbuf.c` 实测支撑**，不依赖此推理。
4. **原 C 对 `snaplen<=0` / 超大 snaplen 的处理**：P2-6 的"变 1 字节"是 Rust 侧可复算的事实（截断 + `max(1)`），但"C 会怎么做"未核实（cJSON `valueint` 钳位只是合理推测）。请对照 `libpcap.c` 确认这是否构成新的差分分歧，并补进 `gen_config.py` 向量。
5. **BPF 表达式在真实部署中的分布**：AUDIT2 明确要求"动手前先审计用户配置中 BPF 表达式的分布"。仓库内找不到该调研的任何记录；P1-1/P1-2 的实际发生频率（多少现场 task 用了 ≥11 个转发主机或 `tcp dst port`）需业务方数据支撑。**这决定 P1-1/P1-2 是"发布阻塞"还是"文档说明即可"。**
6. **collector 侧 socket 语义**：AUDIT2 要求的第二项预研（PUSH/PULL vs REQ/REP、是否 CURVE/PLAIN、是否有 ZMTP 心跳依赖）无记录。`codec.rs:292-297 peer_type_compatible()` 容忍 `PUSH`/`ROUTER` 的宽松判定（偏离 RFC27：libzmq 对不兼容 Socket-Type 会 ERROR 断连）是否需要收紧，取决于真实 collector 形态。
7. **`PACKET_STATISTICS.tp_drops` 的 u32 环绕**：`wrapping_sub` 对 32 位累计计数器正确，但需在有 `--ignored` live 测试的环境验证与 libpcap `ps_drop` 曲线的一致性（本报告只做了静态核对）。
8. **`PcapWriter` 恒写小端**：与 libpcap"按主机字节序写"不同（读侧兼容双向 ✅）。若下游有按主机字节序解析 pcap 的老工具（少见），需确认。

---

## 7. 结论与下一步建议（按优先级）

**结论**：P3 是一次**方向正确、实现纪律优秀**的重写——安全 Rust、模块边界清晰、可测试性好、测试与 fuzz 面明显扩大，且已证明纯 Rust 读路径可以比 libpcap 更快。但**"纯 Rust 已完成"这一声明目前只对"被测到的子集"成立**：4 个 P1（其中 2 个是"常见合法 BPF 过滤器编译失败 → 探针静默不抓包"，1 个是"优雅退出丢 ZMQ 批次"，1 个是"抓包缓冲被静默缩小一个量级"）说明替换门槛尚未达到，而现有门禁（clippy/fuzz/差分/文档）在结构上看不见它们。因此**综合评级 B，P3 不宜作为默认切换的发布里程碑**；建议按下面的顺序补齐后，再重新宣布"完成"。

**下一步（按优先级）**

1. **[P1-1] 实现跳转中继（JA jump-around）+ 复杂度/长度显式报错**，并加 11/50/200 项 `not host`、N 项 `port`/`host` 或链回归；同步把这些形态加进 `parity/gen_bpf_cases.py`，让差分门禁自身能发现它。**这是唯一可能让现场"完全没有数据"的缺陷，最高优先。**
2. **[P1-2] 补齐 `[src|dst] PROTO port/portrange` 与 `ether src|dst`，并在 PARITY §4 列出完整不支持清单**；把"编译失败表达式"提升为 stats/`info` 里可见的字段而非仅 stderr。
3. **[P1-3] 让 `Output::destroy()` 有唯一调用点**（`TaskManager::stop()` / reload 前显式遍历），并用 mock peer 写一条"重载时批次不丢"的回归测试。
4. **[P1-4] `SO_RCVBUFFORCE` + `getsockopt` 回读 + 缩水告警**；同时把 §6-1（混杂模式）确认清楚——两者同属"采集面等价性"，最好一个 PR 一并解决。
5. **[P2-1] 表达式长度/递归深度上限**（消除可达的进程 abort）；给 `bpf` fuzz 加结构型种子。
6. **[P2-9/P2-10] 采集与 BPF 路径进门禁**：一个可跑的 live 抓包 CI job（privileged 容器或 `unshare -n`+veth），以及 pcap reader fuzz；把 DST（`crates/sim`）扩到"BPF 过滤 + ZMTP 输出"的离线端到端闭环，这是唯一能同时覆盖 P2-2/P1-3 的层次。
7. **[P2-2/P2-7/P2-8] ZMTP 健壮性包**：写缓冲单 FIFO 不变量 + `can_write_messages`、TCP keepalive/`TCP_USER_TIMEOUT`/握手超时、connector 重解析 DNS、`hwm` 范围校验 + `pending_bytes` 指标。
8. **[P2-3/P2-4/P2-5/P2-6] 错误与资源卫生包**：错误限频 + 正确计入 `error_drop_*`、空闲不忙轮询、`SO_TIMESTAMPNS` 返回值检查与降级可见、配置数值 `try_into` + 范围校验。
9. **[P2-11/P2-12] 一致性与流程包**：一次改齐 11 处文档矛盾（含测试数 107、README 快速上手指令、基准重跑）、补 `CONTRIBUTING.md`/`CHANGELOG.md`/`CODEOWNERS`、为 P3 补 feature flag 或 capturer 类型开关以恢复可回退性、把 AUDIT2 要求的两项预研补成文档、修正 AUDIT3 中"逐项 dead_code allow"与"unsafe 全部有安全注释"两处与现状不符的措辞。
10. **[工程加固小项，可合并为一个 PR]**：CI 全部加 `--locked` + 新增 1.88 MSRV job + workflow 级 `permissions`；`deny.toml` 把 `wildcards`/`unknown-registry` 提到 `deny` 并覆盖 fuzz workspace；`release.yml` 删除 macOS 的 `brew install libpcap zeromq`；`fuzz.sh` 头注释同步 target 列表；P3 表中的 19 项硬化按需排期。

*本报告全部结论可由文中 `文件:行` 与 §1 列出的命令复现；未复现的推断已全部收敛到 §6。*
