# 上游 issue 草稿（cloud-probe / Netis）

> 来源：将 `netis/cloud-probe` 移植为 Rust 的过程中，通过 **C↔Rust / Go↔Rust 差分模糊测试**、逐字节对拍与源码对照发现。
> 逐条差分的记录见本仓库 `PARITY.md §2`（有意分歧）与 `AUDIT*.md`。
> 参考基线：`cloud-probe` @ `f925e5f6`（`v0.9.4-3`），Linux 7.x，libpcap 1.10.4，Go 1.27。
> 除 `#231`（ZMQ VLAN 越界，已报）外，以下均未见已报 issue。
>
> 用法：每条可直接贴进 GitHub issue（用仓库自带模板）。`测试环境` 里的 CP 版本/OS 请替换为你的实际值。
> 标 **[请确认]** 的是"可能是 by design"、希望维护者答复的。

---

## S1. CPM HTTP 客户端无条件 `InsecureSkipVerify: true`（TLS 校验被关闭）

**测试环境**
- CP 版本：v0.9.4（commit f925e5f6）
- 操作系统：任意
- 运行平台：容器/虚拟机

**问题描述**
`cpdaemon` 连接 CPM 时把 TLS 证书校验关掉，且没有开关：

- `cpdaemon/cmd/internal/asm/provider.go:114` → `InsecureSkipVerify: true`

也就是说，任何能对 CPM 通道做中间人的一方，都可以用任意自签证书冒充 CPM，返回伪造的 JSON——而这些响应会**驱动探针创建采集任务、下发 BPF 表达式 / 转发主机 / 输出目标**。这不是只影响"本地可见"的问题，而是远程可影响探针行为。

**重现方法**
1. 起一个 CPM 的"假"HTTPS 服务端，使用自签证书；
2. 配置 `cpm.base_url` 指向它；
3. 观察 `cpdaemon` 正常握手并接受其响应（无证书错误）。

**期望**
默认校验服务端证书（可用配置显式关闭），并支持 mTLS（PKCS#12 目前只在配置了 cert 时用于客户端证书，且 `provider.go:116` 才走 PKCS#12 分支）。

**实际**
无条件 `InsecureSkipVerify: true`，无配置可开启校验。

**附件 / 证据**
- 源码位置见上；本仓库 `SECURITY.md` 有更完整的威胁模型与临时缓解建议（专用管理网/本地反代校验）。

---

## S2-2. `packet_split.c` 接受畸形 IPv4 `ihl<5` / TCP data-offset<5，导致在错误偏移解析 L4 并转发畸形分片

**测试环境**
- CP 版本：v0.9.4（f925e5f6）；libpcap 1.10.4；Linux

**问题描述**
`packet_split.c` 对 IPv4 头长和 TCP 头长**只检查"不超过 caplen"，不检查最小合法值 20 字节**：

- `packet_split.c:250` → `result->ip_hdr_len = result->ipv4_hdr->ihl * 4;`
- `packet_split.c:265` → `result->l4_hdr_len = (result->tcp_hdr->offx2 >> 4) * 4;`

前面的检查只保证 `caplen >= sizeof(struct ipv4_hdr)`（20 字节，`:216`），`ihl=1` 时 `ip_hdr_len=4` 仍然通过；于是 L4 偏移落到 IP 头内部，TCP 端口/协议/校验和全部按错误位置解析，并据此**生成/转发畸形分片**。探针处理的是不可信网络帧，畸形头是攻击面。

**重现方法**
1. 构造以太帧 + IPv4（`ihl=1`）或 TCP（data offset=0）；
2. 调用 `parse_packet` 并 `build_fragment`；
3. 观察 C 返回解析成功并产出分片（端口/协议错位）。

**期望**
`ihl >= 5`、TCP data offset `>= 5`，否则 `parse_packet` 返回失败。

**实际**
接受并继续解析。对照：独立移植实现（Rust）额外校验两者 ≥20 字节并拒绝，同一输入两侧行为不同（差分测试已固定）。

**附件 / 证据**
- `PARITY.md §2.2`（本仓库）有逐条差分与复现说明。

---

## S2-3. 配置数值越界被 cJSON 静默钳位后接受（不报错）

**测试环境**
- CP 版本：v0.9.4（f925e5f6）

**问题描述**
`config.c` 用 cJSON 的 `valueint` 读数值字段（`config.c:217/255/266/...`，如 `snaplen`、`buffer_size_mb`、`timeout_ms`、`ring_size`）。cJSON 在解析超范围数字时会**钳位到 `INT_MAX/INT_MIN`**（`cpworker/src/cJSON/cJSON.c:366/370`、`:388/392`、`:2463/2467`），而不是报错。

于是 `"snaplen": 2147483648` 被静默变成 `2147483647`，`buffer_size_mb`/`timeout_ms`/`ring_size` 同理——一个 typo 就能让探针带着荒谬参数运行，而日志上看不出配置被改。

**重现方法**
1. 配置 `{"capturer":{"type":"libpcap","libpcap":{"interface":"lo","snaplen":2147483648}}}`；
2. 启动；
3. 实际生效的 snaplen 为 `2147483647`，无任何报错。

**期望**
超范围数值报错（含字段名与允许范围），而不是钳位。

**实际**
钳位后接受。对照：Rust 端口改为 `invalid libpcap.snaplen 2147483648: must be between 0 and 262144`（`PARITY.md §2.3`）。

---

## S2-4. `zmq.hwm=0` 语义为"无限队列"，配置无校验 → 内存可无界增长 **[请确认]**

**测试环境**
- CP 版本：v0.9.4（f925e5f6）

**问题描述**
`output_zmq.c:390` 直接把配置值设给 `ZMQ_SNDHWM`：
`zmq_setsockopt(pusher, ZMQ_SNDHWM, &opts.hwm, sizeof(opts.hwm))`，`config.c` 对 `zmq.hwm` 无范围校验。libzmq 约定 **`ZMQ_SNDHWM=0` 表示"无上限"**。

当 collector 背压/断连时，发送队列会无界增长 → 内存耗尽（OOM），而配置里 `"hwm": 0` 看起来像"0 条"。

**重现方法**
1. `"outputs":[{"type":"zmq","zmq":{"host":"127.0.0.1","port":9000,"hwm":0}}]`；
2. 让 collector 只接受连接、不读取；
3. 观察进程内存持续增长。

**期望**：对 `hwm` 做范围校验，或把 `0` 显式定义为"无限"并在文档/日志中警示。
**请确认**：这是有意允许"无限队列"，还是被认为应当由运维自行保证？

---

## S2-5. 接口 down 时 task 创建直接失败（不重试） **[请确认]**

**测试环境**
- CP 版本：v0.9.4（f925e5f6）；libpcap 1.10.4

**问题描述**
libpcap capturer 在 `pcap_activate` 失败时直接让 task 创建失败（`libpcap.c` 中 `if (pcap_activate(p) < 0) { error_format(...); goto error; }`，约 `:203`）。接口 flapping（网络故障、容器网络重建期间很常见）会让该 task **直接不启动**，而不是存活等待接口恢复。

**重现方法**
1. 把一个接口 `ip link set <if> down`；
2. 创建 `libpcap` 任务；
3. 观察到 `pcap_activate error: That device is not up` 且任务未创建；接口恢复后也不会自动重试。

**期望**：可配置为"创建失败即报错"或"保持任务、等待接口恢复"。
**请确认**：当前"直接失败"是刻意的吗？（有现场会希望 task 在接口短暂 down 时存活。）

---

## S2-6. 配置解码过于宽容：字段名大小写不敏感 + 缺失字段零值填充 **[请确认]**

**测试环境**
- CP 版本：v0.9.4（f925e5f6）；Go 1.27

**问题描述**
`cpdaemon`/`cpm` 用 Go `encoding/json` 解码 worker 配置，而 `encoding/json` 对结构体字段名是**大小写不敏感**匹配的（`cpdaemon/pkg/worker/config.go:23-60` 的 `json:"..."` 标签），且**缺失字段保留零值**、不一定报错。

结果：`snAplen` / `sNaplen` 这类拼写错误、漏写必填段，都可能被静默接受并用默认值起 task，排障困难。

**重现方法**
1. 把 `snaplen` 写成 `snAplen`；
2. 观察仍能解析（落到默认值），无告警。

**期望**：严格匹配字段名；缺失必填字段给出明确错误。
**请确认**：这是刻意的宽容，还是可以收紧？

---

## S3-7. cJSON 对重复 key / 尾随垃圾 / 非法 `\uXXXX` 的宽容语义 **[请确认]**

**测试环境**
- CP 版本：v0.9.4（f925e5f6）

**问题描述**（三小项，均属"是否应严格校验 JSON"的取舍）
1. **重复 key 取首个**：`{"command":"a","command":"b"}` → cJSON 取 `"a"`（`cJSON_GetObjectItemCaseSensitive` 返回首个），而多数 JSON 实现取最后一个。
2. **尾随垃圾容忍**：`{...},` 仍被接受。
3. **非法 `\uXXXX` 转义**：宽容接受。

**影响**：歧义/非法输入在同一份配置里可能被不同实现（或后续版本）解释成不同结果；对"配置即代码"的运维不友好。

**请确认**：这些是有意为之（保持宽松）还是可以改为严格报错？

---

## S3-8. `req_pattern` 端口解析接受 `-0`（`strtol`）

**测试环境**
- CP 版本：v0.9.4（f925e5f6）

**问题描述**
`req_pattern.c:183` 用 `strtol(value, &endptr, 10)` 解析端口，`strtol` 接受 `-0`（及前导空白/符号），得到端口 0 而非报错。差分测试显示：C 接受 `port -0`，Rust 的 `u16::parse` 拒绝。

**重现方法**：`req_pattern` 表达式里写 `port -0`；观察 C 侧接受。
**期望**：非法端口报错。
**实际**：`-0` 被当作 0。影响很小，仅作健壮性记录。

---

## S3-9. `timeout_ms==0` 时 libpcap TPACKET_V3 分批延迟（已有 workaround，确认残留） **[请确认]**

**测试环境**
- CP 版本：v0.9.4（f925e5f6）；libpcap 1.10.4

**问题描述**
`timeout_ms==0` 时 libpcap 会把 TPACKET_V3 的 `tp_retire_blk_tov` 设为 `UINT_MAX`，块只有填满或 retire 才可见 → 低速下**多秒成批交付**（ZMQ 突发）。当前 `libpcap.c:160+` 已有 workaround（启用 immediate mode 退回 TPACKET_V2；不可用时设 10ms 回退）。

**请确认**：该 workaround 是否已覆盖你们支持的全部 libpcap 版本？在 **libpcap < 1.5（无 `pcap_set_immediate_mode`）** 的运行时，回退 10ms 是否仍会造成可感知的分批？若是，是否值得在文档中明确最低 libpcap 版本？

---

## 附：不建议报的（供参考，避免重复）
- **libpcap 在 loopback 只交付接收副本**（`linux_check_direction`）：这是 libpcap 的预期行为，不是 cloud-probe 缺陷。
- **`pcap_set_immediate_mode` weak symbol 的运行时版本耦合**：是规避手段，不是 bug。
- **issue #231（ZMQ VLAN 遍历越界读写）**：已报告，且在独立移植中已复现并做了回归。
