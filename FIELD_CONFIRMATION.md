# 上线前需现场/业务确认清单

本文件把 `IMPROVEMENT_PLAN_AUDIT4.md` §5.1「仍需外部输入」的条目整理成可直接对接的清单：
每一项说明**需要什么数据/确认**、**为什么重要**、**如何采集**、以及**它解锁哪个决策**。
这些事项在本环境（单机、单核数、无现场镜像口）无法得出可信结论。

> 状态图例：⬜ 待确认 / ✅ 已确认（附结论）。

## 1. ⬜ BPF 表达式现场分布

- **需要**：CPM 实际下发的 BPF 表达式样本（去敏后即可），至少覆盖出现频率最高的若干条；重点是含
  `vlan`、`greater`、`less`、`len`、算术表达式、`src tcp` 等**本移植当前不支持**的写法。
- **为什么重要**：决定 P5-01/P5-06（BPF 编译器覆盖面）是「发布阻塞」还是「文档说明即可」。
  目前的 tcpdump 子集已支持 `host/net/port/portrange/proto`、`[src|dst]`、`ether host`、
  `ip proto`、`and/or/not`、括号、长跳转链；不支持清单见 `PARITY.md §4`。
- **如何采集**：向 CPM 侧取一份「策略里出现过的 bpf 字段」的去重列表 + 出现次数。
- **解锁决策**：是否需要补齐不支持的语法，或仅在文档/启动日志中对不支持的表达式给出明确告警。

## 2. ⬜ 混杂模式（promisc）意图

- **需要**：确认原 C 实现是否有意设置混杂模式；镜像口/SPAN 场景下的预期采集面。
- **已核实（2026-10，上游源码 + yinjiao 内核实验）**：
  - 上游 C 的 libpcap 路径调用 `pcap_set_promisc(p, opts.promisc)`（`libpcap.c:154`），但
    `opts.promisc = 0` 是**硬编码**（`libpcap.c:340`）、**不从 JSON 读取** → C 的 libpcap 路径
    **永不启用混杂、也不可配置**。DPDK pdump 则 `promiscuous_mode = true` 默认为开（`dpdk/pdump.c:386`）。
  - 本移植（AF_PACKET，libpcap 类比）不设 `PACKET_MR_PROMISC` → **与 C libpcap 完全一致**。
  - yinjiao veth 内核实验：AF_PACKET `SOCK_RAW` 在**非 promisc** 下仍能收到 dst MAC 非本机、
    非广播的单播帧（虚拟设备不建模硬件 RX 过滤）→ promisc 的取舍由**物理网卡/SPAN 镜像**决定，
    veth 无法复现。
  - **现场实测（2026-10，yinjiao 直连口 `ens5f0`，`rx-vlan-filter: on [fixed]`）**：
    在真机 NIC 上，**非混杂模式会丢弃未注册 VLAN 的 802.1Q/QinQ 帧**，而混杂模式不会——
    `tcpdump`（默认混杂）抓到全部 900 帧（含 600 带 VLAN 标签），`tcpdump -p`（关混杂）
    只抓到 300 帧（无 VLAN），与 cpworker（不设 promisc）**完全一致**。
    → **promisc 不是纯 parity 问题，而是 trunk/SPAN 场景的功能正确性前提**：
    C libpcap 硬编码 `promisc=0`，在带 VLAN 的镜像口会**丢带标签流量**，与本移植一致但均不完整。
- **为什么重要**：直接决定采集面等价性（三篇审计均未定论）。本移植的 AF_PACKET 路径当前
  **不设** `PACKET_MR_PROMISC`。
- **如何采集**：现场以镜像口/SPAN 部署时，对比同一镜像流量下 C 版与本移植版抓到的帧数/流量
  （即验证物理网卡在非 promisc 下是否丢弃镜像帧）。
- **解锁决策**：若现场确为 SPAN/trunk 且网卡在非 promisc 下丢 VLAN 帧（已实测成立），
  则**必须新增** `promisc` 配置项并**默认开启**（相对 oracle 的功能修复；DPDK pdump 本就默认开）。
  这是当前唯一同时影响 parity 与功能正确性的现场项。

## 3. ⬜ libpcap TPACKET ring 相对 `SO_RCVBUF` 的高负载容量

- **需要**：高负载（如 10Gbps 镜像口）下的实测：ring 可用 MB 数、丢包率、`SO_RCVBUF` 上限。
- **已实测（2026-10，yinjiao ↔ jinjiao 25G 直连）**：
  - 环境：yinjiao(10.0.0.11) 在 `ens5f0`（25G，直连 jinjiao 10.0.0.10）实抓；jinjiao 用 `iperf3 -u`
    定向泛洪。cpworker 配置 `buffer_size_mb=256` → 实测 **`SO_RCVBUF=536,870,912`（512 MB，SO_RCVBUFFORCE）**，
    BPF `udp and dst port 5201`，输出 null。
  - 实测（单位 pps 为 `iperf3 -l 1448` 报文的到达率）：

    | 到达速率 | 包数 | cpworker 捕获 | 内核 `Drop Packets` | iperf 自身 socket 丢包 |
    | --- | --- | --- | --- | --- |
    | 4.37 Gbps (380k pps) | 3,796,167 | 全部 | **0** | 0.64% |
    | 7.16 Gbps (618k pps) | 3,706,822 | 全部 | **0** | 0% |
    | 8.72 Gbps (753k pps) | 4,516,894 | 全部 | **0** | 0% |
    | 14.2 Gbps (1.25M pps) | 10,018,455 | 6,771,712 | **2,728,783 (27%)** | 1.8% |

  - **结论**：单线程采集路径在 **~750k–900k pps（≈8–9 Gbps @1448B）以内零丢包且精确捕获**；
    超过后**用户态 drain 成为瓶颈**，内核 `PACKET_STATISTICS` 的 drop 计数线性上升（buffer 再大也不能
    提升稳态 drain 上限，只能延缓首次丢弃）。注意 iperf3 普通 UDP socket 在 4.37G 已丢 0.64%，而
    `AF_PACKET + 大 SO_RCVBUF` 路径 0 丢——采集路径在大缓冲下优于普通 socket。
  - **含义**：`buffer_size_mb=256`（512MB）对低速率域充裕；若要支撑 >9 Gbps 的镜像口，需要
    **多 worker/多队列**（RPS/RSS 或按接口多 task）而非单纯加大 buffer——可作为后续增强项。
- **为什么重要**：核心结论（256 MiB 默认）已实测；「ring 可用 MB 级」仍需高负载确认，
  关系到 P3「去 C 依赖」后采集路径的可达上限。
- **如何采集**：在目标硬件上用现成工具对比：C 版（libpcap TPACKET_V3）与本移植版
  （AF_PACKET mmap ring）在同一流量下的 `cap_drop`/`cap_bytes`。
  可用 `bench/live_bench.py`（root、veth 参数化）做受控注入。
- **解锁决策**：`buffer_size_mb` 默认值与上限是否需要在现场硬件上重新标定；
  是否需要为高带宽口增加多 task/多队列采集。

## 4. ⬜ VLAN / H3 的现场影响

- **已实测（2026-10，yinjiao ↔ jinjiao 25G 直连 + `ens5f0`）**：
  - 用 Python 原始 L2 构造正确的 802.1Q（vlan 100）与 QinQ（outer 0x88a8/100 + inner 0x8100/200）
    的 HTTP 请求帧，从 jinjiao 发向 yinjiao。
  - `tcpdump`（混杂）同口抓到并正确解出**全部 900 帧**（300 无标签 + 300 单标签 + 300 QinQ）。
  - cpworker（不设 promisc）只抓到 **300 帧**（无标签组）。
  - 隔离验证：同一批帧用 **`pcap_file` 捕获器**喂给 cpworker（本地），输出 pcap **900/900 全保留，
    含 600 带标签** → 捕获器的 VLAN 重插（AUXDATA，P5-03）**正确**。
  - 再用 **`tcpdump -p`（关混杂）** 复测，同样只得 300 帧 → **根因是 promisc，不是 VLAN 处理**。
  - **结论**：VLAN 帧丢失源于**非混杂模式下 NIC 的 VLAN 过滤**（j36.2），而非 P5-03 重插缺陷；
    修 j36.2（加 `promisc` 并默认开）即可同时解决 VLAN 场景。H3 未涉及（无对应头样本）。
- **需要**：在 trunk 口 / 镜像口实测带 802.1Q（含 QinQ）与 H3 扩展头的流量。
- **为什么重要**：评估 VLAN 重插与 H3 相关处理在现场的严重度（P5-03 已实现 AUXDATA VLAN 重插，
  但现场量级未知）。
- **如何采集**：现场抓到带标签的样本 pcap + 本移植版回放/实采的对照。
- **解锁决策**：VLAN/H3 相关缺陷是否构成发布阻塞。

## 5. ⬜ `vxlan-split` 服务器硬件复测（= `IMPROVEMENT_PLAN.md` P4.1）

- **已实测（2026-10-01，yinjiao，Xeon Gold 6430 ×128、503 GiB、`scaling_governor=performance`）**：
  用 `bench/bench.py`（`N=1000000`、`REPEAT=3`、离线 pcap 回放）在同机对比 C vs Rust：

  | 场景 | C 中位 | Rust 中位 | C/Rust 比值 |
  | --- | --- | --- | --- |
  | null | 0.174 s | 0.144 s | **1.21×**（Rust 快） |
  | file | 0.405 s | 0.344 s | **1.18×**（Rust 快） |
  | vxlan-split | 4.154 s | 4.160 s | **1.00×**（持平；区间 0.88–1.17×） |

  - Peak RSS：Rust 在 null/file 更低（1.1 vs 2.6 MB）；vxlan-split 略高（2.9 vs 2.6 MB）。
  - `vxlan-split` 的方差较大（ratio spread 0.29，stdev 223/313 ms），因为该机为共用的真实
    服务器（背景负载）。结论：在目标硬件上 Rust **不慢于 C**（null/file 更快，vxlan-split 持平）。
  - 完整原始行已追加进 `bench/RESULTS.md`（“Run 2026-10-01 04:20:17”）。
- **需要**：一台固定 CPU 频率、关闭频率调节（`performance` governor）的服务器。
- **为什么重要**：当前相对性能数字是在本环境测的；`vxlan-split` 的绝对吞吐/CPU 需要目标硬件复测。
- **如何采集**：用 `bench/`（`bench.py`/`measure.py`/`live_bench.py`）在目标机复跑并记录
  `RESULTS.md`（含 `startup_s`/`flush_after_s`/离散度）。
- **解锁决策**：是否达到验收的吞吐/时延目标 → 已满足（Rust ≥ C）。

## 6. ⬜ CPM 通道安全策略（产品决策）

- **需要**：确认 CPM 通道是否允许/要求校验证书、是否必须 mTLS。
- **为什么重要**：原 Go 实现仍硬编码 `InsecureSkipVerify: true`（上游 issue #232，已报告）；
  **本移植已改为默认校验服务端证书**（`cpm.client.tls.insecure_skip_verify = false`，见
  `SECURITY.md` / `PARITY.md` §2.7），且 **PKCS#12/mTLS 客户端证书已接线**（`ryg.2`）：配置
  `cpm.client.tls.pkcs12_cert_file` 时以该证书作为客户端身份。是否在部署中**强制** mTLS 仍由产品决定。
  这是可远程影响探针行为的通道，仍需要产品确认最终策略。
- **如何采集**：与产品/安全团队确认部署拓扑（是否专用管理网、是否已有本地校验反代、CPM 证书链、
  是否需要并要求探针出示客户端证书）。
- **解锁决策**：是否保持默认校验（现态）/ 是否要求 mTLS（客户端证书支持已就绪，仅需部署配置）。

---

### 已闭环（无需现场，保留以备复核）

- **「`af_packet_live` 特权执行」**、**「A1 loopback 重复帧」**、**「实时抓包吞吐/保真度门禁」**：
  见 `IMPROVEMENT_PLAN_AUDIT4.md` §5.2。
