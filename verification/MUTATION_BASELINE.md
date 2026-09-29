# Mutation baseline（mutation 基线记录）

`VERIFICATION_COVERAGE.md §7` 的 mutation 维度落地记录。工具 `cargo-mutants`
（`verification/mutants.toml`、`verify_mutation.sh`）；每周 `verification.yml` 分 4 shard 运行，
当前 **advisory**，待基线建立后纳阻塞。

## 怎么跑

```bash
cargo install cargo-mutants            # 或 CI 的 taiki-e/install-action
./verify_mutation.sh                   # 配置范围内全量（慢，本地/定时）
./verify_mutation.sh --in-diff         # 只变异相对 origin/main 的改动行（PR 用）
./verify_mutation.sh --shard 1/4       # 分片（周任务矩阵）
# 单文件快速采样：
cat > /tmp/mut-one.toml <<'EOF'
examine_globs = ["crates/cpworker/src/output/gre.rs"]
EOF
cargo mutants --config /tmp/mut-one.toml --no-times
```

## 测量记录

| 日期 | 范围 | mutants | caught | missed | 结论 |
|---|---|---:|---:|---:|---|
| 2026-09-29 | `crates/cpworker/src/output/gre.rs` | 76 | 0 | **76** | GRE 输出路径**几乎没有测试**（行覆盖 ~8%） |
| 2026-09-30 | `crates/cpworker/src/output/gre.rs`（补测后） | 50 | **50** | 0 | 100%（抽出 `Egress` 抽象 + 21 个单测；不可观测/root-only 项已 `exclude_re`） |
| 2026-09-30 | `crates/cpgolib/src/cpworker/stats.rs`（补测后） | 56 | **56** | 0 | 100%（跨单位借位、const 字面值、compare 排序） |
| 2026-09-30 | `crates/cpworker/src/config.rs`（补测后） | 70 | 59 | 0 | 0 missed；8 unviable / 3 runner-timeout（已 `exclude_re` 并注明，行为由访问器测试断言） |
| 2026-09-30 | `crates/cpworker/src/output/vxlan.rs`（补测后） | 96 | **96** | 0 | 100%（抽出共享 `Egress` + 19 个单测 + 6 组 golden wire 向量；等价/root-only 项已 `exclude_re`） |
| 2026-09-30 | `crates/cpworker/src/packet.rs`（补测后） | 284 | 251 | 0 | 0 missed；46 个新测试（VLAN 单/双、IPv4/IPv6 + 扩展头、边界长度、`extract_ipport`/VXLAN 逐层）；剩余为等价边界 guard（已 `exclude_re`） |
| 2026-09-30 | `crates/cpworker/src/packet_split.rs`（补测后） | 128 | **127** | 0 | 仅 `158:81` 等价（校验和只读 ihl 字节）；补 golden 校验和 / 分片字节 / 校验和归零不变量测试 |
| 2026-09-30 | `crates/cpworker/src/zmtp/**`（部分） | — | 71 | 27 | 运行被超时中断；已捕获多处 `Conn`/`ZmtpPush` 状态机存活，待补齐（见下） |
| 2026-09-30 | `crates/cpworker/src/zmtp/codec.rs`（补测后） | 101 | **92** | 0 | 3 例等价（已 `exclude_re`）；补常量/Display/greeting/命令/边界测试 |
| 2026-09-30 | `crates/cpworker/src/bpf/**`（部分） | — | 44 | 98 | 运行被超时中断；bpf parser/compiler/interp 仍有大量未固定行为，待专门收敛 |

首次测量中 `GreOutput::send_packet` 与 `_pmtudisc_consts` 的全部算术/比较/逻辑变异均**存活**，说明该路径的行为没有被任何测试固定。
补测后 GRE 与 cpgolib stats 均达到 100% caught，config 无 missed。

### 已关闭的缺口

- `cpworker::output::gre`：抽出 `Egress` trait（`RawSocketEgress` / 测试用 `MockEgress`）后将发送/重试/统计状态机完全单测化；
  覆盖 slice/clamp、未知方向丢弃、令牌桶扣减、部分发送、ENOBUFS 重试与耗尽、其它 errno、error-info 5s 窗口。
- `cpgolib::cpworker::stats::{BytesStats,PacketsStats}`：补跨单位借位、单位常量字面值、`compare` 排序、相等不减。
- `cpworker::output::vxlan`：抽出 `Egress`（与 GRE 共享 `output::Egress`/`RawSocketEgress`），
  覆盖 fast path / slice / 令牌桶 / 部分发送 / ENOBUFS 重试·耗尽 / 其它 errno / error-info 窗口 /
  分片发送路径；并用 6 组 golden wire 向量固定 VNI v1/v2/方向/时间戳/校验和布局。
- `cpworker::packet`：L2–L4 解析器补 46 个测试（Ethernet/VLAN 单·双、IPv4/TCP/UDP、
  IPv6 + HOPOPTS/ROUTING/DSTOPTS 扩展头、FRAGMENT 拒绝、payload_len 截断、`extract_ipport` v4/v6/VLAN/VXLAN 逐层）；
  mutation 从 46 caught 提升到 251 caught，剩余为等价边界 guard。
- `cpworker::packet_split`：补校验和 golden 值（`cksum_*`/`htons`/IP·TCP·UDP v4·v6）、分片字节 golden、
  “重算后校验和归零”不变量、IPv6/UDP 长度修正；mutation 127/128（仅一例等价）。
- `cpworker::zmtp::codec`：补常量/`Display`/greeting 签名/命令帧（ERROR）/短/长帧与 255·上限边界测试；mutation 92/101（3 例等价）。
- `cpworker::config` 访问器与反序列化：`output_type`/`capturer_type`/`snaplen`/`interface`/`forward_host`、
  `canonical_dump`（含 libpcap bpf 与输出主机排除）、`de_nonnull`/`de_nonnull_bool`、`int_in`、`parse_pmtudisc`、
  日志级别与 execution model、重复/ 空 fingerprint、默认值（pmtudisc=-1 等）。

### 待补（尚未测量）

- `cpworker::bpf::{parser,compiler,interp}`、`zmtp::client`、`cpgolib` 其余模块。全量 `./verify_mutation.sh`（分 4 shard，weekly）后回填。
- `cpworker::bpf::mod::attach_filter`（需 root，归入 `live-capture`）。

## 策略

- 阈值（Tier 0 ≥85% / Tier 1 ≥75% / Tier 2 ≥60%，见 `policy.toml`）为**目标**；
  未基线化前 **不阻塞**，仅每周报告 + 记录缺口。
- PR 使用 `--in-diff`（只变异改动行）；待全量基线稳定后可对改动范围启用"零存活 mutant"硬门禁。
- 缺口清单（已关闭见上；待测范围见下）：
  - ~~`cpworker::output::gre`~~ ✅ 100%
  - ~~`cpworker::output::vxlan`~~ ✅ 100%
  - `cpworker::packet` ✅ 251/284（余为等价边界 guard）
  - `cpworker::packet_split` ✅ 127/128（唯一存活为等价）
  - `cpworker::zmtp::codec` ✅ 92/101（3 例等价）
  - ~~`cpgolib::cpworker::stats::sub`~~ ✅ 100%
  - ~~`cpworker::config` 访问器~~ ✅ 0 missed
  - `cpworker::bpf::{parser,compiler,interp}`（部分：44 caught / 98 missed，待收敛）
  - `cpworker::bpf::mod::attach_filter`（需 root，归入 `live-capture` 覆盖）
