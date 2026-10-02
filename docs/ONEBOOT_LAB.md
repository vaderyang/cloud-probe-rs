# OneBoot 真机发布验证流水线

本文说明如何用内网 PXE 装机平台 **OneBoot**（`oneboot.netisdev.com`）为
`cloud-probe-rs` 做「跨平台构建 → 对应平台上真机验证」的发布流程。

相关文件：

| 文件 | 作用 |
| --- | --- |
| `tools/oneboot/oneboot_client.py` | OneBoot 管理 API 的无依赖客户端（只读自检 / 列表 / 上传 kickstart / 触发） |
| `tools/oneboot/on_target_smoke.sh` | **在目标机上执行**的发布件冒烟/兼容性验证，输出 `result.json` |
| `tools/oneboot/lab_verify.py` | 编排：生成 kickstart → 上传 → 触发启动 → 回收结果 → 产出 JUnit |
| `tools/oneboot/vm_verify.py` | 无 BMC/物理机时，用本机 QEMU/KVM 装同一 OS 并验证 |
| `tools/oneboot/run_inventory.py` | 读取机器清单，逐台执行并按清单聚合结果 |
| `tools/oneboot/inventory.example.json` | 机器清单模板（复制为 `inventory.json`） |
| `.github/workflows/lab-verify.yml` | 内网 self-hosted runner 上的验证工作流 |

---

## 1. 侦察结论（为什么这样设计）

### 1.1 OneBoot 是什么

内部网络装机控制台（前端 React + 后端 gunicorn，nginx 反代；PXE 由 dnsmasq/TFTP/HTTP 提供）：

- **80 个 ISO**，架构 `x86_64` / `ARM64` / `LoongArch`，覆盖
  CentOS 7/8、RHEL 7/8/9/10、Kylin V10/V11、UOS、OpenEuler、NeoKylin、Rocky、
  Ubuntu、Debian、VMware 等；
- 启动链：iPXE → `/boot/<source>` 菜单 → `/boot/<source>/go?ks=<file>` →
  `kernel/initrd` + `inst.ks=http://<next-server>:8080/kickstart/<source>/<file>`；
- Ubuntu 走 NoCloud autoinstall（`/boot/.../go` 里注入
  `autoinstall ds=nocloud-net;s=http://<next-server>/autoinstall/<source>/<file>/`）。

### 1.2 关键约束

| 约束 | 证据 | 影响 |
| --- | --- | --- |
| **仅内网可达** | `oneboot.netisdev.com` → `10.1.1.182`；公网 DoH 返回 NXDOMAIN | GitHub 托管 runner **无法**直连；编排必须在内网（self-hosted runner 或本机） |
| 管理 API **无鉴权** | `GET/PUT/POST /api/v1/*` 均无 Authorization 头 | 客户端默认**只读**；写操作（上传 kickstart、触发）必须先 `--apply` |
| 无 per-MAC 自动装机绑定 | 前端与 API 只有 clients/sessions/kickstart；无 MAC→source 映射 | 无人值守装机需要选菜单，或 BMC/串口驱动，或给 OneBoot 加绑定能力（见 §6） |

### 1.3 已发现的实际问题：基线前的发布件跑不上大多数目标系统

收编前 `release.yml` 在 `ubuntu-latest`（Ubuntu 24.04，glibc 2.39）上原生构建
`x86_64-unknown-linux-gnu`。实测本机（Ubuntu 22.04，glibc 2.35）构建产物：

```bash
$ objdump -T target/release/cpworker | grep -oE 'GLIBC_[0-9.]+' | sort -V | uniq -c | tail
     12 GLIBC_2.34
```

即二进制要求 **glibc ≥ 2.34**。而 ISO 清单里的 CentOS 7、RHEL 7/8、Kylin V10、
UOS、OpenEuler 20.03 都是 glibc 2.17–2.28 —— **装上去直接 `GLIBC_2.34 not found`**。
这正是 `on_target_smoke.sh` 的 `bin:*` 检查会立刻抓到的问题。

**已验证的修复**：在 `quay.io/pypa/manylinux2014_x86_64`（CentOS 7，glibc 2.17）容器里
构建，产物最高只依赖 **GLIBC_2.16**：

```text
$ (manylinux2014_x86_64) cargo build --release --workspace --locked \
    --bin cpworker --bin cpctl --bin cpdaemon --bin dockerpid --bin cripid
cpworker: GLIBC_2.16
cpctl:    GLIBC_2.16
cpdaemon: GLIBC_2.16
dockerpid: GLIBC_2.16
cripid:   GLIBC_2.16
```

于是覆盖全部 glibc ≥ 2.17 的系统。该容器配方现在**就是** `release.yml` 里
`*-unknown-linux-gnu` 的构建方式（不再有第二套 gnu 产物，产物名也不再带
`-glibc217` 后缀），清单里直接用 `"artifact": "x86_64-unknown-linux-gnu"` 选取。
见 §5。

> **musl 静态构建暂不可用**：`x86_64-unknown-linux-musl` 编译失败，12 处错误集中在
> `crates/cpworker/src/capturer/af_packet.rs`（TPACKET_V3 环）与 `unix_manager.rs`，
> 都是 glibc 与 musl 的 `libc` 结构体字段类型差异（如 `msg_controllen`、`tp_*` 的
> `u32`/`usize`）。这是真实的移植 bug，已单独建 bead；修好前用 glibc 2.17 基线方案。

---

## 2. 架构

```text
 GitHub Actions（公网）                    内网 self-hosted runner（能到 OneBoot 与目标机）
 ┌───────────────────────┐                 ┌──────────────────────────────────────────────┐
 │ build matrix          │  release/       │ lab-verify.yml (workflow_dispatch / tag)      │
 │  · gnu (glibc 基线)    │  artifact       │  1. 下载 release tarball                      │
 │  · musl (静态)         │ ───────────────▶│  2. lab_verify.py：起 HTTP 载荷服务            │
 │  · aarch64 / macOS     │                 │     渲染 kickstart（%post/late-commands 拉取    │
 └───────────────────────┘                 │     on_target_smoke.sh 并执行）                │
                                            │  3. PUT /api/v1/kickstart/<source>/<file>     │
                                            │  4. BMC(ipmitool) 触发 PXE / 或人工选菜单       │
                                            │  5. 回收 result.json（callback 或 SSH 拉取）    │
                                            │  6. 产出 JUnit → CI 汇总                      │
                                            └───────────────┬──────────────────────────────┘
                                                            │ PXE + HTTP
                                            ┌───────────────▼──────────────────────────────┐
                                            │ 目标机：OneBoot 装 OS → %post 跑冒烟 → 回传    │
                                            └──────────────────────────────────────────────┘
```

**要点**：OneBoot 只在「装完 OS 后」把控制权交给我们。因此验证分两段——
`on_target_smoke.sh` 同时通过 kickstart `%post`（RHEL 系）或 `late-commands`
（Ubuntu）在**目标系统内**执行，结果通过 callback POST 或 SSH 拉回编排端。

---

## 3. on_target_smoke.sh 验证什么

在目标系统的已安装环境里：

1. 下载 release 包并校验 sha256（可变 `ARTIFACT_SHA256`）；
2. 解包，对 5 个二进制做**加载/ABI 检查**：
   - `cpworker/cpctl/cpdaemon` 走 `--version`（clap）；
   - `dockerpid/cripid` 无 `--version`，走 `ldd` + 弱参数执行，检测
     `GLIBC_x.y not found` / `error while loading shared libraries` / exit 127；
3. 特权 AF_PACKET 路径：建 veth 对 → 用生成的配置启动 `cpworker` →
   `cpctl info`（RPC 通）→ python3 注入 `FRAMES` 个 UDP 帧 →
   `cpctl -f jsonl stats -n 1` 读 `counters.cap_packets`，断言 **捕获数 ≥ 注入数**；
4. 输出 `result.json`（schema `cprs-on-target-smoke-v1`），并按 `CALLBACK_URL` 回传。

权限/依赖不足时对应检查记 `SKIP` 而非 `FAIL`；任何 `FAIL` 决定退出码。

**本地自测**（无需 OneBoot）：

```bash
# 造一个包并本地起 HTTP 服务
mkdir -p /tmp/pkg/cloud-probe-rs-local /tmp/serve
cp target/release/cpworker target/release/cpctl /tmp/pkg/cloud-probe-rs-local/
tar -C /tmp/pkg -czf /tmp/serve/cloud-probe-rs-local.tar.gz cloud-probe-rs-local
(cd /tmp/serve && python3 -m http.server 18080 &)

# 非特权：capture 会 SKIP
ARTIFACT_URL=http://127.0.0.1:18080/cloud-probe-rs-local.tar.gz \
  WORKDIR=/tmp/smoke bash tools/oneboot/on_target_smoke.sh; echo $?

# 特权：跑完整 veth 捕获
sudo env ARTIFACT_URL=... WORKDIR=/tmp/smoke-root FRAMES=1500 \
  bash tools/oneboot/on_target_smoke.sh
```bash

---

## 4. 运行手册

### 4.1 准备机器清单

```bash
cp tools/oneboot/inventory.example.json tools/oneboot/inventory.json
$EDITOR tools/oneboot/inventory.json
```

字段见模板注释。密钥**不落盘**：BMC/SSH 用 `pass_env`/`key_env` 指向环境变量
（CI 里用 secrets）。

### 4.2 只读自检（安全，不动任何东西）

```bash
tools/oneboot/oneboot_client.py selftest
# PASS status / sources / kickstart / install-events / clients / boot-script
```bash

### 4.3 干跑（渲染 kickstart，不上传、不动机器）

```bash
tools/oneboot/lab_verify.py plan \
  --artifact dist/cloud-probe-rs-x86_64-unknown-linux-gnu.tar.gz \
  --source centos_7_9_x86_64_dvd_2009 --serve-host 172.16.103.86
```

或整份清单干跑：

```bash
tools/oneboot/run_inventory.py --artifact-dir dist --dry-run
```bash

### 4.4 真正执行（会写 OneBoot 并重启目标机）

```bash
export LAB_BMC_PASS=...          # inventory 里 pass_env 指定的变量
export LAB_SSH_KEY="$(cat ~/.ssh/lab_key)"

tools/oneboot/run_inventory.py \
  --inventory tools/oneboot/inventory.json \
  --artifact-dir dist \
  --junit-dir build/lab-junit \
  --apply --trigger ipmi
```

- `--trigger manual`：脚本打印引导 URL，人工在 PXE 菜单里选生成的 kickstart；
- `--trigger ipmi`：先 `chassis bootdev pxe` 再 `power reset`；
- 结果优先走 callback POST，其次 `--ssh-host` 拉 `/root/cprs-smoke/result.json`。

### 4.5 对已装好的机器直接验证（不重装，最省时）

机器已是目标 OS 时（例如一次性装好后保留），跳过 PXE：

```bash
tools/oneboot/run_inventory.py --verify-ssh --apply \
  --ssh-key ~/.ssh/lab_key --artifact-dir dist
```text

这条路径非常适合把 OneBoot 装好的机器**长期挂成 self-hosted runner 池**：
重装用 §4.4，日常回归用 §4.5。

### 4.6 用虚拟机验证（没有物理机 / BMC 时）

`vm_verify.py` 把同一套流程放进本机 QEMU/KVM：用 OneBoot 的**同一个 ISO +
kernel/initrd + 同一 kickstart**，只是把 stage2/repo 换成从本机挂载的 ISO 提供，
因此不需要 BMC、也不需要加入 PXE 二层网段。

```bash
tools/oneboot/vm_verify.py \
  --artifact dist/cloud-probe-rs-x86_64-unknown-linux-gnu.tar.gz \
  --source centos_7_9_x86_64_dvd_2009 \
  --junit-out build/vm-junit/centos7.xml
# 或整份清单：tools/oneboot/run_inventory.py --driver vm --artifact-dir dist
```

要求：`qemu-system-x86_64`、`qemu-img`、`/dev/kvm`、`sudo`（loop 挂载）、nginx 或
python3。首次运行会把 ISO 缓存到 `--workdir`（默认 `/tmp/cprs-vm`），之后复用。

**几个非显然的坑（已处理）**：

1. OneBoot 的 stage2 **session 会在安装中被清理**：虚拟机走 QEMU user-mode NAT，
   OneBoot 看不到它的 DHCP 租约，`active_sessions` 归零、`/mnt/sessions/...` 404，
   anaconda 随即报 `Error populating transaction`。→ 改用本机挂载 ISO + nginx 提供 repo。
2. QEMU user-mode 把宿主映射为 `10.0.2.2`：kickstart 里的载荷/回调 URL 必须指向它。
3. `/images/<source>/` 是按需从一次 `/go` 请求生成、并随 session 清理的，所以 driver
   会先发一次 `/go` 再下载 kernel/initrd。
4. repo 用 `python3 -m http.server` 时，anaconda 经 slirp 下载会 `No more mirrors`；
   nginx 正常（driver 优先 nginx）。

**实测（CentOS 7.9, glibc 2.17）**：安装成功，5 个二进制全部加载运行，
`capture:fidelity captured 4000 >= injected 2000 icmp frames`，`ok=true`。

**已支持的 boot_style**：

| boot_style | OS | VM 引导方式 | 状态 |
| --- | --- | --- | --- |
| `redhat` | CentOS/RHEL/Kylin/UOS/openEuler/Rocky | 挂载 ISO 树，`inst.repo=` + `inst.ks=` | ✅ 实测 CentOS 7.9 |
| `casper` | Ubuntu (live-server Autoinstall) | 服务原始 ISO，`url=` + `autoinstall ds=nocloud-net;s=` | ✅ 实测 Ubuntu 20.04.6 |

> **OneBoot 自身的坑（2026-10-02 精确定位，`cloud-probe-rs-2hs.5`）**：
> `http://10.40.1.254:8080/iso/Ubuntu/` 下所有 Ubuntu ISO 返回 **403**（nginx/1.20.1），
> 而同级 `CentOS7/ CentOS8/ Debian/ KylinV10/ KylinV11/ FnOS/ NeoKylin/` **全部 200**。
>
> 关键鉴别：在可读目录里请求一个**不存在**的文件应得 404
> （实测 `/iso/CentOS7/nope.iso` → 404、`/iso/Debian/nope.iso` → 404），
> 而 `/iso/Ubuntu/nope.iso` 与 `/iso/Ubuntu/index.html` 都是 **403**。
> 这说明 nginx 是在**走进该目录**时失败（EACCES），而不是找不到文件 ——
> 即 `/data/iso/Ubuntu` 对 nginx 的 worker 用户不可读/不可进入，
> 与具体 ISO 是否存在无关。（另一个可能的成因是 location 级的 `deny`；
> 两者在外部都表现为 403，需在主机上区分。）
>
> 影响：OneBoot 生成的 Ubuntu 引导脚本正是
> `url=http://<dist-host>:8080/iso/Ubuntu/<iso>`（`/boot/ubuntu_*/go`），
> 该 URL 403 → casper 无法下载/挂载 ISO → **经此服务器的 Ubuntu PXE 装机失败**。
>
> 主机侧确认（需要 10.40.1.254 的登录权限，当前**未持有**）：
> ```sh
> namei -l /data/iso/Ubuntu
> sudo -u <nginx-user> test -rx /data/iso/Ubuntu && echo traversable
> nginx -T | grep -n -A6 'iso/Ubuntu'
> ```
> 最可能的修法：`sudo chmod o+rx /data/iso/Ubuntu`（并确保 ISO 本身 `o+r`；
> 若有 SELinux，另需 `restorecon -Rv /data/iso/Ubuntu`）。
> 验证：`curl -sI http://10.40.1.254:8080/iso/Ubuntu/ubuntu-20.04.6-live-server-amd64.iso | head -1` 应为 200，
> 然后 `tools/oneboot/vm_verify.py --source ubuntu_20_04_6_live_server_amd64 --boot-style casper`（不传 `--iso`）应能直连取 ISO。
>
> 无服务器权限时的绕行：`--iso <本地ISO>`（用公开镜像，如 huaweicloud/tuna，已验证）。
> `vm_verify.py` 现在会在启动前先探测该 URL，403 时**快速失败并打印上面的定位**，
> 不再让失败推迟到 casper 深处（`--skip-iso-preflight` 可跳过探测）。

> 注：目标机无 python3 时（CentOS 7），`on_target_smoke.sh` 用 netns + ping 注入
> ICMP 帧并用 awk 写 `result.json`，不再依赖解释器。

---

## 5. 构建侧（跨平台产物）

`release.yml` 目前产出：`x86_64/aarch64-unknown-linux-gnu`、`aarch64/x86_64-apple-darwin`。
Linux gnu 产物在 manylinux2014 容器里构建（glibc 2.17 基线，见 §1.3），一个 target
triple 只有一套产物：

| target（产物名 `cloud-probe-rs-<target>.tar.gz`） | 构建环境 | 状态 |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` + `manylinux2014_x86_64`（CentOS 7, glibc 2.17） | ✅ 实测 GLIBC_2.16 |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` + `manylinux2014_aarch64` | 同配方，待 CI 首跑确认 |
| `aarch64/x86_64-apple-darwin` | macOS runner 原生 | 不变 |

镜像只能跑在自己的架构上，所以两个 Linux 条目分别落在 x86_64 / arm64 runner，
构建走 `docker run`（不是 container job）：runner 负责 checkout、打包、上传，也负责
下面的地板门禁（CentOS 7 镜像里的 binutils 不便依赖）。容器内构建是 native 的，
产物落在 `target/release` 而不是 `target/<triple>/release`。

**glibc 地板门禁**（`Verify the glibc floor`，仅 Linux 步骤）用 `objdump -T` 取
`cpworker` 依赖的最高 `GLIBC_2.<minor>`，高于 2.17 直接失败，防止基线回退。

历史：这条配方最初位于 `.github/workflows/release-linux-baseline.yml`，产物带
`-glibc217` 后缀，与 `ubuntu-latest` 原生构建（实测需要 GLIBC_2.34）同时发布，两套
gnu 产物并存造成选择混淆；收编进 `release.yml` 后原生 Linux 构建与后缀一起删除。

后续（见 bead）：

1. 修 musl 移植 bug，增 `*-unknown-linux-musl` 静态产物作为兜底；
2. aarch64 基线的 `manylinux2014_aarch64` 首次 CI 通过后去掉“待确认”标记
   （可直接对 `release.yml` 触发 `workflow_dispatch`，门禁日志会打印实测的 glibc 版本，
   不需要打 tag）。

macOS 保持现状（OneBoot 只做 x86/ARM/LoongArch 的 Linux PXE，无法验证 macOS）。

---

### 5.1 aarch64 / x86_64 gnu 基线：构建 + 地板 + **在目标 userland 里真实执行**（`cloud-probe-rs-2hs.2`）

`release.yml` 的 Linux 条目在 manylinux2014 容器（CentOS 7，glibc 2.17）里构建，容器与 runner **同架构**
（x86_64 用 `ubuntu-latest` + `manylinux2014_x86_64`；aarch64 用 `ubuntu-24.04-arm` +
`manylinux2014_aarch64`）。2026-10-02 首次 `workflow_dispatch` 验证（run 37044653454，`publish release`
因 `if: startsWith(github.ref,'refs/tags/v')` 被 skip，未发布任何东西）：

| target | 构建 | objdump 地板 | 容器内执行 |
|---|---|---|---|
| `aarch64-unknown-linux-gnu` | ✅ success | `cpworker requires glibc 2.17` → OK | ✅ `cpctl 0.9.0` / `cpdaemon 0.9.0` / `dockerpid` / `cripid` 均执行 |
| `x86_64-unknown-linux-gnu` | ✅ success | `cpworker requires glibc 2.16` → OK | ✅ 同上 |

「构建成功」比它看起来要弱：地板检查只是**静态**读符号版本，而**从未被执行过的交叉产物只能证明它链接得过**。
因此构建脚本现在会在容器内**运行**全部五个二进制（只要求「启动并有输出」——各二进制 flag 不同，而
空输出正是「动态加载器解析不了」这种失败），这证明动态加载器与该二进制引用的每一个带版本的 glibc
符号在目标 glibc 上**运行期确实存在**。`ubuntu-24.04-arm` 是**真 arm64 硬件**，不是模拟。

仍未覆盖：Kylin/UOS 等**具体发行版用户态**的现场确认（其 glibc 补丁、SELinux 策略、内核差异）。
OneBoot 机队当前 4 个客户端中没有 arm64 机器，故该半仍需 arm64 现场机器。

## 6. 已知缺口与后续

1. **无人值守装机**：OneBoot 无 per-MAC «下次启动用哪个 ISO+kickstart» 的 API。
   当前靠 `--trigger manual`（人工点一下）或 `--trigger ipmi` + 菜单。
   长期方案（择一）：
   - 给 OneBoot 增 `POST /api/v1/boot/next {mac, source, ks}`，由 dnsmasq 按 MAC
     下发对应 `/boot/.../go`。**仓库侧已就绪**：`oneboot_client.OneBoot.boot_next()`
     与 `lab_verify.py --trigger oneboot-api` 已实现（不在 CLI 暴露，CLI 保持只读）。
     2026-10-02 实测该端点 **404**（OneBoot 是 Flask 应用），因此服务端实现仍需
     OneBoot 源码；客户端在此前的行为是给出可执行的失败信息并退回 `--trigger manual`；
   - 或把目标机一次性装成 self-hosted runner，日常只走 `--verify-ssh`。
2. **Ubuntu/Debian**：`casper` autoinstall 已生成并在 `lab_verify.py` 中支持；
   Debian `debian-installer` 与 VMware ESXi 未覆盖。
3. **LoongArch**：ISO 有 Kylin V11 LoongArch，需确认 Rust 目标与交叉工具链。
4. **构建网络**：内网 runner 若无法访问 crates.io，需要内网镜像或 vendored 依赖。
5. **安全**：self-hosted runner **只应响应 `workflow_dispatch` / tag**，绝不跑
   未审 PR；本仓库 `lab-verify.yml` 已按此约束编写。
6. **OneBoot `/iso/Ubuntu/` 返回 403**（见 §4.6）：需 OneBoot 侧修权限，否则 Ubuntu 既
   不能用它的 PXE 装，也不能从它的 HTTP 直接拉 ISO；暂用公开镜像 + `--iso` 绕过。

---

## 7. 安全说明

- `oneboot_client.py` 默认只读；写 API 只能通过 `lab_verify.py --apply` 触发。
- 上传的 kickstart 名固定为 `cprs-verify.cfg`，便于识别与清理
  （`oneboot_client.delete_kickstart(source, "cprs-verify.cfg")`）。
- 载荷服务监听 `0.0.0.0:8000`，仅服务一个临时目录；用完即关。
- BMC 口令只经 `--bmc-pass` 传给 `ipmitool` 且打印时脱敏；SSH 私钥写入 0600
  临时文件并在结束后删除。
