# tools/oneboot — OneBoot 真机验证工具链

用内部 PXE 装机平台 OneBoot 为 `cloud-probe-rs` 做「发布件在真实目标系统上能否运行」的
验证。设计、侦察结论与运行手册见 **[`../../docs/ONEBOOT_LAB.md`](../../docs/ONEBOOT_LAB.md)**。

| 文件 | 作用 |
| --- | --- |
| `oneboot_client.py` | OneBoot 管理 API 客户端；`selftest` 为只读探活 |
| `on_target_smoke.sh` | **在目标机内**执行：解包 → 二进制 ABI/加载 → veth AF_PACKET 抓包 → `result.json` |
| `lab_verify.py` | 编排：渲染 kickstart → 上传 OneBoot → 触发 PXE → 回收结果 → JUnit |
| `run_inventory.py` | 按机器清单批量执行并聚合 |
| `inventory.example.json` | 机器清单模板（复制为 `inventory.json`） |

## 快速开始

```bash
# 1. 只读探活（安全）
tools/oneboot/oneboot_client.py selftest

# 2. 本地验证 smoke 载荷本身（不需要 OneBoot）
ARTIFACT_URL=http://<host>:18080/cloud-probe-rs-x86_64-unknown-linux-gnu.tar.gz \
  WORKDIR=/tmp/smoke bash tools/oneboot/on_target_smoke.sh

# 3. 干跑：渲染 kickstart，不上传、不动机器
tools/oneboot/lab_verify.py plan \
  --artifact dist/cloud-probe-rs-x86_64-unknown-linux-gnu.tar.gz \
  --source centos_7_9_x86_64_dvd_2009 --serve-host <内网IP>

# 4. 真正执行（会 PUT kickstart 并重启目标机；需 --apply）
export LAB_BMC_PASS=... LAB_SSH_KEY="$(cat ~/.ssh/lab_key)"
cp tools/oneboot/inventory.example.json tools/oneboot/inventory.json   # 编辑
tools/oneboot/run_inventory.py --artifact-dir dist --junit-dir build/lab-junit \
  --apply --trigger ipmi
```

- **默认只读**：只有 `--apply` 才会写 OneBoot / 动目标机。
- **结果回收**：优先目标机 callback POST，其次 `--ssh-host` 拉取
  `/root/cprs-smoke/result.json`。
- **已装好的机器**：加 `--verify-ssh` 跳过 PXE，直接 SSH 跑 smoke（适合把机器挂成
  self-hosted runner 后做日常回归）。
