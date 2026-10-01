#!/usr/bin/env python3
"""Reversible legacy/switchdev mirror probe; isolated PF preserves kernel NFS.

Build flow_mirror.c and primary.c first. Run only with no other lab experiment.
Matches only the generator MAC. Never changes firmware or unbinds the PF.
"""
import json
import os
from pathlib import Path
import shlex
import time

import perf_capture as perf


def vf_driver(action):
    for bdf in ["0000:b8:00.1", "0000:b8:00.2"]:
        perf.ssh("yinjiao", "sudo -n sh -c " + shlex.quote(
            f"echo {bdf} >/sys/bus/pci/drivers/mlx5_core/{action}"))


def health():
    result = perf.ssh("yinjiao", "ping -c 1 -W 2 10.2.0.12 | tail -2; "
                      "findmnt -t nfs,nfs4 -o TARGET,SOURCE | head -4")
    if "1 received" not in result:
        raise RuntimeError("NFS link health check failed: " + result)
    return result


def launch_flow(device_args, prefix):
    env = " FLOW_NO_COUNT=1" if os.environ.get("PERF_FLOW_NO_COUNT") else ""
    perf.ssh("yinjiao", f"sudo -n rm -rf /var/run/dpdk/{prefix}; "
             f"sudo -n setsid nohup env LD_LIBRARY_PATH={perf.LD}{env} {perf.ROOT}/flow_mirror "
             f"-l 24 --file-prefix {prefix} --log-level notice " + device_args +
             " >/tmp/cpperf-mirror.log 2>&1 </dev/null &")
    for _ in range(30):
        log = perf.ssh("yinjiao", "sudo -n cat /tmp/cpperf-mirror.log")
        if "mirror ready" in log or "mirror validate=" in log or "PCI_BUS:" in log:
            # Give creation a moment after validation succeeds.
            time.sleep(1)
            return perf.ssh("yinjiao", "sudo -n cat /tmp/cpperf-mirror.log")
        time.sleep(0.5)
    return log


def launch_rx(vf, cores, prefix, nq, device_args_override=None):
    stats = f"/tmp/cpperf-{prefix}.json"
    log = f"/tmp/cpperf-{prefix}.log"
    binary = os.environ.get("PERF_PRIMARY_BINARY", f"{perf.ROOT}/dpdk_primary")
    desc = int(os.environ.get("PERF_PRIMARY_DESC", "4096"))
    argument_key = "PERF_ORIGINAL_ARGS" if prefix == "original" else "PERF_CAPTURE_ARGS"
    device_args = os.environ.get(argument_key, os.environ.get("PERF_DEVICE_ARGS", ""))
    if device_args_override is not None:
        device_args = device_args_override
    device = shlex.quote(vf + device_args)
    perf.ssh("yinjiao", f"sudo -n rm -f {stats}; sudo -n setsid nohup env "
             f"LD_LIBRARY_PATH={perf.LD} PRIMARY_RXQ={nq} PRIMARY_MBUF=131072 PRIMARY_DESC={desc} PRIMARY_INSPECT=1 "
             f"PRIMARY_STATS={stats} {binary} -l {cores} "
             f"--file-prefix {prefix} --log-level notice -a {device} >{log} 2>&1 </dev/null &")
    perf.wait_log(log, "pdump_init=ok")


def counts():
    out = perf.ssh("yinjiao", "sudo -n cat /tmp/cpperf-original.json /tmp/cpperf-mirrored.json")
    return [json.loads(line) for line in out.splitlines()]


def physical():
    out = perf.ssh("yinjiao", "date +%s.%N; sudo -n ethtool -S ens8np0")
    lines = out.splitlines()
    result = {"time": float(lines[0])}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.strip().split(":", 1)
            if key in ["rx_packets_phy", "rx_discards_phy", "rx_out_of_buffer",
                       "rx_steer_missed_packets"]:
                result[key] = int(value)
    return result


def main():
    evidence = {}
    switched = False
    try:
        perf.setup()
        evidence["health_before"] = health()
        perf.ssh("yinjiao", "sudo -n sh -c 'echo 0 >/sys/class/net/ens8np0/device/sriov_numvfs; "
                 "echo 2 >/sys/class/net/ens8np0/device/sriov_numvfs'; sleep 3; "
                 f"sudo -n ip link set ens8v0 address {perf.DST}; sudo -n ip link set ens8v0 up; "
                 "sudo -n ip link set ens8v1 address 1a:ca:0a:26:a8:8e; sudo -n ip link set ens8v1 up")
        evidence["legacy"] = launch_flow("-a 0000:b8:00.1 -a 0000:b8:00.2", "flowlegacy")
        perf.ssh("yinjiao", "sudo -n pkill -TERM -x flow_mirror || true")
        time.sleep(1)
        vf_driver("unbind")
        try:
            evidence["switchdev"] = perf.ssh("yinjiao",
                "sudo -n devlink dev eswitch set pci/0000:b8:00.0 mode switchdev 2>&1")
            switched = True
        finally:
            vf_driver("bind")
        time.sleep(3)
        perf.ssh("yinjiao", f"sudo -n ip link set ens8v0 address {perf.DST}; "
                 "sudo -n ip link set ens8v0 up; "
                 "sudo -n ip link set ens8v1 address 1a:ca:0a:26:a8:8e; "
                 "sudo -n ip link set ens8v1 up; "
                 "sudo -n ip link set ens8npf0vf0 up; sudo -n ip link set ens8npf0vf1 up")
        evidence["ports"] = perf.ssh("yinjiao", "sudo -n devlink port show; ip -br link show")
        evidence["health_switchdev"] = health()
        evidence["flow"] = launch_flow("-a '0000:b8:00.0,representor=[0,1],dv_flow_en=1'", "flowcontrol")
        evidence["health_flow"] = health()
        print(json.dumps(evidence), flush=True)
        if "mirror ready" in evidence["flow"]:
            queue_cases = json.loads(os.environ.get("PERF_QUEUE_CASES", "[[4,4],[8,8]]"))
            for queue_case in queue_cases:
                original_queues, capture_queues = queue_case[:2]
                original_args = queue_case[2] if len(queue_case) > 2 else None
                perf.ssh("yinjiao", "sudo -n pkill -TERM -x dpdk_primary || true")
                time.sleep(1)
                launch_rx("0000:b8:00.1", "32-39,56", "original", original_queues, original_args)
                launch_rx("0000:b8:00.2", "40-47,57", "mirrored", capture_queues)
                txcores = int(os.environ.get("PERF_TX_CORES", "4"))
                perf.ssh("laojun", f"/tmp/lj_tx.sh 8-{8 + txcores} {txcores} 11 {perf.DST}")
                time.sleep(1)
                before = counts()
                wire0 = physical()
                l0 = perf.snapshot("laojun", {})
                time.sleep(5)
                after = counts()
                wire1 = physical()
                l1 = perf.snapshot("laojun", {})
                perf.ssh("laojun", "sudo -n pkill -9 -x dpdk-testpmd || true")
                result = {"rxq": capture_queues, "original_rxq": original_queues,
                          "before": before, "after": after,
                          "device_args": os.environ.get("PERF_DEVICE_ARGS", ""),
                          "original_args": original_args if original_args is not None else os.environ.get("PERF_ORIGINAL_ARGS", os.environ.get("PERF_DEVICE_ARGS", "")),
                          "capture_args": os.environ.get("PERF_CAPTURE_ARGS", os.environ.get("PERF_DEVICE_ARGS", "")),
                          "descriptors": int(os.environ.get("PERF_PRIMARY_DESC", "4096")),
                          "flow_count": not bool(os.environ.get("PERF_FLOW_NO_COUNT")),
                          "wire_before": wire0, "wire_after": wire1,
                          "offered_mpps": (l1["tx_packets_phy"]-l0["tx_packets_phy"])/
                          (l1["time"]-l0["time"])/1e6,
                          "original_mpps": (after[0]["rx"]-before[0]["rx"])/
                          (after[0]["time"]-before[0]["time"])/1e6,
                          "mirrored_mpps": (after[1]["rx"]-before[1]["rx"])/
                          (after[1]["time"]-before[1]["time"])/1e6}
                evidence.setdefault("measurements", []).append(result)
                print(json.dumps(result), flush=True)
    except Exception as error:
        evidence["error"] = str(error)
        print("MIRROR ERROR: " + str(error), flush=True)
    finally:
        perf.ssh("yinjiao", "sudo -n pkill -TERM -x flow_mirror || true")
        perf.stop()
        if switched:
            vf_driver("unbind")
            perf.ssh("yinjiao", "sudo -n devlink dev eswitch set pci/0000:b8:00.0 mode legacy")
            vf_driver("bind")
        perf.restore()
        evidence["health_after"] = health()
        Path("/tmp/cpperf-mirror-evidence.json").write_text(json.dumps(evidence, indent=2))
        print("MIRROR RESTORED", flush=True)


if __name__ == "__main__":
    main()
