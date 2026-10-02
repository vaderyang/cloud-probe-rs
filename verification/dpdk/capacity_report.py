#!/usr/bin/env python3
"""Derive auditable capacity rows from raw, cumulative counter snapshots."""
import csv
from datetime import datetime
import gzip
import json
from pathlib import Path
import re
import sys


def cap(s):
    return s.get("capture", {}).get("value", [{}])[0].get("counters", {})


def stamp(s):
    v = s["capture"]["value"][0]["ts"]
    return datetime.fromisoformat(v[:26] + v[-6:]).timestamp()


def packet(s, name):
    return cap(s).get(name, {}).get("packets", 0)


def derive(d):
    if "error" in d:
        return None
    l0, y0 = d["samples"][0]
    l1, y1 = d["samples"][-1]
    direct = d["backend"].startswith("direct")
    before_l, before_y = d["before"]
    end_l, end_y = d["drained_l"], d["drained"]
    wire_packets = end_y["nic"]["value"]["rx_packets_phy"] - before_y["nic"]["value"]["rx_packets_phy"]
    offered_packets = end_l["nic"]["value"]["tx_packets_phy"] - before_l["nic"]["value"]["tx_packets_phy"]
    matched = re.search(r"CAP_TX_DONE total=(\d+)", d.get("tx_log", ""))
    tx_total = int(matched[1]) if matched and not d.get("testpmd") else offered_packets
    got = (end_y["primary"]["rx"] - before_y["primary"]["rx"]) if direct else packet(end_y, "cap_packets") - packet(before_y, "cap_packets")
    missing = tx_total - got
    memory = []
    name = "dpdk_primary" if direct else "cpworker"
    for s in [*d["startup"], *[y for _, y in d["samples"]], end_y]:
        p = s.get("processes", {}).get("value", {}).get(name)
        if p:
            m = p["memory"]
            memory.append((m["Rss"] + m.get("Shared_Hugetlb", 0) + m.get("Private_Hugetlb", 0)) / 2**20)
    mem_max = max(memory)
    vf_dt = y1["vf"]["time"] - y0["vf"]["time"]
    out_buffer = y1["vf"]["value"]["rx_out_of_buffer"] - y0["vf"]["value"]["rx_out_of_buffer"]
    dt = (y1["primary"]["time"] - y0["primary"]["time"]) if direct else (14.0 if d.get("burst_capture") else stamp(y1) - stamp(y0))
    csrc0, csrc1 = (before_y, end_y) if d.get("burst_capture") else (y0, y1)
    captured = d["primary_rx_mpps"] if direct else (packet(csrc1, "cap_packets") - packet(csrc0, "cap_packets")) / dt / 1e6
    row = dict(label=d.get("label", ""), backend=d["backend"], ring=d.get("ring_mb", d.get("ring", "")),
               pipeline_mb=d.get("pipeline", 0), affinity=d.get("affinity", "48-49"),
               capture_window_mode=d.get("capture_window_mode", "live-delta"), device=d.get("device", "0000:b8:00.1"),
               testpmd=bool(d.get("testpmd")), target_mpps=d["target_mpps"],
               offered_mpps=d["offered_mpps"], wire_mpps=d["wire_mpps"], captured_mpps=captured,
               worker_cpu_pct=100 * d["cpu_cores"].get("cpworker", 0),
               primary_cpu_cores=d["cpu_cores"].get("dpdk_primary", 0),
               capture_seconds=dt, cpu_seconds=d["cpu_seconds"],
               socket_drop_mpps=(packet(csrc1, "drop_packets") - packet(csrc0, "drop_packets")) / dt / 1e6 if not direct else 0,
               vf_out_of_buffer_mpps=out_buffer / vf_dt / 1e6,
               pdump_ringfull_mpps=d.get("primary_ringfull_mpps", 0),
               pdump_nombuf_mpps=d.get("primary_nombuf_mpps", 0),
               primary_rx_mpps=d.get("primary_rx_mpps", 0),
               primary_imissed_mpps=d.get("primary_imissed_mpps", 0),
               memory_current_mib=d["memory_current_mib"], mapped_rss_huge_mib=mem_max,
               fits_physical_512=mem_max <= 512, throttled_periods=d["cgroup_cpu_delta"]["nr_throttled"],
               throttled_usec=d["cgroup_cpu_delta"]["throttled_usec"],
               system_softirq_cores=d["system_softirq_cores"],
               burst_tx_packets=tx_total, burst_wire_packets=wire_packets, burst_captured_packets=got,
               burst_forwarded_packets=packet(end_y, "fwd_packets") - packet(before_y, "fwd_packets") if not direct else got,
               forwarded_mpps=(packet(csrc1, "fwd_packets") - packet(csrc0, "fwd_packets")) / dt / 1e6 if not direct else captured,
               burst_missing_packets=missing, burst_loss_pct=100 * max(missing, 0) / max(tx_total, 1),
               burst_vf_out_of_buffer=end_y["vf"]["value"]["rx_out_of_buffer"] - before_y["vf"]["value"]["rx_out_of_buffer"],
               burst_socket_drop=packet(end_y, "drop_packets") - packet(before_y, "drop_packets"))
    for key, first, last, counter in [
        ("offered", l0["nic"], l1["nic"], "tx_packets_phy"),
        ("wire", y0["nic"], y1["nic"], "rx_packets_phy"),
    ]:
        row[f"{key}_seconds"] = last["time"] - first["time"]
        row[f"{key}_delta_packets"] = last["value"][counter] - first["value"][counter]
    row["capture_delta_packets"] = (y1["primary"]["rx"] - y0["primary"]["rx"]) if direct else packet(csrc1, "cap_packets") - packet(csrc0, "cap_packets")
    row["capture_counter_seconds"] = dt if direct else stamp(csrc1) - stamp(csrc0)
    row["cpu_delta_ticks"] = sum(y1["processes"]["value"][name][f"{t}time_ticks"] - y0["processes"]["value"][name][f"{t}time_ticks"] for t in ["u", "s"])
    row["cgroup_periods"] = d["cgroup_cpu_delta"]["nr_periods"]
    row["cgroup_cpu_max"] = y1["cgroup"]["value"]["cpu.max"]
    row["cgroup_memory_max"] = int(y1["cgroup"]["value"]["memory.max"])
    row["hugetlb_current_mib"] = int(y1["cgroup"]["value"]["hugetlb.2MB.current"]) / 2**20
    row["sampling_valid"] = abs(row["offered_mpps"] - row["wire_mpps"]) / max(row["wire_mpps"], 1e-9) < 0.03
    row["near_loss_free"] = row["burst_loss_pct"] <= 0.1
    return row


if __name__ == "__main__":
    source = Path(sys.argv[1])
    read = gzip.open if source.suffix == ".gz" else open
    with read(source, "rt") as f:
        rows = [dict(evidence_line=i, **r) for i, line in enumerate(f, 1) if (r := derive(json.loads(line)))]
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    for r in rows:
        print(f"{r['backend']:12s} {str(r['ring']):>5s} {r['target_mpps']:6.2f} "
              f"O/W/C={r['offered_mpps']:7.3f}/{r['wire_mpps']:7.3f}/{r['captured_mpps']:7.3f} "
              f"CPU={r['worker_cpu_pct']:5.1f}% P={r['primary_cpu_cores']:.2f} "
              f"loss={r['burst_loss_pct']:.4f}% NIC={r['vf_out_of_buffer_mpps']:.3f} "
              f"ring={r['pdump_ringfull_mpps']:.3f} mem={r['mapped_rss_huge_mib']:.1f} "
              f"throttle={r['throttled_periods']}")
