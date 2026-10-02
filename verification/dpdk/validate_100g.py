#!/usr/bin/env python3
"""Check the recorded numerical subgate in PRIMARY_DESIGN.md; never run traffic.

This consumes normalized, epoch-tagged deltas, not arbitrary cpctl snapshots.
Passing checks consistency of supplied evidence, not its physical authenticity.
"""

import argparse
import json
import sys


WINDOW_NS = 10_000_000_000
MIN_WINDOWS = 60
MIN_RUNS = 3
PROFILE = "primary-zmq-64b-v1"
ZERO_FIELDS = (
    "nic_missed", "nic_nombuf", "capture_drop", "pipeline_drop",
    "filtered", "direction_drop", "ratelimit_drop", "error_drop",
    "receiver_missing", "receiver_duplicate", "receiver_payload_error",
    "receiver_direction_error", "receiver_timestamp_error",
)


class InvalidEvidence(ValueError):
    """Incomplete, inconsistent or failing acceptance evidence."""


def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def integer(obj, key):
    value = obj.get(key)
    require(type(value) is int and value >= 0, f"{key}: expected nonnegative integer")
    return value


def line_rate(packets):
    # Include FCS, preamble/SFD and IFG; use integers rather than rounded Mpps.
    wire_bits = packets * 84 * 8
    ideal_bits = 100_000_000_000 * 10
    require(ideal_bits * 9999 <= wire_bits * 10000 <= ideal_bits * 10001,
            "offered rate must be 100G within 0.01% in every window")


def validate(report):
    """Fail closed on absent evidence. Return the number of checked epochs."""
    require(isinstance(report, dict), "report must be an object")
    require(integer(report, "schema_version") == 1, "unsupported schema_version")
    require(report.get("profile") == PROFILE, f"profile must be {PROFILE}")
    runs = report.get("runs")
    require(isinstance(runs, list) and len(runs) >= MIN_RUNS, "need at least three runs")
    run_ids = set()
    checked = 0
    for run in runs:
        require(isinstance(run, dict), "run must be an object")
        run_id = run.get("id")
        require(isinstance(run_id, str) and run_id and run_id not in run_ids,
                "run ids must be nonempty and unique")
        run_ids.add(run_id)
        require(integer(run, "warmup_ns") >= WINDOW_NS, "need at least 10 s warmup")
        require(integer(run, "initial_backlog_packets") == 0, "initial backlog must be zero")
        require(integer(run, "final_backlog_packets") == 0, "final backlog must be zero")
        require(integer(run, "drain_ns") <= 1_000_000_000, "drain exceeds 1 s")
        backlog_limit = integer(run, "backlog_limit_packets")
        windows = run.get("windows")
        require(isinstance(windows, list) and len(windows) >= MIN_WINDOWS,
                "need at least 60 contiguous 10 s windows per run")
        previous_end = None
        queue_ids = None
        run_packets = 0
        for window in windows:
            require(isinstance(window, dict), "window must be an object")
            start = integer(window, "start_ns")
            end = integer(window, "end_ns")
            require(end - start == WINDOW_NS, "window must last exactly 10 s")
            require(previous_end is None or start == previous_end, "windows must be contiguous")
            previous_end = end
            packets = integer(window, "generated_packets")
            run_packets += packets
            line_rate(packets)
            require(integer(window, "frame_min_bytes") == 64
                    and integer(window, "frame_max_bytes") == 64,
                    "all physical frames must be 64 bytes including FCS")
            for key in ("capture_packets", "forwarded_packets", "receiver_unique_packets"):
                require(integer(window, key) == packets, f"{key}: packet conservation failed")
            # Live physical counter latches have propagation/sampling skew.
            # Exact physical conservation is checked at quiet run boundaries.
            for prefix in ("tx", "rx"):
                physical_packets = integer(window, f"{prefix}_phy_packets")
                line_rate(physical_packets)
                require(integer(window, f"{prefix}_phy_bytes") == physical_packets * 64,
                        f"{prefix}_phy_bytes: physical byte count failed")
            for key in ("capture_bytes", "receiver_payload_bytes"):
                require(integer(window, key) == packets * 60, f"{key}: FCS-stripped byte count failed")
            for key in ZERO_FIELDS:
                require(integer(window, key) == 0, f"{key}: must be zero")
            queues = window.get("queues")
            require(isinstance(queues, list) and len(queues) >= 2, "need at least two RSS queues")
            ids = []
            queue_packets = 0
            queue_bytes = 0
            for queue in queues:
                require(isinstance(queue, dict), "queue must be an object")
                ids.append(integer(queue, "id"))
                count = integer(queue, "capture_packets")
                size = integer(queue, "capture_bytes")
                require(count > 0 and size == 60 * count, "queue must receive valid packets")
                queue_packets += count
                queue_bytes += size
            require(len(set(ids)) == len(ids), "duplicate queue id")
            require(queue_ids is None or set(ids) == queue_ids, "queue set changed during run")
            queue_ids = set(ids)
            require(queue_packets == packets and queue_bytes == packets * 60,
                    "per-queue totals disagree with global capture")
            require(integer(window, "max_backlog_packets") <= backlog_limit,
                    "backlog exceeded predeclared bound")
            require(integer(window, "max_delivery_latency_ns") <= 1_000_000_000,
                    "delivery latency exceeds 1 s")
            checked += 1
        for prefix in ("tx", "rx"):
            require(integer(run, f"{prefix}_phy_packets") == run_packets,
                    f"{prefix}_phy_packets: whole-run packet conservation failed")
            require(integer(run, f"{prefix}_phy_bytes") == run_packets * 64,
                    f"{prefix}_phy_bytes: whole-run physical byte count failed")
        batches = integer(run, "zmq_data_batches")
        require(0 < batches <= run_packets, "invalid ZMQ data batch count")
        # BatchBuilder: 24-byte batch header; each data record has a 2-byte
        # length, 16-byte header and 60-byte Ethernet frame + 4-byte MPLS.
        message_bytes = 82 * run_packets + 24 * batches
        for key in ("forwarded_bytes", "receiver_message_bytes"):
            require(integer(run, key) == message_bytes, f"{key}: ZMQ message byte count failed")
    return checked


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="normalized evidence JSON; see PRIMARY_DESIGN.md")
    args = parser.parse_args(argv)
    try:
        with open(args.report, encoding="utf-8") as source:
            report = json.load(source, object_pairs_hook=unique_object)
        checked = validate(report)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"NUMERICAL_GATE_FAIL: {error}", file=sys.stderr)
        return 1
    print(f"NUMERICAL_GATE_PASS: {checked} epochs; physical/semantic evidence review still required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
