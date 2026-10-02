#!/usr/bin/env python3
"""Synthetic evidence only: these tests never establish hardware acceptance."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import validate_100g as gate


def passing_report():
    # Nearest integral packet count to 100G for one ten-second epoch.
    count = 1_488_095_238
    window = {
        "start_ns": 0, "end_ns": gate.WINDOW_NS,
        "generated_packets": count,
        "frame_min_bytes": 64, "frame_max_bytes": 64,
        "tx_phy_packets": count, "rx_phy_packets": count,
        "capture_packets": count, "forwarded_packets": count,
        "receiver_unique_packets": count,
        "tx_phy_bytes": count * 64, "rx_phy_bytes": count * 64,
        "capture_bytes": count * 60,
        "receiver_payload_bytes": count * 60,
        "max_backlog_packets": 1024, "max_delivery_latency_ns": 100_000,
        "queues": [
            {"id": queue_id, "capture_packets": count // 2,
             "capture_bytes": count // 2 * 60}
            for queue_id in range(2)
        ],
        **dict.fromkeys(gate.ZERO_FIELDS, 0),
    }
    runs = []
    for run_id in range(3):
        windows = []
        for epoch in range(60):
            item = copy.deepcopy(window)
            item["start_ns"] = epoch * gate.WINDOW_NS
            item["end_ns"] = (epoch + 1) * gate.WINDOW_NS
            windows.append(item)
        runs.append({
            "id": f"synthetic-{run_id}", "warmup_ns": gate.WINDOW_NS,
            "initial_backlog_packets": 0, "final_backlog_packets": 0,
            "drain_ns": 100_000, "backlog_limit_packets": 1024,
            "tx_phy_packets": count * 60, "rx_phy_packets": count * 60,
            "tx_phy_bytes": count * 60 * 64, "rx_phy_bytes": count * 60 * 64,
            "zmq_data_batches": 60 * 100_000,
            "forwarded_bytes": 82 * count * 60 + 24 * 60 * 100_000,
            "receiver_message_bytes": 82 * count * 60 + 24 * 60 * 100_000,
            "windows": windows,
        })
    return {"schema_version": 1, "profile": gate.PROFILE, "runs": runs}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.report = passing_report()
        self.run = self.report["runs"][0]
        self.window = self.run["windows"][0]

    def test_complete_synthetic_evidence(self):
        self.assertEqual(gate.validate(self.report), 180)

    def test_one_missing_or_extra_packet_at_any_stage_fails(self):
        for key in ("capture_packets", "forwarded_packets", "receiver_unique_packets"):
            for delta in (-1, 1):
                with self.subTest(key=key, delta=delta):
                    self.window[key] += delta
                    with self.assertRaisesRegex(gate.InvalidEvidence, key):
                        gate.validate(self.report)
                    self.window[key] -= delta

    def test_whole_run_physical_loss_and_excess_fail(self):
        for key in ("tx_phy_packets", "rx_phy_packets"):
            for delta in (-1, 1):
                with self.subTest(key=key, delta=delta):
                    self.run[key] += delta
                    with self.assertRaisesRegex(gate.InvalidEvidence, key):
                        gate.validate(self.report)
                    self.run[key] -= delta

    def test_live_physical_latch_skew_is_not_treated_as_loss(self):
        self.window["rx_phy_packets"] += 1
        self.window["rx_phy_bytes"] += 64
        self.assertEqual(gate.validate(self.report), 180)

    def test_every_drop_and_semantic_error_fails_even_with_equal_totals(self):
        for key in gate.ZERO_FIELDS:
            with self.subTest(key=key):
                self.window[key] = 1
                with self.assertRaisesRegex(gate.InvalidEvidence, key):
                    gate.validate(self.report)
                self.window[key] = 0

    def test_fcs_and_output_byte_accounting(self):
        for key in ("tx_phy_bytes", "rx_phy_bytes", "capture_bytes", "receiver_payload_bytes"):
            with self.subTest(key=key):
                self.window[key] += 1
                with self.assertRaisesRegex(gate.InvalidEvidence, key):
                    gate.validate(self.report)
                self.window[key] -= 1

    def test_zmq_bytes_include_record_mpls_and_batch_overhead(self):
        for key in ("forwarded_bytes", "receiver_message_bytes", "tx_phy_bytes", "rx_phy_bytes"):
            with self.subTest(key=key):
                self.run[key] -= 1
                with self.assertRaisesRegex(gate.InvalidEvidence, key):
                    gate.validate(self.report)
                self.run[key] += 1
        self.run["forwarded_bytes"] = self.run["tx_phy_packets"] * 60
        with self.assertRaisesRegex(gate.InvalidEvidence, "ZMQ message byte"):
            gate.validate(self.report)

    def test_short_burst_and_two_runs_do_not_pass(self):
        self.run["windows"].pop()
        with self.assertRaisesRegex(gate.InvalidEvidence, "60 contiguous"):
            gate.validate(self.report)
        self.report = passing_report()
        self.report["runs"].pop()
        with self.assertRaisesRegex(gate.InvalidEvidence, "three runs"):
            gate.validate(self.report)

    def test_gap_and_overlap_are_rejected(self):
        for offset in (-1, 1):
            with self.subTest(offset=offset):
                item = self.run["windows"][1]
                item["start_ns"] += offset
                item["end_ns"] += offset
                with self.assertRaisesRegex(gate.InvalidEvidence, "contiguous"):
                    gate.validate(self.report)
                item["start_ns"] -= offset
                item["end_ns"] -= offset

    def test_raw_rx_profile_is_rejected(self):
        self.report["profile"] = "raw-rx"
        with self.assertRaisesRegex(gate.InvalidEvidence, "profile"):
            gate.validate(self.report)

    def test_68_byte_frames_are_rejected(self):
        self.window["frame_min_bytes"] = 68
        self.window["frame_max_bytes"] = 68
        with self.assertRaisesRegex(gate.InvalidEvidence, "including FCS"):
            gate.validate(self.report)

    def test_underload_and_impossible_rate_are_rejected(self):
        for count in (0, 1_487_900_000, 1_488_300_000):
            with self.subTest(count=count):
                self.window["generated_packets"] = count
                with self.assertRaisesRegex(gate.InvalidEvidence, "offered rate"):
                    gate.validate(self.report)

    def test_malformed_counters_fail_closed(self):
        for value in (-1, True, "1488095238", 1.0, None):
            with self.subTest(value=value):
                self.window["capture_packets"] = value
                with self.assertRaisesRegex(gate.InvalidEvidence, "nonnegative integer"):
                    gate.validate(self.report)
        del self.window["capture_packets"]
        with self.assertRaisesRegex(gate.InvalidEvidence, "capture_packets"):
            gate.validate(self.report)

    def test_queue_sum_cannot_overwrite_global_total(self):
        self.window["queues"][0]["capture_packets"] -= 1
        self.window["queues"][0]["capture_bytes"] -= 60
        with self.assertRaisesRegex(gate.InvalidEvidence, "per-queue totals"):
            gate.validate(self.report)

    def test_duplicate_and_changing_queues(self):
        self.window["queues"][1]["id"] = 0
        with self.assertRaisesRegex(gate.InvalidEvidence, "duplicate queue"):
            gate.validate(self.report)
        self.window["queues"][1]["id"] = 2
        with self.assertRaisesRegex(gate.InvalidEvidence, "queue set changed"):
            gate.validate(self.report)

    def test_backlog_and_latency_cannot_hide_buffering(self):
        self.window["max_backlog_packets"] = 1025
        with self.assertRaisesRegex(gate.InvalidEvidence, "backlog exceeded"):
            gate.validate(self.report)
        self.window["max_backlog_packets"] = 1024
        self.window["max_delivery_latency_ns"] = 1_000_000_001
        with self.assertRaisesRegex(gate.InvalidEvidence, "latency exceeds"):
            gate.validate(self.report)

    def test_terminal_drain_and_warmup(self):
        for key, value in (("initial_backlog_packets", 1), ("final_backlog_packets", 1),
                           ("drain_ns", 1_000_000_001), ("warmup_ns", 0)):
            with self.subTest(key=key):
                saved = self.run[key]
                self.run[key] = value
                with self.assertRaises(gate.InvalidEvidence):
                    gate.validate(self.report)
                self.run[key] = saved

    def test_reusing_run_is_rejected(self):
        self.report["runs"][1]["id"] = self.run["id"]
        with self.assertRaisesRegex(gate.InvalidEvidence, "unique"):
            gate.validate(self.report)

    def test_cli_exit_codes_and_no_traceback_for_invalid_json(self):
        script = Path(__file__).with_name("validate_100g.py")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            for content, expected_code, expected_label in (
                (json.dumps(self.report), 0, "NUMERICAL_GATE_PASS"),
                ("{", 1, "NUMERICAL_GATE_FAIL"),
                ("[]", 1, "NUMERICAL_GATE_FAIL"),
                ('{"schema_version": 1, "schema_version": 2}', 1, "NUMERICAL_GATE_FAIL"),
                (json.dumps({}), 1, "NUMERICAL_GATE_FAIL"),
            ):
                with self.subTest(content=content[:40]):
                    path.write_text(content, encoding="utf-8")
                    result = subprocess.run([sys.executable, str(script), str(path)],
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, expected_code)
                    self.assertIn(expected_label, result.stdout + result.stderr)
                    self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
