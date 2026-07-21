#!/usr/bin/env python3
"""
Unit tests for the Stage-2 two-phase scan helpers in detector/scan.py
(stdlib unittest only). Covers signal-first chunk ordering and the phase-2
time-budget pre-check. review_chunk is monkeypatched throughout, so NO Ollama /
network call is ever made. Run: python tests/unit/test_twophase.py -v
"""

import importlib.util
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "detector"))
_spec = importlib.util.spec_from_file_location(
    "scan", os.path.join(ROOT, "detector", "scan.py"))
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _ok_result(score=0):
    return {"risk_score": score, "key_changes": [], "suspicious_findings": [],
            "reasoning": ""}


class TestOrderChunksBySignal(unittest.TestCase):
    def test_signal_chunk_is_lifted_to_front(self):
        chunks = [("plain", ["a.py"]), ("hot", ["b.py"]), ("plain2", ["c.py"])]
        ordered = scan.order_chunks_by_signal(chunks, {"b.py"})
        self.assertEqual(ordered[0][1], ["b.py"])

    def test_stable_within_groups(self):
        chunks = [("x", ["a"]), ("y", ["b"]), ("z", ["c"])]
        # No signals -> order unchanged (stable sort, all same key).
        self.assertEqual(scan.order_chunks_by_signal(chunks, set()), chunks)


class TestScanTierPhase1(unittest.TestCase):
    """Phase 1 has no deadline: every chunk is scanned, never budget-floored."""

    def setUp(self):
        self._orig = scan.review_chunk
        scan.review_chunk = lambda text, system: _ok_result(0)

    def tearDown(self):
        scan.review_chunk = self._orig

    def test_all_chunks_scanned_no_budget(self):
        chunks = [("c1", ["a.py"]), ("c2", ["b.py"])]
        durations = []
        outcomes, budget = scan.scan_tier(chunks, "tier1", "sys", None, durations)
        self.assertEqual([o["status"] for o in outcomes], ["ok", "ok"])
        self.assertEqual(budget, [])
        self.assertEqual(len(durations), 2)      # both completions recorded


class TestScanTierPhase2Budget(unittest.TestCase):
    def test_past_deadline_floors_all_without_a_call(self):
        # A deadline already in the past must floor every tier2 chunk to review
        # WITHOUT ever calling the model.
        def _boom(text, system):
            raise AssertionError("review_chunk must not be called past deadline")

        orig = scan.review_chunk
        scan.review_chunk = _boom
        try:
            chunks = [("c1", ["a.yml"]), ("c2", ["b.yml", "c.yml"])]
            outcomes, budget = scan.scan_tier(
                chunks, "tier2", "sys", time.monotonic() - 1, [])
        finally:
            scan.review_chunk = orig
        self.assertEqual([o["status"] for o in outcomes], ["budget", "budget"])
        self.assertEqual(budget, ["a.yml", "b.yml", "c.yml"])

    def test_remaining_below_estimate_is_not_started(self):
        # Plenty of clock left in absolute terms, but less than EST_CHUNK_SECONDS
        # -> the chunk is floored rather than started (never begin a call we don't
        # expect to finish).
        orig_est = scan.EST_CHUNK_SECONDS
        orig_rc = scan.review_chunk
        scan.EST_CHUNK_SECONDS = 10_000          # est dwarfs the remaining budget
        scan.review_chunk = lambda text, system: _ok_result(0)
        try:
            deadline = time.monotonic() + 5      # 5s remaining < 10000s estimate
            outcomes, budget = scan.scan_tier(
                chunks=[("c1", ["a.yml"])], tier="tier2", system="sys",
                deadline=deadline, durations=[])
        finally:
            scan.EST_CHUNK_SECONDS = orig_est
            scan.review_chunk = orig_rc
        self.assertEqual([o["status"] for o in outcomes], ["budget"])
        self.assertEqual(budget, ["a.yml"])

    def test_ample_budget_scans_the_chunk(self):
        orig_est = scan.EST_CHUNK_SECONDS
        orig_rc = scan.review_chunk
        scan.EST_CHUNK_SECONDS = 1
        scan.review_chunk = lambda text, system: _ok_result(0)
        try:
            deadline = time.monotonic() + 3600
            outcomes, budget = scan.scan_tier(
                chunks=[("c1", ["a.yml"])], tier="tier2", system="sys",
                deadline=deadline, durations=[])
        finally:
            scan.EST_CHUNK_SECONDS = orig_est
            scan.review_chunk = orig_rc
        self.assertEqual([o["status"] for o in outcomes], ["ok"])
        self.assertEqual(budget, [])


if __name__ == "__main__":
    unittest.main()
