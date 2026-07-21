#!/usr/bin/env python3
"""End-to-end test for CHANGE 1's corroboration loop in detector/scan.py (stdlib
unittest + the in-process FakeOllama; no real model or network).

  CHANGE 1  corroborate(): a would-be block (chunk score >= BLOCK) gets ONE
            second independent review before it can block. Disagreement demotes
            to review (never pass); agreement keeps the block.

The pure-function halves — corroborate()'s failure paths in isolation, the
per-file injection exemption (CHANGE 2), priority() added-lines-only (CHANGE 3),
and the FAIL_SAFE clamp (CHANGE 4) — live in
tests/unit/test_corroborate_units.py.

Run:  python tests/model/test_corroborate.py -v
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, os.path.join(TESTS, "support"))
from fake_ollama import FakeOllama  # noqa: E402

SCAN = os.path.join(ROOT, "detector", "scan.py")
PROMPT = os.path.join(ROOT, "prompts", "intent.md")
FIXTURES = os.path.join(TESTS, "fixtures")

# Load scan.py by path (no package/__init__.py) for the module's REVIEW band.
_spec = importlib.util.spec_from_file_location("scan", SCAN)
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def fx(name):
    return os.path.join(FIXTURES, name)


def run_scan(args, cwd=ROOT, env_extra=None):
    """Run scan.py end-to-end, returning (json_or_None, proc, comment).

    RETRIES=1/RETRY_BACKOFF=0 so one request maps to one model call — the initial
    review and the corroboration second call are then exactly one request each.
    """
    fd, comment_path = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    env = dict(os.environ)
    env.update({
        "PROMPT_FILE": PROMPT,
        "COMMENT_FILE": comment_path,
        "RETRIES": "1",
        "RETRY_BACKOFF": "0",
        "REQUEST_TIMEOUT": "5",
    })
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run([sys.executable, SCAN, *args], cwd=cwd, env=env,
                              capture_output=True, text=True, timeout=60)
        try:
            with open(comment_path, encoding="utf-8") as fh:
                comment = fh.read()
        except OSError:
            comment = ""
    finally:
        try:
            os.unlink(comment_path)
        except OSError:
            pass
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = None
    return data, proc, comment


# ---- CHANGE 1: corroborate a would-be block --------------------------------

class TestCorroborateEndToEnd(unittest.TestCase):
    """Full loop: one chunk scores >= BLOCK, corroboration fires on the second
    request. Uses a single-file fixture so there is exactly one chunk."""

    def test_disagreement_demotes_block_to_review(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 85}, {"risk_score": 20}])  # [85, 20]
            data, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["verdict"], "review")             # demoted, not block
        self.assertEqual(data["score"], scan.REVIEW)            # max(REVIEW, 20)
        self.assertEqual(len(fake.requests), 2)                 # corroboration fired
        self.assertEqual(proc.returncode, 0)

    def test_agreement_keeps_block(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 85}, {"risk_score": 85}])  # [85, 85]
            data, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["verdict"], "block")              # corroborated
        self.assertEqual(data["score"], 85)
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(proc.returncode, 1)                    # block -> non-zero

    def test_below_block_does_not_corroborate(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 30}])                  # [30] < BLOCK
            data, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(len(fake.requests), 1)                 # exactly one call
        self.assertEqual(data["score"], 30)


if __name__ == "__main__":
    unittest.main()
