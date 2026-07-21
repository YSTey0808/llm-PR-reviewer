#!/usr/bin/env python3
"""End-to-end tests proving the FakeOllama harness drives detector/scan.py
(stdlib unittest only — no real model, network, or GPU).

Each test starts an in-process FakeOllama on an ephemeral port, points scan.py's
OLLAMA_URL at it, runs scan.py as a subprocess against a fixture diff, and
asserts on the JSON scan.py prints to stdout. This exercises the transport path,
the retry loop, and both fail-safe branches — the parts the pure-function unit
tests (tests/unit/) cannot reach.

Run:  python tests/model/test_harness.py -v
"""

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
from fake_ollama import FakeOllama, BENIGN_RESULT  # noqa: E402

SCAN = os.path.join(ROOT, "detector", "scan.py")
PROMPT = os.path.join(ROOT, "prompts", "intent.md")
FIXTURES = os.path.join(TESTS, "fixtures")


def run_scan(fake_url, diff_name, request_timeout="2", extra_env=None):
    """Run scan.py against `diff_name` with OLLAMA_URL pointed at the fake.

    Returns (parsed_stdout_json, exit_code). Retries are disabled (RETRIES=1,
    RETRY_BACKOFF=0) so one request maps to one chunk and runs stay fast.
    """
    env = dict(os.environ)
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
        comment_file = tmp.name
    env.update({
        "OLLAMA_URL": fake_url,
        "PROMPT_FILE": PROMPT,
        "COMMENT_FILE": comment_file,
        "RETRIES": "1",
        "RETRY_BACKOFF": "0",
        "REQUEST_TIMEOUT": request_timeout,
    })
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [sys.executable, SCAN, "--diff", os.path.join(FIXTURES, diff_name)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
        )
    finally:
        try:
            os.unlink(comment_file)
        except OSError:
            pass
    try:
        result = json.loads(proc.stdout)
    except ValueError as exc:  # surface scan.py's stderr to explain the failure
        raise AssertionError(
            f"scan.py stdout was not JSON: {exc}\n"
            f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}")
    return result, proc.returncode


class TestScriptedScore(unittest.TestCase):
    def test_fake_score_flows_through_to_verdict(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 85}])
            result, code = run_scan(fake.url, "new_exec.diff")
        self.assertEqual(result["score"], 85)
        self.assertEqual(result["verdict"], "block")
        self.assertEqual(code, 1)                 # block -> non-zero exit

    def test_scripted_pass_score(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 10}])
            result, code = run_scan(fake.url, "new_exec.diff")
        self.assertEqual(result["score"], 10)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(code, 0)


class TestEcho(unittest.TestCase):
    def test_request_body_records_what_was_sent(self):
        with FakeOllama() as fake:
            fake.echo()
            result, _ = run_scan(fake.url, "new_exec.diff")
            self.assertEqual(len(fake.requests), 1)
            sent = fake.requests[0]["messages"][-1]["content"]
            self.assertIn("scripts/run.sh", sent)       # the changed file reached the model
            self.assertIn("<untrusted_diff>", sent)     # wrapped as untrusted data
        self.assertEqual(result["score"], 0)


class TestFailSafes(unittest.TestCase):
    def test_garbage_reply_is_content_failsafe(self):
        with FakeOllama() as fake:
            fake.garbage()
            result, _ = run_scan(fake.url, "new_exec.diff")
        self.assertEqual(result["failsafe"], "content")
        self.assertEqual(result["verdict"], "review")   # floored, never a clean pass

    def test_http_error_is_infra_failsafe(self):
        with FakeOllama() as fake:
            fake.http_error(500)
            result, _ = run_scan(fake.url, "new_exec.diff")
        self.assertEqual(result["failsafe"], "infra")
        self.assertEqual(result["verdict"], "review")

    def test_hang_past_timeout_is_infra_failsafe(self):
        with FakeOllama() as fake:
            fake.hang(3)
            result, _ = run_scan(fake.url, "new_exec.diff", request_timeout="1")
        self.assertEqual(result["failsafe"], "infra")


class TestInjectionFixture(unittest.TestCase):
    def test_injection_marker_floors_score(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 0}])           # model says benign...
            result, _ = run_scan(fake.url, "injection_in_sample.diff")
        self.assertTrue(result["injection"])            # ...but the tripwire fires
        self.assertGreaterEqual(result["score"], 55)    # floored to INJECTION_FLOOR


class TestModeBinaryBlindness(unittest.TestCase):
    """Pins the CURRENT (blind) behaviour before detector logic changes:
    extract_hunks keeps the `diff --git` header but DROPS the `old/new mode`
    and `Binary files ...` lines, so the model is still called yet the actual
    change (a chmod to +x, or a new binary) never reaches it — only the path
    does. The verdict is then whatever the model says about an empty diff."""

    def _assert_change_stripped(self, diff_name, marker, path):
        with FakeOllama() as fake:
            fake.echo()
            run_scan(fake.url, diff_name)
            self.assertEqual(len(fake.requests), 1)     # model IS called...
            sent = fake.requests[0]["messages"][-1]["content"]
            self.assertIn(path, sent)                   # ...it sees the file path...
            self.assertNotIn(marker, sent)              # ...but not the actual change

    def test_binary_marker_stripped_before_model(self):
        self._assert_change_stripped("binary_only.diff", "Binary files", "payload.so")

    def test_chmod_mode_stripped_before_model(self):
        self._assert_change_stripped("chmod_exec.diff", "100755", "ci/deploy.sh")


if __name__ == "__main__":
    unittest.main()
