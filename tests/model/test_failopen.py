#!/usr/bin/env python3
"""Regression tests for four FAIL-OPEN bugs in detector/scan.py — cases where a
scan that should demand review instead exits 0 with a clean pass (stdlib
unittest + the in-process FakeOllama; no real model or network).

Each test drives scan.py end-to-end as a subprocess and asserts the gate does
NOT silently pass:

  BUG 1  git failure must route to the infra fail-safe (review; block when
         FAIL_CLOSED), not look like an empty diff.
  BUG 2  binary-only / mode-only (chmod +x) changes must be surfaced, not vanish
         because extract_hunks drops their metadata.
  BUG 3  a reply missing / with a non-numeric risk_score must be distrusted
         (ContentError -> review), not defaulted to score 0 -> pass.
  BUG 4  main() clamps MAX_CHARS down to a NUM_CTX-derived budget (so Ollama
         can't silently truncate the prompt). The pure fit_max_chars helper is
         covered in tests/unit/test_failopen_units.py.

Run:  python tests/model/test_failopen.py -v
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
from fake_ollama import FakeOllama  # noqa: E402

SCAN = os.path.join(ROOT, "detector", "scan.py")
PROMPT = os.path.join(ROOT, "prompts", "intent.md")
FIXTURES = os.path.join(TESTS, "fixtures")


def fx(name):
    return os.path.join(FIXTURES, name)


def run_scan(args, cwd=ROOT, env_extra=None):
    """Run scan.py with the given argv, returning (json_or_None, proc, comment).

    Retries are disabled (RETRIES=1, RETRY_BACKOFF=0) so one request maps to one
    chunk. COMMENT_FILE is a throwaway temp file whose contents are read back so
    tests can assert on the rendered banner.
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


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                   check=True)


# ---- BUG 1: git failure must not masquerade as a clean pass -----------------

class TestGitFailure(unittest.TestCase):
    def test_git_failure_routes_to_infra_review(self):
        # A non-git directory makes `git diff origin/main...HEAD` fail (exit 128).
        with tempfile.TemporaryDirectory() as d:
            data, proc, comment = run_scan([], cwd=d)
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertNotEqual(data["verdict"], "pass")          # NOT a silent green check
        self.assertEqual(data["verdict"], "review")
        self.assertEqual(data["failsafe"], "infra")
        self.assertNotIn("No diff content to scan", proc.stderr)
        self.assertIn("Scan incomplete", comment)             # infra banner rendered
        self.assertIn("fetch-depth", proc.stderr)             # actionable CI hint

    def test_git_failure_blocks_when_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            data, proc, _ = run_scan([], cwd=d, env_extra={"FAIL_CLOSED": "true"})
        self.assertIsNotNone(data)
        self.assertEqual(data["verdict"], "block")
        self.assertEqual(data["failsafe"], "infra")
        self.assertEqual(proc.returncode, 1)                  # block -> non-zero exit


class TestGitSuccessEmpty(unittest.TestCase):
    def test_empty_diff_from_successful_git_is_genuine_pass(self):
        # git succeeds but there is no diff (HEAD...HEAD) -> a real clean pass,
        # distinct from the git-failure path above.
        with tempfile.TemporaryDirectory() as d:
            git(d, "init")
            git(d, "config", "user.email", "t@example.com")
            git(d, "config", "user.name", "t")
            with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as fh:
                fh.write("hello\n")
            git(d, "add", "-A")
            git(d, "commit", "-m", "init")
            data, proc, _ = run_scan(["--git-base", "HEAD"], cwd=d)
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["verdict"], "pass")
        self.assertEqual(data["score"], 0)
        self.assertIn("No diff content to scan", proc.stderr)


# ---- BUG 2: binary-only / mode-only changes must be surfaced ----------------

class TestBinaryAndModeChanges(unittest.TestCase):
    def test_binary_only_is_review_and_names_file(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 0}])                 # model sees a header, says benign
            data, proc, comment = run_scan(
                ["--diff", fx("binary_only.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["verdict"], "review")           # not a pass despite score 0
        self.assertNotIn("No diff content to scan", proc.stderr)
        files = [f["file"] for f in data["suspicious_findings"]]
        self.assertIn("payload.so", files)
        self.assertIn("payload.so", data["files_binary"])     # marked NOT reviewed
        self.assertIn("were NOT reviewed", comment)           # comment is honest about it

    def test_chmod_exec_produces_executable_finding(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 0}])
            data, proc, _ = run_scan(
                ["--diff", fx("chmod_exec.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        findings = data["suspicious_findings"]
        self.assertTrue(any(f["file"] == "ci/deploy.sh" for f in findings))
        reasons = " ".join(f["reason"] for f in findings).lower()
        self.assertIn("executable", reasons)


# ---- BUG 3: a broken reply must be distrusted, not scored 0 -----------------

class TestBrokenReply(unittest.TestCase):
    def test_missing_risk_score_is_review_not_pass(self):
        with FakeOllama() as fake:
            fake.raw(['{"reasoning": "looks totally fine"}'])   # valid JSON, no risk_score
            data, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["failsafe"], "content")
        self.assertEqual(data["verdict"], "review")

    def test_non_numeric_risk_score_is_review_not_pass(self):
        with FakeOllama() as fake:
            fake.raw(['{"key_changes": [], "suspicious_findings": [], '
                      '"reasoning": "x", "risk_score": "high"}'])
            data, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff")],
                env_extra={"OLLAMA_URL": fake.url})
        self.assertIsNotNone(data, f"stdout not JSON: {proc.stdout!r} / {proc.stderr!r}")
        self.assertEqual(data["failsafe"], "content")
        self.assertEqual(data["verdict"], "review")


# ---- BUG 4: main() clamps MAX_CHARS down to fit NUM_CTX ----------------------

class TestMaxCharsClamp(unittest.TestCase):
    def test_main_clamps_max_chars_and_logs(self):
        with FakeOllama() as fake:
            fake.respond([{"risk_score": 5}])
            _, proc, _ = run_scan(
                ["--diff", fx("lockfile_clean.diff"), "--verbose"],
                env_extra={"OLLAMA_URL": fake.url,
                           "MAX_CHARS": "16000", "NUM_CTX": "4096"})
        self.assertIn("clamping MAX_CHARS", proc.stderr)


if __name__ == "__main__":
    unittest.main()
