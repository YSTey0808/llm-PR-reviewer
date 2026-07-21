#!/usr/bin/env python3
"""
Unit tests for detector/scan.py's intent-focused file classifier (stdlib
unittest only). Covers the three tiers, the "signals beat paths" rule, and the
"any exception -> tier1" fail-up guard. No network or Ollama.
Run: python tests/unit/test_classify.py -v
"""

import importlib.util
import os
import sys
import unittest

# Load scan.py by file path (the repo has no package / __init__.py), mirroring
# tests/unit/test_scan.py. detector/ must be on sys.path so scan.py's own
# `import filters` resolves.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "detector"))
_spec = importlib.util.spec_from_file_location(
    "scan", os.path.join(ROOT, "detector", "scan.py"))
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _diff(path, *added):
    """Minimal cleaned per-file diff: header + one hunk of added lines."""
    body = "".join(f"+{line}\n" for line in added)
    return (f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(added)} @@\n{body}")


class TestTier1(unittest.TestCase):
    def test_workflow_yaml_is_tier1(self):
        d = _diff(".github/workflows/deploy.yml", "name: deploy")
        self.assertEqual(scan.classify_file(".github/workflows/deploy.yml", d),
                         "tier1")

    def test_jenkinsfile_is_tier1(self):
        d = _diff("Jenkinsfile", "pipeline { agent any }")
        self.assertEqual(scan.classify_file("Jenkinsfile", d), "tier1")

    def test_plain_source_is_tier1(self):
        d = _diff("app.py", "x = 1", "y = x + 2", "print(y)")
        self.assertEqual(scan.classify_file("app.py", d), "tier1")

    def test_shell_script_is_tier1(self):
        d = _diff("deploy.sh", "echo hello")
        self.assertEqual(scan.classify_file("deploy.sh", d), "tier1")

    def test_base64_blob_in_prose_promotes_to_tier1(self):
        blob = "A" * 300                         # > 200-char base64-looking run
        d = _diff("README.md", f"token: {blob}")
        # A .md would be tier3 by path, but the content signal beats the path.
        self.assertEqual(scan.classify_file("README.md", d), "tier1")

    def test_content_signal_in_json_promotes_to_tier1(self):
        d = _diff("innocuous.json", '"cmd": "process.env.SECRET"')
        # A .json would be tier2 by path, but process.env is a tier1 signal.
        self.assertEqual(scan.classify_file("innocuous.json", d), "tier1")


class TestTier2(unittest.TestCase):
    def test_config_yaml_no_signals_is_tier2(self):
        d = _diff("config/app.yml", "debug: false", "port: 8080")
        self.assertEqual(scan.classify_file("config/app.yml", d), "tier2")

    def test_lockfile_is_tier2(self):
        d = _diff("package-lock.json", '"lockfileVersion": 3')
        self.assertEqual(scan.classify_file("package-lock.json", d), "tier2")


class TestTier3(unittest.TestCase):
    def test_plain_prose_is_tier3(self):
        d = _diff("README.md", "# Project", "Some documentation.")
        self.assertEqual(scan.classify_file("README.md", d), "tier3")

    def test_binary_png_is_tier3(self):
        d = ("diff --git a/logo.png b/logo.png\n"
             "Binary files a/logo.png and b/logo.png differ\n")
        self.assertEqual(scan.classify_file("logo.png", d), "tier3")


class TestFailUp(unittest.TestCase):
    def test_internal_exception_returns_tier1(self):
        original = scan._has_tier1_signal
        scan._has_tier1_signal = lambda _diff: (_ for _ in ()).throw(
            RuntimeError("boom"))
        try:
            self.assertEqual(scan.classify_file("app.py", "irrelevant"), "tier1")
        finally:
            scan._has_tier1_signal = original


if __name__ == "__main__":
    unittest.main()
