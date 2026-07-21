#!/usr/bin/env python3
"""Offline test runner for the detector (Python standard library only).

Runs every test file in the two offline buckets and reports a per-file
PASS/FAIL line, then a summary. Exits non-zero if ANY file fails — fail-closed,
so a broken or un-runnable test can never read as green.

  tests/unit/   pure functions — no model, network, or subprocess
  tests/model/  the model-call path via the in-process FakeOllama / a recorder

The real-model eval harness (tests/eval/) is intentionally excluded — it needs a
running Ollama and is not part of the offline suite.

Usage:
  python tests/run_tests.py            # both buckets
  python tests/run_tests.py --unit     # only tests/unit/
  python tests/run_tests.py --model    # only tests/model/
"""

import argparse
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUCKETS = {
    "unit": os.path.join(HERE, "unit"),
    "model": os.path.join(HERE, "model"),
}


def discover(bucket_dir):
    """Return sorted test_*.py paths in a bucket directory."""
    return sorted(glob.glob(os.path.join(bucket_dir, "test_*.py")))


def run_file(path):
    """Run one test file as a subprocess; return True on exit code 0."""
    rel = os.path.relpath(path, HERE)
    proc = subprocess.run([sys.executable, path], cwd=os.path.dirname(HERE))
    ok = proc.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'}  {rel}  (exit {proc.returncode})")
    return ok


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unit", action="store_true", help="run only tests/unit/")
    ap.add_argument("--model", action="store_true", help="run only tests/model/")
    args = ap.parse_args()

    # No flag = both buckets.
    which = [b for b in ("unit", "model")
             if getattr(args, b) or not (args.unit or args.model)]

    failures = []
    ran = 0
    for bucket in which:
        files = discover(BUCKETS[bucket])
        if not files:
            # A missing/empty bucket is suspicious, not success.
            print(f"FAIL  {bucket}/  (no test_*.py files found)")
            failures.append(f"{bucket}/ (empty)")
            continue
        print(f"\n== {bucket} ==")
        for path in files:
            ran += 1
            if not run_file(path):
                failures.append(os.path.relpath(path, HERE))

    print("\n" + "-" * 60)
    if failures:
        print(f"FAILED: {len(failures)}/{ran} — {', '.join(failures)}")
        return 1
    print(f"OK: {ran} test file(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
