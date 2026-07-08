#!/usr/bin/env python3
"""
Batch evaluation harness (Python standard library only).

Runs the detector over every sample diff and compares the verdict to the
expected label taken from the folder name:
  samples/malicious/*.diff  -> expected: flagged (verdict != "pass")
  samples/benign/*.diff     -> expected: not flagged (verdict == "pass")

Prints a per-file table and precision / recall / accuracy.

Usage:
  python3 tests/eval.py
  MODEL=qwen2.5-coder:7b python3 tests/eval.py     # try a bigger model
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
SCAN = os.path.join(ROOT, "detector", "scan.py")


def run_one(path):
    """Return (verdict, score) for a single diff, or ('error', -1) on failure."""
    proc = subprocess.run(
        [sys.executable, SCAN, "--diff", path],
        capture_output=True, text=True, cwd=ROOT,
    )
    try:
        out = json.loads(proc.stdout)
        return out.get("verdict", "error"), out.get("score", -1)
    except Exception:
        return "error", -1


def main():
    cases = []  # (path, expected_flagged)
    for label, expected in (("malicious", True), ("benign", False)):
        d = os.path.join(SAMPLES, label)
        for name in sorted(os.listdir(d)):
            if name.endswith(".diff"):
                cases.append((os.path.join(d, name), expected))

    tp = fp = tn = fn = 0
    print(f"{'sample':40} {'expected':10} {'verdict':8} {'score':5} result")
    print("-" * 78)
    for path, expected in cases:
        verdict, score = run_one(path)
        flagged = verdict != "pass"          # block OR review = flagged
        ok = flagged == expected
        if expected and flagged:
            tp += 1
        elif expected and not flagged:
            fn += 1
        elif not expected and flagged:
            fp += 1
        else:
            tn += 1
        rel = os.path.relpath(path, SAMPLES)
        print(f"{rel:40} {('flag' if expected else 'clean'):10} "
              f"{verdict:8} {str(score):5} {'OK' if ok else 'MISS'}")

    print("-" * 78)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    acc = (tp + tn) / len(cases) if cases else 0.0
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision={prec:.2f}  recall={rec:.2f}  accuracy={acc:.2f}")
    print("\nGoal: high recall on malicious (catch attacks) with few FPs on benign.")


if __name__ == "__main__":
    main()