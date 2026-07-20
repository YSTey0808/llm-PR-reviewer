#!/usr/bin/env python3
"""
Batch evaluation harness (Python standard library only).

Runs the detector over every sample diff and compares the verdict to the
expected label taken from the folder name:
  samples/malicious/*.diff  -> expected: flagged (verdict != "pass")
  samples/benign/*.diff     -> expected: not flagged (verdict == "pass")

Prints a per-file table and precision / recall / accuracy.

With --perturb, ALSO scans a few trivially-modified copies of each sample and
reports the verdict-change rate. temperature=0 + seed=7 make a re-run
deterministic, so repeating a scan measures nothing; determinism is not
calibration. A verdict that FLIPS under a semantics-preserving edit (rename a
variable, insert a blank line, reorder two hunks) is the real robustness signal.

Usage:
  python3 tests/eval.py
  python3 tests/eval.py --perturb                  # + robustness (more model calls)
  MODEL=qwen2.5-coder:7b python3 tests/eval.py      # try a bigger model
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
SCAN = os.path.join(ROOT, "detector", "scan.py")

# Skipped when picking an identifier to rename, so a variant renames a real
# program symbol rather than a language keyword.
KEYWORDS = {
    "def", "class", "return", "import", "from", "self", "none", "true", "false",
    "for", "while", "if", "elif", "else", "try", "except", "finally", "with",
    "and", "or", "not", "int", "str", "func", "var", "let", "const", "new",
    "public", "private", "static", "void", "this", "null", "function", "type",
}


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


def run_text(diff_text):
    """Scan an in-memory diff by writing it to a temp file and scanning that."""
    fd, path = tempfile.mkstemp(suffix=".diff")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(diff_text)
        return run_one(path)
    finally:
        os.unlink(path)


# --- semantics-preserving perturbations (operate on the raw diff text) --------

def _content_lines(diff):
    """The added-content text ('+' lines, not the '+++' header)."""
    return "\n".join(l[1:] for l in diff.splitlines()
                     if l.startswith("+") and not l.startswith("+++"))


def perturb_rename(diff):
    """Rename the most common added identifier everywhere (append '_v2').

    Applied only to content lines so file-header paths are left intact. Returns
    the diff unchanged if no suitable identifier is found."""
    counts = Counter(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", _content_lines(diff)))
    target = next((t for t, _ in counts.most_common()
                   if t.lower() not in KEYWORDS), None)
    if not target:
        return diff
    pat = re.compile(rf"\b{re.escape(target)}\b")
    out = []
    for l in diff.splitlines(keepends=True):
        if l[:1] in ("+", "-", " ") and not l.startswith(("+++", "---")):
            out.append(pat.sub(target + "_v2", l))
        else:
            out.append(l)
    return "".join(out)


def perturb_blank_line(diff):
    """Insert one blank ADDED line right after each hunk header."""
    out = []
    for l in diff.splitlines(keepends=True):
        out.append(l)
        if l.startswith("@@"):
            out.append("+\n")
    return "".join(out)


def perturb_reorder(diff):
    """Swap the first two hunks of the first file that has two (no-op otherwise)."""
    lines = diff.splitlines(keepends=True)
    heads = [i for i, l in enumerate(lines) if l.startswith("@@")]
    if len(heads) < 2:
        return diff
    a, b = heads[0], heads[1]
    if any(lines[i].startswith("diff --git") for i in range(a + 1, b)):
        return diff                             # two hunks not in the same file
    c = len(lines)
    for i in range(b + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git"):
            c = i
            break
    reordered = lines[:a] + lines[b:c] + lines[a:b] + lines[c:]
    return "".join(reordered)


PERTURBATIONS = [
    ("rename", perturb_rename),
    ("blank-line", perturb_blank_line),
    ("reorder", perturb_reorder),
]


def prf(tp, fp, tn, fn, total):
    """Precision, recall, and accuracy from a confusion-matrix tally."""
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    acc = (tp + tn) / total if total else 0.0
    return prec, rec, acc


def collect_cases():
    cases = []  # (path, expected_flagged)
    for label, expected in (("malicious", True), ("benign", False)):
        d = os.path.join(SAMPLES, label)
        for name in sorted(os.listdir(d)):
            if name.endswith(".diff"):
                cases.append((os.path.join(d, name), expected))
    return cases


def run_accuracy(cases):
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
    prec, rec, acc = prf(tp, fp, tn, fn, len(cases))
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision={prec:.2f}  recall={rec:.2f}  accuracy={acc:.2f}")
    print("\nGoal: high recall on malicious (catch attacks) with few FPs on benign.")


def run_perturb(cases):
    """For each sample, scan the original and its perturbed variants; a verdict
    that changes under a semantics-preserving edit is a robustness failure."""
    print(f"{'sample':40} {'orig':8} "
          + " ".join(f"{name:11}" for name, _ in PERTURBATIONS) + " changed")
    print("-" * 92)
    changed_count = 0
    for path, _expected in cases:
        with open(path, encoding="utf-8", errors="replace") as fh:
            diff = fh.read()
        base_verdict, _ = run_one(path)
        cells = []
        changed = False
        for _name, fn in PERTURBATIONS:
            variant = fn(diff)
            if variant == diff:
                cells.append("(=)")           # no-op edit; can't change anything
                continue
            v, _ = run_text(variant)
            cells.append(v if v == base_verdict else f"{v}*")
            if v != base_verdict:
                changed = True
        if changed:
            changed_count += 1
        rel = os.path.relpath(path, SAMPLES)
        print(f"{rel:40} {base_verdict:8} "
              + " ".join(f"{c:11}" for c in cells)
              + f" {'YES' if changed else 'no'}")

    print("-" * 92)
    total = len(cases)
    rate = changed_count / total if total else 0.0
    print(f"verdict-change rate = {changed_count}/{total} = {rate:.2f}  "
          f"(* marks a flipped verdict; lower is more robust)")
    print("Determinism (temperature=0, seed=7) is NOT calibration — this is the "
          "real robustness signal.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--perturb", action="store_true",
                    help="also scan trivially-modified copies and report the "
                         "verdict-change rate (robustness, not accuracy)")
    args = ap.parse_args()

    cases = collect_cases()
    if args.perturb:
        run_perturb(cases)
    else:
        run_accuracy(cases)


if __name__ == "__main__":
    main()
