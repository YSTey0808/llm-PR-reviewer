#!/usr/bin/env python3
"""
Malicious-intent PR gate — detector (Python standard library only).

Reads a diff, asks a LOCAL Ollama model to judge INTENT (not ordinary bugs),
aggregates a score across files, and exits non-zero on 'block' so CI can fail
the check.

Improvements for small local models:
  - Structured output: passes a JSON *schema* to Ollama so the reply is
    constrained to the exact shape (far more reliable than "give me JSON").
  - Light chain-of-thought: the schema asks for a one-line `observation`
    BEFORE the confidence, so the model reasons then scores.
  - Per-file chunking: large files are split (not truncated) so nothing is lost.
  - Fail-safe: if a file can't be scanned (timeout / error / unparseable),
    the verdict is floored at 'review' instead of silently passing.

Usage:
  python3 detector/scan.py --diff samples/malicious/exfil.diff   # hand test
  python3 detector/scan.py --git-base origin/main                # CI: diff vs base

Env (defaults shown):
  OLLAMA_URL http://localhost:11434 | MODEL qwen2.5-coder:3b
  PROMPT_FILE prompts/intent.md | BLOCK_THRESHOLD 7 | REVIEW_THRESHOLD 4
  MAX_CHARS 8000 | FAIL_SAFE review
"""

import argparse
import json
import os
import re
import subprocess
import sys
import unicodedata
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("MODEL", "qwen2.5-coder:3b")
PROMPT_FILE = os.environ.get("PROMPT_FILE", "prompts/intent.md")
BLOCK = int(os.environ.get("BLOCK_THRESHOLD", "7"))
REVIEW = int(os.environ.get("REVIEW_THRESHOLD", "4"))
MAX_CHARS = int(os.environ.get("MAX_CHARS", "8000"))
FAIL_SAFE = os.environ.get("FAIL_SAFE", "review")   # verdict floor on scan error

CATEGORIES = [
    "exfiltration", "backdoor", "logic_bomb",
    "ci_cd_tampering", "obfuscation", "suspicious_network",
]

# JSON schema handed to Ollama's structured-output "format" — constrains the
# model to emit exactly this. `observation` is first so the model reasons first.
SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "observation": {"type": "string"},
                    "type": {"type": "string", "enum": CATEGORIES},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 10},
                    "rationale": {"type": "string"},
                },
                "required": ["observation", "type", "confidence", "rationale"],
            },
        }
    },
    "required": ["findings"],
}

_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go",
    ".rb": "Ruby", ".java": "Java", ".sh": "Shell", ".yml": "YAML",
    ".yaml": "YAML", ".php": "PHP", ".rs": "Rust", ".c": "C", ".cpp": "C++",
}
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def sanitize(text):
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def lang_of(name):
    return _LANG.get(os.path.splitext(name)[1].lower(), "code")


def get_diff(args):
    if args.diff:
        with open(args.diff, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    base = args.git_base or "origin/main"
    return subprocess.run(
        ["git", "diff", "--unified=3", f"{base}...HEAD"],
        capture_output=True, text=True,
    ).stdout


def split_by_file(diff):
    if "diff --git" not in diff:
        return [("input", diff)]
    parts, current, name = [], [], "unknown"
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if current:
                parts.append((name, "".join(current)))
                current = []
            m = re.search(r"b/(\S+)", line)
            name = m.group(1) if m else "unknown"
        current.append(line)
    if current:
        parts.append((name, "".join(current)))
    return parts


def chunk_text(text, limit):
    """Split on line boundaries so a big file is scanned fully, not truncated."""
    if len(text) <= limit:
        return [text]
    chunks, cur, size = [], [], 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit and cur:
            chunks.append("".join(cur))
            cur, size = [], 0
        cur.append(line)
        size += len(line)
    if cur:
        chunks.append("".join(cur))
    return chunks


def call_model(system, user):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": SCHEMA,                       # structured output
        "options": {"temperature": 0, "seed": 7},
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp).get("message", {}).get("content", "")


def parse_findings(raw):
    def load(s):
        obj = json.loads(s)
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            return obj.get("findings", [])
        return []
    try:
        return load(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return load(m.group(0))
            except Exception:
                return []
        return []


def scan_file(name, text, system):
    """Scan one file's diff (chunked). Returns (findings, errored)."""
    lang = lang_of(name)
    findings, errored = [], False
    for chunk in chunk_text(sanitize(text), MAX_CHARS):
        user = (
            f"File: {name}\nLanguage: {lang}\n"
            f"---DIFF START---\n{chunk}\n---DIFF END---"
        )
        try:
            raw = call_model(system, user)
        except Exception:
            errored = True
            continue
        fs = parse_findings(raw)
        if not fs and raw.strip():              # one retry on empty/garbled
            try:
                fs = parse_findings(call_model(system, user))
            except Exception:
                errored = True
        for f in fs:
            try:
                conf = int(f.get("confidence", 0))
            except Exception:
                conf = 0
            findings.append({
                "type": str(f.get("type", "unknown")),
                "confidence": max(0, min(10, conf)),
                "file": f.get("file", name),
                "rationale": str(f.get("rationale", ""))[:300],
            })
    return findings, errored


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["type"], f["file"], f["rationale"][:60])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def aggregate(findings, errored):
    if not findings:
        score, verdict = 0, "pass"
    else:
        top = max(f["confidence"] for f in findings)
        highs = sum(1 for f in findings if f["confidence"] >= 6)
        score = min(10, top + (1 if highs >= 2 else 0))
        verdict = "block" if score >= BLOCK else "review" if score >= REVIEW else "pass"
    if errored and verdict == "pass":           # never silently pass an unscannable diff
        verdict = FAIL_SAFE
    return score, verdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", help="path to a diff file (hand testing)")
    ap.add_argument("--git-base", help="base ref for git diff (CI)")
    args = ap.parse_args()

    with open(PROMPT_FILE, encoding="utf-8") as fh:
        system = fh.read()

    diff = get_diff(args)
    if not diff.strip():
        print(json.dumps({"verdict": "pass", "score": 0, "findings": []}))
        print("No diff content to scan.", file=sys.stderr)
        return 0

    all_findings, errored = [], False
    for name, text in split_by_file(diff):
        if not text.strip():
            continue
        fs, err = scan_file(name, text, system)
        all_findings.extend(fs)
        errored = errored or err

    all_findings = dedupe(all_findings)
    score, verdict = aggregate(all_findings, errored)
    print(json.dumps({"verdict": verdict, "score": score, "findings": all_findings}, indent=2))

    lines = [f"### Intent gate: {verdict.upper()} (score {score})", ""]
    for f in all_findings:
        lines.append(f"- `{f['file']}` — {f['type']} (conf {f['confidence']}): {f['rationale']}")
    if errored:
        lines.append("- note: one or more files could not be scanned; verdict floored to fail-safe.")
    summary = "\n".join(lines)
    print(summary, file=sys.stderr)
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a") as fh:
            fh.write(summary + "\n")

    return 1 if verdict == "block" else 0


if __name__ == "__main__":
    sys.exit(main())