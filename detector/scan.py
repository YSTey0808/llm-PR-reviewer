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
  - Line mapping: added lines are numbered from the @@ hunk headers so each
    finding carries a `line`, emitted as a GitHub annotation
    (::error file=..,line=..::) that shows inline on the PR.
  - Parallel scanning: chunks are scanned through a small thread pool
    (I/O-bound HTTP waits; Ollama enforces its own parallelism/queue), with
    results re-ordered by (file, chunk) index so output is deterministic.
  - Timeout + one retry with short backoff per request.
  - PR summary: one extra model call describes what the PR does, added as a
    top-level `summary` key (additive; never affects the verdict).
  - Fail-safe: if a file can't be scanned (timeout / error / unparseable),
    the verdict is floored at 'review' instead of silently passing.

Usage:
  python3 detector/scan.py --diff samples/malicious/exfil.diff   # hand test
  python3 detector/scan.py --git-base origin/main                # CI: diff vs base
  python3 detector/scan.py --diff x.diff --verbose               # timing on stderr

Env (defaults shown):
  OLLAMA_URL http://localhost:11434 | MODEL qwen2.5-coder:3b
  PROMPT_FILE prompts/intent.md | SUMMARY_PROMPT_FILE prompts/summary.md
  BLOCK_THRESHOLD 7 | REVIEW_THRESHOLD 4 | MAX_CHARS 8000 | FAIL_SAFE review
  MAX_WORKERS 3 | REQUEST_TIMEOUT 120 | RETRY_BACKOFF 2
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("MODEL", "qwen2.5-coder:3b")
PROMPT_FILE = os.environ.get("PROMPT_FILE", "prompts/intent.md")
SUMMARY_PROMPT_FILE = os.environ.get("SUMMARY_PROMPT_FILE", "prompts/summary.md")
BLOCK = int(os.environ.get("BLOCK_THRESHOLD", "7"))
REVIEW = int(os.environ.get("REVIEW_THRESHOLD", "4"))
MAX_CHARS = int(os.environ.get("MAX_CHARS", "8000"))
FAIL_SAFE = os.environ.get("FAIL_SAFE", "review")   # verdict floor on scan error
MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "3")))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "120"))
RETRY_BACKOFF = float(os.environ.get("RETRY_BACKOFF", "2"))

CATEGORIES = [
    "exfiltration", "backdoor", "logic_bomb",
    "ci_cd_tampering", "obfuscation", "suspicious_network",
]

# JSON schema handed to Ollama's structured-output "format" — constrains the
# model to emit exactly this. `observation` is first so the model reasons first.
# `line` is the new-file line number shown in the diff's `+  N| ` prefix.
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
                    "line": {"type": "integer"},
                    "rationale": {"type": "string"},
                },
                "required": ["observation", "type", "confidence", "line", "rationale"],
            },
        }
    },
    "required": ["findings"],
}

SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
}

_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go",
    ".rb": "Ruby", ".java": "Java", ".sh": "Shell", ".yml": "YAML",
    ".yaml": "YAML", ".php": "PHP", ".rs": "Rust", ".c": "C", ".cpp": "C++",
}
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

_VERBOSE = False
_START = time.monotonic()


def log(msg, force=False):
    if _VERBOSE or force:
        print(f"[{time.monotonic() - _START:7.1f}s] {msg}", file=sys.stderr)


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


def annotate_lines(text):
    """Prefix each added line with its new-file line number from the @@ headers.

    Returns (annotated_text, valid_added_lines, first_added_line). The model is
    asked to echo one of these numbers back; anything else is corrected.
    """
    out, valid = [], set()
    new_ln = None
    for line in text.splitlines(keepends=True):
        m = _HUNK_RE.match(line)
        if m:
            new_ln = int(m.group(1))
            out.append(line)
            continue
        if new_ln is None or line.startswith(("+++", "---", "\\")):
            out.append(line)
            continue
        if line.startswith("+"):
            out.append(f"+{new_ln:>5}| {line[1:]}")
            valid.add(new_ln)
            new_ln += 1
        elif line.startswith("-"):
            out.append(line)
        else:                                   # context line
            out.append(line)
            new_ln += 1
    first = min(valid) if valid else None
    return "".join(out), valid, first


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


def call_model(system, user, schema):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": schema,                       # structured output
        "options": {"temperature": 0, "seed": 7},
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.load(resp).get("message", {}).get("content", "")


def parse_findings(raw):
    """Return the findings list, or None when the reply is unparseable."""
    def load(s):
        obj = json.loads(s)
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            return obj.get("findings", [])
        return None
    try:
        return load(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return load(m.group(0))
            except Exception:
                return None
        return None


def scan_chunk(name, chunk, system, valid_lines, first_added):
    """Scan one chunk. At most 2 model calls (retry covers errors AND garbled
    replies). Returns (findings, errored)."""
    user = (
        f"File: {name}\nLanguage: {lang_of(name)}\n"
        f"---DIFF START---\n{chunk}\n---DIFF END---"
    )
    fs = None
    for attempt in (1, 2):
        try:
            raw = call_model(system, user, SCHEMA)
        except Exception as exc:
            log(f"{name}: model call failed (attempt {attempt}): {exc}", force=True)
            if attempt == 1:
                time.sleep(RETRY_BACKOFF)
            continue
        fs = parse_findings(raw)
        if fs is not None:
            break
        log(f"{name}: unparseable reply (attempt {attempt})", force=True)
        if attempt == 1:
            time.sleep(RETRY_BACKOFF)
    if fs is None:
        return [], True

    findings = []
    for f in fs:
        try:
            conf = int(f.get("confidence", 0))
        except Exception:
            conf = 0
        try:
            line = int(f.get("line"))
        except Exception:
            line = None
        if line not in valid_lines:             # hallucinated/missing line
            line = first_added
        findings.append({
            "type": str(f.get("type", "unknown")),
            "confidence": max(0, min(10, conf)),
            "file": name,
            "line": line,
            "rationale": str(f.get("rationale", ""))[:300],
        })
    return findings, False


def summarize(diff, prompt_file):
    """One model call describing what the PR does. Best-effort: any failure
    returns '' and never affects the verdict."""
    try:
        with open(prompt_file, encoding="utf-8") as fh:
            system = fh.read()
    except OSError as exc:
        log(f"summary prompt unavailable: {exc}", force=True)
        return ""
    text = sanitize(diff)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + "\n[diff truncated]"
    for attempt in (1, 2):
        try:
            raw = call_model(system, f"---DIFF START---\n{text}\n---DIFF END---",
                             SUMMARY_SCHEMA)
            obj = json.loads(raw)
            return str(obj.get("summary", "")).strip()
        except Exception as exc:
            log(f"summary call failed (attempt {attempt}): {exc}", force=True)
            if attempt == 1:
                time.sleep(RETRY_BACKOFF)
    return ""


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


def _esc_annotation(msg):
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_annotations(findings):
    """GitHub workflow commands -> inline PR annotations. Printed to stdout
    AFTER the JSON, and only inside Actions so local stdout stays pure JSON."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for f in findings:
        if f["confidence"] >= BLOCK:
            level = "error"
        elif f["confidence"] >= REVIEW:
            level = "warning"
        else:
            continue
        loc = f"file={f['file']}" + (f",line={f['line']}" if f.get("line") else "")
        msg = _esc_annotation(
            f"[{f['type']}] confidence {f['confidence']} — {f['rationale']}")
        print(f"::{level} {loc}::{msg}")


def main():
    global _VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", help="path to a diff file (hand testing)")
    ap.add_argument("--git-base", help="base ref for git diff (CI)")
    ap.add_argument("--verbose", action="store_true",
                    help="per-file timing and progress on stderr")
    args = ap.parse_args()
    _VERBOSE = args.verbose

    with open(PROMPT_FILE, encoding="utf-8") as fh:
        system = fh.read()

    diff = get_diff(args)
    if not diff.strip():
        print(json.dumps(
            {"verdict": "pass", "score": 0, "findings": [], "summary": ""}))
        print("No diff content to scan.", file=sys.stderr)
        return 0

    # Build the flat (file, chunk) task list up front so a single thread pool
    # covers everything and results can be re-ordered deterministically.
    tasks = []                                  # (file_idx, chunk_idx, name, chunk, valid, first)
    file_names = []
    for fi, (name, text) in enumerate(split_by_file(diff)):
        if not text.strip():
            continue
        annotated, valid, first = annotate_lines(sanitize(text))
        chunks = chunk_text(annotated, MAX_CHARS)
        file_names.append(name)
        for ci, chunk in enumerate(chunks):
            tasks.append((fi, ci, name, chunk, valid, first))

    log(f"model={MODEL} files={len(file_names)} chunks={len(tasks)} "
        f"workers={min(MAX_WORKERS, max(1, len(tasks)))}")

    results = {}                                # (file_idx, chunk_idx) -> (name, findings, errored, secs)
    workers = min(MAX_WORKERS, max(1, len(tasks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        def run(task):
            fi, ci, name, chunk, valid, first = task
            t0 = time.monotonic()
            fs, err = scan_chunk(name, chunk, system, valid, first)
            return (fi, ci), (name, fs, err, time.monotonic() - t0)
        for key, val in ex.map(run, tasks):
            results[key] = val

    all_findings, errored = [], False
    per_file = {}                               # name -> [chunks, findings, secs]
    for key in sorted(results):
        name, fs, err, secs = results[key]
        all_findings.extend(fs)
        errored = errored or err
        stat = per_file.setdefault(name, [0, 0, 0.0])
        stat[0] += 1
        stat[1] += len(fs)
        stat[2] += secs
    for name, (nchunks, nfind, secs) in per_file.items():
        log(f"file {name}: {nchunks} chunk(s), {nfind} finding(s), {secs:.1f}s model time")

    summary_text = summarize(diff, SUMMARY_PROMPT_FILE)

    all_findings = dedupe(all_findings)
    score, verdict = aggregate(all_findings, errored)
    print(json.dumps({"verdict": verdict, "score": score,
                      "findings": all_findings, "summary": summary_text}, indent=2))
    emit_annotations(all_findings)
    log(f"done: verdict={verdict} score={score} total={time.monotonic() - _START:.1f}s")

    lines = [f"### Intent gate: {verdict.upper()} (score {score})", ""]
    if summary_text:
        lines += [f"**What this PR does:** {summary_text}", ""]
    for f in all_findings:
        loc = f"{f['file']}" + (f":{f['line']}" if f.get("line") else "")
        lines.append(f"- `{loc}` — {f['type']} (conf {f['confidence']}): {f['rationale']}")
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
