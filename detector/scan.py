#!/usr/bin/env python3
"""
Malicious-intent PR gate — detector (Python standard library only).

Reads a diff, sends the changed hunks (only) to a LOCAL Ollama model in ONE
call, and gets back a structured security review: key changes, suspicious
findings, security reasoning, and — generated LAST, conditioned on that
reasoning — a 0-100 risk score. The result is rendered as a markdown comment
(comment.md) for a sticky PR comment, printed as JSON on stdout, and the risk
score is gated so CI can fail the check on 'block'.

Design notes for small local models:
  - Structured output: passes a JSON *schema* to Ollama's `format` option so
    the reply is constrained to the exact shape (far more reliable than
    "give me JSON").
  - Hunks only: file headers and @@ hunks are kept; index/mode/binary noise is
    stripped so the context budget is spent on actual changes.
  - Timeout + retries with exponential backoff before failing safe, so a blip
    doesn't open the gate.
  - Untrusted-diff wrapping: the diff is wrapped in <untrusted_diff> tags and a
    regex tripwire floors the score if injection markers appear (see INJECTION).
  - Differentiated fail-safe: an infra failure (Ollama down/timeout) fails open
    to 'review'; a content failure (reply won't parse) is distrusted as possible
    evasion. Both are floored at least to 'review', shown loudly in the comment,
    and — on a protected branch (FAIL_CLOSED) — escalated to 'block'.

Usage:
  python3 detector/scan.py --diff samples/malicious/exfil.diff   # hand test
  python3 detector/scan.py --git-base origin/main                # CI: diff vs base
  python3 detector/scan.py --diff x.diff --verbose               # timing on stderr

Large diffs (big pushes, repo init) are split on file boundaries into chunks
that each fit the per-call budget, scanned in priority order (high-risk files
first) up to MAX_CHUNKS calls, and aggregated into ONE verdict — replacing the
old truncate-and-floor behaviour.

Env (defaults shown):
  OLLAMA_URL http://localhost:11434 | MODEL qwen2.5-coder:3b
  PROMPT_FILE prompts/intent.md | COMMENT_FILE comment.md
  BLOCK_THRESHOLD 70 | REVIEW_THRESHOLD 40 | MAX_CHARS 16000 | NUM_CTX 4096
  NUM_PREDICT 512 | FAIL_SAFE review | REQUEST_TIMEOUT 600 | RETRY_BACKOFF 2
  RETRIES 3 | INJECTION_FLOOR 55 | FAIL_CLOSED false
  MAX_CHARS is the PER-CHUNK budget | MAX_CHUNKS 8 | REDUCE concat
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("MODEL", "qwen2.5-coder:3b")
PROMPT_FILE = os.environ.get("PROMPT_FILE", "prompts/intent.md")
COMMENT_FILE = os.environ.get("COMMENT_FILE", "comment.md")
BLOCK = int(os.environ.get("BLOCK_THRESHOLD", "70"))
REVIEW = int(os.environ.get("REVIEW_THRESHOLD", "40"))
# PER-CHUNK character budget: the most diff chars sent to the model in ONE call.
# A large diff is split on file boundaries and packed into chunks under this
# budget (see pack()), so this must be sized by the SAME fit math the single
# call always relied on: NUM_CTX budget - system prompt - NUM_PREDICT output
# headroom. NB: the 16000 default (~4000 tok) plus the ~1.5k-tok system prompt
# and 512 output tokens (~6k tok) OVERFLOWS the default NUM_CTX=4096 — Ollama
# would silently clip it. Raise NUM_CTX (and the action's warm-up num_ctx to
# match) for the full budget; the default is kept for backward compatibility.
MAX_CHARS = int(os.environ.get("MAX_CHARS", "16000"))
# Hard cap on model calls per scan: bounds total wall-clock (each chunk is one
# bounded warm call under REQUEST_TIMEOUT). Files that don't fit within this many
# chunks are left unscanned and floor the verdict to review.
MAX_CHUNKS = max(1, int(os.environ.get("MAX_CHUNKS", "8")))
# Reduce strategy for combining chunk results: "concat" = deterministic merge
# (default); "llm" = one extra, presentation-only model call that rewrites the
# reasoning narrative (never the score/findings/verdict).
REDUCE = os.environ.get("REDUCE", "concat").lower()
# Ollama's context window. Its default (2048 tokens) is smaller than MAX_CHARS,
# so without this the prompt is SILENTLY truncated by Ollama before the model
# sees it. Sized to hold the system prompt + a per-chunk diff + output headroom.
# Bigger = more RAM/slower on the runner; the action warms the model with this
# SAME value so the timed scan call reuses the loaded model.
NUM_CTX = int(os.environ.get("NUM_CTX", "4096"))
# Hard ceiling on generated tokens. Without it, under constrained JSON decoding
# a small model can run away generating until it hits the context limit, blowing
# past REQUEST_TIMEOUT. This is the primary guard against inference timeouts.
NUM_PREDICT = int(os.environ.get("NUM_PREDICT", "512"))
FAIL_SAFE = os.environ.get("FAIL_SAFE", "review")   # verdict floor on infra error
# Per-request read timeout. Sized for a warm model; the action warms the model
# in its setup step so this budget isn't spent on the first-call cold start.
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "180"))
RETRY_BACKOFF = float(os.environ.get("RETRY_BACKOFF", "2"))
RETRIES = max(1, int(os.environ.get("RETRIES", "3")))
# Fail-closed policy: on a protected/release branch, treat scan errors as a
# block instead of failing open to review. The calling workflow sets this true
# for protected branches; default false keeps dev branches fail-open.
FAIL_CLOSED = os.environ.get("FAIL_CLOSED", "false").lower() in ("1", "true", "yes")
# Score floor applied when prompt-injection markers are found in the diff.
# Sits in the 'review' band so a human always looks, without hard-blocking.
INJECTION_FLOOR = int(os.environ.get("INJECTION_FLOOR", "55"))

MARKER = "<!-- intent-gate-comment -->"

# Prompt-injection tripwire: text in a diff that tries to talk the model into
# under-scoring itself. A regex catch is independent of the model, so it holds
# even when the model is successfully manipulated. Detection floors the score
# (see INJECTION_FLOOR); it never lets an injected diff pass as clean.
INJECTION = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+instructions"
    r"|you\s+are\s+now|disregard\s+the\s+above"
    r"|risk[_\s]?score\s*(=|:|to)\s*0"
    r"|pre-?approved|reviewer[-\s]?bot|system\s*:)",
    re.IGNORECASE,
)

# File-aware chunking priorities: when a diff is too big to scan in one budget,
# these decide which files the model sees FIRST (and which get dropped last).
# High-risk PATHS — CI/CD, container, package-manifest, and shell files are the
# usual vectors for exfiltration / release tampering, so they scan first.
HIGH_RISK_PATH = re.compile(
    r"(\.github/workflows/"
    r"|(^|/)Dockerfile"
    r"|\.sh$"
    r"|(^|/)package\.json$"
    r"|(^|/)requirements\.txt$"
    r"|(^|/)go\.mod$"
    r"|\.ya?ml$)",
    re.IGNORECASE,
)
# Signal KEYWORDS in a file's diff — code that evaluates, spawns, decodes, or
# reaches the network / handles secrets. Each distinct hit nudges priority up.
SIGNAL_KEYWORDS = re.compile(
    r"(eval|exec|base64|subprocess|os\.system|urllib|requests"
    r"|socket|token|secret|password|curl)",
    re.IGNORECASE,
)

# System prompt for the optional REDUCE="llm" pass. PRESENTATION-ONLY: it merges
# the per-chunk narratives into one, and must not invent findings or change the
# score — the score/findings/verdict are fixed by the deterministic aggregation.
REDUCE_SYSTEM = (
    "You are a security-review editor. You are given the suspicious findings and "
    "the per-chunk reasoning notes from a diff that was scanned in several parts. "
    "Merge them into ONE coherent 'why this score' narrative. Do NOT add new "
    "findings, do NOT compute or mention a score, and do NOT contradict the "
    "findings — only summarise the reasoning you are given. Return STRICT JSON: "
    '{"reasoning": "<merged narrative>"}'
)

# Small schema for the reduce pass — just the rewritten reasoning string.
REDUCE_SCHEMA = {
    "type": "object",
    "properties": {"reasoning": {"type": "string"}},
    "required": ["reasoning"],
}

# JSON schema handed to Ollama's structured-output "format" — constrains the
# model to emit exactly this shape. Ollama emits properties in declaration
# order under grammar-constrained decoding, so risk_score is placed LAST: the
# score is generated after (and conditioned on) the reasoning tokens.
SCHEMA = {
    "type": "object",
    "properties": {
        "key_changes": {"type": "array", "items": {"type": "string"}},
        "suspicious_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["file", "reason"],
            },
        },
        "reasoning": {"type": "string"},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
    },
    "required": ["key_changes", "suspicious_findings", "reasoning",
                 "risk_score"],
}

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

_VERBOSE = False
_START = time.monotonic()

# Verdict ordering, so fail-safe policy can only ever escalate severity.
_RANK = {"pass": 0, "review": 1, "block": 2}


class InfraError(Exception):
    """Transport/availability failure talking to Ollama (down, timeout, HTTP,
    bad envelope). Genuinely transient — fail open to review."""


class ContentError(Exception):
    """Ollama replied but the content could not be parsed into the schema. A
    diff that reliably breaks the parser looks like evasion — distrust it."""


def escalate(verdict, floor):
    """Return whichever of the two verdicts is more severe."""
    return verdict if _RANK[verdict] >= _RANK[floor] else floor


def apply_injection_floor(result, floor):
    """Raise a below-floor score to the injection floor and explain the bump in
    the reasoning, so the rendered score and the model's prose can't contradict
    each other ("benign, score 0" next to a shown 55).

    Only ever raises: if the model independently scored at/above the floor, the
    result is left untouched. The note is a labelled system annotation, not the
    model's words — the model's own assessment is preserved ahead of it.
    """
    if result["risk_score"] < floor:
        note = (f"Automated tripwire: prompt-injection marker(s) were detected "
                f"in the diff, so the score was raised to the {floor} review "
                f"floor for human inspection — above the model's own assessment "
                f"of {result['risk_score']}.")
        result["reasoning"] = (f"{result['reasoning']}\n\n{note}"
                               if result["reasoning"] else note)
        result["risk_score"] = floor
    return result


def log(msg, force=False):
    if _VERBOSE or force:
        print(f"[{time.monotonic() - _START:7.1f}s] {msg}", file=sys.stderr)


def sanitize(text):
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def get_diff(args):
    if args.diff:
        with open(args.diff, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    base = args.git_base or "origin/main"
    return subprocess.run(
        ["git", "diff", "--unified=3", f"{base}...HEAD"],
        capture_output=True, text=True,
    ).stdout


def extract_hunks(diff):
    """Keep only what the model needs: file headers and @@ hunks.

    Drops index/mode/similarity/binary metadata lines so the context budget
    is spent on the actual changed hunks, not git noise.
    """
    out = []
    in_hunk = False
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git"):
            in_hunk = False
            out.append(line)
        elif line.startswith(("--- ", "+++ ")):
            out.append(line)
        elif line.startswith("@@"):
            in_hunk = True
            out.append(line)
        elif in_hunk and line[:1] in ("+", "-", " ", "\\"):
            out.append(line)
        # anything else (index, mode, similarity, Binary files ...) is dropped
    return "".join(out)


_DIFF_GIT = re.compile(r'^diff --git a/(.*?) b/(.*?)\s*$', re.MULTILINE)


def split_by_file(hunks):
    """Split cleaned hunks into per-file diffs on `diff --git` boundaries.

    Returns a list of (path, file_diff), one entry per file, with each file's
    hunks kept WHOLE (a file's diff is never split across entries). `path` is
    taken from the `b/` side of the `diff --git a/… b/…` header, falling back to
    the `a/` side or "unknown". Any text before the first `diff --git` header
    (shouldn't occur after extract_hunks) is ignored.
    """
    files = []
    matches = list(_DIFF_GIT.finditer(hunks))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(hunks)
        path = m.group(2) or m.group(1) or "unknown"
        files.append((path, hunks[start:end]))
    return files


def priority(path, file_diff):
    """Higher = scan first. High-risk paths and signal-keyword hits raise it, so
    the files most likely to carry an attack are the last to be dropped when a
    diff exceeds the chunk budget."""
    score = 0
    if HIGH_RISK_PATH.search(path):
        score += 100
    # Count DISTINCT signal keywords present, so one file mentioning many
    # different risky APIs ranks above one repeating a single keyword.
    score += 10 * len({m.group(0).lower() for m in SIGNAL_KEYWORDS.finditer(file_diff)})
    return score


def pack(files, budget, max_chunks):
    """Greedy-pack whole files into at most `max_chunks` chunks under `budget`
    chars each, scanning the highest-priority files first.

    Returns (chunks, overflow_files, truncated_files):
      - chunks: list of (chunk_text, [paths]) to send to the model.
      - truncated_files: paths of single files larger than `budget`; each gets
        its own chunk truncated to `budget` with a "[file truncated]" marker.
      - overflow_files: paths that could not be placed once max_chunks chunks
        exist (left UNSCANNED — the caller floors the verdict to review).
    """
    ranked = sorted(files, key=lambda f: priority(f[0], f[1]), reverse=True)
    chunks = []                                 # list of [text, [paths]]
    overflow_files = []
    truncated_files = []
    for path, fdiff in ranked:
        if len(fdiff) > budget:                 # oversize single file -> own chunk
            if len(chunks) < max_chunks:
                chunks.append([fdiff[:budget] + "\n[file truncated]", [path]])
                truncated_files.append(path)
            else:
                overflow_files.append(path)
            continue
        placed = False
        for chunk in chunks:                    # first-fit into an existing chunk
            if len(chunk[0]) + len(fdiff) <= budget:
                chunk[0] += fdiff
                chunk[1].append(path)
                placed = True
                break
        if not placed:
            if len(chunks) < max_chunks:
                chunks.append([fdiff, [path]])
            else:
                overflow_files.append(path)
    return [(text, paths) for text, paths in chunks], overflow_files, truncated_files


def call_model(system, user, schema):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": schema,                       # structured output
        "keep_alive": -1,                       # keep model resident between calls
        "options": {"temperature": 0, "seed": 7, "num_ctx": NUM_CTX,
                    "num_predict": NUM_PREDICT},
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            envelope = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # connection refused / timeout / HTTP error / non-JSON envelope — all
        # transport/availability problems, not model-content problems.
        raise InfraError(str(exc)) from exc
    return envelope.get("message", {}).get("content", "")


def coerce_result(raw):
    """Parse the model reply into the expected shape, or None if hopeless."""
    try:
        obj = json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except Exception:
            return None
    if not isinstance(obj, dict):
        return None
    try:
        score = int(obj.get("risk_score", 0))
    except Exception:
        score = 0
    findings = []
    for f in obj.get("suspicious_findings") or []:
        if isinstance(f, dict):
            findings.append({"file": str(f.get("file", "unknown")),
                             "reason": str(f.get("reason", ""))[:400]})
    return {
        "risk_score": max(0, min(100, score)),
        "key_changes": [str(c) for c in (obj.get("key_changes") or [])],
        "suspicious_findings": findings,
        "reasoning": str(obj.get("reasoning", "")).strip(),
    }


def review_chunk(hunks, system):
    """One model call over a single chunk of the diff, wrapped as untrusted data.
    Retries
    transient failures with exponential backoff before giving up. Returns the
    parsed result, or raises InfraError / ContentError so the caller can apply
    the right fail-safe policy for each failure kind.

    A blip should not open the gate, and retrying shrinks the DoS surface: a
    single dropped request can't flip a scan to fail-safe on its own.
    """
    user = f"<untrusted_diff>\n{hunks}\n</untrusted_diff>"
    last = None                                 # (kind, exception) of the final attempt
    for attempt in range(RETRIES):
        try:
            raw = call_model(system, user, SCHEMA)
        except InfraError as exc:
            last = ("infra", exc)
            log(f"model call failed (attempt {attempt + 1}/{RETRIES}): {exc}",
                force=True)
        else:
            result = coerce_result(raw)
            if result is not None:
                return result
            last = ("content", ContentError("unparseable model reply"))
            log(f"unparseable reply (attempt {attempt + 1}/{RETRIES})", force=True)
        if attempt + 1 < RETRIES:
            time.sleep(RETRY_BACKOFF * (2 ** attempt))
    kind, exc = last
    raise exc if kind == "content" else InfraError(str(exc))


def aggregate_results(outcomes, files_scanned, num_chunks):
    """Combine the successful per-chunk results into ONE result (deterministic
    "concat" reduce). Returns (result, notable_reasonings):

      - risk_score: max over successful chunks (0 if none succeeded) — the score
        reflects the WORST chunk, never an average.
      - suspicious_findings: union, deduped on (file, reason.strip().lower()).
      - key_changes: union, deduped on the stripped string.
      - reasoning: only the reasoning from chunks that produced a finding OR
        scored >= REVIEW, each prefixed with that chunk's files; if none are
        notable, a single "No notable findings…" line.

    notable_reasonings (the same prefixed strings) is returned for the optional
    LLM reduce pass. A failed chunk contributes nothing here; the caller applies
    the cross-chunk fail-safe separately.
    """
    successful = [o for o in outcomes if o["status"] == "ok"]
    risk_score = max((o["result"]["risk_score"] for o in successful), default=0)

    findings, seen_f = [], set()
    for o in successful:
        for f in o["result"]["suspicious_findings"]:
            key = (f["file"], f["reason"].strip().lower())
            if key not in seen_f:
                seen_f.add(key)
                findings.append(f)

    key_changes, seen_k = [], set()
    for o in successful:
        for c in o["result"]["key_changes"]:
            k = c.strip()
            if k and k not in seen_k:
                seen_k.add(k)
                key_changes.append(c)

    notable = []
    for o in successful:
        r = o["result"]
        if (r["suspicious_findings"] or r["risk_score"] >= REVIEW) and r["reasoning"]:
            notable.append(f"[{', '.join(o['paths'])}] {r['reasoning']}")
    reasoning = ("\n\n".join(notable) if notable
                 else f"No notable findings across {files_scanned} files "
                      f"/ {num_chunks} chunks.")

    result = {
        "risk_score": risk_score,
        "key_changes": key_changes,
        "suspicious_findings": findings,
        "reasoning": reasoning,
    }
    return result, notable


def reduce_llm(result, notable_reasonings):
    """Optional REDUCE="llm" pass: one extra, PRESENTATION-ONLY model call that
    rewrites the merged reasoning into a single coherent narrative.

    Returns the new reasoning string, or None on any failure (InfraError /
    ContentError / unparseable) so the caller silently keeps the deterministic
    "concat" reasoning. It NEVER touches risk_score, findings, or the verdict —
    only the reasoning prose — and never raises.
    """
    findings_txt = "\n".join(
        f"- {f['file']}: {f['reason']}" for f in result["suspicious_findings"]
    ) or "(none)"
    notes_txt = "\n\n".join(notable_reasonings) or "(none)"
    user = (f"Suspicious findings:\n{findings_txt}\n\n"
            f"Per-chunk reasoning notes:\n{notes_txt}")
    try:
        raw = call_model(REDUCE_SYSTEM, user, REDUCE_SCHEMA)
    except InfraError:
        return None
    try:
        obj = json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except Exception:
            return None
    if not isinstance(obj, dict):
        return None
    return str(obj.get("reasoning", "")).strip() or None


def verdict_of(score):
    return "block" if score >= BLOCK else "review" if score >= REVIEW else "pass"


def risk_band(score):
    if score >= BLOCK:
        return "🔴 high risk"
    if score >= REVIEW:
        return "🟡 medium risk"
    return "🟢 low risk"


def render_markdown(result, verdict, failsafe=None, injection=False, coverage=None):
    icon = {"pass": "✅", "review": "⚠️", "block": "⛔"}.get(verdict, "❓")
    lines = [
        MARKER,
        f"## {icon} Intent Gate — {verdict.upper()}",
        "",
    ]
    if failsafe:
        # A fail-safe must never be mistaken for a clean pass — lead with it.
        if failsafe == "infra":
            lines += [
                "> ⚠️ **Scan incomplete (service error) — manual review "
                "required.** The model could not be reached after retries, so "
                "this diff was **not** actually scanned. This is NOT a clean "
                f"pass; the verdict was set to `{verdict}`.",
                "",
            ]
        else:                                   # content
            lines += [
                "> 🛑 **Scan could not parse the model's response — treated as "
                "suspicious.** A diff whose reply cannot be parsed is unusual "
                "and may be an evasion attempt. Manual review required; the "
                f"verdict was set to `{verdict}`.",
                "",
            ]
    if injection:
        lines += [
            "> 🛡️ **Prompt-injection markers detected in the diff.** The diff "
            "contains text that tries to manipulate the reviewing model, so the "
            f"score was floored to at least {INJECTION_FLOOR}. Inspect the diff "
            "for instructions aimed at the reviewer.",
            "",
        ]
    if coverage:
        overflow = coverage.get("overflow") or []
        truncated = coverage.get("truncated") or []
        lines += [
            f"_Scanned {coverage['files_scanned']} files across "
            f"{coverage['num_chunks']} chunks._",
            "",
        ]
        if overflow or truncated:
            lines += [
                "> ⚠️ **Not fully scanned — verdict floored to at least "
                "`review`.** The diff was too large to send to the model in "
                "full, so some files were not completely reviewed:",
                "",
            ]
            if overflow:
                lines.append("> - **Unscanned (over budget):** "
                             + ", ".join(f"`{p}`" for p in overflow))
            if truncated:
                lines.append("> - **Truncated (file larger than one chunk):** "
                             + ", ".join(f"`{p}`" for p in truncated))
            lines.append("")
    lines += [
        "### Risk Score",
        f"**{result['risk_score']} / 100** — {risk_band(result['risk_score'])}",
        "",
        "### Key Changes",
    ]
    if result["key_changes"]:
        lines += [f"- {c}" for c in result["key_changes"]]
    else:
        lines.append("None identified.")
    lines += ["", "### Suspicious Findings"]
    if result["suspicious_findings"]:
        lines += ["| File | Reason |", "|---|---|"]
        for f in result["suspicious_findings"]:
            reason = f["reason"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{f['file']}` | {reason} |")
    else:
        lines.append("None. ✅")
    if result["reasoning"]:
        lines += ["", "### Why this score", "", result["reasoning"]]
    return "\n".join(lines) + "\n"


def main():
    global _VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", help="path to a diff file (hand testing)")
    ap.add_argument("--git-base", help="base ref for git diff (CI)")
    ap.add_argument("--verbose", action="store_true",
                    help="timing and progress on stderr")
    args = ap.parse_args()
    _VERBOSE = args.verbose

    with open(PROMPT_FILE, encoding="utf-8") as fh:
        system = fh.read()

    diff = get_diff(args)
    hunks = extract_hunks(sanitize(diff))
    if not hunks.strip():
        print(json.dumps({"verdict": "pass", "score": 0,
                          "key_changes": [], "suspicious_findings": [],
                          "reasoning": ""}))
        print("No diff content to scan.", file=sys.stderr)
        return 0

    injection = bool(INJECTION.search(hunks))   # check full diff, pre-truncation
    if injection:
        log("prompt-injection markers found in diff; score will be floored",
            force=True)

    # File-aware chunking: split on file boundaries, greedy-pack whole files into
    # per-call budgets (high-risk files first), and scan each chunk on its own —
    # replacing the old truncate-and-floor of the tail.
    files = split_by_file(hunks)
    if not files:                               # defensive: hunks with no file header
        files = [("unknown", hunks)]
    chunks, overflow_files, truncated_files = pack(files, MAX_CHARS, MAX_CHUNKS)
    files_scanned = sum(len(paths) for _text, paths in chunks)
    num_chunks = len(chunks)
    log(f"model={MODEL} files={len(files)} chunks={num_chunks} "
        f"scanned={files_scanned} overflow={len(overflow_files)} "
        f"truncated={len(truncated_files)}")

    outcomes = []                               # per-chunk: status/result/paths
    for i, (text, paths) in enumerate(chunks):
        log(f"chunk {i + 1}/{num_chunks} files={len(paths)} chars={len(text)}")
        try:
            res = review_chunk(text, system)
        except InfraError as exc:
            outcomes.append({"status": "infra", "result": None, "paths": paths})
            # Loud, machine-parseable line so the workflow can route to Slack/alerts.
            log(f"FAILSAFE kind=infra chunk={i + 1} fail_closed={FAIL_CLOSED} "
                f"detail={exc}", force=True)
        except ContentError as exc:
            outcomes.append({"status": "content", "result": None, "paths": paths})
            log(f"FAILSAFE kind=content chunk={i + 1} fail_closed={FAIL_CLOSED} "
                f"detail={exc}", force=True)
        else:
            outcomes.append({"status": "ok", "result": res, "paths": paths})

    # Reduce: one successful chunk is used verbatim (its result IS the final
    # result); otherwise merge deterministically, optionally rewriting the
    # reasoning prose via the presentation-only LLM pass.
    successful = [o for o in outcomes if o["status"] == "ok"]
    if num_chunks == 1 and len(successful) == 1:
        result = successful[0]["result"]
    else:
        result, notable = aggregate_results(outcomes, files_scanned, num_chunks)
        if REDUCE == "llm" and notable:
            merged = reduce_llm(result, notable)
            if merged:                          # None -> silently keep concat prose
                result["reasoning"] = merged

    # Cross-chunk fail-safe (infra beats content). Successfully-scanned chunks
    # still contribute findings and can raise the score even when one failed.
    failsafe = None                             # None | "infra" | "content"
    if any(o["status"] == "infra" for o in outcomes):
        failsafe = "infra"
    elif any(o["status"] == "content" for o in outcomes):
        failsafe = "content"

    if injection:                               # floor regardless of the model's score
        apply_injection_floor(result, INJECTION_FLOOR)

    verdict = verdict_of(result["risk_score"])
    # Fail-safe policy, differentiated by error type. escalate() can only raise
    # severity, never lower a real finding.
    if failsafe == "infra":                     # transient outage -> fail open to review
        verdict = escalate(verdict, "block" if FAIL_CLOSED else FAIL_SAFE)
    elif failsafe == "content":                 # parser broke on the diff -> distrust it
        verdict = escalate(verdict, "block" if FAIL_CLOSED else "review")
    if overflow_files or truncated_files:       # partially scanned -> never a clean pass
        verdict = escalate(verdict, "review")

    coverage = {"files_scanned": files_scanned, "num_chunks": num_chunks,
                "overflow": overflow_files, "truncated": truncated_files}

    print(json.dumps({"verdict": verdict, "score": result["risk_score"],
                      "truncated": bool(truncated_files or overflow_files),
                      "injection": injection, "failsafe": failsafe,
                      "num_chunks": num_chunks, "files_scanned": files_scanned,
                      "files_unscanned": overflow_files,
                      "files_truncated": truncated_files,
                      "key_changes": result["key_changes"],
                      "suspicious_findings": result["suspicious_findings"],
                      "reasoning": result["reasoning"]}, indent=2))

    comment = render_markdown(result, verdict, failsafe, injection, coverage)
    with open(COMMENT_FILE, "w", encoding="utf-8") as fh:
        fh.write(comment)
    log(f"wrote {COMMENT_FILE}")

    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a", encoding="utf-8") as fh:
            fh.write(comment + "\n")

    log(f"done: verdict={verdict} score={result['risk_score']} "
        f"total={time.monotonic() - _START:.1f}s")
    return 1 if verdict == "block" else 0


if __name__ == "__main__":
    sys.exit(main())
