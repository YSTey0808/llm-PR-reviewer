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
  NUM_PREDICT 768 | FAIL_SAFE review | REQUEST_TIMEOUT 600 | RETRY_BACKOFF 2
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

import filters                                   # local: four-state classification

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
# and 768 output tokens (~6k tok) OVERFLOWS the default NUM_CTX=4096 — Ollama
# would silently clip it. Raise NUM_CTX (and the action's warm-up num_ctx to
# match) for the full budget; the default is kept for backward compatibility.
MAX_CHARS = int(os.environ.get("MAX_CHARS", "16000"))
# Hard cap on model calls per scan: bounds total wall-clock (each chunk is one
# bounded warm call under REQUEST_TIMEOUT). Files that don't fit within this many
# chunks are left unscanned and floor the verdict to review.
MAX_CHUNKS = max(1, int(os.environ.get("MAX_CHUNKS", "8")))
# Wall-clock budget for model calls, enforced ALONGSIDE MAX_CHUNKS (whichever
# hits first). A warm 3B does ~5-15s/chunk, so a fixed MAX_CHUNKS=8 leaves
# throughput on the table on a fast runner; conversely a slow/cold model must
# not blow the CI job's own timeout. Chunks not reached before the budget are
# left UNSCANNED and floor the verdict to review — same as budget overflow.
MAX_SECONDS = float(os.environ.get("MAX_SECONDS", "300"))
# Above this raw-diff size, re-run `git diff` with --unified=1 instead of =3:
# context lines are roughly half the bytes of a big diff, so trimming them keeps
# more actual CHANGES inside the per-chunk budget. Only affects the --git-base
# path; a hand-supplied --diff file is used as-is.
LARGE_DIFF_CHARS = int(os.environ.get("LARGE_DIFF_CHARS", "200000"))
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
NUM_PREDICT = int(os.environ.get("NUM_PREDICT", "768"))
# Verdict floor on infra error. Clamp to a real verdict: "pass" would silently
# disable the fail-safe, and any unrecognised value would KeyError in escalate().
_FAIL_SAFE_RAW = os.environ.get("FAIL_SAFE", "review").strip().lower()
FAIL_SAFE = _FAIL_SAFE_RAW if _FAIL_SAFE_RAW in ("review", "block") else "review"
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
# Corroborate a would-be block with a second independent review before it can
# block a PR. max() over up to MAX_CHUNKS chunks compounds each chunk's FP into a
# large PR-level FP; a lone chunk that scores >= BLOCK gets one more look on the
# same text. Only fires on would-be blocks, so it's ~free on normal PRs.
CORROBORATE = os.environ.get("CORROBORATE", "true").lower() in ("1", "true", "yes")

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

# Paths where injection MARKERS are legitimate content, not an attack: this repo
# dogfoods itself, so the very strings INJECTION greps for live in the detector,
# its prompts, and its own test fixtures/samples. Editing any of them must not
# trip the tripwire. Injection is checked per file, skipping these paths, so
# security tooling is allowed to contain the strings it detects.
INJECTION_EXEMPT = re.compile(
    r"(^|/)(samples|tests|fixtures|testdata|prompts)/"
    r"|(^|/)detector/scan\.py$",
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
        # Bounded: key_changes is emitted FIRST, so an unbounded list on a
        # multi-file chunk burns the whole NUM_PREDICT budget enumerating
        # changes, the JSON truncates mid-object, coerce_result can't parse it,
        # and a benign refactor gets the "possible evasion" content-fail banner.
        # Grammar-constrained decoding enforces these caps for free.
        "key_changes": {
            "type": "array", "maxItems": 5,
            "items": {"type": "string", "maxLength": 120},
        },
        "suspicious_findings": {
            "type": "array", "maxItems": 8,
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["file", "reason"],
            },
        },
        "reasoning": {"type": "string", "maxLength": 1200},
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

    def _git_diff(context):
        return subprocess.run(
            ["git", "diff", f"--unified={context}", f"{base}...HEAD"],
            capture_output=True, text=True,
        )

    proc = _git_diff(3)
    # A non-zero git exit must NOT masquerade as an empty (clean) diff: without
    # this check a failed `git diff` yields "" -> no hunks -> a silent pass. The
    # usual cause in CI is a shallow checkout (actions/checkout defaults to
    # fetch-depth: 1), so `{base}...HEAD` has no merge-base to diff against.
    # Raise InfraError so main() routes it to the infra fail-safe, never exit 0.
    if proc.returncode != 0:
        raise InfraError(
            f"`git diff {base}...HEAD` failed (exit {proc.returncode}): "
            f"{proc.stderr.strip() or '(no stderr)'} — the base ref may be "
            f"missing history; in CI set actions/checkout `fetch-depth: 0` so "
            f"the merge-base with {base} exists."
        )
    # Big diff: re-diff with less context so more actual changes fit the budget.
    if len(proc.stdout) > LARGE_DIFF_CHARS:
        tight = _git_diff(1)
        if tight.returncode == 0 and tight.stdout:
            log(f"raw diff {len(proc.stdout)} chars > {LARGE_DIFF_CHARS}; "
                f"re-diffing with --unified=1 ({len(tight.stdout)} chars)")
            return tight.stdout
    return proc.stdout


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


def detect_injection(files):
    """True if any NON-exempt file's diff contains a prompt-injection marker.

    Checked PER FILE (over split_by_file output) rather than over the whole hunks
    blob, so a marker in an exempt path — the detector, its prompts, its own test
    fixtures/samples — can't trip the tripwire on a legitimate maintenance PR.
    Non-exempt files are still checked in full, so a real injected diff still
    floors as before.
    """
    for path, file_diff in files:
        if INJECTION_EXEMPT.search(path):
            continue
        if INJECTION.search(file_diff):
            return True
    return False


def metadata_findings(raw_diff):
    """Scan the RAW diff (BEFORE extract_hunks strips them) for risk-bearing
    changes that carry no textual hunk: new executables, files made executable,
    and binary blobs.

    extract_hunks throws `new/old mode`, `Binary files … differ`, and
    `GIT binary patch` lines away, so on their own these produce zero hunks and
    fail OPEN — a chmod +x on a CI script or a committed binary would reach the
    model as an empty diff and pass. Running here, on the raw diff, makes them
    visible regardless of what the model sees.

    Returns (findings, binary_paths):
      - findings: [{"file", "reason"}] to merge into the result unconditionally.
      - binary_paths: files whose bytes are binary and were NOT sent to the model
        (surfaced in coverage so the comment never implies they were reviewed).
    """
    findings = []
    binary_paths = []
    path = "unknown"
    for line in raw_diff.splitlines():
        m = _DIFF_GIT.match(line)
        if m:
            path = m.group(2) or m.group(1) or "unknown"
            continue
        if line.startswith("new file mode ") and line.rstrip().endswith("755"):
            findings.append({
                "file": path,
                "reason": "New file added with executable permissions (mode "
                          "100755); flag a new executable committed to the repo.",
            })
        elif line.startswith("new mode ") and line.rstrip().endswith("755"):
            findings.append({
                "file": path,
                "reason": "File mode changed to executable (100755) with no "
                          "content change shown in the diff (chmod +x).",
            })
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            if path not in binary_paths:
                binary_paths.append(path)
            findings.append({
                "file": path,
                "reason": "Binary content changed; the bytes cannot be reviewed "
                          "as a text diff and were not sent to the model.",
            })
    return findings, binary_paths


def priority(path, file_diff):
    """Higher = scan first. High-risk paths and signal-keyword hits raise it, so
    the files most likely to carry an attack are the last to be dropped when a
    diff exceeds the chunk budget."""
    score = 0
    if HIGH_RISK_PATH.search(path):
        score += 100
    # Count DISTINCT signal keywords present, so one file mentioning many
    # different risky APIs ranks above one repeating a single keyword. Scan only
    # ADDED content lines ('+', not the '+++' header), matching the prompt's own
    # rule: a file that REMOVES eval/subprocess/etc. must not be promoted.
    added = "\n".join(l for l in file_diff.splitlines()
                      if l.startswith("+") and not l.startswith("+++"))
    score += 10 * len({m.group(0).lower() for m in SIGNAL_KEYWORDS.finditer(added)})
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
    # A missing or non-numeric risk_score is NOT a benign 0 — it means the model
    # never produced the one field the gate turns on. Defaulting it to 0 rewards
    # a broken/evasive reply with a pass; instead return None so review_chunk
    # raises ContentError and the reply is distrusted (fail-safe to review).
    if "risk_score" not in obj:
        return None
    try:
        score = int(obj["risk_score"])
    except (TypeError, ValueError):
        return None
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


def corroborate(result, hunks, system):
    """Second, independent look at a chunk that scored >= BLOCK before it is
    allowed to block a PR.

    One chunk's per-chunk FP compounds across max() over up to MAX_CHUNKS chunks
    into a large PR-level FP, so a lone would-be block is re-reviewed on the SAME
    text. If the second call also lands >= BLOCK the block stands; if it lands
    below BLOCK the chunk is demoted into the review band — max(REVIEW, second),
    NEVER to pass. A failed second call (infra/content) KEEPS the block: a failure
    must never rescue a chunk toward pass.
    """
    try:
        second = review_chunk(hunks, system)
    except (InfraError, ContentError):
        return result                           # failure must not rescue a block
    if second["risk_score"] >= BLOCK:
        return result                           # block corroborated
    demoted = max(REVIEW, second["risk_score"])
    note = (f"Automated corroboration: an initial score of "
            f"{result['risk_score']} (>= block) was re-reviewed independently on "
            f"the same diff and scored {second['risk_score']}; the two did not "
            f"agree, so the score was demoted to {demoted} (review) for human "
            f"inspection rather than auto-blocking on a single call.")
    result["reasoning"] = (f"{result['reasoning']}\n\n{note}"
                           if result["reasoning"] else note)
    result["risk_score"] = demoted
    return result


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


def cap_paths(paths, limit=20):
    """Render a path list as capped, backticked, comma-joined text.

    GitHub's PR-comment limit is 65536 chars; a repo-init listing 300 paths blows
    it, `gh` rejects the comment, and NO comment is posted at all. Cap every path
    list so a large push still yields a comment, just an abbreviated one.
    """
    shown = ", ".join(f"`{p}`" for p in paths[:limit])
    if len(paths) > limit:
        shown += f" …and {len(paths) - limit} more"
    return shown


def render_markdown(result, verdict, failsafe=None, injection=False, coverage=None,
                    scored=True):
    icon = {"pass": "✅", "review": "⚠️", "block": "⛔"}.get(verdict, "❓")
    lines = [
        MARKER,
        f"## {icon} Intent Gate — {verdict.upper()}",
        "",
    ]
    boot = (coverage or {}).get("bootstrap")
    if boot:
        # An honest "8 of 340 scanned" beats a green check implying 340 were.
        lines += [
            f"> 📦 **Initial import: {boot['total']} files. Full intent review "
            f"not attempted.** Scanned {coverage.get('files_scanned', 0)} "
            f"CI/executable surfaces; the rest of this push was not reviewed for "
            f"intent. Requires manual sign-off.",
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
        binary = coverage.get("binary") or []
        excluded = coverage.get("excluded") or []
        lockfiles = coverage.get("lockfiles") or []
        lines += [
            f"_Scanned {coverage['files_scanned']} files across "
            f"{coverage['num_chunks']} chunks._",
            "",
        ]
        if binary:
            lines += [
                "> ⚠️ **Binary / non-text changes were NOT reviewed by the "
                "model.** These files changed as binary content; they were "
                "flagged from diff metadata only — their bytes were never sent "
                "to the model:",
                "",
                "> - " + cap_paths(binary),
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
                lines.append("> - **Unscanned (ran out of budget):** "
                             + cap_paths(overflow))
            if truncated:
                lines.append("> - **Truncated (file larger than one chunk):** "
                             + cap_paths(truncated))
            lines.append("")
        # EXCLUDED / lockfiles are informational — they do NOT floor the verdict.
        # "Chose not to look (by policy)" is deliberately distinct from the
        # "ran out of budget" floor above.
        if excluded:
            lines += [
                "_Not scanned by policy (vendored / generated / build artifacts) "
                "— did not affect the verdict:_ " + cap_paths(excluded),
                "",
            ]
        if lockfiles:
            lines += [
                "_Dependency lockfiles checked by rule, not sent to the model:_ "
                + cap_paths(lockfiles),
                "",
            ]
    if scored:
        score_line = (f"**{result['risk_score']} / 100** — "
                      f"{risk_band(result['risk_score'])}")
    else:
        # No chunk produced a score (all failed, or nothing scannable). A shown
        # "0 / 100 — low risk" next to a REVIEW verdict is a contradiction that
        # reads as a clean pass; say n/a instead.
        score_line = "**n/a** — no diff chunk was successfully scored (see above)."
    lines += [
        "### Risk Score",
        score_line,
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


def fit_max_chars(system_prompt, num_ctx, num_predict,
                  chars_per_token=3.6, safety=0.85):
    """Derive the per-chunk character budget that actually fits Ollama's context
    window, so MAX_CHARS and NUM_CTX can't silently contradict each other.

    Ollama does not error when system + diff + num_predict exceed num_ctx — it
    quietly truncates the prompt, so the model may score a clipped diff and even
    lose part of its own rubric. Two hand-set knobs that must agree is a bug
    generator; make the budget DERIVED instead:

        diff_tokens = num_ctx*safety - num_predict - system_tokens
        budget_chars = diff_tokens * chars_per_token

    Raises ValueError if the system prompt plus num_predict alone don't fit
    num_ctx (no room for ANY diff) — a misconfiguration to surface loudly rather
    than paper over.
    """
    system_tokens = len(system_prompt) / chars_per_token
    diff_tokens = num_ctx * safety - num_predict - system_tokens
    if diff_tokens <= 0:
        raise ValueError(
            f"context window too small: num_ctx={num_ctx} cannot hold the system "
            f"prompt (~{system_tokens:.0f} tok) plus num_predict={num_predict} "
            f"output tokens with no room left for the diff. Raise NUM_CTX or "
            f"shorten the prompt.")
    return int(diff_tokens * chars_per_token)


def emit(result, verdict, failsafe=None, injection=False, coverage=None,
         scored=True):
    """Print the JSON verdict on stdout, write the sticky comment, append to the
    GitHub step summary, and return the process exit code (1 only on block).

    Single exit point for every path — normal scan, git failure, and the
    binary/mode-only path — so none of them can accidentally exit 0 silently.
    """
    cov = coverage or {}
    overflow = cov.get("overflow", [])
    truncated = cov.get("truncated", [])
    binary = cov.get("binary", [])
    excluded = cov.get("excluded", [])
    lockfiles = cov.get("lockfiles", [])
    print(json.dumps({
        "verdict": verdict,
        "score": result["risk_score"] if scored else None,
        "scored": scored,
        "truncated": bool(truncated or overflow),
        "injection": injection,
        "failsafe": failsafe,
        "bootstrap": bool(cov.get("bootstrap")),
        "num_chunks": cov.get("num_chunks", 0),
        "files_scanned": cov.get("files_scanned", 0),
        "files_unscanned": overflow,
        "files_truncated": truncated,
        "files_binary": binary,
        "files_excluded": excluded,
        "files_lockfiles": lockfiles,
        "key_changes": result["key_changes"],
        "suspicious_findings": result["suspicious_findings"],
        "reasoning": result["reasoning"],
    }, indent=2))
    comment = render_markdown(result, verdict, failsafe, injection, coverage,
                              scored)
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


def main():
    global _VERBOSE, MAX_CHARS
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", help="path to a diff file (hand testing)")
    ap.add_argument("--git-base", help="base ref for git diff (CI)")
    ap.add_argument("--verbose", action="store_true",
                    help="timing and progress on stderr")
    args = ap.parse_args()
    _VERBOSE = args.verbose

    with open(PROMPT_FILE, encoding="utf-8") as fh:
        system = fh.read()

    # BUG 4: MAX_CHARS and NUM_CTX must agree or Ollama silently truncates the
    # prompt. Derive the real per-chunk char budget from the context window and
    # clamp DOWN to it (a smaller hand-set MAX_CHARS is left as-is).
    fitted = fit_max_chars(system, NUM_CTX, NUM_PREDICT)
    if fitted < MAX_CHARS:
        log(f"clamping MAX_CHARS {MAX_CHARS} -> {fitted} so the system prompt + "
            f"diff + num_predict={NUM_PREDICT} fit num_ctx={NUM_CTX} (Ollama "
            f"truncates silently otherwise)", force=True)
        MAX_CHARS = fitted

    # BUG 1: a git failure must NOT look like an empty (clean) diff. get_diff now
    # raises InfraError on a non-zero git exit; route it to the infra fail-safe
    # (review, or block under FAIL_CLOSED) and render the fail-safe banner.
    try:
        diff = get_diff(args)
    except InfraError as exc:
        log(f"FAILSAFE kind=infra stage=get_diff fail_closed={FAIL_CLOSED} "
            f"detail={exc}", force=True)
        result = {"risk_score": 0, "key_changes": [], "suspicious_findings": [],
                  "reasoning": f"The diff could not be produced, so nothing was "
                               f"scanned: {exc}"}
        verdict = escalate("pass", "block" if FAIL_CLOSED else FAIL_SAFE)
        return emit(result, verdict, failsafe="infra", scored=False)

    raw_diff = sanitize(diff)
    # BUG 2: extract_hunks discards binary/mode metadata, so scan the RAW diff
    # for those hunk-less, risk-bearing changes first — they can never fail open.
    meta_findings, binary_paths = metadata_findings(raw_diff)
    hunks = extract_hunks(raw_diff)

    if not hunks.strip():
        if meta_findings:
            # No textual hunks, but binary/mode changes carry risk — floor to
            # review and show them, never the silent clean-pass path.
            result = {"risk_score": 0, "key_changes": [],
                      "suspicious_findings": meta_findings,
                      "reasoning": "No textual hunks were present to send to the "
                                   "model, but change metadata (new executable, "
                                   "mode change, or binary content) was detected "
                                   "and flagged for human review."}
            coverage = {"files_scanned": 0, "num_chunks": 0, "overflow": [],
                        "truncated": [], "binary": binary_paths,
                        "excluded": [], "lockfiles": []}
            return emit(result, escalate("pass", "review"), coverage=coverage,
                        scored=False)
        print(json.dumps({"verdict": "pass", "score": 0,
                          "key_changes": [], "suspicious_findings": [],
                          "reasoning": ""}))
        print("No diff content to scan.", file=sys.stderr)
        return 0

    # File-aware chunking: split on file boundaries, greedy-pack whole files into
    # per-call budgets (high-risk files first), and scan each chunk on its own —
    # replacing the old truncate-and-floor of the tail.
    files = split_by_file(hunks)
    if not files:                               # defensive: hunks with no file header
        files = [("unknown", hunks)]

    # Injection tripwire, checked PER FILE over the pre-truncation split so that
    # markers in the detector's own prompts/fixtures/samples don't self-trip.
    injection = detect_injection(files)
    if injection:
        log("prompt-injection markers found in diff; score will be floored",
            force=True)

    # Four-state classification BEFORE packing: pull vendored/generated junk
    # (EXCLUDED, no floor) and lockfiles (regex-scanned, never to the model) out
    # of the model's workload, and collect deterministic findings. Only `to_scan`
    # reaches the model. See detector/filters.py for the SCAN/DETERMINISTIC/
    # EXCLUDED/UNSCANNED split.
    to_scan, determ_findings, excluded_paths, lockfile_paths = filters.classify(files)
    log(f"classify: scan={len(to_scan)} excluded={len(excluded_paths)} "
        f"lockfiles={len(lockfile_paths)} determ_findings={len(determ_findings)}")

    # Bootstrap: an initial-import-sized push is too big for a genuine intent
    # review. Scan only the CI/executable surfaces (highest risk), run the
    # regexes, and force `review` with a comment that says so plainly. Decided on
    # the scannable set so a lockfile bump / vendored dump can't false-trigger it.
    bootstrap = filters.is_bootstrap(to_scan)
    bootstrap_total = len(to_scan)
    if bootstrap:
        exec_paths = {f["file"] for f in meta_findings
                      if "executable" in f["reason"].lower()}
        to_scan = [(p, d) for p, d in to_scan
                   if HIGH_RISK_PATH.search(p) or p in exec_paths]
        log(f"bootstrap: {bootstrap_total} scannable files; scanning "
            f"{len(to_scan)} CI/executable surfaces only", force=True)

    chunks, overflow_files, truncated_files = pack(to_scan, MAX_CHARS, MAX_CHUNKS)
    files_scanned = sum(len(paths) for _text, paths in chunks)
    num_chunks = len(chunks)
    log(f"model={MODEL} files={len(files)} chunks={num_chunks} "
        f"scanned={files_scanned} overflow={len(overflow_files)} "
        f"truncated={len(truncated_files)}")

    outcomes = []                               # per-chunk: status/result/paths
    for i, (text, paths) in enumerate(chunks):
        # Wall-clock budget: if we're out of time, leave the remaining chunks
        # UNSCANNED (they floor to review — same as budget overflow) rather than
        # blow the CI job's own timeout. Checked BEFORE the call so a slow model
        # can't overrun by one full REQUEST_TIMEOUT past the budget.
        if time.monotonic() - _START >= MAX_SECONDS:
            remaining = [p for _t, ps in chunks[i:] for p in ps]
            overflow_files.extend(remaining)
            log(f"MAX_SECONDS={MAX_SECONDS}s budget reached after {i} chunks; "
                f"{len(remaining)} files left unscanned (floor to review)",
                force=True)
            break
        log(f"chunk {i + 1}/{len(chunks)} files={len(paths)} chars={len(text)}")
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
            # A would-be block gets one independent second look before it can
            # block the PR (demotes to review on disagreement, keeps block on a
            # failed second call). Runs before the single-chunk verbatim path and
            # the aggregate max(), so both reduce paths see the demoted score.
            if CORROBORATE and res["risk_score"] >= BLOCK:
                res = corroborate(res, text, system)
            outcomes.append({"status": "ok", "result": res, "paths": paths})

    # Recompute from ATTEMPTED chunks: an early MAX_SECONDS break leaves the
    # pre-loop totals overcounting (unreached chunks became overflow_files above).
    files_scanned = sum(len(o["paths"]) for o in outcomes)
    num_chunks = len(outcomes)

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

    # BUG 2 + classify: merge the hunk-less change metadata (binary/mode/exec)
    # AND the deterministic regex findings (lockfile hosts, hand-edited build
    # output, lockfile-without-manifest) into the findings unconditionally, so the
    # comment always names them even when the model — which never saw them —
    # reported nothing.
    seen = {(f["file"], f["reason"].strip().lower())
            for f in result["suspicious_findings"]}
    for f in meta_findings + determ_findings:
        key = (f["file"], f["reason"].strip().lower())
        if key not in seen:
            seen.add(key)
            result["suspicious_findings"].append(f)

    if injection:                               # floor regardless of the model's score
        apply_injection_floor(result, INJECTION_FLOOR)

    # A score is meaningful only if at least one chunk was actually scored. With
    # none, render "n/a" instead of "0 / 100 — low risk" next to a REVIEW verdict.
    scored = bool(successful)

    verdict = verdict_of(result["risk_score"])
    # Fail-safe policy, differentiated by error type. escalate() can only raise
    # severity, never lower a real finding.
    if failsafe == "infra":                     # transient outage -> fail open to review
        verdict = escalate(verdict, "block" if FAIL_CLOSED else FAIL_SAFE)
    elif failsafe == "content":                 # parser broke on the diff -> distrust it
        verdict = escalate(verdict, "block" if FAIL_CLOSED else "review")
    if overflow_files or truncated_files:       # partially scanned -> never a clean pass
        verdict = escalate(verdict, "review")
    if binary_paths:                            # binary bytes never reached the model
        verdict = escalate(verdict, "review")
    if determ_findings:                         # a real supply-chain finding, no score
        verdict = escalate(verdict, "review")
    if bootstrap:                               # initial import -> manual sign-off
        verdict = escalate(verdict, "review")

    coverage = {"files_scanned": files_scanned, "num_chunks": num_chunks,
                "overflow": overflow_files, "truncated": truncated_files,
                "binary": binary_paths, "excluded": excluded_paths,
                "lockfiles": lockfile_paths}
    if bootstrap:
        coverage["bootstrap"] = {"total": bootstrap_total}
    return emit(result, verdict, failsafe, injection, coverage, scored)


if __name__ == "__main__":
    sys.exit(main())
