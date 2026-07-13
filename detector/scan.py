#!/usr/bin/env python3
"""
Malicious-intent PR gate — detector (Python standard library only).

Reads a diff, sends the changed hunks (only) to a LOCAL Ollama model in ONE
call, and gets back a structured review: what the PR does, a 0-100 risk score,
key changes, and suspicious findings. The result is rendered as a markdown
comment (comment.md) for a sticky PR comment, printed as JSON on stdout, and
the risk score is gated so CI can fail the check on 'block'.

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

Env (defaults shown):
  OLLAMA_URL http://localhost:11434 | MODEL qwen2.5-coder:3b
  PROMPT_FILE prompts/intent.md | COMMENT_FILE comment.md
  BLOCK_THRESHOLD 70 | REVIEW_THRESHOLD 40 | MAX_CHARS 24000 | NUM_CTX 16384
  FAIL_SAFE review | REQUEST_TIMEOUT 300 | RETRY_BACKOFF 2 | RETRIES 3
  INJECTION_FLOOR 55 | FAIL_CLOSED false
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
MAX_CHARS = int(os.environ.get("MAX_CHARS", "24000"))
# Ollama's context window. Its default (2048 tokens) is smaller than MAX_CHARS,
# so without this the prompt is SILENTLY truncated by Ollama before the model
# sees it. Sized to hold the system prompt + a MAX_CHARS diff (~6000 tokens) +
# output headroom. Bigger = more RAM/slower on the runner.
NUM_CTX = int(os.environ.get("NUM_CTX", "16384"))
FAIL_SAFE = os.environ.get("FAIL_SAFE", "review")   # verdict floor on infra error
# Per-request read timeout. Sized for a warm model; the action warms the model
# in its setup step so this budget isn't spent on the first-call cold start.
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "300"))
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

# JSON schema handed to Ollama's structured-output "format" — constrains the
# model to emit exactly this shape.
SCHEMA = {
    "type": "object",
    "properties": {
        "intent_summary": {"type": "string"},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
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
    },
    "required": ["intent_summary", "risk_score", "key_changes",
                 "suspicious_findings", "reasoning"],
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


def call_model(system, user, schema):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": schema,                       # structured output
        "options": {"temperature": 0, "seed": 7, "num_ctx": NUM_CTX},
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
        "intent_summary": str(obj.get("intent_summary", "")).strip(),
        "risk_score": max(0, min(100, score)),
        "key_changes": [str(c) for c in (obj.get("key_changes") or [])],
        "suspicious_findings": findings,
        "reasoning": str(obj.get("reasoning", "")).strip(),
    }


def review_diff(hunks, system):
    """One model call over the whole diff, wrapped as untrusted data. Retries
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


def verdict_of(score):
    return "block" if score >= BLOCK else "review" if score >= REVIEW else "pass"


def risk_band(score):
    if score >= BLOCK:
        return "🔴 high risk"
    if score >= REVIEW:
        return "🟡 medium risk"
    return "🟢 low risk"


def render_markdown(result, verdict, failsafe=None, truncated=None, injection=False):
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
    if truncated:
        kept, total = truncated
        pct = round(100 * kept / total)
        lines += [
            f"> ⚠️ **Large diff — only the first {kept:,} of {total:,} "
            f"characters (~{pct}%) were scanned.** Changes beyond that point "
            "were not reviewed; the verdict is floored to at least `review`.",
            "",
        ]
    lines += [
        "### Summary",
        result["intent_summary"] or "_No summary produced._",
        "",
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
        lines += ["", "<details><summary>Model reasoning</summary>", "",
                  result["reasoning"], "", "</details>"]
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
        print(json.dumps({"verdict": "pass", "score": 0, "intent_summary": "",
                          "key_changes": [], "suspicious_findings": [],
                          "reasoning": ""}))
        print("No diff content to scan.", file=sys.stderr)
        return 0

    injection = bool(INJECTION.search(hunks))   # check full diff, pre-truncation
    if injection:
        log("prompt-injection markers found in diff; score will be floored",
            force=True)

    truncated = None                            # (kept_chars, total_chars) or None
    if len(hunks) > MAX_CHARS:
        truncated = (MAX_CHARS, len(hunks))
        log(f"diff truncated: {len(hunks)} -> {MAX_CHARS} chars", force=True)
        hunks = hunks[:MAX_CHARS] + "\n[diff truncated]"

    log(f"model={MODEL} diff_chars={len(hunks)}")
    failsafe = None                             # None | "infra" | "content"
    try:
        result = review_diff(hunks, system)
    except InfraError as exc:
        failsafe = "infra"
        result = {"intent_summary": "", "risk_score": 0, "key_changes": [],
                  "suspicious_findings": [], "reasoning": ""}
        # Loud, machine-parseable line so the workflow can route to Slack/alerts.
        log(f"FAILSAFE kind=infra fail_closed={FAIL_CLOSED} detail={exc}", force=True)
    except ContentError as exc:
        failsafe = "content"
        result = {"intent_summary": "", "risk_score": 0, "key_changes": [],
                  "suspicious_findings": [], "reasoning": ""}
        log(f"FAILSAFE kind=content fail_closed={FAIL_CLOSED} detail={exc}", force=True)

    if injection:                               # floor regardless of the model's score
        result["risk_score"] = max(result["risk_score"], INJECTION_FLOOR)

    verdict = verdict_of(result["risk_score"])
    # Fail-safe policy, differentiated by error type. escalate() can only raise
    # severity, never lower a real finding.
    if failsafe == "infra":                     # transient outage -> fail open to review
        verdict = escalate(verdict, "block" if FAIL_CLOSED else FAIL_SAFE)
    elif failsafe == "content":                 # parser broke on the diff -> distrust it
        verdict = escalate(verdict, "block" if FAIL_CLOSED else "review")
    if truncated:                               # partially scanned -> never a clean pass
        verdict = escalate(verdict, "review")

    print(json.dumps({"verdict": verdict, "score": result["risk_score"],
                      "truncated": bool(truncated), "injection": injection,
                      "failsafe": failsafe,
                      "intent_summary": result["intent_summary"],
                      "key_changes": result["key_changes"],
                      "suspicious_findings": result["suspicious_findings"],
                      "reasoning": result["reasoning"]}, indent=2))

    comment = render_markdown(result, verdict, failsafe, truncated, injection)
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
