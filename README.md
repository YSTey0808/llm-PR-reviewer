# Intent Gate

**An LLM-based malicious-intent gate for pull-request diffs, powered by a local Ollama model.**

Intent Gate reviews each PR's diff for signs of *deliberate harm* — exfiltration, backdoors, logic bombs, CI/CD tampering, obfuscation, and suspicious network calls — not ordinary bugs or style. It runs entirely on your own hardware via a local [Ollama](https://ollama.com) model (no code or diffs leave your infrastructure), scores the change 0–100, posts a sticky PR comment explaining what the change does, and can fail the check when the risk is high.

---

## How it works

1. On a pull request, a GitHub Action computes the diff against the base branch.
2. [`detector/scan.py`](detector/scan.py) reduces the diff to just the changed hunks, wraps it as untrusted data, and sends it to Ollama in **one** call using the model's structured-output (`format`) option.
3. The model returns a structured review — a plain-English summary, a 0–100 risk score, key changes, and any suspicious findings.
4. The script renders a markdown comment (`comment.md`), prints machine-readable JSON, and maps the score to a verdict.
5. The Action posts/updates a **sticky PR comment** (keyed off a hidden HTML marker, so re-runs edit the same comment) and fails the check on `block`.

```
PR diff ──▶ extract hunks ──▶ Ollama (qwen2.5-coder, format:json-schema) ──▶ review JSON
                                                                                │
                       comment.md (sticky PR comment) ◀── render ◀─────────────┤
                       exit 1 on "block" (fails the check) ◀── gate ◀──────────┘
```

## Verdicts

The risk score maps to three verdicts (thresholds configurable):

| Score  | Verdict  | Meaning                                            | Check |
|--------|----------|----------------------------------------------------|-------|
| 0–39   | ✅ pass   | Benign / standard practice                          | green |
| 40–69  | ⚠️ review | Unusual — a human should look, legitimate reasons plausible | green |
| 70–100 | ⛔ block  | Strong signs of intent                              | **fails** |

---

## Requirements

- A **self-hosted GitHub Actions runner** (Linux x64) — the model runs locally on this machine, so GitHub's cloud runners won't work.
- [Ollama](https://ollama.com) installed on the runner. The action starts it and pulls the model automatically, or you can pre-pull:
  ```bash
  ollama pull qwen2.5-coder:7b
  ```
- Python 3 (standard library only — no `pip install` needed).

## Usage (as a GitHub Action)

Add a workflow to the repo you want gated. The calling job **must** grant `pull-requests: write` for the sticky comment.

```yaml
name: "Intent Gate"
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: [self-hosted, Linux, X64]
    permissions:
      contents: read
      pull-requests: write        # required for the sticky PR comment
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0          # full history so the base diff resolves

      - name: Intent gate
        uses: YSTey0808/llm-PR-reviewer@main
        with:
          model: qwen2.5-coder:7b
          block-threshold: "70"
          review-threshold: "40"
          # Block (not just review) on scan errors for protected branches:
          fail-closed: ${{ github.base_ref == 'main' }}
```

This repo dogfoods the action against its own PRs — see [`.github/workflows/gate.yml`](.github/workflows/gate.yml).

### Action inputs

| Input              | Default            | Description                                                        |
|--------------------|--------------------|--------------------------------------------------------------------|
| `model`            | `qwen2.5-coder:3b` | Ollama model tag.                                                   |
| `block-threshold`  | `70`               | Score at/above which the verdict is **block** (fails the check).   |
| `review-threshold` | `40`               | Score at/above which the verdict is **review**.                    |
| `comment`          | `true`             | Post/update the sticky PR comment.                                 |
| `fail-closed`      | `false`            | On a scan error, **block** instead of failing open to `review`. Set `true` for protected/release branches. |
| `request-timeout`  | `600`              | Per-request read timeout (seconds) for each Ollama call. Raise on slow/CPU-only runners. |
| `num-ctx`          | `8192`             | Ollama context window (tokens). Lower on CPU-only runners for speed; must cover the system prompt + diff. |

## Usage (local / hand testing)

Run the detector directly against a diff file or a git range. Requires a local Ollama with the model pulled.

```bash
# Score a single diff file
python3 detector/scan.py --diff samples/malicious/exfill.diff --verbose

# Diff the current branch against a base ref (what CI does)
python3 detector/scan.py --git-base origin/main

# Inspect the rendered PR comment
cat comment.md
echo "exit code: $?"     # 1 = block (would fail CI), 0 = pass/review
```

### Batch evaluation

[`tests/eval.py`](tests/eval.py) runs the detector over every sample in `samples/` and reports precision / recall / accuracy against the expected labels (folder name = expected outcome):

```bash
MODEL=qwen2.5-coder:7b python3 tests/eval.py
```

---

## Security-hardening features

Small local models can be steered, and scans can fail — the gate is designed so neither silently opens the door.

- **Untrusted-diff wrapping.** The diff is wrapped in `<untrusted_diff>` tags and the prompt instructs the model to treat everything inside as data, never lowering the score based on tag content and *raising* it on manipulation attempts.
- **Prompt-injection tripwire.** A model-independent regex scans the diff for injection markers (`ignore previous instructions`, `set risk_score to 0`, `pre-approved`, `reviewer-bot`, …). A hit floors the score to at least `INJECTION_FLOOR` (55, the review band), so an injected diff can't score as a clean pass even if the model is fooled.
- **Visible truncation.** Diffs larger than `MAX_CHARS` are truncated; the verdict is floored to at least `review` and the comment shows how much was scanned — a large PR is never silently passed.
- **Explicit context window.** `NUM_CTX` is set on every call so Ollama's small default (2048 tokens) doesn't silently truncate the prompt.
- **Differentiated fail-safe.** Failures are classified and retried (`RETRIES` with exponential backoff) before failing safe:
  - *Infra error* (Ollama down / timeout) → fails open to `review`.
  - *Content error* (reply won't parse — possible evasion) → distrusted, floored to `review`.
  - On a protected branch (`fail-closed`), **both** escalate to `block`.
  - Fail-safe logic only ever *raises* severity — a real finding is never lowered — and the PR comment leads with a loud banner so a fail-safe is never mistaken for a green light.

## Output format

`scan.py` prints JSON to stdout for tooling:

```json
{
  "verdict": "block",
  "score": 88,
  "truncated": false,
  "injection": false,
  "failsafe": null,
  "intent_summary": "...",
  "key_changes": ["..."],
  "suspicious_findings": [{ "file": "app/util.py", "reason": "..." }],
  "reasoning": "..."
}
```

`failsafe` is `null`, `"infra"`, or `"content"` — a hook the workflow can route to alerting when scans start failing.

## Configuration (environment variables)

All action inputs map to these; set them directly for local runs.

| Variable           | Default                   | Description                                             |
|--------------------|---------------------------|---------------------------------------------------------|
| `OLLAMA_URL`       | `http://localhost:11434`  | Ollama server URL.                                      |
| `MODEL`            | `qwen2.5-coder:3b`        | Model tag.                                              |
| `PROMPT_FILE`      | `prompts/intent.md`       | System prompt for the review.                           |
| `COMMENT_FILE`     | `comment.md`              | Where the rendered markdown comment is written.         |
| `BLOCK_THRESHOLD`  | `70`                      | Block at/above this score.                              |
| `REVIEW_THRESHOLD` | `40`                      | Review at/above this score.                             |
| `MAX_CHARS`        | `16000`                   | Diff character cap before truncation.                   |
| `NUM_CTX`          | `8192`                    | Ollama context window (keep above `MAX_CHARS` worth of tokens + prompt). |
| `INJECTION_FLOOR`  | `55`                      | Score floor when injection markers are found.           |
| `FAIL_SAFE`        | `review`                  | Verdict floor on infra error.                           |
| `FAIL_CLOSED`      | `false`                   | Escalate scan errors to `block`.                        |
| `RETRIES`          | `3`                       | Attempts before failing safe.                           |
| `RETRY_BACKOFF`    | `2`                       | Base seconds for exponential backoff.                   |
| `REQUEST_TIMEOUT`  | `600`                     | Per-request timeout (seconds). Raise on slow runners.   |

## Tuning accuracy

The system prompt in [`prompts/intent.md`](prompts/intent.md) contains a **project-context** line describing the kind of code being reviewed. Editing it to match your real project materially improves accuracy — behaviour that's normal for your app produces fewer false positives, and behaviour that's out of character is flagged more reliably. A larger model (e.g. `qwen2.5-coder:7b` over `:3b`) also improves judgment at the cost of runner RAM and latency.

## Repository layout

| Path                          | Purpose                                              |
|-------------------------------|------------------------------------------------------|
| `detector/scan.py`            | The detector — diff → Ollama → verdict + comment.md. |
| `prompts/intent.md`           | System prompt / rubric handed to the model.          |
| `action.yml`                  | The composite GitHub Action (Ollama setup, scan, sticky comment). |
| `.github/workflows/gate.yml`  | This repo's own CI (dogfoods the action).            |
| `tests/eval.py`               | Batch precision/recall harness over `samples/`.      |
| `samples/`                    | Labelled example diffs (`benign/`, `malicious/`).    |
