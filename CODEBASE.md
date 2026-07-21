# Intent Gate — Codebase Guide

A local-LLM gate that reviews a pull-request **diff** for *deliberate malicious
intent* (exfiltration, backdoors, logic bombs, CI/CD tampering, obfuscation,
suspicious network calls) — not ordinary bugs or style. It runs a local
[Ollama](https://ollama.com) model, scores the change 0–100, renders a sticky PR
comment, and fails CI on a `block` verdict.

**Guiding invariant (repeated everywhere):** a failure or manipulation must
*never silently open the gate*. Every code path fails toward `review`/`block`,
never toward `pass`. Standard library only — no `pip`, no third-party imports.

---

## 1. The pipeline at a glance

```
git diff ─▶ get_diff ─▶ sanitize ─▶ metadata_findings (binary/mode/exec, raw)
                                  └▶ extract_hunks ─▶ split_by_file
                                        │
                    detect_injection ◀──┤ (per-file tripwire, exempt paths skipped)
                                        │
                        filters.classify ─▶ SCAN / DETERMINISTIC / EXCLUDED
                                        │
                    filters.is_bootstrap? ─▶ (huge import ⇒ scan CI surfaces only)
                                        │
                              pack ─▶ chunks (high-risk files first, budget-bounded)
                                        │
                    review_chunk (Ollama call + retries) per chunk
                                        │  would-be block ⇒ corroborate (2nd look)
                                        │
                    aggregate_results (max score, union findings) [+ optional LLM reduce]
                                        │
      merge meta + deterministic findings ─▶ injection floor ─▶ fail-safe escalation
                                        │
                    emit ─▶ stdout JSON + comment.md + GITHUB_STEP_SUMMARY, exit code
```

Verdict banding: `pass` (0–39) · `review` (40–69) · `block` (70–100). Only
`block` exits non-zero (fails the check).

---

## 2. What each file does

### Core detector
| File | Purpose |
|---|---|
| [detector/scan.py](detector/scan.py) | **The detector.** Turns a diff into a verdict: reads the diff, strips it to hunks, chunks big diffs on file boundaries, calls Ollama per chunk with a JSON-schema-constrained prompt, aggregates, applies every fail-safe, and emits JSON + `comment.md`. Fully line-by-line below. |
| [detector/filters.py](detector/filters.py) | **Pre-model classification.** Splits each changed file into four fates — `SCAN` (to the model), `DETERMINISTIC` (regex decides: lockfile hosts, hand-edited build output, lockfile-without-manifest), `EXCLUDED` (vendored/generated junk; named but no floor), and the bootstrap check for initial-import-sized pushes. Keeps high-volume, low-signal text away from a small model. |
| [prompts/intent.md](prompts/intent.md) | **The system prompt / rubric** handed to the model. Defines the output field order (analysis first, `risk_score` last), the 0–100 rubric bands, the malicious-intent categories, false-positive-reduction rules, and the anti-injection instructions. The JSON output shape is enforced separately by `SCHEMA` in `scan.py`. |

### Packaging / CI
| File | Purpose |
|---|---|
| [action.yml](action.yml) | **Composite GitHub Action.** Three steps: (1) wait for the runner's Ollama service and warm the model at the same `num_ctx` the scan uses; (2) pick the base ref by trigger type and run `scan.py --git-base`; (3) post/update the sticky PR comment via `gh`, keyed off the hidden HTML marker. Maps action inputs → env vars `scan.py` reads. |
| [.github/workflows/gate.yml](.github/workflows/gate.yml) | This repo's **own CI** — dogfoods the action against its own PRs (`uses: ./`). Runs on a self-hosted runner, grants `pull-requests: write`, and sets `fail-closed` for PRs into `main`. |
| [README.md](README.md) | User-facing docs: how it works, verdict table, requirements, usage as an Action and locally, the security-hardening feature list, env-var reference, and the **Tuning accuracy** note (edit the project-context line in the prompt). |
| [CLAUDE.md](CLAUDE.md) | Working rules for AI assistants in this repo (don't execute tests, don't explore repo-wide, stdlib-only, fail-toward-review design principle). |
| [.claude/settings.json](.claude/settings.json) | Claude Code permission allowlist for previously-approved commands in this repo. |
| [.gitignore](.gitignore) | Standard Python ignores + the one generated fixture (`tests/fixtures/large_chunked.diff`); hand-authored fixtures and samples are committed. |

### Tests & harness (`tests/`)
Split into two offline buckets (`unit/`, `model/`), shared `support/` infra, and a real-model `eval/` harness. `tests/run_tests.py` runs the two offline buckets.

| File | Purpose |
|---|---|
| [tests/run_tests.py](tests/run_tests.py) | **Offline runner.** Globs `test_*.py` in `unit/` + `model/`, runs each as a subprocess, prints per-file PASS/FAIL, exits non-zero if any fail (fail-closed). `--unit` / `--model` scope it; `eval/` is excluded (needs a real Ollama). |
| [tests/unit/test_scan.py](tests/unit/test_scan.py) | `unittest` cases for the **pure helpers** (sanitize, extract_hunks, split_by_file, priority, pack, coerce_result, verdict_of, escalate, injection regex, render_markdown). No network. |
| [tests/unit/test_units.py](tests/unit/test_units.py) | Same pure helpers as plain `check()` assertions (a lighter-weight mirror of `test_scan.py`). |
| [tests/unit/test_failopen_units.py](tests/unit/test_failopen_units.py) | Pure `fit_max_chars` budget helper in isolation (split out of the fail-open suite). |
| [tests/unit/test_corroborate_units.py](tests/unit/test_corroborate_units.py) | Pure halves of the robustness suite: `corroborate()` failure paths, per-file injection exemption, `priority()` added-lines-only, `FAIL_SAFE` clamp. |
| [tests/model/test_harness.py](tests/model/test_harness.py) | **End-to-end** tests: run `scan.py` as a subprocess against `FakeOllama` — scored verdict flow, echo/what-was-sent, both fail-safe branches, injection flooring, and the binary/mode blindness pin. |
| [tests/model/test_failopen.py](tests/model/test_failopen.py) | End-to-end regressions for **fail-open bugs**: git failure ⇒ infra review (block when fail-closed); binary/mode-only changes surfaced; missing/non-numeric score ⇒ content review; main() clamps `MAX_CHARS` to `NUM_CTX`. |
| [tests/model/test_corroborate.py](tests/model/test_corroborate.py) | End-to-end `corroborate()` loop: a second look demotes a lone block to review, keeps block on agreement. |
| [tests/model/test_bigpush.py](tests/model/test_bigpush.py) | End-to-end **four-state big-push** tests (monkeypatches `call_model` with a recorder): node_modules never sent, CI workflow scanned first, excluded-alone doesn't floor, budget overflow does floor, lockfile host findings without a model call, dist-only artifact finding, and 500-file bootstrap. |
| [tests/support/fake_ollama.py](tests/support/fake_ollama.py) | **Scriptable in-process fake Ollama** (`http.server` + threading). Stands in for `/api/chat` so tests drive the whole detector offline. Modes: `respond` (scripted scores), `garbage` (→ ContentError), `http_error`/`hang` (→ InfraError), `raw` (verbatim content), `echo` (record what was sent). `.requests` captures every POST body. |
| [tests/support/make_large_diff.py](tests/support/make_large_diff.py) | Generates a fixed benign ~75 KB diff (`tests/fixtures/large_chunked.diff`) to exercise multi-chunk `pack()` locally. |
| [tests/support/make_big_diff.py](tests/support/make_big_diff.py) | Configurable synthetic **repo-init** diff generator (src + node_modules + huge lockfile + CI workflow + min.js) for chunking/priority stress tests. |
| [tests/eval/eval.py](tests/eval/eval.py) | **Batch scoring harness.** Runs the detector over every `samples/**/*.diff`, compares the verdict to the folder-name label (malicious ⇒ flagged, benign ⇒ pass), and prints precision/recall/accuracy. `--perturb` also scans semantics-preserving variants (rename var / blank line / reorder hunks) and reports the **verdict-change rate** (robustness, not accuracy). Needs a real Ollama. |
| [tests/eval/check_contamination.py](tests/eval/check_contamination.py) | **Contamination guard (a real failing test).** Tokenises each sample's file name and flags overlap with the whole prompt, minus a generic-vocabulary `EXCLUSION` set. Exits non-zero if the prompt "names" a sample — i.e. leaks the answer key. Whole-file token count; polices distinctive leak tokens (`healthcheck`, `rename`, …). |
| [tests/GUIDE.md](tests/GUIDE.md) | How to run and extend the test suite; documents the buckets, fake server, and fixtures. |
| [tests/fixtures/*.diff](tests/fixtures/) | Hand-written diff *shapes*: `binary_only`, `chmod_exec`, `new_exec`, `lockfile_evil`, `lockfile_clean`, `injection_marker`, `dist_only`. |
| [samples/benign/*.diff](samples/benign/), [samples/malicious/*.diff](samples/malicious/) | The 23 labelled eval diffs (11 benign, 12 malicious). Folder name = expected outcome. |
| [test_150.py](test_150.py) | A 150-line throwaway scratch file of `var_N = …` assignments (a size fixture; not part of the suite). |
| [comment.md](comment.md) | **Generated output** — the last rendered sticky PR comment written by `scan.py`. Not source. |

---

## 3. `detector/scan.py` — line by line

Line numbers refer to the current file. Grouped by section; every meaningful
line/block is explained.

### Module docstring & imports (1–57)
- **1–44 — Docstring.** States the contract: read a diff, send hunks-only to a
  *local* Ollama in structured-output mode, get back key changes / findings /
  reasoning / a score decided **last**. Documents the design notes (schema-
  constrained output, hunks-only, timeout+retries, untrusted-diff wrapping,
  differentiated fail-safe) and the env knobs with their defaults.
- **46–55 — Standard-library imports only.** `argparse, json, os, re,
  subprocess, sys, time, unicodedata, urllib.error, urllib.request`.
- **57 — `import filters`.** The local four-state classifier (loaded as a
  top-level module because the repo has no package/`__init__.py`).

### Configuration constants (59–123)
Every knob is read from the environment with a default, so the Action can tune
behaviour without code changes.
- **59–62** — `OLLAMA_URL`, `MODEL` (`qwen2.5-coder:3b`), `PROMPT_FILE`,
  `COMMENT_FILE`.
- **63–64** — `BLOCK` (70) and `REVIEW` (40) score thresholds.
- **65–73 — `MAX_CHARS` (16000).** Per-*chunk* character budget. The long
  comment warns it must be sized by the same fit math the single call relied on
  (context − prompt − output), and that the raw default overflows `NUM_CTX=4096`
  unless raised — which `fit_max_chars` later enforces.
- **74–77 — `MAX_CHUNKS` (8).** Hard cap on model calls per scan; files beyond
  it are left unscanned and floor to review. `max(1, …)` guarantees ≥1.
- **78–83 — `MAX_SECONDS` (300).** Wall-clock budget enforced alongside
  `MAX_CHUNKS`; whichever hits first stops scanning (unreached chunks floor to
  review).
- **84–88 — `LARGE_DIFF_CHARS` (200000).** Above this raw size, re-run
  `git diff` with `--unified=1` to spend budget on changes, not context.
- **89–92 — `REDUCE` ("concat").** How per-chunk results merge: deterministic
  concat, or an optional presentation-only `"llm"` rewrite of the narrative.
- **93–98 — `NUM_CTX` (4096).** Ollama context window; set explicitly so
  Ollama's small default doesn't silently truncate the prompt.
- **99–102 — `NUM_PREDICT` (768).** Hard ceiling on generated tokens — the
  primary guard against runaway generation blowing the request timeout. *(Raised
  from 512 to give the bounded schema room to finish the JSON.)*
- **103–106 — `FAIL_SAFE`.** Verdict floor on infra error, **clamped** to
  `("review","block")`; `"pass"` or anything unrecognised coerces to `review`
  (a `"pass"` floor would silently disable the fail-safe / KeyError in
  `escalate`).
- **107–111** — `REQUEST_TIMEOUT` (180), `RETRY_BACKOFF` (2), `RETRIES` (≥1, 3).
- **112–115 — `FAIL_CLOSED`.** On a protected branch, treat scan *errors* as a
  block instead of failing open to review.
- **116–118 — `INJECTION_FLOOR` (55).** Score floor when injection markers are
  found — sits in the review band so a human always looks.
- **119–123 — `CORROBORATE` (true).** Whether a would-be block gets one
  independent second look before it can block (guards against a single chunk's
  false positive compounding through the cross-chunk `max()`).

### Regexes & schemas (125–223)
- **125** — `MARKER`, the hidden HTML comment that makes the PR comment "sticky"
  (the Action greps for it to update in place).
- **131–137 — `INJECTION`.** Model-independent tripwire regex for prompt-
  injection phrases (`ignore previous instructions`, `risk_score to 0`,
  `pre-approved`, `reviewer-bot`, `system:` …). Holds even when the model is
  fooled.
- **144–148 — `INJECTION_EXEMPT`.** Paths where those very markers are
  legitimate content (this repo dogfoods itself): `samples/`, `tests/`,
  `fixtures/`, `prompts/`, and `detector/scan.py`. Checked per file so
  self-maintenance PRs don't self-trip.
- **154–163 — `HIGH_RISK_PATH`.** CI/workflow, Dockerfile, `*.sh`,
  `package.json`, `requirements.txt`, `go.mod`, `*.yml` — the usual
  exfiltration/tampering vectors, scanned first.
- **166–170 — `SIGNAL_KEYWORDS`.** Risky APIs (`eval|exec|base64|subprocess|
  os.system|urllib|requests|socket|token|secret|password|curl`); each distinct
  hit nudges a file's priority up.
- **175–189 — `REDUCE_SYSTEM` / `REDUCE_SCHEMA`.** System prompt + tiny schema
  for the optional `REDUCE="llm"` pass — presentation-only: it may only rewrite
  the merged reasoning, never invent findings or change the score.
- **195–223 — `SCHEMA`.** The JSON schema handed to Ollama's `format` option so
  the reply is grammar-constrained to the exact shape. **Field order matters:**
  `key_changes` → `suspicious_findings` → `reasoning` → `risk_score`, so the
  score is generated *after* (conditioned on) the reasoning. **Bounds** cap the
  output so a multi-file chunk can't burn `NUM_PREDICT` enumerating changes and
  truncate the JSON: `key_changes` ≤ 5 items / 120 chars each,
  `suspicious_findings` ≤ 8, `reasoning` ≤ 1200 chars. All four fields
  `required`.
- **217 — `_ZERO_WIDTH`.** Translation table stripping zero-width/BOM code
  points (an obfuscation vector).
- **219–223** — `_VERBOSE`, `_START` (monotonic clock for timing logs), and
  `_RANK` (`pass<review<block`) so fail-safe policy can only *escalate*.

### Error types & verdict helpers (226–263)
- **226–233 — `InfraError` / `ContentError`.** The two failure kinds:
  transport/availability (transient ⇒ fail open to review) vs a reply that won't
  parse (looks like evasion ⇒ distrust). Differentiating them is what lets the
  fail-safe be nuanced.
- **236–238 — `escalate(verdict, floor)`.** Returns the *more severe* of two
  verdicts via `_RANK`. Used everywhere a floor is applied — it can only raise.
- **241–258 — `apply_injection_floor(result, floor)`.** Raises a below-floor
  score up to `floor` and appends a labelled system note to the reasoning
  explaining the bump (so the shown score and the prose can't contradict). Only
  ever raises; leaves an already-high score untouched.
- **261–263 — `log(msg, force)`.** Timestamped stderr logging, gated on
  `--verbose` unless `force`.

### Diff acquisition & cleaning (266–347)
- **266–267 — `sanitize(text)`.** NFKC-normalise and strip zero-width chars
  before anything else sees the diff.
- **270–302 — `get_diff(args)`.** Either read `--diff <file>` or run
  `git diff --unified=3 {base}...HEAD`. **Critical fail-safe (288–294):** a
  non-zero git exit raises `InfraError` instead of returning `""` — otherwise a
  failed diff would look like a clean (empty) diff and silently pass; the error
  message points at the shallow-checkout cause (`fetch-depth: 0`). **296–302:**
  for very large diffs, re-diff with `--unified=1` to fit more real changes.
- **305–325 — `extract_hunks(diff)`.** Keep only `diff --git` headers, `---`/
  `+++`, `@@` hunk headers, and `+/-/ /\` lines within a hunk. Drops
  index/mode/similarity/**binary** noise so budget is spent on actual changes.
  (This is *why* binary/mode changes need `metadata_findings` — they're stripped
  here.)
- **328 — `_DIFF_GIT`.** Regex capturing the `a/…` and `b/…` paths from a
  `diff --git` header.
- **331–347 — `split_by_file(hunks)`.** Split cleaned hunks into
  `(path, file_diff)` on `diff --git` boundaries, each file kept whole; path
  taken from the `b/` side (fallback `a/`, then `"unknown"`).

### Injection & metadata scanning (350–411)
- **350–364 — `detect_injection(files)`.** True if any **non-exempt** file's
  diff contains an injection marker. Per-file so an exempt path can't trip it and
  can't mask a real one elsewhere.
- **367–411 — `metadata_findings(raw_diff)`.** Scans the **raw** diff (before
  `extract_hunks` strips them) for hunk-less, risk-bearing changes:
  `new file mode …755` (new executable), `new mode …755` (chmod +x), and
  `Binary files …`/`GIT binary patch`. Returns `(findings, binary_paths)`.
  Without this, a chmod +x on a CI script or a committed binary would reach the
  model as an empty diff and pass — this makes them visible regardless of what
  the model sees.

### Prioritisation & packing (414–466)
- **414–428 — `priority(path, file_diff)`.** Higher = scanned first.
  `+100` for a high-risk path; `+10 ×` the count of **distinct** signal keywords
  found on **added** lines only (so a file that *removes* `eval`/`subprocess` is
  not promoted — matches the prompt's "judge the `+` lines" rule).
- **431–466 — `pack(files, budget, max_chunks)`.** Greedy first-fit packing of
  whole files (highest-priority first) into ≤`max_chunks` chunks under `budget`
  chars. Returns `(chunks, overflow_files, truncated_files)`: a single file
  bigger than budget gets its own truncated chunk (`[file truncated]`); files
  that don't fit once `max_chunks` is full become `overflow` (unscanned ⇒ caller
  floors to review). Files are never split across chunks.

### The model call & parsing (469–531)
- **469–494 — `call_model(system, user, schema)`.** POST to `/api/chat` with the
  system+user messages, `stream:false`, the `format` schema, `keep_alive:-1`
  (keep the model resident between chunk calls), and options
  `temperature:0, seed:7, num_ctx, num_predict`. Any transport/JSON-envelope
  failure becomes `InfraError`. Returns the raw `message.content` string.
- **497–531 — `coerce_result(raw)`.** Parse the reply into the 4-field shape, or
  `None` if hopeless. Tries `json.loads`, then a `{…}` substring fallback.
  **Key fail-safe (515–520):** a missing or non-numeric `risk_score` returns
  `None` (⇒ `ContentError` ⇒ review) — it is **not** defaulted to 0, because a
  0 would read as a clean pass. Clamps the score to 0–100, filters findings to
  well-formed dicts, and truncates each reason to 400 chars.

### Per-chunk review & corroboration (534–591)
- **534–562 — `review_chunk(hunks, system)`.** Wrap the chunk in
  `<untrusted_diff>` tags and call the model with retries + exponential backoff.
  On success returns the parsed result; otherwise raises the *last* failure's
  kind (`ContentError` or `InfraError`) so the caller applies the right policy.
  Retrying shrinks the DoS surface — a single dropped request can't flip a scan
  to fail-safe.
- **565–591 — `corroborate(result, hunks, system)`.** A chunk that scored
  `>= BLOCK` gets one **independent second review on the same text** before it
  can block. If the second call also lands `>= BLOCK` the block stands; if it
  lands lower the chunk is demoted to `max(REVIEW, second)` — never to pass — with
  an explanatory note. A failed second call (infra/content) **keeps** the block:
  a failure must never rescue a chunk toward pass.

### Aggregation & reduce (594–678)
- **594–644 — `aggregate_results(outcomes, files_scanned, num_chunks)`.**
  Combine successful per-chunk results deterministically: score = **max** over
  chunks (worst behaviour, never an average); findings = union deduped on
  `(file, reason)`; key_changes = union deduped on the string; reasoning = only
  the narratives from chunks that had a finding or scored `>= REVIEW`, each
  prefixed with its files (else a single "No notable findings…" line). Also
  returns those notable narratives for the optional LLM reduce.
- **647–678 — `reduce_llm(result, notable_reasonings)`.** Optional
  `REDUCE="llm"` pass: one extra presentation-only call that rewrites the merged
  reasoning into one narrative. Returns `None` on any failure (caller silently
  keeps the concat prose). **Never** touches score/findings/verdict; never
  raises.

### Rendering (681–828)
- **681–690 — `verdict_of(score)` / `risk_band(score)`.** Score → verdict
  (`block`/`review`/`pass`) and → the coloured risk-band label for the comment.
- **693–703 — `cap_paths(paths, limit=20)`.** Render a capped, backticked path
  list so a repo-init listing 300 paths doesn't blow GitHub's 65 536-char comment
  limit (which would make `gh` reject the comment entirely).
- **706–828 — `render_markdown(...)`.** Builds the sticky comment. Leads with the
  hidden `MARKER`, then loud banners that must never be mistaken for a clean
  pass: bootstrap notice, infra/content fail-safe banners, the injection banner,
  coverage (scanned counts, binary-not-reviewed, overflow/truncated floors,
  excluded-by-policy, lockfiles-by-rule). Then the score line (or `n/a` when no
  chunk was scored), Key Changes, a Suspicious Findings table, and the "Why this
  score" reasoning.

### Budget fitting (831–856)
- **831–856 — `fit_max_chars(system_prompt, num_ctx, num_predict, …)`.** Derives
  the per-chunk char budget that actually fits the context window
  (`diff_tokens = num_ctx·safety − num_predict − system_tokens`, ×
  `chars_per_token`), so `MAX_CHARS` and `NUM_CTX` can't silently contradict
  each other (Ollama truncates without erroring). Raises `ValueError` if the
  prompt + output alone don't fit — a misconfig to surface loudly.

### Emit (859–903)
- **859–903 — `emit(result, verdict, …)`.** The **single exit point** for every
  path. Prints the machine-readable JSON verdict to stdout, writes `comment.md`,
  appends to `GITHUB_STEP_SUMMARY` if present, and returns the exit code
  (`1` only on `block`). Centralising exit here means no path can accidentally
  `exit 0` silently.

### `main()` — the orchestration (906–1116)
- **906–914** — parse `--diff` / `--git-base` / `--verbose`.
- **916–917** — read the system prompt from `PROMPT_FILE`.
- **919–927 — Budget reconciliation (BUG 4).** Call `fit_max_chars` and clamp
  `MAX_CHARS` down to what fits `NUM_CTX` (a smaller hand-set value is kept).
- **929–941 — Diff acquisition + git-failure fail-safe (BUG 1).** `get_diff`
  raising `InfraError` routes to the infra fail-safe (review, or block under
  `FAIL_CLOSED`), rendered with the fail-safe banner and `scored=False` — never
  a silent empty-diff pass.
- **943–947** — `sanitize`, then `metadata_findings` on the **raw** diff (BUG 2)
  *before* `extract_hunks` strips binary/mode lines.
- **949–968 — No-hunks handling.** If there are no textual hunks but metadata
  findings exist (binary/mode/exec), floor to review and show them; only a truly
  empty diff is the genuine clean pass (with a stderr note).
- **970–975** — `split_by_file`; defensive fallback to a single `("unknown", …)`
  file if no header was found.
- **977–982 — Injection tripwire** over the per-file split (exempt paths
  skipped); log if fired.
- **984–991 — `filters.classify`.** Split into `to_scan` (to the model),
  `determ_findings` (regex, no model call), `excluded_paths` (policy, no floor),
  and `lockfile_paths`.
- **993–1005 — Bootstrap mode.** If the *scannable* set is initial-import-sized,
  scan only CI/executable surfaces and force review with an honest comment.
- **1007–1012 — `pack`** the scannable files into chunks; record scanned /
  overflow / truncated counts.
- **1014–1046 — The scan loop.** For each chunk: **1020–1026** stop if past
  `MAX_SECONDS` (remaining chunks become overflow ⇒ review); **1028–1038**
  `review_chunk`, recording `infra`/`content` failure outcomes with a loud
  machine-parseable `FAILSAFE …` log line; **1044–1046** on success, run
  `corroborate` for a would-be block, then record the outcome.
- **1048–1051** — recompute `files_scanned`/`num_chunks` from *attempted* chunks
  (an early `MAX_SECONDS` break makes the pre-loop totals overcount).
- **1053–1064 — Reduce.** One successful chunk is used verbatim; otherwise
  `aggregate_results`, optionally rewriting the prose via `reduce_llm` when
  `REDUCE="llm"`.
- **1066–1072 — Cross-chunk fail-safe kind** (`infra` beats `content`);
  successful chunks still contribute findings/score even when one failed.
- **1074–1085 — Merge deterministic findings.** Fold `metadata_findings` +
  `determ_findings` into `suspicious_findings`, deduped — so the comment always
  names them even though the model never saw those files.
- **1087–1088** — apply the injection floor if markers were found.
- **1090–1092** — `scored` is true only if at least one chunk was scored (else
  the comment shows `n/a`, not a misleading `0/100`).
- **1094–1108 — Verdict + escalation ladder.** `verdict_of(score)`, then
  escalate for: infra (review, or block under fail-closed), content (review, or
  block under fail-closed), overflow/truncated (review), binary (review),
  deterministic findings (review), bootstrap (review). `escalate` guarantees
  these can only raise severity.
- **1110–1116 — Coverage + emit.** Assemble the coverage dict (adding
  `bootstrap` totals if applicable) and hand everything to `emit`, whose return
  is the process exit code.
- **1119–1120** — `sys.exit(main())`.

---

## 4. Where the "never fail open" invariant lives

Concrete places the gate refuses to pass silently — a useful map when changing
anything:

- **git failure ⇒ InfraError**, not empty diff — `get_diff` (288–294).
- **binary/mode/exec changes surfaced** even with no hunks — `metadata_findings`
  (367–411) + no-hunks branch (949–963).
- **missing/non-numeric score ⇒ None ⇒ ContentError ⇒ review**, not a default 0 —
  `coerce_result` (515–520).
- **budget overflow / truncation / bootstrap / binary ⇒ review floor** — the
  escalation ladder (1101–1108).
- **injection markers ⇒ INJECTION_FLOOR** regardless of the model's score —
  `apply_injection_floor` (241–258, applied 1087–1088).
- **a lone would-be block is re-checked**, and a failed second look keeps the
  block — `corroborate` (565–591).
- **fail-safe policy can only escalate** — `escalate` + `_RANK` (222–238).
- **`FAIL_SAFE` clamped away from `pass`** — (103–106).
- **single exit point** so nothing exits 0 by accident — `emit` (859–903).
