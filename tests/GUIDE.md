# Tests guide

How to run and extend the detector's test suite. **Python standard library
only** — no pytest, no third-party deps, and **no running Ollama required** for
the offline suite (the model-path tests start their own fake server on an
ephemeral port).

Run everything from the repo root (`llm-PR-reviewer/`).

## Layout

The suite is split into two offline buckets by what each test needs, plus shared
support code and a separate real-model harness:

```
tests/
  unit/       pure functions — no model, network, or subprocess
  model/      the model-call path, driven through an in-process fake Ollama
  support/    shared test infra (fake server, diff generators) — not tests
  eval/       needs a REAL Ollama / dataset meta-checks — NOT in the offline run
  fixtures/   hand-written diff-shape fixtures
  run_tests.py   runs the unit + model buckets in one go
```

| File | Bucket | What it covers |
|---|---|---|
| `tests/unit/test_units.py` | unit | Pure helpers of `detector/scan.py` (sanitize, hunk extraction, injection tripwire, verdict banding, `coerce_result`, `split_by_file`, `priority`, `pack`) as plain `check()` assertions. |
| `tests/unit/test_scan.py` | unit | The same pure helpers as structured `unittest` cases (adds `render_markdown`, `apply_injection_floor`). |
| `tests/unit/test_failopen_units.py` | unit | `fit_max_chars` budget helper in isolation (BUG 4). |
| `tests/unit/test_corroborate_units.py` | unit | `corroborate()` failure paths, per-file injection exemption, `priority()` added-lines-only, and the `FAIL_SAFE` clamp (CHANGE 1–4). |
| `tests/model/test_harness.py` | model | **End-to-end**: drives `detector/scan.py` as a subprocess against the fake Ollama — transport path, retries, and both fail-safe branches. |
| `tests/model/test_failopen.py` | model | Four FAIL-OPEN regressions end-to-end: git-failure routing, binary/mode surfacing, distrusting a broken reply, and main()'s MAX_CHARS clamp. |
| `tests/model/test_corroborate.py` | model | The full corroboration loop (would-be block demoted/kept) end-to-end. |
| `tests/model/test_bigpush.py` | model | Four-state big-push handling (`filters.py` wired into `scan.py`); monkeypatches `scan.call_model` with a recorder. |
| `tests/support/fake_ollama.py` | support | Scriptable in-process fake Ollama server used by the model bucket. |
| `tests/support/make_big_diff.py` | support | Configurable synthetic repo-init diff generator (chunking stress fixture). |
| `tests/support/make_large_diff.py` | support | Fixed benign large-diff generator (writes `tests/fixtures/large_chunked.diff`). |
| `tests/eval/eval.py` | eval | Scoring harness over `samples/**` (requires a real Ollama). |
| `tests/eval/check_contamination.py` | eval | Fails if a sample's distinctive name tokens leak into `prompts/intent.md`. |
| `tests/fixtures/*.diff` | — | Hand-written diff fixtures (see below). `large_chunked.diff` is generated and gitignored. |

## Running the tests

The offline suite (unit + model) via the runner:

```bash
python tests/run_tests.py          # both buckets; exits non-zero if any file fails
python tests/run_tests.py --unit   # only tests/unit/
python tests/run_tests.py --model  # only tests/model/
```

Individual files (each is directly runnable):

```bash
python tests/unit/test_units.py                 # expect "all unit tests passed"
python tests/unit/test_scan.py -v
python tests/unit/test_failopen_units.py -v
python tests/unit/test_corroborate_units.py -v
python tests/model/test_harness.py -v
python tests/model/test_failopen.py -v
python tests/model/test_corroborate.py -v
python tests/model/test_bigpush.py -v
```

No Ollama, network, or GPU is needed for any of the above. The `tests/eval/`
harness is separate and requires a real Ollama — it is not part of `run_tests.py`.

## The fake Ollama server (`tests/support/fake_ollama.py`)

`FakeOllama` stands in for the real Ollama `/api/chat` endpoint so tests can drive
the whole detector deterministically. Use it as a context manager; point
`scan.py`'s `OLLAMA_URL` at `fake.url`. Model-bucket tests add
`tests/support/` to `sys.path`, then `from fake_ollama import FakeOllama`.

```python
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))          # tests/model
TESTS = os.path.dirname(HERE)                              # tests/
sys.path.insert(0, os.path.join(TESTS, "support"))
from fake_ollama import FakeOllama

with FakeOllama() as fake:
    fake.respond([{"risk_score": 85}])   # scripted model result(s)
    # ... run scan.py with env OLLAMA_URL=fake.url ...
    assert fake.requests                 # inspect what was sent
```

Modes (the last one set wins; each re-arms the server):

| Mode | Behaviour | Drives |
|---|---|---|
| `respond([{...}, ...])` | Return these results in order, one per call; the last entry repeats once exhausted. Missing keys are filled from `BENIGN_RESULT`, so `[{"risk_score": 85}]` is enough. | a normal scored reply |
| `garbage()` | Reply `200` with non-JSON content. | `ContentError` → `failsafe=content` |
| `http_error(code=500)` | Reply with an HTTP error status. | `InfraError` → `failsafe=infra` |
| `hang(seconds)` | Sleep before replying (set `REQUEST_TIMEOUT` below this). | client timeout → `InfraError` |
| `echo()` | Record the request and reply benign. | assert **what** was sent |
| `raw([...])` | Reply `200` with each string as the model `content` VERBATIM (no benign merge) — script valid JSON missing a field. | a broken but parseable reply |

`.requests` holds the parsed body of every POST received. Inspect
`fake.requests[i]["messages"][-1]["content"]` to see which files/hunks reached
the model.

**Note for scripted runs:** set `RETRIES=1` and `RETRY_BACKOFF=0` in the env so
one request maps to one chunk (no retry duplicates) and runs stay fast. The
model bucket's `run_scan()` helpers already do this.

## Fixtures (`tests/fixtures/`)

Small, hand-written unified diffs, each capturing a diff **shape**:

| Fixture | Shape |
|---|---|
| `binary_only.diff` | One file, `Binary files … differ`, no `@@` hunks. |
| `chmod_exec.diff` | `old mode 100644` → `new mode 100755`, no content change. |
| `new_exec.diff` | New file with `new file mode 100755` and a small hunk. |
| `lockfile_evil.diff` | `package-lock.json` with a `resolved` URL to a non-npm host; `package.json` untouched. |
| `lockfile_clean.diff` | `package-lock.json` + `package.json` both changed, all URLs `registry.npmjs.org`. |
| `injection_marker.diff` | Adds `ignore previous instructions` in an ordinary path (`src/util.py`) — trips the injection tripwire. Markers inside `samples/`/`tests/`/`prompts/` are exempt. |
| `dist_only.diff` | `dist/bundle.js` changed, no `src/` change. |

**Current behaviour these pin (before any detector change):** `extract_hunks`
keeps the `diff --git` header but drops `old/new mode` and `Binary files …`
lines. So `binary_only.diff` and `chmod_exec.diff` still reach the model, but
only the file path does — the actual mode/binary change is invisible to it.
`tests/model/test_harness.py::TestModeBinaryBlindness` locks this in.

## Big-diff generator (`tests/support/make_big_diff.py`)

Deterministic, stdlib-only generator modelling an "initial commit": N `src/`
files, M `node_modules/` files, a huge `package-lock.json`, a
`.github/workflows/ci.yml` (high-risk path), and some `*.min.js`.

```bash
python tests/support/make_big_diff.py                       # 500 files -> stdout
python tests/support/make_big_diff.py out.diff              # 500 files -> out.diff
python tests/support/make_big_diff.py --files 50 out.diff   # 50 files  -> out.diff
```

Drive `scan.py` over it end-to-end against the fake to watch chunking/priority
(`pack()`) in action — expect several chunks, high-risk paths scanned first, and
overflow files flooring the verdict to `review`:

```python
import os, sys, subprocess, json, tempfile
sys.path.insert(0, "tests/support")
from fake_ollama import FakeOllama

with FakeOllama() as fake:
    fake.respond([{"risk_score": 30}])
    env = dict(os.environ)
    env.update(OLLAMA_URL=fake.url, PROMPT_FILE="prompts/intent.md",
               COMMENT_FILE=tempfile.mktemp(suffix=".md"),
               RETRIES="1", RETRY_BACKOFF="0", REQUEST_TIMEOUT="5")
    p = subprocess.run([sys.executable, "detector/scan.py", "--diff", "out.diff"],
                       env=env, capture_output=True, text=True)
    o = json.loads(p.stdout)
    print("verdict", o["verdict"], "chunks", o["num_chunks"],
          "scanned", o["files_scanned"], "calls", len(fake.requests))
```

## Writing a new test

**Pure helper?** Add a `unittest` case to `tests/unit/test_scan.py` (or a plain
`check()` to `tests/unit/test_units.py`). No model, no subprocess.

**Needs the model-call path?** Add to the model bucket:

1. Start a `FakeOllama`, pick a mode.
2. Call `run_scan(...)` (from the model file you're extending) — it runs
   `scan.py` as a subprocess with the right env and returns the parsed JSON.
3. Assert on the parsed JSON (`score`, `verdict`, `failsafe`, `injection`, …)
   and/or on `fake.requests` for what was sent.

Both buckets are picked up automatically by `tests/run_tests.py` (it globs
`test_*.py`), so a new file needs no runner change.
