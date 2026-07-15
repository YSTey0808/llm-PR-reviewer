# Tests guide

How to run and extend the detector's test suite. **Python standard library
only** — no pytest, no third-party deps, and **no running Ollama required**
(the end-to-end tests start their own fake server on an ephemeral port).

Run everything from the repo root (`llm-PR-reviewer/`).

## What's here

| File | What it covers |
|---|---|
| `tests/unit_test.py` | Pure helpers of `detector/scan.py` (sanitize, hunk extraction, injection tripwire, verdict banding, `coerce_result`, `split_by_file`, `priority`, `pack`) as plain `check()` assertions. |
| `tests/test_scan.py` | The same pure helpers as structured `unittest` cases. |
| `tests/test_harness.py` | **End-to-end**: drives `detector/scan.py` as a subprocess against a fake Ollama server — the transport path, retries, and both fail-safe branches. |
| `tests/fake_ollama.py` | Scriptable in-process fake Ollama server used by `test_harness.py`. |
| `tests/fixtures/*.diff` | Hand-written diff fixtures (see below). `large_chunked.diff` is generated and gitignored. |
| `tests/make_big_diff.py` | Configurable synthetic repo-init diff generator (chunking stress fixture). |
| `tests/make_large_diff.py` | Fixed benign large-diff generator (writes `tests/fixtures/large_chunked.diff`). |
| `tests/eval.py` | Scoring harness over `samples/**` (requires a real Ollama; not part of the offline suite). |

## Running the tests

```bash
python tests/test_harness.py -v     # end-to-end (fake server); expect "Ran 9 tests ... OK"
python tests/test_scan.py -v        # pure-helper unittest; expect "Ran 19 tests ... OK"
python tests/unit_test.py           # pure-helper checks; expect "all unit tests passed"
```

All three in one go:

```bash
python tests/test_harness.py && python tests/test_scan.py && python tests/unit_test.py
```

No Ollama, network, or GPU is needed for any of the above.

## The fake Ollama server (`fake_ollama.py`)

`FakeOllama` stands in for the real Ollama `/api/chat` endpoint so tests can drive
the whole detector deterministically. Use it as a context manager; point
`scan.py`'s `OLLAMA_URL` at `fake.url`.

```python
from fake_ollama import FakeOllama

with FakeOllama() as fake:
    fake.respond([{"risk_score": 85}])   # scripted model result(s)
    # ... run scan.py with env OLLAMA_URL=fake.url ...
    assert fake.requests                 # inspect what was sent to the model
```

Modes (the last one set wins; each re-arms the server):

| Mode | Behaviour | Drives |
|---|---|---|
| `respond([{...}, ...])` | Return these results in order, one per call; the last entry repeats once exhausted. Missing keys are filled from `BENIGN_RESULT`, so `[{"risk_score": 85}]` is enough. | a normal scored reply |
| `garbage()` | Reply `200` with non-JSON content. | `ContentError` → `failsafe=content` |
| `http_error(code=500)` | Reply with an HTTP error status. | `InfraError` → `failsafe=infra` |
| `hang(seconds)` | Sleep before replying (set `REQUEST_TIMEOUT` below this). | client timeout → `InfraError` |
| `echo()` | Record the request and reply benign. | assert **what** was sent |

`.requests` holds the parsed body of every POST received. Inspect
`fake.requests[i]["messages"][-1]["content"]` to see which files/hunks reached
the model.

**Note for scripted runs:** set `RETRIES=1` and `RETRY_BACKOFF=0` in the env so
one request maps to one chunk (no retry duplicates) and runs stay fast.
`test_harness.py`'s `run_scan()` helper already does this.

## Fixtures (`tests/fixtures/`)

Small, hand-written unified diffs, each capturing a diff **shape**:

| Fixture | Shape |
|---|---|
| `binary_only.diff` | One file, `Binary files … differ`, no `@@` hunks. |
| `chmod_exec.diff` | `old mode 100644` → `new mode 100755`, no content change. |
| `new_exec.diff` | New file with `new file mode 100755` and a small hunk. |
| `lockfile_evil.diff` | `package-lock.json` with a `resolved` URL to a non-npm host; `package.json` untouched. |
| `lockfile_clean.diff` | `package-lock.json` + `package.json` both changed, all URLs `registry.npmjs.org`. |
| `injection_in_sample.diff` | Adds `ignore previous instructions` inside `samples/malicious/` (trips the injection tripwire). |
| `dist_only.diff` | `dist/bundle.js` changed, no `src/` change. |

**Current behaviour these pin (before any detector change):** `extract_hunks`
keeps the `diff --git` header but drops `old/new mode` and `Binary files …`
lines. So `binary_only.diff` and `chmod_exec.diff` still reach the model, but
only the file path does — the actual mode/binary change is invisible to it.
`test_harness.py::TestModeBinaryBlindness` locks this in.

## Big-diff generator (`make_big_diff.py`)

Deterministic, stdlib-only generator modelling an "initial commit": N `src/`
files, M `node_modules/` files, a huge `package-lock.json`, a
`.github/workflows/ci.yml` (high-risk path), and some `*.min.js`.

```bash
python tests/make_big_diff.py                     # 500 files -> stdout
python tests/make_big_diff.py out.diff            # 500 files -> out.diff
python tests/make_big_diff.py --files 50 out.diff  # 50 files  -> out.diff
```

Drive `scan.py` over it end-to-end against the fake to watch chunking/priority
(`pack()`) in action — expect several chunks, high-risk paths scanned first, and
overflow files flooring the verdict to `review`:

```python
import os, sys, subprocess, json, tempfile
sys.path.insert(0, "tests")
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

## Writing a new end-to-end test

1. Start a `FakeOllama`, pick a mode.
2. Call `run_scan(fake.url, "<fixture>.diff")` (from `test_harness.py`) — it runs
   `scan.py` as a subprocess with the right env and returns `(json, exit_code)`.
3. Assert on the parsed JSON (`score`, `verdict`, `failsafe`, `injection`, …)
   and/or on `fake.requests` for what was sent.
