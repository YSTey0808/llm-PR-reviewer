#!/usr/bin/env python3
"""Generate a large, BENIGN unified diff for hand-testing detector/scan.py's
multi-chunk path (stdlib only, fully deterministic — no randomness, no network).

The default fixture is sized against scan.py's real defaults (MAX_CHARS=16000,
MAX_CHUNKS=8) so a local run splits it into several chunks and exercises every
branch of pack():
  - ~5 normal modules (~10-12 KB each)  -> greedy-packed into ~3-4 chunks.
  - 1 oversized module (> 16000 chars)  -> own chunk, truncated ("[file
    truncated]"), which floors the verdict to `review`.
  - 1 high-risk-path file (.github/workflows/ci.yml) -> shows priority() ordering
    (scanned first) in scan.py --verbose logs.

Content is deliberately benign (plain functions, no eval/exec/base64/injection
markers) so the test isolates CHUNKING mechanics, not detection scoring.

Usage:
  python tests/support/make_large_diff.py                   # -> tests/fixtures/large_chunked.diff
  python tests/support/make_large_diff.py path/to/out.diff  # custom output path
"""
import os
import sys

# tests/support/ -> tests/ -> fixtures/
TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(TESTS, "fixtures", "large_chunked.diff")


def file_diff(path, n_funcs):
    """A whole-file add: `diff --git` header + one `@@` hunk of `n_funcs` small
    benign functions, all as `+` lines. Deterministic given (path, n_funcs)."""
    body = []
    for i in range(n_funcs):
        body += [
            f"+def feature_{i}(items):",
            f'+    """Return the running total for feature {i} (benign demo code)."""',
            "+    total = 0",
            "+    for value in items:",
            f"+        total += value * {i + 1}",
            "+    return total",
            "+",
        ]
    added = len(body)
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode 100644\n"
        f"index 0000000..1111111\n"
        f"--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{added} @@\n"
    )
    return header + "\n".join(body) + "\n"


def workflow_diff():
    """A benign, high-risk-PATH file (.github/workflows) so priority() ranks it
    first — visible in scan.py --verbose ordering."""
    body = [
        "+name: CI",
        "+on: [push]",
        "+jobs:",
        "+  test:",
        "+    runs-on: ubuntu-latest",
        "+    steps:",
        "+      - uses: actions/checkout@v4",
        "+      - run: python -m pytest -q",
    ]
    path = ".github/workflows/ci.yml"
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode 100644\n"
        f"index 0000000..2222222\n"
        f"--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(body)} @@\n"
    )
    return header + "\n".join(body) + "\n"


def build():
    parts = [workflow_diff()]
    # ~5 normal modules (~11 KB each at 55 funcs) -> pack into a few chunks.
    for i in range(5):
        parts.append(file_diff(f"app/module_{i}.py", n_funcs=55))
    # 1 oversized module (> 16000 chars at 130 funcs) -> truncated in its own chunk.
    parts.append(file_diff("app/big_module.py", n_funcs=130))
    return "".join(parts)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    diff = build()
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(diff)
    print(f"wrote {out} ({len(diff)} chars)")


if __name__ == "__main__":
    main()
