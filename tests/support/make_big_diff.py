#!/usr/bin/env python3
"""Generate a large, synthetic *repo-init* unified diff for stress-testing
detector/scan.py's chunking / prioritisation path (stdlib only, deterministic —
no randomness, no network).

Unlike tests/support/make_large_diff.py (a fixed ~75 KB benign fixture), this is a
CONFIGURABLE generator modelling the shape of a real "initial commit" of a
JavaScript/Python repo:

  - N source files under src/            (the code you actually want reviewed)
  - M vendored files under node_modules/ (noise that should rank LOW)
  - one huge package-lock.json           (a single oversize file -> truncated)
  - a .github/workflows/ci.yml           (high-risk PATH -> scanned FIRST)
  - several *.min.js                      (minified bundles -> low priority)

The mix lets a run exercise pack()/priority(): high-risk paths first, oversize
files truncated, low-priority vendored files overflowing past MAX_CHUNKS. Content
is benign (plain functions, no eval/exec/injection markers) so the harness
isolates CHUNKING mechanics, not detection scoring.

Usage:
  python tests/support/make_big_diff.py                     # 500 files -> stdout
  python tests/support/make_big_diff.py out.diff            # 500 files -> out.diff
  python tests/support/make_big_diff.py --files 50 out.diff  # 50 files -> out.diff
"""
import argparse
import sys


def _new_file(path, lines):
    """A whole-file add: `diff --git` header + one `@@` hunk, all `+` lines.
    Mirrors the header style in tests/support/make_large_diff.py."""
    added = len(lines)
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode 100644\n"
        f"index 0000000..1111111\n"
        f"--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{added} @@\n"
    )
    return header + "".join(f"+{line}\n" for line in lines)


def _source_file(i):
    lines = [
        f"def feature_{i}(items):",
        f'    """Return the running total for feature {i} (benign demo code)."""',
        "    total = 0",
        "    for value in items:",
        f"        total += value * {i + 1}",
        "    return total",
        "",
    ]
    return _new_file(f"src/module_{i}.py", lines)


def _node_modules_file(i):
    lines = [
        f"module.exports = function pkg{i}(x) {{",
        f"  return x + {i};",
        "};",
    ]
    return _new_file(f"node_modules/pkg{i}/index.js", lines)


def _min_js_file(i):
    # A single dense minified line, as real *.min.js bundles look.
    body = ";".join(f"var a{j}={j}" for j in range(40))
    return _new_file(f"dist/bundle_{i}.min.js", [f"!function(){{{body}}}();"])


def _workflow_file():
    lines = [
        "name: CI",
        "on: [push]",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - run: python -m pytest -q",
    ]
    return _new_file(".github/workflows/ci.yml", lines)


def _package_lock(entries):
    """A single huge package-lock.json add (one oversize file)."""
    lines = ["{", '  "name": "big-repo",', '  "lockfileVersion": 3,',
             '  "packages": {']
    for i in range(entries):
        lines += [
            f'    "node_modules/pkg{i}": {{',
            '      "version": "1.0.0",',
            f'      "resolved": "https://registry.npmjs.org/pkg{i}/-/pkg{i}-1.0.0.tgz",',
            f'      "integrity": "sha512-fake{i}"',
            "    },",
        ]
    lines += ["  }", "}"]
    return _new_file("package-lock.json", lines)


def build(n_files):
    """Assemble a repo-init diff of roughly `n_files` files.

    Budget split (deterministic): ~40% src, ~50% node_modules, a handful of
    *.min.js, plus one workflow and one huge package-lock.json.
    """
    n_files = max(4, n_files)
    n_src = max(1, int(n_files * 0.40))
    n_min = max(1, min(5, n_files // 50 + 1))
    fixed = 2                                    # workflow + package-lock.json
    n_node = max(1, n_files - n_src - n_min - fixed)
    lock_entries = max(50, n_node)              # make the lockfile genuinely huge

    parts = [_workflow_file()]                  # high-risk path first in output
    parts += [_source_file(i) for i in range(n_src)]
    parts += [_node_modules_file(i) for i in range(n_node)]
    parts += [_min_js_file(i) for i in range(n_min)]
    parts.append(_package_lock(lock_entries))
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", nargs="?", help="output path (default: stdout)")
    ap.add_argument("--files", type=int, default=500,
                    help="approximate total number of files (default 500)")
    args = ap.parse_args()

    diff = build(args.files)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(diff)
        print(f"wrote {args.out} ({len(diff)} chars, ~{args.files} files)",
              file=sys.stderr)
    else:
        sys.stdout.write(diff)


if __name__ == "__main__":
    main()
