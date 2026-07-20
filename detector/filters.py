#!/usr/bin/env python3
"""
Pre-model classification for the intent gate (Python standard library only).

scan.py used to know only TWO fates for a changed file: it was scanned, or it
overflowed the budget and floored the verdict to `review`. Collapsing those is
what makes the gate useless on big pushes — "we chose not to look at
node_modules/" and "we ran out of budget before this source file" landed in the
same bucket, so every large PR floored to review forever and people stopped
reading it.

This module splits a file's fate into FOUR states:

    SCAN          -> sent to the model
    DETERMINISTIC -> a regex decides, no model call (lockfiles, hand-edited
                     build output); its findings floor the verdict, not a score
    EXCLUDED      -> not scanned BY POLICY (vendored/generated junk); named in
                     the comment; does NOT floor the verdict
    UNSCANNED     -> wanted to scan it but ran out of budget/chunks; DOES floor
                     to review (handled in scan.pack(), not here)

Design principle (shared with scan.py): every path here fails toward
`review`/`block`, never toward `pass`. When in doubt a file is scanned or
flagged, never silently dropped.
"""

import os
import posixpath
import re

# Vendored / generated / artifact junk: high-volume, low-signal text that a 3B
# model either wastes its context budget on or hallucinates over. Excluded BY
# POLICY — named in the comment, but never floors the verdict.
#
# DELIBERATELY ABSENT: config. .github/workflows/, Dockerfile, *.yml, .gitignore
# (hides files from review), .vscode/settings.json and .devcontainer/ (execute
# on a dev's machine) are the HIGHEST-risk surface, not the lowest — they must
# always be scanned, so they are never added to this list.
EXCLUDED_PATH = re.compile(
    r"(^|/)(node_modules|vendor|third_party|\.venv|__pycache__|__snapshots__"
    r"|testdata|\.terraform|Pods)/"
    r"|\.min\.js$|\.min\.css$|\.js\.map$|\.snap$|\.log$"
    r"|_pb2\.py$|\.pb\.go$|\.generated\.",
    re.IGNORECASE,
)

# Build output. Excluded ONLY when a plausible source file also changed in the
# same push (normal "rebuilt and committed the dist" churn). Changed ALONE ->
# someone hand-edited a shipped artifact with no corresponding source change,
# which is the event-stream / ua-parser-js compromise signature -> a FINDING,
# handled in classify().
BUILD_OUTPUT_PATH = re.compile(r"(^|/)(dist|build|out|target)/", re.IGNORECASE)

# Dependency lockfiles: thousands of lines of resolved hashes. Never sent to the
# model (that volume makes a small model hallucinate); scanned by the two
# regexes below instead.
LOCKFILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "Pipfile.lock",
    "uv.lock",
})

# Lockfile basename -> the manifest that MUST change alongside it. A lockfile
# that moves with no manifest change means dependencies were altered without
# being declared — the dependency-confusion signature, which the model can never
# catch because it only ever sees one chunk.
LOCKFILE_MANIFESTS = {
    "package-lock.json": ("package.json",),
    "yarn.lock": ("package.json",),
    "pnpm-lock.yaml": ("package.json",),
    "poetry.lock": ("pyproject.toml",),
    "uv.lock": ("pyproject.toml",),
    "Cargo.lock": ("Cargo.toml",),
    "go.sum": ("go.mod",),
    "composer.lock": ("composer.json",),
    "Gemfile.lock": ("Gemfile",),
    "Pipfile.lock": ("Pipfile",),
}

# Canonical package-registry domains. A resolved URL whose host is outside this
# set (suffix-matched, so subdomains like registry.npmjs.org pass under
# npmjs.org) is a finding. Extended at runtime from INTENT_GATE_REGISTRIES
# (comma-separated) for an internal Artifactory/Nexus.
_CANONICAL_HOSTS = {
    "npmjs.org", "npmjs.com", "yarnpkg.com", "pythonhosted.org", "pypi.org",
    "crates.io", "golang.org", "rubygems.org", "maven.apache.org",
    "github.com", "githubusercontent.com", "packagist.org",
}


def canonical_hosts():
    """Allowlisted registry hosts, including any from INTENT_GATE_REGISTRIES.

    Read at call time (not import) so tests and CI can set the env var per run.
    """
    hosts = set(_CANONICAL_HOSTS)
    for extra in os.environ.get("INTENT_GATE_REGISTRIES", "").split(","):
        extra = extra.strip().lower()
        if extra:
            hosts.add(extra)
    return hosts


# A push bigger than this is treated as an initial import / bootstrap: too large
# for a genuine intent review, so scan only the CI/executable surfaces, run the
# regexes, and force `review` with a comment that says so plainly.
BOOTSTRAP_FILES = int(os.environ.get("BOOTSTRAP_FILES", "60"))
BOOTSTRAP_ADDED_LINES = int(os.environ.get("BOOTSTRAP_ADDED_LINES", "3000"))

# URL in an added lockfile line. Host is group 2; scheme is group 1 (http:// on
# its own — no TLS — is a finding regardless of host).
_URL = re.compile(r"(https?)://([A-Za-z0-9._~\-]+)")
# Non-registry dependency sources: local paths and VCS refs. In a lockfile these
# mean a dependency resolves to something other than a published, hashed
# artifact — worth a human look.
_BAD_DEP = re.compile(
    r"(git\+[a-z0-9.+\-]*://"          # git+https://, git+ssh:// ...
    r"|(?<![A-Za-z])git://"
    r"|(?<![A-Za-z])ssh://"
    r"|(?<![A-Za-z0-9_])(?:file|link):(?=[./~]))",  # file:../x, link:./y
    re.IGNORECASE,
)

_MAX_LOCKFILE_FINDINGS = 25  # one poisoned lockfile must not emit thousands


def is_lockfile(path):
    """True if `path`'s basename is a known dependency lockfile."""
    return posixpath.basename(path) in LOCKFILES


def _added_lines(file_diff):
    """Added content lines ('+', not the '+++' header), leading '+' stripped."""
    for line in file_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            yield line[1:]


def _host_is_canonical(host, allow):
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allow)


def lockfile_findings(path, file_diff):
    """Regex-scan a lockfile's added lines for supply-chain red flags.

    Flags, deduped and capped:
      - a resolved/url host outside the canonical registry allowlist,
      - a plain http:// (non-TLS) resolve URL,
      - a local (file:/link:) or VCS (git+/git:/ssh:) dependency source.

    Returns [{"file", "reason"}]. Never sends anything to the model.
    """
    allow = canonical_hosts()
    findings = []
    seen = set()

    def add(key, reason):
        if key in seen or len(findings) >= _MAX_LOCKFILE_FINDINGS:
            return
        seen.add(key)
        findings.append({"file": path, "reason": reason})

    for line in _added_lines(file_diff):
        for scheme, host in _URL.findall(line):
            if scheme.lower() == "http":
                add(("http", host.lower()),
                    f"Lockfile resolves a dependency over plain HTTP (no TLS): "
                    f"http://{host} — vulnerable to tampering in transit.")
            if not _host_is_canonical(host, allow):
                add(("host", host.lower()),
                    f"Lockfile resolves a dependency from a non-canonical host "
                    f"`{host}`, outside the registry allowlist (set "
                    f"INTENT_GATE_REGISTRIES if this is an internal mirror).")
        if _BAD_DEP.search(line):
            add(("dep", line.strip()[:80]),
                "Lockfile pins a dependency to a local path or VCS ref "
                "(file:/link:/git+/ssh:), not a published registry artifact: "
                f"{line.strip()[:120]}")
    return findings


def lockfile_without_manifest(files):
    """A lockfile changed with no matching manifest change -> a finding.

    Dependency-confusion signature: dependencies moved without being declared in
    the manifest the developer actually reviews. The model can NEVER catch this
    because it only ever sees one chunk at a time. Manifest presence is checked
    in the SAME directory as the lockfile.
    """
    changed = {(posixpath.dirname(p), posixpath.basename(p)) for p, _ in files}
    findings = []
    for path, _ in files:
        base = posixpath.basename(path)
        manifests = LOCKFILE_MANIFESTS.get(base)
        if not manifests:
            continue
        d = posixpath.dirname(path)
        if not any((d, m) in changed for m in manifests):
            findings.append({
                "file": path,
                "reason": f"Lockfile changed with no matching change to "
                          f"{' or '.join(manifests)} in the same directory — "
                          f"dependencies moved without being declared "
                          f"(dependency-confusion signature).",
            })
    return findings


def classify(files):
    """Split split_by_file() output into the four fates.

    Returns (to_scan, determ_findings, excluded_paths, lockfile_paths):
      - to_scan: [(path, file_diff)] to hand to the model (via pack()).
      - determ_findings: [{"file", "reason"}] decided by regex, no model call.
      - excluded_paths: not scanned by policy; named in the comment; NO floor.
      - lockfile_paths: lockfiles handled deterministically (never to the model).
    """
    to_scan = []
    determ_findings = []
    excluded_paths = []
    lockfile_paths = []
    build_files = []
    source_present = False

    for path, fdiff in files:
        if is_lockfile(path):
            lockfile_paths.append(path)
            determ_findings.extend(lockfile_findings(path, fdiff))
        elif EXCLUDED_PATH.search(path):
            excluded_paths.append(path)
        elif BUILD_OUTPUT_PATH.search(path):
            build_files.append((path, fdiff))
        else:
            source_present = True
            to_scan.append((path, fdiff))

    # Build output: churn when real source also changed (exclude, no floor);
    # a hand-edited shipped artifact when it changed ALONE (a finding).
    for path, _fdiff in build_files:
        if source_present:
            excluded_paths.append(path)
        else:
            determ_findings.append({
                "file": path,
                "reason": "Build output changed with no corresponding source "
                          "change — a shipped artifact was hand-edited "
                          "(event-stream / ua-parser-js compromise signature).",
            })

    determ_findings.extend(lockfile_without_manifest(files))
    return to_scan, determ_findings, excluded_paths, lockfile_paths


def count_added_lines(files):
    """Total added content lines across (path, file_diff) pairs."""
    return sum(1 for _p, d in files for _ in _added_lines(d))


def is_bootstrap(scannable):
    """True if the SCANNABLE set is an initial-import-sized push.

    Called on the post-classify `to_scan` set, not the raw file list, so a
    4000-line package-lock.json bump or a node_modules/ dump (both excluded from
    to_scan) can't false-trigger bootstrap mode — only a genuine large import of
    real source files does.
    """
    if len(scannable) > BOOTSTRAP_FILES:
        return True
    return count_added_lines(scannable) > BOOTSTRAP_ADDED_LINES
