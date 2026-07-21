#!/usr/bin/env python3
"""
Contamination check for the eval set (Python standard library only).

The eval in tests/eval/eval.py is only meaningful if the system prompt does NOT
contain the answers. It is easy to "improve accuracy" by writing each sample's
scenario and expected score straight into prompts/intent.md — then the model is
recalling the key, not judging the diff. This test makes that failure LOUD: it
tokenises every sample's file name and flags overlap with the whole prompt, and
exits non-zero when a sample's distinctive tokens appear in the prompt.

Approach: whole-file token count. For each sample basename we take the tokens
that are NOT generic security/rubric vocabulary (EXCLUSION) and check whether
they show up anywhere in prompts/intent.md. A hit means the prompt names that
specific sample — contamination.

Inherent limitation (accepted, by design of a whole-file token count): samples
whose names are built ENTIRELY from unavoidable vocabulary — config_from_env,
dependency_bump, auth_backdoor, env_exfil — cannot be policed here. Any intent
prompt must legitimately contain "config", "env", "dependency", "auth",
"backdoor", "exfiltration", so those tokens live in EXCLUSION and the test would
be permanently red otherwise. This check therefore polices the DISTINCTIVE leak
tokens (e.g. "healthcheck", "rename", and any future sample-specific word);
scenario-level leaks phrased purely in generic vocabulary are out of its reach.

This is a test: it fails toward "contaminated" (exit 1), never silently green.

Run:
  python3 tests/eval/check_contamination.py
"""

import os
import re
import sys

# tests/eval/ -> tests/ -> repo root
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(ROOT, "samples")
PROMPT = os.path.join(ROOT, "prompts", "intent.md")

# A sample is contaminated when at least this many of its distinctive tokens
# appear in the prompt. 1 = the prompt names the sample at all.
THRESHOLD = 1

# Minimum token length considered. Short tokens ("api", "url", "ci") are noise.
MIN_LEN = 4

# Generic security / rubric / dev vocabulary that ANY intent prompt legitimately
# contains, so overlap on these is not evidence of contamination. Kept flat and
# explicit rather than clever: this is the knob you tune when adding samples.
EXCLUSION = {
    # English stopwords / connectives that survive the len>=4 filter
    "from", "with", "that", "this", "into", "your", "when", "then", "here",
    # malicious-intent category vocabulary (prompts/intent.md must name these)
    "backdoor", "exfil", "exfill", "exfiltration", "injection", "inject",
    "obfuscation", "obfuscated", "eval", "exec", "subprocess", "socket",
    "network", "curl", "base64", "reverse", "shell", "logic", "bomb", "attack",
    "leak", "postinstall",
    # secrets / auth / config vocabulary
    "secret", "secrets", "credential", "credentials", "token", "tokens",
    "password", "hash", "hashing", "keys", "authorized", "auth", "config",
    "configuration", "environment",  # note: bare "env" is < MIN_LEN
    "dependency", "dependencies", "version", "bump",
    # benign / infra vocabulary the rubric and FP-reduction list use
    "documented", "call", "calls", "service", "comment", "logging", "refactor",
    "test", "tests", "fixture", "fixtures", "workflow", "localhost",
    # multi-word sample name fragments that are generic on their own
    "multi", "file", "char", "code", "charcode", "npm",
}


def tokens(text):
    """Lowercase alphanumeric tokens (split on any non-alnum boundary)."""
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def sample_basenames():
    names = []
    for label in ("benign", "malicious"):
        d = os.path.join(SAMPLES, label)
        for name in sorted(os.listdir(d)):
            if name.endswith(".diff"):
                names.append((label, name[: -len(".diff")]))
    return names


def main():
    with open(PROMPT, encoding="utf-8") as fh:
        prompt_text = fh.read().lower()
    prompt_tokens = tokens(prompt_text)
    # Collapsed alnum-only form so a hyphen/space-joined name still matches:
    # "healthcheck" is a substring of "health-check" -> "healthcheck".
    collapsed = re.sub(r"[^a-z0-9]", "", prompt_text)

    rows = []          # (label, sample, sorted(distinctive), sorted(overlap))
    contaminated = []
    for label, sample in sample_basenames():
        distinctive = {t for t in tokens(sample)
                       if len(t) >= MIN_LEN and t not in EXCLUSION}
        overlap = {t for t in distinctive
                   if t in prompt_tokens or t in collapsed}
        rows.append((label, sample, sorted(distinctive), sorted(overlap)))
        if len(overlap) >= THRESHOLD:
            contaminated.append((sample, sorted(overlap)))

    print(f"{'sample':40} {'distinctive tokens':28} overlap with prompt")
    print("-" * 92)
    for label, sample, distinctive, overlap in rows:
        rel = f"{label}/{sample}"
        mark = "  <-- CONTAMINATED" if overlap else ""
        print(f"{rel:40} {', '.join(distinctive) or '-':28} "
              f"{', '.join(overlap) or '-'}{mark}")
    print("-" * 92)

    if contaminated:
        print(f"\nFAIL: {len(contaminated)} sample(s) named in the prompt "
              f"(the eval is contaminated):", file=sys.stderr)
        for sample, overlap in contaminated:
            print(f"  - {sample}: {', '.join(overlap)}", file=sys.stderr)
        print("\nRemove the sample-specific scenario/score from prompts/intent.md.",
              file=sys.stderr)
        return 1
    print("\nOK: no sample's distinctive tokens appear in the prompt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
