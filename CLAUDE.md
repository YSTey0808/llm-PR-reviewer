# Working rules for this repo

## Do not execute

- Do NOT run tests, python, pytest, or unittest. The human runs them.
- Do NOT run ollama, curl, or any network command.
- Do NOT run scan.py to "verify" anything.
- Write the code, write the tests, stop. Report the command for me to run.

## Do not explore

- Read ONLY the files named in the prompt. No repo-wide grep/find/ls.
- Do not re-read a file you've already read this session.
- Do not read samples/\*.diff unless explicitly told to.

## Output style

- No summaries of what you're about to do. Just do it.
- No recap of the code you just wrote — I can read the diff.
- End with: files changed (one line each) + the exact command to run.

## Repo constraints

- Python 3, standard library ONLY. No pip, no third-party imports. Ever.
- Design principle: a failure or manipulation must NEVER silently open the gate.
  Any new code path must fail toward `review`/`block`, never toward `pass`.
