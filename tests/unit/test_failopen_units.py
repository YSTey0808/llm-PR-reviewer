#!/usr/bin/env python3
"""Pure-function unit tests split out of the fail-open regression suite
(stdlib unittest only — no model, network, or subprocess).

These cover BUG 4's helper in isolation: fit_max_chars derives a char budget
that fits NUM_CTX and raises when the prompt + reserved output cannot fit. The
end-to-end half — git-failure routing, binary/mode surfacing, distrusting a
broken reply, and main()'s MAX_CHARS clamp — lives in tests/model/test_failopen.py.

Run:  python tests/unit/test_failopen_units.py -v
"""

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
SCAN = os.path.join(ROOT, "detector", "scan.py")

# Load scan.py by path (no package/__init__.py) for the fit_max_chars unit test;
# detector/ on sys.path so scan.py's own `import filters` resolves.
sys.path.insert(0, os.path.join(ROOT, "detector"))
_spec = importlib.util.spec_from_file_location("scan", SCAN)
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


# ---- BUG 4: MAX_CHARS must be derived to fit NUM_CTX -------------------------

class TestFitMaxChars(unittest.TestCase):
    def test_budget_is_positive_and_well_under_default_max_chars(self):
        budget = scan.fit_max_chars("x" * 4800, 4096, 512)
        self.assertGreater(budget, 0)
        self.assertLess(budget, 16000)

    def test_raises_when_prompt_and_output_do_not_fit(self):
        with self.assertRaises(ValueError):
            scan.fit_max_chars("x" * 100000, 4096, 512)


if __name__ == "__main__":
    unittest.main()
