"""The console's text state: line, history, scrollback, completion.

THERE IS NO PYTHON ORACLE. The Stage 4.5 reference has a command registry and a
dispatcher and no UI, so there is no line editor to differential against. The
harness's named cases are the specification; this file runs them and pins the
handful of behaviours a later "simplification" would most plausibly break.

The UTF-8 cases are not decoration. The research measured WM_CHAR arriving as
UTF-16 including Cyrillic -- the toggle key itself types a Cyrillic letter on a
Russian layout -- so a cursor that could land between the bytes of a character
is a real way to produce invalid UTF-8, which the bridge's escaper would then
replace with U+FFFD: corruption laundered into validity.
"""
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import nativebuild as nb                                           # noqa: E402


def build():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "console_line_harness.cpp")],
        "console_line_harness.exe")


class TheNamedCasesPass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build())
        cls.lines = cls.result.stdout.splitlines()

    def test_every_case_passed(self):
        self.assertEqual([], [line for line in self.lines if "[FAIL]" in line],
                         self.result.stdout)

    def test_the_harness_reported_success(self):
        self.assertTrue(json.loads(self.lines[-1])["ok"], self.result.stdout)

    def test_the_cases_actually_ran(self):
        """A harness that printed nothing would pass the two checks above."""
        passed = [line for line in self.lines if "[PASS]" in line]
        self.assertGreater(len(passed), 40, self.result.stdout)


class TheSpecificationIsCoveredByName(unittest.TestCase):
    """Each promise this module makes has a case that would catch its loss."""

    @classmethod
    def setUpClass(cls):
        cls.text = nb.run(build()).stdout

    def test_utf8_editing_is_covered(self):
        for promise in ("Backspace removes the whole character, not one byte",
                        "Right steps OVER a multi-byte character",
                        "the pair completes into one 4-byte character"):
            with self.subTest(promise=promise):
                self.assertIn(promise, self.text)

    def test_history_walking_is_covered(self):
        for promise in ("the same command twice in a row is one history entry",
                        "stops at the oldest rather than wrapping",
                        "Down past the newest leaves an EMPTY line"):
            with self.subTest(promise=promise):
                self.assertIn(promise, self.text)

    def test_completion_limits_are_covered(self):
        for promise in ("completes only as far as they agree",
                        "a prefix nothing matches changes nothing",
                        "does not touch a line that already has an argument"):
            with self.subTest(promise=promise):
                self.assertIn(promise, self.text)

    def test_scrolling_bounds_are_covered(self):
        for promise in ("scrolling past the top stops at the oldest",
                        "new output pins the view back to the bottom",
                        "it is the OLDEST that were dropped"):
            with self.subTest(promise=promise):
                self.assertIn(promise, self.text)


if __name__ == "__main__":
    unittest.main()
