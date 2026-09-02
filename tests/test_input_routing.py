"""The key router: who gets a key, and who is denied it.

THERE IS NO PYTHON ORACLE. tools/modplatform/input_actions.py is a declaration
registry -- it names actions and owns them -- and says in its own docstring that
no engine path delivers them. Routing is new in this stage, so the harness's
named cases are the specification and this file pins the two rules that would be
most tempting to "simplify" later:

  * an up whose down the engine already saw is ALWAYS forwarded, or that key
    stays held down inside the game;
  * the toggle key's own character is swallowed, or the key that opens the
    console types itself into it.

Both were written into research/evidence/STAGE8-INPUT/preregistration.md before
the first measurement.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import nativebuild as nb                                           # noqa: E402

WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x0100, 0x0101, 0x0102
VK_OEM_3, VK_RETURN, VK_ESCAPE = 0xC0, 0x0D, 0x1B


def build():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "input_routing_harness.cpp")],
        "input_routing_harness.exe")


def trace(messages):
    """Feed (message, wparam) pairs through the router and read the decisions."""
    script = "\n".join("%d %d" % pair for pair in messages) + "\n"
    result = subprocess.run([build(), "--trace"], input=script,
                            capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout)


class TheNamedCasesPass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build())

    def test_every_case_passed(self):
        self.assertEqual(
            [], [line for line in self.result.stdout.splitlines()
                 if "[FAIL]" in line], self.result.stdout)

    def test_the_harness_reported_success(self):
        verdict = json.loads(self.result.stdout.splitlines()[-1])
        self.assertTrue(verdict["ok"], self.result.stdout)


class AClosedConsoleIsNotAKeylogger(unittest.TestCase):
    """The privacy boundary registered before the first keystroke was read."""

    def test_nothing_but_the_toggle_is_read_while_closed(self):
        decisions = trace([(WM_KEYDOWN, ord("S")), (WM_CHAR, ord("s")),
                           (WM_KEYUP, ord("S")), (WM_CHAR, ord("x"))])
        for decision in decisions:
            with self.subTest(message=decision["message"]):
                self.assertEqual("nothing", decision["action"])
                self.assertTrue(decision["forward"])


class TheKeyUpRule(unittest.TestCase):

    def test_a_key_held_across_the_open_still_gets_its_up(self):
        decisions = trace([
            (WM_KEYDOWN, ord("W")),        # held before the console opened
            (WM_KEYDOWN, VK_OEM_3),        # console opens mid-hold
            (WM_CHAR, 0x60),
            (WM_KEYUP, VK_OEM_3),
            (WM_KEYUP, ord("W")),          # must reach the game
        ])
        self.assertTrue(decisions[0]["forward"], "the down went to the game")
        self.assertTrue(decisions[-1]["forward"],
                        "its up must too, or the character keeps walking")

    def test_a_key_pressed_while_open_is_swallowed_at_both_ends(self):
        decisions = trace([
            (WM_KEYDOWN, VK_OEM_3), (WM_CHAR, 0x60), (WM_KEYUP, VK_OEM_3),
            (WM_KEYDOWN, ord("W")), (WM_KEYUP, ord("W")),
        ])
        self.assertFalse(decisions[-2]["forward"])
        self.assertFalse(decisions[-1]["forward"])
        self.assertEqual(0, decisions[-1]["held"], "nothing is left held down")

    def test_closing_does_not_strand_a_key(self):
        decisions = trace([
            (WM_KEYDOWN, VK_OEM_3), (WM_CHAR, 0x60), (WM_KEYUP, VK_OEM_3),
            (WM_KEYDOWN, ord("A")),        # swallowed
            (WM_KEYDOWN, VK_OEM_3), (WM_CHAR, 0x60), (WM_KEYUP, VK_OEM_3),
            (WM_KEYUP, ord("A")),          # still ours, even though closed
        ])
        self.assertFalse(decisions[-1]["forward"])
        self.assertEqual(0, decisions[-1]["held"])


class TheToggle(unittest.TestCase):

    def test_the_toggle_types_nothing_into_the_console_it_opened(self):
        for character, layout in ((0x60, "US backquote"), (0x0451, "RU yo")):
            with self.subTest(layout=layout):
                decisions = trace([(WM_KEYDOWN, VK_OEM_3), (WM_CHAR, character)])
                self.assertEqual("open", decisions[0]["action"])
                self.assertEqual("swallowed_char", decisions[1]["action"])
                self.assertFalse(decisions[1]["forward"])

    def test_escape_closes_and_the_game_does_not_get_it(self):
        decisions = trace([(WM_KEYDOWN, VK_OEM_3), (WM_CHAR, 0x60),
                           (WM_KEYUP, VK_OEM_3), (WM_KEYDOWN, VK_ESCAPE)])
        self.assertEqual("close", decisions[-1]["action"])
        self.assertFalse(decisions[-1]["forward"],
                         "otherwise closing the console opens the pause menu")


class ShiftIsPreservedWhereSlateWouldHaveLostIt(unittest.TestCase):
    """The measured difference that chose this mechanism over the Slate one."""

    def test_a_letter_and_its_capital_are_different_characters(self):
        decisions = trace([(WM_KEYDOWN, VK_OEM_3), (WM_CHAR, 0x60),
                           (WM_KEYUP, VK_OEM_3),
                           (WM_CHAR, 0x0444),      # Cyrillic ef
                           (WM_CHAR, 0x0424)])     # its capital
        self.assertEqual("text", decisions[-2]["action"])
        self.assertEqual(0x0444, decisions[-2]["character"])
        self.assertEqual(0x0424, decisions[-1]["character"])
        self.assertNotEqual(decisions[-2]["character"], decisions[-1]["character"])


if __name__ == "__main__":
    unittest.main()
