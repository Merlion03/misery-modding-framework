"""The console UI is a frontend client of the SAME command engine.

The window, the painting and the window-procedure attach need a game and are
covered by the manual acceptance pass. What this covers is the part that could
silently rot without one: that ConsoleUi still reaches the real registry through
console_backend, rather than a second registry, a stub, or a copy of the
envelope format that would drift from the ABI's.

The check is a link, not a mock. If someone gave the UI its own command list to
make a build go green, this stops linking against the engine that answers
MbConsoleTable::run and the test fails.
"""
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import nativebuild as nb                                           # noqa: E402

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")


def build():
    sources = [os.path.join(REPO, "runtime", "tests", "console_ui_link_check.cpp")]
    sources += [os.path.join(INTERNAL, name) for name in
                ("InputSource.cpp", "ConsoleUi.cpp", "BridgeTables.cpp",
                 "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
                 "ModDiscovery.cpp")]
    return nb.build_exe(sources, "console_ui_link_check.exe",
                        extra="user32.lib gdi32.lib")


class TheUiLinksAgainstTheRealEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build())
        cls.verdict = json.loads(cls.result.stdout.strip().splitlines()[-1])

    def test_it_links_and_every_assertion_held(self):
        self.assertTrue(self.verdict["ok"], self.result.stdout)
        self.assertEqual(0, self.verdict["failures"], self.result.stdout)

    def test_the_registry_it_sees_is_the_one_with_the_builtins(self):
        # 14 builtins are declared by the bridge before any mod registers
        # anything. A UI with its own list would not see them.
        self.assertEqual(14, self.verdict["commands"], self.result.stdout)

    def test_the_default_toggle_is_the_key_the_research_measured(self):
        # VK_OEM_3: backquote/tilde on the US layout, Cyrillic yo on the Russian
        # one -- the same virtual key, which is why one default covers both.
        self.assertEqual(0xC0, self.verdict["toggle_key"])


class NothingIsAttachedUntilItIsStarted(unittest.TestCase):
    """A module that attached a window procedure on load would be a surprise."""

    def test_the_link_check_reports_a_clean_initial_state(self):
        result = nb.run(build())
        verdict = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(verdict["ok"], result.stdout)


if __name__ == "__main__":
    unittest.main()
