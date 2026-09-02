"""The bridge's reply arena refuses oversized values instead of inventing one.

The arena backs every out-string the bridge returns. Its previous Put() answered
an oversized value with the literal "<detail too long>" and had no way to tell
the caller, and every caller was a success path -- so the call returned
MB_STATUS_OK carrying seventeen bytes that were not the document its signature
promised. A confident wrong answer, which is the failure mode this project
guards hardest against.

The harness builds itself here rather than being skipped when absent: a test
that quietly does not run is worse than no test.
"""
import json
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import nativebuild as nb                                           # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_no_mod_specific_core import strip_comments                # noqa: E402


class ReplyArenaFailsClosed(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        exe = nb.build_exe(
            [os.path.join(REPO, "runtime", "tests", "arena_harness.cpp")],
            "arena_harness.exe")
        cls.result = nb.run(exe)
        cls.lines = cls.result.stdout.splitlines()

    def test_every_case_passed(self):
        failed = [ln for ln in self.lines if "[FAIL]" in ln]
        self.assertEqual([], failed)

    def test_the_harness_reported_success(self):
        verdict = json.loads(self.lines[-1])
        self.assertTrue(verdict["ok"], self.result.stdout)
        self.assertEqual(0, verdict["failures"])


class NoSuccessPathCanReturnTheSentinel(unittest.TestCase):
    """The old shape must be unreachable, not merely unused.

    Put() was removed rather than deprecated so the compiler, not a reviewer,
    finds any caller still expecting a sentinel. This asserts the removal held
    and that the one remaining sentinel user is the failure reporter itself.
    """

    def setUp(self):
        internal = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
        # Comments are stripped, reusing the scanner the mod-specificity guard
        # already uses: prose that NAMES the old sentinel while explaining why
        # it is gone must not read as a use of it.
        self.sources = {}
        for name in ("BridgeCore.h", "BridgeTables.cpp"):
            with open(os.path.join(internal, name), encoding="utf-8") as handle:
                self.sources[name] = strip_comments(handle.read(),
                                                    os.path.splitext(name)[1])

    def test_the_old_put_is_gone(self):
        for name, text in self.sources.items():
            self.assertNotIn("ThreadArena().Put(", text, name)

    def test_the_sentinel_is_only_reachable_through_the_failure_reporter(self):
        core = self.sources["BridgeCore.h"]
        # The literal appears once, inside PutOrSentinel.
        self.assertEqual(1, core.count('"<detail too long>"'))
        users = re.findall(r"(\w+)\(\)\.PutOrSentinel\(", core)
        self.assertEqual({"ThreadArena"}, set(users))
        # ...and every one of those calls is inside Fail().
        fail_body = core[core.index("MbStatus Fail("):]
        fail_body = fail_body[:fail_body.index("\n}\n")]
        self.assertEqual(core.count("PutOrSentinel("),
                         fail_body.count("PutOrSentinel(") + 1)  # +1 definition

    def test_every_bridge_success_path_checks_the_arena(self):
        """Each TryPut in the tables is guarded and refuses with the limit code."""
        tables = self.sources["BridgeTables.cpp"]
        calls = tables.count("ThreadArena().TryPut(")
        self.assertGreater(calls, 0, "no success path uses TryPut")
        guarded = tables.count("if (!ThreadArena().TryPut(")
        self.assertEqual(calls, guarded,
                         "an unguarded TryPut ignores its own refusal")
        self.assertEqual(calls, tables.count("MB_E_LIMIT_EXCEEDED"),
                         "a refusal that does not report MB_E_LIMIT_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
