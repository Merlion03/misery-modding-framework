#!/usr/bin/env python3
"""The liveness refusal, proven on a graph the test owns.

WHY THIS IS A UNIT TEST AND NOT A LIVE ONE
------------------------------------------
Post-walk validation refuses to publish an anchor whose FUObjectItem no longer
vouches for it. Provoking that on a real game means catching a destruction
inside the seconds-long window of one resolution, and three runs of back-to-back
resolutions across real menu -> gameplay transitions -- 253 attempts, with
validation confirmed executing on every one -- never hit it: the transition
destroys the old generation and creates the new one with a gap between, so
resolutions land on "absent" rather than on "stale".

An absence of hits is not evidence that the refusal works. So it is proven here
instead, deterministically, against a synthetic object array whose every
FUObjectItem field the harness sets. The CODE under test is the real
`misery::resolve::Universe`; only the graph is synthetic.

THE CASE THIS ALL EXISTS FOR
----------------------------
`StillIs` re-reads an object's own name and class. Both survive destruction
untouched until the memory is reused, so on its own it detects RECYCLED memory,
not FREED memory -- it would publish a destroyed object as live. The harness
asserts exactly that pair: on a destroyed-but-intact object the semantic check
still passes while the slot check refuses.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HARNESS = os.path.join(REPO, "workspace", "msvc-stage5",
                       "slot_validation_harness.exe")


@unittest.skipUnless(os.path.isfile(HARNESS),
                     "slot_validation_harness.exe has not been built")
class SlotValidationRefusesEveryDeadState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = subprocess.run([HARNESS], capture_output=True, text=True,
                                    timeout=120)
        cls.lines = cls.result.stdout.splitlines()
        cls.verdict = json.loads(cls.lines[-1])

    def test_every_case_passed(self):
        failed = [ln for ln in self.lines if "[FAIL]" in ln]
        self.assertEqual([], failed)
        self.assertTrue(self.verdict["ok"], self.verdict)
        self.assertEqual(0, self.verdict["failures"])
        self.assertEqual(0, self.result.returncode)

    def test_every_refusal_reason_is_covered(self):
        """Each distinct way a slot can stop vouching for an object.

        Listed explicitly so that deleting a branch from the validator makes
        this fail, rather than silently reducing what is proven.
        """
        for reason in ("its slot now holds a different object",
                       "its slot has a new serial number",
                       "it no longer claims the slot it was found in",
                       "its InternalIndex is unreadable",
                       "it is marked garbage",
                       "it is marked unreachable"):
            self.assertTrue(any(reason in ln for ln in self.lines),
                            "no case exercised: %s" % reason)

    def test_a_destroyed_object_with_intact_bytes_is_refused(self):
        """The hole the live gate exposed, and the reason for the change.

        The semantic check must still PASS on it -- that is what made it
        insufficient -- and the slot check must still REFUSE.
        """
        line = [ln for ln in self.lines
                if "destroyed-but-intact bytes" in ln]
        self.assertEqual(1, len(line), self.lines)
        self.assertIn("[PASS]", line[0])
        self.assertIn("semantic=passes", line[0])
        self.assertIn("slot=it is marked garbage", line[0])


if __name__ == "__main__":
    unittest.main()
