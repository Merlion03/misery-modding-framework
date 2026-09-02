"""The support bundle: a closed document, structurally redacted, named by the
reference's projection.

THERE IS NO PYTHON ORACLE FOR THE BUNDLE. The Stage 4.5 reference has console
builtins that answer the same questions but no bundle document; the accepted
Stage 8 decision D6 is the specification, and this test pins it: the field list
is an ALLOWLIST checked for exact equality, not a superset check that would let
a field slip in.

THERE IS AN ORACLE FOR THE ERROR NAMES. tools/modplatform/errors.py defines the
dotted "<subsystem>.<code_name>" projection, and every error the bundle carries
is compared against it.

REDACTION IS PROVED, NOT ASSUMED. The harness induces a failure whose detail
names a file under Q:\\Users\\alice\\..., as the newest record in the ring, and
the bundle must show Q:\\Users\\<user>\\... -- the first version of the harness
flooded the ring AFTER inducing that failure, scrolled it out, and passed "no
user path survives" for the wrong reason.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import errors as E                                                 # noqa: E402
import nativebuild as nb                                           # noqa: E402

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
SOURCES = ["BridgeTables.cpp", "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
           "ModDiscovery.cpp"]

# THE ALLOWLIST. Adding a field to the bundle means adding it here, on purpose.
ALLOWED_TOP_LEVEL = {
    "schema", "build", "framework", "generation", "mods", "capabilities",
    "resources", "events", "services", "commands", "items", "recent_errors",
    "counters",
}
ALLOWED_BUILD = {"build_key", "engine_version", "engine_cl"}
ALLOWED_MOD = {"mod_id", "state", "epoch", "owned", "released", "revoked",
               "faults", "active_frames", "reclaimable"}
ALLOWED_ERROR = {"seq", "subsystem", "code", "name", "detail", "mod_id"}

# What must never appear anywhere in the document.
FORBIDDEN_SUBSTRINGS = ("MachineId", "EpicAccountId", "LoginId", "UserName",
                        "Users\\alice", "Users/alice", "settings_root",
                        "framework_dir")


def build_harness():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "diagnostics_harness.cpp")] +
        [os.path.join(INTERNAL, name) for name in SOURCES],
        "diagnostics_harness.exe")


class TheNamedCasesPass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build_harness())
        cls.lines = cls.result.stdout.splitlines()

    def test_every_case_passed(self):
        self.assertEqual([], [ln for ln in self.lines if "[FAIL]" in ln],
                         self.result.stdout)

    def test_the_harness_reported_success(self):
        self.assertTrue(json.loads(self.lines[-1])["ok"], self.result.stdout)


class TheBundleIsAClosedDocument(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        result = subprocess.run([build_harness(), "--bundle"], capture_output=True,
                                text=True, timeout=300)
        cls.text = result.stdout.strip()
        cls.bundle = json.loads(cls.text)

    def test_the_document_parses_as_json(self):
        self.assertIsInstance(self.bundle, dict)

    def test_the_top_level_fields_are_exactly_the_allowlist(self):
        self.assertEqual(ALLOWED_TOP_LEVEL, set(self.bundle))

    def test_the_build_block_is_exactly_the_allowlist(self):
        self.assertEqual(ALLOWED_BUILD, set(self.bundle["build"]))
        self.assertEqual("sha256:0123abcd", self.bundle["build"]["build_key"])

    def test_each_mod_record_is_exactly_the_allowlist(self):
        for mod in self.bundle["mods"]:
            with self.subTest(mod=mod.get("mod_id")):
                self.assertEqual(ALLOWED_MOD, set(mod))
                self.assertIsInstance(mod["state"], str, "state is a NAME")

    def test_each_error_record_is_exactly_the_allowlist(self):
        for record in self.bundle["recent_errors"]["errors"]:
            with self.subTest(seq=record.get("seq")):
                self.assertEqual(ALLOWED_ERROR, set(record))

    def test_nothing_forbidden_appears_anywhere(self):
        for needle in FORBIDDEN_SUBSTRINGS:
            with self.subTest(needle=needle):
                self.assertNotIn(needle, self.text)

    def test_the_user_segment_was_redacted_at_write_time(self):
        """The induced failure named a user path; the bundle shows <user>."""
        details = [r["detail"] for r in self.bundle["recent_errors"]["errors"]]
        redacted = [d for d in details if "Users\\<user>\\" in d]
        self.assertTrue(redacted, "the path-bearing failure is not in the ring")

    def test_items_are_null_not_zero_when_unattached(self):
        self.assertEqual({"declared": None, "live": None}, self.bundle["items"])

    def test_the_ring_is_bounded_and_counts_what_it_dropped(self):
        ring = self.bundle["recent_errors"]
        self.assertEqual(64, ring["capacity"])
        self.assertLessEqual(len(ring["errors"]), 64)
        self.assertEqual(ring["recorded"] - len(ring["errors"]), ring["dropped"])
        self.assertGreater(ring["dropped"], 0, "the flood did not overflow")
        seqs = [r["seq"] for r in ring["errors"]]
        self.assertEqual(sorted(seqs), seqs, "oldest first")


class ErrorNamesMatchTheReferenceProjection(unittest.TestCase):
    """Every (subsystem, code) the bundle carries is named as errors.py names it."""

    @classmethod
    def setUpClass(cls):
        result = subprocess.run([build_harness(), "--bundle"], capture_output=True,
                                text=True, timeout=300)
        cls.errors = json.loads(result.stdout)["recent_errors"]["errors"]

    def test_every_record_agrees(self):
        pairs = {(r["subsystem"], r["code"]) for r in self.errors}
        self.assertGreaterEqual(len(pairs), 3, "the harness induces at least 3 kinds")
        for record in self.errors:
            with self.subTest(pair=(record["subsystem"], record["code"])):
                expected = "%s.%s" % (E.SUBSYSTEM_NAMES[record["subsystem"]],
                                      E.code_name(record["subsystem"], record["code"]))
                self.assertEqual(expected, record["name"])

    def test_the_induced_kinds_are_the_ones_expected(self):
        names = {r["name"] for r in self.errors}
        self.assertIn("services.not_found", names)
        self.assertIn("platform.wrong_thread", names)
        self.assertIn("settings.invalid_argument", names)


if __name__ == "__main__":
    unittest.main()
