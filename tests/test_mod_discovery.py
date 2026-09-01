#!/usr/bin/env python3
"""What the runtime's managed-mod discovery considers an installed mod.

Named test_mod_discovery rather than test_discovery: tests/test_discovery.py
already exists, covers tools/discovery (finding the GAME), and five other
test modules import its make_install_tree helper.

WHY THIS IS A UNIT TEST
-----------------------
Discovery is pure filesystem logic: it reads mod.json, checks that the declared
assembly exists, and builds a load plan. Nothing about it needs a game.

It nevertheless failed IN a game. The first version invented its own layout --
a mod's directory name was both its id and its assembly's stem -- which rejected
the framework's own fixture, whose id is ``alphamod`` and whose assembly is
``AlphaManagedMod.dll``. The symptom was a managed mod dying on load, ten
minutes into a Steam launch, behind a CoreCLR start and a save entry.

Every case is exercised against a directory tree the harness builds, and the
first of them is the one that broke.
"""
import os
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HARNESS = os.path.join(REPO, "workspace", "msvc-stage5",
                       "discovery_harness.exe")


@unittest.skipUnless(os.path.isfile(HARNESS),
                     "discovery_harness.exe has not been built "
                     "(nativebuild.build_harnesses)")
class DiscoveryReadsTheInstalledLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = subprocess.run([HARNESS], capture_output=True, text=True,
                                    timeout=120)
        cls.cases = {}
        for line in cls.result.stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 4 and parts[0] in ("ok", "FAILED"):
                cls.cases[parts[1]] = (parts[0] == "ok", parts[2], parts[3])

    def case(self, name):
        self.assertIn(name, self.cases,
                      "the harness did not report %r; it printed:\n%s"
                      % (name, self.result.stdout))
        ok, expected, actual = self.cases[name]
        self.assertTrue(ok, "%s: expected %r, got %r" % (name, expected, actual))

    def test_the_harness_ran_every_case(self):
        # A harness that crashed after two cases must not look like two passes.
        self.assertEqual(15, len(self.cases), self.result.stdout)
        self.assertIn("PASS", self.result.stdout.splitlines()[-1],
                      self.result.stdout)
        self.assertEqual(0, self.result.returncode, self.result.stderr[-2000:])

    # THE REGRESSION. A mod's id comes from its manifest. It is not its
    # directory name, and it is not its assembly's stem.
    def test_the_id_comes_from_the_manifest_not_the_directory(self):
        self.case("with the duplicate gone the mod is planned under its "
                  "manifest id")
        self.case("the planned id is the manifest's")

    # A directory that never claimed to be a mod is invisible; one that claimed
    # to be and could not be read is REPORTED. The difference matters: authors
    # keep scratch folders under Mods/, and a mod disappearing silently is the
    # failure mode that costs an evening.
    def test_a_directory_with_no_manifest_is_not_a_refusal(self):
        self.case("a directory with no manifest is not reported at all")

    def test_a_content_only_mod_is_not_a_refusal(self):
        self.case("a content-only mod is not reported as skipped")

    def test_every_malformed_claim_is_reported(self):
        self.case("four subjects are reported refused")
        self.case("an unreadable manifest is reported")
        self.case("a manifest with no mod_id is reported")
        self.case("a declared but absent assembly is reported")

    # An installation still holding an older copy of a mod under its previous
    # directory name. NEITHER is loaded: picking one would make the outcome
    # depend on the order the filesystem happened to enumerate, between two
    # copies that may well differ.
    def test_an_ambiguous_id_loads_nothing_and_names_both(self):
        self.case("an ambiguous id plans nothing at all")
        self.case("no mod is planned while an id is ambiguous")
        self.case("the ambiguous id is refused under the id itself")
        self.case("both colliding folders are named in the reason")

    # ...and the ambiguity is the only thing stopping it. With the stale copy
    # gone the mod loads normally, so the rule above cannot be masking a
    # discovery that was broken anyway.
    def test_removing_the_duplicate_restores_the_mod(self):
        self.case("with the duplicate gone nothing about alphamod is refused")
        self.case("exactly one mod is planned")

    def test_an_empty_installation_is_ordinary(self):
        self.case("a missing Mods directory plans nothing and reports nothing")


if __name__ == "__main__":
    unittest.main()
