#!/usr/bin/env python3
"""The C++ load planner must answer exactly what Stage 4 answers.

WHY THIS TEST IS THE WHOLE POINT OF THE PORT
--------------------------------------------
Step 4 moved Stage 4's discovery and load planning into the runtime, where the
game can reach it without Python. A port is only worth having if it is a port
and not a fork, and "we were careful" is not a property anyone can check.

So both planners are run over the SAME mod trees, built by Stage 4's OWN
fixture builders (tools/modframework/treefixtures.py), and the load order and
every exclusion must match. A divergence is a failing test here rather than a
mod that loads on one path and not the other.

Only the DECISIONS are compared -- which mods load, in what order, and under
which codes the rest were refused. Diagnostic prose is not: two
implementations may reasonably word the same refusal differently, and pinning
the wording would make the test fail for reasons nobody cares about while
telling us nothing about behaviour.

THE ADVERSARIAL CASES ARE NOT AN AFTERTHOUGHT
---------------------------------------------
Stage 4's negative fixtures encode failures it was made to survive: a duplicate
id that must refuse both claimants, a broken folder that must not evict an
unrelated mod, a case-collision that must not let a rename decide which mod
loads, dependency and version failures that must fail closed. Every one of them
runs through both planners here. `ALL_NEGATIVE` is iterated rather than listed,
so a failure class added to Stage 4 later is automatically demanded of the port.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

HARNESS = os.path.join(REPO, "workspace", "msvc-stage5", "mod_plan_harness.exe")

import resolve as stage4_resolve                                   # noqa: E402
import treefixtures as fixtures                                    # noqa: E402


def python_plan(root):
    """Stage 4's own answer, reduced to the decisions."""
    plan, _report = stage4_resolve.plan_from_root(root)
    return {"load_order": list(plan.load_order),
            "excluded": {k: sorted(set(v)) for k, v in plan.excluded.items()},
            "ok": plan.ok}


def cpp_plan(root):
    """The runtime's answer, through the harness."""
    result = subprocess.run([HARNESS, root], capture_output=True, text=True,
                            timeout=120)
    if result.returncode != 0:
        raise AssertionError("the harness failed on %s: %s"
                             % (root, result.stderr[-2000:]))
    parsed = json.loads(result.stdout)
    return {"load_order": parsed["load_order"],
            "excluded": {k: sorted(v) for k, v in parsed["excluded"].items()},
            "ok": parsed["ok"]}


def normalise(plan, root):
    """Absolute paths appear as subjects for manifests too broken to name a mod.

    They are the one part of the answer that legitimately differs between two
    machines, so they are reduced to the folder name before comparison. The
    CODES attached to them are compared unchanged.
    """
    out = {"load_order": plan["load_order"], "ok": plan["ok"], "excluded": {}}
    for subject, codes in plan["excluded"].items():
        key = subject
        if os.path.isabs(subject):
            key = os.path.basename(os.path.normpath(subject))
        out["excluded"][key] = codes
    return out


@unittest.skipUnless(os.path.isfile(HARNESS),
                     "mod_plan_harness.exe has not been built "
                     "(nativebuild.build_harnesses)")
class TheCppPlannerAgreesWithStage4(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="misery-modplan-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def assertSamePlan(self, why=""):
        expected = normalise(python_plan(self.root), self.root)
        actual = normalise(cpp_plan(self.root), self.root)
        self.assertEqual(expected["load_order"], actual["load_order"],
                         "load order differs%s" % (" (%s)" % why if why else ""))
        self.assertEqual(expected["excluded"], actual["excluded"],
                         "exclusions differ%s" % (" (%s)" % why if why else ""))
        self.assertEqual(expected["ok"], actual["ok"])
        return expected

    # ---- the happy paths --------------------------------------------------

    def test_an_empty_root_plans_nothing(self):
        self.assertSamePlan()

    def test_one_mod(self):
        fixtures.build_mod(self.root, "Solo", "solomod")
        plan = self.assertSamePlan()
        self.assertEqual(["solomod"], plan["load_order"])

    def test_the_folder_name_is_not_the_identity(self):
        # The id and the folder deliberately differ, which is how "folder name
        # is not identity" gets tested rather than assumed.
        fixtures.build_mod(self.root, "ZZZ_Something_Else", "alphamod")
        plan = self.assertSamePlan()
        self.assertEqual(["alphamod"], plan["load_order"])

    def test_dependencies_load_before_dependents(self):
        fixtures.build_mod(self.root, "B", "betamod",
                           dependencies=[{"mod_id": "alphamod",
                                          "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "A", "alphamod")
        plan = self.assertSamePlan()
        self.assertEqual(["alphamod", "betamod"], plan["load_order"])

    def test_independent_mods_are_ordered_by_id_not_by_folder(self):
        fixtures.build_mod(self.root, "zzz_first_on_disk", "aaamod")
        fixtures.build_mod(self.root, "aaa_last_on_disk", "zzzmod")
        plan = self.assertSamePlan()
        self.assertEqual(["aaamod", "zzzmod"], plan["load_order"])

    def test_an_optional_dependency_that_is_present_orders_the_load(self):
        fixtures.build_mod(self.root, "Opt", "optmod",
                           optional_dependencies=[{"mod_id": "basemod",
                                                   "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Base", "basemod")
        plan = self.assertSamePlan()
        self.assertEqual(["basemod", "optmod"], plan["load_order"])

    def test_an_absent_optional_dependency_does_not_exclude(self):
        fixtures.build_mod(self.root, "Opt", "optmod",
                           optional_dependencies=[{"mod_id": "nothere",
                                                   "version": "^1.0.0"}])
        plan = self.assertSamePlan()
        self.assertEqual(["optmod"], plan["load_order"])
        self.assertEqual({}, plan["excluded"])

    # ---- every failure class Stage 4 knows about --------------------------

    def test_every_stage4_negative_fixture_agrees(self):
        # Iterated, not listed: a failure class added to Stage 4 later is
        # demanded of the port automatically.
        self.assertTrue(fixtures.ALL_NEGATIVE, "Stage 4 has no negatives?")
        for build in fixtures.ALL_NEGATIVE:
            with self.subTest(fixture=build.__name__):
                root = tempfile.mkdtemp(prefix="misery-neg-")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                build(root)
                expected = normalise(python_plan(root), root)
                actual = normalise(cpp_plan(root), root)
                self.assertEqual(expected["load_order"], actual["load_order"])
                self.assertEqual(expected["excluded"], actual["excluded"])

    # ---- the adversarial properties, stated directly ----------------------

    def test_a_broken_folder_cannot_evict_an_unrelated_mod(self):
        fixtures.negative_malformed_manifest(self.root)
        fixtures.build_mod(self.root, "Healthy", "healthymod")
        plan = self.assertSamePlan()
        self.assertEqual(["healthymod"], plan["load_order"],
                         "one unreadable manifest poisoned the scan")

    def test_a_duplicate_refuses_both_even_when_one_twin_is_broken(self):
        # The broken twin must not be filed under its own id as "malformed" and
        # thereby evict the healthy owner under a code naming the wrong problem.
        fixtures.build_mod(self.root, "GoodCopy", "twinmod", version="1.0.0")
        broken = os.path.join(self.root, "BadCopy")
        os.makedirs(broken, exist_ok=True)
        fixtures.write_raw_manifest(
            broken, '{"manifest_version": 1, "mod_id": "twinmod", '
                    '"name": "x", "version": "not-a-version", '
                    '"framework_api": "^0.4.0"}')
        plan = self.assertSamePlan()
        self.assertEqual([], plan["load_order"])
        self.assertIn("duplicate_mod_id", plan["excluded"].get("twinmod", []))

    def test_a_case_colliding_folder_refuses_every_member(self):
        fixtures.build_mod(self.root, "CaseMod", "casemod")
        # A second folder differing only in case cannot exist on Windows, so
        # the collision is expressed the way a Linux-authored install would
        # arrive: two manifests claiming one id from two folder names.
        other = os.path.join(self.root, "casemod_other")
        os.makedirs(other, exist_ok=True)
        fixtures.write_manifest(other, fixtures.manifest_body("casemod"))
        plan = self.assertSamePlan()
        self.assertEqual([], plan["load_order"])

    def test_a_dependency_on_an_excluded_mod_fails_closed(self):
        fixtures.negative_duplicate_mod_id(self.root)
        fixtures.build_mod(self.root, "Dependent", "dependentmod",
                           dependencies=[{"mod_id": "dupemod",
                                          "version": "^1.0.0"}])
        plan = self.assertSamePlan()
        self.assertEqual([], plan["load_order"],
                         "a mod whose dependency was refused still loaded")

    def test_exclusion_propagates_transitively(self):
        fixtures.build_mod(self.root, "Ghosted", "ghosted",
                           dependencies=[{"mod_id": "missing",
                                          "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Middle", "middlemod",
                           dependencies=[{"mod_id": "ghosted",
                                          "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Outer", "outermod",
                           dependencies=[{"mod_id": "middlemod",
                                          "version": "^1.0.0"}])
        plan = self.assertSamePlan()
        self.assertEqual([], plan["load_order"])

    def test_the_plan_does_not_depend_on_enumeration_order(self):
        # Folder names are chosen so that sorting by name and sorting by id
        # disagree; then the folders are created in a shuffled order. Neither
        # planner may notice.
        ids = ["mmod", "amod", "zmod", "gmod"]
        folders = ["9_m", "3_a", "0_z", "5_g"]
        pairs = list(zip(folders, ids))
        random.Random(20260901).shuffle(pairs)
        for folder, mod_id in pairs:
            fixtures.build_mod(self.root, folder, mod_id)
        plan = self.assertSamePlan("shuffled creation order")
        self.assertEqual(["amod", "gmod", "mmod", "zmod"], plan["load_order"])


if __name__ == "__main__":
    unittest.main()
