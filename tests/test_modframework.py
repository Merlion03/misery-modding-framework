#!/usr/bin/env python3
"""Stage 4: discovery, validation and dependency resolution -- no game needed.

That these run with no MISERY, no Unreal and no containers is the architectural
claim being tested, not a convenience: discovery, validation and arbitration
were split from execution precisely so the trustworthy part of a mod loader can
be proven on a laptop.

The determinism tests deserve special mention. They do not check that the output
"looks sorted" -- they feed the SAME manifests in many different orders and
require byte-identical plans, because the defect being guarded against is a
resolver that quietly inherits filesystem enumeration order.
"""
import itertools
import json
import os
import random
import shutil
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import diagnostics as D                                            # noqa: E402
import discovery                                                   # noqa: E402
import treefixtures as fixtures                                    # noqa: E402
import manifest as M                                               # noqa: E402
import execution                                                   # noqa: E402
import resolve                                                     # noqa: E402
import semver                                                      # noqa: E402


class TempRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="modframework-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def plan(self, **kwargs):
        kwargs.setdefault("check_artifacts", True)
        return resolve.plan_from_root(self.root, **kwargs)[0]

    def codes_for(self, plan, mod_id):
        return sorted({d.code for d in plan.diagnostics if d.subject == mod_id})


# --------------------------------------------------------------------------
# semver
# --------------------------------------------------------------------------

class SemverTests(unittest.TestCase):
    def test_versions_compare_numerically_not_lexically(self):
        self.assertGreater(semver.Version("0.10.0"), semver.Version("0.9.0"))
        self.assertGreater(semver.Version("1.0.0"), semver.Version("0.99.99"))

    def test_caret_allows_minor_and_patch_but_not_major(self):
        requirement = semver.Requirement("^1.2.0")
        self.assertTrue(requirement.matches(semver.Version("1.2.0")))
        self.assertTrue(requirement.matches(semver.Version("1.9.9")))
        self.assertFalse(requirement.matches(semver.Version("2.0.0")))
        self.assertFalse(requirement.matches(semver.Version("1.1.9")))

    def test_a_bare_version_means_caret(self):
        self.assertEqual(str(semver.Requirement("1.2.0").operator), "^")
        self.assertTrue(semver.Requirement("1.2.0").matches(semver.Version("1.5.0")))

    def test_exact_and_at_least(self):
        self.assertTrue(semver.Requirement("==1.2.3").matches(semver.Version("1.2.3")))
        self.assertFalse(semver.Requirement("==1.2.3").matches(semver.Version("1.2.4")))
        self.assertTrue(semver.Requirement(">=1.0.0").matches(semver.Version("9.9.9")))

    def test_zero_major_is_not_given_a_special_rule(self):
        # Deliberate: some ecosystems treat every 0.x bump as breaking. Applying
        # that silently would reject dependencies the author thought they allowed.
        self.assertTrue(semver.Requirement("^0.4.0").matches(semver.Version("0.9.0")))

    def test_unsupported_operators_are_named_not_mis_reported(self):
        for text in ("<2.0.0", "<=2.0.0", "!=1.0.0", "~>1.2"):
            with self.assertRaises(semver.VersionError) as caught:
                semver.Requirement(text)
            self.assertIn("does not support", str(caught.exception))

    def test_leading_zeros_are_refused(self):
        for text in ("1.02.0", "01.2.0", "1.2.03"):
            with self.assertRaises(semver.VersionError):
                semver.Version(text)

    def test_non_versions_are_refused(self):
        for text in ("1.2", "1.2.3.4", "v1.2.3", "", "abc", None, 5):
            with self.assertRaises(semver.VersionError):
                semver.Version(text)


# --------------------------------------------------------------------------
# manifest schema
# --------------------------------------------------------------------------

class ManifestTests(TempRoot):
    def parse(self, body, root=None):
        parsed, problems, _declared = M.parse(
            body, root or self.root, os.path.join(self.root, "mod.json"))
        return parsed, problems

    def test_a_minimal_manifest_parses(self):
        parsed, problems = self.parse(fixtures.manifest_body("goodmod"))
        self.assertIsNotNone(parsed)
        self.assertEqual([], D.fatal(problems))
        self.assertEqual("goodmod", parsed.mod_id)
        self.assertEqual([], parsed.dependencies)
        self.assertEqual([], parsed.content)

    def test_every_required_field_is_required(self):
        for field in M.REQUIRED_FIELDS:
            body = fixtures.manifest_body("goodmod")
            del body[field]
            parsed, problems = self.parse(body)
            self.assertIsNone(parsed, "%s was not required" % field)
            self.assertTrue(D.fatal(problems))

    def test_manifest_version_is_read_before_anything_else(self):
        # A future manifest must be refused by NUMBER, without its other fields
        # being judged against today's rules.
        body = fixtures.manifest_body("goodmod", manifest_version=99)
        body["version"] = "not a version"
        parsed, problems = self.parse(body)
        self.assertIsNone(parsed)
        codes = {d.code for d in problems}
        self.assertEqual({D.UNSUPPORTED_MANIFEST_VERSION}, codes)

    def test_unknown_fields_are_refused_not_ignored(self):
        body = fixtures.manifest_body("goodmod")
        body["dependancies"] = []          # a plausible typo
        parsed, problems = self.parse(body)
        self.assertIsNone(parsed)
        self.assertTrue(any(d.code == D.MALFORMED_MANIFEST for d in problems))

    def test_mod_id_syntax_is_enforced(self):
        for bad in ("NotLowercase", "1leading", "has-dash", "has space", "",
                    "has__separator"):
            parsed, problems = self.parse(fixtures.manifest_body(bad))
            self.assertIsNone(parsed, "%r was accepted" % bad)
            self.assertTrue(any(d.code == D.INVALID_MOD_ID for d in problems),
                            "%r gave %s" % (bad, [d.code for d in problems]))

    def test_reserved_mod_ids_are_refused(self):
        for reserved in ("misery", "engine", "core"):
            parsed, _ = self.parse(fixtures.manifest_body(reserved))
            self.assertIsNone(parsed, "%r was accepted" % reserved)

    def test_framework_api_incompatibility_is_its_own_code(self):
        parsed, problems = self.parse(
            fixtures.manifest_body("goodmod", framework_api="^9.0.0"))
        self.assertIsNone(parsed)
        self.assertIn(D.UNSUPPORTED_FRAMEWORK_API, {d.code for d in problems})

    def test_self_dependency_is_refused_at_the_field(self):
        parsed, problems = self.parse(fixtures.manifest_body(
            "goodmod", dependencies=[{"mod_id": "goodmod", "version": "^1.0.0"}]))
        self.assertIsNone(parsed)
        self.assertTrue(any("itself" in d.detail for d in problems))

    def test_a_dependency_listed_twice_is_refused(self):
        parsed, _ = self.parse(fixtures.manifest_body("goodmod", dependencies=[
            {"mod_id": "other", "version": "^1.0.0"},
            {"mod_id": "other", "version": "^2.0.0"}]))
        self.assertIsNone(parsed)

    def test_required_and_optional_cannot_name_the_same_mod(self):
        parsed, _ = self.parse(fixtures.manifest_body(
            "goodmod",
            dependencies=[{"mod_id": "other", "version": "^1.0.0"}],
            optional_dependencies=[{"mod_id": "other", "version": "^1.0.0"}]))
        self.assertIsNone(parsed)

    def test_a_dependency_cannot_also_be_a_conflict(self):
        parsed, _ = self.parse(fixtures.manifest_body(
            "goodmod",
            dependencies=[{"mod_id": "other", "version": "^1.0.0"}],
            conflicts=[{"mod_id": "other"}]))
        self.assertIsNone(parsed)

    def test_artifact_paths_may_not_escape_the_mod_folder(self):
        for evil in ("../OtherMod/Content/x", "/abs/path", "C:/x", "a/../../b"):
            parsed, _ = self.parse(fixtures.manifest_body("goodmod", code=[evil]))
            self.assertIsNone(parsed, "%r was accepted" % evil)

    def test_dependencies_are_sorted_regardless_of_authored_order(self):
        first, _ = self.parse(fixtures.manifest_body("goodmod", dependencies=[
            {"mod_id": "zeta", "version": "^1.0.0"},
            {"mod_id": "alpha", "version": "^1.0.0"}]))
        second, _ = self.parse(fixtures.manifest_body("goodmod", dependencies=[
            {"mod_id": "alpha", "version": "^1.0.0"},
            {"mod_id": "zeta", "version": "^1.0.0"}]))
        self.assertEqual([d.mod_id for d in first.dependencies],
                         [d.mod_id for d in second.dependencies])

    def test_unreadable_json_is_a_malformed_manifest_against_the_folder(self):
        path = os.path.join(self.root, "Broken")
        os.makedirs(path)
        fixtures.write_raw_manifest(path, "{not json")
        parsed, problems, _ = M.load(path)
        self.assertIsNone(parsed)
        self.assertEqual(D.MALFORMED_MANIFEST, problems[0].code)
        self.assertEqual(path, problems[0].subject)

    def test_a_missing_manifest_file_is_reported(self):
        path = os.path.join(self.root, "Empty")
        os.makedirs(path)
        parsed, problems, _ = M.load(path)
        self.assertIsNone(parsed)
        self.assertEqual(D.MALFORMED_MANIFEST, problems[0].code)


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

class DiscoveryTests(TempRoot):
    def test_folders_without_a_manifest_are_ignored_silently(self):
        os.makedirs(os.path.join(self.root, "screenshots"))
        os.makedirs(os.path.join(self.root, "backup of my mods"))
        fixtures.build_mod(self.root, "AlphaMod", "alphamod")
        _report, found = discovery.scan(self.root)
        self.assertEqual(["alphamod"], [d.mod_id for d in found])

    def test_the_folder_name_does_not_become_the_identity(self):
        fixtures.build_mod(self.root, "TotallyDifferentFolder", "alphamod")
        _report, found = discovery.scan(self.root)
        self.assertEqual("alphamod", found[0].mod_id)
        self.assertEqual("TotallyDifferentFolder", found[0].folder)

    def test_renaming_a_folder_does_not_change_the_plan(self):
        fixtures.build_mod(self.root, "AAA", "zebra")
        fixtures.build_mod(self.root, "ZZZ", "antelope")
        before = self.plan().load_order
        os.rename(os.path.join(self.root, "AAA"),
                  os.path.join(self.root, "MMM_renamed"))
        after = self.plan().load_order
        self.assertEqual(before, after)
        # And the order is by mod_id, not by folder name.
        self.assertEqual(["antelope", "zebra"], after)

    def test_a_missing_root_is_an_error_not_an_empty_plan(self):
        with self.assertRaises(discovery.DiscoveryError):
            discovery.scan(os.path.join(self.root, "nope"))

    def test_an_empty_root_is_an_empty_plan_not_an_error(self):
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertTrue(plan.ok)

    def test_declared_content_must_exist(self):
        fixtures.build_mod(self.root, "ClaimsContent", "claimscontent",
                           content=["Mod_claimscontent_P"])
        plan = self.plan()
        self.assertNotIn("claimscontent", plan.load_order)
        self.assertIn(D.MISSING_ARTIFACT, plan.excluded["claimscontent"])

    def test_a_partial_container_is_missing_not_present(self):
        path = fixtures.build_mod(self.root, "Partial", "partial",
                                  content=["Mod_partial_P"])
        fixtures.touch_container(path, "Mod_partial_P")
        os.remove(os.path.join(path, "Content", "Mod_partial_P.ucas"))
        plan = self.plan()
        self.assertNotIn("partial", plan.load_order)

    def test_declared_code_must_exist(self):
        fixtures.build_mod(self.root, "ClaimsCode", "claimscode", code=["items.py"])
        plan = self.plan()
        self.assertNotIn("claimscode", plan.load_order)
        self.assertIn(D.MISSING_ARTIFACT, plan.excluded["claimscode"])

    def test_content_belonging_to_another_mod_is_refused(self):
        path = fixtures.build_mod(self.root, "Thief", "thief",
                                  content=["Mod_thief_P"])
        fixtures.touch_container(path, "Mod_thief_P")

        def reader(_utoc):
            return {"package_paths": ["/Game/Mods/victim/Meshes/SM_Loot"]}

        plan = resolve.plan_from_root(self.root, container_reader=reader)[0]
        self.assertNotIn("thief", plan.load_order)
        self.assertIn(D.CONTENT_NAMESPACE_MISMATCH, plan.excluded["thief"])


# --------------------------------------------------------------------------
# resolution -- one class per failure the stage must detect
# --------------------------------------------------------------------------

class ResolutionTests(TempRoot):
    def test_two_independent_mods_both_load(self):
        fixtures.build_mod(self.root, "AlphaMod", "alphamod")
        fixtures.build_mod(self.root, "BetaMod", "betamod")
        plan = self.plan()
        self.assertEqual(["alphamod", "betamod"], plan.load_order)
        self.assertTrue(plan.ok)

    def test_a_dependency_loads_before_its_dependent(self):
        fixtures.build_mod(self.root, "Zzz", "zzzbase", version="1.0.0")
        fixtures.build_mod(self.root, "Aaa", "aaauser",
                           dependencies=[{"mod_id": "zzzbase", "version": "^1.0.0"}])
        plan = self.plan()
        # Alphabetically aaauser comes first; the dependency edge must win.
        self.assertEqual(["zzzbase", "aaauser"], plan.load_order)

    def test_duplicate_mod_id_refuses_BOTH_claimants(self):
        fixtures.negative_duplicate_mod_id(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.DUPLICATE_MOD_ID, plan.excluded["dupemod"])

    def test_duplicate_choice_does_not_depend_on_folder_order(self):
        # The failure this guards: keeping "whichever came first". Renaming the
        # folders to reverse their alphabetical order must change nothing.
        fixtures.negative_duplicate_mod_id(self.root)
        first = self.plan().as_dict()
        os.rename(os.path.join(self.root, "FirstCopy"),
                  os.path.join(self.root, "ZLast"))
        second = self.plan().as_dict()
        self.assertEqual(first["load_order"], second["load_order"])
        self.assertEqual([], second["load_order"])

    def test_missing_required_dependency(self):
        fixtures.negative_missing_dependency(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.MISSING_DEPENDENCY, plan.excluded["needsghost"])

    def test_incompatible_dependency_version(self):
        fixtures.negative_incompatible_version(self.root)
        plan = self.plan()
        self.assertEqual(["provider"], plan.load_order)
        self.assertIn(D.INCOMPATIBLE_DEPENDENCY_VERSION, plan.excluded["consumer"])

    def test_dependency_cycle_refuses_every_member(self):
        members = fixtures.negative_dependency_cycle(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        for mod_id in members:
            self.assertIn(D.DEPENDENCY_CYCLE, plan.excluded[mod_id])

    def test_a_two_mod_cycle_is_detected(self):
        fixtures.build_mod(self.root, "A", "aaa",
                           dependencies=[{"mod_id": "bbb", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "B", "bbb",
                           dependencies=[{"mod_id": "aaa", "version": "^1.0.0"}])
        plan = self.plan()
        self.assertEqual([], plan.load_order)

    def test_a_cycle_through_an_optional_dependency_is_detected(self):
        # Optional dependencies still order the load, so they can close a cycle.
        fixtures.build_mod(self.root, "A", "aaa",
                           dependencies=[{"mod_id": "bbb", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "B", "bbb", optional_dependencies=[
            {"mod_id": "aaa", "version": "^1.0.0"}])
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.DEPENDENCY_CYCLE, plan.excluded["aaa"])

    def test_explicit_conflict_refuses_both_sides(self):
        fixtures.negative_explicit_conflict(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.EXPLICIT_CONFLICT, plan.excluded["fighter"])
        self.assertIn(D.EXPLICIT_CONFLICT, plan.excluded["rival"])

    def test_a_conflict_scoped_to_a_version_does_not_fire_on_another(self):
        fixtures.build_mod(self.root, "Fighter", "fighter",
                           conflicts=[{"mod_id": "rival", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Rival", "rival", version="2.0.0")
        plan = self.plan()
        self.assertEqual(["fighter", "rival"], plan.load_order)

    def test_malformed_manifest_does_not_stop_the_scan(self):
        fixtures.negative_malformed_manifest(self.root)
        fixtures.build_mod(self.root, "AlphaMod", "alphamod")
        plan = self.plan()
        self.assertEqual(["alphamod"], plan.load_order)
        self.assertEqual(1, len(plan.excluded))

    def test_unsupported_manifest_version(self):
        fixtures.negative_unsupported_manifest_version(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)

    def test_unsupported_framework_api(self):
        fixtures.negative_unsupported_framework_api(self.root)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.UNSUPPORTED_FRAMEWORK_API, plan.excluded["needsnewer"])

    def test_exclusion_propagates_to_dependents(self):
        fixtures.build_mod(self.root, "Broken", "broken", framework_api="^9.0.0")
        fixtures.build_mod(self.root, "Middle", "middle",
                           dependencies=[{"mod_id": "broken", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Leaf", "leaf",
                           dependencies=[{"mod_id": "middle", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Innocent", "innocent")
        plan = self.plan()
        self.assertEqual(["innocent"], plan.load_order)
        self.assertIn(D.DEPENDENCY_EXCLUDED, plan.excluded["middle"])
        self.assertIn(D.DEPENDENCY_EXCLUDED, plan.excluded["leaf"])

    def test_an_absent_optional_dependency_is_not_fatal(self):
        fixtures.build_mod(self.root, "Solo", "solo", optional_dependencies=[
            {"mod_id": "nowhere", "version": "^1.0.0"}])
        plan = self.plan()
        self.assertEqual(["solo"], plan.load_order)
        self.assertTrue(plan.ok)
        self.assertIn(D.OPTIONAL_DEPENDENCY_ABSENT,
                      {d.code for d in plan.diagnostics})

    def test_a_present_but_incompatible_optional_dependency_is_fatal(self):
        fixtures.build_mod(self.root, "Provider", "provider", version="1.0.0")
        fixtures.build_mod(self.root, "Solo", "solo", optional_dependencies=[
            {"mod_id": "provider", "version": "^2.0.0"}])
        plan = self.plan()
        self.assertNotIn("solo", plan.load_order)
        self.assertIn(D.INCOMPATIBLE_DEPENDENCY_VERSION, plan.excluded["solo"])

    def test_every_mod_in_the_plan_has_its_dependencies_in_the_plan_before_it(self):
        fixtures.build_mod(self.root, "Base", "base", version="1.0.0")
        fixtures.build_mod(self.root, "Mid", "mid", version="1.0.0",
                           dependencies=[{"mod_id": "base", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "Top", "top",
                           dependencies=[{"mod_id": "mid", "version": "^1.0.0"},
                                         {"mod_id": "base", "version": "^1.0.0"}])
        plan = self.plan()
        positions = {mod_id: i for i, mod_id in enumerate(plan.load_order)}
        for mod_id in plan.load_order:
            for dependency in plan.manifests[mod_id].dependencies:
                self.assertIn(dependency.mod_id, positions,
                              "%s loaded without %s" % (mod_id, dependency.mod_id))
                self.assertLess(positions[dependency.mod_id], positions[mod_id])

    def test_no_partially_accepted_mod_reaches_the_plan(self):
        """Every mod is either fully in the plan with a manifest, or fully out."""
        for build in fixtures.ALL_NEGATIVE:
            root = tempfile.mkdtemp(prefix="neg-")
            self.addCleanup(shutil.rmtree, root, ignore_errors=True)
            build(root)
            fixtures.build_mod(root, "Healthy", "healthy")
            plan = resolve.plan_from_root(root)[0]
            self.assertIn("healthy", plan.load_order,
                          "%s took down an unrelated mod" % build.__name__)
            for mod_id in plan.load_order:
                self.assertIn(mod_id, plan.manifests)
                self.assertNotIn(mod_id, plan.excluded)
            for mod_id in plan.excluded:
                self.assertNotIn(mod_id, plan.load_order)
                self.assertNotIn(mod_id, plan.manifests)


# --------------------------------------------------------------------------
# determinism -- the property, not the appearance
# --------------------------------------------------------------------------

class DeterminismTests(TempRoot):
    def build_set(self, root):
        fixtures.build_mod(root, "ZFolder", "alpha", version="1.0.0")
        fixtures.build_mod(root, "AFolder", "beta", version="1.0.0",
                           dependencies=[{"mod_id": "alpha", "version": "^1.0.0"}])
        fixtures.build_mod(root, "MFolder", "gamma", version="1.0.0",
                           dependencies=[{"mod_id": "alpha", "version": "^1.0.0"}])
        fixtures.build_mod(root, "QFolder", "delta", version="1.0.0",
                           dependencies=[{"mod_id": "beta", "version": "^1.0.0"},
                                         {"mod_id": "gamma", "version": "^1.0.0"}])

    def test_resolution_is_identical_under_every_input_permutation(self):
        self.build_set(self.root)
        _report, found = discovery.scan(self.root)
        baseline = json.dumps(resolve.resolve(list(found)).as_dict(), sort_keys=True)
        for permutation in itertools.permutations(found):
            got = json.dumps(resolve.resolve(list(permutation)).as_dict(),
                             sort_keys=True)
            self.assertEqual(baseline, got,
                             "resolution depended on the order of its input")

    def test_discovery_is_identical_under_a_shuffled_listing(self):
        # Simulate a filesystem that enumerates differently between runs.
        self.build_set(self.root)
        real_listdir = os.listdir
        results = []
        for seed in range(8):
            rng = random.Random(seed)

            def shuffled(path, _real=real_listdir, _rng=rng):
                entries = list(_real(path))
                _rng.shuffle(entries)
                return entries

            os.listdir = shuffled
            try:
                plan = resolve.plan_from_root(self.root)[0]
            finally:
                os.listdir = real_listdir
            results.append(json.dumps(plan.as_dict(), sort_keys=True))
        self.assertEqual(1, len(set(results)),
                         "the plan changed with filesystem enumeration order")

    def test_the_load_order_respects_dependencies_and_breaks_ties_by_mod_id(self):
        self.build_set(self.root)
        plan = self.plan()
        self.assertEqual(["alpha", "beta", "gamma", "delta"], plan.load_order)

    def test_diagnostics_are_sorted_stably(self):
        for build in fixtures.ALL_NEGATIVE:
            build(self.root)
        first = self.plan().as_dict()["diagnostics"]
        second = self.plan().as_dict()["diagnostics"]
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))

    def test_a_deep_dependency_chain_does_not_hit_the_recursion_limit(self):
        # The cycle detector is iterative on purpose; a legal-but-deep mod set
        # must resolve rather than raise RecursionError.
        depth = 400
        for index in range(depth):
            deps = ([{"mod_id": "m%03d" % (index - 1), "version": "^1.0.0"}]
                    if index else None)
            fixtures.build_mod(self.root, "Folder%03d" % index, "m%03d" % index,
                               dependencies=deps)
        plan = self.plan()
        self.assertEqual(depth, len(plan.load_order))
        self.assertEqual(["m%03d" % i for i in range(depth)], plan.load_order)


class AdversarialReviewRegressions(TempRoot):
    """One test per defect an adversarial review of this code confirmed.

    Each of these passed review only because someone went looking for it: the
    62 tests that existed at the time were all green. They are grouped here so
    that what they cost to find is not lost the next time the file is edited.
    """

    def _colliding_pair(self):
        """Two mods in folders that COLLIDE case-insensitively.

        Built under separate parents because Windows folds "Alphamod" and
        "alphamod" onto one directory -- the second build_mod would simply
        overwrite the first's manifest, and the test would then be exercising a
        duplicate mod_id instead of a case collision.
        """
        left = tempfile.mkdtemp(prefix="collide-a-")
        right = tempfile.mkdtemp(prefix="collide-b-")
        self.addCleanup(shutil.rmtree, left, ignore_errors=True)
        self.addCleanup(shutil.rmtree, right, ignore_errors=True)
        return (fixtures.build_mod(left, "Alphamod", "moda"),
                fixtures.build_mod(right, "alphamod", "modb"))

    # ---- A: case-colliding folders used to fail OPEN --------------------
    def test_case_colliding_folders_refuse_every_member(self):
        """The defect: the folder whose name sorted first by codepoint was kept
        and the other refused, so renaming a folder's case changed which of two
        unrelated mods loaded. Simulated, because Windows cannot hold both."""
        first, second = self._colliding_pair()
        real = discovery.candidate_folders
        try:
            discovery.candidate_folders = lambda _root: [
                ("Alphamod", first), ("alphamod", second)]
            plan = resolve.resolve(discovery.discover(self.root,
                                                      check_artifacts=False))
        finally:
            discovery.candidate_folders = real
        self.assertEqual([], plan.load_order,
                         "a case collision admitted one of the pair")
        for mod_id in ("moda", "modb"):
            self.assertIn(mod_id, plan.excluded)

    def test_case_collision_outcome_does_not_depend_on_which_sorts_first(self):
        first, second = self._colliding_pair()
        real = discovery.candidate_folders
        plans = []
        try:
            for listing in ([("Alphamod", first), ("alphamod", second)],
                            [("alphamod", second), ("Alphamod", first)]):
                discovery.candidate_folders = lambda _root, _l=listing: _l
                plans.append(resolve.resolve(
                    discovery.discover(self.root, check_artifacts=False)
                ).load_order)
        finally:
            discovery.candidate_folders = real
        self.assertEqual([[], []], plans)

    # ---- B: sorted() over a set containing None crashed the whole scan ---
    def test_a_container_mixing_vanilla_and_foreign_paths_does_not_crash(self):
        """ns.owning_mod returns None outside /Game/Mods, so the old
        {owners} - {mine} set held None and str together and sorted() raised
        TypeError -- which escaped and killed the scan for every mod."""
        path = fixtures.build_mod(self.root, "Thief", "thief",
                                  content=["Mod_thief_P"])
        fixtures.touch_container(path, "Mod_thief_P")
        fixtures.build_mod(self.root, "Bystander", "bystander")

        def reader(_utoc):
            return {"package_paths": ["/Game/SurvivalGameKitV2/Foo",
                                      "/Game/Mods/victim/Meshes/SM_A"]}

        plan = resolve.plan_from_root(self.root, container_reader=reader)[0]
        self.assertIn("bystander", plan.load_order,
                      "one bad container took down an unrelated mod")
        self.assertIn(D.CONTENT_NAMESPACE_MISMATCH, plan.excluded["thief"])

    # ---- C: a requirement the regex could not match raised AttributeError -
    def test_a_requirement_with_an_internal_newline_raises_VersionError(self):
        # Leading and trailing whitespace is stripped and is fine; it is an
        # INTERNAL newline that ``.+`` cannot span, which used to return None
        # from the regex and raise AttributeError one line later.
        for text in ("1.0.0\nx", "^1.0.0\n2.0.0", "1.0.0\r\nx"):
            with self.assertRaises(semver.VersionError):
                semver.Requirement(text)

    def test_surrounding_whitespace_is_still_accepted(self):
        self.assertTrue(semver.Requirement("  ^1.0.0  ").matches(
            semver.Version("1.2.0")))

    def test_a_manifest_with_a_newline_requirement_does_not_abort_the_scan(self):
        fixtures.build_mod(self.root, "Weird", "weird",
                           dependencies=[{"mod_id": "other",
                                          "version": "1.0.0\nx"}])
        fixtures.build_mod(self.root, "Bystander", "bystander")
        plan = self.plan()
        self.assertIn("bystander", plan.load_order)
        self.assertIn("weird", plan.excluded)

    # ---- D: a missing dependency version silently meant ^0.0.0 -----------
    def test_a_dependency_must_state_its_version(self):
        """The old default was "0.0.0", i.e. ^0.0.0 -- "major must be 0" -- so a
        dependency present at 1.0.0 was refused while the manifest looked like
        it was asking for any version."""
        fixtures.build_mod(self.root, "Provider", "provider", version="1.0.0")
        fixtures.build_mod(self.root, "Consumer", "consumer",
                           dependencies=[{"mod_id": "provider"}])
        plan = self.plan()
        self.assertNotIn("consumer", plan.load_order)
        self.assertTrue(any("does not state a version" in d.detail
                            for d in plan.diagnostics),
                        [d.detail for d in plan.diagnostics])

    def test_any_version_can_still_be_expressed(self):
        fixtures.build_mod(self.root, "Provider", "provider", version="7.1.2")
        fixtures.build_mod(self.root, "Consumer", "consumer",
                           dependencies=[{"mod_id": "provider",
                                          "version": ">=0.0.0"}])
        self.assertEqual(["consumer", "provider"], sorted(self.plan().load_order))

    # ---- E: the cycle diagnostic named edges that do not exist -----------
    def test_the_cycle_diagnostic_names_only_real_edges(self):
        # a -> c -> b -> a. Sorting the component and joining with " -> " would
        # print "a -> b -> c -> a", claiming two edges that do not exist.
        fixtures.build_mod(self.root, "A", "aaa",
                           dependencies=[{"mod_id": "ccc", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "C", "ccc",
                           dependencies=[{"mod_id": "bbb", "version": "^1.0.0"}])
        fixtures.build_mod(self.root, "B", "bbb",
                           dependencies=[{"mod_id": "aaa", "version": "^1.0.0"}])
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        text = " ".join(d.detail for d in plan.diagnostics
                        if d.code == D.DEPENDENCY_CYCLE)
        for real_edge in ("aaa -> ccc", "ccc -> bbb", "bbb -> aaa"):
            self.assertIn(real_edge, text)
        for fake_edge in ("aaa -> bbb", "bbb -> ccc", "ccc -> aaa"):
            self.assertNotIn(fake_edge, text)

    # ---- F: a duplicate paired with another failure was never a duplicate -
    def test_a_duplicate_is_detected_even_when_one_twin_is_broken(self):
        """The old grouping only counted manifests that fully validated, so the
        broken twin was filed under its own id as "malformed" -- which then
        evicted the healthy owner of that id under a code naming the wrong
        problem."""
        fixtures.build_mod(self.root, "Good", "alphamod", version="1.0.0")
        body = fixtures.manifest_body("alphamod")
        body["version"] = "not a version"
        fixtures.write_manifest(os.path.join(self.root, "Evil"), body)
        plan = self.plan()
        self.assertEqual([], plan.load_order)
        self.assertIn(D.DUPLICATE_MOD_ID, plan.excluded["alphamod"])

    def test_a_broken_folder_cannot_evict_an_unrelated_mod(self):
        fixtures.build_mod(self.root, "Innocent", "innocent")
        body = fixtures.manifest_body("somethingelse")
        body["version"] = "not a version"
        fixtures.write_manifest(os.path.join(self.root, "Broken"), body)
        plan = self.plan()
        self.assertEqual(["innocent"], plan.load_order)

    # ---- G: a container stem was an unowned namespace --------------------
    def test_a_mod_cannot_declare_another_mods_container_stem(self):
        """Stems share one staging directory, so an unnamespaced stem lets one
        mod's container overwrite another's."""
        path = fixtures.build_mod(self.root, "Evil", "evilmod",
                                  content=["Mod_alphamod_P"])
        fixtures.touch_container(path, "Mod_alphamod_P")
        plan = self.plan()
        self.assertNotIn("evilmod", plan.load_order)
        self.assertIn(D.CONTENT_NAMESPACE_MISMATCH, plan.excluded["evilmod"])

    def test_a_mod_may_declare_its_own_namespaced_containers(self):
        path = fixtures.build_mod(self.root, "Fine", "finemod",
                                  content=["Mod_finemod_P", "Mod_finemod_Extra_P"])
        fixtures.touch_container(path, "Mod_finemod_P")
        fixtures.touch_container(path, "Mod_finemod_Extra_P")
        self.assertEqual(["finemod"], self.plan().load_order)

    # ---- H and I: declarations -------------------------------------------
    def _mod_with_code(self, folder, mod_id, body_text):
        path = fixtures.build_mod(self.root, folder, mod_id, code=["items.py"])
        code_dir = os.path.join(path, "Code")
        os.makedirs(code_dir, exist_ok=True)
        with open(os.path.join(code_dir, "items.py"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write(body_text)
        return path

    DECL = ('{"local_id": %r, "display_name": "n", "short_name": "s", '
            '"description": "d", "weight": 0.1, "mesh": "/Game/Mods/%s/Meshes/SM_A", '
            '"icon": "/Game/Mods/%s/Textures/T_A"}')

    def test_an_unusable_local_id_is_refused(self):
        for bad in ("Not Lowercase", "has__separator", "1leading", ""):
            root = tempfile.mkdtemp(prefix="localid-")
            self.addCleanup(shutil.rmtree, root, ignore_errors=True)
            path = fixtures.build_mod(root, "M", "themod", code=["items.py"])
            os.makedirs(os.path.join(path, "Code"), exist_ok=True)
            with open(os.path.join(path, "Code", "items.py"), "w",
                      encoding="utf-8") as handle:
                handle.write("def item_definitions():\n    return [%s]\n"
                             % (self.DECL % (bad, "themod", "themod")))
            plan = resolve.plan_from_root(root)[0]
            declarations, diagnostics = execution.item_declarations(plan)
            self.assertEqual([], declarations, "%r was accepted" % bad)
            self.assertTrue(diagnostics)

    def test_one_bad_declaration_discards_the_whole_mods_items(self):
        """A partially accepted mod must never reach the execution plan."""
        good = self.DECL % ("fine", "themod", "themod")
        bad = self.DECL % ("Not Valid", "themod", "themod")
        self._mod_with_code(
            "M", "themod",
            "def item_definitions():\n    return [%s, %s]\n" % (good, bad))
        fixtures.build_mod(self.root, "Other", "othermod")
        plan = resolve.plan_from_root(self.root)[0]
        declarations, diagnostics = execution.item_declarations(plan)
        self.assertEqual([], [d for d in declarations if d["mod_id"] == "themod"],
                         "the valid half of a broken mod's items leaked through")
        self.assertTrue(any("whole or not at all" in d.detail for d in diagnostics))

    def test_a_code_module_that_raises_contributes_nothing(self):
        self._mod_with_code("M", "themod",
                            "raise RuntimeError('boom')\n")
        plan = resolve.plan_from_root(self.root)[0]
        declarations, diagnostics = execution.item_declarations(plan)
        self.assertEqual([], declarations)
        self.assertTrue(diagnostics)

    def test_a_declaration_naming_its_own_mod_id_is_refused(self):
        decl = ('{"mod_id": "victim", "local_id": "x", "display_name": "n", '
                '"short_name": "s", "description": "d", "weight": 0.1, '
                '"mesh": "/Game/Mods/themod/Meshes/SM_A", '
                '"icon": "/Game/Mods/themod/Textures/T_A"}')
        self._mod_with_code("M", "themod",
                            "def item_definitions():\n    return [%s]\n" % decl)
        plan = resolve.plan_from_root(self.root)[0]
        declarations, diagnostics = execution.item_declarations(plan)
        self.assertEqual([], declarations)
        self.assertTrue(any("names a mod_id" in d.detail for d in diagnostics))

    def test_the_two_row_name_separators_are_the_same_constant(self):
        self.assertEqual(M.ROW_NAME_SEPARATOR, execution.ROW_NAME_SEPARATOR)


class CrossStageIdentityTests(unittest.TestCase):
    """Stage 4's mod_id rule must be acceptable to BOTH stages that consume it.

    This is the test that found the real inconsistency: Stage 3's namespace rule
    accepts ``has__sep`` (harmless inside a package path) while Stage 2's ItemId
    refuses it (it would make ``<mod_id>__<local_id>`` ambiguous to decompose).
    Each rule is correct on its own terms, and a mod_id is used by both -- so
    the set Stage 4 accepts has to be the intersection, and it has to STAY the
    intersection when either stage's rule moves.
    """

    def setUp(self):
        for path in (os.path.join(REPO, "research", "instruments", "items"),):
            if path not in sys.path:
                sys.path.insert(0, path)

    def test_stage4_separator_matches_the_one_stage2_actually_uses(self):
        import definition as stage2                                # noqa: PLC0415
        self.assertEqual(stage2.SEPARATOR, M.ROW_NAME_SEPARATOR,
                         "Stage 2 changed its row-name separator; Stage 4's "
                         "mod_id rule is now guarding the wrong character")

    def test_every_mod_id_stage4_accepts_is_accepted_by_both_stages(self):
        import definition as stage2                                # noqa: PLC0415
        import namespace as stage3                                 # noqa: PLC0415
        candidates = ["alphamod", "betamod", "a", "mod_with_underscores",
                      "m0dw1thd1g1ts", "x" * 40,
                      # things that must be refused by at least one stage
                      "has__separator", "NotLowercase", "1leading", "has-dash",
                      "misery", "", "x" * 200]
        accepted_by_stage4 = []
        for candidate in candidates:
            parsed, _problems, _declared = M.parse(
                fixtures.manifest_body(candidate), "/tmp/x", "/tmp/x/mod.json")
            if parsed is not None:
                accepted_by_stage4.append(candidate)
        self.assertTrue(accepted_by_stage4, "the test data accepts nothing")
        for mod_id in accepted_by_stage4:
            stage3.check_mod_id(mod_id)                # must not raise
            stage2.ItemId(mod_id, "someitem")          # must not raise

    def test_the_known_divergence_is_refused_by_stage4(self):
        parsed, problems, _ = M.parse(fixtures.manifest_body("has__separator"),
                                      "/tmp/x", "/tmp/x/mod.json")
        self.assertIsNone(parsed)
        self.assertIn(D.INVALID_MOD_ID, {d.code for d in problems})


class DiagnosticVocabularyTests(unittest.TestCase):
    def test_every_failure_class_the_stage_must_detect_has_a_code(self):
        # Named one by one rather than counted, so adding a code cannot make a
        # missing one look covered.
        required = {
            "missing required dependency": D.MISSING_DEPENDENCY,
            "incompatible version": D.INCOMPATIBLE_DEPENDENCY_VERSION,
            "dependency cycle": D.DEPENDENCY_CYCLE,
            "explicit conflict": D.EXPLICIT_CONFLICT,
            "duplicate ModId": D.DUPLICATE_MOD_ID,
            "malformed manifest": D.MALFORMED_MANIFEST,
            "unsupported manifest version": D.UNSUPPORTED_MANIFEST_VERSION,
            "unsupported framework API": D.UNSUPPORTED_FRAMEWORK_API,
            "missing declared artifact": D.MISSING_ARTIFACT,
        }
        for label, code in required.items():
            self.assertIn(code, D.ALL_CODES, label)
            self.assertIn(code, D.FATAL_CODES,
                          "%s must keep the mod out of the plan" % label)

    def test_an_unknown_code_cannot_be_constructed(self):
        with self.assertRaises(ValueError):
            D.Diagnostic("something_new", "modid", "detail")

    def test_only_the_informational_code_is_non_fatal(self):
        self.assertEqual({D.OPTIONAL_DEPENDENCY_ABSENT},
                         D.ALL_CODES - D.FATAL_CODES)


if __name__ == "__main__":
    unittest.main()
