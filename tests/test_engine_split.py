#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/reflection/engine_split.py (method RF-02).

Standard library only, and **no test here ever touches the live UE_5.4 install
or the game installation**. Every Engine/Source, Engine/Plugins and evidence
input is built byte by byte under a temporary directory, per the task's own
requirement: "a synthetic fixture ... so the classification logic is checked
without depending on the live UE tree or the live game container."

The fixture deliberately exercises shapes the real UE 5.4.4 tree either does
not have today, or has only once, so a decoder tuned to agree with today's
real run would still be exercised here:

  * a lowercase ``*.build.cs`` file .................. test_build_cs_case_insensitive_glob
  * a ``: SomeCustomModuleRules`` base (not the literal
    ``: ModuleRules``) ................................ test_module_rules_subclass_matches
  * a ``.uplugin`` with a trailing comma before ``]`` .. test_uplugin_trailing_comma_tolerated
  * a ``.uplugin`` with an empty/absent Modules array .. test_uplugin_with_no_modules_contributes_nothing
  * a ``.uplugin`` that is not valid JSON even after
    the trailing-comma fallback ....................... test_uplugin_parse_failure_reported_not_raised
  * two modules sharing one name across the engine
    and the game-plugin candidate sets (does NOT occur
    in the real 394 -- checks.collision_count is 0 there,
    but the branch must still be provably correct) ..... test_collision_is_reported_not_silently_resolved
  * /Script/MISERY ALSO colliding with an engine or
    game-plugin name (pathological; rule 1 must still
    win) ................................................ test_misery_rule_wins_even_on_a_collision
  * a name absent from both sets ....................... test_unclassified_is_reported_never_guessed
  * a name matching an engine name ONLY by case ......... test_case_insensitive_near_miss_is_flagged_not_matched
  * RF-01's "43 unmatched" closing check, both outcomes
    (a plugin whose OWN declared module turns out to be
    one of the 394, and one whose declared modules do
    not) ................................................ test_close_rf01_unmatched_{resolved,still_open}
  * the game-side reachability check, all three
    outcomes (all encrypted / some readable / path not
    present in pak-paths.txt at all) .................... test_check_uplugin_payload_reachability_*
  * the output-path guard (plan.md 1.5 layer 1 / D-01) .. test_out_path_inside_install_refused
  * --classes-jsonl requires --build-key ................ test_classes_jsonl_requires_build_key
  * determinism: two runs, --no-timestamp, byte-identical
    output except nothing (no timestamp to differ) ...... test_determinism_two_runs_identical
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "reflection"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import engine_split as es  # noqa: E402


# --------------------------------------------------------------------------- #
# fixture builders
# --------------------------------------------------------------------------- #

def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _write_json(path: str, obj) -> None:
    _write(path, json.dumps(obj))


def build_cs(module_name: str, base: str = "ModuleRules") -> str:
    return ("// Copyright fixture\n\nusing UnrealBuildTool;\n\n"
           "public class %s : %s\n{\n    public %s(ReadOnlyTargetRules Target)"
           " : base(Target)\n    {\n    }\n}\n" % (module_name, base, module_name))


def build_fake_engine_tree(root: str) -> str:
    """A small Engine/ tree exercising every shape listed in the module docstring.

    Returns the Engine/ directory path (what ``--ue-engine-root`` expects).
    """
    engine_root = os.path.join(root, "UE_5.4", "Engine")

    # Engine/Source -- three .Build.cs shapes.
    _write(os.path.join(engine_root, "Source", "Runtime", "FakeEngineModule",
                        "FakeEngineModule.Build.cs"),
           build_cs("FakeEngineModule"))
    # lowercase extension, like the real Steamworks.build.cs
    _write(os.path.join(engine_root, "Source", "Runtime", "Weird", "Weird.build.cs"),
           build_cs("WeirdModule"))
    # a ModuleRules SUBCLASS, like the real TestModuleRules case
    _write(os.path.join(engine_root, "Source", "Programs", "Something",
                        "Something.Build.cs"),
           build_cs("SomeTestModule", base="FixtureTestModuleRules"))

    # Engine/Plugins -- four .uplugin shapes.
    _write_json(os.path.join(engine_root, "Plugins", "Cat", "FakePlugin",
                             "FakePlugin.uplugin"),
               {"FriendlyName": "FakePlugin",
                "Modules": [{"Name": "FakePluginRuntime", "Type": "Runtime"},
                           {"Name": "FakePluginEditor", "Type": "Editor"}]})

    # trailing comma before ']' -- not standard JSON, real UE ships 34 of these
    trailing_comma_text = (
        '{\n  "FriendlyName": "TrailingCommaPlugin",\n  "Modules":\n  [\n'
        '    {\n      "Name": "TrailingCommaModule",\n      "Type": "Runtime",\n    },\n'
        '  ]\n}\n')
    _write(os.path.join(engine_root, "Plugins", "Cat", "TrailingCommaPlugin",
                        "TrailingCommaPlugin.uplugin"),
           trailing_comma_text)

    # no Modules array at all -- a real, legitimate shape (10 of 619 real files)
    _write_json(os.path.join(engine_root, "Plugins", "Cat", "EmptyModulesPlugin",
                             "EmptyModulesPlugin.uplugin"),
               {"FriendlyName": "EmptyModulesPlugin"})

    # a plugin whose FILENAME matches nothing, but whose declared module DOES
    # match one of the 394 -- the "resolved" branch of close_rf01_unmatched
    _write_json(os.path.join(engine_root, "Plugins", "Cat", "AnotherEnginePlugin",
                             "AnotherEnginePlugin.uplugin"),
               {"FriendlyName": "AnotherEnginePlugin",
                "Modules": [{"Name": "SomeOtherModuleName", "Type": "Runtime"}]})

    # not valid JSON even after the trailing-comma fallback
    _write(os.path.join(engine_root, "Plugins", "Cat", "BrokenPlugin",
                        "BrokenPlugin.uplugin"),
           "{ this is not json at all")

    return engine_root


def build_fake_evidence(root: str) -> dict:
    """RF-01/V-07/CK-01-shaped evidence files a caller does not have to open
    the live UE tree or the game to build. Returns a dict of paths.
    """
    evidence = os.path.join(root, "evidence")

    script_modules_rows = [
        "/Script/FakeEngineModule\t1\t0\t0\t0\t0",
        "/Script/WeirdModule\t1\t0\t0\t0\t0",
        "/Script/SomeTestModule\t1\t0\t0\t0\t0",
        "/Script/FakePluginRuntime\t1\t0\t0\t0\t0",
        "/Script/FakePluginEditor\t1\t0\t0\t0\t0",
        "/Script/SomeOtherModuleName\t1\t0\t0\t0\t0",
        "/Script/TrailingCommaModule\t1\t0\t0\t0\t0",
        "/Script/MISERY\t29\t5\t5\t18\t0",
        "/Script/GamePluginOne\t10\t2\t2\t0\t0",
        "/Script/GamePluginOneExtra\t3\t1\t1\t0\t0",  # unclassified, like SteamCoreShared
        "/Script/TotallyUnknownModule\t1\t0\t0\t0\t0",  # unclassified
        "/Script/fakeenginemodule\t1\t0\t0\t0\t0",  # unclassified, case near-miss only
    ]
    script_modules_path = os.path.join(evidence, "RF-01", "script-modules.tsv")
    _write(script_modules_path,
          "# fixture header comment, mirrors RF-01's own\n"
          "package\tobjects\tclasses_with_cdo\tclass_default_objects\t"
          "members_of_classes\tpackage_members_unclassified\n"
          + "\n".join(script_modules_rows) + "\n")

    staged_plugins_lines = [
        "Engine/Plugins/Cat/FakePlugin/FakePlugin.uplugin",
        "Engine/Plugins/Cat/TrailingCommaPlugin/TrailingCommaPlugin.uplugin",
        "Engine/Plugins/Cat/EmptyModulesPlugin/EmptyModulesPlugin.uplugin",
        "Engine/Plugins/Cat/AnotherEnginePlugin/AnotherEnginePlugin.uplugin",
        "Engine/Plugins/Cat/BrokenPlugin/BrokenPlugin.uplugin",
        "MISERY/MISERY.uproject",
        "MISERY/Plugins/MISERY.upluginmanifest",
        "MISERY/Plugins/SomeGame/GamePluginOne.uplugin",
    ]
    staged_plugins_path = os.path.join(evidence, "V-07", "staged-plugins.txt")
    _write(staged_plugins_path, "\n".join(staged_plugins_lines) + "\n")

    pak_paths_lines = [
        "# fixture pak-paths.txt, mirrors CK-01's own. Columns: size, uncompressed, enc, method, path.",
        "        1157         1157 E  0 MISERY/Plugins/SomeGame/GamePluginOne.uplugin",
    ]
    pak_paths_path = os.path.join(evidence, "CK-01", "pak-paths.txt")
    _write(pak_paths_path, "\n".join(pak_paths_lines) + "\n")

    rf01_json_path = os.path.join(evidence, "RF-01", "global-ucas.json")
    _write_json(rf01_json_path, {
        "staged_plugin_comparison": {
            "staged_plugin_name_with_no_module_of_that_name":
                ["EmptyModulesPlugin", "AnotherEnginePlugin"],
        },
    })

    engine_version_json_path = os.path.join(evidence, "unreal", "engine-version.json")
    _write_json(engine_version_json_path, {
        "claim": {
            "engine_cl": {"evidence": {"confidence": 0.90, "evidence_level": "INFERRED"}},
            "engine_version": {"evidence": {"confidence": 0.93, "evidence_level": "INFERRED"}},
        },
    })

    return {
        "script_modules": script_modules_path,
        "staged_plugins": staged_plugins_path,
        "pak_paths": pak_paths_path,
        "rf01_json": rf01_json_path,
        "engine_version_json": engine_version_json_path,
    }


def build_document_from_fixture(root: str, **overrides) -> dict:
    engine_root = build_fake_engine_tree(root)
    paths = build_fake_evidence(root)
    kwargs = dict(
        engine_root=engine_root,
        script_modules_path=paths["script_modules"],
        staged_plugins_path=paths["staged_plugins"],
        pak_paths_path=paths["pak_paths"],
        rf01_json_path=paths["rf01_json"],
        engine_version_json_path=paths["engine_version_json"],
        build_key="sha256:" + "0" * 64,
        recorded_at="2026-01-01T00:00:00Z",
        with_timestamp=False,
    )
    kwargs.update(overrides)
    return es.build_document(**kwargs)


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

class TestClassification(unittest.TestCase):

    def test_full_fixture_classifies_every_shape_correctly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = build_document_from_fixture(directory)
        by_bare = {row["bare_name"]: row for row in document["classification"]["rows"]}

        self.assertEqual(by_bare["FakeEngineModule"]["category"], "engine")
        self.assertEqual(by_bare["FakeEngineModule"]["evidence_kind"], "build.cs")
        self.assertEqual(by_bare["WeirdModule"]["category"], "engine",
                        "a lowercase .build.cs must match exactly like .Build.cs")
        self.assertEqual(by_bare["SomeTestModule"]["category"], "engine",
                        "a ModuleRules SUBCLASS base must still count as a module declaration")
        self.assertEqual(by_bare["FakePluginRuntime"]["category"], "engine")
        self.assertEqual(by_bare["FakePluginRuntime"]["evidence_kind"], "uplugin")
        self.assertEqual(by_bare["FakePluginEditor"]["category"], "engine")
        self.assertEqual(by_bare["SomeOtherModuleName"]["category"], "engine")
        self.assertEqual(by_bare["TrailingCommaModule"]["category"], "engine",
                        "the trailing-comma .uplugin must still parse and contribute its module")

        self.assertEqual(by_bare["MISERY"]["category"], "game-misery")
        self.assertEqual(by_bare["GamePluginOne"]["category"], "game-plugin")
        self.assertEqual(by_bare["GamePluginOne"]["evidence_kind"], "staged-uplugin-filename")

        self.assertEqual(by_bare["GamePluginOneExtra"]["category"], "unclassified",
                        "a differently-named module of a real game plugin must NOT be "
                        "force-fit into game-plugin (rule 3)")
        self.assertEqual(by_bare["TotallyUnknownModule"]["category"], "unclassified")
        self.assertEqual(by_bare["fakeenginemodule"]["category"], "unclassified",
                        "case must matter: only an EXACT string match is 'engine'")

        counts = document["classification"]["counts"]
        self.assertEqual(sum(counts.values()), len(document["classification"]["rows"]))
        self.assertEqual(counts["collision"], 0)

    def test_case_insensitive_near_miss_is_flagged_not_matched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = build_document_from_fixture(directory)
        misses = {m["bare_name"]: m["engine_names_differing_only_in_case"]
                 for m in document["classification"]["case_insensitive_near_misses"]}
        self.assertIn("fakeenginemodule", misses)
        self.assertIn("FakeEngineModule", misses["fakeenginemodule"])

    def test_unclassified_is_reported_never_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = build_document_from_fixture(directory)
        unclassified = document["classification"]["unclassified"]
        self.assertIn("TotallyUnknownModule", unclassified)
        self.assertIn("GamePluginOneExtra", unclassified)
        # every unclassified row must carry NO evidence fields (an absence,
        # never a guessed attribution)
        by_bare = {row["bare_name"]: row for row in document["classification"]["rows"]}
        for name in unclassified:
            row = by_bare[name]
            self.assertIsNone(row["matched_name"])
            self.assertIsNone(row["evidence_file"])
            self.assertIsNone(row["evidence_kind"])

    def test_collision_is_reported_not_silently_resolved(self) -> None:
        engine_names = {"Shared": [{"kind": "build.cs", "file": "Engine/Source/x.Build.cs", "line": 1}]}
        game_plugin_candidates = {"Shared": {"staged_path": "MISERY/Plugins/x/x.uplugin", "line": 1}}
        result = es.classify_modules(["/Script/Shared"], engine_names, game_plugin_candidates)
        self.assertEqual(result["rows"][0]["category"], "collision")
        self.assertEqual(result["counts"]["collision"], 1)
        self.assertEqual(len(result["collisions"]), 1)
        self.assertEqual(result["collisions"][0]["kind"], "engine-and-game-plugin")

    def test_misery_rule_wins_even_on_a_collision(self) -> None:
        """Rule 1 (MISERY) is checked BEFORE rules 2/3 -- even a pathological
        fixture where 'MISERY' also happens to be an engine or plugin name
        must still classify as game-misery, and the collision must still be
        VISIBLE (not swallowed)."""
        engine_names = {"MISERY": [{"kind": "build.cs", "file": "Engine/Source/x.Build.cs", "line": 1}]}
        result = es.classify_modules(["/Script/MISERY"], engine_names, {})
        self.assertEqual(result["rows"][0]["category"], "game-misery")
        self.assertEqual(len(result["collisions"]), 1)
        self.assertEqual(result["collisions"][0]["kind"], "MISERY-also-matched")

    def test_rows_are_sorted_deterministically_regardless_of_input_order(self) -> None:
        engine_names = {"Zeta": [{"kind": "build.cs", "file": "f", "line": 1}],
                        "Alpha": [{"kind": "build.cs", "file": "f", "line": 1}]}
        result = es.classify_modules(["/Script/Zeta", "/Script/Alpha"], engine_names, {})
        self.assertEqual([r["bare_name"] for r in result["rows"]], ["Alpha", "Zeta"])


# --------------------------------------------------------------------------- #
# engine module set construction
# --------------------------------------------------------------------------- #

class TestEngineModuleScan(unittest.TestCase):

    def test_build_cs_case_insensitive_glob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            names, stats = es.scan_engine_source_modules(engine_root, [])
        self.assertIn("WeirdModule", names)
        self.assertEqual(stats["file_count"], 3)
        self.assertEqual(stats["module_count"], 3)
        self.assertEqual(stats["files_with_zero_matches"], [])

    def test_module_rules_subclass_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            names, _stats = es.scan_engine_source_modules(engine_root, [])
        self.assertIn("SomeTestModule", names)

    def test_zero_match_file_is_warned_not_silently_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = os.path.join(directory, "Engine")
            _write(os.path.join(engine_root, "Source", "Bad", "Bad.Build.cs"),
                  "// no class declaration in this file at all\n")
            warnings: list[str] = []
            names, stats = es.scan_engine_source_modules(engine_root, warnings)
        self.assertEqual(names, {})
        self.assertEqual(stats["file_count"], 1)
        self.assertEqual(stats["files_with_zero_matches"], ["Engine/Source/Bad/Bad.Build.cs"])
        self.assertTrue(any("no 'public class" in w for w in warnings))

    def test_uplugin_trailing_comma_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            names, stats = es.scan_engine_plugin_modules(engine_root, [])
        self.assertIn("TrailingCommaModule", names)
        self.assertIn("Engine/Plugins/Cat/TrailingCommaPlugin/TrailingCommaPlugin.uplugin",
                      stats["needed_trailing_comma_fix"])

    def test_uplugin_with_no_modules_contributes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            names, _stats = es.scan_engine_plugin_modules(engine_root, [])
        self.assertNotIn("EmptyModulesPlugin", names)  # the plugin declares no module of its own name

    def test_uplugin_parse_failure_reported_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            warnings: list[str] = []
            names, stats = es.scan_engine_plugin_modules(engine_root, warnings)
        self.assertIn("Engine/Plugins/Cat/BrokenPlugin/BrokenPlugin.uplugin",
                      stats["parse_failures"])
        self.assertTrue(any("BrokenPlugin.uplugin" in w for w in warnings))
        # every OTHER file must still have been read -- one bad file must not
        # abort the whole scan
        self.assertIn("FakePluginRuntime", names)

    def test_uplugin_line_citation_finds_the_declaration(self) -> None:
        # Reopening the cited file must happen while the fixture tree still
        # exists -- it was previously outside the TemporaryDirectory block,
        # so the directory was already deleted by the time open() ran.
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            names, _stats = es.scan_engine_plugin_modules(engine_root, [])
            provenance = names["FakePluginRuntime"][0]
            self.assertIsNotNone(provenance["line"])
            with open(os.path.join(engine_root, provenance["file"].replace("Engine/", "", 1)),
                     encoding="utf-8") as handle:
                lines = handle.readlines()
            self.assertIn('"FakePluginRuntime"', lines[provenance["line"] - 1])

    def test_merge_reports_a_real_overlap(self) -> None:
        build_cs = {"Shared": [{"kind": "build.cs", "file": "a", "line": 1}]}
        uplugin = {"Shared": [{"kind": "uplugin", "file": "b", "line": 1}],
                  "OnlyPlugin": [{"kind": "uplugin", "file": "b", "line": 2}]}
        merged, overlap = es.merge_engine_names(build_cs, uplugin)
        self.assertEqual(overlap, 1)
        self.assertEqual(len(merged["Shared"]), 2, "both provenances must be kept, not one dropped")
        self.assertEqual(set(merged), {"Shared", "OnlyPlugin"})


# --------------------------------------------------------------------------- #
# JSON leniency
# --------------------------------------------------------------------------- #

class TestJsonLeniency(unittest.TestCase):

    def test_strict_json_parses_without_the_fallback(self) -> None:
        value, needed_fix = es.load_json_lenient('{"a": 1}')
        self.assertEqual(value, {"a": 1})
        self.assertFalse(needed_fix)

    def test_trailing_comma_before_bracket_is_fixed(self) -> None:
        value, needed_fix = es.load_json_lenient('{"a": [1, 2,]}')
        self.assertEqual(value, {"a": [1, 2]})
        self.assertTrue(needed_fix)

    def test_trailing_comma_before_brace_is_fixed(self) -> None:
        value, needed_fix = es.load_json_lenient('{"a": 1,}')
        self.assertEqual(value, {"a": 1})
        self.assertTrue(needed_fix)

    def test_comma_inside_a_string_value_is_left_alone(self) -> None:
        value, needed_fix = es.load_json_lenient('{"a": "x, y"}')
        self.assertEqual(value, {"a": "x, y"})
        self.assertFalse(needed_fix)

    def test_a_string_that_is_only_a_comma_is_left_alone(self) -> None:
        value, needed_fix = es.load_json_lenient('["a", ","]')
        self.assertEqual(value, ["a", ","])
        self.assertFalse(needed_fix)

    def test_unrecoverable_json_still_raises(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            es.load_json_lenient("{ not json, at all }")


# --------------------------------------------------------------------------- #
# closing RF-01's 43-unmatched finding
# --------------------------------------------------------------------------- #

class TestClosingRf01Unmatched(unittest.TestCase):

    def test_resolved_and_still_open_and_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            paths = build_fake_evidence(directory)
            unmatched = es.load_rf01_unmatched_plugins(paths["rf01_json"])
            # close_rf01_unmatched wants ALL staged names (engine-side included),
            # not just the game-plugin subset load_staged_game_plugin_candidates
            # returns -- rebuild that map the way build_document does.
            all_staged = {}
            with open(paths["staged_plugins"], encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line.lower().endswith(".uplugin"):
                        all_staged[os.path.splitext(os.path.basename(line))[0]] = line
            script_bare_names = {"FakeEngineModule", "SomeOtherModuleName", "MISERY"}
            warnings: list[str] = []
            result = es.close_rf01_unmatched(unmatched + ["NeverStaged"], all_staged,
                                             engine_root, script_bare_names, warnings)
        self.assertEqual(result["resolved_present_via_module_array_read"], 1)
        self.assertEqual([r["plugin"] for r in result["resolved_detail"]],
                        ["AnotherEnginePlugin"])
        self.assertEqual(result["resolved_detail"][0]["present_via"], ["SomeOtherModuleName"])
        self.assertEqual(result["still_open"], 1)
        self.assertEqual([r["plugin"] for r in result["still_open_detail"]],
                        ["EmptyModulesPlugin"])
        self.assertEqual(result["not_found"], 1)
        self.assertEqual(result["not_found_detail"][0]["name"], "NeverStaged")


# --------------------------------------------------------------------------- #
# game-side reachability
# --------------------------------------------------------------------------- #

class TestPayloadReachability(unittest.TestCase):

    def test_all_encrypted_is_not_reachable(self) -> None:
        candidates = {"GamePluginOne": {"staged_path": "MISERY/Plugins/x/GamePluginOne.uplugin"}}
        with tempfile.TemporaryDirectory() as directory:
            pak_paths = os.path.join(directory, "pak-paths.txt")
            _write(pak_paths, "        1000         1000 E  0 MISERY/Plugins/x/GamePluginOne.uplugin\n")
            result = es.check_uplugin_payload_reachability(candidates, pak_paths)
        self.assertFalse(result["reachable"])
        self.assertTrue(result["per_candidate"][0]["encrypted"])

    def test_an_unencrypted_entry_is_reachable(self) -> None:
        candidates = {"GamePluginOne": {"staged_path": "MISERY/Plugins/x/GamePluginOne.uplugin"}}
        with tempfile.TemporaryDirectory() as directory:
            pak_paths = os.path.join(directory, "pak-paths.txt")
            _write(pak_paths, "        1000         1000 -  0 MISERY/Plugins/x/GamePluginOne.uplugin\n")
            result = es.check_uplugin_payload_reachability(candidates, pak_paths)
        self.assertTrue(result["reachable"])
        self.assertFalse(result["per_candidate"][0]["encrypted"])

    def test_a_path_missing_from_pak_paths_is_not_reachable_and_says_so(self) -> None:
        candidates = {"GamePluginOne": {"staged_path": "MISERY/Plugins/x/GamePluginOne.uplugin"}}
        with tempfile.TemporaryDirectory() as directory:
            pak_paths = os.path.join(directory, "pak-paths.txt")
            _write(pak_paths, "        1000         1000 E  0 MISERY/Plugins/other/Other.uplugin\n")
            result = es.check_uplugin_payload_reachability(candidates, pak_paths)
        self.assertFalse(result["reachable"])
        self.assertFalse(result["per_candidate"][0]["found_in_pak_paths"])

    def test_a_path_containing_a_space_is_parsed_whole(self) -> None:
        candidates = {"X": {"staged_path": "MISERY/Plugins/My Plugin/X.uplugin"}}
        with tempfile.TemporaryDirectory() as directory:
            pak_paths = os.path.join(directory, "pak-paths.txt")
            _write(pak_paths, "        1000         1000 E  0 MISERY/Plugins/My Plugin/X.uplugin\n")
            result = es.check_uplugin_payload_reachability(candidates, pak_paths)
        self.assertTrue(result["per_candidate"][0]["found_in_pak_paths"])


# --------------------------------------------------------------------------- #
# classes.jsonl patching
# --------------------------------------------------------------------------- #

class TestPatchReflectionJsonl(unittest.TestCase):

    def test_patches_known_leaves_unknown_null_preserves_other_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "classes.jsonl")
            rows = [
                {"kind": "class", "raw_name": "A", "module": "FakeEngineModule"},
                {"kind": "class", "raw_name": "B", "module": "TotallyUnknownModule"},
                {"kind": "class", "raw_name": "C", "module": None},
            ]
            with open(path, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
            stats = es.patch_reflection_jsonl(path, {"FakeEngineModule": "engine"})
            with open(path, encoding="utf-8") as handle:
                patched = [json.loads(line) for line in handle]
        self.assertEqual(stats["rows_total"], 3)
        self.assertEqual(stats["rows_patched"], 1)
        self.assertEqual(stats["rows_module_origin_null"], 2)
        by_name = {r["raw_name"]: r for r in patched}
        self.assertEqual(by_name["A"]["module_origin"], "engine")
        self.assertIsNone(by_name["B"]["module_origin"])
        self.assertIsNone(by_name["C"]["module_origin"])
        # nothing else about the row was touched
        self.assertEqual(by_name["A"]["kind"], "class")
        self.assertEqual(by_name["A"]["module"], "FakeEngineModule")

    def test_output_is_sorted_keys_one_object_per_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "classes.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"module": "X", "kind": "class"}) + "\n")
            es.patch_reflection_jsonl(path, {"X": "engine"})
            with open(path, encoding="utf-8") as handle:
                lines = [line for line in handle if line.strip()]
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["module_origin"], "engine")
        # sort_keys=True: 'kind' < 'module' < 'module_origin' alphabetically
        self.assertLess(lines[0].index('"kind"'), lines[0].index('"module"'))
        self.assertLess(lines[0].index('"module"'), lines[0].index('"module_origin"'))


# --------------------------------------------------------------------------- #
# CLI / integration
# --------------------------------------------------------------------------- #

class TestCli(unittest.TestCase):

    def test_full_run_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            paths = build_fake_evidence(directory)
            out = os.path.join(directory, "out")
            os.makedirs(out)
            code = es.main([
                "--ue-engine-root", engine_root,
                "--script-modules", paths["script_modules"],
                "--staged-plugins", paths["staged_plugins"],
                "--pak-paths", paths["pak_paths"],
                "--rf01-json", paths["rf01_json"],
                "--engine-version-json", paths["engine_version_json"],
                "--out", os.path.join(out, "engine-split.json"),
                "--modules-out", os.path.join(out, "module-classification.tsv"),
                "--engine-index-out", os.path.join(out, "engine-module-index.tsv"),
                "--no-timestamp",
            ])
        self.assertEqual(code, 0)

    def test_classes_jsonl_requires_build_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            classes_path = os.path.join(directory, "classes.jsonl")
            _write(classes_path, json.dumps({"kind": "class", "module": "X"}) + "\n")
            code = es.main(["--classes-jsonl", classes_path])
        self.assertEqual(code, 2)

    def test_out_path_inside_install_refused(self) -> None:
        """plan.md 1.5 layer 1 / D-01: nothing is ever written into a game
        installation, not even a temp file."""
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            paths = build_fake_evidence(directory)
            install = os.path.join(directory, "install")
            os.makedirs(install)
            target = os.path.join(install, "x.json")
            code = es.main([
                "--ue-engine-root", engine_root,
                "--script-modules", paths["script_modules"],
                "--staged-plugins", paths["staged_plugins"],
                "--pak-paths", paths["pak_paths"],
                "--rf01-json", paths["rf01_json"],
                "--out", target,
                "--install-dir", install,
            ])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(target))

    def test_determinism_two_runs_are_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            paths = build_fake_evidence(directory)
            run1 = os.path.join(directory, "run1.json")
            run2 = os.path.join(directory, "run2.json")
            for target in (run1, run2):
                code = es.main([
                    "--ue-engine-root", engine_root,
                    "--script-modules", paths["script_modules"],
                    "--staged-plugins", paths["staged_plugins"],
                    "--pak-paths", paths["pak_paths"],
                    "--rf01-json", paths["rf01_json"],
                    "--engine-version-json", paths["engine_version_json"],
                    "--out", target,
                    "--build-key", "sha256:" + "0" * 64,
                    "--recorded-at", "2026-01-01T00:00:00Z",
                    "--no-timestamp",
                ])
                self.assertEqual(code, 0)
            with open(run1, "rb") as handle:
                body1 = handle.read()
            with open(run2, "rb") as handle:
                body2 = handle.read()
        self.assertEqual(body1, body2)

    def test_subprocess_invocation_matches_library_call(self) -> None:
        """Exercises the real ``if __name__ == '__main__'`` entry point, not
        just importing the module -- catches an argv/exit-code wiring bug an
        in-process call to main() cannot."""
        with tempfile.TemporaryDirectory() as directory:
            engine_root = build_fake_engine_tree(directory)
            paths = build_fake_evidence(directory)
            out = os.path.join(directory, "out.json")
            completed = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "tools", "reflection",
                                              "engine_split.py"),
                 "--ue-engine-root", engine_root,
                 "--script-modules", paths["script_modules"],
                 "--staged-plugins", paths["staged_plugins"],
                 "--pak-paths", paths["pak_paths"],
                 "--rf01-json", paths["rf01_json"],
                 "--out", out, "--no-timestamp"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, msg=completed.stderr)
            self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
