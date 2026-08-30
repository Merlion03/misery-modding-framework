#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Mod Kit pipeline (Stage 3).

Offline: no Unreal, no game, no cook. Everything here is the part of the
pipeline that decides WHAT to build -- namespacing, validation, planning -- and
that part is deliberately separable from the part that runs the editor, because
a cook takes minutes and a naming mistake should not cost one.

The collision test is the one that matters most: two mods shipping byte-identical
source filenames must not produce a single overlapping object path. Inside one
container that would be a duplicate; across two mounted containers it is worse,
because IoStore answers a chunk id from whichever container it reaches first, so
one mod would silently answer for the other's assets.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "tools", "modkit"))

import fixtures                # noqa: E402
import modspec                 # noqa: E402
import namespace as ns         # noqa: E402
import profiles                # noqa: E402
import validate as V           # noqa: E402


class Namespacing(unittest.TestCase):

    def test_paths_are_deterministic(self):
        for _ in range(3):
            self.assertEqual(ns.package_path("mymod", "mesh", "Shape"),
                             "/Game/Mods/mymod/Meshes/SM_Shape")
            self.assertEqual(ns.object_path("mymod", "texture", "Icon"),
                             "/Game/Mods/mymod/Textures/T_Icon."
                             "T_Icon")

    def test_two_mods_same_asset_name_never_collide(self):
        a = ns.object_path("alphamod", "mesh", "Shape")
        b = ns.object_path("betamod", "mesh", "Shape")
        self.assertNotEqual(a, b)
        self.assertIn("alphamod", a)
        self.assertIn("betamod", b)

    def test_reserved_and_malformed_mod_ids_are_refused(self):
        for bad in ("misery", "vanilla", "Engine", "", "1mod", "my-mod", "MyMod"):
            with self.assertRaises(ns.NamespaceError, msg=bad):
                ns.check_mod_id(bad)

    def test_generated_paths_can_never_reach_vanilla_roots(self):
        for mod_id in ("mymod", "another"):
            path = ns.package_path(mod_id, "mesh", "Thing")
            for forbidden in ns.FORBIDDEN_PREFIXES:
                self.assertFalse(path.startswith(forbidden), path)

    def test_owning_mod_round_trips(self):
        path = ns.package_path("mymod", "material", "Body")
        self.assertEqual(ns.owning_mod(path), "mymod")
        self.assertIsNone(ns.owning_mod("/Game/SurvivalGameKitV2/Whatever"))

    def test_container_name_is_namespaced_and_patch_priority(self):
        self.assertEqual(ns.container_name("mymod"), "Mod_mymod_P")


class SpecValidation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="modkit-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _spec(self, mod_id="mymod"):
        return modspec.ModSpec.load(fixtures.build_fixture_mod(self.tmp, mod_id))

    def test_a_generated_fixture_validates_clean(self):
        findings = V.validate_spec(self._spec())
        self.assertEqual([], [f.as_dict() for f in findings])

    def test_missing_source_is_a_fatal_finding(self):
        spec = self._spec()
        os.remove(spec.source_of(spec.meshes[0].source))
        codes = [f.code for f in V.validate_spec(spec)]
        self.assertIn("missing_source", codes)

    def test_unknown_material_reference_is_caught(self):
        path = fixtures.build_fixture_mod(self.tmp, "refmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["meshes"][0]["slots"][0]["material"] = "NoSuchMaterial"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        codes = [f.code for f in V.validate_spec(modspec.ModSpec.load(path))]
        self.assertIn("unknown_material_reference", codes)

    def test_unknown_texture_reference_is_caught(self):
        path = fixtures.build_fixture_mod(self.tmp, "texmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["materials"][0]["base_color"] = {"texture": "Nope"}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        codes = [f.code for f in V.validate_spec(modspec.ModSpec.load(path))]
        self.assertIn("unknown_texture_reference", codes)

    def test_duplicate_object_path_is_caught(self):
        path = fixtures.build_fixture_mod(self.tmp, "dupmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["textures"].append(dict(raw["textures"][0]))
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        codes = [f.code for f in V.validate_spec(modspec.ModSpec.load(path))]
        self.assertIn("duplicate_object_path", codes)

    def test_unsupported_material_feature_is_a_named_diagnostic(self):
        path = fixtures.build_fixture_mod(self.tmp, "emitmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["materials"][0]["emissive"] = {"constant": [1.0, 0.1, 0.0]}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        findings = V.validate_spec(modspec.ModSpec.load(path))
        matched = [f for f in findings if f.code == "unsupported_material_feature"]
        self.assertTrue(matched, [f.as_dict() for f in findings])
        self.assertIn("emissive", matched[0].detail)
        self.assertTrue(matched[0].fatal,
                        "an unsupported feature must stop the build, not be dropped")

    def test_unsupported_toolchain_fails_closed(self):
        path = fixtures.build_fixture_mod(self.tmp, "oldmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["unreal_version"] = "5.3.2"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        with self.assertRaises(modspec.SpecError) as cm:
            modspec.ModSpec.load(path)
        self.assertEqual(cm.exception.code, "unsupported_toolchain")

    def test_unsupported_source_format_is_refused(self):
        path = fixtures.build_fixture_mod(self.tmp, "fmtmod")
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["meshes"][0]["source"] = "meshes/shape.blend"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        with self.assertRaises(modspec.SpecError) as cm:
            modspec.ModSpec.load(path)
        self.assertEqual(cm.exception.code, "unsupported_source")

    def test_two_mods_with_identical_filenames_produce_disjoint_paths(self):
        """The headline collision case, end to end from real files on disk."""
        a = modspec.ModSpec.load(fixtures.build_fixture_mod(self.tmp, "alphamod"))
        b = modspec.ModSpec.load(fixtures.build_fixture_mod(self.tmp, "betamod"))
        self.assertEqual(os.path.basename(a.meshes[0].source),
                         os.path.basename(b.meshes[0].source))
        pa = set(V.expected_object_paths(a))
        pb = set(V.expected_object_paths(b))
        self.assertTrue(pa and pb)
        self.assertEqual(set(), pa & pb)
        self.assertNotEqual(a.container_name(), b.container_name())


class MaterialProfiles(unittest.TestCase):

    def test_an_unmeasured_parent_is_refused_not_guessed(self):
        with self.assertRaises(profiles.UnsupportedParent):
            profiles.profile_for("/Game/Some/Other/Material")

    def test_the_measured_channel_order_is_recorded(self):
        profile = profiles.profile_for(profiles.M_BASIC)
        self.assertEqual(("ao", "roughness", "metallic"), profile["mask_channels"])

    def test_emissive_is_declared_unsupported_on_the_proven_parent(self):
        self.assertIn("emissive", profiles.profile_for(profiles.M_BASIC)
                      ["does_not_support"])


class ContainerValidation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="modkit-container-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.spec = modspec.ModSpec.load(fixtures.build_fixture_mod(self.tmp, "mymod"))
        self.packages = [p.rsplit(".", 1)[0]
                         for p in V.expected_object_paths(self.spec)]

    def test_a_clean_container_passes(self):
        report = {"chunk_types": {1: len(self.packages), 6: 1},
                  "package_paths": self.packages}
        self.assertEqual([], [f.as_dict()
                              for f in V.validate_container(self.spec, report)])

    def test_a_shader_archive_chunk_is_fatal(self):
        report = {"chunk_types": {1: 4, 6: 1, 8: 1}, "package_paths": self.packages}
        findings = V.validate_container(self.spec, report)
        self.assertTrue(any(f.code == "forbidden_shader_chunk" for f in findings))

    def test_a_missing_generated_asset_is_caught(self):
        report = {"chunk_types": {1: 1, 6: 1}, "package_paths": self.packages[:-1]}
        self.assertTrue(any(f.code == "missing_generated_asset"
                            for f in V.validate_container(self.spec, report)))

    def test_content_outside_the_mod_namespace_is_caught(self):
        report = {"chunk_types": {1: 1, 6: 1},
                  "package_paths": self.packages + ["/Game/SurvivalGameKitV2/Thing"]}
        self.assertTrue(any(f.code == "content_outside_mod_namespace"
                            for f in V.validate_container(self.spec, report)))

    def test_another_mods_content_is_caught(self):
        report = {"chunk_types": {1: 1, 6: 1},
                  "package_paths": self.packages + ["/Game/Mods/someone/Meshes/SM_X"]}
        self.assertTrue(any(f.code == "content_from_another_mod"
                            for f in V.validate_container(self.spec, report)))

    def test_no_chunk_census_is_itself_a_finding(self):
        """Silence about shader chunks is not the same as no shader chunks."""
        report = {"package_paths": self.packages}
        self.assertTrue(any(f.code == "no_chunk_census"
                            for f in V.validate_container(self.spec, report)))


class GeneratedSources(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="modkit-src-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_the_glb_is_structurally_valid(self):
        import struct
        path = fixtures.write_cube_glb(os.path.join(self.tmp, "c.glb"))
        with open(path, "rb") as handle:
            blob = handle.read()
        magic, version, length = struct.unpack_from("<4sII", blob, 0)
        self.assertEqual(b"glTF", magic)
        self.assertEqual(2, version)
        self.assertEqual(len(blob), length)
        json_len, json_tag = struct.unpack_from("<I4s", blob, 12)
        self.assertEqual(b"JSON", json_tag)
        doc = json.loads(blob[20:20 + json_len].decode("utf-8"))
        self.assertEqual(2, len(doc["meshes"][0]["primitives"]),
                         "two primitives is what gives the mesh two material slots")
        bin_len, bin_tag = struct.unpack_from("<I4s", blob, 20 + json_len)
        self.assertEqual(b"BIN\x00", bin_tag)
        self.assertEqual(len(blob), 20 + json_len + 8 + bin_len)

    def test_the_png_is_structurally_valid(self):
        path = fixtures.write_png(os.path.join(self.tmp, "t.png"), 4, 4, (10, 20, 30))
        with open(path, "rb") as handle:
            blob = handle.read()
        self.assertTrue(blob.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", blob)
        self.assertTrue(blob.rstrip().endswith(b"IEND\xaeB`\x82"))

    def test_srgb_encoding_round_trips_the_endpoints(self):
        self.assertAlmostEqual(0.0, fixtures.srgb_encode([0.0])[0], places=6)
        self.assertAlmostEqual(255.0, fixtures.srgb_encode([1.0])[0], places=3)


if __name__ == "__main__":
    unittest.main()
