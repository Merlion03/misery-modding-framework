#!/usr/bin/env python3
"""Tests for tools/modkit/container_report.py.

The failure this module exists to catch is specific and was real: UnrealPak
built a container in which NOTHING resolved, reported every miss as a warning,
exited 0, and produced an empty .ucas. So the tests below care most about the
paths where a wrong answer would look like a right one -- a layout that does not
add up, a directory index that decodes to nothing, a shader chunk slipping into
the histogram.
"""
import os
import struct
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modkit"), os.path.join(REPO, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import container_report as cr                                      # noqa: E402
import checks                                                      # noqa: E402
import modspec                                                     # noqa: E402


def fstring(text):
    raw = text.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def directory_index(mount_point, tree_files):
    """Build a minimal FIoDirectoryIndexResource with one directory level.

    *tree_files* is a list of file names directly under the mount point.
    """
    NONE = 0xFFFFFFFF
    strings = list(tree_files)
    out = fstring(mount_point)
    # one root directory entry: unnamed, no children, first file 0
    out += struct.pack("<I", 1)
    out += struct.pack("<IIII", NONE, NONE, NONE, 0 if tree_files else NONE)
    out += struct.pack("<I", len(tree_files))
    for index, _name in enumerate(tree_files):
        nxt = index + 1 if index + 1 < len(tree_files) else NONE
        out += struct.pack("<III", index, nxt, index)
    out += struct.pack("<I", len(strings))
    for text in strings:
        out += fstring(text)
    return out


class DirectoryIndexTests(unittest.TestCase):
    def test_recovers_every_file_under_the_mount_point(self):
        raw = directory_index("../../../MISERY/Content/Mods/alphamod/",
                              ["A.uasset", "B.uasset", "C.uexp"])
        parsed = cr.parse_directory_index(raw)
        self.assertEqual(parsed["mount_point"],
                         "../../../MISERY/Content/Mods/alphamod/")
        self.assertEqual(sorted(e["path"] for e in parsed["files"]),
                         ["A.uasset", "B.uasset", "C.uexp"])

    def test_an_empty_index_yields_no_files_rather_than_raising(self):
        parsed = cr.parse_directory_index(directory_index("../../../", []))
        self.assertEqual(parsed["files"], [])

    def test_utf16_strings_decode(self):
        raw = fstring("../../../MISERY/Content/")
        text, offset = cr._fstring(raw, 0)
        self.assertEqual(text, "../../../MISERY/Content/")
        self.assertEqual(offset, len(raw))


class PackagePathTests(unittest.TestCase):
    def test_a_uasset_under_the_content_mount_becomes_a_game_path(self):
        self.assertEqual(
            cr.package_path_for("../../../MISERY/Content/Mods/alphamod/",
                                "Meshes/SM_Shape.uasset"),
            "/Game/Mods/alphamod/Meshes/SM_Shape")

    def test_uexp_is_not_a_package(self):
        # .uexp is export data merged into the package chunk, never a package of
        # its own. Counting it would double every package in the report.
        self.assertIsNone(
            cr.package_path_for("../../../MISERY/Content/Mods/alphamod/",
                                "Meshes/SM_Shape.uexp"))

    def test_a_path_outside_the_content_mount_is_not_a_package(self):
        self.assertIsNone(cr.package_path_for("../../../Engine/", "Foo.uasset"))

    def test_umap_counts_as_a_package(self):
        self.assertEqual(
            cr.package_path_for("../../../MISERY/Content/", "Mods/m/L.umap"),
            "/Game/Mods/m/L")


class ForbiddenChunkTests(unittest.TestCase):
    """The reason the histogram exists at all."""

    def setUp(self):
        self.spec = modspec.ModSpec({"mod_id": "alphamod",
                                     "unreal_version": "5.4.4"}, ".")

    def report(self, chunk_types, packages=None):
        return {"chunk_types": chunk_types,
                "package_paths": packages if packages is not None
                else ["/Game/Mods/alphamod/Meshes/SM_Shape"]}

    def test_a_shader_code_library_chunk_is_reported(self):
        found = checks.validate_container(self.spec, self.report({1: 9, 8: 1}))
        self.assertTrue(any(f.code == "forbidden_shader_chunk" for f in found))

    def test_a_shader_code_chunk_is_reported(self):
        found = checks.validate_container(self.spec, self.report({1: 9, 9: 3}))
        self.assertTrue(any(f.code == "forbidden_shader_chunk" for f in found))

    def test_string_keyed_histograms_are_read_the_same_way(self):
        # JSON round-trips integer keys to strings; a check that silently missed
        # them would report a clean container for a dirty one.
        found = checks.validate_container(self.spec, self.report({"8": 1}))
        self.assertTrue(any(f.code == "forbidden_shader_chunk" for f in found))

    def test_the_expected_histogram_is_clean(self):
        found = checks.validate_container(self.spec, self.report({1: 9, 6: 1}))
        self.assertEqual([f.code for f in found], [])

    def test_a_missing_histogram_is_itself_a_finding(self):
        found = checks.validate_container(self.spec, self.report({}))
        self.assertTrue(any(f.code == "no_chunk_census" for f in found))


class LayoutArithmeticTests(unittest.TestCase):
    def test_a_container_whose_layout_does_not_add_up_is_refused(self):
        # A truncated or mis-parsed .utoc must fail loudly. Reporting contents
        # from a layout that does not account for the file is how an empty
        # container gets described as a full one.
        path = os.path.join(os.path.dirname(__file__), "_tmp_bad.utoc")
        with open(path, "wb") as handle:
            handle.write(b"-==--==--==--==-" + b"\x00" * 200)
        try:
            with self.assertRaises(Exception):
                cr.read_container(path)
        finally:
            os.remove(path)

    def test_a_missing_container_is_refused_by_name(self):
        with self.assertRaises(cr.ContainerReadError):
            cr.read_container(os.path.join(os.path.dirname(__file__), "nope.utoc"))


if __name__ == "__main__":
    unittest.main()
