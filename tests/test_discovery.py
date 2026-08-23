#!/usr/bin/env python3
"""Unit tests for tools/discovery (plan.md 2; exit criterion 3 of milestone M0).

Standard library only. These tests NEVER touch the real game installation and never read
the real registry: every case builds a synthetic Steam library and a synthetic install
tree under a temporary directory, and the registry helpers are replaced with fakes. The
mandatory case named by plan.md 2.3 -- "покрыт unit-тестом на разобранный
libraryfolders.vdf" -- is TestLibraryFolders below.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DISCOVERY = os.path.join(REPO_ROOT, "tools", "discovery")
TOOLS_INVENTORY = os.path.join(REPO_ROOT, "tools", "inventory")
for _directory in (TOOLS_DISCOVERY, TOOLS_INVENTORY):
    if _directory not in sys.path:
        sys.path.insert(0, _directory)

import find_misery as fm  # noqa: E402
import pathguard  # noqa: E402  (the shared plan.md 1.5 layer 1 guard find_misery imports)

SCHEMA_PATH = os.path.join(REPO_ROOT, "research", "schema", "install.schema.json")

# A SteamID64-shaped value that is NOT anybody's account. The real appmanifest on the
# research machine carries a real LastOwner; this fixture stands in for it so the test can
# assert the field never reaches the output without putting a real id in a public repo.
FAKE_LAST_OWNER = "76561190000000000"

# Structurally faithful trimmed copy of appmanifest_2119830.acf, including the nested
# InstalledDepots block and the SharedDepots block, and including LastOwner on purpose.
ACF_FIXTURE = '''"AppState"
{
\t"appid"\t\t"2119830"
\t"universe"\t\t"1"
\t"name"\t\t"MISERY"
\t"StateFlags"\t\t"4"
\t"installdir"\t\t"MISERY"
\t"LastUpdated"\t\t"1787394913"
\t"SizeOnDisk"\t\t"5057001973"
\t"buildid"\t\t"24826585"
\t"LastOwner"\t\t"%s"
\t"InstalledDepots"
\t{
\t\t"2119831"
\t\t{
\t\t\t"manifest"\t\t"3002776385514127223"
\t\t\t"size"\t\t"5057001973"
\t\t}
\t}
\t"SharedDepots"
\t{
\t\t"228989"\t\t"228980"
\t\t"228990"\t\t"228980"
\t\t"229007"\t\t"228980"
\t}
\t"UserConfig"
\t{
\t\t"language"\t\t"english"
\t}
}
''' % FAKE_LAST_OWNER


def vdf_quote(path: str) -> str:
    """Spell a Windows path the way Steam writes it inside KeyValues: doubled slashes."""
    return path.replace("\\", "\\\\")


def libraryfolders_fixture(paths: list[str]) -> str:
    """Current-format libraryfolders.vdf listing several libraries.

    Library 0 does NOT list app 2119830 in its apps block; library 1 does. That ordering
    is deliberate: it proves the enumeration does not simply take the first library.
    """
    blocks = []
    for index, path in enumerate(paths):
        if index == 1:
            apps = '\t\t\t"2119830"\t\t"5057001973"\n\t\t\t"228980"\t\t"324225172"\n'
        else:
            apps = '\t\t\t"4500"\t\t"5987020482"\n'
        blocks.append(
            '\t"%d"\n\t{\n\t\t"path"\t\t"%s"\n\t\t"label"\t\t""\n'
            '\t\t"contentid"\t\t"506000248684188319%d"\n'
            '\t\t"apps"\n\t\t{\n%s\t\t}\n\t}\n' % (index, vdf_quote(path), index, apps)
        )
    return '"libraryfolders"\n{\n%s}\n' % "".join(blocks)


def write_file(path: str, content: str | bytes = "") -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    kwargs = {} if isinstance(content, bytes) else {"encoding": "utf-8", "newline": "\n"}
    with open(path, mode, **kwargs) as handle:
        handle.write(content)
    return path


def make_install_tree(root: str, shipping: bool = True, global_utoc: bool = True,
                      big_secondary: bool = True, paks: bool = True) -> str:
    """Synthetic MISERY installation. Sizes are token-sized but the LAYOUT is real."""
    win64 = os.path.join(root, "MISERY", "Binaries", "Win64")
    if shipping:
        write_file(os.path.join(win64, "MISERY-Win64-Shipping.exe"), b"MZ" + b"S" * 64)
    if big_secondary:
        # Deliberately LARGER than the Shipping image, mirroring reality (282 MB vs
        # 134 MB) so the D-04 test cannot pass by accident of file ordering or size.
        write_file(os.path.join(win64, "MISERY.exe"), b"MZ" + b"D" * 4096)
    write_file(os.path.join(root, "MISERY.exe"), b"MZ" + b"L" * 32)
    if paks:
        paks_dir = os.path.join(root, "MISERY", "Content", "Paks")
        if global_utoc:
            write_file(os.path.join(paks_dir, "global.utoc"), b"\x2d\x3d\x38\x8f" + b"0" * 60)
            write_file(os.path.join(paks_dir, "global.ucas"), b"g" * 128)
        write_file(os.path.join(paks_dir, "MISERY-Windows.utoc"), b"\x2d\x3d\x38\x8f" + b"1" * 40)
        write_file(os.path.join(paks_dir, "MISERY-Windows.ucas"), b"m" * 512)
        write_file(os.path.join(paks_dir, "MISERY-Windows.pak"), b"p" * 256)
    return root


def make_steam_library(steam_root: str, extra_libraries: list[str],
                       acf: str | None = ACF_FIXTURE,
                       installdir: str = "MISERY") -> str:
    """Steam root whose libraryfolders.vdf lists steam_root plus extra_libraries.

    The app manifest is placed in extra_libraries[0], i.e. library index 1 -- the one
    whose apps block lists the app id.
    """
    libraries = [steam_root] + extra_libraries
    write_file(os.path.join(steam_root, "steamapps", "libraryfolders.vdf"),
               libraryfolders_fixture(libraries))
    holder = extra_libraries[0] if extra_libraries else steam_root
    if acf is not None:
        write_file(os.path.join(holder, "steamapps", "appmanifest_2119830.acf"), acf)
    make_install_tree(os.path.join(holder, "steamapps", "common", installdir))
    return steam_root


class EnvSandbox(unittest.TestCase):
    """Base class: no MISERY_GAME_DIR from the developer's shell may reach a test, and
    no test may reach the real registry."""

    def setUp(self) -> None:
        self._saved_env = os.environ.pop(fm.ENV_OVERRIDE, None)
        self._saved_winreg = fm._winreg
        fm._winreg = lambda: None  # registry absent -> steps 2 and 7 must degrade
        self.tmp = tempfile.TemporaryDirectory(prefix="misery-discovery-")
        self.addCleanup(self.tmp.cleanup)
        # realpath: some Windows hosts hand out TEMP in 8.3 short form while the
        # code under test resolves paths to their long form; comparing a raw temp
        # path against a resolved one then fails there and passes here.
        # tests/test_inventory.py already resolves at this point.
        self.root = os.path.realpath(self.tmp.name)
        # An empty repo root, so research/config/local.json is genuinely absent.
        self.repo_root = os.path.join(self.root, "repo")
        os.makedirs(self.repo_root, exist_ok=True)

    def tearDown(self) -> None:
        fm._winreg = self._saved_winreg
        if self._saved_env is not None:
            os.environ[fm.ENV_OVERRIDE] = self._saved_env
        else:
            os.environ.pop(fm.ENV_OVERRIDE, None)

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = fm.main(argv + ["--repo-root", self.repo_root])
        return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# plan.md 2.3: mandatory unit test over a parsed libraryfolders.vdf
# ---------------------------------------------------------------------------


class TestLibraryFolders(unittest.TestCase):
    def test_several_libraries_are_all_enumerated(self) -> None:
        text = libraryfolders_fixture(
            [r"D:\Games\Steam", r"E:\SteamLibrary", r"C:\Program Files (x86)\Steam"]
        )
        libraries = fm.parse_libraryfolders(text)
        self.assertEqual(3, len(libraries))
        self.assertEqual(
            [r"D:\Games\Steam", r"E:\SteamLibrary", r"C:\Program Files (x86)\Steam"],
            [entry["path"] for entry in libraries],
        )
        self.assertEqual(["0", "1", "2"], [entry["key"] for entry in libraries])

    def test_apps_block_is_parsed_with_sizes(self) -> None:
        libraries = fm.parse_libraryfolders(
            libraryfolders_fixture([r"D:\Games\Steam", r"E:\SteamLibrary"])
        )
        self.assertNotIn("2119830", libraries[0]["apps"])
        self.assertEqual(5057001973, libraries[1]["apps"]["2119830"])
        self.assertEqual(324225172, libraries[1]["apps"]["228980"])

    def test_paths_are_normalized_to_one_spelling(self) -> None:
        # Forward slashes (as the HKCU SteamPath value uses) collapse to backslashes, the
        # trailing separator goes, the drive letter is upper-cased. Directory-name casing
        # is left alone on purpose: it comes from the filesystem, which is the authority
        # on it, and rewriting it would make the output differ from what Steam wrote.
        text = '"libraryfolders"\n{\n\t"0"\n\t{\n\t\t"path"\t\t"d:/games/steam/"\n\t}\n}\n'
        self.assertEqual(r"D:\games\steam", fm.parse_libraryfolders(text)[0]["path"])

    def test_legacy_flat_format(self) -> None:
        text = (
            '"LibraryFolders"\n{\n'
            '\t"TimeNextStatsReport"\t\t"1787394913"\n'
            '\t"ContentStatsID"\t\t"-123456789"\n'
            '\t"1"\t\t"E:\\\\SteamLibrary"\n'
            '\t"2"\t\t"F:\\\\Games"\n'
            "}\n"
        )
        libraries = fm.parse_libraryfolders(text)
        self.assertEqual([r"E:\SteamLibrary", r"F:\Games"],
                         [entry["path"] for entry in libraries])
        self.assertEqual([{}, {}], [entry["apps"] for entry in libraries])

    def test_bookkeeping_keys_are_not_libraries(self) -> None:
        text = (
            '"libraryfolders"\n{\n'
            '\t"TimeNextStatsReport"\t\t"1787394913"\n'
            '\t"0"\n\t{\n\t\t"path"\t\t"D:\\\\Games\\\\Steam"\n\t}\n}\n'
        )
        self.assertEqual(1, len(fm.parse_libraryfolders(text)))

    def test_entry_without_path_is_dropped_not_crashed(self) -> None:
        text = (
            '"libraryfolders"\n{\n'
            '\t"0"\n\t{\n\t\t"label"\t\t""\n\t}\n'
            '\t"1"\n\t{\n\t\t"path"\t\t"E:\\\\SteamLibrary"\n\t}\n}\n'
        )
        self.assertEqual([r"E:\SteamLibrary"],
                         [entry["path"] for entry in fm.parse_libraryfolders(text)])

    def test_comments_and_malformed_input(self) -> None:
        text = (
            '// written by Steam\n"libraryfolders"\n{\n'
            '\t"0"\n\t{\n\t\t"path"\t\t"D:\\\\Games\\\\Steam"\n\t}\n}\n'
        )
        self.assertEqual(1, len(fm.parse_libraryfolders(text)))
        with self.assertRaises(fm.VdfError):
            fm.parse_vdf('"libraryfolders"\n{\n\t"0"\t\t"unterminated\n')


# ---------------------------------------------------------------------------
# plan.md 2.1 step 4: app manifest
# ---------------------------------------------------------------------------


class TestAppManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = fm.extract_appmanifest(fm.parse_vdf(ACF_FIXTURE))

    def test_scalar_fields(self) -> None:
        self.assertEqual(2119830, self.manifest["app_id"])
        self.assertEqual("MISERY", self.manifest["installdir"])
        self.assertEqual(24826585, self.manifest["buildid"])
        self.assertEqual(5057001973, self.manifest["size_on_disk"])
        self.assertEqual(4, self.manifest["state_flags"])

    def test_nested_installed_depots(self) -> None:
        self.assertEqual(
            {"2119831": {"manifest": "3002776385514127223", "size": 5057001973}},
            self.manifest["depots"],
        )
        # The depot manifest id exceeds the exact-integer range of a JSON double, so it
        # must stay a decimal STRING (install.schema.json requires the same).
        self.assertIsInstance(self.manifest["depots"]["2119831"]["manifest"], str)
        self.assertEqual(
            3002776385514127223,
            int(self.manifest["depots"]["2119831"]["manifest"]),
        )

    def test_shared_depots_are_sorted_strings(self) -> None:
        self.assertEqual(["228989", "228990", "229007"], self.manifest["shared_depots"])
        for value in self.manifest["shared_depots"]:
            self.assertIsInstance(value, str)

    def test_last_owner_is_only_recorded_as_a_boolean(self) -> None:
        self.assertTrue(self.manifest["last_owner_present"])
        # extract_appmanifest whitelists fields; the only place the raw value survives is
        # the underscore-prefixed key that main() pops before building the document.
        exported = {key: value for key, value in self.manifest.items()
                    if not key.startswith("_")}
        self.assertNotIn("last_owner", exported)
        self.assertNotIn(FAKE_LAST_OWNER, json.dumps(exported))

    def test_unknown_future_steam_fields_do_not_leak(self) -> None:
        text = ACF_FIXTURE.replace(
            '\t"universe"\t\t"1"\n',
            '\t"universe"\t\t"1"\n\t"SomeFutureAccountField"\t\t"76561190000000001"\n',
        )
        manifest = fm.extract_appmanifest(fm.parse_vdf(text))
        exported = {key: value for key, value in manifest.items()
                    if not key.startswith("_")}
        self.assertNotIn("76561190000000001", json.dumps(exported))

    def test_missing_blocks_yield_empty_containers_not_exceptions(self) -> None:
        manifest = fm.extract_appmanifest(fm.parse_vdf('"AppState"\n{\n\t"appid"\t"1"\n}\n'))
        self.assertEqual({}, manifest["depots"])
        self.assertEqual([], manifest["shared_depots"])
        self.assertFalse(manifest["last_owner_present"])
        self.assertIsNone(manifest["buildid"])

    def test_case_insensitive_keys(self) -> None:
        manifest = fm.extract_appmanifest(
            fm.parse_vdf(ACF_FIXTURE.replace('"installdir"', '"InstallDir"'))
        )
        self.assertEqual("MISERY", manifest["installdir"])


# ---------------------------------------------------------------------------
# plan.md 2.1 step 6: validation against a synthetic install tree
# ---------------------------------------------------------------------------


class TestValidation(EnvSandbox):
    def test_complete_tree_passes(self) -> None:
        install = make_install_tree(os.path.join(self.root, "good"))
        result = fm.validate_install(install)
        self.assertTrue(result["shipping_exe_present"])
        self.assertTrue(result["global_utoc_present"])
        self.assertEqual([], result["errors"])
        # 3 executables + 2 .utoc + 2 .ucas + 1 .pak, i.e. everything make_install_tree
        # created -- the count must be of the tree, not of the two validated files.
        self.assertEqual(8, result["file_count"])
        self.assertTrue(result["read_only_respected"])

    def test_missing_shipping_exe_names_check_one(self) -> None:
        install = make_install_tree(os.path.join(self.root, "no-exe"), shipping=False)
        result = fm.validate_install(install)
        self.assertFalse(result["shipping_exe_present"])
        self.assertTrue(result["global_utoc_present"])
        self.assertEqual(1, len(result["errors"]))
        self.assertIn("check 1 failed", result["errors"][0])
        self.assertIn("MISERY-Win64-Shipping.exe", result["errors"][0])

    def test_missing_global_utoc_names_check_two(self) -> None:
        install = make_install_tree(os.path.join(self.root, "no-utoc"), global_utoc=False)
        result = fm.validate_install(install)
        self.assertTrue(result["shipping_exe_present"])
        self.assertFalse(result["global_utoc_present"])
        self.assertEqual(1, len(result["errors"]))
        self.assertIn("check 2 failed", result["errors"][0])
        self.assertIn("global.utoc", result["errors"][0])

    def test_both_missing_reports_both(self) -> None:
        install = make_install_tree(os.path.join(self.root, "empty"),
                                    shipping=False, paks=False)
        result = fm.validate_install(install)
        self.assertEqual(2, len(result["errors"]))

    def test_absent_directory(self) -> None:
        result = fm.validate_install(os.path.join(self.root, "nope"))
        self.assertFalse(result["shipping_exe_present"])
        self.assertIsNone(result["file_count"])
        self.assertIn("not a directory", result["errors"][0])


class TestExecutablesAndContainers(EnvSandbox):
    def test_primary_is_the_shipping_image_never_the_bigger_exe(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        primary, shim, secondary = fm.relative_executables(install)
        # Decision D-04: MISERY\Binaries\Win64\MISERY.exe is bigger, and is still only a
        # secondary read-only oracle.
        self.assertEqual(fm.SHIPPING_EXE_REL, primary)
        self.assertEqual("MISERY.exe", shim)
        self.assertEqual(["MISERY\\Binaries\\Win64\\MISERY.exe"], secondary)
        big = os.path.getsize(os.path.join(install, "MISERY", "Binaries", "Win64",
                                           "MISERY.exe"))
        small = os.path.getsize(os.path.join(install, fm.SHIPPING_EXE_REL.replace("\\", os.sep)))
        self.assertGreater(big, small)
        self.assertNotEqual(primary, secondary[0])

    def test_containers_carry_name_kind_size_and_sibling(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        containers = fm.enumerate_containers(install)
        by_path = {entry["path"]: entry for entry in containers}
        self.assertEqual(
            [
                "MISERY/Content/Paks/MISERY-Windows.pak",
                "MISERY/Content/Paks/MISERY-Windows.ucas",
                "MISERY/Content/Paks/MISERY-Windows.utoc",
                "MISERY/Content/Paks/global.ucas",
                "MISERY/Content/Paks/global.utoc",
            ],
            [entry["path"] for entry in containers],
        )
        self.assertEqual("utoc", by_path["MISERY/Content/Paks/global.utoc"]["kind"])
        self.assertEqual("ucas", by_path["MISERY/Content/Paks/global.ucas"]["kind"])
        self.assertEqual("pak", by_path["MISERY/Content/Paks/MISERY-Windows.pak"]["kind"])
        self.assertEqual(
            "MISERY/Content/Paks/global.ucas",
            by_path["MISERY/Content/Paks/global.utoc"]["sibling_path"],
        )
        self.assertIsNone(by_path["MISERY/Content/Paks/MISERY-Windows.pak"]["sibling_path"])
        for entry in containers:
            self.assertEqual(os.path.getsize(
                os.path.join(install, entry["path"].replace("/", os.sep))), entry["size"])
            # Discovery does not hash: null means "not measured" (plan.md 3.2, task F-02).
            self.assertIsNone(entry["sha256"])

    def test_missing_paks_dir_yields_empty_list(self) -> None:
        install = make_install_tree(os.path.join(self.root, "nopaks"), paks=False)
        self.assertEqual([], fm.enumerate_containers(install))


# ---------------------------------------------------------------------------
# C-13: privacy
# ---------------------------------------------------------------------------


class TestPathHandling(unittest.TestCase):
    def test_default_repo_root_is_the_repository(self) -> None:
        # find_misery.py lives in <repo>/tools/discovery/, so this must be three levels
        # up, not two: with two, research/config/local.json was looked for under tools/.
        root = fm.default_repo_root()
        self.assertTrue(os.path.isfile(os.path.join(root, "plan.md")), root)
        self.assertTrue(os.path.isdir(os.path.join(root, "research", "schema")), root)

    def test_canonical_case_takes_the_case_from_the_filesystem(self) -> None:
        with tempfile.TemporaryDirectory(prefix="misery-case-") as _tmp:
            tmp = os.path.realpath(_tmp)  # 8.3 short form on some CI hosts
            real = os.path.join(tmp, "MixedCase", "SubDir")
            os.makedirs(real)
            self.assertEqual(fm.normalize_path(real),
                             fm.canonical_case(real.lower()))
            self.assertEqual(fm.normalize_path(real),
                             fm.canonical_case(real.replace("\\", "/").upper()))

    def test_canonical_case_leaves_a_nonexistent_path_alone(self) -> None:
        self.assertEqual(r"D:\no\such\PLACE",
                         fm.canonical_case("d:/no/such/PLACE"))

    def test_canonical_case_leaves_a_unc_path_alone(self) -> None:
        self.assertEqual(r"\\server\share\Steam",
                         fm.canonical_case(r"\\server\share\Steam"))


class TestPrivacy(unittest.TestCase):
    def test_profile_paths_become_placeholders(self) -> None:
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            self.skipTest("LOCALAPPDATA is not set")
        self.assertEqual(
            "%LOCALAPPDATA%\\MISERY\\Saved\\Logs",
            fm.privatize_path(os.path.join(local, "MISERY", "Saved", "Logs")),
        )
        self.assertEqual("%LOCALAPPDATA%", fm.privatize_path(local))

    def test_localappdata_wins_over_userprofile(self) -> None:
        local = os.environ.get("LOCALAPPDATA")
        profile = os.environ.get("USERPROFILE")
        if not local or not profile:
            self.skipTest("profile environment variables are not set")
        if not local.lower().startswith(profile.lower()):
            self.skipTest("LOCALAPPDATA is not inside USERPROFILE on this machine")
        self.assertTrue(fm.privatize_path(local + "\\x").startswith("%LOCALAPPDATA%"))

    def test_paths_outside_the_profile_are_untouched(self) -> None:
        self.assertEqual(r"D:\Games\Steam", fm.privatize_path("D:/Games/Steam/"))

    def test_check_privacy_finds_a_planted_account_id(self) -> None:
        self.assertEqual([FAKE_LAST_OWNER],
                         fm.check_privacy('{"x": "%s"}' % FAKE_LAST_OWNER,
                                          [FAKE_LAST_OWNER]))
        self.assertEqual([], fm.check_privacy('{"x": "D:\\\\Games"}', [FAKE_LAST_OWNER]))

    def test_check_privacy_backstops_any_steamid64(self) -> None:
        # Catches an account id even if it arrives in a Steam field we never anticipated.
        self.assertEqual(["76561198000000123"],
                         fm.check_privacy('{"whatever": "76561198000000123"}'))
        # A 19-digit depot manifest id must not be mistaken for one.
        self.assertEqual([], fm.check_privacy('{"manifest": "3002776385514127223"}'))
        self.assertEqual([], fm.check_privacy('{"size": 5057001973}'))

    def test_check_privacy_finds_a_literal_profile_path(self) -> None:
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            self.skipTest("LOCALAPPDATA is not set")
        self.assertIn(fm.normalize_path(local),
                      fm.check_privacy(json.dumps({"p": local})))


# ---------------------------------------------------------------------------
# end to end
# ---------------------------------------------------------------------------


class TestEndToEnd(EnvSandbox):
    def steam_case(self) -> tuple[str, str]:
        steam = os.path.join(self.root, "Steam")
        other = os.path.join(self.root, "SteamLibrary")
        make_steam_library(steam, [other])
        install = os.path.join(other, "steamapps", "common", "MISERY")
        return steam, install

    def test_steam_libraryfolders_path(self) -> None:
        steam, install = self.steam_case()
        out = os.path.join(self.root, "install.json")
        code, stdout, stderr = self.run_main(["--steam-root", steam, "--out", out])
        self.assertEqual(0, code, stderr)
        document = json.loads(open(out, encoding="utf-8").read())
        self.assertEqual("steam-libraryfolders", document["method"])
        self.assertEqual(fm.privatize_path(install), document["install_dir"])
        self.assertEqual(2119830, document["app_id"])
        self.assertEqual(24826585, document["steam_buildid"])
        self.assertEqual({"2119831": {"manifest": "3002776385514127223",
                                      "size": 5057001973}}, document["depots"])
        self.assertEqual(["228989", "228990", "229007"], document["shared_depots"])
        self.assertEqual(fm.SHIPPING_EXE_REL, document["primary_executable"])
        self.assertEqual("MISERY.exe", document["launcher_shim"])
        self.assertEqual(["MISERY\\Binaries\\Win64\\MISERY.exe"],
                         document["secondary_executables"])
        self.assertEqual([], document["validation"]["errors"])
        self.assertIn("install_dir=", stdout)

    def test_last_owner_never_appears_in_the_output(self) -> None:
        steam, _install = self.steam_case()
        out = os.path.join(self.root, "install.json")
        code, _stdout, stderr = self.run_main(["--steam-root", steam, "--out", out])
        self.assertEqual(0, code, stderr)
        with open(out, encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn(FAKE_LAST_OWNER, text)
        # No SteamID64-shaped token anywhere, whatever field it might have come from.
        self.assertIsNone(re.search(r"(?<!\d)7656119\d{10}(?!\d)", text))
        # No LastOwner FIELD. The words "LastOwner present -- excluded ... (C-13)" do
        # appear in the trace, and that is the point: the document has to testify that
        # the field was seen and dropped, not merely be silent about it.
        self.assertNotIn('"LastOwner"', text)
        self.assertNotIn("last_owner", text)
        # The trace must still testify that the field existed and was dropped on purpose,
        # otherwise "we excluded it" is not evidence of anything.
        document = json.loads(text)
        manifest_steps = [entry for entry in document["discovery_trace"]
                          if entry["name"] == "app-manifest" and entry["status"] == "found"]
        self.assertTrue(manifest_steps)
        self.assertIn("LastOwner present", manifest_steps[-1]["detail"])
        self.assertIn("C-13", manifest_steps[-1]["detail"])

    def test_the_library_listing_the_app_is_preferred_but_all_are_traced(self) -> None:
        steam, _install = self.steam_case()
        code, stdout, _stderr = self.run_main(["--steam-root", steam])
        self.assertEqual(0, code)
        document = json.loads(stdout)
        enumeration = [entry for entry in document["discovery_trace"]
                       if entry["name"] == "library-enumeration"]
        self.assertEqual(1, len(enumeration))
        self.assertEqual("steam-metadata", enumeration[0]["oracle_class"])
        self.assertIn("2 library folder(s)", enumeration[0]["detail"])
        self.assertIn("app 2119830 listed", enumeration[0]["detail"])

    def test_trace_covers_every_step_that_ran(self) -> None:
        steam, _install = self.steam_case()
        code, stdout, _stderr = self.run_main(["--steam-root", steam])
        self.assertEqual(0, code)
        trace = json.loads(stdout)["discovery_trace"]
        self.assertEqual([1, 1, 2, 3, 4, 5, 6], sorted(entry["step"] for entry in trace))
        for entry in trace:
            self.assertIn(entry["status"],
                          {"found", "not-found", "skipped", "error", "ok", "failed"})
            self.assertTrue(entry["detail"])
            self.assertNotEqual(entry["detail"], entry["status"])
        skipped = [entry for entry in trace if entry["status"] == "skipped"]
        self.assertTrue(skipped)
        for entry in skipped:
            # A skipped step whose detail does not say why is decoration, not evidence.
            self.assertGreater(len(entry["detail"]), 20)

    def test_trace_entries_do_not_pose_as_knowledge_base_records(self) -> None:
        # tools/kb/validate.py treats any object carrying evidence_level / claim_type /
        # oracle / confidence as a KB record and then demands build_key and a sources[]
        # array on it. install.json is a raw measurement artifact, like
        # install-inventory.json, so no object in it may carry those keys.
        steam, _install = self.steam_case()
        code, stdout, _stderr = self.run_main(["--steam-root", steam])
        self.assertEqual(0, code)
        document = json.loads(stdout)
        marker_keys = {"evidence_level", "claim_type", "oracle", "confidence"}

        def walk(node):
            if isinstance(node, dict):
                self.assertEqual(set(), marker_keys & set(node),
                                 "knowledge-base marker key in install.json")
                self.assertNotIn("source", node)
                self.assertNotIn("sources", node)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(document)

    def test_env_override(self) -> None:
        install = make_install_tree(os.path.join(self.root, "override"))
        os.environ[fm.ENV_OVERRIDE] = install
        try:
            code, stdout, _stderr = self.run_main([])
        finally:
            os.environ.pop(fm.ENV_OVERRIDE, None)
        self.assertEqual(0, code)
        document = json.loads(stdout)
        self.assertEqual("env-override", document["method"])
        self.assertIsNone(document["steam_path"])
        self.assertIsNone(document["steam_buildid"])
        self.assertIn("null because no Steam", document["notes"])

    def test_local_config_is_honoured_and_not_created(self) -> None:
        install = make_install_tree(os.path.join(self.root, "cfg-install"))
        config = os.path.join(self.repo_root, "research", "config", "local.json")
        self.assertFalse(os.path.exists(config))
        write_file(config, json.dumps({"install_dir": install}))
        code, stdout, _stderr = self.run_main([])
        self.assertEqual(0, code)
        self.assertEqual("local-config", json.loads(stdout)["method"])

    def test_absent_local_config_is_not_created_by_a_run(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        code, _stdout, _stderr = self.run_main(["--install-dir", install])
        self.assertEqual(0, code)
        self.assertFalse(
            os.path.exists(os.path.join(self.repo_root, "research", "config", "local.json"))
        )

    def test_override_recovers_steam_metadata_when_the_layout_is_standard(self) -> None:
        steam, install = self.steam_case()
        code, stdout, _stderr = self.run_main(["--install-dir", install])
        self.assertEqual(0, code)
        document = json.loads(stdout)
        self.assertEqual("explicit-path", document["method"])
        self.assertEqual(24826585, document["steam_buildid"])

    def test_missing_registry_and_no_override_exits_one(self) -> None:
        code, stdout, stderr = self.run_main([])
        self.assertEqual(1, code)
        self.assertEqual("", stdout)
        self.assertIn("NOT found", stderr)
        self.assertIn("winreg unavailable", stderr)
        self.assertIn("--deep", stderr)

    def test_registry_helpers_survive_an_absent_registry(self) -> None:
        roots, notes = fm.registry_steam_roots()
        self.assertEqual([], roots)
        self.assertTrue(any("winreg unavailable" in note for note in notes))
        found, notes = fm.uninstall_registry_candidates()
        self.assertEqual([], found)
        self.assertTrue(any("winreg unavailable" in note for note in notes))

    def test_validation_failure_still_writes_the_document_but_exits_one(self) -> None:
        install = make_install_tree(os.path.join(self.root, "broken"), global_utoc=False)
        out = os.path.join(self.root, "install.json")
        code, _stdout, stderr = self.run_main(["--install-dir", install, "--out", out])
        self.assertEqual(1, code)
        self.assertIn("check 2 failed", stderr)
        document = json.loads(open(out, encoding="utf-8").read())
        self.assertFalse(document["validation"]["global_utoc_present"])
        failed = [entry for entry in document["discovery_trace"]
                  if entry["name"] == "validation"]
        self.assertEqual(["failed"], [entry["status"] for entry in failed])

    def test_steam_metadata_and_filesystem_disagreement_is_reported(self) -> None:
        steam = os.path.join(self.root, "Steam")
        other = os.path.join(self.root, "SteamLibrary")
        # Steam claims installdir "MISERY_MOVED"; only "MISERY" exists on disk.
        make_steam_library(steam, [other],
                           acf=ACF_FIXTURE.replace('"installdir"\t\t"MISERY"',
                                                   '"installdir"\t\t"MISERY_MOVED"'))
        code, _stdout, stderr = self.run_main(["--steam-root", steam])
        self.assertEqual(1, code)
        self.assertIn("steam-metadata and filesystem disagree", stderr)

    def test_deep_flag_is_required_for_a_disk_scan(self) -> None:
        code, _stdout, stderr = self.run_main([])
        self.assertEqual(1, code)
        self.assertIn("only", stderr)
        self.assertIn("--deep", stderr)

    def test_deep_scan_finds_a_tree_by_the_validation_predicate(self) -> None:
        install = make_install_tree(os.path.join(self.root, "deep", "somewhere", "MISERY"))
        scan_root = os.path.join(self.root, "deep")
        code, stdout, stderr = self.run_main(["--deep", "--deep-drives", scan_root])
        # The scan already reports which roots it searched and how many candidates it
        # found; attach that to the failure. This test failed on a CI host while passing
        # locally, and "AssertionError: 0 != 1" said nothing about which of the two --
        # the walk or the validation predicate -- had given up.
        context = (
            "\n  scan root : %s"
            "\n  install   : %s"
            "\n  exists    : %s"
            "\n  exit code : %s"
            "\n  stderr    : %s"
            "\n  stdout    : %s"
            % (scan_root, install,
               os.path.isfile(os.path.join(install, "MISERY", "Binaries", "Win64",
                                           "MISERY-Win64-Shipping.exe")),
               code, stderr.strip()[:2000], stdout.strip()[:600])
        )
        self.assertEqual(0, code, context)
        document = json.loads(stdout)
        self.assertEqual("disk-scan", document["method"])
        self.assertEqual(fm.privatize_path(install), document["install_dir"])

    def test_profile_privatisation_survives_an_aliased_profile_variable(self) -> None:
        """LOCALAPPDATA naming the same directory by another route must still privatise.

        Windows can hand a profile variable out in 8.3 short form while the paths we
        privatise arrive resolved to their long form. The prefix comparison then finds
        nothing, the literal profile path survives, and the C-13 guard refuses to emit
        the document at all -- the tool stops working on that host. A GitHub Windows
        runner is such a host, and this went unnoticed locally because 8.3 generation
        is disabled on the development volume.

        8.3 cannot be forced here, so the same asymmetry is built with a junction: the
        variable points at the alias, the fact arrives via the real directory.
        """
        real = os.path.join(self.root, "profile-real")
        alias = os.path.join(self.root, "profile-alias")
        os.makedirs(real, exist_ok=True)
        if subprocess.run(["cmd", "/c", "mklink", "/J", alias, real],
                          capture_output=True).returncode != 0:
            self.skipTest("cannot create a junction on this filesystem")
        saved = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = alias
        try:
            under_real = os.path.join(real, "MISERY", "Saved")
            self.assertEqual("%LOCALAPPDATA%" + os.sep + os.path.join("MISERY", "Saved"),
                             fm.privatize_path(under_real),
                             "a path under the profile must privatise even when the "
                             "variable names that directory by a different route")
            self.assertEqual([], fm.check_privacy(fm.privatize_path(under_real)),
                             "and the privatised form must satisfy the C-13 guard")
        finally:
            if saved is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = saved

    def test_a_profile_path_inside_free_text_is_privatised(self) -> None:
        """A profile path in the MIDDLE of a trace detail must not reach the document.

        privatize_path only rewrites a string that IS a path. Trace details are prose
        ("drives searched: ..."), so the prefix test never fired and a literal
        user-profile path survived into discovery_trace[].detail while every declared
        path field was clean. The C-13 guard then refused to emit anything, which is
        how this was found -- on a CI host, not here.
        """
        profile = os.path.join(self.root, "profile")
        os.makedirs(profile, exist_ok=True)
        saved = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = profile
        try:
            leaky = os.path.join(profile, "Temp", "scan-root")
            document = {
                "install_dir": "D:" + os.sep + "Games",
                "discovery_trace": [
                    {"step": 7, "detail": "drives searched: " + leaky + " (1 candidate)"}
                ],
            }
            cleaned = fm.privatize_document(document)
            detail = cleaned["discovery_trace"][0]["detail"]
            self.assertNotIn(profile, detail,
                             "the profile directory must not survive in free text")
            self.assertIn("%LOCALAPPDATA%", detail,
                          "and it must be replaced by the placeholder, not deleted")
            self.assertIn("(1 candidate)", detail,
                          "the rest of the sentence must be preserved")
            self.assertEqual([], fm.check_privacy(fm.dump_json(cleaned)),
                             "and the result must satisfy the C-13 guard")
            # A path outside the profile is not a leak and must be left alone.
            self.assertEqual("D:" + os.sep + "Games", cleaned["install_dir"])
        finally:
            if saved is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = saved

    def test_refuses_to_write_inside_the_installation(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        for relative in ("install.json", os.path.join("MISERY", "install.json")):
            out = os.path.join(install, relative)
            code, _stdout, stderr = self.run_main(["--install-dir", install, "--out", out])
            self.assertEqual(2, code, relative)
            self.assertIn("D-01", stderr)
            self.assertFalse(os.path.exists(out))

    def test_an_install_root_with_no_common_anchor_does_not_break_the_write(self) -> None:
        # Renamed from test_writes_to_a_different_drive_without_crashing, which named a
        # different-drive scenario but actually exercised two things: the no-common-anchor
        # branch of the guard, and a refusal for an --out inside the installation. The
        # refusal half duplicated test_refuses_to_write_inside_the_installation and
        # expected fm.DiscoveryError, which write_document no longer raises -- the shared
        # guard raises pathguard.OutputPathRefused. Only the anchor case is kept here, and
        # the output path is outside every installation root.
        #
        # What is actually under test: the guard compares with os.path.commonpath, which
        # raises ValueError when two paths share no anchor. That is the ordinary case of
        # an installation on D: and an output on C:, and it must mean "outside", not
        # "cannot decide" -- otherwise every cross-drive run would die on a ValueError.
        make_install_tree(os.path.join(self.root, "install"))
        out = os.path.join(self.root, "out.json")
        other_anchor = "Z:" if not self.root.upper().startswith("Z:") else "Y:"
        named_root = other_anchor + "\\Games\\MISERY"
        # The pair really does have no common anchor; without this the test could pass
        # for the wrong reason (e.g. if the temp dir moved onto the same drive letter).
        with self.assertRaises(ValueError):
            os.path.commonpath([os.path.normcase(out), os.path.normcase(named_root)])
        fm.write_document({"install_dir": named_root}, out, named_root)
        self.assertTrue(os.path.isfile(out))
        # The decision is made from the parsed anchor with no filesystem access, so a
        # real second drive would take exactly this branch: whether the drive exists is
        # not an input to it. That is why there is no separate "real other drive" test.
        self.assertFalse(pathguard.is_inside(out, named_root))

    def test_output_is_deterministic_text(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        out = os.path.join(self.root, "install.json")
        code, _stdout, _stderr = self.run_main(["--install-dir", install, "--out", out])
        self.assertEqual(0, code)
        with open(out, "rb") as handle:
            raw = handle.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r\n", raw)
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8")
        document = json.loads(text)
        self.assertEqual(text, fm.dump_json(document))
        self.assertEqual(sorted(document), list(document))

    def test_user_directories_are_emitted_as_placeholders(self) -> None:
        install = make_install_tree(os.path.join(self.root, "install"))
        code, stdout, _stderr = self.run_main(["--install-dir", install])
        self.assertEqual(0, code)
        document = json.loads(stdout)
        for key in ("user_config_dir", "user_save_dir", "crash_dir", "log_dir"):
            self.assertTrue(document[key].startswith("%LOCALAPPDATA%"), key)


# ---------------------------------------------------------------------------
# plan.md 1.5 layer 1 / decision D-01: the output-path guard, attacked
# ---------------------------------------------------------------------------


class TestOutputPathGuard(EnvSandbox):
    r"""Attack surface of pathguard as reached through the discovery tool.

    tests/test_inventory.py::TestOutputPathGuard already covers, against
    snapshot_install / verify_install: a directory symlink, case folding, 8.3 short
    names, a relative --out resolved from a cwd inside the tree, ``..`` escapes, the
    ``startswith`` sibling-prefix trap and the root path itself. Repeating those here
    would only duplicate them. What was covered nowhere, and is covered here:

    * an **NTFS junction**. A junction is a different reparse point from a symlink
      (IO_REPARSE_TAG_MOUNT_POINT, not IO_REPARSE_TAG_SYMLINK) and ``mklink /J``
      needs no privilege at all, so it is the cheapest bypass available -- and it is
      the exact hole the deleted inline copy in ``find_misery.write_document`` left
      open, because that copy was built on ``os.path.abspath``, which resolves
      neither kind of reparse point.
    * the **structural** protected root: an installation that the invocation did not
      name. A guard that only knows ``--install-dir`` switches itself off on the one
      invocation that is already wrong.
    * the **recorded/configured** protected root, i.e. the known real installation,
      which no argument may unlock.

    Every installation here is a throwaway tree under a temp directory. The one place
    the real game folder appears is as a candidate output path handed to
    ``check_output_path``, which returns a string or raises and never opens anything.
    """

    def setUp(self) -> None:
        super().setUp()
        self.alpha = make_install_tree(os.path.join(self.root, "InstallAlpha"))
        self.bravo = make_install_tree(os.path.join(self.root, "InstallBravo"))
        self.safe = os.path.join(self.root, "safe")
        os.makedirs(self.safe, exist_ok=True)

    def make_junction(self, link: str, target: str) -> str:
        """Create an NTFS junction, or skip the test if the filesystem refuses.

        ``mklink /J`` rather than ctypes: it is what an operator (or an attacker)
        would actually type, and it needs no elevation. A skip here is honest -- the
        vector does not exist on a volume that cannot hold a junction.
        """
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", link, target],
            capture_output=True, text=True,
        )
        if result.returncode != 0 or not os.path.isdir(link):
            self.skipTest(
                "cannot create an NTFS junction here: %s"
                % ((result.stderr or result.stdout).strip() or "mklink failed")
            )
        return link

    def test_junction_into_the_installation_is_refused(self) -> None:
        link = self.make_junction(os.path.join(self.safe, "j"), self.alpha)
        target = os.path.join(link, "pwned.json")
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(target, self.alpha, repo_root=self.repo_root)
        self.assertFalse(os.path.exists(target))

    def test_junction_is_refused_even_when_install_dir_names_another_tree(self) -> None:
        # The junction points at InstallAlpha while the invocation names InstallBravo,
        # so only the structural source can catch this. This is the combination that
        # the pre-fix guard accepted.
        link = self.make_junction(os.path.join(self.safe, "j"), self.alpha)
        with self.assertRaises(pathguard.OutputPathRefused) as caught:
            pathguard.check_output_path(
                os.path.join(link, "pwned.json"), self.bravo, repo_root=self.repo_root
            )
        self.assertIn("2.1 step 6", str(caught.exception))

    def test_junction_into_a_deep_subdirectory_of_the_installation_is_refused(self) -> None:
        deep = os.path.join(self.alpha, "MISERY", "Content", "Paks")
        link = self.make_junction(os.path.join(self.safe, "jpaks"), deep)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(
                os.path.join(link, "pwned.json"), self.bravo, repo_root=self.repo_root
            )

    def test_symlink_into_a_deep_subdirectory_of_the_installation_is_refused(self) -> None:
        # The symlink counterpart of the case above. tests/test_inventory.py links to the
        # installation ROOT, which the structural source catches on its own because the
        # marker files are visible through the link; only a link that lands BELOW the
        # root depends on realpath, so only this shape is a regression test for it.
        deep = os.path.join(self.alpha, "MISERY", "Content", "Paks")
        link = os.path.join(self.safe, "spaks")
        try:
            os.symlink(deep, link, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError) as error:
            self.skipTest("cannot create a directory symlink here: %s" % error)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(
                os.path.join(link, "pwned.json"), self.bravo, repo_root=self.repo_root
            )

    def test_resolve_real_expands_a_junction_before_the_comparison(self) -> None:
        # The primitive the two tests above depend on, pinned directly. os.path.abspath
        # -- what the deleted inline copy used -- returns the junction path unchanged and
        # is therefore not a substitute.
        deep = os.path.join(self.alpha, "MISERY", "Content", "Paks")
        link = self.make_junction(os.path.join(self.safe, "jpaks"), deep)
        candidate = os.path.join(link, "does-not-exist-yet.json")
        self.assertEqual(
            os.path.normpath(os.path.join(deep, "does-not-exist-yet.json")),
            pathguard.resolve_real(candidate),
        )
        self.assertEqual(os.path.normpath(candidate), os.path.abspath(candidate))

    def make_hard_link(self, link: str, target: str) -> str:
        """Create a hard link, or skip. Needs no privilege on the same NTFS volume."""
        try:
            os.link(target, link)
        except (OSError, NotImplementedError, AttributeError) as error:
            self.skipTest("cannot create a hard link here: %s" % error)
        return link

    def test_a_hard_link_out_of_the_installation_is_refused(self) -> None:
        # Found by attacking the guard, not by reading it. A hard link has no target
        # to resolve, so realpath returns the link's own path and the containment
        # check sees a perfectly innocent output path -- while opening it with mode
        # "w" truncates the file inside the installation. Before the fix this write
        # succeeded and the installation file was overwritten.
        victim = os.path.join(self.alpha, "MISERY", "Content", "Paks", "global.utoc")
        original = open(victim, "rb").read()
        link = self.make_hard_link(os.path.join(self.safe, "out.json"), victim)
        # The premise of the attack: the path really does look outside.
        self.assertEqual(os.path.normpath(link), pathguard.resolve_real(link))
        self.assertEqual([], pathguard.structural_install_roots(link))
        with self.assertRaises(pathguard.OutputPathRefused) as caught:
            pathguard.check_output_path(link, self.alpha, repo_root=self.repo_root)
        self.assertIn("hard link", str(caught.exception))
        self.assertIn("D-01", str(caught.exception))
        self.assertEqual(original, open(victim, "rb").read())

    def test_the_cli_refuses_a_hard_linked_out_path(self) -> None:
        victim = os.path.join(self.alpha, "MISERY", "Content", "Paks", "global.utoc")
        original = open(victim, "rb").read()
        link = self.make_hard_link(os.path.join(self.safe, "install.json"), victim)
        code, _stdout, stderr = self.run_main(
            ["--install-dir", self.alpha, "--out", link]
        )
        self.assertEqual(2, code, stderr)
        self.assertIn("D-01", stderr)
        self.assertEqual(original, open(victim, "rb").read())

    def test_a_single_named_output_file_may_be_overwritten(self) -> None:
        # The complement: the hard-link rule must not turn an ordinary re-run into a
        # refusal. An existing output file with exactly one name is still accepted.
        target = os.path.join(self.safe, "install.json")
        write_file(target, "{}\n")
        self.assertEqual(1, pathguard.hard_link_count(target))
        self.assertEqual(
            os.path.normpath(target),
            pathguard.check_output_path(target, self.alpha, repo_root=self.repo_root),
        )
        code, _stdout, stderr = self.run_main(
            ["--install-dir", self.alpha, "--out", target]
        )
        self.assertEqual(0, code, stderr)

    def test_an_installation_the_invocation_did_not_name_is_protected(self) -> None:
        # No junction, no symlink: just a second installation. --install-dir names
        # InstallAlpha, --out lands in InstallBravo.
        with self.assertRaises(pathguard.OutputPathRefused) as caught:
            pathguard.check_output_path(
                os.path.join(self.bravo, "MISERY", "x.json"),
                self.alpha, repo_root=self.repo_root,
            )
        self.assertIn("2.1 step 6", str(caught.exception))

    def test_a_directory_that_is_not_an_installation_is_not_protected(self) -> None:
        # The complement of the test above: the structural source must fire only on
        # the plan.md 2.1 step 6 predicate (BOTH markers), or every parent directory
        # would slowly become unwritable. self.safe sits next to two installations.
        self.assertEqual(
            [], pathguard.structural_install_roots(os.path.join(self.safe, "x.json"))
        )
        self.assertEqual(
            os.path.normpath(os.path.join(self.safe, "x.json")),
            pathguard.check_output_path(
                os.path.join(self.safe, "x.json"), self.alpha, repo_root=self.repo_root
            ),
        )

    def test_one_marker_alone_does_not_make_a_directory_an_installation(self) -> None:
        # plan.md 2.1 step 6 requires BOTH markers, and this is the cost of that: a
        # tree whose global.utoc a Steam update has momentarily removed is not
        # structurally recognized, so on a fresh clone with nothing recorded and
        # MISERY_GAME_DIR unset it is not protected either. The gap is written down in
        # the pathguard docstring; this test pins the predicate that causes it, so
        # loosening the predicate cannot happen silently.
        half = os.path.join(self.root, "half")
        write_file(os.path.join(half, pathguard.INSTALL_MARKERS[0]), b"MZ")
        self.assertFalse(pathguard.looks_like_install_root(half))
        self.assertEqual(
            os.path.normpath(os.path.join(half, "x.json")),
            pathguard.check_output_path(
                os.path.join(half, "x.json"), self.alpha, repo_root=self.repo_root
            ),
        )

    def test_the_known_real_installation_cannot_be_unlocked_by_any_argument(self) -> None:
        # D-01 has no escape hatch. A mistyped --install-dir names a directory that is
        # not an installation, and on exactly that invocation the named-root check is
        # useless -- so the recorded/configured source has to carry it.
        self.assertTrue(pathguard.CONFIGURED_INSTALL_ROOTS)
        for root in pathguard.CONFIGURED_INSTALL_ROOTS:
            for candidate in (root, os.path.join(root, "pwned.json"),
                             os.path.join(root, "MISERY", "Content", "Paks", "x.json")):
                with self.subTest(candidate=candidate):
                    # The guard is asked about the real path but never writes: the
                    # check runs before anything is opened, so whatever was or was
                    # not there stays exactly as it was.
                    existed = os.path.exists(candidate)
                    with self.assertRaises(pathguard.OutputPathRefused):
                        pathguard.check_output_path(
                            candidate, self.safe, repo_root=self.repo_root
                        )
                    self.assertEqual(existed, os.path.exists(candidate))

    def test_the_environment_variable_only_ever_adds_a_protected_root(self) -> None:
        os.environ[fm.ENV_OVERRIDE] = self.bravo
        try:
            # Naming Bravo through the environment does not stop Alpha being protected.
            with self.assertRaises(pathguard.OutputPathRefused):
                pathguard.check_output_path(
                    os.path.join(self.alpha, "x.json"), self.safe,
                    repo_root=self.repo_root,
                )
            # And a directory that is not an installation at all becomes protected
            # merely by being named in the environment, which is the safe direction.
            os.environ[fm.ENV_OVERRIDE] = self.safe
            with self.assertRaises(pathguard.OutputPathRefused):
                pathguard.check_output_path(
                    os.path.join(self.safe, "x.json"), self.alpha,
                    repo_root=self.repo_root,
                )
        finally:
            os.environ.pop(fm.ENV_OVERRIDE, None)

    def test_a_legitimate_output_outside_every_root_is_still_accepted(self) -> None:
        for candidate in (
            os.path.join(self.safe, "ok.json"),
            os.path.join(self.root, "ok.json"),          # the PARENT of two installs
            os.path.join(self.root, "InstallAlpha-old", "ok.json"),  # prefix sibling
        ):
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    os.path.normpath(candidate),
                    pathguard.check_output_path(
                        candidate, self.alpha, repo_root=self.repo_root
                    ),
                )

    def test_a_legitimate_output_on_another_drive_is_accepted(self) -> None:
        # A real cross-anchor accept, with both paths existing: the temp directory and
        # the repository are on different drives on the research machine. If they are
        # not, the branch is already covered by
        # test_an_install_root_with_no_common_anchor_does_not_break_the_write.
        if os.path.splitdrive(self.root)[0].lower() == \
                os.path.splitdrive(REPO_ROOT)[0].lower():
            self.skipTest("the temp directory and the repository share a drive here")
        candidate = os.path.join(REPO_ROOT, "workspace", "guard-probe.json")
        self.assertEqual(
            os.path.normpath(candidate),
            pathguard.check_output_path(candidate, self.alpha, repo_root=REPO_ROOT),
        )
        self.assertFalse(os.path.exists(candidate))  # checking creates nothing

    def test_the_cli_refuses_an_out_through_a_junction(self) -> None:
        link = self.make_junction(os.path.join(self.safe, "j"), self.alpha)
        target = os.path.join(link, "install.json")
        code, stdout, stderr = self.run_main(
            ["--install-dir", self.alpha, "--out", target]
        )
        self.assertEqual(2, code, stderr)
        self.assertEqual("", stdout)
        self.assertIn("D-01", stderr)
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(os.path.join(self.alpha, "install.json")))

    def test_the_cli_refuses_an_out_inside_a_tree_install_dir_did_not_name(self) -> None:
        # The mistyped-argument case end to end: --install-dir points at a directory
        # that is not an installation, --out points into a real one.
        target = os.path.join(self.bravo, "MISERY", "install.json")
        code, _stdout, stderr = self.run_main(
            ["--install-dir", self.safe, "--out", target]
        )
        self.assertEqual(2, code, stderr)
        self.assertIn("D-01", stderr)
        self.assertIn("2.1 step 6", stderr)
        self.assertFalse(os.path.exists(target))

    def test_the_cli_writes_normally_outside_every_installation(self) -> None:
        target = os.path.join(self.safe, "install.json")
        code, stdout, stderr = self.run_main(
            ["--install-dir", self.alpha, "--out", target]
        )
        self.assertEqual(0, code, stderr)
        self.assertTrue(os.path.isfile(target))
        self.assertIn("install_dir=", stdout)

    def test_find_misery_and_pathguard_agree_on_the_validation_predicate(self) -> None:
        # The two markers are declared twice -- SHIPPING_EXE_REL / GLOBAL_UTOC_REL for
        # discovery, INSTALL_MARKERS for the guard. If they ever drift, the guard stops
        # recognizing the trees discovery recognizes, and the structural source goes
        # quiet without any test failing. Hence this test.
        self.assertEqual(
            (os.path.normpath(fm.SHIPPING_EXE_REL), os.path.normpath(fm.GLOBAL_UTOC_REL)),
            tuple(os.path.normpath(marker) for marker in pathguard.INSTALL_MARKERS),
        )


# ---------------------------------------------------------------------------
# the emitted document must validate against research/schema/install.schema.json
# ---------------------------------------------------------------------------


class TestSchemaConformance(EnvSandbox):
    def build_document(self) -> dict:
        steam = os.path.join(self.root, "Steam")
        other = os.path.join(self.root, "SteamLibrary")
        make_steam_library(steam, [other])
        code, stdout, stderr = self.run_main(["--steam-root", steam])
        self.assertEqual(0, code, stderr)
        return json.loads(stdout)

    def test_required_fields_of_plan_2_2_are_all_present(self) -> None:
        with open(SCHEMA_PATH, encoding="utf-8") as handle:
            schema = json.load(handle)
        document = self.build_document()
        for key in schema["required"]:
            self.assertIn(key, document)
        for key in document:
            self.assertIn(key, schema["properties"], "field not allowed by the schema")

    def test_validates_with_jsonschema_when_available(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed; run under the canonical venv")
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        schema_dir = os.path.dirname(SCHEMA_PATH)
        with open(SCHEMA_PATH, encoding="utf-8") as handle:
            schema = json.load(handle)
        # Every sibling schema is registered under both its $id and its bare filename,
        # exactly as tools/kb/validate.py does it, so cross-file $refs resolve offline.
        resources = []
        for name in sorted(os.listdir(schema_dir)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(schema_dir, name), encoding="utf-8") as handle:
                document = json.load(handle)
            resource = Resource.from_contents(document, default_specification=DRAFT202012)
            for uri in {document.get("$id"), name}:
                if uri:
                    resources.append((uri, resource))
        registry = Registry().with_resources(resources)
        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)
        validator = cls(schema, registry=registry)
        errors = sorted(validator.iter_errors(self.build_document()),
                        key=lambda err: list(err.absolute_path))
        self.assertEqual([], ["/".join(str(part) for part in err.absolute_path) + ": "
                              + err.message for err in errors])


if __name__ == "__main__":
    unittest.main(verbosity=2)
