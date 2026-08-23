#!/usr/bin/env python3
"""Unit tests for tools/inventory (plan.md tasks R-04, R-05; safety layer 1.5-3).

Standard library only. These tests NEVER touch the real game installation: every
case builds a synthetic tree under a temporary directory. The exit criterion of
R-04 -- "verify detects an artificially introduced change in a test copy of the
tree" -- is what test_verify_* below proves.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_INVENTORY = os.path.join(REPO_ROOT, "tools", "inventory")
if TOOLS_INVENTORY not in sys.path:
    sys.path.insert(0, TOOLS_INVENTORY)

import pathguard  # noqa: E402
import snapshot_install as snap  # noqa: E402
import verify_install as verify_mod  # noqa: E402


def _short_path_or_none(path: str) -> str | None:
    """Windows 8.3 alias of *path*, or None when unavailable.

    Used by the guard tests: 8.3 names are one of the ways the same directory can
    be spelled differently, and the volume may have them disabled.
    """
    if os.name != "nt":
        return None
    import ctypes

    buffer = ctypes.create_unicode_buffer(4096)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 4096)
    if length == 0 or length >= 4096:
        return None
    return buffer.value


# Trimmed but structurally faithful copy of appmanifest_2119830.acf. Inline on
# purpose: the test must not depend on the Steam installation being present.
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
'''

SYNTHETIC_TREE = {
    "MISERY.exe": b"bootstrap-shim-placeholder",
    "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe": b"shipping-exe-placeholder-0001",
    "MISERY/Binaries/Win64/MISERY.exe": b"secondary-exe-placeholder",
    "MISERY/Content/Paks/global.utoc": b"global-utoc-bytes",
    "MISERY/Content/Paks/global.ucas": b"global-ucas-bytes" * 4,
    "MISERY/Content/Paks/MISERY-Windows.utoc": b"main-utoc-bytes",
    "MISERY/Content/Paks/MISERY-Windows.ucas": b"main-ucas-bytes" * 8,
    "Engine/Extras/Redist/readme.txt": b"redist notes\n",
}


def write_tree(root: str, files: dict) -> None:
    for relative, payload in files.items():
        absolute = os.path.join(root, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(absolute), exist_ok=True)
        with open(absolute, "wb") as handle:
            handle.write(payload)


def absolute_of(root: str, relative: str) -> str:
    return os.path.join(root, relative.replace("/", os.sep))


def stat_snapshot(root: str) -> dict:
    """path -> (size, mtime_ns) for every file, used to prove read-only behaviour."""
    result = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            absolute = os.path.join(dirpath, name)
            stat = os.stat(absolute)
            result[snap.relative_posix(root, absolute)] = (stat.st_size, stat.st_mtime_ns)
    return result


class TempTreeCase(unittest.TestCase):
    """Base class: a synthetic installation tree in a temp dir."""

    files = SYNTHETIC_TREE

    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory(prefix="misery-inv-test-")
        self.addCleanup(self._tempdir.cleanup)
        self.root = os.path.realpath(self._tempdir.name)
        self.install = os.path.join(self.root, "install")
        os.makedirs(self.install)
        write_tree(self.install, self.files)

    def snapshot(self, **kwargs) -> dict:
        kwargs.setdefault("expected_file_count", len(self.files))
        return snap.build_inventory(self.install, **kwargs)


class TestHashing(TempTreeCase):
    def test_streaming_hash_matches_one_shot(self) -> None:
        payload = bytes(range(256)) * 97  # 24 832 bytes, not a buffer multiple
        target = os.path.join(self.root, "blob.bin")
        with open(target, "wb") as handle:
            handle.write(payload)
        for buf_size in (1, 7, 4096, 1 << 20):
            with self.subTest(buf_size=buf_size):
                sha256_hex, sha1_hex = snap.hash_file(target, buf_size=buf_size)
                self.assertEqual(sha256_hex, hashlib.sha256(payload).hexdigest())
                self.assertEqual(sha1_hex, hashlib.sha1(payload).hexdigest())

    def test_empty_file(self) -> None:
        target = os.path.join(self.root, "empty.bin")
        with open(target, "wb"):
            pass
        sha256_hex, sha1_hex = snap.hash_file(target)
        self.assertEqual(sha256_hex, hashlib.sha256(b"").hexdigest())
        self.assertEqual(sha1_hex, hashlib.sha1(b"").hexdigest())

    def test_buffer_is_bounded_and_reused(self) -> None:
        """A tiny buffer must still hash a much larger file (no whole-file read)."""
        payload = os.urandom(200_000)
        target = os.path.join(self.root, "big.bin")
        with open(target, "wb") as handle:
            handle.write(payload)
        sha256_hex, _ = snap.hash_file(target, buf_size=512)
        self.assertEqual(sha256_hex, hashlib.sha256(payload).hexdigest())


class TestSnapshot(TempTreeCase):
    def test_records_every_file_with_required_fields(self) -> None:
        diagnostics: dict = {}
        document = self.snapshot(diagnostics=diagnostics)
        self.assertEqual(document["file_count"], len(self.files))
        self.assertTrue(diagnostics["file_count_matches_expected"])
        self.assertEqual(
            sorted(record["path"] for record in document["files"]),
            sorted(self.files),
        )
        for record in document["files"]:
            self.assertEqual(
                sorted(record),
                ["mtime", "mtime_epoch", "path", "sha1", "sha256", "size"],
            )
            self.assertNotIn("\\", record["path"])
            self.assertEqual(record["size"], len(self.files[record["path"]]))
            self.assertEqual(
                record["sha256"],
                hashlib.sha256(self.files[record["path"]]).hexdigest(),
            )
            self.assertEqual(
                record["sha1"], hashlib.sha1(self.files[record["path"]]).hexdigest()
            )
            self.assertRegex(
                record["mtime"],
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$",
            )
            self.assertIsInstance(record["mtime_epoch"], int)
        self.assertEqual(
            document["total_size"], sum(len(v) for v in self.files.values())
        )

    def test_files_are_sorted_by_path(self) -> None:
        document = self.snapshot()
        paths = [record["path"] for record in document["files"]]
        self.assertEqual(paths, sorted(paths))

    def test_snapshot_does_not_modify_the_tree(self) -> None:
        before = stat_snapshot(self.install)
        self.snapshot()
        self.assertEqual(stat_snapshot(self.install), before)

    def test_two_snapshots_are_byte_identical_except_generated_at(self) -> None:
        first = snap.dump_json(self.snapshot())
        second = snap.dump_json(self.snapshot())

        first_doc = json.loads(first)
        second_doc = json.loads(second)
        del first_doc["generated_at"]
        del second_doc["generated_at"]
        self.assertEqual(first_doc, second_doc)

        def strip_generated_at(text: str) -> list[str]:
            return [
                line for line in text.splitlines() if '"generated_at"' not in line
            ]

        self.assertEqual(strip_generated_at(first), strip_generated_at(second))
        # And the only differing line really is generated_at.
        differing = [
            (a, b)
            for a, b in zip(first.splitlines(), second.splitlines())
            if a != b
        ]
        for line_a, line_b in differing:
            self.assertIn('"generated_at"', line_a)
            self.assertIn('"generated_at"', line_b)

    def test_serialization_is_utf8_lf_no_bom_sorted(self) -> None:
        out_path = os.path.join(self.root, "inventory.json")
        snap.write_json(self.snapshot(), out_path)
        with open(out_path, "rb") as handle:
            raw = handle.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "BOM must not be emitted")
        self.assertNotIn(b"\r\n", raw)
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8")
        top_level_keys = [
            line.strip().split('"')[1]
            for line in text.splitlines()
            if line.startswith("  \"")
        ]
        self.assertEqual(top_level_keys, sorted(top_level_keys))

    def test_file_count_mismatch_warns_but_does_not_fail(self) -> None:
        diagnostics: dict = {}
        document = snap.build_inventory(
            self.install, expected_file_count=53, diagnostics=diagnostics
        )
        self.assertFalse(diagnostics["file_count_matches_expected"])
        self.assertEqual(document["file_count"], len(self.files))
        self.assertTrue(
            any("file count" in warning for warning in diagnostics["warnings"]),
            diagnostics["warnings"],
        )
        # The closed schema has no field for the expectation, so it is recorded
        # in 'notes' instead.
        self.assertIn("expected 53", document["notes"])

    def test_engine_version_is_provisional_and_overridable(self) -> None:
        default_doc = self.snapshot()
        self.assertEqual(
            default_doc["engine_version"],
            {"value": snap.DEFAULT_ENGINE_VERSION, "provisional": True},
        )
        self.assertIn("engine_version source: default", default_doc["notes"])

        override = self.snapshot(engine_version="5.4.9", engine_version_source="cli")
        self.assertEqual(override["engine_version"]["value"], "5.4.9")
        self.assertTrue(override["engine_version"]["provisional"])
        self.assertIn("engine_version source: cli", override["notes"])
        self.assertIn("ue5.4.9", override["build_id"])

    def test_missing_install_dir_raises(self) -> None:
        with self.assertRaises(NotADirectoryError):
            snap.build_inventory(os.path.join(self.root, "does-not-exist"))


class TestBuildIdentity(TempTreeCase):
    def test_build_key_is_sha256_of_shipping_exe(self) -> None:
        document = self.snapshot()
        expected = hashlib.sha256(
            self.files["MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"]
        ).hexdigest()
        # plan.md 3.2 / kb-record.schema.json: the stored form carries the
        # 'sha256:' prefix; build_id slices the bare hex.
        self.assertEqual(document["build_key"], "sha256:" + expected)
        self.assertIn(expected[:12], document["build_id"])

    def test_content_key_is_sha256_over_sorted_utoc_digests(self) -> None:
        document = self.snapshot()
        utoc_paths = sorted(
            path for path in self.files if path.lower().endswith(".utoc")
        )
        # The contributing paths and the ordering rule live in 'notes', because
        # install-inventory.schema.json closes the top-level object.
        for path in utoc_paths:
            self.assertIn(path, document["notes"])
        digest = hashlib.sha256()
        for path in utoc_paths:
            digest.update(hashlib.sha256(self.files[path]).hexdigest().encode("ascii"))
        self.assertEqual(document["content_key"], "sha256:" + digest.hexdigest())

    def test_content_only_change_moves_content_key_not_build_key(self) -> None:
        before = self.snapshot()
        with open(
            absolute_of(self.install, "MISERY/Content/Paks/MISERY-Windows.utoc"), "wb"
        ) as handle:
            handle.write(b"patched-utoc-bytes")
        after = self.snapshot()
        self.assertEqual(before["build_key"], after["build_key"])
        self.assertNotEqual(before["content_key"], after["content_key"])

    def test_code_change_moves_build_key_and_build_id(self) -> None:
        before = self.snapshot()
        with open(
            absolute_of(self.install, "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"),
            "wb",
        ) as handle:
            handle.write(b"shipping-exe-placeholder-0002")
        after = self.snapshot()
        self.assertNotEqual(before["build_key"], after["build_key"])
        self.assertNotEqual(before["build_id"], after["build_id"])
        self.assertEqual(before["content_key"], after["content_key"])

    def test_build_id_format(self) -> None:
        build_key = "0123456789abcdef" * 4
        self.assertEqual(
            snap.make_build_id("24826585", "5.4.4", build_key),
            "misery-24826585-ue5.4.4-0123456789ab",
        )

    def test_build_id_marks_unknowns_instead_of_guessing(self) -> None:
        self.assertEqual(
            snap.make_build_id(None, "5.4.4", None),
            "misery-%s-ue5.4.4-%s"
            % (snap.UNKNOWN_STEAM_BUILDID_SEGMENT, snap.UNKNOWN_BUILD_KEY_SEGMENT),
        )

    def test_missing_shipping_exe_yields_unknown_segment_and_warning(self) -> None:
        os.remove(
            absolute_of(self.install, "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe")
        )
        diagnostics: dict = {}
        document = snap.build_inventory(
            self.install, expected_file_count=None, diagnostics=diagnostics
        )
        self.assertIsNone(document["build_key"])
        self.assertIn(snap.UNKNOWN_BUILD_KEY_SEGMENT, document["build_id"])
        self.assertTrue(
            any("build_key source missing" in w for w in diagnostics["warnings"]),
            diagnostics["warnings"],
        )


class TestVdfParser(unittest.TestCase):
    def test_parses_appmanifest_fixture(self) -> None:
        parsed = snap.parse_appmanifest_text(ACF_FIXTURE)
        self.assertEqual(parsed["app_id"], "2119830")
        self.assertEqual(parsed["name"], "MISERY")
        self.assertEqual(parsed["installdir"], "MISERY")
        self.assertEqual(parsed["buildid"], "24826585")
        self.assertEqual(parsed["size_on_disk"], 5057001973)
        self.assertEqual(parsed["last_updated_epoch"], 1787394913)
        # 1787394913 == time.gmtime -> 2026-08-22T10:35:13Z (checked independently)
        self.assertEqual(parsed["last_updated_utc"], "2026-08-22T10:35:13Z")
        self.assertEqual(
            parsed["installed_depots"],
            {"2119831": {"manifest": "3002776385514127223", "size": 5057001973}},
        )
        self.assertEqual(
            parsed["shared_depots"],
            {"228989": "228980", "228990": "228980", "229007": "228980"},
        )

    def test_nested_structure_and_escapes(self) -> None:
        parsed = snap.parse_vdf(
            '"AppState" { "LauncherPath" "D:\\\\Games\\\\Steam\\\\steam.exe" }'
        )
        self.assertEqual(
            parsed["AppState"]["LauncherPath"], r"D:\Games\Steam\steam.exe"
        )

    def test_case_insensitive_lookup(self) -> None:
        parsed = snap.parse_vdf('"AppState" { "AppID" "1" }')
        self.assertEqual(snap.vdf_get(parsed, "appstate", "appid"), "1")
        self.assertIsNone(snap.vdf_get(parsed, "appstate", "nope"))
        self.assertEqual(snap.vdf_get(parsed, "x", "y", default="fallback"), "fallback")

    def test_tolerates_comments_bare_tokens_and_truncation(self) -> None:
        text = (
            '// leading comment\n'
            '"AppState"\n{\n'
            '  "appid" "2119830"  // trailing comment\n'
            '  bareKey bareValue\n'
            '  "Nested" { "k" "v" }\n'
            '  "truncated" "unterminated\n'
        )
        parsed = snap.parse_appmanifest_text(text)
        self.assertEqual(parsed["app_id"], "2119830")
        state = snap.parse_vdf(text)["AppState"]
        self.assertEqual(state["bareKey"], "bareValue")
        self.assertEqual(state["Nested"], {"k": "v"})
        self.assertEqual(state["truncated"], "unterminated\n")

    def test_missing_and_non_integer_fields_become_none(self) -> None:
        parsed = snap.parse_appmanifest_text('"AppState" { "SizeOnDisk" "not-a-number" }')
        self.assertIsNone(parsed["size_on_disk"])
        self.assertIsNone(parsed["buildid"])
        self.assertIsNone(parsed["last_updated_epoch"])
        self.assertEqual(parsed["installed_depots"], {})
        self.assertEqual(parsed["shared_depots"], {})

    def test_empty_input_does_not_raise(self) -> None:
        self.assertEqual(snap.parse_vdf(""), {})
        self.assertIsNone(snap.parse_appmanifest_text("")["app_id"])

    def test_absent_appmanifest_is_recorded_not_fatal(self) -> None:
        warnings: list[str] = []
        record = snap.read_appmanifest(
            os.path.join(tempfile.gettempdir(), "no-such-appmanifest-2119830.acf"),
            warnings,
        )
        self.assertFalse(record["appmanifest_present"])
        self.assertIsNone(record["buildid"])
        self.assertTrue(any("appmanifest not found" in w for w in warnings), warnings)


class TestVerify(TempTreeCase):
    def setUp(self) -> None:
        super().setUp()
        self.baseline = self.snapshot()
        self.inventory_path = os.path.join(self.root, "install-inventory.json")
        snap.write_json(self.baseline, self.inventory_path)

    def kinds(self, findings: list[dict]) -> list[str]:
        return [item["kind"] for item in findings]

    def test_clean_tree_matches(self) -> None:
        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(findings, [])
        self.assertEqual(verify_mod.exit_code_for(findings), 0)

    def test_detects_modified_file_as_hash_change(self) -> None:
        target = absolute_of(
            self.install, "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
        )
        original = os.stat(target)
        original_payload = self.files[
            "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
        ]
        tampered = b"shipping-exe-placeholder-9999"
        self.assertEqual(len(tampered), len(original_payload))  # same size on purpose
        with open(target, "wb") as handle:
            handle.write(tampered)
        # Restore the timestamp: the hash alone must be enough to catch this.
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))

        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(len(findings), 1, findings)
        finding = findings[0]
        self.assertEqual(finding["kind"], "hash_changed")
        self.assertEqual(finding["severity"], "serious")
        self.assertEqual(
            finding["path"], "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
        )
        self.assertEqual(finding["actual_sha256"], hashlib.sha256(tampered).hexdigest())
        self.assertEqual(verify_mod.exit_code_for(findings), 1)

    def test_detects_size_change_as_size_and_hash_change(self) -> None:
        target = absolute_of(self.install, "Engine/Extras/Redist/readme.txt")
        with open(target, "wb") as handle:
            handle.write(b"redist notes, but longer now\n")
        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(
            sorted(self.kinds(findings)), ["hash_changed", "size_changed"]
        )
        self.assertEqual(verify_mod.exit_code_for(findings), 1)

    def test_detects_deleted_file(self) -> None:
        os.remove(absolute_of(self.install, "MISERY/Content/Paks/global.utoc"))
        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(self.kinds(findings), ["missing"])
        self.assertEqual(findings[0]["path"], "MISERY/Content/Paks/global.utoc")
        self.assertEqual(findings[0]["severity"], "serious")
        self.assertEqual(verify_mod.exit_code_for(findings), 1)

    def test_detects_added_file(self) -> None:
        added = absolute_of(self.install, "MISERY/Content/Paks/zzz_mod_P.pak")
        with open(added, "wb") as handle:
            handle.write(b"an intruder")
        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(self.kinds(findings), ["added"])
        self.assertEqual(findings[0]["path"], "MISERY/Content/Paks/zzz_mod_P.pak")
        self.assertEqual(findings[0]["actual_size"], len(b"an intruder"))
        self.assertEqual(verify_mod.exit_code_for(findings), 1)

    def test_touched_but_identical_is_benign(self) -> None:
        target = absolute_of(self.install, "MISERY/Content/Paks/MISERY-Windows.ucas")
        stat = os.stat(target)
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))

        findings = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(self.kinds(findings), ["mtime_changed_hash_same"])
        finding = findings[0]
        self.assertEqual(finding["severity"], "benign")
        self.assertNotEqual(
            finding["expected_mtime_utc"], finding["actual_mtime_utc"]
        )
        self.assertEqual(
            finding["sha256"],
            hashlib.sha256(self.files["MISERY/Content/Paks/MISERY-Windows.ucas"])
            .hexdigest(),
        )
        # Content intact -> the install still "matches"...
        self.assertEqual(verify_mod.exit_code_for(findings), 0)
        # ...unless the caller asked for strictness.
        self.assertEqual(verify_mod.exit_code_for(findings, strict=True), 1)

    def test_fast_mode_reports_mtime_as_unverified(self) -> None:
        target = absolute_of(self.install, "MISERY/Content/Paks/MISERY-Windows.ucas")
        stat = os.stat(target)
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))

        findings = verify_mod.verify(self.baseline, self.install, fast=True)
        self.assertEqual(self.kinds(findings), ["mtime_changed_unverified"])
        self.assertEqual(findings[0]["severity"], "serious")
        self.assertEqual(verify_mod.exit_code_for(findings), 1)

    def test_fast_mode_cannot_see_a_same_size_same_mtime_edit(self) -> None:
        """The documented tradeoff of --fast, asserted so it stays documented."""
        relative = "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
        target = absolute_of(self.install, relative)
        stat = os.stat(target)
        with open(target, "wb") as handle:
            handle.write(b"shipping-exe-placeholder-9999")
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))

        self.assertEqual(verify_mod.verify(self.baseline, self.install, fast=True), [])
        self.assertEqual(
            self.kinds(verify_mod.verify(self.baseline, self.install)), ["hash_changed"]
        )

    def test_missing_baseline_hash_is_reported_not_silently_passed(self) -> None:
        inventory = json.loads(json.dumps(self.baseline))
        for record in inventory["files"]:
            if record["path"] == "MISERY/Content/Paks/global.ucas":
                record["sha256"] = None
        findings = verify_mod.verify(inventory, self.install)
        self.assertEqual(self.kinds(findings), ["baseline_hash_missing"])
        self.assertEqual(findings[0]["severity"], "benign")

    def test_findings_order_is_deterministic(self) -> None:
        os.remove(absolute_of(self.install, "MISERY/Content/Paks/global.utoc"))
        with open(absolute_of(self.install, "extra.bin"), "wb") as handle:
            handle.write(b"x")
        first = verify_mod.verify(self.baseline, self.install)
        second = verify_mod.verify(self.baseline, self.install)
        self.assertEqual(first, second)
        self.assertEqual(sorted(self.kinds(first)), ["added", "missing"])

    def test_report_text_mentions_result(self) -> None:
        findings = verify_mod.verify(self.baseline, self.install)
        report = verify_mod.format_report(
            findings, self.baseline, self.install, False, False
        )
        self.assertIn("RESULT: MATCH", report)

    def test_cli_exit_codes(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main([self.inventory_path, "--install-dir", self.install])
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())

        os.remove(absolute_of(self.install, "MISERY/Content/Paks/global.utoc"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main([self.inventory_path, "--install-dir", self.install])
        self.assertEqual(code, 1)
        self.assertIn("missing", stdout.getvalue())

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main(
                [os.path.join(self.root, "no-such-inventory.json")]
            )
        self.assertEqual(code, 2)

        bad = os.path.join(self.root, "not-an-inventory.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("{ this is not json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main([bad])
        self.assertEqual(code, 2)

    def test_cli_json_report(self) -> None:
        os.remove(absolute_of(self.install, "MISERY/Content/Paks/global.utoc"))
        report_path = os.path.join(self.root, "verify-report.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main(
                [
                    self.inventory_path,
                    "--install-dir",
                    self.install,
                    "--json",
                    report_path,
                ]
            )
        self.assertEqual(code, 1)
        with open(report_path, "rb") as handle:
            raw = handle.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r\n", raw)
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(payload["serious_count"], 1)
        self.assertEqual(payload["mode"], "full")
        self.assertEqual(payload["baseline_build_key"], self.baseline["build_key"])


class TestSnapshotCli(TempTreeCase):
    def test_stdout_carries_only_the_build_id_line(self) -> None:
        out_path = os.path.join(self.root, "cli-inventory.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = snap.main(
                [
                    "--install-dir",
                    self.install,
                    "--out",
                    out_path,
                    "--expected-file-count",
                    str(len(self.files)),
                    "--engine-version",
                    "5.4.4",
                    "--steam-root",
                    os.path.join(self.root, "fake-steam"),
                ]
            )
        self.assertEqual(code, 0, stderr.getvalue())
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith("build_id=misery-"))
        with open(out_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual("build_id=%s" % document["build_id"], lines[0])
        self.assertIn("install-inventory snapshot", stderr.getvalue())

    def test_cli_reports_usage_error_for_missing_install_dir(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = snap.main(["--install-dir", os.path.join(self.root, "nope")])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")

    def test_cli_never_writes_into_the_scanned_tree(self) -> None:
        before = stat_snapshot(self.install)
        out_path = os.path.join(self.root, "outside-inventory.json")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            snap.main(["--install-dir", self.install, "--out", out_path])
        self.assertEqual(stat_snapshot(self.install), before)
        self.assertTrue(os.path.isfile(out_path))


class TestOutputPathGuard(TempTreeCase):
    """plan.md 1.5 layer 1: no tool accepts a path inside the installation as output.

    ``self.install`` stands in for the game installation; the real folder is never
    touched. Every case asserts both halves of the contract: the tool refuses with
    a non-zero exit, and it leaves nothing behind -- no partial file, no change to
    the stand-in tree.
    """

    def inside(self, *parts: str) -> str:
        return os.path.join(self.install, *parts)

    def test_pure_guard_accepts_outside_and_refuses_inside(self) -> None:
        outside = os.path.join(self.root, "inventory.json")
        self.assertEqual(
            pathguard.check_output_path(outside, self.install),
            os.path.normpath(outside),
        )
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(self.inside("x.json"), self.install)

    def test_install_root_itself_is_refused(self) -> None:
        for spelling in (
            self.install,
            self.install + os.sep,
            os.path.join(self.install, "MISERY", ".."),
        ):
            with self.subTest(spelling=spelling):
                with self.assertRaises(pathguard.OutputPathRefused):
                    pathguard.check_output_path(spelling, self.install)

    def test_sibling_directory_sharing_a_name_prefix_is_accepted(self) -> None:
        # The startswith() trap: "<root>/install-sibling" begins with the install
        # root as a *string* but is not inside it. commonpath gets this right.
        sibling = os.path.join(self.root, "install-sibling", "inventory.json")
        self.assertEqual(
            pathguard.check_output_path(sibling, self.install),
            os.path.normpath(sibling),
        )

    @unittest.skipUnless(os.name == "nt", "case-insensitive paths are a Windows trait")
    def test_case_difference_does_not_get_past_the_guard(self) -> None:
        shouting = self.install.upper()
        self.assertNotEqual(shouting, self.install)  # the temp name has lowercase
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(os.path.join(shouting, "x.json"), self.install)
        # ... and with the roles swapped: root given in a different case.
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(self.inside("x.json"), shouting)

    @unittest.skipUnless(os.name == "nt", "8.3 short names are a Windows trait")
    def test_short_8_3_name_is_expanded_before_comparison(self) -> None:
        short = _short_path_or_none(self.install)
        if short is None or os.path.normcase(short) == os.path.normcase(self.install):
            self.skipTest("no 8.3 alias for the temp directory on this volume")
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(os.path.join(short, "x.json"), self.install)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(self.inside("x.json"), short)

    def test_resolve_real_resolves_the_deepest_existing_ancestor(self) -> None:
        # The output file does not exist yet, which is the normal case. The guard
        # therefore realpath()s the deepest ancestor that does exist and appends
        # the remainder -- the same code path that expands an 8.3 name, exercised
        # here without depending on 8.3 being enabled on the volume.
        expected = os.path.normpath(
            os.path.join(self.install, "MISERY", "Content", "does", "not", "exist.json")
        )
        odd_spelling = os.path.join(
            self.install, "MISERY", ".", "Content", "..", "Content",
            "does", "not", "exist.json",
        )
        self.assertEqual(pathguard.resolve_real(odd_spelling), expected)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(odd_spelling, self.install)

    def test_directory_symlink_into_the_installation_is_refused(self) -> None:
        link = os.path.join(self.root, "link-to-install")
        try:
            os.symlink(self.install, link, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError) as error:
            self.skipTest("cannot create a directory symlink here: %s" % error)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(os.path.join(link, "x.json"), self.install)

    def test_relative_path_is_resolved_against_the_current_directory(self) -> None:
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.install)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path("x.json", self.install)
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(
                os.path.join("MISERY", "Content", "x.json"), self.install
            )
        # Same relative spelling, cwd outside the installation: accepted.
        os.chdir(self.root)
        self.assertEqual(
            pathguard.check_output_path("x.json", self.install),
            os.path.join(self.root, "x.json"),
        )

    def test_dotdot_escape_back_into_the_root_is_refused(self) -> None:
        sneaky = os.path.join(self.root, "outside", "..", "install", "x.json")
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(sneaky, self.install)

    def test_empty_arguments_are_rejected_not_silently_allowed(self) -> None:
        for bad in ("", "   ", None):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    pathguard.check_output_path(bad, self.install)
                with self.assertRaises(ValueError):
                    pathguard.check_output_path("out.json", bad)

    def test_snapshot_cli_refuses_out_inside_the_installation(self) -> None:
        before = stat_snapshot(self.install)
        target = self.inside("MISERY", "Content", "Paks", "inventory.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = snap.main(["--install-dir", self.install, "--out", target])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")  # no build_id line on refusal
        message = stderr.getvalue()
        self.assertIn("D-01", message)
        self.assertIn("1.5", message)
        self.assertIn(os.path.basename(target), message)
        self.assertFalse(os.path.exists(target), "a partial file was created")
        self.assertEqual(stat_snapshot(self.install), before)

    def test_snapshot_cli_still_accepts_a_path_outside_the_installation(self) -> None:
        target = os.path.join(self.root, "legit-inventory.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = snap.main(
                [
                    "--install-dir",
                    self.install,
                    "--out",
                    target,
                    "--expected-file-count",
                    str(len(self.files)),
                ]
            )
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertTrue(os.path.isfile(target))
        self.assertTrue(stdout.getvalue().startswith("build_id="))

    def test_write_json_guard_holds_for_direct_callers(self) -> None:
        document = self.snapshot()
        target = self.inside("direct.json")
        with self.assertRaises(pathguard.OutputPathRefused):
            snap.write_json(document, target)
        self.assertFalse(os.path.exists(target))
        # install_dir is taken from the document itself, so a caller that forgets
        # to pass it is still guarded.
        self.assertEqual(document["install_dir"], os.path.normpath(self.install))

    def test_verify_cli_refuses_json_report_inside_the_installation(self) -> None:
        inventory_path = os.path.join(self.root, "baseline.json")
        snap.write_json(self.snapshot(), inventory_path)
        before = stat_snapshot(self.install)
        target = self.inside("verify-report.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main(
                [
                    inventory_path,
                    "--install-dir",
                    self.install,
                    "--json",
                    target,
                ]
            )
        self.assertEqual(code, 2)
        message = stderr.getvalue()
        self.assertIn("D-01", message)
        self.assertIn(os.path.basename(target), message)
        self.assertFalse(os.path.exists(target), "a partial file was created")
        self.assertEqual(stat_snapshot(self.install), before)

    def test_verify_cli_refuses_a_relative_json_report_resolving_inside(self) -> None:
        inventory_path = os.path.join(self.root, "baseline.json")
        snap.write_json(self.snapshot(), inventory_path)
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.install)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main(
                [inventory_path, "--install-dir", self.install, "--json", "report.json"]
            )
        self.assertEqual(code, 2)
        self.assertIn("D-01", stderr.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.install, "report.json")))

    def test_verify_cli_uses_the_inventory_root_when_install_dir_is_omitted(self) -> None:
        # Without --install-dir the root comes from the inventory, and the guard
        # must use that root too -- otherwise --json into the installation slips
        # through whenever the argument is left out.
        inventory_path = os.path.join(self.root, "baseline.json")
        snap.write_json(self.snapshot(), inventory_path)
        target = self.inside("report.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main([inventory_path, "--json", target])
        self.assertEqual(code, 2)
        self.assertIn("D-01", stderr.getvalue())
        self.assertFalse(os.path.exists(target))

    def test_verify_cli_still_accepts_a_report_path_outside(self) -> None:
        inventory_path = os.path.join(self.root, "baseline.json")
        snap.write_json(self.snapshot(), inventory_path)
        target = os.path.join(self.root, "legit-report.json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_mod.main(
                [inventory_path, "--install-dir", self.install, "--json", target]
            )
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())
        self.assertTrue(os.path.isfile(target))


class TestSteamRootDerivation(unittest.TestCase):
    def test_derives_root_from_steamapps_common_layout(self) -> None:
        install = os.path.join("D:", os.sep, "Games", "Steam", "steamapps", "common", "MISERY")
        self.assertEqual(
            snap.derive_steam_root(install),
            os.path.normpath(os.path.join("D:", os.sep, "Games", "Steam")),
        )

    def test_returns_none_for_unrelated_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            self.assertIsNone(snap.derive_steam_root(os.path.join(temp, "MISERY")))


class TestNoGameFolderAccess(unittest.TestCase):
    """Guard: the suite must not depend on the real installation existing."""

    def test_default_install_dir_is_not_used_by_tests(self) -> None:
        self.assertEqual(
            snap.DEFAULT_INSTALL_DIR, r"D:\Games\Steam\steamapps\common\MISERY"
        )
        # Nothing in this suite passes DEFAULT_INSTALL_DIR to build_inventory; the
        # assertion above only pins the documented default so a silent change to it
        # cannot make some future test walk the real tree by accident.


if __name__ == "__main__":
    unittest.main()
