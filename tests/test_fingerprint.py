#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/fingerprint/fingerprint.py (plan.md tasks F-03 and F-05).

**No test here opens the game installation.** Every installation these tests work on
is built file by file under a temporary directory: synthetic PE images, a synthetic
IoStore container, a synthetic Steam app manifest and a synthetic non-UFS manifest. A
test that re-ran the composer over the real MISERY tree and asserted the numbers it
produced would prove only that the composer is self-consistent.

The synthetic builders are reused rather than rewritten: ``PEBuilder`` from
tests/test_pe_info.py and ``build_utoc`` from tests/test_container_info.py are the
INDEPENDENT models of those two formats that F-01 and F-02 are already tested against.
Copying them here would create a second model that could drift from the first.

What is pinned, and why each one is here rather than merely nice:

* **A-05 reproduces automatically.** The named case must fall out of a set comparison.
  So the test does not merely assert that A-05 appears - it empties the recon-id table
  first and asserts the anomaly is still detected, which is the difference between a
  detector and an assertion dressed as one.
* **D-04 is never a finding.** The Development-build reading appears only in the
  ``hypothesis`` field, at 0.65, naming D-04, the read-only oracle restriction and the
  ban on using the file as a bindings target. The ``description`` field must not carry
  a word of it.
* **Every annotation is the reduced envelope**, and every one of them passes
  ``tools/kb/validate.py``'s annotation rules with zero findings - checked by running
  the real linter over the real document, not by eyeballing the shape.
* **The document validates against the PUBLISHED schema** through a plain
  ``jsonschema.Draft202012Validator``, the way a stranger with an editor would.
* **Two runs differ only in ``identity.generated_at``** (plan.md 3.3, M1 exit criteria).
* **C-13**: an app manifest carrying ``LastOwner`` must not leak the account id.
* **D-01**: an output path inside the installation is refused before anything is written.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m pytest -q tests/test_fingerprint.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory"),
              os.path.dirname(os.path.abspath(__file__))):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import fingerprint as fp  # noqa: E402
import pathguard  # noqa: E402

# The independent format models, imported from the suites that own them.
from test_pe_info import (PEBuilder, build_resource_blob,  # noqa: E402
                          build_version_resource)
from test_container_info import build_utoc  # noqa: E402

SCHEMA_PATH = os.path.join(REPO_ROOT, "research", "schema", "fingerprint.schema.json")


def _load_validator_module():
    spec = importlib.util.spec_from_file_location(
        "misery_kb_validate_for_fingerprint",
        os.path.join(REPO_ROOT, "tools", "kb", "validate.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validate = _load_validator_module()


# --------------------------------------------------------------------------- #
# a synthetic installation
# --------------------------------------------------------------------------- #

APP_MANIFEST = '''"AppState"
{
\t"appid"\t\t"2119830"
\t"name"\t\t"MISERY"
\t"installdir"\t\t"MISERY"
\t"LastOwner"\t\t"76561198000000000"
\t"buildid"\t\t"24826585"
\t"SizeOnDisk"\t\t"%d"
\t"LastUpdated"\t\t"1787394913"
\t"InstalledDepots"
\t{
\t\t"2119831"
\t\t{
\t\t\t"manifest"\t\t"3002776385514127223"
\t\t\t"size"\t\t"%d"
\t\t}
\t}
\t"SharedDepots"
\t{
\t\t"228989"\t\t"228980"
\t}
}
'''


def _exe(**sections) -> bytes:
    """A minimal PE32+ image carrying the named extra sections."""
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xcc" * 0x200, characteristics=0x60000020)
    rva = 0x2000
    for name, characteristics in sections.items():
        builder.add_section(name.replace("__", "."), rva, b"\x11" * 0x200,
                            characteristics=characteristics)
        rva += 0x1000
    return builder.build(fix_checksum=True)


def _exe_with_version(strings: dict) -> bytes:
    """A PE32+ image whose .rsrc carries a populated VS_VERSIONINFO."""
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xcc" * 0x200, characteristics=0x60000020)
    resource_rva = 0x2000
    blob = build_resource_blob(resource_rva, {
        16: {1: {0x0409: build_version_resource(strings)}},
    })
    builder.add_section(".rsrc", resource_rva, blob, characteristics=0x40000040)
    builder.directories[2] = (resource_rva, len(blob))
    return builder.build(fix_checksum=True)


def make_install(tmp_path, *, with_uedbg: bool = True,
                 manifest_lines: tuple[str, ...] | None = None) -> str:
    """Build a temporary tree shaped like the real installation and return its root.

    Deliberately NOT a copy of the real one: three executables, one module, one
    container pair, one non-UFS manifest and one Steam app manifest are the minimum
    that exercises every field group of plan.md 3.1.
    """
    root = tmp_path / "steamapps" / "common" / "MISERY"
    (root / "MISERY" / "Binaries" / "Win64").mkdir(parents=True)
    (root / "MISERY" / "Content" / "Paks").mkdir(parents=True)
    (root / "MISERY" / "Plugins" / "SamplePlugin" / "Source").mkdir(parents=True)
    (root / "Engine" / "Binaries" / "Win64").mkdir(parents=True)

    (root / "MISERY.exe").write_bytes(_exe())
    (root / "MISERY" / "Binaries" / "Win64" / "MISERY-Win64-Shipping.exe").write_bytes(
        _exe_with_version({"ProductName": "MISERY", "InternalName": "MISERY",
                           "ProductVersion": "++UE5+Release-5.4-CL-35576357",
                           "OriginalFilename": "MISERY-Win64-Shipping.exe"}))
    second = {"__uedbg": 0x60000020} if with_uedbg else {}
    (root / "MISERY" / "Binaries" / "Win64" / "MISERY.exe").write_bytes(_exe(**second))
    (root / "Engine" / "Binaries" / "Win64" / "helper.dll").write_bytes(_exe())
    (root / "MISERY" / "Plugins" / "SamplePlugin" / "Source" / "note.txt").write_bytes(
        b"plugin source placeholder\n")

    (root / "MISERY" / "Content" / "Paks" / "global.utoc").write_bytes(
        build_utoc(entry_count=2, block_count=1))
    (root / "MISERY" / "Content" / "Paks" / "global.ucas").write_bytes(b"\x00" * 64)

    if manifest_lines is None:
        manifest_lines = (
            "MISERY.exe\t2026-08-19T21:06:14.918Z",
            "MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe\t2026-08-19T20:49:56.388Z",
            "Engine\\Binaries\\Win64\\helper.dll\t2026-05-04T21:41:42.222Z",
        )
    (root / "Manifest_NonUFSFiles_Win64.txt").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8")

    total = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    manifest_dir = tmp_path / "steamapps"
    (manifest_dir / "appmanifest_2119830.acf").write_text(
        APP_MANIFEST % (total, total), encoding="utf-8")
    return str(root)


@pytest.fixture()
def install(tmp_path):
    return make_install(tmp_path)


@pytest.fixture()
def payload(install):
    return fp.build_document(install)


# --------------------------------------------------------------------------- #
# 1. the one thing this composer computes for itself
# --------------------------------------------------------------------------- #

class TestStreamDigests:

    def test_three_digests_in_one_pass_match_hashlib(self, tmp_path):
        blob = bytes(range(256)) * 5000
        target = tmp_path / "blob.bin"
        target.write_bytes(blob)
        got = fp.stream_digests(str(target))
        assert got["sha256"] == hashlib.sha256(blob).hexdigest()
        assert got["sha1"] == hashlib.sha1(blob).hexdigest()
        assert got["md5"] == hashlib.md5(blob).hexdigest()

    def test_a_buffer_smaller_than_the_file_still_hashes_all_of_it(self, tmp_path):
        blob = os.urandom(9000)
        target = tmp_path / "blob.bin"
        target.write_bytes(blob)
        assert fp.stream_digests(str(target), buf_size=64)["sha256"] == \
            hashlib.sha256(blob).hexdigest()

    def test_an_empty_file_hashes_to_the_empty_digest(self, tmp_path):
        target = tmp_path / "empty.bin"
        target.write_bytes(b"")
        assert fp.stream_digests(str(target))["sha256"] == hashlib.sha256(b"").hexdigest()


# --------------------------------------------------------------------------- #
# 2. the non-UFS manifest reader and the comparison
# --------------------------------------------------------------------------- #

class TestManifestReader:

    def test_backslashes_are_normalised_and_blanks_skipped(self, tmp_path):
        target = tmp_path / "Manifest_NonUFSFiles_Win64.txt"
        target.write_text("a\\b\\c.dll\t2026-01-01T00:00:00.000Z\n\n\nd.exe\tX\n",
                          encoding="utf-8")
        warnings: list[str] = []
        entries, lines = fp.read_non_ufs_manifest(str(target), warnings)
        assert set(entries) == {"a/b/c.dll", "d.exe"}
        assert lines == 2
        assert warnings == []

    def test_a_duplicate_path_is_reported(self, tmp_path):
        target = tmp_path / "Manifest_NonUFSFiles_Win64.txt"
        target.write_text("a.dll\tX\na.dll\tY\n", encoding="utf-8")
        warnings: list[str] = []
        entries, lines = fp.read_non_ufs_manifest(str(target), warnings)
        assert lines == 2 and len(entries) == 1
        assert any("more than once" in w for w in warnings)

    def test_a_missing_manifest_is_a_warning_not_a_crash(self, tmp_path):
        warnings: list[str] = []
        entries, lines = fp.read_non_ufs_manifest(str(tmp_path / "nope.txt"), warnings)
        assert entries == {} and lines == 0 and warnings

    def test_the_comparison_runs_in_both_directions(self):
        result = fp.compare_against_manifest({"a", "b"}, {"b", "c"})
        assert result["file-not-in-non-ufs-manifest"] == ["a"]
        assert result["manifest-entry-missing-on-disk"] == ["c"]


# --------------------------------------------------------------------------- #
# 3. F-05: A-05 must be DETECTED, not asserted
# --------------------------------------------------------------------------- #

class TestA05:

    def test_the_missing_executable_is_found(self, payload):
        anomalies = payload["document"]["anomalies"]
        hits = [a for a in anomalies
                if a["kind"] == "file-not-in-non-ufs-manifest"
                and a["path"] == "MISERY/Binaries/Win64/MISERY.exe"]
        assert len(hits) == 1
        assert hits[0]["id"] == "A-05"

    def test_it_is_still_detected_with_the_recon_id_table_emptied(self, install,
                                                                 monkeypatch):
        """The id is a cross-reference, not a detection rule.

        If emptying the table made the anomaly disappear, the detector would be a
        lookup wearing a detector's name.
        """
        monkeypatch.setattr(fp, "RECON_ANOMALY_IDS", {})
        monkeypatch.setattr(fp, "RECON_SECTION_IDS", {})
        anomalies = fp.build_document(install)["document"]["anomalies"]
        hits = [a for a in anomalies
                if a["path"] == "MISERY/Binaries/Win64/MISERY.exe"
                and a["kind"] == "file-not-in-non-ufs-manifest"]
        assert len(hits) == 1
        assert hits[0]["id"] is None

    def test_an_installation_where_it_is_listed_produces_no_such_anomaly(self, tmp_path):
        install = make_install(tmp_path, manifest_lines=(
            "MISERY.exe\tX",
            "MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe\tX",
            "MISERY\\Binaries\\Win64\\MISERY.exe\tX",
            "Engine\\Binaries\\Win64\\helper.dll\tX"))
        anomalies = fp.build_document(install)["document"]["anomalies"]
        assert not [a for a in anomalies
                    if a["kind"] == "file-not-in-non-ufs-manifest"
                    and a["path"] == "MISERY/Binaries/Win64/MISERY.exe"]

    def test_the_count_equals_the_set_difference(self, payload):
        document = payload["document"]
        on_disk = document["layout"]["file_count"]
        in_manifest = len(payload["manifest_entries"])
        missing = [a for a in document["anomalies"]
                   if a["kind"] == "file-not-in-non-ufs-manifest"]
        orphans = [a for a in document["anomalies"]
                   if a["kind"] == "manifest-entry-missing-on-disk"]
        assert len(missing) - len(orphans) == on_disk - in_manifest


class TestD04IsNeverAFinding:

    def _a05(self, payload):
        return [a for a in payload["document"]["anomalies"]
                if a["path"] == "MISERY/Binaries/Win64/MISERY.exe"]

    def test_the_hypothesis_field_carries_it_and_says_so(self, payload):
        for entry in self._a05(payload):
            assert entry["hypothesis"] is not None
            assert "HYPOTHESIS" in entry["hypothesis"]
            assert "0.65" in entry["hypothesis"]
            assert "D-04" in entry["hypothesis"]

    def test_it_names_the_read_only_oracle_restriction(self, payload):
        text = self._a05(payload)[0]["hypothesis"]
        assert "read-only oracle" in text
        assert "not a bindings target" in text
        assert "RISK-07" in text

    def test_the_description_does_not_mention_it(self, payload):
        for entry in self._a05(payload):
            lowered = entry["description"].lower()
            assert "development" not in lowered
            assert "hypothesis" not in lowered

    def test_no_other_file_inherits_the_hypothesis(self, payload):
        for entry in payload["document"]["anomalies"]:
            if entry["path"] != "MISERY/Binaries/Win64/MISERY.exe":
                assert entry["hypothesis"] is None

    def test_the_report_states_the_restriction(self, payload):
        text = fp.render_anomalies_md(payload)
        assert "HYPOTHESIS, confidence 0.65" in text
        assert "D-04" in text
        assert "read-only oracle" in text
        assert "bindings" in text


class TestSectionSurvey:

    def test_the_uedbg_section_is_reported(self, payload):
        hits = [a for a in payload["document"]["anomalies"]
                if a["kind"] == "unexpected-pe-section"
                and a["path"] == "MISERY/Binaries/Win64/MISERY.exe"]
        assert len(hits) == 1
        assert ".uedbg" in hits[0]["description"]
        assert hits[0]["id"] == "A-05"

    def test_an_installation_without_it_reports_no_section_anomaly(self, tmp_path):
        install = make_install(tmp_path, with_uedbg=False)
        anomalies = fp.build_document(install)["document"]["anomalies"]
        assert not [a for a in anomalies if a["kind"] == "unexpected-pe-section"]

    def test_a_section_claim_is_never_class_p(self, payload):
        """plan.md 10.3 v2.4: naming what a byte range IS puts it in class I."""
        for entry in payload["document"]["anomalies"]:
            if entry["kind"] != "unexpected-pe-section":
                continue
            evidence = entry["evidence"]
            assert evidence["claim_class"] == "I"
            assert evidence["evidence_level"] == "INFERRED"
            assert evidence["confidence"] < 0.80
            assert "external-doc" in evidence["oracle"]

    def test_ordinary_sections_are_not_reported(self, payload):
        reported = {a["path"] for a in payload["document"]["anomalies"]
                    if a["kind"] == "unexpected-pe-section"}
        assert "MISERY.exe" not in reported


# --------------------------------------------------------------------------- #
# 4. evidence discipline, checked with the real linter
# --------------------------------------------------------------------------- #

def _annotations(node, pointer="$"):
    if isinstance(node, dict):
        if validate.is_annotation(node, at_root=pointer == "$"):
            yield pointer, node
        for key, value in node.items():
            yield from _annotations(value, f"{pointer}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _annotations(value, f"{pointer}[{index}]")


class TestEveryAnnotationIsWellFormed:

    def test_every_evidence_object_is_the_reduced_envelope(self, payload):
        found = 0
        for _pointer, obj in _annotations(payload["document"]):
            found += 1
            assert set(obj) <= validate.ANNOTATION_KEYS
        assert found >= 5, "the document should carry annotations at all"

    def test_the_real_linter_reports_nothing_on_them(self, payload):
        problems = []
        for pointer, obj in _annotations(payload["document"]):
            problems.extend((pointer, f.rule, f.message)
                            for f in validate.lint_annotation(pointer, obj))
        assert problems == []

    def test_no_confidence_reaches_the_forbidden_ceiling(self, payload):
        for _pointer, obj in _annotations(payload["document"]):
            assert obj["confidence"] <= 0.99

    def test_every_oracle_is_in_the_closed_vocabulary(self, payload):
        for _pointer, obj in _annotations(payload["document"]):
            assert set(obj["oracle"]) <= set(validate.ORACLES)

    def test_the_whole_document_passes_the_json_lint_layer(self, tmp_path, payload):
        """validate_file over the real document, both layers, as CI runs it."""
        target = tmp_path / "fingerprint.json"
        target.write_text(fp.dump_json(payload["document"]), encoding="utf-8")
        report = validate.validate_file(
            target, "builds/probe/fingerprint.json",
            pathlib.Path(REPO_ROOT) / "research" / "schema", set())
        errors = [f.to_dict() for f in report.findings
                  if f.severity == validate.SEVERITY_ERROR]
        assert errors == []
        assert report.annotation_count == report.record_count > 0


class TestNullsAreDeliberate:

    def test_the_section_4_fields_are_null_and_say_why(self, payload):
        engine = payload["document"]["engine"]
        for field in ("engine_cl", "engine_branch", "build_configuration",
                      "is_source_distribution", "is_perforce_build"):
            assert engine[field] is None
        assert "section 4" in engine["evidence"]["note"]

    def test_engine_version_is_marked_provisional(self, payload):
        engine = payload["document"]["engine"]
        assert engine["engine_version"] == "5.4.4"
        assert engine["engine_version_provisional"] is True
        assert "PROVISIONAL" in engine["evidence"]["note"]

    def test_engine_version_can_be_marked_concluded(self, install):
        document = fp.build_document(install, engine_version_provisional=False)["document"]
        assert document["engine"]["engine_version_provisional"] is False

    def test_the_changelist_string_is_recorded_but_not_decoded(self, payload):
        """The literal is kept; turning it into engine_cl is plan.md 4 method V-03."""
        document = payload["document"]
        assert document["engine"]["engine_cl"] is None
        strings = [entry["pe"]["version_info"]["strings"]
                   for entry in document["executables"]
                   if entry["role"] == "primary-shipping"][0]
        assert strings["ProductVersion"] == "++UE5+Release-5.4-CL-35576357"

    def test_the_game_group_claims_nothing(self, payload):
        game = payload["document"]["game"]
        assert game["game_name"] is None
        assert game["project_module_name"] is None
        assert game["game_version_string_if_any"] is None
        assert game["evidence"]["evidence_level"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# 5. the field groups of plan.md 3.1
# --------------------------------------------------------------------------- #

class TestFieldGroups:

    def test_every_group_is_present(self, payload):
        document = payload["document"]
        for group in ("identity", "steam", "executables", "engine", "game", "modules",
                      "containers", "plugins", "layout", "anomalies"):
            assert group in document

    def test_executables_carry_three_digests_and_a_full_pe_object(self, payload):
        for entry in payload["document"]["executables"]:
            assert len(entry["sha256"]) == 64
            assert len(entry["sha1"]) == 40
            assert len(entry["md5"]) == 32
            assert entry["pe"]["sections"]
            assert entry["pe"]["machine"] is not None

    def test_the_roles_are_assigned_by_exact_path(self, payload):
        roles = {entry["path"]: entry["role"]
                 for entry in payload["document"]["executables"]}
        assert roles["MISERY.exe"] == "launcher-shim"
        assert roles["MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"] == \
            "primary-shipping"
        assert roles["MISERY/Binaries/Win64/MISERY.exe"] == "secondary-oracle"

    def test_modules_are_the_dlls_of_the_three_trees(self, payload):
        paths = {entry["path"] for entry in payload["document"]["modules"]}
        assert paths == {"Engine/Binaries/Win64/helper.dll"}

    @pytest.mark.parametrize("relpath,kind", [
        ("Engine/Binaries/Win64/EOSSDK-Win64-Shipping.dll", "engine"),
        ("Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll", "thirdparty"),
        ("MISERY/Binaries/Win64/tbb.dll", "game"),
        ("MISERY/Plugins/Sample/Binaries/x.dll", "plugin"),
        ("MISERY/Plugins/S/Source/ThirdParty/y.dll", "thirdparty"),
    ])
    def test_module_kind(self, relpath, kind):
        assert fp.module_kind(relpath) == kind

    def test_a_module_root_prefix_does_not_match_a_longer_directory_name(self):
        """MODULE_ROOTS carries a trailing slash so 'Engine/BinariesOld' is not a match."""
        assert "Engine/BinariesOld/x.dll".startswith(fp.MODULE_ROOTS) is False
        assert "Engine/Binaries/Win64/x.dll".startswith(fp.MODULE_ROOTS) is True

    @pytest.mark.parametrize("relpath,category", [
        ("MISERY.exe", "executable"),
        ("a/b.dll", "module"),
        ("MISERY/Content/Paks/global.utoc", "container"),
        ("Manifest_NonUFSFiles_Win64.txt", "manifest"),
        ("controller_ps4.vdf", "config"),
        ("Engine/Content/Renderer/TessellationTable.bin", "data"),
        ("Engine/Extras/GPUDumpViewer/OpenGPUDumpViewer.sh", "other"),
    ])
    def test_category_of(self, relpath, category):
        assert fp.category_of(relpath) == category

    def test_containers_are_spliced_and_carry_this_run_s_digest(self, payload):
        containers = payload["document"]["containers"]
        assert {entry["path"] for entry in containers} == {
            "MISERY/Content/Paks/global.utoc", "MISERY/Content/Paks/global.ucas"}
        layout = {row["path"]: row["sha256"]
                  for row in payload["document"]["layout"]["files"]}
        for entry in containers:
            assert entry["sha256"] == layout[entry["path"]]

    def test_the_utoc_header_survived_the_splice(self, payload):
        utoc = [entry for entry in payload["document"]["containers"]
                if entry["kind"] == "utoc"][0]
        assert utoc["utoc"]["toc_entry_count"] == 2
        assert utoc["utoc"]["toc_header_size"] == 144

    def test_plugins_come_from_the_directory_and_admit_it(self, payload):
        plugins = payload["document"]["plugins"]
        assert [entry["name"] for entry in plugins] == ["SamplePlugin"]
        assert plugins[0]["descriptor_available"] is False
        assert plugins[0]["source"] == "disk"
        assert plugins[0]["evidence"]["confidence"] < 0.80

    def test_layout_covers_every_file_and_flags_manifest_membership(self, payload):
        layout = payload["document"]["layout"]
        rows = {row["path"]: row for row in layout["files"]}
        assert layout["file_count"] == len(rows)
        assert layout["total_size"] == sum(row["size"] for row in layout["files"])
        assert rows["MISERY.exe"]["in_non_ufs_manifest"] is True
        assert rows["MISERY/Binaries/Win64/MISERY.exe"]["in_non_ufs_manifest"] is False


class TestIdentity:

    def test_build_key_is_the_sha256_of_the_shipping_exe(self, install, payload):
        target = os.path.join(install, "MISERY", "Binaries", "Win64",
                              "MISERY-Win64-Shipping.exe")
        expected = hashlib.sha256(open(target, "rb").read()).hexdigest()
        assert payload["document"]["identity"]["build_key"] == "sha256:" + expected

    def test_build_id_follows_plan_3_2(self, payload):
        identity = payload["document"]["identity"]
        bare = identity["build_key"].split(":", 1)[1]
        assert identity["build_id"] == "misery-24826585-ue5.4.4-" + bare[:12]

    def test_content_key_is_over_the_utoc_digests(self, install, payload):
        target = os.path.join(install, "MISERY", "Content", "Paks", "global.utoc")
        digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
        expected = hashlib.sha256(digest.encode("ascii")).hexdigest()
        assert payload["document"]["identity"]["content_key"] == "sha256:" + expected

    def test_the_install_dir_is_recorded(self, install, payload):
        assert os.path.normcase(payload["document"]["identity"]["install_dir"]) == \
            os.path.normcase(os.path.abspath(install))


class TestSteamAndC13:

    def test_the_steam_block_is_read(self, payload):
        steam = payload["document"]["steam"]
        assert steam["app_id"] == 2119830
        assert steam["steam_buildid"] == 24826585
        assert steam["depot_id"] == 2119831
        assert steam["depot_manifest_id"] == "3002776385514127223"
        assert steam["install_dir_name"] == "MISERY"
        assert len(steam["appmanifest_sha256"]) == 64

    def test_the_account_id_never_appears_anywhere_in_the_document(self, payload):
        """C-13. Searched over the SERIALISED document, not over the steam block.

        Checking only `steam` would miss a leak through notes, a path or a warning,
        and a leak through any of those is the same leak.
        """
        text = fp.dump_json(payload["document"])
        # The VALUE must be absent everywhere. The NAME is allowed exactly once, in
        # `notes`, where the document states that it is never read - a refusal that is
        # written down is auditable, and a refusal that is silent is indistinguishable
        # from having forgotten.
        assert "76561198000000000" not in text
        assert text.count("LastOwner") == 1
        assert "LastOwner" in payload["document"]["notes"]
        assert "never read" in payload["document"]["notes"]
        assert "LastOwner" not in fp.dump_json(payload["document"]["steam"])


# --------------------------------------------------------------------------- #
# 6. the published schema, and reproducibility
# --------------------------------------------------------------------------- #

class TestPublishedSchema:

    def test_the_document_validates_with_a_plain_draft_2020_12_validator(self, payload):
        pytest.importorskip("jsonschema")
        status, errors = fp.validate_against_schema(payload["document"], SCHEMA_PATH)
        assert status == "pass", errors

    def test_a_document_with_an_extra_key_is_rejected(self, payload):
        """Proves the check above can fail; a validator that accepts anything is not one."""
        pytest.importorskip("jsonschema")
        broken = dict(payload["document"])
        broken["surprise"] = 1
        status, errors = fp.validate_against_schema(broken, SCHEMA_PATH)
        assert status == "fail" and errors

    def test_a_missing_schema_is_SKIPPED_and_never_reported_as_a_pass(self, payload,
                                                                      tmp_path):
        """"We did not look" must not be spelled the same way as "we looked and it was fine"."""
        status, details = fp.validate_against_schema(
            payload["document"], str(tmp_path / "nowhere" / "fingerprint.schema.json"))
        assert status == "skipped"
        assert details and "could not be read" in details[0]


class TestReproducibility:

    def test_two_builds_differ_only_in_generated_at(self, install):
        first = fp.build_document(install)["document"]
        second = fp.build_document(install)["document"]
        assert first["identity"]["generated_at"] is not None
        first["identity"]["generated_at"] = second["identity"]["generated_at"] = "<t>"
        assert fp.dump_json(first) == fp.dump_json(second)

    def test_the_anomalies_report_is_reproducible_too(self, install):
        first = fp.build_document(install)
        second = fp.build_document(install)
        stamp = second["document"]["identity"]["generated_at"]
        first["document"]["identity"]["generated_at"] = stamp
        assert fp.render_anomalies_md(first) == fp.render_anomalies_md(second)

    def test_first_difference_names_the_field_that_moved(self):
        assert fp.first_difference({"a": [1, {"b": 2}]}, {"a": [1, {"b": 2}]}) is None
        assert fp.first_difference({"a": 1}, {"a": 2}) == "$.a (1 vs 2)"
        assert "present in only one run" in fp.first_difference({"a": 1}, {})
        assert "items" in fp.first_difference({"a": [1]}, {"a": [1, 2]})
        assert fp.first_difference({"a": [1, {"b": 2}]},
                                    {"a": [1, {"b": 3}]}) == "$.a[1].b (2 vs 3)"

    def test_first_difference_does_not_call_a_nan_a_difference(self):
        """Python's == on NaN is False, so an object comparison would lie here.

        This is not a hypothetical: a document holding a single NaN would be written
        byte-identically by two runs and still be reported as non-reproducible.
        """
        # Two DISTINCT NaN objects, which is what two separate parses produce. The same
        # object would compare equal by dict's identity short-circuit and would hide the
        # trap rather than demonstrate it.
        left, right = {"entropy": float("nan")}, {"entropy": float("nan")}
        assert left != right, "the trap this test exists for has stopped existing"
        assert fp.first_difference(left, right) is None

    def test_a_changed_app_manifest_is_attributed_only_when_confirmed(self, tmp_path):
        """The mutable-input list must be an attribution, never an exemption.

        Steam rewrites appmanifest_*.acf on its own schedule, so two builds can differ
        in steam.appmanifest_sha256 with nothing else moving. That is the input
        changing. But a list of forgiven pointers would also forgive real
        non-determinism at the same pointer, so the tool re-reads the file and only
        attributes the difference when the re-read proves it changed.
        """
        acf = tmp_path / "appmanifest_2119830.acf"
        acf.write_bytes(b"first")
        first = {"steam": {"appmanifest_path": str(acf),
                           "appmanifest_sha256": hashlib.sha256(b"first").hexdigest()}}
        where = "$.steam.appmanifest_sha256 ('a' vs 'b')"

        # The file has NOT changed -> no attribution, so the check stays a failure.
        assert fp.attribute_to_a_changed_input(where, first) is None

        # The file HAS changed -> attributed, and the sentence says what it re-read.
        acf.write_bytes(b"second")
        reason = fp.attribute_to_a_changed_input(where, first)
        assert reason is not None
        assert "Steam rewrote its own bookkeeping file" in reason
        assert hashlib.sha256(b"second").hexdigest() in reason

    def test_no_other_pointer_is_ever_attributed(self, tmp_path):
        acf = tmp_path / "appmanifest_2119830.acf"
        acf.write_bytes(b"first")
        first = {"steam": {"appmanifest_path": str(acf),
                           "appmanifest_sha256": hashlib.sha256(b"first").hexdigest()}}
        acf.write_bytes(b"second")
        for pointer in ("$.identity.build_key (x vs y)",
                        "$.layout.tree_hash (x vs y)",
                        "$.steam.size_on_disk (1 vs 2)",
                        "$.executables[0].sha256 (x vs y)"):
            assert fp.attribute_to_a_changed_input(pointer, first) is None, pointer

    def test_the_document_states_the_caveat(self, payload):
        notes = payload["document"]["notes"]
        assert "appmanifest_sha256" in notes
        assert "is NOT the only field that can differ" in notes

    def test_the_serialisation_is_deterministic_and_bom_free(self, payload):
        text = fp.dump_json(payload["document"])
        assert not text.startswith("\ufeff")
        assert text.endswith("\n")
        assert "\r" not in text
        assert json.loads(text) == payload["document"]
        keys = list(json.loads(text).keys())
        assert keys == sorted(keys)


class TestAnomaliesReport:

    def test_it_names_every_missing_file(self, payload):
        text = fp.render_anomalies_md(payload)
        for entry in payload["document"]["anomalies"]:
            if entry["kind"] == "file-not-in-non-ufs-manifest":
                assert entry["path"] in text

    def test_the_group_sums_are_stated_and_agree(self, payload):
        text = fp.render_anomalies_md(payload)
        missing = [a for a in payload["document"]["anomalies"]
                   if a["kind"] == "file-not-in-non-ufs-manifest"]
        assert "Сумма по группам: **%d**" % len(missing) in text
        assert "группировка потеряла записи" not in text

    def test_the_timestamp_comparison_is_actually_run(self, payload):
        stats = payload["manifest_timestamps"]
        assert stats["compared"] == len(payload["manifest_entries"])
        assert stats["same"] + stats["differ"] + stats["unknown"] == stats["compared"]

    def test_it_carries_exactly_one_timestamp(self, payload):
        text = fp.render_anomalies_md(payload)
        stamp = payload["document"]["identity"]["generated_at"]
        assert text.count(stamp) == 1


# --------------------------------------------------------------------------- #
# 7. D-01: the installation is never written to
# --------------------------------------------------------------------------- #

class TestOutputGuard:

    def test_an_out_path_inside_the_installation_is_refused(self, install, capsys):
        inside = os.path.join(install, "fingerprint.json")
        code = fp.main(["--install-dir", install, "--out", inside])
        assert code == 2
        assert not os.path.exists(inside)
        assert "refusing to write inside the game installation" in capsys.readouterr().err

    def test_an_anomalies_path_inside_the_installation_is_refused(self, install,
                                                                  tmp_path, capsys):
        inside = os.path.join(install, "anomalies.md")
        code = fp.main(["--install-dir", install,
                        "--out", str(tmp_path / "out.json"),
                        "--anomalies-out", inside])
        assert code == 2
        assert not os.path.exists(inside)
        assert not (tmp_path / "out.json").exists(), \
            "the guard must refuse before anything is written"

    def test_the_guard_is_the_shared_one(self):
        """Imported, never reimplemented (plan.md 1.5 layer 1)."""
        assert fp.pathguard is pathguard


class TestExitCodes:
    """A failing check about the OUTPUT must not be reported as a clean run."""

    def test_a_clean_run_exits_zero_and_writes_both_files(self, install, tmp_path):
        out = tmp_path / "out" / "fingerprint.json"
        anomalies = tmp_path / "out" / "anomalies.md"
        out.parent.mkdir()
        code = fp.main(["--install-dir", install, "--out", str(out),
                        "--anomalies-out", str(anomalies),
                        "--repo-root", str(tmp_path / "no-such-repo")])
        assert code == 0
        assert out.exists() and anomalies.exists()

    def test_a_schema_failure_exits_one(self, install, tmp_path, monkeypatch):
        monkeypatch.setattr(fp, "validate_against_schema",
                            lambda document, schema_path: (False, ["synthetic"]))
        code = fp.main(["--install-dir", install,
                        "--out", str(tmp_path / "fingerprint.json"),
                        "--repo-root", str(tmp_path / "no-such-repo")])
        assert code == 1

    def test_a_registry_mismatch_alone_does_not_exit_nonzero(self, install, tmp_path):
        """An installation-facing finding is a finding, not a tool failure."""
        code = fp.main(["--install-dir", install,
                        "--out", str(tmp_path / "fingerprint.json"),
                        "--repo-root", str(tmp_path / "no-such-repo")])
        assert code == 0

    def test_the_correctness_check_names_are_real_check_names(self, install, tmp_path):
        code = fp.main(["--install-dir", install,
                        "--out", str(tmp_path / "fingerprint.json"),
                        "--repo-root", str(tmp_path / "no-such-repo"),
                        "--selftest-reproducible"])
        assert code == 0
        emitted = set(fp.TOOL_CORRECTNESS_CHECKS)
        assert emitted == {"validates_against_published_schema",
                           "two_runs_differ_only_in_generated_at"}


# --------------------------------------------------------------------------- #
# 8. composition: the numbers come from the other tools
# --------------------------------------------------------------------------- #

class TestItComposesRatherThanParses:

    def test_the_pe_object_is_exactly_what_pe_info_produced(self, install, payload):
        import pe_info
        target = os.path.join(install, "MISERY", "Binaries", "Win64",
                              "MISERY-Win64-Shipping.exe")
        expected = pe_info.analyze(target, want_file_digest=False)["pe"]
        got = [entry["pe"] for entry in payload["document"]["executables"]
               if entry["role"] == "primary-shipping"][0]
        assert got == expected

    def test_the_container_entry_is_exactly_container_info_s_shape(self, install,
                                                                   payload):
        import container_info
        expected = container_info.build_document(install_dir=install)["containers"]
        got = payload["document"]["containers"]
        assert [entry["path"] for entry in got] == [e["path"] for e in expected]
        for mine, theirs in zip(got, expected):
            assert mine["utoc"] == theirs["utoc"]
            assert mine["pak"] == theirs["pak"]
            assert set(mine) == set(theirs)

    def test_identity_uses_the_inventory_implementation(self):
        import snapshot_install
        assert fp.inventory is snapshot_install


# --------------------------------------------------------------------------- #
# 9. checks the tool reports about itself
# --------------------------------------------------------------------------- #

class TestSelfChecks:

    def test_the_reproduction_checks_pass_on_a_stable_tree(self, payload):
        names = {check["check"] for check in payload["checks"]}
        assert "manifest_comparison_reproduced" in names
        assert "pe_section_survey_reproduced" in names
        for check in payload["checks"]:
            assert check["passed"], check

    def test_the_notes_state_the_content_key_rule(self, payload):
        notes = payload["document"]["notes"]
        assert "content_key ordering rule" in notes
        assert "tree_hash rule" in notes
        assert "C-13" in notes
        assert "D-02" in notes

    def test_a_registry_mismatch_is_reported_and_not_swallowed(self, payload, tmp_path):
        index = tmp_path / "research" / "builds"
        index.mkdir(parents=True)
        (index / "index.json").write_text("{}", encoding="utf-8")
        checks = fp.verify_against_registry(payload["document"], str(tmp_path))
        assert checks and not checks[0]["passed"]
        assert "no entry in index.json" in checks[0]["detail"]

    def test_a_missing_registry_is_reported_as_a_failure_not_a_pass(self, payload,
                                                                    tmp_path):
        checks = fp.verify_against_registry(payload["document"], str(tmp_path))
        assert checks and not checks[0]["passed"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
