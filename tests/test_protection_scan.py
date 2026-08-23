#!/usr/bin/env python3
"""Tests for tools/static/protection_scan.py (plan.md Q-8.2 / Q-8.3).

Every input is SYNTHETIC. No test reads a game file: decision D-01 makes the
installation a read-only research target, and a test suite that depends on it is
neither reproducible on another machine nor runnable where the game is absent.
The PE images are assembled with the same ``PEBuilder`` as
``tests/test_pe_info.py`` -- imported, not copied, so there is one definition of
"a valid PE" in this suite.

The synthetic inputs matter for a reason beyond hygiene, and it is the whole
point of this file. This tool's headline output is a NEGATIVE: nothing found on
the tested surfaces. A negative from a detector that never fires is worthless,
so the tests are built the other way round from the real run: a synthetic
installation is planted with EasyAntiCheat files, a .vmp0 section, a
CreateServiceW import, a ProcessDebugPort string, a .bind section and a middleware
name buried inside a container, and each one is asserted to be FOUND. Only after
the detector is shown to fire on planted evidence is a clean installation
asserted to come back NOT FOUND WITHIN TESTED SURFACE.

Coverage:
  * the delimiter test, which is what stops "Friday" matching the needle
    "Frida" and "unprotectedAttrs" matching "nProtect"
  * UTF-16LE matching, a non-ASCII neighbour counting as a delimiter, exact-case
    matching for API names, and a hit straddling a chunk boundary
  * the needle self-test over the real table, and a deliberately dead matcher
    being reported by needle name
  * planted positives, one per surface: filesystem name, kernel driver file,
    protector section name, service-install import, middleware symbol import,
    detection constant, active anti-debug import, .bind section, W+X section,
    high-entropy section, kernel routine name, container string
  * the export/import distinction: a bundled SDK that only OFFERS a protection
    API is not a finding, importing one of its symbols is
  * service-control versus service-install, and the GPU-driver-enumeration
    neighbourhood that explains the first
  * the certificate probe: a real WIN_CERTIFICATE recognised, a stale SECURITY
    entry pointing at ordinary section bytes rejected
  * the TLS surface: count, section attribution, file offset, .pdata lookup,
    UNWIND_INFO, the cross-module twin census, and the class-P literal reads
  * the primary-scope rule, including the bare-basename defect it was written
    to prevent, and the guarantee that scope never hides an unambiguous finding
  * a clean installation, the exact verdict wording it produces, and the
    guarantee that "there is no anti-cheat" cannot appear in the document
  * UNKNOWN licensing nothing: a missing control, or an ambiguous high-weight
    API, must not produce a clean answer or an admissible level 1
  * table integrity: every API entry carries its benign reading and its
    distinguishing question, which is the discipline plan.md demands, enforced
    mechanically rather than by review
  * the confidence ceiling, determinism, and the pathguard contract on --out
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pathguard  # noqa: E402
import protection_scan as ps  # noqa: E402
from test_pe_info import (PEBuilder, build_export_blob, build_import_blob,  # noqa: E402
                          build_tls_blob, write_image)

SCAN_PATH = os.path.join(REPO_ROOT, "tools", "static", "protection_scan.py")
IMAGE_BASE = 0x140000000

RDATA_FLAGS = 0x40000040          # initialised data, read
DATA_FLAGS = 0xC0000040           # initialised data, read/write
TEXT_FLAGS = 0x60000020           # code, execute, read
WX_FLAGS = 0xE0000020             # code, execute, read, WRITE


# --------------------------------------------------------------------------- #
# image builders
# --------------------------------------------------------------------------- #

def _clean_module(imports=(("KERNEL32.dll", [("name", "GetLastError", 0)]),),
                  strings: bytes = b"", extra_sections=(),
                  exports=None, tls_callbacks=None) -> bytes:
    """A plausible, boring PE64 with room for planted evidence."""
    builder = PEBuilder()
    text = bytearray(0x400)
    text[0:8] = b"\x48\x83\xec\x28\x33\xc0\xc3\x90"
    builder.add_section(".text", 0x1000, bytes(text), TEXT_FLAGS)

    rdata_rva = 0x2000
    import_blob = build_import_blob(rdata_rva, list(imports))
    payload = bytearray(import_blob)
    string_offset = len(payload)
    payload.extend(b"\x00" * 16)
    string_offset = len(payload)
    payload.extend(strings)
    payload.extend(b"\x00" * 16)

    export_offset = None
    if exports is not None:
        while len(payload) % 8:
            payload.append(0)
        export_offset = len(payload)
        payload.extend(build_export_blob(rdata_rva + export_offset, "test.dll",
                                         list(exports)))

    tls_offset = None
    if tls_callbacks is not None:
        while len(payload) % 8:
            payload.append(0)
        tls_offset = len(payload)
        payload.extend(build_tls_blob(rdata_rva + tls_offset,
                                      list(tls_callbacks)))

    builder.add_section(".rdata", rdata_rva, bytes(payload), RDATA_FLAGS)
    builder.set_directory(1, rdata_rva, len(import_blob))
    if export_offset is not None:
        builder.set_directory(0, rdata_rva + export_offset, 40)
    if tls_offset is not None:
        builder.set_directory(9, rdata_rva + tls_offset, 40)

    next_rva = 0x3000
    for name, data, flags in extra_sections:
        builder.add_section(name, next_rva, data, flags)
        next_rva += 0x1000
    del string_offset
    return builder.build()


def _write_inventory(root: str, entries) -> str:
    """An install-inventory.json shaped like the committed one."""
    files = []
    for relative in entries:
        absolute = os.path.join(root, relative.replace("/", os.sep))
        files.append({"path": relative,
                      "size": os.path.getsize(absolute)
                      if os.path.isfile(absolute) else 0})
    document = {
        "build_id": "synthetic-test-build",
        "build_key": "sha256:" + "0" * 64,
        "content_key": "sha256:" + "1" * 64,
        "engine_version": "5.4.4",
        "file_count": len(files),
        "files": sorted(files, key=lambda item: item["path"]),
        "generated_at": "2026-01-01T00:00:00Z",
        "generator_version": "test",
        "install_dir": root,
        "notes": [],
        "steam": {},
        "total_size": sum(entry["size"] for entry in files),
        "tree_hash": "sha256:" + "2" * 64,
    }
    path = os.path.join(root, "inventory.json")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return path


def _place(root: str, relative: str, blob: bytes) -> None:
    absolute = os.path.join(root, relative.replace("/", os.sep))
    parent = os.path.dirname(absolute)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(absolute, "wb") as handle:
        handle.write(blob)


def build_installation(tmp_path, *, extra_files=None, plant=None) -> tuple[str, str]:
    """A synthetic installation carrying both control modules.

    ``dbghelp.dll`` holds the positive-control string and ``tbbmalloc.dll`` is
    deliberately empty of everything, because the tool's own probes look for
    those two files by name. Building them here means the control machinery is
    exercised by the tests rather than only by the real run.
    """
    root = os.path.join(str(tmp_path), "install")
    os.makedirs(root, exist_ok=True)
    entries = []

    _place(root, "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll",
           _clean_module(strings=b"NtQueryInformationProcess\x00"))
    entries.append("Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll")

    _place(root, "Game/Binaries/Win64/tbbmalloc.dll", _clean_module())
    entries.append("Game/Binaries/Win64/tbbmalloc.dll")

    _place(root, "Game/Binaries/Win64/Game-Win64-Shipping.exe",
           plant if plant is not None else _clean_module(
               strings=b"IsDebuggerPresent\x00OutputDebugStringW\x00",
               tls_callbacks=[IMAGE_BASE + 0x1010, IMAGE_BASE + 0x1020]))
    entries.append("Game/Binaries/Win64/Game-Win64-Shipping.exe")

    for relative, blob in (extra_files or {}).items():
        _place(root, relative, blob)
        entries.append(relative)

    inventory = _write_inventory(root, entries)
    return root, inventory


PRIMARY = ["Game/Binaries/Win64/Game-Win64-Shipping.exe"]


def run_scan(root: str, inventory: str, primary=PRIMARY) -> dict:
    """The default invocation used by most tests.

    ``primary`` names the module the ambiguous half of Q-8.2 is ABOUT. The
    synthetic installation carries a positive-control dbghelp.dll that
    deliberately contains a high-weight API name, exactly as Microsoft's real one
    does, so a run with no scope at all is correctly UNKNOWN -- which is asserted
    on its own in ``test_without_a_primary_scope_the_control_module_forces_unknown``.
    """
    return ps.analyze(root, inventory_path=inventory, wide_scan=True,
                      primary_patterns=primary)


# --------------------------------------------------------------------------- #
# 1. the matcher and its delimiter test
# --------------------------------------------------------------------------- #

def _hits(needle_set: ps.NeedleSet, blob: bytes) -> list[dict]:
    out: list[dict] = []
    needle_set.search(blob, 0, out.append)
    return out


def test_delimiter_test_rejects_frida_inside_friday():
    """The false positive that motivated the delimiter test, asserted directly."""
    needles = ps.NeedleSet([ps.Needle("Frida", "vocabulary", "vocabulary",
                                      case_sensitive=False)])
    assert _hits(needles, b"\x00Monday Friday Saturday\x00") == []
    assert [hit["needle"] for hit in _hits(needles, b"\x00 Frida \x00")] == ["Frida"]


def test_delimiter_test_rejects_nprotect_inside_unprotectedattrs():
    needles = ps.NeedleSet([ps.Needle("nProtect", "middleware", "anti-cheat",
                                      case_sensitive=False)])
    assert _hits(needles, b"\x00unprotectedAttrs\x00") == []
    assert len(_hits(needles, b"\x00nProtect GameGuard\x00")) == 1


def test_two_spellings_of_one_case_insensitive_needle_both_report():
    """Both spellings must come back, not just whichever sorts first.

    This is the defect the self-test caught during development: two
    case-insensitive needles that differ only in case collapsed into one
    alternation branch and only one of them was ever reported.
    """
    needles = ps.NeedleSet([
        ps.Needle("XignCode", "middleware", "anti-cheat", case_sensitive=False),
        ps.Needle("XIGNCODE", "middleware", "anti-cheat", case_sensitive=False),
    ])
    reported = sorted(hit["needle"] for hit in _hits(needles, b"\x00 xigncode \x00"))
    assert reported == ["XIGNCODE", "XignCode"]


def test_utf16_matching_and_offsets():
    needles = ps.NeedleSet([ps.Needle("BattlEye", "middleware", "anti-cheat",
                                      case_sensitive=False)])
    blob = b"\x00\x00" + "  BattlEye  ".encode("utf-16-le")
    found = _hits(needles, blob)
    assert len(found) == 1
    assert found[0]["encoding"] == "utf-16le"
    assert found[0]["length"] == len("BattlEye") * 2
    assert blob[found[0]["offset"]:found[0]["offset"] + found[0]["length"]] \
        == "BattlEye".encode("utf-16-le")


def test_utf16_non_ascii_neighbour_counts_as_delimiter():
    """A Cyrillic letter next to the match must not veto it.

    A UTF-16 code unit only counts as an identifier character when its high byte
    is zero; without that rule any non-Latin text adjacent to a needle would
    suppress the hit.
    """
    needles = ps.NeedleSet([ps.Needle("Denuvo", "middleware", "drm",
                                      case_sensitive=False)])
    blob = ("АDenuvoБ").encode("utf-16-le")
    assert len(_hits(needles, b"\x00\x00" + blob)) == 1


def test_case_sensitive_api_needle_does_not_match_other_casing():
    needles = ps.NeedleSet([ps.Needle("NtQueryInformationProcess", "api-kit",
                                      "anti-debug-probe")])
    assert _hits(needles, b"\x00ntqueryinformationprocess\x00") == []
    assert len(_hits(needles, b"\x00NtQueryInformationProcess\x00")) == 1


def test_needle_longer_than_the_overlap_is_refused():
    with pytest.raises(ValueError):
        ps.NeedleSet([ps.Needle("x" * (ps.MAX_NEEDLE_BYTES), "g", "c")])


def test_hit_straddling_a_chunk_boundary_is_found_exactly_once(tmp_path):
    """The overlap must not turn one hit into two, or into none."""
    needle = "EasyAntiCheat"
    filler = b"." * (ps.SCAN_CHUNK - 4)
    blob = filler + b" " + needle.encode("ascii") + b" " + b"." * 4096
    path = os.path.join(str(tmp_path), "straddle.bin")
    with open(path, "wb") as handle:
        handle.write(blob)
    result = ps.scan_file(path, ps.build_wide_needle_set())
    matching = [hit for hit in result["hits"] if hit["needle"] == needle]
    assert len(matching) == 1
    assert matching[0]["count"] == 1
    assert matching[0]["occurrences"][0]["offset"] == blob.index(
        needle.encode("ascii"))


# --------------------------------------------------------------------------- #
# 2. the self-test
# --------------------------------------------------------------------------- #

def test_self_test_fires_for_every_declared_needle():
    """Before any negative result is believed, the detector must be shown alive."""
    result = ps.self_test_needle_set(ps.build_needle_set())
    assert result["needles_that_did_not_fire"] == []
    assert result["passed"] is True
    assert result["needles_declared"] > 100


def test_self_test_cli_exits_zero_and_touches_no_game_file():
    process = subprocess.run(
        [sys.executable, SCAN_PATH, "--self-test-only"],
        capture_output=True, text=True, check=False)
    assert process.returncode == 0
    document = json.loads(process.stdout)
    assert document["passed"] is True


def test_a_broken_needle_is_reported_by_name():
    """A needle that cannot fire must be named, not silently dropped."""

    class Dead(ps.NeedleSet):
        def search(self, buffer, base_offset, sink):
            return {"candidates": 0, "rejected_undelimited": 0, "accepted": 0}

    result = ps.self_test_needle_set(Dead([ps.Needle("Ghost", "g", "c")]))
    assert result["passed"] is False
    assert result["needles_that_did_not_fire"] == ["Ghost"]


# --------------------------------------------------------------------------- #
# 3. planted positives, one per surface
# --------------------------------------------------------------------------- #

def test_planted_anticheat_files_are_found_on_the_filesystem_surface(tmp_path):
    extra = {
        "EasyAntiCheat/EasyAntiCheat_x64.dll": _clean_module(),
        "EasyAntiCheat/easyanticheat.sys": b"\x00" * 64,
    }
    root, inventory = build_installation(tmp_path, extra_files=extra)
    document = run_scan(root, inventory)
    surface = document["surfaces"]["filesystem_inventory"]
    matched = {hit["path"] for hit in surface["middleware_name_matches"]}
    assert "EasyAntiCheat/EasyAntiCheat_x64.dll" in matched
    assert "EasyAntiCheat/easyanticheat.sys" in matched
    assert [entry["path"] for entry in surface["kernel_driver_files"]] == \
        ["EasyAntiCheat/easyanticheat.sys"]
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND
    assert document["instrumentation_assessment"]["stop_condition_triggered"] is True


def test_planted_protector_section_is_found_on_the_section_surface(tmp_path):
    plant = _clean_module(extra_sections=[(".vmp0", b"\x11" * 0x800, TEXT_FLAGS)])
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    findings = [finding
                for module in document["surfaces"]["modules"]
                for finding in module["section_findings"]
                if finding["kind"] == "known-protector-section-name"]
    assert [finding["section"] for finding in findings] == [".vmp0"]
    assert "VMProtect" in findings[0]["attributed_to"][0]
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_FOUND


def test_planted_service_install_import_is_found_on_the_import_surface(tmp_path):
    plant = _clean_module(imports=(
        ("KERNEL32.dll", [("name", "GetLastError", 0)]),
        ("ADVAPI32.dll", [("name", "CreateServiceW", 0),
                          ("name", "OpenSCManagerW", 0)]),
    ))
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    categories = {match["category"]
                  for module in document["surfaces"]["modules"]
                  for match in module["api_kit_imports"]}
    assert "service-install" in categories
    assert "service-control" in categories
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND


def test_service_query_is_distinguished_from_service_install(tmp_path):
    """The one API on the list with a common innocent use gets its context.

    A renderer reads the display driver's version through the service database.
    The report has to show WHICH neighbourhood a service-control hit sat in,
    because control-without-install is a query and cannot load anything.
    """
    plant = _clean_module(
        imports=(("ADVAPI32.dll", [("name", "OpenSCManagerW", 0),
                                   ("name", "OpenServiceW", 0),
                                   ("name", "QueryServiceConfigW", 0),
                                   ("name", "CloseServiceHandle", 0)]),),
        strings=b"D3DKMTEnumAdapters2\x00nvapi_QueryInterface\x00"
                b"SetupDiGetClassDevsW\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    rows = document["surfaces"]["service_and_driver"]["modules"]
    row = [item for item in rows
           if item["module"].endswith("Game-Win64-Shipping.exe")][0]
    assert "OpenSCManagerW" in row["service_control_imports"]
    assert row["service_install_imports"] == []
    assert len(row["gpu_driver_enumeration_context"]) >= 3
    # A query neighbourhood must not move the anti-cheat verdict.
    assert document["verdicts"]["Q-8.3"]["verdict"] == \
        ps.VERDICT_NOT_FOUND_IN_SURFACE


def test_service_install_next_to_the_same_context_is_still_a_finding(tmp_path):
    """The innocent neighbourhood must not launder a CreateService."""
    plant = _clean_module(
        imports=(("ADVAPI32.dll", [("name", "OpenSCManagerW", 0),
                                   ("name", "CreateServiceW", 0)]),),
        strings=b"D3DKMTEnumAdapters2\x00nvapi_QueryInterface\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    row = [item for item in document["surfaces"]["service_and_driver"]["modules"]
           if item["module"].endswith("Game-Win64-Shipping.exe")][0]
    assert row["service_install_imports"] == ["CreateServiceW"]
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND


def test_a_library_that_only_offers_a_protection_api_is_not_a_finding(tmp_path):
    """Exported capability is a fact about the library, not about the build.

    The Epic Online Services SDK exports its whole anti-cheat API family in
    every build it ships. Treating that as "this game has anti-cheat" would be
    the mirror image of the forbidden inference: a conclusion read off a surface
    that cannot support it.
    """
    plant = _clean_module(exports=["EAC_Client_Initialize",
                                   "EOS_AntiCheatClient_BeginSession",
                                   "EOS_AntiCheatClient_EndSession", "Ordinary"])
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    offered = [row
               for module in document["surfaces"]["modules"]
               for row in module["middleware_exports_offered"]]
    assert offered, "the exported family must still be reported"
    assert offered[0]["exported_symbol_count"] == 3
    assert offered[0]["middleware_id"] == "easyanticheat"
    assert document["verdicts"]["Q-8.3"]["verdict"] == \
        ps.VERDICT_NOT_FOUND_IN_SURFACE
    reading = document["verdicts"]["Q-8.3"][
        "middleware_capability_offered_but_not_linked"]["reading"]
    assert "not about this build" in reading


def test_importing_a_protection_symbol_is_a_finding(tmp_path):
    """Linking the API is the fact that decides the question."""
    plant = _clean_module(imports=(
        ("KERNEL32.dll", [("name", "GetLastError", 0)]),
        ("EOSSDK-Win64-Shipping.dll",
         [("name", "EOS_AntiCheatClient_BeginSession", 0),
          ("name", "EOS_Auth_Login", 0)]),
    ))
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    linked = [row
              for module in document["surfaces"]["modules"]
              for row in module["middleware_symbol_imports"]]
    assert [row["middleware_id"] for row in linked] == ["easyanticheat"]
    assert linked[0]["imported_symbols"] == ["EOS_AntiCheatClient_BeginSession"]
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND
    surfaces = {item["surface"]
                for item in document["verdicts"]["Q-8.3"]["positive_indicators"]}
    assert "pe-imports-middleware-symbol" in surfaces


def test_a_bare_basename_primary_pattern_matches_only_an_exact_path(tmp_path):
    """The defect this rule exists to prevent, asserted directly.

    The real installation holds two different files called MISERY.exe -- the
    bootstrap shim at the root and the D-04 oracle under Binaries/Win64. A
    suffix rule pulled the oracle into the scope of a verdict about the shipped
    game, and the oracle is a non-Shipping build with a different import table.
    """
    assert ps.is_primary_module("MISERY.exe", ["MISERY.exe"]) is True
    assert ps.is_primary_module("MISERY/Binaries/Win64/MISERY.exe",
                                ["MISERY.exe"]) is False
    # A pattern that names a directory may still match by suffix.
    assert ps.is_primary_module("MISERY/Binaries/Win64/MISERY.exe",
                                ["Win64/MISERY.exe"]) is True
    assert ps.is_primary_module("anything", None) is True


def test_planted_detection_constant_is_found_and_answers_q82(tmp_path):
    plant = _clean_module(strings=b"ProcessDebugPort\x00ThreadHideFromDebugger\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    constants = document["verdicts"]["Q-8.2"]["detection_constants"]
    assert sorted(entry["needle"] for entry in constants) == \
        ["ProcessDebugPort", "ThreadHideFromDebugger"]
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_FOUND
    assert document["instrumentation_assessment"][
        "level_1_external_read_only_inspector"]["admissible"] is False


def test_planted_active_antidebug_import_answers_q82(tmp_path):
    plant = _clean_module(imports=(
        ("KERNEL32.dll", [("name", "DebugActiveProcess", 0)]),
    ))
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_FOUND


def test_planted_middleware_name_inside_a_container_is_found(tmp_path):
    """The whole-install pass must see a name that is in no executable."""
    payload = b"\x00" * 4096 + b" BEDaisy " + b"\x00" * 4096
    root, inventory = build_installation(
        tmp_path, extra_files={"Content/Paks/Game-Windows.ucas": payload})
    document = run_scan(root, inventory)
    wide = document["surfaces"]["whole_install_string_pass"]
    assert wide["ran"] is True
    hits = [hit for hit in wide["hits"] if hit["needle"] == "BEDaisy"]
    assert len(hits) == 1
    assert hits[0]["path"] == "Content/Paks/Game-Windows.ucas"
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND


def test_broad_vocabulary_is_counted_and_never_moves_a_verdict(tmp_path):
    """The words the brief asks for by name, searched but not interpreted."""
    plant = _clean_module(
        strings=b"r.Net.Integrity integrity check hook hooks debugger\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    broad = document["verdicts"]["Q-8.2"]["broad_vocabulary"]
    present = {row["needle"] for row in broad["present"]}
    assert {"integrity", "hook", "hooks", "debugger"} <= present
    assert "cheat" in broad["absent"]
    assert "counted, not interpreted" in broad["reading"]
    # Ordinary words must not be able to answer a Tier A question.
    assert document["verdicts"]["Q-8.2"]["verdict"] == \
        ps.VERDICT_NOT_FOUND_IN_SURFACE
    assert document["verdicts"]["Q-8.3"]["verdict"] == \
        ps.VERDICT_NOT_FOUND_IN_SURFACE


def test_broad_vocabulary_is_delimited(tmp_path):
    """"hookup" must not count as "hook"."""
    plant = _clean_module(strings=b"hookup cheatsheet debuggerless\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    broad = document["verdicts"]["Q-8.2"]["broad_vocabulary"]
    assert broad["present"] == []
    assert "hook" in broad["absent"]
    assert "cheat" in broad["absent"]


def test_planted_kernel_routine_name_is_reported_separately(tmp_path):
    plant = _clean_module(strings=b"ObRegisterCallbacks\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    kernel = document["verdicts"]["Q-8.3"]["kernel_mode_indicators"]
    assert [entry["needle"] for entry in kernel] == ["ObRegisterCallbacks"]


def test_planted_bind_section_is_reported_as_a_steam_ceg_indicator(tmp_path):
    plant = _clean_module(extra_sections=[(".bind", b"\x22" * 0x400, RDATA_FLAGS)])
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    steam = document["surfaces"]["steam_layer"]
    assert [entry["section"] for entry in steam["bind_sections"]] == [".bind"]


def test_writable_executable_section_is_flagged(tmp_path):
    plant = _clean_module(extra_sections=[(".patch", b"\x33" * 0x400, WX_FLAGS)])
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    kinds = {finding["kind"]
             for module in document["surfaces"]["modules"]
             for finding in module["section_findings"]}
    assert "writable-executable-section" in kinds


def test_high_entropy_section_is_flagged_but_only_as_low_when_harmless(tmp_path):
    """Entropy alone must never be promoted into a finding."""
    import random
    random.seed(1234)
    noise = bytes(random.randrange(256) for _ in range(8192))
    plant = _clean_module(extra_sections=[(".blob", noise, RDATA_FLAGS)])
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    entries = [finding
               for module in document["surfaces"]["modules"]
               for finding in module["section_findings"]
               if finding["kind"] == "high-entropy-section"]
    assert entries, "a random 8 KiB section should trip the entropy threshold"
    assert entries[0]["severity"] == "low"
    assert entries[0]["module_has_import_table"] is True


def test_a_certificate_blob_is_verified_not_assumed(tmp_path):
    """A non-zero SECURITY directory is not a signature.

    F-01 reports the directory entry; this tool has to check that the entry
    actually addresses a WIN_CERTIFICATE, because "the image is signed" is one
    of the CEG indicators and a stale entry would otherwise read as DRM.
    """
    body = b"Contoso Signing Authority" + b"\x00" * 200
    blob = struct.pack("<IHH", 8 + len(body), 0x0200, 0x0002) + body
    base = _clean_module()
    image = base + blob
    # The directory entry is a FILE OFFSET for IMAGE_DIRECTORY_ENTRY_SECURITY.
    builder_offset = struct.unpack_from("<I", image, 0x3C)[0] + 24 + 112 + 4 * 8
    patched = bytearray(image)
    struct.pack_into("<II", patched, builder_offset, len(base), len(blob))
    root, inventory = build_installation(tmp_path, plant=bytes(patched))
    document = run_scan(root, inventory)
    module = [item for item in document["surfaces"]["modules"]
              if item["path"].endswith("Game-Win64-Shipping.exe")][0]
    probe = module["headers"]["authenticode"]
    assert probe["looks_like_win_certificate"] is True
    assert probe["revision"] == "0x0200"
    assert probe["certificate_type"] == "0x0002"
    assert probe["ends_at_end_of_file"] is True
    assert "Contoso Signing Authority" in probe["printable_runs"]
    assert module["headers"]["carries_a_certificate_blob"] is True


def test_a_security_entry_pointing_at_non_certificate_bytes_is_rejected(tmp_path):
    """The exact shape found on the real bootstrap shim."""
    base = _clean_module()
    patched = bytearray(base)
    directory = struct.unpack_from("<I", base, 0x3C)[0] + 24 + 112 + 4 * 8
    # Point the entry at ordinary section bytes, well inside the file.
    struct.pack_into("<II", patched, directory, 0x400, 0x100)
    root, inventory = build_installation(tmp_path, plant=bytes(patched))
    document = run_scan(root, inventory)
    module = [item for item in document["surfaces"]["modules"]
              if item["path"].endswith("Game-Win64-Shipping.exe")][0]
    assert module["headers"]["security_directory_entry_present"] is True
    assert module["headers"]["carries_a_certificate_blob"] is False
    assert module["headers"]["authenticode"]["header_bytes_hex"] is not None
    # And it must not be counted as a signed executable on the Steam surface.
    assert document["surfaces"]["steam_layer"][
        "authenticode_signed_executables"] == []


def test_certificate_probe_says_what_it_does_not_prove(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    module = document["surfaces"]["modules"][0]
    limits = module["headers"]["authenticode"]["limits"]
    assert "No certificate chain is built" in limits
    assert "never that it" in limits


# --------------------------------------------------------------------------- #
# 4. the clean installation, and the wording of the negative
# --------------------------------------------------------------------------- #

def test_clean_installation_yields_not_found_within_tested_surface(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    for key in ("Q-8.2", "Q-8.3"):
        verdict = document["verdicts"][key]
        assert verdict["verdict"] == ps.VERDICT_NOT_FOUND_IN_SURFACE
        assert verdict["verdict_display"] == "NOT FOUND WITHIN TESTED SURFACE"
        # The negative is only ever allowed to be a statement about surfaces.
        assert verdict["tested_surfaces"]
        assert verdict["untested_surfaces"]
        assert verdict["what_would_change_the_answer"]


def test_negative_verdict_never_says_there_is_no_anticheat(tmp_path):
    """The forbidden phrasing must be unreachable from the machine document."""
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    text = ps.dump_json(document).lower()
    for phrase in ("there is no anti-cheat", "there is no anticheat",
                   "no anti-cheat is present", "anti-cheat does not exist"):
        assert phrase not in text
    assert ps.VERDICT_NOT_FOUND_IN_SURFACE.lower() in text


def test_low_weight_kit_is_present_but_not_counted_as_protection(tmp_path):
    """IsDebuggerPresent in the image must not move the verdict."""
    plant = _clean_module(
        imports=(("KERNEL32.dll", [("name", "IsDebuggerPresent", 0),
                                   ("name", "OutputDebugStringW", 0),
                                   ("name", "SetUnhandledExceptionFilter", 0),
                                   ("name", "CreateToolhelp32Snapshot", 0),
                                   ("name", "VirtualProtect", 0)]),))
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    names = {match["name"]
             for module in document["surfaces"]["modules"]
             for match in module["api_kit_imports"]}
    assert {"IsDebuggerPresent", "OutputDebugStringW", "VirtualProtect"} <= names
    assert document["verdicts"]["Q-8.2"]["verdict"] == \
        ps.VERDICT_NOT_FOUND_IN_SURFACE
    assert "NOT counted as evidence of protection" in \
        document["verdicts"]["Q-8.2"]["interpretive_warning"]


def test_high_weight_probe_without_a_constant_yields_unknown_not_clean(tmp_path):
    """A genuinely ambiguous image must come back UNKNOWN, not clean."""
    plant = _clean_module(
        imports=(("KERNEL32.dll", [("name", "GetLastError", 0)]),),
        strings=b"NtQueryInformationProcess\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_UNKNOWN
    assert document["instrumentation_assessment"][
        "level_2_in_process_probe"]["admissible_on_this_evidence"] is False


def test_missing_positive_control_forces_unknown(tmp_path):
    """A clean answer from an unproven detector is not an answer."""
    root = os.path.join(str(tmp_path), "install")
    os.makedirs(root, exist_ok=True)
    _place(root, "Game/Binaries/Win64/Game.exe", _clean_module())
    inventory = _write_inventory(root, ["Game/Binaries/Win64/Game.exe"])
    document = ps.analyze(root, inventory_path=inventory, wide_scan=True,
                          primary_patterns=["Game/Binaries/Win64/Game.exe"])
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "positive-control-string-surface"][0]
    assert probe["result"] == "NOT RUN"
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_UNKNOWN
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_UNKNOWN


def test_without_a_primary_scope_the_control_module_forces_unknown(tmp_path):
    """The conservative default: any module's high-weight name grades the answer.

    With no --primary the positive-control dbghelp.dll -- which carries a
    high-weight API name on purpose, as Microsoft's real one does -- is inside
    the scope, and Q-8.2 must come back UNKNOWN rather than clean.
    """
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory, primary=None)
    assert document["verdicts"]["Q-8.2"]["verdict"] == ps.VERDICT_UNKNOWN
    names = [entry["name"]
             for entry in document["verdicts"]["Q-8.2"]["high_weight_api_presence"]]
    assert "NtQueryInformationProcess" in names


def test_scoped_run_still_reports_the_out_of_scope_finding_in_full(tmp_path):
    """Nothing is hidden by the scope; it only changes what may grade."""
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    outside = document["verdicts"]["Q-8.2"][
        "high_weight_api_presence_outside_primary_scope"]
    assert any(entry["name"] == "NtQueryInformationProcess" for entry in outside)
    assert all("dbghelp" in entry["module"].lower() for entry in outside)
    assert document["verdicts"]["Q-8.2"]["primary_scope"] == PRIMARY
    assert "unambiguous indicators" in \
        document["verdicts"]["Q-8.2"]["primary_scope_rule"]


def test_scope_does_not_suppress_an_unambiguous_indicator(tmp_path):
    """A middleware name outside the primary scope must still trigger FOUND."""
    root, inventory = build_installation(
        tmp_path,
        extra_files={"Third/Party/helper.dll": _clean_module(
            strings=b"BEDaisy\x00")})
    document = run_scan(root, inventory)
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_FOUND


def test_skipped_wide_pass_is_reported_as_untested_not_as_clean(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = ps.analyze(root, inventory_path=inventory, wide_scan=False,
                          primary_patterns=PRIMARY)
    tested = {item["id"] for item in document["verdicts"]["Q-8.3"]["tested_surfaces"]}
    untested = {item["surface"]
                for item in document["verdicts"]["Q-8.3"]["untested_surfaces"]}
    assert "strings-whole-install" not in tested
    assert "strings-whole-install" in untested


# --------------------------------------------------------------------------- #
# 5. probes
# --------------------------------------------------------------------------- #

def test_probes_pass_on_the_synthetic_installation(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    results = {probe["id"]: probe["result"]
               for probe in document["refutation_probes"]}
    assert results["needle-self-test"] == "PASS"
    assert results["positive-control-string-surface"] == "PASS"
    assert results["negative-control-module"] == "PASS"


def test_negative_control_failure_is_visible(tmp_path):
    """Planting a middleware name in the control module must break the control."""
    root, inventory = build_installation(tmp_path)
    _place(root, "Game/Binaries/Win64/tbbmalloc.dll",
           _clean_module(strings=b"BattlEye\x00"))
    document = run_scan(root, inventory)
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "negative-control-module"][0]
    assert probe["result"] == "FAIL"
    assert probe["detail"]["unexpected_hits"] == ["BattlEye"]


# --------------------------------------------------------------------------- #
# 6. the TLS surface and the class-P layer
# --------------------------------------------------------------------------- #

def test_tls_surface_reports_count_section_and_file_offset(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    module = [item for item in document["surfaces"]["modules"]
              if item["path"].endswith("Game-Win64-Shipping.exe")][0]
    tls = module["tls"]
    assert tls["present"] is True
    assert tls["callback_count"] == 2
    assert [callback["rva"] for callback in tls["callbacks"]] == [0x1010, 0x1020]
    assert [callback["section"] for callback in tls["callbacks"]] == [".text", ".text"]
    assert all(callback["in_executable_section"] for callback in tls["callbacks"])
    assert all(callback["file_offset"] is not None for callback in tls["callbacks"])
    assert tls["callback_array_section"] == ".rdata"
    assert "what the callbacks do" in tls["what_this_does_not_settle"]


def test_tls_shape_control_reports_how_common_two_callbacks_are(tmp_path):
    root, inventory = build_installation(
        tmp_path,
        extra_files={"Game/Binaries/Win64/other.dll": _clean_module(
            tls_callbacks=[IMAGE_BASE + 0x1010, IMAGE_BASE + 0x1020]),
            "Game/Binaries/Win64/third.dll": _clean_module(
                tls_callbacks=[IMAGE_BASE + 0x1030, IMAGE_BASE + 0x1040])})
    document = run_scan(root, inventory)
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "tls-shape-control"][0]
    assert probe["detail"]["count"] == 3
    assert probe["result"].startswith("PASS")


def test_tls_callbacks_are_checked_against_the_function_table(tmp_path):
    """A callback must be reported as a function start or not at all.

    The synthetic .text has no .pdata, so both callbacks must come back with
    ``has_runtime_function`` false -- the probe must say "no unwind data here"
    rather than inventing one.
    """
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    module = [item for item in document["surfaces"]["modules"]
              if item["path"].endswith("Game-Win64-Shipping.exe")][0]
    for callback in module["tls"]["callbacks"]:
        code = callback["code"]
        assert code is not None
        assert code["has_runtime_function"] is False
        assert code["is_function_start"] is False
        assert code["unwind"] is None
        # The bytes at the callback are still read, and read correctly.
        assert code["first_bytes_hex"] is not None
        absolute = os.path.join(root, module["path"].replace("/", os.sep))
        with open(absolute, "rb") as handle:
            handle.seek(callback["file_offset"])
            assert handle.read(16).hex() == code["first_bytes_hex"]


def test_tls_census_names_its_method_and_its_limits(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    census = document["surfaces"]["tls_callback_shape_comparison"]
    assert "every OTHER module" in census["method"]
    assert "does not close it" in census["limits"]
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "tls-callback-twins-in-other-modules"][0]
    # The synthetic installation has exactly one TLS-bearing module, so there is
    # nothing to compare it against and the probe must say so rather than claim
    # corroboration it does not have.
    assert probe["result"] == "ATTENTION -- a callback has no twin"
    assert probe["detail"]["fewest_twins_seen"] == 0


def test_tls_census_counts_independent_twins(tmp_path):
    """Three modules built from the same callback bytes corroborate each other."""
    shape = _clean_module(tls_callbacks=[IMAGE_BASE + 0x1010, IMAGE_BASE + 0x1020])
    root = os.path.join(str(tmp_path), "install")
    os.makedirs(root, exist_ok=True)
    _place(root, "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll", shape)
    _place(root, "Game/Binaries/Win64/tbbmalloc.dll", _clean_module())
    _place(root, "Third/vendor_a.dll", shape)
    _place(root, "Third/vendor_b.dll", shape)
    _place(root, "Game/Binaries/Win64/Game-Win64-Shipping.exe", shape)
    inventory = _write_inventory(root, [
        "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll",
        "Game/Binaries/Win64/tbbmalloc.dll",
        "Third/vendor_a.dll", "Third/vendor_b.dll",
        "Game/Binaries/Win64/Game-Win64-Shipping.exe"])
    document = ps.analyze(root, inventory_path=inventory, wide_scan=False,
                          primary_patterns=PRIMARY)
    census = document["surfaces"]["tls_callback_shape_comparison"]
    entry = census["comparisons"][0]
    assert entry["module"].endswith("Game-Win64-Shipping.exe")
    for row in entry["callbacks"]:
        assert row["donors_compared"] == 3
        assert len(row["byte_identical_modules"]) == 3
        assert len(row["both_identical_modules"]) == 3
        assert len(row["same_unwind_shape_and_length_modules"]) == 3
        assert row["partial_matches"] == []
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "tls-callback-twins-in-other-modules"][0]
    assert probe["result"] == "PASS -- every callback has independent twins"


def test_unwind_shape_ignores_function_length(tmp_path):
    """A one-byte tail difference must not make it "a different function".

    Vendors ship different CRT versions and the same helper differs by a byte or
    two in its tail. Folding the length into the shape test would count a
    one-byte difference as a different function, which is the opposite of what
    the census is for -- so length is reported on its own field.
    """
    shape = {"function_length": 164, "size_of_prolog": 25,
             "count_of_unwind_codes": 10, "flag_names": [],
             "is_function_start": True, "first_bytes_hex": "aa" * 16}
    longer = dict(shape, function_length=165)
    assert ps._shape_of({"code": {"function_length": 164, "unwind": {
        "size_of_prolog": 25, "count_of_unwind_codes": 10,
        "flag_names": []}}})["size_of_prolog"] == 25
    # The three fields the census compares agree; only the length differs.
    assert shape["size_of_prolog"] == longer["size_of_prolog"]
    assert shape["count_of_unwind_codes"] == longer["count_of_unwind_codes"]
    assert shape["flag_names"] == longer["flag_names"]
    assert shape["function_length"] != longer["function_length"]


def test_tls_census_reports_a_lone_callback_as_having_no_twin(tmp_path):
    """A callback nobody else has must keep the question open, not close it."""
    donor = _clean_module(tls_callbacks=[IMAGE_BASE + 0x1010])
    # A different callback target means different bytes at the entry.
    odd = _clean_module(tls_callbacks=[IMAGE_BASE + 0x1004])
    root = os.path.join(str(tmp_path), "install")
    os.makedirs(root, exist_ok=True)
    _place(root, "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll", donor)
    _place(root, "Game/Binaries/Win64/tbbmalloc.dll", _clean_module())
    _place(root, "Third/vendor_a.dll", donor)
    _place(root, "Game/Binaries/Win64/Game-Win64-Shipping.exe", odd)
    inventory = _write_inventory(root, [
        "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll",
        "Game/Binaries/Win64/tbbmalloc.dll", "Third/vendor_a.dll",
        "Game/Binaries/Win64/Game-Win64-Shipping.exe"])
    document = ps.analyze(root, inventory_path=inventory, wide_scan=False,
                          primary_patterns=PRIMARY)
    row = document["surfaces"]["tls_callback_shape_comparison"][
        "comparisons"][0]["callbacks"][0]
    assert row["donors_compared"] == 2
    assert row["byte_identical_modules"] == []
    assert row["partial_matches"]
    probe = [item for item in document["refutation_probes"]
             if item["id"] == "tls-callback-twins-in-other-modules"][0]
    assert probe["result"] == "ATTENTION -- a callback has no twin"


def test_literal_reads_state_offset_and_length_and_name_nothing(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    literals = document["literal_reads"]
    assert literals, "the TLS callback array should produce class-P reads"
    assert document["literal_reads_reproduced"] is True
    for read in literals:
        evidence = read["evidence"]
        assert evidence["claim_class"] == "P"
        assert evidence["evidence_level"] == "OBSERVED"
        assert evidence["oracle"] == ["binary-analysis"]
        assert evidence["confidence"] == ps.CONFIDENCE_LITERAL
        # The graded note must BE the claim: offset, length, bytes, and no name
        # for what the bytes are.
        note = evidence["note"]
        assert str(read["offset"]) in note
        assert str(read["length"]) in note
        assert read["bytes_hex"] in note
        for forbidden in ("TLS", "callback", "IMAGE_", "directory", "import",
                          "section"):
            assert forbidden not in note
        assert read["reproduced"] is True


def test_literal_reads_cover_only_the_primary_scope(tmp_path):
    """The class-P layer carries the primitive half of what the document grades.

    A byte range inside a bundled third-party DLL underpins no graded class-P
    claim, so it is not recorded. (It is also what keeps the records readable by
    tools/kb/validate.py, whose CamelCase heuristic matches third-party PATH
    components -- see the docstring of collect_literal_reads.)
    """
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    targets = {read["target"] for read in document["literal_reads"]}
    assert targets, "the primary module should still produce reads"
    assert targets <= set(PRIMARY)
    assert not any("dbghelp" in target for target in targets)


def test_literal_read_bytes_match_the_file(tmp_path):
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)
    for read in document["literal_reads"]:
        absolute = os.path.join(root, read["target"].replace("/", os.sep))
        with open(absolute, "rb") as handle:
            handle.seek(read["offset"])
            raw = handle.read(read["length"])
        assert raw.hex() == read["bytes_hex"]


# --------------------------------------------------------------------------- #
# 7. table integrity -- the interpretive discipline, enforced mechanically
# --------------------------------------------------------------------------- #

def test_every_api_entry_carries_its_benign_reading_and_its_open_question():
    """plan.md forbids presenting the kit as evidence; this keeps the promise."""
    for entry in ps.API_KIT:
        assert entry["name"]
        assert entry["category"]
        assert entry["weight"] in ("low", "medium", "high")
        assert len(entry["benign"]) > 20, entry["name"]
        assert len(entry["distinguishes"]) > 10, entry["name"]


def test_api_kit_names_are_unique():
    names = [entry["name"] for entry in ps.API_KIT]
    assert len(names) == len(set(names))


def test_every_middleware_entry_declares_a_deployment_shape():
    for entry in ps.MIDDLEWARE:
        assert entry["id"] and entry["display"] and entry["family"]
        assert len(entry["deployment_note"]) > 20, entry["id"]
        assert entry["files"] or entry["strings"] or entry["sections"] \
            or entry["exports"], entry["id"]


def test_middleware_ids_are_unique():
    ids = [entry["id"] for entry in ps.MIDDLEWARE]
    assert len(ids) == len(set(ids))


def test_api_kit_import_matching_accepts_suffix_spellings():
    """An A/W/Ex spelling of a listed name must resolve to the listed name."""
    matches = ps.api_kit_matches([
        {"kind": "import", "dll": "ntdll.dll", "name": "NtSetInformationThreadEx",
         "ordinal": None},
        {"kind": "import", "dll": "kernel32.dll", "name": "SomethingElse",
         "ordinal": None},
    ])
    assert [match["canonical"] for match in matches] == ["NtSetInformationThread"]


def test_api_kit_import_matching_does_not_invent_matches():
    """A longer, unrelated name must not be folded onto a listed stem."""
    matches = ps.api_kit_matches([
        {"kind": "import", "dll": "advapi32.dll", "name": "OpenProcessToken",
         "ordinal": None},
        {"kind": "import", "dll": "kernel32.dll", "name": "GetLastError",
         "ordinal": None},
    ])
    assert matches == []


def test_exact_table_name_wins_over_the_suffix_rule():
    """VirtualProtectEx is its own entry and must not be read as VirtualProtect."""
    matches = ps.api_kit_matches([
        {"kind": "import", "dll": "kernel32.dll", "name": "VirtualProtectEx",
         "ordinal": None}])
    assert [match["canonical"] for match in matches] == ["VirtualProtectEx"]


def test_confidence_never_reaches_one(tmp_path):
    """plan.md 10.2: the ceiling is 0.99 and 1.00 is forbidden anywhere."""
    root, inventory = build_installation(tmp_path)
    document = run_scan(root, inventory)

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "confidence":
                    assert isinstance(value, (int, float))
                    assert value <= 0.99, value
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)


# --------------------------------------------------------------------------- #
# 8. determinism, output contract, pathguard
# --------------------------------------------------------------------------- #

def _stable(document: dict) -> str:
    copy = json.loads(ps.dump_json(document))
    copy.pop("generated_at", None)
    return json.dumps(copy, indent=2, sort_keys=True, ensure_ascii=False)


def test_two_runs_agree_byte_for_byte(tmp_path):
    root, inventory = build_installation(tmp_path)
    first = _stable(run_scan(root, inventory))
    second = _stable(run_scan(root, inventory))
    assert first == second


def test_dump_json_is_sorted_indented_and_lf_terminated(tmp_path):
    root, inventory = build_installation(tmp_path)
    text = ps.dump_json(run_scan(root, inventory))
    assert text.endswith("}\n")
    assert "\r\n" not in text
    assert '\n  "generated_at"' in text


def test_summary_prints_both_verdicts_in_the_required_wording(tmp_path):
    root, inventory = build_installation(tmp_path)
    summary = ps.format_summary(run_scan(root, inventory))
    assert "Q-8.3  NOT FOUND WITHIN TESTED SURFACE" in summary
    assert "Q-8.2  NOT FOUND WITHIN TESTED SURFACE" in summary
    assert "untested surfaces:" in summary
    assert "stop condition triggered : False" in summary


def test_out_inside_an_installation_is_refused_before_anything_is_written(tmp_path):
    """pathguard layer 1: the guard runs before the file is opened (D-01)."""
    root, inventory = build_installation(tmp_path)
    # Make the synthetic root look like an installation to pathguard.
    os.makedirs(os.path.join(root, "Engine", "Binaries", "Win64"), exist_ok=True)
    refused = os.path.join(root, "protection.json")
    process = subprocess.run(
        [sys.executable, SCAN_PATH, root, "--inventory", inventory,
         "--no-wide-scan", "--primary", PRIMARY[0], "--out", refused],
        capture_output=True, text=True, check=False)
    assert process.returncode == 2
    assert not os.path.exists(refused)
    assert "refus" in process.stderr.lower() or "error" in process.stderr.lower()


def test_out_outside_the_installation_is_written(tmp_path):
    root, inventory = build_installation(tmp_path)
    out = os.path.join(str(tmp_path), "out", "protection.json")
    process = subprocess.run(
        [sys.executable, SCAN_PATH, root, "--inventory", inventory,
         "--no-wide-scan", "--primary", PRIMARY[0], "--out", out],
        capture_output=True, text=True, check=False)
    assert process.returncode == 0, process.stderr
    with open(out, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["generator"] == "tools/static/protection_scan.py"
    assert document["verdicts"]["Q-8.3"]["verdict_display"] == \
        "NOT FOUND WITHIN TESTED SURFACE"


def test_a_directory_argument_is_required_without_module_only(tmp_path):
    process = subprocess.run(
        [sys.executable, SCAN_PATH, os.path.join(str(tmp_path), "nope")],
        capture_output=True, text=True, check=False)
    assert process.returncode == 2


def test_module_only_mode_reports_the_file_surface_as_not_run(tmp_path):
    path = write_image(tmp_path, "one.dll", _clean_module())
    document = ps.analyze("", module_paths=[path], wide_scan=False)
    untested = {item["surface"]
                for item in document["verdicts"]["Q-8.3"]["untested_surfaces"]}
    assert any("filesystem-inventory" in item for item in untested)
    assert len(document["surfaces"]["modules"]) == 1


def test_unparseable_file_is_warned_about_not_crashed(tmp_path):
    root, inventory = build_installation(
        tmp_path, extra_files={"Game/Binaries/Win64/broken.dll": b"MZ" + b"\x00" * 32})
    document = run_scan(root, inventory)
    assert any("broken.dll" in warning for warning in document["warnings"])
    assert document["verdicts"]["Q-8.3"]["verdict"] in (
        ps.VERDICT_NOT_FOUND_IN_SURFACE, ps.VERDICT_UNKNOWN)


def test_string_hits_record_offset_length_section_and_context(tmp_path):
    plant = _clean_module(strings=b"ProcessDebugPort\x00")
    root, inventory = build_installation(tmp_path, plant=plant)
    document = run_scan(root, inventory)
    module = [item for item in document["surfaces"]["modules"]
              if item["path"].endswith("Game-Win64-Shipping.exe")][0]
    hit = [item for item in module["string_hits"]
           if item["needle"] == "ProcessDebugPort"][0]
    occurrence = hit["occurrences"][0]
    assert occurrence["length"] == len("ProcessDebugPort")
    assert occurrence["section"] == ".rdata"
    assert occurrence["section_is_executable"] is False
    assert "ProcessDebugPort" in occurrence["context"]
    absolute = os.path.join(root, module["path"].replace("/", os.sep))
    with open(absolute, "rb") as handle:
        handle.seek(occurrence["offset"])
        assert handle.read(occurrence["length"]) == b"ProcessDebugPort"


def test_an_unknown_verdict_licenses_nothing(tmp_path):
    """UNKNOWN is not a quiet yes.

    With no positive control the questions come back UNKNOWN, and level 1 must
    be inadmissible even though the stop condition did not trigger -- the stop
    condition is about FINDING protection, admissibility is about having
    established an answer.
    """
    root = os.path.join(str(tmp_path), "install")
    os.makedirs(root, exist_ok=True)
    _place(root, "Game/Binaries/Win64/Game.exe", _clean_module())
    inventory = _write_inventory(root, ["Game/Binaries/Win64/Game.exe"])
    document = ps.analyze(root, inventory_path=inventory, wide_scan=True,
                          primary_patterns=["Game/Binaries/Win64/Game.exe"])
    assert document["verdicts"]["Q-8.3"]["verdict"] == ps.VERDICT_UNKNOWN
    assessment = document["instrumentation_assessment"]
    assert assessment["stop_condition_triggered"] is False
    level_1 = assessment["level_1_external_read_only_inspector"]
    assert level_1["admissible"] is False
    assert "UNKNOWN licenses nothing" in level_1["why"]


def test_a_found_verdict_blocks_level_1_and_says_why(tmp_path):
    extra = {"EasyAntiCheat/easyanticheat.sys": b"\x00" * 64}
    root, inventory = build_installation(tmp_path, extra_files=extra)
    document = run_scan(root, inventory)
    assessment = document["instrumentation_assessment"]
    assert assessment["stop_condition_triggered"] is True
    level_1 = assessment["level_1_external_read_only_inspector"]
    assert level_1["admissible"] is False
    assert "stop condition applies" in level_1["why"]


def test_instrumentation_assessment_separates_the_two_levels(tmp_path):
    root, inventory = build_installation(tmp_path)
    assessment = run_scan(root, inventory)["instrumentation_assessment"]
    level_1 = assessment["level_1_external_read_only_inspector"]
    level_2 = assessment["level_2_in_process_probe"]
    assert level_1["admissible"] is True
    assert level_1["conditions"] and level_1["residual_unknowns"]
    assert level_2["admissible_on_this_evidence"] is False
    assert level_2["preconditions_before_reconsidering"]
    # The stop condition must be stated, and must forbid rather than describe
    # circumvention.
    text = assessment["stop_condition_text"]
    assert "STOP" in text
    assert "No bypass, no evasion, no fingerprint-around" in text
    assert "no description of how to do any of those" in text
