#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/static/tu_literals.py (CK-01 binary-side bound).

Standard library only, and **no test here opens the game installation**. Every
image is assembled byte by byte with the same ``PEBuilder`` as
``tests/test_pe_info.py`` -- imported, not copied, so there is one definition of
what a PE looks like in this suite.

What has to be tested, and why each item is here
------------------------------------------------
The document this tool produces is used to argue that an ABSENCE means nothing:
``research/modkit/ck-01.md`` leans on ``power.p_present_given_no_fatal`` to say
that ``UnversionedPropertySerialization.cpp`` not appearing in the Shipping
image is exactly what a fully linked translation unit looks like. An argument
shaped like that fails in two directions, and both are tested:

  * the matcher must FIND what is there ......... test_ascii_literal_is_found,
                                                 test_utf16_literal_is_found,
                                                 test_plugin_path_anchors_on_the_last_source
  * the matcher must NOT find what is not ...... test_decoy_probe_passes,
                                                 test_absent_path_reports_absent
  * the counts must add up, or the measured
    power is wrong by an unknown amount ........ test_run_accounting_adds_up,
                                                 test_unclassified_run_is_counted,
                                                 test_corpus_partition_sums
  * the power measurement must MOVE with the
    corpus, not sit at a constant .............. test_power_reflects_the_corpus,
                                                 test_power_contingency_cells
  * the probes must be able to FAIL ............ test_two_build_roots_fail_the_probe
  * a run straddling a scan-slice boundary must
    be found exactly once ...................... test_slice_boundary_run_found_once
  * class P must stay class P ................... test_literal_reads_state_offset_and_length
  * the output guard must refuse ................ test_out_path_inside_install_refused

The slice test matters more than its size suggests. The scanner reads the image
in overlapping windows, and a run that touches a window edge is deliberately
dropped so the neighbouring window can report it. Get that wrong in one
direction and every count is inflated by duplicates; wrong in the other and
literals near a 32 MiB boundary vanish silently. The test drives the window size
down to a few kilobytes and puts a literal across the seam.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "static"),
              os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory"),
              os.path.dirname(os.path.abspath(__file__))):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pathguard  # noqa: E402
import tu_literals  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

BUILD_ROOT = "D:/build/++UE5/Sync/"
OTHER_ROOT = "F:/Elsewhere/Projects/thing/"

CK01_RELATIVE = ("Runtime/CoreUObject/Private/Serialization/"
                 "UnversionedPropertySerialization.cpp")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def rdata_blob(*items: bytes, pad: int = 8) -> bytes:
    """Concatenate literals separated by NUL runs, as a compiler would.

    The separator matters: the scanner expands a run to the nearest
    non-printable byte, so two adjacent literals with no NUL between them are
    one run by construction. That is a real property of the format and the tool
    documents it; here the NULs keep each literal its own run.
    """
    out = bytearray()
    for item in items:
        out += item
        out += b"\x00" * pad
    return bytes(out)


def _full(relative: str, root: str) -> str:
    """Spell a literal the way MSVC does: build root, module root, Source, rest.

    A relative that already names its own ``Source`` directory -- a plugin tree
    -- is taken as written; anything else is an engine path and gets the
    ``Engine/Source`` head that the real literals carry.
    """
    if "/Source/" in relative:
        return root + relative
    return root + "Engine/Source/" + relative


def ascii_path(relative: str, root: str = BUILD_ROOT) -> bytes:
    return _full(relative, root).replace("/", "\\").encode("ascii")


def utf16_path(relative: str, root: str = BUILD_ROOT) -> bytes:
    return _full(relative, root).replace("/", "\\").encode("utf-16-le")


def image_with(tmp_path, blob: bytes, name: str = "synthetic.exe") -> str:
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xc3" * 0x200)
    builder.add_section(".rdata", 0x2000, blob, characteristics=0x40000040)
    return write_image(tmp_path, name, builder.build())


def analyze(path: str, **kwargs) -> dict:
    return tu_literals.analyze(path, **kwargs)


def make_source_tree(root: str, files: dict[str, str]) -> str:
    """Create ``<root>/Engine/Source/...`` and return the Engine/Source path.

    ``files`` maps a path relative to ``Engine/Source`` to file contents, so a
    test can decide independently whether a translation unit carries a
    fatal-error construct and whether its path is in the image.
    """
    source_root = os.path.join(root, "Engine", "Source")
    for relative, text in files.items():
        target = os.path.join(source_root, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return source_root


# --------------------------------------------------------------------------- #
# the matcher finds what is there
# --------------------------------------------------------------------------- #

def test_ascii_literal_is_found(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path, queries=[CK01_RELATIVE])
    result = document["queries"][0]
    assert result["found"] is True
    assert result["match_count"] == 1
    match = result["matches"][0]
    assert match["encodings"] == ["ascii"]
    assert match["relative_path"] == "Engine/Source/" + CK01_RELATIVE
    with open(path, "rb") as handle:
        handle.seek(match["first_offset"])
        raw = handle.read(len(ascii_path(CK01_RELATIVE)))
    assert raw == ascii_path(CK01_RELATIVE)


def test_utf16_literal_is_found(tmp_path):
    path = image_with(tmp_path, rdata_blob(utf16_path(CK01_RELATIVE)))
    document = analyze(path, queries=[CK01_RELATIVE])
    result = document["queries"][0]
    assert result["found"] is True
    assert result["matches"][0]["encodings"] == ["utf-16le"]


def test_both_encodings_of_one_path_are_one_record(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE),
                                          utf16_path(CK01_RELATIVE)))
    document = analyze(path, queries=[CK01_RELATIVE])
    match = document["queries"][0]["matches"][0]
    assert match["occurrence_count"] == 2
    assert match["encodings"] == ["ascii", "utf-16le"]


def test_odd_aligned_utf16_is_rejected_and_counted(tmp_path):
    """A wide run that is not 2-byte aligned is the tail of something else."""
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xc3" * 0x200)
    # One filler byte inside the section shifts the wide literal onto an odd
    # file offset: .rdata's raw pointer is file-aligned, hence even.
    blob = b"\x00" + utf16_path(CK01_RELATIVE) + b"\x00" * 8
    builder.add_section(".rdata", 0x2000, blob)
    path = write_image(tmp_path, "odd.exe", builder.build())
    document = analyze(path, queries=[CK01_RELATIVE])
    assert document["queries"][0]["found"] is False
    assert document["scan_surface"]["utf16_parity_rejected"] >= 1


def test_plugin_path_anchors_on_the_last_source(tmp_path):
    literal = ascii_path("Engine/Plugins/Runtime/Widget/Source/Wid/Thing.cpp")
    path = image_with(tmp_path, rdata_blob(literal))
    document = analyze(path, queries=["Wid/Thing.cpp"])
    assert document["queries"][0]["found"] is True
    assert (document["queries"][0]["matches"][0]["relative_path"]
            == "Widget/Source/Wid/Thing.cpp")


def test_query_is_case_and_separator_insensitive(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path, queries=[
        CK01_RELATIVE.replace("/", "\\").upper()])
    assert document["queries"][0]["found"] is True


# --------------------------------------------------------------------------- #
# the matcher does not find what is not there
# --------------------------------------------------------------------------- #

def test_absent_path_reports_absent(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path("Runtime/Core/Private/X.cpp")))
    document = analyze(path, queries=[CK01_RELATIVE])
    assert document["queries"][0]["found"] is False
    assert document["queries"][0]["matches"] == []


def test_decoy_probe_passes(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path)
    assert document["probes"]["decoy_query"]["passed"] is True
    assert document["probes"]["decoy_query"]["found"] is False


def test_roundtrip_probe_passes(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path)
    assert document["probes"]["roundtrip_query"]["passed"] is True


def test_a_short_run_is_not_promoted_to_a_path(tmp_path):
    """``\\Source\\x.h`` is shorter than MIN_RUN_BYTES and must not count."""
    path = image_with(tmp_path, rdata_blob(b"\\Source\\x.h"))
    document = analyze(path)
    assert document["source_path_literals"]["distinct_relative_paths"] == 0


# --------------------------------------------------------------------------- #
# the counts add up
# --------------------------------------------------------------------------- #

def test_run_accounting_adds_up(tmp_path):
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        ascii_path("Runtime/Core/Private/HAL/MallocBinned2.cpp"),
        ascii_path("Runtime/Core/Private/Misc/Notes.txt"),
        utf16_path("Runtime/Core/Private/Misc/Paths.cpp")))
    document = analyze(path)
    accounting = document["probes"]["run_accounting"]
    assert accounting["passed"] is True
    assert (accounting["classified_as_source_paths"]
            + accounting["unclassified_runs"] == accounting["runs_found"])


def test_unclassified_run_is_counted(tmp_path):
    """A run with the marker but no source extension is counted, not dropped."""
    path = image_with(tmp_path, rdata_blob(
        ascii_path("Runtime/Core/Private/Misc/Notes.txt")))
    document = analyze(path)
    assert document["source_path_literals"]["distinct_relative_paths"] == 0
    assert document["probes"]["run_accounting"]["unclassified_runs"] == 1
    assert document["probes"]["run_accounting"]["passed"] is True


def test_every_hit_is_attributed_to_a_section(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path)
    hit = document["source_path_literals"]["sections_hit"]
    assert sum(hit.values()) == document["source_path_literals"]["total_occurrences"]
    assert ".rdata" in hit


# --------------------------------------------------------------------------- #
# the probes can fail
# --------------------------------------------------------------------------- #

def test_two_build_roots_fail_the_probe(tmp_path):
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        ascii_path("Runtime/Game/Private/Thing.cpp", root=OTHER_ROOT)))
    document = analyze(path)
    probe = document["probes"]["prefix_census"]
    assert probe["distinct_drive_roots"] == 2
    assert probe["passed"] is False


def test_one_build_root_passes_the_probe(tmp_path):
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        ascii_path("Runtime/Core/Private/Misc/Paths.cpp")))
    document = analyze(path)
    assert document["probes"]["prefix_census"]["passed"] is True


def test_drive_roots_fold_a_deeper_prefix(tmp_path):
    """A plugin path pushes the raw prefix deeper; the fold must undo that."""
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        ascii_path("Engine/Plugins/FX/Niagara/Source/Nia/Sim.cpp")))
    document = analyze(path)
    literals = document["source_path_literals"]
    assert len(literals["prefixes"]) == 2
    assert list(literals["drive_roots"]) == ["D:/build/"]


# --------------------------------------------------------------------------- #
# slice boundaries
# --------------------------------------------------------------------------- #

def _rdata_raw_pointer(path: str) -> int:
    import pe_info
    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        for section in headers.sections:
            if section["name"] == ".rdata":
                return section["raw_pointer"]
    raise AssertionError(".rdata not found in the synthetic image")


def _straddling_image(tmp_path, name: str) -> tuple[str, int]:
    """An image whose only source-path literal crosses a chosen seam.

    Returns the image path and the seam offset. The seam is derived from the
    real layout rather than guessed, because ``.rdata`` does not begin at a
    round number and a guessed seam silently stops straddling anything.
    """
    literal = ascii_path(CK01_RELATIVE)
    filler = bytes(6000)
    probe = image_with(tmp_path, filler, name="layout-" + name)
    rdata_start = _rdata_raw_pointer(probe)
    offset_in_rdata = 2000
    seam = rdata_start + offset_in_rdata + len(literal) // 2
    assert 0 < offset_in_rdata < len(filler) - len(literal), (
        "the synthetic layout must actually straddle the seam")
    blob = bytearray(filler)
    blob[offset_in_rdata:offset_in_rdata + len(literal)] = literal
    # Same builder shape as the probe, so the layout the seam was computed from
    # is the layout the literal actually lands in.
    built = image_with(tmp_path, bytes(blob), name=name)
    assert _rdata_raw_pointer(built) == rdata_start, (
        "the probe image and the real one must have the same layout")
    assert rdata_start + offset_in_rdata < seam < (
        rdata_start + offset_in_rdata + len(literal)), (
        "the seam must fall strictly inside the literal")
    return built, seam


def test_slice_boundary_run_found_once(tmp_path, monkeypatch):
    straddling, seam = _straddling_image(tmp_path, "straddle.exe")
    monkeypatch.setattr(tu_literals, "SLICE_BYTES", seam)
    monkeypatch.setattr(tu_literals, "SLICE_OVERLAP", 600)
    document = analyze(straddling, queries=[CK01_RELATIVE])
    result = document["queries"][0]
    assert result["found"] is True, "a literal across a slice seam was lost"
    assert result["matches"][0]["occurrence_count"] == 1, (
        "a literal across a slice seam was counted twice")
    assert document["scan_surface"]["slices"] > 1
    assert document["probes"]["run_accounting"]["passed"] is True


def test_slice_boundary_result_matches_a_single_slice_scan(tmp_path, monkeypatch):
    """The seam must not change the answer, only the way it was reached."""
    straddling, seam = _straddling_image(tmp_path, "straddle-cmp.exe")
    monkeypatch.setattr(tu_literals, "SLICE_BYTES", seam)
    monkeypatch.setattr(tu_literals, "SLICE_OVERLAP", 600)
    sliced = analyze(straddling, queries=[CK01_RELATIVE])
    monkeypatch.setattr(tu_literals, "SLICE_BYTES", 1 << 20)
    whole = analyze(straddling, queries=[CK01_RELATIVE])
    assert whole["scan_surface"]["slices"] == 1
    assert (sliced["queries"][0]["matches"]
            == whole["queries"][0]["matches"])


# --------------------------------------------------------------------------- #
# the power measurement
# --------------------------------------------------------------------------- #

FATAL_SOURCE = ('#include "X.h"\nvoid f() { LowLevelFatalError(TEXT("no")); }\n')
QUIET_SOURCE = '#include "X.h"\nvoid f() { return; }\n'
CHECKED_SOURCE = '#include "X.h"\nvoid f() { check(true); }\n'


def test_power_is_none_without_source_root(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path)
    assert document["power"] is None
    assert any("power of the presence test was NOT measured" in warning
               for warning in document["warnings"])


def test_corpus_partition_sums(tmp_path):
    source_root = make_source_tree(str(tmp_path / "ue"), {
        "Runtime/Core/Private/Misc/Paths.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Unix/UnixThing.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Misc/PathsTest.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Misc/Quiet.cpp": QUIET_SOURCE,
    })
    path = image_with(tmp_path, rdata_blob(
        ascii_path("Runtime/Core/Private/Misc/Paths.cpp")))
    document = analyze(path, source_root=source_root,
                       corpus=["Runtime/Core/Private"])
    power = document["power"]
    assert power["cpp_total"] == 4
    assert power["platform_excluded"] == 1
    assert power["test_excluded"] == 1
    assert power["candidates"] == 2
    assert power["probe_corpus_partition"]["buckets_sum_to_file_count"] is True


def test_power_reflects_the_corpus(tmp_path):
    """P must move with the image, not sit at a constant."""
    files = {
        "Runtime/Core/Private/Misc/A.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Misc/B.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Misc/C.cpp": QUIET_SOURCE,
        "Runtime/Core/Private/Misc/D.cpp": QUIET_SOURCE,
    }
    source_root = make_source_tree(str(tmp_path / "ue"), files)
    none_present = image_with(tmp_path, rdata_blob(b"\x00" * 32), name="none.exe")
    doc_none = analyze(none_present, source_root=source_root,
                       corpus=["Runtime/Core/Private"])
    assert doc_none["power"]["candidates_with_literal"] == 0
    assert doc_none["power"]["p_present_overall"] == 0.0

    two_present = image_with(tmp_path, rdata_blob(
        ascii_path("Runtime/Core/Private/Misc/A.cpp"),
        ascii_path("Runtime/Core/Private/Misc/B.cpp")), name="two.exe")
    doc_two = analyze(two_present, source_root=source_root,
                      corpus=["Runtime/Core/Private"])
    assert doc_two["power"]["candidates_with_literal"] == 2
    assert doc_two["power"]["p_present_overall"] == 0.5


def test_power_contingency_cells(tmp_path):
    """The fatal-family split is the one the CK-01 argument leans on."""
    source_root = make_source_tree(str(tmp_path / "ue"), {
        "Runtime/Core/Private/Misc/Loud.cpp": FATAL_SOURCE,
        "Runtime/Core/Private/Misc/Quiet.cpp": QUIET_SOURCE,
        "Runtime/Core/Private/Misc/Checked.cpp": CHECKED_SOURCE,
    })
    path = image_with(tmp_path, rdata_blob(
        ascii_path("Runtime/Core/Private/Misc/Loud.cpp")))
    power = analyze(path, source_root=source_root,
                    corpus=["Runtime/Core/Private"])["power"]
    fatal = power["contingency_fatal_family"]
    assert fatal["fatal_present"] == 1
    assert fatal["fatal_absent"] == 0
    assert fatal["nofatal_present"] == 0
    assert fatal["nofatal_absent"] == 2
    assert power["p_present_given_fatal"] == 1.0
    assert power["p_present_given_no_fatal"] == 0.0
    check = power["contingency_check_family"]
    assert check["check_present"] == 0
    assert check["check_absent"] == 1
    assert check["nocheck_present"] == 1


def test_missing_corpus_root_warns_and_does_not_invent_numbers(tmp_path):
    source_root = make_source_tree(str(tmp_path / "ue"), {
        "Runtime/Core/Private/Misc/A.cpp": FATAL_SOURCE})
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path, source_root=source_root,
                       corpus=["Runtime/Core/Private", "Runtime/NotThere"])
    assert document["power"]["roots_missing"] == 1
    assert document["power"]["cpp_total"] == 1
    assert any("is not a directory" in warning
               for warning in document["warnings"])


# --------------------------------------------------------------------------- #
# class P stays class P
# --------------------------------------------------------------------------- #

def test_literal_reads_state_offset_and_length(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path, queries=[CK01_RELATIVE])
    assert document["literal_reads"], "a found query must yield a literal read"
    for read in document["literal_reads"]:
        claim = read["claim"]
        assert str(read["offset"]) in claim
        assert str(read["length"]) in claim
        assert read["evidence"]["claim_class"] == "P"
        assert read["evidence"]["oracle"] == ["binary-analysis"]
        assert read["evidence"]["note"].startswith(claim)
        lowered = claim.lower()
        for forbidden in ("structure", "field", "path literal", "__file__",
                          "translation unit", "signature", "layout"):
            assert forbidden not in lowered, (
                "a class-P claim must not name what the bytes are: %r" % claim)


def test_literal_read_is_reproduced(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    document = analyze(path, queries=[CK01_RELATIVE])
    for read in document["literal_reads"]:
        assert read["reproduced"] is True
        note = read["evidence"]["sources"][0]["note"]
        assert "PENDING" not in note
        assert "gave the same bytes" in note


def test_no_literal_read_when_nothing_was_found(tmp_path):
    path = image_with(tmp_path, rdata_blob(b"\x00" * 32))
    document = analyze(path, queries=[CK01_RELATIVE])
    assert document["literal_reads"] == []


# --------------------------------------------------------------------------- #
# CLI and the output guard
# --------------------------------------------------------------------------- #

def test_out_path_inside_install_refused(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    install = pathguard.CONFIGURED_INSTALL_ROOTS[0]
    refused = os.path.join(install, "tu-literals.json")
    code = tu_literals.main([path, "--out", refused, "--install-dir", install])
    assert code == 2
    assert not os.path.exists(refused)


def test_cli_writes_json_and_paths(tmp_path):
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        ascii_path("Runtime/Core/Private/Misc/Paths.cpp")))
    out_json = str(tmp_path / "out.json")
    out_paths = str(tmp_path / "out.txt")
    code = tu_literals.main([path, "--json", "--out", out_json,
                             "--paths-out", out_paths])
    assert code == 0
    document = json.load(open(out_json, encoding="utf-8"))
    assert document["file"]["size"] == os.path.getsize(path)
    assert "_paths" not in document, "the internal path map must stay internal"
    text = open(out_paths, encoding="utf-8").read()
    assert CK01_RELATIVE in text
    assert "Runtime/Core/Private/Misc/Paths.cpp" in text


def test_cli_rejects_a_missing_source_root(tmp_path):
    path = image_with(tmp_path, rdata_blob(ascii_path(CK01_RELATIVE)))
    code = tu_literals.main([path, "--ue-source-root",
                             str(tmp_path / "definitely-not-here")])
    assert code == 2


def test_cli_on_a_non_pe_fails_cleanly(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pe at all" * 8)
    assert tu_literals.main([str(junk)]) == 2


def test_two_runs_agree_apart_from_time(tmp_path):
    path = image_with(tmp_path, rdata_blob(
        ascii_path(CK01_RELATIVE),
        utf16_path("Runtime/Core/Private/Misc/Paths.cpp")))
    first = analyze(path)
    second = analyze(path)
    for document in (first, second):
        document.pop("generated_at")
        document.pop("timings_seconds")
    assert first == second


@pytest.mark.parametrize("extension", [".cpp", ".h", ".inl", ".hpp"])
def test_accepted_extensions(tmp_path, extension):
    relative = "Runtime/Core/Private/Misc/Widget" + extension
    path = image_with(tmp_path, rdata_blob(ascii_path(relative)),
                      name="ext%s.exe" % extension.strip("."))
    document = analyze(path, queries=[relative])
    assert document["queries"][0]["found"] is True
