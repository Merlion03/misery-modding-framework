#!/usr/bin/env python3
"""Tests for tools/static/extract_strings.py (task S-01).

The tool was written in an earlier run and never executed. That is the reason
this file exists and it shapes what it tests: not "does the summary look
plausible" but "does each documented rule do what the docstring says, on input
whose ground truth is known by construction".

Every image here is SYNTHETIC, assembled byte by byte with the same
``PEBuilder`` as ``tests/test_pe_info.py`` -- imported, not copied, so there is
one definition of "a valid PE" in this suite. No test reads a game file: D-01
makes the installation a read-only research target, and a suite that depends on
it is neither reproducible on another machine nor runnable where the game is
absent. It also could not assert anything: a run over a 134 MB binary cannot
distinguish "this image contains 1.7 million strings" from "this scanner reports
1.7 million of anything".

What is asserted, and why each of these was worth an assertion:

* the minimum-length floor is 4 CHARACTERS in both encodings, and a run one
  character shorter is absent. A floor that silently drifted to 8 would make a
  later xref hunt for ``Link`` come back empty and read as evidence;
* a UTF-16 candidate is accepted at an even offset and REJECTED AND COUNTED at
  an odd one. The count is the tested part: a silent drop is the failure mode;
* offsets and RVAs. Every string is planted at a known offset, and the RVA is
  checked against the section's own arithmetic -- and the round trip through
  ``pe_info.PEHeaders.rva_to_offset``, a different implementation;
* the three ways an offset can have no RVA, kept apart by reason string;
* WINDOWING IS INVISIBLE. The same image scanned with an 8 MiB window and with
  a 17-byte window must produce identical records and identical cross-encoding
  overlap counts. This is the test that a straddling-window bug fails: the
  carried extents are in the previous window's coordinate frame and have to be
  rebased, and nothing in a single-window run can notice if they are not;
* the read of a window plus its lookahead must fit inside one
  ``pe_info.Image.read_at``, which refuses anything over ``MAX_SINGLE_READ``.
  A hard-coded 8 MiB commit asks for 8 MiB + lookahead and dies on the first
  region big enough to need a second window -- which is how the tool failed the
  first time it was ever pointed at a file over 8 MiB;
* the module-extraction rule on the grouped engine trees (``Runtime/Online/HTTP``
  must give HTTP, not Online);
* the file-level enumeration and the named ``--file-query`` lookup, both
  answers, and the wording that bounds an absent one;
* probes P2, P3, P4 and P5 report the numbers they claim to report. P2's
  low-information share and P4's absent-RVA direction were both dead code that
  could never refute anything, so each gets a test that fails if it goes dead
  again;
* the class-P literal layer: claim wording carries offset AND length, names
  nothing about the bytes, and the re-read attestation is only present when the
  re-read happened;
* the pathguard contract on both output paths, and C-13's separation of the
  verbatim JSONL from the publishable summary.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import extract_strings  # noqa: E402
import pe_info  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

TOOL_PATH = os.path.join(REPO_ROOT, "tools", "static", "extract_strings.py")
RDATA_FLAGS = 0x40000040
TEXT_FLAGS = 0x60000020


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def build_image(tmp_path, name: str, rdata: bytes, *, overlay: bytes = b"",
                rdata_vsize: int | None = None,
                text: bytes = b"\xcc" * 32) -> tuple[str, bytes]:
    """A two-section PE32+ whose .rdata holds *rdata* verbatim, plus an overlay.

    The blob is returned as well as the path so a test can compute an expected
    offset from the same bytes the tool will read.
    """
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, text, characteristics=TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000, rdata, characteristics=RDATA_FLAGS,
                        vsize=rdata_vsize)
    blob = builder.build() + overlay
    return write_image(tmp_path, name, blob), blob


def scan(path: str, **kwargs) -> dict:
    """analyze() with the slow, irrelevant passes off unless a test wants them."""
    kwargs.setdefault("want_noise_control", False)
    kwargs.setdefault("want_file_digest", False)
    return extract_strings.analyze(path, **kwargs)


def records_of(path: str, out_path: str, **kwargs) -> list[dict]:
    """Every JSONL record the scan of *path* emits, in emission order."""
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        scan(path, jsonl_handle=handle, **kwargs)
    with open(out_path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def find_record(records: list[dict], text: str, encoding: str) -> dict:
    hits = [r for r in records if r["text"] == text and r["encoding"] == encoding]
    assert len(hits) == 1, ("expected exactly one %s record for %r, got %d"
                            % (encoding, text, len(hits)))
    return hits[0]


def rdata_section(document: dict) -> dict:
    for region in document["tested_surface"]["regions"]:
        if region["name"] == ".rdata":
            return region
    raise AssertionError("no .rdata region in the tested surface")


# --------------------------------------------------------------------------- #
# 1. the two run patterns and the length floor
# --------------------------------------------------------------------------- #

def test_ascii_and_utf16_runs_are_found_at_their_planted_offsets(tmp_path):
    payload = (b"\x00" * 16 + b"HelloWorld\x00"
               + b"\x00" * 5 + utf16("WideString") + b"\x00\x00")
    path, blob = build_image(tmp_path, "runs.exe", payload)
    records = records_of(path, str(tmp_path / "runs.jsonl"))

    narrow = find_record(records, "HelloWorld", "ascii")
    wide = find_record(records, "WideString", "utf-16le")

    assert narrow["offset"] == blob.index(b"HelloWorld")
    assert narrow["length"] == 10 and narrow["char_count"] == 10
    assert narrow["nul_terminated"] is True
    assert wide["offset"] == blob.index(utf16("WideString"))
    # A UTF-16 record's length is in BYTES and its char_count in CODE UNITS.
    # Conflating the two would make every offset arithmetic downstream wrong.
    assert wide["length"] == 20 and wide["char_count"] == 10
    assert wide["nul_terminated"] is True


def test_the_length_floor_is_four_characters_in_both_encodings(tmp_path):
    payload = (b"\x00ABC\x00"          # three ASCII characters: below the floor
               + b"ABCD\x00"           # four: at the floor
               + utf16("XYZ") + b"\x00\x00"
               + utf16("WXYZ") + b"\x00\x00")
    path, _ = build_image(tmp_path, "floor.exe", payload)
    records = records_of(path, str(tmp_path / "floor.jsonl"))
    texts = {(r["text"], r["encoding"]) for r in records}

    assert ("ABCD", "ascii") in texts
    assert ("WXYZ", "utf-16le") in texts
    assert ("ABC", "ascii") not in texts
    assert ("XYZ", "utf-16le") not in texts


def test_min_length_is_a_knob_and_shorter_runs_appear_when_it_is_lowered(tmp_path):
    payload = b"\x00ABC\x00"
    path, _ = build_image(tmp_path, "knob.exe", payload)
    at_four = records_of(path, str(tmp_path / "four.jsonl"), min_length=4)
    at_three = records_of(path, str(tmp_path / "three.jsonl"), min_length=3)

    assert not [r for r in at_four if r["text"] == "ABC"]
    assert [r for r in at_three if r["text"] == "ABC"]


def test_short_runs_are_flagged_as_noise_band_and_never_dropped(tmp_path):
    payload = b"\x00ABCD\x00" + b"\x00" + b"LongEnoughToBeClean\x00"
    path, _ = build_image(tmp_path, "band.exe", payload)
    records = records_of(path, str(tmp_path / "band.jsonl"))

    assert find_record(records, "ABCD", "ascii")["noise_band"] is True
    assert find_record(records, "LongEnoughToBeClean",
                       "ascii")["noise_band"] is False


def test_the_printable_class_excludes_tab_cr_and_lf(tmp_path):
    # A newline inside a text blob must SPLIT the record, not be absorbed: the
    # offset a later xref hunt points at is the offset of the line.
    payload = b"\x00FirstLine\nSecondLine\x00"
    path, _ = build_image(tmp_path, "lines.exe", payload)
    records = records_of(path, str(tmp_path / "lines.jsonl"))
    texts = {r["text"] for r in records if r["encoding"] == "ascii"}

    assert "FirstLine" in texts and "SecondLine" in texts
    assert not [t for t in texts if "\n" in t]


# --------------------------------------------------------------------------- #
# 2. the UTF-16 alignment rule -- decision 2(b)
# --------------------------------------------------------------------------- #

def test_an_odd_aligned_utf16_run_is_rejected_and_counted(tmp_path):
    # The section's raw pointer is file-aligned (0x200), so parity inside the
    # payload is parity in the file. One byte of padding shifts the run to an
    # odd offset; the tool must refuse it AND say that it did.
    aligned = build_image(tmp_path, "even.exe",
                          b"\x00\x00" + utf16("EvenSide") + b"\x00\x00")[0]
    odd = build_image(tmp_path, "odd.exe",
                      b"\x00" + utf16("OddSideXX") + b"\x00\x00")[0]

    even_doc = scan(aligned)
    odd_doc = scan(odd)

    assert even_doc["summary"]["records_utf16"] == 1
    assert even_doc["summary"]["utf16_rejected_odd_alignment"] == 0
    assert odd_doc["summary"]["records_utf16"] == 0
    assert odd_doc["summary"]["utf16_rejected_odd_alignment"] == 1


def test_a_utf16_run_next_to_a_non_ascii_wide_character_is_flagged(tmp_path):
    # The one systematic way this scanner splits a real string: a wide character
    # with a non-zero high byte ends the run. The flag is what tells a reader
    # the record may be half of something.
    payload = b"\x00\x00" + utf16("Left") + b"\x2c\x4e" + utf16("Right") + b"\x00\x00"
    path, _ = build_image(tmp_path, "wide.exe", payload)
    records = records_of(path, str(tmp_path / "wide.jsonl"))

    assert find_record(records, "Left", "utf-16le")["abuts_wide_non_ascii"] is True
    assert find_record(records, "Right", "utf-16le")["abuts_wide_non_ascii"] is True


def test_low_information_is_a_flag_and_not_a_filter(tmp_path):
    payload = (b"\x00\x00" + utf16("1111") + b"\x00\x00"
               + utf16("RealText") + b"\x00\x00")
    path, _ = build_image(tmp_path, "lowinfo.exe", payload)
    records = records_of(path, str(tmp_path / "lowinfo.jsonl"))

    digits = find_record(records, "1111", "utf-16le")
    real = find_record(records, "RealText", "utf-16le")
    assert digits["low_information"] is True      # emitted, with its text
    assert digits["alpha_count"] == 0 and digits["distinct_chars"] == 1
    assert real["low_information"] is False


# --------------------------------------------------------------------------- #
# 3. addresses
# --------------------------------------------------------------------------- #

def test_a_section_offset_gets_the_rva_the_section_arithmetic_gives(tmp_path):
    path, blob = build_image(tmp_path, "rva.exe", b"\x00\x00AddressMe\x00")
    document = scan(path)
    records = records_of(path, str(tmp_path / "rva.jsonl"))
    record = find_record(records, "AddressMe", "ascii")
    region = rdata_section(document)

    expected = region["section_rva"] + (record["offset"]
                                        - blob.index(b"\x00\x00AddressMe") - 2
                                        + 2 - 0)
    # Stated the plain way as well, from the region the record names:
    delta = record["offset"] - next(
        r["start"] for r in document["tested_surface"]["regions"]
        if r["name"] == ".rdata")
    assert record["rva"] == region["section_rva"] + delta
    assert record["rva"] == expected or record["rva"] == region["section_rva"] + delta
    assert record["rva_absent_reason"] is None


def test_a_header_offset_is_identity_mapped(tmp_path):
    # ".rdata" itself lives in the section table, inside SizeOfHeaders, so the
    # header region always has at least one string in it.
    path, _ = build_image(tmp_path, "hdr.exe", b"\x00PlaceHolder\x00")
    records = records_of(path, str(tmp_path / "hdr.jsonl"))
    header_records = [r for r in records if r["region_kind"] == "headers"]

    assert header_records, "no string was found in the header region"
    for record in header_records:
        assert record["rva"] == record["offset"]
        assert record["rva_absent_reason"] is None


def test_an_overlay_offset_has_no_rva_and_says_which_kind_of_nowhere(tmp_path):
    path, _ = build_image(tmp_path, "ovl.exe", b"\x00InSection\x00",
                          overlay=b"\x00InTheOverlay\x00")
    document = scan(path)
    records = records_of(path, str(tmp_path / "ovl.jsonl"))
    record = find_record(records, "InTheOverlay", "ascii")

    assert record["region_kind"] == "overlay"
    assert record["rva"] is None
    assert "overlay" in record["rva_absent_reason"]
    assert find_record(records, "InSection", "ascii")["rva"] is not None
    assert document["summary"]["records_without_rva"] >= 1


def test_a_string_in_a_sections_raw_tail_is_flagged_beyond_virtual_size(tmp_path):
    # VirtualSize smaller than the raw size: the loader may or may not map the
    # tail depending on alignment rounding, so the record says where it is.
    payload = b"\x00Mapped\x00" + b"\x00" * 24 + b"RawTailOnly\x00"
    path, blob = build_image(tmp_path, "tail.exe", payload, rdata_vsize=16)
    records = records_of(path, str(tmp_path / "tail.jsonl"))

    assert find_record(records, "Mapped", "ascii")["beyond_virtual_size"] is False
    assert find_record(records, "RawTailOnly",
                       "ascii")["beyond_virtual_size"] is True


def test_every_reported_rva_round_trips_through_the_pe_parser(tmp_path):
    payload = b"\x00" + b"\x00".join(
        (b"Alpha%02d" % index) for index in range(40)) + b"\x00"
    path, _ = build_image(tmp_path, "trip.exe", payload,
                          overlay=b"\x00OverlayString\x00")
    records = records_of(path, str(tmp_path / "trip.jsonl"))

    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        for record in records:
            if record["rva"] is None:
                continue
            assert headers.rva_to_offset(record["rva"]) == record["offset"]


# --------------------------------------------------------------------------- #
# 4. the region tiling
# --------------------------------------------------------------------------- #

def test_the_regions_tile_the_whole_file_exactly(tmp_path):
    path, blob = build_image(tmp_path, "tile.exe", b"\x00Something\x00",
                             overlay=b"tail bytes here")
    document = scan(path)
    regions = document["tested_surface"]["regions"]

    assert regions[0]["start"] == 0
    assert regions[-1]["end"] == len(blob)
    assert sum(r["length"] for r in regions) == len(blob)
    for left, right in zip(regions, regions[1:]):
        assert left["end"] == right["start"]

    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "P3-region-cover-is-complete")
    assert probe["refuted_the_conclusion"] is False
    assert probe["observed"]["bytes_covered"] == len(blob)


# --------------------------------------------------------------------------- #
# 5. windowing must be invisible -- the straddling-boundary contract
# --------------------------------------------------------------------------- #

# One repeat unit of 14 bytes with a KNOWN cross-encoding overlap in it:
#   "ABCDE" is an ASCII run of 5 at unit+0,
#   and from unit+4 there are five (printable, NUL) pairs, so the UTF-16 run is
#   [unit+4, unit+14) -- the two ranges share exactly the byte at unit+4.
# So N units contain exactly N overlapping pairs, known by construction rather
# than by asking the scanner.
OVERLAP_UNIT = b"ABCDE\x00F\x00G\x00H\x00I\x00"
OVERLAP_UNITS = 24


def test_a_tiny_window_produces_exactly_the_same_records_as_one_big_one(
        tmp_path, monkeypatch):
    payload = OVERLAP_UNIT * OVERLAP_UNITS
    path, _ = build_image(tmp_path, "window.exe", payload)

    whole = records_of(path, str(tmp_path / "whole.jsonl"))

    # 17 bytes is deliberately odd and coprime with the 14-byte unit, so commit
    # boundaries land at every position inside the unit over the payload.
    monkeypatch.setattr(extract_strings, "SCAN_WINDOW", 17)
    monkeypatch.setattr(extract_strings, "LOOKAHEAD", 48)
    windowed = records_of(path, str(tmp_path / "windowed.jsonl"))

    assert [(r["offset"], r["encoding"], r["text"]) for r in whole] \
        == [(r["offset"], r["encoding"], r["text"]) for r in windowed]


def test_the_cross_encoding_overlap_count_is_the_constructed_one_either_way(
        tmp_path, monkeypatch):
    payload = OVERLAP_UNIT * OVERLAP_UNITS
    path, _ = build_image(tmp_path, "overlap.exe", payload)

    whole = scan(path)["summary"]["ranges_claimed_by_both_encodings"]

    monkeypatch.setattr(extract_strings, "SCAN_WINDOW", 17)
    monkeypatch.setattr(extract_strings, "LOOKAHEAD", 48)
    windowed = scan(path)["summary"]["ranges_claimed_by_both_encodings"]

    # Ground truth: one overlapping pair per unit. The windowed run has to agree
    # -- the extents carried across a commit boundary are in the previous
    # window's coordinate frame and must be rebased into the next one. Without
    # the rebase this number drifts, and no single-window run can notice.
    assert whole == OVERLAP_UNITS
    assert windowed == OVERLAP_UNITS


def test_a_continuation_of_an_earlier_window_is_counted_not_silently_dropped(
        tmp_path, monkeypatch):
    payload = b"\x00" * 8 + b"A" * 200 + b"\x00" * 8
    path, _ = build_image(tmp_path, "cont.exe", payload)

    monkeypatch.setattr(extract_strings, "SCAN_WINDOW", 17)
    monkeypatch.setattr(extract_strings, "LOOKAHEAD", 512)
    summary = scan(path)["summary"]

    # The 200-byte run crosses eleven commit boundaries, and each following
    # window sees its tail as a match at buffer position zero. Those are
    # refusals, and a refusal that is not counted is indistinguishable from a
    # scanner that never saw the bytes.
    assert summary["runs_continued_from_a_previous_window"] > 0


def test_the_window_and_its_lookahead_fit_in_one_bounded_read():
    # pe_info.Image.read_at refuses a single read over MAX_SINGLE_READ. The
    # scan asks for SCAN_WINDOW + LOOKAHEAD in one call, so the sum -- not the
    # window alone -- is what has to stay under the limit. It did not, and the
    # tool died on the first region larger than 8 MiB.
    assert extract_strings.SCAN_WINDOW > 0
    assert extract_strings.SCAN_WINDOW + extract_strings.LOOKAHEAD \
        <= pe_info.MAX_SINGLE_READ
    assert extract_strings.LOOKAHEAD > extract_strings.MAX_STRING_BYTES


def test_a_run_spanning_a_commit_boundary_is_reported_once_at_full_length(
        tmp_path, monkeypatch):
    payload = b"\x00" * 8 + b"A" * 200 + b"\x00" * 8
    path, blob = build_image(tmp_path, "span.exe", payload)

    monkeypatch.setattr(extract_strings, "SCAN_WINDOW", 17)
    monkeypatch.setattr(extract_strings, "LOOKAHEAD", 512)
    records = records_of(path, str(tmp_path / "span.jsonl"))
    long_runs = [r for r in records if r["text"] == "A" * 200]

    assert len(long_runs) == 1
    assert long_runs[0]["offset"] == blob.index(b"A" * 200)


# --------------------------------------------------------------------------- #
# 6. classification and module extraction
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text,category", [
    ("/Script/CoreUObject", "unreal-script-path"),
    ("/Game/Maps/Zone_01", "unreal-content-path"),
    ("D:\\build\\++UE5\\Sync\\Engine\\Source\\Runtime\\Core\\Private\\X.cpp",
     "build-source-path"),
    ("TaskGraph.cpp", "source-file-name"),
    ("LogTemp", "unreal-log-category"),
    ("r.Shadow.Quality", "unreal-console-variable"),
    ("UObjectBase", "unreal-type-name"),
    ("KERNEL32.dll", "dll-name"),
    ("Engine/Config/BaseEngine.ini", "ini-or-config-path"),
    ("just some prose", "unclassified"),
])
def test_classification_rules(text, category):
    assert extract_strings.classify_string(text)[0] == category


@pytest.mark.parametrize("path,module", [
    ("D:/build/++UE5/Sync/Engine/Source/Runtime/Core/Private/Async/TaskGraph.cpp",
     "Core"),
    # The two cases the obvious "fourth component" rule gets wrong: these are
    # grouping directories, and taking them would invent modules no .build.cs
    # ever declared.
    ("D:/build/++UE5/Sync/Engine/Source/Runtime/Experimental/Chaos/Private/A.cpp",
     "Chaos"),
    ("D:/build/++UE5/Sync/Engine/Source/Runtime/Online/HTTP/Private/B.cpp",
     "HTTP"),
    ("D:/build/++UE5/Sync/Engine/Plugins/Animation/ACLPlugin/Source/ACLPlugin/"
     "Private/C.cpp", "ACLPlugin"),
    ("D:\\build\\Engine\\Source\\Runtime\\CoreUObject\\Public\\UObject\\Obj.h",
     "CoreUObject"),
])
def test_engine_module_extraction_uses_the_layout_rule(path, module):
    found = extract_strings.extract_engine_module(path)
    assert found is not None and found["module"] == module


def test_a_path_with_no_layout_directory_extracts_no_module():
    assert extract_strings.extract_engine_module("D:/p4/UE5/Main/x/y/z.cpp") is None


# --------------------------------------------------------------------------- #
# 7. the three findings
# --------------------------------------------------------------------------- #

# The leading pad is two bytes, not one, on purpose: the section's raw pointer
# is file-aligned, so the UTF-16 copy would start at an odd file offset behind a
# one-byte pad and the alignment rule would (correctly) refuse it.
SCRIPT_PAYLOAD = (b"\x00\x00/Script/CoreUObject\x00"
                  + utf16("/Script/CoreUObject") + b"\x00\x00"
                  + b"/Script/AsciiOnlyModule\x00")


def test_script_paths_are_split_by_how_many_encodings_saw_them(tmp_path):
    path, _ = build_image(tmp_path, "script.exe", SCRIPT_PAYLOAD)
    finding = scan(path)["findings"]["script_paths"]

    assert finding["names_in_both_encodings"] == ["CoreUObject"]
    assert finding["names_ascii_only"] == ["AsciiOnlyModule"]
    assert sorted(finding["names"]) == ["AsciiOnlyModule", "CoreUObject"]
    assert finding["occurrences_by_name"]["CoreUObject"] == {"ascii": 1, "utf16": 1}
    # A name reached by two acts of measurement may carry 0.85; a name reached
    # by one may not, and the two are graded in separate records.
    assert finding["evidence_both_encodings"]["confidence"] == \
        extract_strings.CONFIDENCE_TWO_METHODS
    assert len(finding["evidence_both_encodings"]["sources"]) == 2
    assert finding["evidence_union"]["confidence"] < 0.80
    assert len(finding["evidence_union"]["sources"]) == 1


def test_a_script_path_reached_through_an_absorbed_prefix_is_not_lost(tmp_path):
    # The artefact this correction exists for, built deliberately: the narrow
    # string's last character plus its NUL terminator read as one (printable,
    # NUL) pair, so the UTF-16 run begins one code unit before the path and an
    # anchored rule would classify the record as unclassified and lose the name.
    payload = (b"\x00\x00X\x00" + utf16("/Script/AbsorbedModule") + b"\x00\x00")
    path, _ = build_image(tmp_path, "absorbed.exe", payload)
    records = records_of(path, str(tmp_path / "absorbed.jsonl"))
    finding = scan(path)["findings"]["script_paths"]

    absorbed = find_record(records, "X/Script/AbsorbedModule", "utf-16le")
    assert absorbed["category"] == "unreal-script-path-absorbed-prefix"
    assert "AbsorbedModule" in finding["names"]
    assert finding["occurrences_reached_through_an_absorbed_prefix"] == 1
    assert finding["names_reached_only_through_an_absorbed_prefix"] == \
        ["AbsorbedModule"]
    # The name's own offset is two bytes past the record's, and the document
    # says so rather than letting a consumer compute it wrongly.
    first = finding["first_occurrence"]["AbsorbedModule"]["utf-16le"]
    assert first["absorbed_prefix_characters"] == 1
    assert first["name_offset"] == absorbed["offset"] + 2


def test_two_independent_methods_are_required_for_the_higher_grade():
    with pytest.raises(ValueError):
        extract_strings.interpretive_annotation(
            "x.exe", 0.85, "note",
            methods=[{"id": "only-one", "oracle": "binary-analysis",
                      "note": "one method"}],
            oracles=["binary-analysis"])


SOURCE_PAYLOAD = (
    b"\x00D:\\build\\++UE5\\Sync\\Engine\\Source\\Runtime\\CoreUObject\\Private"
    b"\\Serialization\\UnversionedPropertySerialization.cpp\x00"
    b"D:\\build\\++UE5\\Sync\\Engine\\Source\\Runtime\\Core\\Private\\Async"
    b"\\TaskGraph.cpp\x00")


def test_source_paths_yield_modules_files_and_a_named_query(tmp_path):
    path, _ = build_image(tmp_path, "source.exe", SOURCE_PAYLOAD)
    finding = scan(path, file_queries=[
        "UnversionedPropertySerialization.cpp", "NotInThisImage.cpp",
    ])["findings"]["engine_source_paths"]

    assert finding["path_literal_count"] == 2
    assert finding["modules"] == ["Core", "CoreUObject"]
    assert finding["build_roots"] == {"D:/build/++UE5/Sync": 2}
    assert finding["engine_trees"] == {"Engine/Source": 2}
    assert finding["distinct_files"] == 2
    assert finding["files"] == ["TaskGraph.cpp",
                               "UnversionedPropertySerialization.cpp"]
    assert finding["files_by_module"]["CoreUObject"] == \
        ["UnversionedPropertySerialization.cpp"]

    present = finding["file_queries"]["UnversionedPropertySerialization.cpp"]
    assert present["present"] is True
    assert present["modules"] == ["CoreUObject"]
    assert present["occurrences"]["UnversionedPropertySerialization.cpp"] == \
        {"ascii": 1, "utf16": 0}

    absent = finding["file_queries"]["NotInThisImage.cpp"]
    assert absent["present"] is False
    assert absent["matched_spellings"] == []
    # An absent answer must carry its own bound, or a later reader will quote it
    # as "the file is not in the build".
    assert "absence is not evidence" in absent["what_an_absent_answer_means"]


def test_a_file_query_is_matched_case_insensitively(tmp_path):
    path, _ = build_image(tmp_path, "case.exe", SOURCE_PAYLOAD)
    finding = scan(path, file_queries=["taskgraph.CPP"])[
        "findings"]["engine_source_paths"]
    answer = finding["file_queries"]["taskgraph.CPP"]

    assert answer["present"] is True
    assert answer["matched_spellings"] == ["TaskGraph.cpp"]


def test_the_module_corroboration_pass_uses_the_local_engine_tree(tmp_path):
    tree = tmp_path / "Engine" / "Source" / "Runtime" / "Core"
    tree.mkdir(parents=True)
    (tree / "Core.Build.cs").write_text("// module rules\n", encoding="utf-8")
    # Both spellings ship in UE 5.4.4; a case-sensitive index loses one of them.
    lower = tmp_path / "Engine" / "Source" / "Runtime" / "MRMesh"
    lower.mkdir(parents=True)
    (lower / "MRMesh.build.cs").write_text("// module rules\n", encoding="utf-8")
    (tmp_path / "Engine" / "Intermediate").mkdir(parents=True)
    (tmp_path / "Engine" / "Intermediate" / "Ghost.Build.cs").write_text(
        "// generated\n", encoding="utf-8")

    warnings: list[str] = []
    index = extract_strings.build_ue_module_index(
        str(tmp_path / "Engine"), warnings)

    assert index["available"] is True
    assert index["modules"]["core"].endswith("Core.Build.cs")
    assert index["modules"]["mrmesh"].endswith("MRMesh.build.cs")
    # Intermediate holds generated rules for other projects built on THIS
    # machine; counting them would make the index a statement about the machine.
    assert "ghost" not in index["modules"]


def test_a_missing_engine_tree_warns_and_does_not_corroborate(tmp_path):
    warnings: list[str] = []
    index = extract_strings.build_ue_module_index(
        str(tmp_path / "absent"), warnings)

    assert index["available"] is False and index["modules"] == {}
    assert warnings and "did not run" in warnings[0]


def test_origin_reports_two_tiers_and_grades_them_apart(tmp_path):
    v07 = tmp_path / "staged-plugins.json"
    v07.write_text(json.dumps({
        "build_key": "sha256:deadbeef",
        "reading": {"plugin_and_project_files": [
            "MISERY/Plugins/AsciiOnlyModule/AsciiOnlyModule.uplugin",
            "Engine/Plugins/Runtime/NeverLinked/NeverLinked.uplugin",
        ]},
    }), encoding="utf-8")
    engine = tmp_path / "Engine" / "Source" / "Runtime" / "CoreUObject"
    engine.mkdir(parents=True)
    (engine / "CoreUObject.Build.cs").write_text("// rules\n", encoding="utf-8")

    path, _ = build_image(tmp_path, "origin.exe", SCRIPT_PAYLOAD)
    document = scan(path, ue_source_root=str(tmp_path / "Engine"),
                    v07_plugins=str(v07))
    origin = document["findings"]["origin"]

    # Corroborated tier: the string scan AND the container index reach it.
    assert "AsciiOnlyModule" in origin["corroborated_game_names"]
    assert origin["evidence_corroborated"]["confidence"] == \
        extract_strings.CONFIDENCE_TWO_METHODS
    assert len(origin["evidence_corroborated"]["sources"]) == 2
    # Heuristic tier: nothing here, and it is graded as a hypothesis regardless.
    assert origin["evidence_heuristic"]["evidence_level"] == "HYPOTHESIS"
    assert origin["evidence_heuristic"]["confidence"] == \
        extract_strings.CONFIDENCE_HEURISTIC
    assert len(origin["evidence_heuristic"]["sources"]) == 1

    agreement = origin["plugin_name_agreement"]
    assert agreement["plugin_names_also_seen_as_script_modules"] == \
        ["AsciiOnlyModule"]
    assert agreement["plugin_names_never_seen_as_a_script_module"] == \
        ["NeverLinked"]
    assert "CoreUObject" in agreement["script_modules_that_are_not_a_plugin_name"]
    # The document must say WHY the two sets differ by construction, or the set
    # arithmetic above reads as a discrepancy rather than as a category error.
    assert "MODULE name" in agreement["why_the_two_sets_differ_by_construction"]


def test_an_unreadable_v07_artifact_warns_instead_of_failing(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    path, _ = build_image(tmp_path, "warn.exe", SCRIPT_PAYLOAD)

    document = scan(path, v07_plugins=str(broken))

    assert document["container_index"]["available"] is False
    assert any("could not be read" in line for line in document["warnings"])


# --------------------------------------------------------------------------- #
# 8. the refutation probes report what they claim to report
# --------------------------------------------------------------------------- #

def test_probe_p2_counts_the_utf16_low_information_share(tmp_path):
    # Three integer-table-shaped runs and one real string: the share is 3/4.
    # This number was dead code -- always zero, so P2 could never refute -- and
    # this test is what fails if it goes dead again.
    payload = (b"\x00\x00" + utf16("1111") + b"\x00\x00"
               + utf16("2222") + b"\x00\x00"
               + utf16("3333") + b"\x00\x00"
               + utf16("RealText") + b"\x00\x00")
    path, _ = build_image(tmp_path, "p2.exe", payload)
    probe = next(p for p in scan(path)["refutation_probes"]
                 if p["id"] == "P2-utf16-is-not-an-integer-table")

    assert probe["observed"]["accepted"] == 4
    assert probe["observed"]["low_information_accepted"] == 3
    assert probe["observed"]["low_information_share"] == 0.75
    assert probe["refuted_the_conclusion"] is True


def test_probe_p4_checks_absent_rvas_in_the_other_direction(tmp_path):
    path, _ = build_image(tmp_path, "p4.exe", b"\x00Mapped\x00",
                          overlay=b"\x00Unmapped\x00")
    probe = next(p for p in scan(path)["refutation_probes"]
                 if p["id"] == "P4-rva-round-trips-through-the-pe-parser")

    assert probe["observed"]["records_with_absent_rva_checked"] >= 1
    assert probe["observed"]["absent_rva_but_mappable"] == []
    assert probe["observed"]["mismatch_count"] == 0
    assert probe["observed"]["spread_sample_records"] >= 1
    assert probe["refuted_the_conclusion"] is False


def test_probe_p4_reports_an_offset_wrongly_called_unaddressable(tmp_path):
    # Force the failure the probe exists to catch: an offset the raw section
    # table does cover, reported with no RVA. If the check were dead this would
    # pass silently, which is what it did.
    path, _ = build_image(tmp_path, "p4bad.exe", b"\x00Mapped\x00")
    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        section = headers.sections[-1]
        sink = extract_strings.StringSink(None, 16)
        sink.add({
            "offset": section["raw_pointer"], "length": 6, "char_count": 6,
            "encoding": "ascii", "rva": None, "rva_absent_reason": "made up",
            "region": ".rdata", "region_kind": "section", "region_index": 1,
            "section": ".rdata", "noise_band": False, "nul_terminated": True,
            "clipped": False, "abuts_wide_non_ascii": False,
            "category": "unclassified", "category_rule": "none",
            "text": "Mapped", "alpha_count": 6, "digit_count": 0,
            "other_count": 0, "distinct_chars": 5, "low_information": False,
        })
        result = extract_strings.probe_rva_round_trip(headers, sink, 16)

    assert result["absent_rva_but_mappable_count"] == 1
    assert result["absent_rva_but_mappable"][0]["raw_range_owner"] == ".rdata"


def test_probe_p5_reports_the_overlap_and_the_populations(tmp_path):
    path, _ = build_image(tmp_path, "p5.exe", OVERLAP_UNIT * 4)
    probe = next(p for p in scan(path)["refutation_probes"]
                 if p["id"] == "P5-cross-encoding-double-count")

    assert probe["observed"]["overlapping_pairs"] == 4
    assert probe["observed"]["utf16_records"] == 4
    assert probe["observed"]["overlap_over_utf16"] == 1.0
    # This payload is pathological by construction -- every UTF-16 run shares a
    # byte with an ASCII run -- so the probe SHOULD refute here. A probe that
    # said "did not refute" on input built to trip it would be worthless.
    assert probe["refuted_the_conclusion"] is True


def test_the_noise_control_is_deterministic_and_bounded():
    first = extract_strings.noise_control(4, 1 << 18, 1 << 20)
    second = extract_strings.noise_control(4, 1 << 18, 1 << 20)

    assert first["ran"] is True
    assert first["control_bytes"] == 1 << 18
    assert first["histogram"] == second["histogram"]
    assert first["expected_at_target_size"] == second["expected_at_target_size"]
    # UTF-16 runs are not uniform-random noise -- that is the stated reason the
    # UTF-16 noise band is empty, so the control had better agree.
    assert first["histogram"]["utf-16le"] == {}

    huge = extract_strings.noise_control(
        4, extract_strings.MAX_NOISE_CONTROL_BYTES * 4, 1 << 20)
    assert huge["control_bytes"] == extract_strings.MAX_NOISE_CONTROL_BYTES


def test_probe_p1_names_the_noise_dominated_lengths_when_the_control_runs(tmp_path):
    path, _ = build_image(tmp_path, "p1.exe", b"\x00SomeString\x00",
                          text=bytes(range(0x20, 0x80)) * 4)
    document = scan(path, want_noise_control=True,
                    noise_control_bytes=1 << 18)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "P1-low-length-noise-floor")

    assert probe["observed"]["control_ran"] is True
    assert probe["observed"]["expected_by_length_from_random_control"]
    assert document["noise_control"]["extrapolation_is_linear_and_is_a_lower_bound"]


# --------------------------------------------------------------------------- #
# 9. the class-P literal layer
# --------------------------------------------------------------------------- #

def test_literal_reads_state_offset_and_length_and_nothing_about_the_bytes(tmp_path):
    path, _ = build_image(tmp_path, "lit.exe", SCRIPT_PAYLOAD)
    document = scan(path, literal_samples=4)
    literals = document["literal_reads"]

    assert 1 <= len(literals) <= 4
    for read in literals:
        claim = read["evidence"]["note"]
        assert read["evidence"]["claim_class"] == "P"
        assert read["evidence"]["confidence"] == extract_strings.CONFIDENCE_LITERAL
        assert read["evidence"]["oracle"] == ["binary-analysis"]
        assert ("%d" % read["offset"]) in claim
        assert ("%d bytes" % read["length"]) in claim or read["length"] == 1
        # Class P for binary-analysis dies the moment the claim names what the
        # bytes ARE. The interpretation lives in the other layer, by join key.
        for forbidden in ("string", "package path", "module", "structure",
                          "signature", "vtable"):
            assert forbidden not in claim.lower()
        assert read["join_key"].startswith("strings.jsonl@offset=")


def test_the_rerun_attestation_is_only_written_after_the_reread_happened(tmp_path):
    path, _ = build_image(tmp_path, "rerun.exe", b"\x00Reproduce\x00")
    literal = extract_strings.literal_read("x.exe", "k", 0, b"\x01\x02")

    assert "PENDING" in literal["evidence"]["sources"][0]["note"]
    assert "reproduced" not in literal["evidence"]["note"]

    document = scan(path, literal_samples=2)
    for read in document["literal_reads"]:
        assert read["reproduced"] is True
        assert extract_strings.RERUN_CONFIRMED in read["evidence"]["note"]
        assert "PENDING" not in read["evidence"]["sources"][0]["note"]


def test_a_failed_reread_is_recorded_as_unreproduced(tmp_path):
    path, _ = build_image(tmp_path, "fail.exe", b"\x00Reproduce\x00")
    literal = extract_strings.literal_read("fail.exe", "k", 0, b"\xde\xad\xbe\xef")
    warnings: list[str] = []

    reproduced = extract_strings.confirm_literal_reads(
        path, [literal], "fail.exe", warnings)

    assert reproduced is False
    assert literal["reproduced"] is False
    assert extract_strings.RERUN_NOT_CONFIRMED in literal["evidence"]["note"]
    assert warnings and "did NOT reproduce" in warnings[0]


# --------------------------------------------------------------------------- #
# 10. determinism, the JSONL, and the output-path contract
# --------------------------------------------------------------------------- #

def test_two_runs_differ_only_in_the_timestamp_and_the_timings(tmp_path):
    path, _ = build_image(tmp_path, "det.exe", SCRIPT_PAYLOAD + SOURCE_PAYLOAD)
    first = scan(path)
    second = scan(path)

    for document in (first, second):
        document.pop("generated_at")
        document.pop("timings_seconds")
    assert extract_strings.dump_json(first) == extract_strings.dump_json(second)


def test_records_are_emitted_in_ascending_offset_order(tmp_path):
    path, _ = build_image(tmp_path, "order.exe",
                          SCRIPT_PAYLOAD + SOURCE_PAYLOAD + OVERLAP_UNIT * 8,
                          overlay=b"\x00OverlayText\x00")
    records = records_of(path, str(tmp_path / "order.jsonl"))
    keys = [(r["offset"], extract_strings.ENCODING_ORDER[r["encoding"]])
            for r in records]

    assert keys == sorted(keys)
    assert len(records) == len(set((r["offset"], r["encoding"]) for r in records))


def test_the_jsonl_holds_one_record_per_string_and_the_summary_only_counts(
        tmp_path):
    path, _ = build_image(tmp_path, "split.exe", SCRIPT_PAYLOAD)
    jsonl = str(tmp_path / "split.jsonl")
    records = records_of(path, jsonl)
    document = scan(path)

    assert document["summary"]["records_total"] == len(records)
    # C-13: the verbatim table is the separate file. The summary carries counts,
    # the classified names its findings argue from, and a bounded class-P
    # sample -- not the table.
    assert "text" not in json.dumps(document["summary"])


def test_the_d04_oracle_is_stamped_on_the_document(tmp_path):
    oracle = tmp_path / "MISERY" / "Binaries" / "Win64"
    oracle.mkdir(parents=True)
    path, _ = build_image(oracle, "MISERY.exe", b"\x00Oracle\x00")
    shipping, _ = build_image(oracle, "MISERY-Win64-Shipping.exe",
                              b"\x00Shipping\x00")

    assert scan(path)["d04_oracle_only"] is True
    assert scan(shipping)["d04_oracle_only"] is False


def test_a_non_pe_input_is_refused_with_exit_2(tmp_path):
    junk = tmp_path / "not-a-pe.bin"
    junk.write_bytes(b"this is not a PE image" * 8)
    result = subprocess.run(
        [sys.executable, TOOL_PATH, str(junk)],
        capture_output=True, text=True)

    assert result.returncode == 2
    assert "error:" in result.stderr


def test_a_missing_input_is_refused_with_exit_2(tmp_path):
    result = subprocess.run(
        [sys.executable, TOOL_PATH, str(tmp_path / "absent.exe")],
        capture_output=True, text=True)

    assert result.returncode == 2
    assert "not a file" in result.stderr


def test_an_output_path_inside_an_installation_is_refused_before_anything_opens(
        tmp_path):
    install = tmp_path / "install"
    (install / "Engine" / "Binaries" / "Win64").mkdir(parents=True)
    (install / "MISERY" / "Content" / "Paks").mkdir(parents=True)
    path, _ = build_image(tmp_path, "guard.exe", b"\x00Guarded\x00")
    refused = install / "MISERY" / "summary.json"

    result = subprocess.run(
        [sys.executable, TOOL_PATH, path, "--out", str(refused),
         "--install-dir", str(install), "--no-noise-control", "--no-digest"],
        capture_output=True, text=True)

    assert result.returncode == 2
    assert not refused.exists()


def test_the_cli_prints_a_summary_and_the_c13_reminder(tmp_path):
    path, _ = build_image(tmp_path, "cli.exe", SCRIPT_PAYLOAD + SOURCE_PAYLOAD)
    out = tmp_path / "out.json"
    jsonl = tmp_path / "out.jsonl"

    result = subprocess.run(
        [sys.executable, TOOL_PATH, path, "--out", str(out),
         "--jsonl-out", str(jsonl), "--no-noise-control", "--no-digest",
         "--file-query", "TaskGraph.cpp"],
        capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert out.exists() and jsonl.exists()
    assert "C-13" in result.stdout
    assert "query TaskGraph.cpp" in result.stdout
    assert "PRESENT" in result.stdout
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["task"] == "S-01"
    assert document["generator"] == "tools/static/extract_strings.py"


def test_the_json_document_is_lf_sorted_and_newline_terminated(tmp_path):
    path, _ = build_image(tmp_path, "shape.exe", b"\x00Shape\x00")
    text = extract_strings.dump_json(scan(path))

    assert text.endswith("\n")
    assert "\r\n" not in text
    reparsed = json.loads(text)
    assert list(reparsed) == sorted(reparsed)
