#!/usr/bin/env python3
"""Tests for tools/static/sigscan.py (task S-07).

Every input is a SYNTHETIC PE image assembled byte by byte, built with the same
``PEBuilder`` as ``tests/test_pe_info.py`` -- imported, not copied -- so a test
knows the exact byte it planted at the exact offset it planted it. No test reads
a game file: D-01 makes the installation a read-only research target, and a
suite that depended on it would be neither reproducible elsewhere nor runnable
where the game is absent.

The matcher is the part of this repository with the most leverage per line: a
signature that silently matches twice, or that is reported once when it occurs
twice, corrupts every finding built on top of it. So the emphasis here is on the
counting rules rather than on the reporting:

  * the pattern grammar, including every form it must REFUSE
  * the derived quality numbers (anchor, distinct values, masked fraction)
  * the de-duplication rule across buffer boundaries, driven at buffer sizes
    down to ``pattern length + 1``, which is the smallest the matcher allows
  * overlapping occurrences, which must all be found
  * a match that STRADDLES a buffer boundary, found exactly once
  * matches must not be found across a surface-range boundary
  * the three verdicts and the fourth state (count truncation)
  * surface construction and clamping
  * the class-P literal layer and its re-read attestation
  * the refutation probes, including the one that would have caught the
    label-join defect this file was written alongside
  * determinism and the pathguard contract on both output paths
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import pe_info  # noqa: E402
import sigscan  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

SIGSCAN_PATH = os.path.join(REPO_ROOT, "tools", "static", "sigscan.py")

TEXT_RVA = 0x1000
EXEC_CHARACTERISTICS = 0x60000020    # CNT_CODE | MEM_EXECUTE | MEM_READ
DATA_CHARACTERISTICS = 0x40000040    # CNT_INITIALIZED_DATA | MEM_READ


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _exec_image(tmp_path, name: str, text: bytes, *, extra: bytes = b"") -> str:
    """A PE whose ``.text`` holds exactly *text*, plus an optional data section."""
    builder = PEBuilder()
    builder.add_section(".text", TEXT_RVA, text,
                        characteristics=EXEC_CHARACTERISTICS)
    if extra:
        builder.add_section(".rdata", TEXT_RVA + 0x10000, extra,
                            characteristics=DATA_CHARACTERISTICS)
    return write_image(tmp_path, name, builder.build())


def _surface_of(path: str, kind: str = sigscan.SURFACE_EXEC) -> dict:
    image = pe_info.Image.open(path)
    try:
        headers = pe_info.PEHeaders(image)
        return sigscan.build_surface(headers, kind, None, image.size, [])
    finally:
        image.close()


def _count(path: str, pattern_text: str, *, kind: str = sigscan.SURFACE_EXEC,
           chunk_size: int = sigscan.SCAN_CHUNK, count_cap: int = 4096) -> tuple:
    surface = _surface_of(path, kind)
    pattern = sigscan.parse_pattern(pattern_text, label="p")
    got = sigscan.scan_surface(path, surface, [pattern], hit_limit=64,
                               count_cap=count_cap, chunk_size=chunk_size)[0]
    return got.count, list(got.offsets), got.truncated


# --------------------------------------------------------------------------- #
# the pattern grammar
# --------------------------------------------------------------------------- #

def test_pattern_parses_literals_and_wildcards():
    pattern = sigscan.parse_pattern("48 89 5C 24 ?? 57 ?")
    assert pattern.length == 7
    assert pattern.mask == bytes([1, 1, 1, 1, 0, 1, 0])
    assert pattern.values == bytes([0x48, 0x89, 0x5C, 0x24, 0, 0x57, 0])
    assert pattern.literal_bytes == 5
    assert pattern.masked_bytes == 2
    assert pattern.text == "48 89 5C 24 ?? 57 ??"


def test_pattern_is_case_insensitive_and_accepts_commas():
    assert (sigscan.parse_pattern("48,89,5c,24").text
            == sigscan.parse_pattern("48 89 5C 24").text)


def test_nibble_wildcard_is_refused_with_the_reason_named():
    for token in ("4?", "?8"):
        with pytest.raises(sigscan.PatternError) as info:
            sigscan.parse_pattern("48 89 %s 24" % token)
        message = str(info.value)
        assert "NIBBLE" in message
        assert "decoder" in message


def test_pattern_refuses_empty_and_junk_and_overlong():
    with pytest.raises(sigscan.PatternError):
        sigscan.parse_pattern("")
    with pytest.raises(sigscan.PatternError):
        sigscan.parse_pattern("48 ZZ")
    with pytest.raises(sigscan.PatternError):
        sigscan.parse_pattern("489")
    with pytest.raises(sigscan.PatternError):
        sigscan.parse_pattern(" ".join(["90"] * (sigscan.MAX_PATTERN_BYTES + 1)))
    with pytest.raises(sigscan.PatternError):
        sigscan.parse_pattern(b"48 89")


def test_wildcard_positions_are_normalised_so_one_signature_hashes_one_way():
    left = sigscan.Pattern(bytes([0x48, 0xFF, 0x57]), bytes([1, 0, 1]))
    right = sigscan.Pattern(bytes([0x48, 0x11, 0x57]), bytes([1, 0, 1]))
    assert left.values == right.values
    assert (left.facts()["sha256_of_pattern_text"]
            == right.facts()["sha256_of_pattern_text"])


def test_anchor_is_the_longest_literal_run_and_ties_go_left():
    pattern = sigscan.parse_pattern("11 22 ?? 33 44 55 ?? 66 77")
    assert (pattern.anchor_offset, pattern.anchor_length) == (3, 3)
    assert pattern.anchor == bytes([0x33, 0x44, 0x55])
    tie = sigscan.parse_pattern("11 22 ?? 33 44")
    assert tie.anchor_offset == 0


def test_distinct_literal_values_counts_only_literal_positions():
    assert sigscan.parse_pattern("CC CC CC CC").distinct_literal_values == 1
    assert sigscan.parse_pattern("CC ?? CC 90").distinct_literal_values == 2


def test_masked_fraction_and_all_wildcard_has_no_anchor():
    blank = sigscan.parse_pattern("?? ?? ?? ??")
    assert blank.masked_fraction == 1.0
    assert blank.anchor_length == 0
    assert blank.anchor == b""


def test_pattern_rejects_mismatched_values_and_mask():
    with pytest.raises(sigscan.PatternError):
        sigscan.Pattern(b"\x01\x02", b"\x01")
    with pytest.raises(sigscan.PatternError):
        sigscan.Pattern(b"", b"")


# --------------------------------------------------------------------------- #
# the matcher: counting rules
# --------------------------------------------------------------------------- #

def test_a_unique_pattern_is_found_once_at_the_planted_offset(tmp_path):
    text = b"\x90" * 100 + bytes.fromhex("4889745210574883EC20") + b"\x90" * 100
    path = _exec_image(tmp_path, "one.exe", text)
    surface = _surface_of(path)
    base = surface["ranges"][0]["file_offset"]
    count, offsets, truncated = _count(path, "48 89 74 52 10 57 48 83 EC 20")
    assert (count, truncated) == (1, False)
    assert offsets == [base + 100]


def test_wildcards_match_any_byte_at_that_position(tmp_path):
    body = bytes.fromhex("4889745210574883EC20")
    text = b"\x90" * 40 + body + b"\x90" * 40
    path = _exec_image(tmp_path, "wild.exe", text)
    assert _count(path, "48 89 74 ?? 10 57 48 83 EC 20")[0] == 1
    # the same pattern with the wildcard made literal-but-wrong finds nothing
    assert _count(path, "48 89 74 FF 10 57 48 83 EC 20")[0] == 0


def test_two_occurrences_are_both_counted(tmp_path):
    body = bytes.fromhex("4889745210574883EC20")
    text = b"\x90" * 30 + body + b"\x90" * 30 + body + b"\x90" * 30
    path = _exec_image(tmp_path, "two.exe", text)
    surface = _surface_of(path)
    base = surface["ranges"][0]["file_offset"]
    count, offsets, _ = _count(path, "48 89 74 52 10 57 48 83 EC 20")
    assert count == 2
    assert offsets == [base + 30, base + 30 + len(body) + 30]


def test_overlapping_occurrences_are_all_found(tmp_path):
    # "AA AA AA" occurs at 0, 1, 2 and 3 inside six AA bytes.
    text = b"\x90" * 8 + b"\xaa" * 6 + b"\x90" * 8
    path = _exec_image(tmp_path, "overlap.exe", text)
    surface = _surface_of(path)
    base = surface["ranges"][0]["file_offset"]
    count, offsets, _ = _count(path, "AA AA AA")
    assert count == 4
    assert offsets == [base + 8 + i for i in range(4)]


@pytest.mark.parametrize("chunk_size", [4, 5, 8, 16, 64, 1024, 1 << 20])
def test_counts_are_invariant_under_buffer_size(tmp_path, chunk_size):
    """The de-duplication rule, driven at every buffer size down to length+1.

    This is the single most important test in the file. The overlap between two
    buffers is ``max pattern length - 1`` bytes, and a match starting inside the
    overlap is deliberately deferred to the next buffer. If that bookkeeping is
    wrong the count doubles for every match near a boundary -- which turns a
    unique signature into an ambiguous one, silently.
    """
    body = bytes.fromhex("DEADBEEF")
    # 21 copies at irregular spacing, so some copy lands astride every boundary
    # any of the parametrised buffer sizes can produce.
    text = bytearray()
    for index in range(21):
        text.extend(b"\x90" * (index % 7 + 1))
        text.extend(body)
    path = _exec_image(tmp_path, "invariant.exe", bytes(text))
    count, offsets, truncated = _count(path, "DE AD BE EF", chunk_size=chunk_size)
    assert not truncated
    assert count == 21, "buffer size %d changed the count" % chunk_size
    assert offsets == sorted(offsets)
    assert len(set(offsets)) == len(offsets)


def test_a_match_straddling_a_buffer_boundary_is_found_exactly_once(tmp_path):
    """The boundary case built by hand, so the failure names itself.

    With a 16-byte buffer the first buffer covers file offsets [B, B+16) and the
    pattern is planted so that it begins at B+14 and ends at B+18 -- inside the
    first buffer's overlap and wholly inside the second buffer.
    """
    text = b"\x90" * 14 + bytes.fromhex("11223344") + b"\x90" * 30
    path = _exec_image(tmp_path, "straddle.exe", text)
    surface = _surface_of(path)
    base = surface["ranges"][0]["file_offset"]
    for chunk_size in (5, 6, 7, 12, 16, 17, 18):
        count, offsets, _ = _count(path, "11 22 33 44", chunk_size=chunk_size)
        assert count == 1, "chunk_size %d" % chunk_size
        assert offsets == [base + 14]


def test_no_match_is_reported_across_a_surface_range_boundary(tmp_path):
    """Two sections are two ranges, and a pattern may not span the gap.

    Half the pattern at the end of one section and half at the start of the next
    must not count: the bytes are not contiguous in the address space the
    signature is about, and a matcher that stitched ranges would invent hits.
    """
    builder = PEBuilder()
    builder.add_section(".text", TEXT_RVA, b"\x90" * 60 + b"\x11\x22",
                        characteristics=EXEC_CHARACTERISTICS)
    builder.add_section(".text2", TEXT_RVA + 0x10000, b"\x33\x44" + b"\x90" * 60,
                        characteristics=EXEC_CHARACTERISTICS)
    path = write_image(tmp_path, "split.exe", builder.build())
    surface = _surface_of(path)
    assert surface["range_count"] == 2
    assert _count(path, "11 22 33 44")[0] == 0
    # each half is still findable inside its own range
    assert _count(path, "90 90 11 22")[0] == 1
    assert _count(path, "33 44 90 90")[0] == 1


def test_pattern_longer_than_the_range_finds_nothing(tmp_path):
    path = _exec_image(tmp_path, "tiny.exe", b"\x11\x22\x33")
    assert _count(path, " ".join(["11"] * 600), chunk_size=64)[0] == 0


# --------------------------------------------------------------------------- #
# verdicts and the fourth state
# --------------------------------------------------------------------------- #

def test_verdict_of_maps_counts_to_the_three_names():
    pattern = sigscan.parse_pattern("11 22")

    def collector(count, truncated=False):
        got = sigscan.HitCollector(pattern, 4, 4096)
        got.count = count
        got.truncated = truncated
        return got

    assert sigscan.verdict_of(collector(0)) == sigscan.VERDICT_ABSENT
    assert sigscan.verdict_of(collector(1)) == sigscan.VERDICT_UNIQUE
    assert sigscan.verdict_of(collector(2)) == sigscan.VERDICT_AMBIGUOUS
    assert sigscan.verdict_of(collector(9)) == sigscan.VERDICT_AMBIGUOUS
    # truncation outranks the count: "at least the cap" is never unique
    assert sigscan.verdict_of(collector(1, True)) == sigscan.VERDICT_AMBIGUOUS


def test_count_cap_truncates_and_says_so(tmp_path):
    path = _exec_image(tmp_path, "many.exe", b"\xaa" * 500)
    count, _, truncated = _count(path, "AA AA AA", count_cap=10)
    assert truncated is True
    assert count == 10


def test_hit_limit_bounds_recorded_addresses_without_bounding_the_count():
    pattern = sigscan.parse_pattern("11 22")
    got = sigscan.HitCollector(pattern, hit_limit=2, count_cap=100)
    for offset in range(5):
        got.add(offset)
    assert got.count == 5
    assert got.offsets == [0, 1]
    assert got.truncated is False


# --------------------------------------------------------------------------- #
# surface construction
# --------------------------------------------------------------------------- #

def test_exec_surface_excludes_a_data_section(tmp_path):
    body = bytes.fromhex("CAFEBABE")
    path = _exec_image(tmp_path, "surf.exe", b"\x90" * 20, extra=b"\x90" * 20 + body)
    assert _count(path, "CA FE BA BE", kind=sigscan.SURFACE_EXEC)[0] == 0
    assert _count(path, "CA FE BA BE", kind=sigscan.SURFACE_INITIALIZED)[0] == 1
    assert _count(path, "CA FE BA BE", kind=sigscan.SURFACE_ALL)[0] == 1


def test_surface_publishes_its_ranges_and_what_it_did_not_search(tmp_path):
    path = _exec_image(tmp_path, "pub.exe", b"\x90" * 32, extra=b"\x00" * 16)
    surface = _surface_of(path)
    assert surface["kind"] == sigscan.SURFACE_EXEC
    assert [r["name"] for r in surface["ranges"]] == [".text"]
    assert surface["ranges"][0]["rva"] == TEXT_RVA
    assert surface["bytes_searched"] == surface["ranges"][0]["length"]
    assert "resources" in surface["not_searched"]


def test_surface_clamps_a_section_that_claims_more_than_the_file_holds(tmp_path):
    builder = PEBuilder()
    builder.add_section(".text", TEXT_RVA, b"\x90" * 64,
                        characteristics=EXEC_CHARACTERISTICS,
                        raw_size_override=1 << 20)
    path = write_image(tmp_path, "overclaim.exe", builder.build())
    image = pe_info.Image.open(path)
    try:
        headers = pe_info.PEHeaders(image)
        warnings: list[str] = []
        surface = sigscan.build_surface(headers, sigscan.SURFACE_EXEC, None,
                                        image.size, warnings)
        assert surface["bytes_searched"] <= image.size
        assert any("only" in w and "on disk" in w for w in warnings)
    finally:
        image.close()


def test_section_restriction_warns_when_the_name_is_absent(tmp_path):
    path = _exec_image(tmp_path, "restrict.exe", b"\x90" * 32)
    image = pe_info.Image.open(path)
    try:
        headers = pe_info.PEHeaders(image)
        warnings: list[str] = []
        surface = sigscan.build_surface(headers, sigscan.SURFACE_EXEC,
                                        ("nosuch",), image.size, warnings)
        assert surface["range_count"] == 0
        assert any("nosuch" in w for w in warnings)
    finally:
        image.close()


def test_non_pe_target_falls_back_to_the_flat_surface(tmp_path):
    path = os.path.join(str(tmp_path), "notpe.bin")
    with open(path, "wb") as handle:
        handle.write(b"\x11\x22\x33\x44" * 8)
    surface = sigscan.build_surface(None, sigscan.SURFACE_EXEC, None, 32, [])
    assert surface["kind"] == sigscan.SURFACE_ALL
    assert surface["ranges"][0]["rva"] is None


# --------------------------------------------------------------------------- #
# the library reader
# --------------------------------------------------------------------------- #

def test_load_library_reads_a_sigmake_document_and_skips_rejected(tmp_path):
    path = os.path.join(str(tmp_path), "lib.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"signatures": [
            {"label": "good", "pattern": "11 22 33", "accepted": True,
             "source_rva": 0x1000},
            {"label": "bad", "pattern": "44 55 66", "accepted": False,
             "rejections": [{"code": "not_unique"}]},
        ]}, handle)
    rows, provenance, notes = sigscan.load_library(path, include_rejected=False)
    assert [r["label"] for r in rows] == ["good"]
    assert provenance["format"] == "sigmake document"
    rows, _, _ = sigscan.load_library(path, include_rejected=True)
    assert [r["label"] for r in rows] == ["good", "bad"]
    assert rows[1]["rejections"][0]["code"] == "not_unique"
    assert notes == []


def test_load_library_accepts_a_bare_list_and_notes_unusable_rows(tmp_path):
    path = os.path.join(str(tmp_path), "bare.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([{"label": "a", "pattern": "11 22"}, {"label": "b"}, 7], handle)
    rows, provenance, notes = sigscan.load_library(path, include_rejected=False)
    assert [r["label"] for r in rows] == ["a"]
    assert provenance["format"] == "bare list"
    assert len(notes) == 2


def test_load_library_refuses_a_document_that_is_neither_shape(tmp_path):
    path = os.path.join(str(tmp_path), "wrong.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"nothing": "here"}, handle)
    with pytest.raises(ValueError):
        sigscan.load_library(path, include_rejected=False)


# --------------------------------------------------------------------------- #
# the assembled document
# --------------------------------------------------------------------------- #

def _analyze(path, patterns, **kwargs):
    rows = [{"label": label, "pattern": text, "accepted_in_library": True,
             "source_rva": rva, "source_file_offset": None, "rejections": []}
            for label, text, rva in patterns]
    return sigscan.analyze(path, rows, **kwargs)


def test_document_reports_one_unique_one_ambiguous_one_absent(tmp_path):
    body = bytes.fromhex("11223344")
    twice = bytes.fromhex("55667788")
    text = (b"\x90" * 16 + body + b"\x90" * 16 + twice + b"\x90" * 16
            + twice + b"\x90" * 16)
    path = _exec_image(tmp_path, "doc.exe", text)
    document = _analyze(path, [("u", "11 22 33 44", None),
                               ("a", "55 66 77 88", None),
                               ("z", "AB CD EF 01", None)])
    verdicts = {r["label"]: r["verdict"] for r in document["signatures"]}
    assert verdicts == {"u": "unique", "a": "ambiguous", "z": "absent"}
    assert document["summary"]["unique"] == 1
    assert document["summary"]["ambiguous"] == 1
    assert document["summary"]["absent"] == 1
    assert document["task"] == "S-07"
    # the document must serialise; a bytes object left in it would raise here
    json.loads(sigscan.dump_json(document))


def test_meaning_is_present_on_every_record_and_distinguishes_the_cases():
    same = sigscan._meaning("absent", True, None, False)
    other = sigscan._meaning("absent", False, None, False)
    assert "defect in this tool pair" in same
    assert "DESIGNED failure direction" in other
    assert "coin toss" in sigscan._meaning("ambiguous", True, None, False)
    assert "not a signature of anything" in sigscan._meaning("unique", True,
                                                             True, True)
    wrong_place = sigscan._meaning("unique", True, False, False)
    assert "do not use this signature" in wrong_place


def test_found_at_source_rva_is_checked_when_the_image_is_the_source(tmp_path):
    body = bytes.fromhex("11223344")
    text = b"\x90" * 16 + body + b"\x90" * 16
    path = _exec_image(tmp_path, "src.exe", text)
    digest = sigscan._file_digest(path, os.path.getsize(path))
    provenance = {"source_image": {"sha256": digest}}
    document = _analyze(path, [("right", "11 22 33 44", TEXT_RVA + 16),
                               ("wrong", "11 22 33 44", TEXT_RVA + 999)],
                        library_provenance=provenance)
    by_label = {r["label"]: r for r in document["signatures"]}
    assert document["summary"]["same_image_as_signature_source"] is True
    assert by_label["right"]["found_at_source_rva"] is True
    assert by_label["wrong"]["found_at_source_rva"] is False


def test_a_different_image_is_detected_by_digest_and_warned_about(tmp_path):
    path = _exec_image(tmp_path, "target.exe", b"\x90" * 64)
    provenance = {"source_image": {"sha256": "0" * 64}}
    document = _analyze(path, [("p", "90 90 90 90", None)],
                        library_provenance=provenance)
    assert document["summary"]["same_image_as_signature_source"] is False
    assert any("NOT the image the signatures were cut from" in w
               for w in document["warnings"])
    # and the interpretive annotation drops to the single-method confidence
    assert (document["interpreted_annotation"]["confidence"]
            == sigscan.CONFIDENCE_INTERPRETED_SINGLE_METHOD)
    assert len(document["interpreted_annotation"]["sources"]) == 1


def test_unparseable_signature_is_reported_and_does_not_stop_the_scan(tmp_path):
    path = _exec_image(tmp_path, "mixed.exe", b"\x90" * 64)
    document = _analyze(path, [("ok", "90 90 90 90", None),
                               ("bad", "9? 90", None)])
    assert document["summary"]["signatures_unparseable"] == 1
    assert [r["label"] for r in document["unparseable"]] == ["bad"]
    assert [r["label"] for r in document["signatures"]] == ["ok"]


# --------------------------------------------------------------------------- #
# the class-P layer
# --------------------------------------------------------------------------- #

def test_literal_read_is_class_p_and_names_nothing_about_the_bytes():
    record = sigscan.literal_read("some/file.exe", "join", 4096, b"\x11\x22\x33")
    assert record["evidence"]["claim_class"] == "P"
    assert record["evidence"]["evidence_level"] == "OBSERVED"
    assert record["evidence"]["oracle"] == ["binary-analysis"]
    assert record["evidence"]["confidence"] <= 0.99
    claim = record["claim"]
    # plan.md 10.3 v2.4: a class-P binary-analysis claim must state the offset
    # AND the length, and must not name what the bytes are.
    assert "4096" in claim and "3 bytes" in claim
    for forbidden in ("signature", "pattern", "function", "match", "vtable"):
        assert forbidden not in claim.lower()
    # the join key lives OUTSIDE the graded object
    assert "join_key" not in record["evidence"]
    assert record["join_key"] == "join"


def test_literal_reads_carry_a_reread_attestation(tmp_path):
    body = bytes.fromhex("11223344")
    path = _exec_image(tmp_path, "lit.exe", b"\x90" * 16 + body + b"\x90" * 16)
    document = _analyze(path, [("p", "11 22 33 44", None)])
    assert document["literal_reads"]
    for read in document["literal_reads"]:
        assert read["reproduced"] is True
        assert sigscan.RERUN_CONFIRMED in read["evidence"]["sources"][0]["note"]
        assert read["evidence"]["note"].endswith(sigscan.RERUN_CONFIRMED)


def test_attestation_records_a_failure_rather_than_hiding_it(tmp_path):
    path = _exec_image(tmp_path, "gone.exe", b"\x90" * 32)
    reads = [sigscan.literal_read("x", "j", 0, b"\xff\xff")]
    warnings: list[str] = []
    ok = sigscan.confirm_literal_reads(path, reads, "x", warnings)
    assert ok is False
    assert reads[0]["reproduced"] is False
    assert sigscan.RERUN_NOT_CONFIRMED in reads[0]["evidence"]["sources"][0]["note"]
    assert warnings and "did NOT reproduce" in warnings[0]


def test_interpreted_annotation_is_class_i_and_needs_two_methods_for_085():
    corroborated = sigscan.scan_annotation("x", same_image=True)
    assert corroborated["claim_class"] == "I"
    assert corroborated["evidence_level"] == "INFERRED"
    assert corroborated["confidence"] == sigscan.CONFIDENCE_INTERPRETED_CORROBORATED
    assert corroborated["confidence"] >= 0.80
    methods = {s["method"] for s in corroborated["sources"]}
    assert methods == {"S-07", "S-06"}
    alone = sigscan.scan_annotation("x", same_image=False)
    assert alone["confidence"] < 0.80


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def test_all_probes_run_and_none_is_refuted_on_a_sane_image(tmp_path):
    """No probe fires on a surface with the properties a real code surface has.

    "Sane" here has to include the property the short-prefix probe tests for: a
    four-byte prefix must be AMBIGUOUS, as it is in tens of megabytes of real
    x86-64. So the prefix is planted a further nine times with different tails,
    which leaves the full twelve-byte pattern unique and the prefix common --
    the shape the probe expects to see.
    """
    body = bytes.fromhex("1122334455667788AABBCCDD")
    decoys = bytearray()
    for index in range(9):
        decoys.extend(b"\x91" * (index + 3))
        decoys.extend(body[:4])
        decoys.extend(bytes([0xE0 + index]) * 8)
    text = b"\x90" * 64 + body + bytes(decoys) + b"\x91" * 4096
    path = _exec_image(tmp_path, "probes.exe", text)
    document = _analyze(path, [("p", sigscan.format_pattern(body, b"\x01" * 12),
                                None)], probe_window=256)
    ids = {p["id"] for p in document["refutation_probes"]}
    assert ids == {"all-wildcard-control", "one-byte-flip-control",
                   "short-prefix-control", "buffer-size-invariance",
                   "unique-verdict-population"}
    for probe in document["refutation_probes"]:
        assert probe["refuted"] is False, probe["id"]


def test_all_wildcard_control_finds_one_hit_per_position(tmp_path):
    path = _exec_image(tmp_path, "blank.exe", b"\x90" * 4096)
    document = _analyze(path, [("p", " ".join(["90"] * 12), None)],
                        probe_window=256)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "all-wildcard-control")
    assert probe["occurrences"] == probe["occurrences_expected"]
    assert probe["occurrences"] == 256 - 11


def test_buffer_size_invariance_probe_joins_on_the_label_not_the_index(tmp_path):
    """The regression test for the defect this probe itself was blind to.

    ``analyze`` sorts ``results`` by label before the probes run, while the
    re-scan returns collectors in PATTERN order. A probe that joined the two by
    list index compared one signature's count against another's and reported
    disagreements that were an artefact of the sort. The labels below are chosen
    so that alphabetical order and pattern order disagree, and the occurrence
    counts differ between the two signatures -- which is exactly the shape that
    made the old code report a false disagreement.
    """
    once = bytes.fromhex("11223344")
    twice = bytes.fromhex("55667788")
    text = (b"\x90" * 16 + once + b"\x90" * 16 + twice + b"\x90" * 16
            + twice + b"\x90" * 16)
    path = _exec_image(tmp_path, "join.exe", text)
    # "z_once" sorts AFTER "a_twice", but is supplied first.
    document = _analyze(path, [("z_once", "11 22 33 44", None),
                               ("a_twice", "55 66 77 88", None)],
                        probe_window=256)
    assert [r["label"] for r in document["signatures"]] == ["a_twice", "z_once"]
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "buffer-size-invariance")
    assert probe["disagreements"] == []
    assert probe["refuted"] is False


def test_short_prefix_control_is_refuted_when_the_surface_is_tiny(tmp_path):
    """A probe that can never fire is decoration; this shows it fires.

    On a 200-byte surface a four-byte prefix really is unique, so the probe
    must report itself REFUTED rather than pass silently.
    """
    body = bytes.fromhex("1122334455667788AABBCCDD")
    path = _exec_image(tmp_path, "small.exe", b"\x90" * 32 + body + b"\x90" * 32)
    document = _analyze(path, [("p", sigscan.format_pattern(body, b"\x01" * 12),
                                None)], probe_window=64)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "short-prefix-control")
    assert probe["refuted"] is True
    assert probe["not_ambiguous"][0]["label"] == "p"


# --------------------------------------------------------------------------- #
# determinism, artifacts and the CLI contract
# --------------------------------------------------------------------------- #

def test_two_runs_differ_only_in_the_timestamp_and_the_timings(tmp_path):
    path = _exec_image(tmp_path, "det.exe", b"\x90" * 64 + b"\x11\x22\x33\x44")
    first = _analyze(path, [("p", "11 22 33 44", None)], want_probes=False)
    second = _analyze(path, [("p", "11 22 33 44", None)], want_probes=False)
    for document in (first, second):
        document.pop("generated_at")
        document.pop("timings_seconds")
    assert sigscan.dump_json(first) == sigscan.dump_json(second)


def test_dump_json_is_sorted_lf_and_newline_terminated(tmp_path):
    path = _exec_image(tmp_path, "fmt.exe", b"\x90" * 64)
    text = sigscan.dump_json(_analyze(path, [("p", "90 90 90 90", None)],
                                      want_probes=False))
    assert text.endswith("\n")
    assert "\r" not in text
    assert '"generated_at"' in text


def test_jsonl_is_one_object_per_signature(tmp_path):
    body = bytes.fromhex("11223344")
    path = _exec_image(tmp_path, "jl.exe", b"\x90" * 16 + body + b"\x90" * 16)
    document = _analyze(path, [("p", "11 22 33 44", None)], want_probes=False)
    lines = sigscan.jsonl_lines(document)
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["verdict"] == "unique"
    assert row["label"] == "p"
    assert row["surface_kind"] == sigscan.SURFACE_EXEC


def _run_cli(args):
    return subprocess.run([sys.executable, SIGSCAN_PATH] + args,
                          capture_output=True, text=True)


def test_cli_scans_an_inline_pattern_and_exits_zero(tmp_path):
    body = bytes.fromhex("11223344")
    path = _exec_image(tmp_path, "cli.exe", b"\x90" * 16 + body + b"\x90" * 16)
    done = _run_cli([path, "--pattern", "11 22 33 44", "--no-probes", "--json"])
    assert done.returncode == 0, done.stderr
    document = json.loads(done.stdout)
    assert document["summary"]["unique"] == 1


def test_cli_require_unique_exits_one_when_a_signature_is_not_unique(tmp_path):
    path = _exec_image(tmp_path, "req.exe", b"\x90" * 64)
    done = _run_cli([path, "--pattern", "AB CD EF 01", "--no-probes",
                     "--require-unique"])
    assert done.returncode == 1


def test_cli_refuses_a_nibble_wildcard_with_a_reason(tmp_path):
    path = _exec_image(tmp_path, "nib.exe", b"\x90" * 64)
    done = _run_cli([path, "--pattern", "4? 89", "--no-probes", "--json"])
    # the pattern is unparseable, which is reported in the document rather than
    # crashing the run
    assert done.returncode == 0
    document = json.loads(done.stdout)
    assert document["summary"]["signatures_unparseable"] == 1
    assert "NIBBLE" in document["unparseable"][0]["reason"]


def test_cli_refuses_duplicate_labels(tmp_path):
    path = _exec_image(tmp_path, "dup.exe", b"\x90" * 64)
    done = _run_cli([path, "--pattern", "11 22", "--label", "same",
                     "--pattern", "33 44", "--label", "same", "--no-probes"])
    assert done.returncode == 2
    assert "duplicate signature label" in done.stderr


def test_cli_refuses_nothing_to_search_for(tmp_path):
    path = _exec_image(tmp_path, "none.exe", b"\x90" * 64)
    done = _run_cli([path, "--no-probes"])
    assert done.returncode == 2
    assert "nothing to search for" in done.stderr


def test_cli_refuses_a_count_cap_of_zero(tmp_path):
    path = _exec_image(tmp_path, "cap.exe", b"\x90" * 64)
    done = _run_cli([path, "--pattern", "90 90", "--count-cap", "0"])
    assert done.returncode == 2


def test_out_inside_an_installation_is_refused(tmp_path):
    """D-01 layer 1: the output guard is imported, and it binds here too."""
    install = os.path.join(str(tmp_path), "install")
    os.makedirs(os.path.join(install, "Engine", "Binaries", "Win64"))
    with open(os.path.join(install, "Engine", "Binaries", "Win64", "x.exe"),
              "wb") as handle:
        handle.write(b"\x00")
    path = _exec_image(tmp_path, "guard.exe", b"\x90" * 64)
    done = _run_cli([path, "--pattern", "90 90 90 90", "--no-probes",
                     "--install-dir", install,
                     "--out", os.path.join(install, "out.json")])
    assert done.returncode == 2
    assert not os.path.exists(os.path.join(install, "out.json"))


def test_out_and_jsonl_out_are_written_where_permitted(tmp_path):
    body = bytes.fromhex("11223344")
    path = _exec_image(tmp_path, "w.exe", b"\x90" * 16 + body + b"\x90" * 16)
    out = os.path.join(str(tmp_path), "sub", "scan.json")
    jsonl = os.path.join(str(tmp_path), "sub", "scan.jsonl")
    done = _run_cli([path, "--pattern", "11 22 33 44", "--no-probes",
                     "--out", out, "--jsonl-out", jsonl])
    assert done.returncode == 0, done.stderr
    with open(out, encoding="utf-8") as handle:
        assert json.load(handle)["summary"]["unique"] == 1
    with open(jsonl, encoding="utf-8") as handle:
        assert len(handle.read().strip().splitlines()) == 1
