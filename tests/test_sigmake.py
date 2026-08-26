#!/usr/bin/env python3
"""Tests for tools/static/sigmake.py (task S-06).

Synthetic PE images throughout, built with the ``PEBuilder`` of
``tests/test_pe_info.py`` -- imported, not copied. No test reads a game file
(D-01), and every ``.pdata`` row, every ``.reloc`` entry and every byte of every
function body here was written by the test that asserts on it, so a failure
names the field rather than merely going red.

What this tool has to get right, in order of how much damage getting it wrong
would do:

  1. it must REFUSE what it cannot justify. A signature emitted for a range that
     is not a function, or one that matches twice, or one that is mostly holes,
     is worse than no signature at all. Every rejection code has a test that
     makes it fire, and a test that it fires for the right reason.
  2. it must publish the pattern whose uniqueness was actually CHECKED. The
     ladder builds several candidates; emitting a different rung than the one
     that was counted would attach a verified verdict to an unverified pattern.
  3. it must not confuse a ``RUNTIME_FUNCTION`` range with a function. Chained
     records, shared unwind info, adjacent ranges and missing records each get a
     test, and the census counts each one.
  4. the mask must contain only what an oracle PROVES moves. The relocation
     component is exact and is tested against a hand-built ``.reloc``; the rel32
     component is a heuristic and must be labelled as one on every record.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import pe_info  # noqa: E402
import sigmake  # noqa: E402
import sigscan  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

SIGMAKE_PATH = os.path.join(REPO_ROOT, "tools", "static", "sigmake.py")

TEXT_RVA = 0x1000
PDATA_RVA = 0x40000
RELOC_RVA = 0x50000
EXEC_CHARACTERISTICS = 0x60000020
DATA_CHARACTERISTICS = 0x40000040

DIRECTORY_EXCEPTION = 3
DIRECTORY_BASERELOC = 5


# --------------------------------------------------------------------------- #
# fixture builders
# --------------------------------------------------------------------------- #

def pdata_blob(rows) -> bytes:
    """``rows`` is a sequence of ``(begin_rva, end_rva, unwind_rva)``."""
    return b"".join(struct.pack("<III", *row) for row in rows)


def unwind_info(*, flags: int = 0, prolog: int = 4, codes: int = 0,
                frame: int = 0, chain_to: tuple | None = None) -> bytes:
    """One ``UNWIND_INFO``: version 1, *flags* in the top five bits of byte 0.

    When *chain_to* is given the record carries ``UNW_FLAG_CHAININFO`` and the
    trailing ``RUNTIME_FUNCTION`` naming the primary range, which is exactly how
    MSVC describes a continuation chunk.
    """
    if chain_to is not None:
        flags |= sigmake.UNW_FLAG_CHAININFO
    head = bytes([(flags << 3) | 1, prolog, codes, frame])
    body = b"\x00" * (2 * ((codes + 1) & ~1))
    tail = struct.pack("<III", *chain_to) if chain_to is not None else b""
    return head + body + tail


def reloc_blob(page_rva: int, entries) -> bytes:
    """One ``IMAGE_BASE_RELOCATION`` block; ``entries`` is ``(type, offset)``."""
    words = b"".join(struct.pack("<H", (kind << 12) | offset)
                     for kind, offset in entries)
    if len(words) % 4:
        words += struct.pack("<H", 0)          # ABSOLUTE padding, covers nothing
    return struct.pack("<II", page_rva, 8 + len(words)) + words


def build_image(tmp_path, name: str, *, text: bytes, pdata: bytes = b"",
                xdata: bytes = b"", xdata_rva: int = 0x30000,
                reloc: bytes = b"") -> str:
    builder = PEBuilder()
    builder.add_section(".text", TEXT_RVA, text,
                        characteristics=EXEC_CHARACTERISTICS)
    if xdata:
        builder.add_section(".xdata", xdata_rva, xdata,
                            characteristics=DATA_CHARACTERISTICS)
    if pdata:
        builder.add_section(".pdata", PDATA_RVA, pdata,
                            characteristics=DATA_CHARACTERISTICS)
        builder.set_directory(DIRECTORY_EXCEPTION, PDATA_RVA, len(pdata))
    if reloc:
        builder.add_section(".reloc", RELOC_RVA, reloc,
                            characteristics=DATA_CHARACTERISTICS)
        builder.set_directory(DIRECTORY_BASERELOC, RELOC_RVA, len(reloc))
    return write_image(tmp_path, name, builder.build())


def distinct_body(length: int, seed: int) -> bytes:
    """A byte run that is unique in these fixtures and passes the variety gate.

    Not random: the tests must be reproducible, and a body that occasionally
    repeats a neighbour would make a uniqueness assertion flaky.
    """
    return bytes(((seed * 37 + index * 53 + 11) % 251) + 1
                 for index in range(length))


def _tables(path):
    image = pe_info.Image.open(path)
    headers = pe_info.PEHeaders(image)
    warnings: list[str] = []
    return image, headers, warnings


# --------------------------------------------------------------------------- #
# the boundary oracle
# --------------------------------------------------------------------------- #

def test_boundary_table_reads_every_runtime_function_row(tmp_path):
    rows = [(TEXT_RVA + 0x000, TEXT_RVA + 0x040, 0x30000),
            (TEXT_RVA + 0x040, TEXT_RVA + 0x100, 0x30004),
            (TEXT_RVA + 0x200, TEXT_RVA + 0x280, 0x30004)]
    path = build_image(tmp_path, "pd.exe", text=b"\x90" * 0x400,
                       pdata=pdata_blob(rows),
                       xdata=unwind_info() + unwind_info())
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.BoundaryTable(headers, warnings)
        assert table.census["runtime_function_count"] == 3
        assert table.census["distinct_begin_addresses"] == 3
        assert table.index_of_begin(TEXT_RVA + 0x040) == 1
        assert table.index_of_begin(TEXT_RVA + 0x041) is None
        record = table.record(1)
        assert record["begin_address"] == TEXT_RVA + 0x040
        assert record["end_address"] == TEXT_RVA + 0x100
        assert record["range_length"] == 0xC0
    finally:
        image.close()


def test_census_counts_adjacent_ranges_and_shared_unwind_info(tmp_path):
    rows = [(TEXT_RVA + 0x000, TEXT_RVA + 0x040, 0x30000),
            (TEXT_RVA + 0x040, TEXT_RVA + 0x080, 0x30000),   # adjacent + shared
            (TEXT_RVA + 0x100, TEXT_RVA + 0x140, 0x30000)]   # shared only
    path = build_image(tmp_path, "adj.exe", text=b"\x90" * 0x400,
                       pdata=pdata_blob(rows), xdata=unwind_info())
    image, headers, warnings = _tables(path)
    try:
        census = sigmake.BoundaryTable(headers, warnings).census
        assert census["adjacent_ranges"] == 1
        assert census["distinct_unwind_info_addresses"] == 1
        assert census["unwind_info_addresses_shared"] == 1
        assert census["records_sharing_unwind_info"] == 3
        assert census["max_records_per_unwind_info"] == 3
        # the caveat is stated on the artifact, not only in the module docstring
        assert "not a proven end" in census["discrepancies_named"]["adjacent_ranges"]
        assert "LOWER BOUND" in census["discrepancies_named"]["missing_records"]
    finally:
        image.close()


def test_census_sizes_the_gap_between_ranges_and_executable_bytes(tmp_path):
    rows = [(TEXT_RVA, TEXT_RVA + 0x40, 0x30000)]
    path = build_image(tmp_path, "cov.exe", text=b"\x90" * 0x200,
                       pdata=pdata_blob(rows), xdata=unwind_info())
    image, headers, warnings = _tables(path)
    try:
        census = sigmake.BoundaryTable(headers, warnings).census
        assert census["bytes_covered_by_ranges"] == 0x40
        assert census["executable_bytes_on_disk"] >= 0x200
        assert 0 < census["coverage_fraction_of_executable_bytes"] < 1
    finally:
        image.close()


def test_a_chained_record_is_identified_and_resolved_to_its_primary(tmp_path):
    """The chunk relation, decoded end to end from a hand-built UNWIND_INFO."""
    primary_begin = TEXT_RVA + 0x000
    chunk_begin = TEXT_RVA + 0x200
    plain = unwind_info(codes = 2)
    chained = unwind_info(codes=0, chain_to=(primary_begin, TEXT_RVA + 0x040,
                                             0x30000))
    xdata = plain + chained
    rows = [(primary_begin, TEXT_RVA + 0x040, 0x30000),
            (chunk_begin, TEXT_RVA + 0x240, 0x30000 + len(plain))]
    path = build_image(tmp_path, "chain.exe", text=b"\x90" * 0x400,
                       pdata=pdata_blob(rows), xdata=xdata)
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.BoundaryTable(headers, warnings)
        assert table.chain_scan_ran is True
        primary = table.record(0)
        chunk = table.record(1)
        assert primary["is_chunk"] is False
        assert chunk["is_chunk"] is True
        assert chunk["unwind_flags_decoded"] == ["UNW_FLAG_CHAININFO"]
        assert chunk["chain_primary_begin_address"] == primary_begin
        assert table.census["records_with_chaininfo"] == 1
        assert table.census["primary_ranges"] == 1
        assert table.census["primaries_with_at_least_one_chunk"] == 1
        assert table.census["chained_records_with_unresolved_primary"] == 0
        assert [c["begin_address"] for c in table.chunks_of(primary_begin)] \
            == [chunk_begin]
    finally:
        image.close()


def test_exception_handler_flags_are_decoded_without_being_called_chunks(tmp_path):
    xdata = unwind_info(flags=sigmake.UNW_FLAG_EHANDLER)
    rows = [(TEXT_RVA, TEXT_RVA + 0x40, 0x30000)]
    path = build_image(tmp_path, "eh.exe", text=b"\x90" * 0x200,
                       pdata=pdata_blob(rows), xdata=xdata)
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.BoundaryTable(headers, warnings)
        assert table.record(0)["is_chunk"] is False
        assert table.record(0)["unwind_flags_decoded"] == ["UNW_FLAG_EHANDLER"]
        assert table.census["records_with_exception_handler"] == 1
        assert table.census["records_with_chaininfo"] == 0
    finally:
        image.close()


def test_no_exception_directory_warns_and_refuses_every_target(tmp_path):
    path = build_image(tmp_path, "nopdata.exe", text=distinct_body(0x80, 1))
    document = sigmake.analyze(path, [{"rva": TEXT_RVA, "label": "f",
                                       "origin": "t", "identified_by": None}],
                               want_probes=False, want_file_digest=False)
    assert document["summary"]["signatures_accepted"] == 0
    codes = [r["code"] for r in document["signatures"][0]["rejections"]]
    assert codes == ["boundary_unknown"]
    assert any("exception directory is absent" in w
               for w in document["warnings"])


def test_index_containing_explains_an_address_inside_another_range(tmp_path):
    rows = [(TEXT_RVA, TEXT_RVA + 0x40, 0x30000)]
    path = build_image(tmp_path, "inside.exe", text=distinct_body(0x200, 2),
                       pdata=pdata_blob(rows), xdata=unwind_info())
    target = {"rva": TEXT_RVA + 0x10, "label": "mid", "origin": "t",
              "identified_by": None}
    document = sigmake.analyze(path, [target], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert [r["code"] for r in record["rejections"]] == ["boundary_unknown"]
    assert record["boundary"]["offset_into_that_range"] == 0x10
    assert record["boundary"]["nearest_enclosing_range"]["begin_address"] == TEXT_RVA


# --------------------------------------------------------------------------- #
# the relocation oracle
# --------------------------------------------------------------------------- #

def test_relocation_table_decodes_widths_and_locates_covered_bytes(tmp_path):
    blob = reloc_blob(TEXT_RVA, [(10, 0x10), (3, 0x20), (0, 0)])
    path = build_image(tmp_path, "rel.exe", text=b"\x90" * 0x200, reloc=blob)
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.RelocationTable(headers, warnings)
        assert table.census["entry_count"] == 2      # ABSOLUTE covers nothing
        assert table.census["block_count"] == 1
        assert table.covered_positions(TEXT_RVA + 0x10, 8) == list(range(8))
        assert table.covered_positions(TEXT_RVA + 0x20, 4) == list(range(4))
        assert table.covered_positions(TEXT_RVA + 0x40, 8) == []
        # a fixup starting just before the range still reaches into it
        assert table.covered_positions(TEXT_RVA + 0x14, 8) == [0, 1, 2, 3]
    finally:
        image.close()


def test_relocation_census_reports_entries_per_section_and_in_code(tmp_path):
    blob = (reloc_blob(TEXT_RVA, [(10, 0x10)])
            + reloc_blob(RELOC_RVA, [(10, 0x08)]))
    path = build_image(tmp_path, "relsec.exe", text=b"\x90" * 0x200, reloc=blob)
    image, headers, warnings = _tables(path)
    try:
        census = sigmake.RelocationTable(headers, warnings).census
        assert census["entries_in_executable_sections"] == 1
        assert census["entries_per_section"][".text"] == 1
        assert ".text" in census["executable_sections"]
        assert "EMPTY over code" in census[
            "what_zero_in_executable_sections_means"]
    finally:
        image.close()


def test_no_relocation_directory_warns_and_leaves_the_mask_empty(tmp_path):
    path = build_image(tmp_path, "norel.exe", text=b"\x90" * 0x200)
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.RelocationTable(headers, warnings)
        assert table.census["entry_count"] == 0
        assert table.covered_positions(TEXT_RVA, 32) == []
        assert any("relocation directory is absent" in w for w in warnings)
    finally:
        image.close()


def test_a_relocation_block_declaring_a_bad_size_stops_the_walk(tmp_path):
    bad = struct.pack("<II", TEXT_RVA, 4)     # SizeOfBlock < 8
    path = build_image(tmp_path, "badrel.exe", text=b"\x90" * 0x200, reloc=bad)
    image, headers, warnings = _tables(path)
    try:
        table = sigmake.RelocationTable(headers, warnings)
        assert table.census["entry_count"] == 0
        assert any("SizeOfBlock" in w for w in warnings)
    finally:
        image.close()


# --------------------------------------------------------------------------- #
# the mask policy
# --------------------------------------------------------------------------- #

def test_relocation_holes_are_exact_and_labelled_as_proven():
    mask, breakdown = sigmake.build_mask(16, [4, 5, 6, 7], [], "reloc")
    assert mask == bytes([1, 1, 1, 1, 0, 0, 0, 0] + [1] * 8)
    assert breakdown["masked_by_base_relocation"] == 4
    assert breakdown["masked_by_rel32_heuristic"] == 0
    assert breakdown["base_relocation_is_exact"] is True
    assert breakdown["rel32_is_a_heuristic"] is False
    assert "every hole is a proven relocation" in breakdown["heuristic_note"]


def test_rel32_holes_only_appear_in_the_opt_in_mode_and_say_they_are_guesses():
    plain, first = sigmake.build_mask(16, [], [2], sigmake.MASK_MODE_RELOC)
    assert plain == b"\x01" * 16
    assert first["masked_by_rel32_heuristic"] == 0

    masked, second = sigmake.build_mask(16, [], [2],
                                        sigmake.MASK_MODE_RELOC_REL32)
    # the E8/E9 byte itself stays literal; its four displacement bytes do not
    assert masked == bytes([1, 1, 1, 0, 0, 0, 0] + [1] * 9)
    assert second["masked_by_rel32_heuristic"] == 4
    assert second["rel32_is_a_heuristic"] is True
    assert "GUESSED" in second["heuristic_note"]


def test_mask_policy_states_the_unsolved_component_rather_than_hiding_it(tmp_path):
    path = build_image(tmp_path, "pol.exe", text=b"\x90" * 0x200,
                       reloc=reloc_blob(RELOC_RVA, [(10, 8)]))
    image, headers, warnings = _tables(path)
    try:
        policy = sigmake._mask_policy(sigmake.MASK_MODE_RELOC,
                                      sigmake.RelocationTable(headers, warnings))
        assert policy["exact_component"]["entries_in_executable_sections"] == 0
        assert "instruction decoder" in policy["unsolved_component"]["why_not_masked"]
        assert "conservative" in policy["unsolved_component"]["chosen_side"]
    finally:
        image.close()


def test_fragility_counts_rel32_candidates_and_bounds_disp32_windows():
    # E8 followed by a displacement of 0 resolves to the byte after the call,
    # which is inside the image; so it is a candidate.
    body = b"\x90\xe8\x00\x00\x00\x00\x90\x90"
    window = sigmake.fragility(body, 0x1000, 0x100000)
    assert window["rel32_candidate_offsets"] == [1]
    assert window["rel32_candidates"] == 1
    assert window["disp32_windows_examined"] == len(body) - 3
    assert 0 <= window["disp32_windows_resolving_into_image"] \
        <= window["disp32_windows_examined"]
    assert "no instruction was decoded" in window["method"]
    assert "Phase 1 has no decoder" in window["not_detected"]


def test_fragility_ignores_a_rel32_whose_target_leaves_the_image():
    body = b"\xe8\x00\x00\x00\x7f" + b"\x90" * 8     # huge positive displacement
    assert sigmake.fragility(body, 0x1000, 0x2000)["rel32_candidates"] == 0


# --------------------------------------------------------------------------- #
# the justification gate: every refusal must fire
# --------------------------------------------------------------------------- #

GATE = dict(min_length=12, max_masked_fraction=0.30, min_literal_bytes=10,
            min_anchor_bytes=6, min_distinct_values=4)


def _codes(values: bytes, mask: bytes, **overrides):
    gate = dict(GATE)
    gate.update(overrides)
    problems = sigmake.justify(sigscan.Pattern(values, mask), **gate)
    return [item["code"] for item in problems]


def test_gate_accepts_a_reasonable_pattern():
    assert _codes(distinct_body(16, 3), b"\x01" * 16) == []


def test_gate_refuses_a_short_pattern():
    assert "too_short" in _codes(distinct_body(8, 4), b"\x01" * 8)


def test_gate_refuses_an_all_wildcard_pattern():
    codes = _codes(bytes(32), bytes(32))
    assert "too_few_literal_bytes" in codes
    assert "too_masked" in codes
    assert "anchor_too_short" in codes
    assert "low_variety" in codes


def test_gate_refuses_a_run_of_padding_bytes():
    assert _codes(b"\xcc" * 32, b"\x01" * 32) == ["low_variety"]


def test_gate_refuses_a_pattern_that_is_mostly_holes():
    values = distinct_body(20, 5)
    mask = bytes([1] * 12 + [0] * 8)       # 40% masked, over the 30% limit
    codes = _codes(values, mask)
    assert "too_masked" in codes
    assert "too_short" not in codes


def test_gate_refuses_scattered_literal_bytes_with_no_anchor():
    values = distinct_body(24, 6)
    mask = bytes([1, 0] * 12)              # no run longer than one byte
    codes = _codes(values, mask, max_masked_fraction=0.60, min_literal_bytes=8)
    assert codes == ["anchor_too_short"]


def test_gate_reports_every_failure_at_once_not_just_the_first():
    """A caller fixing one complaint must be able to see the rest immediately.

    Eight literal ``CC`` bytes fail three ways at once: too short (8 < 12), too
    few compared bytes (8 < 10) and no variety (one distinct value). They do NOT
    fail the anchor test -- eight consecutive literal bytes clear the six-byte
    minimum -- and asserting the exact set is what keeps this test honest about
    which thresholds actually bind.
    """
    codes = _codes(b"\xcc" * 8, b"\x01" * 8)
    assert set(codes) == {"too_short", "too_few_literal_bytes", "low_variety"}
    # shrink it to four bytes and the anchor test binds too
    assert "anchor_too_short" in _codes(b"\xcc" * 4, b"\x01" * 4)


def test_every_rejection_code_has_prose_explaining_it():
    for code, reason in sigmake.REJECTIONS.items():
        assert isinstance(reason, str) and len(reason) > 40, code


# --------------------------------------------------------------------------- #
# padding, ladder and label helpers
# --------------------------------------------------------------------------- #

def test_trailing_padding_is_trimmed_but_interior_int3_is_kept():
    body, trimmed = sigmake.trim_padding(b"\x48\xcc\x89\xcc\xcc\x00\x00")
    assert body == b"\x48\xcc\x89"
    assert trimmed == 4
    assert sigmake.trim_padding(b"\xcc" * 6) == (b"", 6)
    assert sigmake.trim_padding(b"\x48\x89") == (b"\x48\x89", 0)


def test_ladder_is_ascending_clipped_and_ends_on_the_range_length():
    assert sigmake._ladder(200, 12, 96) == [12, 16, 20, 24, 32, 40, 48, 64, 80, 96]
    assert sigmake._ladder(33, 12, 96) == [12, 16, 20, 24, 32, 33]
    assert sigmake._ladder(8, 12, 96) == []
    assert sigmake._ladder(12, 12, 96) == [12]


def test_parse_rva_argument_reads_both_forms_and_refuses_junk():
    assert sigmake.parse_rva_argument("0xf4d8e0") == (0xF4D8E0, None)
    assert sigmake.parse_rva_argument("0xf4d8e0=Name::slot") == (0xF4D8E0,
                                                                 "Name::slot")
    assert sigmake.parse_rva_argument("4660") == (4660, None)
    with pytest.raises(ValueError):
        sigmake.parse_rva_argument("not-a-number")
    with pytest.raises(ValueError):
        sigmake.parse_rva_argument("-8")


def test_safe_filename_sanitises_and_disambiguates_long_template_names():
    long_a = "TThing<" + "A" * 200 + ">::vtable_slot_0"
    long_b = "TThing<" + "A" * 200 + ">::vtable_slot_1"
    first = sigmake.safe_filename(long_a)
    second = sigmake.safe_filename(long_b)
    assert first != second, "two long names must not collide"
    for name in (first, second):
        assert name.endswith(".json")
        assert not set(name) & set('<>:"/\\|?*')
        assert len(name) < 120


# --------------------------------------------------------------------------- #
# end to end: placement, ladder, uniqueness, emission
# --------------------------------------------------------------------------- #

def _one_function_image(tmp_path, name, body, *, pad=b"\x90" * 0x100,
                        reloc=b""):
    text = pad + body + pad
    rows = [(TEXT_RVA + len(pad), TEXT_RVA + len(pad) + len(body), 0x30000)]
    return build_image(tmp_path, name, text=text, pdata=pdata_blob(rows),
                       xdata=unwind_info(), reloc=reloc), TEXT_RVA + len(pad)


def _target(rva, label="f", identified_by=None):
    return {"rva": rva, "label": label, "origin": "test",
            "identified_by": identified_by}


def test_a_unique_function_yields_an_accepted_signature(tmp_path):
    body = distinct_body(0x60, 7)
    path, rva = _one_function_image(tmp_path, "accept.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["accepted"] is True
    assert record["rejections"] == []
    assert record["self_scan"]["verdict"] == sigscan.VERDICT_UNIQUE
    assert record["self_scan"]["occurrences"] == 1
    assert record["section"] == ".text"
    assert record["range_length"] == 0x60
    assert record["masked_bytes"] == 0
    assert document["summary"]["signatures_accepted"] == 1
    assert document["task"] == "S-06"


def test_the_emitted_pattern_is_the_rung_whose_uniqueness_was_checked(tmp_path):
    """The defect this test exists for: emitting a rung that was never counted.

    ``--mode grow`` builds a candidate at every ladder length and stops counting
    at the first that is unique. Publishing ``_pattern_objects[-1]`` -- the
    LONGEST rung built -- instead of the one that was counted produced a record
    whose ``pattern`` and whose ``self_scan.length`` disagreed, and silently
    threw away the whole point of preferring a short pattern.
    """
    body = distinct_body(0x60, 8)
    path, rva = _one_function_image(tmp_path, "rung.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    # a 0x60-byte function offers rungs up to 0x60; the first (12 bytes) is
    # already unique here, so 12 is what must be emitted.
    assert record["length"] == 12
    assert record["self_scan"]["length"] == 12
    assert record["emitted_ladder_index"] == 0
    assert record["self_scan"]["ladder_rung"] == 0
    assert len(record["pattern"].split()) == record["length"]
    # and the number the verdict is about is the number beside it
    assert record["length"] == record["self_scan"]["length"]


def test_grow_walks_up_the_ladder_until_the_pattern_is_unique(tmp_path):
    """A prefix shared by two functions forces the ladder to keep growing."""
    shared = distinct_body(20, 9)
    tail_a = distinct_body(40, 10)
    tail_b = distinct_body(40, 11)
    pad = b"\x90" * 0x40
    text = pad + shared + tail_a + pad + shared + tail_b + pad
    first = TEXT_RVA + len(pad)
    second = TEXT_RVA + len(pad) + len(shared) + len(tail_a) + len(pad)
    rows = [(first, first + 60, 0x30000), (second, second + 60, 0x30000)]
    path = build_image(tmp_path, "grow.exe", text=text, pdata=pdata_blob(rows),
                       xdata=unwind_info())
    document = sigmake.analyze(path, [_target(first, "a"), _target(second, "b")],
                               want_probes=False, want_file_digest=False)
    for record in document["signatures"]:
        assert record["accepted"] is True
        # 12 and 16 both fall inside the shared 20-byte prefix, so they cannot
        # be unique; the accepted length has to reach past it.
        assert record["length"] > 20, record["label"]
        assert record["self_scan"]["occurrences"] == 1
        assert record["self_scan"]["passes_used"] >= 3


def test_a_duplicated_function_is_refused_not_unique(tmp_path):
    """The failure mode this tool pair exists to prevent, made to fire.

    Two byte-identical 40-byte functions. No ladder length can separate them, so
    the honest answer is a refusal -- not the first of the two addresses.
    """
    body = distinct_body(40, 12)
    pad = b"\x90" * 0x40
    text = pad + body + pad + body + pad
    first = TEXT_RVA + len(pad)
    second = TEXT_RVA + 2 * len(pad) + len(body)
    rows = [(first, first + 40, 0x30000), (second, second + 40, 0x30000)]
    path = build_image(tmp_path, "dup.exe", text=text, pdata=pdata_blob(rows),
                       xdata=unwind_info())
    document = sigmake.analyze(path, [_target(first, "a")], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["accepted"] is False
    assert [r["code"] for r in record["rejections"]] == ["not_unique"]
    assert record["self_scan"]["occurrences"] == 2
    assert document["summary"]["signatures_accepted"] == 0
    assert document["summary"]["rejection_codes"] == {"not_unique": 1}
    # the pattern is kept for review, but marked unusable
    assert record["pattern"] is not None


def test_a_chunk_address_is_refused_as_not_a_function_start(tmp_path):
    primary = TEXT_RVA + 0x100
    chunk = TEXT_RVA + 0x200
    plain = unwind_info(codes=2)
    chained = unwind_info(chain_to=(primary, primary + 0x40, 0x30000))
    rows = [(primary, primary + 0x40, 0x30000),
            (chunk, chunk + 0x40, 0x30000 + len(plain))]
    text = bytearray(b"\x90" * 0x400)
    text[0x100:0x140] = distinct_body(0x40, 13)
    text[0x200:0x240] = distinct_body(0x40, 14)
    path = build_image(tmp_path, "chunkref.exe", text=bytes(text),
                       pdata=pdata_blob(rows), xdata=plain + chained)
    document = sigmake.analyze(path, [_target(chunk, "cold")],
                               want_probes=False, want_file_digest=False)
    record = document["signatures"][0]
    assert record["accepted"] is False
    assert [r["code"] for r in record["rejections"]] == ["chunk_not_function_start"]
    assert record["pattern"] is None
    assert document["summary"]["boundary_targets_that_are_chunks"] == 1


def test_a_function_shorter_than_min_length_is_refused_too_short(tmp_path):
    body = distinct_body(6, 15)
    path, rva = _one_function_image(tmp_path, "short.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert [r["code"] for r in record["rejections"]] == ["too_short"]
    assert record["range_length"] == 6


def test_a_range_in_a_data_section_is_refused_as_not_executable(tmp_path):
    body = distinct_body(0x40, 16)
    builder = PEBuilder()
    builder.add_section(".text", TEXT_RVA, b"\x90" * 0x200,
                        characteristics=EXEC_CHARACTERISTICS)
    builder.add_section(".rdata", 0x20000, b"\x90" * 0x40 + body,
                        characteristics=DATA_CHARACTERISTICS)
    rows = [(0x20040, 0x20040 + len(body), 0x30000)]
    builder.add_section(".xdata", 0x30000, unwind_info(),
                        characteristics=DATA_CHARACTERISTICS)
    builder.add_section(".pdata", PDATA_RVA, pdata_blob(rows),
                        characteristics=DATA_CHARACTERISTICS)
    builder.set_directory(DIRECTORY_EXCEPTION, PDATA_RVA, len(pdata_blob(rows)))
    path = write_image(tmp_path, "indata.exe", builder.build())
    document = sigmake.analyze(path, [_target(0x20040, "d")],
                               want_probes=False, want_file_digest=False)
    codes = [r["code"] for r in document["signatures"][0]["rejections"]]
    assert codes == ["range_not_executable"]


def test_trailing_padding_of_a_function_is_trimmed_and_counted(tmp_path):
    body = distinct_body(0x20, 17) + b"\xcc" * 6
    path, rva = _one_function_image(tmp_path, "pad.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["range_length"] == 0x26
    assert record["trailing_padding_trimmed"] == 6
    assert record["length"] <= 0x20


def test_max_length_caps_the_published_pattern(tmp_path):
    body = distinct_body(0x200, 18)
    path, rva = _one_function_image(tmp_path, "cap.exe", body)
    document = sigmake.analyze(path, [_target(rva)], mode=sigmake.MODE_WHOLE,
                               max_length=32, want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["length"] == 32
    assert record["range_length"] == 0x200


def test_whole_mode_takes_the_range_and_reports_one_pass(tmp_path):
    body = distinct_body(0x30, 19)
    path, rva = _one_function_image(tmp_path, "whole.exe", body)
    document = sigmake.analyze(path, [_target(rva)], mode=sigmake.MODE_WHOLE,
                               want_probes=False, want_file_digest=False)
    record = document["signatures"][0]
    assert record["length"] == 0x30
    assert record["lengths_tried"] == [0x30]
    assert document["mode"]["length_mode"] == sigmake.MODE_WHOLE


def test_mask_breakdown_and_fragility_are_published_on_every_signature(tmp_path):
    """The defect this test exists for: both fields left permanently None.

    ``_place`` computed the fragility window and the mask breakdown and then
    never stored either, so every accepted record carried ``fragility: null``
    and the summary line that reads it crashed the whole run with a TypeError.
    """
    body = b"\x90\xe8\x00\x00\x00\x00" + distinct_body(0x3A, 20)
    path, rva = _one_function_image(tmp_path, "fields.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["accepted"] is True
    assert record["fragility"] is not None
    assert record["mask_breakdown"] is not None
    assert record["mask_breakdown"]["mask_mode"] == sigmake.MASK_MODE_RELOC
    assert record["range_fragility"] is not None
    # the per-signature fragility describes the EMITTED length, not the range
    assert (record["fragility"]["disp32_windows_examined"]
            == max(0, record["length"] - 3))
    assert (record["range_fragility"]["disp32_windows_examined"]
            >= record["fragility"]["disp32_windows_examined"])
    assert isinstance(document["summary"]["accepted_with_rel32_candidates"], int)


def test_no_internal_working_field_reaches_the_document(tmp_path):
    """Internal keys leaking out broke JSON serialisation and C-13 alike.

    ``_body`` held the raw bytes read for the target: a bytes object, which
    ``json.dumps`` refuses, and -- had it been text -- a copy of the function
    body published past the ``--max-length`` cap.
    """
    body = distinct_body(0x60, 21)
    path, rva = _one_function_image(tmp_path, "clean.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    for record in document["signatures"]:
        leaked = [key for key in record if key.startswith("_")]
        assert leaked == [], leaked
    # the whole document must round-trip through JSON
    assert json.loads(sigmake.dump_json(document))["task"] == "S-06"


def test_reloc_covered_bytes_become_holes_in_the_emitted_pattern(tmp_path):
    """The exact oracle, end to end: a fixup inside a function makes a hole."""
    body = distinct_body(0x40, 22)
    pad = b"\x90" * 0x100
    begin = TEXT_RVA + len(pad)
    # a DIR64 fixup eight bytes into the function body
    page = begin & ~0xFFF
    blob = reloc_blob(page, [(10, (begin + 8) - page)])
    path, rva = _one_function_image(tmp_path, "hole.exe", body, pad=pad,
                                    reloc=blob)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    record = document["signatures"][0]
    assert record["masked_bytes"] > 0
    assert record["mask_breakdown"]["masked_by_base_relocation"] \
        == record["masked_bytes"]
    assert record["mask_breakdown"]["masked_by_rel32_heuristic"] == 0
    tokens = record["pattern"].split()
    assert tokens[8] == "??"
    assert document["relocation_oracle"]["entries_in_executable_sections"] == 1


# --------------------------------------------------------------------------- #
# targets from the RTTI document
# --------------------------------------------------------------------------- #

def _rtti_document(sha, entries):
    return {"file": {"sha256": sha},
            "classes": [{"decoded_name": name,
                         "attribution": {"bucket": bucket},
                         "vtable": {"code_slot_target_rvas": rvas}}
                        for name, bucket, rvas in entries]}


def test_targets_from_rtti_expands_slots_and_filters_by_bucket(tmp_path):
    path = os.path.join(str(tmp_path), "rtti.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(_rtti_document("ab" * 32, [
            ("FThing", "unreal-engine", [0x1000, 0x2000]),
            ("std::locale", "msvc-crt-stl", [0x3000]),
        ]), handle)
    warnings: list[str] = []
    every = sigmake.targets_from_rtti(path, "ab" * 32, None, warnings)
    assert [t["rva"] for t in every] == [0x1000, 0x2000, 0x3000]
    assert every[0]["label"] == "FThing::vtable_slot_0"
    assert every[0]["identified_by"]["method"] == "S-10"
    only_ue = sigmake.targets_from_rtti(path, "ab" * 32, ("unreal-engine",),
                                        warnings)
    assert [t["rva"] for t in only_ue] == [0x1000, 0x2000]
    assert warnings == []


def test_a_slot_target_shared_by_two_classes_becomes_one_target(tmp_path):
    """One function, one signature, every user recorded.

    Two signatures with identical bytes and different labels would both be
    rejected ``not_unique`` -- for a reason that is about the naming and not
    about the image, which would be a lie about the bytes.
    """
    path = os.path.join(str(tmp_path), "shared.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(_rtti_document("cd" * 32, [
            ("FA", "unreal-engine", [0x1000]),
            ("FB", "unreal-engine", [0x1000]),
        ]), handle)
    targets = sigmake.targets_from_rtti(path, "cd" * 32, None, [])
    assert len(targets) == 1
    assert targets[0]["identified_by"]["vtable_user_count"] == 2
    assert set(targets[0]["identified_by"]["vtable_users"]) == {
        "FA::vtable_slot_0", "FB::vtable_slot_0"}


def test_a_digest_mismatch_warns_that_the_rvas_are_from_another_image(tmp_path):
    path = os.path.join(str(tmp_path), "other.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(_rtti_document("ef" * 32, [("F", "unreal-engine", [0x1000])]),
                  handle)
    warnings: list[str] = []
    sigmake.targets_from_rtti(path, "00" * 32, None, warnings)
    assert any("DIFFERENT image" in w for w in warnings)


def test_targets_from_rtti_refuses_a_document_of_the_wrong_shape(tmp_path):
    path = os.path.join(str(tmp_path), "bad.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"nope": 1}, handle)
    with pytest.raises(ValueError):
        sigmake.targets_from_rtti(path, None, None, [])


# --------------------------------------------------------------------------- #
# evidence layers
# --------------------------------------------------------------------------- #

def test_literal_reads_are_class_p_named_to_s06_and_reproduced(tmp_path):
    body = distinct_body(0x40, 23)
    path, rva = _one_function_image(tmp_path, "lit.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    assert document["literal_reads"]
    read = document["literal_reads"][0]
    assert read["evidence"]["claim_class"] == "P"
    assert read["evidence"]["sources"][0]["method"] == "S-06"
    assert read["reproduced"] is True
    for forbidden in ("signature", "pattern", "function"):
        assert forbidden not in read["claim"].lower()
    assert str(read["offset"]) in read["claim"]


def test_interpreted_annotation_needs_a_second_method_for_the_higher_grade():
    alone = sigmake.signature_annotation("x", boundary_corroborated=False)
    assert alone["claim_class"] == "I"
    assert alone["confidence"] < 0.80
    assert len(alone["sources"]) == 1
    both = sigmake.signature_annotation("x", boundary_corroborated=True)
    assert both["confidence"] == sigmake.CONFIDENCE_INTERPRETED_CORROBORATED
    assert {s["method"] for s in both["sources"]} == {"S-06", "S-10"}
    assert "external-doc" in both["oracle"]


def test_rtti_provenance_raises_the_annotation_to_the_corroborated_grade(tmp_path):
    body = distinct_body(0x40, 24)
    path, rva = _one_function_image(tmp_path, "corr.exe", body)
    plain = sigmake.analyze(path, [_target(rva)], want_probes=False,
                            want_file_digest=False)
    named = sigmake.analyze(path, [_target(rva, identified_by={"method": "S-10"})],
                            want_probes=False, want_file_digest=False)
    assert (plain["interpreted_annotation"]["confidence"]
            == sigmake.CONFIDENCE_INTERPRETED_SINGLE_METHOD)
    assert (named["interpreted_annotation"]["confidence"]
            == sigmake.CONFIDENCE_INTERPRETED_CORROBORATED)


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def test_probes_run_and_the_gate_control_proves_the_gate_binds(tmp_path):
    body = distinct_body(0x60, 25)
    path, rva = _one_function_image(tmp_path, "probe.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_file_digest=False)
    ids = {p["id"] for p in document["refutation_probes"]}
    assert ids == {"reloc-oracle-covers-code",
                   "boundary-oracle-is-not-a-function-inventory",
                   "gate-refuses-a-non-signature", "one-byte-flip-control",
                   "acceptance-population"}
    gate = next(p for p in document["refutation_probes"]
                if p["id"] == "gate-refuses-a-non-signature")
    assert gate["refuted"] is False
    assert len(gate["controls"]) == 3
    for control in gate["controls"]:
        assert control["rejected"] is True
        assert control["expected_code_present"] is True


def test_one_byte_flip_control_makes_every_accepted_signature_vanish(tmp_path):
    body = distinct_body(0x60, 26)
    path, rva = _one_function_image(tmp_path, "flip.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_file_digest=False)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "one-byte-flip-control")
    assert probe["patterns_flipped"] == 1
    assert probe["survivors"] == []
    assert probe["refuted"] is False


def test_reloc_probe_is_refuted_when_a_fixup_really_does_land_in_code(tmp_path):
    """The probe must be able to come back REFUTED, or it proves nothing."""
    body = distinct_body(0x40, 27)
    pad = b"\x90" * 0x100
    begin = TEXT_RVA + len(pad)
    page = begin & ~0xFFF
    blob = reloc_blob(page, [(10, (begin + 8) - page)])
    path, rva = _one_function_image(tmp_path, "relprobe.exe", body, pad=pad,
                                    reloc=blob)
    document = sigmake.analyze(path, [_target(rva)], want_file_digest=False)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "reloc-oracle-covers-code")
    assert probe["entries_in_executable_sections"] == 1
    assert probe["refuted"] is True


def test_acceptance_population_publishes_the_denominator(tmp_path):
    body = distinct_body(6, 28)
    path, rva = _one_function_image(tmp_path, "denom.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_file_digest=False)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "acceptance-population")
    assert probe["requested"] == 1
    assert probe["accepted"] == 0
    assert probe["rejection_codes"] == {"too_short": 1}


# --------------------------------------------------------------------------- #
# artifacts, determinism, CLI
# --------------------------------------------------------------------------- #

def test_two_runs_differ_only_in_the_timestamp_and_the_timings(tmp_path):
    body = distinct_body(0x60, 29)
    path, rva = _one_function_image(tmp_path, "det.exe", body)
    first = sigmake.analyze(path, [_target(rva)], want_probes=False,
                            want_file_digest=False)
    second = sigmake.analyze(path, [_target(rva)], want_probes=False,
                             want_file_digest=False)
    for document in (first, second):
        document.pop("generated_at")
        document.pop("timings_seconds")
    assert sigmake.dump_json(first) == sigmake.dump_json(second)


def test_library_document_holds_only_accepted_signatures(tmp_path):
    good = distinct_body(0x60, 30)
    twin = distinct_body(0x28, 31)
    pad = b"\x90" * 0x40
    text = pad + good + pad + twin + pad + twin + pad
    a = TEXT_RVA + len(pad)
    b = TEXT_RVA + 2 * len(pad) + len(good)
    rows = [(a, a + len(good), 0x30000), (b, b + len(twin), 0x30000),
            (b + len(twin) + len(pad), b + 2 * len(twin) + len(pad), 0x30000)]
    path = build_image(tmp_path, "lib.exe", text=text, pdata=pdata_blob(rows),
                       xdata=unwind_info())
    document = sigmake.analyze(path, [_target(a, "good"), _target(b, "twin")],
                               want_probes=False, want_file_digest=False)
    library = sigmake.library_document(document)
    assert [s["label"] for s in library["signatures"]] == ["good"]
    assert all(s["accepted"] for s in library["signatures"])
    # and the full document still records the refusal with its reason
    twin_record = next(s for s in document["signatures"] if s["label"] == "twin")
    assert twin_record["accepted"] is False


def test_the_library_round_trips_into_sigscan(tmp_path):
    """The contract between the two tools, exercised rather than asserted."""
    body = distinct_body(0x60, 32)
    path, rva = _one_function_image(tmp_path, "rt.exe", body)
    made = sigmake.analyze(path, [_target(rva)], want_probes=False,
                           want_file_digest=True)
    library_path = os.path.join(str(tmp_path), "library.json")
    with open(library_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(sigmake.dump_json(sigmake.library_document(made)))
    rows, provenance, notes = sigscan.load_library(library_path,
                                                   include_rejected=False)
    assert len(rows) == 1 and notes == []
    scanned = sigscan.analyze(path, rows, library_provenance=provenance,
                              want_probes=False)
    record = scanned["signatures"][0]
    assert record["verdict"] == sigscan.VERDICT_UNIQUE
    assert scanned["summary"]["same_image_as_signature_source"] is True
    assert record["found_at_source_rva"] is True
    assert record["hits"][0]["rva"] == rva


def test_jsonl_is_one_object_per_signature_accepted_or_not(tmp_path):
    body = distinct_body(0x60, 33)
    path, rva = _one_function_image(tmp_path, "jl.exe", body)
    document = sigmake.analyze(path, [_target(rva)], want_probes=False,
                               want_file_digest=False)
    lines = sigmake.jsonl_lines(document)
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["accepted"] is True
    assert row["source_rva"] == rva
    assert row["mask_mode"] == sigmake.MASK_MODE_RELOC
    assert row["rejection_codes"] == []


def _run_cli(args):
    return subprocess.run([sys.executable, SIGMAKE_PATH] + args,
                          capture_output=True, text=True)


def test_cli_emits_a_signature_for_an_rva_and_exits_zero(tmp_path):
    body = distinct_body(0x60, 34)
    path, rva = _one_function_image(tmp_path, "cli.exe", body)
    done = _run_cli([path, "--rva", "0x%x=Named::slot" % rva, "--no-probes",
                     "--json"])
    assert done.returncode == 0, done.stderr
    document = json.loads(done.stdout)
    assert document["summary"]["signatures_accepted"] == 1
    assert document["signatures"][0]["label"] == "Named::slot"


def test_cli_prints_a_summary_naming_the_boundary_caveat(tmp_path):
    body = distinct_body(0x60, 35)
    path, rva = _one_function_image(tmp_path, "sum.exe", body)
    done = _run_cli([path, "--rva", "0x%x" % rva, "--no-probes"])
    assert done.returncode == 0, done.stderr
    assert "NOT function starts" in done.stdout
    assert "NOT masked: RIP-relative displacements" in done.stdout


def test_cli_run_where_everything_is_refused_still_exits_zero(tmp_path):
    """An honest "no" is a successful run, not a failure."""
    body = distinct_body(6, 36)
    path, rva = _one_function_image(tmp_path, "norej.exe", body)
    done = _run_cli([path, "--rva", "0x%x" % rva, "--no-probes", "--json"])
    assert done.returncode == 0
    document = json.loads(done.stdout)
    assert document["summary"]["signatures_accepted"] == 0


def test_cli_refuses_max_length_above_the_c13_ceiling(tmp_path):
    body = distinct_body(0x60, 37)
    path, rva = _one_function_image(tmp_path, "ceil.exe", body)
    done = _run_cli([path, "--rva", "0x%x" % rva,
                     "--max-length", str(sigmake.HARD_MAX_LENGTH + 1)])
    assert done.returncode == 2
    assert "hard ceiling" in done.stderr


def test_cli_refuses_no_targets_and_bad_numbers(tmp_path):
    path, rva = _one_function_image(tmp_path, "args.exe", distinct_body(0x60, 38))
    assert _run_cli([path]).returncode == 2
    assert _run_cli([path, "--rva", "zz"]).returncode == 2
    assert _run_cli([path, "--rva", "0x%x" % rva,
                     "--max-masked-fraction", "2.0"]).returncode == 2
    assert _run_cli([path, "--rva", "0x%x" % rva,
                     "--min-length", "0"]).returncode == 2


def test_duplicate_labels_are_renamed_rather_than_silently_merged(tmp_path):
    body = distinct_body(0x60, 39)
    path, rva = _one_function_image(tmp_path, "dupl.exe", body)
    done = _run_cli([path, "--rva", "0x%x=same" % rva,
                     "--rva", "0x%x=same" % (rva + 4), "--no-probes", "--json"])
    assert done.returncode == 0, done.stderr
    document = json.loads(done.stdout)
    labels = [s["label"] for s in document["signatures"]]
    assert len(set(labels)) == len(labels)
    assert any("duplicate label" in w for w in document["warnings"])


def test_every_output_path_inside_an_installation_is_refused(tmp_path):
    """D-01 layer 1, on all four output flags."""
    install = os.path.join(str(tmp_path), "install")
    os.makedirs(os.path.join(install, "Engine", "Binaries", "Win64"))
    with open(os.path.join(install, "Engine", "Binaries", "Win64", "x.exe"),
              "wb") as handle:
        handle.write(b"\x00")
    body = distinct_body(0x60, 40)
    path, rva = _one_function_image(tmp_path, "guard.exe", body)
    for flag in ("--out", "--jsonl-out", "--library-out", "--split-out"):
        done = _run_cli([path, "--rva", "0x%x" % rva, "--no-probes",
                         "--install-dir", install,
                         flag, os.path.join(install, "leak")])
        assert done.returncode == 2, flag
        assert not os.path.exists(os.path.join(install, "leak"))


def test_split_out_writes_one_file_per_accepted_signature(tmp_path):
    body = distinct_body(0x60, 41)
    path, rva = _one_function_image(tmp_path, "split.exe", body)
    out_dir = os.path.join(str(tmp_path), "signatures")
    done = _run_cli([path, "--rva", "0x%x=Some<T>::slot" % rva, "--no-probes",
                     "--split-out", out_dir])
    assert done.returncode == 0, done.stderr
    written = os.listdir(out_dir)
    assert len(written) == 1
    with open(os.path.join(out_dir, written[0]), encoding="utf-8") as handle:
        one = json.load(handle)
    assert len(one["signatures"]) == 1
    assert one["signatures"][0]["label"] == "Some<T>::slot"


def test_no_chain_scan_loses_the_chunk_refusal_and_says_so(tmp_path):
    """Turning the flag scan off must lose the refusal, not fake it."""
    primary = TEXT_RVA + 0x100
    chunk = TEXT_RVA + 0x200
    plain = unwind_info(codes=2)
    chained = unwind_info(chain_to=(primary, primary + 0x40, 0x30000))
    rows = [(primary, primary + 0x40, 0x30000),
            (chunk, chunk + 0x40, 0x30000 + len(plain))]
    text = bytearray(b"\x90" * 0x400)
    text[0x100:0x140] = distinct_body(0x40, 42)
    text[0x200:0x240] = distinct_body(0x40, 43)
    path = build_image(tmp_path, "nochain.exe", text=bytes(text),
                       pdata=pdata_blob(rows), xdata=plain + chained)
    off = sigmake.analyze(path, [_target(chunk, "cold")], want_chain_scan=False,
                          want_probes=False, want_file_digest=False)
    record = off["signatures"][0]
    assert record["boundary"]["is_chunk"] is None
    assert record["accepted"] is True, "without the flag scan it cannot refuse"
    assert off["boundary_oracle"]["census"]["chain_scan_ran"] is False
    assert off["boundary_oracle"]["census"]["records_with_chaininfo"] is None
