#!/usr/bin/env python3
"""Tests for tools/static/vtable_scan.py (task S-09).

This file exists because the tool did not have one. It was written in a run that
died before executing it, and its first execution -- against a real DLL -- raised
``TypeError`` inside the whole-file digest, because ``pe_info.PEImage.iter_chunks``
yields ``(offset, memoryview)`` pairs and the digest fed the pair to
``hashlib.update``. That defect was on the ONE path a synthetic-image test would
have covered in a line, so the regression test for it is the first test below and
it asserts the digest against an independent computation rather than against
itself.

Inputs are SYNTHETIC PE images assembled byte by byte, reusing
``tests/test_rtti_scan.py``'s ``RttiImageBuilder`` -- imported, not copied, so
there is one definition in this suite of "an image with a known RTTI graph in
it". That builder emits a locator immediately in front of every vtable, which is
exactly what the RTTI split under test needs: the ground truth for "how many
candidates carry a locator" is the number of classes the test asked for.

The synthetic images carry no base-relocation table, so the tests run the scan
with ``use_relocation_filter=False``. That is a documented mode of the tool
(``--no-relocation-filter``), not a workaround: it is the run definition
``rtti_scan.py``'s internal census uses, and it is the definition the cross-check
compares against.

No test reads a game file (D-01).

Coverage:
  * the whole-file digest, against an independent hashlib computation
  * the RTTI split: the two sides partition the population, per tier as well
  * the subpopulation shape: contiguous runs, slot sharing, function starts
  * the cross-link between named and unnamed candidates
  * the mechanical cross-check against an rtti_scan.py document, including the
    case where it disagrees
  * class-P literal reads, their re-read attestation, and the 0.99 ceiling
  * determinism and the JSONL artifact
"""

from __future__ import annotations

import hashlib
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

import rtti_scan  # noqa: E402
import vtable_scan  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402
from test_rtti_scan import RttiImageBuilder  # noqa: E402

VTABLE_SCAN_PATH = os.path.join(REPO_ROOT, "tools", "static", "vtable_scan.py")

IMAGE_BASE = 0x140000000
RDATA_FLAGS = 0x40000040
DATA_FLAGS = 0xC0000040
TEXT_FLAGS = 0x60000020


def _scan(path: str, **kwargs) -> dict:
    """The scan as these tests run it: no relocation filter, no digest surprises."""
    options = {
        "use_relocation_filter": False,
        "want_source_paths": False,
        "want_file_digest": True,
    }
    options.update(kwargs)
    return vtable_scan.analyze(path, **options)


@pytest.fixture()
def rtti_image(tmp_path):
    """Three classes, three locators, three vtables with known slot counts."""
    builder = RttiImageBuilder()
    builder.add_class(".?AVBase@@", vtable_slots=2)
    builder.add_class(".?AVDerived@@", bases=(".?AVBase@@",), vtable_slots=5)
    builder.add_class(".?AVThird@@", bases=(".?AVBase@@",), vtable_slots=3)
    blob, expected = builder.build()
    path = write_image(tmp_path, "rtti.exe", blob)
    return path, expected


# --------------------------------------------------------------------------- #
# 1. the digest -- the regression test for the defect the first run found
# --------------------------------------------------------------------------- #

def test_the_whole_file_digest_matches_an_independent_computation(rtti_image):
    """_sha256 must stream iter_chunks correctly, which it did not.

    Asserted against hashlib over the file read in one go -- a computation that
    shares no code with the tool -- because a digest compared against itself
    would have passed while the tool was raising TypeError on every real input.
    """
    path, _expected = rtti_image
    document = _scan(path)
    with open(path, "rb") as handle:
        expected = hashlib.sha256(handle.read()).hexdigest()
    assert document["file"]["sha256"] == expected


def test_the_digest_can_be_skipped_without_breaking_the_document(rtti_image):
    path, _expected = rtti_image
    document = _scan(path, want_file_digest=False)
    assert document["file"]["sha256"] is None
    assert document["candidates_total"] >= 3


# --------------------------------------------------------------------------- #
# 2. the RTTI split
# --------------------------------------------------------------------------- #

def test_the_split_partitions_the_population(rtti_image):
    """Every candidate is on exactly one side. A count that drifts is a bug."""
    path, _expected = rtti_image
    document = _scan(path)
    split = document["statistics"]["rtti_split"]
    with_rtti = split["with_an_rtti_locator"]["candidates"]
    without = split["without_an_rtti_locator"]["candidates"]
    assert with_rtti + without == document["candidates_total"]
    assert with_rtti == document["summary"][
        "candidates_with_an_rtti_complete_object_locator"]
    assert without == document["summary"][
        "candidates_without_an_rtti_complete_object_locator"]


def test_the_split_finds_every_planted_locator(rtti_image):
    """Ground truth: the builder put a locator in front of all three vtables."""
    path, expected = rtti_image
    document = _scan(path)
    split = document["statistics"]["rtti_split"]
    assert split["with_an_rtti_locator"]["candidates"] == len(expected["classes"])


def test_the_split_is_reported_per_tier_and_the_tiers_agree(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    split = document["statistics"]["rtti_split"]
    for side in ("with_an_rtti_locator", "without_an_rtti_locator"):
        per_tier = sum(split["by_tier"][tier][side]["candidates"]
                       for tier in vtable_scan.TIER_ORDER)
        assert per_tier == split[side]["candidates"], side


def test_the_split_slot_totals_add_up(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    split = document["statistics"]["rtti_split"]
    total = (split["with_an_rtti_locator"]["slot_total"]
             + split["without_an_rtti_locator"]["slot_total"])
    assert total == document["statistics"]["totals"]["slot_total"]


def test_the_named_side_slot_counts_match_the_planted_ones(rtti_image):
    path, expected = rtti_image
    document = _scan(path)
    planted = sorted(record["vtable_slots"] for record in expected["classes"])
    split = document["statistics"]["rtti_split"]["with_an_rtti_locator"]
    assert split["slot_count_min"] == planted[0]
    assert split["slot_count_max"] == planted[-1]
    assert split["slot_total"] == sum(planted)


# --------------------------------------------------------------------------- #
# 3. the subpopulation shape, on ground truth this test lays out by hand
# --------------------------------------------------------------------------- #

class _Functions:
    """A stand-in for FunctionIndex: whatever the test says is a function start."""

    def __init__(self, starts=()) -> None:
        self._starts = set(starts)

    def is_start(self, rva: int) -> bool:
        return rva in self._starts


def _row(rva: int, slots: int, targets: list[int], tier=vtable_scan.TIER_STORED,
         locator=None) -> dict:
    return {"vtable_rva": rva, "slot_count": slots, "slot_target_rvas": targets,
            "tier": tier, "rtti_locator_rva": locator}


def test_contiguous_runs_are_counted_by_adjacency_not_by_proximity():
    """Two candidates are one run only when the second starts where the first ends."""
    rows = [
        _row(0x1000, 2, [1, 2]),          # occupies 0x1000..0x1010
        _row(0x1010, 2, [3, 4]),          # exactly adjacent -> same run
        _row(0x1030, 1, [5]),             # a 16-byte gap -> a new run
    ]
    shape = vtable_scan._subpopulation_shape(rows, _Functions(), 8)
    assert shape["candidates"] == 3
    assert shape["contiguous_runs"] == 2
    assert shape["largest_contiguous_run"] == 2
    assert shape["candidates_in_a_contiguous_run_of_2_or_more"] == 2


def test_slot_target_sharing_counts_targets_not_candidates():
    rows = [
        _row(0x1000, 2, [0xAAA, 0xBBB]),
        _row(0x1010, 2, [0xAAA, 0xCCC]),
    ]
    shape = vtable_scan._subpopulation_shape(rows, _Functions(), 8)
    assert shape["distinct_slot_targets"] == 3
    assert shape["slot_targets_shared_within_this_subpopulation"] == 1
    assert shape["share_of_targets_that_are_shared"] == round(1 / 3, 4)


def test_a_repeated_target_within_one_candidate_is_not_sharing():
    """One vtable naming the same function twice is not two vtables sharing it."""
    rows = [_row(0x1000, 3, [0xAAA, 0xAAA, 0xAAA])]
    shape = vtable_scan._subpopulation_shape(rows, _Functions(), 8)
    assert shape["distinct_slot_targets"] == 1
    assert shape["slot_targets_shared_within_this_subpopulation"] == 0


def test_function_start_share_is_over_slots_not_over_targets():
    rows = [_row(0x1000, 3, [0xAAA, 0xAAA, 0xBBB])]
    shape = vtable_scan._subpopulation_shape(rows, _Functions([0xAAA]), 8)
    assert shape["slot_total"] == 3
    assert shape["slot_targets_at_a_function_start"] == 2
    assert shape["share_of_slots_at_a_function_start"] == round(2 / 3, 4)


def test_an_empty_subpopulation_reports_none_not_zero():
    """A rate over no candidates is unknown, not nought."""
    shape = vtable_scan._subpopulation_shape([], _Functions(), 8)
    assert shape["candidates"] == 0
    assert shape["slot_count_min"] is None
    assert shape["share_of_targets_that_are_shared"] is None
    assert shape["largest_contiguous_run"] is None


def test_the_cross_link_counts_unnamed_candidates_sharing_a_named_target():
    named = _row(0x1000, 2, [0xAAA, 0xBBB], locator=0x900)
    sharing = _row(0x2000, 1, [0xAAA])
    unrelated = _row(0x3000, 1, [0xFFF])
    split = vtable_scan.characterise_rtti_split(
        [named, sharing, unrelated], _Functions(), 8)
    link = split["cross_link"]
    assert link[
        "candidates_without_a_locator_sharing_a_slot_target_with_a_named_vtable"] == 1
    assert link["distinct_shared_targets"] == 1
    assert link["share_of_the_no_locator_population"] == 0.5


def test_the_cross_link_is_labelled_as_an_upper_bound():
    """The number is nearly all shared thunks, and the document has to say so."""
    split = vtable_scan.characterise_rtti_split(
        [_row(0x1000, 1, [0xAAA], locator=0x900)], _Functions(), 8)
    assert "upper bound" in split["cross_link"]["what_it_means"]


def test_the_split_states_what_the_comparison_cannot_show():
    split = vtable_scan.characterise_rtti_split([], _Functions(), 8)
    note = split["what_the_comparison_can_and_cannot_show"]
    assert "is not evidence of being one" in note


# --------------------------------------------------------------------------- #
# 4. the mechanical cross-check against an rtti_scan.py document
# --------------------------------------------------------------------------- #

def _rtti_document(path: str, tmp_path, name: str = "rtti.json") -> str:
    """Run the real rtti_scan.py over the same image and write its document."""
    document = rtti_scan.analyze(path, want_vtable_census=True)
    out = os.path.join(str(tmp_path), name)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(rtti_scan.dump_json(document))
    return out


def test_the_two_tools_agree_on_every_rtti_reachable_vtable(rtti_image, tmp_path):
    """The whole point of having built S-09 separately from S-10.

    If these recalls are not 1.0 with 0 slot-count disagreements on an image
    whose RTTI graph the test laid out itself, then one of the two tools is wrong
    and finding out which is the value of the comparison.
    """
    path, expected = rtti_image
    rtti_path = _rtti_document(path, tmp_path)
    document = _scan(path, rtti_json=rtti_path)
    check = document["cross_check"]
    assert check["readable"] is True
    known = check["known_vtables"]
    assert known["in_the_rtti_artifact"] == len(expected["classes"])
    assert known["recovered_as_a_candidate"] == known["in_the_rtti_artifact"]
    assert known["recall"] == 1.0
    assert known["slot_count_disagreements"] == 0
    assert known["not_recovered"] == []


def test_the_unfiltered_census_agrees_between_the_two_tools(rtti_image, tmp_path):
    path, _expected = rtti_image
    rtti_path = _rtti_document(path, tmp_path)
    document = _scan(path, rtti_json=rtti_path)
    census = document["cross_check"]["census"]
    assert census["comparison_is_valid_only_if_the_sections_match"] is True
    assert census["their_slots"] == census["my_slots"]
    assert census["slots_agree"] is True
    assert census["runs_agree"] is True


def test_the_locator_count_agrees_from_both_directions(rtti_image, tmp_path):
    """S-09 reaches the locator from the vtable; S-10 reaches it from the name."""
    path, expected = rtti_image
    rtti_path = _rtti_document(path, tmp_path)
    document = _scan(path, rtti_json=rtti_path)
    count = document["cross_check"]["independent_rtti_locator_count"]
    assert count["found_from_the_vtable_side"] == len(expected["classes"])
    assert count["found_by_rtti_scan_from_the_name_side"] == \
        len(expected["classes"])
    assert count["agree"] is True


def test_a_disagreement_is_reported_and_not_smoothed_over(rtti_image, tmp_path):
    """Corrupt the artifact's slot count; the cross-check must notice.

    A comparison that could only ever report agreement would be decoration, so
    this test makes it fail on purpose.
    """
    path, expected = rtti_image
    rtti_path = _rtti_document(path, tmp_path)
    with open(rtti_path, "r", encoding="utf-8") as handle:
        artifact = json.load(handle)
    changed = 0
    for row in artifact["classes"]:
        vtable = row.get("vtable") or {}
        if vtable.get("vtable_rva") is not None:
            vtable["code_slot_count"] = (vtable.get("code_slot_count") or 0) + 7
            changed += 1
    assert changed, "the artifact carried no vtable to corrupt"
    with open(rtti_path, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle)
    document = _scan(path, rtti_json=rtti_path)
    known = document["cross_check"]["known_vtables"]
    assert known["slot_count_disagreements"] == changed
    assert known["slot_count_disagreement_examples"]
    assert document["summary"]["cross_check_slot_count_disagreements"] == changed


def test_an_unreadable_artifact_is_a_warning_not_a_crash(rtti_image, tmp_path):
    path, _expected = rtti_image
    broken = os.path.join(str(tmp_path), "broken.json")
    with open(broken, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    document = _scan(path, rtti_json=broken)
    assert document["cross_check"]["readable"] is False
    assert any("could not be read" in w for w in document["warnings"])


def test_without_an_artifact_the_crosscheck_is_absent_not_invented(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    assert not document["cross_check"]
    # The key is ABSENT rather than null: a summary that carried recall=None
    # would read as "measured, and the answer is nothing", and this run did not
    # measure it at all.
    assert "cross_check_recall" not in document["summary"]


# --------------------------------------------------------------------------- #
# 5. the evidence layers
# --------------------------------------------------------------------------- #

def test_literal_reads_state_offset_and_length_and_nothing_else(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    assert document["literal_reads"]
    for read in document["literal_reads"]:
        evidence = read["evidence"]
        assert evidence["claim_class"] == "P"
        assert evidence["evidence_level"] == "OBSERVED"
        assert evidence["oracle"] == ["binary-analysis"]
        note = evidence["note"]
        assert "at offset %d" % read["offset"] in note
        lowered = note.lower()
        for forbidden in ("vtable", "struct", "field", "layout", "signature"):
            assert forbidden not in lowered, (forbidden, note)


def test_literal_reads_are_actually_re_read_and_match_the_file(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    assert document["summary"]["literal_reads_reproduced"] is True
    with open(path, "rb") as handle:
        for read in document["literal_reads"]:
            assert read["reproduced"] is True
            handle.seek(read["offset"])
            assert handle.read(read["length"]).hex() == read["bytes_hex"]


def test_no_confidence_anywhere_reaches_one(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    found: list[float] = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "confidence" and isinstance(value, (int, float)):
                    found.append(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(vtable_scan.public_document(document))
    assert found
    assert max(found) <= 0.99


def test_the_refutation_probes_all_state_what_would_refute_them(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    assert document["refutation_probes"]
    for probe in document["refutation_probes"]:
        assert probe.get("probe")
        # Every probe must name the outcome that would break the conclusion it
        # guards. Some carry the finding under `result`, some under `verdict`,
        # and one (the positional premise) reports only whether the decisive
        # test was available at all -- but `what_would_refute` is mandatory,
        # because a probe that does not say what would refute it is not a probe.
        assert probe.get("what_would_refute"), probe["probe"]


# --------------------------------------------------------------------------- #
# 6. determinism, artifacts, CLI
# --------------------------------------------------------------------------- #

def test_two_runs_agree_except_for_the_clock(rtti_image):
    path, _expected = rtti_image
    volatile = ("generated_at", "timings_seconds")

    def scrub(node):
        if isinstance(node, dict):
            return {key: scrub(value) for key, value in node.items()
                    if key not in volatile and not key.startswith("_")}
        if isinstance(node, list):
            return [scrub(item) for item in node]
        return node

    first = scrub(vtable_scan.public_document(_scan(path)))
    second = scrub(vtable_scan.public_document(_scan(path)))
    assert vtable_scan.dump_json(first) == vtable_scan.dump_json(second)


def test_the_jsonl_artifact_carries_the_rtti_flag_per_row(rtti_image):
    path, _expected = rtti_image
    document = _scan(path)
    lines = vtable_scan.jsonl_lines(document, vtable_scan.TIER_ORDER, 1)
    assert lines
    rows = [json.loads(line) for line in lines]
    assert any(row["rtti_locator_rva"] is not None for row in rows)
    for row in rows:
        assert row["build_target"]
        assert row["tier"] in vtable_scan.TIER_ORDER


def test_cli_prints_the_split_and_writes_its_artifacts(rtti_image, tmp_path):
    path, _expected = rtti_image
    out = os.path.join(str(tmp_path), "doc.json")
    jsonl = os.path.join(str(tmp_path), "rows.jsonl")
    result = subprocess.run(
        [sys.executable, VTABLE_SCAN_PATH, path, "--no-relocation-filter",
         "--no-source-paths", "--tiers", "all", "--out", out,
         "--jsonl-out", jsonl],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "The population WITHOUT an RTTI locator, against the one with" \
        in result.stdout
    assert os.path.isfile(out) and os.path.isfile(jsonl)
    with open(out, "r", encoding="utf-8") as handle:
        assert json.load(handle)["task"] == "S-09"


def test_the_contiguity_confound_is_stated_in_the_document(rtti_image):
    """The split must not let contiguity be read as a discriminator.

    A candidate spans its slots only, and an RTTI-bearing vtable always has its
    locator pointer in the slot before it, so two of them can never be adjacent
    under this definition -- the locator-bearing side is pinned to a largest run
    of 1 by construction. Asserted here because a caveat that is only in a
    comment is a caveat the document does not carry.
    """
    path, _expected = rtti_image
    document = _scan(path)
    split = document["statistics"]["rtti_split"]
    note = split["contiguity_is_confounded_across_this_split"]
    assert "artefact of the definition" in note
    assert split["with_an_rtti_locator"]["largest_contiguous_run"] == 1
