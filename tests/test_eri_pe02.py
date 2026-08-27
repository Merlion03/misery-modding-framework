#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability PE-02 (research/
evidence/PE-01/README.md's own evidence track -- NOT a plan.md 8.2 "I-0N"
capability, see eri.py's own module docstring "WHAT PE-02 IS" section).

PE-02 gathers LIVE evidence for the PE-01 HYPOTHESIS that UObject::
ProcessEvent sits at C++ vtable slot 77 (byte offset 0x268): for a bounded
sample of I-04's OWN already-walked, already-validated objects, it reads
each object's OWN instance vtable pointer (object_ptr + 0x00 -- NOT the
same read as I-04's own _classify_object() check 3, which reads the vtable
at CLASS_PTR's own address; see _classify_processevent_vtable_candidate()'s
own docstring in eri.py), then the candidate function pointer stored at
that vtable's own slot, and tallies the resulting candidate addresses by
frequency AND by how many DISTINCT object classes observed each one. No
MISERY process runs in this environment (nor in CI), so every test below
exercises the plain-Python logic functions against a fake memory model --
the SAME "duck-typed narrow interface, faked in tests" idiom
tests/test_eri_i02.py/test_eri_i04.py/test_eri_i06.py already established,
cross-imported here rather than re-derived.

Run:  python -m pytest -q tests/test_eri_pe02.py
(plain stdlib ctypes -- this suite does NOT need
D:\\Tools\\venv-research\\Scripts\\python.exe.)
"""

from __future__ import annotations

import json
import os
import struct
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import eri as tool  # noqa: E402

# Cross-import from the I-01/I-02/I-03/I-04 test modules -- the established
# convention in this repo (test_eri_i06.py already does this for
# test_eri_i01/i02/i03/i04). Reuses VALID_BUILD_KEY/_patch_fake_win32api from
# test_eri_i01, MemoryFakeApi/BASE_ADDRESS/IMAGE_SIZE_BYTES/GUOBJECTARRAY_VA
# from test_eri_i02, make_fnamepool_memory from test_eri_i03, and
# obj_addr/make_i04_object_chunk_memory/_misery_five_class_fixture/
# _combined_i04_run_memory/_fake_i04_api from test_eri_i04, rather than
# re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402
import test_eri_i02 as i02_tests  # noqa: E402
import test_eri_i04 as i04_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY
BASE_ADDRESS = i02_tests.BASE_ADDRESS
IMAGE_SIZE_BYTES = i02_tests.IMAGE_SIZE_BYTES
MemoryFakeApi = i02_tests.MemoryFakeApi
GUOBJECTARRAY_VA = i02_tests.GUOBJECTARRAY_VA

SLOT = tool.DEFAULT_PROCESSEVENT_VTABLE_SLOT
SLOT_OFFSET = tool._vtable_slot_byte_offset(SLOT)


def _pack_ptr(address: int) -> bytes:
    return struct.pack("<Q", address)


def _obj_record(*, valid: bool = True, name_text: str | None = None,
                name_ok: bool = True, class_ptr: int | None = None,
                outer_ptr: int = 0, outer_ok: bool = True) -> dict:
    """Builds a dict shaped EXACTLY like _classify_object()'s own return
    value -- see that function's own docstring for the field meanings.
    PE-02's own functions never re-derive this dict themselves; they only
    ever consume one I-04's own walk_object_universe() already built. Tests
    below construct it directly (bypassing a real walk) so each scenario's
    class_ptr/name_ok/name_text can be controlled precisely.
    """
    return {
        "valid": valid, "rejection_kind": None, "rejection_reason": None,
        "name_text": name_text, "name_ok": name_ok,
        "class_ptr": class_ptr, "outer_ptr": outer_ptr, "outer_ok": outer_ok,
    }


# --------------------------------------------------------------------------- #
# a small synthetic universe: three "classes" (Alpha, Beta, Gamma), each with
# its own vtable; Alpha and Beta's own vtables agree on ONE dominant
# candidate at SLOT_OFFSET, Gamma's own vtable holds a DIFFERENT (minority)
# candidate. Two Alpha INSTANCES (proving distinct_class_count counts
# classes, not instances) and one each of Beta/Gamma.
# --------------------------------------------------------------------------- #

CLASS_ALPHA = BASE_ADDRESS + 0x02_0000_1000
CLASS_BETA = BASE_ADDRESS + 0x02_0000_2000
CLASS_GAMMA = BASE_ADDRESS + 0x02_0000_3000

OBJ_A1 = BASE_ADDRESS + 0x01_0000_1000
OBJ_A2 = BASE_ADDRESS + 0x01_0000_2000
OBJ_B1 = BASE_ADDRESS + 0x01_0000_3000
OBJ_C1 = BASE_ADDRESS + 0x01_0000_4000

VTABLE_ALPHA = BASE_ADDRESS + 0x1000
VTABLE_BETA = BASE_ADDRESS + 0x2000
VTABLE_GAMMA = BASE_ADDRESS + 0x3000

CANDIDATE_DOMINANT_VA = BASE_ADDRESS + 0x500000
CANDIDATE_MINORITY_VA = BASE_ADDRESS + 0x600000
CANDIDATE_OUT_OF_RANGE_VA = BASE_ADDRESS + IMAGE_SIZE_BYTES + 0x8000


def _dominant_multi_class_fixture():
    """Alpha (2 instances) and Beta (1 instance) both resolve to the SAME
    candidate RVA -- 3 instances, 2 distinct classes.
    """
    memory = {
        OBJ_A1: _pack_ptr(VTABLE_ALPHA),
        OBJ_A2: _pack_ptr(VTABLE_ALPHA),
        OBJ_B1: _pack_ptr(VTABLE_BETA),
        VTABLE_ALPHA + SLOT_OFFSET: _pack_ptr(CANDIDATE_DOMINANT_VA),
        VTABLE_BETA + SLOT_OFFSET: _pack_ptr(CANDIDATE_DOMINANT_VA),
    }
    objects_by_address = {
        CLASS_ALPHA: _obj_record(valid=False, name_text="Alpha", name_ok=True),
        CLASS_BETA: _obj_record(valid=False, name_text="Beta", name_ok=True),
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA),
        OBJ_A2: _obj_record(valid=True, name_text="AlphaInstance2", class_ptr=CLASS_ALPHA),
        OBJ_B1: _obj_record(valid=True, name_text="BetaInstance1", class_ptr=CLASS_BETA),
    }
    return memory, objects_by_address


def _with_minority_outlier(memory, objects_by_address):
    """Adds ONE Gamma instance whose own vtable resolves to a DIFFERENT
    candidate -- the minority outlier.
    """
    memory = dict(memory)
    objects_by_address = dict(objects_by_address)
    memory[OBJ_C1] = _pack_ptr(VTABLE_GAMMA)
    memory[VTABLE_GAMMA + SLOT_OFFSET] = _pack_ptr(CANDIDATE_MINORITY_VA)
    objects_by_address[CLASS_GAMMA] = _obj_record(
        valid=False, name_text="Gamma", name_ok=True)
    objects_by_address[OBJ_C1] = _obj_record(
        valid=True, name_text="GammaInstance1", class_ptr=CLASS_GAMMA)
    return memory, objects_by_address


# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

def test_default_processevent_vtable_slot_is_77():
    assert tool.DEFAULT_PROCESSEVENT_VTABLE_SLOT == 77


def test_default_pe02_vtable_sample_size():
    assert tool.DEFAULT_PE02_VTABLE_SAMPLE_SIZE == 500


def test_vtable_slot_byte_offset():
    assert tool._vtable_slot_byte_offset(77) == 0x268
    assert tool._vtable_slot_byte_offset(0) == 0
    assert tool._vtable_slot_byte_offset(76) == 0x260


# --------------------------------------------------------------------------- #
# _classify_processevent_vtable_candidate -- the per-object read+validate
# --------------------------------------------------------------------------- #

def test_classify_accepts_in_range_candidate():
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is True
    assert entry["rejection_kind"] is None
    assert entry["object_class_raw_name"] == "Alpha"
    assert entry["vtable_ptr_hex"] == "0x%x" % VTABLE_ALPHA
    assert entry["candidate_va_decimal"] == CANDIDATE_DOMINANT_VA
    assert entry["candidate_rva_decimal"] == CANDIDATE_DOMINANT_VA - BASE_ADDRESS
    assert entry["candidate_in_module_range"] is True


def test_classify_rejects_out_of_module_range_candidate():
    """The module-range plausibility check on the CANDIDATE: an aligned,
    non-null pointer that nonetheless resolves outside [base, base+size)
    is real DATA (recorded, VA/RVA both present), but 'accepted' is False
    and it is excluded from the aggregate tally.
    """
    memory = {
        OBJ_A1: _pack_ptr(VTABLE_ALPHA),
        VTABLE_ALPHA + SLOT_OFFSET: _pack_ptr(CANDIDATE_OUT_OF_RANGE_VA),
    }
    objects_by_address = {
        CLASS_ALPHA: _obj_record(valid=False, name_text="Alpha", name_ok=True),
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA),
    }
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "candidate_out_of_module_range"
    assert entry["candidate_va_decimal"] == CANDIDATE_OUT_OF_RANGE_VA
    assert entry["candidate_in_module_range"] is False


def test_classify_rejects_implausible_own_vtable_pointer():
    memory = {OBJ_A1: _pack_ptr(0)}  # null vtable pointer
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "vtable_pointer_implausible"
    assert entry["candidate_va_hex"] is None  # never reached the slot read


def test_classify_rejects_own_vtable_out_of_module_range():
    far_vtable = BASE_ADDRESS + IMAGE_SIZE_BYTES + 0x10000
    memory = {OBJ_A1: _pack_ptr(far_vtable)}
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "vtable_out_of_module_range"


def test_classify_own_vtable_read_failure_never_raises():
    api = MemoryFakeApi(memory={}, fail_read_addresses={OBJ_A1})
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "vtable_read_failure"


def test_classify_slot_read_failure_never_raises():
    memory = {OBJ_A1: _pack_ptr(VTABLE_ALPHA)}
    api = MemoryFakeApi(memory=memory, fail_read_addresses={VTABLE_ALPHA + SLOT_OFFSET})
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "slot_read_failure"
    assert entry["vtable_ptr_hex"] == "0x%x" % VTABLE_ALPHA  # already-read data kept


def test_classify_rejects_implausible_candidate_pointer():
    memory = {
        OBJ_A1: _pack_ptr(VTABLE_ALPHA),
        VTABLE_ALPHA + SLOT_OFFSET: _pack_ptr(0),  # null candidate
    }
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is False
    assert entry["rejection_kind"] == "candidate_pointer_implausible"
    assert entry["candidate_rva_hex"] is None


def test_classify_accepts_candidate_not_8_byte_aligned():
    """A REGRESSION test for a real bug caught and fixed before this
    capability's first live run: the candidate function pointer must NOT be
    checked with _pointer_is_plausible() (8-byte alignment, a real contract
    for HEAP-allocated data, never for a CODE address -- x86-64 has no
    alignment requirement for a CALL/JMP target, and MSVC does not guarantee
    every function entry point lands on an 8-byte boundary). A candidate
    landing on an odd/non-8-byte-aligned address, in-range and non-null,
    must still be ACCEPTED -- rejecting it here would risk manufacturing a
    false "slot 77 refuted" result from a mismatched check, not from real
    evidence.
    """
    odd_candidate = BASE_ADDRESS + 0x12345  # in range, deliberately not %8==0.
    assert odd_candidate % 8 != 0
    memory = {
        OBJ_A1: _pack_ptr(VTABLE_ALPHA),
        VTABLE_ALPHA + SLOT_OFFSET: _pack_ptr(odd_candidate),
    }
    objects_by_address = {
        OBJ_A1: _obj_record(valid=True, name_text="AlphaInstance1", class_ptr=CLASS_ALPHA)}
    api = MemoryFakeApi(memory=memory)
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, CLASS_ALPHA, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["accepted"] is True
    assert entry["rejection_kind"] is None
    assert entry["candidate_va_decimal"] == odd_candidate


def test_classify_owner_class_name_none_when_unresolvable():
    """class_ptr pointing at an address absent from objects_by_address (a
    dangling/unresolved reference) -- honestly None, never guessed.
    """
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory)
    dangling_class_ptr = BASE_ADDRESS + 0x09_0000_0000
    entry = tool._classify_processevent_vtable_candidate(
        api, 1, OBJ_A1, dangling_class_ptr, objects_by_address,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot_offset=SLOT_OFFSET)
    assert entry["object_class_raw_name"] is None
    assert entry["accepted"] is True  # unresolved class name never blocks acceptance


# --------------------------------------------------------------------------- #
# scan_processevent_vtable_candidates -- sampling + per-object loop
# --------------------------------------------------------------------------- #

def test_scan_samples_only_valid_objects_bounded_by_sample_size():
    memory, objects_by_address = _dominant_multi_class_fixture()
    # add an INVALID entry -- must never be sampled.
    objects_by_address[BASE_ADDRESS + 0x08_0000_0000] = _obj_record(valid=False)
    api = MemoryFakeApi(memory=memory)
    result = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=2)
    assert result["valid_objects_available"] == 3  # A1, A2, B1
    assert result["sample_size_used"] == 2  # bounded by sample_size
    assert len(result["objects"]) == 2


def test_scan_uses_all_valid_objects_when_fewer_than_sample_size():
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory)
    result = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    assert result["valid_objects_available"] == 3
    assert result["sample_size_used"] == 3  # never an error, just "use all"
    assert result["accepted_count"] == 3


def test_scan_zero_valid_objects_reports_zero_samples_not_an_error():
    api = MemoryFakeApi(memory={})
    result = tool.scan_processevent_vtable_candidates(
        api, 1, {}, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        vtable_slot=SLOT, sample_size=500)
    assert result["valid_objects_available"] == 0
    assert result["sample_size_used"] == 0
    assert result["objects"] == []
    assert result["accepted_count"] == 0
    assert result["rejected_counts"] == {}


def test_scan_read_failure_on_one_object_does_not_abort_the_scan():
    """The torn-read precedent: a read failure on ONE already-located,
    already-validated (I-04 'valid': True) object is a counted rejection,
    never propagated, and scanning continues to every other sampled object.
    """
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory, fail_read_addresses={OBJ_A2})
    result = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    assert result["sample_size_used"] == 3  # all three still attempted
    assert result["accepted_count"] == 2  # A1, B1 succeed
    assert result["rejected_counts"] == {"vtable_read_failure": 1}
    by_addr = {e["object_address_hex"]: e for e in result["objects"]}
    assert by_addr["0x%x" % OBJ_A2]["rejection_kind"] == "vtable_read_failure"
    assert by_addr["0x%x" % OBJ_A2]["accepted"] is False


# --------------------------------------------------------------------------- #
# aggregate_processevent_vtable_candidates -- pure tally
# --------------------------------------------------------------------------- #

def test_aggregate_dominant_candidate_across_all_objects():
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory)
    scan = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    aggregate = tool.aggregate_processevent_vtable_candidates(scan["objects"])
    assert len(aggregate["candidate_tally"]) == 1
    top = aggregate["top_candidate"]
    assert top["instance_count"] == 3
    assert top["candidate_rva_decimal"] == CANDIDATE_DOMINANT_VA - BASE_ADDRESS
    assert aggregate["minority_candidates"] == []


def test_aggregate_distinct_class_count_is_per_class_not_per_instance():
    """The critical assertion this whole capability exists to get right:
    3 INSTANCES (2 Alpha + 1 Beta) but only 2 DISTINCT CLASSES observed the
    dominant candidate -- distinct_class_count must be 2, not 3.
    """
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory)
    scan = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    aggregate = tool.aggregate_processevent_vtable_candidates(scan["objects"])
    top = aggregate["top_candidate"]
    assert top["instance_count"] == 3
    assert top["distinct_class_count"] == 2
    assert top["class_names"] == ["Alpha", "Beta"]


def test_aggregate_minority_outlier_under_a_different_class():
    memory, objects_by_address = _with_minority_outlier(*_dominant_multi_class_fixture())
    api = MemoryFakeApi(memory=memory)
    scan = tool.scan_processevent_vtable_candidates(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    aggregate = tool.aggregate_processevent_vtable_candidates(scan["objects"])
    assert len(aggregate["candidate_tally"]) == 2
    top = aggregate["top_candidate"]
    assert top["instance_count"] == 3
    assert top["candidate_rva_decimal"] == CANDIDATE_DOMINANT_VA - BASE_ADDRESS
    minority = aggregate["minority_candidates"]
    assert len(minority) == 1
    assert minority[0]["instance_count"] == 1
    assert minority[0]["distinct_class_count"] == 1
    assert minority[0]["class_names"] == ["Gamma"]
    assert minority[0]["candidate_rva_decimal"] == CANDIDATE_MINORITY_VA - BASE_ADDRESS
    # the dominant candidate must never absorb the outlier's own instance.
    assert minority[0]["candidate_rva_decimal"] != top["candidate_rva_decimal"]


def test_aggregate_unresolved_class_name_tracked_separately():
    entry_known = {
        "accepted": True, "candidate_rva_decimal": 0x1000,
        "candidate_rva_hex": "0x1000", "object_class_raw_name": "Alpha"}
    entry_unknown = {
        "accepted": True, "candidate_rva_decimal": 0x1000,
        "candidate_rva_hex": "0x1000", "object_class_raw_name": None}
    aggregate = tool.aggregate_processevent_vtable_candidates(
        [entry_known, entry_unknown])
    top = aggregate["top_candidate"]
    assert top["instance_count"] == 2
    assert top["distinct_class_count"] == 1  # None never counted as a class
    assert top["unresolved_class_instance_count"] == 1


def test_aggregate_rejected_entries_excluded_from_tally():
    entries = [
        {"accepted": True, "candidate_rva_decimal": 0x1000,
         "candidate_rva_hex": "0x1000", "object_class_raw_name": "Alpha"},
        {"accepted": False, "candidate_rva_decimal": None,
         "candidate_rva_hex": None, "object_class_raw_name": "Beta"},
    ]
    aggregate = tool.aggregate_processevent_vtable_candidates(entries)
    assert len(aggregate["candidate_tally"]) == 1
    assert aggregate["top_candidate"]["instance_count"] == 1


def test_aggregate_empty_objects_list():
    aggregate = tool.aggregate_processevent_vtable_candidates([])
    assert aggregate["candidate_tally"] == []
    assert aggregate["top_candidate"] is None
    assert aggregate["minority_candidates"] == []


# --------------------------------------------------------------------------- #
# run_pe02_vtable_scan -- the whole capability, scan + aggregate wired
# --------------------------------------------------------------------------- #

def test_run_pe02_vtable_scan_wires_scan_and_aggregate():
    memory, objects_by_address = _with_minority_outlier(*_dominant_multi_class_fixture())
    api = MemoryFakeApi(memory=memory)
    result = tool.run_pe02_vtable_scan(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    assert result["vtable_slot"] == SLOT
    assert result["vtable_slot_offset_hex"] == "0x%x" % SLOT_OFFSET
    assert result["sample_size_used"] == 4
    assert result["accepted_count"] == 4
    assert result["top_candidate"]["distinct_class_count"] == 2
    assert len(result["minority_candidates"]) == 1
    assert isinstance(result["note"], str) and result["note"]  # never blank


def test_run_pe02_vtable_scan_never_raises_on_torn_reads():
    memory, objects_by_address = _dominant_multi_class_fixture()
    api = MemoryFakeApi(memory=memory, fail_read_addresses={OBJ_A2})
    result = tool.run_pe02_vtable_scan(
        api, 1, objects_by_address, base_address=BASE_ADDRESS,
        image_size_bytes=IMAGE_SIZE_BYTES, vtable_slot=SLOT, sample_size=500)
    assert result["rejected_counts"] == {"vtable_read_failure": 1}
    assert result["accepted_count"] == 2


# --------------------------------------------------------------------------- #
# build_pe02_document -- raw output, no evidence envelope
# --------------------------------------------------------------------------- #

def test_build_pe02_document_shape():
    result = {
        "vtable_slot": 77, "vtable_slot_offset_hex": "0x268",
        "sample_size_requested": 500, "valid_objects_available": 3,
        "sample_size_used": 3, "accepted_count": 3, "rejected_counts": {},
        "objects": [], "candidate_tally": [], "top_candidate": None,
        "minority_candidates": [], "note": "raw data only",
    }
    doc = tool.build_pe02_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["capability"] == "PE-02"
    assert doc["vtable_slot"] == 77
    assert doc["sample_size_used"] == 3
    for marker_key in ("evidence_level", "claim_type", "oracle", "confidence"):
        assert marker_key not in doc
    json.loads(tool.dump_json(doc))  # round-trips as JSON


# --------------------------------------------------------------------------- #
# CLI argument parsing / requirement validation / output-path resolution
# --------------------------------------------------------------------------- #

def test_cli_run_pe02_vtable_scan_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_pe02_vtable_scan is False
    assert args.processevent_vtable_slot is None
    assert args.pe02_vtable_sample_size == tool.DEFAULT_PE02_VTABLE_SAMPLE_SIZE
    assert args.pe02_out is None


def test_parse_processevent_vtable_slot_default_and_override():
    assert tool._parse_processevent_vtable_slot(None) == tool.DEFAULT_PROCESSEVENT_VTABLE_SLOT
    assert tool._parse_processevent_vtable_slot("76") == 76
    assert tool._parse_processevent_vtable_slot("0x4d") == 0x4d
    with pytest.raises(ValueError):
        tool._parse_processevent_vtable_slot("garbage")


def test_resolve_pe02_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_pe02_output_path(args) is None


def test_resolve_pe02_output_path_explicit():
    args = tool.build_arg_parser().parse_args(
        ["--run-pe02-vtable-scan", "--pe02-out", "custom-pe02.json"])
    assert tool._resolve_pe02_output_path(args) == "custom-pe02.json"


def test_resolve_pe02_output_path_via_run_dir():
    args = tool.build_arg_parser().parse_args(
        ["--run-pe02-vtable-scan", "--run-dir", "some/run/dir"])
    assert tool._resolve_pe02_output_path(args) == os.path.join(
        "some/run/dir", "pe02-vtable-scan.json")


def test_resolve_pe02_output_path_raises_without_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-pe02-vtable-scan"])
    with pytest.raises(ValueError, match="--pe02-out"):
        tool._resolve_pe02_output_path(args)


def test_validate_pe02_requirements_noop_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    tool._validate_pe02_requirements(args)  # must not raise


def test_validate_pe02_requirements_raises_without_run_i04():
    args = tool.build_arg_parser().parse_args(["--run-pe02-vtable-scan"])
    with pytest.raises(ValueError, match="--run-i04"):
        tool._validate_pe02_requirements(args)


def test_validate_pe02_requirements_passes_when_run_i04_given():
    args = tool.build_arg_parser().parse_args(
        ["--run-pe02-vtable-scan", "--run-i04"])
    tool._validate_pe02_requirements(args)  # must not raise


# --------------------------------------------------------------------------- #
# main() end-to-end -- writes pe02-vtable-scan.json, never touches
# manifest.json's own capabilities_enabled (PE-02 is not a valid
# eri_capability_id per instrument-run-manifest.schema.json's closed enum).
# --------------------------------------------------------------------------- #

def test_main_run_pe02_writes_raw_json_document(tmp_path, monkeypatch):
    entries, entries_text, misery_names = i04_tests._misery_five_class_fixture()
    memory = i04_tests._combined_i04_run_memory(entries, entries_text)
    # Every 'valid' object in this fixture shares ONE vtable pointer
    # (i04_tests.VALID_VTABLE_ADDR, since none of _misery_five_class_
    # fixture()'s own entries set a custom 'vtable' kind) -- so ONE extra
    # memory entry at that shared vtable's own slot is enough to give every
    # sampled object the SAME candidate, an honest (if class-homogeneous,
    # since every one of them is a direct instance of the native "Class"
    # metaclass) end-to-end smoke test of main()'s own wiring.
    candidate_va = BASE_ADDRESS + 0x300000
    memory[i04_tests.VALID_VTABLE_ADDR + SLOT_OFFSET] = _pack_ptr(candidate_va)
    api, _ = i04_tests._fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04",
        "--run-pe02-vtable-scan",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "pe02-vtable-scan.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "PE-02"
    assert doc["vtable_slot"] == tool.DEFAULT_PROCESSEVENT_VTABLE_SLOT
    assert doc["sample_size_used"] == 7  # Class, BlueprintGeneratedClass, 5 Misery classes
    assert doc["accepted_count"] == 7
    top = doc["top_candidate"]
    assert top is not None
    assert top["candidate_rva_decimal"] == candidate_va - BASE_ADDRESS
    assert top["instance_count"] == 7
    assert doc["minority_candidates"] == []
    for marker_key in ("evidence_level", "claim_type", "oracle", "confidence"):
        assert marker_key not in doc

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    # "PE-02" must NEVER appear here -- instrument-run-manifest.schema.json's
    # own eri_capability_id enum is closed to "I-01".."I-16".
    assert "PE-02" not in manifest["capabilities_enabled"]
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03", "I-04"]
    assert any(a.endswith("pe02-vtable-scan.json") for a in manifest["artifacts"])


def test_main_run_pe02_requires_run_i04(tmp_path, monkeypatch):
    api, _ = i04_tests._fake_i04_api(tmp_path, memory={})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-pe02-vtable-scan"])
    assert rc == 2
    assert not os.path.exists(run_dir)  # all-or-nothing: nothing written
    assert api.calls["open_process"] == 0


def test_main_without_run_pe02_never_touches_pe02_at_all(tmp_path, monkeypatch):
    entries, entries_text, _ = i04_tests._misery_five_class_fixture()
    memory = i04_tests._combined_i04_run_memory(entries, entries_text)
    api, _ = i04_tests._fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0
    assert not os.path.exists(os.path.join(run_dir, "pe02-vtable-scan.json"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03", "I-04"]
    assert not any(a.endswith("pe02-vtable-scan.json") for a in manifest["artifacts"])


# --------------------------------------------------------------------------- #
# still exactly one ReadProcessMemory/OpenProcess call site -- PE-02 adds
# new CALLERS of Win32Api.read_process_memory (via the existing _read_u64()
# helper, reused verbatim), never a second wrapper, and opens no handle of
# its own at all.
# --------------------------------------------------------------------------- #

def test_source_still_has_exactly_one_readprocessmemory_call_site():
    source = open(tool.__file__, encoding="utf-8").read()
    assert source.count(".ReadProcessMemory(") == 1, (
        "eri.py must call ReadProcessMemory from exactly one place -- "
        "Win32Api.read_process_memory -- so a reviewer can audit it by "
        "reading one line")


def test_source_still_has_exactly_one_openprocess_call_site():
    source = open(tool.__file__, encoding="utf-8").read()
    assert source.count(".OpenProcess(") == 1, (
        "eri.py must call OpenProcess from exactly one place -- "
        "Win32Api.open_process -- so a reviewer can audit it by reading "
        "one line")
