#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-05 (plan.md 8.2).

I-05 is the UFunction decoder: for every proof-set class (the SAME
select_i06_proof_set() output I-06 already uses, reused verbatim), it walks
UClass::Children/UField::Next (a NEW linked list this capability introduces,
DIFFERENT from ChildProperties/FField::Next) to find which children are
UFunction instances (identified by an exact ClassPrivate == the live
"Function" meta-class address check), then decodes each UFunction's own
FunctionFlags/NumParms/ParmsSize/ReturnValueOffset and walks ITS OWN
UStruct::ChildProperties (a UFunction's own parameters) via I-06's OWN
decode_property_type()/walk_property_chain(), completely unchanged. See
eri.py's own module docstring, "WHAT I-05 IS", for the full algorithm, the
two already-corrected I-06 offset bugs this capability was designed to stay
skeptical of, and the MANDATORY EMPIRICAL SELF-CHECK (NumParms vs the number
of accepted ChildProperties-chain entries) this capability builds in for its
own newly-introduced, not-yet-live-verified UStruct-total-size offset
(USTRUCT_TOTAL_SIZE_SHIPPING).

No MISERY process runs in this environment (nor in CI), so every test below
exercises the plain-Python logic functions against a fake memory model --
the SAME "duck-typed narrow interface, faked in tests" idiom
tests/test_eri_i02.py/test_eri_i03.py/test_eri_i04.py/test_eri_i06.py already
established, cross-imported here rather than re-derived.

Run:  python -m pytest -q tests/test_eri_i05.py
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

# Cross-import from the I-01/I-02/I-03/I-04/I-06 test modules -- the
# established convention in this repo (test_eri_i06.py already does this for
# test_eri_i01/i02/i03/i04). Reuses VALID_BUILD_KEY/_write_stub_exe/
# _patch_fake_win32api/_load_schema/_build_registry from test_eri_i01,
# MemoryFakeApi/BASE_ADDRESS/IMAGE_SIZE_BYTES/GUOBJECTARRAY_VA from
# test_eri_i02, make_fnamepool_memory/NAMEPOOL_VA from test_eri_i03,
# obj_addr/make_i04_object_chunk_memory/_misery_five_class_fixture/
# _fake_i04_api from test_eri_i04, and the FFieldClass/FField test registry
# (build_fieldclass_registry/write_fproperty/uobject_owner/field_addr/
# _NameAllocator) from test_eri_i06, rather than re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402
import test_eri_i02 as i02_tests  # noqa: E402
import test_eri_i03 as i03_tests  # noqa: E402
import test_eri_i04 as i04_tests  # noqa: E402
import test_eri_i06 as i06_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY
MemoryFakeApi = i02_tests.MemoryFakeApi
GUOBJECTARRAY_VA = i02_tests.GUOBJECTARRAY_VA

NAMEPOOL_VA = i03_tests.NAMEPOOL_VA
make_fnamepool_memory = i03_tests.make_fnamepool_memory

_NameAllocator = i06_tests._NameAllocator
build_fieldclass_registry = i06_tests.build_fieldclass_registry
write_fproperty = i06_tests.write_fproperty
uobject_owner = i06_tests.uobject_owner
field_addr = i06_tests.field_addr


# --------------------------------------------------------------------------- #
# fake-memory helpers -- a UField/UFunction object's own bytes, covering
# BOTH the UObjectBase-shaped fields I-04 already established
# (ClassPrivate/NamePrivate/OuterPrivate, reused unchanged) and UField::Next
# (this capability's own new offset), plus -- for a UFunction specifically --
# its own FunctionFlags/NumParms/ParmsSize/ReturnValueOffset. ONE contiguous
# blob per node, matching test_eri_i06.py's own write_fproperty() convention.
# --------------------------------------------------------------------------- #

UFIELD_BASE = 0xB000_0000_0000
UFIELD_STRIDE = 0x200
UFUNCTION_BLOB_SIZE = tool.UFUNCTION_RETURN_VALUE_OFFSET_OFFSET + 2  # covers up to +0xBA


def ufield_addr(index: int) -> int:
    return UFIELD_BASE + index * UFIELD_STRIDE


def write_ufield_node(memory: dict, address: int, *, class_ptr: int, outer_ptr: int,
                      name_id: int, next_ptr: int) -> None:
    """A plain UField-shaped node (no UFunction-specific fields) -- enough
    for walk_children_chain()/_classify_child_field()'s own tests, which
    never read past UField::Next.
    """
    blob = bytearray(tool.DEFAULT_UFIELD_NEXT_OFFSET + 8)
    struct.pack_into("<Q", blob, tool.DEFAULT_CLASS_PRIVATE_OFFSET, class_ptr)
    struct.pack_into("<I", blob, tool.DEFAULT_NAME_PRIVATE_OFFSET, name_id)
    struct.pack_into("<Q", blob, tool.DEFAULT_OUTER_PRIVATE_OFFSET, outer_ptr)
    struct.pack_into("<Q", blob, tool.DEFAULT_UFIELD_NEXT_OFFSET, next_ptr)
    memory[address] = bytes(blob)


def write_ufunction_object(memory: dict, address: int, *, class_ptr: int, outer_ptr: int,
                           name_id: int, next_ptr: int, function_flags: int = 0,
                           num_parms: int = 0, parms_size: int = 0,
                           return_value_offset: int = 0,
                           child_properties_ptr: int = 0) -> None:
    """A full UFunction-shaped node: the SAME UField header
    write_ufield_node() writes, PLUS UStruct::ChildProperties
    (USTRUCT_CHILD_PROPERTIES_OFFSET, +0x50 -- the function's OWN parameter
    chain) and FunctionFlags/NumParms/ParmsSize/ReturnValueOffset at
    UFUNCTION_FUNCTION_FLAGS_OFFSET/UFUNCTION_NUM_PARMS_OFFSET/UFUNCTION_
    PARMS_SIZE_OFFSET/UFUNCTION_RETURN_VALUE_OFFSET_OFFSET (+0xB0/+0xB4/
    +0xB6/+0xB8) -- the exact offset constants eri.py itself defines, never
    a magic number. ChildProperties is baked into THIS SAME blob (never a
    separate, smaller dict entry patched in afterward) because
    MemoryFakeApi's own read_process_memory serves a read from the FIRST
    memory blob (in insertion order) whose own [start, start+len) range
    covers it -- a later, narrower override at the SAME address range would
    silently lose to this wider blob, never actually take effect.
    """
    blob = bytearray(UFUNCTION_BLOB_SIZE)
    struct.pack_into("<Q", blob, tool.DEFAULT_CLASS_PRIVATE_OFFSET, class_ptr)
    struct.pack_into("<I", blob, tool.DEFAULT_NAME_PRIVATE_OFFSET, name_id)
    struct.pack_into("<Q", blob, tool.DEFAULT_OUTER_PRIVATE_OFFSET, outer_ptr)
    struct.pack_into("<Q", blob, tool.DEFAULT_UFIELD_NEXT_OFFSET, next_ptr)
    struct.pack_into("<Q", blob, tool.USTRUCT_CHILD_PROPERTIES_OFFSET, child_properties_ptr)
    struct.pack_into("<I", blob, tool.UFUNCTION_FUNCTION_FLAGS_OFFSET, function_flags)
    struct.pack_into("<B", blob, tool.UFUNCTION_NUM_PARMS_OFFSET, num_parms)
    struct.pack_into("<H", blob, tool.UFUNCTION_PARMS_SIZE_OFFSET, parms_size)
    struct.pack_into("<H", blob, tool.UFUNCTION_RETURN_VALUE_OFFSET_OFFSET, return_value_offset)
    memory[address] = bytes(blob)


def _finish(memory: dict, allocator: "_NameAllocator") -> "MemoryFakeApi":
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    return MemoryFakeApi(memory=memory)


OWNER_ADDRESS = 0x9000_0000_1000
FUNCTION_CLASS_ADDRESS = 0x9000_0000_2000
NOT_FUNCTION_CLASS_ADDRESS = 0x9000_0000_3000


# --------------------------------------------------------------------------- #
# constants sanity -- pins the exact offset arithmetic the brief specified,
# so a future accidental edit to any of these is caught immediately.
# --------------------------------------------------------------------------- #

def test_default_ufield_next_offset_derivation():
    assert tool.DEFAULT_UFIELD_NEXT_OFFSET == tool.DEFAULT_OUTER_PRIVATE_OFFSET + 8
    assert tool.DEFAULT_UFIELD_NEXT_OFFSET == 0x28


def test_ustruct_children_offset_derivation():
    assert tool.USTRUCT_CHILDREN_OFFSET == tool.USTRUCT_CHILD_PROPERTIES_OFFSET - 8
    assert tool.USTRUCT_CHILDREN_OFFSET == 0x48


def test_ustruct_total_size_shipping_value():
    assert tool.USTRUCT_TOTAL_SIZE_SHIPPING == 0xB0


def test_ufunction_field_offsets():
    assert tool.UFUNCTION_FUNCTION_FLAGS_OFFSET == 0xB0
    assert tool.UFUNCTION_NUM_PARMS_OFFSET == 0xB4
    assert tool.UFUNCTION_PARMS_SIZE_OFFSET == 0xB6
    assert tool.UFUNCTION_RETURN_VALUE_OFFSET_OFFSET == 0xB8


# --------------------------------------------------------------------------- #
# find_function_class_address
# --------------------------------------------------------------------------- #

def test_find_function_class_address_found():
    all_classes = [
        {"address": 1, "raw_name": "Object"},
        {"address": 2, "raw_name": "Function"},
        {"address": 3, "raw_name": "Struct"},
    ]
    assert tool.find_function_class_address(all_classes) == 2


def test_find_function_class_address_absent():
    all_classes = [{"address": 1, "raw_name": "Object"}, {"address": 3, "raw_name": "Struct"}]
    assert tool.find_function_class_address(all_classes) is None


# --------------------------------------------------------------------------- #
# walk_children_chain / _classify_child_field
# --------------------------------------------------------------------------- #

def test_walk_children_chain_empty_children_ptr():
    api = MemoryFakeApi(memory={})  # never read at all.
    result = tool.walk_children_chain(
        api, 1, 0, namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result == {"accepted": [], "nodes_visited": 0, "rejected_counts": {},
                      "ok": True, "note": None}


def test_walk_children_chain_single_function():
    memory: dict = {}
    allocator = _NameAllocator()
    name_id = allocator.add("DoSomething")
    write_ufield_node(memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=name_id, next_ptr=0)
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result["ok"] is True
    assert result["nodes_visited"] == 1
    assert result["rejected_counts"] == {}
    assert result["accepted"] == [{"address": ufield_addr(0), "raw_name": "DoSomething"}]


def test_walk_children_chain_multiple_functions_preserves_order():
    memory: dict = {}
    allocator = _NameAllocator()
    names = ["First", "Second", "Third"]
    ids = [allocator.add(n) for n in names]
    write_ufield_node(memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=ids[0], next_ptr=ufield_addr(1))
    write_ufield_node(memory, ufield_addr(1), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=ids[1], next_ptr=ufield_addr(2))
    write_ufield_node(memory, ufield_addr(2), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=ids[2], next_ptr=0)
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result["ok"] is True
    assert [c["raw_name"] for c in result["accepted"]] == names


def test_walk_children_chain_cycle_is_a_documented_failure_not_a_hang():
    memory: dict = {}
    allocator = _NameAllocator()
    id_a, id_b = allocator.add("A"), allocator.add("B")
    write_ufield_node(memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=id_a, next_ptr=ufield_addr(1))
    write_ufield_node(memory, ufield_addr(1), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=id_b, next_ptr=ufield_addr(0))
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS, max_chain_length=100)
    assert result["ok"] is False
    assert "cycle" in result["note"].lower()
    assert len(result["accepted"]) == 2  # both nodes WERE examined before the cycle was caught.


def test_walk_children_chain_exceeds_max_chain_length():
    memory: dict = {}
    allocator = _NameAllocator()
    n = 20
    for i in range(n):
        name_id = allocator.add("F%d" % i)
        next_ptr = ufield_addr(i + 1) if i < n - 1 else ufield_addr(n)  # never terminates.
        write_ufield_node(memory, ufield_addr(i), class_ptr=FUNCTION_CLASS_ADDRESS,
                          outer_ptr=OWNER_ADDRESS, name_id=name_id, next_ptr=next_ptr)
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS, max_chain_length=10)
    assert result["ok"] is False
    assert "max_chain_length" in result["note"]
    assert result["nodes_visited"] == 10


def test_walk_children_chain_outer_round_trip_failure_is_counted_not_accepted():
    memory: dict = {}
    allocator = _NameAllocator()
    name_id = allocator.add("Foreign")
    wrong_owner = OWNER_ADDRESS + 0x1000
    write_ufield_node(memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=wrong_owner, name_id=name_id, next_ptr=0)
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result["ok"] is True
    assert result["accepted"] == []
    assert result["rejected_counts"] == {"outer_mismatch": 1}


def test_walk_children_chain_not_a_function_sibling_is_skipped_walk_continues():
    # index 0: outer round-trips fine, but ClassPrivate is NOT the "Function"
    # meta-class -- a real UField, simply not a UFunction; index 1: a real
    # accepted UFunction. The walk must still find index 1.
    memory: dict = {}
    allocator = _NameAllocator()
    not_a_func_id = allocator.add("SomeProperty")
    good_id = allocator.add("RealFunction")
    write_ufield_node(memory, ufield_addr(0), class_ptr=NOT_FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=not_a_func_id, next_ptr=ufield_addr(1))
    write_ufield_node(memory, ufield_addr(1), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=good_id, next_ptr=0)
    api = _finish(memory, allocator)
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result["ok"] is True
    assert result["nodes_visited"] == 2
    assert result["rejected_counts"] == {"not_a_function": 1}
    assert len(result["accepted"]) == 1
    assert result["accepted"][0]["raw_name"] == "RealFunction"


def test_walk_children_chain_read_failure_aborts_the_walk():
    memory: dict = {}
    allocator = _NameAllocator()
    name_id = allocator.add("Foo")
    write_ufield_node(memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS,
                      outer_ptr=OWNER_ADDRESS, name_id=name_id, next_ptr=0)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    fail_addr = ufield_addr(0) + tool.DEFAULT_CLASS_PRIVATE_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={fail_addr})
    result = tool.walk_children_chain(
        api, 1, ufield_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=OWNER_ADDRESS,
        function_class_address=FUNCTION_CLASS_ADDRESS)
    assert result["ok"] is False
    assert result["rejected_counts"] == {"read_failure": 1}
    assert "Next pointer was never read" in result["note"]


# --------------------------------------------------------------------------- #
# _decode_ufunction_base_fields
# --------------------------------------------------------------------------- #

def test_decode_ufunction_base_fields_reads_all_four_fields():
    memory: dict = {}
    allocator = _NameAllocator()
    write_ufunction_object(
        memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS, outer_ptr=OWNER_ADDRESS,
        name_id=allocator.add("Foo"), next_ptr=0,
        function_flags=tool.FUNC_NATIVE | tool.FUNC_STATIC, num_parms=3,
        parms_size=24, return_value_offset=16)
    api = _finish(memory, allocator)
    result = tool._decode_ufunction_base_fields(api, 1, ufield_addr(0))
    assert result["valid"] is True
    assert result["function_flags"] == (tool.FUNC_NATIVE | tool.FUNC_STATIC)
    assert result["num_parms"] == 3
    assert result["parms_size"] == 24
    assert result["return_value_offset"] == 16


def test_decode_ufunction_base_fields_read_failure_reported_not_raised():
    memory: dict = {}
    allocator = _NameAllocator()
    write_ufunction_object(
        memory, ufield_addr(0), class_ptr=FUNCTION_CLASS_ADDRESS, outer_ptr=OWNER_ADDRESS,
        name_id=allocator.add("Foo"), next_ptr=0)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    fail_addr = ufield_addr(0) + tool.UFUNCTION_FUNCTION_FLAGS_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={fail_addr})
    result = tool._decode_ufunction_base_fields(api, 1, ufield_addr(0))
    assert result["valid"] is False
    assert "read failure" in result["rejection_reason"]
    assert result["function_flags"] is None


# --------------------------------------------------------------------------- #
# run_i05 -- proof-set-level orchestration, the MANDATORY EMPIRICAL
# SELF-CHECK (NumParms vs accepted parameter count), and the honest
# "Function meta-class not found" outcome.
# --------------------------------------------------------------------------- #

def _cls(name, address, object_path=None):
    return {"address": address, "raw_name": name, "object_path": object_path}


def test_run_i05_function_class_not_found_reported_honestly():
    api = MemoryFakeApi(memory={})  # never read -- function_class lookup is pure/in-memory.
    all_classes = [_cls("Object", 1), _cls("Actor", 2)]  # no "Function" entry.
    proof_set = [_cls("MiseryFocusSubsystem", 100)]
    result = tool.run_i05(api, 1, NAMEPOOL_VA, all_classes, proof_set)
    assert result["function_class_found"] is False
    assert result["function_class_address_hex"] is None
    assert result["classes"] == []
    assert result["functions_accepted_total"] == 0
    assert result["num_parms_cross_check"] == {"match": 0, "mismatch": 0, "mismatches": []}
    assert "not found" in result["note"] or "was not found" in result["note"]


def _build_single_function_fixture(*, num_parms_declared: int, real_parameter_count: int):
    """A single proof-set class (address CLASS_ADDR) whose own Children
    chain has exactly one UFunction (FUNCTION_ADDR), whose own
    ChildProperties chain has *real_parameter_count* real FIntProperty
    parameters, each owned (FField::Owner) by the FUNCTION's own address --
    NEVER the owning class's -- exactly per the module docstring's "a
    UFunction's own parameters are its own child properties" rule.
    *num_parms_declared* is written into the UFunction's own NumParms field
    directly, independently of *real_parameter_count* -- the caller decides
    whether the two should agree (the MANDATORY EMPIRICAL SELF-CHECK's own
    two tests below use this to construct both outcomes deliberately).

    Returns (api, all_classes, proof_set_classes).
    """
    class_addr = 0x9000_0000_9000
    function_addr = ufield_addr(0)

    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    memory = dict(fc_memory)

    # UFunction::ChildProperties -- its OWN parameter chain, owner ==
    # function_addr (never class_addr). Written BEFORE write_ufunction_object()
    # below so the function's own child_properties_ptr can be baked directly
    # into its own blob.
    # property_flags=CPF_PARM: these are meant to simulate TRUE parameters,
    # not Blueprint-style local variables -- run_i05() filters the accepted
    # ChildProperties-chain entries to CPF_Parm-flagged ones (a live finding,
    # see run_i05()'s own "MANDATORY EMPIRICAL SELF-CHECK" docstring
    # paragraph), so a synthetic parameter lacking CPF_Parm would silently
    # be excluded from 'parameters' and this fixture's own real_parameter_
    # count would stop matching len(function_entry["parameters"]).
    param_addrs = [field_addr(i) for i in range(real_parameter_count)]
    for i, addr in enumerate(param_addrs):
        param_name_id = allocator.add("Param%d" % i)
        next_ptr = param_addrs[i + 1] if i + 1 < len(param_addrs) else 0
        write_fproperty(
            memory, addr, class_ptr=addr_by_name["FIntProperty"],
            owner_raw=uobject_owner(function_addr), next_ptr=next_ptr,
            name_id=param_name_id, offset_internal=i * 4,
            property_flags=tool.CPF_PARM)
    child_properties_ptr = param_addrs[0] if real_parameter_count else 0

    # UClass::Children -- one UFunction, owned (OuterPrivate) by class_addr.
    memory[class_addr + tool.USTRUCT_CHILDREN_OFFSET] = struct.pack("<Q", function_addr)
    function_name_id = allocator.add("DoStuff")
    write_ufunction_object(
        memory, function_addr, class_ptr=FUNCTION_CLASS_ADDRESS, outer_ptr=class_addr,
        name_id=function_name_id, next_ptr=0,
        function_flags=tool.FUNC_NATIVE, num_parms=num_parms_declared,
        parms_size=4 * real_parameter_count, return_value_offset=0,
        child_properties_ptr=child_properties_ptr)

    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)

    all_classes = [
        _cls("MiseryFocusSubsystem", class_addr), _cls("Function", FUNCTION_CLASS_ADDRESS),
    ]
    proof_set_classes = [_cls("MiseryFocusSubsystem", class_addr)]
    return api, all_classes, proof_set_classes


def test_run_i05_num_parms_cross_check_match():
    api, all_classes, proof_set = _build_single_function_fixture(
        num_parms_declared=2, real_parameter_count=2)
    result = tool.run_i05(api, 1, NAMEPOOL_VA, all_classes, proof_set)
    assert result["function_class_found"] is True
    assert result["functions_accepted_total"] == 1
    function_entry = result["classes"][0]["functions"][0]
    assert function_entry["raw_name"] == "DoStuff"
    assert function_entry["num_parms"] == 2
    assert len(function_entry["parameters"]) == 2
    assert function_entry["num_parms_matches_accepted_count"] is True
    assert result["num_parms_cross_check"] == {"match": 1, "mismatch": 0, "mismatches": []}


def test_run_i05_num_parms_cross_check_mismatch():
    # NumParms says 5, but only 2 real parameters actually exist on the
    # function's own ChildProperties chain -- a DELIBERATE synthetic
    # disagreement, exactly the case the MANDATORY EMPIRICAL SELF-CHECK
    # exists to catch.
    api, all_classes, proof_set = _build_single_function_fixture(
        num_parms_declared=5, real_parameter_count=2)
    result = tool.run_i05(api, 1, NAMEPOOL_VA, all_classes, proof_set)
    assert result["functions_accepted_total"] == 1
    function_entry = result["classes"][0]["functions"][0]
    assert function_entry["num_parms"] == 5
    assert len(function_entry["parameters"]) == 2
    assert function_entry["num_parms_matches_accepted_count"] is False
    assert result["num_parms_cross_check"]["match"] == 0
    assert result["num_parms_cross_check"]["mismatch"] == 1
    mismatch = result["num_parms_cross_check"]["mismatches"][0]
    assert mismatch["num_parms"] == 5
    assert mismatch["accepted_parameter_count"] == 2
    assert mismatch["local_variable_count"] == 0
    assert mismatch["function_raw_name"] == "DoStuff"


def test_run_i05_excludes_local_variables_lacking_cpf_parm_from_parameters():
    """A live finding, not a source-derived assumption (see run_i05()'s own
    docstring): a Blueprint-generated UFunction's own ChildProperties chain
    holds BOTH true parameters (CPF_Parm set) AND compiler-generated local
    variables of the function body (CPF_Parm unset) -- NumParms counts only
    the former. This mixes two true parameters with two local variables on
    ONE function's own chain and asserts the split is exactly right: NumParms
    (2) matches the CPF_Parm-filtered count (2), 'parameters' contains only
    the two flagged entries, and the two unflagged ones are counted in
    'local_variable_count', never silently dropped.
    """
    class_addr = 0x9000_0000_9500
    function_addr = ufield_addr(10)
    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    memory = dict(fc_memory)

    entries = [
        ("RealParamA", tool.CPF_PARM),
        ("Temp_int_Loop_Counter_Variable", 0),
        ("RealParamB", tool.CPF_PARM),
        ("CallFunc_Add_IntInt_ReturnValue", 0),
    ]
    param_addrs = [field_addr(10 + i) for i in range(len(entries))]
    for i, (addr, (name, flags)) in enumerate(zip(param_addrs, entries)):
        name_id = allocator.add(name)
        next_ptr = param_addrs[i + 1] if i + 1 < len(param_addrs) else 0
        write_fproperty(
            memory, addr, class_ptr=addr_by_name["FIntProperty"],
            owner_raw=uobject_owner(function_addr), next_ptr=next_ptr,
            name_id=name_id, offset_internal=i * 4, property_flags=flags)

    memory[class_addr + tool.USTRUCT_CHILDREN_OFFSET] = struct.pack("<Q", function_addr)
    function_name_id = allocator.add("MixedLocalsFunction")
    write_ufunction_object(
        memory, function_addr, class_ptr=FUNCTION_CLASS_ADDRESS, outer_ptr=class_addr,
        name_id=function_name_id, next_ptr=0,
        function_flags=tool.FUNC_NATIVE, num_parms=2, parms_size=8,
        return_value_offset=0, child_properties_ptr=param_addrs[0])

    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)

    all_classes = [
        _cls("MiseryFocusSubsystem", class_addr), _cls("Function", FUNCTION_CLASS_ADDRESS),
    ]
    proof_set = [_cls("MiseryFocusSubsystem", class_addr)]
    result = tool.run_i05(api, 1, NAMEPOOL_VA, all_classes, proof_set)

    assert result["functions_accepted_total"] == 1
    function_entry = result["classes"][0]["functions"][0]
    assert function_entry["num_parms"] == 2
    assert function_entry["local_variable_count"] == 2
    assert function_entry["num_parms_matches_accepted_count"] is True
    assert {p["raw_name"] for p in function_entry["parameters"]} == {"RealParamA", "RealParamB"}
    assert result["num_parms_cross_check"] == {"match": 1, "mismatch": 0, "mismatches": []}


# --------------------------------------------------------------------------- #
# build_i05_function_record -- is_return/is_out/is_reference derivation from
# property_flags_raw, the MANDATORY EMPIRICAL SELF-CHECK's own 'notes'
# surfacing, the multiple-CPF_ReturnParm anomaly note, and full schema
# validation against the REAL research/schema/reflection-record.schema.json
# composed with kb-record.schema.json (reusing test_eri_i01's own offline
# registry, exactly like test_eri_i06.py's own property-record tests).
# --------------------------------------------------------------------------- #

def _param_decoded(**overrides):
    base = {
        "valid": True, "address_hex": "0x2000", "raw_name": "Param",
        "property_class": "FIntProperty", "array_dim": 1, "size": 4, "total_size": 4,
        "offset": 0, "property_flags_raw": "0x0", "rep_index": 0, "rep_notify_func": None,
        "type_name": None, "bool_byte_offset": None, "bool_field_mask": None,
        "is_bitfield": None, "struct_name": None, "enum_name": None, "class_name": None,
        "inner": None, "key_type": None, "value_type": None, "notes": [],
    }
    base.update(overrides)
    return base


def _function_entry(**overrides):
    base = {
        "address": 0x1000, "address_hex": "0x1000", "raw_name": "DoStuff",
        "function_flags": tool.FUNC_NATIVE,
        "num_parms": 0, "parms_size": 0, "return_value_offset": 0,
        "parameters": [], "local_variable_count": 0,
        "num_parms_matches_accepted_count": True,
        "param_chain_ok": True, "param_chain_note": None, "param_chain_nodes_visited": 0,
    }
    base.update(overrides)
    return base


def test_build_i05_function_record_flags_derivation_all_set():
    param = _param_decoded(
        raw_name="ReturnValue", offset=0,
        property_flags_raw="0x%x" % (tool.CPF_RETURN_PARM | tool.CPF_OUT_PARM
                                     | tool.CPF_REFERENCE_PARM))
    entry = _function_entry(num_parms=1, parameters=[param])
    row = tool.build_i05_function_record(
        entry, owner="MiseryFocusSubsystem", build_key=VALID_BUILD_KEY,
        recorded_at="2026-08-27T12:00:00Z")
    p = row["parameters"][0]
    assert p["is_return"] is True
    assert p["is_out"] is True
    assert p["is_reference"] is True
    assert p["ordinal"] == 0
    assert p["name"] == "ReturnValue"


def test_build_i05_function_record_flags_derivation_none_set():
    param = _param_decoded(raw_name="PlainParam", property_flags_raw="0x0")
    entry = _function_entry(num_parms=1, parameters=[param])
    row = tool.build_i05_function_record(
        entry, owner="MiseryFocusSubsystem", build_key=VALID_BUILD_KEY,
        recorded_at="2026-08-27T12:00:00Z")
    p = row["parameters"][0]
    assert p["is_return"] is False
    assert p["is_out"] is False
    assert p["is_reference"] is False


def test_build_i05_function_record_multiple_return_parms_is_a_noted_anomaly():
    param0 = _param_decoded(raw_name="A", property_flags_raw="0x%x" % tool.CPF_RETURN_PARM)
    param1 = _param_decoded(raw_name="B", property_flags_raw="0x%x" % tool.CPF_RETURN_PARM)
    entry = _function_entry(num_parms=2, parameters=[param0, param1])
    row = tool.build_i05_function_record(
        entry, owner="X", build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    assert row["parameters"][0]["is_return"] is True
    assert row["parameters"][1]["is_return"] is True
    assert "structural anomaly" in row["notes"]
    assert "CPF_ReturnParm" in row["notes"]


def test_build_i05_function_record_num_parms_mismatch_is_a_noted_self_check_failure():
    entry = _function_entry(num_parms=5, parameters=[], num_parms_matches_accepted_count=False)
    row = tool.build_i05_function_record(
        entry, owner="X", build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    assert "MANDATORY EMPIRICAL SELF-CHECK MISMATCH" in row["notes"]


def test_build_i05_function_record_shape_and_grading():
    param = _param_decoded(raw_name="Amount", offset=24)
    entry = _function_entry(
        function_flags=tool.FUNC_NATIVE | tool.FUNC_STATIC | tool.FUNC_NET
        | tool.FUNC_NET_RELIABLE,
        num_parms=1, parms_size=16, return_value_offset=8, parameters=[param])
    row = tool.build_i05_function_record(
        entry, owner="MiseryFocusSubsystem", build_key=VALID_BUILD_KEY,
        recorded_at="2026-08-27T12:00:00Z")
    assert row["kind"] == "function"
    assert row["raw_name"] == "DoStuff"
    assert row["owner"] == "MiseryFocusSubsystem"
    assert row["num_parms"] == 1
    assert row["parms_size"] == 16
    assert row["return_value_offset"] == 8
    assert row["is_native"] is True
    assert row["is_static"] is True
    assert row["is_event"] is False
    assert row["is_net"] is True
    assert row["net_flags_raw"] == "0x%x" % (tool.FUNC_NET | tool.FUNC_NET_RELIABLE)
    assert row["native_func_address"] is None
    assert row["bytecode_size"] is None
    assert row["confidence"] == 0.75
    assert row["evidence_level"] == "OBSERVED"
    assert row["oracle"] == ["runtime-reflection"]
    assert len(row["sources"]) == 1  # NEVER cross-checked -- mirrors I-06's own property_record.
    assert row["method"] == "I-05"
    assert len(row["parameters"]) == 1
    assert row["parameters"][0]["name"] == "Amount"
    assert row["parameters"][0]["offset"] == 24
    json.loads(tool.dump_json(row))


def _function_record_validator():
    pytest.importorskip("jsonschema")
    pytest.importorskip("referencing")
    from jsonschema import Draft202012Validator
    schema = i01_tests._load_schema("reflection-record.schema.json")
    return Draft202012Validator(schema, registry=i01_tests._build_registry())


def test_build_i05_function_record_validates_against_real_schema():
    validator = _function_record_validator()
    param = _param_decoded(
        raw_name="ReturnValue", offset=0,
        property_flags_raw="0x%x" % tool.CPF_RETURN_PARM)
    entry = _function_entry(num_parms=1, parameters=[param])
    row = tool.build_i05_function_record(
        entry, owner="MiseryFocusSubsystem", build_key=VALID_BUILD_KEY,
        recorded_at="2026-08-27T12:00:00Z")
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_build_i05_function_record_zero_parameters_validates_against_real_schema():
    validator = _function_record_validator()
    entry = _function_entry(num_parms=0, parameters=[])
    row = tool.build_i05_function_record(
        entry, owner="MiseryFocusSubsystem", build_key=VALID_BUILD_KEY,
        recorded_at="2026-08-27T12:00:00Z")
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_build_i05_document_shape():
    result = {
        "function_class_found": True, "function_class_address_hex": "0x1234",
        "classes_examined": 1, "functions_accepted_total": 2,
        "rejected_counts_total": {"not_a_function": 3},
        "num_parms_cross_check": {"match": 2, "mismatch": 0, "mismatches": []},
        "classes": [{
            "class_address": 0x1000, "class_raw_name": "MiseryFocusSubsystem",
            "object_path": "/Script/MISERY.MiseryFocusSubsystem",
            "children_ptr_hex": "0x2000", "children_read_ok": True,
            "children_read_error": None,
            "functions": [{"raw_name": "A"}, {"raw_name": "B"}],
            "nodes_visited": 5, "rejected_counts": {"not_a_function": 3},
            "chain_ok": True, "chain_note": None,
        }],
        "note": None,
    }
    doc = tool.build_i05_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["capability"] == "I-05"
    assert doc["function_class_found"] is True
    assert doc["functions_accepted_total"] == 2
    assert doc["classes"][0]["function_count"] == 2
    assert doc["num_parms_cross_check"] == {"match": 2, "mismatch": 0, "mismatches": []}
    assert "evidence_level" not in doc
    json.loads(tool.dump_json(doc))


# --------------------------------------------------------------------------- #
# CLI argument parsing / path resolution / requirement validation.
# --------------------------------------------------------------------------- #

def test_cli_run_i05_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_i05 is False
    assert args.children_offset is None
    assert args.ufield_next_offset is None
    assert args.i05_children_max_chain_length == tool.DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH
    assert args.i05_out is None
    assert args.functions_jsonl_out is None


def test_parse_children_offset_default_and_override():
    assert tool._parse_children_offset(None) == tool.USTRUCT_CHILDREN_OFFSET
    assert tool._parse_children_offset("0x48") == 0x48
    with pytest.raises(ValueError):
        tool._parse_children_offset("garbage")


def test_parse_ufield_next_offset_default_and_override():
    assert tool._parse_ufield_next_offset(None) == tool.DEFAULT_UFIELD_NEXT_OFFSET
    assert tool._parse_ufield_next_offset("0x28") == 0x28
    with pytest.raises(ValueError):
        tool._parse_ufield_next_offset("garbage")


def test_resolve_i05_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_i05_output_path(args) is None
    assert tool._resolve_functions_jsonl_path(args) is None


def test_resolve_i05_output_path_requires_i05_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i05"])
    with pytest.raises(ValueError):
        tool._resolve_i05_output_path(args)


def test_resolve_functions_jsonl_path_requires_flag_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i05"])
    with pytest.raises(ValueError):
        tool._resolve_functions_jsonl_path(args)


def test_resolve_i05_output_path_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(["--run-i05", "--run-dir", run_dir])
    assert tool._resolve_i05_output_path(args) == os.path.join(run_dir, "i05-functions.json")
    assert tool._resolve_functions_jsonl_path(args) == os.path.join(run_dir, "functions.jsonl")


def test_resolve_functions_jsonl_path_explicit_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit = str(tmp_path / "custom-functions.jsonl")
    args = tool.build_arg_parser().parse_args(
        ["--run-i05", "--run-dir", run_dir, "--functions-jsonl-out", explicit])
    assert tool._resolve_functions_jsonl_path(args) == explicit


def test_validate_i05_requirements_noop_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    tool._validate_i05_requirements(args)  # must not raise


def test_validate_i05_requirements_raises_when_missing_run_i04():
    args = tool.build_arg_parser().parse_args(["--run-i05", "--run-i02", "--run-i03"])
    with pytest.raises(ValueError, match="--run-i04"):
        tool._validate_i05_requirements(args)


def test_validate_i05_requirements_passes_when_run_i04_given():
    args = tool.build_arg_parser().parse_args(
        ["--run-i05", "--run-i02", "--run-i03", "--run-i04"])
    tool._validate_i05_requirements(args)  # must not raise


def test_validate_i05_requirements_does_not_require_run_i06():
    # I-05 has NO actual data dependency on run_i06() -- only on run_i04()'s
    # own class list -- so --run-i05 must be legal WITHOUT --run-i06 in the
    # same invocation (see _validate_i05_requirements()'s own docstring).
    args = tool.build_arg_parser().parse_args(
        ["--run-i05", "--run-i02", "--run-i03", "--run-i04"])
    assert args.run_i06 is False
    tool._validate_i05_requirements(args)  # must not raise


# --------------------------------------------------------------------------- #
# main() end-to-end -- a synthetic fixture combining I-02/I-03/I-04's own
# established memory shapes with I-05's own UClass::Children/UFunction/
# ChildProperties memory, producing functions.jsonl via the full CLI.
# --------------------------------------------------------------------------- #

def test_main_run_i05_writes_functions_jsonl_for_misery_class(tmp_path, monkeypatch):
    entries, entries_text, misery_names = i04_tests._misery_five_class_fixture()
    # Append a "Function" meta-class (index 10) to the SAME object universe
    # I-04 already walks -- its own ClassPrivate == the seed ("Class",
    # obj_addr(1)), its own Outer == the CoreUObject package (obj_addr(0)),
    # exactly mirroring how index 3 ("BlueprintGeneratedClass") is already
    # wired in _misery_five_class_fixture() itself.
    function_class_name_id = 0x700000
    entries.append({
        "class_ptr": i04_tests.obj_addr(1), "outer_ptr": i04_tests.obj_addr(0),
        "name_entry_id": function_class_name_id})
    entries_text[function_class_name_id] = ("Function", False)
    function_class_index = len(entries) - 1

    chunk_memory, objects_ptr = i04_tests.make_i04_object_chunk_memory(entries)
    struct_blob = bytearray(0x2C)
    struct.pack_into("<Q", struct_blob, tool.GUOBJECTARRAY_OFFSET_OBJECTS, objects_ptr)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_MAX_ELEMENTS, 100)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS, len(entries))
    memory = dict(chunk_memory)
    memory[GUOBJECTARRAY_VA] = bytes(struct_blob)

    # I-06's own FField/FFieldClass registry (for the function's own
    # parameter, an FIntProperty) -- allocator seeded well past
    # entries_text's own highest block (6 fixed names + 5 MISERY classes +
    # 1 Function meta-class == block 12 at most) so the two id ranges never
    # collide, mirroring test_eri_i06.py's own end-to-end fixture.
    allocator = _NameAllocator(start_block=50)
    fc_memory, addr_by_name, allocator = build_fieldclass_registry(allocator=allocator)
    memory.update(fc_memory)

    misery_class_address = i04_tests.obj_addr(5)  # "MiseryBlueprintFunctionLibrary"
    function_class_address = i04_tests.obj_addr(function_class_index)
    function_address = ufield_addr(0)

    param_name_id = allocator.add("ReturnValue")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=uobject_owner(function_address), next_ptr=0, name_id=param_name_id,
        property_flags=tool.CPF_RETURN_PARM | tool.CPF_PARM, offset_internal=0)

    function_name_id = allocator.add("DoSomething")
    write_ufunction_object(
        memory, function_address, class_ptr=function_class_address,
        outer_ptr=misery_class_address, name_id=function_name_id, next_ptr=0,
        function_flags=tool.FUNC_NATIVE | tool.FUNC_STATIC, num_parms=1,
        parms_size=4, return_value_offset=0, child_properties_ptr=field_addr(0))
    memory[misery_class_address + tool.USTRUCT_CHILDREN_OFFSET] = struct.pack(
        "<Q", function_address)

    # Every OTHER proof-set class (I-06's own proof set: the remaining 4
    # MISERY classes, plus "Class" itself via select_i06_engine_proof_classes()'s
    # own name-preference search) legitimately declares zero of its own
    # child fields -- a null Children pointer, per walk_children_chain()'s
    # own docstring, is a valid, non-error result.
    for other_index in (1, 6, 7, 8, 9):
        other_address = i04_tests.obj_addr(other_index)
        memory[other_address + tool.USTRUCT_CHILDREN_OFFSET] = struct.pack("<Q", 0)

    combined_names = dict(entries_text)
    combined_names.update(allocator.entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries=combined_names)
    memory.update(fnamepool_memory)

    api, _ = i04_tests._fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04", "--run-i05",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "functions.jsonl"), encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    assert len(rows) == 1
    row = rows[0]
    assert row["raw_name"] == "DoSomething"
    assert row["owner"] == "MiseryBlueprintFunctionLibrary"
    assert row["is_native"] is True
    assert row["is_static"] is True
    assert row["num_parms"] == 1
    assert len(row["parameters"]) == 1
    assert row["parameters"][0]["name"] == "ReturnValue"
    assert row["parameters"][0]["is_return"] is True
    assert row["confidence"] == 0.75

    with open(os.path.join(run_dir, "i05-functions.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "I-05"
    assert doc["function_class_found"] is True
    assert doc["functions_accepted_total"] == 1
    assert doc["num_parms_cross_check"]["match"] == 1
    assert doc["num_parms_cross_check"]["mismatch"] == 0

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03", "I-04", "I-05"]
    assert any(a.endswith("i05-functions.json") for a in manifest["artifacts"])
    assert any(a.endswith("functions.jsonl") for a in manifest["artifacts"])


def test_main_run_i05_requires_run_i04(tmp_path, monkeypatch):
    api, _ = i04_tests._fake_i04_api(tmp_path, memory={})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i05"])
    assert rc == 2
    assert not os.path.exists(run_dir)
    assert api.calls["open_process"] == 0


def test_main_without_run_i05_never_touches_i05_at_all(tmp_path, monkeypatch):
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
    assert not os.path.exists(os.path.join(run_dir, "i05-functions.json"))
    assert not os.path.exists(os.path.join(run_dir, "functions.jsonl"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert "I-05" not in manifest["capabilities_enabled"]


# --------------------------------------------------------------------------- #
# still exactly one ReadProcessMemory/OpenProcess call site -- I-05 adds new
# CALLERS of Win32Api.read_process_memory (via _read_u8/_read_u32/_read_u64/
# _read_u16, every one of which already funnels through the SAME one ctypes
# call site), never a second wrapper, and adds NO new OpenProcess caller at
# all. Every capability's own test file re-pins this fact
# (test_eri_i02/i03/i04/i06.py all do), so this file does too.
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
