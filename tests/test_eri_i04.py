#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-04 (plan.md 8.2).

I-04 is the first real UObject/UClass TRAVERSAL: it walks EVERY object
I-02's own GUObjectArray chunk-walk locates (not a bounded sample), reads
each one's ClassPrivate/NamePrivate/OuterPrivate (UObjectBase.h +0x10/+0x18/
+0x20), decodes its name via I-03's own FNamePool decode, and classifies
which objects ARE UClass instances via a ClassPrivate self-reference fixed
point -- see eri.py's own module docstring, "WHAT I-04 IS", for the full
algorithm and its deliberate scope boundary (no UClass/UStruct/UField field
is ever read). No MISERY process runs in this environment (nor in CI), so
every test below exercises the plain-Python logic functions against a fake
memory model -- the SAME "duck-typed narrow interface, faked in tests" idiom
tests/test_eri_i02.py/test_eri_i03.py already established, cross-imported
here (MemoryFakeApi, FakeWin32ApiWithMemory, BASE_ADDRESS, IMAGE_SIZE_BYTES,
GUOBJECTARRAY_VA from test_eri_i02; make_fnamepool_memory, NAMEPOOL_VA,
NAME_POOL_INITIALIZED_VA from test_eri_i03) rather than re-derived.

Run:  python -m pytest -q tests/test_eri_i04.py
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

# Cross-import from the I-01/I-02/I-03 test modules -- the established
# convention in this repo (test_eri_i03.py already does this for
# test_eri_i01/test_eri_i02). Reuses VALID_BUILD_KEY/TARGET_NAME/proc/mod/
# _write_stub_exe/_patch_fake_win32api/IDENTITY_KWARGS/_manifest_validator
# from test_eri_i01, MemoryFakeApi/FakeWin32ApiWithMemory/BASE_ADDRESS/
# IMAGE_SIZE_BYTES/GUOBJECTARRAY_VA from test_eri_i02, and
# make_fnamepool_memory/NAMEPOOL_VA/NAME_POOL_INITIALIZED_VA from
# test_eri_i03, rather than re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402
import test_eri_i02 as i02_tests  # noqa: E402
import test_eri_i03 as i03_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY
BASE_ADDRESS = i02_tests.BASE_ADDRESS
IMAGE_SIZE_BYTES = i02_tests.IMAGE_SIZE_BYTES
MemoryFakeApi = i02_tests.MemoryFakeApi
GUOBJECTARRAY_VA = i02_tests.GUOBJECTARRAY_VA

NAMEPOOL_VA = i03_tests.NAMEPOOL_VA
NAME_POOL_INITIALIZED_VA = i03_tests.NAME_POOL_INITIALIZED_VA
make_fnamepool_memory = i03_tests.make_fnamepool_memory

CLASS_PRIVATE_OFFSET = tool.DEFAULT_CLASS_PRIVATE_OFFSET
NAME_PRIVATE_OFFSET = tool.DEFAULT_NAME_PRIVATE_OFFSET
OUTER_PRIVATE_OFFSET = tool.DEFAULT_OUTER_PRIVATE_OFFSET

VALID_VTABLE_ADDR = BASE_ADDRESS + 0x2000
INVALID_VTABLE_ADDR = BASE_ADDRESS + IMAGE_SIZE_BYTES + 0x50000

# --------------------------------------------------------------------------- #
# fake object-universe memory -- a GUObjectArray chunk of FUObjectItems, each
# pointing at a fake UObject whose own ClassPrivate/NamePrivate/OuterPrivate
# fields are written at the SAME offsets eri.py itself reads. Deterministic
# per-index addressing (obj_addr(i)) so a test can reference "the object at
# index j" as ANOTHER entry's class_ptr/outer_ptr BEFORE that entry exists,
# with no two-pass address-assignment dance needed.
# --------------------------------------------------------------------------- #

OBJECTS_BASE = GUOBJECTARRAY_VA + 0x00500000
OBJECT_STRIDE = 0x1000
OBJECT_BLOB_SIZE = 0x40  # covers vtable(0x00)+class_ptr(0x10)+name(0x18)+outer_ptr(0x20)


def obj_addr(index: int) -> int:
    return OBJECTS_BASE + index * OBJECT_STRIDE


def make_i04_object_chunk_memory(entries: list, *,
                                 guobjectarray_va: int = GUOBJECTARRAY_VA) -> tuple:
    """*entries*[i] is either None (a null/never-allocated slot) or a dict:
      'name_entry_id': int (the FNameEntryId written at NamePrivate's own
        offset -- the caller separately builds FNamePool memory, via
        make_fnamepool_memory, mapping this id to the intended text; merged
        into the same memory dict by the test, mirroring test_eri_i03.py's
        own "chunk_memory + fnamepool_memory" merge pattern),
      'class_ptr': int (0 for none, else obj_addr(j) for some other index j
        -- addresses are deterministic via obj_addr(), so forward references
        need no two-pass wiring),
      'outer_ptr': int (0 for top-level, else obj_addr(j)),
      'vtable': 'valid' | 'invalid' (default 'valid') -- what THIS entry's
        own first 8 bytes look like, i.e. what another object's ClassPrivate
        check(3) would see if it pointed AT this entry. 'missing' (bytes
        left as configured zero, functionally identical to an invalid
        vtable since zero is never inside the module range) is not a
        distinct case here -- use 'invalid'.
      'misaligned': bool -- nudge this entry's own address off 8-byte
        alignment (check 1 must reject it before any read).
    Returns (memory, objects_ptr).
    """
    chunk_table_addr = guobjectarray_va + 0x00600000
    items_addr = chunk_table_addr + 0x1000
    items_region_len = max(len(entries), 1) * tool.SIZEOF_FUOBJECTITEM
    items_blob = bytearray(items_region_len)
    memory: dict = {}

    for i, entry in enumerate(entries):
        if entry is None:
            struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, 0)
            continue
        address = obj_addr(i)
        if entry.get("misaligned"):
            address += 1
        obj_blob = bytearray(OBJECT_BLOB_SIZE)
        vtable_kind = entry.get("vtable", "valid")
        vtable_value = VALID_VTABLE_ADDR if vtable_kind == "valid" else INVALID_VTABLE_ADDR
        struct.pack_into("<Q", obj_blob, 0, vtable_value)
        if entry.get("name_entry_id") is not None:
            struct.pack_into("<I", obj_blob, NAME_PRIVATE_OFFSET, entry["name_entry_id"])
        struct.pack_into("<Q", obj_blob, CLASS_PRIVATE_OFFSET, entry.get("class_ptr", 0))
        struct.pack_into("<Q", obj_blob, OUTER_PRIVATE_OFFSET, entry.get("outer_ptr", 0))
        memory[address] = bytes(obj_blob)
        struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, address)

    memory[items_addr] = bytes(items_blob)
    memory[chunk_table_addr] = struct.pack("<Q", items_addr)
    return memory, chunk_table_addr


# --------------------------------------------------------------------------- #
# constants sanity
# --------------------------------------------------------------------------- #

def test_default_class_private_offset_derivation():
    # vtable(8) + ObjectFlags(4) + InternalIndex(4) + = +0x10, matching
    # UObjectBase.h's own declaration order (DEFAULT_NAME_PRIVATE_OFFSET's
    # own comment carries the full derivation).
    assert tool.DEFAULT_CLASS_PRIVATE_OFFSET == 0x10


def test_default_outer_private_offset_derivation():
    # NamePrivate's own offset (+0x18) + FName's own proven 8-byte size.
    assert tool.DEFAULT_OUTER_PRIVATE_OFFSET == tool.DEFAULT_NAME_PRIVATE_OFFSET + 8
    assert tool.DEFAULT_OUTER_PRIVATE_OFFSET == 0x20


# --------------------------------------------------------------------------- #
# _pointer_is_plausible / _vtable_pointer_in_module_range
# --------------------------------------------------------------------------- #

def test_pointer_is_plausible_rejects_null():
    assert tool._pointer_is_plausible(0) is False


def test_pointer_is_plausible_rejects_misaligned():
    assert tool._pointer_is_plausible(BASE_ADDRESS + 1) is False


def test_pointer_is_plausible_accepts_aligned_nonnull_even_outside_image():
    # object/class/outer addresses are heap-allocated -- legitimately
    # outside the module's own image range, and must NOT be rejected for
    # that reason alone.
    far_heap_addr = BASE_ADDRESS + IMAGE_SIZE_BYTES + 0x10_000_000
    assert far_heap_addr % 8 == 0
    assert tool._pointer_is_plausible(far_heap_addr) is True


def test_vtable_pointer_in_module_range():
    assert tool._vtable_pointer_in_module_range(
        BASE_ADDRESS + 0x100, BASE_ADDRESS, IMAGE_SIZE_BYTES) is True
    assert tool._vtable_pointer_in_module_range(
        BASE_ADDRESS + IMAGE_SIZE_BYTES, BASE_ADDRESS, IMAGE_SIZE_BYTES) is False  # exclusive end
    assert tool._vtable_pointer_in_module_range(
        BASE_ADDRESS - 1, BASE_ADDRESS, IMAGE_SIZE_BYTES) is False


# --------------------------------------------------------------------------- #
# _classify_object -- structural validation checks 1-3, per-object.
# --------------------------------------------------------------------------- #

def _single_object_universe(entry: dict, *, name_text: str = "Foo", name_id: int = 0x10000):
    """One object at index 0, whose OWN NamePrivate decodes to *name_text*.
    Returns (api, object_ptr).
    """
    entry = dict(entry)
    entry.setdefault("name_entry_id", name_id)
    chunk_memory, _ = make_i04_object_chunk_memory([entry])
    fnamepool_memory, _ = make_fnamepool_memory(entries={name_id: (name_text, False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    return api, obj_addr(0)


def test_classify_object_valid_native_class_shape():
    api, object_ptr = _single_object_universe(
        {"class_ptr": obj_addr(0), "outer_ptr": 0}, name_text="Class")
    record = tool._classify_object(
        api, 1, object_ptr, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is True
    assert record["rejection_kind"] is None
    assert record["name_text"] == "Class"
    assert record["name_ok"] is True
    assert record["class_ptr"] == object_ptr
    assert record["outer_ptr"] == 0
    assert record["outer_ok"] is True


def test_classify_object_rejects_misaligned_object_pointer_without_reading():
    api = MemoryFakeApi(memory={})  # nothing configured -- a read would AssertionError
    misaligned = obj_addr(0) + 1
    record = tool._classify_object(
        api, 1, misaligned, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "pointer_alignment"
    assert "not a plausible" in record["rejection_reason"]


def test_classify_object_rejects_undecodable_name():
    entry = {"class_ptr": obj_addr(0), "outer_ptr": 0, "name_entry_id": 0x40000}
    chunk_memory, _ = make_i04_object_chunk_memory([entry])
    # a header claiming length 3 followed by an invalid ASCII byte.
    block_base = NAMEPOOL_VA + 0x00100000
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    header = (0 & 0x1) | (0x07 << 1) | ((3 & 0x3FF) << 6)
    entry_bytes = struct.pack("<H", header) + b"\xffAB"
    memory = dict(chunk_memory)
    memory[NAME_POOL_INITIALIZED_VA] = b"\x01"
    memory[blocks_table_addr] = struct.pack("<Q", block_base) * 8  # covers block 0..7
    memory[block_base] = entry_bytes
    api = MemoryFakeApi(memory=memory)
    record = tool._classify_object(
        api, 1, obj_addr(0), base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "name_decode"
    assert record["name_ok"] is False


def test_classify_object_rejects_null_class_pointer():
    api, object_ptr = _single_object_universe({"class_ptr": 0, "outer_ptr": 0})
    record = tool._classify_object(
        api, 1, object_ptr, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "class_pointer_implausible"
    # the object's own name/outer are still recorded -- checks 1-2 passed,
    # only check 3 (ClassPrivate) failed, per the module docstring's own
    # "does not invalidate the object's basic identity" rule for ancestors.
    assert record["name_ok"] is True


def test_classify_object_rejects_misaligned_class_pointer():
    api, object_ptr = _single_object_universe({"class_ptr": obj_addr(0) + 3, "outer_ptr": 0})
    record = tool._classify_object(
        api, 1, object_ptr, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "class_pointer_implausible"


def test_classify_object_rejects_class_pointer_with_out_of_range_vtable():
    # a SECOND object (index 1) whose own vtable is 'invalid' (outside the
    # module range) -- the FIRST object's ClassPrivate points at it.
    entries = [
        {"class_ptr": obj_addr(1), "outer_ptr": 0, "name_entry_id": 0x10000},
        {"class_ptr": obj_addr(1), "outer_ptr": 0, "vtable": "invalid",
         "name_entry_id": 0x20000},
    ]
    chunk_memory, _ = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("Foo", False), 0x20000: ("BadClass", False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    record = tool._classify_object(
        api, 1, obj_addr(0), base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "class_pointer_implausible"
    assert "vtable pointer" in record["rejection_reason"]


def test_classify_object_read_failure_on_already_located_object_is_a_rejection_not_a_raise():
    entry = {"class_ptr": obj_addr(0), "outer_ptr": 0, "name_entry_id": 0x10000}
    chunk_memory, _ = make_i04_object_chunk_memory([entry])
    memory = dict(chunk_memory)
    api = MemoryFakeApi(
        memory=memory, fail_read_addresses={obj_addr(0) + NAME_PRIVATE_OFFSET})
    record = tool._classify_object(
        api, 1, obj_addr(0), base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_live_va=NAMEPOOL_VA, class_private_offset=CLASS_PRIVATE_OFFSET,
        name_private_offset=NAME_PRIVATE_OFFSET, outer_private_offset=OUTER_PRIVATE_OFFSET)
    assert record["valid"] is False
    assert record["rejection_kind"] == "read_failure"


# --------------------------------------------------------------------------- #
# resolve_object_path -- 0-level (package itself), 1-level (common case),
# 2+-level (":" subobject delimiter), cycle detection, depth bound.
# --------------------------------------------------------------------------- #

def _record(name_text, outer_ptr, *, name_ok=True, outer_ok=True):
    return {"name_text": name_text, "name_ok": name_ok, "outer_ptr": outer_ptr,
            "outer_ok": outer_ok}


def test_resolve_object_path_zero_level_package_itself():
    objects = {obj_addr(0): _record("/Script/MISERY", 0)}
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is True
    assert result["object_path"] == "/Script/MISERY"
    assert result["package"] == "/Script/MISERY"
    assert result["note"] is None


def test_resolve_object_path_one_level_common_case():
    objects = {
        obj_addr(0): _record("MiseryFocusSubsystem", obj_addr(1)),
        obj_addr(1): _record("/Script/MISERY", 0),
    }
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is True
    assert result["object_path"] == "/Script/MISERY.MiseryFocusSubsystem"
    assert result["package"] == "/Script/MISERY"


def test_resolve_object_path_deep_nesting_uses_colon_delimiter():
    # Baz -> Bar -> /Game/Foo (Outer null): "/Game/Foo.Bar:Baz"
    objects = {
        obj_addr(0): _record("Baz", obj_addr(1)),
        obj_addr(1): _record("Bar", obj_addr(2)),
        obj_addr(2): _record("/Game/Foo", 0),
    }
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is True
    assert result["object_path"] == "/Game/Foo.Bar:Baz"
    assert result["package"] == "/Game/Foo"


def test_resolve_object_path_cycle_detection_does_not_hang():
    # A <-> B, a deliberately looping Outer chain.
    objects = {
        obj_addr(0): _record("A", obj_addr(1)),
        obj_addr(1): _record("B", obj_addr(0)),
    }
    result = tool.resolve_object_path(obj_addr(0), objects, max_depth=100)
    assert result["ok"] is False
    assert "cycle" in result["note"].lower()


def test_resolve_object_path_self_referential_outer_is_a_cycle():
    objects = {obj_addr(0): _record("Weird", obj_addr(0))}
    result = tool.resolve_object_path(obj_addr(0), objects, max_depth=100)
    assert result["ok"] is False
    assert "cycle" in result["note"].lower()


def test_resolve_object_path_depth_bound_enforced():
    # A real, non-cyclic chain of 20 ancestors -- must fail once max_depth
    # (16) is exceeded, not hang and not silently truncate a wrong answer.
    objects = {}
    for i in range(20):
        outer = obj_addr(i + 1) if i < 19 else 0
        objects[obj_addr(i)] = _record("Level%d" % i, outer)
    result = tool.resolve_object_path(obj_addr(0), objects, max_depth=16)
    assert result["ok"] is False
    assert "max depth" in result["note"].lower()


def test_resolve_object_path_within_depth_bound_succeeds():
    # Exactly 3 ancestors -- comfortably under a max_depth of 16.
    objects = {
        obj_addr(0): _record("Leaf", obj_addr(1)),
        obj_addr(1): _record("Mid", obj_addr(2)),
        obj_addr(2): _record("/Game/Deep", 0),
    }
    result = tool.resolve_object_path(obj_addr(0), objects, max_depth=16)
    assert result["ok"] is True


def test_resolve_object_path_unresolved_ancestor_is_a_failure_not_a_crash():
    objects = {obj_addr(0): _record("Foo", obj_addr(99))}  # obj_addr(99) never located
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is False
    assert "unresolved" in result["note"].lower()


def test_resolve_object_path_ancestor_with_undecoded_name_is_unresolved():
    objects = {
        obj_addr(0): _record("Foo", obj_addr(1)),
        obj_addr(1): _record(None, 0, name_ok=False),
    }
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is False


def test_resolve_object_path_unusual_top_level_name_is_best_effort_flagged():
    # top-level ancestor whose name does NOT start with "/" -- unusual, but
    # still produces a best-effort path with 'ok' True and a note.
    objects = {obj_addr(0): _record("NotAPackage", 0)}
    result = tool.resolve_object_path(obj_addr(0), objects)
    assert result["ok"] is True
    assert result["object_path"] == "NotAPackage"
    assert result["package"] is None
    assert result["note"] is not None and "unusual" in result["note"].lower()


# --------------------------------------------------------------------------- #
# walk_object_universe -- the full-array walk, corruption bookkeeping.
# --------------------------------------------------------------------------- #

def test_walk_object_universe_counts_valid_and_rejected():
    entries = [
        {"class_ptr": obj_addr(2), "outer_ptr": 0, "name_entry_id": 0x10000},  # valid
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x20000},  # class_ptr null -> rejected
        {"class_ptr": obj_addr(2), "outer_ptr": 0, "name_entry_id": 0x30000},  # valid (self-ref-ish)
    ]
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("A", False), 0x20000: ("B", False), 0x30000: ("C", False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    walk = tool.walk_object_universe(
        api, 1, objects_ptr, 3, BASE_ADDRESS, IMAGE_SIZE_BYTES, NAMEPOOL_VA,
        max_scan_indices=100)
    assert walk["indices_scanned"] == 3
    assert walk["objects_located"] == 3
    assert walk["valid_count"] == 2
    assert walk["rejected_counts"]["class_pointer_implausible"] == 1
    assert len(walk["objects_by_address"]) == 3


def test_walk_object_universe_skips_null_and_unreadable_slots():
    entries = [
        {"class_ptr": obj_addr(0), "outer_ptr": 0, "name_entry_id": 0x10000},
        None,  # a freed/never-allocated slot
    ]
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={0x10000: ("A", False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    walk = tool.walk_object_universe(
        api, 1, objects_ptr, 2, BASE_ADDRESS, IMAGE_SIZE_BYTES, NAMEPOOL_VA,
        max_scan_indices=100)
    assert walk["indices_scanned"] == 2
    assert walk["objects_located"] == 1


# --------------------------------------------------------------------------- #
# find_uclass_self_reference -- the seed, cross-checked, honest failure.
# --------------------------------------------------------------------------- #

def test_find_uclass_self_reference_finds_and_cross_checks():
    objects = {
        obj_addr(0): {
            "valid": True, "class_ptr": obj_addr(0), "name_text": "Class",
            "name_ok": True, "outer_ptr": obj_addr(1), "outer_ok": True},
        obj_addr(1): {
            "valid": True, "class_ptr": obj_addr(0), "name_text": "/Script/CoreUObject",
            "name_ok": True, "outer_ptr": 0, "outer_ok": True},
    }
    seed = tool.find_uclass_self_reference(
        objects, path_resolver=lambda addr: tool.resolve_object_path(addr, objects))
    assert seed is not None
    assert seed["address"] == obj_addr(0)


def test_find_uclass_self_reference_none_found_reports_honestly():
    objects = {
        obj_addr(0): {
            "valid": True, "class_ptr": obj_addr(1), "name_text": "NotClass",
            "name_ok": True, "outer_ptr": 0, "outer_ok": True},
    }
    seed = tool.find_uclass_self_reference(
        objects, path_resolver=lambda addr: tool.resolve_object_path(addr, objects))
    assert seed is None


def test_find_uclass_self_reference_self_ref_but_wrong_name_is_not_accepted():
    """A self-referential ClassPrivate ALONE is not enough -- must also
    cross-check the decoded name/object_path, per the module docstring's
    'never merely trusted' rule.
    """
    objects = {
        obj_addr(0): {
            "valid": True, "class_ptr": obj_addr(0), "name_text": "SomethingElse",
            "name_ok": True, "outer_ptr": 0, "outer_ok": True},
    }
    seed = tool.find_uclass_self_reference(
        objects, path_resolver=lambda addr: tool.resolve_object_path(addr, objects))
    assert seed is None


def test_find_uclass_self_reference_self_ref_but_wrong_path_is_not_accepted():
    objects = {
        obj_addr(0): {
            "valid": True, "class_ptr": obj_addr(0), "name_text": "Class",
            "name_ok": True, "outer_ptr": obj_addr(1), "outer_ok": True},
        obj_addr(1): {
            "valid": True, "class_ptr": obj_addr(0), "name_text": "/Script/WrongModule",
            "name_ok": True, "outer_ptr": 0, "outer_ok": True},
    }
    seed = tool.find_uclass_self_reference(
        objects, path_resolver=lambda addr: tool.resolve_object_path(addr, objects))
    assert seed is None


# --------------------------------------------------------------------------- #
# compute_class_identity -- the two-round fixed point, the operator's own
# 5-object worked example: Class, BlueprintGeneratedClass (Class=Class),
# MiseryFocusSubsystem (Class=Class), a Blueprint-class-instance
# (Class=BlueprintGeneratedClass), and a plain gameplay object instance
# (Class=MiseryFocusSubsystem). Correct classification: True/True/True/True/
# False respectively (is-a-UClass), and is_blueprint_generated True ONLY
# for the Blueprint-class-instance one.
#
# NOTE for the reviewer: the task this capability was specified from
# summarizes the expected is-a-UClass sequence as "true/false/true/true/
# false", which would classify the "BlueprintGeneratedClass" object itself
# as NOT a UClass. That contradicts BOTH real UE C++ semantics (UClass,
# UScriptStruct, UFunction, UEnum and UBlueprintGeneratedClass are ALL
# native types whose own metaclass is UClass, so BlueprintGeneratedClass's
# own ClassPrivate=="Class", exactly like MiseryFocusSubsystem's) AND the
# SAME task's own algorithm description two paragraphs earlier ("pass 1
# adds every native 'type descriptor' UClass (Class itself, ScriptStruct,
# Function, Enum, BlueprintGeneratedClass, and every ordinary native UClass
# like MiseryFocusSubsystem...)" -- explicitly listing BlueprintGeneratedClass
# among the objects that DO join in pass 1, i.e. True). This test asserts
# the architecturally correct True/True/True/True/False, not the
# summary sentence's apparent "false" for object 2 -- see
# compute_class_identity()'s own docstring for the full reasoning this
# resolves against, and flag this specific discrepancy for review.
# --------------------------------------------------------------------------- #

def _five_object_fixture():
    """Index map: 0=CoreUObject pkg, 1=Class(seed), 2=Engine pkg,
    3=BlueprintGeneratedClass, 4=MISERY pkg, 5=MiseryFocusSubsystem,
    6=Game/Foo pkg, 7=Blueprint-class-instance (BP_Foo_C),
    8=plain gameplay object instance (an ordinary MiseryFocusSubsystem
    instance).
    """
    entries = [
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x10000},              # 0: /Script/CoreUObject
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(0),
         "name_entry_id": 0x20000},                                              # 1: Class (seed)
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x30000},              # 2: /Script/Engine
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(2),
         "name_entry_id": 0x40000},                                              # 3: BlueprintGeneratedClass
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x50000},              # 4: /Script/MISERY
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(4),
         "name_entry_id": 0x60000},                                              # 5: MiseryFocusSubsystem
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x70000},              # 6: /Game/Foo
        {"class_ptr": obj_addr(3), "outer_ptr": obj_addr(6),
         "name_entry_id": 0x80000},                                              # 7: BP_Foo_C (BP class instance)
        {"class_ptr": obj_addr(5), "outer_ptr": obj_addr(6),
         "name_entry_id": 0x90000},                                              # 8: plain gameplay instance
    ]
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("/Script/CoreUObject", False),
        0x20000: ("Class", False),
        0x30000: ("/Script/Engine", False),
        0x40000: ("BlueprintGeneratedClass", False),
        0x50000: ("/Script/MISERY", False),
        0x60000: ("MiseryFocusSubsystem", False),
        0x70000: ("/Game/Foo", False),
        0x80000: ("BP_Foo_C", False),
        0x90000: ("SomeActorInstance", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    return memory, objects_ptr, len(entries)


def test_run_i04_five_object_classification():
    memory, objects_ptr, num_elements = _five_object_fixture()
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i04(
        api, 1, BASE_ADDRESS, IMAGE_SIZE_BYTES, objects_ptr, num_elements, NAMEPOOL_VA,
        max_scan_indices=100)
    assert result["seed_found"] is True
    assert result["fixed_point_converged"] is True

    by_addr = {c["address"]: c for c in result["classes"]}
    is_class = {
        obj_addr(1): obj_addr(1) in by_addr,      # Class
        obj_addr(3): obj_addr(3) in by_addr,      # BlueprintGeneratedClass
        obj_addr(5): obj_addr(5) in by_addr,      # MiseryFocusSubsystem
        obj_addr(7): obj_addr(7) in by_addr,      # BP_Foo_C instance-of-BGC
        obj_addr(8): obj_addr(8) in by_addr,      # plain gameplay instance
    }
    assert is_class[obj_addr(1)] is True
    assert is_class[obj_addr(3)] is True
    assert is_class[obj_addr(5)] is True
    assert is_class[obj_addr(7)] is True
    assert is_class[obj_addr(8)] is False  # NOT a UClass -- an ordinary instance

    assert by_addr[obj_addr(1)]["is_blueprint_generated"] is False
    assert by_addr[obj_addr(3)]["is_blueprint_generated"] is False
    assert by_addr[obj_addr(5)]["is_blueprint_generated"] is False
    assert by_addr[obj_addr(7)]["is_blueprint_generated"] is True  # true ONLY for this one

    assert by_addr[obj_addr(1)]["object_path"] == "/Script/CoreUObject.Class"
    assert by_addr[obj_addr(3)]["object_path"] == "/Script/Engine.BlueprintGeneratedClass"
    assert by_addr[obj_addr(5)]["object_path"] == "/Script/MISERY.MiseryFocusSubsystem"
    assert by_addr[obj_addr(7)]["object_path"] == "/Game/Foo.BP_Foo_C"


def test_run_i04_widget_blueprint_generated_class_is_classified_correctly():
    """Regression pin for a real defect found by a targeted layout+safety
    review of this workflow (2026-08-27): the original class-identity
    computation grew from exactly two FIXED roots {seed,
    BlueprintGeneratedClass}, so it silently missed instances of
    UWidgetBlueprintGeneratedClass -- a real, distinct native UE 5.4 type
    (Engine/Source/Runtime/UMG/Public/Blueprint/
    WidgetBlueprintGeneratedClass.h) that is NOT literally named
    "BlueprintGeneratedClass" but still plays the exact same
    "class-of-a-Blueprint-asset" role, named by UE's own convention with
    the same "GeneratedClass" suffix. This fixture never mentions the
    literal name "BlueprintGeneratedClass" for the Widget Blueprint's own
    class chain at all, to prove the fix is genuinely general (name-suffix
    based) and not a second hardcoded special case.

    Index map: 0=CoreUObject pkg, 1=Class (seed), 2=UMG pkg,
    3=WidgetBlueprintGeneratedClass (a meta-type, NOT literally named
    "BlueprintGeneratedClass"), 4=Game/UI pkg, 5=WBP_MainMenu_C (an actual
    live Widget Blueprint asset, instance-of-WidgetBlueprintGeneratedClass).
    """
    entries = [
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x10000},              # 0: /Script/CoreUObject
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(0),
         "name_entry_id": 0x20000},                                              # 1: Class (seed)
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x30000},              # 2: /Script/UMG
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(2),
         "name_entry_id": 0x40000},                                              # 3: WidgetBlueprintGeneratedClass
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x50000},              # 4: /Game/UI
        {"class_ptr": obj_addr(3), "outer_ptr": obj_addr(4),
         "name_entry_id": 0x60000},                                              # 5: WBP_MainMenu_C
    ]
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("/Script/CoreUObject", False),
        0x20000: ("Class", False),
        0x30000: ("/Script/UMG", False),
        0x40000: ("WidgetBlueprintGeneratedClass", False),
        0x50000: ("/Game/UI", False),
        0x60000: ("WBP_MainMenu_C", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i04(
        api, 1, BASE_ADDRESS, IMAGE_SIZE_BYTES, objects_ptr, len(entries), NAMEPOOL_VA,
        max_scan_indices=100)
    assert result["seed_found"] is True

    by_addr = {c["address"]: c for c in result["classes"]}
    # WidgetBlueprintGeneratedClass itself IS a UClass (a native meta-type,
    # caught in round 1 -- its own ClassPrivate is "Class" directly).
    assert obj_addr(3) in by_addr
    assert by_addr[obj_addr(3)]["is_blueprint_generated"] is False
    # The critical assertion: the actual Widget Blueprint asset must ALSO
    # be classified as a UClass -- this is exactly what the two-fixed-roots
    # design silently missed.
    assert obj_addr(5) in by_addr, (
        "WBP_MainMenu_C (an instance of WidgetBlueprintGeneratedClass, not "
        "literally 'BlueprintGeneratedClass') was not classified as a "
        "UClass -- the meta-type-root generalization regressed.")
    assert by_addr[obj_addr(5)]["is_blueprint_generated"] is True
    assert by_addr[obj_addr(5)]["object_path"] == "/Game/UI.WBP_MainMenu_C"
    # meta_type_roots must have discovered WidgetBlueprintGeneratedClass by
    # name pattern, not via the separate, BlueprintGeneratedClass-only
    # find_blueprint_generated_class_address() cross-check (which correctly
    # finds nothing here, since this fixture has no object literally named
    # "BlueprintGeneratedClass" at all).
    assert "WidgetBlueprintGeneratedClass" in result["meta_type_roots"]
    assert result["blueprint_generated_class_address_hex"] is None


def test_run_i04_seed_not_found_reports_zero_classes_honestly():
    """No self-referential object exists in this synthetic image -- must
    report zero UClass instances found, not crash or guess.
    """
    entries = [
        {"class_ptr": obj_addr(1), "outer_ptr": 0, "name_entry_id": 0x10000},
        {"class_ptr": obj_addr(0), "outer_ptr": 0, "name_entry_id": 0x20000},
    ]
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("A", False), 0x20000: ("B", False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i04(
        api, 1, BASE_ADDRESS, IMAGE_SIZE_BYTES, objects_ptr, 2, NAMEPOOL_VA,
        max_scan_indices=100)
    assert result["seed_found"] is False
    assert result["classes"] == []
    assert result["class_address_universe_size"] == 0
    assert "seed search failed" in result["note"]


def test_compute_class_identity_does_not_sweep_in_instances_of_native_classes():
    """Regression pin for the general-vs-roots distinction: a fixed point
    that (wrongly) grows from 'any address already in the universe' would
    ALSO admit obj_addr(8) (a plain instance of MiseryFocusSubsystem) once
    MiseryFocusSubsystem itself joins round 1. The correct, roots-based
    implementation must not.
    """
    memory, objects_ptr, num_elements = _five_object_fixture()
    api = MemoryFakeApi(memory=memory)
    walk = tool.walk_object_universe(
        api, 1, objects_ptr, num_elements, BASE_ADDRESS, IMAGE_SIZE_BYTES, NAMEPOOL_VA,
        max_scan_indices=100)
    objects_by_address = walk["objects_by_address"]

    def path_of(addr):
        return tool.resolve_object_path(addr, objects_by_address)

    seed = tool.find_uclass_self_reference(objects_by_address, path_resolver=path_of)
    assert seed is not None
    fixed_point = tool.compute_class_identity(
        objects_by_address, seed["address"], path_resolver=path_of)
    assert obj_addr(8) not in fixed_point["class_address_universe"]
    assert obj_addr(5) in fixed_point["class_address_universe"]


# --------------------------------------------------------------------------- #
# classify_classes_by_module / select_game_sample
# --------------------------------------------------------------------------- #

def _entry(raw_name, object_path, package, is_bp=None):
    return {
        "address": 1, "address_hex": "0x1", "raw_name": raw_name,
        "object_path": object_path, "package": package,
        "object_path_ok": True, "object_path_note": None,
        "is_blueprint_generated": is_bp,
    }


def test_classify_classes_by_module_buckets_correctly():
    classes = [
        _entry("MiseryFocusSubsystem", "/Script/MISERY.MiseryFocusSubsystem", "/Script/MISERY"),
        _entry("BP_Foo_C", "/Game/Foo.BP_Foo_C", "/Game/Foo", is_bp=True),
        _entry("SomeEngineClass", "/Script/Engine.SomeEngineClass", "/Script/Engine"),
    ]
    buckets = tool.classify_classes_by_module(classes)
    assert len(buckets["misery"]) == 1
    assert buckets["misery"][0]["module"] == "/Script/MISERY"
    assert buckets["misery"][0]["module_origin"] == "game-misery"
    assert len(buckets["game"]) == 1
    assert buckets["game"][0]["module"] is None
    assert len(buckets["other"]) == 1
    assert buckets["other"][0]["module_origin"] == "unclassified"


def test_select_game_sample_prioritizes_blueprint_generated_and_caps():
    classes = (
        [_entry("Plain%d" % i, "/Game/X.Plain%d" % i, "/Game/X") for i in range(3)] +
        [_entry("BP%d_C" % i, "/Game/X.BP%d_C" % i, "/Game/X", is_bp=True) for i in range(2)])
    sample = tool.select_game_sample(classes, cap=3)
    assert len(sample) == 3
    assert sample[0]["is_blueprint_generated"] is True
    assert sample[1]["is_blueprint_generated"] is True
    assert sample[2]["is_blueprint_generated"] is not True  # fills remaining capacity


def test_select_game_sample_no_cap_truncation_when_under_cap():
    classes = [_entry("A", "/Game/X.A", "/Game/X")]
    sample = tool.select_game_sample(classes, cap=25)
    assert len(sample) == 1


# --------------------------------------------------------------------------- #
# build_i04_class_record / dump_jsonl -- shape, and validated against the
# REAL research/schema/reflection-record.schema.json composed with
# kb-record.schema.json, reusing test_eri_i01's own offline registry helper.
# --------------------------------------------------------------------------- #

def _classes_record_validator():
    pytest.importorskip("jsonschema")
    pytest.importorskip("referencing")
    from jsonschema import Draft202012Validator
    schema = i01_tests._load_schema("reflection-record.schema.json")
    return Draft202012Validator(schema, registry=i01_tests._build_registry())


def test_build_i04_class_record_misery_shape_and_grading():
    entry = {
        "address_hex": "0x1000", "raw_name": "MiseryFocusSubsystem",
        "object_path": "/Script/MISERY.MiseryFocusSubsystem",
        "package": "/Script/MISERY", "module": "/Script/MISERY",
        "module_origin": "game-misery", "object_path_ok": True,
        "object_path_note": None, "is_blueprint_generated": False,
    }
    row = tool.build_i04_class_record(
        entry, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        cross_checked=True)
    assert row["kind"] == "class"
    assert row["raw_name"] == "MiseryFocusSubsystem"
    assert row["confidence"] == 0.90
    assert row["evidence_level"] == "OBSERVED"
    assert row["claim_class"] == "I"
    assert row["oracle"] == ["runtime-reflection", "global-ucas"]
    assert len(row["sources"]) == 2
    assert row["module"] == "/Script/MISERY"
    assert row["module_origin"] == "game-misery"
    assert row["is_native"] is None
    assert row["size"] is None
    assert row["super"] is None
    json.loads(tool.dump_json(row))


def test_build_i04_class_record_game_sample_shape_and_grading():
    entry = {
        "address_hex": "0x2000", "raw_name": "BP_Foo_C",
        "object_path": "/Game/Foo.BP_Foo_C", "package": "/Game/Foo",
        "module": None, "module_origin": "unclassified", "object_path_ok": True,
        "object_path_note": None, "is_blueprint_generated": True,
    }
    row = tool.build_i04_class_record(
        entry, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        cross_checked=False)
    assert row["confidence"] == 0.75
    assert row["oracle"] == ["runtime-reflection"]
    assert len(row["sources"]) == 1
    assert row["is_blueprint_generated"] is True
    assert row["claim_type"] == "asset-exists"
    json.loads(tool.dump_json(row))


def test_build_i04_class_record_validates_against_real_schema():
    validator = _classes_record_validator()
    entry = {
        "address_hex": "0x1000", "raw_name": "MiseryFocusSubsystem",
        "object_path": "/Script/MISERY.MiseryFocusSubsystem",
        "package": "/Script/MISERY", "module": "/Script/MISERY",
        "module_origin": "game-misery", "object_path_ok": True,
        "object_path_note": None, "is_blueprint_generated": False,
    }
    row = tool.build_i04_class_record(
        entry, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        cross_checked=True)
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_build_i04_class_record_game_sample_validates_against_real_schema():
    validator = _classes_record_validator()
    entry = {
        "address_hex": "0x2000", "raw_name": "BP_Foo_C",
        "object_path": "/Game/Foo.BP_Foo_C", "package": "/Game/Foo",
        "module": None, "module_origin": "unclassified", "object_path_ok": True,
        "object_path_note": None, "is_blueprint_generated": True,
    }
    row = tool.build_i04_class_record(
        entry, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        cross_checked=False)
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_dump_jsonl_shape():
    rows = [{"b": 2, "a": 1}, {"d": 4, "c": 3}]
    text = tool.dump_jsonl(rows)
    lines = text.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1, "b": 2}
    assert text.endswith("\n")


def test_dump_jsonl_empty_list_is_empty_string():
    assert tool.dump_jsonl([]) == ""


# --------------------------------------------------------------------------- #
# build_i04_document
# --------------------------------------------------------------------------- #

def test_build_i04_document_shape():
    result = {
        "seed_found": True, "seed_address_hex": "0x1000",
        "class_address_universe_size": 4, "round1_size": 3,
        "blueprint_generated_class_address_hex": "0x2000",
        "fixed_point_passes_run": 3, "fixed_point_converged": True,
        "walk": {"indices_scanned": 9, "objects_located": 9, "valid_count": 9,
                 "rejected_counts": {"pointer_alignment": 0, "read_failure": 0,
                                     "name_decode": 0, "class_pointer_implausible": 0}},
        "note": None,
    }
    doc = tool.build_i04_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None,
        misery_classes_count=5, game_classes_total_count=12,
        game_classes_sample_count=12, other_classes_count=340)
    assert doc["capability"] == "I-04"
    assert doc["misery_classes_count"] == 5
    assert doc["game_classes_total_count"] == 12
    assert doc["other_classes_count"] == 340
    assert "evidence_level" not in doc
    assert "oracle" not in doc
    json.loads(tool.dump_json(doc))


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_cli_run_i04_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_i04 is False
    assert args.class_private_offset is None
    assert args.outer_private_offset is None
    assert args.i04_max_scan_indices == tool.DEFAULT_I02_MAX_SCAN_INDICES
    assert args.i04_max_outer_depth == tool.DEFAULT_I04_MAX_OUTER_DEPTH
    assert args.i04_max_fixed_point_passes == tool.DEFAULT_I04_MAX_FIXED_POINT_PASSES
    assert args.i04_game_sample_cap == tool.DEFAULT_I04_GAME_SAMPLE_CAP
    assert args.i04_out is None
    assert args.classes_jsonl_out is None


def test_parse_class_private_offset_default_and_override():
    assert tool._parse_class_private_offset(None) == tool.DEFAULT_CLASS_PRIVATE_OFFSET
    assert tool._parse_class_private_offset("0x30") == 0x30
    with pytest.raises(ValueError):
        tool._parse_class_private_offset("garbage")


def test_parse_outer_private_offset_default_and_override():
    assert tool._parse_outer_private_offset(None) == tool.DEFAULT_OUTER_PRIVATE_OFFSET
    assert tool._parse_outer_private_offset("0x40") == 0x40
    with pytest.raises(ValueError):
        tool._parse_outer_private_offset("garbage")


def test_resolve_i04_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_i04_output_path(args) is None
    assert tool._resolve_classes_jsonl_path(args) is None


def test_resolve_i04_output_path_requires_i04_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i04"])
    with pytest.raises(ValueError):
        tool._resolve_i04_output_path(args)


def test_resolve_classes_jsonl_path_requires_flag_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i04"])
    with pytest.raises(ValueError):
        tool._resolve_classes_jsonl_path(args)


def test_resolve_i04_output_path_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(["--run-i04", "--run-dir", run_dir])
    assert tool._resolve_i04_output_path(args) == os.path.join(run_dir, "i04-classes.json")
    assert tool._resolve_classes_jsonl_path(args) == os.path.join(run_dir, "classes.jsonl")


def test_resolve_classes_jsonl_path_explicit_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit = str(tmp_path / "custom-classes.jsonl")
    args = tool.build_arg_parser().parse_args(
        ["--run-i04", "--run-dir", run_dir, "--classes-jsonl-out", explicit])
    assert tool._resolve_classes_jsonl_path(args) == explicit


def test_validate_i04_requirements_noop_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    tool._validate_i04_requirements(args)  # must not raise


def test_validate_i04_requirements_raises_when_missing_run_i02():
    args = tool.build_arg_parser().parse_args(["--run-i04", "--run-i03"])
    with pytest.raises(ValueError, match="--run-i02"):
        tool._validate_i04_requirements(args)


def test_validate_i04_requirements_raises_when_missing_run_i03():
    args = tool.build_arg_parser().parse_args(["--run-i04", "--run-i02"])
    with pytest.raises(ValueError, match="--run-i03"):
        tool._validate_i04_requirements(args)


def test_validate_i04_requirements_raises_when_missing_both():
    args = tool.build_arg_parser().parse_args(["--run-i04"])
    with pytest.raises(ValueError):
        tool._validate_i04_requirements(args)


def test_validate_i04_requirements_passes_when_both_given():
    args = tool.build_arg_parser().parse_args(["--run-i04", "--run-i02", "--run-i03"])
    tool._validate_i04_requirements(args)  # must not raise


# --------------------------------------------------------------------------- #
# main() end-to-end -- a synthetic fixture producing classes.jsonl with the
# expected /Script/MISERY rows, and a bounded /Game sample.
# --------------------------------------------------------------------------- #

def _fake_i04_api(tmp_path, memory, **fake_kwargs) -> tuple:
    exe_bytes = b"the live process's actual module bytes for an I-04 test"
    exe_path = i01_tests._write_stub_exe(tmp_path, "MISERY-Win64-Shipping.exe", exe_bytes)
    api = i02_tests.FakeWin32ApiWithMemory(
        processes=[i01_tests.proc(4242, i01_tests.TARGET_NAME)],
        modules_by_pid={4242: [i01_tests.mod(
            i01_tests.TARGET_NAME, exe_path, BASE_ADDRESS, IMAGE_SIZE_BYTES)]},
        memory=memory,
        **fake_kwargs)
    return api, exe_path


def _combined_i04_run_memory(entries: list, entries_text: dict, *,
                             max_elements: int = 100):
    """Combines the I-04 object-chunk memory with a GUObjectArray struct
    (I-02's own shape) and an FNamePool image (I-03's own), for a
    main()-level end-to-end --run-i02 --run-i03 --run-i04 test.
    """
    chunk_memory, objects_ptr = make_i04_object_chunk_memory(entries)
    struct_blob = bytearray(0x2C)
    struct.pack_into("<Q", struct_blob, tool.GUOBJECTARRAY_OFFSET_OBJECTS, objects_ptr)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_MAX_ELEMENTS, max_elements)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS, len(entries))
    memory = dict(chunk_memory)
    memory[GUOBJECTARRAY_VA] = bytes(struct_blob)
    fnamepool_memory, _ = make_fnamepool_memory(entries=entries_text)
    memory.update(fnamepool_memory)
    return memory


def _misery_five_class_fixture():
    """0=CoreUObject pkg, 1=Class(seed), 2=Engine pkg, 3=BlueprintGeneratedClass,
    4=/Script/MISERY pkg, 5-9=the five MISERY classes RF-01 also found.
    """
    misery_names = [
        "MiseryBlueprintFunctionLibrary", "MiseryEditableText",
        "MiseryFocusableWidget", "MiseryFocusSubsystem", "MiseryGameViewportClient",
    ]
    entries = [
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x10000},
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(0), "name_entry_id": 0x20000},
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x30000},
        {"class_ptr": obj_addr(1), "outer_ptr": obj_addr(2), "name_entry_id": 0x40000},
        {"class_ptr": 0, "outer_ptr": 0, "name_entry_id": 0x50000},
    ]
    entries_text = {
        0: ("None", False),  # run_i03()'s own default id=0 decode
        0x10000: ("/Script/CoreUObject", False), 0x20000: ("Class", False),
        0x30000: ("/Script/Engine", False), 0x40000: ("BlueprintGeneratedClass", False),
        0x50000: ("/Script/MISERY", False),
    }
    for i, name in enumerate(misery_names):
        idx = 5 + i
        entry_id = 0x60000 + i * 0x10000
        entries.append({"class_ptr": obj_addr(1), "outer_ptr": obj_addr(4),
                        "name_entry_id": entry_id})
        entries_text[entry_id] = (name, False)
    return entries, entries_text, misery_names


def test_main_run_i04_writes_classes_jsonl_with_expected_misery_rows(tmp_path, monkeypatch):
    entries, entries_text, misery_names = _misery_five_class_fixture()
    memory = _combined_i04_run_memory(entries, entries_text)
    api, _ = _fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "classes.jsonl"), encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    assert len(rows) == 5
    found_names = {row["raw_name"] for row in rows}
    assert found_names == set(misery_names)
    for row in rows:
        assert row["module"] == "/Script/MISERY"
        assert row["module_origin"] == "game-misery"
        assert row["confidence"] == 0.90
        assert row["object_path"].startswith("/Script/MISERY.")

    with open(os.path.join(run_dir, "i04-classes.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "I-04"
    assert doc["seed_found"] is True
    assert doc["misery_classes_count"] == 5

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03", "I-04"]
    assert any(a.endswith("i04-classes.json") for a in manifest["artifacts"])
    assert any(a.endswith("classes.jsonl") for a in manifest["artifacts"])


def test_main_run_i04_bounds_game_sample(tmp_path, monkeypatch):
    entries, entries_text, _ = _misery_five_class_fixture()
    # add 5 /Game Blueprint-class instances, capped to 2 by --i04-game-sample-cap.
    for i in range(5):
        idx = 10 + i
        entry_id = 0xA0000 + i * 0x10000
        pkg_id = 0x200000 + i * 0x10000  # well clear of entry_id's own 0xA0000.. range
        entries.append({"class_ptr": 0, "outer_ptr": 0, "name_entry_id": pkg_id})
        entries_text[pkg_id] = ("/Game/Foo%d" % i, False)
    first_pkg_index = len(entries) - 5  # index of the FIRST package entry just appended
    for i in range(5):
        entry_id = 0xA0000 + i * 0x10000
        pkg_index = first_pkg_index + i
        entries.append({
            "class_ptr": obj_addr(3), "outer_ptr": obj_addr(pkg_index),
            "name_entry_id": entry_id})
        entries_text[entry_id] = ("BP_Foo%d_C" % i, False)
    memory = _combined_i04_run_memory(entries, entries_text)
    api, _ = _fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100", "--i04-game-sample-cap", "2",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "classes.jsonl"), encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    game_rows = [r for r in rows if r["package"] and r["package"].startswith("/Game/")]
    assert len(game_rows) == 2  # bounded, not the full 5 found
    for row in game_rows:
        assert row["is_blueprint_generated"] is True
        assert row["confidence"] == 0.75

    with open(os.path.join(run_dir, "i04-classes.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["game_classes_total_count"] == 5  # full count, honestly reported
    assert doc["game_classes_sample_count"] == 2  # only this many written


def test_main_run_i04_seed_not_found_still_succeeds_with_empty_classes_jsonl(tmp_path, monkeypatch):
    entries = [
        {"class_ptr": obj_addr(1), "outer_ptr": 0, "name_entry_id": 0x10000},
        {"class_ptr": obj_addr(0), "outer_ptr": 0, "name_entry_id": 0x20000},
    ]
    entries_text = {0: ("None", False), 0x10000: ("A", False), 0x20000: ("B", False)}
    memory = _combined_i04_run_memory(entries, entries_text)
    api, _ = _fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "2",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0  # a failed seed search is a valid, honest finding, not a crash

    with open(os.path.join(run_dir, "classes.jsonl"), encoding="utf-8") as handle:
        content = handle.read()
    assert content == ""  # zero records, legitimately empty

    with open(os.path.join(run_dir, "i04-classes.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["seed_found"] is False
    assert doc["misery_classes_count"] == 0


def test_main_run_i04_requires_i02_and_i03_together(tmp_path, monkeypatch):
    api, _ = _fake_i04_api(tmp_path, memory={})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i04"])
    assert rc == 2
    assert not os.path.exists(run_dir)
    assert api.calls["open_process"] == 0


def test_main_without_run_i04_never_touches_i04_at_all(tmp_path, monkeypatch):
    entries, entries_text, _ = _misery_five_class_fixture()
    memory = _combined_i04_run_memory(entries, entries_text)
    api, _ = _fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i02", "--run-i03",
                    "--i02-poll-interval-seconds", "0"])
    assert rc == 0
    assert not os.path.exists(os.path.join(run_dir, "i04-classes.json"))
    assert not os.path.exists(os.path.join(run_dir, "classes.jsonl"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03"]


# --------------------------------------------------------------------------- #
# still exactly one ReadProcessMemory call site -- I-04 adds new CALLERS of
# Win32Api.read_process_memory, never a second wrapper.
# --------------------------------------------------------------------------- #

def test_source_still_has_exactly_one_readprocessmemory_call_site():
    source = open(tool.__file__, encoding="utf-8").read()
    assert source.count(".ReadProcessMemory(") == 1, (
        "eri.py must call ReadProcessMemory from exactly one place -- "
        "Win32Api.read_process_memory -- so a reviewer can audit it by "
        "reading one line")
