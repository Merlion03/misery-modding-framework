#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-06 (plan.md 8.2).

I-06 is the FProperty decoder: it walks each PROOF-SET class's own
UStruct::ChildProperties (+0x50 -- corrected LIVE this pass from an initial
+0x40, which missed UStruct's private FStructBaseChain base subobject
present in every non-editor/Shipping build; see USTRUCT_CHILD_PROPERTIES_
OFFSET's own comment in eri.py for the full derivation) Next-linked FField
sibling chain, decodes
each node via decode_property_type() (a REUSABLE, address-only FField/
FProperty decoder -- see its own module docstring in eri.py), dispatching on
FFieldClass::Name (never EClassCastFlags) after walking FFieldClass::
SuperClass to confirm "is this really an FProperty descendant", and applies
an Owner round-trip self-consistency check for every TOP-LEVEL chain entry.
No MISERY process runs in this environment (nor in CI), so every test below
exercises the plain-Python logic functions against a fake memory model --
the SAME "duck-typed narrow interface, faked in tests" idiom
tests/test_eri_i02.py/test_eri_i03.py/test_eri_i04.py already established,
cross-imported here rather than re-derived.

Run:  python -m pytest -q tests/test_eri_i06.py
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
# convention in this repo (test_eri_i04.py already does this for
# test_eri_i01/i02/i03). Reuses VALID_BUILD_KEY/TARGET_NAME/proc/mod/
# _write_stub_exe/_patch_fake_win32api/_load_schema/_build_registry from
# test_eri_i01, MemoryFakeApi/FakeWin32ApiWithMemory/BASE_ADDRESS/
# IMAGE_SIZE_BYTES/GUOBJECTARRAY_VA from test_eri_i02,
# make_fnamepool_memory/NAMEPOOL_VA/NAME_POOL_INITIALIZED_VA from
# test_eri_i03, and obj_addr/make_i04_object_chunk_memory/
# _misery_five_class_fixture/_combined_i04_run_memory/_fake_i04_api from
# test_eri_i04, rather than re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402
import test_eri_i02 as i02_tests  # noqa: E402
import test_eri_i03 as i03_tests  # noqa: E402
import test_eri_i04 as i04_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY
BASE_ADDRESS = i02_tests.BASE_ADDRESS
IMAGE_SIZE_BYTES = i02_tests.IMAGE_SIZE_BYTES
MemoryFakeApi = i02_tests.MemoryFakeApi
GUOBJECTARRAY_VA = i02_tests.GUOBJECTARRAY_VA

NAMEPOOL_VA = i03_tests.NAMEPOOL_VA
NAME_POOL_INITIALIZED_VA = i03_tests.NAME_POOL_INITIALIZED_VA
make_fnamepool_memory = i03_tests.make_fnamepool_memory

NAME_PRIVATE_OFFSET = tool.DEFAULT_NAME_PRIVATE_OFFSET


# --------------------------------------------------------------------------- #
# shared fake-memory helpers -- an FNameEntryId allocator (auto-incrementing,
# one dedicated block per distinct text, matching make_fnamepool_memory's own
# "offset==0 within its own block" requirement), an FFieldClass writer, an
# FField/FProperty object writer, and a plain "UObject with only a readable
# NamePrivate" writer for FObjectProperty/FClassProperty/FStructProperty/
# FEnumProperty's own referenced-type resolution tests.
# --------------------------------------------------------------------------- #

class _NameAllocator:
    """FNameEntryId 0 is always "None" (I-03's own confirmed id==0 mapping);
    every other distinct text gets its own dedicated block, auto-incrementing,
    so a test never has to hand-pick non-colliding ids itself.
    """

    def __init__(self, start_block: int = 1):
        self._next_block = start_block
        self.entries: dict = {0: ("None", False)}
        self._by_text: dict = {}

    def add(self, text: str) -> int:
        if text in self._by_text:
            return self._by_text[text]
        entry_id = self._next_block << tool.FNAME_BLOCK_OFFSET_BITS
        self._next_block += 1
        self.entries[entry_id] = (text, False)
        self._by_text[text] = entry_id
        return entry_id

    def reserve_block(self) -> int:
        """The next block number this allocator has NOT yet assigned to any
        text -- for a test that needs to construct a deliberately-corrupt
        FNameEntryId (an undecodable header) without colliding with any
        name this allocator has already registered or will register via
        add() afterward (add() always advances _next_block, never reuses a
        reserved-but-unassigned block).
        """
        block = self._next_block
        self._next_block += 1
        return block


FIELDCLASS_BASE = 0xA000_0000_0000
FIELDCLASS_STRIDE = 0x1000
FIELD_BASE = 0xA000_0001_0000
FIELD_STRIDE = 0x200
UOBJECT_BASE = 0xA000_0002_0000
UOBJECT_STRIDE = 0x100
CLASS_BASE = 0xA000_0003_0000
CLASS_STRIDE = 0x100


def fieldclass_addr(index: int) -> int:
    return FIELDCLASS_BASE + index * FIELDCLASS_STRIDE


def field_addr(index: int) -> int:
    return FIELD_BASE + index * FIELD_STRIDE


def uobject_addr(index: int) -> int:
    return UOBJECT_BASE + index * UOBJECT_STRIDE


def class_addr(index: int) -> int:
    return CLASS_BASE + index * CLASS_STRIDE


# FFieldClass::Name -> FFieldClass::SuperClass's own Name (None == root,
# SuperClass field written as 0). Deliberately simplified from the real
# engine hierarchy (real FProperty's own SuperClass is FField, not 0) --
# decode_property_type() only ever checks "FProperty" appears SOMEWHERE in
# the chain, never that the chain reaches an ULTIMATE root, so terminating
# synthetic chains right at FProperty keeps every test's own memory image
# smaller without weakening what is actually being exercised. "FField" is
# its own root with NO "FProperty" ancestor at all -- used by the
# not_a_property rejection test.
FIELDCLASS_HIERARCHY = {
    "FField": None,
    "FProperty": None,
    "FNumericProperty": "FProperty",
    "FBoolProperty": "FProperty",
    "FObjectProperty": "FProperty",
    "FClassProperty": "FObjectProperty",
    "FStructProperty": "FProperty",
    "FEnumProperty": "FProperty",
    "FArrayProperty": "FProperty",
    "FSetProperty": "FProperty",
    "FMapProperty": "FProperty",
    "FNameProperty": "FProperty",
    "FStrProperty": "FProperty",
    "FTextProperty": "FProperty",
    "FFloatProperty": "FNumericProperty",
    "FIntProperty": "FNumericProperty",
}


def build_fieldclass_registry(allocator: "_NameAllocator | None" = None) -> tuple:
    """Returns (memory: dict, addr_by_name: dict[str, int], allocator:
    _NameAllocator) -- every FFieldClass named in FIELDCLASS_HIERARCHY,
    wired to its own declared SuperClass. Callers merge *memory* into their
    own test's own memory dict and *allocator.entries* into the FNamePool
    fixture (make_fnamepool_memory(entries=...)).

    *allocator*, when given, lets a caller that ALSO has its own,
    independently-numbered FNameEntryIds in play (e.g. a main()-level
    end-to-end test reusing test_eri_i04's own fixture, whose entries_text
    already occupies low block numbers) supply an allocator pre-seeded with
    a start_block clear of that range -- so a SINGLE make_fnamepool_memory()
    call over the UNION of both dicts produces one consistent blocks table,
    rather than two independent calls each silently overwriting the other's
    own blocks_table_addr entry (see this session's own found-and-fixed
    test bug: two independent make_fnamepool_memory() calls, each keyed by
    the SAME default namepool_rva, collide on the identical blocks_table_addr
    dict key).
    """
    if allocator is None:
        allocator = _NameAllocator()
    names = list(FIELDCLASS_HIERARCHY.keys())
    addr_by_name = {name: fieldclass_addr(i) for i, name in enumerate(names)}
    memory: dict = {}
    for name in names:
        # FFieldClass::Name is stored WITHOUT the leading "F" -- the real
        # FFieldClass constructor strips it (Field.cpp:46-61, "Skip the 'F'
        # prefix for the name": `check(InCPPName[0] == 'F'); Name =
        # ++InCPPName;`), confirmed against a LIVE decode this session
        # (see FFIELDCLASS_NAME_PROPERTY's own comment in eri.py). name[1:]
        # simulates that stripping; addr_by_name stays keyed by the
        # F-prefixed name purely for this test file's own readability.
        assert name.startswith("F")
        name_id = allocator.add(name[1:])
        super_name = FIELDCLASS_HIERARCHY[name]
        super_ptr = addr_by_name[super_name] if super_name else 0
        blob = bytearray(0x28)
        struct.pack_into("<I", blob, tool.FFIELDCLASS_NAME_OFFSET, name_id)
        struct.pack_into("<Q", blob, tool.FFIELDCLASS_SUPERCLASS_OFFSET, super_ptr)
        memory[addr_by_name[name]] = bytes(blob)
    return memory, addr_by_name, allocator


def write_fproperty(memory: dict, addr: int, *, class_ptr: int, owner_raw: int,
                    next_ptr: int, name_id: int, array_dim: int = 1,
                    element_size: int = 4, property_flags: int = 0,
                    rep_index: int = 0, offset_internal: int = 0,
                    rep_notify_id: int = 0, extra: bytes = b"") -> None:
    """Writes one FField/FProperty object's own bytes (+0x00..+0x6F, plus
    *extra* starting at +0x70 for a type-specific decoder) into *memory*.
    """
    blob = bytearray(tool.FPROPERTY_SIZE_BYTES + len(extra))
    struct.pack_into("<Q", blob, tool.FFIELD_CLASS_PRIVATE_OFFSET, class_ptr)
    struct.pack_into("<Q", blob, tool.FFIELD_OWNER_OFFSET, owner_raw)
    struct.pack_into("<Q", blob, tool.FFIELD_NEXT_OFFSET, next_ptr)
    struct.pack_into("<I", blob, tool.FFIELD_NAME_PRIVATE_OFFSET, name_id)
    struct.pack_into("<i", blob, tool.FPROPERTY_ARRAY_DIM_OFFSET, array_dim)
    struct.pack_into("<i", blob, tool.FPROPERTY_ELEMENT_SIZE_OFFSET, element_size)
    struct.pack_into("<Q", blob, tool.FPROPERTY_PROPERTY_FLAGS_OFFSET, property_flags)
    struct.pack_into("<H", blob, tool.FPROPERTY_REP_INDEX_OFFSET, rep_index)
    struct.pack_into("<i", blob, tool.FPROPERTY_OFFSET_INTERNAL_OFFSET, offset_internal)
    struct.pack_into("<I", blob, tool.FPROPERTY_REP_NOTIFY_FUNC_OFFSET, rep_notify_id)
    if extra:
        blob[tool.FPROPERTY_SIZE_BYTES:tool.FPROPERTY_SIZE_BYTES + len(extra)] = extra
    memory[addr] = bytes(blob)


def write_uobject_name_only(memory: dict, addr: int, name_id: int) -> None:
    """A minimal fake UObject: just enough bytes for _resolve_uobject_handle_
    name()'s own direct-read tier (NamePrivate at DEFAULT_NAME_PRIVATE_OFFSET)
    to succeed -- used as an FObjectProperty::PropertyClass/
    FStructProperty::Struct/FEnumProperty::Enum/FClassProperty::MetaClass
    resolution target.
    """
    blob = bytearray(NAME_PRIVATE_OFFSET + 4)
    struct.pack_into("<I", blob, NAME_PRIVATE_OFFSET, name_id)
    memory[addr] = bytes(blob)


def uobject_owner(addr: int) -> int:
    return addr | tool.FFIELD_OWNER_UOBJECT_TAG_MASK


def field_owner(addr: int) -> int:
    return addr  # plain FField* -- naturally untagged (test addresses are 8-byte aligned).


# --------------------------------------------------------------------------- #
# canonicalize_object_path
# --------------------------------------------------------------------------- #

def test_canonicalize_object_path_two_examples_agree():
    new_style = "/Script/MISERY.MiseryFocusSubsystem"
    old_style = "/Script/MISERY/MiseryFocusSubsystem"
    assert tool.canonicalize_object_path(new_style) == new_style
    assert tool.canonicalize_object_path(old_style) == new_style
    assert tool.canonicalize_object_path(old_style) == tool.canonicalize_object_path(new_style)


def test_canonicalize_object_path_idempotent():
    new_style = "/Script/MISERY.MiseryFocusSubsystem"
    old_style = "/Script/MISERY/MiseryFocusSubsystem"
    once = tool.canonicalize_object_path(old_style)
    twice = tool.canonicalize_object_path(once)
    assert once == twice == new_style
    assert tool.canonicalize_object_path(tool.canonicalize_object_path(new_style)) == new_style


def test_canonicalize_object_path_bare_name_unchanged():
    assert tool.canonicalize_object_path("Object") == "Object"


def test_canonicalize_object_path_deep_nesting_already_canonical():
    path = "/Game/Foo.Bar:Baz"
    assert tool.canonicalize_object_path(path) == path


def test_canonicalize_object_path_none_passthrough():
    assert tool.canonicalize_object_path(None) is None


# --------------------------------------------------------------------------- #
# _decode_ffield_owner -- the FFieldVariant tagged-pointer decode.
# --------------------------------------------------------------------------- #

def test_decode_ffield_owner_uobject_tag_set():
    decoded = tool._decode_ffield_owner(0x1000 | 1)
    assert decoded == {"is_uobject": True, "address": 0x1000}


def test_decode_ffield_owner_ffield_tag_clear():
    decoded = tool._decode_ffield_owner(0x2000)
    assert decoded == {"is_uobject": False, "address": 0x2000}


def test_decode_ffield_owner_null():
    decoded = tool._decode_ffield_owner(0)
    assert decoded == {"is_uobject": False, "address": 0}


# --------------------------------------------------------------------------- #
# _walk_fieldclass_super_chain -- SuperClass chain walk, dispatch's own
# structural-validation core.
# --------------------------------------------------------------------------- #

def test_walk_fieldclass_super_chain_reaches_fproperty():
    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    memory = dict(fc_memory)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)
    result = tool._walk_fieldclass_super_chain(
        api, 1, addr_by_name["FIntProperty"], namepool_live_va=NAMEPOOL_VA)
    assert result["ok"] is True
    # _walk_fieldclass_super_chain()'s own 'names' holds the RAW, F-stripped
    # strings FFieldClass::Name actually stores at runtime (Field.cpp:46-61
    # -- see FFIELDCLASS_NAME_PROPERTY's own comment in eri.py); the
    # F-prefixed canonical form is reconstructed one level up, by
    # decode_property_type() itself, never here.
    assert result["names"] == ["IntProperty", "NumericProperty", "Property"]
    assert "NumericProperty" in result["names"]


def test_walk_fieldclass_super_chain_field_never_reaches_fproperty():
    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    memory = dict(fc_memory)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)
    result = tool._walk_fieldclass_super_chain(
        api, 1, addr_by_name["FField"], namepool_live_va=NAMEPOOL_VA)
    assert result["ok"] is True
    assert result["names"] == ["Field"]  # raw, F-stripped -- see the other test above.
    assert "Property" not in result["names"]


def test_walk_fieldclass_super_chain_cycle_detection_does_not_hang():
    a_addr, b_addr = fieldclass_addr(0), fieldclass_addr(1)
    allocator = _NameAllocator()
    a_id, b_id = allocator.add("A"), allocator.add("B")
    memory = {}
    blob_a = bytearray(0x28)
    struct.pack_into("<I", blob_a, tool.FFIELDCLASS_NAME_OFFSET, a_id)
    struct.pack_into("<Q", blob_a, tool.FFIELDCLASS_SUPERCLASS_OFFSET, b_addr)
    blob_b = bytearray(0x28)
    struct.pack_into("<I", blob_b, tool.FFIELDCLASS_NAME_OFFSET, b_id)
    struct.pack_into("<Q", blob_b, tool.FFIELDCLASS_SUPERCLASS_OFFSET, a_addr)
    memory[a_addr] = bytes(blob_a)
    memory[b_addr] = bytes(blob_b)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)
    result = tool._walk_fieldclass_super_chain(
        api, 1, a_addr, namepool_live_va=NAMEPOOL_VA, max_depth=100)
    assert result["ok"] is False
    assert "cycle" in result["note"].lower()


def test_walk_fieldclass_super_chain_exceeds_max_depth():
    # A real, non-cyclic 20-hop chain -- must fail once max_depth (16) is
    # exceeded, not hang and not silently truncate.
    allocator = _NameAllocator()
    memory = {}
    addrs = [fieldclass_addr(i) for i in range(20)]
    for i in range(20):
        super_ptr = addrs[i + 1] if i < 19 else 0
        name_id = allocator.add("Level%d" % i)
        blob = bytearray(0x28)
        struct.pack_into("<I", blob, tool.FFIELDCLASS_NAME_OFFSET, name_id)
        struct.pack_into("<Q", blob, tool.FFIELDCLASS_SUPERCLASS_OFFSET, super_ptr)
        memory[addrs[i]] = bytes(blob)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)
    result = tool._walk_fieldclass_super_chain(
        api, 1, addrs[0], namepool_live_va=NAMEPOOL_VA, max_depth=16)
    assert result["ok"] is False
    assert "max_depth" in result["note"] or "max depth" in result["note"].lower()


def test_walk_fieldclass_super_chain_read_failure_is_reported_not_raised():
    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    memory = dict(fc_memory)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    fail_addr = addr_by_name["FIntProperty"] + tool.FFIELDCLASS_SUPERCLASS_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={fail_addr})
    result = tool._walk_fieldclass_super_chain(
        api, 1, addr_by_name["FIntProperty"], namepool_live_va=NAMEPOOL_VA)
    assert result["ok"] is False
    assert "read failure" in result["note"].lower()


# --------------------------------------------------------------------------- #
# _resolve_uobject_handle_name -- two-tier best-effort name resolution.
# --------------------------------------------------------------------------- #

def test_resolve_uobject_handle_name_direct_read_success():
    allocator = _NameAllocator()
    name_id = allocator.add("MyStruct")
    memory = {}
    write_uobject_name_only(memory, uobject_addr(0), name_id)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    api = MemoryFakeApi(memory=memory)
    result = tool._resolve_uobject_handle_name(
        api, 1, uobject_addr(0), namepool_live_va=NAMEPOOL_VA, objects_by_address=None)
    assert result == {"name": "MyStruct", "source": "direct-read", "note": None}


def test_resolve_uobject_handle_name_i04_walk_hit_skips_a_read():
    objects_by_address = {uobject_addr(0): {"name_ok": True, "name_text": "Cached"}}
    api = MemoryFakeApi(memory={})  # a read would AssertionError -- must not happen.
    result = tool._resolve_uobject_handle_name(
        api, 1, uobject_addr(0), namepool_live_va=NAMEPOOL_VA,
        objects_by_address=objects_by_address)
    assert result == {"name": "Cached", "source": "i04-walk", "note": None}


def test_resolve_uobject_handle_name_implausible_pointer():
    api = MemoryFakeApi(memory={})
    result = tool._resolve_uobject_handle_name(
        api, 1, 0, namepool_live_va=NAMEPOOL_VA, objects_by_address=None)
    assert result["name"] is None
    assert "not a plausible" in result["note"]


def test_resolve_uobject_handle_name_direct_read_failure():
    api = MemoryFakeApi(memory={}, fail_read_addresses={uobject_addr(0) + NAME_PRIVATE_OFFSET})
    result = tool._resolve_uobject_handle_name(
        api, 1, uobject_addr(0), namepool_live_va=NAMEPOOL_VA, objects_by_address=None)
    assert result["name"] is None
    assert "read failed" in result["note"]


# --------------------------------------------------------------------------- #
# decode_property_type -- structural rejections common to every dispatch.
# --------------------------------------------------------------------------- #

def _base_fixture():
    """(memory, addr_by_name, allocator) -- the shared FFieldClass registry,
    ready for a caller to add its own FField/FProperty object(s) and UObject
    resolution target(s) on top before merging FNamePool memory.
    """
    fc_memory, addr_by_name, allocator = build_fieldclass_registry()
    return dict(fc_memory), addr_by_name, allocator


def _finish(memory: dict, allocator: _NameAllocator) -> "MemoryFakeApi":
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    return MemoryFakeApi(memory=memory)


def test_decode_property_type_rejects_misaligned_pointer_without_reading():
    api = MemoryFakeApi(memory={})  # a read would AssertionError.
    decoded = tool.decode_property_type(
        api, 1, field_addr(0) + 1, namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "pointer_alignment"
    assert decoded["next_ptr"] is None


def test_decode_property_type_rejects_read_failure_on_base_batch():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id)
    api_memory = dict(memory)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    api_memory.update(fnamepool_memory)
    api = MemoryFakeApi(
        memory=api_memory,
        fail_read_addresses={field_addr(0) + tool.FFIELD_CLASS_PRIVATE_OFFSET})
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "read_failure"
    assert decoded["next_ptr"] is None  # aborted before the batch read completed.


def test_decode_property_type_rejects_class_pointer_implausible():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=0, owner_raw=0, next_ptr=0, name_id=name_id)
    api = _finish(memory, allocator)
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "class_pointer_implausible"
    assert decoded["next_ptr"] == 0  # base batch DID succeed -- Next is known.


def test_decode_property_type_rejects_not_a_property():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Weird")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FField"],
        owner_raw=0, next_ptr=0, name_id=name_id)
    api = _finish(memory, allocator)
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "not_a_property"
    assert "FField" in decoded["rejection_reason"]


def test_decode_property_type_rejects_superclass_chain_failure():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=0, next_ptr=0, name_id=name_id)
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    fail_addr = addr_by_name["FIntProperty"] + tool.FFIELDCLASS_SUPERCLASS_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={fail_addr})
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "superclass_chain_failure"
    assert decoded["next_ptr"] == 0  # base batch DID succeed.


def test_decode_property_type_rejects_name_decode_failure():
    memory, addr_by_name, allocator = _base_fixture()
    # A deliberately-corrupt FNameEntryId (a header claiming length 3
    # followed by an invalid ASCII byte, exactly like test_eri_i04's own
    # test_classify_object_rejects_undecodable_name) -- placed in a block
    # this allocator has NOT already assigned to a real name (reserve_block())
    # and added as its OWN extra entry in the SAME single make_fnamepool_
    # memory() call, never a second call that would silently overwrite the
    # registry's own already-established blocks table.
    bad_block = allocator.reserve_block()
    bad_id = bad_block << tool.FNAME_BLOCK_OFFSET_BITS
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=0, next_ptr=0, name_id=bad_id)
    header = (0 & 0x1) | (0x07 << 1) | ((3 & 0x3FF) << 6)
    entry_bytes = struct.pack("<H", header) + b"\xffAB"
    block_base = NAMEPOOL_VA + 0x00300000
    fnamepool_memory, addrs = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    # Extend the SAME blocks table with the corrupt block's own pointer,
    # rather than replacing the key wholesale.
    block_bases = dict(addrs["block_bases"])
    block_bases[bad_block] = block_base
    max_block = max(block_bases)
    blocks_blob = bytearray((max_block + 1) * 8)
    for block, base in block_bases.items():
        struct.pack_into("<Q", blocks_blob, block * 8, base)
    memory[addrs["blocks_table_addr"]] = bytes(blocks_blob)
    memory[block_base] = entry_bytes
    api = MemoryFakeApi(memory=memory)
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "name_decode"
    assert decoded["next_ptr"] == 0  # base batch DID succeed.


def test_decode_property_type_container_depth_exceeded():
    api = MemoryFakeApi(memory={})  # never reached.
    decoded = tool.decode_property_type(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA,
        max_container_depth=2, container_depth=3)
    assert decoded["valid"] is False
    assert decoded["rejection_kind"] == "container_depth_exceeded"


# --------------------------------------------------------------------------- #
# Each of the 12 named type-specific decoders, independently.
# --------------------------------------------------------------------------- #

def _decode_one(memory, addr_by_name, allocator, *, class_ptr_name, extra=b"",
                array_dim=1, element_size=4, offset_internal=0x10,
                rep_notify_id=0, name_text="MyProp"):
    name_id = allocator.add(name_text)
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name[class_ptr_name],
        owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id,
        array_dim=array_dim, element_size=element_size,
        offset_internal=offset_internal, rep_notify_id=rep_notify_id, extra=extra)
    api = _finish(memory, allocator)
    return tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)


def test_decode_bool_property_native_bool():
    memory, addr_by_name, allocator = _base_fixture()
    extra = bytes([1, 0, 0xFF, 0xFF])  # FieldSize=1 ByteOffset=0 ByteMask=0xff FieldMask=0xff
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FBoolProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FBoolProperty"
    assert decoded["type_name"] == "bool"
    assert decoded["bool_byte_offset"] == 0
    assert decoded["bool_field_mask"] == "0xff"
    assert decoded["is_bitfield"] is False


def test_decode_bool_property_packed_bitfield():
    memory, addr_by_name, allocator = _base_fixture()
    extra = bytes([4, 2, 0x08, 0x08])  # FieldSize=4 ByteOffset=2 ByteMask=0x08 FieldMask=0x08
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FBoolProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["bool_byte_offset"] == 2
    assert decoded["bool_field_mask"] == "0x08"
    assert decoded["is_bitfield"] is True


def test_decode_bool_property_invariant_violation_is_a_note_not_a_rejection():
    memory, addr_by_name, allocator = _base_fixture()
    extra = bytes([4, 0, 0x08, 0x04])  # FieldMask (0x04) neither ByteMask (0x08) nor 0xff.
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FBoolProperty", extra=extra)
    assert decoded["valid"] is True
    assert any("invariant violated" in n for n in decoded["notes"])


def test_decode_object_property():
    memory, addr_by_name, allocator = _base_fixture()
    class_name_id = allocator.add("Actor")
    write_uobject_name_only(memory, uobject_addr(0), class_name_id)
    extra = struct.pack("<Q", uobject_addr(0))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FObjectProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FObjectProperty"
    assert decoded["class_name"] == "Actor"


def test_decode_class_property():
    memory, addr_by_name, allocator = _base_fixture()
    prop_class_id = allocator.add("Class")
    meta_class_id = allocator.add("Actor")
    write_uobject_name_only(memory, uobject_addr(0), prop_class_id)
    write_uobject_name_only(memory, uobject_addr(1), meta_class_id)
    extra = struct.pack("<Q", uobject_addr(0)) + struct.pack("<Q", uobject_addr(1))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FClassProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FClassProperty"
    assert decoded["class_name"] == "Class"
    assert any("MetaClass" in n and "Actor" in n for n in decoded["notes"])


def test_decode_struct_property():
    memory, addr_by_name, allocator = _base_fixture()
    struct_name_id = allocator.add("Vector")
    write_uobject_name_only(memory, uobject_addr(0), struct_name_id)
    extra = struct.pack("<Q", uobject_addr(0))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FStructProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FStructProperty"
    assert decoded["struct_name"] == "Vector"


def test_decode_enum_property():
    memory, addr_by_name, allocator = _base_fixture()
    enum_name_id = allocator.add("EMyEnum")
    write_uobject_name_only(memory, uobject_addr(0), enum_name_id)
    underlying_name_id = allocator.add("UnderlyingByteProp")
    write_fproperty(
        memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=field_owner(field_addr(0)), next_ptr=0, name_id=underlying_name_id,
        element_size=1)
    extra = struct.pack("<Q", field_addr(1)) + struct.pack("<Q", uobject_addr(0))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FEnumProperty", extra=extra)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FEnumProperty"
    assert decoded["enum_name"] == "EMyEnum"
    assert any("UnderlyingProp=FIntProperty" in n for n in decoded["notes"])


def test_decode_enum_property_underlying_prop_failure_is_a_note_not_fatal():
    memory, addr_by_name, allocator = _base_fixture()
    enum_name_id = allocator.add("EMyEnum")
    write_uobject_name_only(memory, uobject_addr(0), enum_name_id)
    extra = struct.pack("<Q", 0) + struct.pack("<Q", uobject_addr(0))  # UnderlyingProp null.
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FEnumProperty", extra=extra)
    assert decoded["valid"] is True  # the ENUM property itself still decodes.
    assert decoded["enum_name"] == "EMyEnum"
    assert any("did not decode as a valid FProperty" in n for n in decoded["notes"])


def test_decode_array_property_with_nested_inner_int():
    memory, addr_by_name, allocator = _base_fixture()
    inner_name_id = allocator.add("")  # Inner properties are typically unnamed.
    write_fproperty(
        memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=field_owner(field_addr(0)), next_ptr=0, name_id=inner_name_id,
        element_size=4)
    extra = struct.pack("<B", 0) + b"\x00" * 7 + struct.pack("<Q", field_addr(1))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FArrayProperty", extra=extra, element_size=0x10)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FArrayProperty"
    assert decoded["type_name"] == "TArray"
    assert decoded["inner"] == {
        "property_class": "FIntProperty", "type_name": None, "size": 4,
        "struct_name": None, "enum_name": None, "class_name": None, "inner": None,
    }


def test_decode_array_property_inner_failure_reported_via_notes_not_fatal():
    memory, addr_by_name, allocator = _base_fixture()
    extra = struct.pack("<B", 0) + b"\x00" * 7 + struct.pack("<Q", 0)  # Inner null.
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FArrayProperty", extra=extra, element_size=0x10)
    assert decoded["valid"] is True
    assert decoded["inner"] is None
    assert any("Inner" in n and "did not decode" in n for n in decoded["notes"])


def test_decode_set_property():
    memory, addr_by_name, allocator = _base_fixture()
    element_name_id = allocator.add("")
    write_fproperty(
        memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=field_owner(field_addr(0)), next_ptr=0, name_id=element_name_id,
        element_size=4)
    extra = struct.pack("<Q", field_addr(1))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FSetProperty", extra=extra, element_size=4)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FSetProperty"
    assert decoded["type_name"] == "TSet"
    assert decoded["inner"]["property_class"] == "FIntProperty"


def test_decode_map_property():
    memory, addr_by_name, allocator = _base_fixture()
    key_name_id = allocator.add("")
    value_name_id = allocator.add("")
    write_fproperty(
        memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=field_owner(field_addr(0)), next_ptr=0, name_id=key_name_id,
        element_size=4)
    write_fproperty(
        memory, field_addr(2), class_ptr=addr_by_name["FStructProperty"],
        owner_raw=field_owner(field_addr(0)), next_ptr=0, name_id=value_name_id,
        element_size=0x10, extra=struct.pack("<Q", 0))
    extra = struct.pack("<Q", field_addr(1)) + struct.pack("<Q", field_addr(2))
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FMapProperty", extra=extra, element_size=0x18)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FMapProperty"
    assert decoded["type_name"] == "TMap"
    assert decoded["key_type"]["property_class"] == "FIntProperty"
    assert decoded["value_type"]["property_class"] == "FStructProperty"


def test_decode_name_property():
    memory, addr_by_name, allocator = _base_fixture()
    decoded = _decode_one(memory, addr_by_name, allocator, class_ptr_name="FNameProperty")
    assert decoded["valid"] is True
    assert decoded["type_name"] == "FName"


def test_decode_str_property():
    memory, addr_by_name, allocator = _base_fixture()
    decoded = _decode_one(memory, addr_by_name, allocator, class_ptr_name="FStrProperty")
    assert decoded["valid"] is True
    assert decoded["type_name"] == "FString"


def test_decode_text_property():
    memory, addr_by_name, allocator = _base_fixture()
    decoded = _decode_one(memory, addr_by_name, allocator, class_ptr_name="FTextProperty")
    assert decoded["valid"] is True
    assert decoded["type_name"] == "FText"


def test_decode_numeric_property_generic_fallback():
    memory, addr_by_name, allocator = _base_fixture()
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FFloatProperty", element_size=4)
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FFloatProperty"
    assert decoded["type_name"] is None  # correctness over a lossy guessed name.
    assert decoded["size"] == 4


def test_decode_property_with_no_dispatcher_still_valid_base_fields_only():
    # a hypothetical FProperty-descendant this pass has no decoder for
    # (e.g. a delegate/interface property) -- base fields still decode.
    memory, addr_by_name, allocator = _base_fixture()
    # "DelegateProperty" -- bare, F-stripped, matching the real FFieldClass
    # constructor's own runtime behavior (Field.cpp:46-61) that every OTHER
    # entry in this fixture already goes through via build_fieldclass_
    # registry()'s own name[1:] stripping; this one is added by hand (a type
    # deliberately absent from FIELDCLASS_HIERARCHY) so it must strip its
    # own "F" the same way to stay consistent with the rest of the registry.
    delegate_id = allocator.add("DelegateProperty")
    # index 100 -- well clear of the 16 legitimate FIELDCLASS_HIERARCHY
    # entries (indices 0..15), so this address cannot collide with
    # field_addr(0)/FIELD_BASE the way fieldclass_addr(16) -- the very next
    # index -- would (FIELDCLASS_STRIDE * 16 == FIELD_BASE - FIELDCLASS_BASE,
    # a real address collision this session's own test-writing caught).
    delegate_addr = fieldclass_addr(100)
    blob = bytearray(0x28)
    struct.pack_into("<I", blob, tool.FFIELDCLASS_NAME_OFFSET, delegate_id)
    struct.pack_into("<Q", blob, tool.FFIELDCLASS_SUPERCLASS_OFFSET, addr_by_name["FProperty"])
    memory[delegate_addr] = bytes(blob)
    addr_by_name["FDelegateProperty"] = delegate_addr
    decoded = _decode_one(memory, addr_by_name, allocator, class_ptr_name="FDelegateProperty")
    assert decoded["valid"] is True
    assert decoded["property_class"] == "FDelegateProperty"
    assert any("no type-specific decoder" in n for n in decoded["notes"])


# --------------------------------------------------------------------------- #
# RepNotifyFunc convention -- id 0 ("None") is "no function", never a note;
# a real name is preserved; a decode error is reported via 'notes'.
# --------------------------------------------------------------------------- #

def test_rep_notify_func_none_id_zero_is_null_no_note():
    memory, addr_by_name, allocator = _base_fixture()
    decoded = _decode_one(memory, addr_by_name, allocator,
                          class_ptr_name="FIntProperty", rep_notify_id=0)
    assert decoded["valid"] is True
    assert decoded["rep_notify_func"] is None
    assert decoded["notes"] == []


def test_rep_notify_func_real_name_preserved():
    memory, addr_by_name, allocator = _base_fixture()
    rep_notify_id = allocator.add("OnRep_Health")
    name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id,
        rep_notify_id=rep_notify_id)
    api = _finish(memory, allocator)
    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is True
    assert decoded["rep_notify_func"] == "OnRep_Health"


# --------------------------------------------------------------------------- #
# walk_property_chain -- ChildProperties/Next chain traversal.
# --------------------------------------------------------------------------- #

def test_walk_property_chain_empty_child_properties():
    api = MemoryFakeApi(memory={})  # never read at all.
    result = tool.walk_property_chain(
        api, 1, 0, namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result == {"accepted": [], "nodes_visited": 0, "rejected_counts": {},
                      "ok": True, "note": None}


def test_walk_property_chain_single_property():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result["ok"] is True
    assert result["nodes_visited"] == 1
    assert len(result["accepted"]) == 1
    assert result["accepted"][0]["raw_name"] == "Health"
    assert result["rejected_counts"] == {}


def test_walk_property_chain_multiple_properties_preserves_order():
    memory, addr_by_name, allocator = _base_fixture()
    name0 = allocator.add("First")
    name1 = allocator.add("Second")
    name2 = allocator.add("Third")
    owner = uobject_owner(class_addr(0))
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=field_addr(1), name_id=name0)
    write_fproperty(memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=field_addr(2), name_id=name1)
    write_fproperty(memory, field_addr(2), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=0, name_id=name2)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result["ok"] is True
    assert [p["raw_name"] for p in result["accepted"]] == ["First", "Second", "Third"]


def test_walk_property_chain_cycle_is_a_documented_failure_not_a_hang():
    memory, addr_by_name, allocator = _base_fixture()
    name0 = allocator.add("A")
    name1 = allocator.add("B")
    owner = uobject_owner(class_addr(0))
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=field_addr(1), name_id=name0)
    write_fproperty(memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=field_addr(0), name_id=name1)  # cycle back to 0.
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0),
        max_chain_length=100)
    assert result["ok"] is False
    assert "cycle" in result["note"].lower()
    assert len(result["accepted"]) == 2  # both nodes WERE examined before the cycle was caught.


def test_walk_property_chain_exceeds_max_chain_length():
    memory, addr_by_name, allocator = _base_fixture()
    owner = uobject_owner(class_addr(0))
    n = 20
    for i in range(n):
        name_id = allocator.add("Prop%d" % i)
        next_ptr = field_addr(i + 1) if i < n - 1 else field_addr(n)  # never terminates.
        write_fproperty(memory, field_addr(i), class_ptr=addr_by_name["FIntProperty"],
                        owner_raw=owner, next_ptr=next_ptr, name_id=name_id)
    # field_addr(n) itself is unwritten -- but max_chain_length triggers first.
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0),
        max_chain_length=10)
    assert result["ok"] is False
    assert "max_chain_length" in result["note"]
    assert result["nodes_visited"] == 10


def test_walk_property_chain_owner_mismatch_is_counted_not_accepted():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Foreign")
    wrong_owner = uobject_owner(class_addr(1))  # NOT class_addr(0).
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=wrong_owner, next_ptr=0, name_id=name_id)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result["ok"] is True
    assert result["accepted"] == []
    assert result["rejected_counts"] == {"owner_mismatch": 1}


def test_walk_property_chain_owner_plain_ffield_is_a_mismatch_for_top_level():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Foo")
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=field_owner(class_addr(0)),  # tag bit 0 -- NOT a UObject owner.
                    next_ptr=0, name_id=name_id)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result["accepted"] == []
    assert result["rejected_counts"] == {"owner_mismatch": 1}


def test_walk_property_chain_rejected_node_does_not_abort_the_walk():
    # index 0: not_a_property (class_ptr -> "FField", never reaches
    # "FProperty"); index 1: a real, valid, owner-matched property. The
    # walk must still find index 1.
    memory, addr_by_name, allocator = _base_fixture()
    bad_name = allocator.add("Bad")
    good_name = allocator.add("Good")
    owner = uobject_owner(class_addr(0))
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FField"],
                    owner_raw=owner, next_ptr=field_addr(1), name_id=bad_name)
    write_fproperty(memory, field_addr(1), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=0, name_id=good_name)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    assert result["ok"] is True
    assert result["nodes_visited"] == 2
    assert result["rejected_counts"] == {"not_a_property": 1}
    assert len(result["accepted"]) == 1
    assert result["accepted"][0]["raw_name"] == "Good"


def test_walk_property_chain_ordinal_skips_rejected_nodes():
    # Confirms the module's own algorithm step 8: a rejected node consumes
    # NO ordinal slot -- the SECOND accepted property's own ordinal (as
    # assigned by enumerate() over 'accepted', matching main()'s own wiring)
    # is 1, not 2, even though a rejected node sits between the two.
    memory, addr_by_name, allocator = _base_fixture()
    owner = uobject_owner(class_addr(0))
    name0 = allocator.add("First")
    bad_name = allocator.add("Rejected")
    name2 = allocator.add("Third")
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=field_addr(1), name_id=name0)
    write_fproperty(memory, field_addr(1), class_ptr=addr_by_name["FField"],
                    owner_raw=owner, next_ptr=field_addr(2), name_id=bad_name)
    write_fproperty(memory, field_addr(2), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=owner, next_ptr=0, name_id=name2)
    api = _finish(memory, allocator)
    result = tool.walk_property_chain(
        api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA, owner_address=class_addr(0))
    ordinals = list(enumerate(result["accepted"]))
    assert [(o, p["raw_name"]) for o, p in ordinals] == [(0, "First"), (1, "Third")]


# --------------------------------------------------------------------------- #
# _to_property_type_ref
# --------------------------------------------------------------------------- #

def test_to_property_type_ref_none_for_invalid():
    assert tool._to_property_type_ref(None) is None
    assert tool._to_property_type_ref({"valid": False}) is None


def test_to_property_type_ref_reduces_valid_decode():
    decoded = {
        "valid": True, "property_class": "FIntProperty", "type_name": None,
        "size": 4, "struct_name": None, "enum_name": None, "class_name": None,
        "inner": None, "extra_internal_field": "dropped",
    }
    reduced = tool._to_property_type_ref(decoded)
    assert reduced == {
        "property_class": "FIntProperty", "type_name": None, "size": 4,
        "struct_name": None, "enum_name": None, "class_name": None, "inner": None,
    }
    assert "extra_internal_field" not in reduced


# --------------------------------------------------------------------------- #
# select_i06_engine_proof_classes / select_i06_proof_set
# --------------------------------------------------------------------------- #

def _cls(name, address):
    return {"address": address, "raw_name": name, "object_path": "/Script/Engine.%s" % name}


def test_select_i06_engine_proof_classes_preference_order_and_cap():
    all_classes = [
        _cls("SceneComponent", 1), _cls("Pawn", 2), _cls("Object", 3),
        _cls("Actor", 4), _cls("Struct", 5), _cls("Class", 6),
        _cls("ActorComponent", 7), _cls("Irrelevant", 8),
    ]
    selected = tool.select_i06_engine_proof_classes(all_classes, cap=3)
    assert [c["raw_name"] for c in selected] == ["Object", "Actor", "Struct"]


def test_select_i06_engine_proof_classes_missing_name_skipped_not_an_error():
    all_classes = [_cls("Object", 1), _cls("Pawn", 2)]
    selected = tool.select_i06_engine_proof_classes(all_classes, cap=5)
    assert [c["raw_name"] for c in selected] == ["Object", "Pawn"]


def test_select_i06_proof_set_combines_and_dedupes():
    misery = [_cls("MiseryFocusSubsystem", 100)]
    game = [_cls("BP_Foo_C", 200)]
    all_classes = [_cls("Object", 1), _cls("Actor", 2), misery[0], game[0]]
    combined = tool.select_i06_proof_set(
        misery_classes=misery, game_sample=game, all_classes=all_classes,
        engine_class_cap=5)
    addresses = [c["address"] for c in combined]
    assert addresses == [100, 200, 1, 2]  # misery, then game, then engine -- no duplicates.


# --------------------------------------------------------------------------- #
# run_i06 -- per-proof-set-class ChildProperties reads + chain walks.
# --------------------------------------------------------------------------- #

def test_run_i06_multiple_classes():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id)
    memory[class_addr(0) + tool.USTRUCT_CHILD_PROPERTIES_OFFSET] = struct.pack(
        "<Q", field_addr(0))
    memory[class_addr(1) + tool.USTRUCT_CHILD_PROPERTIES_OFFSET] = struct.pack("<Q", 0)
    api = _finish(memory, allocator)
    proof_set = [_cls("MiseryFocusSubsystem", class_addr(0)), _cls("Empty", class_addr(1))]
    result = tool.run_i06(api, 1, NAMEPOOL_VA, None, proof_set)
    assert result["classes_examined"] == 2
    assert result["properties_accepted_total"] == 1
    c0, c1 = result["classes"]
    assert c0["child_properties_read_ok"] is True
    assert len(c0["properties"]) == 1
    assert c1["child_properties_read_ok"] is True
    assert len(c1["properties"]) == 0


def test_run_i06_child_properties_read_failure_is_per_class_not_fatal():
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("Health")
    write_fproperty(memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
                    owner_raw=uobject_owner(class_addr(1)), next_ptr=0, name_id=name_id)
    memory[class_addr(1) + tool.USTRUCT_CHILD_PROPERTIES_OFFSET] = struct.pack(
        "<Q", field_addr(0))
    fnamepool_memory, _ = make_fnamepool_memory(entries=allocator.entries)
    memory.update(fnamepool_memory)
    fail_addr = class_addr(0) + tool.USTRUCT_CHILD_PROPERTIES_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={fail_addr})
    proof_set = [_cls("Broken", class_addr(0)), _cls("Good", class_addr(1))]
    result = tool.run_i06(api, 1, NAMEPOOL_VA, None, proof_set)
    assert result["classes_examined"] == 2
    c0, c1 = result["classes"]
    assert c0["child_properties_read_ok"] is False
    assert c0["child_properties_read_error"] is not None
    assert c0["properties"] == []
    assert c1["child_properties_read_ok"] is True
    assert len(c1["properties"]) == 1
    assert result["properties_accepted_total"] == 1  # class 1's own property still counted.


# --------------------------------------------------------------------------- #
# build_i06_document / build_i06_property_record -- shape, and validated
# against the REAL research/schema/reflection-record.schema.json composed
# with kb-record.schema.json, reusing test_eri_i01's own offline registry.
# --------------------------------------------------------------------------- #

def _property_record_validator():
    pytest.importorskip("jsonschema")
    pytest.importorskip("referencing")
    from jsonschema import Draft202012Validator
    schema = i01_tests._load_schema("reflection-record.schema.json")
    return Draft202012Validator(schema, registry=i01_tests._build_registry())


def _valid_decoded(**overrides):
    base = {
        "valid": True, "address_hex": "0x1000", "raw_name": "Health",
        "property_class": "FIntProperty", "array_dim": 1, "size": 4, "total_size": 4,
        "offset": 24, "property_flags_raw": "0x0", "rep_index": 0, "rep_notify_func": None,
        "type_name": None, "bool_byte_offset": None, "bool_field_mask": None,
        "is_bitfield": None, "struct_name": None, "enum_name": None, "class_name": None,
        "inner": None, "key_type": None, "value_type": None, "notes": [],
    }
    base.update(overrides)
    return base


def test_build_i06_property_record_shape_and_grading():
    row = tool.build_i06_property_record(
        _valid_decoded(), owner="MiseryFocusSubsystem", owner_kind="class", ordinal=0,
        build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    assert row["kind"] == "property"
    assert row["raw_name"] == "Health"
    assert row["owner"] == "MiseryFocusSubsystem"
    assert row["owner_kind"] == "class"
    assert row["ordinal"] == 0
    assert row["ordinal_basis"] == "runtime-link-order"
    assert row["offset"] == 24
    assert row["size"] == 4
    assert row["confidence"] == 0.75
    assert row["evidence_level"] == "OBSERVED"
    assert row["claim_class"] == "I"
    assert row["claim_type"] == "class-property"
    assert row["oracle"] == ["runtime-reflection"]
    assert len(row["sources"]) == 1  # NEVER cross-checked -- see the module docstring.
    assert row["method"] == "I-06"
    assert row["is_blueprint_visible"] is None
    assert row["is_editable"] is None
    assert row["is_transient"] is None
    assert row["is_config"] is None
    assert row["cpp_type"] is None
    json.loads(tool.dump_json(row))


def test_build_i06_property_record_notes_joined():
    row = tool.build_i06_property_record(
        _valid_decoded(notes=["first note", "second note"]),
        owner="X", owner_kind="class", ordinal=0,
        build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    assert row["notes"] == "first note; second note"


def test_build_i06_property_record_validates_against_real_schema():
    validator = _property_record_validator()
    row = tool.build_i06_property_record(
        _valid_decoded(), owner="MiseryFocusSubsystem", owner_kind="class", ordinal=0,
        build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_build_i06_property_record_with_nested_inner_validates_against_real_schema():
    validator = _property_record_validator()
    inner = {
        "property_class": "FIntProperty", "type_name": None, "size": 4,
        "struct_name": None, "enum_name": None, "class_name": None, "inner": None,
    }
    row = tool.build_i06_property_record(
        _valid_decoded(raw_name="Items", property_class="FArrayProperty",
                       type_name="TArray", size=0x10, total_size=0x10, inner=inner),
        owner="MiseryFocusSubsystem", owner_kind="class", ordinal=1,
        build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    errors = list(validator.iter_errors(row))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_build_i06_document_shape():
    result = {
        "classes_examined": 2, "properties_accepted_total": 3,
        "rejected_counts_total": {"owner_mismatch": 1},
        "classes": [{
            "class_address": 0x1000, "class_raw_name": "MiseryFocusSubsystem",
            "object_path": "/Script/MISERY.MiseryFocusSubsystem",
            "child_properties_ptr_hex": "0x2000",
            "child_properties_read_ok": True, "child_properties_read_error": None,
            "properties": [{"raw_name": "Health"}, {"raw_name": "Mana"}],
            "nodes_visited": 3, "rejected_counts": {"owner_mismatch": 1},
            "chain_ok": True, "chain_note": None,
        }],
    }
    doc = tool.build_i06_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["capability"] == "I-06"
    assert doc["classes_examined"] == 2
    assert doc["properties_accepted_total"] == 3
    assert doc["classes"][0]["property_count"] == 2
    assert "evidence_level" not in doc
    json.loads(tool.dump_json(doc))


# --------------------------------------------------------------------------- #
# CLI argument parsing / path resolution / requirement validation.
# --------------------------------------------------------------------------- #

def test_cli_run_i06_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_i06 is False
    assert args.child_properties_offset is None
    assert args.i06_max_chain_length == tool.DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH
    assert args.i06_max_superclass_depth == tool.DEFAULT_I06_MAX_SUPERCLASS_DEPTH
    assert args.i06_max_container_depth == tool.DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH
    assert args.i06_engine_class_cap == tool.DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP
    assert args.i06_out is None
    assert args.properties_jsonl_out is None


def test_parse_child_properties_offset_default_and_override():
    assert tool._parse_child_properties_offset(None) == tool.USTRUCT_CHILD_PROPERTIES_OFFSET
    assert tool._parse_child_properties_offset("0x50") == 0x50
    with pytest.raises(ValueError):
        tool._parse_child_properties_offset("garbage")


def test_resolve_i06_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_i06_output_path(args) is None
    assert tool._resolve_properties_jsonl_path(args) is None


def test_resolve_i06_output_path_requires_i06_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i06"])
    with pytest.raises(ValueError):
        tool._resolve_i06_output_path(args)


def test_resolve_properties_jsonl_path_requires_flag_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i06"])
    with pytest.raises(ValueError):
        tool._resolve_properties_jsonl_path(args)


def test_resolve_i06_output_path_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(["--run-i06", "--run-dir", run_dir])
    assert tool._resolve_i06_output_path(args) == os.path.join(run_dir, "i06-properties.json")
    assert tool._resolve_properties_jsonl_path(args) == os.path.join(run_dir, "properties.jsonl")


def test_resolve_properties_jsonl_path_explicit_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit = str(tmp_path / "custom-properties.jsonl")
    args = tool.build_arg_parser().parse_args(
        ["--run-i06", "--run-dir", run_dir, "--properties-jsonl-out", explicit])
    assert tool._resolve_properties_jsonl_path(args) == explicit


def test_validate_i06_requirements_noop_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    tool._validate_i06_requirements(args)  # must not raise


def test_validate_i06_requirements_raises_when_missing_run_i04():
    args = tool.build_arg_parser().parse_args(["--run-i06", "--run-i02", "--run-i03"])
    with pytest.raises(ValueError, match="--run-i04"):
        tool._validate_i06_requirements(args)


def test_validate_i06_requirements_passes_when_run_i04_given():
    args = tool.build_arg_parser().parse_args(
        ["--run-i06", "--run-i02", "--run-i03", "--run-i04"])
    tool._validate_i06_requirements(args)  # must not raise


# --------------------------------------------------------------------------- #
# main() end-to-end -- a synthetic fixture combining I-02/I-03/I-04's own
# established memory shapes with I-06's own FField/FFieldClass/ChildProperties
# memory, producing properties.jsonl via the full CLI.
# --------------------------------------------------------------------------- #

def test_main_run_i06_writes_properties_jsonl_for_misery_class(tmp_path, monkeypatch):
    entries, entries_text, misery_names = i04_tests._misery_five_class_fixture()
    # Built by hand rather than via i04_tests._combined_i04_run_memory():
    # that helper's own single make_fnamepool_memory(entries=entries_text)
    # call must be the ONLY one against this run's shared NAMEPOOL_VA --
    # I-06's own FFieldClass/FField names need to join THAT SAME call (a
    # SECOND independent make_fnamepool_memory() call, even over a disjoint
    # id range, recomputes its own block_base placement from scratch and
    # silently overwrites the first call's own memory[blocks_table_addr]
    # entry, corrupting I-04's own "Class" seed lookup -- found and fixed
    # this session while writing this exact test).
    chunk_memory, objects_ptr = i04_tests.make_i04_object_chunk_memory(entries)
    struct_blob = bytearray(0x2C)
    struct.pack_into("<Q", struct_blob, tool.GUOBJECTARRAY_OFFSET_OBJECTS, objects_ptr)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_MAX_ELEMENTS, 100)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS, len(entries))
    memory = dict(chunk_memory)
    memory[GUOBJECTARRAY_VA] = bytes(struct_blob)

    # I-06's own FField/FFieldClass registry -- allocator seeded well past
    # entries_text's own highest block (5 MISERY classes + 5 fixed names ==
    # block 10 at most) so the two id ranges never collide. ONE FIntProperty
    # ("Health") owned by the first MISERY class in the fixture (index 5,
    # "MiseryBlueprintFunctionLibrary", per _misery_five_class_fixture()'s
    # own docstring).
    allocator = _NameAllocator(start_block=50)
    fc_memory, addr_by_name, allocator = build_fieldclass_registry(allocator=allocator)
    memory.update(fc_memory)
    misery_class_address = i04_tests.obj_addr(5)
    health_name_id = allocator.add("Health")
    write_fproperty(
        memory, field_addr(0), class_ptr=addr_by_name["FIntProperty"],
        owner_raw=uobject_owner(misery_class_address), next_ptr=0,
        name_id=health_name_id, offset_internal=0x30)
    memory[misery_class_address + tool.USTRUCT_CHILD_PROPERTIES_OFFSET] = struct.pack(
        "<Q", field_addr(0))
    # The proof set is EVERY /Script/MISERY class (all 5, indices 5..9) PLUS
    # select_i06_engine_proof_classes()'s own name-preference search over
    # I-04's FULL class universe -- which finds index 1 here, since this
    # fixture's own seed object is literally named "Class"
    # (I06_ENGINE_CLASS_NAME_PREFERENCE's own first entry). Every one of
    # these legitimately declares zero of its own properties (a null
    # ChildProperties, per walk_property_chain()'s own docstring, is a
    # valid, non-error result) except the one under test (index 5).
    for other_index in (1, 6, 7, 8, 9):
        other_address = i04_tests.obj_addr(other_index)
        memory[other_address + tool.USTRUCT_CHILD_PROPERTIES_OFFSET] = struct.pack("<Q", 0)

    combined_names = dict(entries_text)
    combined_names.update(allocator.entries)
    fnamepool_memory, _ = make_fnamepool_memory(entries=combined_names)
    memory.update(fnamepool_memory)

    api, _ = i04_tests._fake_i04_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04", "--run-i06",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i04-max-scan-indices", "100",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "properties.jsonl"), encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    assert len(rows) == 1
    row = rows[0]
    assert row["raw_name"] == "Health"
    assert row["owner"] == "MiseryBlueprintFunctionLibrary"
    assert row["owner_kind"] == "class"
    assert row["ordinal"] == 0
    assert row["property_class"] == "FIntProperty"
    assert row["offset"] == 0x30
    assert row["confidence"] == 0.75

    with open(os.path.join(run_dir, "i06-properties.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "I-06"
    assert doc["properties_accepted_total"] == 1

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03", "I-04", "I-06"]
    assert any(a.endswith("i06-properties.json") for a in manifest["artifacts"])
    assert any(a.endswith("properties.jsonl") for a in manifest["artifacts"])


def test_main_run_i06_hard_read_failure_writes_nothing_at_all(tmp_path, monkeypatch):
    """The SAME 'all-or-nothing' guarantee test_main_run_i02_hard_read_
    failure_writes_nothing_at_all (test_eri_i02.py) proves for I-02 alone,
    exercised here with --run-i06 ALSO in the flag set: a genuine tool
    malfunction on I-02's own foundational NumElements read (the game
    process dying mid-run is the real-world equivalent) must abort the WHOLE
    run -- including I-06, which never even gets a chance to start -- before
    ANYTHING is written. This closes the one live coverage gap the I-06
    review flagged: main()'s write-ordering guarantee (every run_iNN() call
    happens before any _write_guarded/_write_guarded_jsonl call) was
    previously only verified by reading the code, never by a test that
    actually requests --run-i06 alongside the injected failure.
    """
    memory = {GUOBJECTARRAY_VA: bytes(0x2C)}  # never read this far.
    num_elements_addr = GUOBJECTARRAY_VA + tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS
    api, _ = i04_tests._fake_i04_api(
        tmp_path, memory, fail_read_addresses={num_elements_addr})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i04", "--run-i06",
        "--i02-poll-interval-seconds", "0",
    ])
    assert rc == 2
    assert not os.path.exists(run_dir)


def test_decode_property_type_deep_container_recursion_threads_and_bounds_correctly():
    """Genuine multi-level recursion -- 5 REAL FArrayProperty objects, each
    one's own Inner pointing to the NEXT one elsewhere in memory (never a
    directly-injected container_depth like test_decode_property_type_
    container_depth_exceeded above) -- proving container_depth+1 threading
    actually accumulates correctly through real recursive decode_property_
    type() calls inside _decode_array_property(), not merely that the depth
    guard itself works when handed a pre-set value (the one live coverage
    gap the I-06 review flagged: the existing container_depth_exceeded test
    only proves the CHECK works, never that all four container helpers
    correctly thread container_depth + 1 through genuine recursion).

    field_addr(0..3) (decoded at depth 0..3) must each decode successfully
    with their own 'inner' populated. field_addr(4) (depth 4) must ALSO
    still decode successfully -- 4 <= the default max_container_depth=4 --
    but its OWN Inner recursive call lands at depth 5, exceeding the bound:
    caught and reduced to inner=None by _to_property_type_ref(), never
    propagated to invalidate field_addr(4) itself or any ancestor level.
    field_addr(5) is referenced by field_addr(4)'s own Inner pointer but
    never needs real memory behind it at all: the depth check is
    decode_property_type()'s own FIRST check, before any read, so the
    rejection happens without ever touching field_addr(5).
    """
    assert tool.DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH == 4
    memory, addr_by_name, allocator = _base_fixture()
    name_id = allocator.add("DeepArray")
    for level in range(5):  # field_addr(0..4), each Inner -> field_addr(level+1).
        write_fproperty(
            memory, field_addr(level), class_ptr=addr_by_name["FArrayProperty"],
            owner_raw=uobject_owner(class_addr(0)), next_ptr=0, name_id=name_id,
            element_size=0x10,
            extra=(struct.pack("<B", 0) + b"\x00" * 7 +
                   struct.pack("<Q", field_addr(level + 1))))
    api = _finish(memory, allocator)

    decoded = tool.decode_property_type(api, 1, field_addr(0), namepool_live_va=NAMEPOOL_VA)
    assert decoded["valid"] is True

    node = decoded
    for level in range(4):  # depths 0,1,2,3 -- each must have a populated Inner.
        assert node["property_class"] == "FArrayProperty", "level %d" % level
        assert node["inner"] is not None, "level %d Inner missing" % level
        node = node["inner"]
    # node is now field_addr(4)'s own property_type_ref, decoded at depth 4 --
    # still a VALID FArrayProperty (4 <= max_container_depth=4).
    assert node["property_class"] == "FArrayProperty"
    # field_addr(4)'s OWN Inner recursive call lands at depth 5, exceeding
    # the bound -- reduced to None, never fabricated.
    assert node["inner"] is None

    # Bonus: decoding field_addr(4) directly (the exact call the depth-4
    # ancestor above made internally) confirms its own rejection reason is
    # genuinely the depth guard, not a coincidental unrelated failure.
    field4_direct = tool.decode_property_type(
        api, 1, field_addr(4), namepool_live_va=NAMEPOOL_VA, container_depth=4)
    assert field4_direct["valid"] is True
    assert any("did not decode" in n for n in field4_direct["notes"])


def test_main_run_i06_requires_run_i04(tmp_path, monkeypatch):
    api, _ = i04_tests._fake_i04_api(tmp_path, memory={})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i06"])
    assert rc == 2
    assert not os.path.exists(run_dir)
    assert api.calls["open_process"] == 0


def test_main_without_run_i06_never_touches_i06_at_all(tmp_path, monkeypatch):
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
    assert not os.path.exists(os.path.join(run_dir, "i06-properties.json"))
    assert not os.path.exists(os.path.join(run_dir, "properties.jsonl"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert "I-06" not in manifest["capabilities_enabled"]


# --------------------------------------------------------------------------- #
# still exactly one ReadProcessMemory call site -- I-06 adds new CALLERS of
# Win32Api.read_process_memory (via _read_u8/_read_u32/_read_u64/_read_i32/
# _read_u16, every one of which already funnels through the SAME one
# ctypes.windll... call site), never a second wrapper.
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
