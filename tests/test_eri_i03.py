#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-03 (plan.md 8.2).

I-03 resolves an FName (an FNameEntryId) to its string text by reading the
RF-06 candidate FNamePool's own internal block table directly
(research/evidence/RF-06/README.md), reusing I-02's own ReadProcessMemory
call site and rva_to_live_va()/chunk-walk arithmetic rather than adding a
second one of either. No MISERY process runs in this environment (nor in
CI), so every test below exercises the plain-Python logic functions
(decode_fname_entry_id, run_i03, sample_object_names) against a fake memory
model -- the same "duck-typed narrow interface, faked in tests" idiom
tests/test_eri_i02.py already established for this file, cross-imported
here (MemoryFakeApi, FakeWin32ApiWithMemory, BASE_ADDRESS, IMAGE_SIZE_BYTES)
rather than re-derived.

Run:  python -m pytest -q tests/test_eri_i03.py
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

# Cross-import from the I-01/I-02 test modules -- an established convention
# in this repo (test_eri_i02.py already does this for test_eri_i01.py; see
# e.g. tests/test_sigscan.py for the original precedent). Reuses
# VALID_BUILD_KEY/TARGET_NAME/proc/mod/_write_stub_exe/_patch_fake_win32api/
# IDENTITY_KWARGS/_manifest_validator from test_eri_i01, and
# MemoryFakeApi/FakeWin32ApiWithMemory/BASE_ADDRESS/IMAGE_SIZE_BYTES/
# GUOBJECTARRAY_VA/make_guobjectarray_memory from test_eri_i02, rather than
# re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402
import test_eri_i02 as i02_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY
BASE_ADDRESS = i02_tests.BASE_ADDRESS
IMAGE_SIZE_BYTES = i02_tests.IMAGE_SIZE_BYTES
MemoryFakeApi = i02_tests.MemoryFakeApi

NAMEPOOL_RVA = tool.DEFAULT_NAMEPOOL_RVA
NAMEPOOL_VA = BASE_ADDRESS + NAMEPOOL_RVA
NAME_POOL_INITIALIZED_RVA = tool.DEFAULT_NAME_POOL_INITIALIZED_RVA
NAME_POOL_INITIALIZED_VA = BASE_ADDRESS + NAME_POOL_INITIALIZED_RVA
NAME_PRIVATE_OFFSET = tool.DEFAULT_NAME_PRIVATE_OFFSET
GUOBJECTARRAY_VA = i02_tests.GUOBJECTARRAY_VA


# --------------------------------------------------------------------------- #
# fake FNamePool memory -- one independent "block" region per distinct
# FNameEntryId used, always at offset 0 within its own block (i.e. every id
# passed to these helpers must be a multiple of 0x10000, block<<16). This
# keeps the helper simple while still exercising the real block-pointer-
# table/entry-stride arithmetic -- a SEPARATE test below
# (test_decode_fname_entry_id_nonzero_offset_within_a_shared_block) builds a
# raw memory dict by hand to cover a non-zero Offset within one block, since
# that is the one axis this helper's own simplification does not exercise.
# --------------------------------------------------------------------------- #

def _pack_fname_entry(text: str, *, is_wide: bool = False, probe_hash: int = 0x07) -> bytes:
    length = len(text)
    header = ((1 if is_wide else 0) & tool.FNAME_HEADER_IS_WIDE_MASK) \
        | ((probe_hash & 0x1F) << 1) \
        | ((length & tool.FNAME_HEADER_LEN_MASK) << tool.FNAME_HEADER_LEN_SHIFT)
    char_bytes = text.encode("utf-16-le") if is_wide else text.encode("ascii")
    return struct.pack("<H", header) + char_bytes


def make_fnamepool_memory(*, entries: dict, base_address: int = BASE_ADDRESS,
                          namepool_rva: int = NAMEPOOL_RVA,
                          name_pool_initialized_rva: int = NAME_POOL_INITIALIZED_RVA,
                          pool_initialized: bool = True) -> tuple:
    """*entries*: {name_entry_id: (text, is_wide)}. Every name_entry_id MUST
    be a multiple of 0x10000 (offset 0 within its own, dedicated block) --
    see the module-level comment above for why. Returns (memory, addrs).
    """
    namepool_va = base_address + namepool_rva
    initialized_va = base_address + name_pool_initialized_rva
    blocks_table_addr = namepool_va + tool.NAMEPOOL_OFFSET_BLOCKS

    memory: dict = {initialized_va: bytes([1 if pool_initialized else 0])}
    block_bases: dict = {}
    next_block_base = namepool_va + 0x00100000  # well clear of the struct itself

    for name_entry_id, (text, is_wide) in entries.items():
        block = name_entry_id >> tool.FNAME_BLOCK_OFFSET_BITS
        offset = name_entry_id & 0xFFFF
        assert offset == 0, (
            "test bug: make_fnamepool_memory requires offset==0 (one entry "
            "per its own dedicated block) -- got name_entry_id=0x%x" % name_entry_id)
        if block not in block_bases:
            block_bases[block] = next_block_base
            next_block_base += 0x00010000
        memory[block_bases[block]] = _pack_fname_entry(text, is_wide=is_wide)

    if block_bases:
        max_block = max(block_bases)
        blocks_blob = bytearray((max_block + 1) * 8)
        for block, block_base in block_bases.items():
            struct.pack_into("<Q", blocks_blob, block * 8, block_base)
        memory[blocks_table_addr] = bytes(blocks_blob)

    return memory, {
        "namepool_va": namepool_va, "initialized_va": initialized_va,
        "blocks_table_addr": blocks_table_addr, "block_bases": block_bases,
    }


# --------------------------------------------------------------------------- #
# constants sanity -- RF-06's own static candidates, and the derived
# UObjectBase.h field-layout offset, pinned so a future edit cannot silently
# drift from the evidence they were read from.
# --------------------------------------------------------------------------- #

def test_default_namepool_rva_matches_rf06_static_candidate():
    static_candidate_va = 0x1479C2180
    declared_image_base = 0x140000000
    assert tool.DEFAULT_NAMEPOOL_RVA == static_candidate_va - declared_image_base
    assert tool.DEFAULT_NAMEPOOL_RVA == 0x079C2180


def test_default_name_pool_initialized_rva_matches_rf06_static_candidate():
    static_candidate_va = 0x147995E5E
    declared_image_base = 0x140000000
    assert (tool.DEFAULT_NAME_POOL_INITIALIZED_RVA
            == static_candidate_va - declared_image_base)
    assert tool.DEFAULT_NAME_POOL_INITIALIZED_RVA == 0x07995E5E


def test_fname_header_bit_layout_constants():
    assert tool.FNAME_BLOCK_OFFSET_BITS == 16
    assert tool.FNAME_ENTRY_STRIDE == 2
    assert tool.FNAME_ENTRY_HEADER_SIZE_BYTES == 2
    assert tool.FNAME_HEADER_IS_WIDE_MASK == 0x1
    assert tool.FNAME_HEADER_LEN_SHIFT == 6
    assert tool.FNAME_HEADER_LEN_MASK == 0x3FF


def test_default_name_private_offset_cross_checks_against_rf05_internal_index():
    """UObjectBase.h's own member declaration order: vtable(8) +
    ObjectFlags(4) + InternalIndex(4) + ClassPrivate(8) = NamePrivate's own
    start. The +0x0C landing for InternalIndex here is the SAME +0xc RF-05's
    own independent disassembly of UObjectBase::~UObjectBase found -- see
    DEFAULT_NAME_PRIVATE_OFFSET's own comment in eri.py for the full
    derivation this pins.
    """
    vtable_offset = 0x00
    object_flags_offset = vtable_offset + 8
    internal_index_offset = object_flags_offset + 4
    class_private_offset = internal_index_offset + 4
    name_private_offset = class_private_offset + 8
    assert internal_index_offset == 0x0C  # RF-05's own independently-found offset
    assert name_private_offset == 0x18
    assert tool.DEFAULT_NAME_PRIVATE_OFFSET == 0x18


# --------------------------------------------------------------------------- #
# decode_fname_entry_id -- the core decode arithmetic, pinned against a
# synthetic memory image so the test suite does not depend on any live
# process. FNameEntryId 0 decoding to "None" is the mandatory, RF-06-
# prescribed confirmation step.
# --------------------------------------------------------------------------- #

def test_decode_fname_entry_id_zero_decodes_to_none():
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)})
    api = MemoryFakeApi(memory=memory)
    result = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, 0)
    assert result["text"] == "None"
    assert result["is_wide"] is False
    assert result["length"] == 4
    assert result["block"] == 0
    assert result["offset"] == 0
    assert result["decode_error"] is None


def test_decode_fname_entry_id_header_bit_layout_independent_of_module_constants():
    """Regression pin for a real defect found by adversarial review of this
    workflow (2026-08-27): every other test in this file builds its synthetic
    FNameEntryHeader bytes via _pack_fname_entry(), which computes the header
    using tool.FNAME_HEADER_IS_WIDE_MASK/FNAME_HEADER_LEN_MASK/
    FNAME_HEADER_LEN_SHIFT -- the SAME constants decode_fname_entry_id() uses
    to extract is_wide/length. That makes every "None"-decode test upstream
    of this one a pure encode/decode round-trip of one shared formula: it
    proves internal self-consistency, never that the formula matches the
    real MSVC-compiled FNameEntryHeader layout. A wrong FNAME_HEADER_LEN_SHIFT
    would sail through every other test in this file undetected.

    This test hardcodes the expected raw header bytes by hand, independent of
    any module constant, with the bit math shown inline -- computed directly
    from Engine/Source/Runtime/Core/Public/UObject/NameTypes.h:194-203 (this
    build's WITH_CASE_PRESERVING_NAME==0 branch): a single little-endian
    uint16 packed as `uint16 bIsWide:1; uint16 LowercaseProbeHash:5;
    uint16 Len:10;`, MSVC's LSB-first bitfield packing (bit 0 = bIsWide,
    bits 1-5 = LowercaseProbeHash, bits 6-15 = Len) -- the SAME bit order the
    module's decode logic assumes, but arrived at here by hand, not by
    calling or mirroring eri.py's own constants.

    Case 1: "None" (len=4, is_wide=0, probe_hash=0 for a clean literal).
      bit 0 (bIsWide)          = 0
      bits 1-5 (LowercaseProbeHash) = 0
      bits 6-15 (Len=4)        = 4 << 6 = 0b0000_0001_0000_0000 = 0x0100
      header_u16 = 0x0000 | 0x0000 | 0x0100 = 0x0100
      little-endian bytes: 0x00, 0x01
    """
    header_bytes = bytes([0x00, 0x01])  # hand-computed 0x0100, see docstring
    entry_bytes = header_bytes + b"None"
    namepool_va = BASE_ADDRESS + NAMEPOOL_RVA
    initialized_va = BASE_ADDRESS + NAME_POOL_INITIALIZED_RVA
    blocks_table_addr = namepool_va + tool.NAMEPOOL_OFFSET_BLOCKS
    entry_addr = namepool_va + 0x00100000
    memory = {
        initialized_va: bytes([1]),
        blocks_table_addr: entry_addr.to_bytes(8, "little"),
        entry_addr: entry_bytes,
    }
    api = MemoryFakeApi(memory=memory)
    result = tool.decode_fname_entry_id(api, 1, namepool_va, 0)
    assert result["text"] == "None", (
        "hand-computed header 0x0100 (len=4, is_wide=0 per NameTypes.h's "
        "actual bit layout) did not decode to 'None' -- either the bit "
        "layout assumption is wrong, or decode_fname_entry_id() no longer "
        "matches it. Do not adjust this test's hardcoded bytes to make it "
        "pass; re-derive the bit math from NameTypes.h again instead.")
    assert result["is_wide"] is False
    assert result["length"] == 4

    # Case 2: is_wide=1, len=1 ("x", 2-byte UTF-16LE char), probe_hash=0.
    #   bit 0 = 1; bits 1-5 = 0; bits 6-15 (Len=1) = 1<<6 = 0x0040
    #   header_u16 = 0x0001 | 0x0040 = 0x0041 -> bytes 0x41, 0x00
    wide_header_bytes = bytes([0x41, 0x00])
    wide_entry_bytes = wide_header_bytes + "x".encode("utf-16-le")
    wide_id = 0x10000  # block 1, offset 0
    wide_entry_addr = namepool_va + 0x00110000
    memory2 = {
        initialized_va: bytes([1]),
        blocks_table_addr: (
            entry_addr.to_bytes(8, "little") + wide_entry_addr.to_bytes(8, "little")),
        entry_addr: entry_bytes,
        wide_entry_addr: wide_entry_bytes,
    }
    api2 = MemoryFakeApi(memory=memory2)
    result2 = tool.decode_fname_entry_id(api2, 1, namepool_va, wide_id)
    assert result2["text"] == "x", (
        "hand-computed header 0x0041 (len=1, is_wide=1) did not decode to "
        "'x' -- see this test's docstring; do not adjust the hardcoded "
        "bytes to make it pass.")
    assert result2["is_wide"] is True
    assert result2["length"] == 1


def test_decode_fname_entry_id_wide_entry_decodes_utf16():
    name_entry_id = 0x10000  # block 1, offset 0
    memory, _ = make_fnamepool_memory(entries={name_entry_id: ("Wide\u00e9Name", True)})
    api = MemoryFakeApi(memory=memory)
    result = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, name_entry_id)
    assert result["is_wide"] is True
    assert result["text"] == "Wide\u00e9Name"
    assert result["block"] == 1
    assert result["length"] == len("Wide\u00e9Name")


def test_decode_fname_entry_id_zero_length_decodes_to_empty_string_not_none():
    name_entry_id = 0x20000
    memory, _ = make_fnamepool_memory(entries={name_entry_id: ("", False)})
    api = MemoryFakeApi(memory=memory)
    result = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, name_entry_id)
    assert result["length"] == 0
    assert result["text"] == ""  # empty, not the decode-FAILURE sentinel None
    assert result["decode_error"] is None


def test_decode_fname_entry_id_undecodable_bytes_reports_error_not_raise():
    """A byte sequence that fails to decode is a STRUCTURAL REFUTATION
    signal, reported as data (text=None, decode_error set, raw bytes
    preserved for diagnosis) -- never raised.
    """
    name_entry_id = 0x30000
    block_base = NAMEPOOL_VA + 0x00100000
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    # header: not wide, length 3, followed by a byte >= 0x80 -- invalid ASCII.
    header = (0 & 0x1) | (0x07 << 1) | ((3 & 0x3FF) << 6)
    entry_bytes = struct.pack("<H", header) + b"\xffAB"
    memory = {
        NAME_POOL_INITIALIZED_VA: b"\x01",
        blocks_table_addr: struct.pack("<Q", block_base) * 4,  # covers block 0-3
        block_base: entry_bytes,
    }
    api = MemoryFakeApi(memory=memory)
    result = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, name_entry_id)
    assert result["text"] is None
    assert result["decode_error"] is not None
    assert result["raw_bytes_hex"] == b"\xffAB".hex()
    assert result["length"] == 3


def test_decode_fname_entry_id_nonzero_offset_within_a_shared_block():
    """A second axis make_fnamepool_memory's own one-entry-per-block
    simplification does not exercise: two entries in the SAME block, at
    Offset 0 and a nonzero Offset, must not clash -- entry_ptr = block_base +
    Offset * FNAME_ENTRY_STRIDE(2).
    """
    block_base = NAMEPOOL_VA + 0x00100000
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    first_entry = _pack_fname_entry("AAAA", is_wide=False)  # 2 + 4 = 6 bytes
    # second entry lives at Offset=10 -> byte offset 20, well clear of the
    # first entry's 6 bytes.
    second_offset = 10
    second_entry = _pack_fname_entry("BBBB", is_wide=False)
    block_blob = bytearray(64)
    block_blob[0:len(first_entry)] = first_entry
    block_blob[second_offset * tool.FNAME_ENTRY_STRIDE:
               second_offset * tool.FNAME_ENTRY_STRIDE + len(second_entry)] = second_entry
    memory = {
        NAME_POOL_INITIALIZED_VA: b"\x01",
        blocks_table_addr: struct.pack("<Q", block_base),
        block_base: bytes(block_blob),
    }
    api = MemoryFakeApi(memory=memory)
    first = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, 0)
    second = tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, second_offset)
    assert first["text"] == "AAAA"
    assert second["text"] == "BBBB"
    assert second["offset"] == second_offset


def test_decode_fname_entry_id_propagates_read_failure_on_block_pointer():
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    api = MemoryFakeApi(memory={}, fail_read_addresses={blocks_table_addr})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, 0)


def test_decode_fname_entry_id_propagates_read_failure_on_header():
    block_base = NAMEPOOL_VA + 0x00100000
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    memory = {blocks_table_addr: struct.pack("<Q", block_base)}
    api = MemoryFakeApi(memory=memory, fail_read_addresses={block_base})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.decode_fname_entry_id(api, 1, NAMEPOOL_VA, 0)


# --------------------------------------------------------------------------- #
# run_i03 -- bNamePoolInitialized gate, the id=0 "decoded_as_expected"
# confirmation, and the honest not-yet-initialized / hard-failure paths.
# --------------------------------------------------------------------------- #

def test_run_i03_id_zero_decodes_as_expected_true():
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)})
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                          image_size_bytes=IMAGE_SIZE_BYTES)
    assert result["pool_initialized"] is True
    assert result["decoded"]["text"] == "None"
    assert result["decoded_as_expected"] is True
    assert result["namepool_live_va"] == NAMEPOOL_VA
    assert result["name_pool_initialized_live_va"] == NAME_POOL_INITIALIZED_VA


def test_run_i03_wrong_decode_reports_decoded_as_expected_false():
    """A real, reportable STRUCTURAL REFUTATION -- id=0 decodes to something
    other than 'None' -- must be reported as data, never raised.
    """
    memory, _ = make_fnamepool_memory(entries={0: ("Wrong", False)})
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                          image_size_bytes=IMAGE_SIZE_BYTES)
    assert result["decoded"]["text"] == "Wrong"
    assert result["decoded_as_expected"] is False


def test_run_i03_decoded_as_expected_is_none_for_nonzero_id():
    name_entry_id = 0x10000
    memory, _ = make_fnamepool_memory(entries={name_entry_id: ("SomeName", False)})
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                          image_size_bytes=IMAGE_SIZE_BYTES, name_entry_id=name_entry_id)
    assert result["decoded"]["text"] == "SomeName"
    assert result["decoded_as_expected"] is None  # no known expected answer for this id


def test_run_i03_pool_not_initialized_reports_honestly_without_decoding():
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)}, pool_initialized=False)
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                          image_size_bytes=IMAGE_SIZE_BYTES)
    assert result["pool_initialized"] is False
    assert result["decoded"] is None
    assert result["decoded_as_expected"] is None


def test_run_i03_hard_read_failure_on_initialized_byte_propagates():
    api = MemoryFakeApi(memory={}, fail_read_addresses={NAME_POOL_INITIALIZED_VA})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                     image_size_bytes=IMAGE_SIZE_BYTES)


def test_run_i03_hard_read_failure_inside_decode_propagates():
    blocks_table_addr = NAMEPOOL_VA + tool.NAMEPOOL_OFFSET_BLOCKS
    memory = {NAME_POOL_INITIALIZED_VA: b"\x01"}
    api = MemoryFakeApi(memory=memory, fail_read_addresses={blocks_table_addr})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.run_i03(api, process_handle=1, base_address=BASE_ADDRESS,
                     image_size_bytes=IMAGE_SIZE_BYTES)


def test_run_i03_custom_rva_overrides_defaults():
    custom_namepool_rva = 0x1000
    custom_initialized_rva = 0x2000
    memory, _ = make_fnamepool_memory(
        entries={0: ("None", False)},
        namepool_rva=custom_namepool_rva,
        name_pool_initialized_rva=custom_initialized_rva)
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i03(
        api, process_handle=1, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        namepool_rva=custom_namepool_rva, name_pool_initialized_rva=custom_initialized_rva)
    assert result["namepool_live_va"] == BASE_ADDRESS + custom_namepool_rva
    assert result["decoded"]["text"] == "None"
    assert result["decoded_as_expected"] is True


# --------------------------------------------------------------------------- #
# sample_object_names -- the "/Script/MISERY live reflection" probe. Reuses
# _locate_object_pointer (I-02's own chunk-walk arithmetic, factored out for
# exactly this reuse) rather than re-deriving the walk.
# --------------------------------------------------------------------------- #

def make_object_chunk_memory(*, object_name_entry_ids: list,
                             guobjectarray_va: int = GUOBJECTARRAY_VA,
                             name_private_offset: int = NAME_PRIVATE_OFFSET) -> tuple:
    """object_name_entry_ids[i] is either an int FNameEntryId (a populated
    slot whose fake UObject's own NamePrivate.ComparisonIndex is that id) or
    None (a freed/never-allocated null slot). ONE chunk (chunk_index 0).
    Returns (memory, objects_ptr) -- objects_ptr is GUOBJECTARRAY_OFFSET_
    OBJECTS's own value (the chunk POINTER TABLE's address), matching
    test_eri_i02.make_guobjectarray_memory's own 'objects_ptr' naming.
    """
    chunk_table_addr = guobjectarray_va + 0x00040000
    items_addr = chunk_table_addr + 0x1000
    items_region_len = max(len(object_name_entry_ids), 1) * tool.SIZEOF_FUOBJECTITEM
    items_blob = bytearray(items_region_len)
    obj_size = name_private_offset + 8  # room for NamePrivate (ComparisonIndex+Number)
    fake_obj_base = items_addr + items_region_len + 0x1000

    memory: dict = {}
    for i, name_entry_id in enumerate(object_name_entry_ids):
        if name_entry_id is None:
            struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, 0)
            continue
        obj_addr = fake_obj_base + i * (obj_size + 0x40)
        obj_blob = bytearray(obj_size)
        struct.pack_into("<I", obj_blob, name_private_offset, name_entry_id)
        memory[obj_addr] = bytes(obj_blob)
        struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, obj_addr)

    memory[items_addr] = bytes(items_blob)
    memory[chunk_table_addr] = struct.pack("<Q", items_addr)
    return memory, chunk_table_addr


def test_sample_object_names_finds_misery():
    """Target is '/Script/MISERY', not the bare leaf 'MISERY' -- corrected
    2026-08-27 after the first live run showed UPackage objects store their
    FULL '/Script/<Module>' path as their own NamePrivate, not just the leaf
    (see MISERY_PACKAGE_TARGET_NAME's own comment in eri.py for the full
    story: the original 'MISERY'-only assumption was a real, live-run-caught
    false negative, not a tool defect).
    """
    object_ids = [0x10000, 0x20000, 0x30000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("SomeOtherThing", False),
        0x20000: ("/Script/MISERY", False),
        0x30000: ("YetAnotherName", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=3, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100)
    assert result["misery_found"] is True
    assert "/Script/MISERY" in result["decoded_names"]
    assert result["objects_examined"] == 3
    assert result["decode_failures"] == 0
    assert result["target_name"] == "/Script/MISERY"


def test_sample_object_names_not_found_reports_honestly():
    object_ids = [0x10000, 0x20000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("SomeClass", False),
        0x20000: ("OtherObject", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=2, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100)
    assert result["misery_found"] is False
    assert "MISERY" not in result["decoded_names"]
    assert sorted(result["decoded_names"]) == ["OtherObject", "SomeClass"]
    # the bounded-sample honesty caveat must appear in the output itself.
    assert "bounded" in result["note"].lower()
    assert "not" in result["note"].lower() and "exhaustive" in result["note"].lower()


def test_sample_object_names_skips_unreadable_locating_slot_not_counted():
    object_ids = [0x10000, 0x20000, 0x30000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("First", False), 0x20000: ("Second", False), 0x30000: ("Third", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    # index 1's own FUObjectItem.Object field read fails -- located by
    # computing its item address directly from the items region layout
    # (chunk 0, stride SIZEOF_FUOBJECTITEM), mirroring test_eri_i02's
    # equivalent "unreadable slot while locating" test.
    items_addr_bytes = memory[objects_ptr]
    items_addr = struct.unpack("<Q", items_addr_bytes)[0]
    unreadable_item_addr = items_addr + 1 * tool.SIZEOF_FUOBJECTITEM
    api = MemoryFakeApi(memory=memory, fail_read_addresses={unreadable_item_addr})
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=3, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100)
    assert result["objects_examined"] == 2  # indices 0 and 2 only
    assert result["indices_scanned"] == 3
    assert sorted(result["decoded_names"]) == ["First", "Third"]
    assert result["decode_failures"] == 0


def test_sample_object_names_torn_read_on_nameprivate_counts_as_decode_failure():
    object_ids = [0x10000, 0x20000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("First", False), 0x20000: ("Second", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    # find object 0's own address (from the items region) and make its
    # NamePrivate field unreadable -- a torn read on an ALREADY-located
    # object, which must count as a decode failure, not be silently skipped.
    items_addr = struct.unpack("<Q", memory[objects_ptr])[0]
    obj0_addr = struct.unpack(
        "<Q", memory[items_addr][0:8])[0]
    unreadable_nameprivate_addr = obj0_addr + NAME_PRIVATE_OFFSET
    api = MemoryFakeApi(memory=memory, fail_read_addresses={unreadable_nameprivate_addr})
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=2, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100)
    assert result["objects_examined"] == 2  # both were LOCATED (committed to the sample)
    assert result["decode_failures"] == 1
    assert result["decoded_names"] == ["Second"]


def test_sample_object_names_respects_sample_size_bound():
    object_ids = [0x10000 * (i + 1) for i in range(10)]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    entries = {oid: ("Name%d" % i, False) for i, oid in enumerate(object_ids)}
    fnamepool_memory, _ = make_fnamepool_memory(entries=entries)
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=10, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=4, max_scan_indices=100)
    assert result["objects_examined"] == 4
    assert result["indices_scanned"] == 4
    assert len(result["decoded_names"]) == 4


def test_sample_object_names_respects_max_scan_indices_bound_when_sparse():
    object_ids = [None] * 50  # nothing populated at all
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    api = MemoryFakeApi(memory=chunk_memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=5_000_000, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=32, max_scan_indices=50)
    assert result["indices_scanned"] == 50
    assert result["objects_examined"] == 0
    assert result["misery_found"] is False


def test_sample_object_names_duplicate_names_all_recorded_not_deduplicated():
    object_ids = [0x10000, 0x20000, 0x30000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={
        0x10000: ("Repeated", False), 0x20000: ("Repeated", False), 0x30000: ("Unique", False),
    })
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=3, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100)
    assert result["decoded_names"].count("Repeated") == 2
    assert result["decoded_names"].count("Unique") == 1


def test_sample_object_names_target_name_parameter_overridable():
    object_ids = [0x10000]
    chunk_memory, objects_ptr = make_object_chunk_memory(object_name_entry_ids=object_ids)
    fnamepool_memory, _ = make_fnamepool_memory(entries={0x10000: ("CustomTarget", False)})
    memory = {**chunk_memory, **fnamepool_memory}
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_object_names(
        api, 1, objects_ptr, num_elements=1, namepool_live_va=NAMEPOOL_VA,
        name_private_offset=NAME_PRIVATE_OFFSET, sample_size=10, max_scan_indices=100,
        target_name="CustomTarget")
    assert result["misery_found"] is True  # field name is generic; value is "found"
    assert result["target_name"] == "CustomTarget"


# --------------------------------------------------------------------------- #
# build_i03_document
# --------------------------------------------------------------------------- #

def _sample_run_i03_result(decoded_text="None", decoded_as_expected=True,
                           pool_initialized=True):
    decoded = None if not pool_initialized else {
        "block": 0, "offset": 0, "block_base_hex": "0x5000", "entry_ptr_hex": "0x5000",
        "header_u16_hex": "0x010e", "is_wide": False, "length": len(decoded_text),
        "raw_bytes_hex": decoded_text.encode("ascii").hex(), "text": decoded_text,
        "decode_error": None,
    }
    return {
        "namepool_rva": 0x79C2180, "namepool_rva_hex": "0x79c2180",
        "namepool_live_va": 0x7FF600000000 + 0x79C2180,
        "namepool_live_va_hex": "0x7ff6000079c2180",
        "name_pool_initialized_rva": 0x7995E5E, "name_pool_initialized_rva_hex": "0x7995e5e",
        "name_pool_initialized_live_va": 0x7FF600000000 + 0x7995E5E,
        "name_pool_initialized_live_va_hex": "0x7ff600007995e5e",
        "pool_initialized": pool_initialized,
        "name_entry_id": 0,
        "decoded": decoded,
        "decoded_as_expected": decoded_as_expected if pool_initialized else None,
    }


def test_build_i03_document_shape_and_values():
    result = _sample_run_i03_result()
    doc = tool.build_i03_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["capability"] == "I-03"
    assert doc["decoded"]["text"] == "None"
    assert doc["decoded_as_expected"] is True
    assert doc["misery_reflection"] is None
    assert doc["identity_self_established"] is True
    assert doc["build_key"] == VALID_BUILD_KEY
    assert doc["generator"] == tool.GENERATOR_NAME
    assert doc["generator_version"] == tool.GENERATOR_VERSION
    assert "evidence_level" not in doc
    assert "oracle" not in doc
    json.loads(tool.dump_json(doc))


def test_build_i03_document_includes_misery_reflection_when_given():
    result = _sample_run_i03_result()
    reflection = {
        "sample_size_requested": 512, "max_scan_indices": 200_000,
        "indices_scanned": 3, "objects_examined": 3, "decode_failures": 0,
        "decoded_names": ["A", "MISERY", "B"], "target_name": "MISERY",
        "misery_found": True, "note": "bounded, NOT exhaustive sample...",
    }
    doc = tool.build_i03_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at=None,
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None, misery_reflection=reflection)
    assert doc["misery_reflection"]["misery_found"] is True
    assert "MISERY" in doc["misery_reflection"]["decoded_names"]
    json.loads(tool.dump_json(doc))


def test_build_i03_document_pool_not_initialized_shape():
    result = _sample_run_i03_result(pool_initialized=False)
    doc = tool.build_i03_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at=None,
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["pool_initialized"] is False
    assert doc["decoded"] is None
    assert doc["decoded_as_expected"] is None
    json.loads(tool.dump_json(doc))


# --------------------------------------------------------------------------- #
# build_manifest with capabilities_enabled including I-03
# --------------------------------------------------------------------------- #

def test_build_manifest_with_i03_capability_validates_against_schema():
    validator = i01_tests._manifest_validator()
    manifest = tool.build_manifest(
        run_id="r", arguments=["--run-i02", "--run-i03"], tool_version="0.1.0",
        build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=["research/instrument-runs/r/i01-process-info.json",
                   "research/instrument-runs/r/i02-guobjectarray.json",
                   "research/instrument-runs/r/i03-fnamepool.json"],
        capabilities_enabled=["I-01", "I-02", "I-03"],
        **i01_tests.IDENTITY_KWARGS)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03"]
    errors = list(validator.iter_errors(manifest))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_cli_run_i03_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_i03 is False
    assert args.namepool_rva is None
    assert args.name_pool_initialized_rva is None
    assert args.i03_name_entry_id == 0
    assert args.i03_out is None
    assert args.run_i03_reflection is False
    assert args.i03_reflection_sample_size == tool.DEFAULT_I03_REFLECTION_SAMPLE_SIZE
    assert args.i03_reflection_max_scan_indices == tool.DEFAULT_I02_MAX_SCAN_INDICES
    assert args.name_private_offset is None


def test_cli_i03_name_entry_id_accepts_hex_and_decimal():
    args = tool.build_arg_parser().parse_args(["--i03-name-entry-id", "0x10000"])
    assert args.i03_name_entry_id == 0x10000
    args = tool.build_arg_parser().parse_args(["--i03-name-entry-id", "65536"])
    assert args.i03_name_entry_id == 65536


def test_parse_namepool_rva_default_and_override():
    assert tool._parse_namepool_rva(None) == tool.DEFAULT_NAMEPOOL_RVA
    assert tool._parse_namepool_rva("0x1000") == 0x1000
    assert tool._parse_namepool_rva("4096") == 4096
    with pytest.raises(ValueError):
        tool._parse_namepool_rva("not-a-number")


def test_parse_name_pool_initialized_rva_default_and_override():
    assert (tool._parse_name_pool_initialized_rva(None)
            == tool.DEFAULT_NAME_POOL_INITIALIZED_RVA)
    assert tool._parse_name_pool_initialized_rva("0x2000") == 0x2000
    with pytest.raises(ValueError):
        tool._parse_name_pool_initialized_rva("garbage")


def test_parse_name_private_offset_default_and_override():
    assert tool._parse_name_private_offset(None) == tool.DEFAULT_NAME_PRIVATE_OFFSET
    assert tool._parse_name_private_offset("0x20") == 0x20
    with pytest.raises(ValueError):
        tool._parse_name_private_offset("garbage")


def test_resolve_i03_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_i03_output_path(args) is None


def test_resolve_i03_output_path_requires_i03_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i03"])
    with pytest.raises(ValueError):
        tool._resolve_i03_output_path(args)


def test_resolve_i03_output_path_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(["--run-i03", "--run-dir", run_dir])
    assert tool._resolve_i03_output_path(args) == os.path.join(run_dir, "i03-fnamepool.json")


def test_resolve_i03_output_path_explicit_out_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit = str(tmp_path / "custom-i03.json")
    args = tool.build_arg_parser().parse_args(
        ["--run-i03", "--run-dir", run_dir, "--i03-out", explicit])
    assert tool._resolve_i03_output_path(args) == explicit


def test_validate_i03_reflection_requirements_noop_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    tool._validate_i03_reflection_requirements(args)  # must not raise


def test_validate_i03_reflection_requirements_raises_when_missing_run_i02():
    args = tool.build_arg_parser().parse_args(["--run-i03-reflection", "--run-i03"])
    with pytest.raises(ValueError, match="--run-i02"):
        tool._validate_i03_reflection_requirements(args)


def test_validate_i03_reflection_requirements_raises_when_missing_run_i03():
    args = tool.build_arg_parser().parse_args(["--run-i03-reflection", "--run-i02"])
    with pytest.raises(ValueError, match="--run-i03"):
        tool._validate_i03_reflection_requirements(args)


def test_validate_i03_reflection_requirements_raises_when_missing_both():
    args = tool.build_arg_parser().parse_args(["--run-i03-reflection"])
    with pytest.raises(ValueError):
        tool._validate_i03_reflection_requirements(args)


def test_validate_i03_reflection_requirements_passes_when_both_given():
    args = tool.build_arg_parser().parse_args(
        ["--run-i03-reflection", "--run-i02", "--run-i03"])
    tool._validate_i03_reflection_requirements(args)  # must not raise


# --------------------------------------------------------------------------- #
# main() end-to-end, FakeWin32ApiWithMemory substituted for the real
# Win32Api (same monkeypatch pattern test_eri_i01.py/test_eri_i02.py use) --
# still no live game process anywhere.
# --------------------------------------------------------------------------- #

def _fake_i03_api(tmp_path, memory, **fake_kwargs) -> tuple:
    exe_bytes = b"the live process's actual module bytes for an I-03 test"
    exe_path = i01_tests._write_stub_exe(tmp_path, "MISERY-Win64-Shipping.exe", exe_bytes)
    api = i02_tests.FakeWin32ApiWithMemory(
        processes=[i01_tests.proc(4242, i01_tests.TARGET_NAME)],
        modules_by_pid={4242: [i01_tests.mod(
            i01_tests.TARGET_NAME, exe_path, BASE_ADDRESS, IMAGE_SIZE_BYTES)]},
        memory=memory,
        **fake_kwargs)
    return api, exe_path


def test_main_run_i03_writes_document_and_capability(tmp_path, monkeypatch):
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)})
    api, _ = _fake_i03_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i03"])
    assert rc == 0

    with open(os.path.join(run_dir, "i03-fnamepool.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "I-03"
    assert doc["decoded"]["text"] == "None"
    assert doc["decoded_as_expected"] is True
    assert doc["misery_reflection"] is None

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-03"]
    assert any(a.endswith("i03-fnamepool.json") for a in manifest["artifacts"])


def test_main_run_i03_pool_not_initialized_still_succeeds_rc0(tmp_path, monkeypatch):
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)}, pool_initialized=False)
    api, _ = _fake_i03_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i03"])
    assert rc == 0

    with open(os.path.join(run_dir, "i03-fnamepool.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["pool_initialized"] is False
    assert doc["decoded"] is None


def test_main_run_i03_hard_read_failure_writes_nothing_at_all(tmp_path, monkeypatch):
    api, _ = _fake_i03_api(
        tmp_path, memory={}, fail_read_addresses={NAME_POOL_INITIALIZED_VA})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i03"])
    assert rc == 2
    assert not os.path.exists(run_dir)


def test_main_run_i03_reflection_requires_i02_and_i03_together(tmp_path, monkeypatch):
    api, _ = _fake_i03_api(tmp_path, memory={})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i03-reflection"])
    assert rc == 2
    assert not os.path.exists(run_dir)
    # nothing was even touched on the fake Win32 API -- validated before any
    # handle was opened.
    assert api.calls["open_process"] == 0


def make_combined_run_memory(*, object_name_entry_ids: list, entries_text: dict,
                             num_elements: int | None = None, max_elements: int = 100,
                             base_address: int = BASE_ADDRESS,
                             guobjectarray_va: int = GUOBJECTARRAY_VA,
                             name_private_offset: int = NAME_PRIVATE_OFFSET,
                             pool_initialized: bool = True) -> dict:
    """Combines a GUObjectArray struct + one chunk of FUObjectItems (I-02's
    own struct shape) with an FNamePool memory image (I-03's own), for a
    main()-level end-to-end test that runs --run-i02 --run-i03
    --run-i03-reflection together in one invocation. Each fake object's
    first 8 bytes are ALSO a plausible vtable pointer (inside the fake
    module image), so I-02's own check_sample_walk can pass too, though
    nothing in these tests depends on that.
    """
    if num_elements is None:
        num_elements = len(object_name_entry_ids)

    chunk_table_addr = guobjectarray_va + 0x00040000
    items_addr = chunk_table_addr + 0x1000
    items_region_len = max(len(object_name_entry_ids), 1) * tool.SIZEOF_FUOBJECTITEM
    items_blob = bytearray(items_region_len)
    obj_size = name_private_offset + 8
    fake_obj_base = items_addr + items_region_len + 0x1000
    valid_vtable_addr = base_address + 0x2000

    memory: dict = {}
    for i, name_entry_id in enumerate(object_name_entry_ids):
        if name_entry_id is None:
            struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, 0)
            continue
        obj_addr = fake_obj_base + i * (obj_size + 0x40)
        obj_blob = bytearray(obj_size)
        struct.pack_into("<Q", obj_blob, 0, valid_vtable_addr)
        struct.pack_into("<I", obj_blob, name_private_offset, name_entry_id)
        memory[obj_addr] = bytes(obj_blob)
        struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, obj_addr)

    memory[items_addr] = bytes(items_blob)
    memory[chunk_table_addr] = struct.pack("<Q", items_addr)

    struct_blob = bytearray(0x2C)
    struct.pack_into("<Q", struct_blob, tool.GUOBJECTARRAY_OFFSET_OBJECTS, chunk_table_addr)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_MAX_ELEMENTS, max_elements)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS, num_elements)
    memory[guobjectarray_va] = bytes(struct_blob)

    fnamepool_memory, _ = make_fnamepool_memory(
        entries=entries_text, base_address=base_address, pool_initialized=pool_initialized)
    memory.update(fnamepool_memory)
    return memory


def test_main_run_i03_reflection_full_pipeline_finds_misery(tmp_path, monkeypatch):
    """Target is '/Script/MISERY' -- see test_sample_object_names_finds_misery's
    own docstring for why (corrected 2026-08-27 after the first live run).
    """
    object_ids = [0x10000, 0x20000, 0x30000]
    entries_text = {
        0: ("None", False),  # run_i03()'s own default id=0 decode
        0x10000: ("SomeOtherThing", False),
        0x20000: ("/Script/MISERY", False),
        0x30000: ("YetAnotherName", False),
    }
    memory = make_combined_run_memory(
        object_name_entry_ids=object_ids, entries_text=entries_text)
    api, _ = _fake_i03_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i03-reflection",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "3",
        "--i03-reflection-sample-size", "10", "--i03-reflection-max-scan-indices", "100",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "i03-fnamepool.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    reflection = doc["misery_reflection"]
    assert reflection is not None
    assert reflection["misery_found"] is True
    assert "/Script/MISERY" in reflection["decoded_names"]
    assert reflection["objects_examined"] == 3

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02", "I-03"]
    assert any(a.endswith("i03-fnamepool.json") for a in manifest["artifacts"])


def test_main_run_i03_reflection_full_pipeline_honest_miss(tmp_path, monkeypatch):
    object_ids = [0x10000, 0x20000]
    entries_text = {
        0: ("None", False),  # run_i03()'s own default id=0 decode
        0x10000: ("SomeClass", False),
        0x20000: ("AnotherClass", False),
    }
    memory = make_combined_run_memory(
        object_name_entry_ids=object_ids, entries_text=entries_text)
    api, _ = _fake_i03_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02", "--run-i03", "--run-i03-reflection",
        "--i02-poll-interval-seconds", "0", "--i02-sample-size", "2",
        "--i03-reflection-sample-size", "10", "--i03-reflection-max-scan-indices", "100",
    ])
    assert rc == 0  # a miss is NOT a failed run

    with open(os.path.join(run_dir, "i03-fnamepool.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    reflection = doc["misery_reflection"]
    assert reflection["misery_found"] is False
    assert "bounded" in reflection["note"].lower()


def test_main_without_run_i03_never_touches_i03_at_all(tmp_path, monkeypatch):
    memory, _ = make_fnamepool_memory(entries={0: ("None", False)})
    api, _ = _fake_i03_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir])
    assert rc == 0
    assert not os.path.exists(os.path.join(run_dir, "i03-fnamepool.json"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01"]


# --------------------------------------------------------------------------- #
# still exactly one ReadProcessMemory call site -- I-03 adds new CALLERS of
# Win32Api.read_process_memory, never a second wrapper around the real
# kernel32 ReadProcessMemory. This mirrors test_eri_i02.py's own equivalent
# test; re-asserted here so a future edit that adds a second call site
# cannot pass I-03's own suite even if it somehow skipped I-02's.
# --------------------------------------------------------------------------- #

def test_source_still_has_exactly_one_readprocessmemory_call_site():
    source = open(tool.__file__, encoding="utf-8").read()
    assert source.count(".ReadProcessMemory(") == 1, (
        "eri.py must call ReadProcessMemory from exactly one place -- "
        "Win32Api.read_process_memory -- so a reviewer can audit it by "
        "reading one line, even after I-03's additions")
