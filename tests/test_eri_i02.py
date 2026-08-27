#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-02 (plan.md 8.2).

I-02 is the first capability in eri.py's life that reads target-process
MEMORY (I-01 only reads the OS's own module table via Toolhelp32), and the
first consumer of the RF-05 candidate GUObjectArray
(research/evidence/RF-05/README.md). No MISERY process runs in this
environment (nor in CI), so every test below exercises the plain-Python
logic functions (rva_to_live_va, evaluate_struct_invariants,
sample_walk_objects, run_i02) against a fake memory model -- a dict mapping
address -> bytes that a fake read_process_memory serves reads from, the same
"duck-typed narrow interface, faked in tests" idiom test_eri_i01.py already
uses for Toolhelp32/OpenProcess. Win32Api.read_process_memory's own two
distinct failure paths (a hard Win32 failure, and a PARTIAL read) are tested
directly against a fake stand-in for the kernel32 DLL object
_kernel32_dll() returns -- the one thing a FakeWin32Api-based test cannot
reach, since FakeWin32Api replaces Win32Api itself, one layer above the real
ctypes call.

Run:  python -m pytest -q tests/test_eri_i02.py
(plain stdlib ctypes -- this suite does NOT need
D:\\Tools\\venv-research\\Scripts\\python.exe.)
"""

from __future__ import annotations

import ctypes
import json
import os
import struct
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import eri as tool  # noqa: E402

# Cross-import from the I-01 test module -- an established convention in
# this repo (see e.g. tests/test_sigscan.py importing from
# tests/test_pe_info.py): reuses FakeWin32Api (Toolhelp32/OpenProcess
# simulation), the process/module helpers, VALID_BUILD_KEY,
# _write_stub_exe/_patch_fake_win32api (for main()-level tests), and the
# offline jsonschema validator machinery, rather than re-deriving any of it.
import test_eri_i01 as i01_tests  # noqa: E402

VALID_BUILD_KEY = i01_tests.VALID_BUILD_KEY


# --------------------------------------------------------------------------- #
# fake memory model -- a dict of {start_address: bytes_blob}, served by a
# fake read_process_memory the same "duck-typed interface, faked in tests"
# way Toolhelp32/OpenProcess are faked in test_eri_i01.FakeWin32Api. Two
# variants: MemoryFakeApi (read_process_memory only, for testing run_i02/
# sample_walk_objects/evaluate_struct_invariants directly without any
# process/module simulation) and FakeWin32ApiWithMemory (adds memory to
# test_eri_i01.FakeWin32Api, for main()-level end-to-end tests).
# --------------------------------------------------------------------------- #

class _FakeMemoryMixin:
    """read_process_memory(handle, address, size), backed by:

    * ``fail_read_addresses`` -- addresses that always raise
      ReadProcessMemoryFailedError, simulating a hard Win32 failure or an
      unreadable/unmapped page;
    * ``sequenced_reads`` -- {address: [bytes, bytes, ...]}, one queued
      response per read of that EXACT address, popped in order -- used to
      simulate two different values read from the SAME address at two
      different times (check 3's two NumElements reads);
    * ``memory`` -- {start_address: bytes_blob}, the static fallback: a read
      is served by whichever blob's [start, start+len) range fully covers
      [address, address+size).

    A read whose address is not covered by any of the three is a TEST SETUP
    bug, not a simulated Win32 failure, and raises AssertionError loudly
    rather than silently returning zero bytes.
    """

    def _init_memory(self, *, memory=None, fail_read_addresses=None,
                     sequenced_reads=None):
        self._memory = dict(memory or {})
        self._fail_read_addresses = set(fail_read_addresses or ())
        self._sequenced_reads = {
            addr: list(seq) for addr, seq in (sequenced_reads or {}).items()}

    def read_process_memory(self, handle, address, size):
        if address in self._fail_read_addresses:
            raise tool.ReadProcessMemoryFailedError(
                "simulated ReadProcessMemory failure at 0x%x" % address)
        queued = self._sequenced_reads.get(address)
        if queued:
            data = queued.pop(0)
            assert len(data) == size, (
                "test bug: sequenced read at 0x%x queued %d bytes but %d "
                "were requested" % (address, len(data), size))
            return data
        for start, blob in self._memory.items():
            if start <= address and address + size <= start + len(blob):
                offset = address - start
                return blob[offset:offset + size]
        raise AssertionError(
            "read_process_memory: no configured memory covers "
            "address=0x%x size=%d (test setup bug, not a simulated Win32 "
            "failure)" % (address, size))


class MemoryFakeApi(_FakeMemoryMixin):
    """Minimal fake exposing only read_process_memory -- enough to test
    run_i02/sample_walk_objects/evaluate_struct_invariants directly, with no
    Toolhelp32/OpenProcess simulation needed at all.
    """

    def __init__(self, *, memory=None, fail_read_addresses=None, sequenced_reads=None):
        self._init_memory(memory=memory, fail_read_addresses=fail_read_addresses,
                          sequenced_reads=sequenced_reads)


class FakeWin32ApiWithMemory(_FakeMemoryMixin, i01_tests.FakeWin32Api):
    """test_eri_i01.FakeWin32Api (Toolhelp32/OpenProcess) plus the fake
    memory model above -- for main()-level end-to-end tests that exercise
    --run-i02 through the full CLI, including I-01's own process/module
    discovery.
    """

    def __init__(self, *, memory=None, fail_read_addresses=None,
                sequenced_reads=None, **kwargs):
        i01_tests.FakeWin32Api.__init__(self, **kwargs)
        self._init_memory(memory=memory, fail_read_addresses=fail_read_addresses,
                          sequenced_reads=sequenced_reads)


# --------------------------------------------------------------------------- #
# a fake GUObjectArray memory image -- struct + one chunk pointer table +
# one chunk's worth of FUObjectItem entries + fake UObjects with a vtable
# pointer either inside or outside the fake module's image range. All
# addresses are made up but internally consistent, laid out well apart from
# each other so no blob's range can accidentally overlap another's.
# --------------------------------------------------------------------------- #

BASE_ADDRESS = 0x7FF600000000
IMAGE_SIZE_BYTES = 0x0A000000  # ~160 MiB, a plausible Shipping.exe size
GUOBJECTARRAY_RVA = tool.DEFAULT_GUOBJECTARRAY_RVA
GUOBJECTARRAY_VA = BASE_ADDRESS + GUOBJECTARRAY_RVA


def make_guobjectarray_memory(*, num_elements: int, max_elements: int,
                              object_kinds: list, base_address: int = BASE_ADDRESS,
                              image_size_bytes: int = IMAGE_SIZE_BYTES,
                              guobjectarray_va: int = GUOBJECTARRAY_VA):
    """Builds a fake memory image for ONE chunk (chunk_index 0 for every
    index in *object_kinds*, i.e. len(object_kinds) must stay well under
    NUM_ELEMENTS_PER_CHUNK=65536, true for every test below).

    *object_kinds*[i] is one of:
      'valid'   -- FUObjectItem[i].Object is a fake UObject whose own first
                   8 bytes (vtable pointer) fall INSIDE
                   [base_address, base_address+image_size_bytes).
      'invalid' -- same, but the vtable pointer falls OUTSIDE that range
                   (a plausible "wrong candidate" signal).
      'null'    -- FUObjectItem[i].Object is a null pointer (a freed or
                   never-allocated slot).

    Returns (memory: dict[int, bytes], addrs: dict) where addrs carries
    every address a test might need to target directly:
      'guobjectarray_va', 'objects_ptr' (== the chunk pointer table's own
      address, the value the struct's Objects field points to),
      'items_addr' (chunk 0's FUObjectItem array base),
      'object_addrs' (object_addrs[i] = index i's fake UObject's own
      address, or None for a 'null' slot -- reading THIS address is what
      check 2's vtable-plausibility read targets),
      'item_addr' (a callable: item_addr(i) = the address of
      FUObjectItem[i] itself, which is also FUObjectItem[i].Object's own
      address since FUOBJECTITEM_OFFSET_OBJECT == 0 -- reading THIS address
      is what check 2's LOCATION read, not its sample read, targets).
    """
    chunk_table_addr = guobjectarray_va + 0x20000
    items_addr = chunk_table_addr + 0x1000
    items_region_len = max(len(object_kinds), 1) * tool.SIZEOF_FUOBJECTITEM
    items_blob = bytearray(items_region_len)

    fake_obj_base = items_addr + items_region_len + 0x1000
    valid_vtable_addr = base_address + 0x2000
    invalid_vtable_addr = base_address + image_size_bytes + 0x50000

    memory: dict = {}
    object_addrs: list = []
    next_obj_off = 0
    for i, kind in enumerate(object_kinds):
        if kind == "null":
            struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, 0)
            object_addrs.append(None)
            continue
        if kind not in ("valid", "invalid"):
            raise AssertionError("test bug: unknown object_kinds entry %r" % kind)
        obj_addr = fake_obj_base + next_obj_off
        next_obj_off += 0x20
        vtable_addr = valid_vtable_addr if kind == "valid" else invalid_vtable_addr
        # 8-byte vtable pointer + 8 bytes of harmless padding, matching the
        # 8 bytes check 2 actually reads (FUObjectItem.Object's first field).
        memory[obj_addr] = struct.pack("<Q", vtable_addr) + b"\x00" * 8
        struct.pack_into("<Q", items_blob, i * tool.SIZEOF_FUOBJECTITEM, obj_addr)
        object_addrs.append(obj_addr)

    memory[items_addr] = bytes(items_blob)
    memory[chunk_table_addr] = struct.pack("<Q", items_addr)  # chunk[0] pointer only

    struct_blob = bytearray(0x2C)
    struct.pack_into("<Q", struct_blob, tool.GUOBJECTARRAY_OFFSET_OBJECTS, chunk_table_addr)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_MAX_ELEMENTS, max_elements)
    struct.pack_into("<i", struct_blob, tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS, num_elements)
    memory[guobjectarray_va] = bytes(struct_blob)

    addrs = {
        "guobjectarray_va": guobjectarray_va,
        "objects_ptr": chunk_table_addr,
        "items_addr": items_addr,
        "object_addrs": object_addrs,
        "item_addr": lambda i: items_addr + i * tool.SIZEOF_FUOBJECTITEM,
    }
    return memory, addrs


# --------------------------------------------------------------------------- #
# rva_to_live_va -- the shared static-candidate-to-live-VA arithmetic every
# future ERI capability (I-03 onward) reuses.
# --------------------------------------------------------------------------- #

def test_rva_to_live_va_basic_arithmetic():
    assert tool.rva_to_live_va(0x7FF6D8020000, 0x07A78ED0) == 0x7FF6D8020000 + 0x07A78ED0


def test_rva_to_live_va_zero_rva_returns_base_unchanged():
    assert tool.rva_to_live_va(0x7FF600000000, 0) == 0x7FF600000000


def test_default_guobjectarray_rva_matches_rf05_static_candidate():
    """research/evidence/RF-05/README.md: static candidate VA 0x147a78ed0,
    against the PE's declared ImageBase 0x140000000 -> RVA 0x07a78ed0.
    """
    static_candidate_va = 0x147A78ED0
    declared_image_base = 0x140000000
    assert tool.DEFAULT_GUOBJECTARRAY_RVA == static_candidate_va - declared_image_base
    assert tool.DEFAULT_GUOBJECTARRAY_RVA == 0x07A78ED0


def test_rva_to_live_va_reproduces_static_va_when_base_equals_declared_image_base():
    # Sanity check only -- the live process is NOT actually loaded at its
    # declared ImageBase (ASLR); see rva_to_live_va's own docstring. But if
    # it hypothetically were, the arithmetic must reproduce RF-05's own
    # static VA exactly.
    assert (tool.rva_to_live_va(0x140000000, tool.DEFAULT_GUOBJECTARRAY_RVA)
            == 0x147A78ED0)


# --------------------------------------------------------------------------- #
# check (1): evaluate_struct_invariants -- never raises, an implausible
# reading is a refutation, not a tool error.
# --------------------------------------------------------------------------- #

def test_evaluate_struct_invariants_plausible_pair_passes():
    result = tool.evaluate_struct_invariants(num_elements=1000, max_elements=5000)
    assert result["pass"] is True
    assert result["reason"] is None
    assert result["num_elements"] == 1000
    assert result["max_elements"] == 5000


def test_evaluate_struct_invariants_fails_when_not_positive():
    zero = tool.evaluate_struct_invariants(num_elements=0, max_elements=5000)
    assert zero["pass"] is False
    assert "not > 0" in zero["reason"]

    negative = tool.evaluate_struct_invariants(num_elements=-5, max_elements=5000)
    assert negative["pass"] is False
    assert "not > 0" in negative["reason"]


def test_evaluate_struct_invariants_fails_when_num_elements_exceeds_max():
    result = tool.evaluate_struct_invariants(num_elements=6000, max_elements=5000)
    assert result["pass"] is False
    assert "exceeds MaxElements" in result["reason"]


def test_evaluate_struct_invariants_fails_when_max_elements_absurdly_large():
    result = tool.evaluate_struct_invariants(
        num_elements=1000, max_elements=tool.MAX_PLAUSIBLE_MAX_ELEMENTS)
    assert result["pass"] is False
    assert "plausibility ceiling" in result["reason"]


def test_evaluate_struct_invariants_combines_multiple_reasons():
    result = tool.evaluate_struct_invariants(
        num_elements=-1, max_elements=tool.MAX_PLAUSIBLE_MAX_ELEMENTS + 1)
    assert result["pass"] is False
    # both "not > 0" and "plausibility ceiling" reasons present, joined.
    assert "not > 0" in result["reason"]
    assert "plausibility ceiling" in result["reason"]


# --------------------------------------------------------------------------- #
# check (2): sample_walk_objects
# --------------------------------------------------------------------------- #

def test_sample_walk_objects_all_valid_passes_with_full_fraction():
    object_kinds = ["valid"] * 10
    memory, addrs = make_guobjectarray_memory(
        num_elements=10, max_elements=100, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=10,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=10, max_scan_indices=1000)
    assert result["sample_size_examined"] == 10
    assert result["pass_count"] == 10
    assert result["fail_count"] == 0
    assert result["pass_fraction"] == 1.0
    assert result["pass"] is True
    assert result["reason"] is None


def test_sample_walk_objects_at_exact_threshold_passes():
    # 4 valid, 1 invalid -> 0.8 pass fraction, exactly at the 0.80 threshold.
    object_kinds = ["valid", "valid", "valid", "valid", "invalid"]
    memory, addrs = make_guobjectarray_memory(
        num_elements=5, max_elements=100, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=5,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=10, max_scan_indices=1000)
    assert result["pass_count"] == 4
    assert result["fail_count"] == 1
    assert result["pass_fraction"] == pytest.approx(0.8)
    assert result["pass"] is True  # >= threshold, not merely > threshold


def test_sample_walk_objects_below_threshold_is_refuted_not_raised():
    # 1 valid, 4 invalid -> 0.2 pass fraction, well below 0.80.
    object_kinds = ["valid", "invalid", "invalid", "invalid", "invalid"]
    memory, addrs = make_guobjectarray_memory(
        num_elements=5, max_elements=100, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=5,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=10, max_scan_indices=1000)
    assert result["pass"] is False
    assert result["reason"] is not None
    assert "threshold" in result["reason"]


def test_sample_walk_objects_all_null_examines_nothing_and_is_refuted():
    object_kinds = ["null"] * 10
    memory, addrs = make_guobjectarray_memory(
        num_elements=10, max_elements=100, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=10,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=5, max_scan_indices=100)
    assert result["sample_size_examined"] == 0
    assert result["pass"] is False
    assert "no non-null" in result["reason"]
    assert result["indices_scanned"] == 10  # scanned all 10 (num_elements), stopped there


def test_sample_walk_objects_skips_unreadable_slot_during_location_not_counted():
    """A read failure while merely LOCATING a candidate object (the
    FUObjectItem.Object field read) is skipped like a null slot -- it must
    not crash the walk, and must not count against the sample.
    """
    object_kinds = ["valid", "valid", "valid"]
    memory, addrs = make_guobjectarray_memory(
        num_elements=3, max_elements=100, object_kinds=object_kinds)
    unreadable_item_addr = addrs["item_addr"](1)  # index 1 is unreadable
    api = MemoryFakeApi(memory=memory, fail_read_addresses={unreadable_item_addr})
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=3,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=10, max_scan_indices=100)
    assert result["sample_size_examined"] == 2  # indices 0 and 2 only
    assert result["pass_count"] == 2
    assert result["fail_count"] == 0
    assert result["indices_scanned"] == 3
    assert result["pass"] is True


def test_sample_walk_objects_torn_vtable_read_counts_as_failed_sample():
    """A read failure on the VTABLE POINTER of an object already committed
    to the sample (its Object field WAS readable and non-null) counts as a
    FAILED sample -- the "torn read during concurrent GC" scenario
    RF-05/README.md's own method anticipates -- never silently skipped.
    """
    object_kinds = ["valid", "valid", "valid"]
    memory, addrs = make_guobjectarray_memory(
        num_elements=3, max_elements=100, object_kinds=object_kinds)
    torn_object_addr = addrs["object_addrs"][1]
    api = MemoryFakeApi(memory=memory, fail_read_addresses={torn_object_addr})
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=3,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=10, max_scan_indices=100)
    assert result["sample_size_examined"] == 3  # all three were located and sampled
    assert result["pass_count"] == 2
    assert result["fail_count"] == 1
    assert result["pass_fraction"] == pytest.approx(2 / 3)
    assert result["pass"] is False  # 0.667 < 0.80 threshold


def test_sample_walk_objects_stops_at_sample_size_with_huge_num_elements():
    """The bound is on SAMPLE_SIZE (non-null objects examined), not on
    NumElements: a huge (even implausible) NumElements must never turn this
    into a scan of millions of slots when the first few are populated.
    """
    object_kinds = ["valid"] * 5  # exactly enough to satisfy sample_size=5
    memory, addrs = make_guobjectarray_memory(
        num_elements=5_000_000, max_elements=10_000_000, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=5_000_000,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=5, max_scan_indices=200_000)
    assert result["sample_size_examined"] == 5
    assert result["indices_scanned"] == 5  # never touched the huge NumElements
    assert result["pass"] is True


def test_sample_walk_objects_capped_by_max_scan_indices_when_sparse():
    """A huge NumElements with a sparse/empty population must be capped by
    max_scan_indices, not by NumElements itself -- otherwise a corrupted
    NumElements turns this into an effectively unbounded scan.
    """
    object_kinds = ["null"] * 50  # only 50 addressable slots configured
    memory, addrs = make_guobjectarray_memory(
        num_elements=5_000_000, max_elements=10_000_000, object_kinds=object_kinds)
    api = MemoryFakeApi(memory=memory)
    result = tool.sample_walk_objects(
        api, handle=1, objects_ptr=addrs["objects_ptr"], num_elements=5_000_000,
        base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        sample_size=32, max_scan_indices=50)
    assert result["indices_scanned"] == 50
    assert result["sample_size_examined"] == 0
    assert result["pass"] is False


# --------------------------------------------------------------------------- #
# run_i02: the whole capability, three checks combined into one collapsed
# 'structurally_consistent' verdict WITHOUT losing the per-check booleans.
# --------------------------------------------------------------------------- #

def test_run_i02_all_checks_pass():
    memory, _ = make_guobjectarray_memory(
        num_elements=100, max_elements=1000, object_kinds=["valid"] * 10)
    api = MemoryFakeApi(memory=memory)
    sleep_calls = []
    result = tool.run_i02(
        api, process_handle=1, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        guobjectarray_rva=GUOBJECTARRAY_RVA, sample_size=5, poll_interval_seconds=0.01,
        max_scan_indices=1000, sleep_fn=sleep_calls.append)
    assert result["structurally_consistent"] is True
    assert result["check_struct_invariants"]["pass"] is True
    assert result["check_sample_walk"]["pass"] is True
    assert result["check_growth_non_decreasing"]["pass"] is True
    assert result["guobjectarray_rva"] == GUOBJECTARRAY_RVA
    assert result["guobjectarray_live_va"] == GUOBJECTARRAY_VA
    assert result["guobjectarray_live_va_hex"] == "0x%x" % GUOBJECTARRAY_VA
    assert sleep_calls == [0.01]  # slept exactly once, with the poll interval


def test_run_i02_check1_fails_independently_of_the_other_two():
    memory, _ = make_guobjectarray_memory(
        num_elements=0, max_elements=1000, object_kinds=["valid"] * 5)
    api = MemoryFakeApi(memory=memory)
    result = tool.run_i02(
        api, process_handle=1, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        guobjectarray_rva=GUOBJECTARRAY_RVA, sample_size=5, poll_interval_seconds=0,
        max_scan_indices=1000, sleep_fn=lambda seconds: None)
    assert result["check_struct_invariants"]["pass"] is False
    assert result["check_sample_walk"]["pass"] is True
    assert result["check_growth_non_decreasing"]["pass"] is True
    # the collapsed verdict is false even though two of three checks passed --
    # never averaged, ALL three must pass.
    assert result["structurally_consistent"] is False


def test_run_i02_check3_fails_on_decreasing_num_elements():
    memory, _ = make_guobjectarray_memory(
        num_elements=100, max_elements=1000, object_kinds=["valid"] * 5)
    num_elements_addr = GUOBJECTARRAY_VA + tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS
    api = MemoryFakeApi(
        memory=memory,
        sequenced_reads={num_elements_addr: [struct.pack("<i", 100), struct.pack("<i", 50)]})
    result = tool.run_i02(
        api, process_handle=1, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        guobjectarray_rva=GUOBJECTARRAY_RVA, sample_size=5, poll_interval_seconds=0,
        max_scan_indices=1000, sleep_fn=lambda seconds: None)
    growth = result["check_growth_non_decreasing"]
    assert growth["num_elements_first"] == 100
    assert growth["num_elements_second"] == 50
    assert growth["non_decreasing"] is False
    assert growth["pass"] is False
    assert result["structurally_consistent"] is False
    # check 1 used the FIRST reading (100), which is plausible on its own.
    assert result["check_struct_invariants"]["pass"] is True


def test_run_i02_equal_num_elements_between_polls_passes_non_decreasing():
    """RF-05/README.md's own pass criterion is NON-DECREASING, not
    'increased' -- a static menu legitimately does not grow NumElements in a
    short poll window, and that must not be misreported as a refutation.
    """
    memory, _ = make_guobjectarray_memory(
        num_elements=42, max_elements=1000, object_kinds=["valid"] * 5)
    api = MemoryFakeApi(memory=memory)  # both reads see the same static 42
    result = tool.run_i02(
        api, process_handle=1, base_address=BASE_ADDRESS, image_size_bytes=IMAGE_SIZE_BYTES,
        guobjectarray_rva=GUOBJECTARRAY_RVA, sample_size=5, poll_interval_seconds=0,
        max_scan_indices=1000, sleep_fn=lambda seconds: None)
    growth = result["check_growth_non_decreasing"]
    assert growth["num_elements_first"] == growth["num_elements_second"] == 42
    assert growth["non_decreasing"] is True
    assert growth["pass"] is True


def test_run_i02_hard_read_failure_on_num_elements_propagates():
    """A foundational read this function cannot proceed without at all
    failing hard is a TOOL malfunction, not a structural finding -- it must
    propagate as ReadProcessMemoryFailedError, never be swallowed into a
    refutation result.
    """
    memory, _ = make_guobjectarray_memory(
        num_elements=10, max_elements=100, object_kinds=["valid"] * 3)
    num_elements_addr = GUOBJECTARRAY_VA + tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS
    api = MemoryFakeApi(memory=memory, fail_read_addresses={num_elements_addr})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.run_i02(
            api, process_handle=1, base_address=BASE_ADDRESS,
            image_size_bytes=IMAGE_SIZE_BYTES, guobjectarray_rva=GUOBJECTARRAY_RVA,
            sample_size=5, poll_interval_seconds=0, max_scan_indices=1000,
            sleep_fn=lambda seconds: None)


def test_run_i02_hard_read_failure_on_objects_pointer_propagates():
    memory, _ = make_guobjectarray_memory(
        num_elements=10, max_elements=100, object_kinds=["valid"] * 3)
    objects_field_addr = GUOBJECTARRAY_VA + tool.GUOBJECTARRAY_OFFSET_OBJECTS
    api = MemoryFakeApi(memory=memory, fail_read_addresses={objects_field_addr})
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.run_i02(
            api, process_handle=1, base_address=BASE_ADDRESS,
            image_size_bytes=IMAGE_SIZE_BYTES, guobjectarray_rva=GUOBJECTARRAY_RVA,
            sample_size=5, poll_interval_seconds=0, max_scan_indices=1000,
            sleep_fn=lambda seconds: None)


# --------------------------------------------------------------------------- #
# Win32Api.read_process_memory -- the ONE ReadProcessMemory call site,
# tested directly against a fake stand-in for the kernel32 DLL object
# _kernel32_dll() returns, covering both distinct failure modes: a hard
# Win32 failure (BOOL false) and a PARTIAL read (BOOL true, but fewer bytes
# actually read than requested).
# --------------------------------------------------------------------------- #

class _FakeReadProcessMemoryDll:
    """Stands in for what _kernel32_dll() returns, exposing only
    ReadProcessMemory with a Python-native (non-ctypes-marshalled) surface
    -- since monkeypatching eri._kernel32_dll bypasses ctypes' own foreign-
    function calling convention entirely, this receives the exact Python
    objects Win32Api.read_process_memory constructs and passes through.
    """

    def __init__(self, *, ok: bool, bytes_actually_read: int | None, data: bytes = b""):
        self.ok = ok
        self.bytes_actually_read = bytes_actually_read
        self.data = data
        self.calls: list = []

    def ReadProcessMemory(self, handle, address_cvoid, buffer, size_csize, bytes_read_byref):
        self.calls.append((handle, address_cvoid.value, size_csize.value))
        if self.ok:
            ctypes.memmove(buffer, self.data, len(self.data))
        actually_read = (
            size_csize.value if self.bytes_actually_read is None
            else self.bytes_actually_read)
        bytes_read_byref._obj.value = actually_read
        return 1 if self.ok else 0


def test_win32api_read_process_memory_success_returns_exact_bytes(monkeypatch):
    data = b"ABCDEFGH"
    fake_dll = _FakeReadProcessMemoryDll(ok=True, bytes_actually_read=None, data=data)
    monkeypatch.setattr(tool, "_kernel32_dll", lambda: fake_dll)
    result = tool.Win32Api().read_process_memory(1234, 0x1000, len(data))
    assert result == data
    assert fake_dll.calls == [(1234, 0x1000, len(data))]


def test_win32api_read_process_memory_hard_failure_raises(monkeypatch):
    fake_dll = _FakeReadProcessMemoryDll(ok=False, bytes_actually_read=0)
    monkeypatch.setattr(tool, "_kernel32_dll", lambda: fake_dll)
    with pytest.raises(tool.ReadProcessMemoryFailedError):
        tool.Win32Api().read_process_memory(1234, 0x2000, 8)


def test_win32api_read_process_memory_partial_read_raises_distinctly(monkeypatch):
    """A partial read (BOOL true, but too few bytes) is a DISTINCT failure
    mode from a hard failure, and must never be silently treated as if the
    full read had succeeded.
    """
    fake_dll = _FakeReadProcessMemoryDll(ok=True, bytes_actually_read=4, data=b"ABCD")
    monkeypatch.setattr(tool, "_kernel32_dll", lambda: fake_dll)
    with pytest.raises(tool.ReadProcessMemoryFailedError, match="PARTIAL"):
        tool.Win32Api().read_process_memory(1234, 0x3000, 8)


def test_source_has_exactly_one_readprocessmemory_call_site():
    """Mirrors test_eri_i01.py's equivalent OpenProcess test: exactly one
    CALL (open paren right after '.ReadProcessMemory') anywhere in the file
    -- the prototype registration ('dll.ReadProcessMemory.argtypes = ...')
    is a separate, expected mention that does not have an open paren there.
    """
    source = open(tool.__file__, encoding="utf-8").read()
    assert source.count(".ReadProcessMemory(") == 1, (
        "eri.py must call ReadProcessMemory from exactly one place -- "
        "Win32Api.read_process_memory -- so a reviewer can audit it by "
        "reading one line")


# --------------------------------------------------------------------------- #
# build_i02_document
# --------------------------------------------------------------------------- #

def test_build_i02_document_shape_and_values():
    result = {
        "guobjectarray_rva": 0x1000,
        "guobjectarray_rva_hex": "0x1000",
        "guobjectarray_live_va": 0x7FF600001000,
        "guobjectarray_live_va_hex": "0x7ff600001000",
        "check_struct_invariants": {
            "num_elements": 10, "max_elements": 100, "pass": True, "reason": None},
        "check_sample_walk": {
            "sample_size_requested": 5, "sample_size_examined": 5, "pass_count": 5,
            "fail_count": 0, "pass_fraction": 1.0, "pass_fraction_threshold": 0.8,
            "indices_scanned": 5, "max_scan_indices": 1000, "pass": True, "reason": None},
        "check_growth_non_decreasing": {
            "num_elements_first": 10, "num_elements_second": 10,
            "poll_interval_seconds": 0.01, "non_decreasing": True, "pass": True},
        "structurally_consistent": True,
    }
    doc = tool.build_i02_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["capability"] == "I-02"
    assert doc["guobjectarray_rva_hex"] == "0x1000"
    assert doc["guobjectarray_rva_decimal"] == 0x1000
    assert doc["guobjectarray_live_va_hex"] == "0x7ff600001000"
    assert doc["structurally_consistent"] is True
    assert doc["check_struct_invariants"]["pass"] is True
    assert doc["check_sample_walk"]["pass"] is True
    assert doc["check_growth_non_decreasing"]["pass"] is True
    assert doc["identity_self_established"] is True
    assert doc["build_key_cross_checked"] is False
    assert doc["known_build"] is False
    assert doc["build_id"] is None
    assert doc["build_key"] == VALID_BUILD_KEY
    assert doc["recorded_at"] == "2026-08-27T12:00:00Z"
    assert doc["generator"] == tool.GENERATOR_NAME
    assert doc["generator_version"] == tool.GENERATOR_VERSION
    # same is_record() reason as build_i01_document -- see that function's
    # own docstring, and build_i02_document's.
    assert "evidence_level" not in doc
    assert "oracle" not in doc
    json.loads(tool.dump_json(doc))


def test_build_i02_document_can_report_a_refuted_candidate():
    result = {
        "guobjectarray_rva": 0x1000, "guobjectarray_rva_hex": "0x1000",
        "guobjectarray_live_va": 0x7FF600001000, "guobjectarray_live_va_hex": "0x7ff600001000",
        "check_struct_invariants": {
            "num_elements": 0, "max_elements": 100, "pass": False,
            "reason": "NumElements (0) is not > 0"},
        "check_sample_walk": {
            "sample_size_requested": 5, "sample_size_examined": 0, "pass_count": 0,
            "fail_count": 0, "pass_fraction": 0.0, "pass_fraction_threshold": 0.8,
            "indices_scanned": 5, "max_scan_indices": 1000, "pass": False,
            "reason": "no non-null FUObjectItem.Object pointer was found"},
        "check_growth_non_decreasing": {
            "num_elements_first": 0, "num_elements_second": 0,
            "poll_interval_seconds": 2.0, "non_decreasing": True, "pass": True},
        "structurally_consistent": False,
    }
    doc = tool.build_i02_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at=None,
        identity_self_established=True, build_key_cross_checked=False,
        known_build=False, build_id=None)
    assert doc["structurally_consistent"] is False
    assert doc["check_struct_invariants"]["pass"] is False
    json.loads(tool.dump_json(doc))


# --------------------------------------------------------------------------- #
# build_manifest with capabilities_enabled=['I-01', 'I-02']
# --------------------------------------------------------------------------- #

def test_build_manifest_defaults_to_i01_only_when_capabilities_enabled_omitted():
    """Backward compatibility: every caller written before I-02 existed
    (including build_i01_document's own tests) must keep working unchanged.
    """
    manifest = tool.build_manifest(
        run_id="r", arguments=[], tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=None, **i01_tests.IDENTITY_KWARGS)
    assert manifest["capabilities_enabled"] == ["I-01"]


def test_build_manifest_with_i02_capability_validates_against_schema():
    validator = i01_tests._manifest_validator()
    manifest = tool.build_manifest(
        run_id="r", arguments=["--run-i02"], tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=["research/instrument-runs/r/i01-process-info.json",
                   "research/instrument-runs/r/i02-guobjectarray.json"],
        capabilities_enabled=["I-01", "I-02"],
        **i01_tests.IDENTITY_KWARGS)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02"]
    errors = list(validator.iter_errors(manifest))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_cli_run_i02_defaults():
    args = tool.build_arg_parser().parse_args([])
    assert args.run_i02 is False
    assert args.guobjectarray_rva is None
    assert args.i02_sample_size == tool.DEFAULT_I02_SAMPLE_SIZE
    assert args.i02_poll_interval_seconds == tool.DEFAULT_I02_POLL_INTERVAL_SECONDS
    assert args.i02_max_scan_indices == tool.DEFAULT_I02_MAX_SCAN_INDICES
    assert args.i02_out is None


def test_parse_guobjectarray_rva_default_when_none():
    assert tool._parse_guobjectarray_rva(None) == tool.DEFAULT_GUOBJECTARRAY_RVA


def test_parse_guobjectarray_rva_accepts_hex_string():
    assert tool._parse_guobjectarray_rva("0x1000") == 0x1000


def test_parse_guobjectarray_rva_accepts_decimal_string():
    assert tool._parse_guobjectarray_rva("4096") == 4096


def test_parse_guobjectarray_rva_rejects_garbage():
    with pytest.raises(ValueError):
        tool._parse_guobjectarray_rva("not-a-number")


def test_resolve_i02_output_path_none_when_not_requested():
    args = tool.build_arg_parser().parse_args([])
    assert tool._resolve_i02_output_path(args) is None


def test_resolve_i02_output_path_none_even_if_i02_out_given_without_run_i02():
    args = tool.build_arg_parser().parse_args(["--i02-out", "x.json"])
    assert tool._resolve_i02_output_path(args) is None


def test_resolve_i02_output_path_requires_i02_out_or_run_dir():
    args = tool.build_arg_parser().parse_args(["--run-i02"])
    with pytest.raises(ValueError):
        tool._resolve_i02_output_path(args)


def test_resolve_i02_output_path_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(["--run-i02", "--run-dir", run_dir])
    assert tool._resolve_i02_output_path(args) == os.path.join(run_dir, "i02-guobjectarray.json")


def test_resolve_i02_output_path_explicit_out_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit = str(tmp_path / "custom-i02.json")
    args = tool.build_arg_parser().parse_args(
        ["--run-i02", "--run-dir", run_dir, "--i02-out", explicit])
    assert tool._resolve_i02_output_path(args) == explicit


# --------------------------------------------------------------------------- #
# main() end-to-end with --run-i02, FakeWin32ApiWithMemory substituted for
# the real Win32Api (same monkeypatch pattern test_eri_i01.py's own main()
# tests use) -- still no live game process anywhere.
# --------------------------------------------------------------------------- #

def _fake_i02_api(tmp_path, memory, **fake_kwargs) -> tuple:
    exe_bytes = b"the live process's actual module bytes for an I-02 test"
    exe_path = i01_tests._write_stub_exe(tmp_path, "MISERY-Win64-Shipping.exe", exe_bytes)
    api = FakeWin32ApiWithMemory(
        processes=[i01_tests.proc(4242, i01_tests.TARGET_NAME)],
        modules_by_pid={4242: [i01_tests.mod(
            i01_tests.TARGET_NAME, exe_path, BASE_ADDRESS, IMAGE_SIZE_BYTES)]},
        memory=memory,
        **fake_kwargs)
    return api, exe_path


def test_main_run_i02_writes_document_and_capability(tmp_path, monkeypatch):
    memory, _ = make_guobjectarray_memory(
        num_elements=50, max_elements=500, object_kinds=["valid"] * 10)
    api, _ = _fake_i02_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02",
        "--i02-sample-size", "5", "--i02-poll-interval-seconds", "0",
        "--i02-max-scan-indices", "1000",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "i02-guobjectarray.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["capability"] == "I-02"
    assert doc["structurally_consistent"] is True

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01", "I-02"]
    assert any(a.endswith("i02-guobjectarray.json") for a in manifest["artifacts"])
    assert any(a.endswith("i01-process-info.json") for a in manifest["artifacts"])


def test_main_run_i02_refuted_candidate_still_succeeds(tmp_path, monkeypatch):
    """A structurally refuted candidate is a valid, reported research
    outcome -- rc must still be 0, and the document must plainly say
    structurally_consistent: false, never raise or degrade the run.
    """
    memory, _ = make_guobjectarray_memory(
        num_elements=0, max_elements=500, object_kinds=["invalid"] * 5)
    api, _ = _fake_i02_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main([
        "--run-dir", run_dir, "--run-i02",
        "--i02-sample-size", "5", "--i02-poll-interval-seconds", "0",
        "--i02-max-scan-indices", "1000",
    ])
    assert rc == 0

    with open(os.path.join(run_dir, "i02-guobjectarray.json"), encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["structurally_consistent"] is False
    assert doc["check_struct_invariants"]["pass"] is False


def test_main_run_i02_hard_read_failure_writes_nothing_at_all(tmp_path, monkeypatch):
    """A genuine tool malfunction during I-02 (ReadProcessMemoryFailedError
    on a foundational read) must abort the WHOLE run before anything is
    written -- not an I-01 document with no manifest to explain it.
    """
    memory, _ = make_guobjectarray_memory(
        num_elements=10, max_elements=100, object_kinds=["valid"] * 3)
    num_elements_addr = GUOBJECTARRAY_VA + tool.GUOBJECTARRAY_OFFSET_NUM_ELEMENTS
    api, _ = _fake_i02_api(tmp_path, memory, fail_read_addresses={num_elements_addr})
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir, "--run-i02", "--i02-poll-interval-seconds", "0"])
    assert rc == 2
    assert not os.path.exists(run_dir)


def test_main_without_run_i02_never_touches_i02_at_all(tmp_path, monkeypatch):
    """Plain I-01-only invocation: no --run-i02, so I-02 must not run, and
    the manifest must list only I-01 -- the pre-I-02 behaviour, unchanged.
    """
    memory, _ = make_guobjectarray_memory(
        num_elements=50, max_elements=500, object_kinds=["valid"] * 10)
    api, _ = _fake_i02_api(tmp_path, memory)
    i01_tests._patch_fake_win32api(monkeypatch, api)

    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--run-dir", run_dir])
    assert rc == 0
    assert not os.path.exists(os.path.join(run_dir, "i02-guobjectarray.json"))

    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["capabilities_enabled"] == ["I-01"]
