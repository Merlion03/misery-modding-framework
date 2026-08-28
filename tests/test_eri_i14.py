#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for ERI capability I-14 -- which .pak containers a live process has
mounted (research/RESEARCH_LOG.md, CT-03 / plan.md task CT-03).

Standard library only; every test drives a synthetic memory image through the
same `MemoryFakeApi` the I-02 tests already use, so nothing here touches a live
process or the game installation.

WHAT THESE TESTS ARE ACTUALLY GUARDING

I-14 differs from I-02..I-06 in one important way: it cannot lean on the
UObject graph. `FPakPlatformFile` is not a UObject, so the anchor is a raw
global plus a pointer chase, and a wrong offset anywhere along it yields
plausible-looking garbage rather than an obvious failure. The tests therefore
concentrate on the places where being wrong is silent:

  * identity is by VTABLE, never by position in the chain -- a node that is
    not an FPakPlatformFile must be walked past, not adopted;
  * `FPakFile` has TWO vtable pointers, because an `IPakFile` subobject sits
    at +0x10, and the accessors are compiled against that secondary base --
    forgetting it shifts PakFilename from 0x18 to 0x08 and MountPoint from
    0xC8 to 0xB8, both of which still decode to *something*;
  * `GetLowerLevel()` is decoded from its own five bytes rather than assumed,
    so an inserted wrapper does not break the walk;
  * an FString whose Num/Max are nonsense, whose buffer is not NUL-terminated,
    or which contains control characters is rejected instead of being reported
    as a container name.

The concrete ground truth these were written against is the live run recorded
in `research/instrument-runs/2026-08-28T0915Z-ct03-snapshotA/`: exactly one
mounted container, `../../../MISERY/Content/Paks/MISERY-Windows.pak`, mount
point `../../../`, read order 4 -- every field of which was independently
confirmed against that container's own bytes on disk.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import eri as tool  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_eri_i02 import MemoryFakeApi  # noqa: E402


BASE = 0x140000000
IMAGE_SIZE = 0x8000000
MANAGER_RVA = tool.DEFAULT_PLATFORM_FILE_MANAGER_RVA
PAK_VT_RVA = tool.DEFAULT_PAKPLATFORMFILE_VTABLE_RVA
PF_VT1_RVA = tool.DEFAULT_PAKFILE_VTABLE_PRIMARY_RVA
PF_VT2_RVA = tool.DEFAULT_PAKFILE_VTABLE_IPAKFILE_RVA

PAK_PF = 0x20000000000       # the FPakPlatformFile instance
PAK_ARRAY = 0x20000001000    # PakFiles.Data
PAK_FILE = 0x20000002000     # one FPakFile
STR_NAME = 0x20000003000     # PakFilename buffer
STR_MOUNT = 0x20000004000    # MountPoint buffer
OTHER_PF = 0x20000005000     # a non-pak wrapper sitting above it
OTHER_VT = BASE + 0x01000000


def _fstring(address: int, text: str) -> tuple:
    """(16-byte FString header, buffer bytes). ArrayNum includes the NUL."""
    raw = text.encode("utf-16-le") + b"\x00\x00"
    num = len(raw) // 2
    return struct.pack("<QII", address if text else 0, num if text else 0, num), raw


def _pak_file_blob(name: str, mount: str, *, vt1=None, vt2=None,
                   magic=tool.PAK_FILE_MAGIC, version=11, num_refs=1,
                   num_entries=4424, total_size=117658732) -> bytes:
    buf = bytearray(b"\x00" * 0x268)
    struct.pack_into("<Q", buf, 0x00, BASE + (PF_VT1_RVA if vt1 is None else vt1))
    struct.pack_into("<I", buf, tool.FPAKFILE_NUMREFS_OFFSET, num_refs)
    struct.pack_into("<Q", buf, tool.FPAKFILE_IPAKFILE_VPTR_OFFSET,
                     BASE + (PF_VT2_RVA if vt2 is None else vt2))
    name_hdr, _ = _fstring(STR_NAME, name)
    buf[tool.FPAKFILE_PAKFILENAME_OFFSET:tool.FPAKFILE_PAKFILENAME_OFFSET + 16] = name_hdr
    mount_hdr, _ = _fstring(STR_MOUNT, mount)
    buf[tool.FPAKFILE_MOUNTPOINT_OFFSET:tool.FPAKFILE_MOUNTPOINT_OFFSET + 16] = mount_hdr
    info = tool.FPAKFILE_INFO_OFFSET
    struct.pack_into("<I", buf, info + tool.FPAKINFO_MAGIC_OFFSET, magic)
    struct.pack_into("<I", buf, info + tool.FPAKINFO_VERSION_OFFSET, version)
    struct.pack_into("<q", buf, info + tool.FPAKINFO_INDEXOFFSET_OFFSET, 117367653)
    struct.pack_into("<q", buf, info + tool.FPAKINFO_INDEXSIZE_OFFSET, 53202)
    struct.pack_into("<I", buf, tool.FPAKFILE_NUMENTRIES_OFFSET, num_entries)
    struct.pack_into("<q", buf, tool.FPAKFILE_CACHEDTOTALSIZE_OFFSET, total_size)
    struct.pack_into("<i", buf, tool.FPAKFILE_PAKCHUNKINDEX_OFFSET, -1)
    buf[tool.FPAKFILE_ISVALID_OFFSET] = 1
    buf[tool.FPAKFILE_ISMOUNTED_OFFSET] = 1
    return bytes(buf)


def _world(*, name="../../../MISERY/Content/Paks/MISERY-Windows.pak",
           mount="../../../", read_order=4, array_num=1, array_max=4,
           topmost=PAK_PF, extra=None, **pak_kwargs) -> dict:
    """A synthetic memory image containing one FPakPlatformFile holding one
    FPakFile, reachable from the manager global."""
    pak_pf = bytearray(b"\x00" * 0x100)
    struct.pack_into("<Q", pak_pf, 0x00, BASE + PAK_VT_RVA)
    struct.pack_into("<Q", pak_pf, tool.FPAKPLATFORMFILE_LOWERLEVEL_OFFSET, OTHER_PF)
    struct.pack_into("<Q", pak_pf, tool.FPAKPLATFORMFILE_PAKFILES_OFFSET, PAK_ARRAY)
    struct.pack_into("<I", pak_pf, tool.FPAKPLATFORMFILE_PAKFILES_OFFSET + 8, array_num)
    struct.pack_into("<I", pak_pf, tool.FPAKPLATFORMFILE_PAKFILES_OFFSET + 12, array_max)

    entry = struct.pack("<IIQ", read_order, 0, PAK_FILE)
    _, name_buf = _fstring(STR_NAME, name)
    _, mount_buf = _fstring(STR_MOUNT, mount)

    memory = {
        BASE + MANAGER_RVA: struct.pack("<Q", topmost),
        PAK_PF: bytes(pak_pf),
        PAK_ARRAY: entry,
        PAK_FILE: _pak_file_blob(name, mount, **pak_kwargs),
        STR_NAME: name_buf,
        STR_MOUNT: mount_buf,
    }
    if extra:
        memory.update(extra)
    return memory


def _run(memory):
    api = MemoryFakeApi(memory=memory)
    return tool.run_i14(api, 0x1234, BASE, IMAGE_SIZE)


# --------------------------------------------------------------------------- #
# the happy path -- must reproduce the shape of the real live observation
# --------------------------------------------------------------------------- #

def test_reports_the_single_mounted_container():
    result = _run(_world())
    assert result["pak_platform_file_found"] is True
    assert result["mounted_pak_count"] == 1
    entry = result["mounted_paks"][0]
    assert entry["pak_filename"] == "../../../MISERY/Content/Paks/MISERY-Windows.pak"
    assert entry["mount_point"] == "../../../"
    assert entry["read_order"] == 4
    assert entry["pak_version"] == 11
    assert entry["num_entries"] == 4424
    assert entry["cached_total_size"] == 117658732
    assert entry["is_mounted"] is True
    assert entry["pakchunk_index"] == -1
    assert "rejected" not in entry


def test_all_structural_checks_pass_on_a_well_formed_pak_file():
    entry = _run(_world())["mounted_paks"][0]
    assert entry["validation"] == {
        "vptr_primary": True, "vptr_ipakfile": True, "num_refs_sane": True,
        "pak_magic": True, "pak_version_sane": True}


def test_document_claim_names_the_container():
    result = _run(_world())
    doc = tool.build_i14_document(
        result=result, build_key="sha256:" + "a" * 64, recorded_at="2026-08-28T00:00:00Z",
        identity_self_established=True, build_key_cross_checked=False,
        known_build=True, build_id="misery-test")
    assert doc["capability"] == "I-14"
    assert "MISERY-Windows.pak" in doc["claim"]
    assert doc["oracle"] == ["runtime-reflection"]
    assert doc["claim_class"] == "I"


def test_document_confidence_stays_below_the_two_method_threshold():
    """This artifact rests on ONE act of measurement, so plan.md 10.3 v2.2
    caps it below 0.80 -- an interpretive claim at 0.80+ needs two independent
    methods, and the validator enforces it. A first draft graded this 0.85 and
    the live validator gate caught it. The corroborated claim, cross-checked
    against the container's own bytes on disk, is graded higher in
    RESEARCH_LOG.md, where that second method actually exists."""
    doc = tool.build_i14_document(
        result=_run(_world()), build_key="sha256:" + "a" * 64,
        recorded_at="2026-08-28T00:00:00Z", identity_self_established=True,
        build_key_cross_checked=False, known_build=True, build_id="misery-test")
    assert doc["confidence"] < 0.80
    assert len(doc["sources"]) == 1


# --------------------------------------------------------------------------- #
# identity is by vtable, not by position
# --------------------------------------------------------------------------- #

def test_walks_past_a_wrapper_that_is_not_the_pak_layer():
    """A wrapper above the pak layer must be walked THROUGH, using its own
    decoded GetLowerLevel, not mistaken for the pak layer."""
    wrapper_vtable = 0x20000006000
    getlower = 0x20000007000
    wrapper = bytearray(b"\x00" * 0x40)
    struct.pack_into("<Q", wrapper, 0x00, OTHER_VT)
    struct.pack_into("<Q", wrapper, 0x18, PAK_PF)          # LowerLevel at +0x18
    vtable = bytearray(b"\x00" * (67 * 8))
    struct.pack_into("<Q", vtable, tool.IPLATFORMFILE_GETLOWERLEVEL_SLOT * 8, getlower)
    memory = _world(topmost=OTHER_PF, extra={
        OTHER_PF: bytes(wrapper),
        OTHER_VT: bytes(vtable),
        getlower: bytes([0x48, 0x8B, 0x41, 0x18, 0xC3]),   # mov rax,[rcx+0x18]; ret
    })
    result = _run(memory)
    assert result["pak_platform_file_found"] is True
    assert len(result["chain"]) == 2
    assert result["chain"][0]["is_pak_platform_file"] is False
    assert result["chain"][1]["is_pak_platform_file"] is True
    assert result["mounted_pak_count"] == 1


def test_bottom_of_chain_without_pak_layer_is_reported_not_guessed():
    getlower = 0x20000007000
    node = bytearray(b"\x00" * 0x40)
    struct.pack_into("<Q", node, 0x00, OTHER_VT)
    vtable = bytearray(b"\x00" * (67 * 8))
    struct.pack_into("<Q", vtable, tool.IPLATFORMFILE_GETLOWERLEVEL_SLOT * 8, getlower)
    memory = _world(topmost=OTHER_PF, extra={
        OTHER_PF: bytes(node),
        OTHER_VT: bytes(vtable),
        getlower: bytes([0x33, 0xC0, 0xC3, 0x00, 0x00]),   # xor eax,eax; ret
    })
    result = _run(memory)
    assert result["pak_platform_file_found"] is False
    assert result["mounted_pak_count"] == 0
    assert "bottom of the platform-file chain" in result["note"]


def test_pak_file_with_wrong_secondary_vtable_is_rejected():
    """The IPakFile subobject vptr at +0x10 is the offset most easily missed;
    a candidate that only matches the primary vtable must not be accepted."""
    result = _run(_world(vt2=0x00999999))
    entry = result["mounted_paks"][0]
    assert entry["rejected"] == "failed structural validation"
    assert entry["validation"]["vptr_primary"] is True
    assert entry["validation"]["vptr_ipakfile"] is False
    assert result["mounted_pak_count"] == 0


def test_pak_file_with_wrong_magic_is_rejected():
    result = _run(_world(magic=0xDEADBEEF))
    assert result["mounted_paks"][0]["rejected"] == "failed structural validation"
    assert result["mounted_pak_count"] == 0


def test_pak_file_with_absurd_version_is_rejected():
    result = _run(_world(version=999))
    assert result["mounted_paks"][0]["validation"]["pak_version_sane"] is False
    assert result["mounted_pak_count"] == 0


# --------------------------------------------------------------------------- #
# refusing implausible arrays rather than walking them
# --------------------------------------------------------------------------- #

def test_refuses_an_array_whose_num_exceeds_max():
    result = _run(_world(array_num=9, array_max=4))
    assert result["mounted_pak_count"] == 0
    assert "implausible" in result["note"]


def test_refuses_an_absurdly_large_array():
    result = _run(_world(array_num=10 ** 7, array_max=10 ** 7))
    assert result["mounted_pak_count"] == 0
    assert "implausible" in result["note"]


def test_empty_but_valid_array_is_reported_as_zero_not_as_failure():
    result = _run(_world(array_num=0, array_max=0))
    assert result["pak_platform_file_found"] is True
    assert result["mounted_pak_count"] == 0
    assert result["note"] is None


# --------------------------------------------------------------------------- #
# FString decoding -- must refuse rather than invent a container name
# --------------------------------------------------------------------------- #

def test_fstring_round_trips_a_normal_path():
    _, buf = _fstring(STR_NAME, "../../../x.pak")
    api = MemoryFakeApi(memory={
        0x500: struct.pack("<QII", STR_NAME, len(buf) // 2, len(buf) // 2),
        STR_NAME: buf})
    out = tool.read_fstring(api, 0, 0x500)
    assert out["ok"] and out["text"] == "../../../x.pak"


def test_fstring_empty_is_valid_not_an_error():
    api = MemoryFakeApi(memory={0x500: struct.pack("<QII", 0, 0, 0)})
    out = tool.read_fstring(api, 0, 0x500)
    assert out["ok"] and out["text"] == ""


def test_fstring_rejects_missing_terminator():
    raw = "abc".encode("utf-16-le")            # no NUL
    api = MemoryFakeApi(memory={
        0x500: struct.pack("<QII", STR_NAME, 3, 3), STR_NAME: raw})
    out = tool.read_fstring(api, 0, 0x500)
    assert not out["ok"] and "NUL" in out["reason"]


def test_fstring_rejects_control_characters():
    raw = "a\x01b".encode("utf-16-le") + b"\x00\x00"
    api = MemoryFakeApi(memory={
        0x500: struct.pack("<QII", STR_NAME, 4, 4), STR_NAME: raw})
    out = tool.read_fstring(api, 0, 0x500)
    assert not out["ok"] and "control" in out["reason"]


def test_fstring_rejects_num_greater_than_max():
    api = MemoryFakeApi(memory={0x500: struct.pack("<QII", STR_NAME, 99, 4)})
    out = tool.read_fstring(api, 0, 0x500)
    assert not out["ok"] and "implausible Num/Max" in out["reason"]


# --------------------------------------------------------------------------- #
# GetLowerLevel decoding
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("code,kind,offset", [
    (bytes([0x48, 0x8B, 0x41, 0x08, 0xC3]), "offset", 0x08),
    (bytes([0x48, 0x8B, 0x41, 0x18, 0xC3]), "offset", 0x18),
    (bytes([0x33, 0xC0, 0xC3, 0x00, 0x00]), "null", None),
    (bytes([0x90, 0x90, 0x90, 0x90, 0x90]), "unknown", None),
])
def test_lower_level_accessor_decoding(code, kind, offset):
    api = MemoryFakeApi(memory={0x900: code})
    out = tool.decode_lower_level_accessor(api, 0, 0x900)
    assert out["kind"] == kind and out["offset"] == offset


def test_unreadable_manager_global_is_reported_not_crashed():
    api = MemoryFakeApi(memory={}, fail_read_addresses={BASE + MANAGER_RVA})
    result = tool.run_i14(api, 0x1234, BASE, IMAGE_SIZE)
    assert result["pak_platform_file_found"] is False
    assert "TopmostPlatformFile" in result["note"]


# --------------------------------------------------------------------------- #
# the read-only invariant still holds after adding this capability
# --------------------------------------------------------------------------- #

def test_i14_added_no_new_win32_call_sites():
    with open(os.path.join(REPO_ROOT, "research", "instruments", "eri", "eri.py"),
              encoding="utf-8") as handle:
        source = handle.read()
    assert source.count(".OpenProcess(") == 1
    assert source.count(".ReadProcessMemory(") == 1
    for forbidden in ("WriteProcessMemory(", "VirtualAllocEx(", "CreateRemoteThread(",
                      "VirtualProtectEx(", "SetWindowsHookEx"):
        assert ("_kernel32_dll()." + forbidden) not in source
