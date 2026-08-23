#!/usr/bin/env python3
"""Tests for tools/static/engine_version.py (plan.md section 4, V-01..V-07).

WHAT IS TESTED AND AGAINST WHAT
-------------------------------
Nothing here reads the game installation. Decision D-01 makes it a read-only
research target, and a suite that depends on it is neither reproducible on
another machine nor runnable where the game is absent. Every input is
SYNTHETIC and assembled byte by byte: the PE images come from the ``PEBuilder``
of ``tests/test_pe_info.py`` (imported, not copied, so there is one definition
of "a valid PE" in this suite), and the containers, the pak index, the
minidumps and the reference Unreal Engine tree are built here.

That matters for more than hygiene. A tool whose only evidence is one run over
a 134 MB binary cannot tell "this image contains the pair (522, 1012)" from
"this scanner reports (522, 1012) for anything". Here the inputs are built with
KNOWN contents, so the assertions are against ground truth rather than against
the tool's own previous output. In particular the two readings that carry the
answer are tested in the negative as well: a V-06 candidate whose neighbouring
bytes do not match the prediction must be REPORTED as a failed refutation and
not quietly used, and a data-format source that disagrees with the others must
pull the confidence below 0.90 by itself.

Coverage:
  * V-01: string extent (the STRING offset and length, not the marker's), the
    branch/changelist/minor line parsed out of the matched text, and the
    changelist found as a compiled immediate
  * V-03: the VS_FIXEDFILEINFO patch component, which is the only place it
    exists on the Shipping image, kept apart from the string literals
  * V-04: the exported D3D12SDKVersion read as four bytes at a stated offset
  * V-05: the TOC version byte at offset 16 of each .utoc, and the literal
    reads' read_locus
  * V-06: exactly-one-hit, the built-in refutation (the neighbour prediction),
    the plausible-band filter, and the refusal to interpret several hits
  * V-07: names only, from the pak index; no payload is touched
  * V-02: the RISK-09 correspondence test, both verdicts, and C-13 (no personal
    XML field and no absolute path in the artifact)
  * the plan.md 4.2 rule as a mechanism: agreement raises, disagreement lowers
  * the confidence ceiling, engine_is_vanilla staying UNKNOWN, determinism, the
    external reference table's own consistency, and the pathguard contract
"""

from __future__ import annotations

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

import container_info  # noqa: E402
import engine_version  # noqa: E402
import pathguard  # noqa: E402
from test_pe_info import (  # noqa: E402
    PEBuilder,
    build_debug_blob,
    build_export_blob,
    build_resource_blob,
    build_version_resource,
)

TOOL_PATH = os.path.join(REPO_ROOT, "tools", "static", "engine_version.py")

IMAGE_BASE = 0x140000000
RDATA_RVA = 0x2000
DATA_RVA = 0x20000
RSRC_RVA = 0x40000
DEBUG_RVA = 0x50000
EXPORT_RVA = 0x60000

RDATA_FLAGS = 0x40000040
DATA_FLAGS = 0xC0000040

DIR_EXPORT = 0
DIR_RESOURCE = 2
DIR_DEBUG = 6

PDB_GUID = bytes(range(16))
PDB_NAME = "SYNTHETIC-Win64-Shipping.pdb"

VERSION_STRINGS = {
    "CompanyName": "Epic Games, Inc.",
    "FileDescription": "SYNTHETIC",
    "FileVersion": "5.4.4.0",
    "InternalName": "SYNTHETIC",
    "OriginalFilename": "MISERY-Win64-Shipping.exe",
    "ProductVersion": "++UE5+Release-5.4-CL-35576357",
}

CHANGELIST = 35576357
BRANCH = "++UE5+Release-5.4"


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #

def _u16(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def build_rdata(*, branch: str = BRANCH, changelist: int = CHANGELIST,
                sdk_version: int = 611) -> tuple[bytes, dict]:
    """`.rdata`: the two marker strings, then the exported SDK constant.

    The offsets the tool must report are computed here and returned, so the
    assertions compare against arithmetic done in the test rather than against
    whatever the tool happened to print.
    """
    blob = bytearray()
    offsets: dict = {}
    blob += b"\x00" * 16                     # leading padding, so offset 0 is not it
    offsets["branch"] = len(blob)
    blob += _u16(branch)
    blob += b"\x00\x00"                      # separator
    offsets["branch_cl"] = len(blob)
    blob += _u16("%s-CL-%d" % (branch, changelist))
    while len(blob) % 8:
        blob.append(0)
    offsets["sdk"] = len(blob)
    blob += struct.pack("<I", sdk_version)
    blob += b"\x00" * 4
    return bytes(blob), offsets


def build_data(*, ue4: int = engine_version.VER_LATEST_ENGINE_UE4,
               ue5: int = 1012,
               neighbour: tuple[int, int] = (
                   engine_version.VER_UE4_OLDEST_LOADABLE_PACKAGE, 0),
               repeat: int = 1,
               noise_pair: tuple[int, int] | None = None) -> tuple[bytes, dict]:
    """`.data`: the FPackageFileVersion pair plus the neighbouring pair.

    ``repeat`` places the same shape more than once, which is the input that
    must make the tool refuse to interpret anything.
    """
    blob = bytearray(b"\x00" * 32)
    offsets: dict = {"pairs": []}
    for _ in range(repeat):
        offsets["pairs"].append(len(blob))
        blob += struct.pack("<II", ue4, ue5)
        blob += struct.pack("<II", *neighbour)
        blob += b"\x00" * 16
    if noise_pair is not None:
        offsets["noise"] = len(blob)
        blob += struct.pack("<II", *noise_pair)
        blob += b"\x00" * 8
    return bytes(blob), offsets


def build_shipping_exe(tmp_path, path: str, *, branch: str = BRANCH,
                       changelist: int = CHANGELIST, sdk_version: int = 611,
                       ue5_version: int = 1012,
                       neighbour: tuple[int, int] = (
                           engine_version.VER_UE4_OLDEST_LOADABLE_PACKAGE, 0),
                       repeat: int = 1,
                       version_strings: dict | None = None,
                       fixed_version: tuple[int, int, int, int] = (5, 4, 4, 0),
                       with_exports: bool = True,
                       with_version_resource: bool = True) -> dict:
    """A synthetic Shipping image carrying everything V-01/V-03/V-04/V-06 read."""
    from test_pe_info import vs_fixed_file_info

    rdata, rdata_offsets = build_rdata(branch=branch, changelist=changelist,
                                       sdk_version=sdk_version)
    # The changelist as a compiled immediate, so V-01's companion read has
    # something to find: `mov eax, <changelist>` followed by `ret`.
    text = b"\x90" * 16 + b"\xb8" + struct.pack("<I", changelist) + b"\xc3"
    data, data_offsets = build_data(ue5=ue5_version, neighbour=neighbour,
                                    repeat=repeat)

    builder = PEBuilder()
    builder.add_section(".text", 0x1000, text, characteristics=0x60000020)
    builder.add_section(".rdata", RDATA_RVA, rdata, characteristics=RDATA_FLAGS)
    builder.add_section(".data", DATA_RVA, data, characteristics=DATA_FLAGS)

    if with_version_resource:
        strings = dict(VERSION_STRINGS if version_strings is None
                       else version_strings)
        blob = build_version_resource(
            strings, fixed=vs_fixed_file_info(file_version=fixed_version,
                                              product_version=fixed_version))
        payload = build_resource_blob(RSRC_RVA, {16: {1: {1033: blob}}})
        builder.add_section(".rsrc", RSRC_RVA, payload, characteristics=RDATA_FLAGS)
        builder.set_directory(DIR_RESOURCE, RSRC_RVA, len(payload))

    if with_exports:
        # build_export_blob lays the name table out for us; the address of each
        # export is not what it computes, so the export we care about is patched
        # to point at the constant in .rdata afterwards.
        exports = build_export_blob(EXPORT_RVA, "SYNTHETIC.exe",
                                    ["AmdPowerXpressRequestHighPerformance",
                                     engine_version.D3D12_SDK_VERSION_EXPORT])
        exports = bytearray(exports)
        # The address table is the first thing build_export_blob writes after the
        # 40-byte directory; find it through the directory's own field.
        address_rva = struct.unpack_from("<I", exports, 28)[0]
        address_offset = address_rva - EXPORT_RVA
        names = ["AmdPowerXpressRequestHighPerformance",
                 engine_version.D3D12_SDK_VERSION_EXPORT]
        index = sorted(names).index(engine_version.D3D12_SDK_VERSION_EXPORT)
        struct.pack_into("<I", exports, address_offset + 4 * index,
                         RDATA_RVA + rdata_offsets["sdk"])
        builder.add_section(".edata", EXPORT_RVA, bytes(exports),
                            characteristics=RDATA_FLAGS)
        builder.set_directory(DIR_EXPORT, EXPORT_RVA, len(exports))

    debug = build_debug_blob(DEBUG_RVA, PDB_NAME, PDB_GUID, 1)
    builder.add_section(".debug", DEBUG_RVA, debug, characteristics=RDATA_FLAGS)
    builder.set_directory(DIR_DEBUG, DEBUG_RVA, 28)

    blob = builder.build()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(blob)
    return {
        "path": path,
        "size": len(blob),
        "rdata_offsets": rdata_offsets,
        "data_offsets": data_offsets,
        "sections": {".rdata": RDATA_RVA, ".data": DATA_RVA},
    }


def build_utoc(path: str, *, version: int = 6, entry_count: int = 1,
               container_flags: int = 0) -> None:
    header = bytearray(container_info.TOC_HEADER_SIZE_EXPECTED)
    header[0:16] = container_info.TOC_MAGIC
    header[16] = version
    struct.pack_into("<I", header, 20, container_info.TOC_HEADER_SIZE_EXPECTED)
    struct.pack_into("<I", header, 24, entry_count)
    struct.pack_into("<I", header, 32, 12)
    struct.pack_into("<I", header, 44, 65536)
    struct.pack_into("<I", header, 52, 1)
    header[80] = container_flags
    struct.pack_into("<Q", header, 88, 0xFFFFFFFFFFFFFFFF)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(header))


def _fstring(text: str) -> bytes:
    raw = text.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def build_pak(path: str, tree: dict[str, list[str]], *, version: int = 11,
              encrypted_index: bool = False) -> None:
    """A pak with a real footer, primary index and full directory index.

    Only the three index structures are built: this tool reads names and never
    an entry payload, so there is nothing else for a test to exercise.
    """
    full = bytearray()
    full += struct.pack("<I", len(tree))
    entry = 0
    for directory in sorted(tree):
        full += _fstring(directory)
        full += struct.pack("<I", len(tree[directory]))
        for name in sorted(tree[directory]):
            full += _fstring(name)
            full += struct.pack("<I", entry)
            entry += 1

    body = bytearray(b"\x00" * 4096)          # stand-in for entry payloads
    full_offset = len(body)
    body += full

    primary = bytearray()
    primary += _fstring("../../../")
    primary += struct.pack("<i", entry)
    primary += struct.pack("<Q", 0x4E5F46A0)
    primary += struct.pack("<i", 0)           # no path hash index
    primary += struct.pack("<i", 1)           # has full directory index
    primary += struct.pack("<qq", full_offset, len(full))
    primary += b"\x00" * 20                   # FSHAHash
    index_offset = len(body)
    body += primary

    size = container_info.pak_footer_size(version)
    footer = bytearray(size)
    fields = {name: (rel, length) for name, rel, length
              in container_info.pak_footer_field_offsets(version)}
    footer[fields["encrypted_index"][0]] = 1 if encrypted_index else 0
    struct.pack_into("<I", footer, fields["magic"][0], container_info.PAK_MAGIC)
    struct.pack_into("<i", footer, fields["pak_version"][0], version)
    struct.pack_into("<q", footer, fields["index_offset"][0], index_offset)
    struct.pack_into("<q", footer, fields["index_size"][0], len(primary))
    body += footer

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(body))


def build_install(tmp_path, **exe_kwargs) -> dict:
    """A directory that pathguard.looks_like_install_root() accepts."""
    root = os.path.join(str(tmp_path), "install")
    exe = os.path.join(root, "MISERY", "Binaries", "Win64",
                       "MISERY-Win64-Shipping.exe")
    built = build_shipping_exe(tmp_path, exe, **exe_kwargs)
    paks = os.path.join(root, "MISERY", "Content", "Paks")
    # The TOC version is not a property of the exe, so it is NOT taken from
    # **exe_kwargs: build_install_with_toc() below rewrites the containers when a
    # test wants them to disagree with the image.
    build_utoc(os.path.join(paks, "global.utoc"))
    build_utoc(os.path.join(paks, "MISERY-Windows.utoc"), container_flags=0x0A)
    build_pak(os.path.join(paks, "MISERY-Windows.pak"), {
        "Engine/Plugins/Runtime/Niagara/": ["Niagara.uplugin"],
        "SYNTHETIC/": ["SYNTHETIC.uproject"],
        "Engine/Config/": ["BaseEngine.ini"],
    })
    built["root"] = root
    assert pathguard.looks_like_install_root(root)
    return built


def build_install_with_toc(tmp_path, toc_version: int, **exe_kwargs) -> dict:
    """An installation whose containers were written by a DIFFERENT UE line."""
    built = build_install(tmp_path, **exe_kwargs)
    paks = os.path.join(built["root"], "MISERY", "Content", "Paks")
    build_utoc(os.path.join(paks, "global.utoc"), version=toc_version)
    build_utoc(os.path.join(paks, "MISERY-Windows.utoc"), version=toc_version,
               container_flags=0x0A)
    return built


# --------------------------------------------------------------------------- #
# synthetic crash reports
# --------------------------------------------------------------------------- #

CRASH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<FGenericCrashContext>
 <RuntimeProperties>
  <EngineVersion>5.4.4-35576357+++UE5+Release-5.4</EngineVersion>
  <EngineCompatibleVersion>5.4.4-35576357+++UE5+Release-5.4</EngineCompatibleVersion>
  <BuildVersion>++UE5+Release-5.4-CL-35576357</BuildVersion>
  <BuildConfiguration>Shipping</BuildConfiguration>
  <GameName>UE-SYNTHETIC</GameName>
  <IsSourceDistribution>false</IsSourceDistribution>
  <IsPerforceBuild>false</IsPerforceBuild>
  <IsUERelease>true</IsUERelease>
  <UserName>SECRET_USER_NAME</UserName>
  <MachineId>SECRET_MACHINE_ID</MachineId>
  <LoginId>SECRET_LOGIN_ID</LoginId>
  <EpicAccountId>SECRET_ACCOUNT_ID</EpicAccountId>
  <CommandLine>SECRET_COMMAND_LINE</CommandLine>
  <BaseDir>C:/Users/SECRET/AppData/Local</BaseDir>
 </RuntimeProperties>
</FGenericCrashContext>
"""

MINIDUMP_MODULE_STRUCT_SIZE = engine_version.MINIDUMP_MODULE_SIZE


def build_minidump(path: str, modules: list[dict]) -> None:
    """A minidump with nothing but a MINIDUMP_MODULE_LIST."""
    header_size = 32
    directory_size = 12
    list_offset = header_size + directory_size
    module_area = 4 + MINIDUMP_MODULE_STRUCT_SIZE * len(modules)
    strings_offset = list_offset + module_area

    strings = bytearray()
    string_rvas: list[int] = []
    cv_rvas: list[tuple[int, int]] = []
    for module in modules:
        string_rvas.append(strings_offset + len(strings))
        encoded = module["name"].encode("utf-16-le")
        strings += struct.pack("<I", len(encoded)) + encoded + b"\x00\x00"
        while len(strings) % 4:
            strings.append(0)
        if module.get("pdb_guid") is None:
            cv_rvas.append((0, 0))
            continue
        record = (b"RSDS" + module["pdb_guid"]
                  + struct.pack("<I", module["pdb_age"])
                  + module["pdb_name"].encode("utf-8") + b"\x00")
        cv_rvas.append((strings_offset + len(strings), len(record)))
        strings += record
        while len(strings) % 4:
            strings.append(0)

    blob = bytearray(strings_offset + len(strings))
    struct.pack_into("<IIII", blob, 0, engine_version.MINIDUMP_SIGNATURE,
                     0xA793, 1, header_size)
    struct.pack_into("<III", blob, header_size,
                     engine_version.MINIDUMP_MODULE_LIST_STREAM,
                     module_area, list_offset)
    struct.pack_into("<I", blob, list_offset, len(modules))
    for index, module in enumerate(modules):
        offset = list_offset + 4 + MINIDUMP_MODULE_STRUCT_SIZE * index
        struct.pack_into("<QIIII", blob, offset,
                         IMAGE_BASE, module["size_of_image"], module["checksum"],
                         module["time_date_stamp"], string_rvas[index])
        struct.pack_into("<13I", blob, offset + 24, *([0] * 13))
        struct.pack_into("<II", blob, offset + 76,
                         cv_rvas[index][1], cv_rvas[index][0])
    blob[strings_offset:strings_offset + len(strings)] = strings
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(blob))


def build_crash_dir(tmp_path, identity: dict) -> str:
    """One report matching *identity* and one from a different build."""
    root = os.path.join(str(tmp_path), "Crashes")
    matching = os.path.join(root, "UECC-Windows-AAAA_0000")
    other = os.path.join(root, "UECC-Windows-BBBB_0000")
    exe_name = os.path.basename(engine_version.SHIPPING_REL)
    for report, module in (
        (matching, {
            "name": "C:/Games/SECRET_PATH/" + exe_name,
            "size_of_image": identity["size_of_image"],
            "checksum": identity["checksum"],
            "time_date_stamp": identity["time_date_stamp"],
            "pdb_guid": PDB_GUID,
            "pdb_age": identity["pdb_age"],
            "pdb_name": "C:/build/SECRET/" + PDB_NAME,
        }),
        (other, {
            "name": exe_name,
            "size_of_image": identity["size_of_image"] + 4096,
            "checksum": identity["checksum"] + 1,
            "time_date_stamp": identity["time_date_stamp"] + 1,
            "pdb_guid": bytes(reversed(PDB_GUID)),
            "pdb_age": 1,
            "pdb_name": PDB_NAME,
        }),
    ):
        os.makedirs(report, exist_ok=True)
        with open(os.path.join(report, "CrashContext.runtime-xml"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write(CRASH_XML)
        build_minidump(os.path.join(report, "UEMinidump.dmp"), [
            module,
            {"name": "UE4SS.dll", "size_of_image": 4096, "checksum": 0,
             "time_date_stamp": 0, "pdb_guid": None, "pdb_age": None,
             "pdb_name": None},
        ])
    return root


# --------------------------------------------------------------------------- #
# synthetic Unreal Engine reference tree
# --------------------------------------------------------------------------- #

def build_ue_tree(tmp_path, *, minor: int = 4, patch: int = 4,
                  changelist: int = CHANGELIST, branch: str = BRANCH,
                  ue5_version_names: int = 13, toc_names: int = 6,
                  sdk_version: int = 611) -> str:
    """An Engine/ directory shaped like the four files the reader wants.

    ``ue5_version_names`` and ``toc_names`` are COUNTS of enum members, not
    values: the reader has to evaluate the enums, and handing it values would
    test nothing.
    """
    engine = os.path.join(str(tmp_path), "UE_%d.%d" % (5, minor), "Engine")
    def write(relative: str, text: str) -> None:
        path = os.path.join(engine, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    write(engine_version.UE_REFERENCE_FILES["build_version"], json.dumps({
        "MajorVersion": 5, "MinorVersion": minor, "PatchVersion": patch,
        "Changelist": changelist, "CompatibleChangelist": 33043543,
        "IsLicenseeVersion": 0, "IsPromotedBuild": 1, "BranchName": branch,
    }, indent="\t"))

    ue4_members = ["\tVER_UE4_OLDEST_LOADABLE_PACKAGE = 214,"]
    # Grow the UE4 enum until AUTOMATIC_VERSION lands on 522, the way the real
    # header does: one member per version, then the PLUS_ONE / minus-one pair.
    for index in range(522 - 214):
        ue4_members.append("\tVER_UE4_FILLER_%d," % index)
    ue4_members.append("\tVER_UE4_AUTOMATIC_VERSION_PLUS_ONE,")
    ue4_members.append("\tVER_UE4_AUTOMATIC_VERSION = "
                       "VER_UE4_AUTOMATIC_VERSION_PLUS_ONE - 1")
    ue5_members = ["\tINITIAL_VERSION = 1000,"]
    for index in range(ue5_version_names - 1):
        ue5_members.append("\tUE5_FILLER_%d," % index)
    ue5_members.append("\tAUTOMATIC_VERSION_PLUS_ONE,")
    ue5_members.append("\tAUTOMATIC_VERSION = AUTOMATIC_VERSION_PLUS_ONE - 1")
    write(engine_version.UE_REFERENCE_FILES["object_version"],
          "enum class EUnrealEngineObjectUE5Version : uint32\n{\n"
          + "\n".join(ue5_members) + "\n};\n\n"
          "enum EUnrealEngineObjectUE4Version\n{\n"
          + "\n".join(ue4_members) + "\n};\n")

    toc_members = ["\tInvalid = 0,"]
    for index in range(toc_names):
        toc_members.append("\tTocFiller_%d," % index)
    toc_members.append("\tLatestPlusOne,")
    toc_members.append("\tLatest = LatestPlusOne - 1")
    write(engine_version.UE_REFERENCE_FILES["io_store"],
          "enum class EIoStoreTocVersion : uint8\n{\n"
          + "\n".join(toc_members) + "\n};\n")

    write(engine_version.UE_REFERENCE_FILES["launch_windows"],
          'extern "C" { _declspec(dllexport) extern const UINT D3D12SDKVersion '
          '= %d; }\n' % sdk_version)
    write(engine_version.UE_REFERENCE_FILES["object_version_cpp"],
          "const FPackageFileVersion GPackageFileUEVersion("
          "VER_LATEST_ENGINE_UE4, EUnrealEngineObjectUE5Version::"
          "AUTOMATIC_VERSION);\n"
          "const FPackageFileVersion GOldestLoadablePackageFileUEVersion = "
          "FPackageFileVersion::CreateUE4Version("
          "VER_UE4_OLDEST_LOADABLE_PACKAGE);\n")
    return engine


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture()
def install(tmp_path):
    return build_install(tmp_path)


@pytest.fixture()
def document(tmp_path, install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    return engine_version.build_document(install["root"], crash_dir,
                                         str(tmp_path))


# --------------------------------------------------------------------------- #
# V-01
# --------------------------------------------------------------------------- #

def test_v01_reports_the_whole_string_not_the_marker(install):
    warnings: list[str] = []
    result = engine_version.scan_v01(install["root"], warnings)
    image = next(group for group in result["images"]
                 if group["path"] == engine_version.SHIPPING_REL)
    expected = install["rdata_offsets"]["branch_cl"] + _raw_pointer(install, ".rdata")
    hit = next(h for h in image["hits"]
               if h["string"] == "%s-CL-%d" % (BRANCH, CHANGELIST))
    # The offset is the start of the STRING, and the length is the string's own
    # byte length excluding the terminator - not the marker's.
    assert hit["offset"] == expected
    assert hit["length"] == len("%s-CL-%d" % (BRANCH, CHANGELIST)) * 2
    assert hit["encoding"] == "utf-16le"
    assert hit["section"] == ".rdata"


def test_v01_parses_branch_changelist_and_minor_line(install):
    warnings: list[str] = []
    result = engine_version.scan_v01(install["root"], warnings)
    parsed = next(group for group in result["images"]
                  if group["path"] == engine_version.SHIPPING_REL)["parsed"]
    assert parsed["branches"] == [BRANCH]
    assert parsed["changelists"] == [CHANGELIST]
    assert parsed["minor_lines"] == ["5.4"]
    # The patch component is NOT available from the string literals: this is the
    # asymmetry the whole confidence split rests on.
    assert parsed["full_versions"] == []


def test_v01_finds_the_changelist_as_a_compiled_immediate(install):
    warnings: list[str] = []
    found = engine_version.scan_v01_changelist_constant(
        install["root"], CHANGELIST, warnings)
    assert found["value"] == CHANGELIST
    assert found["occurrence_count"] == 1
    occurrence = found["occurrences"][0]
    assert occurrence["length"] == 4
    assert occurrence["section"] == ".text"
    assert occurrence["preceding_byte_hex"] == "b8"


# --------------------------------------------------------------------------- #
# V-03
# --------------------------------------------------------------------------- #

def test_v03_supplies_the_patch_component_from_the_fixed_file_info(install):
    warnings: list[str] = []
    result = engine_version.read_v03(install["root"], warnings)
    image = next(group for group in result["images"]
                 if group["path"] == engine_version.SHIPPING_REL)
    assert image["version_info"]["fixed"]["file_version"] == "5.4.4.0"
    # Kept apart from the string literals on purpose, so that "the patch level
    # comes from one structured field" stays visible in the artifact.
    assert image["parsed"]["fixed_file_info_versions"] == ["5.4.4"]
    assert image["parsed"]["full_versions"] == []
    location = image["rt_version_locations"][0]
    assert location["file_offset"] is not None
    assert location["size"] > 0
    assert location["section"] == ".rsrc"


def test_v03_records_the_absence_of_a_version_resource(tmp_path):
    built = build_install(tmp_path, with_version_resource=False)
    warnings: list[str] = []
    result = engine_version.read_v03(built["root"], warnings)
    image = next(group for group in result["images"]
                 if group["path"] == engine_version.SHIPPING_REL)
    assert image["version_info"] is None
    assert any("V-03" in warning for warning in warnings)


# --------------------------------------------------------------------------- #
# V-04
# --------------------------------------------------------------------------- #

def test_v04_reads_the_exported_sdk_version_at_a_stated_offset(install):
    warnings: list[str] = []
    result = engine_version.read_v04(install["root"], warnings)
    export = result["d3d12_sdk_version_export"]
    assert export["present"] is True
    assert export["value"] == 611
    assert export["file_offset"] == (install["rdata_offsets"]["sdk"]
                                     + _raw_pointer(install, ".rdata"))
    literal = result["literal_reads"][0]
    assert literal["length"] == 4
    assert literal["bytes_hex"] == "63 02 00 00"
    assert literal["evidence"]["claim_class"] == "P"
    assert literal["evidence"]["read_locus"]["offset"] == export["file_offset"]


def test_v04_warns_when_the_export_is_absent(tmp_path):
    built = build_install(tmp_path, with_exports=False)
    warnings: list[str] = []
    result = engine_version.read_v04(built["root"], warnings)
    assert result["d3d12_sdk_version_export"]["present"] is False
    assert any("D3D12SDKVersion" in warning for warning in warnings)


# --------------------------------------------------------------------------- #
# V-05
# --------------------------------------------------------------------------- #

def test_v05_reads_the_version_byte_of_every_container(install):
    warnings: list[str] = []
    result = engine_version.read_v05(install["root"], warnings)
    assert len(result["containers"]) == 2
    for container in result["containers"]:
        assert container["magic_matches"] is True
        assert container["version"] == 6
        assert container["toc_header_size"] == 144
        version_read = next(read for read in container["literal_reads"]
                            if read["decoded_field"] == "version")
        assert (version_read["offset"], version_read["length"]) == (16, 1)
        assert version_read["bytes_hex"] == "06"
    assert warnings == []


def test_v05_discovers_containers_instead_of_using_a_fixed_list(tmp_path, install):
    # A patch that adds a container must not be able to leave the claim "every
    # container agrees" resting on the two the tool happened to know about.
    extra = os.path.join(install["root"], "MISERY", "Content", "Paks",
                         "MISERY-Windows_P.utoc")
    build_utoc(extra, version=5)
    warnings: list[str] = []
    result = engine_version.read_v05(install["root"], warnings)
    versions = {container["path"]: container["version"]
                for container in result["containers"]}
    assert len(versions) == 3
    assert versions["MISERY/Content/Paks/MISERY-Windows_P.utoc"] == 5
    # And a container that disagrees must break the vote rather than be outvoted.
    document = engine_version.build_document(install["root"], None, str(tmp_path))
    assert document["cross_validation"]["result"][
        "data_format_votes"]["V-05"]["ue_lines"] == []
    assert document["cross_validation"]["bar_met"] is False


def test_v05_literal_read_states_offset_and_length_and_names_nothing(install):
    warnings: list[str] = []
    result = engine_version.read_v05(install["root"], warnings)
    read = result["containers"][0]["literal_reads"][0]
    note = read["evidence"]["note"]
    assert note == read["claim"]
    assert "offset 16" in note
    assert "1 byte" in note
    # The note IS the claim: it must not name the field, because the validator
    # derives the claim class of a reduced annotation from that string alone.
    assert "version" not in note.lower()
    assert read["evidence"]["read_locus"]["address_kind"] == "file-offset"


# --------------------------------------------------------------------------- #
# V-06
# --------------------------------------------------------------------------- #

def test_v06_finds_the_shape_exactly_once(install):
    warnings: list[str] = []
    result = engine_version.scan_v06(install["root"], warnings)
    assert result["hit_count"] == 1
    hit = result["hits"][0]
    assert hit["file_version_ue4"] == 522
    assert hit["file_version_ue5"] == 1012
    assert hit["section"] == ".data"
    assert hit["offset"] == (install["data_offsets"]["pairs"][0]
                             + _raw_pointer(install, ".data"))
    assert warnings == []


def test_v06_neighbour_prediction_is_the_refutation_attempt(install):
    warnings: list[str] = []
    hit = engine_version.scan_v06(install["root"], warnings)["hits"][0]
    assert hit["neighbour_prediction"] == [
        engine_version.VER_UE4_OLDEST_LOADABLE_PACKAGE, 0]
    assert hit["neighbour_file_version_ue4"] == 214
    assert hit["neighbour_file_version_ue5"] == 0
    assert hit["neighbour_prediction_holds"] is True


def test_v06_failed_refutation_is_reported_not_swallowed(tmp_path):
    built = build_install(tmp_path, neighbour=(999, 7))
    warnings: list[str] = []
    result = engine_version.scan_v06(built["root"], warnings)
    assert result["hit_count"] == 1
    assert result["hits"][0]["neighbour_prediction_holds"] is False
    assert any("refutation attempt FIRED" in warning for warning in warnings)
    # And it must not silently reach the answer: the source produces no reading
    # at all, rather than a reading that happens to agree with the others.
    document = engine_version.build_document(built["root"], None, str(tmp_path))
    vote = document["cross_validation"]["result"]["data_format_votes"]["V-06"]
    assert vote["ue_lines"] == []
    assert vote["status"] == "no-reading"
    assert any("refutation attempt FIRED" in warning
               for warning in document["warnings"])


def test_a_reading_matching_no_reference_line_is_a_disagreement(tmp_path):
    # An SDK version that exists in the image but in no reference row is READ and
    # UNMATCHED. That is a disagreement, and it must withdraw the data-format
    # verdict rather than be outvoted by the two sources that did match - the
    # distinction between "no reading" and "a reading that fits nothing".
    built = build_install(tmp_path, sdk_version=999)
    document = engine_version.build_document(built["root"], None, str(tmp_path))
    votes = document["cross_validation"]["result"]["data_format_votes"]
    assert votes["V-04"]["status"] == "unmatched"
    assert votes["V-05"]["status"] == "matched"
    assert votes["V-06"]["status"] == "matched"
    assert document["cross_validation"]["result"]["data_format_ue_line"] is None
    assert document["cross_validation"]["bar_met"] is False
    assert any("matches no reference UE line" in warning
               for warning in document["warnings"])


def test_contradicting_containers_are_unmatched_not_averaged(tmp_path):
    built = build_install(tmp_path)
    build_utoc(os.path.join(built["root"], "MISERY", "Content", "Paks",
                            "MISERY-Windows.utoc"), version=8)
    document = engine_version.build_document(built["root"], None, str(tmp_path))
    vote = document["cross_validation"]["result"]["data_format_votes"]["V-05"]
    assert vote["status"] == "unmatched"
    assert vote["reading"] == [6, 8]
    assert document["cross_validation"]["bar_met"] is False


def test_v06_refuses_to_interpret_several_hits(tmp_path):
    built = build_install(tmp_path, repeat=2)
    warnings: list[str] = []
    result = engine_version.scan_v06(built["root"], warnings)
    assert result["hit_count"] == 2
    assert result["literal_reads"] == []
    assert any("occurs 2 times" in warning for warning in warnings)


def test_v06_ignores_a_pair_outside_the_plausible_band(tmp_path):
    # 522 followed by 5 is not an EUnrealEngineObjectUE5Version value, so the
    # shape must not match: the filter is what makes one hit meaningful.
    built = build_install(tmp_path, ue5_version=5)
    warnings: list[str] = []
    result = engine_version.scan_v06(built["root"], warnings)
    assert result["hit_count"] == 0


# --------------------------------------------------------------------------- #
# V-07
# --------------------------------------------------------------------------- #

def test_v07_lists_names_from_the_pak_index_only(install):
    warnings: list[str] = []
    result = engine_version.read_v07(install["root"], warnings)
    assert result["available"] is True
    assert result["pak_version"] == 11
    assert result["entry_count"] == 3
    assert result["uplugin_count"] == 1
    assert result["plugin_and_project_files"] == [
        "Engine/Plugins/Runtime/Niagara/Niagara.uplugin",
        "SYNTHETIC/SYNTHETIC.uproject",
    ]
    # A .ini is in the index but is not a plugin or project file, so it must not
    # be reported here.
    assert not any(path.endswith(".ini")
                   for path in result["plugin_and_project_files"])
    assert warnings == []


def test_v07_refuses_an_encrypted_index_instead_of_working_around_it(tmp_path):
    built = build_install(tmp_path)
    build_pak(os.path.join(built["root"], "MISERY", "Content", "Paks",
                           "MISERY-Windows.pak"),
              {"Engine/": ["x.uplugin"]}, encrypted_index=True)
    warnings: list[str] = []
    result = engine_version.read_v07(built["root"], warnings)
    assert result["available"] is False
    assert result["index_encrypted"] is True
    assert any("D-02" in warning for warning in warnings)


# --------------------------------------------------------------------------- #
# V-02: RISK-09
# --------------------------------------------------------------------------- #

def test_v02_separates_this_build_from_another_build(tmp_path, install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    warnings: list[str] = []
    result = engine_version.read_v02(crash_dir, identity, warnings)
    assert result["report_count"] == 2
    assert result["this_build_count"] == 1
    assert result["other_build_count"] == 1
    assert result["undecidable_count"] == 0
    verdicts = {report["report"]: report["build_correspondence"]["verdict"]
                for report in result["reports"]}
    assert verdicts["UECC-Windows-AAAA_0000"] == "this-build"
    assert verdicts["UECC-Windows-BBBB_0000"] == "other-build"
    # Every report carries its own mtime, which plan.md 4.2 makes mandatory.
    assert all(report["mtime_utc"] for report in result["reports"])


def test_v02_compares_all_four_identity_values(tmp_path, install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    result = engine_version.read_v02(crash_dir, identity, [])
    other = next(report for report in result["reports"]
                 if report["report"] == "UECC-Windows-BBBB_0000")
    fields = other["build_correspondence"]["fields"]
    assert set(fields) == {"size_of_image", "checksum", "time_date_stamp",
                           "pdb_guid", "pdb_age"}
    assert fields["size_of_image"]["equal"] is False
    assert fields["pdb_guid"]["equal"] is False


def test_v02_is_undecidable_without_a_minidump(tmp_path, install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    os.remove(os.path.join(crash_dir, "UECC-Windows-AAAA_0000",
                           "UEMinidump.dmp"))
    result = engine_version.read_v02(crash_dir, identity, [])
    assert result["undecidable_count"] == 1
    undecided = next(report for report in result["reports"]
                     if report["report"] == "UECC-Windows-AAAA_0000")
    assert undecided["build_correspondence"]["verdict"] == "undecidable"


def test_v02_reports_a_third_party_loader_as_an_environment_caveat(tmp_path,
                                                                  install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    result = engine_version.read_v02(crash_dir, identity, [])
    assert result["mod_loader_modules_present"] == ["UE4SS.dll"]
    assert "environment caveat" in result["mod_loader_note"]


def test_v02_absent_crash_directory_is_stated_not_guessed(install):
    result = engine_version.read_v02(None, {}, [])
    assert result["available"] is False
    assert result["reports"] == []
    assert result["directory"] == engine_version.CRASH_DIR_REDACTED


# --------------------------------------------------------------------------- #
# C-13
# --------------------------------------------------------------------------- #

def test_no_personal_crash_field_reaches_the_artifact(document):
    text = engine_version.dump_json(document)
    for secret in ("SECRET_USER_NAME", "SECRET_MACHINE_ID", "SECRET_LOGIN_ID",
                   "SECRET_ACCOUNT_ID", "SECRET_COMMAND_LINE"):
        assert secret not in text
    # The XML fields that ARE read must still be there, or the test above would
    # pass on an empty reading.
    assert "BuildConfiguration" in text
    assert "IsSourceDistribution" in text


def test_module_paths_are_reduced_to_basenames(document):
    text = engine_version.dump_json(document)
    assert "SECRET_PATH" not in text
    assert "C:/build/SECRET" not in text
    assert os.path.basename(engine_version.SHIPPING_REL) in text


def test_the_crash_directory_is_recorded_redacted(document):
    v02 = document["sources"]["V-02a_and_V-02b"]
    assert v02["directory"] == engine_version.CRASH_DIR_REDACTED
    assert "%LOCALAPPDATA%" in v02["directory"]


def test_the_install_root_is_not_recorded(document):
    assert "not recorded" in document["install_root_recorded_as"]


# --------------------------------------------------------------------------- #
# the plan.md 4.2 rule, as a mechanism
# --------------------------------------------------------------------------- #

def test_agreement_between_text_and_data_format_meets_the_bar(document):
    cross = document["cross_validation"]
    assert cross["result"]["text_ue_line"] == "5.4"
    assert cross["result"]["data_format_ue_line"] == "5.4"
    assert cross["result"]["text_and_data_format_agree"] is True
    assert cross["bar_met"] is True
    assert (cross["independent_source_count"]
            >= cross["exit_criterion_minimum_sources"])
    assert document["claim"]["engine_version"]["value"] == "5.4.4"
    assert document["claim"]["engine_version"]["evidence"]["confidence"] >= 0.90


def test_every_data_format_source_votes_for_one_line(document):
    votes = document["cross_validation"]["result"]["data_format_votes"]
    assert set(votes) == {"V-04", "V-05", "V-06"}
    for method, vote in votes.items():
        assert vote["ue_lines"] == ["5.4"], method


def test_a_disagreeing_data_format_source_lowers_the_confidence(tmp_path):
    # The TOC says UE 5.3 while the serialization constant says UE 5.4. The
    # data-format sources then agree on nothing, and plan.md 4.2 forbids >= 0.90
    # whatever the text sources say.
    built = build_install_with_toc(tmp_path, toc_version=5)
    document = engine_version.build_document(built["root"], None, str(tmp_path))
    cross = document["cross_validation"]
    assert cross["result"]["data_format_ue_line"] is None
    assert cross["result"]["text_and_data_format_agree"] is False
    assert cross["bar_met"] is False
    for field in ("engine_version", "engine_version_minor_line", "engine_cl",
                  "engine_branch"):
        evidence = document["claim"][field]["evidence"]
        assert evidence["confidence"] < 0.90, field
        assert "CONFIDENCE LOWERED" in evidence["note"], field
    assert any("do not agree" in warning for warning in document["warnings"])


def test_the_minor_line_carries_a_higher_number_than_the_full_version(document):
    full = document["claim"]["engine_version"]["evidence"]["confidence"]
    line = document["claim"]["engine_version_minor_line"]["evidence"]["confidence"]
    # Two DIFFERENT claims, the second strictly weaker: no data-format source
    # resolves the patch component, so the full version cannot carry the number
    # the minor line carries.
    assert line > full


# --------------------------------------------------------------------------- #
# evidence-model contract
# --------------------------------------------------------------------------- #

def _walk_annotations(node):
    if isinstance(node, dict):
        if "evidence_level" in node and "confidence" in node:
            yield node
        for value in node.values():
            yield from _walk_annotations(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_annotations(value)


def test_no_confidence_anywhere_reaches_the_forbidden_band(document):
    seen = 0
    for annotation in _walk_annotations(document):
        seen += 1
        assert 0.0 <= annotation["confidence"] <= 0.99
        assert not (0.99 < annotation["confidence"] < 1.0)
    assert seen >= 5


def test_every_annotation_names_an_oracle_from_the_closed_list(document):
    closed = {"filesystem", "steam-metadata", "vcs-history", "global-ucas",
              "asset-registry", "runtime-reflection", "binary-analysis",
              "container-metadata", "external-doc"}
    for annotation in _walk_annotations(document):
        oracles = annotation["oracle"]
        assert oracles, annotation
        assert set(oracles) <= closed, oracles


def test_class_p_annotations_carry_a_read_locus(document):
    literal = [a for a in _walk_annotations(document)
               if a.get("claim_class") == "P"]
    assert literal
    for annotation in literal:
        assert annotation["evidence_level"] == "OBSERVED"
        locus = annotation["read_locus"]
        assert isinstance(locus["offset"], int)
        assert isinstance(locus["length"], int) and locus["length"] >= 1


def test_engine_is_vanilla_stays_unknown(document):
    node = document["claim"]["engine_is_vanilla"]
    assert node["value"] is None
    assert node["evidence"]["evidence_level"] == "UNKNOWN"
    assert "M3" in node["evidence"]["note"]


def test_is_source_distribution_stays_unknown_because_of_new_01(document):
    node = document["claim"]["is_source_distribution"]
    assert node["value"] is None
    assert node["evidence"]["evidence_level"] == "UNKNOWN"
    assert "NEW-01" in node["evidence"]["note"]
    # The reading itself is still published, or the honesty would be a silence.
    v02 = document["sources"]["V-02a_and_V-02b"]
    values = {bucket["fields"]["IsSourceDistribution"]
              for bucket in v02["engine_fields_of_matching_reports"]}
    assert "false" in values


def test_v02b_is_not_counted_towards_the_bar(document):
    cross = document["cross_validation"]
    assert "V-02b" not in cross["text_sources"]
    assert "V-02b" in cross["text_sources_not_counted"]
    assert "NEW-01" in cross["text_sources_not_counted"]["V-02b"]


def test_v07_is_declared_not_load_bearing(document):
    not_load_bearing = document["cross_validation"]["not_load_bearing"]
    assert "V-07" in not_load_bearing
    assert "A-09" in not_load_bearing["V-07"]


# --------------------------------------------------------------------------- #
# the external reference
# --------------------------------------------------------------------------- #

def test_the_reference_table_actually_discriminates():
    for field in ("package_file_version_ue5", "io_store_toc_latest",
                  "d3d12_sdk_version"):
        values = [row[field] for row in engine_version.UE_REFERENCE]
        # If any two lines shared a value the reading would not be a
        # discriminator, and claiming one would be wrong.
        assert len(set(values)) == len(values), field


def test_a_local_tree_verifies_the_builtin_table(tmp_path):
    engine = build_ue_tree(tmp_path)
    warnings: list[str] = []
    check = engine_version.read_local_ue_reference(engine, warnings)
    assert check["agrees_with_builtin_table"] is True
    assert check["disagreements"] == []
    read = check["read"]
    assert read["engine_version"] == "5.4.4"
    assert read["ue_line"] == "5.4"
    assert read["changelist"] == CHANGELIST
    assert read["package_file_version_ue5"] == 1012
    assert read["io_store_toc_latest"] == 6
    assert read["d3d12_sdk_version"] == 611
    assert read["ver_latest_engine_ue4"] == 522
    assert read["ver_ue4_oldest_loadable_package"] == 214
    assert read["package_version_globals_declared_in_order"] is True
    assert warnings == []
    # C-13: where the tree sits is not recorded.
    assert "not recorded" in check["root_recorded_as"]
    assert engine not in json.dumps(check)


def test_a_disagreeing_local_tree_is_reported(tmp_path):
    engine = build_ue_tree(tmp_path, ue5_version_names=14)
    warnings: list[str] = []
    check = engine_version.read_local_ue_reference(engine, warnings)
    assert check["agrees_with_builtin_table"] is False
    assert any("package_file_version_ue5" in message
               for message in check["disagreements"])
    assert any("DISAGREEMENT" in warning for warning in warnings)


def test_a_directory_that_is_not_an_engine_tree_is_refused(tmp_path):
    warnings: list[str] = []
    assert engine_version.read_local_ue_reference(str(tmp_path), warnings) is None
    assert any("does not look like an Engine directory" in warning
               for warning in warnings)


def test_the_reference_check_is_recorded_as_not_performed_when_skipped(document):
    check = document["external_reference"]["local_reference_check"]
    assert check["performed"] is False
    assert "--ue-source-root" in check["reason"]


# --------------------------------------------------------------------------- #
# determinism, output paths, CLI
# --------------------------------------------------------------------------- #

def test_two_runs_agree_except_for_generated_at(tmp_path, install):
    identity = engine_version.shipping_identity(install["root"])
    crash_dir = build_crash_dir(tmp_path, identity)
    first = engine_version.build_document(install["root"], crash_dir, str(tmp_path))
    second = engine_version.build_document(install["root"], crash_dir, str(tmp_path))
    assert first.pop("generated_at") != "" and second.pop("generated_at") != ""
    assert engine_version.dump_json(first) == engine_version.dump_json(second)


def test_output_is_utf8_lf_sorted_and_newline_terminated(document):
    text = engine_version.dump_json(document)
    assert text.endswith("\n")
    assert "\r" not in text
    decoded = json.loads(text)
    assert list(decoded) == sorted(decoded)


def test_pathguard_refuses_an_output_path_inside_the_installation(tmp_path,
                                                                 install,
                                                                 document):
    inside = os.path.join(install["root"], "engine-version.json")
    with pytest.raises(pathguard.OutputPathRefused):
        engine_version.write_json(document, inside, install["root"])
    assert not os.path.exists(inside)


def test_pathguard_refuses_an_evidence_path_inside_the_installation(tmp_path,
                                                                   install,
                                                                   document):
    inside = os.path.join(install["root"], "evidence")
    with pytest.raises(pathguard.OutputPathRefused):
        engine_version.write_evidence(document, inside, install["root"])


def test_evidence_is_written_for_every_method(tmp_path, install, document):
    out = os.path.join(str(tmp_path), "evidence")
    written = engine_version.write_evidence(document, out, install["root"])
    assert len(written) == len(engine_version.EVIDENCE_FILES) + 2
    for method, filename in engine_version.EVIDENCE_FILES:
        path = os.path.join(out, method, filename)
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        assert payload["method"] == method
        assert payload["build_key"] == document["build_key"]
    assert os.path.isfile(os.path.join(out, "V-06", "external-reference.json"))
    assert os.path.isfile(os.path.join(out, "V-07", "staged-plugins.txt"))


def test_cli_writes_a_document_and_exits_zero(tmp_path, install):
    out = os.path.join(str(tmp_path), "engine-version.json")
    evidence = os.path.join(str(tmp_path), "evidence")
    engine = build_ue_tree(tmp_path)
    completed = subprocess.run(
        [sys.executable, TOOL_PATH,
         "--install-dir", install["root"],
         "--no-crash",
         "--ue-source-root", engine,
         "--out", out,
         "--evidence-dir", evidence],
        capture_output=True, text=True, encoding="utf-8")
    assert completed.returncode == 0, completed.stderr
    assert "bar met" in completed.stdout
    with open(out, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["claim"]["engine_version"]["value"] == "5.4.4"
    assert document["external_reference"]["local_reference_check"][
        "agrees_with_builtin_table"] is True


def test_cli_refuses_a_directory_that_is_not_an_installation(tmp_path):
    completed = subprocess.run(
        [sys.executable, TOOL_PATH, "--install-dir", str(tmp_path), "--no-crash"],
        capture_output=True, text=True, encoding="utf-8")
    assert completed.returncode == 2
    assert "not a MISERY installation" in completed.stderr


# --------------------------------------------------------------------------- #
# helpers used by the assertions above
# --------------------------------------------------------------------------- #

def _raw_pointer(built: dict, section_name: str) -> int:
    """The file offset of *section_name* in the built image.

    Read back out of the image rather than remembered: the assertions on
    offsets are only meaningful if the expected value comes from the file the
    tool actually read.
    """
    import pe_info

    document = pe_info.analyze(built["path"], want_digests=False,
                               want_entropy=False, want_checksum=False)
    section = next(entry for entry in document["pe"]["sections"]
                   if entry["name"] == section_name)
    return section["raw_pointer"]
