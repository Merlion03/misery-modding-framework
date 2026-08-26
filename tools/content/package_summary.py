#!/usr/bin/env python3
"""Read-only reader for a UE 5.4 cooked package header: summary, names, imports,
exports, and the two mutually exclusive property-serialisation shapes.

The question this tool exists to answer
---------------------------------------
``research/unknowns.md`` CK-01 asks whether the shipped build uses *unversioned
property serialization*, and CK-04 asks whether a child Blueprint's property
offsets are baked at cook time or recomputed at load time. Both questions are
about the layout of a cooked package, and the only cooked packages this project
may read are the ones **we cook ourselves** with the same engine at the same
changelist (see ``research/modkit/cooker-comparison.md``). This module is that
reader: point it at a package produced by our own cooker and it reports what the
cooker actually wrote, field by field, with no interpretation left implicit.

It is deliberately NOT a general asset extractor. It reads the header structures
and, for each export, only the FIRST bytes of the export payload -- enough to
tell an ``FUnversionedHeader`` fragment stream from an ``FPropertyTag`` name, and
nothing more. It never writes, never decrypts, and refuses to read anything that
``pathguard`` places inside the game installation, because the game's cooked
packages live inside an encrypted container (D-02) and a "reader" that quietly
half-parsed encrypted bytes would produce confident nonsense.

Where the layout comes from, field by field
-------------------------------------------
The authoritative definition is the first-party UE 5.4.4 source tree on this
machine at the SAME changelist the shipped image was built from (35576357,
``++UE5+Release-5.4``; see ``research/unreal/engine-version.json``). Every field
below carries a file-and-line citation into it.

``Runtime/CoreUObject/Private/UObject/PackageFileSummary.cpp`` (``S``),
``Runtime/CoreUObject/Private/UObject/ObjectResource.cpp`` (``R``),
``Runtime/Core/Private/UObject/UnrealNames.cpp`` (``N``),
``Runtime/CoreUObject/Private/Serialization/UnversionedPropertySerialization.cpp``
(``U``), ``Runtime/CoreUObject/Private/UObject/PropertyTag.cpp`` (``T``),
``Runtime/CoreUObject/Public/UObject/ObjectMacros.h`` (``M``),
``Runtime/Core/Public/UObject/ObjectVersion.h`` (``V``):

    S:72-109     Tag then LegacyFileVersion; current legacy version is -8
    S:124-141    LegacyUE3Version, FileVersionUE4, FileVersionUE5, licensee
    S:142-144    custom version container follows the version fields
    S:146-165    a package whose three version fields are all zero was SAVED
                 UNVERSIONED; the loader then substitutes the running engine's
                 versions. An offline reader has to do the same or stop.
    S:196-197    TotalHeaderSize, then PackageName
    S:199-205    PackageFlags; PKG_Cooked is added by the cooking archive
    S:216-260    NameCount/NameOffset, the SoftObjectPaths pair, LocalizationId
                 (editor-only), the GatherableTextData pair, Export/Import
                 counts and offsets, DependsOffset
    S:265-290    SoftPackageReferences, SearchableNames, ThumbnailTable, Guid,
                 PersistentGuid (editor-only), generations
    S:311-352    SavedByEngineVersion, CompatibleWithEngineVersion,
                 CompressionFlags, CompressedChunks (must be empty)
    S:372-395    PackageSource, AdditionalPackagesToCook,
                 AssetRegistryDataOffset, BulkDataStartOffset,
                 WorldTileInfoDataOffset, ChunkIDs
    S:415-449    PreloadDependency pair, NamesReferencedFromExportDataCount,
                 PayloadTocOffset, DataResourceOffset
    N:4041-4090  FNameEntrySerialized: FString, then two uint16 hashes that the
                 engine reads and discards
    R:349-376    FObjectImport: ClassPackage, ClassName, OuterIndex, ObjectName,
                 PackageName (editor-only), bImportOptional
    R:121-220    FObjectExport, in file order
    R:208-212    **the field that answers CK-01 from the header alone**:
                 ScriptSerializationStartOffset / EndOffset are written ONLY
                 when the archive is NOT using unversioned property
                 serialization. Two int64 per export: a versioned-property
                 export map entry is 112 bytes wide, an unversioned one 96.
    M:131        PKG_UnversionedProperties = 0x00002000
    U:529-556    FUnversionedHeader::Load -- uint16 fragments until bIsLast,
                 then the zero mask
    U:569-598    fragment bit layout: SkipNum 0x007f, HasZero 0x0080,
                 IsLast 0x0100, ValueNum >> 9
    T:436-513    FPropertyTag in the >= PROPERTY_TAG_COMPLETE_TYPE_NAME format:
                 Name (FName) first, and a Name of "None" terminates the chain
    V:46-89      EUnrealEngineObjectUE5Version: INITIAL_VERSION = 1000 and the
                 ordered list that gives every later constant its value

Two shapes, and why the distinction is the whole point
------------------------------------------------------
A cooked export's property data is written in exactly one of two shapes:

``versioned tagged properties``
    a chain of ``FPropertyTag`` records, each of which NAMES its property
    (T:436). Property identity is a name; the name must therefore be in the
    package name map; and a reader needs no knowledge of the class layout.

``unversioned properties``
    an ``FUnversionedHeader`` (U:529) followed by bare values. Property identity
    is the *ordinal position* of the property in the class's schema -- the
    fragments only say "skip N, then N values". A reader needs the exact schema
    of the exact class build, and nothing in the package supplies it.

This module reports which shape each export uses, and never guesses: the shape
is taken from ``PKG_UnversionedProperties`` and CROSS-CHECKED against the export
map stride (R:208). If the two disagree the tool says so and refuses to decode
the payload probes, because a disagreement means the layout assumption is wrong.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
``literal_reads``
    Class **P**. One record per read: target, file offset, length, raw bytes, and
    a claim sentence that states the offset and the length and stops there. Each
    range is read a second time through a freshly opened handle before the record
    may say it reproduced.

``summary`` / ``names`` / ``imports`` / ``exports`` / ``probes``
    Class **I**. These name fields, apply the version gates and decode strings.
    Every one of those steps rests on the engine source, which is the
    ``external-doc`` oracle, so the whole layer is class I whatever the offsets
    are, and it is capped below the literal layer.

C-13: what may and may not leave the working tree
-------------------------------------------------
This tool is pointed at OUR OWN cook output, so its findings are not game
content. It still emits only names, counts, offsets, sizes and hashes plus the
bounded literal reads described above, so that its output can be committed
unchanged whatever it was pointed at.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Two runs over an
unchanged file differ only in ``generated_at``.

Standard library only.

CLI
---
    python tools/content/package_summary.py <file.uasset|.umap>
    python tools/content/package_summary.py <file.uasset> --json
    python tools/content/package_summary.py <a.uasset> --compare <b.uasset>
    python tools/content/package_summary.py <file.uasset> --out out.json

Exit codes: 0 the read completed (whatever the verdict), 2 usage / I/O error /
unparseable input / a refused target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"),):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

try:  # pragma: no cover - exercised by the CLI, not by the unit tests
    import pathguard  # type: ignore
except Exception:  # pragma: no cover
    pathguard = None

TOOL = "tools/content/package_summary.py"
TOOL_VERSION = "1.0.0"

ENGINE_TREE = "D:/Program Files/UE_5.4"
ENGINE_CHANGELIST = 35576357

# --------------------------------------------------------------------------- #
# constants. Every one of them is a literal from the engine tree named above,
# never a remembered value.
# --------------------------------------------------------------------------- #

PACKAGE_FILE_TAG = 0x9E2A83C1          # S:75, ObjectMacros / PackageFileSummary
PACKAGE_FILE_TAG_SWAPPED = 0xC1832A9E  # S:75
CURRENT_LEGACY_FILE_VERSION = -8       # S:107

# EUnrealEngineObjectUE5Version, V:46-89. Values are positional from
# INITIAL_VERSION = 1000 in the order the enum declares them.
UE5_INITIAL_VERSION = 1000
UE5_NAMES_REFERENCED_FROM_EXPORT_DATA = 1001
UE5_PAYLOAD_TOC = 1002
UE5_OPTIONAL_RESOURCES = 1003
UE5_LARGE_WORLD_COORDINATES = 1004
UE5_REMOVE_OBJECT_EXPORT_PACKAGE_GUID = 1005
UE5_TRACK_OBJECT_EXPORT_IS_INHERITED = 1006
UE5_FSOFTOBJECTPATH_REMOVE_ASSET_PATH_FNAMES = 1007
UE5_ADD_SOFTOBJECTPATH_LIST = 1008
UE5_DATA_RESOURCES = 1009
UE5_SCRIPT_SERIALIZATION_OFFSET = 1010
UE5_PROPERTY_TAG_EXTENSION = 1011
UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME = 1012

# Every UE4-era conditional in the summary layout was introduced long before the
# UE4 version that UE5 packages carry (522, observed in our own cook output and
# consistent with the comment at V:45). Rather than enumerate 300 UE4 constants,
# this reader requires a modern UE4 version and refuses below it -- refusing is
# honest, guessing is not.
UE4_MODERN_MIN = 500

# EPackageFlags, M:100-160. Only the flags this tool reports by name.
PACKAGE_FLAGS = [
    (0x00000001, "PKG_NewlyCreated"),
    (0x00000004, "PKG_ClientOptional"),
    (0x00000008, "PKG_ServerSideOnly"),
    (0x00000010, "PKG_CompiledIn"),
    (0x00000020, "PKG_ForDiffing"),
    (0x00000040, "PKG_EditorOnly"),
    (0x00000080, "PKG_Developer"),
    (0x00000100, "PKG_UncookedOnly"),
    (0x00000200, "PKG_Cooked"),
    (0x00000400, "PKG_ContainsNoAsset"),
    (0x00000800, "PKG_NotExternallyReferenceable"),
    (0x00002000, "PKG_UnversionedProperties"),
    (0x00004000, "PKG_ContainsMapData"),
    (0x00008000, "PKG_IsSaving"),
    (0x00010000, "PKG_Compiling"),
    (0x00020000, "PKG_ContainsMap"),
    (0x00040000, "PKG_RequiresLocalizationGather"),
    (0x00200000, "PKG_PlayInEditor"),
    (0x00400000, "PKG_ContainsScript"),
    (0x00800000, "PKG_DisallowExport"),
    (0x08000000, "PKG_CookGenerated"),
    (0x10000000, "PKG_DynamicImports"),
    (0x20000000, "PKG_RuntimeGenerated"),
    (0x40000000, "PKG_ReloadingForCooker"),
    (0x80000000, "PKG_FilterEditorOnly"),
]
PKG_UNVERSIONED_PROPERTIES = 0x00002000  # M:131
PKG_FILTER_EDITOR_ONLY = 0x80000000

# FObjectExport widths, derived field by field from R:121-220 and used only as a
# CROSS-CHECK of the package flag, never as a substitute for it.
EXPORT_ENTRY_SIZE_UNVERSIONED_PROPERTIES = 96
EXPORT_ENTRY_SIZE_VERSIONED_PROPERTIES = 112   # + 2 * int64, R:208-212

# FUnversionedHeader fragment bits, U:579-582.
FRAG_SKIP_NUM_MASK = 0x007F
FRAG_HAS_ZERO_MASK = 0x0080
FRAG_IS_LAST_MASK = 0x0100
FRAG_VALUE_NUM_SHIFT = 9

# hard limits. Each one bounds a number that comes from a file and must
# therefore never be believed.
MAX_NAMES = 1_000_000
MAX_IMPORTS = 500_000
MAX_EXPORTS = 500_000
MAX_STRING_UNITS = 65536
MAX_FRAGMENTS = 4096
PROBE_BYTES = 32

CONFIDENCE_LITERAL = 0.97   # class P, a bounded read reproduced twice
CONFIDENCE_DECODED = 0.90   # class I, rests on the engine source


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ParseError(Exception):
    """The bytes do not match the layout the citations describe."""


# --------------------------------------------------------------------------- #
# FArchive reader. Every read is bounded and every count is clamped, because
# every number here came out of a file.
# --------------------------------------------------------------------------- #


class ArchiveReader:
    def __init__(self, data: bytes, name: str = "<buffer>") -> None:
        self.data = data
        self.name = name
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, count: int, what: str) -> bytes:
        if count < 0 or count > self.remaining():
            raise ParseError(
                "%s: %s wants %d bytes at offset %d, only %d remain"
                % (self.name, what, count, self.pos, self.remaining()))
        out = self.data[self.pos:self.pos + count]
        self.pos += count
        return out

    def i32(self, what: str) -> int:
        return struct.unpack("<i", self.take(4, what))[0]

    def u32(self, what: str) -> int:
        return struct.unpack("<I", self.take(4, what))[0]

    def i64(self, what: str) -> int:
        return struct.unpack("<q", self.take(8, what))[0]

    def u16(self, what: str) -> int:
        return struct.unpack("<H", self.take(2, what))[0]

    def boolean(self, what: str) -> bool:
        """FArchive serialises bool as int32 (Archive.h operator<<(bool&))."""
        return self.i32(what) != 0

    def guid(self, what: str) -> str:
        a, b, c, d = struct.unpack("<4I", self.take(16, what))
        return "%08X%08X%08X%08X" % (a, b, c, d)

    def fstring(self, what: str) -> str:
        """FString: int32 count; count > 0 -> ANSI, count < 0 -> UTF-16LE with
        -count units. The count INCLUDES the terminating NUL."""
        count = self.i32(what + ".len")
        if count == 0:
            return ""
        units = abs(count)
        if units > MAX_STRING_UNITS:
            raise ParseError("%s: %s claims %d units" % (self.name, what, count))
        if count > 0:
            raw = self.take(units, what)
            return raw[:-1].decode("utf-8", "replace") if raw[-1:] == b"\x00" else raw.decode("utf-8", "replace")
        raw = self.take(units * 2, what)
        text = raw.decode("utf-16-le", "replace")
        return text[:-1] if text.endswith("\x00") else text

    def fname_raw(self, what: str) -> tuple[int, int]:
        """FName in a package archive: int32 name-map index, int32 number
        (FLinkerLoad::operator<<(FName&))."""
        return self.i32(what + ".index"), self.i32(what + ".number")

    def engine_version(self, what: str) -> dict:
        major = struct.unpack("<H", self.take(2, what + ".major"))[0]
        minor = struct.unpack("<H", self.take(2, what + ".minor"))[0]
        patch = struct.unpack("<H", self.take(2, what + ".patch"))[0]
        changelist = self.u32(what + ".changelist")
        branch = self.fstring(what + ".branch")
        return {"major": major, "minor": minor, "patch": patch,
                "changelist": changelist, "branch": branch}


# --------------------------------------------------------------------------- #
# the summary
# --------------------------------------------------------------------------- #


def decode_package_flags(flags: int) -> list[str]:
    return [name for bit, name in PACKAGE_FLAGS if flags & bit]


def read_summary(data: bytes, path: str) -> dict:
    ar = ArchiveReader(data, os.path.basename(path))
    tag = ar.u32("Tag")
    if tag == PACKAGE_FILE_TAG_SWAPPED:
        raise ParseError("byte-swapped package (Tag %08X); this reader is little-endian only" % tag)
    if tag != PACKAGE_FILE_TAG:
        raise ParseError("not a UE package: Tag is %08X, expected %08X" % (tag, PACKAGE_FILE_TAG))

    legacy = ar.i32("LegacyFileVersion")
    if legacy >= 0 or legacy < CURRENT_LEGACY_FILE_VERSION:
        raise ParseError("LegacyFileVersion %d is outside the range this reader cites (S:107)" % legacy)

    out: dict = {"tag": "0x%08X" % tag, "legacy_file_version": legacy}
    if legacy != -4:
        out["legacy_ue3_version"] = ar.i32("LegacyUE3Version")
    file_version_ue4 = ar.i32("FileVersionUE4")
    file_version_ue5 = ar.i32("FileVersionUE5") if legacy <= -8 else 0
    file_version_licensee = ar.i32("FileVersionLicenseeUE4")

    custom_count = ar.i32("CustomVersions.count")
    if custom_count < 0 or custom_count > 4096:
        raise ParseError("CustomVersions count %d" % custom_count)
    custom_versions = []
    for _ in range(custom_count):
        key = ar.guid("CustomVersion.key")
        version = ar.i32("CustomVersion.version")
        custom_versions.append({"guid": key, "version": version})

    saved_unversioned = (file_version_ue4 == 0 and file_version_ue5 == 0
                         and file_version_licensee == 0)
    if saved_unversioned:
        # S:146-165: the loader substitutes the running engine's versions. We do
        # the same, and say so, because every conditional below depends on it.
        effective_ue4 = 522
        effective_ue5 = UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME
    else:
        effective_ue4 = file_version_ue4
        effective_ue5 = file_version_ue5

    if effective_ue4 < UE4_MODERN_MIN:
        raise ParseError("FileVersionUE4 %d is below the modern floor this reader accepts (%d)"
                         % (effective_ue4, UE4_MODERN_MIN))

    out.update({
        "file_version_ue4": file_version_ue4,
        "file_version_ue5": file_version_ue5,
        "file_version_licensee_ue4": file_version_licensee,
        "header_saved_unversioned": saved_unversioned,
        "effective_file_version_ue4": effective_ue4,
        "effective_file_version_ue5": effective_ue5,
        "effective_versions_assumed": saved_unversioned,
        "custom_version_count": custom_count,
        "custom_versions": custom_versions,
    })

    out["total_header_size"] = ar.i32("TotalHeaderSize")
    out["package_name"] = ar.fstring("PackageName")
    flags = ar.u32("PackageFlags")
    out["package_flags"] = "0x%08X" % flags
    out["package_flags_value"] = flags
    out["package_flags_decoded"] = decode_package_flags(flags)
    out["uses_unversioned_properties"] = bool(flags & PKG_UNVERSIONED_PROPERTIES)
    filter_editor_only = bool(flags & PKG_FILTER_EDITOR_ONLY)
    out["filter_editor_only"] = filter_editor_only

    out["name_count"] = ar.i32("NameCount")
    out["name_offset"] = ar.i32("NameOffset")
    if effective_ue5 >= UE5_ADD_SOFTOBJECTPATH_LIST:
        out["soft_object_paths_count"] = ar.i32("SoftObjectPathsCount")
        out["soft_object_paths_offset"] = ar.i32("SoftObjectPathsOffset")
    if not filter_editor_only:
        out["localization_id"] = ar.fstring("LocalizationId")
    out["gatherable_text_data_count"] = ar.i32("GatherableTextDataCount")
    out["gatherable_text_data_offset"] = ar.i32("GatherableTextDataOffset")
    out["export_count"] = ar.i32("ExportCount")
    out["export_offset"] = ar.i32("ExportOffset")
    out["import_count"] = ar.i32("ImportCount")
    out["import_offset"] = ar.i32("ImportOffset")
    out["depends_offset"] = ar.i32("DependsOffset")
    out["soft_package_references_count"] = ar.i32("SoftPackageReferencesCount")
    out["soft_package_references_offset"] = ar.i32("SoftPackageReferencesOffset")
    out["searchable_names_offset"] = ar.i32("SearchableNamesOffset")
    out["thumbnail_table_offset"] = ar.i32("ThumbnailTableOffset")
    out["guid"] = ar.guid("Guid")
    if not filter_editor_only:
        out["persistent_guid"] = ar.guid("PersistentGuid")
    generation_count = ar.i32("GenerationCount")
    if generation_count < 0 or generation_count > 4096:
        raise ParseError("GenerationCount %d" % generation_count)
    out["generations"] = [
        {"export_count": ar.i32("Generation.exports"), "name_count": ar.i32("Generation.names")}
        for _ in range(generation_count)
    ]
    out["saved_by_engine_version"] = ar.engine_version("SavedByEngineVersion")
    out["compatible_with_engine_version"] = ar.engine_version("CompatibleWithEngineVersion")
    out["compression_flags"] = ar.u32("CompressionFlags")
    compressed_chunks = ar.i32("CompressedChunks.count")
    if compressed_chunks != 0:
        raise ParseError("package-level compression is present (%d chunks); S:363 refuses these"
                         % compressed_chunks)
    out["package_source"] = ar.u32("PackageSource")
    additional = ar.i32("AdditionalPackagesToCook.count")
    if additional < 0 or additional > 4096:
        raise ParseError("AdditionalPackagesToCook count %d" % additional)
    for _ in range(additional):
        ar.fstring("AdditionalPackagesToCook.entry")
    out["additional_packages_to_cook_count"] = additional
    out["asset_registry_data_offset"] = ar.i32("AssetRegistryDataOffset")
    out["bulk_data_start_offset"] = ar.i64("BulkDataStartOffset")
    out["world_tile_info_data_offset"] = ar.i32("WorldTileInfoDataOffset")
    chunk_id_count = ar.i32("ChunkIDs.count")
    if chunk_id_count < 0 or chunk_id_count > 4096:
        raise ParseError("ChunkIDs count %d" % chunk_id_count)
    out["chunk_ids"] = [ar.i32("ChunkIDs.entry") for _ in range(chunk_id_count)]
    out["preload_dependency_count"] = ar.i32("PreloadDependencyCount")
    out["preload_dependency_offset"] = ar.i32("PreloadDependencyOffset")
    if effective_ue5 >= UE5_NAMES_REFERENCED_FROM_EXPORT_DATA:
        out["names_referenced_from_export_data_count"] = ar.i32("NamesReferencedFromExportDataCount")
    if effective_ue5 >= UE5_PAYLOAD_TOC:
        out["payload_toc_offset"] = ar.i64("PayloadTocOffset")
    if effective_ue5 >= UE5_DATA_RESOURCES:
        out["data_resource_offset"] = ar.i32("DataResourceOffset")
    out["summary_bytes_consumed"] = ar.pos
    return out


# --------------------------------------------------------------------------- #
# name map, import map, export map
# --------------------------------------------------------------------------- #


def read_name_map(data: bytes, summary: dict) -> list[str]:
    count = summary["name_count"]
    if count < 0 or count > MAX_NAMES:
        raise ParseError("NameCount %d" % count)
    if count == 0:
        return []
    ar = ArchiveReader(data, "names")
    ar.pos = summary["name_offset"]
    names = []
    for index in range(count):
        text = ar.fstring("Name[%d]" % index)
        ar.take(4, "Name[%d].hashes" % index)  # N:4085-4087, read and discarded
        names.append(text)
    return names


def resolve(names: list[str], index: int, number: int) -> str:
    if index < 0 or index >= len(names):
        return "<name %d out of range>" % index
    base = names[index]
    return base if number == 0 else "%s_%d" % (base, number - 1)


def read_import_map(data: bytes, summary: dict, names: list[str]) -> list[dict]:
    count = summary["import_count"]
    if count < 0 or count > MAX_IMPORTS:
        raise ParseError("ImportCount %d" % count)
    ar = ArchiveReader(data, "imports")
    ar.pos = summary["import_offset"]
    effective_ue5 = summary["effective_file_version_ue5"]
    out = []
    for index in range(count):
        class_package = resolve(names, *ar.fname_raw("Import[%d].ClassPackage" % index))
        class_name = resolve(names, *ar.fname_raw("Import[%d].ClassName" % index))
        outer_index = ar.i32("Import[%d].OuterIndex" % index)
        object_name = resolve(names, *ar.fname_raw("Import[%d].ObjectName" % index))
        entry = {"index": index, "class_package": class_package, "class_name": class_name,
                 "outer_index": outer_index, "object_name": object_name}
        if not summary["filter_editor_only"]:
            entry["package_name"] = resolve(names, *ar.fname_raw("Import[%d].PackageName" % index))
        if effective_ue5 >= UE5_OPTIONAL_RESOURCES:
            entry["import_optional"] = ar.boolean("Import[%d].bImportOptional" % index)
        out.append(entry)
    return out


def read_export_map(data: bytes, summary: dict, names: list[str]) -> list[dict]:
    count = summary["export_count"]
    if count < 0 or count > MAX_EXPORTS:
        raise ParseError("ExportCount %d" % count)
    ar = ArchiveReader(data, "exports")
    ar.pos = summary["export_offset"]
    effective_ue5 = summary["effective_file_version_ue5"]
    unversioned_properties = summary["uses_unversioned_properties"]
    out = []
    for index in range(count):
        start = ar.pos
        entry: dict = {"index": index}
        entry["class_index"] = ar.i32("Export[%d].ClassIndex" % index)
        entry["super_index"] = ar.i32("Export[%d].SuperIndex" % index)
        entry["template_index"] = ar.i32("Export[%d].TemplateIndex" % index)
        entry["outer_index"] = ar.i32("Export[%d].OuterIndex" % index)
        entry["object_name"] = resolve(names, *ar.fname_raw("Export[%d].ObjectName" % index))
        entry["object_flags"] = "0x%08X" % ar.u32("Export[%d].ObjectFlags" % index)
        entry["serial_size"] = ar.i64("Export[%d].SerialSize" % index)
        entry["serial_offset"] = ar.i64("Export[%d].SerialOffset" % index)
        entry["forced_export"] = ar.boolean("Export[%d].bForcedExport" % index)
        entry["not_for_client"] = ar.boolean("Export[%d].bNotForClient" % index)
        entry["not_for_server"] = ar.boolean("Export[%d].bNotForServer" % index)
        if effective_ue5 >= UE5_TRACK_OBJECT_EXPORT_IS_INHERITED:
            entry["is_inherited_instance"] = ar.boolean("Export[%d].bIsInheritedInstance" % index)
        entry["package_flags"] = "0x%08X" % ar.u32("Export[%d].PackageFlags" % index)
        entry["not_always_loaded_for_editor_game"] = ar.boolean(
            "Export[%d].bNotAlwaysLoadedForEditorGame" % index)
        entry["is_asset"] = ar.boolean("Export[%d].bIsAsset" % index)
        if effective_ue5 >= UE5_OPTIONAL_RESOURCES:
            entry["generate_public_hash"] = ar.boolean("Export[%d].bGeneratePublicHash" % index)
        entry["first_export_dependency"] = ar.i32("Export[%d].FirstExportDependency" % index)
        entry["serialization_before_serialization_dependencies"] = ar.i32(
            "Export[%d].SerBeforeSer" % index)
        entry["create_before_serialization_dependencies"] = ar.i32("Export[%d].CreBeforeSer" % index)
        entry["serialization_before_create_dependencies"] = ar.i32("Export[%d].SerBeforeCre" % index)
        entry["create_before_create_dependencies"] = ar.i32("Export[%d].CreBeforeCre" % index)
        if not unversioned_properties and effective_ue5 >= UE5_SCRIPT_SERIALIZATION_OFFSET:
            # R:208-212. Present ONLY for versioned property serialization.
            entry["script_serialization_start_offset"] = ar.i64("Export[%d].ScriptStart" % index)
            entry["script_serialization_end_offset"] = ar.i64("Export[%d].ScriptEnd" % index)
        entry["entry_bytes"] = ar.pos - start
        out.append(entry)
    return out


# --------------------------------------------------------------------------- #
# the payload probe: which of the two shapes is actually there
# --------------------------------------------------------------------------- #


def decode_unversioned_header(blob: bytes) -> dict:
    """U:529-556 and U:569-598. Fragments are uint16 until bIsLast."""
    ar = ArchiveReader(blob, "unversioned-header")
    fragments = []
    zero_mask_num = 0
    unmasked_num = 0
    schema_index = 0
    covered = []
    while True:
        if len(fragments) >= MAX_FRAGMENTS:
            raise ParseError("more than %d fragments" % MAX_FRAGMENTS)
        packed = ar.u16("fragment[%d]" % len(fragments))
        skip_num = packed & FRAG_SKIP_NUM_MASK
        has_zeroes = bool(packed & FRAG_HAS_ZERO_MASK)
        value_num = packed >> FRAG_VALUE_NUM_SHIFT
        is_last = bool(packed & FRAG_IS_LAST_MASK)
        fragments.append({"packed": "0x%04X" % packed, "skip_num": skip_num,
                          "has_any_zeroes": has_zeroes, "value_num": value_num,
                          "is_last": is_last})
        schema_index += skip_num
        if value_num:
            covered.append([schema_index, schema_index + value_num - 1])
            schema_index += value_num
        if has_zeroes:
            zero_mask_num += value_num
        else:
            unmasked_num += value_num
        if is_last:
            break
    return {
        "fragment_count": len(fragments),
        "fragments": fragments,
        "header_bytes": ar.pos,
        "zero_mask_value_count": zero_mask_num,
        "unmasked_value_count": unmasked_num,
        "schema_indices_touched": covered,
        "highest_schema_index_touched": max((rng[1] for rng in covered), default=-1),
    }


def probe_export_payload(export_data: bytes, base_offset: int, entry: dict,
                         names: list[str], unversioned: bool) -> dict:
    """Read the first bytes of one export's serialised data and report what shape
    they are. Bounded to PROBE_BYTES for the raw sample."""
    start = entry["serial_offset"] - base_offset
    size = entry["serial_size"]
    probe: dict = {"index": entry["index"], "object_name": entry["object_name"],
                   "serial_size": size, "payload_available": False}
    if start < 0 or size < 0 or start + min(size, PROBE_BYTES) > len(export_data):
        probe["note"] = "payload outside the supplied export data"
        return probe
    probe["payload_available"] = True
    head = export_data[start:start + min(size, PROBE_BYTES)]
    probe["first_bytes_hex"] = head.hex()
    if unversioned:
        try:
            probe["unversioned_header"] = decode_unversioned_header(
                export_data[start:start + min(size, 1024)])
            probe["shape"] = "unversioned-fragments"
        except ParseError as exc:
            probe["shape"] = "undecodable"
            probe["error"] = str(exc)
    else:
        # T:436: the first field of the first FPropertyTag is its FName.
        if size >= 8:
            index, number = struct.unpack_from("<ii", export_data, start)
            probe["first_property_tag_name"] = resolve(names, index, number)
            probe["first_property_tag_name_index"] = index
            probe["shape"] = "versioned-tagged-properties"
        else:
            probe["shape"] = "empty"
    return probe


# --------------------------------------------------------------------------- #
# literal layer
# --------------------------------------------------------------------------- #


def relative_target(path: str) -> str:
    """A target string with no drive letter and no leading separator.

    ``kb-record.schema.json#/$defs/read_locus`` refuses both, because an absolute
    path on this machine can carry a user profile (C-13). Dropping the drive keeps
    the string informative and compliant.
    """
    normal = path.replace("\\", "/")
    if len(normal) > 2 and normal[1] == ":":
        normal = normal[2:]
    return normal.lstrip("/")


def literal_read(path: str, offset: int, length: int, what: str) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    The ``claim`` sentence states the offset AND the length and stops there; it
    does not name what the bytes are, which is what keeps it in class P
    (plan.md 10.3 v2.4). The grading envelope follows
    ``kb-record.schema.json#/$defs/annotation``: the enclosing document states the
    build and the claim type once, so this sub-object carries neither. The
    per-source ``oracle`` key is deliberately absent -- it is legal in the schema
    and makes the validator read each source object as a whole record.
    """
    with open(path, "rb") as handle:
        handle.seek(offset)
        first = handle.read(length)
    with open(path, "rb") as handle:  # fresh handle, second read
        handle.seek(offset)
        second = handle.read(length)
    target = relative_target(path)
    locator = "%s@%d+%d" % (target, offset, length)
    return {
        "target": what,
        "offset": offset,
        "length": length,
        "bytes_hex": first.hex(),
        "reproduced": first == second,
        "claim": "the %d bytes at offset %d of %s are %s"
                 % (length, offset, target, first.hex() or "<none>"),
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["filesystem"],
            "read_locus": {"target": target, "address_kind": "file-offset",
                           "offset": offset, "length": length},
            "sources": [
                {"method": "%s read at a determinate offset" % TOOL,
                 "artifact": None, "locator": locator,
                 "note": "first read, through the handle opened for parsing"},
                {"method": "second read through a freshly opened handle",
                 "artifact": None, "locator": locator,
                 "note": "method re-run and result reproduced: %s"
                         % ("yes" if first == second else "NO")},
            ],
            "note": "the claim states offset and length only. If this were wrong -- if the "
                    "bytes were not stable -- the second read through a fresh handle would "
                    "differ, and 'reproduced' would be false.",
        },
    }


# --------------------------------------------------------------------------- #
# one package
# --------------------------------------------------------------------------- #


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def guard(path: str) -> None:
    """Refuse anything inside a MISERY installation.

    The game's cooked packages live inside an encrypted container, so a "reader"
    pointed at one would half-parse ciphertext and report confident nonsense.
    Both halves of pathguard's answer are used: ``structural_install_roots``
    recognises an installation from the path itself (marker files, no
    configuration needed), and ``known_install_roots`` covers the roots this
    machine has recorded. When pathguard cannot be imported the refusal cannot be
    enforced, and that is stated rather than silently skipped.
    """
    if pathguard is None:
        sys.stderr.write("%s: WARNING pathguard is not importable; the "
                         "install-refusal cannot be enforced for %s\n" % (TOOL, path))
        return
    roots = list(pathguard.structural_install_roots(path))
    roots += [value for _source, value in pathguard.known_install_roots()]
    for root in roots:
        try:
            inside = pathguard.is_inside(path, root)
        except Exception:
            continue
        if inside:
            raise SystemExit(
                "%s: refused -- %s is inside the MISERY installation at %s. The game's "
                "cooked packages are inside an encrypted container (D-02); this reader "
                "only reads packages our own cooker produced." % (TOOL, path, root))


def read_package(path: str, uexp_path: str | None = None, probe_limit: int = 16) -> dict:
    guard(path)
    with open(path, "rb") as handle:
        data = handle.read()
    report: dict = {
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "generated_at": now_iso_utc(),
        "engine_tree": ENGINE_TREE,
        "engine_changelist": ENGINE_CHANGELIST,
        "file": {"path": path.replace("\\", "/"), "size": len(data),
                 "sha256": sha256_file(path)},
        "literal_reads": [literal_read(path, 0, 8, "package header first 8 bytes")],
    }
    summary = read_summary(data, path)
    report["summary"] = summary
    names = read_name_map(data, summary)
    report["names"] = {"count": len(names), "entries": names}
    report["imports"] = read_import_map(data, summary, names)
    exports = read_export_map(data, summary, names)
    report["exports"] = exports

    # The stride check has to be INDEPENDENT of the flag, or it checks nothing:
    # read_export_map() already used the flag to decide whether to read the two
    # ScriptSerialization int64s, so `entry_bytes` can only ever come back as the
    # width the flag implied. The independent measurement uses the summary's own
    # offsets: the export map runs from ExportOffset to DependsOffset (the writer
    # order in FLinkerSave), so its total width divided by ExportCount is a stride
    # nobody derived from the flag.
    strides = sorted({entry["entry_bytes"] for entry in exports})
    expected = (EXPORT_ENTRY_SIZE_UNVERSIONED_PROPERTIES if summary["uses_unversioned_properties"]
                else EXPORT_ENTRY_SIZE_VERSIONED_PROPERTIES)
    span = summary["depends_offset"] - summary["export_offset"]
    count = summary["export_count"]
    measured = None
    if count > 0 and span > 0 and span % count == 0:
        measured = span // count
    report["export_entry_stride"] = {
        "observed": strides,
        "observed_note": "width consumed while parsing; by construction it follows the flag",
        "measured_from_summary_offsets": measured,
        "measured_note": "(DependsOffset - ExportOffset) / ExportCount, computed without "
                         "reference to PKG_UnversionedProperties",
        "export_map_span_bytes": span,
        "expected_from_package_flag": expected,
        "agrees_with_package_flag": measured == expected,
        "parse_consumed_expected_width": strides in ([], [expected]),
    }
    stride_ok = report["export_entry_stride"]["agrees_with_package_flag"]

    if uexp_path is None:
        candidate = os.path.splitext(path)[0] + ".uexp"
        uexp_path = candidate if os.path.exists(candidate) else None
    if uexp_path:
        guard(uexp_path)
        with open(uexp_path, "rb") as handle:
            export_data = handle.read()
        report["uexp"] = {"path": uexp_path.replace("\\", "/"), "size": len(export_data),
                          "sha256": sha256_file(uexp_path)}
        base = len(data)
        report["uexp"]["base_offset_used"] = base
        report["uexp"]["base_offset_equals_total_header_size"] = (base == summary["total_header_size"])
        if not stride_ok:
            report["probes"] = {"skipped": "export map stride disagrees with the package flag"}
        else:
            probes = [probe_export_payload(export_data, base, entry, names,
                                          summary["uses_unversioned_properties"])
                      for entry in exports[:probe_limit]]
            report["probes"] = {"exports_probed": len(probes), "entries": probes}
    else:
        report["probes"] = {"skipped": "no .uexp beside the package"}
    report["decoded_layer_evidence"] = {
        "evidence_level": "OBSERVED",
        "claim_class": "I",
        "confidence": CONFIDENCE_DECODED,
        "oracle": ["filesystem", "external-doc"],
        "read_locus": None,
        "sources": [
            {"method": "%s field-by-field decode of the package header" % TOOL,
             "artifact": None, "locator": relative_target(path),
             "note": "every field name, gate and mask is a citation into the UE 5.4.4 "
                     "tree at changelist %d" % ENGINE_CHANGELIST},
            {"method": "export-map width measured from the summary offsets alone",
             "artifact": None, "locator": relative_target(path),
             "note": "(DependsOffset - ExportOffset) / ExportCount, computed without "
                     "reference to the package flag it is used to check"},
        ],
        "note": "grades the decoded layer of this report, not any single claim in it. If "
                "the layout assumption were wrong the two methods would disagree: the "
                "measured export-map width would not equal the width the package flag "
                "implies, and the report says so per file.",
    }
    return report


def compare_packages(left: dict, right: dict) -> dict:
    """Structural diff of two package reports: what the one setting changed."""
    ls, rs = left["summary"], right["summary"]
    keys = sorted(set(ls) | set(rs))
    summary_diff = {}
    for key in keys:
        if key in ("guid", "persistent_guid"):
            continue
        lv, rv = ls.get(key, "<absent>"), rs.get(key, "<absent>")
        if lv != rv:
            summary_diff[key] = {"left": lv, "right": rv}
    left_names, right_names = set(left["names"]["entries"]), set(right["names"]["entries"])
    return {
        "left": left["file"]["path"],
        "right": right["file"]["path"],
        "identical_uasset_sha256": left["file"]["sha256"] == right["file"]["sha256"],
        "identical_uexp_sha256": (left.get("uexp", {}).get("sha256")
                                  == right.get("uexp", {}).get("sha256")),
        "uasset_size": {"left": left["file"]["size"], "right": right["file"]["size"]},
        "uexp_size": {"left": left.get("uexp", {}).get("size"),
                      "right": right.get("uexp", {}).get("size")},
        "summary_field_differences": summary_diff,
        "name_count": {"left": left["names"]["count"], "right": right["names"]["count"]},
        "names_only_in_left": sorted(left_names - right_names),
        "names_only_in_right": sorted(right_names - left_names),
        "export_entry_stride": {
            "left": left["export_entry_stride"]["measured_from_summary_offsets"],
            "right": right["export_entry_stride"]["measured_from_summary_offsets"],
            "method": "(DependsOffset - ExportOffset) / ExportCount",
        },
        "export_shape": {
            "left": sorted({p.get("shape") for p in left.get("probes", {}).get("entries", [])
                            if p.get("shape")}),
            "right": sorted({p.get("shape") for p in right.get("probes", {}).get("entries", [])
                             if p.get("shape")}),
        },
    }


def emit(payload: dict, out_path: str | None, as_json: bool) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    if as_json or not out_path:
        sys.stdout.write(text)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("package", help="cooked .uasset or .umap produced by our own cooker")
    parser.add_argument("--uexp", help="explicit path to the matching .uexp")
    parser.add_argument("--compare", help="a second package to diff against")
    parser.add_argument("--compare-uexp", help="explicit .uexp for --compare")
    parser.add_argument("--probe-limit", type=int, default=16,
                        help="how many exports to probe (default 16)")
    parser.add_argument("--out", help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="also print JSON to stdout")
    args = parser.parse_args(argv)

    try:
        report = read_package(args.package, args.uexp, args.probe_limit)
        if args.compare:
            other = read_package(args.compare, args.compare_uexp, args.probe_limit)
            report = {"tool": TOOL, "tool_version": TOOL_VERSION,
                      "generated_at": now_iso_utc(),
                      "comparison": compare_packages(report, other),
                      "left_report": report, "right_report": other}
    except (ParseError, OSError) as exc:
        sys.stderr.write("%s: %s\n" % (TOOL, exc))
        return 2
    emit(report, args.out, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
