#!/usr/bin/env python3
"""Read-only scanner for characteristic engine constants in a PE (plan.md task S-08).

The question this tool exists to answer
---------------------------------------
plan.md line 571 (task S-08) asks for the *characteristic constants* of a PE
image: serialization version numbers, hash-function tables and seeds, container
magics -- with, for every hit, the offset, the length, the raw bytes and what it
was matched against. The point is not any single number. The point is that a
constant is the one kind of evidence a compiler cannot dissolve: an inlined
function disappears, a symbol name disappears, a class layout is only inferable
-- but a 8192-byte lookup table has to be in the image, byte for byte, or the
code that indexes it does not work.

Why this tool does not carry a hand-written list of constants
------------------------------------------------------------
Because a hand-written list is a list of *guesses about* the engine, and the
first-party UE 5.4.4 source tree at the game's own changelist is on this machine
(research/unreal/engine-version.json, Engine/Build/Build.version declaring
Changelist 35576357, branch ++UE5+Release-5.4). So every pattern this tool looks
for is READ OUT OF THAT TREE at run time and carries the file, the line and the
source text it came from. Nothing is hard-coded except *where to look* and *how
to parse what is there*:

* ``SCALAR_LOCI`` names a file and a regular expression, never a value. The
  value, and the line number it was found on, are results.
* ``TABLE_LOCI`` names the declaration of a ``uint32`` table; the initialiser
  is parsed out of the file and packed little-endian, so the pattern IS the
  engine's table, not a reimplementation of the algorithm that made it.
* the custom-version GUIDs are found by walking the tree for ``FGuid`` literals
  and for the ``FCustomVersionRegistration`` / ``FDevVersionRegistration``
  statements that register them, then joining the two. The join is reported with
  its failures (``registrations_unresolved``), never silently completed.

The consequence to keep in mind while reading the output: the catalogue is a
statement about the SOURCE TREE (oracles ``external-doc`` for what the code says
and ``filesystem`` for the fact that the file on disk holds that text), and the
occurrence list is a statement about the IMAGE (oracle ``binary-analysis``).
Those are two different measurements and they are kept in two different places.

What finding a constant proves, and what it does not
----------------------------------------------------
Stated per family in ``PROVES`` / ``DOES_NOT_PROVE`` on every catalogue entry, and
repeated here because it is the whole discipline of this task:

* A magic or a version number present in the image proves that a constant equal
  to it is stored, or encoded as an immediate, at a determinate offset. Combined
  with the source citation it makes it very likely that the code which
  references that constant was LINKED IN. It does not prove that code runs, that
  the game ever takes that path, or that the value is used the way the source
  uses it. A dead branch keeps its constants.
* A hash TABLE present in the image is a much stronger anchor than a scalar,
  for a mechanical reason: a table of 2048 words cannot be constant-folded,
  cannot be re-derived at compile time by MSVC from the initialiser list, and
  cannot be shared with an unrelated table by accident. It gives M3 an address
  to hang the reflection work on. It still does not prove the hash is used for
  FName rather than for something else in the same module.
* An ABSENT constant proves nothing on its own. It may have been folded into an
  immediate in a form this tool does not search (a 64-bit constant materialised
  as two 32-bit halves, a value reached by arithmetic), the referencing module
  may not be linked, or the surface searched may not include it. Every null
  result here is a statement about the named surface printed in
  ``measurement.searched_surface`` and about the exact byte pattern printed in
  ``constants[].bytes_hex`` -- never about "the file".
* A constant that a family declares as EDITOR-ONLY and that is nevertheless
  present is the interesting case, and it is a refutation probe rather than a
  conclusion: it may mean the module was linked into a non-Shipping target, or
  it may mean the same 16 bytes are declared somewhere else too. D-04 forbids
  concluding a build configuration from this, so the probe reports and stops.

Low-entropy constants are NOT searched, on purpose
--------------------------------------------------
``EIoStoreTocVersion::Latest`` is 6 and ``PakFile_Version_Latest`` is 11. The
four bytes ``06000000`` occur tens of thousands of times in any 134 MB image, so
"found" and "not found" would both be uninformative and the offsets would be
noise. Such entries stay in the catalogue with ``searched: false`` and a stated
reason, because the *value derived from the source* is itself a result worth
recording -- it is what the container work of F-02/V-05 compares its readings
against. The version numbers that ARE searched are searched as a SHAPE: the
eight-byte ``(VER_UE4_AUTOMATIC_VERSION, EUnrealEngineObjectUE5Version)`` pair,
which is what the engine actually stores, exactly as V-06 did for one value --
generalised here to enumerate every UE5 value that occurs next to the UE4
anchor, which is what makes the neighbour exclusion checkable instead of
assumed.

Relation to V-01..V-07 (asked explicitly by M2s, answered explicitly here)
--------------------------------------------------------------------------
``engine_version_crosscheck`` in the output states, field by field, whether each
reading is a NEW measurement act or a re-reading of one V-01..V-07 already
performed. The honest summary, which the document repeats rather than hides:

* the custom-version GUID census, the CRC tables, PACKAGE_FILE_TAG and the hash
  seeds are byte ranges never read before in this project, from a surface
  (initialised data matched against the first-party tree) no V-method used --
  NEW measurement acts;
* the ``(522, 1012)`` pair is V-06's own datum at V-06's own offset. Finding it
  again is a RE-READING, not an independent confirmation, and it is labelled so.
  What is new about it is only the mechanism: the scan enumerates every UE5
  value adjacent to the UE4 anchor instead of testing one.

Determinism
-----------
Standard library only, streaming reads, nothing written near the target, output
JSON with sorted keys and LF endings. Two runs on the same input produce
byte-identical output except ``generated_at`` and ``timings_seconds``. The
catalogue can be written with ``--catalogue-out`` and reused with
``--catalogue-in`` so that a second run does not re-walk 850 MB of source; a
reused catalogue is recorded as such in the document.

Safety
------
Read-only with respect to the game (D-01): every output path goes through
tools/inventory/pathguard.py before anything is opened. No container is
decrypted and none is opened at all (D-02 is not even approached: this tool
reads PE images and text files). The 282 MB ``MISERY/Binaries/Win64/MISERY.exe``
is flagged as the D-04 read-only oracle when it is the target, and no conclusion
about its build configuration is drawn here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented (see tools/inventory/pathguard.py).
import pathguard  # noqa: E402

# The PE layer is F-01's. Re-deriving section tables and RVA translation here
# would give this tool a second, differently-buggy opinion about where .rdata is.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/find_constants.py"
GENERATOR_VERSION = "1.0.0"
SCHEMA_ID = "misery.find-constants/1"
TASK = "S-08"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits. Every one of these bounds a quantity that comes from a FILE --
# either the target image or the source tree -- and must therefore never be
# believed.
# --------------------------------------------------------------------------- #

SCAN_CHUNK = 8 << 20              # streaming window for the image search
MAX_PATTERN_BYTES = 1 << 16       # longest needle we will carry
MAX_OCCURRENCES_PER_PATTERN = 4096
MAX_RECORDED_OFFSETS = 64         # per constant, in the interpreted layer
MAX_PATTERNS = 4096
UE_SOURCE_SUFFIXES = (".h", ".cpp", ".inl", ".hpp", ".cc")
UE_SOURCE_MAX_FILE = 8 << 20
UE_SOURCE_SKIP_DIRS = (".git", "Intermediate", "Binaries", "DerivedDataCache")
MAX_TABLE_WORDS = 1 << 14         # 16384 uint32 = 64 KiB, far above any UE table
MAX_ENUM_ENTRIES = 4096
DEFAULT_LITERAL_SAMPLES = 8
CONTROL_PATTERN_COUNT = 8

# The band of plausible EUnrealEngineObjectUE5Version values for the pair-shape
# scan. Identical in intent to engine_version.py's band and stated here as a
# SEARCH WINDOW, not as knowledge: a value outside it is reported as "no
# candidate at this offset" rather than silently dropped.
UE5_OBJECT_VERSION_MIN = 1000
UE5_OBJECT_VERSION_MAX = 1100

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED_CORROBORATED = 0.85
CONFIDENCE_DECODED_SINGLE_METHOD = 0.79

# plan.md 10.3 class-P criterion 2 is mandatory for the whole 0.80-0.99 band and
# tools/kb/validate.py checks that the record SAYS the method was re-run. A
# record may only say it if it is true, so every literal read really is
# performed twice -- see confirm_literal_reads.
RERUN_CONFIRMED = (
    "Method re-run and reproduced within this run: every range in this group was read "
    "a second time through a second, independently opened file handle and the two "
    "reads agree byte for byte. The limit of that attestation, stated plainly: it is a "
    "re-read of the same file on the same machine, so it catches a transient read, a "
    "seek error and a bookkeeping mistake -- it does not catch reading the wrong file."
)
RERUN_NOT_CONFIRMED = (
    "Method NOT reproduced: the second read of this range disagreed with the first, or "
    "could not be performed. plan.md 10.3 criterion 2 is therefore unmet and this "
    "reading must not be relied on until it is explained."
)


class DerivationError(Exception):
    """A locus named in SCALAR_LOCI / TABLE_LOCI could not be read from the tree."""


# --------------------------------------------------------------------------- #
# families. One string per family, because the summary, the JSONL artifact and
# the refutation probes all group by it and a typo must not silently create a
# thirteenth family.
# --------------------------------------------------------------------------- #

FAMILY_PACKAGE_TAG = "package-file-tag"
FAMILY_OBJECT_VERSION = "object-version-enumerator"
FAMILY_CUSTOM_VERSION_GUID = "custom-version-guid"
FAMILY_CUSTOM_VERSION_NAME = "custom-version-friendly-name"
FAMILY_GUID_LITERAL = "guid-literal"
FAMILY_CONTAINER_MAGIC = "container-magic"
FAMILY_CONTAINER_VERSION = "container-version-enumerator"
FAMILY_HASH_SEED = "hash-seed"
FAMILY_HASH_TABLE = "hash-table"
FAMILY_CONTROL = "synthetic-control"

FAMILY_ORDER = (
    FAMILY_PACKAGE_TAG,
    FAMILY_OBJECT_VERSION,
    FAMILY_CUSTOM_VERSION_GUID,
    FAMILY_CUSTOM_VERSION_NAME,
    FAMILY_GUID_LITERAL,
    FAMILY_CONTAINER_MAGIC,
    FAMILY_CONTAINER_VERSION,
    FAMILY_HASH_SEED,
    FAMILY_HASH_TABLE,
    FAMILY_CONTROL,
)

# What a hit in each family would prove, and what it would not. Attached to
# every catalogue entry so the interpretation travels with the number instead of
# living only in a document that can drift from it.
PROVES: dict[str, str] = {
    FAMILY_PACKAGE_TAG: (
        "that the four-byte package-file tag the engine compares every .uasset "
        "header against is stored, or materialised as an immediate, at this offset; "
        "with the source citation, that the package-loading code path was linked in"),
    FAMILY_OBJECT_VERSION: (
        "that the serialization version pair the engine stamps into every package it "
        "writes is present as initialised data, which names one UE minor line"),
    FAMILY_CUSTOM_VERSION_GUID: (
        "that the sixteen-byte key of one FCustomVersion is stored at this offset, "
        "hence that the module which registers that custom version was linked in"),
    FAMILY_CUSTOM_VERSION_NAME: (
        "that the friendly-name string literal of one FCustomVersionRegistration is "
        "present as UTF-16LE text; a SECOND byte range, independent of the GUID"),
    FAMILY_GUID_LITERAL: (
        "that a sixteen-byte GUID the engine source declares as a literal is stored "
        "at this offset"),
    FAMILY_CONTAINER_MAGIC: (
        "that the container magic is present in the image, hence that the reader or "
        "writer which compares against it was linked in"),
    FAMILY_CONTAINER_VERSION: (
        "nothing by itself -- these values are derived from the source only, to give "
        "the container readings of F-02/V-05 a cited reference to compare against"),
    FAMILY_HASH_SEED: (
        "that the seed or multiplier of a named hash function is present as a "
        "constant; two constants of the same algorithm present together make an "
        "accidental match implausible"),
    FAMILY_HASH_TABLE: (
        "that the engine's lookup table is present in full at this offset. A table "
        "cannot be constant-folded or inlined away, so this is an ANCHOR: an address "
        "the M3 reflection work can start from"),
    FAMILY_CONTROL: (
        "nothing about the game. These patterns exist to measure this tool's "
        "false-positive rate and MUST be absent"),
}

DOES_NOT_PROVE: dict[str, str] = {
    FAMILY_PACKAGE_TAG: (
        "that any package is ever loaded at run time, nor which of the several code "
        "paths that compare against the tag is reached"),
    FAMILY_OBJECT_VERSION: (
        "that the engine is unmodified, nor that a custom build did not backport a "
        "later serializer while leaving this pair alone"),
    FAMILY_CUSTOM_VERSION_GUID: (
        "that the custom version is ever used, that the asset data in this build "
        "carries it, nor -- without a reference tree for the NEIGHBOURING releases -- "
        "that the GUID is specific to UE 5.4"),
    FAMILY_CUSTOM_VERSION_NAME: (
        "that the registration statement runs; a string literal survives in the image "
        "whether or not its static initialiser is reached"),
    FAMILY_GUID_LITERAL: (
        "what the GUID is for. Many of these are derived-data cache keys and plugin "
        "identities, not serialization versions"),
    FAMILY_CONTAINER_MAGIC: (
        "that a container of that kind is shipped with this build, nor that the code "
        "path runs. The containers themselves are F-02's surface, not this one"),
    FAMILY_CONTAINER_VERSION: "anything about this image at all -- they are not searched for",
    FAMILY_HASH_SEED: (
        "which caller uses the hash. The FNV and CityHash constants are also present "
        "in third-party code vendored into the engine tree, so a hit does not single "
        "out the engine's own call site"),
    FAMILY_HASH_TABLE: (
        "that the table is used for any particular purpose, nor which of the several "
        "FCrc entry points is reached"),
    FAMILY_CONTROL: "anything at all",
}


# --------------------------------------------------------------------------- #
# WHERE to look in the source tree. Not WHAT the value is: every entry names a
# file and a regular expression, and the value plus the line number are results.
#
# `path` is relative to --ue-source-root, which is the ENGINE directory (the one
# holding Build/Build.version, Source/ and Plugins/) -- the same convention
# rtti_scan.py uses for --ue-source-root.
# --------------------------------------------------------------------------- #

OBJECT_VERSION_H = "Source/Runtime/Core/Public/UObject/ObjectVersion.h"
PAK_H = "Source/Runtime/PakFile/Public/IPlatformFilePak.h"
IOSTORE_H = "Source/Runtime/Core/Internal/IO/IoStore.h"
CRC_CPP = "Source/Runtime/Core/Private/Misc/Crc.cpp"
FNV_CPP = "Source/Runtime/Core/Private/Misc/Fnv.cpp"
CITYHASH_CPP = "Source/Runtime/Core/Private/Hash/CityHash.cpp"
CITYHASH_H = "Source/Runtime/Core/Public/Hash/CityHash.h"
UNREALNAMES_CPP = "Source/Runtime/Core/Private/UObject/UnrealNames.cpp"

# kind == "define"   : regex must expose group "value" as a C integer literal
# kind == "literal"  : same, for any assignment or initialiser
# kind == "enum"     : `enum_anchor` locates the enum, `enumerator` names the entry
# kind == "ascii"    : regex must expose group "value" as the contents of a
#                      double-quoted C string literal
SCALAR_LOCI: tuple[dict, ...] = (
    {
        "id": "package_file_tag",
        "family": FAMILY_PACKAGE_TAG,
        "name": "PACKAGE_FILE_TAG",
        "path": OBJECT_VERSION_H,
        "kind": "define",
        "regex": r"^#define\s+PACKAGE_FILE_TAG\s+(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 4,
        "searched": True,
        "role": "the tag every FPackageFileSummary is checked against",
    },
    {
        "id": "package_file_tag_swapped",
        "family": FAMILY_PACKAGE_TAG,
        "name": "PACKAGE_FILE_TAG_SWAPPED",
        "path": OBJECT_VERSION_H,
        "kind": "define",
        "regex": r"^#define\s+PACKAGE_FILE_TAG_SWAPPED\s+(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 4,
        "searched": True,
        "role": "the byte-swapped form, compared when a package comes from the other endianness",
    },
    {
        "id": "ue4_object_version_automatic",
        "family": FAMILY_OBJECT_VERSION,
        "name": "EUnrealEngineObjectUE4Version::VER_UE4_AUTOMATIC_VERSION",
        "path": OBJECT_VERSION_H,
        "kind": "enum",
        "enum_name": "EUnrealEngineObjectUE4Version",
        "enumerator": "VER_UE4_AUTOMATIC_VERSION",
        "width": 4,
        "searched": False,
        "not_searched_reason": (
            "a bare four-byte integer of this magnitude occurs by construction "
            "throughout any image; it is searched only as the first half of the "
            "eight-byte FPackageFileVersion pair shape, see measurement."
            "version_pair_shape"),
        "role": "the UE4 half of FPackageFileVersion, frozen for the whole of UE5",
    },
    {
        "id": "ue4_oldest_loadable_package",
        "family": FAMILY_OBJECT_VERSION,
        "name": "EUnrealEngineObjectUE4Version::VER_UE4_OLDEST_LOADABLE_PACKAGE",
        "path": OBJECT_VERSION_H,
        "kind": "enum",
        "enum_name": "EUnrealEngineObjectUE4Version",
        "enumerator": "VER_UE4_OLDEST_LOADABLE_PACKAGE",
        "width": 4,
        "searched": False,
        "not_searched_reason": (
            "not searched for; PREDICTED. It is the refutation attempt of the pair "
            "shape: the eight bytes after GPackageFileUEVersion must read "
            "(this value, 0), because GOldestLoadablePackageFileUEVersion is "
            "declared immediately after it and CreateUE4Version leaves the UE5 half "
            "zero"),
        "role": "the neighbour prediction that makes the pair shape falsifiable",
    },
    {
        "id": "ue5_object_version_initial",
        "family": FAMILY_OBJECT_VERSION,
        "name": "EUnrealEngineObjectUE5Version::INITIAL_VERSION",
        "path": OBJECT_VERSION_H,
        "kind": "enum",
        "enum_name": "EUnrealEngineObjectUE5Version",
        "enumerator": "INITIAL_VERSION",
        "width": 4,
        "searched": False,
        "not_searched_reason": "low-entropy scalar; see ue4_object_version_automatic",
        "role": "the floor of the UE5 serialization version band",
    },
    {
        "id": "ue5_object_version_automatic",
        "family": FAMILY_OBJECT_VERSION,
        "name": "EUnrealEngineObjectUE5Version::AUTOMATIC_VERSION",
        "path": OBJECT_VERSION_H,
        "kind": "enum",
        "enum_name": "EUnrealEngineObjectUE5Version",
        "enumerator": "AUTOMATIC_VERSION",
        "width": 4,
        "searched": False,
        "not_searched_reason": "low-entropy scalar; see ue4_object_version_automatic",
        "role": "the value a package written by THIS engine tree would carry",
    },
    {
        "id": "pak_file_magic",
        "family": FAMILY_CONTAINER_MAGIC,
        "name": "FPakInfo::PakFile_Magic",
        "path": PAK_H,
        "kind": "literal",
        "regex": r"PakFile_Magic\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 4,
        "searched": True,
        "role": "the trailing magic of every .pak footer",
    },
    {
        "id": "pak_version_latest",
        "family": FAMILY_CONTAINER_VERSION,
        "name": "FPakInfo::PakFile_Version_Latest",
        "path": PAK_H,
        "kind": "enum",
        "enum_anchor": r"PakFile_Version_Initial\s*=\s*1",
        "enumerator": "PakFile_Version_Latest",
        "width": 4,
        "searched": False,
        "not_searched_reason": (
            "a single-digit integer; searching for it would return noise. Derived "
            "here so that the pak version F-02 reads out of the footer has a cited "
            "reference"),
        "role": "the pak version this engine tree writes",
    },
    {
        "id": "iostore_toc_magic",
        "family": FAMILY_CONTAINER_MAGIC,
        "name": "FIoStoreTocHeader::TocMagicImg",
        "path": IOSTORE_H,
        "kind": "ascii",
        "regex": r"TocMagicImg\[\]\s*=\s*\"(?P<value>[^\"]+)\"",
        "searched": True,
        "role": "the sixteen-byte magic at the head of every .utoc",
    },
    {
        "id": "iostore_toc_version_latest",
        "family": FAMILY_CONTAINER_VERSION,
        "name": "EIoStoreTocVersion::Latest",
        "path": IOSTORE_H,
        "kind": "enum",
        "enum_name": "EIoStoreTocVersion",
        "enumerator": "Latest",
        "width": 4,
        "searched": False,
        "not_searched_reason": "a single-digit integer; see pak_version_latest",
        "role": "the .utoc version this engine tree writes",
    },
    {
        "id": "fnv32_offset_basis",
        "family": FAMILY_HASH_SEED,
        "name": "FFnv::MemFnv32 offset basis",
        "path": FNV_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint32\s+Offset\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 4,
        "searched": True,
        "role": "FNV-1a 32-bit offset basis",
    },
    {
        "id": "fnv32_prime",
        "family": FAMILY_HASH_SEED,
        "name": "FFnv::MemFnv32 prime",
        "path": FNV_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint32\s+Prime\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 4,
        "searched": True,
        "role": "FNV-1a 32-bit prime",
    },
    {
        "id": "fnv64_offset_basis",
        "family": FAMILY_HASH_SEED,
        "name": "FFnv::MemFnv64 offset basis",
        "path": FNV_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint64\s+Offset\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": ("FNV-1a 64-bit offset basis; the same value is the seed of the pak "
                 "path hash and of FIoStore's chunk-id hash"),
    },
    {
        "id": "fnv64_prime",
        "family": FAMILY_HASH_SEED,
        "name": "FFnv::MemFnv64 prime",
        "path": FNV_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint64\s+Prime\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": "FNV-1a 64-bit prime",
    },
    {
        "id": "cityhash_k0",
        "family": FAMILY_HASH_SEED,
        "name": "CityHash k0",
        "path": CITYHASH_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint64\s+k0\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": "CityHash mixing constant; FName hashes lower-cased strings with CityHash64",
    },
    {
        "id": "cityhash_k1",
        "family": FAMILY_HASH_SEED,
        "name": "CityHash k1",
        "path": CITYHASH_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint64\s+k1\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": "CityHash mixing constant",
    },
    {
        "id": "cityhash_k2",
        "family": FAMILY_HASH_SEED,
        "name": "CityHash k2",
        "path": CITYHASH_CPP,
        "kind": "literal",
        "regex": r"static\s+const\s+uint64\s+k2\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": "CityHash mixing constant, and the one used for short inputs",
    },
    {
        "id": "cityhash_kmul",
        "family": FAMILY_HASH_SEED,
        "name": "CityHash Hash128to64 kMul",
        "path": CITYHASH_H,
        "kind": "literal",
        "regex": r"const\s+uint64\s+kMul\s*=\s*(?P<value>0[xX][0-9a-fA-F]+)",
        "width": 8,
        "searched": True,
        "role": "the multiplier of Hash128to64, reached from every CityHash64 of a long input",
    },
)

# uint32 tables, parsed out of their initialiser lists. `regex` must match the
# DECLARATION line; the brace block that follows is what gets read.
TABLE_LOCI: tuple[dict, ...] = (
    {
        "id": "crc_table_deprecated",
        "family": FAMILY_HASH_TABLE,
        "name": "FCrc::CRCTable_DEPRECATED",
        "path": CRC_CPP,
        "regex": r"FCrc::CRCTable_DEPRECATED\s*\[\s*256\s*\]",
        "expect_words": 256,
        "role": ("the MSB-first CRC-32 table of FCrc::MemCrc_DEPRECATED and "
                 "FCrc::Strihash_DEPRECATED -- the hash FName used before UE5 and the "
                 "one FPackageName still uses for short hashes"),
        "prefix_words": None,
    },
    {
        "id": "crc_tables_sb8_deprecated",
        "family": FAMILY_HASH_TABLE,
        "name": "FCrc::CRCTablesSB8_DEPRECATED",
        "path": CRC_CPP,
        "regex": r"FCrc::CRCTablesSB8_DEPRECATED\s*\[\s*8\s*\]\s*\[\s*256\s*\]",
        "expect_words": 2048,
        "role": "the slice-by-eight form of the deprecated table",
        "prefix_words": 256,
    },
    {
        "id": "crc_tables_sb8",
        "family": FAMILY_HASH_TABLE,
        "name": "FCrc::CRCTablesSB8",
        "path": CRC_CPP,
        "regex": r"FCrc::CRCTablesSB8\s*\[\s*8\s*\]\s*\[\s*256\s*\]",
        "expect_words": 2048,
        "role": ("the reflected CRC-32 table of FCrc::MemCrc32, the software path of "
                 "every FCrc::MemCrc32 call in the engine"),
        "prefix_words": 256,
    },
)

# Extra citations: places OTHER than the defining locus where the same constant
# is written down. Recorded because "this value appears in the pak path hash as
# well as in FFnv" is part of what the constant means, and because a reader who
# only sees Fnv.cpp would not know that.
EXTRA_CITATIONS: tuple[dict, ...] = (
    {"constant_id": "fnv64_offset_basis",
     "path": "Source/Runtime/PakFile/Private/IPlatformFilePak.cpp",
     "regex": r"static\s+const\s+uint64\s+Prime\s*=\s*0[xX]cbf29ce484222325",
     "why": "FPakFile path hashing seeds FNV-1a with the same basis"},
    {"constant_id": "fnv64_offset_basis",
     "path": "Source/Runtime/Core/Private/IO/IoStore.cpp",
     "regex": r"Seed\s*\?\s*static_cast<uint64>\(Seed\)\s*:\s*0[xX]cbf29ce484222325",
     "why": "FIoStore chunk hashing falls back to the same basis when no seed is given"},
    {"constant_id": "cityhash_k2",
     "path": UNREALNAMES_CPP,
     "regex": r"return\s+CityHash64\(reinterpret_cast<const char\*>\(Str\)",
     "why": "the FName hash of UE5 is CityHash64 over the lower-cased string"},
)
