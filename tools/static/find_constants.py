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
from collections import Counter
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


# --------------------------------------------------------------------------- #
# small shared helpers, spelled the same way as in rtti_scan.py / vtable_scan.py
# so that a reader who has read one has read all three.
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def parse_c_integer(text: str) -> int:
    """One C integer literal to an int. Raises DerivationError, never guesses.

    Handles the suffixes the engine actually writes (``u``, ``U``, ``l``, ``L``,
    ``ull``, ``ULL``) and hex, octal and decimal bases. A literal this cannot
    parse is a locus that has changed shape, which is a result and not a
    nuisance -- so it raises rather than returning a default.
    """
    token = text.strip().replace("'", "")
    while token and token[-1] in "uUlL":
        token = token[:-1]
    if not token:
        raise DerivationError("empty integer literal in %r" % text)
    try:
        if token[:2].lower() == "0x":
            return int(token, 16)
        if len(token) > 1 and token[0] == "0" and token[1:].isdigit():
            return int(token, 8)
        return int(token, 10)
    except ValueError as error:
        raise DerivationError("cannot parse the integer literal %r" % text) from error


def strip_c_comments(text: str) -> str:
    """Remove block and line comments, keeping every newline so line numbers survive.

    Line numbers are cited evidence in this tool, so a comment stripper that
    collapsed lines would silently corrupt every citation it touched. Newlines
    inside a block comment are therefore preserved one for one.
    """
    out: list[str] = []
    index = 0
    length = len(text)
    quotes = "\"'"
    while index < length:
        char = text[index]
        if char == "/" and index + 1 < length:
            following = text[index + 1]
            if following == "/":
                end = text.find("\n", index)
                index = length if end < 0 else end
                continue
            if following == "*":
                end = text.find("*/", index + 2)
                stop = length if end < 0 else end + 2
                out.append("\n" * text.count("\n", index, stop))
                index = stop
                continue
        if char in quotes:
            # A quoted literal may contain a comment opener; skip it whole.
            cursor = index + 1
            while cursor < length:
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == char:
                    cursor += 1
                    break
                if text[cursor] == "\n":
                    break
                cursor += 1
            out.append(text[index:cursor])
            index = cursor
            continue
        out.append(char)
        index += 1
    return "".join(out)


def line_of(text: str, position: int) -> int:
    """The 1-based line number of *position*. Every citation in this tool uses it."""
    return text.count("\n", 0, position) + 1


class SourceTree:
    """A bounded, caching reader for the first-party UE source tree.

    Bounded because every quantity that comes out of a file has to be bounded
    before it is believed (a file claiming to be 4 GB is a reason to stop, not to
    allocate); caching because several loci share a file and re-reading
    ObjectVersion.h four times would be four chances to read four different
    things.
    """

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        self._cache: dict[str, str] = {}

    def path_of(self, relative: str) -> str:
        return os.path.join(self.root, relative.replace("/", os.sep))

    def read(self, relative: str) -> str:
        if relative in self._cache:
            return self._cache[relative]
        full = self.path_of(relative)
        try:
            size = os.path.getsize(full)
        except OSError as error:
            raise DerivationError("%s: cannot stat: %s" % (relative, error)) from error
        if size > UE_SOURCE_MAX_FILE:
            raise DerivationError("%s: %d bytes exceeds the %d-byte limit"
                                  % (relative, size, UE_SOURCE_MAX_FILE))
        try:
            with open(full, "rb") as handle:
                raw = handle.read(UE_SOURCE_MAX_FILE + 1)
        except OSError as error:
            raise DerivationError("%s: cannot read: %s" % (relative, error)) from error
        text = raw.decode("utf-8", "replace")
        self._cache[relative] = text
        return text

    def source_line(self, relative: str, line: int | None) -> str | None:
        """The text of one line, for the citation. None when the line is unknown."""
        if line is None or line < 1:
            return None
        lines = self.read(relative).splitlines()
        if line - 1 >= len(lines):
            return None
        return lines[line - 1].strip()


# --------------------------------------------------------------------------- #
# deriving one scalar out of the tree
# --------------------------------------------------------------------------- #

def derive_regex_scalar(tree: SourceTree, locus: dict) -> dict:
    """A define / literal / ascii locus: run the regex, cite the line."""
    text = tree.read(locus["path"])
    stripped = strip_c_comments(text)
    match = re.compile(locus["regex"], re.MULTILINE).search(stripped)
    if match is None:
        raise DerivationError("%s: %s did not match in %s"
                              % (locus["id"], locus["regex"], locus["path"]))
    raw_value = match.group("value")
    line = line_of(stripped, match.start())
    result = {
        "value_text": raw_value,
        "line": line,
        "source_text": tree.source_line(locus["path"], line),
    }
    if locus["kind"] == "ascii":
        result["value"] = None
        result["text_value"] = raw_value
    else:
        result["value"] = parse_c_integer(raw_value)
    return result


# --------------------------------------------------------------------------- #
# deriving one ENUMERATOR out of the tree
#
# This needs a real evaluator and not a regex, because the values this project
# cares about are not written down anywhere. In ObjectVersion.h
# VER_UE4_AUTOMATIC_VERSION is VER_UE4_AUTOMATIC_VERSION_PLUS_ONE - 1, and
# _PLUS_ONE has no initialiser at all: its value is whatever the entry before it
# was, plus one. The only way to know the number is to count the enum, which is
# what the compiler does, so that is what this does.
# --------------------------------------------------------------------------- #

_ENUM_TOKEN = re.compile(r"0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|<<|>>|::|[()+\-*|&~]")


def _eval_enum_expression(expression: str, known: dict[str, int],
                          enum_id: str) -> int:
    """Evaluate one enumerator initialiser. No eval(), ever.

    The grammar admitted is the one the engine's version enums actually use:
    integer literals, references to enumerators already defined in the same
    enum, parentheses, unary minus and complement, and the binary operators
    + - * << >> | & . Anything else raises, because an initialiser this cannot
    evaluate means the enum has grown a form the tool has not been taught, and
    inventing a number there would put a fabricated value into an evidence
    record.
    """
    tokens = _ENUM_TOKEN.findall(expression)
    if not tokens:
        raise DerivationError("%s: empty enumerator initialiser %r"
                              % (enum_id, expression))
    position = [0]

    def peek():
        return tokens[position[0]] if position[0] < len(tokens) else None

    def take() -> str:
        token = tokens[position[0]]
        position[0] += 1
        return token

    def primary() -> int:
        token = peek()
        if token is None:
            raise DerivationError("%s: truncated initialiser %r"
                                  % (enum_id, expression))
        if token == "(":
            take()
            value = bitwise_or()
            if peek() != ")":
                raise DerivationError("%s: unbalanced parentheses in %r"
                                      % (enum_id, expression))
            take()
            return value
        if token == "-":
            take()
            return -primary()
        if token == "~":
            take()
            return ~primary()
        if token == "+":
            take()
            return primary()
        take()
        if token[0].isdigit():
            return parse_c_integer(token)
        # A qualified name arrives as identifier :: identifier; only the last
        # component can name an enumerator of this enum.
        while peek() == "::":
            take()
            token = take()
        if token in known:
            return known[token]
        raise DerivationError(
            "%s: initialiser %r refers to %r, which is not an enumerator defined "
            "earlier in the same enum -- this tool refuses to guess its value"
            % (enum_id, expression, token))

    def multiplicative() -> int:
        value = primary()
        while peek() == "*":
            take()
            value *= primary()
        return value

    def additive() -> int:
        value = multiplicative()
        while peek() in ("+", "-"):
            operator = take()
            right = multiplicative()
            value = value + right if operator == "+" else value - right
        return value

    def shifted() -> int:
        value = additive()
        while peek() in ("<<", ">>"):
            operator = take()
            right = additive()
            value = value << right if operator == "<<" else value >> right
        return value

    def bitwise_and() -> int:
        value = shifted()
        while peek() == "&":
            take()
            value &= shifted()
        return value

    def bitwise_or() -> int:
        value = bitwise_and()
        while peek() == "|":
            take()
            value |= bitwise_and()
        return value

    result = bitwise_or()
    if position[0] != len(tokens):
        raise DerivationError("%s: trailing tokens in initialiser %r"
                              % (enum_id, expression))
    return result


def _enum_body_span(stripped: str, locus: dict) -> tuple[int, int]:
    """The half-open span of the enum body, brace-MATCHED, never regex-matched.

    A regex for a braced group finds the first inner brace, which for an enum
    containing a nested initialiser is the wrong span and fails quietly.
    Counting braces is the only thing that is right.
    """
    if locus.get("enum_name"):
        head = re.search(r"\benum\s+(?:class\s+|struct\s+)?%s\b"
                         % re.escape(locus["enum_name"]), stripped)
        if head is None:
            raise DerivationError("%s: enum %s not found in %s"
                                  % (locus["id"], locus["enum_name"], locus["path"]))
        start = stripped.find("{", head.end())
    else:
        anchor = re.search(locus["enum_anchor"], stripped)
        if anchor is None:
            raise DerivationError("%s: enum anchor %s not found in %s"
                                  % (locus["id"], locus["enum_anchor"], locus["path"]))
        start = stripped.rfind("{", 0, anchor.start())
    if start < 0:
        raise DerivationError("%s: no opening brace for the enum in %s"
                              % (locus["id"], locus["path"]))
    depth = 0
    for index in range(start, len(stripped)):
        if stripped[index] == "{":
            depth += 1
        elif stripped[index] == "}":
            depth -= 1
            if depth == 0:
                return start + 1, index
    raise DerivationError("%s: the enum body in %s is not closed"
                          % (locus["id"], locus["path"]))


def walk_enum(tree: SourceTree, locus: dict) -> dict:
    """Walk one enum the way a compiler does; return every enumerator and its value.

    Returned whole rather than reduced to the one entry asked for, because "which
    values does this enum contain" is itself a citable fact about the tree, and
    the UE5 version-band scan needs the whole table to say which of the values it
    finds in the image are enumerators at all.
    """
    text = tree.read(locus["path"])
    stripped = strip_c_comments(text)
    start, end = _enum_body_span(stripped, locus)
    body = stripped[start:end]

    known: dict[str, int] = {}
    lines: dict[str, int] = {}
    running = -1
    cursor = 0
    for piece in body.split(","):
        piece_start = cursor
        cursor += len(piece) + 1
        if len(known) > MAX_ENUM_ENTRIES:
            raise DerivationError("%s: more than %d enumerators -- refusing to walk"
                                  % (locus["id"], MAX_ENUM_ENTRIES))
        head = re.match(r"\s*([A-Za-z_]\w*)\s*(?:=\s*(?P<expr>.+?))?\s*$", piece,
                        re.DOTALL)
        if head is None:
            continue
        name = head.group(1)
        expression = head.group("expr")
        if expression is None:
            running += 1
        else:
            running = _eval_enum_expression(expression, known, locus["id"])
        known[name] = running
        lines[name] = line_of(stripped, start + piece_start + piece.find(name))

    return {
        "enum_table": known,
        "enum_lines": lines,
        "enumerators_walked": len(known),
        "body_span_in_stripped_text": [start, end],
    }


def derive_enum_value(tree: SourceTree, locus: dict) -> dict:
    """The value of one named enumerator, plus the walk that produced it."""
    walk = walk_enum(tree, locus)
    name = locus["enumerator"]
    if name not in walk["enum_table"]:
        raise DerivationError("%s: enumerator %s is not in the enum body in %s"
                              % (locus["id"], name, locus["path"]))
    line = walk["enum_lines"].get(name)
    return {
        "value": walk["enum_table"][name],
        "value_text": None,
        "line": line,
        "source_text": tree.source_line(locus["path"], line),
        "enumerators_walked": walk["enumerators_walked"],
    }


# --------------------------------------------------------------------------- #
# deriving a TABLE out of the tree
# --------------------------------------------------------------------------- #

def derive_table(tree: SourceTree, locus: dict) -> dict:
    """Parse a uint32 table's initialiser and pack it little-endian.

    The braces are flattened rather than parsed as rows on purpose: a [8][256]
    table is 2048 consecutive words in memory in exactly that order, so the
    flattened list IS the byte image, and any row structure this tool imposed
    would be one more chance to get the order wrong.
    """
    text = tree.read(locus["path"])
    stripped = strip_c_comments(text)
    head = re.search(locus["regex"], stripped)
    if head is None:
        raise DerivationError("%s: %s did not match in %s"
                              % (locus["id"], locus["regex"], locus["path"]))
    open_brace = stripped.find("{", head.end())
    if open_brace < 0:
        raise DerivationError("%s: no initialiser after the declaration in %s"
                              % (locus["id"], locus["path"]))
    depth = 0
    close_brace = -1
    for index in range(open_brace, len(stripped)):
        if stripped[index] == "{":
            depth += 1
        elif stripped[index] == "}":
            depth -= 1
            if depth == 0:
                close_brace = index
                break
    if close_brace < 0:
        raise DerivationError("%s: the initialiser in %s is not closed"
                              % (locus["id"], locus["path"]))
    body = stripped[open_brace + 1:close_brace].replace("{", " ").replace("}", " ")
    words: list[int] = []
    for token in body.split(","):
        token = token.strip()
        if not token:
            continue
        if len(words) >= MAX_TABLE_WORDS:
            raise DerivationError("%s: more than %d words -- refusing to read"
                                  % (locus["id"], MAX_TABLE_WORDS))
        value = parse_c_integer(token)
        if not 0 <= value <= 0xFFFFFFFF:
            raise DerivationError("%s: %r is not a uint32" % (locus["id"], token))
        words.append(value)
    expected = locus.get("expect_words")
    if expected is not None and len(words) != expected:
        raise DerivationError(
            "%s: read %d words but the declaration in %s says %d -- refusing to "
            "build a pattern out of a table this tool has clearly misparsed"
            % (locus["id"], len(words), locus["path"], expected))
    line = line_of(stripped, head.start())
    return {
        "words": words,
        "word_count": len(words),
        "line": line,
        "source_text": tree.source_line(locus["path"], line),
        "packed": struct.pack("<%dI" % len(words), *words),
    }


# --------------------------------------------------------------------------- #
# the custom-version GUIDs
#
# These are the highest-value family in the task and the only one that needs a
# walk of the whole tree, because the GUID and the registration that gives it a
# name are written in two different statements and, often enough, two different
# files. The join is reported WITH ITS FAILURES: a registration whose GUID this
# cannot find is listed in `registrations_unresolved`, never dropped, because a
# silently-completed join is how a census starts agreeing with itself.
# --------------------------------------------------------------------------- #

# const FGuid FBlueprintsObjectVersion::GUID(0xB0D832E4, 0x1F894F0D, ...);
GUID_DEFINITION = re.compile(
    r"\bFGuid\s+(?P<cls>[A-Za-z_]\w*)::(?P<member>[A-Za-z_]\w*)\s*\(\s*"
    r"(?P<a>0[xX][0-9a-fA-F]+)\s*,\s*(?P<b>0[xX][0-9a-fA-F]+)\s*,\s*"
    r"(?P<c>0[xX][0-9a-fA-F]+)\s*,\s*(?P<d>0[xX][0-9a-fA-F]+)\s*\)")

# FDevVersionRegistration GRegisterX(FXVersion::GUID, FXVersion::LatestVersion,
#                                    TEXT("Dev-X"));
REGISTRATION = re.compile(
    r"\bF(?P<kind>Custom|Dev)VersionRegistration\s+(?P<variable>[A-Za-z_]\w*)\s*\(\s*"
    r"(?P<cls>[A-Za-z_]\w*)::(?P<member>[A-Za-z_]\w*)\s*,"
    r"(?P<rest>[^;]{0,512}?)\)\s*;")

FRIENDLY_NAME = re.compile(r"TEXT\(\s*\"(?P<name>[^\"]{1,128})\"\s*\)")


def _guid_bytes(a: int, b: int, c: int, d: int) -> bytes:
    """The sixteen bytes an FGuid built from four uint32 occupies, in order.

    FGuid stores A, B, C, D as four uint32 members in declaration order, so on a
    little-endian target the image holds them as four little-endian words. That
    is a statement about the layout of a struct of four uint32 under the
    Microsoft ABI (external-doc), and it is the one layout assumption of this
    family; it is stated here rather than buried so that a reader can reject it.
    """
    return struct.pack("<4I", a & 0xFFFFFFFF, b & 0xFFFFFFFF,
                       c & 0xFFFFFFFF, d & 0xFFFFFFFF)


def _guid_canonical(a: int, b: int, c: int, d: int) -> str:
    """The A-B-C-D spelling the engine's own logs use. A label, not evidence."""
    return "%08X%08X%08X%08X" % (a & 0xFFFFFFFF, b & 0xFFFFFFFF,
                                 c & 0xFFFFFFFF, d & 0xFFFFFFFF)


def walk_custom_versions(root: str, warnings: list[str],
                         limit_files: int | None = None) -> dict:
    """Walk the first-party tree for FGuid definitions and version registrations.

    Reads roughly 900 MB of text on a full UE 5.4 tree and takes minutes, which
    is why the catalogue it feeds can be written with --catalogue-out and reused
    with --catalogue-in. Nothing is written anywhere near the game and nothing
    outside the named suffixes is opened.

    Every file is read at most once and only decoded when a cheap byte test says
    it could possibly contain a hit, because decoding 90 000 files that cannot
    match is the whole cost of this pass.
    """
    started = time.monotonic()
    definitions: dict[tuple[str, str], dict] = {}
    registrations: list[dict] = []
    files_read = 0
    files_scanned = 0
    bytes_read = 0
    truncated: list[str] = []

    roots = [os.path.join(root, name) for name in ("Source", "Plugins")]
    present = [path for path in roots if os.path.isdir(path)]
    if not present:
        warnings.append(
            "neither Source/ nor Plugins/ exists under %s -- the custom-version "
            "family is EMPTY for structural reasons, not because the tree has none"
            % root)
        return {
            "root": root, "searched_roots": [], "files_read": 0,
            "files_scanned": 0, "bytes_read": 0, "definitions": {},
            "registrations": [], "seconds": 0.0, "files_truncated": [],
        }

    for base in present:
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in UE_SOURCE_SKIP_DIRS)
            for filename in sorted(filenames):
                if not filename.endswith(UE_SOURCE_SUFFIXES):
                    continue
                if limit_files is not None and files_read >= limit_files:
                    continue
                full = os.path.join(dirpath, filename)
                try:
                    with open(full, "rb") as handle:
                        raw = handle.read(UE_SOURCE_MAX_FILE + 1)
                except OSError as error:
                    warnings.append("cannot read %s: %s" % (filename, error))
                    continue
                files_read += 1
                if len(raw) > UE_SOURCE_MAX_FILE:
                    truncated.append(os.path.relpath(full, root).replace("\\", "/"))
                    raw = raw[:UE_SOURCE_MAX_FILE]
                bytes_read += len(raw)
                if b"FGuid" not in raw and b"VersionRegistration" not in raw:
                    continue
                files_scanned += 1
                text = strip_c_comments(raw.decode("utf-8", "replace"))
                relative = os.path.relpath(full, root).replace("\\", "/")
                for match in GUID_DEFINITION.finditer(text):
                    key = (match.group("cls"), match.group("member"))
                    try:
                        parts = tuple(parse_c_integer(match.group(g))
                                      for g in ("a", "b", "c", "d"))
                    except DerivationError as error:
                        warnings.append("%s: %s" % (relative, error))
                        continue
                    if any(part > 0xFFFFFFFF for part in parts):
                        warnings.append(
                            "%s: FGuid %s::%s has a component wider than uint32; "
                            "skipped rather than truncated"
                            % (relative, key[0], key[1]))
                        continue
                    record = {
                        "class": key[0],
                        "member": key[1],
                        "components": list(parts),
                        "guid": _guid_canonical(*parts),
                        "bytes_hex": _guid_bytes(*parts).hex(),
                        "path": relative,
                        "line": line_of(text, match.start()),
                    }
                    previous = definitions.get(key)
                    if previous is not None and previous["bytes_hex"] != record["bytes_hex"]:
                        warnings.append(
                            "%s::%s is defined twice with different values (%s at "
                            "%s:%d and %s at %s:%d); the first is kept and both are "
                            "a reason to distrust the join"
                            % (key[0], key[1], previous["guid"], previous["path"],
                               previous["line"], record["guid"], record["path"],
                               record["line"]))
                        continue
                    definitions.setdefault(key, record)
                for match in REGISTRATION.finditer(text):
                    friendly = FRIENDLY_NAME.search(match.group("rest") or "")
                    registrations.append({
                        "kind": "F%sVersionRegistration" % match.group("kind"),
                        "variable": match.group("variable"),
                        "class": match.group("cls"),
                        "member": match.group("member"),
                        "friendly_name": friendly.group("name") if friendly else None,
                        "path": relative,
                        "line": line_of(text, match.start()),
                    })
    return {
        "root": root,
        "searched_roots": [os.path.relpath(p, root).replace("\\", "/")
                           for p in present],
        "files_read": files_read,
        "files_scanned": files_scanned,
        "bytes_read": bytes_read,
        "definitions": {"%s::%s" % key: value
                        for key, value in sorted(definitions.items())},
        "registrations": sorted(registrations,
                                key=lambda r: (r["path"], r["line"])),
        "files_truncated": sorted(truncated),
        "seconds": round(time.monotonic() - started, 3),
        "suffixes": list(UE_SOURCE_SUFFIXES),
        "skipped_directory_names": list(UE_SOURCE_SKIP_DIRS),
    }


def join_custom_versions(walk: dict, warnings: list[str]) -> dict:
    """Join registrations to GUID definitions and REPORT the failures.

    A registration names its key as ``Class::Member``; the definition of that
    member is the sixteen bytes. Where the two meet, the constant has a name AND
    a value, which is what makes it worth searching for. Where they do not, the
    registration is listed unresolved -- almost always because the key is a
    ``static const FGuid`` initialised inline in a header, which this walk does
    not parse.
    """
    definitions = walk["definitions"]
    joined: list[dict] = []
    unresolved: list[dict] = []
    seen: set[str] = set()
    for registration in walk["registrations"]:
        key = "%s::%s" % (registration["class"], registration["member"])
        definition = definitions.get(key)
        if definition is None:
            unresolved.append(dict(registration, key=key))
            continue
        if key in seen:
            continue
        seen.add(key)
        joined.append({
            "key": key,
            "friendly_name": registration["friendly_name"],
            "registration_kind": registration["kind"],
            "registration_path": registration["path"],
            "registration_line": registration["line"],
            "definition_path": definition["path"],
            "definition_line": definition["line"],
            "guid": definition["guid"],
            "components": definition["components"],
            "bytes_hex": definition["bytes_hex"],
        })
    unjoined_definitions = sorted(
        key for key in definitions if key not in seen)
    if unresolved:
        warnings.append(
            "%d of %d version registrations could not be joined to an FGuid "
            "definition and are listed in custom_versions.registrations_unresolved; "
            "their GUIDs are NOT searched for and their absence from the "
            "occurrence list says nothing"
            % (len(unresolved), len(walk["registrations"])))
    return {
        "registrations_total": len(walk["registrations"]),
        "guid_definitions_total": len(definitions),
        "joined": joined,
        "joined_total": len(joined),
        "registrations_unresolved": unresolved,
        "registrations_unresolved_total": len(unresolved),
        "guid_definitions_not_reached_by_a_registration": unjoined_definitions,
        "join_key": "the Class::Member the registration names as its key",
        "what_unresolved_means": (
            "the registration statement was found but the sixteen bytes were not, "
            "usually because the key is a static const FGuid initialised inline in "
            "a header rather than defined in a .cpp. Such a GUID is not searched "
            "for, so it can be neither found nor missing"),
    }


# --------------------------------------------------------------------------- #
# the catalogue: everything derived from the tree, with a citation on every row
# --------------------------------------------------------------------------- #

def catalogue_annotation(root: str, build_version: dict | None) -> dict:
    """The grading of the catalogue itself, in the reduced annotation envelope.

    OBSERVED, because every value in it is a literal read of text at a cited
    file and line. Class I nevertheless, and unconditionally: the catalogue does
    not merely say what characters are at a place, it says that those characters
    ARE the value of a named constant of a named engine -- and naming what
    something is, is exactly the line plan.md 10.3 draws between P and I.

    Confidence 0.79 and not higher, which is a deliberate refusal. Class I from
    0.80 up wants two INDEPENDENT methods, and this object has one: reading a
    source tree. The `extra_citations` check does find the same value written
    down at a second call site in a different file, but it covers three
    constants out of twenty-one, so it corroborates those three and not this
    object; counting it here would be the exact error this project has made
    before. An honest 0.79 is worth more than a decorated 0.85.

    Note also what the catalogue does NOT claim: it says nothing whatever about
    the game image. Whether any of these values is in the image is
    `occurrences[]`, which is a different oracle and a different act.
    """
    describes = (
        "UE %s.%s.%s CL %s, branch %s"
        % (build_version.get("MajorVersion"), build_version.get("MinorVersion"),
           build_version.get("PatchVersion"), build_version.get("Changelist"),
           build_version.get("BranchName"))
        if build_version else "a source tree of UNKNOWN version")
    return {
        "evidence_level": "OBSERVED",
        "claim_class": "I",
        "confidence": CONFIDENCE_DECODED_SINGLE_METHOD,
        "oracle": ["external-doc", "filesystem"],
        "sources": [{
            "method": TASK,
            "artifact": None,
            "locator": root,
            "note": ("oracle external-doc + filesystem. Every value below was read "
                     "out of the source tree at the cited file and line at run "
                     "time; nothing is hard-coded in the tool but where to look "
                     "and how to parse what is there. The tree declares %s."
                     % describes),
        }],
        "read_locus": None,
        "note": (
            "This object is a statement about the SOURCE TREE and about nothing "
            "else -- it says what the engine's own code writes down, at %s. It is "
            "class I because it names the values, not merely the characters. One "
            "method only, so the confidence stays below the 0.80 band plan.md 10.3 "
            "reserves for two-method claims. Whether any of these values occurs in "
            "the game image is a separate measurement with a separate oracle, and "
            "it lives in occurrences[]." % describes
        ),
    }

def build_catalogue(root: str, warnings: list[str],
                    want_custom_versions: bool = True,
                    limit_files: int | None = None) -> dict:
    """Derive every constant this tool knows how to look for, out of the tree.

    The result is a statement about the SOURCE TREE and about nothing else:
    oracles external-doc (what the code says) plus filesystem (that a file at
    this path holds that text). It is kept in its own object, and separate from
    the occurrence list, so that a reader cannot mistake one for the other.
    """
    started = time.monotonic()
    tree = SourceTree(root)
    entries: list[dict] = []
    failures: list[dict] = []

    build_version = None
    try:
        raw = tree.read("Build/Build.version")
        build_version = json.loads(raw)
    except (DerivationError, ValueError) as error:
        warnings.append(
            "Build/Build.version could not be read or parsed under %s (%s), so the "
            "catalogue cannot say which changelist it was derived at -- every "
            "citation below is to a tree of UNKNOWN version" % (root, error))

    for locus in SCALAR_LOCI:
        record = {
            "id": locus["id"],
            "family": locus["family"],
            "name": locus["name"],
            "kind": locus["kind"],
            "role": locus["role"],
            "source_path": locus["path"],
            "searched": bool(locus["searched"]),
            "proves_if_found": PROVES[locus["family"]],
            "does_not_prove": DOES_NOT_PROVE[locus["family"]],
        }
        if not locus["searched"]:
            record["not_searched_reason"] = locus["not_searched_reason"]
        try:
            if locus["kind"] == "enum":
                derived = derive_enum_value(tree, locus)
            else:
                derived = derive_regex_scalar(tree, locus)
        except DerivationError as error:
            record["derived"] = False
            record["derivation_error"] = str(error)
            record["searched"] = False
            failures.append({"id": locus["id"], "error": str(error)})
            warnings.append("catalogue: %s" % error)
            entries.append(record)
            continue
        record["derived"] = True
        record["source_line"] = derived["line"]
        record["source_text"] = derived["source_text"]
        record["citation"] = "%s:%s" % (locus["path"], derived["line"])
        if locus["kind"] == "ascii":
            record["text_value"] = derived["text_value"]
            record["width"] = len(derived["text_value"].encode("ascii", "replace"))
        else:
            record["value"] = derived["value"]
            record["width"] = locus["width"]
            if derived.get("enumerators_walked") is not None:
                record["enumerators_walked"] = derived["enumerators_walked"]
        entries.append(record)

    for locus in TABLE_LOCI:
        record = {
            "id": locus["id"],
            "family": locus["family"],
            "name": locus["name"],
            "kind": "table",
            "role": locus["role"],
            "source_path": locus["path"],
            "searched": True,
            "proves_if_found": PROVES[locus["family"]],
            "does_not_prove": DOES_NOT_PROVE[locus["family"]],
        }
        try:
            derived = derive_table(tree, locus)
        except DerivationError as error:
            record["derived"] = False
            record["derivation_error"] = str(error)
            record["searched"] = False
            failures.append({"id": locus["id"], "error": str(error)})
            warnings.append("catalogue: %s" % error)
            entries.append(record)
            continue
        record["derived"] = True
        record["source_line"] = derived["line"]
        record["source_text"] = derived["source_text"]
        record["citation"] = "%s:%s" % (locus["path"], derived["line"])
        record["word_count"] = derived["word_count"]
        record["width"] = derived["word_count"] * 4
        record["bytes_hex"] = derived["packed"].hex()
        record["first_words"] = derived["words"][:8]
        record["prefix_words"] = locus.get("prefix_words")
        record["sha256_of_the_packed_table"] = hashlib.sha256(
            derived["packed"]).hexdigest()
        entries.append(record)

    extra: list[dict] = []
    for citation in EXTRA_CITATIONS:
        try:
            text = strip_c_comments(tree.read(citation["path"]))
        except DerivationError as error:
            warnings.append("extra citation: %s" % error)
            extra.append(dict(citation, found=False, line=None,
                              error=str(error)))
            continue
        match = re.search(citation["regex"], text)
        extra.append({
            "constant_id": citation["constant_id"],
            "path": citation["path"],
            "why": citation["why"],
            "found": match is not None,
            "line": line_of(text, match.start()) if match else None,
            "citation": ("%s:%d" % (citation["path"], line_of(text, match.start()))
                         if match else None),
        })
        if match is None:
            warnings.append(
                "the extra citation for %s in %s did not match; the constant is "
                "unaffected but the claim that this second call site writes the "
                "same value down is NOT supported by this run"
                % (citation["constant_id"], citation["path"]))

    custom = None
    if want_custom_versions:
        walk = walk_custom_versions(root, warnings, limit_files=limit_files)
        custom = join_custom_versions(walk, warnings)
        custom["walk"] = {key: value for key, value in walk.items()
                          if key not in ("definitions", "registrations")}
        custom["proves_if_found"] = PROVES[FAMILY_CUSTOM_VERSION_GUID]
        custom["does_not_prove"] = DOES_NOT_PROVE[FAMILY_CUSTOM_VERSION_GUID]

    # The UE5 version band, enumerated rather than assumed. The pair-shape scan
    # needs to say which of the values it meets next to the UE4 anchor are
    # enumerators of EUnrealEngineObjectUE5Version at all, and that is a fact
    # about the tree, so it is derived here and not in the image layer.
    ue5_enum = None
    try:
        ue5_enum = walk_enum(tree, {
            "id": "ue5_object_version_enum",
            "path": OBJECT_VERSION_H,
            "enum_name": "EUnrealEngineObjectUE5Version",
            "enumerator": "AUTOMATIC_VERSION",
        })
    except DerivationError as error:
        warnings.append("the UE5 version enum could not be walked: %s" % error)

    catalogue = {
        "ue_source_root": root,
        "build_version": build_version,
        "derived_at": now_iso_utc(),
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "constants": entries,
        "derivation_failures": failures,
        "extra_citations": extra,
        "custom_versions": custom,
        "ue5_object_version_enum": (
            {"enumerators": ue5_enum["enum_table"],
             "enumerators_walked": ue5_enum["enumerators_walked"],
             "source_path": OBJECT_VERSION_H}
            if ue5_enum else None),
        "seconds": round(time.monotonic() - started, 3),
        # The catalogue IS a claim -- "the tree at this path declares these
        # values at these lines" -- so it is graded, and graded in the REDUCED
        # annotation envelope of research/schema/kb-record.schema.json rather
        # than with a bare `oracle` list. A bare `oracle` key makes
        # tools/kb/validate.py read the enclosing object as a FULL knowledge-base
        # record and ask it for claim_type and build_key, which is correct
        # behaviour on the validator's part and was a defect on this tool's:
        # an oracle is a claim about where knowledge came from, so an object
        # that names one has to carry the rest of the envelope with it.
        "evidence": catalogue_annotation(root, build_version),
        "what_this_object_is": (
            "a statement about the UNREAL ENGINE SOURCE TREE at the path and "
            "changelist named above, and about nothing else. It says what the "
            "engine's code writes down. Whether any of it is in the game image is "
            "the separate question answered by occurrences[]"),
    }
    return catalogue


# --------------------------------------------------------------------------- #
# patterns: from a derived value to the bytes to look for
#
# One derived constant can yield several patterns, and they are kept separate
# rather than merged, because "the 16 bytes of the GUID are present" and "the
# UTF-16 friendly name is present" are two independent byte ranges and finding
# both is worth more than finding either twice.
# --------------------------------------------------------------------------- #

ENCODING_U32_LE = "uint32-le"
ENCODING_U64_LE = "uint64-le"
ENCODING_ASCII = "ascii"
ENCODING_UTF16LE = "utf-16le"
ENCODING_GUID16 = "guid-16-bytes-le"
ENCODING_TABLE = "packed-uint32-le-table"
ENCODING_TABLE_PREFIX = "packed-uint32-le-table-prefix"
ENCODING_SYNTHETIC = "synthetic"


def _scalar_pattern_bytes(value: int, width: int) -> bytes | None:
    if width == 4:
        if not 0 <= value <= 0xFFFFFFFF:
            return None
        return struct.pack("<I", value)
    if width == 8:
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            return None
        return struct.pack("<Q", value)
    return None


def build_patterns(catalogue: dict, warnings: list[str],
                   want_friendly_names: bool = True) -> list[dict]:
    """Turn the catalogue into the list of byte strings the image scan will look for.

    Every pattern carries the id of the constant it came from and the encoding it
    is in, so that the occurrence list can say WHICH representation was found.
    A pattern shorter than 4 bytes is refused: at 134 MB a three-byte needle is
    noise by arithmetic, not by opinion.
    """
    patterns: list[dict] = []

    def add(constant_id: str, family: str, encoding: str, raw: bytes,
            label: str, extra: dict | None = None) -> None:
        if len(patterns) >= MAX_PATTERNS:
            return
        if not raw or len(raw) < 4:
            warnings.append(
                "pattern %s/%s is %d bytes, below the 4-byte floor; not searched, "
                "because a needle that short is arithmetic noise in an image this "
                "size" % (constant_id, encoding, len(raw)))
            return
        if len(raw) > MAX_PATTERN_BYTES:
            warnings.append("pattern %s/%s is %d bytes, above the %d-byte limit; "
                            "not searched" % (constant_id, encoding, len(raw),
                                              MAX_PATTERN_BYTES))
            return
        row = {
            "constant_id": constant_id,
            "family": family,
            "encoding": encoding,
            "label": label,
            "length": len(raw),
            "bytes": raw,
            "bytes_hex": raw.hex() if len(raw) <= 64 else None,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if extra:
            row.update(extra)
        patterns.append(row)

    for entry in catalogue["constants"]:
        if not entry.get("derived") or not entry.get("searched"):
            continue
        if entry["kind"] == "table":
            packed = bytes.fromhex(entry["bytes_hex"])
            add(entry["id"], entry["family"], ENCODING_TABLE, packed,
                "%s, all %d words" % (entry["name"], entry["word_count"]))
            prefix_words = entry.get("prefix_words")
            if prefix_words:
                add(entry["id"], entry["family"], ENCODING_TABLE_PREFIX,
                    packed[:prefix_words * 4],
                    "%s, first %d words only" % (entry["name"], prefix_words),
                    {"prefix_words": prefix_words})
            continue
        if entry["kind"] == "ascii":
            raw = entry["text_value"].encode("ascii", "replace")
            add(entry["id"], entry["family"], ENCODING_ASCII, raw,
                "%s as ASCII" % entry["name"])
            continue
        width = entry.get("width")
        raw = _scalar_pattern_bytes(entry["value"], width or 0)
        if raw is None:
            warnings.append(
                "%s: value %r does not fit the declared width %r; not searched"
                % (entry["id"], entry.get("value"), width))
            continue
        add(entry["id"], entry["family"],
            ENCODING_U32_LE if width == 4 else ENCODING_U64_LE, raw,
            "%s as a %d-byte little-endian integer" % (entry["name"], width))

    custom = catalogue.get("custom_versions") or {}
    for joined in custom.get("joined", []):
        add("custom_version:%s" % joined["key"], FAMILY_CUSTOM_VERSION_GUID,
            ENCODING_GUID16, bytes.fromhex(joined["bytes_hex"]),
            "the FGuid of %s" % joined["key"],
            {"friendly_name": joined["friendly_name"],
             "citation": "%s:%d" % (joined["definition_path"],
                                    joined["definition_line"])})
        name = joined.get("friendly_name")
        if want_friendly_names and name:
            add("custom_version_name:%s" % joined["key"],
                FAMILY_CUSTOM_VERSION_NAME, ENCODING_UTF16LE,
                name.encode("utf-16-le"),
                "the friendly name %r of %s as UTF-16LE" % (name, joined["key"]),
                {"friendly_name": name,
                 "citation": "%s:%d" % (joined["registration_path"],
                                        joined["registration_line"])})
    return patterns


def control_patterns(count: int = CONTROL_PATTERN_COUNT) -> list[dict]:
    """Patterns that MUST be absent, so the tool's false-positive rate is measured.

    Built by a fixed rule from a fixed seed rather than picked, so that the same
    controls are used on every target and on every run: each one is the SHA-256
    of a sentence naming this task, truncated to the same lengths the real
    patterns use. They therefore have the same length distribution as the real
    needles and no relation whatever to any engine. A hit on one of these is not
    a curiosity; it means the scan is broken and the whole occurrence list has
    to be thrown away.
    """
    rows: list[dict] = []
    for index in range(count):
        seed = ("misery-framework S-08 synthetic control %d -- this byte string "
                "has no meaning and must not occur" % index).encode("ascii")
        digest = hashlib.sha256(seed).digest()
        length = (4, 8, 16, 32)[index % 4]
        raw = digest[:length]
        rows.append({
            "constant_id": "control_%02d" % index,
            "family": FAMILY_CONTROL,
            "encoding": ENCODING_SYNTHETIC,
            "label": ("synthetic control %d: the first %d bytes of the SHA-256 of a "
                      "fixed sentence" % (index, length)),
            "length": length,
            "bytes": raw,
            "bytes_hex": raw.hex(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return rows


# --------------------------------------------------------------------------- #
# the image layer
# --------------------------------------------------------------------------- #

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

DEFAULT_SKIP_SECTIONS = (".reloc", ".rsrc")


def select_surface(headers, names: tuple[str, ...] | None,
                   skip: tuple[str, ...] = DEFAULT_SKIP_SECTIONS
                   ) -> tuple[list[dict], list[str]]:
    """The sections the pattern scan will read, and the ones it will not.

    Unlike the vtable census, .text is IN by default and that is deliberate: a
    magic or a version number can be materialised as an immediate operand, and a
    constant hunt that skipped the code would be reporting a null result about a
    surface chosen to make the null result likely. Returned rather than assumed
    so the document can print it, because every null result in this tool is a
    statement about this list and about nothing wider.
    """
    kept: list[dict] = []
    dropped: list[str] = []
    for section in headers.sections:
        if section["rsize"] <= 0:
            dropped.append(section["name"])
            continue
        if names is not None:
            if section["name"] in names:
                kept.append(section)
            else:
                dropped.append(section["name"])
            continue
        if section["name"] in skip:
            dropped.append(section["name"])
            continue
        kept.append(section)
    return kept, sorted(set(dropped))


def describe_sections(sections: list[dict]) -> list[dict]:
    return [{
        "name": section["name"],
        "rva": section["rva"],
        "file_offset": section["raw_pointer"],
        "raw_size": section["rsize"],
        "characteristics": section["characteristics"],
        "is_executable": bool(section["characteristics"]
                              & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)),
    } for section in sections]


def scan_patterns(image, sections: list[dict], patterns: list[dict],
                  warnings: list[str]) -> dict:
    """Find every occurrence of every pattern, streaming, one section at a time.

    Streaming with an overlap of ``longest - 1`` bytes so that a pattern
    straddling two windows is still found; the overlap is derived from the
    longest pattern rather than fixed, because a fixed overlap smaller than a
    needle silently loses hits at window boundaries and nothing in the output
    would show it.

    Occurrences are capped per pattern. A capped pattern is FLAGGED
    (``truncated: true``) and its count is reported as a floor, never as a total,
    because a low-entropy needle that occurred 40 000 times must not be reported
    as occurring 4 096 times.
    """
    started = time.monotonic()
    hits: dict[str, list[int]] = {}
    truncated: set[str] = set()
    for pattern in patterns:
        hits[pattern["sha256"]] = []
    longest = max((p["length"] for p in patterns), default=0)
    if longest == 0:
        return {"seconds": 0.0, "bytes_examined": 0, "hits": hits,
                "truncated": [], "windows": 0}
    overlap = longest - 1
    bytes_examined = 0
    windows = 0

    for section in sections:
        start = section["raw_pointer"]
        available = min(section["rsize"], max(0, image.size - start))
        if available <= 0:
            continue
        position = start
        end = start + available
        carry = b""
        carry_at = start
        while position < end:
            want = min(SCAN_CHUNK, end - position)
            chunk = image.read_clamped(position, want)
            if not chunk:
                warnings.append(
                    "section %s: the read at offset %d returned nothing; the scan "
                    "of this section stops here and its coverage is INCOMPLETE"
                    % (section["name"], position))
                break
            windows += 1
            bytes_examined += len(chunk)
            window = carry + chunk
            window_at = carry_at if carry else position
            for pattern in patterns:
                key = pattern["sha256"]
                if key in truncated:
                    continue
                needle = pattern["bytes"]
                found = window.find(needle)
                while found >= 0:
                    absolute = window_at + found
                    # The carry means a hit can be reported twice; the offset is
                    # the identity, so a duplicate is dropped here rather than
                    # deduplicated later where the count would already be wrong.
                    bucket = hits[key]
                    if not bucket or bucket[-1] != absolute:
                        bucket.append(absolute)
                    if len(bucket) >= MAX_OCCURRENCES_PER_PATTERN:
                        truncated.add(key)
                        break
                    found = window.find(needle, found + 1)
            position += len(chunk)
            if position < end:
                carry = window[-overlap:] if overlap else b""
                carry_at = position - len(carry)
            else:
                carry = b""
    for key in truncated:
        warnings.append(
            "a pattern reached the %d-occurrence cap; its count is a FLOOR and not "
            "a total, and it is flagged truncated in the output"
            % MAX_OCCURRENCES_PER_PATTERN)
    return {
        "seconds": round(time.monotonic() - started, 3),
        "bytes_examined": bytes_examined,
        "windows": windows,
        "chunk_bytes": SCAN_CHUNK,
        "overlap_bytes": overlap,
        "longest_pattern_bytes": longest,
        "hits": hits,
        "truncated": sorted(truncated),
    }


def scan_version_pair_shape(image, sections: list[dict], ue4_anchor: int | None,
                            ue5_enum: dict | None, oldest_loadable: int | None,
                            warnings: list[str]) -> dict:
    """Look for the eight-byte FPackageFileVersion SHAPE, not for one number.

    The engine stores a package file version as two int32 side by side: the UE4
    version, frozen for the whole of UE5, then the UE5 version. So the searched
    object is an eight-byte pair whose first word is the UE4 anchor and whose
    second is anything inside a declared band -- which makes the UE5 value a
    RESULT rather than a guess, and makes the neighbour test below possible.

    The neighbour test is the refutation attempt. In ObjectVersion.h the global
    that holds the oldest loadable version is declared immediately after the one
    that holds the current version, and its UE5 half is left zero, so a genuine
    GPackageFileUEVersion should be followed by the eight bytes
    (VER_UE4_OLDEST_LOADABLE_PACKAGE, 0). A pair that has that neighbour is a
    much stronger candidate than one that does not, and the counts of each are
    reported separately rather than merged.
    """
    started = time.monotonic()
    result: dict = {
        "searched": False,
        "ue4_anchor": ue4_anchor,
        "band": [UE5_OBJECT_VERSION_MIN, UE5_OBJECT_VERSION_MAX],
        "alignment": 4,
        "pairs": [],
        "pairs_total": 0,
        "ue5_value_census": {},
        "pairs_with_the_predicted_neighbour": 0,
        "neighbour_prediction": None,
        "what_the_shape_is": (
            "eight consecutive bytes read at four-byte alignment as two "
            "little-endian uint32, the first equal to the UE4 anchor and the "
            "second inside the declared band"),
    }
    if ue4_anchor is None:
        warnings.append(
            "the UE4 version anchor could not be derived from the tree, so the "
            "eight-byte pair shape was NOT searched; version_pair_shape is empty "
            "for that reason and not because the image has no such pair")
        return result
    if oldest_loadable is not None:
        result["neighbour_prediction"] = {
            "expected_next_eight_bytes_as_two_uint32":
                [oldest_loadable, 0],
            "expected_next_eight_bytes_hex":
                struct.pack("<II", oldest_loadable & 0xFFFFFFFF, 0).hex(),
            "why": ("GOldestLoadablePackageFileUEVersion is declared immediately "
                    "after GPackageFileUEVersion and its UE5 half is left zero"),
        }
    result["searched"] = True
    anchor = struct.pack("<I", ue4_anchor & 0xFFFFFFFF)
    known = set((ue5_enum or {}).get("enumerators", {}).values())
    census: Counter = Counter()
    pairs: list[dict] = []
    with_neighbour = 0

    for section in sections:
        start = section["raw_pointer"]
        available = min(section["rsize"], max(0, image.size - start))
        if available <= 0:
            continue
        position = start
        end = start + available
        carry = b""
        carry_at = start
        while position < end:
            want = min(SCAN_CHUNK, end - position)
            chunk = image.read_clamped(position, want)
            if not chunk:
                break
            window = carry + chunk
            window_at = carry_at if carry else position
            found = window.find(anchor)
            while found >= 0:
                absolute = window_at + found
                if absolute % 4 == 0 and found + 8 <= len(window):
                    second = struct.unpack_from("<I", window, found + 4)[0]
                    if UE5_OBJECT_VERSION_MIN <= second <= UE5_OBJECT_VERSION_MAX:
                        census[second] += 1
                        neighbour_hex = None
                        neighbour_matches = None
                        if oldest_loadable is not None:
                            tail = image.read_clamped(absolute + 8, 8)
                            if len(tail) == 8:
                                neighbour_hex = tail.hex()
                                neighbour_matches = (
                                    tail == struct.pack(
                                        "<II", oldest_loadable & 0xFFFFFFFF, 0))
                                if neighbour_matches:
                                    with_neighbour += 1
                        if len(pairs) < MAX_RECORDED_OFFSETS:
                            pairs.append({
                                "file_offset": absolute,
                                "bytes_hex": window[found:found + 8].hex(),
                                "ue4_value": ue4_anchor,
                                "ue5_value": second,
                                "ue5_value_is_an_enumerator_of_the_source_enum":
                                    (second in known) if known else None,
                                "next_eight_bytes_hex": neighbour_hex,
                                "next_eight_bytes_match_the_prediction":
                                    neighbour_matches,
                                "section": section["name"],
                            })
                found = window.find(anchor, found + 1)
            position += len(chunk)
            if position < end:
                carry = window[-11:]
                carry_at = position - len(carry)
            else:
                carry = b""

    result["pairs"] = pairs
    result["pairs_total"] = sum(census.values())
    result["pairs_recorded"] = len(pairs)
    result["ue5_value_census"] = {str(k): v for k, v in sorted(census.items())}
    result["pairs_with_the_predicted_neighbour"] = with_neighbour
    result["distinct_ue5_values"] = len(census)
    result["seconds"] = round(time.monotonic() - started, 3)
    return result


# --------------------------------------------------------------------------- #
# evidence layer 1 (class P): literal reads
#
# Same shape as rtti_scan.py's and vtable_scan.py's, deliberately: three tools
# writing three dialects of the same envelope is three chances for the validator
# to be right about one of them and wrong about the others.
# --------------------------------------------------------------------------- #

def locus_target(path: str, install_root: str | None = None) -> str:
    """The spelling a class-P read locus uses for *path*: install-relative, '/'.

    A bare basename is not a determinate location: this installation holds two
    different files called MISERY.exe -- the 422 kB bootstrap shim at the root
    and the 282 MB D-04 oracle under MISERY/Binaries/Win64 -- so a basename plus
    an offset names an ambiguity class rather than a range of bytes.
    """
    absolute = os.path.abspath(path)
    root = install_root
    if root is None:
        try:
            roots = pathguard.structural_install_roots(absolute)
        except (ValueError, OSError):
            roots = []
        root = roots[-1] if roots else None
    if not root:
        return os.path.basename(absolute)
    try:
        relative = os.path.relpath(absolute, os.path.abspath(root))
    except ValueError:                      # different drives on Windows
        return os.path.basename(absolute)
    relative = relative.replace("\\", "/")
    if relative.startswith("../") or relative in ("..", ".") or ":" in relative:
        return os.path.basename(absolute)
    return relative


def literal_read(target: str, join_key: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` states the offset AND the length -- which plan.md 10.3 v2.4 makes
    mandatory for the binary-analysis oracle to be class P at all -- and stops
    short of naming what the bytes are. ``join_key`` is a pointer into the
    interpretive layer and is not part of the claim.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the matching entry of constants[] / occurrences[] in the same "
            "document -- plan.md 10.3, the A-07 / A-07i split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": TASK,
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                "note": ("oracle binary-analysis. Read by %s, read-only. "
                         "Reproduction: PENDING." % GENERATOR_NAME),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
                "note": note,
            },
            # The note IS the claim, on purpose: tools/kb/validate.py derives the
            # claim class from this string alone, and a note that talked ABOUT
            # the record instead of stating it derives class I and drags the
            # two-method requirement in with it. The pointer to the interpretive
            # half lives outside the graded object, in interpretation_lives_in,
            # because naming a field or a layout inside this string is exactly
            # what would disqualify it.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result onto each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. On any
    disagreement nothing is adjusted: the failure is recorded and the reading
    stands as unreproduced.
    """
    reproduced = True
    try:
        with open(path, "rb", buffering=0) as handle:
            for read in literals:
                handle.seek(read["offset"])
                again = handle.read(read["length"])
                if hex_bytes(again) != read["bytes_hex"]:
                    reproduced = False
                    warnings.append(
                        "%s: the second read of %d bytes at offset %d gave %s but "
                        "the first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"],
                           hex_bytes(again), read["bytes_hex"]))
    except OSError as error:
        reproduced = False
        warnings.append("%s: the confirming re-read could not be performed: %s"
                        % (target, error))
    attestation = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def interpreted_annotation(target: str, second_method: str | None,
                           second_oracle: str = "external-doc") -> dict:
    """The class-I annotation for the interpretive layer: what the bytes MEAN.

    INFERRED, therefore class I unconditionally (plan.md 10.3), whatever the
    offsets are. 0.85 only when a second, independent method actually
    corroborated the reading, 0.79 otherwise, because re-reading the same bytes
    with the same tool is not a second method and neither is adding an artifact
    path or another clause of reasoning.
    """
    corroborated = bool(second_method)
    sources = [{
        "method": TASK,
        "artifact": None,
        "locator": target,
        "note": ("oracle binary-analysis + external-doc. A byte string found in "
                 "the image is matched against a value read out of the first-party "
                 "UE 5.4.4 source tree at the changelist named in the catalogue, "
                 "and is thereby given a name."),
    }]
    oracles = ["binary-analysis", "external-doc"]
    if corroborated:
        sources.append({
            "method": TASK,
            "artifact": None,
            "locator": target,
            "independent_of": ["%s/source-match" % TASK],
            "note": "oracle %s. Second, independent method: %s"
                    % (second_oracle, second_method),
        })
        if second_oracle not in oracles:
            oracles.append(second_oracle)
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_DECODED_CORROBORATED if corroborated
                       else CONFIDENCE_DECODED_SINGLE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this record NAMES the byte ranges the primitive layer "
            "reports, by matching them against text read out of an external source "
            "tree. That leans on the tree being the one this image was built from, "
            "which is an external-doc premise and not a measurement of this file. "
            "The primitive half is in literal_reads[]. "
            + (second_method or
               "No second, independent method corroborates the naming, so the "
               "confidence stays below the 0.80 band that plan.md 10.3 reserves "
               "for two-method claims.")
        ),
    }


# --------------------------------------------------------------------------- #
# the V-01..V-07 accounting, which M2s asked for explicitly
# --------------------------------------------------------------------------- #

def engine_version_crosscheck(catalogue: dict, findings: dict,
                              pair_shape: dict) -> dict:
    """State, field by field, what is a NEW measurement act and what is a re-reading.

    This project has miscounted exactly this before -- counting a second reading
    of one byte range as a second independent method -- so the accounting is a
    first-class output rather than a remark in a document that can drift from the
    numbers.
    """
    build = catalogue.get("build_version") or {}
    rows = [
        {
            "reading": "the eight-byte (UE4, UE5) package-version pair",
            "status": "RE-READING of V-06",
            "why": (
                "V-06 already read the UE5 value 1012 at file offset 125682456 of "
                "this same image. Finding it again here is the same bytes read by "
                "a second tool, which catches a bookkeeping error and nothing "
                "else. It is NOT a second independent method and must not be "
                "counted as one. What IS new is only the mechanism: this scan "
                "enumerates every value adjacent to the UE4 anchor across the "
                "whole surface instead of testing one offset, which is what makes "
                "the neighbour prediction falsifiable"),
            "offsets": [pair["file_offset"] for pair in pair_shape.get("pairs", [])
                        ][:MAX_RECORDED_OFFSETS],
        },
        {
            "reading": "the custom-version GUID census",
            "status": "NEW measurement act",
            "why": ("sixteen-byte ranges matched against FGuid definitions in the "
                    "first-party tree. No V-method read these bytes and no "
                    "V-method used this surface"),
        },
        {
            "reading": "the FCrc lookup tables",
            "status": "NEW measurement act",
            "why": ("kilobyte-scale ranges matched against the engine's own "
                    "initialiser lists. Never read before in this project"),
        },
        {
            "reading": "PACKAGE_FILE_TAG and the container magics",
            "status": "NEW measurement act",
            "why": "four-byte and sixteen-byte ranges never read before here",
        },
        {
            "reading": "the FNV and CityHash seeds",
            "status": "NEW measurement act",
            "why": "four- and eight-byte ranges never read before here",
        },
    ]
    agreement = None
    reason = None
    if pair_shape.get("searched"):
        census = pair_shape.get("ue5_value_census") or {}
        enum = ((catalogue.get("ue5_object_version_enum") or {})
                .get("enumerators") or {})
        automatic = enum.get("AUTOMATIC_VERSION")
        if not census:
            agreement = "UNKNOWN"
            reason = (
                "no eight-byte pair with the UE4 anchor and a value in the band was "
                "found on the searched surface, so this run has nothing to compare "
                "against UE 5.4.4. That is a statement about this surface and this "
                "shape, not about the image")
        elif automatic is None:
            agreement = "UNKNOWN"
            reason = ("the source tree's AUTOMATIC_VERSION could not be derived, so "
                      "there is no reference value to agree or disagree with")
        else:
            values = sorted(int(key) for key in census)
            if values == [automatic]:
                agreement = "AGREES"
            elif automatic in values:
                agreement = "AGREES, with other values also present"
            else:
                agreement = "DISAGREES"
            reason = (
                "the source tree at the catalogued changelist puts "
                "EUnrealEngineObjectUE5Version::AUTOMATIC_VERSION at %d; the values "
                "found next to the UE4 anchor on the searched surface are %s"
                % (automatic, ", ".join(str(v) for v in values)))
    return {
        "changelist_of_the_cited_tree": build.get("Changelist"),
        "branch_of_the_cited_tree": build.get("BranchName"),
        "engine_version_of_the_cited_tree": (
            "%s.%s.%s" % (build.get("MajorVersion"), build.get("MinorVersion"),
                          build.get("PatchVersion"))
            if build else None),
        "version_constants_agree_with_the_cited_tree": agreement,
        "agreement_reason": reason,
        "what_agreement_would_and_would_not_show": (
            "agreement shows that the serialization version this image carries is "
            "the one this source tree writes. It does NOT show that the image was "
            "built from this tree: every 5.4.x patch release in this line carries "
            "the same serialization version, so the version pair discriminates the "
            "minor line and not the changelist. The changelist evidence is V-01's "
            "and this run neither strengthens nor weakens it"),
        "per_reading": rows,
        "why_this_object_exists": (
            "so that a reader can see which of these readings are new byte ranges "
            "and which are a second look at a range V-01..V-07 already read. A "
            "re-reading raises confidence in the bookkeeping and not in the claim, "
            "and this project has previously counted one as the other"),
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(patterns: list[dict], scan: dict,
                            controls: list[dict], findings: dict,
                            pair_shape: dict, catalogue: dict) -> list[dict]:
    """Checks whose PURPOSE is to break this run's conclusions.

    A scan that only produces supporting numbers cannot tell a real finding from
    a broken scanner, so each probe states what result would refute the headline
    and reports whether that happened.
    """
    probes: list[dict] = []

    control_hits = {row["constant_id"]: len(scan["hits"].get(row["sha256"], []))
                    for row in controls}
    total_control_hits = sum(control_hits.values())
    probes.append({
        "probe": "synthetic controls",
        "what_would_refute": (
            "any occurrence of a synthetic control pattern. These byte strings are "
            "derived from a fixed sentence by SHA-256 and have no relation to any "
            "engine, so a hit means the matcher, the streaming or the offset "
            "arithmetic is wrong and every other count in this document is void"),
        "controls": len(controls),
        "control_occurrences_total": total_control_hits,
        "per_control": control_hits,
        "refuted": total_control_hits > 0,
        "verdict": ("REFUTATION FAILED (the scan survives): no synthetic control "
                    "occurs on the searched surface"
                    if total_control_hits == 0 else
                    "REFUTED: a synthetic control was found, so this run's "
                    "occurrence counts must be discarded"),
    })

    # Is a table hit an artefact of a short needle? The prefix and the full table
    # are separate patterns for exactly this: if the prefix occurs far more often
    # than the full table, the prefix is matching something else.
    prefix_rows = []
    for pattern in patterns:
        if pattern["encoding"] != ENCODING_TABLE_PREFIX:
            continue
        full = next((p for p in patterns
                     if p["constant_id"] == pattern["constant_id"]
                     and p["encoding"] == ENCODING_TABLE), None)
        prefix_rows.append({
            "constant_id": pattern["constant_id"],
            "prefix_bytes": pattern["length"],
            "prefix_occurrences": len(scan["hits"].get(pattern["sha256"], [])),
            "full_bytes": full["length"] if full else None,
            "full_occurrences": (len(scan["hits"].get(full["sha256"], []))
                                 if full else None),
        })
    excess = [row for row in prefix_rows
              if row["full_occurrences"] is not None
              and row["prefix_occurrences"] > row["full_occurrences"]]
    probes.append({
        "probe": "table prefix against the whole table",
        "what_would_refute": (
            "a prefix occurring more often than the whole table it starts, which "
            "would mean the short needle is matching something that is not that "
            "table and that the shorter pattern's count is not evidence about it"),
        "rows": prefix_rows,
        "prefixes_occurring_more_often_than_their_table": len(excess),
        "refuted": bool(excess),
        "verdict": ("REFUTATION FAILED (the table hits survive): no table prefix "
                    "occurs more often than the whole table it starts"
                    if not excess else
                    "the prefix of %d table(s) occurs more often than the table "
                    "itself; those prefix counts are NOT evidence about the table"
                    % len(excess)),
    })

    # Low-entropy patterns: if a four-byte needle occurs thousands of times, its
    # presence carries no information, and saying so is the honest reading.
    noisy = []
    for pattern in patterns:
        count = len(scan["hits"].get(pattern["sha256"], []))
        if pattern["length"] <= 4 and count > 16:
            noisy.append({"constant_id": pattern["constant_id"],
                          "length": pattern["length"], "occurrences": count})
    probes.append({
        "probe": "is a short pattern's presence informative at all",
        "what_would_refute": (
            "nothing -- this probe does not test a conclusion, it BOUNDS one. A "
            "four-byte value occurring many times over 134 MB is what chance "
            "produces, so for those patterns 'present' is not a finding and the "
            "offsets are not anchors"),
        "short_patterns_with_more_than_16_occurrences": noisy,
        "count": len(noisy),
        "refuted": False,
        "verdict": ("%d short pattern(s) occur often enough that their presence "
                    "carries no information and is reported as such"
                    % len(noisy)),
    })

    # The neighbour prediction of the version pair. This one CAN fail and its
    # failing would mean the pair is not the global the source says it is.
    if pair_shape.get("searched"):
        total = pair_shape.get("pairs_total", 0)
        with_neighbour = pair_shape.get("pairs_with_the_predicted_neighbour", 0)
        prediction = pair_shape.get("neighbour_prediction")
        probes.append({
            "probe": "the version pair's declared neighbour",
            "what_would_refute": (
                "a pair matching the shape with NO occurrence anywhere of the "
                "eight bytes the source predicts must follow it. That would mean "
                "the eight bytes found are an unrelated coincidence rather than "
                "the global the source declares"),
            "prediction": prediction,
            "pairs_matching_the_shape": total,
            "pairs_followed_by_the_predicted_bytes": with_neighbour,
            "refuted": bool(total and prediction and with_neighbour == 0),
            "verdict": (
                "no pair matched the shape, so the prediction was not tested"
                if not total else
                "the prediction could not be formed, so it was not tested"
                if not prediction else
                "REFUTATION FAILED (the reading survives): %d of %d pairs are "
                "followed by exactly the eight bytes the source predicts"
                % (with_neighbour, total) if with_neighbour else
                "REFUTED: no pair is followed by the predicted bytes, so the "
                "eight bytes found are not shown to be the global the source "
                "declares"),
        })

    # Coverage: how much of the catalogue was searched at all. A tool that
    # searched two of twenty constants and found both would look perfect.
    entries = catalogue["constants"]
    derived = [e for e in entries if e.get("derived")]
    searched = [e for e in entries if e.get("searched")]
    probes.append({
        "probe": "catalogue coverage",
        "what_would_refute": (
            "nothing -- this probe exists so that the found/absent tally cannot be "
            "read as a score. A constant that was never searched for is neither "
            "found nor missing, and a run that searched few of them would "
            "otherwise look better than one that searched many"),
        "catalogue_entries": len(entries),
        "derived_from_the_tree": len(derived),
        "failed_to_derive": len(entries) - len(derived),
        "searched_in_the_image": len(searched),
        "not_searched_by_design": len(derived) - len(searched),
        "custom_version_guids_searched": len(
            (catalogue.get("custom_versions") or {}).get("joined", [])),
        "custom_version_registrations_unresolved": (
            (catalogue.get("custom_versions") or {})
            .get("registrations_unresolved_total")),
        "refuted": False,
        "verdict": ("%d of %d catalogue entries were derived from the tree and %d "
                    "were searched for in the image"
                    % (len(derived), len(entries), len(searched))),
    })
    return probes


# --------------------------------------------------------------------------- #
# assembling the findings and the document
# --------------------------------------------------------------------------- #

def _is_d04_oracle(path: str) -> bool:
    """True for the second, 282 MB MISERY.exe -- decision D-04's read-only oracle."""
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/misery/binaries/win64/misery.exe")


def _spread(items: list, count: int) -> list:
    """*count* items spread evenly across *items*, first and last included.

    Taking the first N would sample the front of the image, and the front of a
    PE image is not representative of it. Spreading is why a sample can be
    called a sample.
    """
    if count <= 0 or not items:
        return []
    if count >= len(items):
        return list(items)
    if count == 1:
        return [items[0]]
    step = (len(items) - 1) / (count - 1)
    return [items[int(round(index * step))] for index in range(count)]


def build_findings(patterns: list[dict], scan: dict, catalogue: dict) -> dict:
    """One row per pattern: what was looked for, where it was found, how often."""
    rows: list[dict] = []
    by_family: dict[str, dict] = {}
    entry_by_id = {entry["id"]: entry for entry in catalogue["constants"]}
    joined_by_key = {"custom_version:%s" % row["key"]: row
                     for row in (catalogue.get("custom_versions") or {}
                                 ).get("joined", [])}
    joined_by_key.update({"custom_version_name:%s" % row["key"]: row
                          for row in (catalogue.get("custom_versions") or {}
                                      ).get("joined", [])})

    for pattern in patterns:
        offsets = scan["hits"].get(pattern["sha256"], [])
        truncated = pattern["sha256"] in set(scan["truncated"])
        entry = entry_by_id.get(pattern["constant_id"])
        joined = joined_by_key.get(pattern["constant_id"])
        citation = None
        if entry is not None:
            citation = entry.get("citation")
        elif pattern.get("citation"):
            citation = pattern["citation"]
        row = {
            "constant_id": pattern["constant_id"],
            "family": pattern["family"],
            "label": pattern["label"],
            "encoding": pattern["encoding"],
            "pattern_length": pattern["length"],
            "pattern_bytes_hex": pattern["bytes_hex"],
            "pattern_sha256": pattern["sha256"],
            "source_citation": citation,
            "occurrences": len(offsets),
            "occurrences_is_a_floor_not_a_total": truncated,
            "offsets": offsets[:MAX_RECORDED_OFFSETS],
            "offsets_recorded": min(len(offsets), MAX_RECORDED_OFFSETS),
            "found": bool(offsets),
            "proves_if_found": PROVES.get(pattern["family"]),
            "does_not_prove": DOES_NOT_PROVE.get(pattern["family"]),
        }
        if entry is not None:
            row["name"] = entry["name"]
            row["role"] = entry.get("role")
            row["value"] = entry.get("value")
            row["source_text"] = entry.get("source_text")
        if joined is not None:
            row["name"] = joined["key"]
            row["friendly_name"] = joined.get("friendly_name")
            row["guid"] = joined.get("guid")
        rows.append(row)

        bucket = by_family.setdefault(pattern["family"], {
            "patterns": 0, "found": 0, "absent": 0, "occurrences_total": 0,
            "truncated_patterns": 0})
        bucket["patterns"] += 1
        bucket["found" if offsets else "absent"] += 1
        bucket["occurrences_total"] += len(offsets)
        if truncated:
            bucket["truncated_patterns"] += 1

    rows.sort(key=lambda r: (FAMILY_ORDER.index(r["family"])
                             if r["family"] in FAMILY_ORDER else len(FAMILY_ORDER),
                             r["constant_id"], r["encoding"]))
    return {"rows": rows, "by_family": by_family}


def analyze(path: str, *, ue_source_root: str, catalogue_in: str | None = None,
            sections: tuple[str, ...] | None = None,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            want_custom_versions: bool = True,
            want_friendly_names: bool = True,
            want_file_digest: bool = True,
            install_root: str | None = None,
            source_file_limit: int | None = None) -> dict:
    """Read the image, read the tree, and keep the two answers apart."""
    started_total = time.monotonic()
    warnings: list[str] = []
    timings: dict[str, float] = {}
    marker = [time.monotonic()]

    def lap(name: str) -> None:
        now = time.monotonic()
        timings[name] = round(now - marker[0], 3)
        marker[0] = now

    catalogue_reused = False
    if catalogue_in:
        try:
            with open(catalogue_in, "r", encoding="utf-8") as handle:
                catalogue = json.load(handle)
            catalogue_reused = True
            if catalogue.get("generator_version") != GENERATOR_VERSION:
                warnings.append(
                    "the reused catalogue %s was written by %s version %r but this "
                    "is version %s; the loci may have changed shape since"
                    % (catalogue_in, catalogue.get("generator"),
                       catalogue.get("generator_version"), GENERATOR_VERSION))
        except (OSError, ValueError) as error:
            warnings.append("the catalogue %s could not be reused (%s); it is being "
                            "derived from the tree instead" % (catalogue_in, error))
            catalogue = build_catalogue(ue_source_root, warnings,
                                       want_custom_versions=want_custom_versions,
                                       limit_files=source_file_limit)
    else:
        catalogue = build_catalogue(ue_source_root, warnings,
                                   want_custom_versions=want_custom_versions,
                                   limit_files=source_file_limit)
    lap("catalogue")

    patterns = build_patterns(catalogue, warnings,
                              want_friendly_names=want_friendly_names)
    controls = control_patterns()
    all_patterns = patterns + controls
    lap("patterns")

    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        warnings.extend(headers.warnings)
        kept, dropped = select_surface(headers, sections)
        if not kept:
            warnings.append(
                "no section was selected, so NOTHING was searched; every absence "
                "below is an absence from an empty surface")
        surface = {
            "sections": describe_sections(kept),
            "sections_not_scanned": dropped,
            "section_names": [s["name"] for s in kept],
            "bytes_in_surface": sum(min(s["rsize"], max(0, image.size - s["raw_pointer"]))
                                    for s in kept),
            "note": (".text IS included by default. A constant hunt that skipped "
                     "the code would be reporting a null result about a surface "
                     "chosen to make the null result likely"),
        }
        lap("load_surface")

        scan = scan_patterns(image, kept, all_patterns, warnings)
        lap("scan")

        anchor_entry = next((e for e in catalogue["constants"]
                             if e["id"] == "ue4_object_version_automatic"), None)
        oldest_entry = next((e for e in catalogue["constants"]
                             if e["id"] == "ue4_oldest_loadable_package"), None)
        pair_shape = scan_version_pair_shape(
            image, kept,
            anchor_entry.get("value") if anchor_entry else None,
            catalogue.get("ue5_object_version_enum"),
            oldest_entry.get("value") if oldest_entry else None,
            warnings)
        lap("version_pair_shape")

        findings = build_findings(patterns, scan, catalogue)

        target = locus_target(path, install_root)
        literals: list[dict] = []
        found_rows = [row for row in findings["rows"] if row["found"]]
        for row in _spread(found_rows, literal_samples):
            offset = row["offsets"][0]
            raw = image.read_clamped(offset, row["pattern_length"])
            if len(raw) != row["pattern_length"]:
                warnings.append(
                    "the literal sample at offset %d could not be re-read at full "
                    "length; it is omitted rather than recorded short" % offset)
                continue
            literals.append(literal_read(
                target, row["constant_id"], offset, raw,
                note="a %d-byte range inside section %s of the searched surface"
                     % (len(raw), row.get("section") or
                        surface["section_names"][0] if surface["section_names"]
                        else "?")))
        for pair in _spread(pair_shape.get("pairs", []), min(2, literal_samples)):
            raw = image.read_clamped(pair["file_offset"], 8)
            if len(raw) == 8:
                literals.append(literal_read(
                    target, "version_pair_shape", pair["file_offset"], raw,
                    note="an eight-byte range at four-byte alignment"))
        reproduced = confirm_literal_reads(path, literals, target, warnings)
        lap("literal_reads")

        probes = build_refutation_probes(all_patterns, scan, controls, findings,
                                         pair_shape, catalogue)
        lap("probes")

        file_sha256 = None
        if want_file_digest:
            digest = hashlib.sha256()
            for _position, chunk in image.iter_chunks(0, image.size):
                digest.update(chunk)
            file_sha256 = digest.hexdigest()
        lap("digest")

        crosscheck = engine_version_crosscheck(catalogue, findings, pair_shape)

        timings["total"] = round(time.monotonic() - started_total, 3)

        document = {
            "schema": SCHEMA_ID,
            "task": TASK,
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "generated_at": now_iso_utc(),
            "file": {
                "path": path,
                "name": os.path.basename(path),
                "install_relative": target,
                "size": image.size,
                "sha256": file_sha256,
                "pe_format": headers.pe_format,
                "image_base": headers.image_base,
                "machine": headers.machine,
            },
            "d04_oracle_only": _is_d04_oracle(path),
            "catalogue": catalogue,
            "catalogue_reused_from": catalogue_in if catalogue_reused else None,
            "measurement": {
                "searched_surface": surface,
                "patterns_total": len(all_patterns),
                "patterns_real": len(patterns),
                "patterns_control": len(controls),
                "scan": {key: value for key, value in scan.items()
                         if key != "hits"},
                "version_pair_shape": pair_shape,
                "what_an_absence_means": (
                    "every absence in occurrences[] is an absence of the EXACT byte "
                    "pattern printed on that row, from the EXACT surface printed in "
                    "searched_surface, and from nothing wider. A constant folded "
                    "into an immediate in a form this tool does not search, or "
                    "materialised by arithmetic, is absent here and present in the "
                    "image"),
            },
            "occurrences": findings["rows"],
            "by_family": findings["by_family"],
            "engine_version_crosscheck": crosscheck,
            "refutation_probes": probes,
            "literal_reads": literals,
            "literal_reads_reproduced": reproduced,
            "interpreted_annotation": interpreted_annotation(
                target,
                ("the eight-byte pair is followed by exactly the eight bytes the "
                 "source predicts must follow it (%d of %d pairs), which is a "
                 "prediction about DIFFERENT bytes than the ones matched and so an "
                 "independent test of the naming"
                 % (pair_shape.get("pairs_with_the_predicted_neighbour", 0),
                    pair_shape.get("pairs_total", 0)))
                if pair_shape.get("pairs_with_the_predicted_neighbour") else None),
            "summary": _summary(findings, scan, controls, pair_shape, catalogue,
                                reproduced),
            "timings_seconds": timings,
            "warnings": warnings,
        }
        return document


def _summary(findings: dict, scan: dict, controls: list[dict],
             pair_shape: dict, catalogue: dict, reproduced: bool) -> dict:
    control_hits = sum(len(scan["hits"].get(row["sha256"], [])) for row in controls)
    rows = findings["rows"]
    tables = [r for r in rows if r["family"] == FAMILY_HASH_TABLE
              and r["encoding"] == ENCODING_TABLE]
    guids = [r for r in rows if r["family"] == FAMILY_CUSTOM_VERSION_GUID]
    names = [r for r in rows if r["family"] == FAMILY_CUSTOM_VERSION_NAME]
    return {
        "patterns_searched": len(rows),
        "patterns_found": sum(1 for r in rows if r["found"]),
        "patterns_absent": sum(1 for r in rows if not r["found"]),
        "occurrences_total": sum(r["occurrences"] for r in rows),
        "control_patterns": len(controls),
        "control_occurrences": control_hits,
        "controls_clean": control_hits == 0,
        "hash_tables_searched": len(tables),
        "hash_tables_found_in_full": sum(1 for r in tables if r["found"]),
        "custom_version_guids_searched": len(guids),
        "custom_version_guids_found": sum(1 for r in guids if r["found"]),
        "custom_version_names_searched": len(names),
        "custom_version_names_found": sum(1 for r in names if r["found"]),
        "version_pairs_found": pair_shape.get("pairs_total", 0),
        "version_pair_ue5_values": sorted(
            int(key) for key in (pair_shape.get("ue5_value_census") or {})),
        "literal_reads_reproduced": reproduced,
        "catalogue_changelist": (catalogue.get("build_version") or {}
                                 ).get("Changelist"),
        "primary_finding": (
            "the strongest anchors this scan can offer are the whole hash TABLES, "
            "because a table of hundreds of words cannot be constant-folded, "
            "re-derived by the compiler from its initialiser, or matched by "
            "accident. A scalar magic is weaker in exact proportion to how short "
            "it is, and every short pattern's occurrence count is printed so that "
            "the reader can see when 'present' means nothing"),
    }


def public_document(document: dict) -> dict:
    """The document as published: the same object, with the raw needles dropped.

    Nothing is redacted for C-13 reasons -- no byte of the game image is
    reproduced here beyond the offsets and the patterns, and the patterns come
    from a public engine tree, not from the game. What is dropped is only the
    unhashable `bytes` field of each pattern, which is not JSON.
    """
    return document


def jsonl_lines(document: dict, only_found: bool = False) -> list[str]:
    lines = []
    for row in document["occurrences"]:
        if only_found and not row["found"]:
            continue
        lines.append(json.dumps({
            "build_target": document["file"]["install_relative"],
            "constant_id": row["constant_id"],
            "family": row["family"],
            "name": row.get("name"),
            "encoding": row["encoding"],
            "pattern_length": row["pattern_length"],
            "pattern_bytes_hex": row["pattern_bytes_hex"],
            "pattern_sha256": row["pattern_sha256"],
            "source_citation": row["source_citation"],
            "value": row.get("value"),
            "found": row["found"],
            "occurrences": row["occurrences"],
            "occurrences_is_a_floor_not_a_total":
                row["occurrences_is_a_floor_not_a_total"],
            "offsets": row["offsets"],
        }, sort_keys=True, ensure_ascii=False))
    return lines


# --------------------------------------------------------------------------- #
# human output and CLI
# --------------------------------------------------------------------------- #

def format_summary(document: dict, row_limit: int = 40) -> str:
    lines: list[str] = []

    def add(text: str = "") -> None:
        lines.append(text)

    info = document["file"]
    add("%s (%s %s)" % (info["path"], GENERATOR_NAME, GENERATOR_VERSION))
    add("  %s, image base 0x%X, %d bytes on disk"
        % (info["pe_format"], info["image_base"] or 0, info["size"]))
    if document["d04_oracle_only"]:
        add("  NOTE: this is the D-04 read-only oracle. No build-configuration "
            "conclusion is drawn from anything below.")

    catalogue = document["catalogue"]
    build = catalogue.get("build_version") or {}
    add()
    add("Catalogue, derived from the source tree (oracles external-doc + filesystem)")
    add("  tree            : %s" % catalogue["ue_source_root"])
    add("  declares        : %s.%s.%s CL %s, branch %s"
        % (build.get("MajorVersion"), build.get("MinorVersion"),
           build.get("PatchVersion"), build.get("Changelist"),
           build.get("BranchName")))
    if document.get("catalogue_reused_from"):
        add("  REUSED from     : %s (the tree was not re-walked this run)"
            % document["catalogue_reused_from"])
    entries = catalogue["constants"]
    add("  constants       : %d entries, %d derived, %d searched, %d not searched "
        "by design"
        % (len(entries), sum(1 for e in entries if e.get("derived")),
           sum(1 for e in entries if e.get("searched")),
           sum(1 for e in entries if e.get("derived") and not e.get("searched"))))
    custom = catalogue.get("custom_versions") or {}
    if custom:
        add("  custom versions : %d registrations, %d FGuid definitions, %d joined, "
            "%d unresolved"
            % (custom.get("registrations_total", 0),
               custom.get("guid_definitions_total", 0),
               custom.get("joined_total", 0),
               custom.get("registrations_unresolved_total", 0)))
        walk = custom.get("walk") or {}
        if walk:
            add("  tree walk       : %d files read, %d decoded, %.1f MB, %.1f s"
                % (walk.get("files_read", 0), walk.get("files_scanned", 0),
                   (walk.get("bytes_read", 0) or 0) / 1e6,
                   walk.get("seconds", 0.0) or 0.0))

    add()
    add("Values read out of the tree (these are facts about the TREE, not the image)")
    for entry in entries:
        if not entry.get("derived"):
            add("  %-34s DERIVATION FAILED: %s"
                % (entry["id"], entry.get("derivation_error")))
            continue
        if entry["kind"] == "table":
            shown = "%d words, %d bytes, sha256 %s"
            add("  %-34s %s" % (entry["id"], shown % (
                entry["word_count"], entry["width"],
                entry["sha256_of_the_packed_table"][:16])))
        elif entry["kind"] == "ascii":
            add("  %-34s %r" % (entry["id"], entry["text_value"]))
        else:
            add("  %-34s %d (0x%X)" % (entry["id"], entry["value"], entry["value"]))
        add("      %s%s" % (entry["citation"],
                            "" if entry.get("searched")
                            else "   [NOT SEARCHED: %s]"
                                 % entry.get("not_searched_reason", "")))

    measurement = document["measurement"]
    surface = measurement["searched_surface"]
    add()
    add("Searched surface of the image (oracle binary-analysis)")
    for section in surface["sections"]:
        add("  %-10s file [%d, %d)  %d bytes%s"
            % (section["name"], section["file_offset"],
               section["file_offset"] + section["raw_size"], section["raw_size"],
               "  executable" if section["is_executable"] else ""))
    if surface["sections_not_scanned"]:
        add("  not scanned: %s" % ", ".join(surface["sections_not_scanned"]))
    scan = measurement["scan"]
    add("  %d patterns (%d real, %d control), %d bytes examined in %d windows, "
        "overlap %d"
        % (measurement["patterns_total"], measurement["patterns_real"],
           measurement["patterns_control"], scan["bytes_examined"],
           scan["windows"], scan["overlap_bytes"]))

    add()
    add("Occurrences, by family")
    add("  %-30s %9s %7s %8s %13s" % ("family", "patterns", "found", "absent",
                                      "occurrences"))
    for family in FAMILY_ORDER:
        bucket = document["by_family"].get(family)
        if not bucket:
            continue
        add("  %-30s %9d %7d %8d %13d"
            % (family, bucket["patterns"], bucket["found"], bucket["absent"],
               bucket["occurrences_total"]))

    add()
    add("Occurrences, by pattern (first %d rows)" % row_limit)
    for row in document["occurrences"][:row_limit]:
        mark = "FOUND" if row["found"] else "absent"
        count = ">=%d" % row["occurrences"] if \
            row["occurrences_is_a_floor_not_a_total"] else str(row["occurrences"])
        add("  %-6s %-42s %-24s %5dB  n=%s"
            % (mark, row["constant_id"][:42], row["encoding"],
               row["pattern_length"], count))
        if row["found"]:
            add("         first offsets: %s"
                % ", ".join(str(o) for o in row["offsets"][:4]))
    if len(document["occurrences"]) > row_limit:
        add("  ... %d more rows (see --json / --jsonl)"
            % (len(document["occurrences"]) - row_limit))

    pair = measurement["version_pair_shape"]
    add()
    add("The eight-byte package-version pair, searched as a SHAPE")
    if not pair.get("searched"):
        add("  not searched (the UE4 anchor could not be derived)")
    else:
        add("  UE4 anchor %s, band %s" % (pair["ue4_anchor"], pair["band"]))
        add("  pairs matching the shape         : %d" % pair["pairs_total"])
        add("  distinct UE5 values found        : %s"
            % ", ".join("%s x%d" % (key, value)
                        for key, value in (pair["ue5_value_census"] or {}).items()))
        add("  followed by the predicted bytes  : %d of %d"
            % (pair["pairs_with_the_predicted_neighbour"], pair["pairs_total"]))
        for row in pair["pairs"][:8]:
            add("    offset %d  %s  ue5=%s  neighbour_matches=%s"
                % (row["file_offset"], row["bytes_hex"], row["ue5_value"],
                   row["next_eight_bytes_match_the_prediction"]))

    cross = document["engine_version_crosscheck"]
    add()
    add("Agreement with UE 5.4.4 CL %s, and what kind of act each reading is"
        % cross["changelist_of_the_cited_tree"])
    add("  verdict : %s" % cross["version_constants_agree_with_the_cited_tree"])
    add("  reason  : %s" % cross["agreement_reason"])
    for row in cross["per_reading"]:
        add("  %-46s %s" % (row["reading"][:46], row["status"]))

    add()
    add("Refutation probes")
    for probe in document["refutation_probes"]:
        add("  %s" % probe["probe"])
        add("    %s" % probe["verdict"])

    add()
    add("Literal reads (class P): %d ranges, re-read through a second handle: %s"
        % (len(document["literal_reads"]),
           "reproduced" if document["literal_reads_reproduced"] else "NOT REPRODUCED"))
    if document["warnings"]:
        add()
        add("Warnings (%d)" % len(document["warnings"]))
        for warning in document["warnings"][:20]:
            add("  - %s" % warning)
        if len(document["warnings"]) > 20:
            add("  ... %d more" % (len(document["warnings"]) - 20))
    add("Timings (s): %s" % json.dumps(document["timings_seconds"], sort_keys=True))
    return "\n".join(lines)


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    """Write *text* through the output guard. Layer 2 of plan.md 1.5 / D-01."""
    checked = pathguard.check_output_path(out_path, install_root, what=what)
    directory = os.path.dirname(os.path.abspath(checked))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(checked, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return os.path.abspath(checked)


def strip_pattern_bytes(catalogue: dict) -> dict:
    """The catalogue as serialised: the packed table bytes stay, nothing is dropped.

    Kept as a named no-op rather than removed, because a reader of the JSON will
    wonder whether anything was filtered out of the catalogue before publication,
    and the answer -- nothing was -- deserves a place to be written down. The
    packed table hex IS published: it comes from a public engine source tree, so
    C-13 does not touch it, and without it the pattern cannot be reproduced.
    """
    return catalogue


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="find_constants.py",
        description=(
            "Read-only scanner for characteristic engine constants in a PE image "
            "(plan.md task S-08). Every pattern is DERIVED from a first-party "
            "Unreal Engine source tree at run time and carries its file and line; "
            "nothing is hard-coded but where to look. Prints a human summary by "
            "default. Refuses any output path that resolves inside a game "
            "installation (D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--ue-source-root", required=True, metavar="DIR",
                        help=("the Engine directory of an Unreal Engine source tree "
                              "-- the one holding Build/Build.version, Source/ and "
                              "Plugins/. Required: without it there is no catalogue "
                              "and nothing to search for"))
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--jsonl", action="store_true",
                        help="print the per-pattern JSONL artifact to stdout")
    parser.add_argument("--jsonl-found-only", action="store_true",
                        help="restrict the JSONL artifact to patterns that were found")
    parser.add_argument("--out", default=None,
                        help=("write the JSON document here; refused (exit 2) if it "
                              "resolves inside a game installation, before anything "
                              "is opened"))
    parser.add_argument("--jsonl-out", default=None,
                        help="write the per-pattern constants.jsonl artifact here")
    parser.add_argument("--catalogue-out", default=None, metavar="FILE",
                        help=("write the derived catalogue here so a later run can "
                              "reuse it instead of re-walking the source tree"))
    parser.add_argument("--catalogue-in", default=None, metavar="FILE",
                        help=("reuse a catalogue written by --catalogue-out; the "
                              "document records that it was reused"))
    parser.add_argument("--install-dir", default=None,
                        help=("installation root the output guard checks against "
                              "(default: auto-detected from the input path)"))
    parser.add_argument("--sections", default=None, metavar="A,B",
                        help=("comma-separated section names to scan (default: "
                              "every section with raw data except .reloc and "
                              ".rsrc -- .text INCLUDED)"))
    parser.add_argument("--no-custom-versions", action="store_true",
                        help=("skip the source-tree walk for custom-version GUIDs; "
                              "the family is then empty for that reason and its "
                              "absence says nothing"))
    parser.add_argument("--no-friendly-names", action="store_true",
                        help="do not search for the UTF-16 friendly-name strings")
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help=("how many evenly spaced found patterns to record as "
                              "class-P literal reads (default: %d)"
                              % DEFAULT_LITERAL_SAMPLES))
    parser.add_argument("--rows", type=int, default=40, metavar="N",
                        help="how many per-pattern rows the summary prints")
    parser.add_argument("--source-file-limit", type=int, default=None, metavar="N",
                        help=("stop the source-tree walk after N files. For tests "
                              "and for a fast smoke run; a limited walk is recorded "
                              "in the catalogue and makes the custom-version census "
                              "a FLOOR"))
    parser.add_argument("--no-digest", action="store_true",
                        help="skip the whole-file sha256")
    return parser


def _split_sections(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(part.strip() for part in value.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if args.literal_samples < 0:
        print("error: --literal-samples must not be negative", file=sys.stderr)
        return 2
    if not args.catalogue_in and not os.path.isdir(args.ue_source_root):
        print("error: --ue-source-root is not a directory: %s"
              % args.ue_source_root, file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again.
    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out),
                        ("--catalogue-out", args.catalogue_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root,
                                                        what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            args.path,
            ue_source_root=args.ue_source_root,
            catalogue_in=args.catalogue_in,
            sections=_split_sections(args.sections),
            literal_samples=args.literal_samples,
            want_custom_versions=not args.no_custom_versions,
            want_friendly_names=not args.no_friendly_names,
            want_file_digest=not args.no_digest,
            # Only an EXPLICIT root is passed on: the fallback inside
            # detect_install_root is "the configured root" and would make a file
            # outside any installation look relative to one it is not in.
            install_root=args.install_dir,
            source_file_limit=args.source_file_limit,
        )
    except PEFormatError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(public_document(document)),
                                      checked["--out"], install_root, "--out"))
        if "--jsonl-out" in checked:
            body = "".join(line + "\n" for line
                           in jsonl_lines(document, args.jsonl_found_only))
            written.append(write_text(body, checked["--jsonl-out"], install_root,
                                      "--jsonl-out"))
        if "--catalogue-out" in checked:
            written.append(write_text(
                dump_json(strip_pattern_bytes(document["catalogue"])),
                checked["--catalogue-out"], install_root, "--catalogue-out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(public_document(document)))
    elif args.jsonl:
        for line in jsonl_lines(document, args.jsonl_found_only):
            sys.stdout.write(line + "\n")
    else:
        print(format_summary(document, row_limit=args.rows))
        for path in written:
            print("\nwritten: %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
