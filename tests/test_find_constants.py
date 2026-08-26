#!/usr/bin/env python3
"""Tests for tools/static/find_constants.py (task S-08).

This tool has two halves that fail in different ways, so this file has two
halves too.

**The source-derivation layer** turns text into numbers. Its failure mode is
silent: a regex that matches the wrong line, a brace matcher that stops at the
first inner brace, an enum walk that gets an implicit increment wrong -- each of
those produces a number that looks like an answer. So it is tested against a
SYNTHETIC source tree written by these tests, where the expected value of every
constant is known because the test wrote it. The two forms that are genuinely
hard get their own tests: an enumerator with no initialiser (whose value is a
count, not a literal) and an enumerator defined as another one minus one, which
is how ObjectVersion.h actually spells the value this project cares about.

**The image-scanning layer** turns bytes into offsets. Its failure mode is
losing a hit at a window boundary, which no summary line would reveal. So it is
tested against SYNTHETIC PE images assembled byte by byte with the same
``PEBuilder`` as ``tests/test_pe_info.py`` -- imported, not copied -- with the
chunk size shrunk so that the boundary case is reachable, and with a pattern
planted deliberately across it.

No test reads a game file and none reads the real engine tree: decision D-01
makes the installation a read-only research target, and a suite that depended on
either would be neither reproducible on another machine nor runnable where they
are absent.

Coverage:
  * the C integer parser, including the suffixes the engine writes, and refusals
  * the comment stripper's line-number invariant, which every citation rests on
  * the enum walk: implicit increment, X = Y - 1, and refusal to guess
  * brace matching against a nested initialiser
  * the table parser: nested braces flattened, word-count mismatch refused
  * the FGuid / registration join, including the unresolved report
  * a derivation failure recorded on the row instead of raising
  * a planted constant found at the exact offset it was planted at
  * a pattern straddling a scan-window boundary
  * the synthetic controls, which must never be found
  * the eight-byte version-pair shape and its neighbour prediction, both when
    the prediction holds and when it does not
  * the occurrence cap reported as a floor
  * the class-P literal layer, its re-read attestation, and a forced failure
  * no confidence anywhere reaching 1.00
  * determinism, the JSONL artifact, and the pathguard contract on every output
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

import find_constants  # noqa: E402
import pathguard  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

FIND_CONSTANTS_PATH = os.path.join(REPO_ROOT, "tools", "static",
                                   "find_constants.py")

RDATA_FLAGS = 0x40000040          # initialised data, read
DATA_FLAGS = 0xC0000040           # initialised data, read/write
TEXT_FLAGS = 0x60000020           # code, execute, read


# --------------------------------------------------------------------------- #
# 1. the C integer parser
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text,expected", [
    ("0x9E2A83C1", 0x9E2A83C1),
    ("0xcbf29ce484222325", 0xCBF29CE484222325),
    ("0x9ae16a3b2f90404fULL", 0x9AE16A3B2F90404F),
    ("16777619u", 16777619),
    ("1099511628211ull", 1099511628211),
    ("214", 214),
    ("0755", 0o755),
    ("  0x1000193  ", 0x1000193),
])
def test_parse_c_integer(text, expected):
    assert find_constants.parse_c_integer(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "u", "0xZZ", "not_a_number", "12abc"])
def test_parse_c_integer_refuses_rather_than_guessing(text):
    with pytest.raises(find_constants.DerivationError):
        find_constants.parse_c_integer(text)


# --------------------------------------------------------------------------- #
# 2. the comment stripper -- the invariant every citation in this tool rests on
# --------------------------------------------------------------------------- #

def test_stripping_comments_preserves_the_line_count():
    text = ("line one\n"
            "/* a block comment\n"
            "   spanning three\n"
            "   lines */ tail\n"
            "line five // trailing\n"
            "line six\n")
    stripped = find_constants.strip_c_comments(text)
    assert stripped.count("\n") == text.count("\n")
    assert find_constants.line_of(stripped, stripped.index("tail")) == 4
    assert find_constants.line_of(stripped, stripped.index("line six")) == 6


def test_a_comment_opener_inside_a_string_literal_is_not_a_comment():
    text = 'const char* s = "http://example/*not a comment*/";\nkeep = 1;\n'
    stripped = find_constants.strip_c_comments(text)
    assert "not a comment" in stripped
    assert "keep = 1" in stripped


# --------------------------------------------------------------------------- #
# 3. the enum walk
# --------------------------------------------------------------------------- #

ENUM_SOURCE = """\
// A header shaped like ObjectVersion.h
enum class EThing : uint32
{
    FIRST = 1000,
    SECOND,
    THIRD,
    /* a comment between entries */
    FOURTH = 1010,
    FIFTH,
    AUTOMATIC_PLUS_ONE,
    AUTOMATIC = AUTOMATIC_PLUS_ONE - 1
};

enum EOther
{
    OTHER_BASE = 214,
    OTHER_NEXT,
    OTHER_SHIFTED = 1 << 4,
    OTHER_OR = OTHER_BASE | 1,
    OTHER_LAST
};
"""


@pytest.fixture()
def enum_tree(tmp_path):
    root = tmp_path / "Engine"
    target = root / "Source" / "Runtime" / "Core" / "Public" / "UObject"
    target.mkdir(parents=True)
    (target / "Thing.h").write_text(ENUM_SOURCE, encoding="utf-8")
    return find_constants.SourceTree(str(root))


def test_enum_walk_counts_implicit_increments(enum_tree):
    walk = find_constants.walk_enum(enum_tree, {
        "id": "t", "path": "Source/Runtime/Core/Public/UObject/Thing.h",
        "enum_name": "EThing", "enumerator": "AUTOMATIC"})
    table = walk["enum_table"]
    assert table["FIRST"] == 1000
    assert table["SECOND"] == 1001
    assert table["THIRD"] == 1002
    assert table["FOURTH"] == 1010
    assert table["FIFTH"] == 1011


def test_enum_walk_resolves_the_minus_one_idiom(enum_tree):
    """The form ObjectVersion.h really uses, and the one a regex cannot read."""
    derived = find_constants.derive_enum_value(enum_tree, {
        "id": "t", "path": "Source/Runtime/Core/Public/UObject/Thing.h",
        "enum_name": "EThing", "enumerator": "AUTOMATIC"})
    assert derived["value"] == 1011          # AUTOMATIC_PLUS_ONE (1012) - 1
    assert derived["line"] == 11             # counted, not guessed


def test_enum_walk_handles_shift_and_or(enum_tree):
    walk = find_constants.walk_enum(enum_tree, {
        "id": "t", "path": "Source/Runtime/Core/Public/UObject/Thing.h",
        "enum_name": "EOther", "enumerator": "OTHER_LAST"})
    assert walk["enum_table"]["OTHER_NEXT"] == 215
    assert walk["enum_table"]["OTHER_SHIFTED"] == 16
    assert walk["enum_table"]["OTHER_OR"] == 215
    assert walk["enum_table"]["OTHER_LAST"] == 216


def test_enum_walk_can_be_anchored_instead_of_named(enum_tree):
    derived = find_constants.derive_enum_value(enum_tree, {
        "id": "t", "path": "Source/Runtime/Core/Public/UObject/Thing.h",
        "enum_anchor": r"OTHER_BASE\s*=\s*214", "enumerator": "OTHER_NEXT"})
    assert derived["value"] == 215


def test_the_evaluator_refuses_an_unknown_identifier_rather_than_guessing():
    with pytest.raises(find_constants.DerivationError) as caught:
        find_constants._eval_enum_expression("SOMETHING_ELSE - 1", {}, "t")
    assert "refuses to guess" in str(caught.value)


def test_a_missing_enumerator_is_an_error_not_a_zero(enum_tree):
    with pytest.raises(find_constants.DerivationError):
        find_constants.derive_enum_value(enum_tree, {
            "id": "t", "path": "Source/Runtime/Core/Public/UObject/Thing.h",
            "enum_name": "EThing", "enumerator": "NO_SUCH_ENTRY"})


# --------------------------------------------------------------------------- #
# 4. the table parser
# --------------------------------------------------------------------------- #

def _table_source(name: str, rows: int, per_row: int, start: int) -> str:
    """A [rows][per_row] uint32 initialiser whose values the caller can predict."""
    lines = ["uint32 FCrc::%s[%d][%d] = " % (name, rows, per_row), "{"]
    value = start
    for _row in range(rows):
        lines.append("\t{")
        row_values = []
        for _column in range(per_row):
            row_values.append("0x%08x" % (value & 0xFFFFFFFF))
            value += 1
        lines.append("\t\t" + ", ".join(row_values) + ",")
        lines.append("\t},")
    lines.append("};")
    return "\n".join(lines) + "\n"


@pytest.fixture()
def table_tree(tmp_path):
    root = tmp_path / "Engine"
    target = root / "Source" / "Runtime" / "Core" / "Private" / "Misc"
    target.mkdir(parents=True)
    body = ("// a leading comment\n"
            + _table_source("Flat", 1, 8, 0x10)
            + "\n"
            + _table_source("Nested", 4, 8, 0x100)
            + "\n")
    (target / "Crc.cpp").write_text(body, encoding="utf-8")
    return find_constants.SourceTree(str(root))


def test_a_nested_initialiser_is_flattened_in_memory_order(table_tree):
    derived = find_constants.derive_table(table_tree, {
        "id": "nested", "path": "Source/Runtime/Core/Private/Misc/Crc.cpp",
        "regex": r"FCrc::Nested\s*\[\s*4\s*\]\s*\[\s*8\s*\]",
        "expect_words": 32})
    assert derived["word_count"] == 32
    assert derived["words"][:3] == [0x100, 0x101, 0x102]
    assert derived["words"][-1] == 0x11F
    # The packed bytes ARE the pattern, so the packing is asserted directly.
    assert derived["packed"][:8] == struct.pack("<II", 0x100, 0x101)


def test_the_brace_matcher_does_not_stop_at_the_first_inner_brace(table_tree):
    """A regex for a braced group reads the first row and calls it the table."""
    derived = find_constants.derive_table(table_tree, {
        "id": "nested", "path": "Source/Runtime/Core/Private/Misc/Crc.cpp",
        "regex": r"FCrc::Nested\s*\[\s*4\s*\]\s*\[\s*8\s*\]",
        "expect_words": 32})
    assert derived["word_count"] == 32     # not 8, which is the first row


def test_a_word_count_mismatch_refuses_to_build_a_pattern(table_tree):
    """A misparsed table must not become a needle; it must become an error."""
    with pytest.raises(find_constants.DerivationError) as caught:
        find_constants.derive_table(table_tree, {
            "id": "nested", "path": "Source/Runtime/Core/Private/Misc/Crc.cpp",
            "regex": r"FCrc::Nested\s*\[\s*4\s*\]\s*\[\s*8\s*\]",
            "expect_words": 999})
    assert "refusing to build a pattern" in str(caught.value)


def test_a_table_declaration_that_is_absent_raises(table_tree):
    with pytest.raises(find_constants.DerivationError):
        find_constants.derive_table(table_tree, {
            "id": "absent", "path": "Source/Runtime/Core/Private/Misc/Crc.cpp",
            "regex": r"FCrc::NoSuchTable\s*\[", "expect_words": 8})


# --------------------------------------------------------------------------- #
# 5. the custom-version walk and join
# --------------------------------------------------------------------------- #

CUSTOM_VERSION_SOURCE = """\
#include "Thing.h"

// Unique Alpha Object version id
const FGuid FAlphaObjectVersion::GUID(0x11111111, 0x22222222, 0x33333333, 0x44444444);
FDevVersionRegistration GRegisterAlpha(FAlphaObjectVersion::GUID,
    FAlphaObjectVersion::LatestVersion, TEXT("Dev-Alpha"));

const FGuid FBetaCustomVersion::Key(0xAABBCCDD, 0x01020304, 0x05060708, 0x090A0B0C);
FCustomVersionRegistration GRegisterBeta(FBetaCustomVersion::Key,
    FBetaCustomVersion::Latest, TEXT("BetaVer"));

// A registration whose key is defined nowhere this walk can see.
FCustomVersionRegistration GRegisterOrphan(FOrphanVersion::Guid,
    FOrphanVersion::Latest, TEXT("OrphanVer"));

// An FGuid definition that no registration mentions.
const FGuid FLonelyThing::GUID(0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF);
"""


@pytest.fixture()
def custom_version_root(tmp_path):
    root = tmp_path / "Engine"
    target = root / "Source" / "Runtime" / "Core" / "Private" / "UObject"
    target.mkdir(parents=True)
    (target / "DevObjectVersion.cpp").write_text(CUSTOM_VERSION_SOURCE,
                                                 encoding="utf-8")
    (root / "Build").mkdir()
    (root / "Build" / "Build.version").write_text(json.dumps({
        "MajorVersion": 5, "MinorVersion": 4, "PatchVersion": 4,
        "Changelist": 35576357, "BranchName": "++UE5+Release-5.4"}),
        encoding="utf-8")
    return str(root)


def test_the_guid_join_finds_both_registration_spellings(custom_version_root):
    warnings: list[str] = []
    walk = find_constants.walk_custom_versions(custom_version_root, warnings)
    joined = find_constants.join_custom_versions(walk, warnings)
    keys = {row["key"]: row for row in joined["joined"]}
    assert set(keys) == {"FAlphaObjectVersion::GUID", "FBetaCustomVersion::Key"}
    assert keys["FAlphaObjectVersion::GUID"]["friendly_name"] == "Dev-Alpha"
    assert keys["FBetaCustomVersion::Key"]["friendly_name"] == "BetaVer"


def test_the_guid_bytes_are_four_little_endian_words(custom_version_root):
    warnings: list[str] = []
    walk = find_constants.walk_custom_versions(custom_version_root, warnings)
    joined = find_constants.join_custom_versions(walk, warnings)
    row = next(r for r in joined["joined"] if r["key"] == "FBetaCustomVersion::Key")
    assert bytes.fromhex(row["bytes_hex"]) == struct.pack(
        "<4I", 0xAABBCCDD, 0x01020304, 0x05060708, 0x090A0B0C)


def test_an_unjoinable_registration_is_reported_not_dropped(custom_version_root):
    warnings: list[str] = []
    walk = find_constants.walk_custom_versions(custom_version_root, warnings)
    joined = find_constants.join_custom_versions(walk, warnings)
    unresolved = {row["key"] for row in joined["registrations_unresolved"]}
    assert unresolved == {"FOrphanVersion::Guid"}
    assert joined["registrations_unresolved_total"] == 1
    assert any("could not be joined" in w for w in warnings)


def test_a_guid_no_registration_mentions_is_listed_separately(custom_version_root):
    warnings: list[str] = []
    walk = find_constants.walk_custom_versions(custom_version_root, warnings)
    joined = find_constants.join_custom_versions(walk, warnings)
    assert "FLonelyThing::GUID" in \
        joined["guid_definitions_not_reached_by_a_registration"]


def test_an_absent_source_tree_gives_an_empty_family_and_says_why(tmp_path):
    warnings: list[str] = []
    walk = find_constants.walk_custom_versions(str(tmp_path / "nothing_here"),
                                               warnings)
    assert walk["definitions"] == {}
    assert any("EMPTY for structural reasons" in w for w in warnings)


# --------------------------------------------------------------------------- #
# 6. catalogue assembly: a failed derivation is a row, not an exception
# --------------------------------------------------------------------------- #

def test_a_derivation_failure_is_recorded_on_the_row(tmp_path):
    """An empty tree must produce a catalogue of failures, not a traceback.

    This matters because the tool's whole value is that its patterns are cited.
    A locus that cannot be read must therefore appear, marked, in the output --
    a silently omitted row would let a null result look like a searched one.
    """
    root = tmp_path / "Engine"
    root.mkdir()
    warnings: list[str] = []
    catalogue = find_constants.build_catalogue(str(root), warnings,
                                              want_custom_versions=False)
    assert catalogue["constants"], "every locus must still appear as a row"
    assert all(row["derived"] is False for row in catalogue["constants"])
    assert all(row["searched"] is False for row in catalogue["constants"])
    assert all("derivation_error" in row for row in catalogue["constants"])
    assert len(catalogue["derivation_failures"]) == len(catalogue["constants"])
    assert warnings


def test_no_pattern_is_built_from_an_underived_constant(tmp_path):
    root = tmp_path / "Engine"
    root.mkdir()
    warnings: list[str] = []
    catalogue = find_constants.build_catalogue(str(root), warnings,
                                              want_custom_versions=False)
    assert find_constants.build_patterns(catalogue, warnings) == []


# --------------------------------------------------------------------------- #
# 7. a complete synthetic engine tree, for the end-to-end tests
# --------------------------------------------------------------------------- #

PLANTED_PACKAGE_TAG = 0x9E2A83C1
PLANTED_PACKAGE_TAG_SWAPPED = 0xC1832A9E
PLANTED_PAK_MAGIC = 0x5A6F12E1
PLANTED_TOC_MAGIC = b"-==--==--==--==-"
PLANTED_FNV64_BASIS = 0xCBF29CE484222325
PLANTED_UE4_ANCHOR = 522
PLANTED_UE4_OLDEST = 214
PLANTED_UE5_AUTOMATIC = 1012
PLANTED_TABLE_WORDS = 256
PLANTED_TABLE_START = 0x0BADF00D


def _planted_table_bytes() -> bytes:
    return struct.pack("<%dI" % PLANTED_TABLE_WORDS,
                       *[(PLANTED_TABLE_START + n) & 0xFFFFFFFF
                         for n in range(PLANTED_TABLE_WORDS)])


def _write(root, relative: str, text: str) -> None:
    path = os.path.join(root, relative.replace("/", os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


@pytest.fixture()
def engine_tree(tmp_path):
    """A tree holding exactly the loci find_constants.py names, and nothing else.

    Written by the test, so every value the catalogue reports has a value the
    test already knows. The point is not to imitate Unreal; it is to make the
    expected number independent of the tool that reads it.
    """
    root = str(tmp_path / "Engine")
    os.makedirs(root)
    _write(root, "Build/Build.version", json.dumps({
        "MajorVersion": 5, "MinorVersion": 4, "PatchVersion": 4,
        "Changelist": 35576357, "CompatibleChangelist": 33043543,
        "IsLicenseeVersion": 0, "IsPromotedBuild": 1,
        "BranchName": "++UE5+Release-5.4"}))

    _write(root, find_constants.OBJECT_VERSION_H, """\
#pragma once
#define PACKAGE_FILE_TAG            0x%08X
#define PACKAGE_FILE_TAG_SWAPPED    0x%08X

enum class EUnrealEngineObjectUE5Version : uint32
{
    INITIAL_VERSION = 1000,
    SOMETHING_ELSE,
    AUTOMATIC_VERSION_PLUS_ONE = %d,
    AUTOMATIC_VERSION = AUTOMATIC_VERSION_PLUS_ONE - 1
};

enum EUnrealEngineObjectUE4Version
{
    VER_UE4_OLDEST_LOADABLE_PACKAGE = %d,
    VER_UE4_AUTOMATIC_VERSION_PLUS_ONE = %d,
    VER_UE4_AUTOMATIC_VERSION = VER_UE4_AUTOMATIC_VERSION_PLUS_ONE - 1
};
""" % (PLANTED_PACKAGE_TAG, PLANTED_PACKAGE_TAG_SWAPPED,
       PLANTED_UE5_AUTOMATIC + 1, PLANTED_UE4_OLDEST, PLANTED_UE4_ANCHOR + 1))

    _write(root, find_constants.PAK_H, """\
struct FPakInfo
{
    enum
    {
        PakFile_Magic = 0x%08X,
        PakFile_Version_Initial = 1,
        PakFile_Version_NoTimestamps = 2,
        PakFile_Version_CompressionEncryption = 3,
        PakFile_Version_IndexEncryption = 4,
        PakFile_Version_RelativeChunkOffsets = 5,
        PakFile_Version_DeleteRecords = 6,
        PakFile_Version_EncryptionKeyGuid = 7,
        PakFile_Version_FNameBasedCompressionMethod = 8,
        PakFile_Version_FrozenIndex = 9,
        PakFile_Version_PathHashIndex = 10,
        PakFile_Version_Fnv64BugFix = 11,

        PakFile_Version_Last,
        PakFile_Version_Invalid,
        PakFile_Version_Latest = PakFile_Version_Last - 1
    };
};
""" % PLANTED_PAK_MAGIC)

    _write(root, find_constants.IOSTORE_H, """\
enum class EIoStoreTocVersion : uint8
{
    Invalid = 0,
    Initial,
    DirectoryIndex,
    PartitionSize,
    PerfectHash,
    PerfectHashWithOverflow,
    OnDemandMetaData,
    LatestPlusOne,
    Latest = LatestPlusOne - 1
};

struct FIoStoreTocHeader
{
    static constexpr inline char TocMagicImg[] = "%s";
};
""" % PLANTED_TOC_MAGIC.decode("ascii"))

    _write(root, find_constants.FNV_CPP, """\
uint32 FFnv::MemFnv32(const void* Blob, int32 Length, uint32 Fnv)
{
    static const uint32 Offset = 0x811c9dc5;
    static const uint32 Prime = 0x01000193;
    return Fnv;
}
uint64 FFnv::MemFnv64(const void* Blob, int32 Length, uint64 Fnv)
{
    static const uint64 Offset = 0x%016x;
    static const uint64 Prime = 0x00000100000001b3;
    return Fnv;
}
""" % PLANTED_FNV64_BASIS)

    _write(root, find_constants.CITYHASH_CPP, """\
namespace {
    static const uint64 k0 = 0xc3a5c85c97cb3127ULL;
    static const uint64 k1 = 0xb492b66fbe98f273ULL;
    static const uint64 k2 = 0x9ae16a3b2f90404fULL;
}
""")
    _write(root, find_constants.CITYHASH_H, """\
inline uint64 Hash128to64(const uint64 low, const uint64 high)
{
    const uint64 kMul = 0x9ddfea08eb382d69ULL;
    return kMul;
}
""")
    _write(root, find_constants.UNREALNAMES_CPP, """\
static uint64 HashName(const WIDECHAR* Str, int32 Len)
{
    return CityHash64(reinterpret_cast<const char*>(Str), Len * sizeof(WIDECHAR));
}
""")
    _write(root, "Source/Runtime/PakFile/Private/IPlatformFilePak.cpp", """\
static uint64 HashPath(const TCHAR* Path)
{
    static const uint64 Prime = 0xcbf29ce484222325;
    return Prime;
}
""")
    _write(root, "Source/Runtime/Core/Private/IO/IoStore.cpp", """\
static uint64 ChunkSeed(uint32 Seed)
{
    return Seed ? static_cast<uint64>(Seed) : 0xcbf29ce484222325;
}
""")

    crc = ["uint32 FCrc::CRCTable_DEPRECATED[%d] = " % PLANTED_TABLE_WORDS, "{"]
    words = [(PLANTED_TABLE_START + n) & 0xFFFFFFFF
             for n in range(PLANTED_TABLE_WORDS)]
    for start in range(0, PLANTED_TABLE_WORDS, 16):
        crc.append("\t" + ", ".join("0x%08X" % w
                                    for w in words[start:start + 16]) + ",")
    crc.append("};")
    # The two slice-by-eight tables exist so the loci resolve; they are given a
    # different filler so a test can tell which pattern matched what.
    for name in ("CRCTablesSB8_DEPRECATED", "CRCTablesSB8"):
        crc.append("")
        crc.append("uint32 FCrc::%s[8][256] = " % name)
        crc.append("{")
        base = 0x50000000 if name == "CRCTablesSB8" else 0x60000000
        for row in range(8):
            crc.append("\t{")
            row_words = [(base + row * 256 + n) & 0xFFFFFFFF for n in range(256)]
            for start in range(0, 256, 16):
                crc.append("\t\t" + ", ".join("0x%08X" % w
                                              for w in row_words[start:start + 16])
                           + ",")
            crc.append("\t},")
        crc.append("};")
    _write(root, find_constants.CRC_CPP, "\n".join(crc) + "\n")

    _write(root, "Source/Runtime/Core/Private/UObject/DevObjectVersion.cpp",
           CUSTOM_VERSION_SOURCE)
    return root


def test_the_synthetic_tree_derives_every_locus(engine_tree):
    warnings: list[str] = []
    catalogue = find_constants.build_catalogue(engine_tree, warnings)
    failed = [row["id"] for row in catalogue["constants"]
              if not row.get("derived")]
    assert failed == [], "loci that failed to derive: %s" % failed
    by_id = {row["id"]: row for row in catalogue["constants"]}
    assert by_id["package_file_tag"]["value"] == PLANTED_PACKAGE_TAG
    assert by_id["pak_file_magic"]["value"] == PLANTED_PAK_MAGIC
    assert by_id["iostore_toc_magic"]["text_value"] == \
        PLANTED_TOC_MAGIC.decode("ascii")
    assert by_id["ue4_object_version_automatic"]["value"] == PLANTED_UE4_ANCHOR
    assert by_id["ue4_oldest_loadable_package"]["value"] == PLANTED_UE4_OLDEST
    assert by_id["ue5_object_version_automatic"]["value"] == PLANTED_UE5_AUTOMATIC
    # Both of these are reached only by counting the enum to its end and
    # subtracting one. The synthetic enums carry the same number of intervening
    # entries as the real headers on purpose: in a three-entry enum any
    # arithmetic at all would give the right answer, which would test nothing.
    assert by_id["pak_version_latest"]["value"] == 11
    assert by_id["iostore_toc_version_latest"]["value"] == 6
    assert by_id["fnv64_offset_basis"]["value"] == PLANTED_FNV64_BASIS
    assert by_id["crc_table_deprecated"]["word_count"] == PLANTED_TABLE_WORDS
    assert bytes.fromhex(by_id["crc_table_deprecated"]["bytes_hex"]) == \
        _planted_table_bytes()


def test_every_catalogue_row_carries_a_citation_and_an_interpretation(engine_tree):
    warnings: list[str] = []
    catalogue = find_constants.build_catalogue(engine_tree, warnings)
    for row in catalogue["constants"]:
        assert row["citation"], row["id"]
        assert ":" in row["citation"]
        assert row["proves_if_found"], row["id"]
        assert row["does_not_prove"], row["id"]
        if not row["searched"]:
            assert row["not_searched_reason"], row["id"]


def test_the_extra_citations_are_checked_not_asserted(engine_tree):
    warnings: list[str] = []
    catalogue = find_constants.build_catalogue(engine_tree, warnings)
    assert catalogue["extra_citations"]
    assert all(row["found"] for row in catalogue["extra_citations"]), \
        [row for row in catalogue["extra_citations"] if not row["found"]]


# --------------------------------------------------------------------------- #
# 8. the image scan
# --------------------------------------------------------------------------- #

@pytest.fixture()
def catalogue(engine_tree):
    return find_constants.build_catalogue(engine_tree, [])


def _planted_image(tmp_path, name: str = "planted.exe", *, pad: int = 0,
                   with_pair: bool = True, good_neighbour: bool = True) -> str:
    """A PE image carrying, at offsets the test can compute, a known set of needles."""
    body = bytearray()
    body += b"\x00" * pad
    tag_at = len(body)
    body += struct.pack("<I", PLANTED_PACKAGE_TAG)
    body += b"\x00" * 16
    magic_at = len(body)
    body += PLANTED_TOC_MAGIC
    body += b"\x00" * 16
    fnv_at = len(body)
    body += struct.pack("<Q", PLANTED_FNV64_BASIS)
    body += b"\x00" * 16
    table_at = len(body)
    body += _planted_table_bytes()
    # The version pair, 4-byte aligned, optionally followed by the neighbour the
    # source predicts.
    while len(body) % 4:
        body += b"\x00"
    pair_at = len(body)
    if with_pair:
        body += struct.pack("<II", PLANTED_UE4_ANCHOR, PLANTED_UE5_AUTOMATIC)
        if good_neighbour:
            body += struct.pack("<II", PLANTED_UE4_OLDEST, 0)
        else:
            body += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
    body += b"\x00" * 64

    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\x90" * 64, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000, bytes(body), RDATA_FLAGS)
    path = write_image(tmp_path, name, builder.build())
    rdata = next(s for s in builder.sections if s["name"] == ".rdata")
    base = rdata["raw_pointer"]
    return path, {
        "package_file_tag": base + tag_at,
        "iostore_toc_magic": base + magic_at,
        "fnv64_offset_basis": base + fnv_at,
        "crc_table_deprecated": base + table_at,
        "version_pair": base + pair_at,
    }


def test_a_planted_constant_is_found_at_exactly_the_planted_offset(tmp_path,
                                                                  engine_tree):
    path, offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    rows = {(row["constant_id"], row["encoding"]): row
            for row in document["occurrences"]}
    for constant_id in ("package_file_tag", "iostore_toc_magic",
                        "fnv64_offset_basis"):
        row = next(r for (cid, _enc), r in rows.items() if cid == constant_id)
        assert row["found"], constant_id
        assert offsets[constant_id] in row["offsets"], constant_id


def test_the_whole_table_is_found_and_so_is_its_prefix(tmp_path, engine_tree):
    path, offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    table = next(r for r in document["occurrences"]
                 if r["constant_id"] == "crc_table_deprecated"
                 and r["encoding"] == find_constants.ENCODING_TABLE)
    assert table["found"]
    assert table["pattern_length"] == PLANTED_TABLE_WORDS * 4
    assert offsets["crc_table_deprecated"] in table["offsets"]


def test_the_absent_tables_are_absent_and_that_is_all_it_says(tmp_path,
                                                              engine_tree):
    """The SB8 tables are NOT planted, so they must be reported absent."""
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    for constant_id in ("crc_tables_sb8", "crc_tables_sb8_deprecated"):
        rows = [r for r in document["occurrences"]
                if r["constant_id"] == constant_id]
        assert rows
        assert all(not r["found"] for r in rows), constant_id


def test_a_pattern_straddling_a_scan_window_is_still_found(tmp_path, engine_tree,
                                                           monkeypatch):
    """The failure mode a summary line would never show.

    The scan streams in windows and carries `longest - 1` bytes forward. If the
    overlap were fixed, or off by one, a needle laid across a window boundary
    would silently vanish and every count would still look plausible. So the
    chunk is shrunk until the boundary is reachable and a needle is planted
    across it on purpose.
    """
    monkeypatch.setattr(find_constants, "SCAN_CHUNK", 1024)
    # 1024-byte windows; the 1024-byte table needs to start just before one.
    path, offsets = _planted_image(tmp_path, pad=0)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    table = next(r for r in document["occurrences"]
                 if r["constant_id"] == "crc_table_deprecated"
                 and r["encoding"] == find_constants.ENCODING_TABLE)
    assert document["measurement"]["scan"]["windows"] > 1, \
        "the test did not actually produce more than one window"
    assert table["found"], "a 1024-byte needle was lost across a 1024-byte window"
    assert offsets["crc_table_deprecated"] in table["offsets"]


def test_a_hit_at_a_window_boundary_is_not_counted_twice(tmp_path, engine_tree,
                                                          monkeypatch):
    monkeypatch.setattr(find_constants, "SCAN_CHUNK", 1024)
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    for row in document["occurrences"]:
        assert len(row["offsets"]) == len(set(row["offsets"])), row["constant_id"]
        if not row["occurrences_is_a_floor_not_a_total"]:
            assert row["occurrences"] == len(set(row["offsets"])) \
                or row["occurrences"] > find_constants.MAX_RECORDED_OFFSETS


def test_the_synthetic_controls_are_never_found(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    probe = next(p for p in document["refutation_probes"]
                 if p["probe"] == "synthetic controls")
    assert probe["control_occurrences_total"] == 0
    assert probe["refuted"] is False
    assert document["summary"]["controls_clean"] is True


def test_a_control_pattern_that_is_planted_IS_found(tmp_path, engine_tree):
    """The controls have to be findable, or their silence proves nothing.

    A control that could never be found whatever the image contained would be a
    decoration rather than a check, so one is planted and must show up.
    """
    control = find_constants.control_patterns()[2]
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\x90" * 64, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000,
                        b"\x00" * 32 + control["bytes"] + b"\x00" * 32,
                        RDATA_FLAGS)
    path = write_image(tmp_path, "control-planted.exe", builder.build())
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    probe = next(p for p in document["refutation_probes"]
                 if p["probe"] == "synthetic controls")
    assert probe["control_occurrences_total"] >= 1
    assert probe["refuted"] is True
    assert "REFUTED" in probe["verdict"]
    assert document["summary"]["controls_clean"] is False


# --------------------------------------------------------------------------- #
# 9. the version-pair shape and its neighbour prediction
# --------------------------------------------------------------------------- #

def test_the_version_pair_shape_finds_the_pair_and_its_neighbour(tmp_path,
                                                                 engine_tree):
    path, offsets = _planted_image(tmp_path, good_neighbour=True)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    pair = document["measurement"]["version_pair_shape"]
    assert pair["searched"] is True
    assert pair["ue4_anchor"] == PLANTED_UE4_ANCHOR
    assert pair["pairs_total"] == 1
    assert pair["ue5_value_census"] == {str(PLANTED_UE5_AUTOMATIC): 1}
    assert pair["pairs_with_the_predicted_neighbour"] == 1
    row = pair["pairs"][0]
    assert row["file_offset"] == offsets["version_pair"]
    assert row["next_eight_bytes_match_the_prediction"] is True
    assert row["ue5_value_is_an_enumerator_of_the_source_enum"] is True


def test_a_pair_without_the_predicted_neighbour_refutes_the_reading(tmp_path,
                                                                    engine_tree):
    """The probe has to be able to fail, or its passing means nothing."""
    path, _offsets = _planted_image(tmp_path, good_neighbour=False)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    pair = document["measurement"]["version_pair_shape"]
    assert pair["pairs_total"] == 1
    assert pair["pairs_with_the_predicted_neighbour"] == 0
    probe = next(p for p in document["refutation_probes"]
                 if p["probe"] == "the version pair's declared neighbour")
    assert probe["refuted"] is True
    assert "REFUTED" in probe["verdict"]


def test_no_pair_gives_an_honest_unknown_not_a_disagreement(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path, with_pair=False)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    cross = document["engine_version_crosscheck"]
    assert cross["version_constants_agree_with_the_cited_tree"] == "UNKNOWN"
    assert "not about the image" in cross["agreement_reason"]


def test_the_crosscheck_names_the_pair_reading_as_a_re_reading(tmp_path,
                                                              engine_tree):
    """The accounting M2s asked for, asserted rather than trusted."""
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    cross = document["engine_version_crosscheck"]
    rows = {row["reading"]: row["status"] for row in cross["per_reading"]}
    pair_row = next(key for key in rows if "package-version pair" in key)
    assert rows[pair_row] == "RE-READING of V-06"
    assert sum(1 for status in rows.values()
               if status == "NEW measurement act") >= 4
    assert cross["version_constants_agree_with_the_cited_tree"] == "AGREES"
    assert cross["changelist_of_the_cited_tree"] == 35576357


def test_the_crosscheck_refuses_to_claim_the_changelist(tmp_path, engine_tree):
    """Agreeing on a version must not be reported as agreeing on a changelist."""
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    note = document["engine_version_crosscheck"][
        "what_agreement_would_and_would_not_show"]
    assert "does NOT show that the image was built from this tree" in note


# --------------------------------------------------------------------------- #
# 10. the occurrence cap
# --------------------------------------------------------------------------- #

def test_a_capped_count_is_reported_as_a_floor(tmp_path, engine_tree,
                                               monkeypatch):
    monkeypatch.setattr(find_constants, "MAX_OCCURRENCES_PER_PATTERN", 4)
    needle = struct.pack("<I", PLANTED_PACKAGE_TAG)
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\x90" * 64, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000, needle * 32, RDATA_FLAGS)
    path = write_image(tmp_path, "many.exe", builder.build())
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    row = next(r for r in document["occurrences"]
               if r["constant_id"] == "package_file_tag"
               and r["encoding"] == find_constants.ENCODING_U32_LE)
    assert row["occurrences_is_a_floor_not_a_total"] is True
    assert row["occurrences"] == 4
    assert any("FLOOR" in w for w in document["warnings"])


def test_a_short_pattern_with_many_hits_is_flagged_as_uninformative(tmp_path,
                                                                    engine_tree):
    needle = struct.pack("<I", PLANTED_PACKAGE_TAG)
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\x90" * 64, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000, needle * 64, RDATA_FLAGS)
    path = write_image(tmp_path, "noisy.exe", builder.build())
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    probe = next(p for p in document["refutation_probes"]
                 if p["probe"] == "is a short pattern's presence informative at all")
    assert probe["count"] >= 1
    assert any(row["constant_id"] == "package_file_tag"
               for row in probe["short_patterns_with_more_than_16_occurrences"])


# --------------------------------------------------------------------------- #
# 11. the evidence layers
# --------------------------------------------------------------------------- #

def test_literal_reads_state_offset_and_length_and_nothing_else(tmp_path,
                                                               engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    assert document["literal_reads"]
    for read in document["literal_reads"]:
        evidence = read["evidence"]
        assert evidence["claim_class"] == "P"
        assert evidence["evidence_level"] == "OBSERVED"
        assert evidence["oracle"] == ["binary-analysis"]
        note = evidence["note"]
        assert "at offset %d" % read["offset"] in note
        assert "bytes at offset" in note or "byte at offset" in note
        # plan.md 10.3 v2.4: a class-P binary-analysis claim must not name what
        # the bytes ARE. These are the words that would make it class I.
        lowered = note.lower()
        for forbidden in ("struct", "field", "layout", "signature", "table",
                          "guid", "magic", "version"):
            assert forbidden not in lowered, (forbidden, note)


def test_literal_reads_are_actually_re_read(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    assert document["literal_reads_reproduced"] is True
    for read in document["literal_reads"]:
        assert read["reproduced"] is True
        assert "Method re-run and reproduced" in read["evidence"]["note"]


def test_literal_reads_match_the_file(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    with open(path, "rb") as handle:
        for read in document["literal_reads"]:
            handle.seek(read["offset"])
            assert handle.read(read["length"]).hex() == read["bytes_hex"]


def test_a_failed_reproduction_is_recorded_not_swallowed(tmp_path, engine_tree,
                                                        monkeypatch):
    path, _offsets = _planted_image(tmp_path)
    warnings: list[str] = []
    fake = [{"offset": 0, "length": 4, "bytes_hex": "deadbeef",
             "evidence": {"note": "n", "sources": [{"note": "s"}]}}]
    reproduced = find_constants.confirm_literal_reads(path, fake, "t", warnings)
    assert reproduced is False
    assert fake[0]["reproduced"] is False
    assert "Method NOT reproduced" in fake[0]["evidence"]["note"]
    assert any("did NOT reproduce" in w for w in warnings)


def test_the_interpretive_annotation_is_class_i_and_capped(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    annotation = document["interpreted_annotation"]
    assert annotation["claim_class"] == "I"
    assert annotation["evidence_level"] == "INFERRED"
    assert annotation["confidence"] <= find_constants.CONFIDENCE_DECODED_CORROBORATED
    assert "external-doc" in annotation["oracle"]


def test_an_uncorroborated_annotation_stays_below_the_two_method_band():
    annotation = find_constants.interpreted_annotation("t", None)
    assert annotation["confidence"] < 0.80
    assert len(annotation["sources"]) == 1


def test_no_confidence_anywhere_reaches_one(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "confidence" and isinstance(value, (int, float)):
                    found.append(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    assert found
    assert max(found) <= 0.99


# --------------------------------------------------------------------------- #
# 12. determinism, artifacts, and the output guard
# --------------------------------------------------------------------------- #

def test_two_runs_agree_except_for_the_clock(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    volatile = ("generated_at", "timings_seconds", "derived_at", "seconds",
                "walk")

    def scrub(node):
        if isinstance(node, dict):
            return {key: scrub(value) for key, value in node.items()
                    if key not in volatile}
        if isinstance(node, list):
            return [scrub(item) for item in node]
        return node

    first = scrub(find_constants.analyze(path, ue_source_root=engine_tree))
    second = scrub(find_constants.analyze(path, ue_source_root=engine_tree))
    assert find_constants.dump_json(first) == find_constants.dump_json(second)


def test_the_catalogue_round_trips_through_a_file(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    catalogue_path = str(tmp_path / "catalogue.json")
    fresh = find_constants.analyze(path, ue_source_root=engine_tree)
    with open(catalogue_path, "w", encoding="utf-8") as handle:
        handle.write(find_constants.dump_json(fresh["catalogue"]))
    reused = find_constants.analyze(path, ue_source_root=engine_tree,
                                    catalogue_in=catalogue_path)
    assert reused["catalogue_reused_from"] == catalogue_path
    assert [row["constant_id"] for row in reused["occurrences"]] == \
           [row["constant_id"] for row in fresh["occurrences"]]
    assert [row["found"] for row in reused["occurrences"]] == \
           [row["found"] for row in fresh["occurrences"]]


def test_the_jsonl_artifact_is_one_object_per_pattern(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    lines = find_constants.jsonl_lines(document)
    assert len(lines) == len(document["occurrences"])
    for line in lines:
        row = json.loads(line)
        assert row["build_target"]
        assert row["constant_id"]
        assert "found" in row
    only_found = find_constants.jsonl_lines(document, only_found=True)
    assert len(only_found) == sum(1 for r in document["occurrences"] if r["found"])


def test_an_output_path_inside_an_installation_is_refused(tmp_path, engine_tree,
                                                          monkeypatch):
    path, _offsets = _planted_image(tmp_path)
    install = tmp_path / "install"
    (install / "Engine" / "Binaries").mkdir(parents=True)
    monkeypatch.setattr(pathguard, "structural_install_roots",
                        lambda p: [str(install)])
    with pytest.raises(pathguard.OutputPathRefused):
        find_constants.write_text("x", str(install / "out.json"), str(install),
                                  "--out")


def test_cli_human_summary(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    result = subprocess.run(
        [sys.executable, FIND_CONSTANTS_PATH, path,
         "--ue-source-root", engine_tree],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Catalogue, derived from the source tree" in result.stdout
    assert "Refutation probes" in result.stdout
    assert "RE-READING of V-06" in result.stdout


def test_cli_json_is_valid_and_writes_its_artifacts(tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    out = str(tmp_path / "doc.json")
    jsonl = str(tmp_path / "rows.jsonl")
    catalogue = str(tmp_path / "cat.json")
    result = subprocess.run(
        [sys.executable, FIND_CONSTANTS_PATH, path,
         "--ue-source-root", engine_tree, "--json",
         "--out", out, "--jsonl-out", jsonl, "--catalogue-out", catalogue],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["task"] == "S-08"
    assert document["schema"] == find_constants.SCHEMA_ID
    for produced in (out, jsonl, catalogue):
        assert os.path.isfile(produced), produced
    with open(out, "r", encoding="utf-8") as handle:
        assert json.load(handle)["task"] == "S-08"


def test_cli_refuses_a_missing_source_root(tmp_path):
    path, _offsets = _planted_image(tmp_path)
    result = subprocess.run(
        [sys.executable, FIND_CONSTANTS_PATH, path,
         "--ue-source-root", str(tmp_path / "no_such_tree")],
        capture_output=True, text=True)
    assert result.returncode == 2
    assert "not a directory" in result.stderr


def test_an_empty_surface_says_so_instead_of_reporting_clean_absences(
        tmp_path, engine_tree):
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree,
                                      sections=("no_such_section",))
    assert document["measurement"]["searched_surface"]["sections"] == []
    assert any("NOTHING was searched" in w for w in document["warnings"])
    assert all(not row["found"] for row in document["occurrences"])


def test_the_catalogue_is_graded_in_the_reduced_annotation_envelope(engine_tree):
    """A bare `oracle` key makes the validator lint the object as a FULL record.

    That was a real defect in this tool: tools/kb/validate.py fires is_record()
    on any dict carrying `oracle` -- correctly, since an oracle is a claim about
    where knowledge came from -- and then asks for claim_type and build_key,
    which the catalogue has no business carrying. The remedy is not to hide the
    oracle but to put the whole envelope around it, in the reduced annotation
    shape whose closed key set is asserted here.
    """
    catalogue = find_constants.build_catalogue(engine_tree, [],
                                              want_custom_versions=False)
    assert "oracle" not in catalogue, \
        "a bare oracle key at this level is linted as a full record"
    annotation = catalogue["evidence"]
    # The closed property set of kb-record.schema.json#/$defs/annotation.
    assert set(annotation) <= {"evidence_level", "claim_class", "confidence",
                               "sources", "oracle", "read_locus", "note"}
    assert annotation["claim_class"] == "I"
    assert annotation["evidence_level"] == "OBSERVED"
    assert annotation["confidence"] < 0.80
    assert sorted(annotation["oracle"]) == ["external-doc", "filesystem"]


def test_the_catalogue_grading_refuses_the_two_method_band(engine_tree):
    """One method is one method, whatever the extra citations found."""
    catalogue = find_constants.build_catalogue(engine_tree, [],
                                              want_custom_versions=False)
    annotation = catalogue["evidence"]
    assert len(annotation["sources"]) == 1
    assert "One method only" in annotation["note"]


def test_no_object_in_the_document_carries_a_bare_oracle(tmp_path, engine_tree):
    """The invariant, checked over the whole document rather than one object.

    Any dict with an `oracle` key must either BE the reduced annotation (nothing
    outside its closed key set) or carry the full envelope. Anything else is a
    validator violation waiting to happen somewhere the author is not looking.
    """
    path, _offsets = _planted_image(tmp_path)
    document = find_constants.analyze(path, ue_source_root=engine_tree)
    annotation_keys = {"evidence_level", "claim_class", "confidence", "sources",
                       "oracle", "read_locus", "note"}
    offenders: list[str] = []

    def walk(node, pointer="$"):
        if isinstance(node, dict):
            if "oracle" in node and not set(node) <= annotation_keys:
                offenders.append(pointer)
            for key, value in node.items():
                walk(value, "%s.%s" % (pointer, key))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, "%s[%d]" % (pointer, index))

    walk(find_constants.public_document(document))
    assert offenders == [], offenders
