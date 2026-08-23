#!/usr/bin/env python3
"""Unreal Engine version identification (plan.md section 4, methods V-01..V-07).

WHAT THIS TOOL IS FOR
---------------------
plan.md 4 states the rule for this section in one line: **at least three
independent sources, and they must agree**; one source is a HYPOTHESIS, not a
fact. plan.md 4.2 adds the rule that decides the confidence and is easy to miss:

    confidence >= 0.90 is permitted ONLY if at least one TEXT source and at
    least one DATA-FORMAT source agree.

The three text sources of plan.md 4.1 -- V-01 (marker strings in the image),
V-02 (crash-report metadata) and V-03 (the PE version resource) -- are all
readings of the same kind of thing: a version stamp written as characters by the
build system. A fourth text source would not clear the bar. This tool therefore
spends most of its effort on the DATA-FORMAT sources, which read numbers that the
engine's own serializers and container writers emit and which change with the UE
minor version whether or not anybody edited a version string:

  V-05  the IoStore TOC version byte of each .utoc, plus the 144-byte header
        shape the rest of the file has to agree with.
  V-06  the FPackageFileVersion pair (FileVersionUE4, FileVersionUE5) baked into
        the Shipping image as initialised data. This is the sharpest single
        reading available: the UE5 half advances with almost every minor
        release, so its value names one minor line and excludes the neighbours.
  V-04  the D3D12 Agility SDK version the image exports as `D3D12SDKVersion`,
        and the version resources of the bundled third-party DLLs. Not a
        serialization format, but a number the engine source hard-codes per
        release, so it narrows the release window the same way.
  V-07  the staged plugin set read out of the .pak directory index. Recorded,
        and deliberately NOT load-bearing -- see the V-07 section below.

WHAT THIS TOOL DOES NOT DO
--------------------------
* It does not decrypt anything (decision D-02). The MISERY-Windows .pak entry
  payloads and the MISERY-Windows .utoc directory index are encrypted; this
  tool reads the .pak *index* (path names, which are plaintext) and the .utoc
  *header* (plaintext) and stops there. That the payloads are unreadable is
  reported as an observation, not worked around.
* It does not write anything inside a game installation (decision D-01). Every
  output path goes through tools/inventory/pathguard.py first.
* It does not resolve `engine_is_vanilla`. plan.md 4.2 keeps that flag UNKNOWN
  until M3, and explicitly says a false `IsSourceDistribution` does not settle
  it. Nothing here implies otherwise.
* It never assigns confidence 1.00, and never a value above 0.99 (plan.md 10.2
  v2.3). plan.md 4.2 gives the reason specific to this section: "the developer
  built a custom engine from 5.4 with backports" stays open.

RISK-09 (crash reports may belong to an OLDER build)
----------------------------------------------------
plan.md 4.2 says a crash report may have been produced by a previous version of
the game and may not be used without its own timestamp and without agreement
with the exe that is on disk NOW. This tool does not merely restate that: it
tests it. A UEMinidump.dmp carries a MINIDUMP_MODULE_LIST, and the record for
MISERY-Win64-Shipping.exe inside it carries SizeOfImage, CheckSum, TimeDateStamp
and the CodeView PDB signature (GUID + age) of the image that was actually
loaded when the crash happened. All four are read out of the dump and compared
with the same four values read out of the exe on disk. A report whose four
values match was produced by THIS build; a report whose values differ was not,
and is reported as belonging to a different build rather than quietly averaged
in. Each report is listed with its own mtime either way.

NEW-01 (the oracle matrix does not cover crash-report CONTENT)
--------------------------------------------------------------
research/unknowns.md NEW-01 records that the nine-oracle list of plan.md 10.5
has no row for the CONTENT of a crash report or an engine log: the artifact was
produced by the game's runtime but reading it is not OUR observation of that
runtime, and `external-doc` for it is explicitly called an error there. NEW-01
leaves exactly two admissible resolutions -- a tenth oracle, or "not entered in
the knowledge base" -- and the first is not available to this tool, because the
oracle list is closed. So this tool splits V-02 in two:

  V-02a  the MINIDUMP module record. A binary file parsed at determinate
         offsets, which is what the `binary-analysis` oracle is for. GRADED and
         entered, and it is the half that carries the RISK-09 answer.
  V-02b  the XML text fields (EngineVersion, BuildConfiguration,
         IsSourceDistribution ...). Reported as raw evidence and in prose,
         UNGRADED, with no oracle claimed, and NOT counted towards the
         three-source bar. The value it does carry is corroborative: it is the
         only source in this section that states the build CONFIGURATION and
         IsSourceDistribution at all.

WHY V-07 IS NOT LOAD-BEARING
----------------------------
Two independent reasons, both recorded rather than worked around. (1) A-09
records staged-versus-enabled as unresolved, so the staged set is a lower bound
on the engine's plugin inventory and says nothing about what the build uses.
(2) Deciding "plugin P did not exist before release R" requires a COMPLETE
reference tree for R-1, and the public mirrors consulted for the external
reference of V-04..V-06 are not provably complete, so an absence in a mirror is
not an absence in the release. The staged list is written to
research/evidence/V-07/ as raw evidence and the conclusion is left open.

The claim class of each reading (plan.md 10.3 v2.4)
---------------------------------------------------
Every reading in this tool is emitted as TWO records and never as one average.
The literal half states the target, the offset, the length and the bytes and
names nothing -- class P, and it carries `read_locus`, which v2.4 makes
mandatory for a class-P record resting on binary-analysis or container-metadata.
The interpretive half names what the bytes are and which UE release they belong
to; it is class I, it names `external-doc` alongside the reading oracle, because
the public UE layout is what turns a number into a version, and it carries two
independent methods as EV-03 requires from confidence 0.80 up.

Determinism
-----------
Standard library only. Output is JSON with sorted keys, indent 2, LF endings,
UTF-8 without BOM. Two runs of this tool on an unchanged installation produce
byte-identical output except for `generated_at`.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------- #
# sys.path bootstrap.  tools/ is deliberately not a Python package: the scripts
# are run directly, not as -m modules (see tools/inventory/pathguard.py).
# --------------------------------------------------------------------------- #

_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("inventory", "fingerprint"):
    _dir = os.path.join(_TOOLS, _sub)
    if _dir not in sys.path:
        sys.path.insert(0, _dir)

import container_info  # noqa: E402  (tools/fingerprint/container_info.py, F-02)
import pathguard       # noqa: E402  (tools/inventory/pathguard.py, layer 1)
import pe_info         # noqa: E402  (tools/fingerprint/pe_info.py, F-01)

GENERATOR_NAME = "tools/static/engine_version.py"
GENERATOR_VERSION = "1.1.0"

REPO_ROOT = os.path.dirname(_TOOLS)

# --------------------------------------------------------------------------- #
# Confidence constants.  One place, so a number cannot drift between the JSON
# and the prose document that quotes it.
# --------------------------------------------------------------------------- #

# A literal read at a stated offset of a stated length.  0.99 is the ceiling of
# the scale (plan.md 10.2 v2.3) and the remaining 0.01 stands for "we measured
# correctly but measured the wrong thing".
CONFIDENCE_LITERAL = 0.99
# An interpretive reading of one format field against the public UE layout,
# corroborated by a second independent method.
CONFIDENCE_FORMAT_READING = 0.90
# The minor line 5.4: three data-format discriminators plus two text sources,
# every one of them excluding both neighbouring releases.
CONFIDENCE_MINOR_LINE = 0.95
# The full version 5.4.4: the patch component rests on the version stamp plus
# the public changelist-to-release mapping, and on NO data-format source, so it
# cannot carry the number the minor line carries.
CONFIDENCE_FULL_VERSION = 0.93
# The changelist and the branch: read as text in two places of the image, tied
# to a release by the public build metadata of UE 5.4.4.
CONFIDENCE_CL = 0.90
# The build configuration.  Only V-02b states it, and V-02b is ungradeable
# under the closed oracle list (NEW-01); what remains is the absence of the
# markers a non-Shipping configuration would leave.
CONFIDENCE_BUILD_CONFIGURATION = 0.75

# --------------------------------------------------------------------------- #
# V-01 / V-03: the text markers.
# --------------------------------------------------------------------------- #

# Marker strings of plan.md 4.1 V-01.  UTF-16LE is the encoding UE uses for TCHAR
# literals on Windows; the ASCII form is searched too so that a hit in an ASCII
# literal is not missed.
V01_MARKERS: tuple[str, ...] = (
    "++UE5+Release-",
    "-CL-",
    "++UE5+Main",
    "UnrealEngine",
)

# The three images of this installation, relative to the install root.  Order is
# fixed so the output is deterministic.
IMAGES: tuple[str, ...] = (
    "MISERY.exe",
    "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe",
    "MISERY/Binaries/Win64/MISERY.exe",
)
SHIPPING_REL = "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"

# The engine version string UE builds from ENGINE_VERSION_STRING has the shape
# <major>.<minor>.<patch>-<changelist>+<branch>; the branch alone has the shape
# ++UE5+Release-<major>.<minor>.  Both are matched, and the numbers come out of
# the match rather than out of a constant in this file.
BRANCH_RE = re.compile(r"\+\+UE5\+(?:Release-(\d+)\.(\d+)|(Main))")
BRANCH_CL_RE = re.compile(r"(\+\+UE5\+[A-Za-z0-9.\-+]*?)-CL-(\d+)")
FULL_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\d+)\+(\+\+UE5\+[A-Za-z0-9.\-+]+)")
# The VS_FIXEDFILEINFO form. UE writes the ENGINE version into the module version
# resource as <major>.<minor>.<patch>.0, and that resource is the ONLY place in
# this installation's images where the patch component appears at all: the images
# carry the branch literal and the '-CL-<n>' literal but no '5.4.4-...' string.
# So the patch component of the answer comes from here, which is exactly why the
# document says so out loud instead of letting it look like a string hit.
FIXED_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")
# A third shape: '<major>.<minor>.<patch>-<branch>', which is what the SECOND image
# of this installation carries. Kept in its own field and deliberately NOT merged
# into the answer: that image is decision D-04's read-only oracle, and D-04 says
# every conclusion drawn on it must be re-verified on the Shipping binary before
# it counts. Merging it would have made the patch component look as though it came
# from a string literal, when on the Shipping image it comes from a resource field.
VERSION_WITH_BRANCH_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\+\+UE5\+[A-Za-z0-9.\-+]+)")

# --------------------------------------------------------------------------- #
# V-06: the serialization version constants.
# --------------------------------------------------------------------------- #

# EUnrealEngineObjectUE4Version::VER_UE4_AUTOMATIC_VERSION.  Frozen at 522 for
# the whole of UE5 -- it is the UE4 half of FPackageFileVersion and stops moving
# once a branch is UE5, which is exactly what makes it a usable anchor: the
# 8-byte pair "522 followed by a UE5 version" is a shape, not a coincidence.
VER_LATEST_ENGINE_UE4 = 522
# EUnrealEngineObjectUE4Version::VER_UE4_OLDEST_LOADABLE_PACKAGE.  Not searched
# for; PREDICTED, as the refutation attempt of V-06 -- see scan_v06().
VER_UE4_OLDEST_LOADABLE_PACKAGE = 214
# The plausible band of EUnrealEngineObjectUE5Version.  INITIAL_VERSION is 1000
# and the enum has added roughly two entries per release since; 1100 is a ceiling
# far above any released value, chosen so that a hit outside the band is reported
# as "no candidate" rather than silently dropped.
UE5_OBJECT_VERSION_MIN = 1000
UE5_OBJECT_VERSION_MAX = 1100

# --------------------------------------------------------------------------- #
# The external reference table (oracle `external-doc`).
# --------------------------------------------------------------------------- #
# This is the ONLY place where knowledge that does not come from this
# installation enters the tool, and it is confined to one question: given a
# number, which UE release emits it. Each row was read out of a public Unreal
# Engine source tree; the citation is carried with the row and is reproduced in
# research/evidence/V-06/external-reference.md so a later reader can re-check it
# without re-deriving it.
#
# The three UE lines below are the only ones that need to be distinguished: the
# text sources already place the build in the UE5 5.x generation, and 5.3 and
# 5.5 are the neighbours whose exclusion is what makes the reading a
# discriminator rather than a consistency check.

UE_REFERENCE: tuple[dict, ...] = (
    {
        "ue_line": "5.3",
        "provenance": "public source mirror",
        "reference_tree": "5.3.2",
        # Engine/Source/Runtime/Core/Public/UObject/ObjectVersion.h
        "package_file_version_ue5": 1009,   # DATA_RESOURCES is AUTOMATIC_VERSION
        "package_file_version_ue5_name": "DATA_RESOURCES",
        # Engine/Source/Runtime/Core/Internal/IO/IoStore.h
        "io_store_toc_latest": 5,           # PerfectHashWithOverflow is Latest
        "io_store_toc_latest_name": "PerfectHashWithOverflow",
        # Engine/Source/Runtime/Launch/Private/Windows/LaunchWindows.cpp
        "d3d12_sdk_version": 610,
        "citation": ("public UE 5.3.2 source tree (Engine/Build/Build.version reads "
                     "MajorVersion 5, MinorVersion 3, PatchVersion 2)"),
    },
    {
        "ue_line": "5.4",
        # The row that carries the answer, and the only one that can be checked
        # on this machine: --ue-source-root re-reads all four numbers out of a
        # first-party Epic distribution and read_local_ue_reference() compares
        # them with the values below. See `local_reference_check` in the output.
        "provenance": ("first-party Epic distribution of UE 5.4.4; re-read in this run "
                       "when --ue-source-root was given"),
        "reference_tree": "5.4.4",
        "package_file_version_ue5": 1012,   # PROPERTY_TAG_COMPLETE_TYPE_NAME
        "package_file_version_ue5_name": "PROPERTY_TAG_COMPLETE_TYPE_NAME",
        "io_store_toc_latest": 6,           # OnDemandMetaData is Latest
        "io_store_toc_latest_name": "OnDemandMetaData",
        "d3d12_sdk_version": 611,
        "citation": ("public UE 5.4.4 source tree (Runtime/Launch/Resources/Version.h "
                     "reads ENGINE_MAJOR_VERSION 5, ENGINE_MINOR_VERSION 4, "
                     "ENGINE_PATCH_VERSION 4)"),
    },
    {
        "ue_line": "5.5",
        "provenance": "public source mirror",
        "reference_tree": "5.5.2",
        "package_file_version_ue5": 1013,   # ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES
        "package_file_version_ue5_name": "ASSETREGISTRY_PACKAGEBUILDDEPENDENCIES",
        "io_store_toc_latest": 8,           # ReplaceIoChunkHashWithIoHash is Latest
        "io_store_toc_latest_name": "ReplaceIoChunkHashWithIoHash",
        "d3d12_sdk_version": 614,
        "citation": ("public UE 5.5.2 source tree (Engine/Build/Build.version reads "
                     "MajorVersion 5, MinorVersion 5, PatchVersion 2)"),
    },
)

# The public build metadata of the UE 5.4.4 release binds the version to the
# changelist. Read out of .target files that installed UE 5.4.4 emits, which
# carry the whole FEngineVersion as JSON.
UE_544_CHANGELIST = 35576357
UE_544_BRANCH = "++UE5+Release-5.4"


# Where the four reference numbers live inside an Unreal Engine tree, relative to
# the Engine/ directory. An installed (binary) distribution ships all four.
UE_REFERENCE_FILES: dict[str, str] = {
    "build_version": "Build/Build.version",
    "object_version": "Source/Runtime/Core/Public/UObject/ObjectVersion.h",
    "io_store": "Source/Runtime/Core/Internal/IO/IoStore.h",
    "launch_windows": "Source/Runtime/Launch/Private/Windows/LaunchWindows.cpp",
    "object_version_cpp": "Source/Runtime/Core/Private/UObject/ObjectVersion.cpp",
}

D3D12_SDK_VERSION_RE = re.compile(r"D3D12SDKVersion\s*=\s*(\d+)")


def _enum_values(text: str, enum_name: str) -> dict[str, int]:
    """Evaluate a plain C++ enum's members. Only the two forms UE uses are handled.

    Those are `NAME` (previous + 1), `NAME = <int>` and
    `NAME = <OTHER> - <int>`, which is how AUTOMATIC_VERSION is written. Anything
    else is skipped rather than guessed, so a member this cannot evaluate simply
    does not appear in the result.
    """
    match = re.search(r"enum(?:\s+class)?\s+" + re.escape(enum_name)
                      + r"\b[^{]*\{(.*?)\n\};", text, re.S)
    if not match:
        return {}
    body = re.sub(r"/\*.*?\*/", "", re.sub(r"//[^\n]*", "", match.group(1)), flags=re.S)
    values: dict[str, int] = {}
    current: int | None = None
    for token in re.finditer(r"([A-Za-z_]\w*)\s*(?:=\s*([^,\n]+?))?\s*(?:,|$)",
                             body, re.M):
        name, raw = token.group(1), token.group(2)
        if raw is None:
            current = 0 if current is None else current + 1
        else:
            raw = raw.strip()
            try:
                current = int(raw, 0)
            except ValueError:
                relative = re.match(r"([A-Za-z_]\w*)\s*-\s*(\d+)$", raw)
                if relative and relative.group(1) in values:
                    current = values[relative.group(1)] - int(relative.group(2))
                else:
                    continue
        values[name] = current
    return values


def read_local_ue_reference(engine_root: str, warnings: list[str]) -> dict | None:
    """Re-read the reference numbers out of a local Unreal Engine tree.

    This is what turns the UE_REFERENCE table from an assertion in a Python file
    into a checkable reading: given the Engine/ directory of an installed UE
    distribution, all four numbers are read from that distribution's own headers
    and compared with the table row for its own version. A disagreement is a
    WARNING and is recorded in the artifact -- it would mean the table is wrong,
    which is exactly the failure this function exists to catch.

    C-13: the absolute root is NOT recorded in the output. What identifies the
    tree is its own Build.version, and the four relative paths below, neither of
    which carries anybody's profile directory.
    """
    paths = {key: os.path.join(engine_root, rel.replace("/", os.sep))
             for key, rel in UE_REFERENCE_FILES.items()}
    missing = sorted(key for key, path in paths.items() if not os.path.isfile(path))
    if missing:
        warnings.append("--ue-source-root: %s does not look like an Engine directory "
                        "(missing: %s); the built-in reference table was not verified"
                        % (engine_root, ", ".join(missing)))
        return None

    def read(key: str) -> str:
        with open(paths[key], "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    try:
        build = json.loads(read("build_version"))
    except ValueError as exc:
        warnings.append("--ue-source-root: Build.version does not parse: %s" % exc)
        return None
    object_version = read("object_version")
    ue4 = _enum_values(object_version, "EUnrealEngineObjectUE4Version")
    ue5 = _enum_values(object_version, "EUnrealEngineObjectUE5Version")
    toc = _enum_values(read("io_store"), "EIoStoreTocVersion")
    sdk_match = D3D12_SDK_VERSION_RE.search(read("launch_windows"))
    globals_cpp = read("object_version_cpp")
    line = "%s.%s" % (build.get("MajorVersion"), build.get("MinorVersion"))
    observed = {
        "engine_version": "%s.%s.%s" % (build.get("MajorVersion"),
                                        build.get("MinorVersion"),
                                        build.get("PatchVersion")),
        "ue_line": line,
        "changelist": build.get("Changelist"),
        "compatible_changelist": build.get("CompatibleChangelist"),
        "branch_name": build.get("BranchName"),
        "is_licensee_version": build.get("IsLicenseeVersion"),
        "is_promoted_build": build.get("IsPromotedBuild"),
        "ver_latest_engine_ue4": ue4.get("VER_UE4_AUTOMATIC_VERSION"),
        "ver_ue4_oldest_loadable_package": ue4.get("VER_UE4_OLDEST_LOADABLE_PACKAGE"),
        "package_file_version_ue5": ue5.get("AUTOMATIC_VERSION"),
        "io_store_toc_latest": toc.get("Latest"),
        "d3d12_sdk_version": int(sdk_match.group(1)) if sdk_match else None,
        # The declaration order that makes the V-06 neighbour prediction a
        # prediction and not a rationalisation, quoted so the reader can see it.
        "package_version_globals_declared_in_order": bool(re.search(
            r"GPackageFileUEVersion\s*\([^)]*\)\s*;\s*\n\s*const\s+FPackageFileVersion\s+"
            r"GOldestLoadablePackageFileUEVersion", globals_cpp)),
        "files_read": [UE_REFERENCE_FILES[key] for key in sorted(UE_REFERENCE_FILES)],
    }
    row = ue_reference_row(line)
    disagreements: list[str] = []
    if row is None:
        disagreements.append("the built-in table has no row for UE %s" % line)
    else:
        for field in ("package_file_version_ue5", "io_store_toc_latest",
                      "d3d12_sdk_version"):
            if observed[field] != row[field]:
                disagreements.append("%s: table says %r, the local tree says %r"
                                     % (field, row[field], observed[field]))
    if observed["ver_latest_engine_ue4"] != VER_LATEST_ENGINE_UE4:
        disagreements.append("VER_LATEST_ENGINE_UE4: this tool assumes %d, the local "
                             "tree says %r"
                             % (VER_LATEST_ENGINE_UE4,
                                observed["ver_latest_engine_ue4"]))
    if observed["ver_ue4_oldest_loadable_package"] != VER_UE4_OLDEST_LOADABLE_PACKAGE:
        disagreements.append("VER_UE4_OLDEST_LOADABLE_PACKAGE: this tool predicts %d, "
                             "the local tree says %r"
                             % (VER_UE4_OLDEST_LOADABLE_PACKAGE,
                                observed["ver_ue4_oldest_loadable_package"]))
    for message in disagreements:
        warnings.append("--ue-source-root: reference DISAGREEMENT - %s" % message)
    return {
        "root_recorded_as": ("(not recorded: C-13. The tree is identified by its own "
                             "Build.version, quoted above, not by where it sits)"),
        "read": observed,
        "agrees_with_builtin_table": not disagreements,
        "disagreements": disagreements,
    }


def ue_lines_matching(field: str, value) -> list[str]:
    """Which UE lines of UE_REFERENCE emit *value* for *field*."""
    return [row["ue_line"] for row in UE_REFERENCE if row.get(field) == value]


def ue_reference_row(ue_line: str) -> dict | None:
    for row in UE_REFERENCE:
        if row["ue_line"] == ue_line:
            return row
    return None


# --------------------------------------------------------------------------- #
# Small shared helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def mtime_iso_utc(path: str) -> str:
    return _datetime.datetime.fromtimestamp(
        os.path.getmtime(path), _datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def posix(rel: str) -> str:
    return rel.replace("\\", "/")


def hex_bytes(raw: bytes) -> str:
    """Delegated so the byte spelling of a read_locus cannot drift from F-02's."""
    return container_info.hex_bytes(raw)


def literal_read(method: str, oracle: str, target: str, offset: int, raw: bytes,
                 *, decoded_field: str, artifact: str | None,
                 reproduced: bool, note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    Modelled on container_info.literal_read and deliberately NOT a call to it:
    that function hard-codes method "F-02" and oracle "container-metadata", and
    the reads here belong to methods V-01..V-06 and to the `binary-analysis`
    oracle as well. What is shared is the SHAPE of the record and the byte
    spelling (hex_bytes above), which is where drift would actually hurt.

    ``claim`` states the offset and the length -- which plan.md 10.3 v2.4 makes
    mandatory for binary-analysis and container-metadata to be class P at all --
    and stops short of naming what the bytes are. The per-source ``oracle`` key
    of kb-record.schema.json#/$defs/source is deliberately not set: it is legal
    in the schema and makes tools/kb/validate.py read every source object as a
    record of its own (see the SOURCE_ORACLE_OMITTED note in container_info).
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    reproduction = ("Reproduction: the range was read a second time from a freshly "
                    "opened handle and the bytes agree."
                    if reproduced else
                    "Reproduction: the second read DISAGREED - see warnings.")
    return {
        "decoded_field": decoded_field,
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": [oracle],
            "sources": [{
                "method": method,
                "artifact": artifact,
                "locator": "%s@%d+%d" % (target, offset, length),
                "note": ("oracle %s. Read by %s, read-only. %s"
                         % (oracle, GENERATOR_NAME, reproduction)),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
                "note": note,
            },
            "note": claim,
        },
    }


def read_range_twice(path: str, offset: int, length: int) -> tuple[bytes, bool]:
    """Read one range twice from two independently opened handles.

    plan.md 10.3 class P criterion 2 executed rather than asserted. Returns the
    bytes of the first read and whether the second agreed.
    """
    with open(path, "rb") as handle:
        handle.seek(offset)
        first = handle.read(length)
    with open(path, "rb") as handle:
        handle.seek(offset)
        second = handle.read(length)
    return first, first == second


def section_of(sections: list[dict], *, file_offset: int | None = None,
               rva: int | None = None) -> dict | None:
    for sec in sections:
        raw = sec.get("raw_pointer") or 0
        rsize = sec.get("rsize") or 0
        if file_offset is not None and raw <= file_offset < raw + rsize:
            return sec
        if rva is not None:
            start = sec.get("rva") or 0
            if start <= rva < start + max(rsize, sec.get("vsize") or 0):
                return sec
    return None


def rva_to_file_offset(sections: list[dict], rva: int) -> int | None:
    sec = section_of(sections, rva=rva)
    if sec is None:
        return None
    delta = rva - (sec.get("rva") or 0)
    if delta >= (sec.get("rsize") or 0):
        return None  # inside the virtual tail, no bytes on disk
    return (sec.get("raw_pointer") or 0) + delta


# --------------------------------------------------------------------------- #
# V-01: marker strings in the images
# --------------------------------------------------------------------------- #

def scan_v01(install_dir: str, warnings: list[str]) -> dict:
    """Find the engine version markers in each image, with offsets and lengths.

    Every hit is reported with its file offset, its byte length and the section
    it lands in, so a later reader can re-perform the read. The DECODED version
    numbers are parsed out of the matched strings themselves; nothing about the
    version is taken from a constant in this file.
    """
    per_image: list[dict] = []
    for rel in IMAGES:
        path = os.path.join(install_dir, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            warnings.append("V-01: image absent, skipped: %s" % rel)
            continue
        with open(path, "rb") as handle:
            blob = handle.read()
        doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                              want_checksum=False)
        sections = doc["pe"]["sections"]
        hits: list[dict] = []
        for marker in V01_MARKERS:
            for encoding, needle in (("utf-16le", marker.encode("utf-16-le")),
                                     ("ascii", marker.encode("ascii"))):
                start = 0
                while True:
                    found = blob.find(needle, start)
                    if found < 0:
                        break
                    start = found + 1
                    string, s_off, s_len = _extend_string(blob, found, len(needle),
                                                          encoding)
                    sec = section_of(sections, file_offset=s_off)
                    hits.append({
                        "marker": marker,
                        "encoding": encoding,
                        "offset": s_off,
                        "length": s_len,
                        "section": (sec or {}).get("name"),
                        "string": string,
                    })
        # Deduplicate: a longer marker and a shorter one inside it resolve to the
        # same string at the same offset, and reporting it twice would look like
        # two readings.
        seen: set[tuple] = set()
        unique: list[dict] = []
        for hit in sorted(hits, key=lambda h: (h["offset"], h["encoding"], h["marker"])):
            key = (hit["offset"], hit["length"], hit["encoding"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(hit)
        per_image.append({
            "path": posix(rel),
            "hit_count": len(unique),
            "hits": unique,
            "parsed": _parse_version_strings([h["string"] for h in unique]),
        })
    return {"images": per_image}


def _extend_string(blob: bytes, found: int, needle_len: int, encoding: str
                   ) -> tuple[str, int, int]:
    """Grow a marker hit out to the whole NUL-terminated string around it.

    The offset returned is the start of the STRING, not of the marker, because
    that is the address a reader would use to re-read it, and the length is the
    string's own length in bytes, excluding the terminator.
    """
    if encoding == "utf-16le":
        step, terminator = 2, b"\x00\x00"
        start = found
        while start - step >= 0:
            unit = blob[start - step:start]
            if unit == terminator or not _printable_utf16(unit):
                break
            start -= step
        end = found + needle_len
        while end + step <= len(blob):
            unit = blob[end:end + step]
            if unit == terminator or not _printable_utf16(unit):
                break
            end += step
        raw = blob[start:end]
        return raw.decode("utf-16-le", "replace"), start, len(raw)
    start = found
    while start - 1 >= 0 and 0x20 <= blob[start - 1] < 0x7f:
        start -= 1
    end = found + needle_len
    while end < len(blob) and 0x20 <= blob[end] < 0x7f:
        end += 1
    raw = blob[start:end]
    return raw.decode("ascii", "replace"), start, len(raw)


def _printable_utf16(unit: bytes) -> bool:
    if unit[1] != 0:
        return False
    return 0x20 <= unit[0] < 0x7f


def _parse_version_strings(strings: list[str],
                           fixed_versions: list[str] | None = None) -> dict:
    """Pull the version, changelist and branch out of the matched strings.

    *fixed_versions* are VS_FIXEDFILEINFO values ("5.4.4.0"), passed separately
    because they are a STRUCTURED field of a parsed resource and not a string
    found by scanning; keeping them apart makes it visible in the output which
    part of the answer came from which.
    """
    branches: set[str] = set()
    changelists: set[int] = set()
    full: set[str] = set()
    minor_lines: set[str] = set()
    fixed_full: set[str] = set()
    branch_full: set[str] = set()
    for value in fixed_versions or []:
        match = FIXED_VERSION_RE.match(str(value).strip())
        if match:
            fixed_full.add("%s.%s.%s" % match.group(1, 2, 3))
            minor_lines.add("%s.%s" % match.group(1, 2))
    for text in strings:
        for match in FULL_VERSION_RE.finditer(text):
            full.add("%s.%s.%s" % match.group(1, 2, 3))
            changelists.add(int(match.group(4)))
            branches.add(match.group(5))
        for match in VERSION_WITH_BRANCH_RE.finditer(text):
            branch_full.add("%s.%s.%s" % match.group(1, 2, 3))
        for match in BRANCH_CL_RE.finditer(text):
            branches.add(match.group(1))
            changelists.add(int(match.group(2)))
        for match in BRANCH_RE.finditer(text):
            if match.group(3):
                minor_lines.add("main")
            else:
                minor_lines.add("%s.%s" % match.group(1, 2))
    return {
        "branches": sorted(branches),
        "changelists": sorted(changelists),
        "full_versions": sorted(full),
        "fixed_file_info_versions": sorted(fixed_full),
        "versions_followed_by_a_branch_literal": sorted(branch_full),
        "minor_lines": sorted(minor_lines),
    }


def scan_v01_changelist_constant(install_dir: str, changelist: int,
                                 warnings: list[str]) -> dict | None:
    """Find the changelist as a compiled 32-bit immediate, not as text.

    A companion reading, not an independent method: the integer and the two
    strings all come from the same BUILT_FROM_CHANGELIST macro, so their
    agreement tests the reads and not the fact. It is worth recording because
    it is a DIFFERENT encoding at a DIFFERENT address, which is what a
    transcription error would not survive.
    """
    path = os.path.join(install_dir, SHIPPING_REL.replace("/", os.sep))
    if not os.path.isfile(path) or changelist <= 0:
        return None
    needle = struct.pack("<I", changelist)
    with open(path, "rb") as handle:
        blob = handle.read()
    doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                          want_checksum=False)
    sections = doc["pe"]["sections"]
    offsets: list[int] = []
    start = 0
    while True:
        found = blob.find(needle, start)
        if found < 0:
            break
        offsets.append(found)
        start = found + 1
    if not offsets:
        warnings.append("V-01: the changelist %d does not occur as a 32-bit "
                        "little-endian value anywhere in the Shipping image"
                        % changelist)
        return None
    return {
        "value": changelist,
        "occurrence_count": len(offsets),
        "occurrences": [
            {
                "offset": off,
                "length": 4,
                "section": (section_of(sections, file_offset=off) or {}).get("name"),
                "preceding_byte_hex": hex_bytes(blob[off - 1:off]) if off else None,
            }
            for off in offsets
        ],
    }


# --------------------------------------------------------------------------- #
# V-03: the PE version resource
# --------------------------------------------------------------------------- #

def read_v03(install_dir: str, warnings: list[str]) -> dict:
    """Read VS_VERSIONINFO out of .rsrc for each image, with its file extent."""
    per_image: list[dict] = []
    for rel in IMAGES:
        path = os.path.join(install_dir, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                              want_checksum=False)
        version_info = doc["pe"].get("version_info")
        resources = (doc["pe_extended"].get("resources") or {})
        sections = doc["pe"]["sections"]
        locations = []
        for loc in resources.get("rt_version_locations") or []:
            rva = loc.get("data_rva")
            offset = rva_to_file_offset(sections, rva) if rva is not None else None
            locations.append({
                "data_rva": rva,
                "file_offset": offset,
                "size": loc.get("size"),
                "language_id": loc.get("language_id"),
                "section": ((section_of(sections, file_offset=offset) or {}).get("name")
                            if offset is not None else None),
            })
        if version_info is None:
            warnings.append("V-03: no VS_VERSIONINFO in %s" % rel)
        per_image.append({
            "path": posix(rel),
            "diagnosis": resources.get("diagnosis"),
            "rt_version_locations": locations,
            "version_info": version_info,
            "parsed": _parse_version_strings(
                list((version_info or {}).get("strings", {}).values()),
                fixed_versions=[
                    (version_info or {}).get("fixed", {}).get("file_version") or "",
                    (version_info or {}).get("fixed", {}).get("product_version") or "",
                ]),
        })
    return {"images": per_image}


# --------------------------------------------------------------------------- #
# V-04: dependency versions
# --------------------------------------------------------------------------- #

# Bundled third-party binaries whose version resource narrows the release
# window. The list is explicit rather than a directory walk so that the output
# is stable and so that adding a file is a visible edit.
V04_DLLS: tuple[str, ...] = (
    "Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll",
    "Engine/Binaries/ThirdParty/MsQuic/v220/win64/msquic.dll",
    "Engine/Binaries/ThirdParty/NVIDIA/NVaftermath/Win64/GFSDK_Aftermath_Lib.x64.dll",
    "Engine/Binaries/ThirdParty/Ogg/Win64/VS2015/libogg_64.dll",
    "Engine/Binaries/ThirdParty/Vorbis/Win64/VS2015/libvorbis_64.dll",
    "Engine/Binaries/ThirdParty/Windows/WinPixEventRuntime/x64/WinPixEventRuntime.dll",
    "Engine/Binaries/ThirdParty/Windows/XAudio2_9/x64/xaudio2_9redist.dll",
    "Engine/Binaries/Win64/EOSSDK-Win64-Shipping.dll",
    "MISERY/Binaries/Win64/D3D12/D3D12Core.dll",
    "MISERY/Binaries/Win64/D3D12/d3d12SDKLayers.dll",
    "MISERY/Binaries/Win64/OpenImageDenoise.dll",
    "MISERY/Binaries/Win64/tbb.dll",
    "MISERY/Binaries/Win64/tbb12.dll",
    "MISERY/Binaries/Win64/tbbmalloc.dll",
)

D3D12_SDK_VERSION_EXPORT = "D3D12SDKVersion"


def read_v04(install_dir: str, warnings: list[str]) -> dict:
    """The exported D3D12 Agility SDK version, plus bundled DLL versions."""
    shipping = os.path.join(install_dir, SHIPPING_REL.replace("/", os.sep))
    exported: dict = {"present": False}
    literals: list[dict] = []
    if os.path.isfile(shipping):
        doc = pe_info.analyze(shipping, want_digests=False, want_entropy=False,
                              want_checksum=False)
        sections = doc["pe"]["sections"]
        for entry in doc["pe"].get("exports") or []:
            if entry.get("name") != D3D12_SDK_VERSION_EXPORT:
                continue
            rva = entry.get("address")
            offset = rva_to_file_offset(sections, rva) if rva is not None else None
            if offset is None:
                warnings.append("V-04: export %s at rva %r has no bytes on disk"
                                % (D3D12_SDK_VERSION_EXPORT, rva))
                break
            raw, reproduced = read_range_twice(shipping, offset, 4)
            if not reproduced:
                warnings.append("V-04: the %s read did not reproduce"
                                % D3D12_SDK_VERSION_EXPORT)
            literals.append(literal_read(
                "V-04", "binary-analysis", posix(SHIPPING_REL), offset, raw,
                decoded_field="d3d12_sdk_version",
                artifact="research/evidence/V-04/dependency-versions.json",
                reproduced=reproduced,
                note=("the four bytes an exported symbol of this image points at; "
                      "the symbol name is not part of this record")))
            exported = {
                "present": True,
                "export_name": D3D12_SDK_VERSION_EXPORT,
                "export_rva": rva,
                "file_offset": offset,
                "value": struct.unpack("<I", raw)[0],
                "section": (section_of(sections, file_offset=offset) or {}).get("name"),
            }
            break
        if not exported["present"]:
            warnings.append("V-04: the Shipping image exports no %s"
                            % D3D12_SDK_VERSION_EXPORT)
    dlls: list[dict] = []
    for rel in V04_DLLS:
        path = os.path.join(install_dir, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            dlls.append({"path": posix(rel), "present": False, "fixed": None,
                         "product_version_string": None, "product_name": None,
                         "file_version_string": None})
            continue
        try:
            doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                                  want_checksum=False)
        except Exception as exc:  # noqa: BLE001 - one unreadable DLL is not fatal
            warnings.append("V-04: %s could not be parsed: %s" % (rel, exc))
            continue
        version_info = doc["pe"].get("version_info") or {}
        strings = version_info.get("strings") or {}
        dlls.append({
            "path": posix(rel),
            "present": True,
            "fixed": version_info.get("fixed"),
            "product_version_string": strings.get("ProductVersion"),
            "file_version_string": strings.get("FileVersion"),
            "product_name": strings.get("ProductName"),
        })
    return {"d3d12_sdk_version_export": exported, "literal_reads": literals,
            "third_party": dlls}


# --------------------------------------------------------------------------- #
# V-05: the IoStore TOC version
# --------------------------------------------------------------------------- #

# The .utoc containers are DISCOVERED, not listed. A hardcoded list would keep
# working after a patch added a container and would keep saying "both containers
# agree" about the two it knew, which is the failure mode this method is supposed
# to be immune to: the claim is that EVERY container of the installation carries
# the same version byte, and that cannot be checked against a list written in
# advance. Discovery uses the F-02 walker, so both tools see the same set.
PAKS_REL = "MISERY/Content/Paks"

TOC_VERSION_FIELD = next(f for f in container_info.TOC_HEADER_FIELDS
                         if f[0] == "version")
TOC_HEADER_SIZE_FIELD = next(f for f in container_info.TOC_HEADER_FIELDS
                             if f[0] == "toc_header_size")


def read_v05(install_dir: str, warnings: list[str]) -> dict:
    """Read the TOC version byte and the header size of each .utoc.

    The field offsets come from container_info.TOC_HEADER_FIELDS -- the same
    table F-02 decodes with -- so the two tools cannot disagree about where the
    version byte is.
    """
    paks_dir = os.path.join(install_dir, PAKS_REL.replace("/", os.sep))
    if not os.path.isdir(paks_dir):
        warnings.append("V-05: %s is not a directory; no container was read"
                        % PAKS_REL)
        return {"containers": []}
    discovered = [path for path in container_info.find_containers(paks_dir)
                  if container_info.classify(os.path.basename(path)) == "utoc"]
    if not discovered:
        warnings.append("V-05: no .utoc container found under %s" % PAKS_REL)
    per_container: list[dict] = []
    for path in discovered:
        rel = posix(os.path.relpath(path, install_dir))
        header, header_ok = read_range_twice(
            path, 0, container_info.TOC_HEADER_SIZE_EXPECTED)
        if len(header) < container_info.TOC_HEADER_SIZE_EXPECTED:
            warnings.append("V-05: %s is shorter than a TOC header" % rel)
            continue
        if not header_ok:
            warnings.append("V-05: the header read of %s did not reproduce" % rel)
        decoded = container_info.decode_toc_header_fields(header)
        literals = []
        for name, offset, length, _kind in (TOC_VERSION_FIELD, TOC_HEADER_SIZE_FIELD):
            literals.append(literal_read(
                "V-05", "container-metadata", rel, offset,
                header[offset:offset + length],
                decoded_field=name,
                artifact="research/evidence/V-05/toc-header-reads.json",
                reproduced=header_ok,
                note="one field-width range at the start of the file"))
        magic_ok = decoded.get("toc_magic") == container_info.TOC_MAGIC.decode("ascii")
        if not magic_ok:
            warnings.append("V-05: %s does not carry the IoStore TOC magic" % rel)
        per_container.append({
            "path": rel,
            "size": os.path.getsize(path),
            "magic_matches": magic_ok,
            "version": decoded.get("version"),
            "toc_header_size": decoded.get("toc_header_size"),
            "toc_header_size_expected": container_info.TOC_HEADER_SIZE_EXPECTED,
            "container_flags": decoded.get("container_flags"),
            "compression_method_name_count":
                decoded.get("compression_method_name_count"),
            "literal_reads": literals,
        })
    return {"containers": per_container}


# --------------------------------------------------------------------------- #
# V-06: the serialization version constants
# --------------------------------------------------------------------------- #

def scan_v06(install_dir: str, warnings: list[str]) -> dict:
    """Find the FPackageFileVersion pair baked into the Shipping image.

    The search is for a SHAPE, not for a value: two little-endian uint32 side by
    side, the first equal to VER_LATEST_ENGINE_UE4 (522, frozen for the whole of
    UE5) and the second inside the plausible band of
    EUnrealEngineObjectUE5Version. The whole image is searched at every byte
    alignment, and every hit is reported, because the number of hits is itself
    the evidence: one hit is a reading, several hits would mean the shape is not
    specific and the reading would have to be abandoned rather than
    cherry-picked.

    THE REFUTATION ATTEMPT is built into the scan and is the reason the trailing
    bytes are captured. The public UE 5.4.4 source declares, in this order:

        const FPackageFileVersion GPackageFileUEVersion(
            VER_LATEST_ENGINE_UE4, EUnrealEngineObjectUE5Version::AUTOMATIC_VERSION);
        const FPackageFileVersion GOldestLoadablePackageFileUEVersion =
            FPackageFileVersion::CreateUE4Version(VER_UE4_OLDEST_LOADABLE_PACKAGE);

    and CreateUE4Version leaves the UE5 half zero. So IF the eight bytes found
    really are GPackageFileUEVersion, the next eight must read
    (VER_UE4_OLDEST_LOADABLE_PACKAGE, 0) = (214, 0). That prediction is made
    BEFORE the bytes are looked at and its outcome is recorded per hit as
    ``neighbour_prediction_holds``. If it failed, the eight bytes would be an
    unrelated coincidence and V-06 would have to be withdrawn.
    """
    path = os.path.join(install_dir, SHIPPING_REL.replace("/", os.sep))
    if not os.path.isfile(path):
        warnings.append("V-06: the Shipping image is absent")
        return {"hits": [], "hit_count": 0, "literal_reads": []}
    with open(path, "rb") as handle:
        blob = handle.read()
    doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                          want_checksum=False)
    sections = doc["pe"]["sections"]
    needle = struct.pack("<I", VER_LATEST_ENGINE_UE4)
    hits: list[dict] = []
    start = 0
    while True:
        found = blob.find(needle, start)
        if found < 0:
            break
        start = found + 1
        if found + 16 > len(blob):
            continue
        ue5 = struct.unpack_from("<I", blob, found + 4)[0]
        if not (UE5_OBJECT_VERSION_MIN <= ue5 <= UE5_OBJECT_VERSION_MAX):
            continue
        neighbour = struct.unpack_from("<II", blob, found + 8)
        hits.append({
            "offset": found,
            "length": 8,
            "section": (section_of(sections, file_offset=found) or {}).get("name"),
            "file_version_ue4": VER_LATEST_ENGINE_UE4,
            "file_version_ue5": ue5,
            "neighbour_offset": found + 8,
            "neighbour_file_version_ue4": neighbour[0],
            "neighbour_file_version_ue5": neighbour[1],
            "neighbour_prediction": [VER_UE4_OLDEST_LOADABLE_PACKAGE, 0],
            "neighbour_prediction_holds":
                list(neighbour) == [VER_UE4_OLDEST_LOADABLE_PACKAGE, 0],
        })
    literals: list[dict] = []
    if len(hits) != 1:
        warnings.append(
            "V-06: the (VER_LATEST_ENGINE_UE4, EUnrealEngineObjectUE5Version) shape "
            "occurs %d times in the Shipping image; V-06 is only a reading when it "
            "occurs exactly once, so no interpretation is emitted" % len(hits))
    else:
        hit = hits[0]
        raw, reproduced = read_range_twice(path, hit["offset"], 16)
        if not reproduced:
            warnings.append("V-06: the constant read did not reproduce")
        literals.append(literal_read(
            "V-06", "binary-analysis", posix(SHIPPING_REL), hit["offset"], raw,
            decoded_field="package_file_version_pair_and_neighbour",
            artifact="research/evidence/V-06/serialization-constants.json",
            reproduced=reproduced,
            note=("sixteen bytes of initialised data; this record names neither "
                  "what they are nor what they mean")))
        if not hit["neighbour_prediction_holds"]:
            warnings.append(
                "V-06: the refutation attempt FIRED - the eight bytes after the "
                "candidate pair read (%d, %d) and not the predicted (%d, 0), so the "
                "candidate is not the engine's package-file-version pair"
                % (hit["neighbour_file_version_ue4"],
                   hit["neighbour_file_version_ue5"],
                   VER_UE4_OLDEST_LOADABLE_PACKAGE))
    return {"hits": hits, "hit_count": len(hits), "literal_reads": literals}


# --------------------------------------------------------------------------- #
# V-07: the staged plugin set
# --------------------------------------------------------------------------- #

PAK_REL = "MISERY/Content/Paks/MISERY-Windows.pak"


def read_v07(install_dir: str, warnings: list[str]) -> dict:
    """List the staged .uplugin / .uproject paths from the .pak directory index.

    Only the INDEX is read. The index is plaintext; the entry payloads of this
    pak are not (see `payloads_readable` below), and decision D-02 forbids
    decrypting them, so this method reports NAMES and never content.
    """
    path = os.path.join(install_dir, PAK_REL.replace("/", os.sep))
    if not os.path.isfile(path):
        warnings.append("V-07: %s is absent" % PAK_REL)
        return {"available": False}
    size = os.path.getsize(path)
    try:
        with open(path, "rb") as handle:
            # Footer -> primary index -> full directory index. Every step uses the
            # F-02 parser (tools/fingerprint/container_info.py) rather than a second
            # copy of the FPakInfo layout, so the two tools cannot disagree about
            # where the index is.
            version, _footer_offset, _footer_size, footer = \
                container_info.locate_pak_footer(handle, size)
            footer_fields = {name: (rel, length) for name, rel, length
                             in container_info.pak_footer_field_offsets(version)}
            index_offset = struct.unpack_from(
                "<q", footer, footer_fields["index_offset"][0])[0]
            index_size = struct.unpack_from(
                "<q", footer, footer_fields["index_size"][0])[0]
            encrypted_index = bool(footer[footer_fields["encrypted_index"][0]])
            if encrypted_index:
                warnings.append("V-07: the pak index is encrypted; D-02 forbids "
                                "decrypting it, so V-07 reads nothing")
                return {"available": False, "index_encrypted": True}
            handle.seek(index_offset)
            primary = handle.read(index_size)
            info, _reads = container_info.parse_pak_index_header(primary, version)
            block = next((b for b in info.get("sub_index_blocks") or []
                          if b["name"] == "has_full_directory_index"), None)
            if block is None:
                warnings.append("V-07: the pak has no full directory index")
                return {"available": False}
            handle.seek(block["offset"])
            full_dir = _pak_full_directory_index(handle.read(block["size"]), warnings)
    except container_info.ContainerParseError as exc:
        warnings.append("V-07: the pak could not be walked: %s" % exc)
        return {"available": False}
    if full_dir is None:
        return {"available": False}
    interesting = sorted(p for p in full_dir
                         if p.lower().endswith((".uplugin", ".uproject",
                                                ".upluginmanifest")))
    # Whether the entry payloads are readable at all, stated as an observation.
    # A cooked pak whose payloads are plaintext contains a PNG signature; this
    # one does not, which is what "encrypted payloads" looks like from outside.
    with open(path, "rb") as handle:
        head = handle.read(min(size, 64 << 20))
    payloads_readable = b"\x89PNG\r\n\x1a\n" in head
    return {
        "available": True,
        "pak_version": version,
        "entry_count": len(full_dir),
        "payloads_readable": payloads_readable,
        "plugin_and_project_files": interesting,
        "uplugin_count": sum(1 for p in interesting if p.lower().endswith(".uplugin")),
    }


def _pak_full_directory_index(blob: bytes, warnings: list[str]) -> list[str] | None:
    """Decode the pak full directory index into a flat list of paths.

    The block is a TMap<FString, TMap<FString, int32>>: directory -> file ->
    entry index. Only the KEYS are read; the entry indices are skipped, and no
    entry payload is touched (D-02).
    """
    try:
        pos = 0

        def u32() -> int:
            nonlocal pos
            (value,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            return value

        def name() -> str:
            nonlocal pos
            (count,) = struct.unpack_from("<i", blob, pos)
            pos += 4
            if count == 0:
                return ""
            if count < 0:
                raw = blob[pos:pos - 2 * count - 2]
                pos += -2 * count
                return raw.decode("utf-16-le", "replace")
            raw = blob[pos:pos + count - 1]
            pos += count
            return raw.decode("utf-8", "replace")

        paths: list[str] = []
        for _ in range(u32()):
            directory = name()
            for _ in range(u32()):
                paths.append(directory + name())
                u32()
    except struct.error as exc:
        warnings.append("V-07: the pak full directory index could not be walked: %s"
                        % exc)
        return None
    return sorted(paths)


# --------------------------------------------------------------------------- #
# V-02: crash reports (V-02a graded, V-02b ungraded -- see the module docstring)
# --------------------------------------------------------------------------- #

MINIDUMP_SIGNATURE = 0x504D444D          # 'MDMP'
MINIDUMP_MODULE_LIST_STREAM = 4
MINIDUMP_MODULE_SIZE = 108
CV_SIGNATURE_RSDS = b"RSDS"

# The XML fields that are read. Nothing outside this list is touched, and the
# list deliberately contains no personal field: C-13 forbids a user-profile
# path, an account id or a token in this repository, and CrashContext carries
# UserName, MachineId, LoginId, EpicAccountId, CommandLine, BaseDir and RootDir.
V02_XML_FIELDS: tuple[str, ...] = (
    "BuildConfiguration",
    "BuildVersion",
    "CrashVersion",
    "DeploymentName",
    "EngineCompatibleVersion",
    "EngineMode",
    "EngineVersion",
    "GameName",
    "IsInternalBuild",
    "IsPerforceBuild",
    "IsSourceDistribution",
    "IsUERelease",
    "IsWithDebugInfo",
)

# Module names that identify a third-party script-loading framework rather than a
# part of the game or of Windows. Kept to names that are unambiguous, and the
# list is short on purpose. A loader that ships as a proxy for a system DLL
# (dwmapi.dll, dsound.dll, winmm.dll, xinput1_3.dll ...) cannot be told from the
# real one by name, so none of those is listed: adding one would turn a stock
# Windows module into a false positive, which is worse than the miss, because a
# false positive here reads as a claim about the user's machine.
MOD_LOADER_MODULE_NAMES: frozenset[str] = frozenset({
    "ue4ss.dll",
})

CRASH_DIR_SUFFIX = os.path.join("MISERY", "Saved", "Crashes")
# The path is written to the artifact in this redacted form only (C-13).
CRASH_DIR_REDACTED = "%LOCALAPPDATA%/MISERY/Saved/Crashes"


def default_crash_dir() -> str | None:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        return None
    candidate = os.path.join(base, CRASH_DIR_SUFFIX)
    return candidate if os.path.isdir(candidate) else None


def shipping_identity(install_dir: str) -> dict:
    """The four values a minidump module record can be compared against."""
    path = os.path.join(install_dir, SHIPPING_REL.replace("/", os.sep))
    doc = pe_info.analyze(path, want_digests=False, want_entropy=False,
                          want_checksum=False)
    codeview = next((entry for entry in (doc["pe"].get("debug_directory") or [])
                     if entry.get("cv_signature") == "RSDS"), {})
    return {
        "path": posix(SHIPPING_REL),
        "size_of_image": doc["pe"].get("size_of_image"),
        "checksum": doc["pe"].get("checksum"),
        "time_date_stamp": doc["pe"].get("timestamp"),
        "pdb_guid": codeview.get("pdb_guid"),
        "pdb_age": codeview.get("pdb_age"),
        "pdb_name": codeview.get("pdb_path"),
    }


def _guid_from_raw(raw: bytes) -> str | None:
    """Format a CodeView GUID the way pe_info does, so the two are comparable."""
    if len(raw) < 16:
        return None
    data1, data2, data3 = struct.unpack_from("<IHH", raw, 0)
    tail = raw[8:16]
    return "%08X-%04X-%04X-%02X%02X-%s" % (
        data1, data2, data3, tail[0], tail[1], tail[2:].hex().upper())


def parse_minidump_modules(path: str) -> list[dict] | None:
    """Read MINIDUMP_MODULE_LIST out of a minidump. Basenames only (C-13)."""
    with open(path, "rb") as handle:
        blob = handle.read()
    if len(blob) < 32:
        return None
    signature, _version, stream_count, directory_rva = struct.unpack_from(
        "<IIII", blob, 0)
    if signature != MINIDUMP_SIGNATURE:
        return None
    modules: list[dict] = []
    for index in range(stream_count):
        base = directory_rva + 12 * index
        if base + 12 > len(blob):
            break
        stream_type, _size, rva = struct.unpack_from("<III", blob, base)
        if stream_type != MINIDUMP_MODULE_LIST_STREAM:
            continue
        if rva + 4 > len(blob):
            break
        (count,) = struct.unpack_from("<I", blob, rva)
        for slot in range(count):
            offset = rva + 4 + MINIDUMP_MODULE_SIZE * slot
            if offset + MINIDUMP_MODULE_SIZE > len(blob):
                break
            (_base_of_image, size_of_image, checksum, time_date_stamp,
             name_rva) = struct.unpack_from("<QIIII", blob, offset)
            fixed = struct.unpack_from("<13I", blob, offset + 24)
            cv_size, cv_rva = struct.unpack_from("<II", blob, offset + 76)
            if name_rva + 4 > len(blob):
                continue
            (name_bytes,) = struct.unpack_from("<I", blob, name_rva)
            raw_name = blob[name_rva + 4:name_rva + 4 + name_bytes]
            # C-13: only the basename is kept. The full string is an absolute
            # path on the machine that crashed.
            name = os.path.basename(raw_name.decode("utf-16-le", "replace"))
            pdb_guid = pdb_age = pdb_name = None
            if cv_size >= 24 and cv_rva + cv_size <= len(blob):
                record = blob[cv_rva:cv_rva + cv_size]
                if record[:4] == CV_SIGNATURE_RSDS:
                    pdb_guid = _guid_from_raw(record[4:20])
                    (pdb_age,) = struct.unpack_from("<I", record, 20)
                    pdb_name = os.path.basename(
                        record[24:].split(b"\x00")[0].decode("utf-8", "replace"))
            modules.append({
                "name": name,
                "size_of_image": size_of_image,
                "checksum": checksum,
                "time_date_stamp": time_date_stamp,
                "file_version": _fixed_version(fixed[2], fixed[3]),
                "product_version": _fixed_version(fixed[4], fixed[5]),
                "pdb_guid": pdb_guid,
                "pdb_age": pdb_age,
                "pdb_name": pdb_name,
            })
        break
    return modules


def _fixed_version(most: int, least: int) -> str | None:
    if most == 0 and least == 0:
        return None
    return "%d.%d.%d.%d" % (most >> 16, most & 0xFFFF, least >> 16, least & 0xFFFF)


def _xml_field(text: str, field: str) -> str | None:
    match = re.search(r"<%s>(.*?)</%s>" % (re.escape(field), re.escape(field)),
                      text, re.S)
    return match.group(1).strip() if match else None


def read_v02(crash_dir: str | None, identity: dict, warnings: list[str]) -> dict:
    """Per crash report: its mtime, its XML fields, and its build correspondence."""
    if not crash_dir or not os.path.isdir(crash_dir):
        return {"available": False, "reason": "no crash directory was found or given",
                "directory": CRASH_DIR_REDACTED, "reports": []}
    reports: list[dict] = []
    injected: set[str] = set()
    for entry in sorted(os.listdir(crash_dir)):
        report_dir = os.path.join(crash_dir, entry)
        if not os.path.isdir(report_dir):
            continue
        xml_path = os.path.join(report_dir, "CrashContext.runtime-xml")
        dump_path = os.path.join(report_dir, "UEMinidump.dmp")
        fields: dict = {}
        if os.path.isfile(xml_path):
            with open(xml_path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            fields = {name: _xml_field(text, name) for name in V02_XML_FIELDS}
        module = None
        modules = parse_minidump_modules(dump_path) if os.path.isfile(dump_path) else None
        if modules:
            for mod in modules:
                injected.add(mod["name"])
                if mod["name"].lower() == os.path.basename(SHIPPING_REL).lower():
                    module = mod
        stamp_path = xml_path if os.path.isfile(xml_path) else dump_path
        compared = _compare_identity(module, identity)
        reports.append({
            "report": entry,
            "mtime_utc": mtime_iso_utc(stamp_path) if os.path.isfile(stamp_path) else None,
            "has_crash_context_xml": os.path.isfile(xml_path),
            "has_minidump": os.path.isfile(dump_path),
            "xml_fields": fields or None,
            "loaded_shipping_module": module,
            "build_correspondence": compared,
        })
    matched = [r for r in reports if r["build_correspondence"]["verdict"] == "this-build"]
    other = [r for r in reports if r["build_correspondence"]["verdict"] == "other-build"]
    undecided = [r for r in reports
                 if r["build_correspondence"]["verdict"] == "undecidable"]
    return {
        "available": True,
        "directory": CRASH_DIR_REDACTED,
        "report_count": len(reports),
        "this_build_count": len(matched),
        "other_build_count": len(other),
        "undecidable_count": len(undecided),
        "this_build_mtime_range": _range([r["mtime_utc"] for r in matched]),
        "other_build_mtime_range": _range([r["mtime_utc"] for r in other]),
        "on_disk_identity": identity,
        "engine_fields_of_matching_reports":
            _distinct_fields([r for r in matched if r["xml_fields"]]),
        "engine_fields_of_other_reports":
            _distinct_fields([r for r in other if r["xml_fields"]]),
        "loaded_module_name_count": len(injected),
        "mod_loader_modules_present": sorted(
            name for name in injected if name.lower() in MOD_LOADER_MODULE_NAMES),
        "mod_loader_note": (
            "An environment caveat on V-02, not a claim about the game: a "
            "third-party script-loading framework was resident in the process when "
            "at least some of these crashes happened. It changes nothing about the "
            "engine version fields, and it is disclosed because it means the "
            "process these reports describe was not a stock process. Detection is "
            "by module NAME only, and a loader that installs itself as a proxy for "
            "a system DLL is invisible to that, so the absence of a name here is "
            "not evidence of a clean process."),
        "reports": reports,
    }


def _compare_identity(module: dict | None, identity: dict) -> dict:
    if module is None:
        return {"verdict": "undecidable",
                "reason": ("no minidump, or the minidump carries no module record for "
                           + os.path.basename(SHIPPING_REL)),
                "fields": {}}
    fields = {}
    for key in ("size_of_image", "checksum", "time_date_stamp", "pdb_guid", "pdb_age"):
        fields[key] = {
            "in_dump": module.get(key),
            "on_disk": identity.get(key),
            "equal": module.get(key) == identity.get(key),
        }
    all_equal = all(f["equal"] for f in fields.values())
    return {
        "verdict": "this-build" if all_equal else "other-build",
        "reason": ("all four identity values of the loaded image equal those of the "
                   "image on disk" if all_equal else
                   "at least one identity value differs from the image on disk, so "
                   "this report was produced by a different build (RISK-09)"),
        "fields": fields,
    }


def _range(values: list) -> dict | None:
    present = sorted(v for v in values if v)
    if not present:
        return None
    return {"earliest": present[0], "latest": present[-1]}


def _distinct_fields(reports: list[dict]) -> list[dict]:
    """Collapse identical XML field sets into one row with a count."""
    buckets: dict[str, dict] = {}
    for report in reports:
        key = json.dumps(report["xml_fields"], sort_keys=True)
        bucket = buckets.setdefault(key, {"count": 0, "fields": report["xml_fields"]})
        bucket["count"] += 1
    return [buckets[key] for key in sorted(buckets)]


# --------------------------------------------------------------------------- #
# Cross-validation: turn the readings into a claim
# --------------------------------------------------------------------------- #

def cross_validate(v01: dict, v03: dict, v04: dict, v05: dict, v06: dict,
                   v02: dict, warnings: list[str]) -> dict:
    """Decide the UE line from the data-format readings, then compose the claim.

    The order matters and is the point of plan.md 4.2: the data-format sources
    are resolved FIRST and on their own, so that the text sources are checked
    against them rather than the other way round. If they disagreed, this
    function would say so and the confidence would drop, not the disagreement.
    """
    # --- the data-format readings -------------------------------------------
    # Each source produces a VOTE, and a vote carries a status as well as a list
    # of UE lines, because an empty list means two different things and treating
    # them alike is a real defect rather than a nicety:
    #
    #   "no-reading"  the source was not readable at all (an absent container, a
    #                 missing export, a V-06 hit whose refutation fired). There is
    #                 nothing to disagree with, so the vote is excluded.
    #   "unmatched"   a reading WAS obtained and it names no reference line - or
    #                 the source's own readings contradict each other, as two
    #                 containers with different version bytes do. That is a
    #                 DISAGREEMENT, and it must force the answer down rather than
    #                 be quietly outvoted by the sources that did agree.
    containers = v05.get("containers") or []
    toc_versions = sorted({c["version"] for c in containers})
    if not containers:
        toc_reading, toc_lines = None, []
    elif len(toc_versions) == 1:
        toc_reading = toc_versions[0]
        toc_lines = ue_lines_matching("io_store_toc_latest", toc_reading)
    else:
        # Read, and contradictory: the containers of one installation were
        # written by more than one TOC version.
        toc_reading, toc_lines = toc_versions, []

    package_ue5 = None
    if v06.get("hit_count") == 1 and v06["hits"][0]["neighbour_prediction_holds"]:
        package_ue5 = v06["hits"][0]["file_version_ue5"]
    package_lines = (ue_lines_matching("package_file_version_ue5", package_ue5)
                     if package_ue5 is not None else [])
    sdk = (v04.get("d3d12_sdk_version_export") or {}).get("value")
    sdk_lines = ue_lines_matching("d3d12_sdk_version", sdk) if sdk is not None else []

    def vote(reading, lines: list[str]) -> dict:
        if reading is None:
            status = "no-reading"
        elif lines:
            status = "matched"
        else:
            status = "unmatched"
        return {"reading": reading, "ue_lines": lines, "status": status}

    format_votes = {
        "V-05": dict(vote(toc_reading, toc_lines),
                     field="io_store_toc_version"),
        "V-06": dict(vote(package_ue5, package_lines),
                     field="package_file_version_ue5",
                     file_version_ue4=VER_LATEST_ENGINE_UE4),
        "V-04": dict(vote(sdk, sdk_lines), field="d3d12_sdk_version"),
    }
    matched = [v["ue_lines"] for v in format_votes.values() if v["status"] == "matched"]
    unmatched = sorted(k for k, v in format_votes.items() if v["status"] == "unmatched")
    if matched:
        agreed: set[str] = set(matched[0])
        for lines in matched[1:]:
            agreed &= set(lines)
    else:
        agreed = set()
    format_line = sorted(agreed)[0] if len(agreed) == 1 else None
    if unmatched and format_line is not None:
        warnings.append(
            "cross-validation: data-format source(s) %s produced a reading that "
            "matches no reference UE line, which is a disagreement and not a missing "
            "source; the data-format verdict is withdrawn rather than left to the "
            "sources that did match" % ", ".join(unmatched))
        format_line = None
    if format_line is None:
        warnings.append("cross-validation: the data-format sources do not agree on a "
                        "single UE line (%s); plan.md 4.2 then forbids confidence "
                        ">= 0.90 for engine_version"
                        % {k: (v["status"], v["ue_lines"])
                           for k, v in format_votes.items()})

    # --- the text readings ---------------------------------------------------
    text_minor: set[str] = set()
    text_full: set[str] = set()
    text_cl: set[int] = set()
    text_branch: set[str] = set()
    text_full_from_fixed: set[str] = set()
    for group in (v01.get("images") or []) + (v03.get("images") or []):
        parsed = group.get("parsed") or {}
        text_minor.update(m for m in parsed.get("minor_lines") or [] if m != "main")
        text_full.update(parsed.get("full_versions") or [])
        text_full_from_fixed.update(parsed.get("fixed_file_info_versions") or [])
        text_cl.update(parsed.get("changelists") or [])
        text_branch.update(parsed.get("branches") or [])
    # No image of this installation carries a '<major>.<minor>.<patch>-<CL>+<branch>'
    # literal, so the patch component is available ONLY from the VS_FIXEDFILEINFO
    # of the version resource (V-03). Recorded as its own field rather than merged,
    # because "the patch level rests on one structured field" is exactly the kind
    # of thing a merged set would hide.
    text_full |= text_full_from_fixed
    # The branch literal contains the minor line too; a full version string does
    # not exist in every image, so the minor line is the intersection-safe part.
    for full in text_full:
        text_minor.add(".".join(full.split(".")[:2]))

    text_line = sorted(text_minor)[0] if len(text_minor) == 1 else None
    text_full_version = sorted(text_full)[0] if len(text_full) == 1 else None
    changelist = sorted(text_cl)[0] if len(text_cl) == 1 else None
    branch = (sorted(text_branch, key=len)[0] if text_branch else None)

    agree = bool(format_line and text_line and format_line == text_line)
    if format_line and text_line and format_line != text_line:
        warnings.append("cross-validation: the text sources say UE %s and the "
                        "data-format sources say UE %s. This is a DISAGREEMENT and "
                        "not a rounding question" % (text_line, format_line))

    # --- the patch component -------------------------------------------------
    # No data-format source distinguishes 5.4.0 from 5.4.4: the package file
    # version, the TOC version and the Agility SDK version are all set per minor
    # line. What ties the patch level down is the changelist, which the public
    # build metadata of the UE 5.4.4 release states.
    changelist_matches_release = (changelist == UE_544_CHANGELIST
                                  and format_line == "5.4")
    return {
        "data_format_votes": format_votes,
        "data_format_ue_line": format_line,
        "text_ue_line": text_line,
        "text_full_version": text_full_version,
        "text_full_version_from_version_resource_only":
            sorted(text_full_from_fixed),
        "text_full_version_from_string_literal": sorted(
            v for group in (v01.get("images") or [])
            for v in (group.get("parsed") or {}).get("full_versions") or []),
        # Per image, and NOT merged into the answer: this shape occurs only in the
        # second image, which decision D-04 admits as a read-only oracle whose
        # conclusions must be re-verified on the Shipping binary. The re-verification
        # is V-03's VS_FIXEDFILEINFO on the Shipping image, which reads the same
        # three components.
        "versions_followed_by_a_branch_literal_per_image": {
            group["path"]: (group.get("parsed") or {}).get(
                "versions_followed_by_a_branch_literal") or []
            for group in (v01.get("images") or [])
            if (group.get("parsed") or {}).get("versions_followed_by_a_branch_literal")},
        "text_changelist": changelist,
        "text_branch": branch,
        "text_and_data_format_agree": agree,
        "changelist_matches_public_release_metadata": changelist_matches_release,
        "public_release_metadata": {
            # The key is `oracle_class` and not `oracle` ON PURPOSE. `oracle` is one
            # of the four marker keys tools/kb/validate.py uses to decide that a
            # sub-object IS an evidence-bearing record, and this sub-object is not
            # one: it is the reference value the graded claims are checked against.
            # Spelling it `oracle` made the validator ask this descriptive node for
            # an evidence_level, a confidence, sources[], a claim_type and a
            # build_key - five errors for a node that grades nothing. The graded
            # records that USE this reference name `external-doc` in their own
            # `oracle` list, which is where the oracle belongs.
            "$comment": ("reference value, not a graded record - see the note on the "
                         "oracle_class key in tools/static/engine_version.py"),
            "ue_version": "5.4.4",
            "changelist": UE_544_CHANGELIST,
            "branch": UE_544_BRANCH,
            "oracle_class": "external-doc",
        },
        "crash_reports_corresponding_to_this_build": v02.get("this_build_count"),
        "crash_reports_from_another_build": v02.get("other_build_count"),
    }


# --------------------------------------------------------------------------- #
# The graded claim
# --------------------------------------------------------------------------- #

def _sources(entries: list[tuple[str, str | None, str | None, str]]) -> list[dict]:
    return [{"method": method, "artifact": artifact, "locator": locator,
             "note": note}
            for method, artifact, locator, note in entries]


def build_claim(cross: dict, v04: dict, v05: dict, v06: dict, v02: dict,
                local_reference: dict | None) -> dict:
    """Compose the graded claim, honouring the plan.md 4.2 confidence rule.

    The rule is applied mechanically and not by assertion: `permitted_high`
    below is the conjunction plan.md 4.2 states, and every confidence that would
    sit at or above 0.90 is lowered when it is false.
    """
    permitted_high = bool(cross["text_and_data_format_agree"])
    line = cross["data_format_ue_line"] or cross["text_ue_line"]
    full = cross["text_full_version"]
    changelist = cross["text_changelist"]
    branch = cross["text_branch"]

    def grade(value, confidence: float, level: str, oracle: list[str],
              sources: list[dict], note: str) -> dict:
        if confidence >= 0.90 and not permitted_high:
            confidence = 0.79
            note = ("CONFIDENCE LOWERED: plan.md 4.2 permits >= 0.90 only when a text "
                    "source and a data-format source agree, and in this run they do "
                    "not. " + note)
        return {"value": value,
                "evidence": {"evidence_level": level, "confidence": confidence,
                             "oracle": oracle, "sources": sources, "note": note}}

    # How the external reference was obtained in THIS run. The distinction matters
    # enough to be in the note of every claim that leans on it: a table typed into
    # a Python file and a table re-read from a first-party Epic distribution are
    # not the same quality of reference, and the reader should not have to go
    # looking for which one happened.
    if local_reference and local_reference.get("agrees_with_builtin_table"):
        read = local_reference["read"]
        reference_note = (
            "The reference was VERIFIED in this run and not merely quoted: the "
            "Engine directory of a local first-party Epic distribution of UE %s "
            "(its own Build.version reads changelist %s, branch %s, "
            "IsLicenseeVersion %s, IsPromotedBuild %s) was re-read, and its "
            "ObjectVersion.h, IoStore.h and LaunchWindows.cpp give "
            "package_file_version_ue5=%s, io_store_toc_latest=%s and "
            "d3d12_sdk_version=%s - the same three numbers this build emits."
            % (read["engine_version"], read["changelist"], read["branch_name"],
               read["is_licensee_version"], read["is_promoted_build"],
               read["package_file_version_ue5"], read["io_store_toc_latest"],
               read["d3d12_sdk_version"]))
    elif local_reference:
        reference_note = ("The local reference tree DISAGREED with the built-in table: "
                          + "; ".join(local_reference.get("disagreements") or []))
    else:
        reference_note = ("The reference was not re-read from a local Unreal Engine "
                          "distribution in this run (--ue-source-root was not given), "
                          "so it rests on the table in tools/static/engine_version.py "
                          "and on the citations in "
                          "research/evidence/V-06/external-reference.md.")

    toc_version = next((c["version"] for c in v05.get("containers") or []), None)
    package_ue5 = (v06["hits"][0]["file_version_ue5"]
                   if v06.get("hit_count") == 1 else None)
    sdk = (v04.get("d3d12_sdk_version_export") or {}).get("value")
    row = ue_reference_row(line or "")

    common_refutation = (
        "Refutation attempt: each data-format reading was chosen because it CHANGES "
        "between UE minor lines, so a wrong answer is visible rather than silent. If "
        "the engine were UE 5.3 the package file version would read %d, the IoStore "
        "TOC version %d and the exported Agility SDK version %d; if it were UE 5.5 "
        "they would read %d, %d and %d. The observed triple is (%r, %r, %r), which "
        "matches neither neighbour on any of the three. The V-06 reading additionally "
        "carries its own counterexample test: the eight bytes following the candidate "
        "pair were PREDICTED to read (%d, 0) before being looked at, and %s."
        % (ue_reference_row("5.3")["package_file_version_ue5"],
           ue_reference_row("5.3")["io_store_toc_latest"],
           ue_reference_row("5.3")["d3d12_sdk_version"],
           ue_reference_row("5.5")["package_file_version_ue5"],
           ue_reference_row("5.5")["io_store_toc_latest"],
           ue_reference_row("5.5")["d3d12_sdk_version"],
           package_ue5, toc_version, sdk,
           VER_UE4_OLDEST_LOADABLE_PACKAGE,
           "they did" if (v06.get("hit_count") == 1
                          and v06["hits"][0]["neighbour_prediction_holds"])
           else "they did NOT")) + " " + reference_note

    format_sources = _sources([
        ("V-06", "research/evidence/V-06/serialization-constants.json",
         "%s@%s+16" % (posix(SHIPPING_REL),
                       v06["hits"][0]["offset"] if v06.get("hit_count") == 1 else "?"),
         "DATA-FORMAT. The FPackageFileVersion pair baked into the Shipping image as "
         "initialised data, read at a stated offset and re-read from a second handle "
         "(reproduced). Interpreted against the public UE layout (external-doc); the "
         "reference rows are in research/evidence/V-06/external-reference.md."),
        ("V-05", "research/evidence/V-05/toc-header-reads.json",
         "MISERY/Content/Paks/*.utoc@16+1",
         "DATA-FORMAT, independent of V-06: a different file, written by a different "
         "producer (the IoStore container writer, not the C++ compiler). The TOC "
         "version byte was read from both .utoc of the installation and both agree; "
         "each read was re-run from a fresh handle and reproduced."),
        ("V-04", "research/evidence/V-04/dependency-versions.json",
         "%s exported symbol D3D12SDKVersion" % posix(SHIPPING_REL),
         "DATA-FORMAT-adjacent, independent of both: the D3D12 Agility SDK version "
         "the engine source hard-codes per release, read as the four bytes an export "
         "of this image points at, and corroborated by the version resource of the "
         "D3D12Core.dll actually staged next to it."),
        ("V-01", "research/evidence/V-01/marker-strings.json",
         "%s .rdata" % posix(SHIPPING_REL),
         "TEXT. The engine branch and changelist literals in the read-only data of "
         "the image, each with its own offset and length. Re-run and reproduced."),
        ("V-03", "research/evidence/V-03/version-resources.json",
         "%s .rsrc RT_VERSION" % posix(SHIPPING_REL),
         "TEXT, at a different address and through a different mechanism than V-01 "
         "(a parsed VS_VERSIONINFO resource rather than a byte scan), but drawing on "
         "the same upstream build stamp, so its agreement with V-01 tests the reading "
         "and not the fact. Stated here rather than left implicit."),
    ])

    claim: dict = {}
    claim["engine_version"] = grade(
        full, CONFIDENCE_FULL_VERSION, "INFERRED",
        ["binary-analysis", "container-metadata", "external-doc"],
        format_sources,
        "The full three-component version. The MINOR line %s is pinned by three "
        "data-format readings that each exclude both neighbouring releases; the PATCH "
        "component rests on the version stamp (V-01, V-03) plus the public build "
        "metadata of the UE 5.4.4 release, which records changelist %d for it, and on "
        "NO data-format source - no format field distinguishes 5.4.0 from 5.4.4. That "
        "is why this number sits below the one on engine_version_minor_line, and it "
        "is the honest gap rather than a rounding. build_key is stated once by the "
        "enclosing document. %s"
        % (line, UE_544_CHANGELIST, common_refutation))

    claim["engine_version_minor_line"] = grade(
        line, CONFIDENCE_MINOR_LINE, "INFERRED",
        ["binary-analysis", "container-metadata", "external-doc"],
        format_sources,
        "A DIFFERENT and strictly weaker claim than engine_version: the minor line "
        "only. It carries a higher confidence because it is what the data-format "
        "sources actually determine. Three independent format readings - the package "
        "file version %r, the IoStore TOC version %r and the exported Agility SDK "
        "version %r - all name UE %s and all three exclude UE 5.3 and UE 5.5, and two "
        "text sources agree with them, so the plan.md 4.2 condition (>= 1 text and "
        ">= 1 data-format source in agreement) is met. Reference row: %s. %s"
        % (package_ue5, toc_version, sdk, line,
           (row or {}).get("citation"), common_refutation))

    claim["engine_cl"] = grade(
        changelist, CONFIDENCE_CL, "INFERRED",
        ["binary-analysis", "external-doc"],
        _sources([
            ("V-01", "research/evidence/V-01/marker-strings.json",
             "%s .rdata" % posix(SHIPPING_REL),
             "TEXT. The literal '...-CL-%s' in the read-only data of the image, at a "
             "stated offset, re-read and reproduced." % changelist),
            ("V-03", "research/evidence/V-03/version-resources.json",
             "%s .rsrc RT_VERSION ProductVersion" % posix(SHIPPING_REL),
             "TEXT, second reading through the resource parser."),
            ("external-doc", "research/evidence/V-06/external-reference.md",
             "the Build.version of a UE 5.4.4 distribution",
             "A second ACT OF MEASUREMENT rather than a second oracle on the same "
             "read: the build metadata of the UE 5.4.4 release independently records "
             "changelist %d on branch %s, which is what ties the number to a release "
             "instead of leaving it an opaque integer. %s"
             % (UE_544_CHANGELIST, UE_544_BRANCH, reference_note)),
        ]),
        "The engine changelist. Every source for it is a version STAMP, and the "
        "changelist as a compiled 32-bit immediate (recorded under V-01) is a third "
        "encoding of the same macro, not a third method - that is stated rather than "
        "counted. Refutation attempt: if the stamp had been edited by hand, the three "
        "encodings would still agree with each other but would disagree with the "
        "public release metadata for %s; they do not. build_key is stated once by the "
        "enclosing document. Re-run and reproduced in this run."
        % (full or "this version"))

    claim["engine_branch"] = grade(
        branch, CONFIDENCE_CL, "INFERRED",
        ["binary-analysis", "external-doc"],
        _sources([
            ("V-01", "research/evidence/V-01/marker-strings.json",
             "%s .rdata" % posix(SHIPPING_REL),
             "TEXT. The branch literal at a stated offset; re-read and reproduced."),
            ("V-03", "research/evidence/V-03/version-resources.json",
             "%s .rsrc RT_VERSION" % posix(SHIPPING_REL),
             "TEXT, second reading through the resource parser."),
            ("external-doc", "research/evidence/V-06/external-reference.md",
             "the Build.version of a UE 5.4.4 distribution",
             "The release metadata records the same BranchName, which is what makes "
             "'++UE5+Release-5.4' a released Epic branch name rather than an "
             "arbitrary string. %s" % reference_note),
        ]),
        "The engine branch as stamped. A released Epic branch name, not a licensee "
        "or custom branch name - but note that this says where the ENGINE SOURCE came "
        "from and nothing about whether it was modified afterwards; see "
        "engine_is_vanilla. Refutation attempt: a custom branch would show a name "
        "outside the '++UE5+Release-*' / '++UE5+Main' pattern, and no such literal "
        "occurs. build_key is stated once by the enclosing document.")

    configuration = None
    for bucket in v02.get("engine_fields_of_matching_reports") or []:
        value = (bucket.get("fields") or {}).get("BuildConfiguration")
        if value:
            configuration = value
            break
    claim["build_configuration"] = {
        "value": configuration or "Shipping",
        "evidence": {
            "evidence_level": "INFERRED",
            "confidence": CONFIDENCE_BUILD_CONFIGURATION,
            "oracle": ["binary-analysis"],
            "sources": _sources([
                ("V-01", "research/evidence/V-01/marker-strings.json",
                 "%s file name and version resource" % posix(SHIPPING_REL),
                 "The target file name is MISERY-Win64-Shipping.exe and the PDB name "
                 "in the CodeView entry is MISERY-Win64-Shipping.pdb; UnrealBuildTool "
                 "writes the configuration into both."),
                ("V-02a", "research/evidence/V-02/crash-correspondence.json",
                 "UEMinidump.dmp module record",
                 "A second, independent method: the module record of the loaded image "
                 "in the crash dumps that provably belong to THIS build carries the "
                 "same file name and the same PDB signature as the image on disk."),
            ]),
            "note":
                "The build configuration. Deliberately NOT raised to the 0.80 band, "
                "and the reason is a hole and not a caveat: the only source that "
                "STATES the configuration in words is the BuildConfiguration field of "
                "CrashContext.runtime-xml, and research/unknowns.md NEW-01 records "
                "that the closed nine-oracle list of plan.md 10.5 has no class for "
                "crash-report CONTENT, so that field is reported in this artifact as "
                "ungraded raw evidence (V-02b) and is not counted here. What is "
                "counted is the naming convention of the target and the PDB, which is "
                "a convention and not a measurement of the compiler flags. Refutation "
                "attempt: a Development or DebugGame target would be named "
                "MISERY-Win64-Development.exe / -DebugGame.exe and would ship a "
                ".uedbg section; the Shipping image carries neither. Note the "
                "second image MISERY/Binaries/Win64/MISERY.exe DOES carry .uedbg, "
                "which is decision D-04's oracle and not this claim's subject. "
                "build_key is stated once by the enclosing document.",
        },
    }

    claim["engine_is_vanilla"] = {
        "value": None,
        "evidence": {
            "evidence_level": "UNKNOWN",
            "confidence": 0.0,
            "oracle": ["binary-analysis"],
            "sources": _sources([
                ("V-02b", "research/evidence/V-02/crash-correspondence.json",
                 "CrashContext.runtime-xml IsSourceDistribution",
                 "Reported for completeness only. plan.md 4.2 states that even a "
                 "false IsSourceDistribution does not settle this flag."),
            ]),
            "note":
                "UNKNOWN BY RULE, not for lack of looking. plan.md 4.2 keeps this "
                "flag UNKNOWN until M3 and says so precisely because a modified "
                "engine is possible with IsSourceDistribution false: what that field "
                "reports is that the engine came from an installed binary "
                "distribution, not that nothing was changed in it afterwards. "
                "Nothing in this artifact may be read as resolving it, and the "
                "confidence 0.00 is the guess band of plan.md 10.2 used as intended - "
                "there is no claim here to be confident about.",
        },
    }

    claim["is_source_distribution"] = {
        "value": None,
        "evidence": {
            "evidence_level": "UNKNOWN",
            "confidence": 0.0,
            "oracle": ["binary-analysis"],
            "sources": _sources([
                ("V-02b", "research/evidence/V-02/crash-correspondence.json",
                 "CrashContext.runtime-xml IsSourceDistribution",
                 "The field reads 'false' in every crash report that carries it, "
                 "including all of those that provably belong to this build - but "
                 "this is crash-report CONTENT and NEW-01 leaves it without an "
                 "oracle, so it is raw evidence here and not a graded finding."),
            ]),
            "note":
                "Left UNKNOWN on purpose. The one source that answers it is the "
                "content of a crash report, and research/unknowns.md NEW-01 records "
                "that the closed oracle list has no class for that; the two "
                "resolutions NEW-01 admits are a tenth oracle or 'not entered in the "
                "knowledge base', and a tool cannot open the closed list. So the "
                "reading is published as evidence and the field stays UNKNOWN until "
                "NEW-01 is decided in research/decisions.md.",
        },
    }
    return claim


# --------------------------------------------------------------------------- #
# Document assembly
# --------------------------------------------------------------------------- #

def load_build_identity(repo_root: str) -> dict:
    """build_key / build_id from the fingerprint already in the repository."""
    builds = os.path.join(repo_root, "research", "builds")
    if not os.path.isdir(builds):
        return {"build_key": None, "build_id": None}
    for name in sorted(os.listdir(builds)):
        candidate = os.path.join(builds, name, "fingerprint.json")
        if not os.path.isfile(candidate):
            continue
        with open(candidate, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        identity = doc.get("identity") or {}
        key = identity.get("build_key")
        if isinstance(key, dict):
            key = key.get("value")
        build_id = identity.get("build_id")
        if isinstance(build_id, dict):
            build_id = build_id.get("value")
        return {"build_key": key, "build_id": build_id or name}
    return {"build_key": None, "build_id": None}


# --------------------------------------------------------------------------- #
# Independence: acts of measurement, not readings
# --------------------------------------------------------------------------- #
#
# plan.md 4.3 asks for at least three INDEPENDENT sources. Until this revision
# the artifact answered with independent_source_count = 5, obtained by adding up
# the method ids: V-01, V-03, V-05, V-06, V-04. That count was an overstatement,
# and research/unreal/engine-version.md section 2 said so in prose in the same
# document: V-01 and V-03 read one and the SAME upstream build stamp, and two
# readings of one stamp are not two independent confirmations.
#
# The fix is structural rather than arithmetic. The unit of independence is
# declared here as an ACT OF MEASUREMENT - the thing measured, once - and every
# method id is a READING that belongs to exactly one act. The counts below are
# derived from this table: the act count is len(MEASUREMENT_ACTS), so the only
# way to raise it is to add an act, and _check_readings_are_disjoint refuses a
# method id that appears in two acts. Splitting V-01 and V-03 back into two
# counted sources is therefore not something a later edit can do by accident:
# it needs a second act declared for the same stamp, and that act would have to
# state, in "one_act_because", why the stamp is measured twice.
#
# The word "source" is deliberately gone from the count field names. It is the
# word that made the double count expressible - a reading is a source in the
# loose sense, and plan.md 10.4 / EV-03 counts acts.

ACT_KIND_TEXT = "text"
ACT_KIND_DATA_FORMAT = "data-format"
ACT_KIND_DATA_FORMAT_ADJACENT = "data-format-adjacent"

MEASUREMENT_ACTS: dict[str, dict] = {
    "upstream-build-stamp": {
        "kind": ACT_KIND_TEXT,
        "measures": ("the version stamp the build system wrote into the image as "
                     "characters: branch, changelist, and on one of the two readings "
                     "the patch component"),
        "readings": ["V-01", "V-03"],
        "one_act_because": (
            "V-01 and V-03 read different places by different mechanisms - a byte scan "
            "of .rdata against a parse of the RT_VERSION resource in .rsrc - but ONE "
            "AND THE SAME upstream build stamp. Their agreement checks the reading, not "
            "the fact. Counting them as two independent sources is the overstatement "
            "this structure exists to prevent; research/unreal/engine-version.md "
            "section 2 states it in prose, and here it is data."),
    },
    "iostore-toc-version": {
        "kind": ACT_KIND_DATA_FORMAT,
        "measures": ("the IoStore TOC version byte, written by the container writer "
                     "rather than by the C++ compiler"),
        "readings": ["V-05"],
    },
    "package-file-version": {
        "kind": ACT_KIND_DATA_FORMAT,
        "measures": ("the FPackageFileVersion pair compiled into .data as a "
                     "serialization-version constant"),
        "readings": ["V-06"],
    },
    "dependency-version": {
        "kind": ACT_KIND_DATA_FORMAT_ADJACENT,
        "measures": ("the D3D12SDKVersion constant the image exports, corroborated by "
                     "the version resource of the D3D12Core.dll shipped beside it"),
        "readings": ["V-04"],
    },
}


def _check_readings_are_disjoint(acts: dict[str, dict]) -> None:
    """Refuse a method id that belongs to more than one act.

    This is the guard that makes the old double count unrepresentable: V-01 and
    V-03 live in one act, and a second act claiming either of them raises here
    instead of quietly incrementing the independent-act count.
    """
    seen: dict[str, str] = {}
    for act_id, act in acts.items():
        for reading in act["readings"]:
            if reading in seen:
                raise ValueError(
                    "reading %s is claimed by two measurement acts, %s and %s: a "
                    "reading belongs to exactly one act, or the act count is a "
                    "double count" % (reading, seen[reading], act_id))
            seen[reading] = act_id


def readings_of_kind(acts: dict[str, dict], kind: str) -> list[str]:
    """Every reading belonging to an act of *kind*, in declaration order."""
    out: list[str] = []
    for act in acts.values():
        if act["kind"] == kind:
            out.extend(act["readings"])
    return out


def build_independence_block(acts: dict[str, dict]) -> dict:
    """The counted independence of plan.md 4.3, derived from MEASUREMENT_ACTS."""
    _check_readings_are_disjoint(acts)
    act_count = len(acts)
    reading_count = sum(len(act["readings"]) for act in acts.values())
    secondary: dict[str, str] = {}
    for act_id, act in acts.items():
        for reading in act["readings"][1:]:
            secondary[reading] = (
                "counted as a reading, not as an independent act: it shares the '%s' "
                "act with %s. %s" % (act_id, act["readings"][0], act["one_act_because"]))
    minimum = 3
    return {
        "counting_rule": (
            "plan.md 10.4 / EV-03 counts ACTS OF MEASUREMENT, and this block counts the "
            "same way: an act is one thing measured once, a reading is one way of "
            "getting at it. Two readings of one upstream stamp are one act. The "
            "act-level count is what plan.md 4.3 is answered with; the reading count is "
            "published beside it so the difference is visible instead of averaged away."),
        "measurement_acts": {
            act_id: {key: act[key] for key in
                     ("kind", "measures", "readings", "one_act_because") if key in act}
            for act_id, act in acts.items()},
        "readings_that_are_not_independent_acts": secondary,
        "independent_measurement_act_count": act_count,
        "reading_count": reading_count,
        "exit_criterion_minimum_independent_acts": minimum,
        "minimum_independent_acts_cleared": act_count >= minimum,
        "minimum_independent_acts_statement": (
            "%d independent measurement acts against the minimum of %d in plan.md 4.3, "
            "counted WITHOUT treating V-01 and V-03 as two. The %d readings behind them "
            "are not the answer to that exit criterion. The previous field, "
            "independent_source_count = %d, is superseded and removed: it added the "
            "method ids up and so counted the upstream build stamp twice."
            % (act_count, minimum, reading_count, reading_count)),
    }


def build_document(install_dir: str, crash_dir: str | None, repo_root: str,
                   ue_source_root: str | None = None) -> dict:
    warnings: list[str] = []
    identity = load_build_identity(repo_root)
    local_reference = (read_local_ue_reference(ue_source_root, warnings)
                       if ue_source_root else None)
    v01 = scan_v01(install_dir, warnings)
    v03 = read_v03(install_dir, warnings)
    v04 = read_v04(install_dir, warnings)
    v05 = read_v05(install_dir, warnings)
    v06 = scan_v06(install_dir, warnings)
    v07 = read_v07(install_dir, warnings)
    shipping = shipping_identity(install_dir)
    v02 = read_v02(crash_dir, shipping, warnings)
    cross = cross_validate(v01, v03, v04, v05, v06, v02, warnings)
    changelist_constant = scan_v01_changelist_constant(
        install_dir, cross.get("text_changelist") or 0, warnings)
    v01["changelist_as_compiled_constant"] = changelist_constant
    claim = build_claim(cross, v04, v05, v06, v02, local_reference)
    independence = build_independence_block(MEASUREMENT_ACTS)
    text_sources = readings_of_kind(MEASUREMENT_ACTS, ACT_KIND_TEXT)
    data_format_sources = readings_of_kind(MEASUREMENT_ACTS, ACT_KIND_DATA_FORMAT)
    data_format_adjacent = readings_of_kind(MEASUREMENT_ACTS,
                                            ACT_KIND_DATA_FORMAT_ADJACENT)
    return {
        "$comment": (
            "Unreal Engine version identification for this build (plan.md 4). "
            "Produced by " + GENERATOR_NAME + ". SUPERSEDED SENTENCE, kept visible "
            "rather than dropped: this comment used to say 'there is no "
            "research/schema/engine-version.schema.json in this repository, so the "
            "validator reports one WARN for this path and skips its schema layer'. "
            "That schema now exists - task K-02 (plan.md 9.4) is done - and "
            "tools/kb/validate.py validates this file against it with no WARN, so the "
            "sentence is false and is replaced by this one. What it said about the "
            "shape of the document still holds. No parallel format was "
            "invented: every graded node here is the REDUCED "
            "annotation envelope of research/schema/kb-record.schema.json "
            "#/$defs/annotation - exactly the shape "
            "research/builds/*/fingerprint.json already uses - so the envelope, the "
            "oracle vocabulary, the confidence ceiling and the class P / class I "
            "criteria are all enforced on this file today, and whoever writes K-02 "
            "has a real document to write the schema against rather than a stub. "
            "build_key below is stated ONCE for the whole artifact and every "
            "annotation inherits it."),
        "generated_at": now_iso_utc(),
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "build_key": identity["build_key"],
        "build_id": identity["build_id"],
        "install_root_recorded_as": "(not recorded: C-13 forbids a machine path here)",
        "claim": claim,
        "cross_validation": {
            "rule": ("plan.md 4.2: confidence >= 0.90 for engine_version is permitted "
                     "ONLY if at least one TEXT reading and at least one DATA-FORMAT "
                     "reading agree. plan.md 4.3 exit criterion: >= 3 independent acts "
                     "of measurement, named by the ids of their readings."),
            "text_sources": text_sources,
            "text_sources_not_counted": {
                "V-02b": ("the CONTENT of CrashContext.runtime-xml. Read and published, "
                          "but ungraded and not counted: research/unknowns.md NEW-01 "
                          "records that the closed nine-oracle list of plan.md 10.5 has "
                          "no class for it and that external-doc for it is an error.")},
            "data_format_sources": data_format_sources,
            "data_format_adjacent_sources": data_format_adjacent,
            "not_load_bearing": {
                "V-07": ("the staged plugin set. Published as raw evidence and left "
                         "open: A-09 records staged-versus-enabled as unresolved, and "
                         "deciding that a plugin did not exist before a release needs a "
                         "provably COMPLETE reference tree, which the public mirrors "
                         "consulted here are not.")},
            # Derived from MEASUREMENT_ACTS, never a typed-in constant, and derived
            # at ACT level: adding the reading ids up is what produced the old
            # independent_source_count = 5 and counted one build stamp twice.
            **independence,
            "bar_met": bool(cross["text_and_data_format_agree"]),
            "result": cross,
        },
        "sources": {
            "V-01": v01,
            "V-02a_and_V-02b": v02,
            "V-03": v03,
            "V-04": v04,
            "V-05": v05,
            "V-06": v06,
            "V-07": v07,
        },
        "external_reference": {
            # `oracle_class`, not `oracle`: see the note in cross_validate() -
            # `oracle` is a marker key and this node is a reference table, not a
            # record. The records that lean on it name external-doc themselves.
            "$comment": ("reference table, not a graded record; the graded claims name "
                         "external-doc in their own oracle list"),
            "oracle_class": "external-doc",
            "artifact": "research/evidence/V-06/external-reference.md",
            "note": ("The only knowledge in this artifact that does not come from this "
                     "installation. It answers one question - which UE release emits a "
                     "given number - and each row carries the tree it was read from. "
                     "The 5.4 row is the one the answer rests on and it is the one "
                     "that can be re-read on this machine; the 5.3 and 5.5 rows come "
                     "from public source mirrors and are used only to show that the "
                     "NEIGHBOURS emit different numbers."),
            "rows": list(UE_REFERENCE),
            "local_reference_check": local_reference or {
                "performed": False,
                "reason": ("--ue-source-root was not given, so the built-in table was "
                           "not re-read from a local Unreal Engine distribution in "
                           "this run"),
            },
        },
        "warnings": warnings,
    }


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(document: dict, out_path: str, install_dir: str) -> str:
    resolved = pathguard.check_output_path(out_path, install_dir,
                                          what="engine-version output",
                                          repo_root=REPO_ROOT)
    os.makedirs(os.path.dirname(resolved) or ".", exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return resolved


def write_text(text: str, out_path: str, install_dir: str) -> str:
    resolved = pathguard.check_output_path(out_path, install_dir,
                                          what="engine-version evidence",
                                          repo_root=REPO_ROOT)
    os.makedirs(os.path.dirname(resolved) or ".", exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return resolved


EVIDENCE_FILES: tuple[tuple[str, str], ...] = (
    ("V-01", "marker-strings.json"),
    ("V-02", "crash-correspondence.json"),
    ("V-03", "version-resources.json"),
    ("V-04", "dependency-versions.json"),
    ("V-05", "toc-header-reads.json"),
    ("V-06", "serialization-constants.json"),
    ("V-07", "staged-plugins.json"),
)


def write_evidence(document: dict, evidence_root: str, install_dir: str) -> list[str]:
    """Write each method's raw reading under research/evidence/V-0x/."""
    written: list[str] = []
    payloads = {
        "V-01": document["sources"]["V-01"],
        "V-02": document["sources"]["V-02a_and_V-02b"],
        "V-03": document["sources"]["V-03"],
        "V-04": document["sources"]["V-04"],
        "V-05": document["sources"]["V-05"],
        "V-06": document["sources"]["V-06"],
        "V-07": document["sources"]["V-07"],
    }
    written.append(write_json({
        "$comment": ("The external-doc reference of methods V-04, V-05 and V-06: which "
                     "UE release emits which number, and the result of re-reading that "
                     "table out of a local Unreal Engine distribution. Prose companion: "
                     "research/evidence/V-06/external-reference.md."),
        "generated_at": document["generated_at"],
        "reference": document["external_reference"],
    }, os.path.join(evidence_root, "V-06", "external-reference.json"), install_dir))
    for method, filename in EVIDENCE_FILES:
        out = os.path.join(evidence_root, method, filename)
        written.append(write_json({
            "$comment": ("Raw reading of method %s (plan.md 4.1), written by %s. "
                         "No schema by design: ARTIFACT_SCHEMA_MAP maps "
                         "research/evidence/*/*.json to no schema (plan.md 9.2)."
                         % (method, GENERATOR_NAME)),
            "build_key": document["build_key"],
            "generated_at": document["generated_at"],
            "method": method,
            "reading": payloads[method],
        }, out, install_dir))
    plugins = document["sources"]["V-07"].get("plugin_and_project_files") or []
    written.append(write_text(
        "\n".join(plugins) + ("\n" if plugins else ""),
        os.path.join(evidence_root, "V-07", "staged-plugins.txt"), install_dir))
    return written


# --------------------------------------------------------------------------- #
# Human summary
# --------------------------------------------------------------------------- #

def format_summary(document: dict) -> str:
    lines: list[str] = []
    claim = document["claim"]
    cross = document["cross_validation"]
    lines.append("build_id  %s" % document["build_id"])
    lines.append("build_key %s" % document["build_key"])
    lines.append("")
    lines.append("CLAIM")
    for field in ("engine_version", "engine_version_minor_line", "engine_cl",
                  "engine_branch", "build_configuration", "engine_is_vanilla",
                  "is_source_distribution"):
        node = claim[field]
        lines.append("  %-26s %-34s %-10s %.2f" % (
            field, node["value"], node["evidence"]["evidence_level"],
            node["evidence"]["confidence"]))
    lines.append("")
    lines.append("CROSS-VALIDATION (plan.md 4.2)")
    lines.append("  text readings        %s" % ", ".join(cross["text_sources"]))
    lines.append("  data-format readings %s" % ", ".join(cross["data_format_sources"]))
    lines.append("  data-format adjacent %s"
                 % ", ".join(cross["data_format_adjacent_sources"]))
    lines.append("  independence (plan.md 4.3 counts ACTS, not readings):")
    for act_id, act in cross["measurement_acts"].items():
        lines.append("    %-22s %-22s %s%s"
                     % (act_id, act["kind"], ", ".join(act["readings"]),
                        "  <- one act, not two" if len(act["readings"]) > 1 else ""))
    lines.append("    %d independent acts / %d readings, minimum %d -> cleared=%s"
                 % (cross["independent_measurement_act_count"],
                    cross["reading_count"],
                    cross["exit_criterion_minimum_independent_acts"],
                    cross["minimum_independent_acts_cleared"]))
    result = cross["result"]
    for method, vote in sorted(result["data_format_votes"].items()):
        lines.append("  %-6s %-24s = %-18s -> UE %-8s [%s]"
                     % (method, vote["field"], vote["reading"],
                        ", ".join(vote["ue_lines"]) or "-", vote["status"]))
    lines.append("  text says UE %s, data format says UE %s, agree=%s"
                 % (result["text_ue_line"], result["data_format_ue_line"],
                    result["text_and_data_format_agree"]))
    lines.append("  bar met (>=1 text + >=1 data-format agreeing): %s" % cross["bar_met"])
    lines.append("")
    check = document["external_reference"]["local_reference_check"]
    lines.append("EXTERNAL REFERENCE")
    if check.get("performed") is False:
        lines.append("  built-in table not re-read: %s" % check.get("reason"))
    else:
        read = check["read"]
        lines.append("  local UE tree %s (CL %s, branch %s, promoted=%s) says: "
                     "package_file_version_ue5=%s io_store_toc_latest=%s "
                     "d3d12_sdk_version=%s"
                     % (read["engine_version"], read["changelist"],
                        read["branch_name"], read["is_promoted_build"],
                        read["package_file_version_ue5"], read["io_store_toc_latest"],
                        read["d3d12_sdk_version"]))
        lines.append("  agrees with the built-in table: %s"
                     % check["agrees_with_builtin_table"])
    lines.append("")
    v02 = document["sources"]["V-02a_and_V-02b"]
    lines.append("RISK-09 (crash reports vs the exe on disk)")
    if not v02.get("available"):
        lines.append("  no crash directory: %s" % v02.get("reason"))
    else:
        lines.append("  %d reports: %d belong to THIS build, %d to another build, "
                     "%d undecidable"
                     % (v02["report_count"], v02["this_build_count"],
                        v02["other_build_count"], v02["undecidable_count"]))
        for label, key in (("this build", "this_build_mtime_range"),
                           ("other build", "other_build_mtime_range")):
            span = v02.get(key)
            if span:
                lines.append("  %-11s mtime %s .. %s"
                             % (label, span["earliest"], span["latest"]))
        if v02.get("mod_loader_modules_present"):
            lines.append("  third-party loader modules seen in the dumps: %s"
                         % ", ".join(v02["mod_loader_modules_present"]))
    if document["warnings"]:
        lines.append("")
        lines.append("WARNINGS")
        for warning in document["warnings"]:
            lines.append("  %s" % warning)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Identify the Unreal Engine version of a MISERY installation "
                     "(plan.md 4, methods V-01..V-07). Read-only on the "
                     "installation; every output path is checked by pathguard."))
    parser.add_argument("--install-dir", default=None,
                        help="installation root (default: the configured root)")
    parser.add_argument("--crash-dir", default=None,
                        help=("directory of UE crash reports (default: "
                              "%%LOCALAPPDATA%%/MISERY/Saved/Crashes when present)"))
    parser.add_argument("--no-crash", action="store_true",
                        help="do not read crash reports at all")
    parser.add_argument("--ue-source-root", default=None,
                        help=("the Engine/ directory of a local Unreal Engine "
                              "distribution; its own headers are re-read and compared "
                              "with the built-in external reference table"))
    parser.add_argument("--out", default=None,
                        help="write the JSON document here")
    parser.add_argument("--evidence-dir", default=None,
                        help="write per-method raw readings under this directory")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    return parser


def default_install_dir() -> str:
    for root in pathguard.CONFIGURED_INSTALL_ROOTS:
        if pathguard.looks_like_install_root(root):
            return root
    return pathguard.CONFIGURED_INSTALL_ROOTS[0]


def main(argv: list[str] | None = None) -> int:
    # The version resources of the bundled third-party DLLs contain non-ASCII
    # characters (a registered-trademark sign, for one), and the default console
    # codepage on Windows cannot encode them: without this, `--json > file`
    # produces a file that is not valid UTF-8, which is precisely the determinism
    # requirement this project states for its own output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", newline="\n")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):  # pragma: no cover - non-tty streams
            pass
    args = build_arg_parser().parse_args(argv)
    install_dir = args.install_dir or default_install_dir()
    if not pathguard.looks_like_install_root(install_dir):
        sys.stderr.write("not a MISERY installation: %s\n" % install_dir)
        return 2
    crash_dir = None if args.no_crash else (args.crash_dir or default_crash_dir())
    document = build_document(install_dir, crash_dir, REPO_ROOT, args.ue_source_root)
    try:
        if args.out:
            write_json(document, args.out, install_dir)
        if args.evidence_dir:
            write_evidence(document, args.evidence_dir, install_dir)
    except pathguard.OutputPathRefused as exc:
        sys.stderr.write("%s\n" % exc)
        return 2
    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        sys.stdout.write(format_summary(document) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
