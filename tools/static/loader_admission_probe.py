#!/usr/bin/env python3
"""Read-only probe: which package-admission path a shipped UE 5.4 build linked (SP-1).

The question this tool exists to answer
---------------------------------------
plan.md 14.7 SP-1 asks whether ``UClass`` registration depends on the provenance
of the container a package came from. The source-reading half of that question is
answered by reading UE 5.4.4 at CL 35576357 and is written up in
``research/packages/sp1-static-proxy.md``. This tool answers the *other* half,
the one that source cannot answer: **which of the two admission paths the shipped
image actually linked, and which one the shipped data actually selects at
startup.**

Those are two different measurements, and the tool keeps them apart:

``toc`` subcommand -- what the shipped DATA selects
    ``Engine/Source/Runtime/CoreUObject/Private/Serialization/AsyncPackageLoader.cpp``
    lines 202 and 212-215 select the package loader for a cooked build by asking
    one yes/no question: does the chunk ``CreateIoChunkId(0, 0, ScriptObjects)``
    exist in any mounted container? If yes, ``MakeAsyncPackageLoader2`` (the
    IoStore / Zen loader) is installed; if no, the legacy ``FAsyncLoadingThread``
    is. ``CreateIoChunkId`` (``Runtime/Core/Public/IO/IoChunkId.h`` line 136)
    makes that chunk id twelve determinate bytes, eleven zeros and a trailing
    ``0x05``, so the question reduces to a byte-string search in a container's
    chunk-id table. This subcommand reads that table.

``image`` subcommand -- what the shipped IMAGE linked
    A set of exact string literals, each cited to a source file and line, each
    with the expected outcome DECLARED IN THIS FILE before any measurement. Some
    of them are predicted present, some predicted absent, and the absent ones
    carry the weight: they are compiled out by a preprocessor condition
    (``ALT2_ENABLE_LINKERLOAD_SUPPORT``, ``UE_BUILD_SHIPPING``, ``DO_CHECK``)
    whose value in *this* build is what we are trying to learn. A probe whose
    prediction fails is reported as ``PREDICTION_FAILED`` and is a finding, not
    a bug to be tuned away.

Why the TOC read does not violate D-02
--------------------------------------
D-02 forbids extracting a container key and decrypting a container. Nothing here
decrypts anything. Container encryption in UE covers the *compressed blocks of
the .ucas payload*; the ``.utoc`` chunk-id table is written in the clear in every
configuration, and the tool additionally records ``container_flags`` so that a
reader can see for themselves whether the ``Encrypted`` bit (1 << 1, per
``Runtime/Core/Public/IO/IoDispatcher.h`` line 471) is even set on the container
being read. When it is set, the tool still reads only the TOC and says so; it
never touches the ``.ucas``.

What is class P here and what is class I
----------------------------------------
Per plan.md 10.3, a literal read at a determinate location that names nothing
about what the bytes are is class P, and for ``container-metadata`` and
``binary-analysis`` the claim sentence must state the offset AND the length. So
every measurement is emitted twice:

``literal_reads``
    ``offset``, ``length``, ``bytes_hex`` and a ``claim`` sentence naming only
    the offset and the length. No field name, no chunk type, no module name.

``findings``
    The interpretation: that those twelve bytes are the chunk id
    ``EIoChunkType::ScriptObjects`` produced by ``CreateIoChunkId(0, 0, ...)``,
    that its presence selects ``MakeAsyncPackageLoader2``, and so on. Class I,
    leaning on the UE source tree, hence oracle ``external-doc`` alongside
    ``container-metadata`` or ``binary-analysis``.

Safety properties (D-01, D-02, C-13)
------------------------------------
* every input file is opened ``"rb"`` and never written to;
* ``--out`` is routed through ``tools/inventory/pathguard.check_output_path``
  before anything is opened, so a path inside an installation costs nothing;
* the JSON document carries no absolute input path. It carries a ``target``
  token built by ``locus_target`` (installation-relative when the input is
  inside a known installation) plus sha256 and size, per C-13;
* standard library only, per the repository rule for ``tools/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time

_INVENTORY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "inventory")
if _INVENTORY not in sys.path:
    sys.path.insert(0, _INVENTORY)
import pathguard  # noqa: E402

_FINGERPRINT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fingerprint")
if _FINGERPRINT not in sys.path:
    sys.path.insert(0, _FINGERPRINT)
import pe_info  # noqa: E402


GENERATOR_VERSION = "loader_admission_probe/1.0.0"

# Engine source coordinates every interpretation in this file cites. Recorded in
# the document so a reader can re-walk the chain without re-deriving it.
ENGINE_BRANCH = "++UE5+Release-5.4"
ENGINE_CHANGELIST = 35576357

DEFAULT_BUFFER_BYTES = 1 << 20

TOC_MAGIC = b"-==--==--==--==-"

# FIoStoreTocHeader, Runtime/Core/Internal/IO/IoStore.h lines 38-75.
TOC_HEADER_FIELDS = (
    ("toc_header_size", 20, 4, "<I"),
    ("toc_entry_count", 24, 4, "<I"),
    ("toc_compressed_block_entry_count", 28, 4, "<I"),
    ("toc_compressed_block_entry_size", 32, 4, "<I"),
    ("compression_method_name_count", 36, 4, "<I"),
    ("compression_method_name_length", 40, 4, "<I"),
    ("compression_block_size", 44, 4, "<I"),
    ("directory_index_size", 48, 4, "<I"),
    ("partition_count", 52, 4, "<I"),
    ("container_id", 56, 8, "<Q"),
    ("container_flags", 80, 1, "<B"),
    ("toc_chunk_perfect_hash_seeds_count", 84, 4, "<I"),
    ("partition_size", 88, 8, "<Q"),
    ("toc_chunks_without_perfect_hash_count", 96, 4, "<I"),
)

# EIoContainerFlags, Runtime/Core/Public/IO/IoDispatcher.h lines 467-476.
CONTAINER_FLAG_BITS = (
    (1 << 0, "Compressed"),
    (1 << 1, "Encrypted"),
    (1 << 2, "Signed"),
    (1 << 3, "Indexed"),
    (1 << 4, "OnDemand"),
)

# EIoChunkType, Runtime/Core/Public/IO/IoChunkId.h lines 26-43.
CHUNK_TYPE_NAMES = {
    0: "Invalid", 1: "ExportBundleData", 2: "BulkData", 3: "OptionalBulkData",
    4: "MemoryMappedBulkData", 5: "ScriptObjects", 6: "ContainerHeader",
    7: "ExternalFile", 8: "ShaderCodeLibrary", 9: "ShaderCode",
    10: "PackageStoreEntry", 11: "DerivedData", 12: "EditorDerivedData",
    13: "PackageResource",
}

IO_CHUNK_ID_SIZE = 12
IO_OFFSET_AND_LENGTH_SIZE = 10

# CreateIoChunkId(0, 0, EIoChunkType::ScriptObjects), IoChunkId.h line 136:
# little-endian uint64 0 at [0..8), network-order uint16 0 at [8..10),
# byte 10 unused, byte 11 = the EIoChunkType discriminator.
SCRIPT_OBJECTS_CHUNK_ID = bytes(11) + bytes([5])


# --------------------------------------------------------------------------- #
# The declared predictions. Written before the first measurement, on purpose.
# --------------------------------------------------------------------------- #

# ``expect`` is one of "present", "absent", "unknown".
#
# The predictions marked "absent" are the load-bearing ones: each is compiled out
# by a preprocessor condition whose value in this build is the thing under test.
# A hit on one of them refutes the reading of the source that produced it.
#
# ``kind`` records HOW the literal reaches the image, and it is not decoration.
# The first version of this table probed only ``ue_log`` format strings and nine
# of its sixteen predictions failed at once. The cause was not the source
# reading: ``Runtime/Core/Public/Misc/Build.h`` line 306 sets
# ``NO_LOGGING = !USE_LOGGING_IN_SHIPPING`` in a Shipping build, ``Build.h`` line
# 192 defaults ``USE_LOGGING_IN_SHIPPING`` to 0, and under ``NO_LOGGING`` the
# ``UE_LOG`` macro (``Runtime/Core/Public/Logging/LogMacros.h`` lines 146-158)
# references ``Format`` only inside an ``if constexpr`` that is false for every
# verbosity except Fatal. So a Shipping image keeps no non-Fatal UE_LOG format
# string at all, and the whole class is blind for this question rather than
# negative. The ``ue_log`` rows are kept, with ``expect`` set to what a build
# that *does* log would show, precisely so that the blindness is visible in the
# artifact instead of being quietly deleted from it -- and so that the same
# table stays informative when it is run against an image that logs.
#
# ``literal`` rows are the ones that carry the verdict: a plain ``TEXT(...)``
# operand of Printf, FParse, FPaths or a switch arm, which survives every
# logging configuration. Several are deliberately paired -- one inside a
# preprocessor block under test and one immediately outside it in the same
# function -- so that "absent" can be told apart from "this file was not
# compiled in".
IMAGE_PROBES = (
    dict(id="pak-mount-success", kind="ue_log",
         text="Mounted Pak file '%s', mount point: '%s'",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8631",
         expect="present",
         why=("the tail of FPakPlatformFile::Mount. Present iff the legacy pak "
              "mount code was linked at all.")),
    dict(id="pak-mount-iostore-ok", kind="ue_log",
         text='Mounted IoStore container "%s"',
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8574",
         expect="present",
         why=("the sibling-.utoc branch of FPakPlatformFile::Mount, the only "
              "place a non-global container reaches FFilePackageStoreBackend.")),
    dict(id="pak-mount-iostore-missing", kind="ue_log",
         text='IoStore container "%s" not found',
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8604",
         expect="present",
         why=("the branch a bare .pak with no sibling .utoc takes; it sets "
              "bIoStoreSuccess = false while the pak still enters PakFiles.")),
    dict(id="pak-mount-deferred-key", kind="ue_log",
         text=('Deferring mount of pak "%s" until encryption key \'%s\' '
               "becomes available"),
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8532",
         expect="present",
         why="the EncryptionKeyGuid gate, the only key check inside Mount."),
    dict(id="pak-mount-point-warning", kind="ue_log",
         text=("assets in this pak file may not be accessible until a "
               "corresponding UFS Mount Point is added through "
               "FPackageName::RegisterMountPoint."),
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8663",
         expect="present",
         why=("the only mount-point-shaped admission remark in the pak path. "
              "It is a Display log, not a rejection; presence lets a reader "
              "check that for themselves.")),
    dict(id="iostore-imperfect-hash", kind="ue_log",
         text="Falling back to imperfect hashmap for container '%s'",
         source="Runtime/PakFile/Private/IoDispatcherFileBackend.cpp:727",
         expect="present",
         why="FFileIoStoreReader::Initialize, the per-container TOC intake."),
    dict(id="iostore-toc-signature-hash", kind="ue_log",
         text="Toc signature hash: %s",
         source="Runtime/PakFile/Private/IoDispatcherFileBackend.cpp:746",
         expect="present",
         why=("unconditional log in FFileIoStoreReader::Initialize; a control "
              "for the signature probes below, which are conditional.")),
    dict(id="filepackagestore-redirect", kind="ue_log",
         text="Redirecting from %s to 0x%llx",
         source="Runtime/PakFile/Private/FilePackageStore.cpp:364",
         expect="present",
         why=("FFilePackageStoreBackend::GetPackageRedirectInfo -- the package "
              "store backend that turns a container header into loadable "
              "package ids.")),
    dict(id="iostore-missing-signature", kind="literal",
         text="Missing signature",
         source="Runtime/Core/Private/IO/IoStore.cpp:3277",
         expect="unknown",
         why=("reachable only when IsSigningEnabled() can return true, and "
              "IsSigningEnabled (IoStore.cpp:61-68) is `return "
              "GetPakSigningKeysDelegate().IsBound()` under UE_BUILD_SHIPPING "
              "and a literal false otherwise. Declared unknown because MSVC is "
              "not obliged to drop an unreferenced literal, so a hit is weak "
              "evidence and a miss is strong.")),
    dict(id="alt2-linkerload-state", kind="literal",
         text="WaitingForLinkerLoadDependencies",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:2103",
         expect="absent",
         why=("inside #if ALT2_ENABLE_LINKERLOAD_SUPPORT, which is #defined to "
              "WITH_EDITOR at AsyncLoading2.cpp:263-264. A hit would mean this "
              "build kept the file-system fallback that lets AsyncLoading2 load "
              "a legacy .uasset with no package-store entry -- which would "
              "change the answer for a mod in a legacy pak.")),
    dict(id="alt2-linkerload-import", kind="ue_log",
         text=("Package %s might be missing an import from cooked package %s "
               "because it's exports are not yet ready."),
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:5693",
         expect="absent",
         why="second, independently placed string inside the same #if."),
    dict(id="do-check-scriptobject-verify", kind="ue_log",
         text=("Script object %s (0x%016llX) is missing a "
               "NotifyRegistrationEvent from the initial load phase."),
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:4940",
         expect="absent",
         why=("reached through `#elif DO_CHECK` in "
              "FGlobalImportStore::RegistrationComplete (4953-4966). DO_CHECK "
              "is 0 in a Shipping build, so a hit says this image is not "
              "Shipping -- a discriminator for D-04, measured here as a "
              "by-product rather than assumed.")),
    dict(id="cmdline-pakdir", kind="literal",
         text="-pakdir=",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8137",
         expect="absent",
         why=("inside #if !UE_BUILD_SHIPPING in FPakPlatformFile::GetPakFolders. "
              "If absent, the only pak directories this build ever scans are "
              "the three hardcoded ones, which bounds mod discovery.")),
    dict(id="cmdline-paklist", kind="literal",
         text="-paklist=",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8812",
         expect="absent",
         why="inside #if !UE_BUILD_SHIPPING in MountAllPakFiles."),
    dict(id="cmdline-startup-wildcard", kind="literal",
         text="StartupPaksWildcard=",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8237",
         expect="absent",
         why="inside #if !UE_BUILD_SHIPPING in FPakPlatformFile::Initialize."),
    dict(id="pakfolder-project-content", kind="literal",
         text="Paks/",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8147-8149",
         expect="present",
         why=("the three hardcoded pak folders are built with "
              'FString::Printf(TEXT("%sPaks/"), ...); the literal survives in '
              "any configuration.")),
    dict(id="registration-deferred-log", kind="ue_log",
         text="UObjectBase::DeferredRegister %s %s",
         source="Runtime/CoreUObject/Private/UObject/UObjectBase.cpp:195",
         expect="unknown",
         why=("the native-class registration step the source chain ends on. A "
              "Verbose UE_LOG, so its survival depends on the build's logging "
              "configuration and not on the code path being present; declared "
              "unknown so that neither outcome can be read as evidence about "
              "the path.")),
    dict(id="createexport-no-class", kind="ue_log",
         text="Could not find class object for %s",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:6614",
         expect="present",
         why=("inside FAsyncPackage2::EventDrivenCreateExport, the place where "
              "an export -- a UClass export included -- becomes a UObject on "
              "the IoStore path.")),

    # -- non-log literals: the rows that actually carry the verdict ---------- #

    dict(id="mount-patch-suffix", kind="literal",
         text="_P.pak",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8486",
         expect="present",
         why=("the operand of PakFilename.EndsWith inside "
              "FPakPlatformFile::Mount itself. Its presence is evidence that "
              "Mount was compiled into this image; it also names the ONLY "
              "filename-derived rule inside Mount, and that rule adjusts "
              "PakOrder, i.e. precedence, and nothing else.")),
    dict(id="mount-utoc-extension", kind="literal",
         text=".utoc",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8564",
         expect="present",
         why=("FPaths::ChangeExtension(InPakFilename, TEXT(\".utoc\")) inside "
              "Mount -- the sibling-container rule that decides whether a "
              "mounted pak contributes package-store entries at all.")),
    dict(id="global-utoc-path", kind="literal",
         text="%sPaks/global.utoc",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8243",
         expect="present",
         why=("the Printf format in FPakPlatformFile::Initialize whose "
              "FileExists result gates creation of the IoStore file backend "
              "and of FFilePackageStoreBackend.")),
    dict(id="iostore-ucas-extension", kind="literal",
         text=".ucas",
         source="Runtime/PakFile/Private/IoDispatcherFileBackend.cpp:704",
         expect="present",
         why="FFileIoStoreReader::Initialize builds the payload path from it."),
    dict(id="iostore-partition-suffix", kind="literal",
         text="_s%d",
         source="Runtime/PakFile/Private/IoDispatcherFileBackend.cpp:702",
         expect="present",
         why=("the partition suffix in the same function; a second, "
              "independently placed literal from that translation unit.")),
    dict(id="all-paks-wildcard", kind="literal",
         text="*.pak",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:81",
         expect="present",
         why=("ALL_PAKS_WILDCARD -- the pattern FindAllPakFiles matches, so "
              "the shape of automatic discovery: any *.pak in the scanned "
              "folders, with no name allowlist.")),
    dict(id="cmdline-nopak", kind="literal",
         text="NoPak",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8176",
         expect="present",
         why=("an FParse::Param literal in this file that is NOT inside "
              "#if !UE_BUILD_SHIPPING. Control for the three switches "
              "predicted absent: if this one is present and those are absent, "
              "the absences are the preprocessor and not a general stripping "
              "of FParse literals.")),
    dict(id="cmdline-skipoptional", kind="literal",
         text="SkipOptionalPakFiles",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8110",
         expect="present",
         why="second such control, in FindPakFilesInDirectory."),
    dict(id="cmdline-checkpak", kind="literal",
         text="checkpak",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:5981",
         expect="present",
         why=("third such control; also the switch that turns on "
              "CheckIoStoreContainerBlockSignatures at mount time.")),
    dict(id="cmdline-lookloosefirst", kind="literal",
         text="LookLooseFirst",
         source="Runtime/PakFile/Private/IPlatformFilePak.cpp:8240",
         expect="absent",
         why=("inside #if !UE_BUILD_SHIPPING in FPakPlatformFile::Initialize; "
              "fourth member of the shipping-gate group.")),
    dict(id="loaderstate-cooked", kind="literal",
         text="ProcessExportBundles",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:2107",
         expect="present",
         why=("a switch arm of LexToString(EAsyncPackageLoadingState2), "
              "compiled in every configuration. THE control for the two "
              "ALT2 arms below: same function, adjacent lines.")),
    dict(id="loaderstate-alt2-create", kind="literal",
         text="CreateLinkerLoadExports",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:2102",
         expect="absent",
         why=("an arm of the SAME switch, inside "
              "#if ALT2_ENABLE_LINKERLOAD_SUPPORT. Present-vs-absent against "
              "the control above is a controlled test of that macro in this "
              "image, and the macro decides whether AsyncLoading2 can load a "
              "package that has no package-store entry.")),
    dict(id="loaderstate-alt2-wait", kind="literal",
         text="WaitingForLinkerLoadDependencies",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:2103",
         expect="absent",
         why="a second arm inside the same #if."),
    dict(id="loaderstate-deferred", kind="literal",
         text="DeferredPostLoadDone",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:2112",
         expect="present",
         why=("a second unconditional arm, after the #if, so the control is "
              "not a single point.")),
    dict(id="toc-magic", kind="literal",
         text="-==--==--==--==-",
         source="Runtime/Core/Internal/IO/IoStore.h:40",
         expect="present",
         why=("FIoStoreTocHeader::TocMagicImg. A char[] and therefore ASCII, "
              "not UTF-16LE; it is the byte string CheckMagic compares against "
              "and it is present in every container this install ships.")),
    # Not an engine literal: the path the packaged-game bootstrap launches. It
    # is in this table because every other row is only as relevant as the answer
    # to "which of the two game binaries actually runs", and that answer is a
    # string in a third one.
    dict(id="bootstrap-target-shipping", kind="install-literal",
         text="MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe",
         source="not engine source: the packaged-game bootstrap's own target",
         expect="unknown",
         why=("expected present only in the small root-level launcher, absent "
              "in the two game binaries. Its presence there is what makes "
              "MISERY-Win64-Shipping.exe 'the shipped image' for this "
              "question.")),
    dict(id="bootstrap-self-name", kind="install-literal",
         text="BootstrapPackagedGame-Win64-Shipping.exe",
         source="not engine source: the bootstrap's own module name",
         expect="unknown",
         why="identifies the launcher as UE's BootstrapPackagedGame."),

    # A second, independent controlled test of ALT2_ENABLE_LINKERLOAD_SUPPORT.
    # The LexToString arms above are reached only from UE_LOG call sites, so in a
    # NO_LOGGING image the whole function goes unreferenced and every arm
    # disappears together -- controls included, which voids that test rather than
    # answering it. These six literals are runtime arguments to
    # FAsyncLoadingThreadState2::IsTimeLimitExceeded (AsyncLoading2.cpp:2388),
    # a real call in every configuration, three from inside the #if and three
    # from outside it.
    dict(id="timelimit-alt2-serialize", kind="literal",
         text="SerializeLinkerLoadExports",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:5652",
         expect="absent",
         why="argument of an IsTimeLimitExceeded call inside the ALT2 #if."),
    dict(id="timelimit-alt2-postload", kind="literal",
         text="ExecutePostLoadLinkerLoadPackageExports",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:5854",
         expect="absent",
         why="second such argument inside the ALT2 #if."),
    dict(id="timelimit-alt2-deferred", kind="literal",
         text="ExecuteDeferredPostLoadLinkerLoadPackageExports",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:5932",
         expect="absent",
         why="third such argument inside the ALT2 #if."),
    dict(id="timelimit-control-exportbundle", kind="literal",
         text="Event_ProcessExportBundle",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:6285",
         expect="present",
         why=("the matching control: same kind of call, same file, OUTSIDE the "
              "#if. If the controls are absent too, the test is void rather "
              "than negative, and must be reported that way.")),
    dict(id="timelimit-control-queue", kind="literal",
         text="CreateAsyncPackagesFromQueue",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:4514",
         expect="present",
         why="second control, in the function that resolves a package request."),
    dict(id="timelimit-control-loaded", kind="literal",
         text="ProcessLoadedPackagesFromGameThread",
         source="Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp:7746",
         expect="present",
         why="third control."),

    dict(id="script-package-root", kind="literal",
         text="/Script/CoreUObject",
         source="Runtime/CoreUObject/Private/UObject/UObjectBase.cpp:472",
         expect="present",
         why=("the package-name literal UObjectBase::Register compares against "
              "for per-module bootstrap. Native class registration takes its "
              "package name from literals like this one, in the image, and "
              "never from a container.")),
)


# --------------------------------------------------------------------------- #
# small helpers, same shapes as tools/static/rtti_scan.py
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)


def stream_sha256(path: str, buf_size: int = DEFAULT_BUFFER_BYTES) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(buf_size)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def locus_target(path: str, install_root: str | None = None) -> str:
    """A C-13-safe name for an input file: installation-relative when possible."""
    root = install_root or pe_info.detect_install_root(path)
    if root:
        try:
            rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
        except ValueError:
            rel = os.path.basename(path)
        if not rel.startswith(".."):
            return "<install>/" + rel.replace(os.sep, "/")
    return os.path.basename(path)


def literal_read(target: str, join_key: str, offset: int, raw: bytes,
                 oracle: str, method: str, artifact: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    The graded part is nested under ``evidence`` in the shape of
    ``research/schema/kb-record.schema.json#/$defs/annotation`` -- the reduced
    envelope for a sub-object of a larger artifact, which inherits
    ``recorded_at``, ``build_key`` and the 10.5 claim-type row from the enclosing
    document that states them once. Putting the grade at the top level of the
    sub-object instead makes ``tools/kb/validate.py`` read it as a full record
    and ask it for four fields the annotation schema forbids; that is the shape
    ``tools/static/rtti_scan.py`` already uses and the reason it uses it.

    ``claim`` states the offset AND the length, which plan.md 10.3 v2.4 makes
    mandatory before ``binary-analysis`` or ``container-metadata`` may be class P
    at all, and it stops there. ``join_key`` is a pointer into the interpretive
    layer, deliberately outside the graded object: naming the field inside the
    graded sentence is exactly the step that would derive class I.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "findings[] in the same document -- plan.md 10.3, the A-07 / A-07i "
            "split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": 0.99,
            "oracle": [oracle],
            "sources": [{
                "method": method,
                "artifact": artifact,
                "locator": "%s@%d+%d" % (target, offset, length),
                # Filled in by confirm_literal_reads once the second read has
                # actually happened. Never pre-filled: an attestation written
                # before the check is a claim about the author's intention.
                "note": ("oracle %s. Read by %s, read-only. "
                         "Reproduction: PENDING." % (oracle, GENERATOR_VERSION)),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
            },
            # The note IS the claim. validate.py derives the class of a reduced
            # annotation from this sentence, and 10.3 v2.4 admits these two
            # oracles into class P only when the sentence gives an address and an
            # extent and does not name what the bytes are.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def _toc_literal(target: str, join_key: str, offset: int, raw: bytes) -> dict:
    """literal_read with the container-metadata oracle bound in."""
    return literal_read(target, join_key, offset, raw,
                        oracle="container-metadata", method="SP-1")


def confirm_literal_reads(path: str, literals: list[dict],
                          warnings: list[str]) -> bool:
    """Re-read every recorded (offset, length) and compare.

    plan.md 10.3 makes "method re-run and result reproduced" a hard criterion for
    class P, and for a byte read it is cheap and it catches the two things that
    actually happen: a transient handle and an arithmetic slip in the offset. The
    attestation is written only after this pass runs, never before -- an
    attestation written in advance is a claim about the author's intention.
    """
    ok = True
    with open(path, "rb") as handle:
        for record in literals:
            handle.seek(record["offset"])
            again = handle.read(record["length"])
            same = hex_bytes(again) == record["bytes_hex"]
            record["reproduced"] = same
            if not same:
                ok = False
                warnings.append(
                    "second read at offset %d length %d disagrees with the first"
                    % (record["offset"], record["length"]))
    verdict = ("reproduced: the same bytes were read twice"
               if ok else "NOT reproduced: the two reads disagree")
    for record in literals:
        for source in record["evidence"]["sources"]:
            source["note"] = source["note"].replace(
                "Reproduction: PENDING.", "Reproduction: %s." % verdict)
    return ok


def decode_container_flags(value: int) -> tuple[list[str], int]:
    names = [name for bit, name in CONTAINER_FLAG_BITS if value & bit]
    known = 0
    for bit, _ in CONTAINER_FLAG_BITS:
        known |= bit
    return names, value & ~known


# --------------------------------------------------------------------------- #
# subcommand: toc
# --------------------------------------------------------------------------- #

def read_toc(path: str, install_root: str | None,
             max_listed: int) -> dict:
    """Read a .utoc header and its chunk-id table. Never opens the .ucas."""
    target = locus_target(path, install_root)
    size = os.path.getsize(path)
    literals: list[dict] = []
    warnings: list[str] = []

    with open(path, "rb") as handle:
        header = handle.read(144)
        if len(header) < 144:
            raise ValueError("file shorter than a TOC header: %d bytes" % len(header))
        if header[:16] != TOC_MAGIC:
            raise ValueError("no TOC magic at offset 0")
        literals.append(_toc_literal(target, "toc_magic", 0, header[:16]))

        values: dict[str, int] = {}
        for name, offset, length, fmt in TOC_HEADER_FIELDS:
            raw = header[offset:offset + length]
            values[name] = struct.unpack(fmt, raw)[0]
            literals.append(_toc_literal(target, name, offset, raw))
        version = header[16]
        literals.append(_toc_literal(target, "toc_version", 16, header[16:17]))

        flag_names, unknown_flag_bits = decode_container_flags(
            values["container_flags"])
        if unknown_flag_bits:
            warnings.append("container_flags carries bits outside "
                            "EIoContainerFlags: 0x%02x" % unknown_flag_bits)

        entry_count = values["toc_entry_count"]
        chunk_ids_offset = values["toc_header_size"]
        chunk_ids_length = entry_count * IO_CHUNK_ID_SIZE
        if chunk_ids_offset + chunk_ids_length > size:
            raise ValueError(
                "chunk-id table [%d, %d) does not fit in %d bytes"
                % (chunk_ids_offset, chunk_ids_offset + chunk_ids_length, size))

        handle.seek(chunk_ids_offset)
        table = handle.read(chunk_ids_length)

        offlen_offset = chunk_ids_offset + chunk_ids_length
        offlen_length = entry_count * IO_OFFSET_AND_LENGTH_SIZE
        offlen = b""
        if offlen_offset + offlen_length <= size:
            handle.seek(offlen_offset)
            offlen = handle.read(offlen_length)
        else:
            warnings.append("offset/length table does not fit; not read")

    chunks: list[dict] = []
    type_census: dict[str, int] = {}
    script_objects_index = None
    for index in range(entry_count):
        raw = table[index * IO_CHUNK_ID_SIZE:(index + 1) * IO_CHUNK_ID_SIZE]
        type_byte = raw[11]
        type_name = CHUNK_TYPE_NAMES.get(type_byte, "unknown(%d)" % type_byte)
        type_census[type_name] = type_census.get(type_name, 0) + 1
        if raw == SCRIPT_OBJECTS_CHUNK_ID and script_objects_index is None:
            script_objects_index = index
        if index < max_listed:
            record = {
                "index": index,
                "chunk_id_hex": hex_bytes(raw),
                "chunk_type_byte": type_byte,
                "chunk_type_name": type_name,
            }
            if offlen:
                pair = offlen[index * IO_OFFSET_AND_LENGTH_SIZE:
                              (index + 1) * IO_OFFSET_AND_LENGTH_SIZE]
                record["offset_and_length_hex"] = hex_bytes(pair)
                # FIoOffsetAndLength: 5-byte big-endian offset, then 5-byte
                # big-endian length (Runtime/Core/Public/IO/IoDispatcher.h).
                record["chunk_offset"] = int.from_bytes(pair[0:5], "big")
                record["chunk_length"] = int.from_bytes(pair[5:10], "big")
            chunks.append(record)

    # The class-P read that carries the whole verdict: the twelve bytes of the
    # chunk-id slot the ScriptObjects probe matched, with its own offset.
    if script_objects_index is not None:
        slot_offset = chunk_ids_offset + script_objects_index * IO_CHUNK_ID_SIZE
        literals.append(_toc_literal(
            target, "script_objects_chunk_id_slot", slot_offset,
            table[script_objects_index * IO_CHUNK_ID_SIZE:
                  (script_objects_index + 1) * IO_CHUNK_ID_SIZE]))

    reproduced = confirm_literal_reads(path, literals, warnings)

    finding = {
        "question": ("Does this container hold the chunk whose presence selects "
                     "MakeAsyncPackageLoader2 for a cooked build?"),
        "probe_bytes_hex": hex_bytes(SCRIPT_OBJECTS_CHUNK_ID),
        "probe_source": "Runtime/Core/Public/IO/IoChunkId.h:136 (CreateIoChunkId)",
        "selector_source": ("Runtime/CoreUObject/Private/Serialization/"
                            "AsyncPackageLoader.cpp:202,212-215"),
        "script_objects_chunk_present": script_objects_index is not None,
        "script_objects_chunk_index": script_objects_index,
        "evidence": {
            "evidence_level": "INFERRED",
            "claim_class": "I",
            # 0.79 and not higher ON PURPOSE. This tool performs ONE act of
            # measurement -- it reads one table in one file -- and plan.md 10.3
            # gives a class-I claim the 0.80 band only with two independent
            # methods. The second method for this question is the string
            # evidence from the image (the `image` subcommand) and it is a
            # different run on a different file, so it is the WRITE-UP in
            # research/packages/sp1-static-proxy.md that may combine them and
            # grade higher, citing both. Raising the number here would be the
            # exact defect plan.md 10.3 calls "уплощение градации при пересказе",
            # committed in advance.
            "confidence": 0.79,
            "oracle": ["container-metadata", "external-doc"],
            "sources": [{
                "method": "SP-1",
                "artifact": None,
                "locator": "chunk-id table of the container named in `target`",
                "note": ("oracle container-metadata. One method: the chunk-id "
                         "table was read and searched "
                         "for a twelve-byte pattern derived from IoChunkId.h."),
            }],
            "read_locus": None,
            "note": ("Class I: calling twelve bytes a chunk id of type "
                     "ScriptObjects, and naming the consequence for loader "
                     "selection, leans on the UE 5.4.4 source layout, which is "
                     "an external document about vanilla UE and not about this "
                     "build. The bytes alone are in literal_reads. What we "
                     "would see if this were wrong: the twelve-byte pattern "
                     "absent from every container in the install, or present "
                     "with a different trailing discriminator byte."),
        },
    }

    return {
        "subcommand": "toc",
        "generator_version": GENERATOR_VERSION,
        "generated_at": now_iso_utc(),
        "engine_branch": ENGINE_BRANCH,
        "engine_changelist": ENGINE_CHANGELIST,
        "target": target,
        "file_size": size,
        "file_sha256": stream_sha256(path),
        "toc_version": version,
        "header_values": values,
        "container_flags_hex": "0x%02x" % values["container_flags"],
        "container_flags_decoded": flag_names,
        "chunk_type_census": type_census,
        "chunks_listed": chunks,
        "chunks_listed_cap": max_listed,
        "literal_reads": literals,
        "literal_reads_reproduced": reproduced,
        "findings": [finding],
        "warnings": warnings,
        "decrypted_anything": False,
        "read_regions": [
            {"what": "toc header", "offset": 0, "length": 144},
            {"what": "chunk-id table", "offset": chunk_ids_offset,
             "length": chunk_ids_length},
            {"what": "offset/length table", "offset": offlen_offset,
             "length": len(offlen)},
        ],
    }


# --------------------------------------------------------------------------- #
# subcommand: image
# --------------------------------------------------------------------------- #

def encode_probe(text: str) -> dict[str, bytes]:
    """The two encodings a UE string literal can appear in on Windows."""
    return {
        "utf-16le": text.encode("utf-16-le"),
        "ascii": text.encode("ascii", errors="strict"),
    }


def find_all(image: bytes, needle: bytes, cap: int) -> tuple[int, list[int]]:
    hits: list[int] = []
    count = 0
    start = 0
    while True:
        found = image.find(needle, start)
        if found < 0:
            break
        count += 1
        if len(hits) < cap:
            hits.append(found)
        start = found + 1
    return count, hits


def offset_to_rva(headers, offset: int) -> int | None:
    """File offset -> RVA, or None when the byte lives outside any section body.

    A string constant in ``.rdata`` has an RVA; a byte in the PE header, in a
    debug directory or past the last section body does not, and this returns
    None rather than a plausible-looking wrong number -- the same rule
    ``pe_info.PEHeaders.rva_to_offset`` follows in the other direction.
    """
    for section in headers.sections:
        raw_start = section["raw_pointer"]
        raw_size = section["rsize"]
        if raw_size and raw_start <= offset < raw_start + raw_size:
            return section["rva"] + (offset - raw_start)
    return None


def probe_image(path: str, install_root: str | None, hit_cap: int) -> dict:
    target = locus_target(path, install_root)
    size = os.path.getsize(path)
    with pe_info.Image.open(path) as handle:
        headers = pe_info.PEHeaders(handle)
        machine = pe_info.MACHINE_NAMES.get(headers.machine, "unknown")
        section_count = len(headers.sections)

    with open(path, "rb") as handle:
        image = handle.read()

    literals: list[dict] = []
    results: list[dict] = []
    prediction_failures = 0
    predictions_checked = 0

    for probe in IMAGE_PROBES:
        encodings = encode_probe(probe["text"])
        per_encoding = {}
        total = 0
        first_offset = None
        for name, needle in encodings.items():
            count, hits = find_all(image, needle, hit_cap)
            total += count
            per_encoding[name] = {
                "needle_length": len(needle),
                "count": count,
                "offsets": hits,
                "rvas": [offset_to_rva(headers, off) for off in hits],
            }
            if hits and first_offset is None:
                first_offset = (name, hits[0], len(needle))

        observed = "present" if total else "absent"
        expected = probe["expect"]
        if expected == "unknown":
            verdict = "NO_PREDICTION"
        else:
            predictions_checked += 1
            if observed == expected:
                verdict = "PREDICTION_HELD"
            else:
                verdict = "PREDICTION_FAILED"
                prediction_failures += 1

        results.append({
            "id": probe["id"],
            "kind": probe["kind"],
            "text": probe["text"],
            "source": probe["source"],
            "why": probe["why"],
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "total_hits": total,
            "by_encoding": per_encoding,
        })

        if first_offset is not None:
            encoding_name, offset, length = first_offset
            literals.append(literal_read(
                target, "probe:%s:%s" % (probe["id"], encoding_name),
                offset, image[offset:offset + length],
                oracle="binary-analysis", method="SP-1"))

    warnings: list[str] = []
    reproduced = confirm_literal_reads(path, literals, warnings)

    by_kind: dict[str, dict[str, int]] = {}
    for probe in results:
        tally = by_kind.setdefault(
            probe["kind"], {"probes": 0, "present": 0, "absent": 0,
                            "prediction_failures": 0})
        tally["probes"] += 1
        tally[probe["observed"]] += 1
        if probe["verdict"] == "PREDICTION_FAILED":
            tally["prediction_failures"] += 1

    finding = {
        "question": ("Does this image contain the string literals that the "
                     "source chain for package admission and class "
                     "registration is built from, and does it contain the "
                     "literals that only a non-Shipping / editor "
                     "configuration would keep?"),
        "predictions_checked": predictions_checked,
        "prediction_failures": prediction_failures,
        "by_kind": by_kind,
        "evidence": {
            "evidence_level": "INFERRED",
            "claim_class": "I",
            # 0.79 for the same reason as the toc finding: one instrument, one
            # file. The controlled comparisons that make this evidence strong --
            # a literal from inside a preprocessor block against one from
            # outside it in the same function, and the same table run against a
            # second binary built from the same source -- span RUNS, so they are
            # combined and graded in the write-up, not here.
            "confidence": 0.79,
            "oracle": ["binary-analysis", "external-doc"],
            "sources": [{
                "method": "SP-1",
                "artifact": None,
                "locator": "whole-file search for each declared byte string",
                "note": ("oracle binary-analysis. One method: exact byte-string "
                         "search over the whole "
                         "image in two encodings, against a table of "
                         "predictions declared before the run."),
            }],
            "read_locus": None,
            "note": ("Class I: a string literal is evidence that a translation "
                     "unit containing it was compiled in, not proof that the "
                     "code around it is reachable, and its ABSENCE is evidence "
                     "only when a control literal of the same kind, from the "
                     "same file, is present. The literal_reads carry only "
                     "offsets, lengths and bytes. What we would see if the "
                     "preprocessor readings were wrong: a hit on one of the "
                     "rows predicted absent while its controls are present."),
        },
    }

    return {
        "subcommand": "image",
        "generator_version": GENERATOR_VERSION,
        "generated_at": now_iso_utc(),
        "engine_branch": ENGINE_BRANCH,
        "engine_changelist": ENGINE_CHANGELIST,
        "target": target,
        "file_size": size,
        "file_sha256": stream_sha256(path),
        "machine": machine,
        "section_count": section_count,
        "probes": results,
        "by_kind": by_kind,
        "literal_reads": literals,
        "literal_reads_reproduced": reproduced,
        "findings": [finding],
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# summaries
# --------------------------------------------------------------------------- #

def format_toc_summary(document: dict) -> str:
    lines = [
        "target                 %s" % document["target"],
        "size / sha256          %d / %s" % (document["file_size"],
                                            document["file_sha256"]),
        "toc version            %d" % document["toc_version"],
        "container_flags        %s %s" % (document["container_flags_hex"],
                                          document["container_flags_decoded"] or "[]"),
        "toc_entry_count        %d" % document["header_values"]["toc_entry_count"],
        "chunk type census      %s" % document["chunk_type_census"],
    ]
    finding = document["findings"][0]
    lines.append("ScriptObjects chunk    %s (index %s)"
                 % ("PRESENT" if finding["script_objects_chunk_present"]
                    else "ABSENT", finding["script_objects_chunk_index"]))
    for chunk in document["chunks_listed"]:
        lines.append("  [%d] %s type=%d %s off=%s len=%s"
                     % (chunk["index"], chunk["chunk_id_hex"],
                        chunk["chunk_type_byte"], chunk["chunk_type_name"],
                        chunk.get("chunk_offset"), chunk.get("chunk_length")))
    for warning in document["warnings"]:
        lines.append("warning: %s" % warning)
    return "\n".join(lines)


def format_image_summary(document: dict) -> str:
    lines = [
        "target                 %s" % document["target"],
        "size / sha256          %d / %s" % (document["file_size"],
                                            document["file_sha256"]),
        "",
        "%-32s %-8s %-9s %-9s %-18s %s" % ("probe", "kind", "expected",
                                           "observed", "verdict", "hits"),
    ]
    for probe in document["probes"]:
        lines.append("%-32s %-8s %-9s %-9s %-18s %d"
                     % (probe["id"], probe["kind"], probe["expected"],
                        probe["observed"], probe["verdict"],
                        probe["total_hits"]))
    finding = document["findings"][0]
    lines.append("")
    lines.append("predictions checked %d, failures %d"
                 % (finding["predictions_checked"],
                    finding["prediction_failures"]))
    return "\n".join(lines)


def write_text(text: str, out_path: str, install_root: str | None,
               what: str) -> str:
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loader_admission_probe.py",
        description=("Read-only probes for plan.md 14.7 SP-1: which package "
                     "admission path a shipped UE 5.4 build linked (`image`) "
                     "and which one its own data selects (`toc`). Refuses any "
                     "output path inside a game installation (D-01); never "
                     "decrypts anything (D-02)."))
    sub = parser.add_subparsers(dest="subcommand", required=True)

    toc = sub.add_parser("toc", help="read a .utoc header and chunk-id table")
    toc.add_argument("path", help="the .utoc to read (opened read-only)")
    toc.add_argument("--max-listed", type=int, default=64, metavar="N",
                     help="how many chunk-id slots to list (default: 64)")

    image = sub.add_parser("image", help="probe a PE image for declared literals")
    image.add_argument("path", help="the PE image to read (opened read-only)")
    image.add_argument("--hit-cap", type=int, default=8, metavar="N",
                       help="how many offsets to record per encoding")

    for target in (toc, image):
        target.add_argument("--json", action="store_true",
                            help="print the JSON document instead of a summary")
        target.add_argument("--out", default=None,
                            help="write the JSON document here")
        target.add_argument("--install-dir", default=None,
                            help="installation root the output guard checks against")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)
    if args.out is not None:
        try:
            pathguard.check_output_path(args.out, install_root, what="--out")
        except pathguard.OutputPathRefused as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2

    try:
        if args.subcommand == "toc":
            document = read_toc(args.path, install_root, args.max_listed)
            summary = format_toc_summary(document)
        else:
            document = probe_image(args.path, install_root, args.hit_cap)
            summary = format_image_summary(document)
    except (ValueError, OSError, struct.error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    text = dump_json(document)
    if args.out is not None:
        written = write_text(text + "\n", args.out, install_root, "--out")
        print("wrote %s" % written, file=sys.stderr)
    print(text if args.json else summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
