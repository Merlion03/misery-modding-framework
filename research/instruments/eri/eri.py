#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ERI -- External Read-Only Inspector, capabilities I-01 and I-02 (plan.md 8.2).

RESEARCH ONLY -- NOT PRODUCTION. This file lives in research/instruments/,
never in src/, and nothing in Phase 2 may be a refactor of it (plan.md 8.1:
"ни ERI, ни IPP не наследуются продуктом"). Disposability, "no API stability
whatsoever" and "fail loudly and immediately" are the NORM for this file, not
defects to be fixed -- see research/instruments/eri/README.md's own
"RESEARCH ONLY" section and its "Чему из этого кода нельзя подражать в
Phase 2" once filled in.

WHAT I-01 IS
------------
plan.md 8.2, capability I-01: "Найти процесс, получить базовый адрес и
размер образа Shipping-модуля" -- find the MISERY-Win64-Shipping.exe process,
and read the base load address and image size of its own module, as the
OS's module loader currently has it mapped. Every later ERI capability
(I-02..I-15) needs this as its foundation, because every one of them reads
memory relative to that base address.

WHAT I-02 IS
------------
plan.md 8.2, capability I-02: "Перечислить объекты через кандидатный
GUObjectArray" -- enumerate objects via the candidate GUObjectArray. This is
the first capability in this tool's life that actually reads target-process
MEMORY (I-01 only reads the OS's own module table via Toolhelp32), and the
first consumer of RF-05's static candidate (research/evidence/RF-05/README.md,
grade HYPOTHESIS, confidence 0.65). I-02 does not merely re-read the candidate
and assume it still holds because a static signature still matches
byte-for-byte (it does -- see research/builds/misery-24953925-ue5.4.4-bace50f7185d/
sigscan/RF-05-sigscan.json); it VERIFIES the candidate against LIVE structural
behaviour, because plan.md 564-566 places an absolute ceiling on any
static-analysis offset regardless of how well the pattern matches: a
runtime read is a categorically different, stronger kind of evidence, never
interchangeable with "the bytes on disk still look right". The exact three
checks implemented here are the three RF-05/README.md itself names in its own
"What a runtime observation would need to show to move this above HYPOTHESIS"
section -- see run_i02() below for the implementation of each, and
research/evidence/RF-05/README.md for the struct layout and chunk-addressing
arithmetic this is built from. A refuted candidate is a valid, REPORTABLE
research outcome, not a tool malfunction -- see the "STRUCTURAL REFUTATION IS
A RESULT, NOT AN ERROR" section below.

WHAT I-03 IS
------------
plan.md 8.2, capability I-03: "Разрешить FName в строку (обход FNamePool)"
-- resolve an FName (an FNameEntryId, a plain uint32) to its string text by
reading FNamePool's own internal block table directly, bypassing the
in-process C++ API entirely (this tool never calls a single game function --
see the "no game function is ever called" guarantee below, which I-03 does
not weaken in any way). This is the second consumer of a HYPOTHESIS-grade
static candidate (research/evidence/RF-06/README.md, confidence 0.60) and
the second capability that reads target-process memory, reusing I-02's own
ReadProcessMemory call site and rva_to_live_va() helper rather than adding
either a second one.

RF-06/README.md's own "What a runtime observation would need to show to move
this above HYPOTHESIS" section names three steps; I-03 implements the first
two (bNamePoolInitialized is nonzero; decoding FNameEntryId 0 produces the
literal text "None", the one case with a KNOWN expected answer, since
EName::None is guaranteed to be the first hardcoded name ever registered --
UnrealNames.cpp's own REGISTER_NAME loop, cited in RF-06/README.md). Failing
that decode is a real, reportable STRUCTURAL REFUTATION of the FNamePool
candidate, the bit-layout assumption, or both -- see "STRUCTURAL REFUTATION
IS A RESULT, NOT AN ERROR" below, which applies to I-03 exactly as it does
to I-02. RF-06's third step -- cross-checking against a live UObject found
via I-02 -- is implemented here as the "/Script/MISERY live reflection"
probe (sample_object_names()): a BOUNDED, honestly-reported (never claimed
exhaustive) search for the literal leaf FName "MISERY" among a sample of
live UObjects located via I-02's own chunk-walk arithmetic (factored into
_locate_object_pointer() for exactly this reuse).

The FNameEntryHeader bit layout (bIsWide:1 + LowercaseProbeHash:5 + Len:10,
packed LSB-first into one uint16) was read from Engine/Source/Runtime/Core/
Public/UObject/NameTypes.h for this exact build (WITH_CASE_PRESERVING_NAME=0,
confirmed independently by RF-06's own disassembly of the 256-shard
constructor loop), not merely assumed -- decode_fname_entry_id()'s own
docstring has the full citation. The UObjectBase field layout
DEFAULT_NAME_PRIVATE_OFFSET is built from was derived the same way, from
Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectBase.h's own member
declaration order, and cross-checked against RF-05's own independently-found
disassembly offset for InternalIndex (+0xc) -- see
DEFAULT_NAME_PRIVATE_OFFSET's own comment for the full derivation and why
that cross-check landing exactly on +0xc is meaningful, not coincidental.

WHAT I-04 IS
------------
plan.md 8.2, capability I-04: "Дамп UClass с иерархией наследования" -- the
first real UObject/UClass TRAVERSAL, not merely a bounded sample. Where I-03's
own "/Script/MISERY live reflection" probe (sample_object_names()) only ever
read one field (NamePrivate) of a bounded sample of objects, I-04 walks EVERY
object I-02's own GUObjectArray chunk-walk locates (bounded only by
--i04-max-scan-indices, a safety cap, never a statistical sample size) and
reads three UObjectBase fields per object -- ClassPrivate (+0x10),
NamePrivate (+0x18, I-03's own DEFAULT_NAME_PRIVATE_OFFSET, reused verbatim)
and OuterPrivate (+0x20, the ONE genuinely new offset this capability
introduces) -- to answer two questions per object: what is its canonical
object_path (built by walking the Outer chain, bounded and cycle-protected),
and IS this object itself a UClass instance.

The second question is answered without ever reading a single UClass/UStruct/
UField-specific field (ClassFlags, SuperStruct, ChildProperties, ...) --
deliberately out of scope for this pass, see this section's own "scope"
paragraph below. Instead it uses a genuine architectural fixed point of real
UE reflection: UClass::StaticClass()->ClassPrivate == itself (every UClass
"type descriptor" object's own Class is the native UClass type, literally
named "Class" in the FNamePool), so the ONE self-referential object in the
whole live UObject universe (ClassPrivate address == its own address) is
"Class", found and cross-checked against its own decoded name/object_path
(never merely trusted because it happens to be self-referential -- see
find_uclass_self_reference()'s own docstring) before anything is built on
top of it. From that single seed, class_address_universe grows from a SET
of principled ROOTS -- NEVER a general "anything whose ClassPrivate is
already a member of the growing universe joins" closure, which is a subtly
different and WRONG rule this capability deliberately does not implement
(see compute_class_identity()'s own docstring for exactly why: real UE
semantics mean an ORDINARY GAMEPLAY INSTANCE of any native class also has
its own ClassPrivate equal to that class's address, so a truly general
transitive closure would, after enough passes, also sweep in thousands of
plain object instances as "is a UClass" -- not a hypothetical, but what the
literal general rule would produce against a real ~26 000-object live
GUObjectArray). Round 1: every object whose ClassPrivate == the seed
("Class") -- this catches every native type descriptor, "ScriptStruct",
"Function", "Enum", "BlueprintGeneratedClass" itself, and every ordinary
native UClass (MiseryFocusSubsystem, MiseryBlueprintFunctionLibrary, ...),
because UClass, UScriptStruct, UFunction, UEnum and UBlueprintGeneratedClass
are ALL native C++ types whose own metaclass is UClass. Every round-1 member
whose OWN name ends with "GeneratedClass" (find_meta_type_roots(), a GENERAL
name-suffix test -- CORRECTED 2026-08-27 after a targeted review found the
original design's single hardcoded "BlueprintGeneratedClass"-only check
missed real native siblings like UWidgetBlueprintGeneratedClass and
UAnimBlueprintGeneratedClass) is promoted to an additional root; the plain
"BlueprintGeneratedClass" name is ALSO still separately found and
path-cross-checked (find_blueprint_generated_class_address()) as one
specific, reported data point. Round 2+ (bounded by
--i04-max-fixed-point-passes, converged/logged either way): every object
whose ClassPrivate is EXACTLY one of this FIXED root set -- never the whole
growing universe -- joins. This catches real Blueprint class ASSETS of
EVERY discovered meta-type (their own metaclass is one of the roots), while
correctly excluding an ordinary instance of, say, MiseryFocusSubsystem (its
own ClassPrivate is MiseryFocusSubsystem's address, which is never promoted
to a root, since "MiseryFocusSubsystem" does not end in "GeneratedClass")
and an ordinary UScriptStruct/UFunction/UEnum instance (e.g. the
struct-descriptor object for FVector; its own ClassPrivate is "ScriptStruct",
likewise never promoted). See compute_class_identity()'s own docstring for
the full worked trace this reasoning is pinned against, including the
FIRST, ALSO-WRONG attempted fix (a rootless "every distinct ClassPrivate
value" rule) that this project's own test suite caught before it was
trusted.

object_path is built for every classified UClass instance by walking the
Outer chain (bounded depth, cycle-protected -- see resolve_object_path()'s
own docstring), using this session's own confirmed fact (LOG-0051,
i03-fnamepool.json's misery_reflection.decoded_names) that a UPackage's own
NamePrivate already holds its FULL "/Script/<Module>" or "/Game/<...>" path,
never a bare leaf name.

SCOPE, DELIBERATELY (per the task this capability was specified from --
"не угадывай UObject layout" applies with full force to anything past
OuterPrivate): I-04 reads ONLY the three UObjectBase fields named above. It
never reads a byte of UObjectBaseUtility, UObject, UField, UStruct or UClass
storage -- no ClassFlags, no SuperStruct, no ChildProperties, no size, no
alignment. Every such field in the committed classes.jsonl rows this
capability writes is explicitly null, not guessed and not half-implemented
(build_i04_class_record()'s own docstring lists every one). I-04 also never
invokes ProcessEvent or any UFunction, sets no hook, and writes nothing to
the target process -- identical read-only guarantee to I-01/I-02/I-03, using
the SAME single ReadProcessMemory call site and the SAME single OpenProcess
call site; no new Win32 API, no new access right.

classes.jsonl (research/schema/reflection-record.schema.json's class_record
branch) is the committed artifact this capability produces: every classified
UClass instance under /Script/MISERY (the literal exit-criterion target),
plus a small BOUNDED sample of /Game/* Blueprint-generated classes (never an
exhaustive dump -- see build_i04_document()'s own docstring for the sample
cap and the honest full-count reporting alongside it), and explicitly NOT
the hundreds of native /Script/Engine, /Script/CoreUObject etc. classes this
same walk inevitably also finds (their total count is reported, never
persisted -- the "огромный полный semantic dump" the task this capability
was specified from explicitly says not to produce yet).

THE ARCHITECTURAL GUARANTEE THIS FILE EXISTS TO PROVE (plan.md 8.2)
---------------------------------------------------------------------
    "Ничего не пишет, ничего не инжектит, не ставит хуков, не вызывает
    функций игры" -- writes nothing, injects nothing, hooks nothing, calls
    no game function.

This is not a configuration choice this tool happens to make; it is the one
property that makes this tool legitimate read-only research tooling instead
of a cheat-engine-shaped hack. It has to be provable by a reviewer who does
NOT trust this file's comments, so it is provable from two small, greppable
facts rather than from prose:

  1. Every Win32 call this tool ever makes is one of exactly EIGHT functions,
     all read-only observation primitives: CreateToolhelp32Snapshot,
     Process32FirstW, Process32NextW, Module32FirstW, Module32NextW,
     OpenProcess, ReadProcessMemory and CloseHandle. None of them writes to,
     allocates in, protects, or executes anything in the target process. In
     particular: no WriteProcessMemory, no VirtualAllocEx/VirtualProtectEx,
     no CreateRemoteThread/NtCreateThreadEx, no SetWindowsHookEx -- grep this
     file for "kernel32\\." and that is the complete list, forever, for this
     pass. ReadProcessMemory (added for I-02, REUSED verbatim by I-03 -- see
     point 2) reads only; it neither needs nor is ever given any access
     right beyond the PROCESS_VM_READ the handle already carries.
  2. There is exactly ONE call site for OpenProcess in the whole tool (see
     ``Win32Api.open_process`` below), and the access-rights argument it
     passes is the single module-level constant ``PROCESS_ACCESS_RIGHTS``,
     defined once, a few lines below this docstring, as
     ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` and nothing else -- no
     ``PROCESS_ALL_ACCESS``, no ``PROCESS_VM_WRITE``, no
     ``PROCESS_VM_OPERATION``, no ``PROCESS_CREATE_THREAD``, no
     ``PROCESS_DUP_HANDLE``. This constant is UNCHANGED by I-02's or I-03's
     addition: ReadProcessMemory only ever needs PROCESS_VM_READ, which the
     handle already has, so neither capability opens a new kind of handle or
     requests a new right. There is likewise exactly ONE call site for
     ReadProcessMemory (``Win32Api.read_process_memory`` below), the single
     place this tool ever reads target-process memory -- I-03's own
     decode_fname_entry_id()/sample_object_names() call it through the same
     method, never a second wrapper. A reviewer who does not trust this
     docstring needs to read exactly two lines (one per call site) to audit
     both claims, and ``tests/test_eri_i01.py`` pins the "exactly one
     OpenProcess call site" fact and ``tests/test_eri_i02.py`` pins the
     equivalent "exactly one ReadProcessMemory call site" fact (still true
     with I-03 added -- ``tests/test_eri_i03.py`` does not re-pin it,
     because there is still only one file-wide count to pin and I-02's test
     already owns that assertion), so a future edit cannot silently add a
     second one of either.

CORRECTNESS/SAFETY RULE: EXACT MATCH, NEVER SUBSTRING (plan.md 8.5 "только
полностью контролируемых сессий")
---------------------------------------------------------------------------
Process and module name matching in this file is EXACT, case-insensitive
filename equality -- never ``in``, never ``startswith``, never a regex that
could match more than the literal name. This is not merely a correctness
nicety: a substring match (for example matching any process whose name
CONTAINS "MISERY-Win64-Shipping.exe") could silently attach this tool's
read-only handle to an unrelated process that merely has a similar or
longer name, which is both a wrong-result bug and a safety violation of the
"fully controlled session only" rule -- the tool would then be observing (or
a careless future edit could have it act on) a process nobody chose. See
``_names_equal`` below, the single place this comparison happens, and
``find_process_by_name``/``find_module_in_process``, its only two callers.

WHY ctypes, NOT A COMPILED LANGUAGE (plan.md 8.6 Q-8.1)
----------------------------------------------------------
plan.md 8.6 Q-8.1's own stated criterion: "минимальная стоимость до первого
дампа" (minimum cost to first dump). Python + ctypes calling the
Toolhelp32/OpenProcess Win32 API directly needs no new runtime dependency
(ctypes is standard library), is the same language as the rest of this
project's research tooling, and gets to a first working read-only dump
fastest. See the README's "Технология и почему выбрана" section for the
full answer; this paragraph exists so the choice is visible from the code
that embodies it too.

TESTABILITY WITHOUT A LIVE GAME PROCESS
-------------------------------------------
No MISERY process runs in CI or on a dev box without the game launched, so
every Win32 call in this file is reached through the ``Win32Api`` interface
below rather than called directly from the higher-level logic functions.
``tests/test_eri_i01.py`` substitutes a ``FakeWin32Api`` that returns
scripted process/module lists without touching the real Windows API -- the
same "duck-typed narrow interface, faked in tests" idiom
``pyghidra_scripts/dump_xrefs_for_string.py`` uses for the Ghidra API it
cannot start a JVM to exercise. The real ``Win32Api`` is what
``main()`` uses, and it is a thin, mechanical passthrough with no logic of
its own -- everything worth unit-testing lives in the plain-Python functions
below it, which take a Win32Api-shaped object as their first argument.

FAIL LOUDLY, NOT GRACEFULLY (plan.md 8.1)
---------------------------------------------
plan.md 8.1's own comparison table states the OPPOSITE error-handling rule
for ERI/IPP than for production code: "Обработка ошибок: падать громко и
сразу" for both instrument levels, versus "деградировать безопасно" for the
eventual MiseryRuntime product. Every failure mode here -- process not
found, module not found, OpenProcess refused, snapshot creation refused,
ReadProcessMemory refused or partial -- raises a specific exception with an
actionable message and propagates it; nothing here returns None-and-hope,
nothing retries silently, nothing falls back to a default. Do not "fix" this
into graceful degradation; that would be correct for product code and wrong
for this file.

STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR (I-02, I-03)
-------------------------------------------------------------
The rule above is about the TOOL malfunctioning -- a handle refused, a read
that could not be completed at all. It is deliberately NOT the rule for what
I-02 exists to determine: whether the RF-05 candidate's live structural
behaviour actually looks like a GUObjectArray. That question has an honest
"no" as one of its two possible answers, and "no" is exactly as valid and
exactly as worth recording as "yes" -- refuting a HYPOTHESIS is the whole
point of running this check, not a failure of the tool that ran it. So
run_i02() never raises for an implausible NumElements/MaxElements pair, a low
vtable-plausibility fraction, or a decreasing NumElements between polls; it
returns a plain dict with a boolean "pass" per check plus reasoning text, and
main() writes that dict to i02-guobjectarray.json exactly as it is, whichever
way the checks came out. What DOES raise (ReadProcessMemoryFailedError) is
the tool being unable to even attempt the read -- a hard Win32 failure or a
partial read from ReadProcessMemory itself -- because that is a genuine
malfunction, not a research finding, and conflating the two would make a
tool bug indistinguishable from a real refutation of RF-05's candidate.

The identical split applies to I-03: decode_fname_entry_id() decoding
FNameEntryId 0 to something other than "None" is a real, reportable
STRUCTURAL REFUTATION of the RF-06 candidate/bit-layout assumption -- it is
returned as data (decoded_as_expected: False, plus the raw bytes/length/
wide-flag actually observed, for a human to diagnose), never raised. The
"/Script/MISERY live reflection" probe's own not-found result
(misery_found: False) is likewise never treated as a refutation of
anything -- see sample_object_names()'s own docstring for why a miss in a
BOUNDED, non-exhaustive sample of the live UObject universe carries no such
implication. What DOES raise for I-03, identically to I-02, is
ReadProcessMemory itself failing on a foundational read this capability
cannot proceed without (bNamePoolInitialized, or any read inside the
decode arithmetic that is not itself the character-data decode).

Usage
-----
    python research/instruments/eri/eri.py \\
        --run-dir research/instrument-runs/2026-08-27T120000Z

See "Как запускать" in research/instruments/eri/README.md for the full
option reference.

IDENTITY IS SELF-ESTABLISHED, NEVER MERELY ASSERTED (LOG-0048/LOG-0049)
-------------------------------------------------------------------------
On 2026-08-27, an operator ran this tool with a --build-key copied from
earlier static-analysis work, without rechecking it, at the exact moment
Steam had silently updated MISERY as a side effect of launching it
(steam_buildid 24826585 -> 24953925). The supplied --build-key was WRONG for
the process actually being read, and this was only discovered afterward, by
hand, comparing a manually computed sha256 against appmanifest_2119830.acf's
buildid -- a real research-integrity mistake, found late, that had to be
corrected in already-written JSON artifacts.

The fix is structural, not a reminder to "be more careful": every run of
this tool computes the sha256 of MISERY-Win64-Shipping.exe ITSELF, streamed
from module.exe_path -- the exact file the OS loader mapped for the process
this run actually attached to -- and uses that as the authoritative
build_key (see establish_build_identity() below). --build-key is now an
OPTIONAL CROSS-CHECK, never the source of truth: if given, it is compared
against the self-computed hash and a mismatch raises BuildKeyMismatchError
loudly, before any output file is written, instead of silently producing a
document whose build_key lies about which build was actually read.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import json
import os
import re
import struct
import sys
import time
from ctypes import wintypes
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# import the shared output-path guard (plan.md decision D-01 / safety model
# 1.5 layer 1: no tool ever accepts a path inside the game installation as an
# output path). Imported, never reimplemented -- pathguard's own docstring is
# written about exactly the drift that copy-pasting this check invites.
# research/instruments/ is not itself a package (mirrors tools/), so this file
# bootstraps sys.path the same way pyghidra_scripts/_pyghidra_runner.py does
# to reach a sibling directory's module.
# --------------------------------------------------------------------------- #
_HERE = os.path.dirname(os.path.abspath(__file__))                 # research/instruments/eri
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))  # repo root
_TOOLS_INVENTORY = os.path.join(_REPO_ROOT, "tools", "inventory")
if _TOOLS_INVENTORY not in sys.path:
    sys.path.insert(0, _TOOLS_INVENTORY)

import pathguard  # noqa: E402

GENERATOR_NAME = "research/instruments/eri/eri.py"
GENERATOR_VERSION = "0.1.0"

CAPABILITY_ID = "I-01"
CAPABILITY_ID_I02 = "I-02"
CAPABILITY_ID_I03 = "I-03"
CAPABILITY_ID_I04 = "I-04"


# --------------------------------------------------------------------------- #
# small helpers (deliberately duplicated rather than imported across the
# research/instruments <-> tools/static boundary -- tools/static/protection_scan.py
# does the same for these two trivial functions rather than reaching into
# pyghidra_scripts, and this file is meant to be read and thrown away on its
# own, per the RESEARCH ONLY rule above)
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump_json(document: dict) -> str:
    """Deterministic serialization: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _repo_relative(path: str) -> str:
    """*path* relative to the repository root, '/'-separated.

    Used only for the manifest's own 'artifacts' list, which
    research/schema/instrument-run-manifest.schema.json documents as
    repository-relative paths -- never an absolute path, which would carry
    this machine's user profile (C-13). Normal usage (plan.md 8.5: "все
    дампы пишутся в research/ этого репозитория") always has the output
    under the repository, so the relative form is what gets written in
    practice.

    Falls back to the absolute, '/'-separated path if *path* is not
    reachable from the repository root via a relative path at all -- on
    Windows, os.path.relpath() RAISES ValueError for two paths on different
    drive letters (e.g. output on C: while the repository is on D:), rather
    than returning something usable. That case is not a policy violation
    this function's job to enforce (pathguard's own job above is narrower:
    it only refuses a path INSIDE the game installation, never enforces
    "must be under research/"), so this must degrade to a still-valid
    artifact path instead of raising and losing the manifest entirely --
    the I-01 document itself may already be written to disk by the time
    this runs (see main()'s ordering), so crashing here would leave an
    orphaned dump with no manifest to explain it.
    """
    resolved = os.path.abspath(path)
    try:
        relative = os.path.relpath(resolved, _REPO_ROOT)
    except ValueError:
        return resolved.replace(os.sep, "/")
    return relative.replace(os.sep, "/")


# --------------------------------------------------------------------------- #
# Win32 constants -- READ THIS BLOCK to audit the safety guarantee.
# --------------------------------------------------------------------------- #

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008

MAX_PATH = 260
MAX_MODULE_NAME32 = 255

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# THE single access-rights constant this tool ever passes to OpenProcess
# (Win32Api.open_process below is the ONE call site). Read-only query and
# read-only memory-read rights, nothing else: no PROCESS_VM_WRITE, no
# PROCESS_VM_OPERATION (required before a VirtualProtectEx/WriteProcessMemory
# would even be attempted), no PROCESS_CREATE_THREAD, no PROCESS_DUP_HANDLE,
# no PROCESS_ALL_ACCESS. This literal value (0x0410) is the auditable proof
# of plan.md 8.2's "ничего не пишет, ничего не инжектит" for the handle this
# tool holds on the game process.
PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ


# --------------------------------------------------------------------------- #
# ctypes structures -- the WIDE (W) Toolhelp32 layouts only. Mixing the ANSI
# and wide structs/functions is the classic bug this tool must not have: an
# ANSI PROCESSENTRY32 read through the wide Process32FirstW (or vice versa)
# has a different total size and different field widths, which either
# corrupts adjacent memory or silently reads garbage into szExeFile/szModule.
# Every struct, every function below is the W variant, with no ANSI sibling
# anywhere in this file.
# --------------------------------------------------------------------------- #

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),   # ULONG_PTR; value unused
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),         # BYTE*; the base address itself
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


# --------------------------------------------------------------------------- #
# plain-Python records the logic layer actually works with -- decoupled from
# ctypes so FakeWin32Api in the test suite never has to touch a real struct.
# --------------------------------------------------------------------------- #

ProcessEntry = collections.namedtuple("ProcessEntry", ["pid", "exe_file"])
ModuleEntry = collections.namedtuple(
    "ModuleEntry", ["module_name", "exe_path", "base_address", "size"])


# --------------------------------------------------------------------------- #
# exceptions -- every failure mode this tool recognizes raises one of these,
# with an actionable message, and none of them is ever swallowed (plan.md 8.1
# "падать громко и сразу").
# --------------------------------------------------------------------------- #

class EriError(Exception):
    """Base class for every error this tool raises on purpose."""


class SnapshotFailedError(EriError):
    """CreateToolhelp32Snapshot itself failed (not: the snapshot was empty)."""


class ProcessNotFoundError(EriError):
    """No running process has EXACTLY the requested executable filename."""


class TargetModuleNotFoundError(EriError):
    """The target process exists, but its module list has no exact match."""


class OpenProcessFailedError(EriError):
    """OpenProcess (with PROCESS_ACCESS_RIGHTS only) was refused by the OS."""


class ReadProcessMemoryFailedError(EriError):
    """ReadProcessMemory (I-02 onward) could not complete the requested read.

    Covers BOTH distinct failure modes ReadProcessMemory can produce, never
    conflating them: a hard Win32 failure (the BOOL return itself is false --
    typically the address is unmapped, or the process has since exited), and
    a PARTIAL read (the call succeeds, but *lpNumberOfBytesRead is less than
    the size requested -- for example because the requested range straddles
    an unmapped page). A partial read is not "close enough" data; treating
    fewer bytes than requested as if the full read had succeeded would silently
    feed truncated/garbage bytes into struct unpacking downstream, which is
    strictly worse than failing loudly here.

    This is a TOOL malfunction, not a research finding -- see the module
    docstring's "STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR" section for
    why this must never be confused with run_i02()'s own structural-invariant
    checks failing (an implausible NumElements, a low vtable-plausibility
    fraction, a decreasing NumElements): those are honest "no" answers to a
    research question and are returned as data, never raised as this
    exception.
    """


class BuildKeyMismatchError(EriError):
    """--build-key was given, but does not match the self-computed sha256 of
    module.exe_path -- the file the OS loader actually mapped for THIS live
    process.

    This is exactly the class of mistake LOG-0048/LOG-0049 recorded on
    2026-08-27: an operator supplied a --build-key copied from earlier
    static-analysis work, without rechecking it, at the exact moment Steam
    had silently updated the game as a side effect of launching it
    (steam_buildid 24826585 -> 24953925). The recorded build_key was wrong
    for the process actually being read, and the mistake was only caught
    afterward, by hand, and had to be corrected in already-written JSON
    artifacts. That is precisely the failure this exception exists to make
    impossible to miss: a cached/supplied build_key is never the source of
    truth (see establish_build_identity() and the module docstring's
    "IDENTITY IS SELF-ESTABLISHED" section), so a mismatch between what was
    supplied and what this run actually observed must fail loudly, before a
    single output file is written, rather than silently producing a document
    that misattributes this run's data to the wrong build. Do not "simplify"
    this check away or make it a warning -- a warning is exactly what got
    missed in LOG-0048.
    """


def _last_error_suffix(api: "Win32Api | object") -> str:
    """' (GetLastError=N)' when *api* can report one, else ''.

    Best-effort only: FakeWin32Api in tests need not implement
    get_last_error at all, and a real failure is fully actionable from the
    exception type and message alone even without the raw code.
    """
    getter = getattr(api, "get_last_error", None)
    if getter is None:
        return ""
    try:
        code = getter()
    except Exception:  # noqa: BLE001 - diagnostics must never mask the real error
        return ""
    return "" if not code else " (GetLastError=%d)" % code


# --------------------------------------------------------------------------- #
# Win32Api -- the ONLY place any kernel32 function is ever called from. Every
# method here is a mechanical 1:1 wrapper around exactly one Win32 call; no
# branching logic of consequence lives in this class, which is what makes
# "audit the OpenProcess call site" a one-line exercise instead of a
# whole-class one.
# --------------------------------------------------------------------------- #

_kernel32 = None  # lazily bound so importing this module never touches ctypes


def _kernel32_dll():
    """The bound kernel32 DLL with prototypes set, created on first use.

    Deferred past import time so that ``import eri`` (for --help, or for a
    test that only exercises the plain-Python logic functions against
    FakeWin32Api) never requires a Windows kernel32.dll to be loadable --
    useful on the rare occasion this module is merely imported for its
    constants/schema-shape from a non-Windows checker.
    """
    global _kernel32
    if _kernel32 is not None:
        return _kernel32

    dll = ctypes.WinDLL("kernel32", use_last_error=True)

    dll.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    dll.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    dll.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    dll.Process32FirstW.restype = wintypes.BOOL
    dll.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    dll.Process32NextW.restype = wintypes.BOOL

    dll.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    dll.Module32FirstW.restype = wintypes.BOOL
    dll.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    dll.Module32NextW.restype = wintypes.BOOL

    # THE one function whose access-rights argument matters for the whole
    # tool's safety story. argtypes pinned so ctypes never silently truncates
    # dwDesiredAccess on a 64-bit build.
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE

    # THE one function this tool uses to read target-process memory (I-02
    # onward). BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    # LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead). SIZE_T is
    # POINTER-WIDTH (8 bytes on x64), never a 32-bit int -- ctypes.c_size_t is
    # used for both the size argument and the out-parameter it points to,
    # specifically so this never silently truncates on a 64-bit build the way
    # a wrongly-picked c_uint32 would.
    dll.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    dll.ReadProcessMemory.restype = wintypes.BOOL

    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL

    _kernel32 = dll
    return dll


def _is_invalid_handle(value) -> bool:
    """True for every ctypes marshalling of INVALID_HANDLE_VALUE / NULL.

    A failed CreateToolhelp32Snapshot returns (HANDLE)-1
    (INVALID_HANDLE_VALUE); a failed OpenProcess returns NULL. ctypes'
    marshalling of a HANDLE return value can come back as ``None`` (NULL),
    as Python ``-1``, or -- depending on ctypes/platform internals -- as the
    unsigned 64-bit spelling of -1; all three are checked so the failure
    path never depends on which one this ctypes build happens to produce.
    """
    return value in (None, 0, -1, 0xFFFFFFFFFFFFFFFF)


class Win32Api:
    """Real Windows API access. See the module docstring for why every
    logic function below takes an object shaped like this one as a
    parameter instead of calling kernel32 directly: it is the seam
    ``tests/test_eri_i01.py`` substitutes to exercise this tool with no
    MISERY process running anywhere.
    """

    def create_toolhelp32_snapshot(self, flags: int, pid: int) -> int:
        return _kernel32_dll().CreateToolhelp32Snapshot(flags, pid)

    def process32_first(self, snapshot: int) -> ProcessEntry | None:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32_dll().Process32FirstW(snapshot, ctypes.byref(entry)):
            return None
        return ProcessEntry(pid=int(entry.th32ProcessID), exe_file=str(entry.szExeFile))

    def process32_next(self, snapshot: int) -> ProcessEntry | None:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32_dll().Process32NextW(snapshot, ctypes.byref(entry)):
            return None
        return ProcessEntry(pid=int(entry.th32ProcessID), exe_file=str(entry.szExeFile))

    def module32_first(self, snapshot: int) -> ModuleEntry | None:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not _kernel32_dll().Module32FirstW(snapshot, ctypes.byref(entry)):
            return None
        return ModuleEntry(
            module_name=str(entry.szModule), exe_path=str(entry.szExePath),
            base_address=int(entry.modBaseAddr or 0), size=int(entry.modBaseSize))

    def module32_next(self, snapshot: int) -> ModuleEntry | None:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not _kernel32_dll().Module32NextW(snapshot, ctypes.byref(entry)):
            return None
        return ModuleEntry(
            module_name=str(entry.szModule), exe_path=str(entry.szExePath),
            base_address=int(entry.modBaseAddr or 0), size=int(entry.modBaseSize))

    def open_process(self, pid: int) -> int:
        """THE ONLY OpenProcess call site in this entire tool.

        The access mask is the module-level constant PROCESS_ACCESS_RIGHTS
        (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) and nothing else --
        never a parameter, never computed, never widened by a caller. A
        reviewer auditing plan.md 8.2's "read-only, no write/inject" claim
        needs to read this one method and nowhere else in the file.
        """
        return _kernel32_dll().OpenProcess(PROCESS_ACCESS_RIGHTS, False, pid)

    def read_process_memory(self, handle: int, address: int, size: int) -> bytes:
        """THE ONLY ReadProcessMemory call site in this entire tool (I-02
        onward) -- the one place this tool ever reads target-process memory.
        Uses the SAME already-open, already-audited handle
        open_process_read_only() establishes via the one OpenProcess call
        site above; PROCESS_ACCESS_RIGHTS is unchanged by this method's
        existence, because ReadProcessMemory only ever needs the
        PROCESS_VM_READ bit that handle already carries -- no
        PROCESS_VM_WRITE, no PROCESS_VM_OPERATION, no widened mask of any
        kind is requested anywhere for this call to work.

        Raises ReadProcessMemoryFailedError, distinguishing the two failure
        modes the real Win32 call can produce, both handled explicitly:

        * a hard failure -- the BOOL return itself is false (address
          unmapped, process exited, access denied);
        * a PARTIAL read -- the call returns true, but
          *lpNumberOfBytesRead is less than *size* (for example, the
          requested range straddles the end of a mapped page). This is
          checked explicitly and separately from the BOOL return: a partial
          read must never be treated as if the full read had succeeded,
          because the caller would otherwise silently struct-unpack
          truncated or uninitialised bytes as if they were real data.

        Returns exactly *size* bytes on success, never fewer, never a
        larger buffer's unsliced backing memory.
        """
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = _kernel32_dll().ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, ctypes.c_size_t(size),
            ctypes.byref(bytes_read))
        if not ok:
            raise ReadProcessMemoryFailedError(
                "ReadProcessMemory(address=0x%x, size=%d) failed%s" %
                (address, size, _last_error_suffix(self)))
        if bytes_read.value != size:
            raise ReadProcessMemoryFailedError(
                "ReadProcessMemory(address=0x%x, size=%d) returned a PARTIAL "
                "read: only %d of %d requested bytes were actually read%s -- "
                "a distinct failure mode from a hard Win32 failure, and never "
                "silently treated as if the full read had succeeded." %
                (address, size, bytes_read.value, size, _last_error_suffix(self)))
        return buffer.raw[:size]

    def close_handle(self, handle: int) -> bool:
        return bool(_kernel32_dll().CloseHandle(handle))

    def get_last_error(self) -> int:
        return ctypes.get_last_error()


# --------------------------------------------------------------------------- #
# core logic -- takes an api object (Win32Api or a FakeWin32Api in tests),
# never touches kernel32/ctypes directly. Handles are closed on every path,
# including every error path, via try/finally.
# --------------------------------------------------------------------------- #

def _names_equal(a: str, b: str) -> bool:
    """EXACT, case-insensitive filename equality. NEVER substring.

    The one comparison predicate used by both find_process_by_name and
    find_module_in_process. A process or module named
    'NotMISERY-Win64-Shipping.exe' or 'MISERY-Win64-Shipping.exe.bak' must
    NOT match a request for 'MISERY-Win64-Shipping.exe' -- see the module
    docstring's "CORRECTNESS/SAFETY RULE" section for why a substring match
    here would be a safety bug, not merely an inconvenience.
    """
    return a.casefold() == b.casefold()


def find_process_by_name(api, process_name: str) -> ProcessEntry:
    """The one running process whose executable filename EXACTLY (case-
    insensitively) equals *process_name*. Raises ProcessNotFoundError if
    none does; raises SnapshotFailedError if the snapshot itself could not
    be created. The snapshot handle is always closed, on every path.
    """
    snapshot = api.create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0)
    if _is_invalid_handle(snapshot):
        raise SnapshotFailedError(
            "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed%s -- cannot "
            "enumerate running processes at all." % _last_error_suffix(api))
    try:
        entry = api.process32_first(snapshot)
        while entry is not None:
            if _names_equal(entry.exe_file, process_name):
                return entry
            entry = api.process32_next(snapshot)
    finally:
        api.close_handle(snapshot)
    raise ProcessNotFoundError(
        "no running process has the exact executable filename %r (matching is "
        "exact and case-insensitive, never substring -- see the module "
        "docstring). Is the game actually running, and is --process-name "
        "spelled exactly as Windows reports it?" % process_name)


def find_module_in_process(api, pid: int, module_name: str) -> ModuleEntry:
    """The one module of process *pid* whose szModule (or szExePath's own
    basename) EXACTLY equals *module_name*. Raises TargetModuleNotFoundError
    if none does; raises SnapshotFailedError if the module snapshot itself
    could not be created (for example because the process already exited
    between find_process_by_name and this call). The snapshot handle is
    always closed, on every path.
    """
    snapshot = api.create_toolhelp32_snapshot(TH32CS_SNAPMODULE, pid)
    if _is_invalid_handle(snapshot):
        raise SnapshotFailedError(
            "CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid=%d) failed%s -- "
            "the process may have exited, or access was denied." %
            (pid, _last_error_suffix(api)))
    try:
        entry = api.module32_first(snapshot)
        while entry is not None:
            exe_path_basename = os.path.basename(entry.exe_path) if entry.exe_path else ""
            if _names_equal(entry.module_name, module_name) or \
                    _names_equal(exe_path_basename, module_name):
                return entry
            entry = api.module32_next(snapshot)
    finally:
        api.close_handle(snapshot)
    raise TargetModuleNotFoundError(
        "process pid=%d has no module named exactly %r (checked szModule and "
        "the basename of szExePath, both exact case-insensitive match only)." %
        (pid, module_name))


def open_process_read_only(api, pid: int) -> int:
    """OpenProcess(PROCESS_ACCESS_RIGHTS, ..., pid) via the tool's one call
    site (Win32Api.open_process). Raises OpenProcessFailedError, with the
    exact access mask requested in the message, if refused.
    """
    handle = api.open_process(pid)
    if _is_invalid_handle(handle):
        raise OpenProcessFailedError(
            "OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 0x%04x, "
            "pid=%d) was refused%s. This tool never requests more than these "
            "two read-only rights, so a refusal here is either 'the process "
            "already exited' or a genuine access-denied (run as the same user "
            "that owns the game process; do not run elevated to force this -- "
            "that changes what this run can honestly claim about itself)." %
            (PROCESS_ACCESS_RIGHTS, pid, _last_error_suffix(api)))
    return handle


def run_i01(api, process_name: str) -> dict:
    """The whole of capability I-01: find the process, open it read-only
    (proving the access actually holds, per plan.md 8.2's requirement that
    the handle itself carry no write/inject rights), enumerate its modules,
    and return the base address + image size of *process_name*'s own
    module. Every handle opened here is closed before this function returns
    or raises, on every path.

    Returns a plain dict: {"pid", "process_name", "base_address",
    "image_size_bytes", "exe_path"}. "exe_path" is MODULEENTRY32W's own
    szExePath -- the exact file path the OS loader mapped for this live
    process, straight from Module32FirstW/Module32NextW, never a path
    supplied on the command line or cached from a previous run. It exists in
    this dict specifically so a caller (main() below, and any later
    capability that needs to establish or re-confirm build identity) can
    feed it to establish_build_identity() without re-deriving it -- see that
    function's docstring for why self-establishing identity from THIS field,
    every run, is not optional (LOG-0048/LOG-0049). Raises one of the
    EriError subclasses above on any failure -- never returns None, never
    degrades.
    """
    process = find_process_by_name(api, process_name)
    process_handle = open_process_read_only(api, process.pid)
    try:
        module = find_module_in_process(api, process.pid, process_name)
    finally:
        api.close_handle(process_handle)
    return {
        "pid": process.pid,
        "process_name": process.exe_file,
        "base_address": module.base_address,
        "image_size_bytes": module.size,
        "exe_path": module.exe_path,
    }


# --------------------------------------------------------------------------- #
# I-02: enumerate objects via the candidate GUObjectArray (plan.md 8.2), and
# VERIFY it via live structural behaviour rather than merely re-reading it
# and trusting the static signature match -- see the module docstring's
# "WHAT I-02 IS" section and research/evidence/RF-05/README.md for the full
# reasoning and the struct layout this is built from.
# --------------------------------------------------------------------------- #

def rva_to_live_va(base_address: int, rva: int) -> int:
    """live_base_address + RVA -- THE one place this arithmetic happens.

    Every static-analysis candidate (RF-05, RF-06, RF-07, PE-01, ...) is
    recorded as an RVA (offset from the PE's declared ImageBase), NEVER as a
    live virtual address, because ASLR is active for this image at runtime
    even though S-06 separately found zero relocation entries inside
    executable sections (explained by heavy RIP-relative addressing needing
    no relocation fixups -- "no .reloc entries in .text" is NOT the same
    fact as "no ASLR", and the two must never be conflated). Confirmed
    directly this session: this build's live process is NOT loaded at its
    declared PE ImageBase (0x140000000) -- see run_i01()'s own base_address
    read, which came back a different value entirely.

    The live VA of any such candidate is therefore ALWAYS
    live_base_address (THIS session's own I-01 read, never cached from a
    previous session or a different process launch) + RVA (a fixed,
    build-specific constant: RVA = static_candidate_VA - declared_ImageBase).
    Every future ERI capability (I-03 onward) that needs to turn a
    static-analysis candidate into a live address should call this function
    rather than reimplementing the addition slightly differently each time.
    """
    return base_address + rva


# GUObjectArray candidate: research/evidence/RF-05/README.md, static VA
# 0x147a78ed0 against declared PE ImageBase 0x140000000 -> RVA 0x07a78ed0.
# HYPOTHESIS, class I, oracle binary-analysis, confidence 0.65 (RF-05's own
# grade) -- this is exactly the candidate I-02 exists to check against live
# structural behaviour, not to assume still holds because the RVA is
# unchanged. research/builds/misery-24953925-ue5.4.4-bace50f7185d/sigscan/
# RF-05-sigscan.json separately confirms all 5 RF-05 signatures still match
# this new build's exe, unique, at their original RVAs -- good STATIC reason
# to expect this candidate still holds, but plan.md 564-566's ceiling on a
# static-analysis offset applies regardless, which is the entire reason this
# capability exists.
DEFAULT_GUOBJECTARRAY_RVA = 0x07A78ED0

# FUObjectArray struct offsets, all relative to the GUObjectArray candidate's
# own base address (research/evidence/RF-05/README.md's struct-layout table,
# itself read from Engine/Source/Runtime/CoreUObject/Public/UObject/
# UObjectArray.h, UE 5.4.4 CL 35576357). Only the fields I-02 actually reads
# are named here; the ones RF-05 read but I-02 does not need
# (ObjFirstGCIndex, OpenForDisregardForGC, PreAllocatedObjects, MaxChunks)
# are intentionally omitted rather than defined-and-unused.
GUOBJECTARRAY_OFFSET_OBJECTS = 0x10          # FUObjectItem** Objects
GUOBJECTARRAY_OFFSET_MAX_ELEMENTS = 0x20     # int32 MaxElements
GUOBJECTARRAY_OFFSET_NUM_ELEMENTS = 0x24     # int32 NumElements

# FChunkedFixedUObjectArray::GetObjectPtr addressing (RF-05/README.md,
# UObjectArray.h:638-654): NumElementsPerChunk is a compile-time constant
# 64*1024 = 2^16, hence a shift-by-16/mask-0xFFFF, not a division.
NUM_ELEMENTS_PER_CHUNK = 1 << 16

# sizeof(FUObjectItem) = 20 bytes of fields, padded to 24 for pointer
# alignment (RF-05/README.md) -- the per-element stride the chunk walk uses.
SIZEOF_FUOBJECTITEM = 0x18
FUOBJECTITEM_OFFSET_OBJECT = 0x00            # UObjectBase* Object, first field

# Check 1 (NumElements/MaxElements plausibility) ceiling -- see
# evaluate_struct_invariants()'s own docstring for the reasoning.
MAX_PLAUSIBLE_MAX_ELEMENTS = 100_000_000

# Check 2 (vtable-plausibility sample) pass threshold and defaults -- see
# sample_walk_objects()'s own docstring for the reasoning behind the number.
SAMPLE_PASS_FRACTION_THRESHOLD = 0.80
DEFAULT_I02_SAMPLE_SIZE = 32
DEFAULT_I02_MAX_SCAN_INDICES = 200_000

# Check 3 (growth) default poll interval, seconds.
DEFAULT_I02_POLL_INTERVAL_SECONDS = 2.0


def _read_i32(api, handle: int, address: int) -> int:
    """Signed little-endian int32 at *address*. ObjLastNonGCIndex/
    MaxObjectsNotConsideredByGC/MaxElements/NumElements are all declared
    `int32` in source (RF-05/README.md), so this reads SIGNED, not unsigned:
    a genuinely negative NumElements/MaxElements is possible corrupted or
    implausible data, and evaluate_struct_invariants() below must be able to
    see that it is negative, rather than have it silently wrap to a huge
    unsigned value first.
    """
    return struct.unpack("<i", api.read_process_memory(handle, address, 4))[0]


def _read_u64(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint64 at *address*. Every pointer-sized field
    this capability reads (Objects, a chunk pointer, FUObjectItem::Object, a
    UObject's own vtable pointer) is a 64-bit address on this x64 target,
    never signed.
    """
    return struct.unpack("<Q", api.read_process_memory(handle, address, 8))[0]


def _read_u16(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint16 at *address* -- I-03's own
    FNameEntryHeader read (decode_fname_entry_id()), the ONE 16-bit field
    this tool ever reads. Unsigned because FNameEntryHeader's three bitfields
    (bIsWide/LowercaseProbeHash/Len) are packed into a plain `uint16` in
    source (NameTypes.h), never a signed integer.
    """
    return struct.unpack("<H", api.read_process_memory(handle, address, 2))[0]


def _read_u32(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint32 at *address* -- I-03's own FNameEntryId
    read (FName::ComparisonIndex, NamePrivate's first 4 bytes on a live
    UObject; the sample_object_names() reflection probe reads this). Unsigned
    because FNameEntryId::Value is declared `uint32` in source (NameTypes.h),
    and a raw FNameEntryId is never negative/signed.
    """
    return struct.unpack("<I", api.read_process_memory(handle, address, 4))[0]


def evaluate_struct_invariants(num_elements: int, max_elements: int) -> dict:
    """Check (1) of RF-05/README.md's "What a runtime observation would need
    to show to move this above HYPOTHESIS": NumElements/MaxElements must be
    PLAUSIBLE, not merely readable. Never raises -- an implausible reading
    is a STRUCTURAL REFUTATION of the candidate, a valid research outcome,
    not a tool error (see the module docstring's "STRUCTURAL REFUTATION IS A
    RESULT, NOT AN ERROR" section).

    Three conditions, ALL required to PASS:
      * 0 < NumElements -- a genuine, populated object registry has objects
        in it; RF-05/README.md's own expectation is thousands to low
        millions for a running UE process, but even the loosest reading
        requires at least one live object.
      * NumElements <= MaxElements -- MaxElements is the allocated capacity
        (AllocateObjectPool computes it from MaxChunks*NumElementsPerChunk);
        a live count exceeding its own declared capacity is structurally
        impossible for the real struct, and is strong evidence this address
        is not it.
      * MaxElements < MAX_PLAUSIBLE_MAX_ELEMENTS (100,000,000) -- an
        allocated-capacity field reading in the hundreds of millions or
        billions is not "a UE object array that hasn't filled up yet", it is
        noise (wrong address, or a read that landed on unrelated memory).
        100,000,000 is chosen as a ceiling far above any plausible UE
        MaxObjectsInGame/MaxObjectsInEditor cvar value (typically low
        millions at the very most) while still being generous enough that no
        legitimate build could trip it by simply having a large project.
    """
    reasons = []
    if not (num_elements > 0):
        reasons.append("NumElements (%d) is not > 0" % num_elements)
    if not (num_elements <= max_elements):
        reasons.append(
            "NumElements (%d) exceeds MaxElements (%d)" % (num_elements, max_elements))
    if not (max_elements < MAX_PLAUSIBLE_MAX_ELEMENTS):
        reasons.append(
            "MaxElements (%d) exceeds the plausibility ceiling (%d)" %
            (max_elements, MAX_PLAUSIBLE_MAX_ELEMENTS))
    passed = not reasons
    return {
        "num_elements": num_elements,
        "max_elements": max_elements,
        "pass": passed,
        "reason": None if passed else "; ".join(reasons),
    }


def _vtable_pointer_in_module_range(pointer: int, base_address: int, image_size_bytes: int) -> bool:
    """True iff *pointer* falls inside [base_address, base_address+image_size_bytes)
    -- a plausible vtable pointer lives in the SAME module's .rdata/.text,
    never in the heap or a different module. This is the SAME check
    sample_walk_objects() below already used inline for a sampled UObject's
    own vtable pointer; factored out here (I-04) so that capability's own
    structural-validation check (3) -- "the first 8 bytes at ClassPrivate's
    own address look like a vtable pointer" -- reuses the IDENTICAL formula
    rather than re-deriving it a second time, per the "reuse I-02's own
    vtable-pointer check" instruction this capability was specified from.
    sample_walk_objects() itself was updated to call this too, so there is
    exactly one place this comparison is expressed in the whole file.
    """
    return base_address <= pointer < base_address + image_size_bytes


def _locate_object_pointer(api, handle: int, objects_ptr: int, index: int) -> int | None:
    """FChunkedFixedUObjectArray::GetObjectPtr's own shift-16/mask-0xFFFF/
    stride-24 addressing (RF-05/README.md), factored out of I-02's own
    sample_walk_objects so I-03's own "/Script/MISERY live reflection" probe
    (sample_object_names() below) can reuse the IDENTICAL chunk-walk
    arithmetic rather than re-deriving it a second time -- see the module
    docstring's "WHAT I-03 IS" section. sample_walk_objects itself was
    rewritten to call this too, so there is exactly one place this
    arithmetic is expressed in the whole file, not two that could silently
    drift apart.

    Returns FUObjectItem[*index*].Object -- the object pointer -- or None if
    either the chunk itself was never allocated (Blocks[chunk_index] == 0)
    or the slot itself is a freed/never-allocated null. Lets
    ReadProcessMemoryFailedError propagate from EITHER of its two reads (the
    chunk pointer, the slot's Object field) unchanged -- callers that want
    "unreadable is like null, not a tool error" (both sample_walk_objects and
    sample_object_names) catch it themselves at the call site; a caller that
    instead wants a foundational-read failure to abort outright simply does
    not catch it.
    """
    chunk_index = index >> 16
    within_chunk_index = index & 0xFFFF
    chunk_base = _read_u64(api, handle, objects_ptr + chunk_index * 8)
    if chunk_base == 0:
        return None
    item_addr = chunk_base + within_chunk_index * SIZEOF_FUOBJECTITEM
    object_ptr = _read_u64(api, handle, item_addr + FUOBJECTITEM_OFFSET_OBJECT)
    return object_ptr if object_ptr != 0 else None


def sample_walk_objects(api, handle: int, objects_ptr: int, num_elements: int,
                        base_address: int, image_size_bytes: int,
                        sample_size: int = DEFAULT_I02_SAMPLE_SIZE,
                        max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES) -> dict:
    """Check (2) of RF-05/README.md's list: walk a BOUNDED sample of live
    indices using FChunkedFixedUObjectArray::GetObjectPtr's own
    shift-16/mask-0xFFFF/stride-24 arithmetic, and for each sampled non-null
    FUObjectItem::Object pointer, read the UObject's own first 8 bytes (its
    vtable pointer, per RF-05/PE-01's own established finding that
    UObjectBase's destructor is virtual) and check it falls inside
    [base_address, base_address + image_size_bytes) -- a plausible vtable
    lives in the SAME module's .rdata/.text, never in the heap, never in a
    different module.

    Never walks the whole array: indices 0..num_elements are scanned in
    order, stopping as soon as *sample_size* NON-NULL objects have been
    examined, or *max_scan_indices* index slots have been looked at,
    whichever comes first -- max_scan_indices exists purely so a corrupted
    (implausibly huge, or all-null) NumElements cannot turn this into an
    unbounded scan; it is not itself a plausibility signal.

    A read failure (ReadProcessMemoryFailedError) while merely LOCATING a
    candidate object (reading a chunk pointer, or a slot's Object field) is
    treated as an unreadable slot and skipped, exactly like a null slot --
    the target process's own memory layout can legitimately have unmapped or
    since-freed chunks, and this is a SCANNING concern, not a sample result.
    A read failure while reading the VTABLE POINTER of an object THIS
    function already decided to sample counts as a FAILED sample (a "torn
    read during concurrent GC" is exactly the scenario RF-05/README.md's own
    method anticipates) -- it does not silently skip to the next index,
    because that object was already committed to the sample the moment its
    Object pointer was found non-null.

    Threshold: PASS iff at least one object was examined AND the pass
    fraction is >= SAMPLE_PASS_FRACTION_THRESHOLD (0.80). This project's own
    judgment call, recorded here for a future reader to evaluate: a handful
    of failures from a torn read during concurrent GC (RF-05/README.md's own
    framing) is plausible and should NOT by itself refute the candidate, but
    a majority-failing sample cannot plausibly be explained by transient GC
    noise alone and IS strong evidence against the candidate. 0.80 sits well
    above what GC-related noise alone should ever produce (a handful out of
    dozens, not one in five) while still being well below 1.00, so an
    occasional torn read never flips a genuine candidate to REFUTED on its
    own.
    """
    examined = 0
    passed = 0
    failed = 0
    scanned = 0
    index = 0
    image_start = base_address
    image_end = base_address + image_size_bytes
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)

    while index < scan_limit and examined < sample_size:
        scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a sample.

        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        examined += 1
        try:
            vtable_ptr = _read_u64(api, handle, object_ptr)
            plausible = _vtable_pointer_in_module_range(
                vtable_ptr, base_address, image_size_bytes)
        except ReadProcessMemoryFailedError:
            plausible = False  # a torn read on an already-committed sample.

        if plausible:
            passed += 1
        else:
            failed += 1
        index += 1

    pass_fraction = (passed / examined) if examined else 0.0
    if examined == 0:
        reason = (
            "no non-null FUObjectItem.Object pointer was found in the "
            "%d index slot(s) scanned (scan_limit=%d) -- either the array "
            "is genuinely empty, or this is not the object array." %
            (scanned, scan_limit))
        check_passed = False
    else:
        check_passed = pass_fraction >= SAMPLE_PASS_FRACTION_THRESHOLD
        reason = None if check_passed else (
            "only %d of %d sampled objects (%.1f%%) had a vtable pointer "
            "inside [0x%x, 0x%x) -- below the %.0f%% pass threshold." %
            (passed, examined, pass_fraction * 100, image_start, image_end,
             SAMPLE_PASS_FRACTION_THRESHOLD * 100))

    return {
        "sample_size_requested": sample_size,
        "sample_size_examined": examined,
        "pass_count": passed,
        "fail_count": failed,
        "pass_fraction": pass_fraction,
        "pass_fraction_threshold": SAMPLE_PASS_FRACTION_THRESHOLD,
        "indices_scanned": scanned,
        "max_scan_indices": max_scan_indices,
        "pass": check_passed,
        "reason": reason,
    }


def run_i02(api, process_handle: int, base_address: int, image_size_bytes: int,
           guobjectarray_rva: int = DEFAULT_GUOBJECTARRAY_RVA,
           sample_size: int = DEFAULT_I02_SAMPLE_SIZE,
           poll_interval_seconds: float = DEFAULT_I02_POLL_INTERVAL_SECONDS,
           max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
           sleep_fn=time.sleep) -> dict:
    """The whole of capability I-02: verify the RF-05 GUObjectArray candidate
    against LIVE structural behaviour, implementing exactly the three checks
    research/evidence/RF-05/README.md's own "What a runtime observation would
    need to show to move this above HYPOTHESIS" section names (its 4th item,
    cross-checking FName via RF-06, is explicitly out of scope for I-02 --
    that is I-03's job).

    *base_address*/*image_size_bytes* MUST be from THIS SAME session's own
    run_i01() read, never cached from a previous session -- ASLR means the
    live base address changes on every process launch (see
    rva_to_live_va()'s own docstring); using a stale base_address here would
    silently compute the wrong live VA and either read garbage or read a
    different build launched at a coincidentally similar address.

    Never raises for a candidate that fails one, two, or all three checks --
    that is a valid, reportable REFUTATION (see the module docstring's
    "STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR" section). DOES let
    ReadProcessMemoryFailedError propagate for the handful of foundational
    reads this function cannot proceed without at all (the two NumElements
    reads, MaxElements, and the Objects pointer): a hard failure or partial
    read on one of THOSE is the tool being unable to attempt the check, not a
    structural finding about the candidate. Per-sample reads inside the walk
    (check 2) are a different matter and are handled inside
    sample_walk_objects() itself, never raised out of this function.

    Returns a plain dict: {"guobjectarray_rva", "guobjectarray_rva_hex",
    "guobjectarray_live_va", "guobjectarray_live_va_hex",
    "check_struct_invariants", "check_sample_walk",
    "check_growth_non_decreasing", "structurally_consistent"} -- three
    per-check sub-dicts, each carrying its own "pass" boolean and reasoning,
    plus one collapsed "structurally_consistent" verdict that is true iff ALL
    THREE individually pass (plan.md's own grading discipline: a record must
    not average distinct findings into one number, so every per-check
    boolean is kept alongside the collapsed one, never replaced by it).
    """
    guobjectarray_va = rva_to_live_va(base_address, guobjectarray_rva)

    # Check (1): NumElements/MaxElements plausibility -- also produces the
    # FIRST of the two NumElements reads check (3) needs.
    num_elements_first = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_NUM_ELEMENTS)
    max_elements = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_MAX_ELEMENTS)
    check_struct_invariants = evaluate_struct_invariants(num_elements_first, max_elements)

    # Check (2): sample walk, attempted regardless of whether check (1)
    # passed -- an independent structural signal in its own right, and the
    # walk itself is safe (bounded) even against an implausible count.
    objects_ptr = _read_u64(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_OBJECTS)
    check_sample_walk = sample_walk_objects(
        api, process_handle, objects_ptr, num_elements_first, base_address,
        image_size_bytes, sample_size=sample_size, max_scan_indices=max_scan_indices)

    # Check (3): two NumElements reads, separated in time, must be
    # non-decreasing -- RF-05/README.md's own pass criterion is
    # "non-decreasing", NOT "increased": a static menu with no gameplay
    # activity legitimately does not grow NumElements in a short poll
    # window, and that must not be misreported as a refutation.
    sleep_fn(poll_interval_seconds)
    num_elements_second = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_NUM_ELEMENTS)
    non_decreasing = num_elements_second >= num_elements_first
    check_growth_non_decreasing = {
        "num_elements_first": num_elements_first,
        "num_elements_second": num_elements_second,
        "poll_interval_seconds": poll_interval_seconds,
        "non_decreasing": non_decreasing,
        "pass": non_decreasing,
    }

    structurally_consistent = (
        check_struct_invariants["pass"]
        and check_sample_walk["pass"]
        and check_growth_non_decreasing["pass"])

    return {
        "guobjectarray_rva": guobjectarray_rva,
        "guobjectarray_rva_hex": "0x%x" % guobjectarray_rva,
        "guobjectarray_live_va": guobjectarray_va,
        "guobjectarray_live_va_hex": "0x%x" % guobjectarray_va,
        "check_struct_invariants": check_struct_invariants,
        "check_sample_walk": check_sample_walk,
        "check_growth_non_decreasing": check_growth_non_decreasing,
        "structurally_consistent": structurally_consistent,
        # Exposed so a later capability in THIS SAME run (I-03's own
        # "/Script/MISERY live reflection" probe, sample_object_names()
        # below) can reuse the objects pointer and NumElements THIS check
        # already fetched, rather than re-reading them a second time --
        # "reuse I-02's sampling, do not re-walk the array from scratch" per
        # the task that specified this reuse. Neither field is copied into
        # build_i02_document()'s own output (that function only ever copies
        # the specific named fields it always has -- see its own docstring),
        # so adding these here is backward compatible with every existing
        # caller/test that builds a run_i02()-shaped dict by hand.
        "objects_ptr_live_va": objects_ptr,
        "num_elements": num_elements_first,
    }


# --------------------------------------------------------------------------- #
# I-03: resolve an FName (an FNameEntryId) to its string text by reading
# FNamePool's own internal block table directly -- plan.md 8.2, RF-06's
# candidate (research/evidence/RF-06/README.md). See the module docstring's
# "WHAT I-03 IS" section for the full reasoning; this section implements it.
# --------------------------------------------------------------------------- #

# FNamePool/bNamePoolInitialized candidates: research/evidence/RF-06/README.md,
# static VAs 0x1479c2180 / 0x147995e5e against declared PE ImageBase
# 0x140000000 -> RVAs 0x079c2180 / 0x07995e5e. HYPOTHESIS, class I, oracle
# binary-analysis, confidence 0.60 (RF-06's own grade, slightly below RF-05's
# 0.65 -- see that README's "Grade" section for why). Both live in the
# module's own .data section (RF-06/README.md's own "Attempt to refute"
# section), so, like the GUObjectArray candidate, the live VA is
# rva_to_live_va(base_address, rva) -- THIS session's own I-01 base_address,
# never a cached one (ASLR).
DEFAULT_NAMEPOOL_RVA = 0x079C2180
DEFAULT_NAME_POOL_INITIALIZED_RVA = 0x07995E5E

# FNameEntryAllocator::Blocks[FNameMaxBlocks] offset within NamePoolData/
# FNamePool -- RF-06/README.md's own disassembly-confirmed `+0x10` (both
# checked callers dereference `*(puVar15 + Block*8 + 0x10)`), matching
# source: FNameEntryAllocator is FNamePool's own first member
# (UnrealNames.cpp:1514+), but Blocks[FNameMaxBlocks] is FNameEntryAllocator's
# own LAST declared member (source line 697), preceded by
# `mutable FRWLock Lock; uint32 CurrentBlock; uint32 CurrentByteCursor;`
# (UnrealNames.cpp:694-696) -- Lock is a single 8-byte SRWLOCK wrapper (no
# vtable), so Lock(8B) + CurrentBlock(4B) + CurrentByteCursor(4B) = 0x10 bytes
# precede Blocks[], exactly matching this constant. This also matches the
# `InitializeSRWLock(param_1)` RF-06's own decompile of the constructor shows
# as the very first instruction, before the `memset` that zeroes Blocks[].
NAMEPOOL_OFFSET_BLOCKS = 0x10

# FNameEntryHandle/FNameEntryAllocator addressing (UnrealNames.cpp:235,
# "FNameBlockOffsetBits = 16", cited in RF-06/README.md): Block = id>>16,
# Offset = id&0xFFFF, both confirmed a second, independent way in RF-06's own
# two checked callers ("(Block>>16 or param>>0x10) * 8" / "(Offset&0xFFFF)*2").
FNAME_BLOCK_OFFSET_BITS = 16

# FNameEntryAllocator::Stride (UnrealNames.cpp:443, "enum { Stride =
# alignof(FNameEntry) }") -- the per-entry stride Offset is scaled by to
# reach an FNameEntry's own address within a block. RF-06/README.md's own
# callers independently confirm this as the `*2` in `(Offset&0xFFFF)*2`.
FNAME_ENTRY_STRIDE = 2

# sizeof(FNameEntryHeader) (NameTypes.h) -- character data begins exactly
# this many bytes after an FNameEntry's own address, because this build's
# WITH_CASE_PRESERVING_NAME=0 (RF-06's own disassembly-confirmed build-config
# fact: the 256-shard constructor loop matches the #else/non-case-preserving
# branch) compiles OUT FNameEntry's leading ComparisonId field, leaving
# Header as FNameEntry's own first (and only, before the character union)
# member.
FNAME_ENTRY_HEADER_SIZE_BYTES = 2

# FNameEntryHeader's bit layout (NameTypes.h, WITH_CASE_PRESERVING_NAME==0
# branch, read from the actual header file, not assumed from the plan/task
# prompt -- see the module docstring's "WHAT I-03 IS" section):
#     uint16 bIsWide : 1;
#     uint16 LowercaseProbeHash : 5;
#     uint16 Len : 10;
# packed into ONE uint16. MSVC (this build's compiler -- plan.md A-06)
# allocates successive bitfields of a shared underlying type starting from
# the LEAST significant bit, in declaration order: bit 0 is bIsWide, bits
# 1-5 are LowercaseProbeHash, bits 6-15 are Len. This is confirmed, not
# merely assumed, by decode_fname_entry_id() actually decoding FNameEntryId
# 0 to the literal text "None" against a live process (RF-06/README.md's own
# prescribed confirmation step) -- see run_i03()'s own docstring and
# tests/test_eri_i03.py's synthetic id=0 round-trip test, which pins this
# exact bit order independent of any live process. If a future build instead
# uses WITH_CASE_PRESERVING_NAME=1 (this one does not -- confirmed by RF-06),
# the header shape changes to bIsWide:1 + Len:15 and these constants would
# need updating; this file makes no attempt to auto-detect that.
FNAME_HEADER_IS_WIDE_MASK = 0x1
FNAME_HEADER_LEN_SHIFT = 6
FNAME_HEADER_LEN_MASK = 0x3FF  # 10 bits -- naturally bounds Len to 0..1023,
# so a garbage/corrupted header can never make decode_fname_entry_id() below
# attempt an unbounded read: the field WIDTH itself, not a runtime check, is
# what keeps the character-data read small even against a completely wrong
# candidate address.

# UObjectBase's own NamePrivate.ComparisonIndex (FName's first 4 bytes, the
# FNameEntryId component -- NOT the trailing Number suffix) byte offset,
# derived from Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectBase.h
# 's own member declaration order (read in full, not assumed):
#     +0x00  vtable pointer (8B)      -- UObjectBase declares a virtual
#                                         destructor; RF-05/README.md's own
#                                         disassembly of the dtor at
#                                         0x1412c1e40 independently confirms
#                                         this: it begins by writing a vtable
#                                         pointer, "standard C++ dtor-chain
#                                         codegen".
#     +0x08  EObjectFlags ObjectFlags (4B)
#     +0x0C  int32 InternalIndex      (4B)  <- CROSS-CHECK: RF-05/README.md's
#                                              OWN disassembly of the same
#                                              destructor independently found
#                                              "Object->InternalIndex, offset
#                                              0xc" (quoted verbatim). This
#                                              source-order derivation lands
#                                              on the SAME +0xc with no
#                                              adjustment needed -- the two
#                                              independent methods (read the
#                                              header; read the disassembly)
#                                              agree, which is the whole
#                                              point of doing both.
#     +0x10  ClassPrivate (TNonAccessTrackedObjectPtr<UClass>, 8B -- an
#            FObjectPtr wrapping FObjectHandle, which is EITHER a plain
#            UObject* (UE_WITH_OBJECT_HANDLE_LATE_RESOLVE off) or a single
#            UPTRINT-sized packed ref (...on) -- 8 bytes either way; see
#            ObjectHandle.h)
#     +0x18  NamePrivate (FName, 8B: ComparisonIndex (FNameEntryId, 4B) at
#            +0x18 itself, then Number (uint32, 4B) at +0x1C -- NameTypes.h's
#            own static_assert(STRUCT_OFFSET(FName, ComparisonIndex) == 0)
#            confirms ComparisonIndex is FName's own first member)
#     +0x20  OuterPrivate (8B) -- UE_STORE_OBJECT_LIST_INTERNAL_INDEX (which
#            would insert an extra int32 ObjectListInternalIndex between
#            NamePrivate and OuterPrivate) defaults OFF and nothing in this
#            build's evidence suggests it is compiled on, so nothing is
#            inserted here.
# No padding is needed anywhere in this layout: every field up to +0x10 is
# 4-byte, +0x10/+0x18/+0x20 are all naturally 8-/4-byte aligned already, so
# the byte offsets above are exact, not merely "close enough".
DEFAULT_NAME_PRIVATE_OFFSET = 0x18

# sample_object_names()'s own default sample size -- deliberately larger
# than I-02's own DEFAULT_I02_SAMPLE_SIZE (32). I-02's sample only needs
# enough objects to judge vtable plausibility, a STATISTICAL question (32 is
# already generous for that). This probe is instead a NEEDLE search for one
# SPECIFIC object (the "MISERY" UPackage) among what is likely tens of
# thousands of live UObjects in a running game, so a larger bound buys a
# meaningfully better -- though, per the task that specified this probe,
# still explicitly NOT exhaustive -- chance of that one object happening to
# land in the sample. Chosen as a bound, not tuned against a real process
# (no live process was used to pick this number); a future run against the
# real game may want to raise --i03-reflection-sample-size further if this
# default misses.
DEFAULT_I03_REFLECTION_SAMPLE_SIZE = 512

# The literal FName text this probe searches for by default.
#
# CORRECTED 2026-08-27, after the first live run (research/instrument-runs/
# 2026-08-27T145831Z-fullscan/i03-fnamepool.json): the assumption this
# constant originally encoded -- that a UPackage object's own NamePrivate
# holds only its leaf name ("MISERY"), with the full "/Script/MISERY" path
# requiring a separate walk of the Outer chain -- was WRONG. The live decode
# showed every engine/game UPackage's own NamePrivate holds its FULL
# "/Script/<Module>" path directly (e.g. "/Script/CoreUObject",
# "/Script/Engine", and this build's own "/Script/MISERY" -- found verbatim
# in the decoded_names list of that run, without any Outer-chain walk).
# Searching for the bare leaf "MISERY" therefore returned misery_found=False
# even though the package WAS present in the very same sample -- a real
# false negative from an untested assumption, not a tool defect; the probe's
# own decoded_names list (which records everything decoded, regardless of
# what target_name was searched for) is what caught it. Kept as a plain
# constant, not re-verified against every other object kind (a
# non-UPackage UObject's NamePrivate may still be a bare leaf name -- this
# correction is specific to what was actually observed, package objects).
MISERY_PACKAGE_TARGET_NAME = "/Script/MISERY"


def decode_fname_entry_id(api, handle: int, namepool_live_va: int,
                          name_entry_id: int) -> dict:
    """Decode a single FNameEntryId to its string text, per RF-06/README.md's
    own recovered arithmetic:

        Block  = name_entry_id >> FNAME_BLOCK_OFFSET_BITS
        Offset = name_entry_id & 0xFFFF
        block_base = read_u64(namepool_live_va + NAMEPOOL_OFFSET_BLOCKS + Block*8)
        entry_ptr  = block_base + Offset * FNAME_ENTRY_STRIDE
        header     = read_u16(entry_ptr)                    # FNameEntryHeader
        (bIsWide, Len) decoded from header per the bit layout documented
        above FNAME_HEADER_IS_WIDE_MASK
        character data begins at entry_ptr + FNAME_ENTRY_HEADER_SIZE_BYTES,
        Len characters, ANSI (1B/char) if not bIsWide else UTF-16LE (2B/char)

    Lets ReadProcessMemoryFailedError propagate from the block-pointer read
    and the header read -- both are FOUNDATIONAL to attempting this decode
    at all (see the module docstring's "STRUCTURAL REFUTATION IS A RESULT,
    NOT AN ERROR" section: a hard read failure here means the tool could not
    even ATTEMPT the check, never a finding about the candidate). The
    character-data read (once Len/bIsWide are known) is likewise allowed to
    propagate for the same reason -- Len is bounded to 0..1023 by the field
    width itself (FNAME_HEADER_LEN_MASK), so even a garbage header cannot
    turn this into a large or unbounded read.

    Does NOT raise for a successfully-read-but-undecodable byte sequence (an
    ANSI/UTF-16LE decode error) -- that is exactly the "decoded garbage
    instead of a real name" refutation case RF-06/README.md's own
    confirmation step anticipates failing loudly about; it is reported
    honestly in the returned dict ('text': None, 'decode_error': the
    UnicodeDecodeError's own message, 'raw_bytes_hex': every byte actually
    read) rather than raised, so a caller (run_i03(), or a human reading the
    output JSON) can see exactly what was read even when it doesn't decode.

    Returns a plain dict: {'block', 'offset', 'block_base_hex',
    'entry_ptr_hex', 'header_u16_hex', 'is_wide', 'length', 'raw_bytes_hex',
    'text' (str, or None if length==0 was never true but decode failed),
    'decode_error' (None on success)}. A genuinely zero-length name decodes
    to 'text': "" (an empty string is not itself evidence of anything wrong
    -- FNameEntry supports it), which is why 'text' is None ONLY on an
    actual decode error, never conflated with "empty".
    """
    block = name_entry_id >> FNAME_BLOCK_OFFSET_BITS
    offset = name_entry_id & 0xFFFF
    block_base = _read_u64(api, handle, namepool_live_va + NAMEPOOL_OFFSET_BLOCKS + block * 8)
    entry_ptr = block_base + offset * FNAME_ENTRY_STRIDE
    header_u16 = _read_u16(api, handle, entry_ptr)
    is_wide = bool(header_u16 & FNAME_HEADER_IS_WIDE_MASK)
    length = (header_u16 >> FNAME_HEADER_LEN_SHIFT) & FNAME_HEADER_LEN_MASK

    text = ""
    decode_error = None
    raw_bytes = b""
    if length > 0:
        byte_len = length * (2 if is_wide else 1)
        raw_bytes = api.read_process_memory(
            handle, entry_ptr + FNAME_ENTRY_HEADER_SIZE_BYTES, byte_len)
        try:
            text = raw_bytes.decode("utf-16-le") if is_wide else raw_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            text = None
            decode_error = str(error)

    return {
        "block": block,
        "offset": offset,
        "block_base_hex": "0x%x" % block_base,
        "entry_ptr_hex": "0x%x" % entry_ptr,
        "header_u16_hex": "0x%04x" % header_u16,
        "is_wide": is_wide,
        "length": length,
        "raw_bytes_hex": raw_bytes.hex(),
        "text": text,
        "decode_error": decode_error,
    }


def run_i03(api, process_handle: int, base_address: int, image_size_bytes: int,
           namepool_rva: int = DEFAULT_NAMEPOOL_RVA,
           name_pool_initialized_rva: int = DEFAULT_NAME_POOL_INITIALIZED_RVA,
           name_entry_id: int = 0) -> dict:
    """The whole of capability I-03's own FNameEntryId decode, implementing
    the first two of RF-06/README.md's own "What a runtime observation would
    need to show to move this above HYPOTHESIS" steps (the third, the
    "/Script/MISERY" cross-check against a live UObject found via I-02, is
    sample_object_names() below, run separately by main() since it also
    needs I-02's own objects_ptr/num_elements):

      1. Read bNamePoolInitialized; report honestly (never assume) whether
         it is nonzero.
      2. If it IS nonzero, decode *name_entry_id* via decode_fname_entry_id()
         above. When *name_entry_id* == 0 (EName::None, the one case with a
         KNOWN expected answer -- source: UnrealNames.cpp's own REGISTER_NAME
         loop registers it first, per RF-06/README.md), also set
         'decoded_as_expected' to whether the decoded text is exactly "None"
         -- RF-06/README.md's own prescribed confirmation, verbatim.

    *base_address*/*image_size_bytes* MUST be from THIS SAME session's own
    run_i01() read, never cached (ASLR) -- identical requirement to
    run_i02()'s own, for the identical reason (rva_to_live_va()'s own
    docstring). *image_size_bytes* is accepted but not itself used by this
    function's own reads (both RF-06 candidates are read directly by their
    live VA, with no bounds check against the image needed for the decode
    arithmetic itself); it is kept as a parameter for signature symmetry
    with run_i02() and because a future strengthening of this check (an
    "is namepool_live_va inside the module's own mapped image" plausibility
    signal, mirroring I-02's own vtable-in-range check) would need it and
    should not have to change every call site to add it later.

    If bNamePoolInitialized reads as ZERO, this function does NOT attempt
    the decode at all (there would be nothing valid to read yet) -- it
    returns with 'pool_initialized': False and 'decoded'/'decoded_as_expected'
    both None, reported honestly rather than assumed-initialized. This
    should not happen for a running game observed well past its earliest
    bootstrap (RF-06/README.md's own expectation: "true almost immediately
    after process start"), but it is a real possible reading, not an error.

    Never raises for a decode that does not match the expected "None" text
    -- see the module docstring's "STRUCTURAL REFUTATION IS A RESULT, NOT AN
    ERROR" section: that is a valid, reportable refutation of the RF-06
    candidate or the bit-layout assumption, returned as data
    ('decoded_as_expected': False, plus every byte decode_fname_entry_id()
    actually read, for a human to diagnose). DOES let
    ReadProcessMemoryFailedError propagate from the bNamePoolInitialized read
    and from decode_fname_entry_id()'s own foundational reads -- a hard
    Win32 failure there means this capability could not even ATTEMPT the
    check, the same distinction run_i02() draws for its own foundational
    reads.

    Returns a plain dict: {'namepool_rva'/'namepool_rva_hex',
    'namepool_live_va'/'namepool_live_va_hex',
    'name_pool_initialized_rva'/'..._hex',
    'name_pool_initialized_live_va'/'..._hex', 'pool_initialized',
    'name_entry_id', 'decoded' (decode_fname_entry_id()'s own dict, or None
    if the pool was not initialized), 'decoded_as_expected' (bool, or None
    when name_entry_id != 0 -- there is no known expected answer to compare
    against for any other id, or when the pool was not initialized)}.
    """
    namepool_va = rva_to_live_va(base_address, namepool_rva)
    name_pool_initialized_va = rva_to_live_va(base_address, name_pool_initialized_rva)

    initialized_byte = api.read_process_memory(process_handle, name_pool_initialized_va, 1)
    pool_initialized = bool(initialized_byte[0])

    decoded = None
    decoded_as_expected = None
    if pool_initialized:
        decoded = decode_fname_entry_id(api, process_handle, namepool_va, name_entry_id)
        if name_entry_id == 0:
            decoded_as_expected = (decoded["text"] == "None")

    return {
        "namepool_rva": namepool_rva,
        "namepool_rva_hex": "0x%x" % namepool_rva,
        "namepool_live_va": namepool_va,
        "namepool_live_va_hex": "0x%x" % namepool_va,
        "name_pool_initialized_rva": name_pool_initialized_rva,
        "name_pool_initialized_rva_hex": "0x%x" % name_pool_initialized_rva,
        "name_pool_initialized_live_va": name_pool_initialized_va,
        "name_pool_initialized_live_va_hex": "0x%x" % name_pool_initialized_va,
        "pool_initialized": pool_initialized,
        "name_entry_id": name_entry_id,
        "decoded": decoded,
        "decoded_as_expected": decoded_as_expected,
    }


def sample_object_names(api, handle: int, objects_ptr: int, num_elements: int,
                        namepool_live_va: int, name_private_offset: int,
                        sample_size: int = DEFAULT_I03_REFLECTION_SAMPLE_SIZE,
                        max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
                        target_name: str = MISERY_PACKAGE_TARGET_NAME) -> dict:
    """The operator's own stated next milestone after I-02+I-03 land: a
    "/Script/MISERY live reflection" attempt -- a BOUNDED, honestly-reported
    search for the literal leaf FName "MISERY" (a UPackage object's own Name,
    NOT the full "/Script/MISERY" path -- building a full path means walking
    the Outer chain, explicitly out of scope here) among a sample of live
    UObject pointers.

    Reuses _locate_object_pointer() -- the SAME shift-16/mask-0xFFFF/
    stride-24 chunk-addressing arithmetic I-02's own sample_walk_objects
    uses to find populated FUObjectItem.Object slots -- rather than
    re-deriving the walk a second time ("reuse I-02's sampling, do not
    re-walk the array from scratch", per the task that specified this
    probe). For each located object, reads its own
    NamePrivate.ComparisonIndex (the FNameEntryId, 4 bytes, at
    *name_private_offset* bytes into the object -- see
    DEFAULT_NAME_PRIVATE_OFFSET's own comment for how that offset was
    derived from UObjectBase.h and cross-checked against RF-05's own
    independently-found InternalIndex==+0xc) and decodes it via
    decode_fname_entry_id().

    HONESTY, EXPLICIT (this is load-bearing, not a footnote -- per the task
    that specified this probe): this is a PLAUSIBLE, NOT EXHAUSTIVE search.
    The live UObject universe for a running UE game is likely tens of
    thousands of objects; a bounded sample of at most *sample_size* objects,
    scanned starting from index 0, may simply never reach the one UPackage
    object named "MISERY" even if every single piece of the apparatus this
    probe depends on (the RF-05 GUObjectArray candidate, the RF-06 FNamePool
    candidate, the decode arithmetic, the NamePrivate offset) is completely
    correct. A negative result ('misery_found': False) is therefore NEVER
    itself evidence against any of those things -- it means only "not found
    in the objects this particular bounded sample happened to examine". The
    returned dict states this in its own 'note' field, in the output data
    itself, so a downstream reader of the JSON never has to reconstruct this
    caveat from this docstring alone.

    A read failure LOCATING a slot (chunk pointer, Object field -- inside
    _locate_object_pointer()) is skipped, identically to
    sample_walk_objects()'s own "unreadable is like null" handling: it is a
    scanning concern, not a probe result. A read failure reading an
    ALREADY-located object's own NamePrivate field, or anywhere inside
    decode_fname_entry_id() for an object already committed to the sample,
    is counted as one decode failure and skipped, never allowed to abort the
    whole probe -- a torn read during a concurrent GC pass is exactly as
    plausible here as it is for I-02's own vtable read.

    Returns a plain dict: {'sample_size_requested', 'max_scan_indices',
    'indices_scanned', 'objects_examined', 'decode_failures',
    'decoded_names' (every name text this run actually decoded, in the ORDER
    found, duplicates included -- deliberately not deduplicated or filtered,
    so a human reader can judge overall plausibility: real UE object/class
    names, garbage, or a mix -- from the full list, not a single boolean),
    'target_name', 'misery_found' (bool: target_name in decoded_names),
    'note' (the bounded-sample honesty caveat above, restated in the output
    itself)}.
    """
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)
    index = 0
    scanned = 0
    examined = 0
    decode_failures = 0
    decoded_names: list = []

    while index < scan_limit and examined < sample_size:
        scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a sample.

        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        examined += 1
        try:
            name_entry_id = _read_u32(api, handle, object_ptr + name_private_offset)
            decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
        except ReadProcessMemoryFailedError:
            decode_failures += 1
            index += 1
            continue  # a torn read on an already-committed sample.

        if decoded["text"] is None:
            decode_failures += 1
        else:
            decoded_names.append(decoded["text"])
        index += 1

    misery_found = target_name in decoded_names
    return {
        "sample_size_requested": sample_size,
        "max_scan_indices": max_scan_indices,
        "indices_scanned": scanned,
        "objects_examined": examined,
        "decode_failures": decode_failures,
        "decoded_names": decoded_names,
        "target_name": target_name,
        "misery_found": misery_found,
        "note": (
            "bounded, NOT exhaustive sample: %d live object(s) were actually "
            "examined (sample_size_requested=%d, indices_scanned=%d of "
            "max_scan_indices=%d) -- misery_found=False means the target "
            "name was not among THOSE objects, never proof it is absent "
            "from the live process as a whole; see sample_object_names()'s "
            "own docstring." % (examined, sample_size, scanned, max_scan_indices)),
    }


# --------------------------------------------------------------------------- #
# I-04: dump UClass instances with their inheritance-adjacent identity
# (plan.md 8.2 item 8.2, "Дамп UClass с иерархией наследования") -- the
# first real UObject/UClass TRAVERSAL, not a bounded sample. See the module
# docstring's "WHAT I-04 IS" section for the full algorithm and its
# deliberate scope boundary.
# --------------------------------------------------------------------------- #

# UObjectBase field offsets I-04 additionally needs. DEFAULT_NAME_PRIVATE_OFFSET
# (+0x18, I-03's own constant) is REUSED verbatim above -- never redeclared.
#
# +0x10 ClassPrivate: falls straight out of UObjectBase.h's own member
# declaration order (see DEFAULT_NAME_PRIVATE_OFFSET's own comment above for
# the full field-by-field derivation, cross-checked against RF-05's own
# independent disassembly finding InternalIndex==+0xc) -- immediately
# follows InternalIndex (+0x0c, 4 bytes), naturally 8-byte aligned already.
DEFAULT_CLASS_PRIVATE_OFFSET = 0x10

# +0x20 OuterPrivate: the ONE genuinely new offset I-04 introduces, and it
# required zero new guessing -- it falls straight out of two ALREADY-verified
# facts: NamePrivate's own offset (+0x18) and NameTypes.h's own
# static_assert that FName is exactly 8 bytes (STRUCT_OFFSET(FName, Number)
# == 4, sizeof(Number) == 4, i.e. ComparisonIndex(4B)+Number(4B) == 8B) --
# confirmed live this session by I-03's own decode of exactly the +0x18
# ComparisonIndex field. +0x18 + 8 == +0x20.
DEFAULT_OUTER_PRIVATE_OFFSET = 0x20

# The class-identity fixed point's own seed and its cross-check literals --
# see find_uclass_self_reference()/find_blueprint_generated_class_address()
# below and the module docstring's "WHAT I-04 IS" section. Both literal
# object_path strings were directly, live-decoded this session (LOG-0051,
# research/instrument-runs/2026-08-27T145831Z-confirmed/i03-fnamepool.json's
# misery_reflection.decoded_names carries both bare names "Class" and
# "BlueprintGeneratedClass" among its 26 258 decoded entries), so these are
# not invented literals -- they are what this exact live process already
# proved it can decode.
UCLASS_SELF_REFERENCE_NAME = "Class"
UCLASS_SELF_REFERENCE_OBJECT_PATH = "/Script/CoreUObject.Class"
BLUEPRINT_GENERATED_CLASS_NAME = "BlueprintGeneratedClass"
BLUEPRINT_GENERATED_CLASS_OBJECT_PATH = "/Script/Engine.BlueprintGeneratedClass"

# The GENERAL name-suffix test find_meta_type_roots() and run_i04()'s own
# per-object is_blueprint_generated classification both use, chosen instead
# of hardcoding "BlueprintGeneratedClass" as the only recognized meta-type
# name -- see find_meta_type_roots()'s own docstring for why: real UE 5.4
# ships more than one native subclass playing this exact role
# (UWidgetBlueprintGeneratedClass, UAnimBlueprintGeneratedClass), all named
# by this same UE convention, and a fixed enumeration would silently miss
# any of them (a real defect a targeted layout+safety review found and this
# constant/the functions using it fix).
META_TYPE_NAME_SUFFIX = "GeneratedClass"

# Bounds I-04 introduces, all overridable via their own CLI flag (see
# build_arg_parser() below) -- never a second hardcoded copy of any of them.
DEFAULT_I04_MAX_OUTER_DEPTH = 16
DEFAULT_I04_MAX_FIXED_POINT_PASSES = 8
DEFAULT_I04_GAME_SAMPLE_CAP = 25


def _pointer_is_plausible(address: int) -> bool:
    """Cheap, universal plausibility check for any CANDIDATE POINTER I-04
    considers reading (an object's own address, its ClassPrivate, its
    OuterPrivate): non-null and 8-byte aligned, since every UObject
    allocation is pointer-aligned. Deliberately does NOT check the value
    against the module's own image range -- that check is for a
    VTABLE-POINTER-shaped value only (_vtable_pointer_in_module_range
    above), because an object/Class/Outer address is heap-allocated and
    legitimately falls OUTSIDE the module image; conflating the two checks
    would reject every real object address I-04 is meant to examine.
    """
    return address != 0 and address % 8 == 0


def _classify_object(api, handle: int, object_ptr: int, *, base_address: int,
                     image_size_bytes: int, namepool_live_va: int,
                     class_private_offset: int, name_private_offset: int,
                     outer_private_offset: int) -> dict:
    """Read and validate ONE already-located candidate UObject's identity
    fields -- the module docstring's I-04 "structural validation" checks
    1-3, exactly. NEVER raises ReadProcessMemoryFailedError: every read here
    is on an object *_locate_object_pointer* already found non-null, so any
    read failure encountered while examining ITS OWN fields is a TORN read
    on an already-committed candidate -- the SAME "torn read during
    concurrent GC" treatment sample_walk_objects()'s own vtable read and
    sample_object_names()'s own NamePrivate read already establish (their
    own docstrings), never a propagated tool error. A hard/partial
    ReadProcessMemory failure while merely LOCATING a candidate (the chunk
    pointer, the FUObjectItem.Object field) is a walk_object_universe()
    concern, not this function's -- this function is only ever called with
    a non-null object_ptr walk_object_universe() already located.

    Returns a dict, ALWAYS shaped the same way regardless of which check
    failed (so callers -- objects_by_address, resolve_object_path -- never
    need to special-case a missing key): {'valid' (bool, True iff checks 1-3
    ALL passed), 'rejection_kind' (one of 'pointer_alignment',
    'read_failure', 'name_decode', 'class_pointer_implausible', or None when
    valid), 'rejection_reason' (human text, or None), 'name_text' (str or
    None), 'name_ok' (bool -- True iff the object's OWN address was
    plausible AND its FName decoded without error, REGARDLESS of whether
    ClassPrivate itself later failed check 3 -- this is deliberately weaker
    than 'valid', because object_path construction (check 4/5) only ever
    needs an ancestor's name, never its own class-pointer plausibility; see
    resolve_object_path()'s own docstring), 'class_ptr' (int or None -- only
    ever set when 'valid' is True), 'outer_ptr' (int, 0 for 'no Outer', or
    None only when name_ok is False and no read was ever attempted),
    'outer_ok' (bool -- True iff outer_ptr is 0/null OR passed the same
    plausibility check as any other candidate pointer; a False outer_ok
    does NOT itself invalidate the object's own basic identity, only its
    own usability as an ANCESTOR in someone else's object_path walk)}.
    """
    record = {
        "valid": False, "rejection_kind": None, "rejection_reason": None,
        "name_text": None, "name_ok": False,
        "class_ptr": None, "outer_ptr": None, "outer_ok": False,
    }

    # Check 1: the object pointer itself must be a plausible candidate
    # BEFORE any read is attempted at all -- a corrupted/misaligned address
    # must never be dereferenced, per the module docstring's structural-
    # validation section.
    if not _pointer_is_plausible(object_ptr):
        record["rejection_kind"] = "pointer_alignment"
        record["rejection_reason"] = (
            "object pointer 0x%x is not a plausible (non-null, 8-byte-"
            "aligned) address" % object_ptr)
        return record

    try:
        name_entry_id = _read_u32(api, handle, object_ptr + name_private_offset)
        decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
        class_ptr = _read_u64(api, handle, object_ptr + class_private_offset)
        outer_ptr = _read_u64(api, handle, object_ptr + outer_private_offset)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on an already-located object at 0x%x: %s" %
            (object_ptr, error))
        return record

    record["outer_ptr"] = outer_ptr
    record["outer_ok"] = (outer_ptr == 0) or _pointer_is_plausible(outer_ptr)

    # Check 2: a valid FName entry -- decode_fname_entry_id()'s own
    # decode_error must be None. (Len is naturally capped 0..1023 by its own
    # bit width already, per I-03's own FNAME_HEADER_LEN_MASK -- no
    # additional bound needed here.)
    if decoded["decode_error"] is not None:
        record["rejection_kind"] = "name_decode"
        record["rejection_reason"] = (
            "FName decode error at 0x%x: %s" % (object_ptr, decoded["decode_error"]))
        return record

    record["name_text"] = decoded["text"]
    record["name_ok"] = True

    # Check 3: ClassPrivate points to something plausible -- non-null,
    # 8-byte aligned, AND the first 8 bytes at that address look like a
    # vtable pointer inside the module's own image range.
    if not _pointer_is_plausible(class_ptr):
        record["rejection_kind"] = "class_pointer_implausible"
        record["rejection_reason"] = (
            "ClassPrivate 0x%x is not a plausible (non-null, 8-byte-aligned) "
            "address" % class_ptr)
        return record

    try:
        class_vtable = _read_u64(api, handle, class_ptr)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on ClassPrivate 0x%x's own vtable pointer: %s" %
            (class_ptr, error))
        return record

    if not _vtable_pointer_in_module_range(class_vtable, base_address, image_size_bytes):
        record["rejection_kind"] = "class_pointer_implausible"
        record["rejection_reason"] = (
            "ClassPrivate 0x%x's own vtable pointer 0x%x is outside the "
            "module image range [0x%x, 0x%x)" %
            (class_ptr, class_vtable, base_address, base_address + image_size_bytes))
        return record

    record["valid"] = True
    record["class_ptr"] = class_ptr
    return record


def walk_object_universe(api, handle: int, objects_ptr: int, num_elements: int,
                         base_address: int, image_size_bytes: int,
                         namepool_live_va: int,
                         class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
                         name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
                         outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
                         max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES) -> dict:
    """Walks EVERY located index (bounded only by *max_scan_indices*, a
    safety cap against a corrupted/implausibly huge NumElements -- NOT a
    statistical sample size like I-02/I-03's own bounded probes; I-04 IS the
    first real traversal, see the module docstring's "WHAT I-04 IS"
    section), locating each non-null object via _locate_object_pointer()
    (I-02's own chunk-walk arithmetic, reused verbatim -- never re-derived)
    and validating/decoding it via _classify_object() above.

    A read failure while merely LOCATING a slot (chunk pointer, the
    FUObjectItem.Object field) is skipped, identically to I-02's own
    sample_walk_objects()/I-03's own sample_object_names() -- a scanning
    concern, not a census entry; never raised, never counted against
    'objects_located'.

    Returns {'objects_by_address': dict[int, dict] (every LOCATED object's
    own _classify_object() record, keyed by its own address -- this is what
    resolve_object_path() below walks the Outer chain through, purely via
    dict lookups, without any further memory read: the SAME reads
    _classify_object() already made for every object cover every possible
    Outer target too, since every live object's own index was visited),
    'indices_scanned', 'objects_located' (non-null slots), 'valid_count'
    (checks 1-3 all passed), 'rejected_counts' (dict, one entry per
    _classify_object() 'rejection_kind' value)}.
    """
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)
    objects_by_address: dict = {}
    indices_scanned = 0
    objects_located = 0
    valid_count = 0
    rejected_counts = {
        "pointer_alignment": 0, "read_failure": 0,
        "name_decode": 0, "class_pointer_implausible": 0,
    }

    index = 0
    while index < scan_limit:
        indices_scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a census entry.
        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        objects_located += 1
        record = _classify_object(
            api, handle, object_ptr, base_address=base_address,
            image_size_bytes=image_size_bytes, namepool_live_va=namepool_live_va,
            class_private_offset=class_private_offset,
            name_private_offset=name_private_offset,
            outer_private_offset=outer_private_offset)
        objects_by_address[object_ptr] = record
        if record["valid"]:
            valid_count += 1
        else:
            rejected_counts[record["rejection_kind"]] += 1
        index += 1

    return {
        "objects_by_address": objects_by_address,
        "indices_scanned": indices_scanned,
        "objects_located": objects_located,
        "valid_count": valid_count,
        "rejected_counts": rejected_counts,
    }


def resolve_object_path(start_address: int, objects_by_address: dict, *,
                        max_depth: int = DEFAULT_I04_MAX_OUTER_DEPTH) -> dict:
    """Builds *start_address*'s own canonical object_path by walking its
    Outer chain -- start_address -> its Outer -> its Outer's Outer -> ...
    -- purely via dict lookups into *objects_by_address*
    (walk_object_universe()'s own output: every live object this run
    located, keyed by its own address), never a further memory read: the
    object every real Outer pointer can possibly reference was already
    visited by the SAME full-array walk that built this dict, because I-04
    walks every live index, not a bounded sample.

    BOUNDED (max_depth hops, default 16) and CYCLE-PROTECTED (an address
    that repeats within THIS ONE walk is a traversal failure, not an
    infinite loop) -- a corrupted or maliciously-looping Outer chain must
    never be able to hang this function. Exceeding max_depth without
    terminating is likewise reported as a traversal failure, never raised
    and never silently truncated into a plausible-looking wrong answer.

    Algorithm (this session's own confirmed fact, LOG-0051: a UPackage's own
    NamePrivate already holds its FULL "/Script/<Module>" or "/Game/<...>"
    path, never a bare leaf name):
      * Outer == null immediately (a top-level object, typically a
        UPackage): object_path = its own decoded name; package = that same
        name IF it looks like a package (starts with "/"), else None (and
        a note is set -- an unusual, best-effort case, never silently
        assumed fine).
      * Outer non-null, Outer's own Outer null (the common, single-level
        case -- an object owned directly by its package): object_path =
        Outer's decoded name + "." + O's own decoded name, matching real
        UE GetPathName() convention. package = the Outer's own name.

        KNOWN, DELIBERATE CONVENTION MISMATCH against the sibling offline
        record: the already-committed research/reflection/
        misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl (RF-01, a
        DIFFERENT build, 24826585) stores the identical kind of class's
        object_path with a "/" join instead, e.g.
        "/Script/MISERY/MiseryBlueprintFunctionLibrary" (not
        "/Script/MISERY.MiseryBlueprintFunctionLibrary"). This function
        intentionally does NOT match that convention: "." is what real UE
        GetPathName() actually produces (also the exact form
        research/schema/reflection-record.schema.json's own object_path
        field documents as its example, "/Script/MISERY.MiseryCharacter"),
        so runtime-sourced records use "." on purpose. A reader joining or
        matching class records BETWEEN RF-01's classes.jsonl and this
        capability's own classes.jsonl by object_path string will need to
        normalize one convention to the other first (e.g. compare raw_name
        + package instead, both of which agree across the two sources) --
        this is flagged here explicitly rather than silently left for a
        future reader to discover by a failed string match.
      * Deeper nesting (3+ levels): every ancestor from the outermost
        NON-package down to O itself is joined with ":" (the real UE
        subobject delimiter), prefixed by "<package>." -- e.g.
        "/Game/Foo.Bar:Baz". A reasonable, standard approximation; this
        function does not attempt component-path/array-index subtleties
        beyond it.
      * The outermost ancestor is recognized as a package heuristically:
        its decoded name starts with "/" (every package name observed live
        this session started with "/", e.g. "/Script/...", "/Game/...").
        When the walk terminates on an ancestor whose name does NOT start
        with "/", that is unusual: object_path is still built, best-effort,
        but 'ok' is still True and 'note' records the anomaly rather than
        silently assuming it is fine.

    Returns {'object_path' (str or None), 'package' (str or None), 'ok'
    (bool -- False only for an actual traversal FAILURE: cycle, unresolved
    ancestor, or exceeded max_depth -- never False merely for the "unusual
    top-level name" case above, which still produces a best-effort path),
    'note' (str or None -- set for both the failure case and the "unusual"
    best-effort case, so a caller never has to reconstruct the caveat from
    this docstring alone)}.
    """
    chain: list = []
    visited: set = set()
    address = start_address

    for _ in range(max_depth):
        if address in visited:
            return {
                "object_path": None, "package": None, "ok": False,
                "note": "cycle detected in the Outer chain at 0x%x" % address,
            }
        visited.add(address)

        record = objects_by_address.get(address)
        if record is None or not record.get("name_ok"):
            return {
                "object_path": None, "package": None, "ok": False,
                "note": (
                    "Outer chain unresolved: the object at 0x%x was not "
                    "located by this run's own walk, or its own FName "
                    "failed to decode" % address),
            }
        chain.append(record["name_text"])

        outer_ptr = record.get("outer_ptr")
        if outer_ptr in (0, None):
            break  # terminated: this ancestor has no Outer -- top level.
        if not record.get("outer_ok", True):
            return {
                "object_path": None, "package": None, "ok": False,
                "note": (
                    "OuterPrivate of the object at 0x%x is not a plausible "
                    "pointer" % address),
            }
        address = outer_ptr
    else:
        return {
            "object_path": None, "package": None, "ok": False,
            "note": (
                "Outer chain exceeded max depth (%d) without terminating" %
                max_depth),
        }

    top_level = chain[-1]
    looks_like_package = top_level.startswith("/")
    if len(chain) == 1:
        object_path = chain[0]
        package = chain[0] if looks_like_package else None
    else:
        rest = list(reversed(chain[:-1]))  # outermost-non-package ... self
        object_path = top_level + "." + rest[0] + "".join(":" + name for name in rest[1:])
        package = top_level if looks_like_package else None

    note = None if looks_like_package else (
        "outermost ancestor %r does not start with '/' -- unusual; "
        "object_path is best-effort" % top_level)
    return {"object_path": object_path, "package": package, "ok": True, "note": note}


def find_uclass_self_reference(objects_by_address: dict, *,
                               path_resolver) -> dict | None:
    """The class-identity fixed point's own SEED: the object whose own
    ClassPrivate address equals its OWN address (UClass::StaticClass()->
    ClassPrivate == itself, a genuine architectural fixed point in real UE
    reflection, not a hack). Cross-checked, never merely trusted because it
    happens to be self-referential: its own decoded name must be
    UCLASS_SELF_REFERENCE_NAME ("Class") AND its own object_path (via
    *path_resolver*, normally resolve_object_path() bound to the SAME
    objects_by_address this candidate came from) must be exactly
    UCLASS_SELF_REFERENCE_OBJECT_PATH ("/Script/CoreUObject.Class") --
    both literal values this session already live-decoded once (LOG-0051),
    not invented here.

    Every self-referential candidate found is examined (not just the
    first) in case a corrupted/implausible object happens to also satisfy
    the bare self-reference test; only one that ALSO cross-checks is ever
    returned. Returns None -- never a guessed/fabricated seed -- when no
    candidate exists at all, or none of the candidates found cross-check.
    That is a hard structural failure for the whole capability: run_i04()
    reports zero UClass instances found rather than build on an unverified
    seed.
    """
    for address, record in objects_by_address.items():
        if not record["valid"] or record["class_ptr"] != address:
            continue
        if record["name_text"] != UCLASS_SELF_REFERENCE_NAME:
            continue
        resolved = path_resolver(address)
        if resolved["ok"] and resolved["object_path"] == UCLASS_SELF_REFERENCE_OBJECT_PATH:
            return {"address": address, "object_path_result": resolved}
    return None


def find_blueprint_generated_class_address(round1_members: set, objects_by_address: dict,
                                           *, path_resolver) -> int | None:
    """Among *round1_members* (every object whose ClassPrivate == the
    seed's own address), find the ONE whose own decoded name is EXACTLY
    BLUEPRINT_GENERATED_CLASS_NAME ("BlueprintGeneratedClass") AND whose own
    object_path (via *path_resolver*) is exactly
    BLUEPRINT_GENERATED_CLASS_OBJECT_PATH ("/Script/Engine.BlueprintGeneratedClass")
    -- the SAME "find it, then verify it, never just trust the name"
    discipline find_uclass_self_reference() applies to the seed itself.
    Returns None, honestly, when no round-1 member cross-checks.

    This is now ONE cross-checked, specifically-verified data point
    (run_i04()'s own blueprint_generated_class_address_hex field) among
    POSSIBLY SEVERAL meta-type roots find_meta_type_roots() discovers more
    generally by name pattern -- see compute_class_identity()'s own
    docstring for why a single hardcoded address is not enough on its own
    to decide is_blueprint_generated for every object.
    """
    for address in round1_members:
        record = objects_by_address[address]
        if record["name_text"] != BLUEPRINT_GENERATED_CLASS_NAME:
            continue
        resolved = path_resolver(address)
        if resolved["ok"] and resolved["object_path"] == BLUEPRINT_GENERATED_CLASS_OBJECT_PATH:
            return address
    return None


def find_meta_type_roots(round1_members: set, objects_by_address: dict) -> dict:
    """Among *round1_members* (every object whose ClassPrivate == the
    seed's own address -- i.e. every native "type descriptor" object:
    "Class" itself, "ScriptStruct", "Function", "Enum",
    "BlueprintGeneratedClass", and every ordinary native UClass like
    MiseryFocusSubsystem), find every one that is ITSELF a "meta-type" --
    a type whose OWN instances are themselves classes, not ordinary
    objects -- by NAME PATTERN: its own decoded name ends with
    "GeneratedClass" (META_TYPE_NAME_SUFFIX).

    WHY A NAME-SUFFIX PATTERN, not a fixed enumeration of specific names:
    real UE 5.4 has more than one native subclass of UBlueprintGeneratedClass
    that plays this exact "class of a Blueprint asset" role --
    UWidgetBlueprintGeneratedClass (Engine/Source/Runtime/UMG/Public/
    Blueprint/WidgetBlueprintGeneratedClass.h) and
    UAnimBlueprintGeneratedClass (Engine/Source/Runtime/Engine/Classes/
    Animation/AnimBlueprintGeneratedClass.h) are both real, distinct
    engine types, both named with the "GeneratedClass" suffix by UE's own
    convention, and this project has no exhaustive, verified list of every
    such type this specific build ships (there could be others this
    session never observed). A name-suffix test generalizes to catch any
    of them -- present, or not yet seen -- WITHOUT hardcoding each one
    individually the way the plain "BlueprintGeneratedClass"-only check
    (find_blueprint_generated_class_address(), still called separately for
    its own specific cross-checked report) originally did.

    WHY THIS STAYS SOUND (does not sweep in ordinary leaf classes like
    MiseryFocusSubsystem or ordinary struct/function descriptors):
    "GeneratedClass" is not a generic word -- it is UE's own, specific
    naming convention for exactly this one architectural role (a class
    whose OWN instances are Blueprint-asset classes), and no ordinary
    native gameplay class this project has observed is named that way.
    This is a real but bounded risk (a native class COULD theoretically be
    named ending in "GeneratedClass" without playing this role) --
    documented, not hidden: every promoted root is still cross-checked by
    compute_class_identity() against round1_members (i.e. its own
    ClassPrivate really is "Class" -- it cannot be an arbitrary /Game
    object, since round1_members is already restricted to that).

    Returns {name_text: address} for every round1_member whose name ends
    with META_TYPE_NAME_SUFFIX -- always includes "BlueprintGeneratedClass"
    itself when present (its own name ends with "GeneratedClass" too), so
    find_blueprint_generated_class_address()'s separate, path-verified
    result is redundant with (and cross-checks) one entry of this dict,
    not a disjoint computation.
    """
    return {
        record["name_text"]: address
        for address, record in ((a, objects_by_address[a]) for a in round1_members)
        if record["name_text"].endswith(META_TYPE_NAME_SUFFIX)
    }


def compute_class_identity(objects_by_address: dict, seed_address: int, *,
                           path_resolver,
                           max_passes: int = DEFAULT_I04_MAX_FIXED_POINT_PASSES) -> dict:
    """The class-identity fixed point. Grows class_address_universe from
    the seed PLUS every discovered "meta-type" root (find_meta_type_roots()
    above), never from "any address already a member of the growing
    universe" in general (see below for why that general rule is wrong).

    CORRECTED 2026-08-27 (twice in the same session -- see git history /
    RESEARCH_LOG.md for both corrections): a targeted layout+safety review
    of the ORIGINAL I-04 pass found that growing from exactly two FIXED
    roots {seed_address, blueprint_generated_class_address} misses
    UWidgetBlueprintGeneratedClass / UAnimBlueprintGeneratedClass instances
    (real, distinct native UE 5.4 types -- see find_meta_type_roots()'s own
    docstring for the source citations) -- on a real UE5 game using UMG
    (almost certainly true of MISERY), that would have silently excluded
    what is likely the LARGEST category of real /Game Blueprint assets. A
    FIRST attempted fix (collapsing to "class_address_universe is simply
    every distinct ClassPrivate value seen, no roots at all") was ALSO
    wrong, caught by this project's own test suite before being trusted:
    it implicitly assumed every genuinely-loaded UClass has at least one
    live INSTANCE pointing at it (e.g. its own CDO) in THIS snapshot,
    which is not the actual definition of "is a UClass" -- a Blueprint
    class ASSET is a UClass because of WHAT IT IS (an instance of
    BlueprintGeneratedClass or a sibling meta-type), not because of
    whether anything else happens to already be an instance OF IT. THIS
    version restores the "grow from known meta-type roots" shape, fixing
    only the actual defect (roots were too narrowly and permanently fixed
    at exactly two), while keeping the meta-type root discovery itself
    GENERAL (name-suffix, not individually hardcoded).

    Round 1: round1_members = {O : O.ClassPrivate == seed_address}.
    class_address_universe = {seed_address} | round1_members. Every native
    "type descriptor" object -- "Class" itself, "ScriptStruct", "Function",
    "Enum", "BlueprintGeneratedClass", "WidgetBlueprintGeneratedClass",
    "AnimBlueprintGeneratedClass" (if this build has it), and every
    ordinary native UClass (MiseryFocusSubsystem, ...) -- is caught here in
    one pass, because ALL of them are native C++ types whose own metaclass
    is literally "Class".

    Root promotion: find_meta_type_roots(round1_members, ...) finds every
    round1_member whose OWN name ends with "GeneratedClass" -- this is a
    SET, not one fixed address, and can be 1, 2, 3+ elements depending on
    what this specific live build actually has loaded. roots =
    {seed_address} | {every discovered meta-type root's address}.

    Round 2+ (bounded, until convergence or *max_passes*, default 8): any
    object whose ClassPrivate is IN roots (a FIXED set, never grown further
    after round 1 -- see "WHY NOT..." below) and not yet in the universe
    joins. This catches real Blueprint class ASSETS under /Game for EVERY
    discovered meta-type (their own metaclass is one of the roots) in one
    or two more passes; normal UE reflection has no deeper nesting than
    this (a Blueprint asset's class is a meta-type; a meta-type's class is
    "Class"; there is no third tier), so convergence at pass 2 or 3 is the
    expected, not merely hoped-for, outcome.

    WHY roots STAYS FIXED after round 1 (never "any address already in the
    universe joins" in general): real UE semantics mean an ORDINARY
    GAMEPLAY INSTANCE of any class already in the universe has its own
    ClassPrivate equal to THAT class's address too -- e.g. a live, ordinary
    UMiseryFocusSubsystem instance's own ClassPrivate IS MiseryFocusSubsystem's
    address, and MiseryFocusSubsystem joins the universe in round 1 (it is
    a native class, found via round1_members). Under a truly general
    closure rule, once MiseryFocusSubsystem is "in the universe", that
    instance's ClassPrivate would ALSO be "a member of the universe",
    wrongly admitting the instance itself as "a UClass" too. Restricting
    growth to the FIXED, verified roots set (never re-derived from the
    growing universe itself) is what keeps this precise -- every
    class_address_universe member beyond round 1 is provably an instance
    of a KNOWN meta-type, never an instance of an ordinary leaf class.

    is_blueprint_generated for a classified object O is decided by
    run_i04() (not here): it resolves what O's OWN ClassPrivate's decoded
    name IS and checks whether that name ends with "GeneratedClass" --
    the SAME name-suffix test find_meta_type_roots() uses to discover
    roots in the first place, applied per-object at classification time.

    find_uclass_self_reference()'s seed remains required and cross-checked
    exactly as always -- the one non-negotiable anchor this whole
    computation is built from.

    Returns {'class_address_universe' (set[int]), 'round1_size' (int),
    'meta_type_roots' (dict[name, address hex] -- every discovered root
    beyond the seed, for the report), 'blueprint_generated_class_address'
    (int or None, from find_blueprint_generated_class_address(), kept for
    report continuity and as a cross-check against meta_type_roots),
    'passes_run' (int), 'converged' (bool)}.
    """
    round1_members = {
        address for address, record in objects_by_address.items()
        if record["valid"] and record["class_ptr"] == seed_address}
    universe = {seed_address} | round1_members

    bgc_address = find_blueprint_generated_class_address(
        round1_members, objects_by_address, path_resolver=path_resolver)
    meta_type_roots = find_meta_type_roots(round1_members, objects_by_address)

    roots = {seed_address} | set(meta_type_roots.values())

    passes_run = 1
    converged = False
    for _ in range(max(max_passes - 1, 0)):
        passes_run += 1
        new_members = {
            address for address, record in objects_by_address.items()
            if record["valid"] and record["class_ptr"] in roots
            and address not in universe}
        if not new_members:
            converged = True
            break
        universe |= new_members
    else:
        converged = False  # exhausted max_passes still growing -- logged by run_i04()'s own note.

    return {
        "class_address_universe": universe,
        "round1_size": len(round1_members),
        "meta_type_roots": {name: "0x%x" % addr for name, addr in meta_type_roots.items()},
        "blueprint_generated_class_address": bgc_address,
        "passes_run": passes_run,
        "converged": converged,
    }


def _summarize_walk(walk: dict) -> dict:
    return {
        "indices_scanned": walk["indices_scanned"],
        "objects_located": walk["objects_located"],
        "valid_count": walk["valid_count"],
        "rejected_counts": walk["rejected_counts"],
    }


def run_i04(api, process_handle: int, base_address: int, image_size_bytes: int,
           objects_ptr: int, num_elements: int, namepool_live_va: int,
           class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
           name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
           outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
           max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
           max_outer_depth: int = DEFAULT_I04_MAX_OUTER_DEPTH,
           max_fixed_point_passes: int = DEFAULT_I04_MAX_FIXED_POINT_PASSES) -> dict:
    """The whole of capability I-04: walk_object_universe() (every located
    object's ClassPrivate/NamePrivate/OuterPrivate, validated) ->
    find_uclass_self_reference() (the seed, cross-checked) ->
    compute_class_identity() (the meta-type-rooted fixed point) -> object_path +
    is_blueprint_generated for every classified UClass instance.

    *objects_ptr*/*num_elements* MUST be from THIS SAME run's own I-02
    result (never re-walked from scratch -- see the module docstring's
    "WHAT I-04 IS" section); *namepool_live_va* MUST be from THIS SAME run's
    own I-03 result, for the identical reason.

    Never raises for "seed not found" -- that is a hard structural failure
    for the whole capability, reported honestly as zero UClass instances
    found (see find_uclass_self_reference()'s own docstring), not a tool
    malfunction. DOES let ReadProcessMemoryFailedError propagate from
    nothing new here -- every per-object read this function's own callees
    make is already caught and converted into a rejection/failure count
    by _classify_object()/walk_object_universe(), mirroring I-02/I-03's own
    established split (a hard failure LOCATING a slot, or examining an
    ALREADY-located object's own fields, is a scanning/torn-read concern,
    never a propagated tool error for THIS capability, since it introduces
    no new foundational array-level read of its own -- objects_ptr/
    num_elements/namepool_live_va were already foundationally read by I-02/
    I-03 before this function was ever called).

    Returns a plain dict -- see the module docstring's "WHAT I-04 IS"
    section and this function's own field names below for the shape; the
    'classes' list carries one entry per classified UClass instance, with
    'module'/'module_origin'/'package' NOT yet filled in (that is
    classify_classes_by_module()'s own job, run separately by main() so
    this function stays a pure "what did the walk find" result).
    """
    walk = walk_object_universe(
        api, process_handle, objects_ptr, num_elements, base_address, image_size_bytes,
        namepool_live_va, class_private_offset=class_private_offset,
        name_private_offset=name_private_offset, outer_private_offset=outer_private_offset,
        max_scan_indices=max_scan_indices)
    objects_by_address = walk["objects_by_address"]

    def path_of(address: int) -> dict:
        return resolve_object_path(address, objects_by_address, max_depth=max_outer_depth)

    seed = find_uclass_self_reference(objects_by_address, path_resolver=path_of)
    if seed is None:
        return {
            "seed_found": False,
            "seed_address_hex": None,
            "class_address_universe_size": 0,
            "round1_size": 0,
            "blueprint_generated_class_address_hex": None,
            "meta_type_roots": {},
            "fixed_point_passes_run": 0,
            "fixed_point_converged": None,
            "walk": _summarize_walk(walk),
            "classes": [],
            "note": (
                "seed search failed: no valid object was found whose "
                "ClassPrivate equals its own address AND whose decoded "
                "name/object_path cross-check to %r/%r -- I-04 reports "
                "ZERO UClass instances found rather than build on an "
                "unverified seed (see find_uclass_self_reference()'s own "
                "docstring)." %
                (UCLASS_SELF_REFERENCE_NAME, UCLASS_SELF_REFERENCE_OBJECT_PATH)),
        }

    fixed_point = compute_class_identity(
        objects_by_address, seed["address"], path_resolver=path_of,
        max_passes=max_fixed_point_passes)
    bgc_address = fixed_point["blueprint_generated_class_address"]

    # Integrity check on the corrected (2026-08-27) class_address_universe
    # definition: the seed ("Class", self-referential) must be its own
    # witness -- seed.ClassPrivate == seed_address, so seed_address is
    # trivially a member of {record.class_ptr for valid records}. Asserted,
    # not merely assumed: if this ever fails, the walk itself is broken in
    # a way compute_class_identity()'s own docstring does not anticipate,
    # and that is exactly the kind of silent failure this project's own
    # discipline says must surface, not be papered over.
    assert seed["address"] in fixed_point["class_address_universe"], (
        "seed %r not in its own class_address_universe -- the corrected "
        "class-identity computation (compute_class_identity()'s own "
        "docstring) is unsound for this walk; do not trust classes below." %
        seed["address"])

    # Iterate objects_by_address (a dict, insertion-ordered == this run's own
    # scan order) rather than class_address_universe (a plain set, whose
    # iteration order is NOT deterministic/reproducible across runs) --
    # membership-tested against the set, order taken from the dict. This is
    # what makes select_game_sample()'s own "preserves scan order" claim
    # actually true, and this document's own row order reproducible.
    classes = []
    for address in objects_by_address:
        if address not in fixed_point["class_address_universe"]:
            continue
        record = objects_by_address[address]
        resolved = path_of(address)
        # is_blueprint_generated (CORRECTED 2026-08-27, see
        # compute_class_identity()'s own docstring for the full reasoning):
        # resolve what O's OWN ClassPrivate's decoded name IS -- the
        # type-descriptor object O is an instance of -- and check whether
        # THAT name ends with META_TYPE_NAME_SUFFIX ("GeneratedClass"), the
        # SAME general name-suffix test find_meta_type_roots() used to
        # discover roots in the first place (deliberately the SAME
        # constant/test, not a second, possibly-drifting copy) -- so this
        # also catches UWidgetBlueprintGeneratedClass/
        # UAnimBlueprintGeneratedClass instances (real UE 5.4 native
        # subclasses of UBlueprintGeneratedClass), not only the literal
        # "BlueprintGeneratedClass" type itself. None (genuinely
        # undetermined), never guessed, when O's own class_ptr was not
        # itself a validly-classified object in this same walk.
        class_descriptor = objects_by_address.get(record["class_ptr"])
        if class_descriptor is None or not class_descriptor["valid"]:
            is_blueprint_generated = None
        else:
            is_blueprint_generated = class_descriptor["name_text"].endswith(
                META_TYPE_NAME_SUFFIX)
        classes.append({
            "address": address,
            "address_hex": "0x%x" % address,
            "raw_name": record["name_text"],
            "object_path": resolved["object_path"],
            "package": resolved["package"],
            "object_path_ok": resolved["ok"],
            "object_path_note": resolved["note"],
            "is_blueprint_generated": is_blueprint_generated,
        })

    return {
        "seed_found": True,
        "seed_address_hex": "0x%x" % seed["address"],
        "class_address_universe_size": len(fixed_point["class_address_universe"]),
        "round1_size": fixed_point["round1_size"],
        "blueprint_generated_class_address_hex": (
            "0x%x" % bgc_address if bgc_address is not None else None),
        "meta_type_roots": fixed_point["meta_type_roots"],
        "fixed_point_passes_run": fixed_point["passes_run"],
        "fixed_point_converged": fixed_point["converged"],
        "walk": _summarize_walk(walk),
        "classes": classes,
        "note": None if fixed_point["converged"] else (
            "the class-identity fixed point did NOT converge within "
            "max_fixed_point_passes=%d -- class_address_universe was still "
            "growing when the pass bound was hit; the reported set is a "
            "LOWER BOUND, not necessarily complete. See "
            "compute_class_identity()'s own docstring for why this should "
            "not normally happen against real UE 5.4 reflection data." %
            max_fixed_point_passes),
    }


def classify_classes_by_module(classes: list) -> dict:
    """Buckets run_i04()'s own 'classes' list by module/package, per I-04's
    own committed-artifact scope (module docstring's "WHAT I-04 IS"
    section): every /Script/MISERY class is written to classes.jsonl in
    full; /Game classes get a small BOUNDED sample (select_game_sample()
    below), never an exhaustive dump; everything else (native engine
    modules -- /Script/Engine, /Script/CoreUObject, etc. -- and anything
    unclassified) is counted only, never persisted.

    module_origin classification is DELIBERATELY MINIMAL here: only
    "game-misery" (module == "/Script/MISERY" exactly, matching RF-02's own
    established classification string verbatim) is ever asserted; every
    other module -- including genuine engine modules -- is left
    "unclassified", NOT guessed as "engine", because RF-02's own engine/
    game-plugin classification method (checking a module name against UE
    5.4.4's actual module list at the correct changelist) is out of scope
    for this pass and this function does not attempt to reproduce it from
    a name pattern alone (research/schema/reflection-record.schema.json's
    own module_origin description: "reported, never guessed").

    Returns {'misery': list[dict], 'game': list[dict], 'other': list[dict]}
    -- each entry is one of *classes*'s own dicts, enriched with 'module'
    and 'module_origin'.
    """
    misery: list = []
    game: list = []
    other: list = []
    for record in classes:
        package = record["package"]
        module = package if (package and package.startswith("/Script/")) else None
        module_origin = "game-misery" if module == "/Script/MISERY" else "unclassified"
        enriched = dict(record, module=module, module_origin=module_origin)
        if module == "/Script/MISERY":
            misery.append(enriched)
        elif package and package.startswith("/Game/"):
            game.append(enriched)
        else:
            other.append(enriched)
    return {"misery": misery, "game": game, "other": other}


def select_game_sample(game_classes: list, cap: int = DEFAULT_I04_GAME_SAMPLE_CAP) -> list:
    """A small, BOUNDED sample of *game_classes* (classify_classes_by_module()'s
    own 'game' bucket) to actually WRITE to classes.jsonl -- never the full
    set found, per I-04's own committed-artifact scope. Prioritizes
    is_blueprint_generated=True entries first (the task this capability was
    specified from: "especially ones classified is_blueprint_generated=
    true"), then fills any remaining capacity with the rest, each group
    preserving its own original (scan) order for reproducibility. The FULL
    count of *game_classes* (before this cap) is reported separately by
    run_i04()/build_i04_document() regardless of how many are actually
    written here -- this function only ever decides what gets PERSISTED.
    """
    blueprint_generated = [c for c in game_classes if c["is_blueprint_generated"] is True]
    rest = [c for c in game_classes if c["is_blueprint_generated"] is not True]
    return (blueprint_generated + rest)[:cap]


def build_i04_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None,
                       misery_classes_count: int, game_classes_total_count: int,
                       game_classes_sample_count: int, other_classes_count: int) -> dict:
    """The I-04 raw output document -- research/instrument-runs/<run>/
    i04-classes.json, the SAME "raw single-run data document, no evidence
    envelope" shape as build_i01_document()/build_i02_document()/
    build_i03_document() (see build_i01_document()'s own docstring for the
    is_record()/MARKER_KEYS reasoning this mirrors verbatim -- none of the
    fields here is a marker key either). classes.jsonl (a SEPARATE artifact,
    built by build_i04_class_record() below and written by main()) is where
    the actual GRADED knowledge-base claims live; this document is this
    run's own bookkeeping/summary, including the honest full counts for
    everything this pass deliberately does NOT persist (engine-module
    classes, and every /Game class beyond the bounded sample cap) -- see
    the module docstring's "WHAT I-04 IS" section for why those counts
    matter even though the rows themselves are not committed.
    """
    return {
        "capability": CAPABILITY_ID_I04,
        "seed_found": result["seed_found"],
        "seed_address_hex": result["seed_address_hex"],
        "class_address_universe_size": result["class_address_universe_size"],
        "round1_size": result["round1_size"],
        "blueprint_generated_class_address_hex": result["blueprint_generated_class_address_hex"],
        "fixed_point_passes_run": result["fixed_point_passes_run"],
        "fixed_point_converged": result["fixed_point_converged"],
        "walk": result["walk"],
        "misery_classes_count": misery_classes_count,
        "game_classes_total_count": game_classes_total_count,
        "game_classes_sample_count": game_classes_sample_count,
        "other_classes_count": other_classes_count,
        "note": result["note"],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


# The MISERY-cross-check source cited on every /Script/MISERY class_record
# row (build_i04_class_record() below, cross_checked=True) -- see that
# function's own docstring, and the module docstring's confidence/MIX-SPLIT
# reasoning, for why this is a DIFFERENT build than the one this run
# observed, and why that is stated plainly rather than glossed over.
_I04_MISERY_CROSS_CHECK_SOURCE = {
    "method": (
        "RF-01: structured decode of the ScriptObjects chunk of "
        "global.ucas, a DIFFERENT build (misery-24826585-ue5.4.4-"
        "0eef3715244b) than this record's own build_key"),
    "artifact": "research/reflection/misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl",
    "locator": None,
    "note": (
        "CROSS-BUILD corroboration, not a same-build second reading: RF-01's "
        "own record is for build 24826585; this record is for a different "
        "build. The evidentiary value is that the SAME five native "
        "/Script/MISERY class names recur, independently, across a static "
        "offline decode of an earlier build and a live runtime read of the "
        "current build -- strong evidence these are genuine, stable native "
        "classes of the game's own root module, not a coincidental or "
        "misread name. It does NOT independently confirm anything about "
        "THIS record's own build_key, since RF-01 never read this build "
        "at all -- that is why this cross-check alone earns 0.90, not "
        "higher, and why it is stated explicitly here rather than folded "
        "silently into a same-build-looking 'second source'."),
}


def build_i04_class_record(entry: dict, *, build_key: str, recorded_at: str,
                           cross_checked: bool) -> dict:
    """One classes.jsonl row (research/schema/reflection-record.schema.json's
    class_record branch, composed with kb-record.schema.json's envelope) for
    ONE entry of classify_classes_by_module()'s own enriched 'classes' list.

    *cross_checked* selects the MIX-SPLIT evidence grading the task this
    capability was specified from explicitly asked for, justified here
    rather than applied as one blanket number to every record kind:

      * True (every /Script/MISERY class, always -- exactly the ~5 rows
        matching research/reflection/misery-24826585-ue5.4.4-
        0eef3715244b/classes.jsonl's own 5 names): confidence 0.90,
        evidence_level OBSERVED, oracle ["runtime-reflection",
        "global-ucas"], TWO sources -- this run's own I-04 traversal, plus
        _I04_MISERY_CROSS_CHECK_SOURCE above. 0.90 matches LOG-0051's own
        confidence for the SAME live GUObjectArray/FNamePool apparatus this
        record is built from, and is defensible by the SAME "two
        independent methods" criterion kb-record.schema.json's own envelope
        already requires for confidence >= 0.80 (plan.md 10.3): a runtime
        read of build 24953925, cross-checked by an INDEPENDENT static
        decode of build 24826585's global.ucas finding the identical five
        names. It is explicitly NOT claimed as strong as an offline decode
        of THIS SAME build would be (RF-01 never read this build), which is
        exactly why it stays at 0.90 rather than reaching for 0.95+ (that
        band additionally needs, per plan.md 10.3, every one of six
        criteria stated line-by-line -- not attempted here, matching
        LOG-0051's own stated reason for staying at 0.90 rather than
        higher).
      * False (every /Game class in the bounded sample -- there is no
        offline cross-check for a SPECIFIC compiled Blueprint asset, only
        this ONE live read): confidence 0.75, evidence_level OBSERVED,
        oracle ["runtime-reflection"], ONE source. Deliberately kept BELOW
        the kb-record.schema.json envelope's own 0.80 threshold: at 0.75 the
        single-source exemption never needs to be argued for at all (the
        schema's own "confidence >= 0.80 needs >= 2 sources" rule, plan.md
        task EV-03, simply does not apply below it) -- 0.75 is chosen as
        the class-I band plan.md 10.2 itself describes as "one strong ...
        confirmation" (0.60-0.79), near its own top, reflecting that this
        IS a strong single method (a live runtime read via a
        cross-validated GUObjectArray/FNamePool apparatus, not a guess),
        just one without ANY independent corroboration for this specific
        object -- unlike the MISERY classes, nothing else in this
        repository has ever independently observed this particular
        Blueprint asset existing.

    Fields the task this capability was specified from explicitly scoped
    OUT (never guessed, never half-implemented, all explicitly null):
    cdo_name, is_native, is_abstract, within_class, config_name, interfaces,
    property_count, function_count, super, super_object_path, size,
    alignment, class_flags_raw, class_cast_flags_raw, flags_raw -- every one
    of these needs a UObject-, UField-, UStruct- or UClass-specific field
    I-04 deliberately never reads (see the module docstring's "WHAT I-04
    IS" section, "SCOPE" paragraph).
    """
    confidence = 0.90 if cross_checked else 0.75
    oracle = (["runtime-reflection", "global-ucas"] if cross_checked
             else ["runtime-reflection"])
    sources = [{
        "method": (
            "I-04: FUObjectArray walk (I-02's own chunk-walk arithmetic, "
            "reused) + ClassPrivate/NamePrivate/OuterPrivate reads "
            "(UObjectBase.h offsets +0x%x/+0x%x/+0x%x) + FNamePool decode "
            "(I-03's own decode_fname_entry_id, reused) + the ClassPrivate "
            "self-reference fixed point" %
            (DEFAULT_CLASS_PRIVATE_OFFSET, DEFAULT_NAME_PRIVATE_OFFSET,
             DEFAULT_OUTER_PRIVATE_OFFSET)),
        "artifact": None,
        "locator": entry["address_hex"],
        "note": (
            "oracle runtime-reflection. The address is this live UObject's "
            "own address in THIS run's process -- not stable across a "
            "relaunch (ASLR/heap allocation), recorded only for this run's "
            "own audit trail."),
    }]
    if cross_checked:
        sources.append(dict(_I04_MISERY_CROSS_CHECK_SOURCE))

    claim_type = "native-class-exists" if cross_checked else "asset-exists"
    claim = (
        "the live MISERY-Win64-Shipping.exe process (build_key %s) has a "
        "UObject at %s that IS a UClass instance named %r, object_path %r" %
        (build_key, entry["address_hex"], entry["raw_name"], entry["object_path"]))
    notes = None if entry["object_path_ok"] else (
        "object_path is best-effort: %s" % entry["object_path_note"])

    return {
        "kind": "class",
        "raw_name": entry["raw_name"],
        "object_path": entry["object_path"],
        "package": entry["package"],
        "module": entry["module"],
        "module_origin": entry["module_origin"],
        "flags_raw": None,
        "super": None,
        "super_object_path": None,
        "size": None,
        "alignment": None,
        "class_flags_raw": None,
        "class_cast_flags_raw": None,
        "cdo_name": None,
        "is_native": None,
        "is_blueprint_generated": entry["is_blueprint_generated"],
        "is_abstract": None,
        "within_class": None,
        "config_name": None,
        "interfaces": None,
        "property_count": None,
        "function_count": None,
        "claim": claim,
        "claim_type": claim_type,
        "claim_class": "I",
        "evidence_level": "OBSERVED",
        "confidence": confidence,
        "oracle": oracle,
        "sources": sources,
        "build_key": build_key,
        "recorded_at": recorded_at,
        "method": "I-04",
        "refutation_attempt": (
            "if the ClassPrivate self-reference fixed point were wrong, an "
            "object with a non-UClass ClassPrivate could still be admitted "
            "into class_address_universe -- refuted by requiring the SEED "
            "itself to cross-check its own decoded name/object_path against "
            "the known literals 'Class'/'/Script/CoreUObject.Class' before "
            "the fixed point runs at all; by requiring "
            "'BlueprintGeneratedClass' to pass the identical by-name/"
            "by-object_path cross-check before it is ever promoted to a "
            "growth root; and by growing the universe from EXACTLY those "
            "two verified roots, never from 'anything already in the "
            "universe', which would (and, unverified, could) also sweep in "
            "ordinary gameplay object instances of any native class already "
            "found -- see compute_class_identity()'s own docstring for the "
            "full worked reason this specific, narrower rule was chosen."),
        "notes": notes,
        "semantic_alias": None,
    }


def dump_jsonl(records: list) -> str:
    """Deterministic JSONL serialization: one compact (sorted-key) JSON
    object per line, LF-terminated -- the SAME shape
    tools/reflection/global_ucas.py's own dump_jsonl() produces (no indent,
    unlike this file's own dump_json()'s pretty-printed single-document
    form), matching the already-committed research/reflection/*/classes.jsonl
    convention (research/reflection/misery-24826585-ue5.4.4-0eef3715244b/
    classes.jsonl's own 5 lines are exactly this shape).
    """
    return "".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
        for record in records)


# --------------------------------------------------------------------------- #
# document building -- the I-01 JSON output, and the manifest.json required
# by research/schema/instrument-run-manifest.schema.json.
# --------------------------------------------------------------------------- #

BUILD_KEY_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_build_key(build_key: str) -> None:
    """Fail loudly, before opening a single handle, if --build-key is not
    the canonical 'sha256:<64 lowercase hex>' shape
    (research/schema/kb-record.schema.json #/$defs/build_key). Both the
    I-01 document and manifest.json carry this value, and the manifest MUST
    validate against instrument-run-manifest.schema.json -- a malformed
    build_key would only be caught later, at write time, if this check did
    not exist, which is a worse failure (partial work already done) than
    catching it at argument-parse time.
    """
    if not BUILD_KEY_PATTERN.match(build_key):
        raise ValueError(
            "--build-key %r does not match the required shape "
            "'sha256:<64 lowercase hex characters>' "
            "(research/schema/kb-record.schema.json #/$defs/build_key). "
            "Compute it with sha256sum on "
            "MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe, or copy the "
            "value from an existing research/builds/<key>/ entry." % build_key)


# --------------------------------------------------------------------------- #
# identity self-establishment (LOG-0048/LOG-0049) -- see the module docstring's
# "IDENTITY IS SELF-ESTABLISHED" section and BuildKeyMismatchError above for
# why this exists. Every live attach session computes ITS OWN build_key from
# the file the OS loader actually mapped; a supplied --build-key is at most a
# cross-check against that, never the source of truth. Future capabilities
# (I-02, I-03, ...) that need to know or re-confirm which build they are
# reading should call establish_build_identity() with the SAME
# result["exe_path"] run_i01() already returns, rather than re-deriving any
# part of this by hand -- that keeps "identity is self-established" a single
# fact computed in one place, not a convention every capability has to
# remember to reimplement.
# --------------------------------------------------------------------------- #

HASH_BUFFER_BYTES = 1 << 20  # 1 MiB, same streaming convention as
# tools/inventory/snapshot_install.py's hash_file / tools/fingerprint's
# stream_digests / research/schema/kb-record.schema.json #/$defs/sha256's own
# implied streaming contract: one bounded buffer, reused via readinto(), so
# peak additional memory is HASH_BUFFER_BYTES regardless of file size -- a
# Shipping.exe here is ~130 MB and must never be read into memory whole.

DEFAULT_BUILDS_INDEX_PATH = os.path.join(_REPO_ROOT, "research", "builds", "index.json")


def compute_file_sha256(path: str, buf_size: int = HASH_BUFFER_BYTES) -> str:
    """Lowercase hex sha256 digest of *path* (research/schema/kb-record.schema.json
    #/$defs/sha256's own shape, no 'sha256:' prefix), computed in ONE streaming
    pass with a single bounded buffer reused via readinto() -- never a whole-file
    read. Callers that need the canonical 'sha256:<64 hex>' build_key form
    prefix this return value themselves (see establish_build_identity below).

    This is the function that makes identity SELF-established rather than
    merely asserted: called on module.exe_path -- the exact file the OS
    loader mapped for the live process this run attached to, per
    MODULEENTRY32W's szExePath -- its result is data this run measured
    itself, not a value any caller supplied or any previous run cached. See
    the module docstring's "IDENTITY IS SELF-ESTABLISHED" section for why
    that distinction is the entire point (LOG-0048/LOG-0049).
    """
    digest = hashlib.sha256()
    buffer = bytearray(buf_size)
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            digest.update(view[:read])
    return digest.hexdigest()


def lookup_known_build(build_key: str, index_path: str = DEFAULT_BUILDS_INDEX_PATH
                       ) -> tuple[bool, str | None]:
    """(known_build, build_id) for *build_key* against research/builds/index.json
    (or *index_path*, the seam tests use to avoid touching the real committed
    index) -- a dict keyed literally by 'sha256:<hex>' (see that file itself).

    READ-ONLY INFORMATIONAL BOOKKEEPING ONLY. This exists to answer one
    question -- "has this exact build been seen and registered before, and if
    so under which build_id" -- for the I-01 document and the manifest to
    record. It deliberately does nothing else: it does not change what I-01
    reads (base_address/image_size are reported identically whether the
    build is known or not), and it must NEVER be used to pull an RVA,
    address, or signature from a DIFFERENT build's research/evidence/
    directory -- an unknown build gets no bindings/candidates inherited from
    a previous one, and neither does a known one, from this function alone.
    Candidate-lookup/signature-matching against a known build's evidence is
    out of scope here by design; only the KNOWN/UNKNOWN fact and the
    build_id string are surfaced.

    A missing index file is treated as "unknown", not as an error -- the
    index is a convenience registry, not something I-01's own read depends
    on, and an early or stripped-down checkout may not have one yet. A
    present-but-malformed index file DOES raise (json.JSONDecodeError, a
    ValueError subclass main() already handles the same way as every other
    fail-loud EriError), because silently swallowing a corrupt registry file
    would hide a genuine bug rather than an absent-and-expected one.
    """
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            index = json.load(handle)
    except FileNotFoundError:
        return False, None
    entry = index.get(build_key)
    if entry is None:
        return False, None
    build_id = entry.get("build_id")
    return True, (str(build_id) if build_id is not None else None)


def establish_build_identity(*, exe_path: str, given_build_key: str | None,
                             builds_index_path: str = DEFAULT_BUILDS_INDEX_PATH) -> dict:
    """THE one place identity is established for this tool (LOG-0048/LOG-0049).
    Every live attach session calls this, and self-computes its own build_key
    from *exe_path* -- MODULEENTRY32W's szExePath for the module this run
    actually found, i.e. run_i01()'s own result["exe_path"], never a path
    passed on the command line or cached from a previous run. Future
    capabilities that need build identity should call this function with
    that same exe_path rather than reimplementing any part of it.

    *given_build_key* is None when --build-key was not passed (the normal,
    preferred way to invoke this tool from now on): the self-computed hash
    becomes the authoritative build_key, and this function never opens
    research/builds/index.json for anything but the informational
    known/unknown lookup below.

    *given_build_key*, if not None, is treated ONLY as a cross-check, never
    as a source of truth: on a match, this run proceeds, and the returned
    'build_key_cross_checked' is True so the output documents can state that
    the supplied value was INDEPENDENTLY CONFIRMED, not merely asserted. On
    a mismatch, raises BuildKeyMismatchError -- stating both the supplied and
    the self-computed value plainly -- BEFORE this function returns, which is
    before main() writes a single output file. This is the exact check that
    would have caught LOG-0048/LOG-0049 at the moment it happened, instead of
    requiring a human to notice it afterward by hand.

    Also performs the read-only known/unknown-build lookup (see
    lookup_known_build) against *builds_index_path* and folds its result in.

    Returns {"build_key", "identity_self_established" (always True),
    "build_key_cross_checked", "known_build", "build_id"}.
    """
    self_computed_hex = compute_file_sha256(exe_path)
    self_computed_build_key = "sha256:%s" % self_computed_hex

    if given_build_key is not None:
        if given_build_key != self_computed_build_key:
            raise BuildKeyMismatchError(
                "--build-key %r does not match the build actually attached to: "
                "this run independently computed %r from module.exe_path (%r), "
                "the file the OS loader mapped for the process it just found. "
                "This is exactly the class of mistake LOG-0048/LOG-0049 recorded "
                "on 2026-08-27 (a --build-key copied from earlier work, not "
                "rechecked, at the exact moment Steam had silently updated the "
                "game) -- see BuildKeyMismatchError's own docstring. Nothing was "
                "written; rerun with the correct --build-key, or omit --build-key "
                "entirely and let this run's own self-computed hash be the "
                "authoritative build_key." %
                (given_build_key, self_computed_build_key, exe_path))
        build_key = given_build_key
        cross_checked = True
    else:
        build_key = self_computed_build_key
        cross_checked = False

    known_build, build_id = lookup_known_build(build_key, builds_index_path)

    return {
        "build_key": build_key,
        "identity_self_established": True,
        "build_key_cross_checked": cross_checked,
        "known_build": known_build,
        "build_id": build_id,
    }


def build_i01_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-01 output document (task item 6 / README 'Как запускать').

    JSON, not JSONL: this is one process's one snapshot, a single object.
    A later multi-capability ERI export (I-16, once I-02+ exist) can add a
    JSONL sibling that emits one line per capability's own record without
    changing this function or this document's shape -- 'capability' is
    already a field of this object precisely so a JSONL row built the same
    way is self-describing without a wrapper.

    Deliberately does NOT carry 'evidence_level'/'oracle' fields, even
    though the read this document reports is, in fact, OBSERVED via the
    runtime-reflection oracle. This matches the rest of the repository's
    convention for raw evidence artifacts (research/evidence/*/*.json never
    self-grades either): tools/kb/validate.py's is_record() heuristic
    treats ANY dict carrying an evidence_level/oracle marker key as a
    full knowledge-base record and then demands confidence/sources[]/
    claim_type on it too (plan.md 10.2/10.4/10.5) -- fields this raw,
    single-run data document has no business carrying, since the actual
    graded claim belongs in the sibling manifest.json (build_manifest()
    below, which DOES carry the full envelope) or in a future
    RESEARCH_LOG.md entry that cites this file by path and sha256, per
    this project's established C-13 discipline. Re-adding these two keys
    here would make every future run fail tools/kb/validate.py.

    Also carries identity_self_established/build_key_cross_checked/
    known_build/build_id (LOG-0048/LOG-0049 -- see establish_build_identity's
    own docstring and the module docstring's "IDENTITY IS SELF-ESTABLISHED"
    section for why): none of these four is a marker key in
    tools/kb/validate.py's MARKER_KEYS ("evidence_level", "claim_type",
    "oracle", "confidence"), so adding them does not trip is_record() into
    treating this raw document as a full knowledge-base record -- do not
    widen this set to include any of those four marker names for the same
    reason evidence_level/oracle are excluded above.
    """
    base_address = int(result["base_address"])
    return {
        "capability": CAPABILITY_ID,
        "process_name": result["process_name"],
        # PID is a research artifact of THIS run, not a stable identifier
        # across runs: Windows reassigns PIDs, and the same MISERY process
        # relaunched gets a different one. Never key persisted research
        # data on pid alone -- build_key + recorded_at is the reproducible
        # identity; pid is only useful to correlate within one live session.
        "pid": int(result["pid"]),
        "base_address_hex": "0x%x" % base_address,
        "base_address_decimal": base_address,
        "image_size_bytes": int(result["image_size_bytes"]),
        "build_key": build_key,
        # identity is SELF-established every run, never merely asserted by a
        # caller-supplied --build-key (LOG-0048/LOG-0049): see
        # establish_build_identity(). identity_self_established is always
        # True for a document this function produced through main()'s normal
        # flow. build_key_cross_checked is True only when --build-key WAS
        # given AND matched the self-computed hash -- i.e. build_key above
        # was INDEPENDENTLY CONFIRMED, not merely asserted; False means
        # build_key above IS the self-computed hash itself (no --build-key
        # was given, the normal/preferred invocation from now on).
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        # known_build/build_id: read-only informational bookkeeping from
        # research/builds/index.json (lookup_known_build) -- whether this
        # exact build_key has a registry entry, and if so its build_id.
        # Never changes what I-01 reads, and never a signal to reuse
        # candidates/bindings from a different build's research/evidence/.
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i02_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-02 output document -- structural-invariant verification of
    RF-05's candidate GUObjectArray against a LIVE process. *result* is
    run_i02()'s own return dict; see that function's docstring for the exact
    three checks and research/evidence/RF-05/README.md for the struct layout
    and arithmetic this is built from.

    Carries every field of *result* verbatim -- the RVA and live VA checked,
    all three per-check sub-dicts (each with its own 'pass' boolean and
    reasoning text), and the collapsed 'structurally_consistent' verdict --
    plus never averages the three checks into that one collapsed field
    without also keeping each individually visible (plan.md's own grading
    discipline: a record must not average distinct findings into one
    number).

    Deliberately does NOT carry 'evidence_level'/'oracle', for the identical
    is_record() reason build_i01_document's own docstring explains in full:
    none of the fields here (including the four identity fields below) is in
    tools/kb/validate.py's MARKER_KEYS, so this stays a raw, single-run data
    document, never a full knowledge-base record on its own -- the graded
    claim (does this run's evidence move RF-05 above HYPOTHESIS) belongs in
    a future RESEARCH_LOG.md entry that cites this file by path and sha256,
    per this project's established C-13 discipline, not in this document
    itself.

    Carries identity_self_established/build_key_cross_checked/known_build/
    build_id, mirrored from the SAME establish_build_identity() call main()
    already made for the I-01 document in this same run -- I-02 never
    re-establishes identity independently, it is downstream of the one
    identity fact this run already computed for itself (LOG-0048/LOG-0049).
    """
    return {
        "capability": CAPABILITY_ID_I02,
        "guobjectarray_rva_hex": result["guobjectarray_rva_hex"],
        "guobjectarray_rva_decimal": int(result["guobjectarray_rva"]),
        "guobjectarray_live_va_hex": result["guobjectarray_live_va_hex"],
        "guobjectarray_live_va_decimal": int(result["guobjectarray_live_va"]),
        "check_struct_invariants": result["check_struct_invariants"],
        "check_sample_walk": result["check_sample_walk"],
        "check_growth_non_decreasing": result["check_growth_non_decreasing"],
        "structurally_consistent": bool(result["structurally_consistent"]),
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i03_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None,
                       misery_reflection: dict | None = None) -> dict:
    """The I-03 output document -- FNamePool decode verification (RF-06's
    candidate) plus, optionally, the "/Script/MISERY live reflection" probe.
    *result* is run_i03()'s own return dict; see that function's docstring
    for the exact fields, and research/evidence/RF-06/README.md for the
    struct layout and arithmetic this is built from.

    *misery_reflection* is sample_object_names()'s own return dict when
    main() ran that probe (--run-i03-reflection), else None -- kept as an
    explicit optional field rather than a second output document, matching
    this task's own "your call on shape, but keep it consistent" latitude:
    both halves are readings from the SAME live process, in the SAME run, so
    one document rather than two avoids forcing a reader to correlate two
    files by build_key/recorded_at to see the whole I-03 picture.

    Deliberately does NOT carry 'evidence_level'/'oracle', for the identical
    is_record() reason build_i01_document's and build_i02_document's own
    docstrings explain in full: none of the fields here (including the four
    identity fields below) is in tools/kb/validate.py's MARKER_KEYS, so this
    stays a raw, single-run data document, never a full knowledge-base
    record on its own -- the graded claim (does this run's evidence move
    RF-06 above HYPOTHESIS, and separately, was "/Script/MISERY" found)
    belongs in a future RESEARCH_LOG.md entry that cites this file by path
    and sha256, per this project's established C-13 discipline, not in this
    document itself.

    Carries identity_self_established/build_key_cross_checked/known_build/
    build_id, mirrored from the SAME establish_build_identity() call main()
    already made for the I-01 document in this same run -- I-03 never
    re-establishes identity independently, exactly like I-02.
    """
    return {
        "capability": CAPABILITY_ID_I03,
        "namepool_rva_hex": result["namepool_rva_hex"],
        "namepool_rva_decimal": int(result["namepool_rva"]),
        "namepool_live_va_hex": result["namepool_live_va_hex"],
        "namepool_live_va_decimal": int(result["namepool_live_va"]),
        "name_pool_initialized_rva_hex": result["name_pool_initialized_rva_hex"],
        "name_pool_initialized_rva_decimal": int(result["name_pool_initialized_rva"]),
        "name_pool_initialized_live_va_hex": result["name_pool_initialized_live_va_hex"],
        "name_pool_initialized_live_va_decimal": int(result["name_pool_initialized_live_va"]),
        "pool_initialized": bool(result["pool_initialized"]),
        "name_entry_id": int(result["name_entry_id"]),
        "decoded": result["decoded"],
        "decoded_as_expected": result["decoded_as_expected"],
        "misery_reflection": misery_reflection,
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_manifest(*, run_id: str, arguments: list, tool_version: str,
                   build_key: str, executed_at: str, recorded_at: str,
                   artifacts: list[str] | None,
                   identity_self_established: bool, build_key_cross_checked: bool,
                   known_build: bool, build_id: str | None,
                   capabilities_enabled: list[str] | None = None) -> dict:
    """research/instrument-runs/<timestamp>/manifest.json, conforming to
    research/schema/instrument-run-manifest.schema.json.

    instrument_level 'eri' + capabilities_enabled ['I-01'] only (this pass
    implements nothing else). verify_install_before/after are null: this
    tool never invokes tools/inventory/verify_install.py itself, and the
    schema's own instrument_level=='eri' conditional (as opposed to its
    'ipp' branch, which forces both fields to type object) leaves null
    legal here -- research/instrument-runs/README.md states the before/after
    pair is RECOMMENDED for ERI and MANDATORY only for IPP (plan.md 8.5); the
    schema enforces exactly that asymmetry. If a caller ran verify_install.py
    around this session by hand, that result belongs in a hand-edited copy
    of this manifest, not in this tool's own output -- this tool has no way
    to know it happened.

    Envelope fields (evidence_level/confidence/sources/oracle/build_key/
    recorded_at) are inherited from kb-record.schema.json's own
    #/$defs/envelope via the schema's allOf, exactly as the schema's own
    header comment states; they are supplied here as plain properties of
    the returned dict because that composition is structural on the JSON
    Schema side, not something this Python function needs to mirror.
    confidence is kept below 0.80 deliberately: this record's oracle is
    'runtime-reflection', which kb-record.schema.json's class_p_shape does
    NOT admit for class P, so a confidence >= 0.80 would trigger the
    envelope's 'sources needs >= 2 independent methods' rule -- and a
    single instrument run legitimately has exactly one source, itself.

    claim_type is 'other' with a one-sentence claim_type_note: a manifest's
    claim ("this run happened, against this build, with these arguments,
    with exactly these capabilities on") is a bookkeeping fact about the
    RESEARCH PROCESS, not one of the plan.md 10.5 matrix's fourteen rows
    about the game -- tools/kb/validate.py's own lint_record() demands
    claim_type by default (EV-04) and, once it is 'other', a justification
    field naming why no row fits (JUSTIFICATION_KEYS); omitting claim_type
    entirely is legal per kb-record.schema.json ("optional") but fails this
    project's stricter validator policy, so it is supplied here rather than
    left for every future caller to rediscover.

    identity_self_established/build_key_cross_checked/known_build/build_id
    (research/schema/instrument-run-manifest.schema.json's own properties for
    each, added for LOG-0048/LOG-0049): the same identity-self-establishment
    facts build_i01_document() records on its sibling output document, kept
    on this manifest too so the run's own bookkeeping record states plainly
    HOW its build_key was obtained, not only what it is -- see
    establish_build_identity()'s docstring for the full rule this encodes.

    capabilities_enabled: which I-* ids actually ran this session -- ['I-01']
    when None/omitted (this function's original, still-default behaviour,
    preserved so every caller written before I-02 existed keeps working
    unchanged), or ['I-01', 'I-02'] when the caller also ran I-02 in the same
    session (I-02 depends on I-01's own base_address/image_size read, so it
    is never enabled alone). 'sources' below is derived from this same list,
    one {'method': <id>} entry per capability actually enabled, rather than
    hardcoding I-01 -- each enabled capability is a distinct method this
    run's own claim ("this run happened, with exactly these capabilities
    on") rests on.
    """
    capability_ids = list(capabilities_enabled) if capabilities_enabled else [CAPABILITY_ID]
    return {
        "run_id": run_id,
        "instrument_level": "eri",
        "arguments": list(arguments),
        "tool_version": tool_version,
        "capabilities_enabled": capability_ids,
        "verify_install_before": None,
        "verify_install_after": None,
        "executed_at": executed_at,
        "artifacts": artifacts,
        "evidence_level": "OBSERVED",
        "confidence": 0.75,
        "sources": [{"method": capability_id} for capability_id in capability_ids],
        "oracle": ["runtime-reflection"],
        "claim_type": "other",
        "claim_type_note": (
            "a manifest records that a research instrument ran, not a fact "
            "about the game; no plan.md 10.5 matrix row describes an "
            "instrument-run bookkeeping record (research/schema/"
            "instrument-run-manifest.schema.json 'claim_type_note')."
        ),
        "build_key": build_key,
        # identity self-establishment, mirrored from the I-01 document (see
        # build_i01_document's own comment on these same four fields and
        # establish_build_identity's docstring) -- LOG-0048/LOG-0049.
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "notes": (
            "Written by %s (capabilities: %s). recorded_at/executed_at are "
            "real wall-clock time unless --recorded-at pinned them; "
            "--no-timestamp affects only the sibling I-01 output document's "
            "own 'recorded_at' field, never this manifest's, because "
            "instrument-run-manifest.schema.json requires both to be "
            "non-null timestamps at all times." %
            (GENERATOR_NAME, ", ".join(capability_ids))
        ),
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

DEFAULT_PROCESS_NAME = "MISERY-Win64-Shipping.exe"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eri.py",
        description=(
            "ERI capability I-01: find the target process, open it "
            "PROCESS_QUERY_INFORMATION|PROCESS_VM_READ only, and read the "
            "base address and image size of its own module (plan.md 8.2). "
            "Optionally also capability I-02 (--run-i02): verify the RF-05 "
            "candidate GUObjectArray against live structural behaviour. "
            "Optionally also capability I-03 (--run-i03): decode an "
            "FNameEntryId to text via the RF-06 candidate FNamePool, and "
            "optionally (--run-i03-reflection, needs --run-i02 too) a "
            "bounded '/Script/MISERY live reflection' probe over live "
            "UObject names. Writes nothing, injects nothing, hooks nothing, "
            "calls no game function."),
    )
    parser.add_argument(
        "--process-name", default=DEFAULT_PROCESS_NAME, metavar="NAME",
        help="exact (case-insensitive) executable filename to find; NEVER a "
             "substring match (default: %s)" % DEFAULT_PROCESS_NAME)
    parser.add_argument(
        "--build-key", required=False, default=None, metavar="sha256:HEX",
        help="OPTIONAL cross-check against the build_key this run establishes "
             "for ITSELF by hashing the live process's own module.exe_path -- "
             "'sha256:<64 lowercase hex>' (research/schema/kb-record.schema.json "
             "#/$defs/build_key). NEVER the source of truth (LOG-0048/LOG-0049: "
             "a cached/supplied build_key silently outlived a Steam update once "
             "already). Omit this flag -- the normal, preferred way to invoke "
             "this tool -- and the self-computed hash becomes the authoritative "
             "build_key. If given and it does NOT match what this run "
             "independently computed, the run fails loudly with "
             "BuildKeyMismatchError before writing anything; if it matches, the "
             "output documents record that it was independently confirmed.")
    parser.add_argument(
        "--recorded-at", default=None, metavar="ISO8601",
        help="pin the I-01 document's and the manifest's timestamp fields to "
             "this exact ISO-8601 UTC value, for a byte-identical rerun")
    parser.add_argument(
        "--no-timestamp", action="store_true",
        help="omit recorded_at from the I-01 output document (sets it to "
             "null), so two runs against an unchanged target produce "
             "byte-identical JSON for that document. Has no effect on "
             "manifest.json, whose recorded_at/executed_at the schema "
             "requires to be non-null always -- use --recorded-at for a "
             "deterministic manifest too.")
    parser.add_argument(
        "--out", default=None, metavar="PATH",
        help="I-01 process-info JSON output path")
    parser.add_argument(
        "--manifest-out", default=None, metavar="PATH",
        help="manifest.json output path (research/schema/"
             "instrument-run-manifest.schema.json)")
    parser.add_argument(
        "--run-dir", default=None, metavar="DIR",
        help="convenience: sets --out to <run-dir>/i01-process-info.json and "
             "--manifest-out to <run-dir>/manifest.json when either is not "
             "given explicitly, and sets the manifest's run_id to this "
             "directory's own basename (research/instrument-runs/<timestamp>/ "
             "by convention -- see research/instrument-runs/README.md)")
    parser.add_argument(
        "--run-id", default=None, metavar="ID",
        help="manifest.json's run_id; defaults to the basename of --run-dir "
             "if given, else the run's own executed_at timestamp")
    parser.add_argument(
        "--json", action="store_true",
        help="also print a machine-readable one-line summary to stdout")
    parser.add_argument(
        "--run-i02", action="store_true",
        help="also run capability I-02: verify the RF-05 candidate "
             "GUObjectArray against LIVE structural behaviour (plan.md 8.2, "
             "research/evidence/RF-05/README.md's own 'What a runtime "
             "observation would need to show to move this above HYPOTHESIS' "
             "section). Requires I-01's own base_address/image_size from "
             "THIS SAME run -- never enabled standalone. A refuted "
             "candidate is a valid, reported research outcome, not a "
             "failed run (see eri.py's module docstring 'STRUCTURAL "
             "REFUTATION IS A RESULT, NOT AN ERROR').")
    parser.add_argument(
        "--guobjectarray-rva", default=None, metavar="HEX",
        help="override the candidate GUObjectArray RVA I-02 checks "
             "(default: the RF-05 candidate, 0x%x -- research/evidence/"
             "RF-05/README.md). Accepts '0x...' or a plain decimal/hex "
             "string as Python's int(x, 0) understands it." %
             DEFAULT_GUOBJECTARRAY_RVA)
    parser.add_argument(
        "--i02-sample-size", type=int, default=DEFAULT_I02_SAMPLE_SIZE,
        metavar="N",
        help="I-02 check 2: how many non-null sampled objects' vtable "
             "pointers to examine before stopping (default: %d)" %
             DEFAULT_I02_SAMPLE_SIZE)
    parser.add_argument(
        "--i02-poll-interval-seconds", type=float,
        default=DEFAULT_I02_POLL_INTERVAL_SECONDS, metavar="SECONDS",
        help="I-02 check 3: how long to wait between the two NumElements "
             "reads (default: %.1f)" % DEFAULT_I02_POLL_INTERVAL_SECONDS)
    parser.add_argument(
        "--i02-max-scan-indices", type=int,
        default=DEFAULT_I02_MAX_SCAN_INDICES, metavar="N",
        help="I-02 check 2: hard cap on how many object-array index slots "
             "may be looked at while searching for --i02-sample-size "
             "non-null objects, so a corrupted (implausibly huge, or "
             "all-null) NumElements cannot turn the sample walk into an "
             "unbounded scan (default: %d)" % DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--i02-out", default=None, metavar="PATH",
        help="I-02 GUObjectArray-verification JSON output path; defaults "
             "to <run-dir>/i02-guobjectarray.json when --run-dir is given")
    parser.add_argument(
        "--run-i03", action="store_true",
        help="also run capability I-03: decode an FNameEntryId to text via "
             "the RF-06 candidate FNamePool (plan.md 8.2, research/evidence/"
             "RF-06/README.md's own 'What a runtime observation would need "
             "to show to move this above HYPOTHESIS' steps 1-2). By default "
             "decodes FNameEntryId 0 (EName::None), the one case with a "
             "known expected answer ('None') -- see --i03-name-entry-id. "
             "Requires I-01's own base_address/image_size from THIS SAME "
             "run -- never enabled standalone. A decode that does not match "
             "the expected text for id=0 is a valid, reported structural "
             "refutation, not a failed run (see eri.py's module docstring "
             "'STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR').")
    parser.add_argument(
        "--namepool-rva", default=None, metavar="HEX",
        help="override the candidate FNamePool/NamePoolData RVA I-03 reads "
             "(default: the RF-06 candidate, 0x%x -- research/evidence/"
             "RF-06/README.md). Accepts '0x...' or a plain decimal/hex "
             "string as Python's int(x, 0) understands it." %
             DEFAULT_NAMEPOOL_RVA)
    parser.add_argument(
        "--name-pool-initialized-rva", default=None, metavar="HEX",
        help="override the candidate bNamePoolInitialized guard-byte RVA "
             "I-03 reads (default: the RF-06 candidate, 0x%x -- "
             "research/evidence/RF-06/README.md)." %
             DEFAULT_NAME_POOL_INITIALIZED_RVA)
    parser.add_argument(
        "--i03-name-entry-id", type=lambda s: int(s, 0),
        default=0, metavar="ID",
        help="which FNameEntryId to decode (default: 0, EName::None -- the "
             "one id with a known expected decoded text, 'None'). Accepts "
             "'0x...' or a plain decimal/hex string.")
    parser.add_argument(
        "--i03-out", default=None, metavar="PATH",
        help="I-03 FNamePool-decode JSON output path; defaults to "
             "<run-dir>/i03-fnamepool.json when --run-dir is given")
    parser.add_argument(
        "--run-i03-reflection", action="store_true",
        help="also run the '/Script/MISERY live reflection' probe: search "
             "a bounded sample of live UObjects (found via I-02's own "
             "chunk-walk arithmetic) for one whose decoded name equals the "
             "literal leaf FName 'MISERY'. Requires BOTH --run-i02 (for the "
             "GUObjectArray objects pointer/NumElements) and --run-i03 (for "
             "the FNamePool decode) in THIS SAME run -- never enabled "
             "standalone. This is a bounded, NOT exhaustive search: a miss "
             "is reported honestly as 'not found in this sample', never as "
             "a refutation of anything (see sample_object_names()'s own "
             "docstring in eri.py).")
    parser.add_argument(
        "--i03-reflection-sample-size", type=int,
        default=DEFAULT_I03_REFLECTION_SAMPLE_SIZE, metavar="N",
        help="--run-i03-reflection: how many non-null live objects' names "
             "to decode before stopping (default: %d -- deliberately larger "
             "than --i02-sample-size's own default, since this is a needle "
             "search for one specific object rather than a statistical "
             "vtable-plausibility sample; see DEFAULT_I03_REFLECTION_SAMPLE_"
             "SIZE's own comment in eri.py)" % DEFAULT_I03_REFLECTION_SAMPLE_SIZE)
    parser.add_argument(
        "--i03-reflection-max-scan-indices", type=int,
        default=DEFAULT_I02_MAX_SCAN_INDICES, metavar="N",
        help="--run-i03-reflection: hard cap on how many object-array index "
             "slots may be looked at while searching for "
             "--i03-reflection-sample-size non-null objects (default: %d, "
             "same default as --i02-max-scan-indices)" %
             DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--name-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::NamePrivate's own "
             "FNameEntryId component (default: 0x%x -- derived from "
             "UObjectBase.h and cross-checked against RF-05's own "
             "InternalIndex==+0xc finding; see DEFAULT_NAME_PRIVATE_OFFSET's "
             "own comment in eri.py)." % DEFAULT_NAME_PRIVATE_OFFSET)
    parser.add_argument(
        "--run-i04", action="store_true",
        help="also run capability I-04: dump UClass instances with their "
             "inheritance-adjacent identity (plan.md 8.2, 'Дамп UClass с "
             "иерархией наследования') by walking EVERY located UObject in "
             "I-02's own GUObjectArray (not a bounded sample), decoding "
             "each one's own NamePrivate via I-03's own FNamePool decode, "
             "and classifying which ones ARE UClass instances via a "
             "ClassPrivate self-reference fixed point -- never by reading "
             "any UClass/UStruct/UField-specific field (see eri.py's own "
             "module docstring, 'WHAT I-04 IS', for the exact algorithm and "
             "its scope boundary). Requires BOTH --run-i02 and --run-i03 in "
             "THIS SAME run -- never enabled standalone. Writes a raw JSON "
             "summary (--i04-out) and a SEPARATE classes.jsonl artifact "
             "(--classes-jsonl-out): every /Script/MISERY class found, plus "
             "a small bounded /Game sample -- never the hundreds of native "
             "engine classes this walk also finds (their total count is "
             "reported, never persisted).")
    parser.add_argument(
        "--class-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::ClassPrivate "
             "(default: 0x%x -- derived from UObjectBase.h's own member "
             "declaration order; see DEFAULT_CLASS_PRIVATE_OFFSET's own "
             "comment in eri.py)." % DEFAULT_CLASS_PRIVATE_OFFSET)
    parser.add_argument(
        "--outer-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::OuterPrivate "
             "(default: 0x%x -- the ONE genuinely new offset I-04 "
             "introduces; see DEFAULT_OUTER_PRIVATE_OFFSET's own comment "
             "in eri.py)." % DEFAULT_OUTER_PRIVATE_OFFSET)
    parser.add_argument(
        "--i04-max-scan-indices", type=int, default=DEFAULT_I02_MAX_SCAN_INDICES,
        metavar="N",
        help="I-04: hard cap on how many GUObjectArray index slots are "
             "examined -- I-04 is NOT a bounded sample like I-02/I-03's own "
             "probes, it walks every located object up to this cap "
             "(default: %d, same default as --i02-max-scan-indices)" %
             DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--i04-max-outer-depth", type=int, default=DEFAULT_I04_MAX_OUTER_DEPTH,
        metavar="N",
        help="I-04: bound on how many Outer hops object_path construction "
             "follows before treating the walk as a traversal failure "
             "(default: %d)" % DEFAULT_I04_MAX_OUTER_DEPTH)
    parser.add_argument(
        "--i04-max-fixed-point-passes", type=int,
        default=DEFAULT_I04_MAX_FIXED_POINT_PASSES, metavar="N",
        help="I-04: bound on how many passes the ClassPrivate self-"
             "reference fixed point iterates before giving up on "
             "convergence (default: %d)" % DEFAULT_I04_MAX_FIXED_POINT_PASSES)
    parser.add_argument(
        "--i04-game-sample-cap", type=int, default=DEFAULT_I04_GAME_SAMPLE_CAP,
        metavar="N",
        help="I-04: cap on how many /Game/* UClass instances (Blueprint-"
             "generated ones prioritized) are WRITTEN to classes.jsonl -- "
             "the full count found is still reported in the raw i04 "
             "document and CLI summary regardless of this cap (default: "
             "%d)" % DEFAULT_I04_GAME_SAMPLE_CAP)
    parser.add_argument(
        "--i04-out", default=None, metavar="PATH",
        help="I-04 raw JSON output path; defaults to <run-dir>/"
             "i04-classes.json when --run-dir is given")
    parser.add_argument(
        "--classes-jsonl-out", default=None, metavar="PATH",
        help="I-04's classes.jsonl output path (research/schema/"
             "reflection-record.schema.json's class_record branch); "
             "defaults to <run-dir>/classes.jsonl when --run-dir is given. "
             "The operator must pass this explicitly to write to the final "
             "committed location, research/reflection/<build_id>/"
             "classes.jsonl -- this tool does not auto-derive that path "
             "from build identity, matching every other per-capability "
             "output path in this file")
    return parser


def _resolve_output_paths(args: argparse.Namespace) -> tuple[str, str]:
    out_path = args.out
    manifest_path = args.manifest_out
    if args.run_dir:
        if out_path is None:
            out_path = os.path.join(args.run_dir, "i01-process-info.json")
        if manifest_path is None:
            manifest_path = os.path.join(args.run_dir, "manifest.json")
    if not out_path or not manifest_path:
        raise ValueError(
            "both --out and --manifest-out are required unless --run-dir is "
            "given (it supplies defaults for whichever of the two is not "
            "passed explicitly)")
    return out_path, manifest_path


def _resolve_i02_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i02 was not given (nothing to resolve). Otherwise the
    I-02 output path: --i02-out if given explicitly, else
    <run-dir>/i02-guobjectarray.json via the same --run-dir convenience
    --out/--manifest-out already use. Raises ValueError, at parse time,
    before any handle is opened, if --run-i02 was given with neither
    --i02-out nor --run-dir to derive it from -- the same "fail loudly
    before doing any work" shape _resolve_output_paths above already has for
    --out/--manifest-out.
    """
    if not args.run_i02:
        return None
    if args.i02_out:
        return args.i02_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i02-guobjectarray.json")
    raise ValueError(
        "--run-i02 requires --i02-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i02-guobjectarray.json)")


def _resolve_i03_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i03 was not given (nothing to resolve). Otherwise the
    I-03 output path: --i03-out if given explicitly, else
    <run-dir>/i03-fnamepool.json via the same --run-dir convenience
    --out/--manifest-out/--i02-out already use. Raises ValueError, before
    any handle is opened, if --run-i03 was given with neither --i03-out nor
    --run-dir to derive it from -- identical shape to
    _resolve_i02_output_path above.
    """
    if not args.run_i03:
        return None
    if args.i03_out:
        return args.i03_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i03-fnamepool.json")
    raise ValueError(
        "--run-i03 requires --i03-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i03-fnamepool.json)")


def _validate_i03_reflection_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i03-reflection
    was given without BOTH --run-i02 (the probe needs its own objects
    pointer/NumElements) and --run-i03 (the probe needs its own FNamePool
    decode function) in this SAME invocation -- the same "fail loudly before
    doing any work" discipline every other CLI-shape check in this file
    already follows, rather than discovering the missing dependency only
    after I-01 (and possibly I-02 or I-03 alone) has already run.
    """
    if not args.run_i03_reflection:
        return
    missing = []
    if not args.run_i02:
        missing.append("--run-i02")
    if not args.run_i03:
        missing.append("--run-i03")
    if missing:
        raise ValueError(
            "--run-i03-reflection requires %s in this same invocation -- "
            "the '/Script/MISERY' probe reuses I-02's own GUObjectArray "
            "objects pointer/NumElements and I-03's own FNamePool decode, "
            "and is never run standalone." % " and ".join(missing))


def _resolve_i04_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i04 was not given. Otherwise the I-04 raw-JSON output
    path: --i04-out if given explicitly, else <run-dir>/i04-classes.json via
    the same --run-dir convenience --out/--i02-out/--i03-out already use.
    Raises ValueError, before any handle is opened, if --run-i04 was given
    with neither --i04-out nor --run-dir -- identical shape to
    _resolve_i02_output_path/_resolve_i03_output_path above.
    """
    if not args.run_i04:
        return None
    if args.i04_out:
        return args.i04_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i04-classes.json")
    raise ValueError(
        "--run-i04 requires --i04-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i04-classes.json)")


def _resolve_classes_jsonl_path(args: argparse.Namespace) -> str | None:
    """None when --run-i04 was not given. Otherwise I-04's classes.jsonl
    output path: --classes-jsonl-out if given explicitly, else
    <run-dir>/classes.jsonl -- the SAME --run-dir convenience every other
    per-capability output path in this file uses, deliberately NOT an
    auto-derived research/reflection/<build_id>/ path (see
    --classes-jsonl-out's own help text: the operator passes that
    explicitly when writing to the final committed location).
    """
    if not args.run_i04:
        return None
    if args.classes_jsonl_out:
        return args.classes_jsonl_out
    if args.run_dir:
        return os.path.join(args.run_dir, "classes.jsonl")
    raise ValueError(
        "--run-i04 requires --classes-jsonl-out unless --run-dir is given "
        "(it supplies the default <run-dir>/classes.jsonl)")


def _validate_i04_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i04 was
    given without BOTH --run-i02 (I-04 reuses its own GUObjectArray objects
    pointer/NumElements, never re-walking the array from scratch) and
    --run-i03 (I-04 reuses its own FNamePool decode, never adding a second
    FNamePool-reading code path) in this SAME invocation -- the identical
    "fail loudly before doing any work" shape
    _validate_i03_reflection_requirements above already established.
    """
    if not args.run_i04:
        return
    missing = []
    if not args.run_i02:
        missing.append("--run-i02")
    if not args.run_i03:
        missing.append("--run-i03")
    if missing:
        raise ValueError(
            "--run-i04 requires %s in this same invocation -- I-04 reuses "
            "I-02's own GUObjectArray objects pointer/NumElements and "
            "I-03's own FNamePool decode, and is never run standalone." %
            " and ".join(missing))


def _parse_int_literal(value: str | None, default: int, flag_name: str) -> int:
    """*default* when *value* is None (the normal case); otherwise
    int(value, 0) so '0x7a78ed0', '0X7A78ED0' and a plain decimal string are
    all accepted -- matching Python's own int-literal grammar rather than
    inventing a narrower one. Raises ValueError (caught by main()'s existing
    except clause, exactly like a malformed --build-key) on anything else,
    BEFORE any handle is opened. Shared by every RVA/offset-override CLI
    flag in this file (--guobjectarray-rva, --namepool-rva,
    --name-pool-initialized-rva, --name-private-offset) so the same parsing
    rule and error message shape is not re-derived once per flag.
    """
    if value is None:
        return default
    try:
        return int(value, 0)
    except ValueError:
        raise ValueError(
            "%s %r is not a valid integer literal -- give a hex value like "
            "'0x7a78ed0' or a plain decimal string." % (flag_name, value))


def _parse_guobjectarray_rva(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_GUOBJECTARRAY_RVA, "--guobjectarray-rva")


def _parse_namepool_rva(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_NAMEPOOL_RVA, "--namepool-rva")


def _parse_name_pool_initialized_rva(value: str | None) -> int:
    return _parse_int_literal(
        value, DEFAULT_NAME_POOL_INITIALIZED_RVA, "--name-pool-initialized-rva")


def _parse_name_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_NAME_PRIVATE_OFFSET, "--name-private-offset")


def _parse_class_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_CLASS_PRIVATE_OFFSET, "--class-private-offset")


def _parse_outer_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_OUTER_PRIVATE_OFFSET, "--outer-private-offset")


def _write_guarded(document: dict, path: str, *, what: str) -> str:
    """dump_json(document) to *path*, refusing any path inside the game
    installation (plan.md decision D-01) and creating the parent directory
    if needed. Returns the resolved path pathguard checked and wrote to.
    """
    resolved = pathguard.check_output_path(
        path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what=what)
    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return resolved


def _write_guarded_jsonl(records: list, path: str, *, what: str) -> str:
    """dump_jsonl(records) to *path* -- the SAME pathguard-checked,
    parent-directory-creating write _write_guarded() above performs for a
    single JSON document, but for I-04's own classes.jsonl (a LIST of
    records, one JSON object per line, never a single pretty-printed
    document). An empty *records* list writes a legitimately empty file --
    "zero records", not an error; see research/reflection/README.md's own
    "Пустой JSONL самодостаточен и честен" section for why an empty JSONL
    is never treated as a stub/placeholder needing special-casing here.
    """
    resolved = pathguard.check_output_path(
        path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what=what)
    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_jsonl(records))
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.build_key is not None:
            # Format only, at parse time, cheap and before any handle is
            # opened -- exactly like before. This is NOT a truth check: a
            # well-formed but WRONG --build-key is caught later, only after
            # this run has self-computed its own build_key, by
            # establish_build_identity() raising BuildKeyMismatchError
            # (LOG-0048/LOG-0049). See the module docstring's "IDENTITY IS
            # SELF-ESTABLISHED" section.
            validate_build_key(args.build_key)
        out_path, manifest_path = _resolve_output_paths(args)
        i02_out_path = _resolve_i02_output_path(args)  # None unless --run-i02
        i03_out_path = _resolve_i03_output_path(args)  # None unless --run-i03
        i04_out_path = _resolve_i04_output_path(args)  # None unless --run-i04
        classes_jsonl_path = _resolve_classes_jsonl_path(args)  # None unless --run-i04
        guobjectarray_rva = _parse_guobjectarray_rva(args.guobjectarray_rva)
        namepool_rva = _parse_namepool_rva(args.namepool_rva)
        name_pool_initialized_rva = _parse_name_pool_initialized_rva(
            args.name_pool_initialized_rva)
        name_private_offset = _parse_name_private_offset(args.name_private_offset)
        class_private_offset = _parse_class_private_offset(args.class_private_offset)
        outer_private_offset = _parse_outer_private_offset(args.outer_private_offset)
        # --run-i03-reflection needs both --run-i02 and --run-i03 in this
        # same invocation -- checked here, before any handle is opened, same
        # "fail loudly before doing any work" discipline as every other
        # CLI-shape check in this function.
        _validate_i03_reflection_requirements(args)
        # --run-i04 needs both --run-i02 and --run-i03 too -- identical
        # discipline, checked before any handle is opened.
        _validate_i04_requirements(args)

        # Layer 1 first, exactly like the pyghidra_scripts family: a refused
        # output path costs nothing, so it is checked before a single Win32
        # handle is opened.
        pathguard.check_output_path(
            out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what="--out")
        pathguard.check_output_path(
            manifest_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what="--manifest-out")
        if i02_out_path is not None:
            pathguard.check_output_path(
                i02_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i02-out")
        if i03_out_path is not None:
            pathguard.check_output_path(
                i03_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i03-out")
        if i04_out_path is not None:
            pathguard.check_output_path(
                i04_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i04-out")
        if classes_jsonl_path is not None:
            pathguard.check_output_path(
                classes_jsonl_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--classes-jsonl-out")

        i01_recorded_at = (
            args.recorded_at if args.recorded_at
            else (None if args.no_timestamp else now_iso_utc()))
        manifest_timestamp = args.recorded_at if args.recorded_at else now_iso_utc()

        run_id = args.run_id
        if not run_id:
            run_id = (os.path.basename(os.path.normpath(args.run_dir))
                      if args.run_dir else manifest_timestamp)

        api = Win32Api()
        result = run_i01(api, args.process_name)

        # Identity is SELF-established here, from result["exe_path"] -- the
        # file the OS loader actually mapped for the process this run just
        # found -- BEFORE any output document is built or written. A
        # mismatched --build-key raises BuildKeyMismatchError right here,
        # which means NOTHING this run produces (I-01 document, I-02
        # document, manifest) is ever written for a run whose supplied
        # build_key does not match what was actually observed
        # (LOG-0048/LOG-0049).
        identity = establish_build_identity(
            exe_path=result["exe_path"], given_build_key=args.build_key)

        # I-02, if requested, runs BEFORE anything is written -- same reason
        # as identity above: if run_i02() raises (a genuine tool failure,
        # never a mere structural refutation -- see run_i02()'s own
        # docstring), this run must write NOTHING at all, not an I-01
        # document with no manifest to explain it. I-02 opens its OWN handle
        # via the tool's one open_process_read_only()/Win32Api.open_process
        # call site -- the SAME PROCESS_ACCESS_RIGHTS-only access I-01
        # itself already established and closed; PROCESS_ACCESS_RIGHTS is
        # unchanged (still PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only,
        # nothing more), and ReadProcessMemory needs nothing beyond the
        # PROCESS_VM_READ bit that access already carries.
        i02_result = None
        if args.run_i02:
            i02_handle = open_process_read_only(api, result["pid"])
            try:
                i02_result = run_i02(
                    api, i02_handle, result["base_address"], result["image_size_bytes"],
                    guobjectarray_rva=guobjectarray_rva,
                    sample_size=args.i02_sample_size,
                    poll_interval_seconds=args.i02_poll_interval_seconds,
                    max_scan_indices=args.i02_max_scan_indices)
            finally:
                api.close_handle(i02_handle)

        # I-03, if requested, ALSO runs before anything is written -- same
        # reason as I-02 above. I-03 opens its OWN fresh handle (I-02's own
        # handle, if any, is already closed by this point) via the tool's
        # one open_process_read_only()/Win32Api.open_process call site; the
        # "/Script/MISERY" reflection probe (--run-i03-reflection), if also
        # requested, runs inside this SAME handle's try/finally, reusing
        # i02_result's own already-fetched objects_ptr/num_elements
        # (_validate_i03_reflection_requirements already guaranteed i02_result
        # is not None here whenever args.run_i03_reflection is True).
        i03_result = None
        misery_reflection_result = None
        # I-04, if requested, runs in this SAME i03_handle's try/finally --
        # it reuses i02_result's own objects_ptr/num_elements AND i03_result's
        # own namepool_live_va (_validate_i04_requirements already guaranteed
        # both are not None here whenever args.run_i04 is True), the
        # identical "reuse, never re-walk/re-establish" reasoning
        # --run-i03-reflection's own block above already follows.
        i04_result = None
        i04_class_buckets = None
        i04_game_sample = None
        if args.run_i03:
            i03_handle = open_process_read_only(api, result["pid"])
            try:
                i03_result = run_i03(
                    api, i03_handle, result["base_address"], result["image_size_bytes"],
                    namepool_rva=namepool_rva,
                    name_pool_initialized_rva=name_pool_initialized_rva,
                    name_entry_id=args.i03_name_entry_id)
                if args.run_i03_reflection:
                    misery_reflection_result = sample_object_names(
                        api, i03_handle, i02_result["objects_ptr_live_va"],
                        i02_result["num_elements"], i03_result["namepool_live_va"],
                        name_private_offset,
                        sample_size=args.i03_reflection_sample_size,
                        max_scan_indices=args.i03_reflection_max_scan_indices)
                if args.run_i04:
                    i04_result = run_i04(
                        api, i03_handle, result["base_address"], result["image_size_bytes"],
                        i02_result["objects_ptr_live_va"], i02_result["num_elements"],
                        i03_result["namepool_live_va"],
                        class_private_offset=class_private_offset,
                        name_private_offset=name_private_offset,
                        outer_private_offset=outer_private_offset,
                        max_scan_indices=args.i04_max_scan_indices,
                        max_outer_depth=args.i04_max_outer_depth,
                        max_fixed_point_passes=args.i04_max_fixed_point_passes)
                    if i04_result["seed_found"]:
                        i04_class_buckets = classify_classes_by_module(i04_result["classes"])
                        i04_game_sample = select_game_sample(
                            i04_class_buckets["game"], cap=args.i04_game_sample_cap)
                    else:
                        i04_class_buckets = {"misery": [], "game": [], "other": []}
                        i04_game_sample = []
            finally:
                api.close_handle(i03_handle)

        document = build_i01_document(
            result=result, build_key=identity["build_key"], recorded_at=i01_recorded_at,
            identity_self_established=identity["identity_self_established"],
            build_key_cross_checked=identity["build_key_cross_checked"],
            known_build=identity["known_build"], build_id=identity["build_id"])
        written_out = _write_guarded(document, out_path, what="--out")

        capabilities_enabled = [CAPABILITY_ID]
        artifacts = [_repo_relative(written_out)]
        i02_document = None
        written_i02_out = None
        if i02_result is not None:
            i02_document = build_i02_document(
                result=i02_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_i02_out = _write_guarded(i02_document, i02_out_path, what="--i02-out")
            capabilities_enabled.append(CAPABILITY_ID_I02)
            artifacts.append(_repo_relative(written_i02_out))

        i03_document = None
        written_i03_out = None
        if i03_result is not None:
            i03_document = build_i03_document(
                result=i03_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"],
                misery_reflection=misery_reflection_result)
            written_i03_out = _write_guarded(i03_document, i03_out_path, what="--i03-out")
            capabilities_enabled.append(CAPABILITY_ID_I03)
            artifacts.append(_repo_relative(written_i03_out))

        i04_document = None
        written_i04_out = None
        written_classes_jsonl = None
        if i04_result is not None:
            i04_document = build_i04_document(
                result=i04_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"],
                misery_classes_count=len(i04_class_buckets["misery"]),
                game_classes_total_count=len(i04_class_buckets["game"]),
                game_classes_sample_count=len(i04_game_sample),
                other_classes_count=len(i04_class_buckets["other"]))
            written_i04_out = _write_guarded(i04_document, i04_out_path, what="--i04-out")
            capabilities_enabled.append(CAPABILITY_ID_I04)
            artifacts.append(_repo_relative(written_i04_out))

            # classes.jsonl is a SEPARATE artifact, in the format research/
            # schema/reflection-record.schema.json's class_record branch
            # defines -- every /Script/MISERY class (cross_checked=True,
            # confidence 0.90) plus the bounded /Game sample
            # (cross_checked=False, confidence 0.75); see
            # build_i04_class_record()'s own docstring for the full MIX-SPLIT
            # grading reasoning. recorded_at here is manifest_timestamp, NOT
            # i01_recorded_at -- kb-record.schema.json's own envelope
            # requires a non-null recorded_at on every row always, unlike the
            # raw i0N-*.json documents, which may carry a null one under
            # --no-timestamp.
            classes_jsonl_rows = (
                [build_i04_class_record(
                    entry, build_key=identity["build_key"],
                    recorded_at=manifest_timestamp, cross_checked=True)
                 for entry in i04_class_buckets["misery"]] +
                [build_i04_class_record(
                    entry, build_key=identity["build_key"],
                    recorded_at=manifest_timestamp, cross_checked=False)
                 for entry in i04_game_sample])
            written_classes_jsonl = _write_guarded_jsonl(
                classes_jsonl_rows, classes_jsonl_path, what="--classes-jsonl-out")
            artifacts.append(_repo_relative(written_classes_jsonl))

        manifest = build_manifest(
            run_id=run_id, arguments=list(sys.argv[1:] if argv is None else argv),
            tool_version=GENERATOR_VERSION, build_key=identity["build_key"],
            executed_at=manifest_timestamp, recorded_at=manifest_timestamp,
            artifacts=artifacts,
            identity_self_established=identity["identity_self_established"],
            build_key_cross_checked=identity["build_key_cross_checked"],
            known_build=identity["known_build"], build_id=identity["build_id"],
            capabilities_enabled=capabilities_enabled)
        written_manifest = _write_guarded(manifest, manifest_path, what="--manifest-out")

        if args.json:
            summary = {
                "pid": result["pid"],
                "process_name": result["process_name"],
                "base_address_hex": document["base_address_hex"],
                "image_size_bytes": result["image_size_bytes"],
                "build_key": identity["build_key"],
                "build_key_cross_checked": identity["build_key_cross_checked"],
                "known_build": identity["known_build"],
                "build_id": identity["build_id"],
                "out": written_out,
                "manifest_out": written_manifest,
            }
            if i02_document is not None:
                summary["i02_out"] = written_i02_out
                summary["i02_structurally_consistent"] = i02_document["structurally_consistent"]
            if i03_document is not None:
                summary["i03_out"] = written_i03_out
                summary["i03_decoded_as_expected"] = i03_document["decoded_as_expected"]
                if misery_reflection_result is not None:
                    summary["i03_misery_found"] = misery_reflection_result["misery_found"]
            if i04_document is not None:
                summary["i04_out"] = written_i04_out
                summary["classes_jsonl_out"] = written_classes_jsonl
                summary["i04_seed_found"] = i04_document["seed_found"]
                summary["i04_misery_classes_count"] = i04_document["misery_classes_count"]
                summary["i04_game_classes_total_count"] = (
                    i04_document["game_classes_total_count"])
                summary["i04_game_classes_sample_count"] = (
                    i04_document["game_classes_sample_count"])
                summary["i04_other_classes_count"] = i04_document["other_classes_count"]
            print(dump_json(summary))
        else:
            print(
                "pid=%d base_address=%s image_size_bytes=%d"
                % (result["pid"], document["base_address_hex"], result["image_size_bytes"]),
                file=sys.stderr)
            print(
                "build_key=%s (%s) known_build=%s build_id=%s" % (
                    identity["build_key"],
                    "self-computed, independently confirmed by --build-key"
                    if identity["build_key_cross_checked"] else "self-computed",
                    identity["known_build"],
                    identity["build_id"]),
                file=sys.stderr)
            print("written: %s" % written_out, file=sys.stderr)
            if i02_document is not None:
                print(
                    "I-02: guobjectarray_live_va=%s structurally_consistent=%s "
                    "(check_struct_invariants=%s check_sample_walk=%s "
                    "check_growth_non_decreasing=%s)" % (
                        i02_document["guobjectarray_live_va_hex"],
                        i02_document["structurally_consistent"],
                        i02_document["check_struct_invariants"]["pass"],
                        i02_document["check_sample_walk"]["pass"],
                        i02_document["check_growth_non_decreasing"]["pass"]),
                    file=sys.stderr)
                print("written: %s" % written_i02_out, file=sys.stderr)
            if i03_document is not None:
                print(
                    "I-03: namepool_live_va=%s pool_initialized=%s "
                    "name_entry_id=%d decoded_text=%r decoded_as_expected=%s" % (
                        i03_document["namepool_live_va_hex"],
                        i03_document["pool_initialized"],
                        i03_document["name_entry_id"],
                        (i03_document["decoded"]["text"]
                         if i03_document["decoded"] is not None else None),
                        i03_document["decoded_as_expected"]),
                    file=sys.stderr)
                if misery_reflection_result is not None:
                    print(
                        "I-03 reflection: objects_examined=%d misery_found=%s "
                        "decoded_names_sample=%r" % (
                            misery_reflection_result["objects_examined"],
                            misery_reflection_result["misery_found"],
                            misery_reflection_result["decoded_names"][:10]),
                        file=sys.stderr)
                print("written: %s" % written_i03_out, file=sys.stderr)
            if i04_document is not None:
                print(
                    "I-04: seed_found=%s class_address_universe_size=%d "
                    "misery_classes_count=%d game_classes_total_count=%d "
                    "game_classes_sample_count=%d other_classes_count=%d" % (
                        i04_document["seed_found"],
                        i04_document["class_address_universe_size"],
                        i04_document["misery_classes_count"],
                        i04_document["game_classes_total_count"],
                        i04_document["game_classes_sample_count"],
                        i04_document["other_classes_count"]),
                    file=sys.stderr)
                print("written: %s" % written_i04_out, file=sys.stderr)
                print("written: %s" % written_classes_jsonl, file=sys.stderr)
            print("written: %s" % written_manifest, file=sys.stderr)
        return 0
    except (EriError, pathguard.OutputPathRefused, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
