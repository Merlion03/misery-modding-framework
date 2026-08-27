#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ERI -- External Read-Only Inspector, capability I-01 (plan.md 8.2).

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
memory relative to that base address; none of them are implemented here.

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

  1. Every Win32 call this tool ever makes is one of exactly seven functions,
     all read-only observation primitives: CreateToolhelp32Snapshot,
     Process32FirstW, Process32NextW, Module32FirstW, Module32NextW,
     OpenProcess and CloseHandle. None of them writes to, allocates in,
     protects, or executes anything in the target process. In particular:
     no WriteProcessMemory, no VirtualAllocEx/VirtualProtectEx, no
     CreateRemoteThread/NtCreateThreadEx, no SetWindowsHookEx, no
     ReadProcessMemory even (I-01 needs only Toolhelp32 module enumeration,
     not a memory read) -- grep this file for "kernel32\\." and that is the
     complete list, forever, for this pass.
  2. There is exactly ONE call site for OpenProcess in the whole tool (see
     ``Win32Api.open_process`` below), and the access-rights argument it
     passes is the single module-level constant ``PROCESS_ACCESS_RIGHTS``,
     defined once, a few lines below this docstring, as
     ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` and nothing else -- no
     ``PROCESS_ALL_ACCESS``, no ``PROCESS_VM_WRITE``, no
     ``PROCESS_VM_OPERATION``, no ``PROCESS_CREATE_THREAD``, no
     ``PROCESS_DUP_HANDLE``. A reviewer who does not trust this docstring
     needs to read exactly one line to audit the claim, and
     ``tests/test_eri_i01.py`` pins the "exactly one call site" fact so a
     future edit cannot silently add a second one.

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
found, module not found, OpenProcess refused, snapshot creation refused --
raises a specific exception with an actionable message and propagates it;
nothing here returns None-and-hope, nothing retries silently, nothing falls
back to a default. Do not "fix" this into graceful degradation; that would
be correct for product code and wrong for this file.

Usage
-----
    python research/instruments/eri/eri.py --build-key sha256:<64 hex> \\
        --run-dir research/instrument-runs/2026-08-27T120000Z

See "Как запускать" in research/instruments/eri/README.md for the full
option reference.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import json
import os
import re
import sys
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
    "image_size_bytes"}. Raises one of the EriError subclasses above on any
    failure -- never returns None, never degrades.
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
    }


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


def build_i01_document(*, result: dict, build_key: str, recorded_at: str | None) -> dict:
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
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_manifest(*, run_id: str, arguments: list, tool_version: str,
                   build_key: str, executed_at: str, recorded_at: str,
                   artifacts: list[str] | None) -> dict:
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
    """
    return {
        "run_id": run_id,
        "instrument_level": "eri",
        "arguments": list(arguments),
        "tool_version": tool_version,
        "capabilities_enabled": [CAPABILITY_ID],
        "verify_install_before": None,
        "verify_install_after": None,
        "executed_at": executed_at,
        "artifacts": artifacts,
        "evidence_level": "OBSERVED",
        "confidence": 0.75,
        "sources": [{"method": CAPABILITY_ID}],
        "oracle": ["runtime-reflection"],
        "claim_type": "other",
        "claim_type_note": (
            "a manifest records that a research instrument ran, not a fact "
            "about the game; no plan.md 10.5 matrix row describes an "
            "instrument-run bookkeeping record (research/schema/"
            "instrument-run-manifest.schema.json 'claim_type_note')."
        ),
        "build_key": build_key,
        "recorded_at": recorded_at,
        "notes": (
            "Written by %s (capability %s only). recorded_at/executed_at are "
            "real wall-clock time unless --recorded-at pinned them; "
            "--no-timestamp affects only the sibling I-01 output document's "
            "own 'recorded_at' field, never this manifest's, because "
            "instrument-run-manifest.schema.json requires both to be "
            "non-null timestamps at all times." % (GENERATOR_NAME, CAPABILITY_ID)
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
            "Writes nothing, injects nothing, hooks nothing, calls no game "
            "function."),
    )
    parser.add_argument(
        "--process-name", default=DEFAULT_PROCESS_NAME, metavar="NAME",
        help="exact (case-insensitive) executable filename to find; NEVER a "
             "substring match (default: %s)" % DEFAULT_PROCESS_NAME)
    parser.add_argument(
        "--build-key", required=True, metavar="sha256:HEX",
        help="the build this run is against -- 'sha256:<64 lowercase hex>' "
             "(research/schema/kb-record.schema.json #/$defs/build_key). "
             "No default: the tool cannot know which build it is pointed at.")
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


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        validate_build_key(args.build_key)
        out_path, manifest_path = _resolve_output_paths(args)

        # Layer 1 first, exactly like the pyghidra_scripts family: a refused
        # output path costs nothing, so it is checked before a single Win32
        # handle is opened.
        pathguard.check_output_path(
            out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what="--out")
        pathguard.check_output_path(
            manifest_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what="--manifest-out")

        i01_recorded_at = (
            args.recorded_at if args.recorded_at
            else (None if args.no_timestamp else now_iso_utc()))
        manifest_timestamp = args.recorded_at if args.recorded_at else now_iso_utc()

        run_id = args.run_id
        if not run_id:
            run_id = (os.path.basename(os.path.normpath(args.run_dir))
                      if args.run_dir else manifest_timestamp)

        result = run_i01(Win32Api(), args.process_name)

        document = build_i01_document(
            result=result, build_key=args.build_key, recorded_at=i01_recorded_at)
        written_out = _write_guarded(document, out_path, what="--out")

        manifest = build_manifest(
            run_id=run_id, arguments=list(sys.argv[1:] if argv is None else argv),
            tool_version=GENERATOR_VERSION, build_key=args.build_key,
            executed_at=manifest_timestamp, recorded_at=manifest_timestamp,
            artifacts=[_repo_relative(written_out)])
        written_manifest = _write_guarded(manifest, manifest_path, what="--manifest-out")

        if args.json:
            summary = {
                "pid": result["pid"],
                "process_name": result["process_name"],
                "base_address_hex": document["base_address_hex"],
                "image_size_bytes": result["image_size_bytes"],
                "out": written_out,
                "manifest_out": written_manifest,
            }
            print(dump_json(summary))
        else:
            print(
                "pid=%d base_address=%s image_size_bytes=%d"
                % (result["pid"], document["base_address_hex"], result["image_size_bytes"]),
                file=sys.stderr)
            print("written: %s" % written_out, file=sys.stderr)
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
