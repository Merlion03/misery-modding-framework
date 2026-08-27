#!/usr/bin/env python3
"""RESEARCH ONLY -- NOT PRODUCTION. See README.md and plan.md 8.1/8.3/8.4/8.5.

IPP capability P-02 (plan.md 8.3): call exactly one already-identified,
already-classified-safe UFunction through ProcessEvent, to test whether the
ABI reconstructed from decompilation (research/RESEARCH_LOG.md LOG-0056/
LOG-0057) matches real, executed behaviour. This is NOT a generic invoker:
--allow-call accepts only the single literal name this build was reviewed
and checkpointed against ("IsSteamDeck"); every other name is refused.

Escalation record: research/decisions.md, ESC-01. Do not run this against
any process without a fresh ESC-01-equivalent record for the question being
asked -- an empty escalation log makes this tool's own existence here
unauthorised, per research/instruments/ipp/README.md's own warning.

Architecture (deliberately, per plan.md 8.1's "ERI/IPP not inherited by
product" and the explicit instruction this module was built under): this
file imports research/instruments/eri/eri.py ONLY for its already-tested,
PURELY READ-ONLY discovery functions (run_i01/run_i02/run_i03/run_i04/
run_i05, Win32Api, open_process_read_only) -- reusing proven code for
target resolution is safer than a fresh reimplementation, and eri.py itself
gains not one new line, not one new capability, for this reuse: it remains
importable, unmodified, "read-only forever". Every WRITE/EXECUTE Win32 call
in this whole run (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
VirtualFreeEx) is made directly in THIS file, never inside eri.py, and is
gated entirely behind --allow-call.

Everything this controller resolves about the live target (the
MiseryBlueprintFunctionLibrary UClass address, its ClassDefaultObject, the
IsSteamDeck UFunction address, the ProcessEvent function pointer read from
vtable slot 77) is obtained through READ-ONLY memory reads and validated
with self-consistency checks BEFORE any write/execute Win32 call is ever
made. The probe DLL itself (probe/probe.cpp) is handed these four already-
resolved pointers and does no address/name resolution of its own.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
import eri  # noqa: E402  (path insert must precede this import)

TOOL_VERSION = "ipp-controller-0.1.0"

# The ONE function this build of the tool is permitted to call, matching the
# checkpoint this file was reviewed against (research/decisions.md ESC-01).
# Extending this set is a NEW escalation, not a config change: it requires
# its own ESC-NN record and its own review, per plan.md 8.4 condition 5
# ("minimally necessary capability, not the whole set").
ALLOWED_FUNCTION_NAMES = frozenset({"IsSteamDeck"})
TARGET_CLASS_NAME = "MiseryBlueprintFunctionLibrary"
# Sourced from eri.py, not hand-retyped (adversarial review finding): eri.py
# is the single source of truth for every constant it already defines, so a
# future re-derivation there (e.g. DEFAULT_PROCESSEVENT_VTABLE_SLOT changing
# if UE_WITH_IRIS's resolved state ever flips for a later build, per
# LOG-0056 Finding 8's own noted dependency) is picked up here automatically
# instead of this file silently keeping a stale, un-cross-checked literal.
TARGET_MODULE_NAME = eri.DEFAULT_PROCESS_NAME

# The build this tool was reviewed and checkpointed against (the currently
# installed build, confirmed live 2026-08-27 -- research/RESEARCH_LOG.md
# LOG-0058/LOG-0059). A DIFFERENT installed build is a hard stop, never a
# soft warning: every offset/RVA/vtable-slot constant below was verified
# against exactly this build, none of it is assumed to survive a patch.
EXPECTED_BUILD_SHA256 = "bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331"

# research/RESEARCH_LOG.md LOG-0056 (PE-02, two independent methods, OBSERVED
# 0.90): the live-confirmed ProcessEvent vtable slot. Sourced from eri.py,
# same reasoning as TARGET_MODULE_NAME above.
PROCESSEVENT_VTABLE_SLOT = eri.DEFAULT_PROCESSEVENT_VTABLE_SLOT

# UClass::ClassDefaultObject offset, derived from UE 5.4.4 CL 35576357
# Class.h (Shipping, non-editor, x64) by two independent adversarial
# derivations this session, both landing on 0x110 and both reproducing the
# two already-live-confirmed checkpoints (UStruct::Children @ +0x48,
# UStruct::ChildProperties @ +0x50) exactly with no forced padding. NOT
# itself live-tested before this file existed -- validate_cdo_resolution()
# below is the live self-consistency check that closes that gap on every
# run, before any write/execute call is made.
CLASS_DEFAULT_OBJECT_OFFSET = 0x110

# --- IppProbeIo wire format -- MUST match probe/probe.cpp's IppProbeIo byte
# for byte. "<" = little-endian, no implicit padding (the C++ struct is
# #pragma pack(push, 1)):
#   Q magic, I protocol_version, Q process_event_ptr, Q cdo_ptr, Q function_ptr,
#   I parms_size, I return_value_offset,
#   I status, Q exception_code, B parms_before, B parms_after, B return_value_byte, B reserved
IO_STRUCT_FORMAT = "<QIQQQIIIQBBBB"
IO_STRUCT_SIZE = struct.calcsize(IO_STRUCT_FORMAT)
assert IO_STRUCT_SIZE == 60, "IppProbeIo wire format drifted from probe.cpp's 60-byte layout"
IO_MAGIC = 0x4950502D50524245  # "IPP-PRBE", must match probe.cpp's kIppProbeMagic
IO_PROTOCOL_VERSION = 1

STATUS_NAMES = {0: "not_run", 1: "success", 2: "exception", 3: "sanity_check_failed",
                4: "live_parms_size_mismatch"}

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
SYNCHRONIZE = 0x00100000
IPP_ACCESS_RIGHTS = (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ |
                     PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_MODULE_NAME32 = 255
MAX_PATH = 260
WAIT_TIMEOUT_MS = 10000  # generous but bounded -- a hang must be detectable, not silent


class Blocked(Exception):
    """Raised to stop the run cleanly and report a named blocker, per this
    project's standing rule: a blocker is recorded and the run stops, never
    worked around."""


class Module32EntryW(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)), ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE), ("szModule", wt.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wt.WCHAR * MAX_PATH),
    ]


def _k32():
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.restype = wt.HANDLE
    dll.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    dll.VirtualAllocEx.restype = wt.LPVOID
    dll.VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
    dll.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
    dll.WriteProcessMemory.restype = wt.BOOL
    dll.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    dll.ReadProcessMemory.restype = wt.BOOL
    dll.CreateRemoteThread.restype = wt.HANDLE
    dll.CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID,
                                       wt.LPVOID, wt.DWORD, wt.LPVOID]
    dll.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    dll.WaitForSingleObject.restype = wt.DWORD
    dll.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    dll.GetExitCodeThread.restype = wt.BOOL
    dll.GetModuleHandleW.restype = wt.HANDLE
    dll.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    dll.GetProcAddress.restype = wt.LPVOID
    dll.GetProcAddress.argtypes = [wt.HANDLE, ctypes.c_char_p]
    dll.VirtualFreeEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD]
    dll.VirtualFreeEx.restype = wt.BOOL
    dll.CloseHandle.argtypes = [wt.HANDLE]
    dll.CloseHandle.restype = wt.BOOL
    dll.CreateToolhelp32Snapshot.restype = wt.HANDLE
    dll.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    dll.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(Module32EntryW)]
    dll.Module32FirstW.restype = wt.BOOL
    dll.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(Module32EntryW)]
    dll.Module32NextW.restype = wt.BOOL
    return dll


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def find_remote_module_base(k32, pid: int, module_name: str):
    """Toolhelp32 module-snapshot lookup -- the real, non-truncated way to
    get a remote module's 64-bit load base. Deliberately NOT
    GetExitCodeThread(LoadLibraryW-thread): that API returns a 32-bit DWORD,
    which silently truncates a real HMODULE on x64 Windows -- found and
    fixed by this session's own end-to-end rehearsal against a throwaway
    process before this file was written, see the commit this file was
    checkpointed with."""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (0, wt.HANDLE(-1).value):
        raise Blocked("CreateToolhelp32Snapshot failed: %d" % ctypes.get_last_error())
    try:
        entry = Module32EntryW()
        entry.dwSize = ctypes.sizeof(Module32EntryW)
        found = k32.Module32FirstW(snap, ctypes.byref(entry))
        while found:
            if entry.szModule.lower() == module_name.lower():
                return ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
            found = k32.Module32NextW(snap, ctypes.byref(entry))
        return None
    finally:
        k32.CloseHandle(snap)


def find_export_rva(dll_path: str, export_name: str) -> int:
    """Pure struct-based PE export-directory parse -- no third-party
    dependency. Independently cross-checked against objdump -p's own export
    table dump during this session's rehearsal; both agreed exactly."""
    with open(dll_path, "rb") as f:
        data = f.read()
    if data[0:2] != b"MZ":
        raise Blocked("probe DLL is not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise Blocked("probe DLL has no PE signature")
    coff_off = e_lfanew + 4
    _machine, num_sections = struct.unpack_from("<HH", data, coff_off)
    opt_header_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic != 0x20B:
        raise Blocked("probe DLL is not PE32+ (expected x64)")
    data_dir_off = opt_off + 112
    export_dir_rva, _export_dir_size = struct.unpack_from("<II", data, data_dir_off)
    if export_dir_rva == 0:
        raise Blocked("probe DLL has no export directory")
    section_table_off = opt_off + opt_header_size
    sections = []
    for i in range(num_sections):
        off = section_table_off + i * 40
        virt_size, virt_addr = struct.unpack_from("<II", data, off + 8)
        raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
        sections.append((virt_addr, virt_size, raw_ptr, raw_size))

    def rva_to_offset(rva: int) -> int:
        for virt_addr, virt_size, raw_ptr, raw_size in sections:
            if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
                return raw_ptr + (rva - virt_addr)
        raise Blocked("RVA 0x%x not in any section of the probe DLL" % rva)

    exp_off = rva_to_offset(export_dir_rva)
    (_char, _ts, _maj, _minr, _name_rva, _base_ordinal, _num_functions, num_names,
     addr_of_functions, addr_of_names, addr_of_name_ordinals) = struct.unpack_from(
        "<IIHHIIIIIII", data, exp_off)
    names_table_off = rva_to_offset(addr_of_names)
    ordinals_table_off = rva_to_offset(addr_of_name_ordinals)
    functions_table_off = rva_to_offset(addr_of_functions)
    for i in range(num_names):
        name_rva_i = struct.unpack_from("<I", data, names_table_off + i * 4)[0]
        name_off = rva_to_offset(name_rva_i)
        end = data.index(b"\x00", name_off)
        if data[name_off:end].decode("ascii") == export_name:
            ordinal = struct.unpack_from("<H", data, ordinals_table_off + i * 2)[0]
            return struct.unpack_from("<I", data, functions_table_off + ordinal * 4)[0]
    raise Blocked("export %r not found in probe DLL" % export_name)


def build_probe_dll() -> str:
    """Compiles probe/probe.cpp fresh on every run -- 'compile cleanly' is a
    live, per-run check, not a stale pre-built artifact someone forgot to
    refresh. MinGW-w64 g++ (D:\\tools\\mingw64\\bin\\g++.exe), the same
    toolchain this session's rehearsal validated the whole mechanism
    against."""
    gxx = r"D:\tools\mingw64\bin\g++.exe"
    if not os.path.isfile(gxx):
        raise Blocked("MinGW g++ not found at %r" % gxx)
    src = os.path.join(IPP_DIR, "probe", "probe.cpp")
    build_dir = os.path.join(IPP_DIR, "build")
    os.makedirs(build_dir, exist_ok=True)
    out_dll = os.path.join(build_dir, "ipp_probe.dll")
    cmd = [gxx, "-shared", "-o", out_dll, src, "-static", "-O2",
           "-Wall", "-Wextra", "-Wshadow", "-Wconversion"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or result.stdout.strip() or result.stderr.strip():
        raise Blocked(
            "probe.cpp did not compile cleanly (exit=%d):\nstdout:\n%s\nstderr:\n%s" %
            (result.returncode, result.stdout, result.stderr))
    return out_dll


def run_verify_install(run_dir: str, tag: str, mode: str = "full") -> dict:
    """Wraps tools/inventory/verify_install.py, plan.md 8.5's mandatory
    before/after check for every IPP session. Uses the CURRENT build's own
    baseline inventory (research/builds/<build_id>/install-inventory.json),
    resolved from research/builds/index.json by this run's own observed
    build_key, never a hardcoded/stale path. The full --json report is
    written into THIS run's own research/instrument-runs/<timestamp>/
    directory, alongside the manifest -- the shape
    research/schema/instrument-run-manifest.schema.json's own
    verify_install_state.report_artifact field describes ('normally
    alongside this manifest'), not into the ipp/build/ scratch directory."""
    index_path = os.path.join(REPO_ROOT, "research", "builds", "index.json")
    with open(index_path, encoding="utf-8") as f:
        index = json.load(f)
    entry = index.get("sha256:" + EXPECTED_BUILD_SHA256)
    if entry is None:
        raise Blocked("no research/builds/index.json entry for the expected build_key")
    inventory_path = os.path.join(REPO_ROOT, entry["artifacts"]["install_inventory_json"])
    script = os.path.join(REPO_ROOT, "tools", "inventory", "verify_install.py")
    report_path = os.path.join(run_dir, "verify_install_%s.json" % tag)
    cmd = [sys.executable, script, inventory_path, "--json", report_path]
    if mode == "fast":
        cmd.append("--fast")
    result = subprocess.run(cmd, capture_output=True, text=True)
    checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if os.path.isfile(report_path):
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
        summary = {
            "checked_at": report.get("checked_at", checked_at),
            "mode": report.get("mode", "full"),
            "strict": report.get("strict"),
            "result": report.get("result"),
            "serious_count": report.get("serious_count", 0),
            "benign_count": report.get("benign_count", 0),
            "baseline_build_key": report.get("baseline_build_key"),
            "report_artifact": os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/"),
        }
    else:
        summary = {
            "checked_at": checked_at, "mode": mode, "strict": None,
            "result": "mismatch", "serious_count": 1, "benign_count": 0,
            "baseline_build_key": None, "report_artifact": None,
        }
    return summary


def confirm_live_build_identity(api) -> dict:
    """The FIRST action of any --allow-call run (adversarial review finding:
    an earlier draft ran verify_before, which looks up research/builds/
    index.json BY the hardcoded EXPECTED_BUILD_SHA256, before this check had
    ever confirmed that constant matches the actually-running process --
    backwards from the stated principle 'build identity confirmed against
    the live process's own exe hash, before anything else'). Hashes the
    LIVE process's own exe_path (never a supplied/cached value -- the exact
    failure mode research/instruments/eri/eri.py's own --build-key help text
    names: 'a cached/supplied build_key silently outlived a Steam update
    once already', LOG-0048/LOG-0049). Raises Blocked on any mismatch.
    resolve_target() below calls this again as its own first step -- a
    second, cheap, independent re-hash of the same live file a few seconds
    later is a feature (never trust a value from earlier in the same run
    either), not redundancy worth removing."""
    result = eri.run_i01(api, TARGET_MODULE_NAME)
    exe_path = result["exe_path"]
    observed_sha256 = sha256_of_file(exe_path)
    if observed_sha256 != EXPECTED_BUILD_SHA256:
        raise Blocked(
            "build identity mismatch: running process is sha256:%s, this tool was "
            "checkpointed against sha256:%s -- refusing to proceed (plan.md 8.5, "
            "identity self-establishment)" % (observed_sha256, EXPECTED_BUILD_SHA256))
    return result


def resolve_target(api, run_note: list) -> dict:
    """READ-ONLY discovery phase, entirely: resolves the live
    MiseryBlueprintFunctionLibrary UClass, its ClassDefaultObject (with a
    self-consistency check), the IsSteamDeck UFunction, and the ProcessEvent
    function pointer read from CDO vtable slot 77 -- all via
    eri.run_i0N()/api.read_process_memory(), never a write/execute call.
    Raises Blocked with a specific reason on any failed validation; never
    guesses past a mismatch."""
    result = confirm_live_build_identity(api)
    pid = result["pid"]
    base_address = result["base_address"]
    image_size_bytes = result["image_size_bytes"]
    exe_path = result["exe_path"]
    observed_sha256 = sha256_of_file(exe_path)
    run_note.append("build identity confirmed: sha256:%s (self-computed from the live "
                     "process's own exe_path, not supplied/cached)" % observed_sha256)

    i02_handle = eri.open_process_read_only(api, pid)
    try:
        i02_result = eri.run_i02(
            api, i02_handle, base_address, image_size_bytes,
            guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
            sample_size=eri.DEFAULT_I02_SAMPLE_SIZE,
            poll_interval_seconds=0,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    finally:
        api.close_handle(i02_handle)

    i03_handle = eri.open_process_read_only(api, pid)
    try:
        i03_result = eri.run_i03(
            api, i03_handle, base_address, image_size_bytes,
            namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
            name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
            name_entry_id=0)

        i04_result = eri.run_i04(
            api, i03_handle, base_address, image_size_bytes,
            i02_result["objects_ptr_live_va"], i02_result["num_elements"],
            i03_result["namepool_live_va"],
            class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
            name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
            outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES,
            max_outer_depth=eri.DEFAULT_I04_MAX_OUTER_DEPTH,
            max_fixed_point_passes=eri.DEFAULT_I04_MAX_FIXED_POINT_PASSES)
        if not i04_result["seed_found"]:
            raise Blocked("I-04 UClass self-reference seed not found this run -- "
                          "refusing to build on an unverified class universe")

        misery_class = next(
            (c for c in i04_result["classes"] if c["raw_name"] == TARGET_CLASS_NAME), None)
        if misery_class is None:
            raise Blocked("class %r not found in this run's live class universe" %
                          TARGET_CLASS_NAME)
        uclass_address = misery_class["address"]
        run_note.append("live UClass %s resolved fresh this run at 0x%x (not cached from "
                        "any prior session -- addresses are not ASLR-stable across "
                        "launches)" % (TARGET_CLASS_NAME, uclass_address))

        i05_result = eri.run_i05(
            api, i03_handle, i03_result["namepool_live_va"], i04_result["classes"],
            [misery_class])
        class_entry = next(
            (c for c in i05_result["classes"] if c["class_raw_name"] == TARGET_CLASS_NAME),
            None)
        if class_entry is None:
            raise Blocked("I-05 did not walk %r's Children chain this run" % TARGET_CLASS_NAME)
        func_entry = next(
            (f for f in class_entry["functions"] if f["raw_name"] in ALLOWED_FUNCTION_NAMES),
            None)
        if func_entry is None:
            raise Blocked("function %r not found as a child of %r this run" %
                          (sorted(ALLOWED_FUNCTION_NAMES), TARGET_CLASS_NAME))
        if func_entry["parms_size"] != 1 or func_entry["return_value_offset"] != 0:
            raise Blocked(
                "live ABI facts for %r do not match the checkpointed contract "
                "(parms_size=%r return_value_offset=%r, expected 1/0) -- this build's "
                "reflection changed since LOG-0057 and the probe must not proceed on a "
                "stale assumption" % (func_entry["raw_name"], func_entry["parms_size"],
                                       func_entry["return_value_offset"]))
        function_address = func_entry["address"]
        run_note.append("live UFunction %s resolved fresh this run at 0x%x, parms_size=1 "
                        "return_value_offset=0 re-confirmed live" %
                        (func_entry["raw_name"], function_address))

        cdo_bytes = api.read_process_memory(
            i03_handle, uclass_address + CLASS_DEFAULT_OBJECT_OFFSET, 8)
        cdo_address = struct.unpack("<Q", cdo_bytes)[0]
        if cdo_address == 0:
            raise Blocked("ClassDefaultObject at UClass+0x%x is null" %
                          CLASS_DEFAULT_OBJECT_OFFSET)

        cdo_class_ptr_bytes = api.read_process_memory(
            i03_handle, cdo_address + eri.DEFAULT_CLASS_PRIVATE_OFFSET, 8)
        cdo_class_ptr = struct.unpack("<Q", cdo_class_ptr_bytes)[0]
        if cdo_class_ptr != uclass_address:
            raise Blocked(
                "CDO self-consistency check FAILED: candidate CDO at 0x%x has "
                "ClassPrivate=0x%x, expected 0x%x (own UClass address). This is the "
                "live check that closes the gap left by CLASS_DEFAULT_OBJECT_OFFSET "
                "never having been live-tested before this run -- refusing to proceed "
                "on an unverified offset rather than trusting the source derivation "
                "alone." % (cdo_address, cdo_class_ptr, uclass_address))
        run_note.append("CDO self-consistency check PASSED: candidate CDO at 0x%x has "
                        "ClassPrivate == 0x%x (its own UClass address) -- "
                        "CLASS_DEFAULT_OBJECT_OFFSET=0x%x confirmed live, not only by "
                        "source derivation" % (cdo_address, uclass_address,
                                                CLASS_DEFAULT_OBJECT_OFFSET))

        vtable_ptr_bytes = api.read_process_memory(i03_handle, cdo_address, 8)
        vtable_ptr = struct.unpack("<Q", vtable_ptr_bytes)[0]
        if not (base_address <= vtable_ptr < base_address + image_size_bytes):
            raise Blocked(
                "CDO vtable pointer 0x%x is outside the module image bounds "
                "[0x%x, 0x%x) -- refusing to trust it as a real vtable" %
                (vtable_ptr, base_address, base_address + image_size_bytes))

        slot_bytes = api.read_process_memory(
            i03_handle, vtable_ptr + PROCESSEVENT_VTABLE_SLOT * 8, 8)
        process_event_ptr = struct.unpack("<Q", slot_bytes)[0]
        if not (base_address <= process_event_ptr < base_address + image_size_bytes):
            raise Blocked(
                "vtable slot %d value 0x%x is outside the module image bounds -- "
                "refusing to call through it" % (PROCESSEVENT_VTABLE_SLOT, process_event_ptr))
        run_note.append("ProcessEvent function pointer resolved fresh this run: "
                        "0x%x (CDO vtable slot %d, within module image bounds)" %
                        (process_event_ptr, PROCESSEVENT_VTABLE_SLOT))
    finally:
        api.close_handle(i03_handle)

    return {
        "pid": pid, "base_address": base_address, "image_size_bytes": image_size_bytes,
        "exe_path": exe_path, "build_sha256": observed_sha256,
        "uclass_address": uclass_address, "cdo_address": cdo_address,
        "function_name": func_entry["raw_name"], "function_address": function_address,
        "parms_size": func_entry["parms_size"],
        "return_value_offset": func_entry["return_value_offset"],
        "process_event_ptr": process_event_ptr,
    }


def invoke_probe(target: dict, dll_path: str, cleanup_report: dict) -> dict:
    """The one write/execute phase of this whole tool. Every step here was
    rehearsed end-to-end against a throwaway local process before this
    function was written against the real game (see the commit this file
    was checkpointed with for the rehearsal scripts/output).

    *cleanup_report* is an OUT parameter (a dict the caller creates and
    keeps, e.g. {}), filled in here regardless of whether this function
    returns normally or raises Blocked partway through -- so a caller whose
    Blocked propagates from HERE (after the DLL was already loaded) still
    has real data about whether cleanup ran and what it found, not just
    silence (adversarial review findings: unchecked FreeLibrary result, and
    confirm_dll_unloaded() never being consulted on a Blocked exit)."""
    cleanup_report.update({
        "unload_attempted": False,
        "unload_thread_created": None,
        "unload_wait_timed_out": None,
        "unload_freelibrary_result": None,
        "unload_skipped_reason": None,
    })

    k32 = _k32()
    hproc = k32.OpenProcess(IPP_ACCESS_RIGHTS, False, target["pid"])
    if not hproc:
        raise Blocked("OpenProcess(IPP_ACCESS_RIGHTS) failed: %d" % ctypes.get_last_error())

    remote_path_buf = None
    remote_io_buf = None
    remote_base = None
    # True from the moment the RunProbe thread is created until we have
    # POSITIVE confirmation it finished (wait2 == 0). While true, FreeLibrary
    # must not be called -- unmapping the DLL image out from under a thread
    # that may still have live RIP inside it (or inside game code it called
    # into) is itself a crash/corruption risk (adversarial review finding).
    runprobe_thread_may_be_running = False
    try:
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        remote_path_buf = k32.VirtualAllocEx(
            hproc, None, len(path_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_path_buf:
            raise Blocked("VirtualAllocEx(dll path) failed: %d" % ctypes.get_last_error())
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(hproc, remote_path_buf, path_bytes, len(path_bytes),
                                      ctypes.byref(written)):
            raise Blocked("WriteProcessMemory(dll path) failed: %d" % ctypes.get_last_error())

        h_k32 = k32.GetModuleHandleW("kernel32.dll")
        p_loadlibraryw = k32.GetProcAddress(h_k32, b"LoadLibraryW")

        h_thread1 = k32.CreateRemoteThread(hproc, None, 0, p_loadlibraryw, remote_path_buf, 0, None)
        if not h_thread1:
            raise Blocked("CreateRemoteThread(LoadLibraryW) failed: %d" % ctypes.get_last_error())
        wait1 = k32.WaitForSingleObject(h_thread1, WAIT_TIMEOUT_MS)
        k32.CloseHandle(h_thread1)
        if wait1 != 0:
            # LoadLibraryW's own outcome is now genuinely unknown -- it may
            # still be running, or may have finished after we stopped
            # waiting. remote_base is deliberately left unset: the finally
            # block below must not guess a module to unload here.
            cleanup_report["unload_skipped_reason"] = (
                "LoadLibraryW remote thread did not finish within %dms -- its outcome is "
                "unknown, no module base to attempt FreeLibrary against" % WAIT_TIMEOUT_MS)
            raise Blocked("LoadLibraryW remote thread did not finish within %dms "
                          "(WaitForSingleObject returned %d) -- treating as a hang, "
                          "not proceeding" % (WAIT_TIMEOUT_MS, wait1))

        dll_name = os.path.basename(dll_path)
        remote_base = find_remote_module_base(k32, target["pid"], dll_name)
        if remote_base is None:
            raise Blocked("probe DLL does not appear in the target's module list after "
                          "LoadLibraryW returned -- load likely failed silently")

        rva = find_export_rva(dll_path, "RunProbe")
        remote_run_probe = remote_base + rva

        io_bytes = struct.pack(
            IO_STRUCT_FORMAT, IO_MAGIC, IO_PROTOCOL_VERSION, target["process_event_ptr"],
            target["cdo_address"], target["function_address"], target["parms_size"],
            target["return_value_offset"], 0, 0, 0, 0, 0, 0)
        remote_io_buf = k32.VirtualAllocEx(
            hproc, None, IO_STRUCT_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_io_buf:
            raise Blocked("VirtualAllocEx(io struct) failed: %d" % ctypes.get_last_error())
        if not k32.WriteProcessMemory(hproc, remote_io_buf, io_bytes, len(io_bytes),
                                      ctypes.byref(written)):
            raise Blocked("WriteProcessMemory(io struct, before call) failed: %d" %
                          ctypes.get_last_error())

        runprobe_thread_may_be_running = True
        h_thread2 = k32.CreateRemoteThread(hproc, None, 0, remote_run_probe, remote_io_buf, 0, None)
        if not h_thread2:
            runprobe_thread_may_be_running = False  # never actually created
            raise Blocked("CreateRemoteThread(RunProbe) failed: %d" % ctypes.get_last_error())
        wait2 = k32.WaitForSingleObject(h_thread2, WAIT_TIMEOUT_MS)
        if wait2 != 0:
            # Genuinely unknown whether/when this thread will ever finish.
            # Leave runprobe_thread_may_be_running == True: the finally
            # block must NOT call FreeLibrary while this is possibly still
            # executing inside the very image FreeLibrary would unmap.
            cleanup_report["unload_skipped_reason"] = (
                "RunProbe remote thread did not finish within %dms -- its outcome is "
                "unknown, FreeLibrary was deliberately NOT attempted while it may still "
                "be running inside the probe DLL's own image" % WAIT_TIMEOUT_MS)
            raise Blocked("RunProbe remote thread did not finish within %dms "
                          "(WaitForSingleObject returned %d) -- treating as a hang" %
                          (WAIT_TIMEOUT_MS, wait2))
        runprobe_thread_may_be_running = False
        thread_exit_code = wt.DWORD(0)
        k32.GetExitCodeThread(h_thread2, ctypes.byref(thread_exit_code))
        k32.CloseHandle(h_thread2)

        result_buf = ctypes.create_string_buffer(IO_STRUCT_SIZE)
        bytes_read = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(hproc, remote_io_buf, result_buf, IO_STRUCT_SIZE,
                                     ctypes.byref(bytes_read)):
            raise Blocked("ReadProcessMemory(io struct, after call) failed: %d" %
                          ctypes.get_last_error())
        fields = struct.unpack(IO_STRUCT_FORMAT, result_buf.raw)
        (_magic, _ver, _pe, _cdo, _fn, _psz, _rvo, status, exception_code,
         parms_before, parms_after, return_value_byte, _reserved) = fields

        return {
            "thread_exit_code": thread_exit_code.value,
            "status": status, "status_name": STATUS_NAMES.get(status, "unknown"),
            "exception_code": exception_code,
            "parms_before": parms_before, "parms_after": parms_after,
            "return_value_byte": return_value_byte,
            "remote_dll_base": remote_base, "remote_run_probe_address": remote_run_probe,
        }
    finally:
        # Unload and free remote resources REGARDLESS of what happened above
        # -- cleanup is not conditional on success -- EXCEPT FreeLibrary
        # itself, which must not run while the RunProbe thread's outcome is
        # unknown (see runprobe_thread_may_be_running above).
        if remote_base is not None and not runprobe_thread_may_be_running:
            cleanup_report["unload_attempted"] = True
            h_k32 = k32.GetModuleHandleW("kernel32.dll")
            p_freelibrary = k32.GetProcAddress(h_k32, b"FreeLibrary")
            if not p_freelibrary:
                cleanup_report["unload_skipped_reason"] = (
                    "GetProcAddress(FreeLibrary) failed: %d" % ctypes.get_last_error())
            else:
                h_thread3 = k32.CreateRemoteThread(hproc, None, 0, p_freelibrary, remote_base, 0, None)
                cleanup_report["unload_thread_created"] = bool(h_thread3)
                if not h_thread3:
                    cleanup_report["unload_skipped_reason"] = (
                        "CreateRemoteThread(FreeLibrary) failed: %d" % ctypes.get_last_error())
                else:
                    wait3 = k32.WaitForSingleObject(h_thread3, WAIT_TIMEOUT_MS)
                    cleanup_report["unload_wait_timed_out"] = (wait3 != 0)
                    if wait3 == 0:
                        free_exit_code = wt.DWORD(0)
                        k32.GetExitCodeThread(h_thread3, ctypes.byref(free_exit_code))
                        cleanup_report["unload_freelibrary_result"] = bool(free_exit_code.value)
                    k32.CloseHandle(h_thread3)
        elif remote_base is not None and runprobe_thread_may_be_running:
            cleanup_report.setdefault("unload_skipped_reason",
                                      "RunProbe thread outcome unknown -- FreeLibrary withheld")
        if remote_path_buf is not None:
            k32.VirtualFreeEx(hproc, remote_path_buf, 0, MEM_RELEASE)
        if remote_io_buf is not None:
            k32.VirtualFreeEx(hproc, remote_io_buf, 0, MEM_RELEASE)
        k32.CloseHandle(hproc)


def confirm_dll_unloaded(pid: int, dll_name: str) -> bool:
    k32 = _k32()
    base = find_remote_module_base(k32, pid, dll_name)
    return base is None


def write_manifest(run_dir: str, *, arguments: list, capabilities_enabled: list,
                   build_sha256: str, verify_before: dict, verify_after: dict,
                   artifacts: list) -> str:
    manifest = {
        "run_id": os.path.basename(run_dir),
        "instrument_level": "ipp",
        "arguments": arguments,
        "tool_version": TOOL_VERSION,
        "capabilities_enabled": capabilities_enabled,
        "verify_install_before": verify_before,
        "verify_install_after": verify_after,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": artifacts,
        "evidence_level": "OBSERVED",
        "confidence": 0.9,
        "sources": [{"method": "P-02"}],
        "oracle": ["runtime-reflection"],
        "build_key": "sha256:" + build_sha256,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "identity_self_established": True,
        "build_key_cross_checked": False,
        "known_build": True,
        "build_id": "misery-24953925-ue5.4.4-bace50f7185d",
        "claim_type": "other",
        "claim_type_note": "a manifest records that a research instrument ran, not a "
                           "fact about the game (research/schema/instrument-run-manifest"
                           ".schema.json claim_type_note pattern).",
    }
    manifest_path = os.path.join(run_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    return manifest_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-call", metavar="FUNCTION_NAME", default=None,
                        help="Enable capability P-02 for exactly one UFunction name. "
                             "The only accepted value in this build is %r -- any other "
                             "value is refused, not silently accepted." %
                             sorted(ALLOWED_FUNCTION_NAMES))
    parser.add_argument("--run-dir", default=None,
                        help="research/instrument-runs/<timestamp> directory to write "
                             "this run's manifest and artifacts into (default: a fresh "
                             "UTC-timestamped directory under research/instrument-runs/).")
    args = parser.parse_args(argv)

    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    capabilities_enabled = []
    run_note = []

    if args.run_dir is None:
        run_id = time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
        run_dir = os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    else:
        run_dir = args.run_dir
    os.makedirs(run_dir, exist_ok=True)

    verify_before = None
    verify_after = None
    artifacts = []
    # Predeclared so the except-Blocked handler below can still report DLL
    # residency even when injection was attempted and then something later
    # raised Blocked (adversarial review finding: this used to be reachable
    # only on the success path, leaving a Blocked-after-load run silent
    # about whether the probe DLL was left resident in the game process).
    dll_name = None
    target_pid = None
    cleanup_report = {}

    try:
        api = eri.Win32Api()

        if args.allow_call is not None:
            # Build identity, confirmed against the LIVE process, is the
            # very first action of any run that will go on to write/execute
            # anything -- deliberately BEFORE verify_before, which otherwise
            # would look up research/builds/index.json by the hardcoded
            # EXPECTED_BUILD_SHA256 before that constant had ever been
            # checked against what is actually running (adversarial review
            # finding).
            confirm_live_build_identity(api)
            verify_before = run_verify_install(run_dir, "before")
            if verify_before["report_artifact"]:
                artifacts.append(verify_before["report_artifact"])
            if verify_before["result"] == "mismatch":
                raise Blocked(
                    "verify_install.py reported a MISMATCH before this session even "
                    "started (%d serious finding(s)) -- refusing to proceed against an "
                    "installation that does not match its own recorded baseline" %
                    verify_before["serious_count"])

        target = resolve_target(api, run_note)
        target_pid = target["pid"]

        report = {
            "run_note": run_note,
            "target": {k: (hex(v) if isinstance(v, int) and k != "pid" and
                          k != "parms_size" and k != "return_value_offset" else v)
                      for k, v in target.items()},
        }

        if args.allow_call is None:
            report["invocation"] = None
            report["outcome"] = ("discovery-only run: no --allow-call given, capability "
                                 "P-02 was NOT enabled, nothing was written to or "
                                 "executed in the target process")
        else:
            if args.allow_call not in ALLOWED_FUNCTION_NAMES:
                raise Blocked(
                    "--allow-call %r refused: this build only permits %r. Extending "
                    "this list is a new escalation (plan.md 8.4), not a flag change." %
                    (args.allow_call, sorted(ALLOWED_FUNCTION_NAMES)))
            if target["function_name"] != args.allow_call:
                raise Blocked(
                    "resolved target function %r does not match --allow-call %r" %
                    (target["function_name"], args.allow_call))

            capabilities_enabled.append("P-02")
            dll_path = build_probe_dll()
            dll_name = os.path.basename(dll_path)
            run_note.append("probe.cpp compiled cleanly with 0 warnings/errors "
                            "(-Wall -Wextra -Wshadow -Wconversion)")

            invocation = invoke_probe(target, dll_path, cleanup_report)
            report["invocation"] = invocation
            report["cleanup"] = cleanup_report

            unloaded = confirm_dll_unloaded(target["pid"], dll_name)
            report["dll_unloaded_confirmed"] = unloaded

            verify_after = run_verify_install(run_dir, "after")
            if verify_after["report_artifact"]:
                artifacts.append(verify_after["report_artifact"])

            integrity_note = ""
            if invocation["status_name"] == "exception":
                # A caught hardware fault means the ONE call this tool ever
                # makes did not complete normally -- probe.cpp's own header
                # comment explains why setjmp/longjmp cannot run any
                # destructor/lock-release/reentrancy-counter-decrement any
                # engine code between the fault and the call may already
                # have entered. Say so loudly rather than reporting this
                # identically to a clean success.
                integrity_note = (
                    " WARNING: target process integrity is NOT guaranteed after a caught "
                    "exception -- setjmp/longjmp skips any engine-side RAII cleanup that "
                    "may have already run inside the faulted call (see probe.cpp's own "
                    "header comment); treat this game session as suspect, do not simply "
                    "retry, and consider a full restart before trusting it again.")

            report["outcome"] = (
                "status=%s thread_exit_code=%d expected_return_value=false "
                "observed_return_value_byte=%d(%s) parms_before=%d parms_after=%d "
                "exception_code=0x%x dll_unloaded=%s%s" % (
                    invocation["status_name"], invocation["thread_exit_code"],
                    invocation["return_value_byte"],
                    bool(invocation["return_value_byte"]),
                    invocation["parms_before"], invocation["parms_after"],
                    invocation["exception_code"], unloaded, integrity_note))

        report_path = os.path.join(run_dir, "report.json")
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/"))

        print(json.dumps(report, indent=2, sort_keys=True))
        exit_code = 0
    except (Blocked, eri.EriError) as exc:
        # eri.EriError (e.g. ProcessNotFoundError when the game isn't
        # running) is caught alongside our own Blocked, not just Blocked:
        # found by direct testing before any live run against the real
        # game -- without this, a plain "game isn't running yet" produced
        # an unhandled traceback and no report.json instead of a clean,
        # named blocker, exactly the failure mode this tool's whole "record
        # a blocker and stop" discipline exists to avoid.
        report = {"blocked": True, "reason": str(exc), "run_note": run_note,
                  "cleanup": cleanup_report or None}
        if "P-02" in capabilities_enabled and dll_name is not None and target_pid is not None:
            # Injection was attempted before this Blocked was raised --
            # confirm and report DLL residency even on this exit path
            # (adversarial review finding: this used to only be checked on
            # the success path).
            try:
                report["dll_unloaded_confirmed"] = confirm_dll_unloaded(target_pid, dll_name)
            except Exception:  # noqa: BLE001 -- best-effort, never masks the real error
                report["dll_unloaded_confirmed"] = None
        report_path = os.path.join(run_dir, "report.json")
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", exc, file=sys.stderr)
        exit_code = 2
    finally:
        if args.allow_call is not None and verify_before is not None and verify_after is None:
            # An IPP session that enabled a capability but never reached the
            # post-check (blocked mid-flight) still owes plan.md 8.5 an
            # AFTER check -- the game process is still live and worth
            # checking even though the call itself did not complete.
            try:
                verify_after = run_verify_install(run_dir, "after-blocked")
                if verify_after["report_artifact"]:
                    artifacts.append(verify_after["report_artifact"])
            except Exception:  # noqa: BLE001 -- best-effort, never masks the real error
                verify_after = None
        manifest_path = write_manifest(
            run_dir, arguments=arguments, capabilities_enabled=capabilities_enabled,
            build_sha256=EXPECTED_BUILD_SHA256, verify_before=verify_before,
            verify_after=verify_after, artifacts=artifacts)
        print("manifest:", manifest_path, file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
