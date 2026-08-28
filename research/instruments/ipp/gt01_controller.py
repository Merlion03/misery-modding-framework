#!/usr/bin/env python3
"""RESEARCH ONLY -- NOT PRODUCTION. See README.md and plan.md 8.1/8.3/8.4/8.5.

IPP capability GT-01 (escalation ESC-03, research/decisions.md; pre-registration
research/evidence/GT-01/preregistration.md): prove that ONE callback of ours can
execute on the Unreal GameThread of the live MISERY-Win64-Shipping.exe, recording
only POD, doing NO UObject/ProcessEvent/load work, then removing every trace.

Mechanism: an EXECUTE hardware breakpoint (debug register Dr0) on the verified
address of UObject::ProcessEvent (RVA 0x12AC1F0, three agreeing derivations,
LOG-0072), armed on the GameThread ONLY. The injected probe DLL's VEH catches the
resulting one-shot #DB on the GameThread, records POD, and clears Dr0 in the
delivered context. Zero engine bytes are modified.

This is a NEW capability class relative to ESC-01/02: it briefly suspends the
GameThread and writes its debug registers via SetThreadContext. That write happens
ONLY under --arm, and ONLY after every read-only pre-flight gate passes. Without
--arm this runs the full read-only pre-flight + injection + negative control and
writes nothing to any thread's context.

Reuses ipp_controller.py's reviewed injection helpers and eri.py's read-only
build-identity / process discovery.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP_DIR)
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))

import eri  # noqa: E402
import ipp_controller as ipp  # noqa: E402

TOOL_VERSION = "gt01-controller-0.1.0"
EXPECTED_BUILD_SHA256 = "bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331"

# UObject::ProcessEvent, triple-derived (LOG-0072). Guaranteed by whole-image
# sha256 == build_key AND independently by unique signature + vtable slot 77 +
# ESC-01 empirical call. This is the trap location; its bytes are never modified.
PROCESS_EVENT_RVA = 0x12AC1F0

# GtProbeIo wire format -- MUST match probe_gt01/probe_gt01.cpp byte for byte.
#   Q magic, I protocol_version, I armed_tid, Q trap_addr, Q text_lo, Q text_hi,
#   I hit_count, I hit_tid, Q hit_rip, Q hit_return_addr, Q hit_qpc,
#   I hit_return_in_text, I fired,
#   I self_tid, Q self_rsp, Q self_return_addr, I self_done,
#   I veh_installed, I teardown_done, 4x B reserved
IO_FMT = "<QIIQQQ IIQQQ II IQQI II 4B"
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 116, "GtProbeIo wire format drifted from the probe's 116-byte layout (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D47543031  # "IPP-GT01"
IO_PROTO = 1
SENTINEL_TID = 0xFFFFFFFF

# --- thread access rights ---
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_ARM_RIGHTS = (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                     THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION)

TH32CS_SNAPTHREAD = 0x00000004
CONTEXT_AMD64 = 0x00100000
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
DR7_L0_ENABLE = 0x1  # local enable Dr0; RW0/LEN0 nibble = 0 => execute, 1 byte


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("_tail", ctypes.c_ubyte * 976),  # XSAVE area; unused, keeps total 1232
    ]


assert ctypes.sizeof(CONTEXT64) == 1232, "CONTEXT64 must be 1232 bytes (%d)" % ctypes.sizeof(CONTEXT64)


def _aligned_context():
    """Return (context, backing_buffer) with the CONTEXT 16-byte aligned, as
    GetThreadContext/SetThreadContext require (DECLSPEC_ALIGN(16))."""
    size = ctypes.sizeof(CONTEXT64)
    buf = ctypes.create_string_buffer(size + 16)
    addr = ctypes.addressof(buf)
    off = (16 - (addr % 16)) % 16
    ctx = CONTEXT64.from_buffer(buf, off)
    return ctx, buf


class _CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", ctypes.c_void_p), ("UniqueThread", ctypes.c_void_p)]


class _THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_long),
        ("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", _CLIENT_ID),
        ("AffinityMask", ctypes.c_void_p),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long), ("dwFlags", wt.DWORD),
    ]


def _ntdll():
    nt = ctypes.WinDLL("ntdll", use_last_error=True)
    nt.NtQueryInformationThread.restype = ctypes.c_long
    nt.NtQueryInformationThread.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    return nt


def _k32full():
    k = ipp._k32()
    k.OpenThread.restype = wt.HANDLE
    k.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.GetThreadContext.restype = wt.BOOL
    k.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
    k.SetThreadContext.restype = wt.BOOL
    k.SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
    k.SuspendThread.restype = wt.DWORD
    k.SuspendThread.argtypes = [wt.HANDLE]
    k.ResumeThread.restype = wt.DWORD
    k.ResumeThread.argtypes = [wt.HANDLE]
    k.GetThreadTimes.restype = wt.BOOL
    k.GetThreadTimes.argtypes = [wt.HANDLE, ctypes.POINTER(wt.FILETIME),
                                 ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME),
                                 ctypes.POINTER(wt.FILETIME)]
    k.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k.Thread32First.restype = wt.BOOL
    k.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
    k.Thread32Next.restype = wt.BOOL
    k.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
    try:
        k.GetThreadDescription.restype = ctypes.c_long  # HRESULT
        k.GetThreadDescription.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
        k.LocalFree.restype = wt.HPGLOBAL if hasattr(wt, "HPGLOBAL") else ctypes.c_void_p
        k.LocalFree.argtypes = [ctypes.c_void_p]
        has_desc = True
    except AttributeError:
        has_desc = False
    return k, has_desc


def enumerate_thread_ids(k, pid):
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == wt.HANDLE(-1).value or not snap:
        raise ipp.Blocked("CreateToolhelp32Snapshot failed: %d" % ctypes.get_last_error())
    tids = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)
        ok = k.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                tids.append(te.th32ThreadID)
            ok = k.Thread32Next(snap, ctypes.byref(te))
    finally:
        k.CloseHandle(snap)
    return tids


def thread_creation_qword(k, htid):
    c = wt.FILETIME(); e = wt.FILETIME(); kt = wt.FILETIME(); u = wt.FILETIME()
    if not k.GetThreadTimes(htid, ctypes.byref(c), ctypes.byref(e),
                            ctypes.byref(kt), ctypes.byref(u)):
        return None
    return (c.dwHighDateTime << 32) | c.dwLowDateTime


def thread_start_address(nt, htid):
    val = ctypes.c_void_p(0)
    ThreadQuerySetWin32StartAddress = 9
    status = nt.NtQueryInformationThread(htid, ThreadQuerySetWin32StartAddress,
                                         ctypes.byref(val), ctypes.sizeof(val), None)
    if status != 0:
        return None
    return val.value or 0


def thread_teb(nt, htid):
    tbi = _THREAD_BASIC_INFORMATION()
    ThreadBasicInformation = 0
    status = nt.NtQueryInformationThread(htid, ThreadBasicInformation,
                                         ctypes.byref(tbi), ctypes.sizeof(tbi), None)
    if status != 0:
        return None, None
    tid = tbi.ClientId.UniqueThread or 0
    return tbi.TebBaseAddress or 0, int(tid)


def thread_description(k, htid):
    ptr = ctypes.c_wchar_p()
    hr = k.GetThreadDescription(htid, ctypes.byref(ptr))
    if hr < 0:
        return None
    name = ptr.value
    if ptr:
        k.LocalFree(ctypes.cast(ptr, ctypes.c_void_p))
    return name


def identify_gamethread(k, nt, has_desc, pid, base, entry_rva, api, run_note):
    """Two independent derivations of the GameThread OS-thread id (Method 1)."""
    tids = enumerate_thread_ids(k, pid)
    if not tids:
        raise ipp.Blocked("no threads enumerated for pid %d" % pid)
    run_note.append("enumerated %d threads for pid %d" % (len(tids), pid))

    named = []
    earliest = None
    earliest_ct = None
    start_entry_tids = []
    entry_va = base + entry_rva
    for tid in tids:
        htid = k.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
        if not htid:
            continue
        try:
            if has_desc:
                nm = thread_description(k, htid)
                if nm == "GameThread":
                    named.append(tid)
            ct = thread_creation_qword(k, htid)
            if ct is not None and (earliest_ct is None or ct < earliest_ct):
                earliest_ct = ct
                earliest = tid
            sa = thread_start_address(nt, htid)
            if sa == entry_va:
                start_entry_tids.append(tid)
        finally:
            k.CloseHandle(htid)

    e1 = named[0] if len(named) == 1 else None
    # E2: the initial thread == earliest creation AND whose start address is the
    # image entry point. Prefer the intersection; fall back to entry-point match.
    e2 = None
    if earliest in start_entry_tids:
        e2 = earliest
    elif len(start_entry_tids) == 1:
        e2 = start_entry_tids[0]

    run_note.append("E1 (GetThreadDescription=='GameThread'): %s%s"
                    % (e1, "" if has_desc else " [GetThreadDescription unavailable]"))
    run_note.append("E2 (initial thread / entry-point 0x%x): earliest=%s entry_match=%s => %s"
                    % (entry_va, earliest, start_entry_tids, e2))
    return {"tids_total": len(tids), "named_gamethread": named, "e1": e1,
            "earliest": earliest, "entry_match": start_entry_tids, "e2": e2,
            "entry_va": entry_va}


def read_gamethread_teb_fingerprint(nt, api, ro_handle, htid_query, run_note):
    teb, tid = thread_teb(nt, htid_query)
    if not teb:
        raise ipp.Blocked("could not read GameThread TEB")
    # NT_TIB.StackBase @ TEB+0x08 ; DeallocationStack @ TEB+0x1478 (x64)
    stack_base = struct.unpack("<Q", api.read_process_memory(ro_handle, teb + 0x08, 8))[0]
    dealloc = struct.unpack("<Q", api.read_process_memory(ro_handle, teb + 0x1478, 8))[0]
    run_note.append("GameThread TEB=0x%x StackBase=0x%x DeallocationStack=0x%x (tid=%d)"
                    % (teb, stack_base, dealloc, tid))
    return {"teb": teb, "tid_from_tbi": tid, "stack_base": stack_base,
            "deallocation_stack": dealloc}


def read_debug_registers(k, htid):
    ctx, _buf = _aligned_context()
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if not k.GetThreadContext(htid, ctypes.byref(ctx)):
        raise ipp.Blocked("GetThreadContext(DEBUG) failed: %d" % ctypes.get_last_error())
    return {"Dr0": ctx.Dr0, "Dr1": ctx.Dr1, "Dr2": ctx.Dr2,
            "Dr3": ctx.Dr3, "Dr6": ctx.Dr6, "Dr7": ctx.Dr7}


def set_dr0(k, htid, trap_addr, enable):
    """Suspend the thread, set/clear Dr0, resume. Returns the debug regs read back."""
    if k.SuspendThread(htid) == 0xFFFFFFFF:
        raise ipp.Blocked("SuspendThread failed: %d" % ctypes.get_last_error())
    try:
        ctx, _buf = _aligned_context()
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        if not k.GetThreadContext(htid, ctypes.byref(ctx)):
            raise ipp.Blocked("GetThreadContext(arm) failed: %d" % ctypes.get_last_error())
        if enable:
            ctx.Dr0 = trap_addr
            ctx.Dr7 = DR7_L0_ENABLE
        else:
            ctx.Dr0 = 0
            ctx.Dr7 = 0
        ctx.Dr6 = 0
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        if not k.SetThreadContext(htid, ctypes.byref(ctx)):
            raise ipp.Blocked("SetThreadContext failed: %d" % ctypes.get_last_error())
        # read back within the same suspension
        rb, _b2 = _aligned_context()
        rb.ContextFlags = CONTEXT_DEBUG_REGISTERS
        k.GetThreadContext(htid, ctypes.byref(rb))
        readback = {"Dr0": rb.Dr0, "Dr7": rb.Dr7}
    finally:
        k.ResumeThread(htid)
    return readback


def pack_io(armed_tid, trap_addr, text_lo, text_hi):
    return struct.pack(IO_FMT, IO_MAGIC, IO_PROTO, armed_tid & 0xFFFFFFFF, trap_addr,
                       text_lo, text_hi,
                       0, SENTINEL_TID, 0, 0, 0, 0, 0,
                       0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    return {"magic": f[0], "proto": f[1], "armed_tid": f[2], "trap_addr": f[3],
            "text_lo": f[4], "text_hi": f[5], "hit_count": f[6], "hit_tid": f[7],
            "hit_rip": f[8], "hit_return_addr": f[9], "hit_qpc": f[10],
            "hit_return_in_text": f[11], "fired": f[12], "self_tid": f[13],
            "self_rsp": f[14], "self_return_addr": f[15], "self_done": f[16],
            "veh_installed": f[17], "teardown_done": f[18]}


def build_gt01_probe_dll():
    gxx = r"D:\tools\mingw64\bin\g++.exe"
    if not os.path.isfile(gxx):
        raise ipp.Blocked("MinGW g++ not found at %r" % gxx)
    src = os.path.join(IPP_DIR, "probe_gt01", "probe_gt01.cpp")
    build_dir = os.path.join(IPP_DIR, "build")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, "ipp_gt01_probe.dll")
    import subprocess
    cmd = [gxx, "-shared", "-o", out, src, "-static", "-O2", "-Wall", "-Wextra",
           "-Wshadow", "-Wconversion", "-fno-exceptions", "-fno-rtti"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or r.stdout.strip() or r.stderr.strip():
        raise ipp.Blocked("probe_gt01.cpp did not compile cleanly (exit=%d):\n%s\n%s"
                          % (r.returncode, r.stdout, r.stderr))
    return out


def call_export(k, hproc, remote_base, dll_path, export, arg_ptr, timeout_ms):
    rva = ipp.find_export_rva(dll_path, export)
    thr = k.CreateRemoteThread(hproc, None, 0, remote_base + rva, arg_ptr, 0, None)
    if not thr:
        raise ipp.Blocked("CreateRemoteThread(%s) failed: %d" % (export, ctypes.get_last_error()))
    w = k.WaitForSingleObject(thr, timeout_ms)
    code = wt.DWORD(0)
    k.GetExitCodeThread(thr, ctypes.byref(code))
    k.CloseHandle(thr)
    if w != 0:
        raise ipp.Blocked("%s remote thread did not finish in time" % export)
    return code.value


def run_gt01(api, args, run_dir, run_note, artifacts):
    """Full GT-01 flow. Read-only pre-flight always; the single write (Dr0 arm)
    only under args.arm."""
    k, has_desc = _k32full()
    nt = _ntdll()

    # --- identity + module geometry (read-only) ---
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base = i01["pid"], i01["base_address"]
    observed_sha = ipp.sha256_of_file(i01["exe_path"])
    if observed_sha != EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build identity mismatch: live=%s expected=%s"
                          % (observed_sha, EXPECTED_BUILD_SHA256))
    run_note.append("build identity confirmed sha256:%s" % observed_sha)

    # PE geometry from the on-disk image (== live image, hash-confirmed): entry
    # RVA and .text bounds.
    with open(i01["exe_path"], "rb") as f:
        img = f.read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    entry_rva = struct.unpack_from("<I", img, pe + 4 + 20 + 16)[0]
    nsec = struct.unpack_from("<H", img, pe + 4 + 2)[0]
    sizeopt = struct.unpack_from("<H", img, pe + 4 + 16)[0]
    sect = pe + 4 + 20 + sizeopt
    text_lo = text_hi = None
    for i in range(nsec):
        b = sect + i * 40
        nm = img[b:b + 8].rstrip(b"\x00")
        vs, va = struct.unpack_from("<II", img, b + 8)
        if nm == b".text":
            text_lo = base + va
            text_hi = base + va + vs
    if text_lo is None:
        raise ipp.Blocked(".text section not found in image")
    trap_addr = base + PROCESS_EVENT_RVA
    run_note.append("trap_addr=0x%x (base 0x%x + RVA 0x%x); .text [0x%x,0x%x); entry_rva=0x%x"
                    % (trap_addr, base, PROCESS_EVENT_RVA, text_lo, text_hi, entry_rva))

    # --- Method 1: identify the GameThread two ways ---
    gt = identify_gamethread(k, nt, has_desc, pid, base, entry_rva, api, run_note)
    e1, e2 = gt["e1"], gt["e2"]
    if e1 is None and e2 is None:
        raise ipp.Blocked("could not identify the GameThread by either method")
    if e1 is not None and e2 is not None and e1 != e2:
        raise ipp.Blocked("E1 (%s) != E2 (%s): GameThread identity not agreed -- refusing to arm"
                          % (e1, e2))
    tid_gt = e1 if e1 is not None else e2
    run_note.append("GameThread TID = %d (E1==%s, E2==%s)" % (tid_gt, e1, e2))

    ro_handle = eri.open_process_read_only(api, pid)
    try:
        htid_q = k.OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT, False, tid_gt)
        if not htid_q:
            raise ipp.Blocked("OpenThread(query) on GameThread failed: %d" % ctypes.get_last_error())
        try:
            teb_fp = read_gamethread_teb_fingerprint(nt, api, ro_handle, htid_q, run_note)
            # N2: debug registers must be clear before we arm.
            dbg_before = read_debug_registers(k, htid_q)
            run_note.append("N2 pre-arm debug regs: %s" % dbg_before)
            if any(dbg_before[r] != 0 for r in ("Dr0", "Dr1", "Dr2", "Dr3", "Dr7")):
                raise ipp.Blocked("GameThread already uses debug registers (%s) -- ABORT, "
                                  "not fighting for Dr0" % dbg_before)
        finally:
            k.CloseHandle(htid_q)
    finally:
        api.close_handle(ro_handle)

    report = {"pid": pid, "base_address": "0x%x" % base, "build_sha256": observed_sha,
              "trap_addr": "0x%x" % trap_addr, "text_bounds": ["0x%x" % text_lo, "0x%x" % text_hi],
              "gamethread": {"tid": tid_gt, "e1": e1, "e2": e2, "detail": gt},
              "teb_fingerprint": {k2: ("0x%x" % v if isinstance(v, int) else v)
                                  for k2, v in teb_fp.items()},
              "debug_regs_before": {r: "0x%x" % v for r, v in dbg_before.items()}}

    # --- inject the probe DLL ---
    dll_path = build_gt01_probe_dll()
    dll_name = os.path.basename(dll_path)
    run_note.append("probe_gt01.cpp compiled cleanly")

    hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hproc:
        raise ipp.Blocked("OpenProcess failed: %d" % ctypes.get_last_error())

    remote_path = remote_io = remote_base = None
    armed = False
    fired = False
    htid_arm = None
    cleanup = {"disarmed": None, "teardown_done": None, "dll_unloaded": None,
               "debug_regs_after": None}
    try:
        # write DLL path, LoadLibraryW
        pth = (dll_path + "\x00").encode("utf-16-le")
        remote_path = k.VirtualAllocEx(hproc, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                       ipp.PAGE_READWRITE)
        w = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, remote_path, pth, len(pth), ctypes.byref(w))
        p_ll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        h1 = k.CreateRemoteThread(hproc, None, 0, p_ll, remote_path, 0, None)
        if not h1 or k.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("LoadLibraryW remote thread failed/timeout")
        k.CloseHandle(h1)
        remote_base = ipp.find_remote_module_base(k, pid, dll_name)
        if remote_base is None:
            raise ipp.Blocked("probe DLL not in module list after LoadLibraryW")

        # control page
        io_bytes = pack_io(tid_gt, trap_addr, text_lo, text_hi)
        remote_io = k.VirtualAllocEx(hproc, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                     ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, remote_io, io_bytes, len(io_bytes), ctypes.byref(w))

        # Init -> register VEH
        rc = call_export(k, hproc, remote_base, dll_path, "Init", remote_io, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init returned 0x%x (VEH registration failed)" % rc)
        # confirm veh_installed
        rb = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)
        k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
        st = unpack_io(rb.raw)
        if st["veh_installed"] != 1:
            raise ipp.Blocked("veh_installed != 1 after Init")
        run_note.append("VEH installed in target")

        # N1 negative control: recorder on our own injected thread
        call_export(k, hproc, remote_base, dll_path, "RunSelfTest", remote_io, ipp.WAIT_TIMEOUT_MS)
        k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
        st = unpack_io(rb.raw)
        n1_self_tid = st["self_tid"]
        n1_rsp = st["self_rsp"]
        n1_ok = (st["self_done"] == 1 and n1_self_tid != tid_gt and
                 not (teb_fp["deallocation_stack"] <= n1_rsp < teb_fp["stack_base"]))
        report["negative_control_n1"] = {
            "self_tid": n1_self_tid, "gamethread_tid": tid_gt,
            "self_rsp": "0x%x" % n1_rsp, "self_done": st["self_done"],
            "distinguished": bool(n1_ok)}
        run_note.append("N1: self_tid=%d (GT=%d) distinguished=%s" % (n1_self_tid, tid_gt, n1_ok))
        if not n1_ok:
            raise ipp.Blocked("N1 negative control failed: recorder cannot distinguish our thread "
                              "from the GameThread -- instrument invalid")
        # N3: page shows no hit yet
        if st["hit_count"] != 0 or st["hit_tid"] != SENTINEL_TID:
            raise ipp.Blocked("N3 failed: page already shows a hit before arming (count=%d tid=0x%x)"
                              % (st["hit_count"], st["hit_tid"]))
        report["negative_control_n3"] = {"hit_count": 0, "hit_tid_sentinel": True}

        if not args.arm:
            report["armed"] = False
            report["outcome"] = ("DRY RUN: all read-only pre-flight + injection + N1/N2/N3 passed. "
                                 "No debug register was written. Re-run with --arm to fire GT-01.")
        else:
            htid_arm = k.OpenThread(THREAD_ARM_RIGHTS, False, tid_gt)
            if not htid_arm:
                raise ipp.Blocked("OpenThread(arm rights) failed: %d" % ctypes.get_last_error())
            readback = set_dr0(k, htid_arm, trap_addr, enable=True)
            armed = True
            run_note.append("ARMED Dr0=0x%x Dr7=0x%x (readback)" % (readback["Dr0"], readback["Dr7"]))
            if readback["Dr0"] != trap_addr:
                raise ipp.Blocked("arm readback Dr0=0x%x != trap_addr" % readback["Dr0"])
            report["arm_readback"] = {"Dr0": "0x%x" % readback["Dr0"], "Dr7": "0x%x" % readback["Dr7"]}

            # wait for the one-shot fire
            deadline = time.time() + args.timeout_s
            hit = None
            while time.time() < deadline:
                k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
                st = unpack_io(rb.raw)
                if st["hit_count"] >= 1 and st["fired"] == 1:
                    hit = st
                    break
                time.sleep(0.02)
            fired = hit is not None
            report["fired"] = fired
            if hit is not None:
                report["hit"] = {
                    "hit_count": hit["hit_count"], "hit_tid": hit["hit_tid"],
                    "hit_rip": "0x%x" % hit["hit_rip"],
                    "hit_return_addr": "0x%x" % hit["hit_return_addr"],
                    "hit_return_in_text": bool(hit["hit_return_in_text"]),
                    "hit_qpc": hit["hit_qpc"]}
                run_note.append("FIRED count=%d tid=%d rip=0x%x ret=0x%x in_text=%s"
                                % (hit["hit_count"], hit["hit_tid"], hit["hit_rip"],
                                   hit["hit_return_addr"], bool(hit["hit_return_in_text"])))
                # DIRECT evidence of the in-handler one-shot self-clear: read the
                # armed thread's Dr0 BEFORE our external disarm. If the handler
                # cleared it, this is already 0 (distinguishes handler-cleared
                # from us-cleared; the count==1 over a per-frame call is the
                # corroborating inferential proof).
                at_fire = read_debug_registers(k, htid_arm)
                report["debug_regs_at_fire"] = {r: "0x%x" % v for r, v in at_fire.items()}
                report["handler_self_cleared"] = (at_fire["Dr0"] == 0 and at_fire["Dr7"] == 0)
                run_note.append("handler_self_cleared=%s (Dr0=0x%x at fire, pre-external-disarm)"
                                % (report["handler_self_cleared"], at_fire["Dr0"]))

            # disarm / confirm cleared (handler clears on fire; do external clear regardless)
            post = set_dr0(k, htid_arm, trap_addr, enable=False)
            cleanup["disarmed"] = (post["Dr0"] == 0 and post["Dr7"] == 0)
            cleanup["debug_regs_after"] = {"Dr0": "0x%x" % post["Dr0"], "Dr7": "0x%x" % post["Dr7"]}
            armed = False
            run_note.append("disarmed: Dr0=0x%x Dr7=0x%x" % (post["Dr0"], post["Dr7"]))

            # PASS evaluation (pre-registered)
            passed = bool(
                hit is not None and hit["hit_count"] == 1 and hit["hit_tid"] == tid_gt and
                hit["hit_rip"] == trap_addr and hit["hit_return_in_text"] == 1 and
                n1_ok and cleanup["disarmed"])
            report["verdict"] = "PASS" if passed else "NOT-PASS"
            if not passed:
                report["verdict_detail"] = {
                    "count_is_1": bool(hit and hit["hit_count"] == 1),
                    "tid_matches": bool(hit and hit["hit_tid"] == tid_gt),
                    "rip_is_trap": bool(hit and hit["hit_rip"] == trap_addr),
                    "return_in_text": bool(hit and hit["hit_return_in_text"] == 1),
                    "disarmed": cleanup["disarmed"], "fired": fired}
            report["outcome"] = ("GT-01 %s: callback %s on GameThread tid=%d"
                                 % (report["verdict"], "fired" if fired else "did NOT fire", tid_gt))
    finally:
        # Teardown VEH, then unload, then free pages. Never leave the VEH armed.
        try:
            if remote_base is not None and remote_io is not None:
                call_export(k, hproc, remote_base, dll_path, "Teardown", remote_io, ipp.WAIT_TIMEOUT_MS)
                rb2 = ctypes.create_string_buffer(IO_SIZE)
                rd2 = ctypes.c_size_t(0)
                k.ReadProcessMemory(hproc, remote_io, rb2, IO_SIZE, ctypes.byref(rd2))
                cleanup["teardown_done"] = (unpack_io(rb2.raw)["teardown_done"] == 1)
        except Exception as exc:  # noqa: BLE001
            cleanup["teardown_error"] = str(exc)
        if armed and htid_arm:
            try:
                set_dr0(k, htid_arm, trap_addr, enable=False)
            except Exception:  # noqa: BLE001
                pass
        if htid_arm:
            k.CloseHandle(htid_arm)
        # FreeLibrary
        try:
            if remote_base is not None:
                p_free = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
                h3 = k.CreateRemoteThread(hproc, None, 0, p_free, remote_base, 0, None)
                if h3:
                    k.WaitForSingleObject(h3, ipp.WAIT_TIMEOUT_MS)
                    k.CloseHandle(h3)
        except Exception:  # noqa: BLE001
            pass
        for buf in (remote_path, remote_io):
            if buf is not None:
                k.VirtualFreeEx(hproc, buf, 0, ipp.MEM_RELEASE)
        try:
            cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, dll_name)
        except Exception:  # noqa: BLE001
            cleanup["dll_unloaded"] = None
        k.CloseHandle(hproc)
    report["cleanup"] = cleanup
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", action="store_true",
                        help="Actually arm the Dr0 hardware breakpoint (the single write). "
                             "Without it, run read-only pre-flight + injection + N1/N2/N3 only.")
    parser.add_argument("--timeout-s", type=float, default=8.0,
                        help="Seconds to wait for the one-shot fire after arming.")
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])

    run_id = (args.run_dir and os.path.basename(args.run_dir)) or \
        time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)

    run_note = []
    artifacts = []
    verify_before = verify_after = None
    capabilities = ["GT-01"] if args.arm else ["I-01"]
    exit_code = 0
    try:
        api = eri.Win32Api()
        if args.arm:
            verify_before = ipp.run_verify_install(run_dir, "before")
            if verify_before.get("report_artifact"):
                artifacts.append(verify_before["report_artifact"])
            if verify_before["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before session (%d serious)"
                                  % verify_before["serious_count"])
        report = run_gt01(api, args, run_dir, run_note, artifacts)
        report["run_note"] = run_note
        if args.arm:
            verify_after = ipp.run_verify_install(run_dir, "after")
            if verify_after.get("report_artifact"):
                artifacts.append(verify_after["report_artifact"])
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print(json.dumps(report, indent=2, sort_keys=True))
    except (ipp.Blocked, eri.EriError) as exc:
        report = {"blocked": True, "reason": str(exc), "run_note": run_note}
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", exc, file=sys.stderr)
        exit_code = 2
    finally:
        manifest = ipp.write_manifest(
            run_dir, arguments=arguments, capabilities_enabled=capabilities,
            build_sha256=EXPECTED_BUILD_SHA256, verify_before=verify_before,
            verify_after=verify_after, artifacts=artifacts,
            instrument_level=("ipp" if args.arm else "eri"))
        print("manifest:", manifest, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
