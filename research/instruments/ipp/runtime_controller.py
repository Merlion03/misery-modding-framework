#!/usr/bin/env python3
"""RESEARCH ONLY -- NOT PRODUCTION. See README.md and plan.md 8.1/8.3/8.4/8.5.

MiseryRuntime GameThread Dispatcher -- live test (capability CARRIER-FTS, same
escalation family as ESC-05; POD-only, no gameplay). Injects the MSVC-built
MiseryRuntime.dll, which registers ONE persistent FTSTicker pump, runs a
multi-producer POD-job test drained on the GameThread, then does the explicit
Shutdown handshake. All game-side addresses are fingerprint-gated and byte-
verified live==disk, and passed to the DLL, which re-verifies them and fails
closed on mismatch (game runs vanilla).

Gated behind --arm; without it, read-only pre-flight only.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP_DIR)
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
import eri  # noqa: E402
import ipp_controller as ipp  # noqa: E402
import gt01_controller as gt  # noqa: E402
import fts_controller as fts  # noqa: E402 (reuse address resolve/verify + RVAs)

EXPECTED_BUILD_SHA256 = fts.EXPECTED_BUILD_SHA256
DLL_NAME = "MiseryRuntime.dll"

IO_FMT = "<QII QQQ 16s16s16s IIII II IIIII I 8I i IIII 7I"
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 216, "RuntimeIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D4D525452  # "IPP-MRTR"
IO_PROTO = 1


def build_runtime_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if not os.path.isfile(vcvars):
        raise ipp.Blocked("MSVC vcvars64 not found")
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO_ROOT, "runtime", "MiseryRuntime", "Internal")
    build_dir = os.path.join(REPO_ROOT, "workspace", "msvc-probe")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, DLL_NAME)
    if os.path.isfile(out):
        os.remove(out)
    defs = ("/DPLATFORM_WINDOWS=1 /DPLATFORM_MICROSOFT=1 /DPLATFORM_64BITS=1 "
            "/DUE_BUILD_SHIPPING=1 /DUE_BUILD_DEVELOPMENT=0 /DUE_BUILD_TEST=0 /DUE_BUILD_DEBUG=0 "
            "/DWITH_EDITOR=0 /DWITH_EDITORONLY_DATA=0 /DWITH_ENGINE=0 /DWITH_SERVER_CODE=1 "
            "/DWITH_UNREAL_DEVELOPER_TOOLS=0 /DWITH_PLUGIN_SUPPORT=0 /DWITH_ACCESSIBILITY=0 "
            "/DIS_MONOLITHIC=1 /DIS_PROGRAM=0 /DCORE_API= /DCOREUOBJECT_API= /DTRACELOG_API= "
            "/DUNICODE /D_UNICODE /DPLATFORM_EXCEPTIONS_DISABLED=0 "
            "/D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 "
            "/DUBT_COMPILED_PLATFORM=Windows /DOVERRIDE_PLATFORM_HEADER_NAME=Windows")
    inc = ('/I"%s\\Core\\Public" /I"%s\\TraceLog\\Public" /I"%s\\Core\\Internal"' % (ue, ue, ue))
    bat = os.path.join(build_dir, "_build_runtime_ctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\MiseryRuntimeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=build_dir, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("MiseryRuntime.dll did not build:\n%s\n%s" % (r.stdout, r.stderr))
    return out


def read_sig(exe_path, rva, n=16):
    with open(exe_path, "rb") as f:
        img = f.read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    nsec = struct.unpack_from("<H", img, pe + 4 + 2)[0]
    sizeopt = struct.unpack_from("<H", img, pe + 4 + 16)[0]
    sect = pe + 4 + 20 + sizeopt
    for i in range(nsec):
        b = sect + i * 40
        vs, va, rs, rp = struct.unpack_from("<IIII", img, b + 8)
        if va <= rva < va + max(vs, rs) and rva - va < rs:
            off = rp + (rva - va)
            return img[off:off + n]
    raise ipp.Blocked("rva 0x%x not in a section" % rva)


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


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    return {"activated": f[13], "initialized": f[14], "submitted": f[15], "executed": f[16],
            "dropped": f[17], "rejected": f[18], "ticks": f[19], "exec_thread_id": f[20],
            "worker_tids": list(f[21:29]), "state": f[29], "wait_stopped_ok": f[30],
            "exactly_once": f[31], "all_on_gamethread": f[32], "ticks_after_shutdown_delta": f[33]}


def run(api, args, run_note):
    k, has_desc = gt._k32full()
    nt = gt._ntdll()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, exe = i01["pid"], i01["base_address"], i01["exe_path"]
    observed = ipp.sha256_of_file(exe)
    if observed != EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build identity mismatch: live=%s expected=%s" % (observed, EXPECTED_BUILD_SHA256))
    run_note.append("build identity confirmed sha256:%s" % observed)
    addrs = fts.resolve_and_verify_addresses(api, pid, base, exe, run_note)
    sigs = {n: read_sig(exe, rva) for n, rva in
            (("add", fts.RVA_ADD_TICKER), ("get", fts.RVA_GET_CORE_TICKER), ("malloc", fts.RVA_FMEMORY_MALLOC))}

    with open(exe, "rb") as f:
        img = f.read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    entry_rva = struct.unpack_from("<I", img, pe + 4 + 20 + 16)[0]
    gtinfo = gt.identify_gamethread(k, nt, has_desc, pid, base, entry_rva, api, run_note)
    e1, e2 = gtinfo["e1"], gtinfo["e2"]
    tid_gt = e1 if e1 is not None else e2
    if e1 is not None and e2 is not None and e1 != e2:
        raise ipp.Blocked("GameThread E1(%s)!=E2(%s)" % (e1, e2))
    run_note.append("GameThread tid=%s" % tid_gt)

    report = {"pid": pid, "build_sha256": observed, "gamethread_tid": tid_gt,
              "addresses": {n: "0x%x" % v for n, v in addrs.items()}}
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: identity + address verify + GameThread id passed."
        return report

    dll_path = build_runtime_dll()
    run_note.append("MiseryRuntime.dll built with MSVC 14.38")

    hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hproc:
        raise ipp.Blocked("OpenProcess failed: %d" % ctypes.get_last_error())
    remote_path = remote_io = remote_base = None
    cleanup = {}
    try:
        pth = (dll_path + "\x00").encode("utf-16-le")
        remote_path = k.VirtualAllocEx(hproc, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        w = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, remote_path, pth, len(pth), ctypes.byref(w))
        p_ll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        h1 = k.CreateRemoteThread(hproc, None, 0, p_ll, remote_path, 0, None)
        if not h1 or k.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("LoadLibraryW failed/timeout")
        k.CloseHandle(h1)
        remote_base = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if remote_base is None:
            raise ipp.Blocked("runtime DLL not in module list")

        io = struct.pack(IO_FMT, IO_MAGIC, IO_PROTO, args.max_per_tick,
                         addrs["add_ticker"], addrs["get_core_ticker"], addrs["fmemory_malloc"],
                         sigs["add"], sigs["get"], sigs["malloc"],
                         args.producers, args.jobs, args.test_timeout_ms, args.shutdown_timeout_ms,
                         0, 0, 0, 0, 0, 0, 0, 0, *([0] * 8), 0, 0, 0, 0, 0, *([0] * 7))
        remote_io = k.VirtualAllocEx(hproc, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, remote_io, io, len(io), ctypes.byref(w))

        rc_init = call_export(k, hproc, remote_base, dll_path, "Init", remote_io, ipp.WAIT_TIMEOUT_MS)
        run_note.append("Init rc=0x%x" % rc_init)
        rc_run = call_export(k, hproc, remote_base, dll_path, "RunTest", remote_io, 30000)
        run_note.append("RunTest rc=0x%x" % rc_run)
        rc_sd = call_export(k, hproc, remote_base, dll_path, "Shutdown", remote_io, 30000)
        run_note.append("Shutdown rc=0x%x" % rc_sd)

        rb = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)
        k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
        st = unpack_io(rb.raw)
        report["result"] = st
        total = args.producers * args.jobs
        workers_ok = all(st["worker_tids"][p] != tid_gt for p in range(args.producers))
        passed = bool(
            st["activated"] == 1 and st["initialized"] == 1 and
            st["submitted"] == total and st["executed"] == total and st["dropped"] == 0 and
            st["exec_thread_id"] == tid_gt and workers_ok and
            st["exactly_once"] == 1 and st["all_on_gamethread"] == 1 and
            st["state"] == 3 and st["wait_stopped_ok"] == 1 and
            st["ticks_after_shutdown_delta"] == 0)
        report["workers_distinct_from_gamethread"] = workers_ok
        report["verdict"] = "PASS" if passed else "NOT-PASS"
        report["outcome"] = ("Dispatcher %s: %d/%d jobs exactly-once on GameThread tid=%s; "
                             "shutdown handshake=%s; pump stopped=%s"
                             % (report["verdict"], st["executed"], total, tid_gt,
                                st["wait_stopped_ok"] == 1, st["ticks_after_shutdown_delta"] == 0))
    finally:
        if remote_base is not None:
            p_free = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
            h3 = k.CreateRemoteThread(hproc, None, 0, p_free, remote_base, 0, None)
            if h3:
                k.WaitForSingleObject(h3, ipp.WAIT_TIMEOUT_MS)
                k.CloseHandle(h3)
        for buf in (remote_path, remote_io):
            if buf is not None:
                k.VirtualFreeEx(hproc, buf, 0, ipp.MEM_RELEASE)
        try:
            cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
        except Exception:  # noqa: BLE001
            cleanup["dll_unloaded"] = None
        k.CloseHandle(hproc)
    report["cleanup"] = cleanup
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--arm", action="store_true")
    p.add_argument("--producers", type=int, default=4)
    p.add_argument("--jobs", type=int, default=200)
    p.add_argument("--max-per-tick", type=int, default=32)
    p.add_argument("--test-timeout-ms", type=int, default=8000)
    p.add_argument("--shutdown-timeout-ms", type=int, default=5000)
    p.add_argument("--run-dir", default=None)
    args = p.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    run_id = (args.run_dir and os.path.basename(args.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    run_note, artifacts = [], []
    verify_before = verify_after = None
    caps = ["CARRIER-FTS"] if args.arm else ["I-01"]
    exit_code = 0
    try:
        api = eri.Win32Api()
        if args.arm:
            verify_before = ipp.run_verify_install(run_dir, "before")
            if verify_before.get("report_artifact"):
                artifacts.append(verify_before["report_artifact"])
            if verify_before["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before (%d serious)" % verify_before["serious_count"])
        report = run(api, args, run_note)
        report["run_note"] = run_note
        if args.arm:
            verify_after = ipp.run_verify_install(run_dir, "after")
            if verify_after.get("report_artifact"):
                artifacts.append(verify_after["report_artifact"])
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True); f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print(json.dumps(report, indent=2, sort_keys=True))
    except (ipp.Blocked, eri.EriError) as exc:
        report = {"blocked": True, "reason": str(exc), "run_note": run_note}
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True); f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", exc, file=sys.stderr)
        exit_code = 2
    finally:
        ipp.write_manifest(run_dir, arguments=arguments, capabilities_enabled=caps,
                           build_sha256=EXPECTED_BUILD_SHA256, verify_before=verify_before,
                           verify_after=verify_after, artifacts=artifacts,
                           instrument_level=("ipp" if args.arm else "eri"))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
