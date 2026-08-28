#!/usr/bin/env python3
"""RESEARCH ONLY -- NOT PRODUCTION. See README.md and plan.md 8.1/8.3/8.4/8.5.

Carrier-gate controller (capability CARRIER-FTS, escalation ESC-05): register ONE
one-shot POD callback on the live GameThread through the sanctioned FTSTicker
scheduler, using the MSVC-built probe DLL (probe_ftsticker.cpp) that constructs a
legitimate TFunction from genuine UE headers. No vtable/.text write, no HW-BP.

Every game-side address is fingerprint-gated: the live exe's sha256 must equal the
build_key (which guarantees base+RVA is the analyzed function), AND the first
bytes at each resolved VA are re-read live and compared to the on-disk image
(read-only) to catch any runtime patching. Addresses + provenance:
research/evidence/CARRIER-01/derived-addresses.json (LOG-0074).

The single write phase (inject + CreateRemoteThread) is gated behind --arm; without
it this runs read-only pre-flight (identity + address byte-verify + GameThread id)
and does not touch the process.
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
import gt01_controller as gt  # noqa: E402  (GameThread identification + thread helpers)

TOOL_VERSION = "fts-controller-0.1.0"
EXPECTED_BUILD_SHA256 = "bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331"

# Derived, clean-provenance, fingerprint-gated (LOG-0074).
RVA_ADD_TICKER = 0xF4DED0
RVA_GET_CORE_TICKER = 0xF53370
RVA_FMEMORY_MALLOC = 0xFAB790

# FtsProbeIo wire format -- MUST match probe_ftsticker.cpp (72 bytes).
IO_FMT = "<QIIQQQ IIII QQ"
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 72, "FtsProbeIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D46545354  # "IPP-FTST"
IO_PROTO = 1
MARKER_FIRED = 0x46495245  # "FIRE"

DLL_NAME = "ipp_ftsticker_probe.dll"


def build_probe_dll():
    """Compile probe_ftsticker.cpp fresh with MSVC 14.38 + real UE headers, same
    clean-build discipline as the other probes."""
    import subprocess
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if not os.path.isfile(vcvars):
        raise ipp.Blocked("MSVC vcvars64 not found at %r" % vcvars)
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    src = os.path.join(IPP_DIR, "probe_ftsticker", "probe_ftsticker.cpp")
    build_dir = os.path.join(REPO_ROOT, "workspace", "msvc-probe")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, DLL_NAME)
    defs = ("/DPLATFORM_WINDOWS=1 /DPLATFORM_MICROSOFT=1 /DPLATFORM_64BITS=1 "
            "/DUE_BUILD_SHIPPING=1 /DUE_BUILD_DEVELOPMENT=0 /DUE_BUILD_TEST=0 /DUE_BUILD_DEBUG=0 "
            "/DWITH_EDITOR=0 /DWITH_EDITORONLY_DATA=0 /DWITH_ENGINE=0 /DWITH_SERVER_CODE=1 "
            "/DWITH_UNREAL_DEVELOPER_TOOLS=0 /DWITH_PLUGIN_SUPPORT=0 /DWITH_ACCESSIBILITY=0 "
            "/DIS_MONOLITHIC=1 /DIS_PROGRAM=0 /DCORE_API= /DCOREUOBJECT_API= /DTRACELOG_API= "
            "/DUNICODE /D_UNICODE /DPLATFORM_EXCEPTIONS_DISABLED=0 "
            "/D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 "
            "/DUBT_COMPILED_PLATFORM=Windows /DOVERRIDE_PLATFORM_HEADER_NAME=Windows")
    inc = ('/I"%s\\Core\\Public" /I"%s\\TraceLog\\Public" /I"%s\\Core\\Internal"'
           % (ue, ue, ue))
    if os.path.isfile(out):
        os.remove(out)
    bat = os.path.join(build_dir, "_build_ftsticker.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, src, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=build_dir, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("probe_ftsticker.cpp did not build (rc=%s):\nSTDOUT:\n%s\nSTDERR:\n%s"
                          % (r.returncode, r.stdout, r.stderr))
    return out


def resolve_and_verify_addresses(api, pid, base, exe_path, run_note):
    """Fingerprint-gate: whole-image sha256 == build_key, AND the first bytes at
    each resolved VA match the on-disk image byte-for-byte (no runtime patch)."""
    with open(exe_path, "rb") as f:
        img = f.read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    nsec = struct.unpack_from("<H", img, pe + 4 + 2)[0]
    sizeopt = struct.unpack_from("<H", img, pe + 4 + 16)[0]
    sect = pe + 4 + 20 + sizeopt
    secs = []
    for i in range(nsec):
        b = sect + i * 40
        vs, va, rs, rp = struct.unpack_from("<IIII", img, b + 8)
        secs.append((va, vs, rp, rs))

    def rva_disk_bytes(rva, n):
        for va, vs, rp, rs in secs:
            if va <= rva < va + max(vs, rs) and rva - va < rs:
                off = rp + (rva - va)
                return img[off:off + n]
        return None

    out = {}
    ro = eri.open_process_read_only(api, pid)
    try:
        for name, rva in (("add_ticker", RVA_ADD_TICKER),
                          ("get_core_ticker", RVA_GET_CORE_TICKER),
                          ("fmemory_malloc", RVA_FMEMORY_MALLOC)):
            va = base + rva
            disk = rva_disk_bytes(rva, 16)
            live = api.read_process_memory(ro, va, 16)
            if disk != live:
                raise ipp.Blocked("byte mismatch at %s RVA 0x%x: disk %s live %s -- refusing "
                                  "(possible runtime patch)" % (name, rva, disk.hex(), live.hex()))
            out[name] = va
            run_note.append("%s: VA 0x%x byte-verified live==disk (%s)"
                            % (name, va, live[:8].hex()))
    finally:
        api.close_handle(ro)
    return out


def pack_io(add_ticker, get_core_ticker, fmemory_malloc):
    return struct.pack(IO_FMT, IO_MAGIC, IO_PROTO, 0,
                       add_ticker, get_core_ticker, fmemory_malloc,
                       0, 0, 0, 0, 0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    return {"magic": f[0], "proto": f[1], "registered_ok": f[2], "add_ticker": f[3],
            "get_core_ticker": f[4], "fmemory_malloc": f[5], "marker": f[6],
            "callback_tid": f[7], "callback_count": f[8], "worker_tid": f[9]}


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


def run(api, args, run_note):
    k, has_desc = gt._k32full()
    nt = gt._ntdll()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base = i01["pid"], i01["base_address"]
    observed = ipp.sha256_of_file(i01["exe_path"])
    if observed != EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build identity mismatch: live=%s expected=%s" % (observed, EXPECTED_BUILD_SHA256))
    run_note.append("build identity confirmed sha256:%s" % observed)

    addrs = resolve_and_verify_addresses(api, pid, base, i01["exe_path"], run_note)

    # GameThread identity (Method 1 from GT-01): to check the callback thread.
    with open(i01["exe_path"], "rb") as f:
        img = f.read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    entry_rva = struct.unpack_from("<I", img, pe + 4 + 20 + 16)[0]
    gtinfo = gt.identify_gamethread(k, nt, has_desc, pid, base, entry_rva, api, run_note)
    e1, e2 = gtinfo["e1"], gtinfo["e2"]
    tid_gt = e1 if e1 is not None else e2
    if e1 is not None and e2 is not None and e1 != e2:
        raise ipp.Blocked("GameThread E1(%s)!=E2(%s)" % (e1, e2))
    run_note.append("GameThread tid=%s (E1=%s E2=%s)" % (tid_gt, e1, e2))

    report = {"pid": pid, "base_address": "0x%x" % base, "build_sha256": observed,
              "addresses": {n: "0x%x" % v for n, v in addrs.items()},
              "gamethread_tid": tid_gt, "e1": e1, "e2": e2}

    if not args.arm:
        report["armed"] = False
        report["outcome"] = ("DRY RUN: identity + address byte-verify + GameThread id passed. "
                             "No injection. Re-run with --arm for the live one-shot.")
        return report

    dll_path = build_probe_dll()
    run_note.append("probe_ftsticker.cpp built with MSVC 14.38")

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
            raise ipp.Blocked("probe DLL not in module list")

        io_bytes = pack_io(addrs["add_ticker"], addrs["get_core_ticker"], addrs["fmemory_malloc"])
        remote_io = k.VirtualAllocEx(hproc, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, remote_io, io_bytes, len(io_bytes), ctypes.byref(w))

        rc = call_export(k, hproc, remote_base, dll_path, "Init", remote_io, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init returned 0x%x" % rc)
        run_note.append("Init ok")

        rc2 = call_export(k, hproc, remote_base, dll_path, "RegisterTicker", remote_io, ipp.WAIT_TIMEOUT_MS)
        run_note.append("RegisterTicker returned 0x%x" % rc2)

        rb = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)
        # poll for the callback to fire on the GameThread
        hit = None
        deadline = time.time() + args.timeout_s
        while time.time() < deadline:
            k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
            st = unpack_io(rb.raw)
            if st["marker"] == MARKER_FIRED and st["callback_count"] >= 1:
                hit = st
                break
            time.sleep(0.02)
        if hit is None:
            k.ReadProcessMemory(hproc, remote_io, rb, IO_SIZE, ctypes.byref(rd))
            st = unpack_io(rb.raw)
        report["register_rc"] = rc2
        report["registered_ok"] = st["registered_ok"]
        report["worker_tid"] = st["worker_tid"]
        report["fired"] = hit is not None
        if hit is not None:
            report["callback_tid"] = hit["callback_tid"]
            report["callback_count"] = hit["callback_count"]
            report["marker_hex"] = "0x%x" % hit["marker"]
            run_note.append("FIRED: callback_tid=%d count=%d (GameThread=%s worker=%d)"
                            % (hit["callback_tid"], hit["callback_count"], tid_gt, hit["worker_tid"]))

        # let the element self-remove + destroy (holds our DLL vtable) before unload
        time.sleep(args.settle_s)

        passed = bool(hit is not None and hit["callback_count"] == 1 and
                      hit["callback_tid"] == tid_gt and st["registered_ok"] == 1 and
                      hit["worker_tid"] != tid_gt)
        report["verdict"] = "PASS" if passed else "NOT-PASS"
        report["outcome"] = ("CARRIER-FTS %s: callback %s on GameThread tid=%s"
                             % (report["verdict"], "fired" if hit else "did NOT fire", tid_gt))
    finally:
        # unload + free
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", action="store_true", help="Perform the live injection + registration.")
    parser.add_argument("--timeout-s", type=float, default=8.0)
    parser.add_argument("--settle-s", type=float, default=1.0,
                        help="Wait after the fire for the element to self-remove/destroy before unload.")
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])

    run_id = (args.run_dir and os.path.basename(args.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    run_note = []
    artifacts = []
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
