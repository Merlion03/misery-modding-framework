#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01A: prove MiseryRuntime can take real, GC-correct ownership
of a loaded mod asset.

  load MK_Canary (proven P-04 path, unchanged)
    -> Runtime acquires strong ownership (RootSet on the asset's FUObjectItem,
       set INSIDE the same GameThread job as the load, so there is no GC window)
    -> natural GC opportunity           -> asset must SURVIVE
    -> Runtime releases ownership
    -> natural GC opportunity           -> asset must become collectable again
    -> clean shutdown (ReleaseAll) + unload

No forced GC: the experiment relies on the engine's own periodic collection, and
proves attribution by CONTRAST (survives while rooted / collected once released).
Liveness is polled O(1) straight from the object's FUObjectItem -- no universe
walk, so polling cannot itself race a collection.
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
import fts_controller as fts  # noqa: E402
import p04_controller as p04  # noqa: E402

DLL_NAME = "CR01AProbe.dll"
TARGET_PATH = "/Game/ModKit/MK_Canary.MK_Canary"
RVA_GMALLOC = 0x7960030
FREE_SLOT_DISP = 0x48
INTERNAL_INDEX_OFFSET = 0x0C
ROOTSET_FLAG = 1 << 30
ITEM_FLAGS_OFFSET = 8
# Engine root path, derived with clean provenance (research/evidence/CR-01A/
# rootpath-derivation.json). Byte-verified live==disk before use; never guessed.
RVA_SET_ROOT_FLAGS = 0x1210E60
RVA_CLEAR_ROOT_FLAGS = 0x11BB340

IO_FMT = ("<QII QQQ 16s16s16s Q II QQQQ Q II QQ 128H "
          "IIII IIII QQQ II IIII III I III").replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 532, "Cr01aIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D43523141
IO_PROTO = 1


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO_ROOT, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO_ROOT, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
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
    bat = os.path.join(bd, "_build_cr01a.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01AProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("CR01AProbe.dll did not build:\n%s\n%s" % (r.stdout, r.stderr))
    return out


def pack_io(carrier, sigs, gmalloc_va, refl, objects_ptr, path, root_fns):
    tp = [ord(c) for c in path] + [0] * (128 - len(path))
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, 8,
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"],
        sigs["add"], sigs["get"], sigs["malloc"],
        gmalloc_va, FREE_SLOT_DISP, 0,
        refl["cdo"], refl["process_event"], refl["fn_make"], refl["fn_load"],
        objects_ptr, INTERNAL_INDEX_OFFSET, 0,
        root_fns["set"], root_fns["clear"],
        *tp,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0,
        0, 0,
        0, 0, 0, 0,
        0, 0, 0,
        0,
        0, 0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = 3 + 3 + 3 + 3 + 4 + 1 + 2 + 2 + 128
    return {"activated": f[i], "initialized": f[i+1], "state": f[i+2], "wait_stopped_ok": f[i+3],
            "load_ran": f[i+4], "load_tid": f[i+5], "fstring_ok": f[i+6], "freed": f[i+7],
            "asset_ptr": f[i+8], "item_ptr": f[i+9], "handle": f[i+10],
            "rooted_after_acquire": f[i+11], "owned_after_acquire": f[i+12],
            "release_ran": f[i+13], "rooted_after_release": f[i+14],
            "owned_after_release": f[i+15], "release_ok": f[i+16],
            "release_unknown_returned": f[i+17], "duplicate_handle_same": f[i+18],
            "owned_after_duplicate": f[i+19], "released_at_shutdown": f[i+20]}


def probe_liveness(api, handle, item_ptr, asset_ptr, np):
    """O(1) liveness+root check straight from the FUObjectItem."""
    try:
        obj = eri._read_u64(api, handle, item_ptr + 0)
        flags = struct.unpack("<i", api.read_process_memory(
            handle, item_ptr + ITEM_FLAGS_OFFSET, 4))[0]
        alive = (obj == asset_ptr)
        name = None
        if alive:
            ci, nu = struct.unpack("<II", api.read_process_memory(
                handle, asset_ptr + eri.DEFAULT_NAME_PRIVATE_OFFSET, 8))
            name = eri.decode_fname_entry_id(api, handle, np, ci).get("text")
            alive = (name == "MK_Canary")
        return {"item_object_matches": obj == asset_ptr, "name": name, "alive": alive,
                "flags_hex": "0x%x" % (flags & 0xFFFFFFFF),
                "rooted": bool(flags & ROOTSET_FLAG)}
    except Exception as exc:  # noqa: BLE001
        return {"alive": False, "error": str(exc)}


def watch(api, pid, item_ptr, asset_ptr, np, seconds, label, run_note, poll=5.0):
    """Poll liveness for `seconds`, returning the samples."""
    samples = []
    handle = eri.open_process_read_only(api, pid)
    try:
        t0 = time.time()
        while time.time() - t0 < seconds:
            s = probe_liveness(api, handle, item_ptr, asset_ptr, np)
            s["t"] = round(time.time() - t0, 1)
            samples.append(s)
            if not s.get("alive"):
                break
            time.sleep(poll)
    finally:
        api.close_handle(handle)
    alive_end = bool(samples and samples[-1].get("alive"))
    run_note.append("%s: %d samples over %.0fs, alive_at_end=%s rooted_at_end=%s"
                    % (label, len(samples), seconds, alive_end,
                       samples[-1].get("rooted") if samples else None))
    return samples


def run(api, args, run_note):
    k, has_desc = gt._k32full()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    sha = ipp.sha256_of_file(exe)
    if sha != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d build fingerprint confirmed" % pid)
    with open(exe, "rb") as f:
        img = f.read()
    addrs = fts.resolve_and_verify_addresses(api, pid, base, exe, run_note)
    gmalloc_va = base + RVA_GMALLOC

    handle = eri.open_process_read_only(api, pid)
    try:
        gm = eri._read_u64(api, handle, gmalloc_va)
        if not gm:
            raise ipp.Blocked("GMalloc null")
        vt = eri._read_u64(api, handle, gm)
        free_t = eri._read_u64(api, handle, vt + FREE_SLOT_DISP)
        if api.read_process_memory(handle, free_t, 16) != p04.disk_bytes(img, free_t - base):
            raise ipp.Blocked("Free target bytes live != disk")
        run_note.append("Free slot9 -> RVA 0x%x (live==disk)" % (free_t - base))
        i02 = eri.run_i02(api, handle, base, size,
                          guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objects_ptr = i02["objects_ptr_live_va"]
        i03 = eri.run_i03(api, handle, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        np = i03["namepool_live_va"]
        refl = p04.find_reflection_targets(api, handle, base, size, run_note)
        root_fns = {}
        for label, rva in (("set", RVA_SET_ROOT_FLAGS), ("clear", RVA_CLEAR_ROOT_FLAGS)):
            va = base + rva
            live = api.read_process_memory(handle, va, 16)
            if live != p04.disk_bytes(img, rva):
                raise ipp.Blocked("%sRootFlags bytes live != disk at RVA 0x%x" % (label, rva))
            root_fns[label] = va
            run_note.append("%sRootFlags: RVA 0x%x -> VA 0x%x byte-verified live==disk (%s)"
                            % (label, rva, va, live[:8].hex()))
    finally:
        api.close_handle(handle)

    report = {"pid": pid, "build_sha256": sha, "objects_ptr_hex": "0x%x" % objects_ptr,
              "reference_mechanism": {
                  "name": "EInternalObjectFlags::RootSet on the asset's FUObjectItem",
                  "flag": "1<<30 (ObjectMacros.h:624)",
                  "equivalent_engine_api": "UObject::AddToRoot()/RemoveFromRoot() "
                                           "(UObjectBaseUtility.h:196-205, FORCEINLINE)",
                  "engine_functions_called": "FUObjectItem::SetRootFlags RVA 0x1210e60 / ClearRootFlags RVA 0x11bb340 (derived; GRootsCritical RVA 0x7a64310 shared by both)",
                  "why_no_callback_into_our_module":
                      "the reference is a bit in engine-owned FUObjectItem memory, not a "
                      "pointer into ours, so GC never calls our code (unlike FGCObject)"}}
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: baseline + targets resolved, nothing injected."
        return report

    dll = build_dll()
    run_note.append("CR01AProbe.dll built")
    sigs = {"add": p04.disk_bytes(img, fts.RVA_ADD_TICKER),
            "get": p04.disk_bytes(img, fts.RVA_GET_CORE_TICKER),
            "malloc": p04.disk_bytes(img, fts.RVA_FMEMORY_MALLOC)}
    carrier = {"add_ticker": addrs["add_ticker"], "get_core_ticker": addrs["get_core_ticker"],
               "fmemory_malloc": addrs["fmemory_malloc"]}

    hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hproc:
        raise ipp.Blocked("OpenProcess failed")
    rpath = rio = rbase = None
    cleanup = {}
    try:
        pth = (dll + "\x00").encode("utf-16-le")
        rpath = k.VirtualAllocEx(hproc, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                 ipp.PAGE_READWRITE)
        w = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, rpath, pth, len(pth), ctypes.byref(w))
        pll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        h1 = k.CreateRemoteThread(hproc, None, 0, pll, rpath, 0, None)
        k.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(h1)
        rbase = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if rbase is None:
            raise ipp.Blocked("probe DLL not loaded")

        io = pack_io(carrier, sigs, gmalloc_va, refl, objects_ptr, TARGET_PATH, root_fns)
        rio = k.VirtualAllocEx(hproc, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                               ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, rio, io, len(io), ctypes.byref(w))
        buf = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hproc, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        rc = p04.call_export(k, hproc, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init failed 0x%x" % rc)
        run_note.append("Init ok")

        p04.call_export(k, hproc, rbase, dll, "RunLoadAndAcquire", rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io()
        deadline = time.time() + 20
        while time.time() < deadline and st["load_ran"] == 0:
            time.sleep(0.05)
            st = read_io()
        report["acquire"] = {kk: st[kk] for kk in
                             ("load_ran", "load_tid", "fstring_ok", "freed", "handle",
                              "rooted_after_acquire", "owned_after_acquire",
                              "duplicate_handle_same", "owned_after_duplicate",
                              "release_unknown_returned")}
        report["acquire"]["asset_ptr_hex"] = "0x%x" % st["asset_ptr"]
        report["acquire"]["item_ptr_hex"] = "0x%x" % st["item_ptr"]
        run_note.append("acquired: asset=0x%x item=0x%x handle=%d rooted=%d owned=%d"
                        % (st["asset_ptr"], st["item_ptr"], st["handle"],
                           st["rooted_after_acquire"], st["owned_after_acquire"]))
        if not st["asset_ptr"] or not st["item_ptr"] or st["rooted_after_acquire"] != 1:
            raise ipp.Blocked("acquire did not establish ownership")

        asset_ptr, item_ptr = st["asset_ptr"], st["item_ptr"]
        report["phase1_rooted_watch"] = watch(api, pid, item_ptr, asset_ptr, np,
                                              args.gc_window_s, "phase1 (rooted)", run_note)

        p04.call_export(k, hproc, rbase, dll, "RunRelease", rio, ipp.WAIT_TIMEOUT_MS)
        st2 = read_io()
        deadline = time.time() + 20
        while time.time() < deadline and st2["release_ran"] == 0:
            time.sleep(0.05)
            st2 = read_io()
        report["release"] = {kk: st2[kk] for kk in
                             ("release_ran", "release_ok", "rooted_after_release",
                              "owned_after_release")}
        run_note.append("released: ok=%d rooted_now=%d owned=%d"
                        % (st2["release_ok"], st2["rooted_after_release"],
                           st2["owned_after_release"]))

        report["phase2_unrooted_watch"] = watch(api, pid, item_ptr, asset_ptr, np,
                                                args.gc_window_s, "phase2 (released)", run_note)

        p04.call_export(k, hproc, rbase, dll, "Shutdown", rio, 20000)
        st3 = read_io()
        report["shutdown"] = {kk: st3[kk] for kk in
                              ("released_at_shutdown", "wait_stopped_ok", "state")}
    finally:
        if rbase is not None:
            pf = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
            h3 = k.CreateRemoteThread(hproc, None, 0, pf, rbase, 0, None)
            if h3:
                k.WaitForSingleObject(h3, ipp.WAIT_TIMEOUT_MS)
                k.CloseHandle(h3)
        for b in (rpath, rio):
            if b is not None:
                k.VirtualFreeEx(hproc, b, 0, ipp.MEM_RELEASE)
        try:
            cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
        except Exception:  # noqa: BLE001
            cleanup["dll_unloaded"] = None
        k.CloseHandle(hproc)
    report["cleanup"] = cleanup

    p1 = report.get("phase1_rooted_watch") or []
    p2 = report.get("phase2_unrooted_watch") or []
    survived_rooted = bool(p1 and p1[-1].get("alive") and p1[-1].get("rooted"))
    collected_after_release = bool(p2 and not p2[-1].get("alive"))
    report["survived_while_rooted"] = survived_rooted
    report["collected_after_release"] = collected_after_release
    report["verdict"] = "PASS" if (
        survived_rooted and collected_after_release and
        report["acquire"]["rooted_after_acquire"] == 1 and
        report["acquire"]["duplicate_handle_same"] == 1 and
        report["acquire"]["owned_after_duplicate"] == 1 and
        report["acquire"]["release_unknown_returned"] == 0 and
        report["release"]["release_ok"] == 1 and
        report["release"]["rooted_after_release"] == 0 and
        report["release"]["owned_after_release"] == 0 and
        report["shutdown"]["wait_stopped_ok"] == 1 and
        cleanup.get("dll_unloaded")) else "NOT-PASS"
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--gc-window-s", type=float, default=150.0,
                    help="seconds to watch in each phase (UE's default periodic GC is ~60s)")
    ap.add_argument("--run-dir", default=None)
    args = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    run_id = (args.run_dir and os.path.basename(args.run_dir)) or \
        time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    run_note, artifacts = [], []
    vb = va = None
    caps = ["CR-01A"] if args.arm else ["I-01"]
    code = 0
    try:
        api = eri.Win32Api()
        if args.arm:
            vb = ipp.run_verify_install(run_dir, "before")
            if vb.get("report_artifact"):
                artifacts.append(vb["report_artifact"])
            if vb["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before")
        rep = run(api, args, run_note)
        rep["run_note"] = run_note
        if args.arm:
            va = ipp.run_verify_install(run_dir, "after")
            if va.get("report_artifact"):
                artifacts.append(va["report_artifact"])
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print(json.dumps(rep, indent=2, sort_keys=True))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": run_note}
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(run_dir, arguments=arguments, capabilities_enabled=caps,
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=artifacts,
                           instrument_level=("ipp" if args.arm else "eri"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
