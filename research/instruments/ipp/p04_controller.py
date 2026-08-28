#!/usr/bin/env python3
"""RESEARCH ONLY. P-04 live experiment -- executes EXACTLY the pre-registered
chain in research/evidence/P-04/preregistration.md and nothing else.

Re-confirms the live baseline, resolves every target by reflection / proven
derivation (byte-verifying each live address against the hash-checked on-disk
image), injects the P-04 probe, runs the positive pass then the pre-registered
negative control through the proven GameThread dispatcher, shuts down, unloads,
and then inspects the result STRICTLY READ-ONLY.

Gated behind --arm.
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

EXPECTED_BUILD_SHA256 = fts.EXPECTED_BUILD_SHA256
DLL_NAME = "P04Probe.dll"
TARGET_PATH = "/Game/ModKit/MK_Canary.MK_Canary"
NEGATIVE_PATH = "/Game/ModKit/CT05_DOES_NOT_EXIST.CT05_DOES_NOT_EXIST"
EXPECTED_PACKAGE_ID = 0xF6620D12509F26D7
RVA_GMALLOC = 0x7960030
FREE_SLOT_DISP = 0x48
PROCESSEVENT_SLOT = 77

CALLREC = "IIII Q IIII Q II Q II"
IO_FMT = ("<QII QQQ 16s16s16s Q II QQQQ 128H 128H IIII " + CALLREC + CALLREC).replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 808, "P04Io wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D50303400
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
    bat = os.path.join(bd, "_build_p04ctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\P04ProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("P04Probe.dll did not build:\n%s\n%s" % (r.stdout, r.stderr))
    return out


def disk_bytes(img, rva, n=16):
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    nsec = struct.unpack_from("<H", img, pe + 6)[0]
    so = struct.unpack_from("<H", img, pe + 20)[0]
    sect = pe + 24 + so
    for i in range(nsec):
        b = sect + i * 40
        vs, va, rs, rp = struct.unpack_from("<IIII", img, b + 8)
        if va <= rva < va + max(vs, rs) and rva - va < rs:
            off = rp + (rva - va)
            return img[off:off + n]
    return None


def utoc_has_package_id(pak_path, pid_u64):
    utoc = os.path.splitext(pak_path)[0] + ".utoc"
    local = utoc.replace("../../../MISERY/", "")
    for cand in (utoc, local):
        if os.path.isfile(cand):
            with open(cand, "rb") as f:
                data = f.read()
            return struct.pack("<Q", pid_u64) in data, cand
    return None, utoc


def call_export(k, hproc, base, dll, name, arg, timeout):
    rva = ipp.find_export_rva(dll, name)
    t = k.CreateRemoteThread(hproc, None, 0, base + rva, arg, 0, None)
    if not t:
        raise ipp.Blocked("CreateRemoteThread(%s) failed" % name)
    w = k.WaitForSingleObject(t, timeout)
    c = wt.DWORD(0)
    k.GetExitCodeThread(t, ctypes.byref(c))
    k.CloseHandle(t)
    if w != 0:
        raise ipp.Blocked("%s hung" % name)
    return c.value


def find_reflection_targets(api, handle, base, size, run_note):
    """Read-only: CDO, the two UFunctions, ProcessEvent via CDO vtable slot 77."""
    i02 = eri.run_i02(api, handle, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03 = eri.run_i03(api, handle, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                      name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                      name_entry_id=0)
    np = i03["namepool_live_va"]
    walk = eri.walk_object_universe(api, handle, i02["objects_ptr_live_va"], i02["num_elements"],
                                    base, size, np,
                                    class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                    name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                    outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                    max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    objs = walk["objects_by_address"]
    cls = cdo = fmeta = None
    for a, r in objs.items():
        if not r.get("name_ok"):
            continue
        nm = r.get("name_text")
        if nm == "KismetSystemLibrary" and cls is None:
            if eri.canonicalize_object_path(eri.resolve_object_path(a, objs).get("object_path")) \
                    == "/Script/Engine.KismetSystemLibrary":
                cls = a
        elif nm == "Default__KismetSystemLibrary" and cdo is None:
            cdo = a
        elif nm == "Function" and fmeta is None:
            if eri.canonicalize_object_path(eri.resolve_object_path(a, objs).get("object_path")) \
                    == "/Script/CoreUObject.Function":
                fmeta = a
    if cls is None or cdo is None or fmeta is None:
        raise ipp.Blocked("could not resolve KismetSystemLibrary class/CDO/Function meta")
    chain = eri.walk_children_chain(api, handle,
                                    eri._read_u64(api, handle, cls + eri.USTRUCT_CHILDREN_OFFSET),
                                    namepool_live_va=np, owner_address=cls,
                                    function_class_address=fmeta)
    fns = {}
    for fn in chain.get("accepted", []):
        if fn.get("raw_name") in ("MakeSoftObjectPath", "LoadAsset_Blocking"):
            fns[fn["raw_name"]] = fn["address"]
    if len(fns) != 2:
        raise ipp.Blocked("could not resolve both UFunctions: %s" % list(fns))
    vtbl = eri._read_u64(api, handle, cdo)
    if not (base <= vtbl < base + size):
        raise ipp.Blocked("CDO vtable 0x%x outside module" % vtbl)
    pe = eri._read_u64(api, handle, vtbl + PROCESSEVENT_SLOT * 8)
    if not (base <= pe < base + size):
        raise ipp.Blocked("ProcessEvent 0x%x outside module" % pe)
    run_note.append("CDO 0x%x vtable 0x%x ProcessEvent 0x%x (slot %d)" % (cdo, vtbl, pe, PROCESSEVENT_SLOT))
    run_note.append("MakeSoftObjectPath 0x%x  LoadAsset_Blocking 0x%x"
                    % (fns["MakeSoftObjectPath"], fns["LoadAsset_Blocking"]))
    return {"cdo": cdo, "process_event": pe, "np": np, "objs": objs,
            "fn_make": fns["MakeSoftObjectPath"], "fn_load": fns["LoadAsset_Blocking"]}


def pack_io(carrier, sigs, gmalloc_va, tgt, neg, refl):
    tp = [ord(c) for c in tgt] + [0] * (128 - len(tgt))
    npth = [ord(c) for c in neg] + [0] * (128 - len(neg))
    zero_rec = (0,) * 15
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, 8,
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"],
        sigs["add"], sigs["get"], sigs["malloc"],
        gmalloc_va, FREE_SLOT_DISP, 0,
        refl["cdo"], refl["process_event"], refl["fn_make"], refl["fn_load"],
        *tp, *npth,
        0, 0, 0, 0,
        *zero_rec, *zero_rec)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    base = 3 + 3 + 3 + 3 + 4 + 256  # scalars before the 4 lifecycle fields
    i = 0
    # walk positions explicitly
    pos = {}
    idx = 0
    idx += 1  # magic
    idx += 1  # proto
    idx += 1  # max_jobs
    idx += 3  # add,get,malloc
    idx += 3  # sigs
    idx += 1  # gmalloc
    idx += 2  # free_slot, pad
    idx += 4  # cdo, pe, make, load
    idx += 128 + 128
    life = f[idx:idx + 4]
    idx += 4

    def rec(o):
        return {"ran": f[o], "callback_tid": f[o + 1], "fstring_len": f[o + 2],
                "fstring_ok": f[o + 3], "fstring_buffer": f[o + 4],
                "pkg_cmp_index": f[o + 5], "pkg_number": f[o + 6],
                "asset_cmp_index": f[o + 7], "asset_number": f[o + 8],
                "subpath_data": f[o + 9], "subpath_num": f[o + 10], "subpath_max": f[o + 11],
                "returned_object": f[o + 12], "freed": f[o + 13]}
    return {"activated": life[0], "initialized": life[1], "state": life[2],
            "wait_stopped_ok": life[3], "positive": rec(idx), "negative": rec(idx + 15)}


def inspect_result(api, handle, base, size, obj_ptr, run_note):
    """STRICTLY READ-ONLY post-load inspection of the returned UObject."""
    if not obj_ptr:
        return {"present": False}
    i02 = eri.run_i02(api, handle, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03 = eri.run_i03(api, handle, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                      name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                      name_entry_id=0)
    np = i03["namepool_live_va"]
    walk = eri.walk_object_universe(api, handle, i02["objects_ptr_live_va"], i02["num_elements"],
                                    base, size, np,
                                    class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                    name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                    outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                    max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    objs = walk["objects_by_address"]
    rec = objs.get(obj_ptr)
    out = {"present": rec is not None, "address_hex": "0x%x" % obj_ptr}
    if rec is None:
        return out
    out["name"] = rec.get("name_text")
    out["object_path"] = eri.resolve_object_path(obj_ptr, objs).get("object_path")
    cls_rec = objs.get(rec.get("class_ptr") or 0) or {}
    out["class_name"] = cls_rec.get("name_text")
    out["class_path"] = (eri.resolve_object_path(rec.get("class_ptr"), objs).get("object_path")
                         if rec.get("class_ptr") else None)
    # canary depth, read-only via proven property reflection: UDataTable::RowStruct
    try:
        cls_addr = rec.get("class_ptr")
        cp = eri._read_u64(api, handle, cls_addr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        props = eri.walk_property_chain(api, handle, cp, namepool_live_va=np,
                                        owner_address=cls_addr)
        row_off = None
        for p in props.get("accepted", []):
            if p.get("raw_name") == "RowStruct":
                row_off = p.get("offset")
        if row_off is not None:
            rs_ptr = eri._read_u64(api, handle, obj_ptr + row_off)
            out["rowstruct_offset"] = row_off
            out["rowstruct_ptr_hex"] = "0x%x" % rs_ptr
            rs = objs.get(rs_ptr)
            out["rowstruct_name"] = rs.get("name_text") if rs else None
        else:
            out["rowstruct_note"] = "RowStruct property not found on the class chain"
    except Exception as exc:  # noqa: BLE001
        out["rowstruct_error"] = str(exc)
    # package presence
    pkg = None
    for a, r in objs.items():
        if r.get("name_ok") and r.get("name_text") == "MK_Canary":
            cr = objs.get(r.get("class_ptr") or 0) or {}
            if cr.get("name_text") == "Package":
                pkg = eri.resolve_object_path(a, objs).get("object_path")
    out["package_object_path"] = pkg
    run_note.append("loaded object: path=%s class=%s rowstruct=%s"
                    % (out.get("object_path"), out.get("class_name"), out.get("rowstruct_name")))
    return out


def decode_fname(api, handle, np, idx, num):
    if idx == 0:
        return None
    d = eri.decode_fname_entry_id(api, handle, np, idx)
    txt = d.get("text")
    return txt if not num else "%s_%d" % (txt, num - 1)


def run(api, args, run_note):
    k, has_desc = gt._k32full()
    nt = gt._ntdll()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    sha = ipp.sha256_of_file(exe)
    if sha != EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d build sha256 confirmed" % pid)
    with open(exe, "rb") as f:
        img = f.read()

    # ---- baseline ----
    addrs = fts.resolve_and_verify_addresses(api, pid, base, exe, run_note)
    gmalloc_va = base + RVA_GMALLOC
    handle = eri.open_process_read_only(api, pid)
    try:
        gm_inst = eri._read_u64(api, handle, gmalloc_va)
        if not gm_inst:
            raise ipp.Blocked("GMalloc is null")
        vt = eri._read_u64(api, handle, gm_inst)
        free_target = eri._read_u64(api, handle, vt + FREE_SLOT_DISP)
        free_rva = free_target - base
        if not (0 < free_rva < size):
            raise ipp.Blocked("Free slot target outside module")
        live = api.read_process_memory(handle, free_target, 16)
        if live != disk_bytes(img, free_rva):
            raise ipp.Blocked("Free target bytes live != disk")
        run_note.append("GMalloc 0x%x vtable 0x%x Free slot9 -> RVA 0x%x (bytes live==disk)"
                        % (gm_inst, vt, free_rva))
        refl = find_reflection_targets(api, handle, base, size, run_note)
        # MK_Canary must be absent before the load
        pre_hits = [r.get("name_text") for a, r in refl["objs"].items()
                    if r.get("name_ok") and r.get("name_text") in ("MK_Canary",)]
        run_note.append("pre-load MK_Canary objects: %d" % len(pre_hits))
        if pre_hits:
            raise ipp.Blocked("MK_Canary already present before the load -- baseline violated")
        pre_count = len(refl["objs"])
    finally:
        api.close_handle(handle)

    # container + package id
    i14 = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "research", "instruments", "eri", "eri.py"),
                          "--run-i14", "--run-dir",
                          os.path.join(REPO_ROOT, "research", "instrument-runs",
                                       time.strftime("%Y-%m-%dT%H%M%SZ-p04-baseline", time.gmtime()))],
                         capture_output=True, text=True)
    mounted = registered = None
    pak_path = None
    for line in (i14.stdout or "").splitlines():
        pass
    import glob as _g
    cand = sorted(_g.glob(os.path.join(REPO_ROOT, "research", "instrument-runs", "*p04-baseline*",
                                       "i14-mounted-paks.json")))
    if cand:
        j = json.load(open(cand[-1], encoding="utf-8"))
        for p in (j.get("mounted_paks") or []):
            fn = p.get("pak_filename") or ""
            if "MiseryModKit" in fn:
                mounted, registered, pak_path = p.get("is_mounted"), p.get("has_io_container_header"), fn
    run_note.append("container mounted=%s registered=%s (%s)" % (mounted, registered, pak_path))
    if not (mounted and registered):
        raise ipp.Blocked("container baseline not satisfied")
    pid_present, utoc = utoc_has_package_id(
        os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved\Paks\MiseryModKit_P.pak"),
        EXPECTED_PACKAGE_ID)
    run_note.append("PackageId 0x%x present in %s: %s" % (EXPECTED_PACKAGE_ID, utoc, pid_present))
    if not pid_present:
        raise ipp.Blocked("expected PackageId not present in .utoc")

    report = {"pid": pid, "build_sha256": sha,
              "baseline": {"container_mounted": bool(mounted), "io_container_registered": bool(registered),
                           "package_id_present": bool(pid_present),
                           "mk_canary_absent": True, "objects_before": pre_count},
              "addresses": {n: "0x%x" % v for n, v in addrs.items()}}
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: baseline confirmed, targets resolved, nothing injected."
        return report

    dll = build_dll()
    run_note.append("P04Probe.dll built")
    sigs = {"add": disk_bytes(img, fts.RVA_ADD_TICKER),
            "get": disk_bytes(img, fts.RVA_GET_CORE_TICKER),
            "malloc": disk_bytes(img, fts.RVA_FMEMORY_MALLOC)}
    carrier = {"add_ticker": addrs["add_ticker"], "get_core_ticker": addrs["get_core_ticker"],
               "fmemory_malloc": addrs["fmemory_malloc"]}

    hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hproc:
        raise ipp.Blocked("OpenProcess failed")
    rpath = rio = rbase = None
    cleanup = {}
    try:
        pth = (dll + "\x00").encode("utf-16-le")
        rpath = k.VirtualAllocEx(hproc, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        w = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, rpath, pth, len(pth), ctypes.byref(w))
        pll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        h1 = k.CreateRemoteThread(hproc, None, 0, pll, rpath, 0, None)
        k.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(h1)
        rbase = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if rbase is None:
            raise ipp.Blocked("probe DLL not loaded")

        io = pack_io(carrier, sigs, gmalloc_va, TARGET_PATH, NEGATIVE_PATH, refl)
        rio = k.VirtualAllocEx(hproc, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, rio, io, len(io), ctypes.byref(w))

        rc = call_export(k, hproc, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        run_note.append("Init rc=0x%x" % rc)
        if rc != 0:
            raise ipp.Blocked("Init failed 0x%x" % rc)

        buf = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hproc, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        call_export(k, hproc, rbase, dll, "RunPositive", rio, ipp.WAIT_TIMEOUT_MS)
        deadline = time.time() + args.timeout_s
        st = read_io()
        while time.time() < deadline and st["positive"]["ran"] == 0:
            time.sleep(0.05)
            st = read_io()
        run_note.append("positive pass ran=%d" % st["positive"]["ran"])

        call_export(k, hproc, rbase, dll, "RunNegative", rio, ipp.WAIT_TIMEOUT_MS)
        deadline = time.time() + args.timeout_s
        while time.time() < deadline and st["negative"]["ran"] == 0:
            time.sleep(0.05)
            st = read_io()
        run_note.append("negative pass ran=%d" % st["negative"]["ran"])

        call_export(k, hproc, rbase, dll, "Shutdown", rio, 20000)
        st = read_io()
        report["lifecycle"] = {"activated": st["activated"], "initialized": st["initialized"],
                               "state": st["state"], "wait_stopped_ok": st["wait_stopped_ok"]}
        report["positive"] = st["positive"]
        report["negative"] = st["negative"]
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

    # ---- read-only post inspection ----
    handle = eri.open_process_read_only(api, pid)
    try:
        np = eri.run_i03(api, handle, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                         name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                         name_entry_id=0)["namepool_live_va"]
        pos = report["positive"]
        report["fname_result"] = {
            "package_name": decode_fname(api, handle, np, pos["pkg_cmp_index"], pos["pkg_number"]),
            "asset_name": decode_fname(api, handle, np, pos["asset_cmp_index"], pos["asset_number"]),
            "subpath_empty": pos["subpath_data"] == 0 and pos["subpath_num"] == 0,
        }
        report["loaded_object"] = inspect_result(api, handle, base, size,
                                                 pos["returned_object"], run_note)
        neg = report["negative"]
        report["negative_fname"] = {
            "package_name": decode_fname(api, handle, np, neg["pkg_cmp_index"], neg["pkg_number"]),
            "asset_name": decode_fname(api, handle, np, neg["asset_cmp_index"], neg["asset_number"]),
        }
    finally:
        api.close_handle(handle)

    p = report["positive"]
    lo = report["loaded_object"]
    core_pass = bool(
        p["ran"] == 1 and p["fstring_ok"] == 1 and p["freed"] == 1 and
        p["returned_object"] != 0 and lo.get("present") and
        eri.canonicalize_object_path(lo.get("object_path") or "") ==
        eri.canonicalize_object_path("/Game/ModKit/MK_Canary.MK_Canary") and
        lo.get("class_name") == "DataTable" and
        report["negative"]["returned_object"] == 0 and
        report["lifecycle"]["wait_stopped_ok"] == 1)
    report["core_verdict"] = "PASS" if core_pass else "NOT-PASS"
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--timeout-s", type=float, default=15.0)
    ap.add_argument("--run-dir", default=None)
    args = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    run_id = (args.run_dir and os.path.basename(args.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    run_note, artifacts = [], []
    vb = va = None
    caps = ["P-04"] if args.arm else ["I-01"]
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
            json.dump(rep, f, indent=2, sort_keys=True); f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print(json.dumps(rep, indent=2, sort_keys=True))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": run_note}
        rp = os.path.join(run_dir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True); f.write("\n")
        artifacts.append(os.path.relpath(rp, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(run_dir, arguments=arguments, capabilities_enabled=caps,
                           build_sha256=EXPECTED_BUILD_SHA256, verify_before=vb, verify_after=va,
                           artifacts=artifacts, instrument_level=("ipp" if args.arm else "eri"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
