#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C2R Route C -- Runtime materialization of a real S_ItemDetails row.

  game-allocator temp (size = real RowStruct PropertiesSize)
    -> UScriptStruct::InitializeStruct  (struct vtable slot 96)
    -> populate ONLY verified trivially-assignable value types
    -> UDataTable::AddRow (engine deep-copies)
    -> UScriptStruct::DestroyStruct (slot 97) + FMemory::Free  [temp destroyed independently]
    -> verify the target row is still valid
    -> RemoveRow

FAIL CLOSED: every field we intend to write must match name, FProperty class,
offset and size exactly, and every address must byte-verify live==disk, or nothing
is written. Gated behind --arm.
"""
import argparse, ctypes, hashlib, json, os, struct, subprocess, sys, time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP); sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri, ipp_controller as ipp, gt01_controller as gt, fts_controller as fts, p04_controller as p04  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402
import cr01c1_controller as c1  # noqa: E402

DLL_NAME = "CR01C2RProbe.dll"
ROW_NAME = "misery__runtime_materialized_probe"
RVA_FREE = 0xFA0090          # derived in RemoveRowInternal, right after DestroyStruct
INIT_SLOT = 96               # UScriptStruct vtable
DESTROY_SLOT = 97
USTRUCT_PROPERTIES_SIZE = 0x58
BASELINE = 496

# name-prefix -> (expected FProperty class, expected offset, expected size)
FIELDS = {
    "Weight":   ("FDoubleProperty", 48, 8),
    "Width":    ("FIntProperty", 56, 4),
    "Height":   ("FIntProperty", 60, 4),
    "MaxStack": ("FIntProperty", 68, 4),
    "FuelTime": ("FDoubleProperty", 2048, 8),
}
VALUES = {"Weight": 3.25, "FuelTime": 77.5, "Width": 2, "Height": 3, "MaxStack": 7}

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQQ QQQ IIIIII dd iiii 96H "
          "IIII IIII QQ IIII QQ").replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 496, "C2RIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D43325200
IO_PROTO = 1


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    if os.path.isfile(out):
        os.remove(out)
    defs = ("/DPLATFORM_WINDOWS=1 /DPLATFORM_MICROSOFT=1 /DPLATFORM_64BITS=1 /DUE_BUILD_SHIPPING=1 "
            "/DUE_BUILD_DEVELOPMENT=0 /DUE_BUILD_TEST=0 /DUE_BUILD_DEBUG=0 /DWITH_EDITOR=0 "
            "/DWITH_EDITORONLY_DATA=0 /DWITH_ENGINE=0 /DWITH_SERVER_CODE=1 "
            "/DWITH_UNREAL_DEVELOPER_TOOLS=0 /DWITH_PLUGIN_SUPPORT=0 /DWITH_ACCESSIBILITY=0 "
            "/DIS_MONOLITHIC=1 /DIS_PROGRAM=0 /DCORE_API= /DCOREUOBJECT_API= /DTRACELOG_API= "
            "/DUNICODE /D_UNICODE /DPLATFORM_EXCEPTIONS_DISABLED=0 /D_WIN32_WINNT=0x0A00 "
            "/DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 /DUBT_COMPILED_PLATFORM=Windows "
            "/DOVERRIDE_PLATFORM_HEADER_NAME=Windows")
    inc = '/I"%s\\Core\\Public" /I"%s\\TraceLog\\Public" /I"%s\\Core\\Internal"' % (ue, ue, ue)
    bat = os.path.join(bd, "_build_c2rctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C2RProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


def verify_fields(api, h, np, row_struct):
    """FAIL CLOSED: each intended field must match class, offset and size exactly."""
    fields = rdr.struct_fields(api, h, np, row_struct)
    resolved, report = {}, {}
    for prefix, (cls, off, size) in FIELDS.items():
        match = [(n, m) for n, m in fields.items() if n.split("_")[0] == prefix]
        if len(match) != 1:
            raise ipp.Blocked("field %s: expected exactly one match, got %d" % (prefix, len(match)))
        name, meta = match[0]
        if meta["property_class"] != cls:
            raise ipp.Blocked("field %s: FProperty class %r != expected %r"
                              % (prefix, meta["property_class"], cls))
        if meta["offset"] != off or meta["size"] != size:
            raise ipp.Blocked("field %s: offset/size %s/%s != expected %s/%s"
                              % (prefix, meta["offset"], meta["size"], off, size))
        resolved[prefix] = off
        report[prefix] = {"name": name, "class": cls, "offset": off, "size": size,
                          "classification": "trivially assignable value type",
                          "value": VALUES[prefix]}
    return resolved, report


def pack_io(carrier, sigs, r, offs, struct_size, free_va):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, struct_size,
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"], free_va,
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["cdo"], r["fn"],
        r["itemlist"], r["add_row"], r["remove_row"],
        r["row_struct"], r["init"], r["destroy"],
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["FuelTime"], 0,
        VALUES["Weight"], VALUES["FuelTime"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], 0,
        *nm,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0,
        0, 0, 0, 0,
        0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = 3 + 4 + 3 + 3 + 3 + 3 + 6 + 2 + 4 + 96
    return {"activated": f[i], "initialized": f[i+1], "state": f[i+2], "wait_stopped_ok": f[i+3],
            "materialize_ran": f[i+4], "remove_ran": f[i+5], "gt_tid": f[i+6], "fstring_ok": f[i+7],
            "row_fname": f[i+8], "temp_ptr": f[i+9],
            "temp_freed": f[i+10], "err": f[i+11]}


def run(api, args, run_note):
    k, _ = gt._k32full()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    if ipp.sha256_of_file(exe) != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d fingerprint confirmed" % pid)
    with open(exe, "rb") as fh:
        img = fh.read()
    addrs = fts.resolve_and_verify_addresses(api, pid, base, exe, run_note)

    h = eri.open_process_read_only(api, pid)
    try:
        r = c1.resolve(api, h, base, size, img, run_note)   # ItemList, CDO, Conv_StringToName, PE, AddRow, RemoveRow
        row_struct = eri._read_u64(api, h, r["itemlist"] + rdr.OFF_ROWSTRUCT)
        struct_size = struct.unpack("<i", api.read_process_memory(
            h, row_struct + USTRUCT_PROPERTIES_SIZE, 4))[0]
        if not (64 < struct_size < (1 << 20)):
            raise ipp.Blocked("implausible RowStruct PropertiesSize %d" % struct_size)
        svt = eri._read_u64(api, h, row_struct)
        init_va = eri._read_u64(api, h, svt + INIT_SLOT * 8)
        dest_va = eri._read_u64(api, h, svt + DESTROY_SLOT * 8)
        free_va = base + RVA_FREE
        for label, va in (("InitializeStruct", init_va), ("DestroyStruct", dest_va),
                          ("FMemory::Free", free_va)):
            if not (base <= va < base + size):
                raise ipp.Blocked("%s 0x%x outside module" % (label, va))
            if api.read_process_memory(h, va, 16) != p04.disk_bytes(img, va - base):
                raise ipp.Blocked("%s bytes live != disk (RVA 0x%x)" % (label, va - base))
            run_note.append("%s: RVA 0x%x byte-verified live==disk" % (label, va - base))
        offs, field_report = verify_fields(api, h, r["np"], row_struct)
        run_note.append("fail-closed field verification passed for %s" % sorted(offs))
        before, diag = c1.snapshot(api, h, r["itemlist"], r["np"])
        if len(before) != BASELINE:
            raise ipp.Blocked("baseline %d != %d" % (len(before), BASELINE))
        if ROW_NAME in before:
            raise ipp.Blocked("target row already present")
        run_note.append("baseline rows=%d, target absent" % len(before))
    finally:
        api.close_handle(h)

    r["row_struct"], r["init"], r["destroy"] = row_struct, init_va, dest_va
    report = {"pid": pid, "row_struct_hex": "0x%x" % row_struct, "struct_size": struct_size,
              "addresses": {"InitializeStruct": "0x%x" % (init_va - base),
                            "DestroyStruct": "0x%x" % (dest_va - base),
                            "FMemory::Free": "0x%x" % RVA_FREE,
                            "AddRow": "0x%x" % (r["add_row"] - base),
                            "RemoveRow": "0x%x" % (r["remove_row"] - base)},
              "fields": field_report, "baseline_rows": len(before), "target_row": ROW_NAME}
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: all fail-closed checks passed, nothing written."
        return report

    dll = build_dll(); run_note.append("%s built" % DLL_NAME)
    sigs = {"add": p04.disk_bytes(img, fts.RVA_ADD_TICKER),
            "get": p04.disk_bytes(img, fts.RVA_GET_CORE_TICKER),
            "malloc": p04.disk_bytes(img, fts.RVA_FMEMORY_MALLOC)}
    carrier = {"add_ticker": addrs["add_ticker"], "get_core_ticker": addrs["get_core_ticker"],
               "fmemory_malloc": addrs["fmemory_malloc"]}

    hp = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hp:
        raise ipp.Blocked("OpenProcess failed")
    rpath = rio = rbase = None
    cleanup = {}
    try:
        pth = (dll + "\x00").encode("utf-16-le")
        rpath = k.VirtualAllocEx(hp, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        wr = ctypes.c_size_t(0)
        k.WriteProcessMemory(hp, rpath, pth, len(pth), ctypes.byref(wr))
        pll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        t = k.CreateRemoteThread(hp, None, 0, pll, rpath, 0, None)
        k.WaitForSingleObject(t, ipp.WAIT_TIMEOUT_MS); k.CloseHandle(t)
        rbase = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if rbase is None:
            raise ipp.Blocked("probe DLL not loaded")
        io = pack_io(carrier, sigs, r, offs, struct_size, free_va)
        rio = k.VirtualAllocEx(hp, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
        buf = ctypes.create_string_buffer(IO_SIZE); rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        rc = p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init failed 0x%x" % rc)
        run_note.append("Init ok")

        p04.call_export(k, hp, rbase, dll, "RunMaterialize", rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io(); dl = time.time() + 15
        while time.time() < dl and st["materialize_ran"] == 0:
            time.sleep(0.05); st = read_io()
        report["materialize"] = st
        run_note.append("materialize_ran=%d err=%d temp_freed=%d gt_tid=%d"
                        % (st["materialize_ran"], st["err"], st["temp_freed"], st["gt_tid"]))

        h = eri.open_process_read_only(api, pid)
        try:
            after, _ = c1.snapshot(api, h, r["itemlist"], r["np"])
            tgt = after.get(ROW_NAME)
            aa = {"row_count": len(after), "target_present": tgt is not None,
                  "vanilla_unchanged": all(after.get(n, (0, None))[1] == hh
                                           for n, (_, hh) in before.items()),
                  "vanilla_all_present": all(n in after for n in before)}
            if tgt:
                vals = {}
                b = api.read_process_memory(h, tgt[0], 2264)
                vals["Weight"] = struct.unpack_from("<d", b, offs["Weight"])[0]
                vals["Width"] = struct.unpack_from("<i", b, offs["Width"])[0]
                vals["Height"] = struct.unpack_from("<i", b, offs["Height"])[0]
                vals["MaxStack"] = struct.unpack_from("<i", b, offs["MaxStack"])[0]
                vals["FuelTime"] = struct.unpack_from("<d", b, offs["FuelTime"])[0]
                aa["values_read_back"] = vals
                aa["values_match"] = all(abs(vals[kk] - VALUES[kk]) < 1e-9 for kk in VALUES)
                aa["target_row_ptr"] = "0x%x" % tgt[0]
                aa["target_ptr_differs_from_temp"] = tgt[0] != st["temp_ptr"]
                # the target must remain readable/valid AFTER the temp was destroyed+freed
                aa["target_valid_after_temp_destroyed"] = bool(st["temp_freed"] == 1 and len(b) == 2264)
            report["after_materialize"] = aa
        finally:
            api.close_handle(h)
        run_note.append("after materialize: rows=%d target=%s values_match=%s vanilla_unchanged=%s"
                        % (aa["row_count"], aa["target_present"], aa.get("values_match"),
                           aa["vanilla_unchanged"]))

        p04.call_export(k, hp, rbase, dll, "RunRemove", rio, ipp.WAIT_TIMEOUT_MS)
        st2 = read_io(); dl = time.time() + 15
        while time.time() < dl and st2["remove_ran"] == 0:
            time.sleep(0.05); st2 = read_io()
        report["remove"] = st2
        h = eri.open_process_read_only(api, pid)
        try:
            fin, _ = c1.snapshot(api, h, r["itemlist"], r["np"])
            report["after_remove"] = {
                "row_count": len(fin), "target_absent": ROW_NAME not in fin,
                "vanilla_unchanged": all(fin.get(n, (0, None))[1] == hh
                                         for n, (_, hh) in before.items()),
                "vanilla_all_present": all(n in fin for n in before)}
        finally:
            api.close_handle(h)
        run_note.append("after remove: rows=%d absent=%s vanilla_unchanged=%s"
                        % (report["after_remove"]["row_count"],
                           report["after_remove"]["target_absent"],
                           report["after_remove"]["vanilla_unchanged"]))
        p04.call_export(k, hp, rbase, dll, "Shutdown", rio, 20000)
        report["shutdown"] = read_io()
    finally:
        if rbase is not None:
            pf = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
            t3 = k.CreateRemoteThread(hp, None, 0, pf, rbase, 0, None)
            if t3:
                k.WaitForSingleObject(t3, ipp.WAIT_TIMEOUT_MS); k.CloseHandle(t3)
        for b2 in (rpath, rio):
            if b2 is not None:
                k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
        try:
            cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
        except Exception:  # noqa: BLE001
            cleanup["dll_unloaded"] = None
        k.CloseHandle(hp)
    report["cleanup"] = cleanup

    aa = report.get("after_materialize", {}); ar = report.get("after_remove", {})
    report["verdict"] = "PASS" if (
        report["materialize"]["materialize_ran"] == 1 and report["materialize"]["err"] == 0 and
        report["materialize"]["temp_freed"] == 1 and
        aa.get("row_count") == BASELINE + 1 and aa.get("target_present") and
        aa.get("values_match") and aa.get("vanilla_unchanged") and aa.get("vanilla_all_present") and
        aa.get("target_ptr_differs_from_temp") and aa.get("target_valid_after_temp_destroyed") and
        report["remove"]["remove_ran"] == 1 and ar.get("row_count") == BASELINE and
        ar.get("target_absent") and ar.get("vanilla_unchanged") and ar.get("vanilla_all_present") and
        report["shutdown"]["wait_stopped_ok"] == 1 and cleanup.get("dll_unloaded")) else "NOT-PASS"
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    rid = (a.run_dir and os.path.basename(a.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    rdir = a.run_dir or os.path.join(REPO, "research", "instrument-runs", rid)
    os.makedirs(rdir, exist_ok=True)
    note, arts = [], []
    vb = va = None
    caps = ["CR-01C2R"] if a.arm else ["I-01"]
    code = 0
    try:
        api = eri.Win32Api()
        if a.arm:
            vb = ipp.run_verify_install(rdir, "before")
            if vb.get("report_artifact"):
                arts.append(vb["report_artifact"])
            if vb["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before")
        rep = run(api, a, note)
        rep["run_note"] = note
        if a.arm:
            va = ipp.run_verify_install(rdir, "after")
            if va.get("report_artifact"):
                arts.append(va["report_artifact"])
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print(json.dumps(rep, indent=2, sort_keys=True))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": note}
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(rdir, arguments=arguments, capabilities_enabled=caps,
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=arts,
                           instrument_level=("ipp" if a.arm else "eri"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
