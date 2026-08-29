#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C1: safe additive ItemList row registration primitive.

  496 vanilla rows -> Runtime adds ONE uniquely named row -> 497
  -> all 496 vanilla rows byte-identical -> Runtime removes exactly its row -> 496

Row memory ownership stays entirely inside the engine: the runtime calls the
engine's own virtual UDataTable::AddRow / RemoveRow, which allocate, deep-copy,
destroy and free. The runtime allocates and frees nothing, so double-free or a
dangling row is structurally impossible from our side.

All mutation runs on the proven GameThread dispatcher. Gated behind --arm.
"""
import argparse, ctypes, ctypes.wintypes as wt, hashlib, json, os, struct, subprocess, sys, time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP); sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri, ipp_controller as ipp, gt01_controller as gt, fts_controller as fts, p04_controller as p04  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

DLL_NAME = "CR01C1Probe.dll"
PROBE_NAME = "misery_test__probe"
NEG_NAME = "misery_test__never_registered"
RVA_GMALLOC = 0x7960030
FREE_SLOT = 0x48
PE_SLOT = 77
ADDROW_SLOT = 95        # derived; see research/evidence/CR-01C1/rowapi-derivation.json
REMOVEROW_SLOT = 94
ROW_SIZE = 2264         # sizeof(S_ItemDetails): last field BurntFuelItem @2240 size 24
BASELINE_ROWS = 496

IO_FMT = "<QII QQQ 16s16s16s Q II QQQ Q QQ Q 96H IIII IIII Q IIII QQ"
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 424, "C1Io wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D43314331
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
    bat = os.path.join(bd, "_build_c1ctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C1ProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("CR01C1Probe.dll did not build:\n%s\n%s" % (r.stdout, r.stderr))
    return out


def snapshot(api, h, table, np):
    """{rowName: (ptr, sha256 of the row's raw bytes)} for every row."""
    rows, diag = rdr.read_rowmap(api, h, table)
    out = {}
    for ci, num, vptr in rows:
        t = eri.decode_fname_entry_id(api, h, np, ci).get("text")
        nm = "%s_%d" % (t, num - 1) if num else t
        raw = api.read_process_memory(h, vptr, ROW_SIZE)
        out[nm] = (vptr, hashlib.sha256(raw).hexdigest())
    return out, diag


def scalars(api, h, vptr):
    """POD fields of S_ItemDetails that a correct deep copy must reproduce exactly."""
    b = api.read_process_memory(h, vptr, 72)
    return {"Weight": struct.unpack_from("<d", b, 48)[0],
            "Width": struct.unpack_from("<i", b, 56)[0],
            "Height": struct.unpack_from("<i", b, 60)[0],
            "AllowStacking": b[64], "AllowQuickBind": b[65], "AllowDroppingItem": b[66],
            "MaxStack": struct.unpack_from("<i", b, 68)[0]}


def ptr_fields(api, h, vptr):
    """Pointers inside the row, split by ownership semantics.

    FText holds TRefCountPtr<ITextData> (Text.h:811) with a defaulted copy ctor, so
    a correct copy SHARES that pointer and bumps the refcount -- identical FText
    pointers are expected and are NOT aliasing. The real deep-copy indicator is an
    OWNED container: TArray allocates its own buffer, so a correct CopyScriptStruct
    must give the clone a DIFFERENT array data pointer.
    """
    b = api.read_process_memory(h, vptr, 104)
    return {"shared_refcounted": {
                "Name_FText": struct.unpack_from("<Q", b, 0)[0],
                "ShortName_FText": struct.unpack_from("<Q", b, 16)[0],
                "Description_FText": struct.unpack_from("<Q", b, 32)[0]},
            "owned_buffers": {
                "InventoryActions_data": struct.unpack_from("<Q", b, 72)[0],
                "InventoryActions_num": struct.unpack_from("<i", b, 80)[0],
                "WorldActions_data": struct.unpack_from("<Q", b, 88)[0],
                "WorldActions_num": struct.unpack_from("<i", b, 96)[0]}}


def resolve(api, h, base, size, img, run_note):
    """Read-only resolution of every target, with live==disk byte verification."""
    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03 = eri.run_i03(api, h, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                      name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                      name_entry_id=0)
    np = i03["namepool_live_va"]
    w = eri.walk_object_universe(api, h, i02["objects_ptr_live_va"], i02["num_elements"],
                                 base, size, np,
                                 class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                 name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                 outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                 max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    objs = w["objects_by_address"]
    itemlist = cdo = cls = fmeta = None
    for a, r in objs.items():
        if not r.get("name_ok"):
            continue
        nm = r.get("name_text")
        cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
        if nm == "ItemList" and cn == "DataTable":
            itemlist = a
        elif nm == "Default__KismetStringLibrary":
            cdo = a
        elif nm == "KismetStringLibrary" and cn == "Class":
            cls = a
        elif nm == "Function" and fmeta is None:
            if eri.canonicalize_object_path(eri.resolve_object_path(a, objs).get("object_path")) \
                    == "/Script/CoreUObject.Function":
                fmeta = a
    if not (itemlist and cdo and cls and fmeta):
        raise ipp.Blocked("could not resolve ItemList / KismetStringLibrary CDO / class / Function")
    # RowStruct identity
    rs = eri._read_u64(api, h, itemlist + rdr.OFF_ROWSTRUCT)
    rsname = (objs.get(rs) or {}).get("name_text")
    if rsname != "S_ItemDetails":
        raise ipp.Blocked("ItemList RowStruct is %r, expected S_ItemDetails" % rsname)
    # Conv_StringToName
    ch = eri.walk_children_chain(api, h, eri._read_u64(api, h, cls + eri.USTRUCT_CHILDREN_OFFSET),
                                 namepool_live_va=np, owner_address=cls, function_class_address=fmeta)
    fn = None
    for f in ch.get("accepted", []):
        if f.get("raw_name") == "Conv_StringToName":
            fn = f["address"]
    if not fn:
        raise ipp.Blocked("Conv_StringToName not found")
    # ProcessEvent from the CDO vtable, AddRow/RemoveRow from the TABLE vtable
    pe = eri._read_u64(api, h, eri._read_u64(api, h, cdo) + PE_SLOT * 8)
    tvt = eri._read_u64(api, h, itemlist)
    add_row = eri._read_u64(api, h, tvt + ADDROW_SLOT * 8)
    rem_row = eri._read_u64(api, h, tvt + REMOVEROW_SLOT * 8)
    for label, va in (("ProcessEvent", pe), ("AddRow", add_row), ("RemoveRow", rem_row)):
        if not (base <= va < base + size):
            raise ipp.Blocked("%s 0x%x outside module" % (label, va))
        live = api.read_process_memory(h, va, 16)
        if live != p04.disk_bytes(img, va - base):
            raise ipp.Blocked("%s bytes live != disk at RVA 0x%x" % (label, va - base))
        run_note.append("%s: RVA 0x%x byte-verified live==disk" % (label, va - base))
    return {"np": np, "objs": objs, "itemlist": itemlist, "cdo": cdo, "fn": fn,
            "pe": pe, "add_row": add_row, "remove_row": rem_row, "rowstruct": rsname}


def pack_io(carrier, sigs, gmalloc_va, r, source_row):
    nm = [ord(c) for c in PROBE_NAME] + [0] * (96 - len(PROBE_NAME))
    return struct.pack(IO_FMT, IO_MAGIC, IO_PROTO, 0,
                       carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"],
                       sigs["add"], sigs["get"], sigs["malloc"],
                       gmalloc_va, FREE_SLOT, 0,
                       r["pe"], r["cdo"], r["fn"],
                       r["itemlist"], r["add_row"], r["remove_row"], source_row,
                       *nm,
                       0, 0, 0, 0,
                       0, 0, 0, 0,
                       0,
                       0, 0, 0, 0,
                       0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = 3 + 3 + 3 + 3 + 3 + 1 + 2 + 1 + 96
    return {"activated": f[i], "initialized": f[i+1], "state": f[i+2], "wait_stopped_ok": f[i+3],
            "intern_ran": f[i+4], "add_ran": f[i+5], "remove_ran": f[i+6], "gt_tid": f[i+7],
            "probe_fname": f[i+8], "fstring_ok": f[i+9], "add_rc": f[i+10], "remove_rc": f[i+11]}


def run(api, args, run_note):
    k, _ = gt._k32full()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    sha = ipp.sha256_of_file(exe)
    if sha != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d fingerprint confirmed" % pid)
    with open(exe, "rb") as fh:
        img = fh.read()
    addrs = fts.resolve_and_verify_addresses(api, pid, base, exe, run_note)
    gmalloc_va = base + RVA_GMALLOC

    h = eri.open_process_read_only(api, pid)
    try:
        r = resolve(api, h, base, size, img, run_note)
        before, diag = snapshot(api, h, r["itemlist"], r["np"])
        run_note.append("baseline rows=%d (rowmap %s)" % (len(before), diag))
        if len(before) != BASELINE_ROWS:
            raise ipp.Blocked("baseline row count %d != %d" % (len(before), BASELINE_ROWS))
        if PROBE_NAME in before:
            raise ipp.Blocked("probe key already present")
        src_name = None
        for cand in sorted(before):
            pf = ptr_fields(api, h, before[cand][0])
            if pf["owned_buffers"]["InventoryActions_num"] > 0:
                src_name = cand
                break
        if src_name is None:
            raise ipp.Blocked("no vanilla row with a non-empty owned array; "
                              "deep-copy check would be vacuous")
        src_ptr = before[src_name][0]
        src_scalars = scalars(api, h, src_ptr)
        src_ptrs = ptr_fields(api, h, src_ptr)
        run_note.append("clone source row %r @0x%x" % (src_name, src_ptr))
    finally:
        api.close_handle(h)

    report = {"pid": pid, "build_sha256": sha, "rowstruct": r["rowstruct"],
              "itemlist_hex": "0x%x" % r["itemlist"],
              "addresses": {"AddRow": "0x%x" % (r["add_row"] - base),
                            "RemoveRow": "0x%x" % (r["remove_row"] - base),
                            "ProcessEvent": "0x%x" % (r["pe"] - base)},
              "baseline_rows": len(before), "clone_source_row": src_name}
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: preconditions verified, targets resolved, nothing written."
        return report

    dll = build_dll(); run_note.append("CR01C1Probe.dll built")
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
        io = pack_io(carrier, sigs, gmalloc_va, r, src_ptr)
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

        # ---------------- ADD ----------------
        p04.call_export(k, hp, rbase, dll, "RunAdd", rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io(); dl = time.time() + 15
        while time.time() < dl and st["add_ran"] == 0:
            time.sleep(0.05); st = read_io()
        report["add"] = st
        run_note.append("add_ran=%d gt_tid=%d fname=0x%x" % (st["add_ran"], st["gt_tid"], st["probe_fname"]))

        h = eri.open_process_read_only(api, pid)
        try:
            after, _ = snapshot(api, h, r["itemlist"], r["np"])
            probe = after.get(PROBE_NAME)
            report["after_add"] = {
                "row_count": len(after),
                "probe_present": probe is not None,
                "neg_key_present": NEG_NAME in after,
                "vanilla_unchanged": all(after.get(nm, (0, None))[1] == hsh
                                         for nm, (_, hsh) in before.items()),
                "vanilla_all_present": all(nm in after for nm in before),
            }
            if probe:
                report["after_add"]["probe_scalars_match_source"] = (
                    scalars(api, h, probe[0]) == src_scalars)
                pp = ptr_fields(api, h, probe[0])
                so, po = src_ptrs["owned_buffers"], pp["owned_buffers"]
                report["after_add"]["owned_buffer_deep_copied"] = (
                    po["InventoryActions_data"] != so["InventoryActions_data"]
                    and po["InventoryActions_num"] == so["InventoryActions_num"])
                report["after_add"]["fttext_shared_refcounted_as_expected"] = (
                    pp["shared_refcounted"] == src_ptrs["shared_refcounted"])
                report["after_add"]["probe_ptr_fields"] = pp
                report["after_add"]["source_ptr_fields"] = src_ptrs
                report["after_add"]["probe_row_ptr"] = "0x%x" % probe[0]
                report["after_add"]["probe_ptr_differs_from_source_row"] = probe[0] != src_ptr
        finally:
            api.close_handle(h)
        run_note.append("after add: rows=%d probe=%s vanilla_unchanged=%s"
                        % (report["after_add"]["row_count"], report["after_add"]["probe_present"],
                           report["after_add"]["vanilla_unchanged"]))

        # ---------------- REMOVE ----------------
        p04.call_export(k, hp, rbase, dll, "RunRemove", rio, ipp.WAIT_TIMEOUT_MS)
        st2 = read_io(); dl = time.time() + 15
        while time.time() < dl and st2["remove_ran"] == 0:
            time.sleep(0.05); st2 = read_io()
        report["remove"] = st2
        h = eri.open_process_read_only(api, pid)
        try:
            final, _ = snapshot(api, h, r["itemlist"], r["np"])
            report["after_remove"] = {
                "row_count": len(final),
                "probe_absent": PROBE_NAME not in final,
                "vanilla_unchanged": all(final.get(nm, (0, None))[1] == hsh
                                         for nm, (_, hsh) in before.items()),
                "vanilla_all_present": all(nm in final for nm in before),
            }
        finally:
            api.close_handle(h)
        run_note.append("after remove: rows=%d probe_absent=%s vanilla_unchanged=%s"
                        % (report["after_remove"]["row_count"],
                           report["after_remove"]["probe_absent"],
                           report["after_remove"]["vanilla_unchanged"]))

        p04.call_export(k, hp, rbase, dll, "Shutdown", rio, 20000)
        report["shutdown"] = read_io()
    finally:
        if rbase is not None:
            pf = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
            t3 = k.CreateRemoteThread(hp, None, 0, pf, rbase, 0, None)
            if t3:
                k.WaitForSingleObject(t3, ipp.WAIT_TIMEOUT_MS); k.CloseHandle(t3)
        for b in (rpath, rio):
            if b is not None:
                k.VirtualFreeEx(hp, b, 0, ipp.MEM_RELEASE)
        try:
            cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
        except Exception:  # noqa: BLE001
            cleanup["dll_unloaded"] = None
        k.CloseHandle(hp)
    report["cleanup"] = cleanup

    aa, ar = report.get("after_add", {}), report.get("after_remove", {})
    report["verdict"] = "PASS" if (
        report["add"]["add_ran"] == 1 and aa.get("row_count") == BASELINE_ROWS + 1 and
        aa.get("probe_present") and not aa.get("neg_key_present") and
        aa.get("vanilla_unchanged") and aa.get("vanilla_all_present") and
        aa.get("probe_scalars_match_source") and aa.get("owned_buffer_deep_copied") and
        aa.get("probe_ptr_differs_from_source_row") and
        report["remove"]["remove_ran"] == 1 and ar.get("row_count") == BASELINE_ROWS and
        ar.get("probe_absent") and ar.get("vanilla_unchanged") and ar.get("vanilla_all_present") and
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
    caps = ["CR-01C1"] if a.arm else ["I-01"]
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
