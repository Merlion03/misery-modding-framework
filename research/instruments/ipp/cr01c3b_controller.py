#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C3B -- Detached Aggregate Runtime Item Table.

Proves the entire Runtime-owned half of production architecture B with ZERO
writes into any vanilla object:

    reflected UGameplayStatics::SpawnObject(UDataTable, /Engine/Transient)
      -> root through the CR-01A engine root path, in the SAME GameThread job
      -> verify class / outer / vtable / FUObjectItem round trip
      -> RowStruct = the live S_ItemDetails UScriptStruct*
      -> CR-01C2R materializer + engine AddRow into OUR table   (0 -> 1)
      -> engine RemoveRow                                       (1 -> 0)
      -> release the root

The composite-untouched proof is the strong one: MasterItemList's 496 ROW VALUE
POINTERS are captured before and compared after every step. UpdateCachedRowMap
frees and reallocates every row, so an unchanged pointer set is direct evidence
that no rebuild or publication occurred.

FAIL CLOSED everywhere. Gated behind --arm.
"""
import argparse
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP)
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri, ipp_controller as ipp, gt01_controller as gt, fts_controller as fts, p04_controller as p04  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402
import cr01c1_controller as c1  # noqa: E402
import cr01c3_recon as recon  # noqa: E402

DLL_NAME = "CR01C3BProbe.dll"
ROW_NAME = "misery__c3b_detached_probe"

RVA_FREE = 0xFA0090
RVA_SET_ROOT_FLAGS = 0x1210E60      # CR-01A rootpath-derivation.json
RVA_CLEAR_ROOT_FLAGS = 0x11BB340
INIT_SLOT, DESTROY_SLOT = 96, 97
ADDROW_SLOT, REMOVEROW_SLOT = 95, 94
USTRUCT_PROPERTIES_SIZE = 0x58
OFF_ROWSTRUCT = 40
OFF_PARENT_TABLES = 176
ITEMLIST_BASELINE = 496

# name-prefix -> (expected FProperty class, expected offset, expected size)
FIELDS = {
    "Weight": ("FDoubleProperty", 48, 8),
    "Width": ("FIntProperty", 56, 4),
    "Height": ("FIntProperty", 60, 4),
    "AllowStacking": ("FBoolProperty", 64, 1),
    "MaxStack": ("FIntProperty", 68, 4),
}
VALUES = {"Weight": 1.75, "Width": 1, "Height": 2, "MaxStack": 5, "AllowStacking": 1}

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQ QQQ QQQ QQQQ QQ Q IIIIII d iii B 3s 96H "
          "IIII IIII IIII QQQQQ QQQQ IIII IIII QQ").replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 648, "C3BIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D43334200
IO_PROTO = 1


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C3BProbeDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
    # Reuse an up-to-date build. This machine is near its system COMMIT LIMIT and
    # the MSVC linker intermittently dies with LNK1171 / error 1455 there, so
    # rebuilding an unchanged DLL is a real failure mode with no upside. Standard
    # make semantics: rebuild only when a source is newer than the output.
    if os.path.isfile(out) and all(os.path.getmtime(out) > os.path.getmtime(x) for x in srcs):
        return out
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
    bat = os.path.join(bd, "_build_c3bctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C3BProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


class DiskImage:
    """RVA -> on-disk bytes WITHOUT slurping the whole 134 MB image.

    The earlier gates read the entire executable into memory; on this machine a
    single allocation is now capped at roughly 30 MB, so that approach raises
    MemoryError before any check can run. Parsing only the PE headers and then
    seeking gives byte-identical results for the live==disk comparison, which is
    the only thing the image was ever needed for.
    """

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            head = f.read(4096)
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        nsec = struct.unpack_from("<H", head, pe + 6)[0]
        so = struct.unpack_from("<H", head, pe + 20)[0]
        sect = pe + 24 + so
        if sect + nsec * 40 > len(head):
            raise ipp.Blocked("PE section table beyond the first 4 KiB; refusing to guess")
        self.secs = []
        for i in range(nsec):
            b = sect + i * 40
            vs, va, rs, rp = struct.unpack_from("<IIII", head, b + 8)
            self.secs.append((va, vs, rp, rs))

    def bytes_at(self, rva, n=16):
        for va, vs, rp, rs in self.secs:
            if va <= rva < va + max(vs, rs) and rva - va < rs:
                with open(self.path, "rb") as f:
                    f.seek(rp + (rva - va))
                    return f.read(n)
        return None


def verify_carrier_addresses(api, pid, base, image, run_note):
    """fts.resolve_and_verify_addresses without the whole-image read."""
    out = {}
    ro = eri.open_process_read_only(api, pid)
    try:
        for name, rva in (("add_ticker", fts.RVA_ADD_TICKER),
                          ("get_core_ticker", fts.RVA_GET_CORE_TICKER),
                          ("fmemory_malloc", fts.RVA_FMEMORY_MALLOC)):
            va = base + rva
            disk = image.bytes_at(rva, 16)
            live = api.read_process_memory(ro, va, 16)
            if disk != live:
                raise ipp.Blocked("byte mismatch at %s RVA 0x%x: disk %s live %s -- refusing "
                                  "(possible runtime patch)"
                                  % (name, rva, (disk or b"").hex(), live.hex()))
            out[name] = va
            run_note.append("%s: VA 0x%x byte-verified live==disk (%s)"
                            % (name, va, live[:8].hex()))
    finally:
        api.close_handle(ro)
    return out


def verify_fields(api, h, np, row_struct):
    """FAIL CLOSED: name, FProperty class, offset and size must all match."""
    fields = rdr.struct_fields(api, h, np, row_struct)
    resolved, report = {}, {}
    for prefix, (cls, off, size) in FIELDS.items():
        match = [(n, m) for n, m in fields.items() if n.split("_")[0] == prefix]
        if len(match) != 1:
            raise ipp.Blocked("field %s: expected exactly one match, got %d" % (prefix, len(match)))
        name, meta = match[0]
        if meta["property_class"] != cls:
            raise ipp.Blocked("field %s: class %r != %r" % (prefix, meta["property_class"], cls))
        if meta["offset"] != off or meta["size"] != size:
            raise ipp.Blocked("field %s: offset/size %s/%s != %s/%s"
                              % (prefix, meta["offset"], meta["size"], off, size))
        resolved[prefix] = off
        report[prefix] = {"name": name, "class": cls, "offset": off, "size": size,
                          "value": VALUES[prefix]}
    return resolved, report


def bool_semantics(api, h, np, row_struct, prefix):
    """AllowStacking must be a FULL BYTE, never a bitfield, or we refuse to write it.

    rdr.struct_fields() reduces each property to offset/size/class and drops the
    FBoolProperty decode, so this walks the chain itself -- the bitfield mask is
    exactly the thing that must not be assumed.
    """
    cp = eri._read_u64(api, h, row_struct + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    props = eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=row_struct)
    for meta in props.get("accepted", []):
        if (meta.get("raw_name") or "").split("_")[0] != prefix:
            continue
        if meta.get("property_class") != "FBoolProperty":
            raise ipp.Blocked("%s is %s, not FBoolProperty" % (prefix, meta.get("property_class")))
        mask = meta.get("bool_field_mask")
        if meta.get("is_bitfield") or str(mask).lower() not in ("0xff", "255"):
            raise ipp.Blocked("%s is a bitfield (mask %r); refusing a whole-byte write"
                              % (prefix, mask))
        return {"is_bitfield": meta.get("is_bitfield"), "field_mask": mask,
                "byte_offset": meta.get("bool_byte_offset")}
    raise ipp.Blocked("%s not found on the row struct" % prefix)


def table_row_pointers(api, h, table):
    """(name-id -> value pointer). A composite rebuild reallocates every row, so
    an unchanged pointer set proves no rebuild happened."""
    rows, _ = rdr.read_rowmap(api, h, table)
    return {(a, b): p for a, b, p in rows}


def table_hashes(api, h, table, size):
    rows, _ = rdr.read_rowmap(api, h, table)
    out = {}
    for a, b, p in rows:
        try:
            out[(a, b)] = hashlib.sha256(api.read_process_memory(h, p, size)).hexdigest()
        except Exception:  # noqa: BLE001
            out[(a, b)] = None
    return out


def parent_state(api, h, table):
    data = eri._read_u64(api, h, table + OFF_PARENT_TABLES)
    num = struct.unpack("<i", api.read_process_memory(h, table + OFF_PARENT_TABLES + 8, 4))[0]
    mx = struct.unpack("<i", api.read_process_memory(h, table + OFF_PARENT_TABLES + 12, 4))[0]
    elems = []
    if data and 0 < num < 64:
        raw = api.read_process_memory(h, data, num * 8)
        elems = [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(num)]
    return {"data": "0x%x" % data, "num": num, "max": mx,
            "elements": ["0x%x" % e for e in elems]}


def delegate_state(api, h, table):
    data = eri._read_u64(api, h, table + 0x98)
    num = struct.unpack("<i", api.read_process_memory(h, table + 0x98 + 8, 4))[0]
    return {"data": "0x%x" % data, "num": num}


def resolve(api, h, base, size, img, run_note):
    """Read-only resolution of every target, with live==disk byte verification."""
    np, objs = recon.universe(api, h, base, size)
    fmeta = recon.find_function_meta(objs)
    if fmeta is None:
        raise ipp.Blocked("Function meta-class not found")

    def by_name(nm, clsname):
        return [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]

    def one(nm, clsname, label):
        c = by_name(nm, clsname)
        if len(c) != 1:
            raise ipp.Blocked("%s: expected exactly one %s named %s, got %d"
                              % (label, clsname, nm, len(c)))
        return c[0]

    itemlist = one("ItemList", "DataTable", "ItemList")
    master = one("MasterItemList", "CompositeDataTable", "MasterItemList")
    transient = one("/Engine/Transient", "Package", "transient package")
    dt_class = one("DataTable", "Class", "UDataTable UClass")
    gs_cdo = one("Default__GameplayStatics", "GameplayStatics", "GameplayStatics CDO")
    sl_cdo = one("Default__KismetStringLibrary", "KismetStringLibrary", "KismetStringLibrary CDO")
    gs_cls = one("GameplayStatics", "Class", "GameplayStatics UClass")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary UClass")

    def fn_on(cls_addr, want, label):
        for f in recon.class_functions(api, h, np, cls_addr, fmeta):
            if f.get("raw_name") == want:
                return f["address"]
        raise ipp.Blocked("%s not found on %s" % (want, label))

    spawn = fn_on(gs_cls, "SpawnObject", "GameplayStatics")
    conv = fn_on(sl_cls, "Conv_StringToName", "KismetStringLibrary")

    # SpawnObject ABI must be exactly what we pack
    sflags = eri._read_u32(api, h, spawn + 0xB0)
    sparms = eri._read_u16(api, h, spawn + 0xB6)
    if sparms != 24:
        raise ipp.Blocked("SpawnObject ParmsSize %d != 24" % sparms)
    if not (sflags & 0x2000) or not (sflags & 0x400):
        raise ipp.Blocked("SpawnObject flags 0x%x lack FUNC_Static|FUNC_Native" % sflags)
    if eri._read_u64(api, h, spawn + 0xC8):
        raise ipp.Blocked("SpawnObject EventGraphFunction non-null; Parms would be discarded")
    run_note.append("SpawnObject flags=0x%x ParmsSize=24 EventGraphFunction=null" % sflags)

    # RowStruct identity across all three tables
    rs_item = eri._read_u64(api, h, itemlist + OFF_ROWSTRUCT)
    rs_master = eri._read_u64(api, h, master + OFF_ROWSTRUCT)
    if rs_item != rs_master:
        raise ipp.Blocked("ItemList and MasterItemList RowStruct differ")
    if (objs.get(rs_item) or {}).get("name_text") != "S_ItemDetails":
        raise ipp.Blocked("RowStruct is %r, expected S_ItemDetails"
                          % (objs.get(rs_item) or {}).get("name_text"))
    struct_size = struct.unpack("<i", api.read_process_memory(
        h, rs_item + USTRUCT_PROPERTIES_SIZE, 4))[0]
    if not (64 < struct_size < (1 << 20)):
        raise ipp.Blocked("implausible RowStruct PropertiesSize %d" % struct_size)

    # engine functions, all byte-verified live==disk
    plain_vt = eri._read_u64(api, h, itemlist)
    add_row = eri._read_u64(api, h, plain_vt + ADDROW_SLOT * 8)
    rem_row = eri._read_u64(api, h, plain_vt + REMOVEROW_SLOT * 8)
    svt = eri._read_u64(api, h, rs_item)
    init_va = eri._read_u64(api, h, svt + INIT_SLOT * 8)
    dest_va = eri._read_u64(api, h, svt + DESTROY_SLOT * 8)
    pe = eri._read_u64(api, h, eri._read_u64(api, h, sl_cdo) + c1.PE_SLOT * 8)
    set_root = base + RVA_SET_ROOT_FLAGS
    clr_root = base + RVA_CLEAR_ROOT_FLAGS
    free_va = base + RVA_FREE
    for label, va in (("ProcessEvent", pe), ("AddRow", add_row), ("RemoveRow", rem_row),
                      ("InitializeStruct", init_va), ("DestroyStruct", dest_va),
                      ("SetRootFlags", set_root), ("ClearRootFlags", clr_root),
                      ("FMemory::Free", free_va)):
        if not (base <= va < base + size):
            raise ipp.Blocked("%s 0x%x outside module" % (label, va))
        if api.read_process_memory(h, va, 16) != img.bytes_at(va - base, 16):
            raise ipp.Blocked("%s bytes live != disk (RVA 0x%x)" % (label, va - base))
        run_note.append("%s: RVA 0x%x byte-verified live==disk" % (label, va - base))

    # the composite must NOT already own an extra parent
    ps = parent_state(api, h, master)
    if ps["num"] != 1 or ps["elements"] != ["0x%x" % itemlist]:
        raise ipp.Blocked("MasterItemList.ParentTables is not the expected vanilla [ItemList]: %r" % ps)
    run_note.append("MasterItemList.ParentTables vanilla: Num=%d Max=%d" % (ps["num"], ps["max"]))

    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    return {
        "np": np, "objs": objs, "itemlist": itemlist, "master": master,
        "transient": transient, "dt_class": dt_class, "gs_cdo": gs_cdo, "sl_cdo": sl_cdo,
        "spawn": spawn, "conv": conv, "row_struct": rs_item, "struct_size": struct_size,
        "plain_vtable": plain_vt, "add_row": add_row, "remove_row": rem_row,
        "init": init_va, "destroy": dest_va, "pe": pe,
        "set_root": set_root, "clear_root": clr_root, "free": free_va,
        "objects_ptr": i02["objects_ptr_live_va"], "parent_state": ps,
    }


def pack_io(carrier, sigs, r, offs, run_note):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, r["struct_size"],
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"], r["free"],
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["sl_cdo"], r["conv"],
        r["gs_cdo"], r["spawn"],
        r["dt_class"], r["transient"], r["row_struct"],
        r["itemlist"], r["master"], r["plain_vtable"],
        r["add_row"], r["remove_row"], r["init"], r["destroy"],
        r["set_root"], r["clear_root"],
        r["objects_ptr"],
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"], b"\0\0\0",
        *nm,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0)


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = 3 + 4 + 3 + 3 + 2 + 3 + 3 + 4 + 2 + 1 + 6 + 1 + 3 + 1 + 1 + 96
    keys = ["activated", "initialized", "state", "wait_stopped_ok",
            "create_ran", "populate_ran", "remove_ran", "release_ran",
            "gt_tid", "fstring_ok", "err", "err_step",
            "table_ptr", "table_item_ptr", "table_class", "table_outer", "table_vtable",
            "table_rowstruct_after", "row_fname", "temp_ptr", "store_handle",
            "internal_index", "rooted_after_acquire", "rooted_after_release", "temp_freed",
            "table_addrow_matches", "table_removerow_matches", "owned_count", "item_flags"]
    return {k: f[i + n] for n, k in enumerate(keys)}


def snap(api, pid, r, size_of_row):
    """One read-only observation of everything this gate must keep invariant."""
    h = eri.open_process_read_only(api, pid)
    try:
        s = {
            "itemlist_rows": len(table_row_pointers(api, h, r["itemlist"])),
            "itemlist_hashes": table_hashes(api, h, r["itemlist"], size_of_row),
            "master_rows": len(table_row_pointers(api, h, r["master"])),
            "master_row_pointers": table_row_pointers(api, h, r["master"]),
            "master_parents": parent_state(api, h, r["master"]),
            "itemlist_delegate": delegate_state(api, h, r["itemlist"]),
            "master_delegate": delegate_state(api, h, r["master"]),
        }
        return s
    finally:
        api.close_handle(h)


def our_table_state(api, pid, table_ptr, row_struct, size_of_row, offs):
    h = eri.open_process_read_only(api, pid)
    try:
        out = {"row_struct": "0x%x" % eri._read_u64(api, h, table_ptr + OFF_ROWSTRUCT)}
        rows, diag = rdr.read_rowmap(api, h, table_ptr)
        out["row_count"] = len(rows)
        out["rowmap_diag"] = diag
        if rows:
            a, b, p = rows[0]
            out["row_ptr"] = "0x%x" % p
            raw = api.read_process_memory(h, p, size_of_row)
            out["values"] = {
                "Weight": struct.unpack_from("<d", raw, offs["Weight"])[0],
                "Width": struct.unpack_from("<i", raw, offs["Width"])[0],
                "Height": struct.unpack_from("<i", raw, offs["Height"])[0],
                "MaxStack": struct.unpack_from("<i", raw, offs["MaxStack"])[0],
                "AllowStacking": raw[offs["AllowStacking"]],
            }
        return out
    finally:
        api.close_handle(h)


def run(api, args, run_note):
    k, _ = gt._k32full()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    if ipp.sha256_of_file(exe) != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d fingerprint confirmed" % pid)
    img = DiskImage(exe)
    addrs = verify_carrier_addresses(api, pid, base, img, run_note)

    h = eri.open_process_read_only(api, pid)
    try:
        r = resolve(api, h, base, size, img, run_note)
        offs, field_report = verify_fields(api, h, r["np"], r["row_struct"])
        boolsem = bool_semantics(api, h, r["np"], r["row_struct"], "AllowStacking")
        run_note.append("fail-closed field verification passed for %s" % sorted(offs))
        run_note.append("AllowStacking bool semantics: %r" % boolsem)
    finally:
        api.close_handle(h)

    row_size = r["struct_size"]
    before = snap(api, pid, r, row_size)
    if before["itemlist_rows"] != ITEMLIST_BASELINE:
        raise ipp.Blocked("ItemList baseline %d != %d" % (before["itemlist_rows"], ITEMLIST_BASELINE))
    if before["master_rows"] != ITEMLIST_BASELINE:
        raise ipp.Blocked("MasterItemList baseline %d != %d" % (before["master_rows"], ITEMLIST_BASELINE))
    run_note.append("baseline: ItemList=%d MasterItemList=%d parents=%s"
                    % (before["itemlist_rows"], before["master_rows"], before["master_parents"]))

    report = {
        "pid": pid,
        "addresses": {kk: "0x%x" % (r[kk] - base) for kk in
                      ("add_row", "remove_row", "init", "destroy", "pe", "spawn")},
        "root_path": {"SetRootFlags": "0x%x" % RVA_SET_ROOT_FLAGS,
                      "ClearRootFlags": "0x%x" % RVA_CLEAR_ROOT_FLAGS},
        "objects": {kk: "0x%x" % r[kk] for kk in
                    ("itemlist", "master", "transient", "dt_class", "gs_cdo", "row_struct",
                     "plain_vtable")},
        "struct_size": row_size,
        "fields": field_report,
        "allowstacking_bool_semantics": boolsem,
        "baseline": {"itemlist_rows": before["itemlist_rows"],
                     "master_rows": before["master_rows"],
                     "master_parents": before["master_parents"],
                     "itemlist_delegate": before["itemlist_delegate"],
                     "master_delegate": before["master_delegate"]},
        "probe_row": ROW_NAME,
    }
    if not args.arm:
        report["armed"] = False
        report["outcome"] = "DRY RUN: all fail-closed checks passed, nothing written."
        return report

    dll = build_dll(); run_note.append("%s built" % DLL_NAME)
    sigs = {"add": img.bytes_at(fts.RVA_ADD_TICKER, 16),
            "get": img.bytes_at(fts.RVA_GET_CORE_TICKER, 16),
            "malloc": img.bytes_at(fts.RVA_FMEMORY_MALLOC, 16)}
    carrier = {"add_ticker": addrs["add_ticker"], "get_core_ticker": addrs["get_core_ticker"],
               "fmemory_malloc": addrs["fmemory_malloc"]}
    r["sl_cdo"] = r["sl_cdo"]

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
        io = pack_io(carrier, sigs, r, offs, run_note)
        rio = k.VirtualAllocEx(hp, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
        buf = ctypes.create_string_buffer(IO_SIZE); rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        def wait_for(field, timeout=15.0):
            st = read_io(); dl = time.time() + timeout
            while time.time() < dl and st[field] == 0:
                time.sleep(0.05); st = read_io()
            return st

        rc = p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init failed 0x%x" % rc)
        run_note.append("Init ok")

        # ---- 1. construct + root + RowStruct, all in ONE GameThread job -----
        p04.call_export(k, hp, rbase, dll, "RunCreate", rio, ipp.WAIT_TIMEOUT_MS)
        st = wait_for("create_ran")
        report["create"] = st
        run_note.append("create_ran=%d err=%d step=%d table=0x%x rooted=%d"
                        % (st["create_ran"], st["err"], st["err_step"], st["table_ptr"],
                           st["rooted_after_acquire"]))
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed: err=%d at step %d" % (st["err"], st["err_step"]))
        after_create = snap(api, pid, r, row_size)
        report["after_create"] = {
            "our_table": our_table_state(api, pid, st["table_ptr"], r["row_struct"], row_size, offs),
            "itemlist_rows": after_create["itemlist_rows"],
            "master_rows": after_create["master_rows"],
            "master_parents": after_create["master_parents"],
            "master_row_pointers_unchanged":
                after_create["master_row_pointers"] == before["master_row_pointers"],
            "itemlist_hashes_unchanged":
                after_create["itemlist_hashes"] == before["itemlist_hashes"],
            "itemlist_delegate": after_create["itemlist_delegate"],
            "rowstruct_equals_itemlist": st["table_rowstruct_after"] == r["row_struct"],
            "class_ok": st["table_class"] == r["dt_class"],
            "outer_is_transient": st["table_outer"] == r["transient"],
            "vtable_is_plain_udatatable": st["table_vtable"] == r["plain_vtable"],
            "addrow_slot_matches": st["table_addrow_matches"] == 1,
            "removerow_slot_matches": st["table_removerow_matches"] == 1,
        }

        # ---- 2. materialize + AddRow into OUR table ------------------------
        p04.call_export(k, hp, rbase, dll, "RunPopulate", rio, ipp.WAIT_TIMEOUT_MS)
        st = wait_for("populate_ran")
        report["populate"] = st
        after_pop = snap(api, pid, r, row_size)
        ours = our_table_state(api, pid, st["table_ptr"], r["row_struct"], row_size, offs)
        report["after_populate"] = {
            "our_table": ours,
            "values_match": bool(ours.get("values") and all(
                abs(ours["values"][kk] - VALUES[kk]) < 1e-9 for kk in VALUES)),
            "row_ptr_differs_from_temp":
                ours.get("row_ptr") != ("0x%x" % st["temp_ptr"]),
            "temp_freed": st["temp_freed"] == 1,
            "itemlist_rows": after_pop["itemlist_rows"],
            "master_rows": after_pop["master_rows"],
            "master_row_pointers_unchanged":
                after_pop["master_row_pointers"] == before["master_row_pointers"],
            "itemlist_hashes_unchanged":
                after_pop["itemlist_hashes"] == before["itemlist_hashes"],
            "master_parents": after_pop["master_parents"],
            "itemlist_delegate": after_pop["itemlist_delegate"],
        }
        run_note.append("after populate: our_rows=%s values_match=%s master_ptrs_unchanged=%s"
                        % (ours.get("row_count"), report["after_populate"]["values_match"],
                           report["after_populate"]["master_row_pointers_unchanged"]))

        # ---- 3. RemoveRow --------------------------------------------------
        p04.call_export(k, hp, rbase, dll, "RunRemove", rio, ipp.WAIT_TIMEOUT_MS)
        st = wait_for("remove_ran")
        report["remove"] = st
        after_rm = snap(api, pid, r, row_size)
        report["after_remove"] = {
            "our_table": our_table_state(api, pid, st["table_ptr"], r["row_struct"], row_size, offs),
            "master_row_pointers_unchanged":
                after_rm["master_row_pointers"] == before["master_row_pointers"],
            "itemlist_hashes_unchanged":
                after_rm["itemlist_hashes"] == before["itemlist_hashes"],
            "master_parents": after_rm["master_parents"],
        }

        # ---- 4. release the root ------------------------------------------
        p04.call_export(k, hp, rbase, dll, "RunRelease", rio, ipp.WAIT_TIMEOUT_MS)
        st = wait_for("release_ran")
        report["release"] = st
        run_note.append("release_ran=%d rooted_after_release=%d owned=%d item_flags=0x%x"
                        % (st["release_ran"], st["rooted_after_release"], st["owned_count"],
                           st["item_flags"]))

        final = snap(api, pid, r, row_size)
        report["final"] = {
            "itemlist_rows": final["itemlist_rows"],
            "master_rows": final["master_rows"],
            "master_parents": final["master_parents"],
            "master_row_pointers_unchanged":
                final["master_row_pointers"] == before["master_row_pointers"],
            "itemlist_hashes_unchanged": final["itemlist_hashes"] == before["itemlist_hashes"],
            "itemlist_delegate": final["itemlist_delegate"],
            "master_delegate": final["master_delegate"],
            "no_vanilla_reference_to_our_table":
                ("0x%x" % st["table_ptr"]) not in final["master_parents"]["elements"],
        }
        released = p04.call_export(k, hp, rbase, dll, "Shutdown", rio, 20000)
        report["shutdown"] = read_io()
        report["shutdown"]["released_at_shutdown"] = released
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

    ac = report.get("after_create", {}); ap = report.get("after_populate", {})
    ar = report.get("after_remove", {}); fi = report.get("final", {})
    report["verdict"] = "PASS" if (
        report["create"]["create_ran"] == 1 and report["create"]["err"] == 0 and
        report["create"]["rooted_after_acquire"] == 1 and
        ac.get("class_ok") and ac.get("outer_is_transient") and
        ac.get("vtable_is_plain_udatatable") and ac.get("rowstruct_equals_itemlist") and
        ac.get("addrow_slot_matches") and ac.get("removerow_slot_matches") and
        ac.get("our_table", {}).get("row_count") == 0 and
        ac.get("master_row_pointers_unchanged") and ac.get("itemlist_hashes_unchanged") and
        report["populate"]["populate_ran"] == 1 and report["populate"]["err"] == 0 and
        ap.get("our_table", {}).get("row_count") == 1 and ap.get("values_match") and
        ap.get("row_ptr_differs_from_temp") and ap.get("temp_freed") and
        ap.get("itemlist_rows") == ITEMLIST_BASELINE and
        ap.get("master_rows") == ITEMLIST_BASELINE and
        ap.get("master_row_pointers_unchanged") and ap.get("itemlist_hashes_unchanged") and
        report["remove"]["remove_ran"] == 1 and
        ar.get("our_table", {}).get("row_count") == 0 and
        ar.get("master_row_pointers_unchanged") and ar.get("itemlist_hashes_unchanged") and
        report["release"]["release_ran"] == 1 and
        report["release"]["rooted_after_release"] == 0 and
        report["release"]["owned_count"] == 0 and
        fi.get("master_parents", {}).get("num") == 1 and
        fi.get("no_vanilla_reference_to_our_table") and
        fi.get("master_row_pointers_unchanged") and fi.get("itemlist_hashes_unchanged") and
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
    caps = ["CR-01C3B"] if a.arm else ["I-01"]
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
            json.dump(rep, f, indent=2, sort_keys=True, default=str); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print(json.dumps({kk: rep[kk] for kk in rep if kk not in ("run_note",)},
                         indent=2, sort_keys=True, default=str))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": note}
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str); f.write("\n")
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
