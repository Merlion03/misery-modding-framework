#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C3C -- Publish the Runtime aggregate table into MasterItemList.

The one authorised vanilla write: append the Runtime-owned UDataTable as a second
parent of MasterItemList, let the engine publish it through its own delegate
path, verify, then roll back exactly.

    [C3B] spawn -> root -> RowStruct -> materialize -> AddRow into OUR table
    attach : element[1] = table, Num 1->2, data-neutral trigger on ItemList
    verify : composite = vanilla + 1, probe resolves, vanilla preserved,
             RuntimeTable subscribed to MasterItemList, ItemList delegate intact
    detach : Num 2->1, same trigger, composite back to vanilla-only
    zero   : element[1] = 0, ParentTables raw baseline restored
    release: drop the root

SEMANTIC COMPARISON. A composite rebuild reallocates and deep-copies every row,
so raw row bytes legitimately differ in the owned-container pointers and in
allocation slack. The mask for that is DERIVED THIS RUN, not hardcoded: the
union of 8-byte windows where a parent row and its composite copy already differ
at baseline. With that mask, masked(parent) == masked(composite) must hold for
every row before we touch anything -- and must still hold afterwards.

Any post-publication invariant failure triggers the defined rollback immediately,
while the Runtime table is still rooted. Gated behind --arm.
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
from cr01c3b_controller import (DiskImage, verify_carrier_addresses, verify_fields,  # noqa: E402
                                bool_semantics, table_row_pointers, parent_state,
                                delegate_state, RVA_FREE, RVA_SET_ROOT_FLAGS,
                                RVA_CLEAR_ROOT_FLAGS, INIT_SLOT, DESTROY_SLOT,
                                ADDROW_SLOT, REMOVEROW_SLOT, USTRUCT_PROPERTIES_SIZE,
                                OFF_ROWSTRUCT, OFF_PARENT_TABLES, ITEMLIST_BASELINE)

DLL_NAME = "CR01C3CProbe.dll"
ROW_NAME = "misery__c3c_published_probe"
TRIGGER_NAME = "misery__c3c_neutral_trigger"
OFF_OLD_PARENT_TABLES = 192
OFF_DELEGATE = 0x98
VALUES = {"Weight": 2.5, "Width": 2, "Height": 1, "MaxStack": 3, "AllowStacking": 1}

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQ QQQ QQQ QQ QQQQ QQ Q IIII IIIIII d iiiB3s 96H 96H "
          "IIII IIII IIII IIII IIII IIII QQQQQ QQQQQ QQQQ IIII QQ").replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 944, "C3CIo wire format drifted (%d)" % IO_SIZE
IO_MAGIC = 0x4950502D43334300
IO_PROTO = 1


class RollbackNeeded(Exception):
    """A post-publication invariant failed; the defined rollback must run now."""


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C3CProbeDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    bat = os.path.join(bd, "_build_c3cctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C3CProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


# ---------------------------------------------------------------- semantics
def rows_by_key(api, h, table):
    rows, _ = rdr.read_rowmap(api, h, table)
    return {(a, b): p for a, b, p in rows}


def derive_copy_mask(api, h, parent, composite, size):
    """The 8-byte windows in which a deep copy legitimately differs from its
    source: owned-container data pointers and allocation slack. Derived from the
    live baseline, never hardcoded."""
    pm, cm = rows_by_key(api, h, parent), rows_by_key(api, h, composite)
    windows = set()
    for k in pm:
        if k not in cm:
            continue
        a = api.read_process_memory(h, pm[k], size)
        b = api.read_process_memory(h, cm[k], size)
        for i in range(size):
            if a[i] != b[i]:
                windows.add((i // 8) * 8)
    return sorted(windows)


def masked_digest(buf, mask):
    m = bytearray(buf)
    for w in mask:
        m[w:w + 8] = b"\0" * 8
    return hashlib.sha256(bytes(m)).hexdigest()


def semantic_digests(api, h, table, size, mask):
    out = {}
    for k, p in rows_by_key(api, h, table).items():
        try:
            out[k] = masked_digest(api.read_process_memory(h, p, size), mask)
        except Exception:  # noqa: BLE001
            out[k] = None
    return out


def exact_hashes(api, h, table, size):
    out = {}
    for k, p in rows_by_key(api, h, table).items():
        try:
            out[k] = hashlib.sha256(api.read_process_memory(h, p, size)).hexdigest()
        except Exception:  # noqa: BLE001
            out[k] = None
    return out


def delegate_targets(api, h, table, objects_ptr):
    """Decode a UDataTable's OnDataTableChanged invocation list into the object
    indices it targets. A UObject-method delegate stores a TWeakObjectPtr
    (ObjectIndex, ObjectSerialNumber); we scan the instance for that pair rather
    than hardcoding its offset."""
    data = eri._read_u64(api, h, table + OFF_DELEGATE)
    num = struct.unpack("<i", api.read_process_memory(h, table + OFF_DELEGATE + 8, 4))[0]
    out = {"num": num, "data": "0x%x" % data, "targets": []}
    if not data or not (0 < num < 64):
        return out
    raw = api.read_process_memory(h, data, num * 16)
    for i in range(num):
        inst = struct.unpack_from("<Q", raw, i * 16)[0]
        if not inst:
            continue
        try:
            body = api.read_process_memory(h, inst, 64)
        except Exception:  # noqa: BLE001
            continue
        found = None
        for off in range(0, 60, 4):
            idx = struct.unpack_from("<i", body, off)[0]
            if not (0 < idx < 4_000_000):
                continue
            try:
                chunk = eri._read_u64(api, h, objects_ptr + (idx >> 16) * 8)
                if not chunk:
                    continue
                item = chunk + (idx & 0xFFFF) * eri.SIZEOF_FUOBJECTITEM
                obj = eri._read_u64(api, h, item + eri.FUOBJECTITEM_OFFSET_OBJECT)
                # FUObjectItem: Object @0, Flags @8, ClusterRootIndex @12,
                # SerialNumber @16 -- confirmed by round-trip on a known object.
                serial = struct.unpack("<i", api.read_process_memory(h, item + 16, 4))[0]
            except Exception:  # noqa: BLE001
                continue
            nxt = struct.unpack_from("<i", body, off + 4)[0]
            if obj and serial and nxt == serial:
                found = {"index": idx, "serial": serial, "object": "0x%x" % obj}
                break
        out["targets"].append(found or {"instance": "0x%x" % inst, "decoded": False})
    return out


def parent_raw(api, h, master):
    """ParentTables as raw bytes, including the spare slot beyond Num."""
    data = eri._read_u64(api, h, master + OFF_PARENT_TABLES)
    num = struct.unpack("<i", api.read_process_memory(h, master + OFF_PARENT_TABLES + 8, 4))[0]
    mx = struct.unpack("<i", api.read_process_memory(h, master + OFF_PARENT_TABLES + 12, 4))[0]
    slots = []
    if data and 0 < mx <= 64:
        raw = api.read_process_memory(h, data, mx * 8)
        slots = ["0x%x" % struct.unpack_from("<Q", raw, i * 8)[0] for i in range(mx)]
    return {"data": "0x%x" % data, "num": num, "max": mx, "slots": slots}


def old_parent_state(api, h, master):
    data = eri._read_u64(api, h, master + OFF_OLD_PARENT_TABLES)
    num = struct.unpack("<i", api.read_process_memory(h, master + OFF_OLD_PARENT_TABLES + 8, 4))[0]
    elems = []
    if data and 0 < num < 64:
        raw = api.read_process_memory(h, data, num * 8)
        elems = ["0x%x" % struct.unpack_from("<Q", raw, i * 8)[0] for i in range(num)]
    return {"data": "0x%x" % data, "num": num, "elements": elems}


def resolve(api, h, base, size, img, run_note):
    np, objs = recon.universe(api, h, base, size)
    fmeta = recon.find_function_meta(objs)
    if fmeta is None:
        raise ipp.Blocked("Function meta-class not found")

    def one(nm, clsname, label):
        c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
             and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
        if len(c) != 1:
            raise ipp.Blocked("%s: expected exactly one %s named %s, got %d"
                              % (label, clsname, nm, len(c)))
        return c[0]

    itemlist = one("ItemList", "DataTable", "ItemList")
    master = one("MasterItemList", "CompositeDataTable", "MasterItemList")
    transient = one("/Engine/Transient", "Package", "transient package")
    dt_class = one("DataTable", "Class", "UDataTable UClass")
    cdt_class = one("CompositeDataTable", "Class", "UCompositeDataTable UClass")
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
    if eri._read_u16(api, h, spawn + 0xB6) != 24:
        raise ipp.Blocked("SpawnObject ParmsSize != 24")
    sflags = eri._read_u32(api, h, spawn + 0xB0)
    if not (sflags & 0x2000) or not (sflags & 0x400):
        raise ipp.Blocked("SpawnObject flags 0x%x lack FUNC_Static|FUNC_Native" % sflags)
    if eri._read_u64(api, h, spawn + 0xC8):
        raise ipp.Blocked("SpawnObject EventGraphFunction non-null")

    # MasterItemList identity / class / vtable
    if eri._read_u64(api, h, master + eri.DEFAULT_CLASS_PRIVATE_OFFSET) != cdt_class:
        raise ipp.Blocked("MasterItemList ClassPrivate is not UCompositeDataTable")
    composite_vt = eri._read_u64(api, h, master)
    plain_vt = eri._read_u64(api, h, itemlist)
    if composite_vt == plain_vt:
        raise ipp.Blocked("composite and plain vtables are identical; identity check is vacuous")
    for slot in (ADDROW_SLOT, REMOVEROW_SLOT):
        if eri._read_u64(api, h, composite_vt + slot * 8) == \
                eri._read_u64(api, h, plain_vt + slot * 8):
            raise ipp.Blocked("composite slot %d equals the plain one; not the expected override"
                              % slot)
    run_note.append("MasterItemList: class=UCompositeDataTable vtable=0x%x (plain 0x%x), "
                    "row-API slots overridden as expected" % (composite_vt, plain_vt))

    rs_item = eri._read_u64(api, h, itemlist + OFF_ROWSTRUCT)
    rs_master = eri._read_u64(api, h, master + OFF_ROWSTRUCT)
    if rs_item != rs_master:
        raise ipp.Blocked("ItemList and MasterItemList RowStruct differ")
    if (objs.get(rs_item) or {}).get("name_text") != "S_ItemDetails":
        raise ipp.Blocked("RowStruct is not S_ItemDetails")
    struct_size = struct.unpack("<i", api.read_process_memory(
        h, rs_item + USTRUCT_PROPERTIES_SIZE, 4))[0]
    if not (64 < struct_size < (1 << 20)):
        raise ipp.Blocked("implausible RowStruct PropertiesSize %d" % struct_size)

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

    ps = parent_state(api, h, master)
    if ps["num"] != 1 or ps["elements"] != ["0x%x" % itemlist]:
        raise ipp.Blocked("ParentTables is not the vanilla [ItemList]: %r" % ps)
    if ps["max"] - ps["num"] < 1:
        raise ipp.Blocked("ParentTables has no spare capacity (Num=%d Max=%d); NO growth is "
                          "authorised, failing closed" % (ps["num"], ps["max"]))
    praw = parent_raw(api, h, master)
    if praw["slots"][1] != "0x0":
        raise ipp.Blocked("ParentTables element[1] is not null at baseline: %s" % praw["slots"][1])
    run_note.append("ParentTables baseline: Num=%d Max=%d slots=%s" % (ps["num"], ps["max"], praw["slots"]))

    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    return {"np": np, "objs": objs, "itemlist": itemlist, "master": master,
            "transient": transient, "dt_class": dt_class, "cdt_class": cdt_class,
            "gs_cdo": gs_cdo, "sl_cdo": sl_cdo, "spawn": spawn, "conv": conv,
            "row_struct": rs_item, "struct_size": struct_size,
            "plain_vtable": plain_vt, "composite_vtable": composite_vt,
            "add_row": add_row, "remove_row": rem_row, "init": init_va, "destroy": dest_va,
            "pe": pe, "set_root": set_root, "clear_root": clr_root, "free": free_va,
            "objects_ptr": i02["objects_ptr_live_va"], "parent_state": ps, "parent_raw": praw}


def pack_io(carrier, sigs, r, offs):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    tg = [ord(c) for c in TRIGGER_NAME] + [0] * (96 - len(TRIGGER_NAME))
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, r["struct_size"],
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"], r["free"],
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["sl_cdo"], r["conv"],
        r["gs_cdo"], r["spawn"],
        r["dt_class"], r["transient"], r["row_struct"],
        r["itemlist"], r["master"], r["plain_vtable"],
        r["composite_vtable"], r["cdt_class"],
        r["add_row"], r["remove_row"], r["init"], r["destroy"],
        r["set_root"], r["clear_root"],
        r["objects_ptr"],
        OFF_PARENT_TABLES, OFF_ROWSTRUCT, OFF_DELEGATE, 0,
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"], b"\0\0\0",
        *nm, *tg,
        0, 0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0,   0, 0, 0, 0,
        0, 0, 0, 0,   0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0)


OUT_KEYS = ["activated", "initialized", "state", "wait_stopped_ok",
            "create_ran", "populate_ran", "attach_ran", "detach_ran",
            "zero_ran", "release_ran", "gt_tid", "fstring_ok",
            "err", "err_step", "internal_index", "temp_freed",
            "rooted_after_acquire", "rooted_after_release", "owned_count", "item_flags",
            "table_addrow_matches", "table_removerow_matches", "pad3", "pad4",
            "table_ptr", "table_item_ptr", "table_class", "table_outer", "table_vtable",
            "table_rowstruct_after", "row_fname", "trigger_fname", "temp_ptr", "store_handle",
            "parent_data", "parent_elem0", "parent_elem1_before", "parent_elem1_after",
            "parent_num_before", "parent_max", "parent_num_after_attach",
            "parent_num_after_detach"]


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = 3 + 4 + 3 + 3 + 2 + 3 + 3 + 2 + 4 + 2 + 1 + 4 + 6 + 1 + 4 + 1 + 96 + 96
    return {k: f[i + n] for n, k in enumerate(OUT_KEYS)}


def observe(api, pid, r, mask):
    """One read-only observation of every invariant this gate tracks."""
    size = r["struct_size"]
    h = eri.open_process_read_only(api, pid)
    try:
        return {
            "itemlist_rows": len(rows_by_key(api, h, r["itemlist"])),
            "itemlist_exact": exact_hashes(api, h, r["itemlist"], size),
            "master_rows": len(rows_by_key(api, h, r["master"])),
            "master_semantic": semantic_digests(api, h, r["master"], size, mask),
            "master_keys": sorted(rows_by_key(api, h, r["master"])),
            "parent_state": parent_state(api, h, r["master"]),
            "parent_raw": parent_raw(api, h, r["master"]),
            "old_parent": old_parent_state(api, h, r["master"]),
            "itemlist_delegate": delegate_targets(api, h, r["itemlist"], r["objects_ptr"]),
        }
    finally:
        api.close_handle(h)


def our_table(api, pid, table_ptr, size, offs, objects_ptr):
    h = eri.open_process_read_only(api, pid)
    try:
        out = {"row_struct": "0x%x" % eri._read_u64(api, h, table_ptr + OFF_ROWSTRUCT),
               "delegate": delegate_targets(api, h, table_ptr, objects_ptr)}
        rows, _ = rdr.read_rowmap(api, h, table_ptr)
        out["row_count"] = len(rows)
        if rows:
            a, b, p = rows[0]
            out["row_key"] = [a, b]
            out["row_ptr"] = "0x%x" % p
            raw = api.read_process_memory(h, p, size)
            out["values"] = {"Weight": struct.unpack_from("<d", raw, offs["Weight"])[0],
                             "Width": struct.unpack_from("<i", raw, offs["Width"])[0],
                             "Height": struct.unpack_from("<i", raw, offs["Height"])[0],
                             "MaxStack": struct.unpack_from("<i", raw, offs["MaxStack"])[0],
                             "AllowStacking": raw[offs["AllowStacking"]]}
            out["exact"] = hashlib.sha256(raw).hexdigest()
        return out
    finally:
        api.close_handle(h)


def probe_in_master(api, pid, r, offs, key):
    h = eri.open_process_read_only(api, pid)
    try:
        rows = rows_by_key(api, h, r["master"])
        p = rows.get(tuple(key))
        if p is None:
            return {"present": False}
        raw = api.read_process_memory(h, p, r["struct_size"])
        return {"present": True, "row_ptr": "0x%x" % p, "exact": hashlib.sha256(raw).hexdigest(),
                "values": {"Weight": struct.unpack_from("<d", raw, offs["Weight"])[0],
                           "Width": struct.unpack_from("<i", raw, offs["Width"])[0],
                           "Height": struct.unpack_from("<i", raw, offs["Height"])[0],
                           "MaxStack": struct.unpack_from("<i", raw, offs["MaxStack"])[0],
                           "AllowStacking": raw[offs["AllowStacking"]]}}
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
        # verify_fields reports the values of the module it lives in; this gate
        # writes its own, so record what is ACTUALLY written.
        for kk in field_report:
            field_report[kk]["value"] = VALUES[kk]
        boolsem = bool_semantics(api, h, r["np"], r["row_struct"], "AllowStacking")
        run_note.append("fail-closed field verification passed for %s" % sorted(offs))
        mask = derive_copy_mask(api, h, r["itemlist"], r["master"], r["struct_size"])
        pm = rows_by_key(api, h, r["itemlist"])
        cm = rows_by_key(api, h, r["master"])
        agree = sum(1 for kk in pm if kk in cm and
                    masked_digest(api.read_process_memory(h, pm[kk], r["struct_size"]), mask) ==
                    masked_digest(api.read_process_memory(h, cm[kk], r["struct_size"]), mask))
        if agree != len(pm):
            raise ipp.Blocked("derived copy mask does not explain the baseline: %d/%d rows agree"
                              % (agree, len(pm)))
        run_note.append("copy mask derived this run: %d windows; masked(parent)==masked(composite) "
                        "for %d/%d rows" % (len(mask), agree, len(pm)))
        probe_key_absent_master = True
    finally:
        api.close_handle(h)

    before = observe(api, pid, r, mask)
    if before["itemlist_rows"] != ITEMLIST_BASELINE or before["master_rows"] != ITEMLIST_BASELINE:
        raise ipp.Blocked("baseline rows: ItemList=%d MasterItemList=%d, expected %d"
                          % (before["itemlist_rows"], before["master_rows"], ITEMLIST_BASELINE))
    run_note.append("baseline: ItemList=%d MasterItemList=%d parents=%s old_parents=%s "
                    "itemlist_delegate_num=%d"
                    % (before["itemlist_rows"], before["master_rows"],
                       before["parent_state"]["elements"], before["old_parent"]["elements"],
                       before["itemlist_delegate"]["num"]))

    report = {"pid": pid, "struct_size": r["struct_size"], "fields": field_report,
              "allowstacking_bool_semantics": boolsem,
              "copy_mask_windows": mask, "copy_mask_window_count": len(mask),
              "objects": {kk: "0x%x" % r[kk] for kk in
                          ("itemlist", "master", "transient", "dt_class", "cdt_class",
                           "row_struct", "plain_vtable", "composite_vtable")},
              "baseline": {"itemlist_rows": before["itemlist_rows"],
                           "master_rows": before["master_rows"],
                           "parent_raw": before["parent_raw"],
                           "old_parent": before["old_parent"],
                           "itemlist_delegate": before["itemlist_delegate"]},
              "probe_row": ROW_NAME, "trigger_row": TRIGGER_NAME}
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
        io = pack_io(carrier, sigs, r, offs)
        rio = k.VirtualAllocEx(hp, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
        buf = ctypes.create_string_buffer(IO_SIZE); rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        def call(export, field, timeout=20.0):
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            st = read_io(); dl = time.time() + timeout
            while time.time() < dl and st[field] == 0:
                time.sleep(0.05); st = read_io()
            return st

        rc = p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        if rc != 0:
            raise ipp.Blocked("Init failed 0x%x" % rc)

        st = call("RunCreate", "create_ran")
        report["create"] = st
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
        run_note.append("created table 0x%x rooted=%d" % (st["table_ptr"], st["rooted_after_acquire"]))

        st = call("RunPopulate", "populate_ran")
        report["populate"] = st
        if st["populate_ran"] != 1:
            raise ipp.Blocked("populate failed err=%d" % st["err"])
        ours = our_table(api, pid, st["table_ptr"], r["struct_size"], offs, r["objects_ptr"])
        report["runtime_table_before_attach"] = ours
        if ours["row_count"] != 1:
            raise ipp.Blocked("Runtime table has %d rows, expected exactly 1" % ours["row_count"])
        if ours["delegate"]["num"] != 0:
            raise ipp.Blocked("Runtime table already has delegate subscribers before attach")
        probe_key = tuple(ours["row_key"])
        if probe_key in before["master_semantic"]:
            raise ipp.Blocked("probe row name collides with an existing MasterItemList row")
        run_note.append("runtime table populated: 1 row, no subscribers, no vanilla collision")

        # ---------------- the authorised vanilla write --------------------
        published = False
        try:
            st = call("RunAttach", "attach_ran")
            report["attach"] = st
            if st["attach_ran"] != 1:
                raise ipp.Blocked("attach refused err=%d step=%d" % (st["err"], st["err_step"]))
            published = True
            run_note.append("ATTACHED: Num %d->%d elem1 0x%x" %
                            (st["parent_num_before"], st["parent_num_after_attach"],
                             st["parent_elem1_after"]))

            after = observe(api, pid, r, mask)
            ours_after = our_table(api, pid, st["table_ptr"], r["struct_size"], offs, r["objects_ptr"])
            pim = probe_in_master(api, pid, r, offs, list(probe_key))
            vanilla_ok = all(after["master_semantic"].get(kk) == v
                             for kk, v in before["master_semantic"].items())
            names_ok = all(kk in after["master_semantic"] for kk in before["master_semantic"])
            sub = [t for t in ours_after["delegate"]["targets"] if t and t.get("object")]
            subscribed = (ours_after["delegate"]["num"] == 1 and len(sub) == 1
                          and sub[0]["object"] == "0x%x" % r["master"])
            report["after_attach"] = {
                "parent_state": after["parent_state"], "parent_raw": after["parent_raw"],
                "old_parent": after["old_parent"],
                "parents_are_itemlist_then_runtime":
                    after["parent_state"]["elements"] == ["0x%x" % r["itemlist"],
                                                          "0x%x" % st["table_ptr"]],
                "old_parent_reflects_both":
                    after["old_parent"]["elements"] == ["0x%x" % r["itemlist"],
                                                        "0x%x" % st["table_ptr"]],
                "runtime_table_delegate": ours_after["delegate"],
                "runtime_table_subscribed_to_master": subscribed,
                "itemlist_delegate": after["itemlist_delegate"],
                "itemlist_delegate_unchanged":
                    after["itemlist_delegate"] == before["itemlist_delegate"],
                "master_rows": after["master_rows"],
                "master_rows_is_vanilla_plus_one": after["master_rows"] == ITEMLIST_BASELINE + 1,
                "probe_in_master": pim,
                "probe_values_match_source":
                    bool(pim.get("present") and pim["values"] == ours["values"]),
                "probe_row_is_a_copy": pim.get("row_ptr") != ours["row_ptr"],
                "all_vanilla_names_present": names_ok,
                "all_vanilla_rows_semantically_unchanged": vanilla_ok,
                "itemlist_exact_unchanged": after["itemlist_exact"] == before["itemlist_exact"],
                "itemlist_rows": after["itemlist_rows"],
                "composite_rebuilt": after["master_semantic"] != before["master_semantic"]
                                     or after["master_rows"] != before["master_rows"],
            }
            run_note.append("after attach: master_rows=%d probe=%s vanilla_ok=%s subscribed=%s"
                            % (after["master_rows"], pim.get("present"), vanilla_ok, subscribed))
            bad = [kk for kk, v in report["after_attach"].items()
                   if kk in ("parents_are_itemlist_then_runtime", "old_parent_reflects_both",
                             "runtime_table_subscribed_to_master", "itemlist_delegate_unchanged",
                             "master_rows_is_vanilla_plus_one", "probe_values_match_source",
                             "all_vanilla_names_present", "all_vanilla_rows_semantically_unchanged",
                             "itemlist_exact_unchanged") and not v]
            if bad:
                raise RollbackNeeded("post-publication invariants failed: %s" % bad)
        except RollbackNeeded as exc:
            report["rollback_reason"] = str(exc)
            run_note.append("ROLLBACK TRIGGERED: %s" % exc)
        finally:
            if published:
                st = call("RunDetach", "detach_ran")
                report["detach"] = st
                fin = observe(api, pid, r, mask)
                report["after_detach"] = {
                    "parent_state": fin["parent_state"], "old_parent": fin["old_parent"],
                    "old_parent_is_itemlist_only":
                        fin["old_parent"]["elements"] == ["0x%x" % r["itemlist"]],
                    "master_rows": fin["master_rows"],
                    "master_back_to_vanilla_count": fin["master_rows"] == ITEMLIST_BASELINE,
                    "probe_absent": tuple(probe_key) not in fin["master_semantic"],
                    "all_vanilla_rows_semantically_unchanged":
                        all(fin["master_semantic"].get(kk) == v
                            for kk, v in before["master_semantic"].items()),
                    "all_vanilla_names_present":
                        all(kk in fin["master_semantic"] for kk in before["master_semantic"]),
                    "itemlist_exact_unchanged": fin["itemlist_exact"] == before["itemlist_exact"],
                    "runtime_table_delegate":
                        our_table(api, pid, report["create"]["table_ptr"], r["struct_size"],
                                  offs, r["objects_ptr"])["delegate"],
                    "itemlist_delegate": fin["itemlist_delegate"],
                    "itemlist_delegate_unchanged":
                        fin["itemlist_delegate"] == before["itemlist_delegate"],
                }
                st = call("RunZeroSlot", "zero_ran")
                report["zero_slot"] = st
                zr = observe(api, pid, r, mask)
                report["after_zero"] = {
                    "parent_raw": zr["parent_raw"],
                    "parent_raw_equals_baseline": zr["parent_raw"] == before["parent_raw"],
                }
                run_note.append("after detach+zero: master_rows=%d parent_raw_restored=%s"
                                % (report["after_detach"]["master_rows"],
                                   report["after_zero"]["parent_raw_equals_baseline"]))

        st = call("RunRelease", "release_ran")
        report["release"] = st
        final = observe(api, pid, r, mask)
        report["final"] = {
            "itemlist_rows": final["itemlist_rows"], "master_rows": final["master_rows"],
            "parent_raw": final["parent_raw"],
            "parent_raw_equals_baseline": final["parent_raw"] == before["parent_raw"],
            "old_parent": final["old_parent"],
            "itemlist_delegate_unchanged":
                final["itemlist_delegate"] == before["itemlist_delegate"],
            "itemlist_exact_unchanged": final["itemlist_exact"] == before["itemlist_exact"],
            "all_vanilla_rows_semantically_unchanged":
                all(final["master_semantic"].get(kk) == v
                    for kk, v in before["master_semantic"].items()),
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

    aa = report.get("after_attach", {}); ad = report.get("after_detach", {})
    az = report.get("after_zero", {}); fi = report.get("final", {})
    report["verdict"] = "PASS" if (
        not report.get("rollback_reason") and
        report["attach"]["attach_ran"] == 1 and report["attach"]["err"] == 0 and
        aa.get("parents_are_itemlist_then_runtime") and aa.get("old_parent_reflects_both") and
        aa.get("runtime_table_subscribed_to_master") and aa.get("itemlist_delegate_unchanged") and
        aa.get("master_rows_is_vanilla_plus_one") and aa.get("probe_in_master", {}).get("present") and
        aa.get("probe_values_match_source") and aa.get("probe_row_is_a_copy") and
        aa.get("all_vanilla_names_present") and aa.get("all_vanilla_rows_semantically_unchanged") and
        aa.get("itemlist_exact_unchanged") and aa.get("composite_rebuilt") and
        report["detach"]["detach_ran"] == 1 and
        ad.get("old_parent_is_itemlist_only") and ad.get("master_back_to_vanilla_count") and
        ad.get("probe_absent") and ad.get("all_vanilla_rows_semantically_unchanged") and
        ad.get("all_vanilla_names_present") and ad.get("itemlist_exact_unchanged") and
        ad.get("runtime_table_delegate", {}).get("num") == 0 and
        ad.get("itemlist_delegate_unchanged") and
        report["zero_slot"]["zero_ran"] == 1 and az.get("parent_raw_equals_baseline") and
        report["release"]["release_ran"] == 1 and
        report["release"]["rooted_after_release"] == 0 and
        report["release"]["owned_count"] == 0 and
        fi.get("parent_raw_equals_baseline") and fi.get("itemlist_exact_unchanged") and
        fi.get("all_vanilla_rows_semantically_unchanged") and
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
    caps = ["CR-01C3C"] if a.arm else ["I-01"]
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
        print(json.dumps({kk: rep[kk] for kk in rep
                          if kk not in ("run_note", "copy_mask_windows")},
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
