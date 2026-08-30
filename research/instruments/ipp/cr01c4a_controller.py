#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C4A -- Runtime item FText metadata.

Two phases, in this order, because the second must not run unless the first
holds:

  PHASE 1 -- the metadata primitive, entirely on a Runtime-owned table, with NO
  vanilla write at all:
      InitializeStruct -> construct three FTexts engine-natively -> move them
      into the row struct -> AddRow (engine deep-copies) -> DestroyStruct(temp)
      -> READ THE TEXT BACK OUT OF THE ROW -> RemoveRow
  The read-back after the temp is destroyed and freed is the lifecycle proof:
  if the row did not own valid text of its own, this is where it would show.

  PHASE 2 -- one controlled demo through the already-proven CR-01C3 path:
      publish -> SGK ItemDetails must return the expected FText -> AddItem ->
      the item is held for a visual check -> (on request) the proven rollback.

If phase 1 does not hold, phase 2 never runs -- STOP before gameplay mutation.

FText CONSTRUCTION is engine-native: reflected UKismetTextLibrary::
Conv_StringToText. OWNERSHIP is settled by ProcessEvent itself
(ScriptCore.cpp:2143-2156): it never destroys a parameter, so the returned FText
carries exactly one reference and the caller owns it. Transfer into the struct is
therefore a MOVE (relocate 16 bytes, abandon the source), not a copy.
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
import probe_teardown  # noqa: E402
import cr01c3d_controller as c3d  # noqa: E402
from cr01c3b_controller import DiskImage, verify_carrier_addresses, verify_fields  # noqa: E402
from cr01c3c_controller import (rows_by_key, derive_copy_mask, masked_digest,  # noqa: E402
                                semantic_digests, exact_hashes, delegate_targets,
                                parent_raw, old_parent_state)

DLL_NAME = "CR01C4AProbe.dll"
ROW_NAME = "mbpl__c4a_named_item"
TRIGGER_NAME = "mbpl__c4a_neutral_trigger"
STATE_PATH = os.path.join(REPO, "workspace", "c4a-demo-state.json")

TEXTS = {"Name": "MBPL Test Item",
         "ShortName": "MBPL Test",
         "Description": "First runtime-defined MBPL item."}
VALUES = {"Weight": 0.5, "Width": 1, "Height": 1, "MaxStack": 1, "AllowStacking": 0}
TXT_CAP = 128

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQ QQQ QQQ QQQ QQ QQQQ QQ Q QQQQ QQ IIII IIII IIIIII d "
          "iiiB3s iiiiii f I 96H 96H 80s 128H128H128H 128H128H128H 128H128H128H QQQ QQQ QQQ "
          "IIII IIII IIII IIII IIII IIII IIII IIII IIII QQQQQ QQQQQ QQQQ 48s 16s IIII dII QQ"
          ).replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 3648, "C4AIo wire format drifted (%d)" % IO_SIZE
SLOT_IN_OFFSET = struct.calcsize(IO_FMT.split("80s")[0])
assert SLOT_IN_OFFSET == 824, "slot_in offset drifted (%d)" % SLOT_IN_OFFSET
# Anchor on the LAST 128H (the final text buffer) plus the three QQQ pointer
# triples that follow it. "QQQ" alone is not a usable marker: it occurs inside
# the output block too, and rsplit picked the wrong one.
_INPUT_PREFIX = IO_FMT.rsplit("128H", 1)[0] + "128H" + "Q" * 9
_OUTPUT_BLOCK_OFFSET = struct.calcsize(_INPUT_PREFIX)
STATE_OFFSET = _OUTPUT_BLOCK_OFFSET + 8
WAIT_STOPPED_OK_OFFSET = _OUTPUT_BLOCK_OFFSET + 12
IO_MAGIC = 0x4950502D43344100
IO_PROTO = 1


class RollbackNeeded(Exception):
    pass


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C4AProbeDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    bat = os.path.join(bd, "_build_c4actl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C4AProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


def text_fields(api, h, np, row_struct, texts=None):
    """FAIL CLOSED: the three metadata fields must be FTextProperty, 16 bytes,
    at the offsets we are about to write."""
    cp = eri._read_u64(api, h, row_struct + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    props = eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=row_struct)
    found, report = {}, {}
    for meta in props.get("accepted", []):
        prefix = (meta.get("raw_name") or "").split("_")[0]
        if prefix not in TEXTS:
            continue
        if prefix in found:
            raise ipp.Blocked("field %s matched more than once" % prefix)
        if meta.get("property_class") != "FTextProperty":
            raise ipp.Blocked("field %s is %s, not FTextProperty"
                              % (prefix, meta.get("property_class")))
        if meta.get("size") != 16:
            raise ipp.Blocked("field %s size %r != 16" % (prefix, meta.get("size")))
        found[prefix] = meta.get("offset")
        report[prefix] = {"name": meta.get("raw_name"), "class": "FTextProperty",
                          "offset": meta.get("offset"), "size": 16,
                          "intended_value": (texts or TEXTS).get(prefix),
                          "note": "INTENDED, not measured -- what was written is read back "
                                  "from the live row and from the resolver"}
    missing = [k for k in TEXTS if k not in found]
    if missing:
        raise ipp.Blocked("metadata fields not found on the row struct: %s" % missing)
    return found, report


def u16_to_str(seq):
    out = []
    for c in seq:
        if c == 0:
            break
        out.append(chr(c))
    return "".join(out)


def str_to_u16(s, cap=TXT_CAP):
    if len(s) >= cap:
        raise ipp.Blocked("text %r does not fit in %d UTF-16 units" % (s, cap))
    return [ord(c) for c in s] + [0] * (cap - len(s))


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
    tl_cdo = one("Default__KismetTextLibrary", "KismetTextLibrary", "KismetTextLibrary CDO")
    sgk_cdo = one("Default__BP_SGKFunctions_C", "BP_SGKFunctions_C", "BP_SGKFunctions CDO")
    gs_cls = one("GameplayStatics", "Class", "GameplayStatics UClass")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary UClass")
    tl_cls = one("KismetTextLibrary", "Class", "KismetTextLibrary UClass")
    sgk_cls = one("BP_SGKFunctions_C", "BlueprintGeneratedClass", "BP_SGKFunctions UClass")
    mi_cls = one("BP_MasterInventory_C", "BlueprintGeneratedClass", "BP_MasterInventory_C UClass")
    player_inv = one("BP_PlayerInventory", "BP_PlayerInventory_C", "live player inventory")

    def fn_on(cls_addr, want, label):
        for f in recon.class_functions(api, h, np, cls_addr, fmeta):
            if f.get("raw_name") == want:
                return f["address"]
        raise ipp.Blocked("%s not found on %s" % (want, label))

    spawn = fn_on(gs_cls, "SpawnObject", "GameplayStatics")
    conv = fn_on(sl_cls, "Conv_StringToName", "KismetStringLibrary")
    str2txt = fn_on(tl_cls, "Conv_StringToText", "KismetTextLibrary")
    txt2str = fn_on(tl_cls, "Conv_TextToString", "KismetTextLibrary")
    sgk_details = fn_on(sgk_cls, "SGK ItemDetails", "BP_SGKFunctions")
    add_item = fn_on(mi_cls, "AddItem", "BP_MasterInventory_C")
    remove_item = fn_on(mi_cls, "RemoveItem", "BP_MasterInventory_C")

    def gate(fn, label, parms, need=0):
        fl = eri._read_u32(api, h, fn + 0xB0)
        ps = eri._read_u16(api, h, fn + 0xB6)
        rvo = eri._read_u16(api, h, fn + 0xB8)
        if ps != parms:
            raise ipp.Blocked("%s ParmsSize %d != %d" % (label, ps, parms))
        if need and (fl & need) != need:
            raise ipp.Blocked("%s flags 0x%x lack 0x%x" % (label, fl, need))
        if fl & 0x0138C0C4:
            raise ipp.Blocked("%s carries a net/authority flag 0x%x" % (label, fl))
        if eri._read_u64(api, h, fn + 0xC8):
            raise ipp.Blocked("%s EventGraphFunction non-null" % label)
        run_note.append("%s: flags=0x%x ParmsSize=%d RVO=%d EventGraphFunction=null"
                        % (label, fl, ps, rvo))
        return rvo

    gate(spawn, "SpawnObject", 24, need=0x2400)
    gate(add_item, "AddItem", 120)
    gate(remove_item, "RemoveItem", 83)
    gate(sgk_details, "SGK ItemDetails", 2336)
    # the two text conversions: native, static, ParmsSize 32, return at offset 16
    for fn, label in ((str2txt, "Conv_StringToText"), (txt2str, "Conv_TextToString")):
        rvo = gate(fn, label, 32, need=0x2400)
        if rvo != 16:
            raise ipp.Blocked("%s ReturnValueOffset %d != 16" % (label, rvo))
    # and their parameter shapes, so the 16-byte moves land where we think
    for fn, label, want in (
            (str2txt, "Conv_StringToText",
             {"InString": ("FStrProperty", 0, 16), "ReturnValue": ("FTextProperty", 16, 16)}),
            (txt2str, "Conv_TextToString",
             {"InText": ("FTextProperty", 0, 16), "ReturnValue": ("FStrProperty", 16, 16)})):
        cp = eri._read_u64(api, h, fn + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        seen = {}
        for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=fn,
                                          objects_by_address=objs).get("accepted", []):
            raw = pr.get("property_flags_raw")
            pf = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
            if pf & 0x80:
                seen[pr.get("raw_name")] = (pr.get("property_class"), pr.get("offset"), pr.get("size"))
        for nm, exp in want.items():
            if seen.get(nm) != exp:
                raise ipp.Blocked("%s param %s is %r, expected %r" % (label, nm, seen.get(nm), exp))
        run_note.append("%s parameter ABI verified: %s" % (label, sorted(seen)))

    owner = eri._read_u64(api, h, player_inv + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
    role = eri._read_u8(api, h, owner + 336)
    if role != 3:
        raise ipp.Blocked("owning actor Role=%d, not ROLE_Authority" % role)
    nets = [a for a, r in objs.items() if r.get("name_ok")
            and "NetDriver" in ((objs.get(r.get("class_ptr") or 0) or {}).get("name_text") or "")
            and not (r.get("name_text") or "").startswith("Default__")]
    if nets:
        raise ipp.Blocked("live NetDriver instances present (%d)" % len(nets))
    run_note.append("authority: Role=%d, 0 live NetDriver instances" % role)

    if eri._read_u64(api, h, master + eri.DEFAULT_CLASS_PRIVATE_OFFSET) != cdt_class:
        raise ipp.Blocked("MasterItemList is not a UCompositeDataTable")
    composite_vt = eri._read_u64(api, h, master)
    plain_vt = eri._read_u64(api, h, itemlist)
    if composite_vt == plain_vt:
        raise ipp.Blocked("composite and plain vtables identical")
    rs = eri._read_u64(api, h, itemlist + c3d.OFF_ROWSTRUCT)
    if rs != eri._read_u64(api, h, master + c3d.OFF_ROWSTRUCT):
        raise ipp.Blocked("RowStruct mismatch between ItemList and MasterItemList")
    if (objs.get(rs) or {}).get("name_text") != "S_ItemDetails":
        raise ipp.Blocked("RowStruct is not S_ItemDetails")
    struct_size = struct.unpack("<i", api.read_process_memory(h, rs + 0x58, 4))[0]

    add_row = eri._read_u64(api, h, plain_vt + 95 * 8)
    rem_row = eri._read_u64(api, h, plain_vt + 94 * 8)
    svt = eri._read_u64(api, h, rs)
    init_va = eri._read_u64(api, h, svt + 96 * 8)
    dest_va = eri._read_u64(api, h, svt + 97 * 8)
    pe = eri._read_u64(api, h, eri._read_u64(api, h, sl_cdo) + c1.PE_SLOT * 8)
    set_root = base + 0x1210E60
    clr_root = base + 0x11BB340
    free_va = base + 0xFA0090
    for label, va in (("ProcessEvent", pe), ("AddRow", add_row), ("RemoveRow", rem_row),
                      ("InitializeStruct", init_va), ("DestroyStruct", dest_va),
                      ("SetRootFlags", set_root), ("ClearRootFlags", clr_root),
                      ("FMemory::Free", free_va)):
        if not (base <= va < base + size):
            raise ipp.Blocked("%s outside module" % label)
        if api.read_process_memory(h, va, 16) != img.bytes_at(va - base, 16):
            raise ipp.Blocked("%s bytes live != disk" % label)
    run_note.append("all 8 engine addresses byte-verified live==disk")

    praw = parent_raw(api, h, master)
    if praw["num"] != 1 or praw["slots"][0] != "0x%x" % itemlist or praw["slots"][1] != "0x0":
        raise ipp.Blocked("ParentTables is not the vanilla baseline: %r" % praw)

    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    return {"np": np, "objs": objs, "itemlist": itemlist, "master": master, "transient": transient,
            "dt_class": dt_class, "cdt_class": cdt_class, "gs_cdo": gs_cdo, "sl_cdo": sl_cdo,
            "tl_cdo": tl_cdo, "sgk_cdo": sgk_cdo, "spawn": spawn, "conv": conv,
            "str2txt": str2txt, "txt2str": txt2str, "sgk_details": sgk_details,
            "add_item": add_item, "remove_item": remove_item, "player_inv": player_inv,
            "owner": owner, "row_struct": rs, "struct_size": struct_size,
            "plain_vtable": plain_vt, "composite_vtable": composite_vt,
            "add_row": add_row, "remove_row": rem_row, "init": init_va, "destroy": dest_va,
            "pe": pe, "set_root": set_root, "clear_root": clr_root, "free": free_va,
            "objects_ptr": i02["objects_ptr_live_va"], "parent_raw": praw}


def pack_io(carrier, sigs, r, offs, toffs):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    tg = [ord(c) for c in TRIGGER_NAME] + [0] * (96 - len(TRIGGER_NAME))
    return struct.pack(
        IO_FMT, IO_MAGIC, IO_PROTO, r["struct_size"],
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"], r["free"],
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["sl_cdo"], r["conv"],
        r["gs_cdo"], r["spawn"],
        r["tl_cdo"], r["str2txt"], r["txt2str"],
        r["dt_class"], r["transient"], r["row_struct"],
        r["itemlist"], r["master"], r["plain_vtable"],
        r["composite_vtable"], r["cdt_class"],
        r["add_row"], r["remove_row"], r["init"], r["destroy"],
        r["set_root"], r["clear_root"],
        r["objects_ptr"],
        r["player_inv"], r["add_item"], r["remove_item"], r["sgk_details"],
        r["sgk_cdo"], 0,
        c3d.OFF_PARENT_TABLES, c3d.OFF_ROWSTRUCT, 0x98, c3d.OFF_INVENTORY_ARRAY,
        toffs["Name"], toffs["ShortName"], toffs["Description"], 0,
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"], b"\0\0\0",
        c3d.INVITEM["amount"], c3d.INVITEM["quickbind"], c3d.INVITEM["useamount"],
        c3d.INVITEM["decaytime"], c3d.INVITEM["rotated"], c3d.INVITEM["inuse"],
        c3d.INVITEM["durability"], 0,
        *nm, *tg, b"\0" * 80,
        *str_to_u16(TEXTS["Name"]), *str_to_u16(TEXTS["ShortName"]), *str_to_u16(TEXTS["Description"]),
        *([0] * TXT_CAP), *([0] * TXT_CAP), *([0] * TXT_CAP),
        *([0] * TXT_CAP), *([0] * TXT_CAP), *([0] * TXT_CAP),
        0, 0, 0,   0, 0, 0,   0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0,
        b"\0" * 48, b"\0" * 16,
        0, 0, 0, 0,
        0.0, 0, 0,
        0, 0)


OUT_KEYS = ["activated", "initialized", "state", "wait_stopped_ok",
            "create_ran", "populate_ran", "attach_ran", "detach_ran",
            "zero_ran", "release_ran", "resolve_ran", "additem_ran",
            "removeitem_ran", "gt_tid", "fstring_ok", "err",
            "err_step", "internal_index", "temp_freed", "rooted_after_acquire",
            "rooted_after_release", "owned_count", "item_flags", "table_addrow_matches",
            "table_removerow_matches", "resolve_found", "use_item_decay", "use_durability",
            "parent_num_before", "parent_max", "parent_num_after_attach", "parent_num_after_detach",
            "verifytext_ran", "resolvetext_ran", "text_fields_written", "pad4",
            "table_ptr", "table_item_ptr", "table_class", "table_outer", "table_vtable",
            "table_rowstruct_after", "row_fname", "trigger_fname", "temp_ptr", "store_handle",
            "parent_data", "parent_elem0", "parent_elem1_before", "parent_elem1_after",
            "out_remaining_invitem", "out_newitemslot",
            "out_remaining_item", "resolve_width", "resolve_height", "resolve_maxstack",
            "resolve_weight", "resolve_allowstacking"]
OUT_INDEX = len(struct.unpack(_INPUT_PREFIX, bytes(struct.calcsize(_INPUT_PREFIX))))
_TXT_INDEX = len(struct.unpack(IO_FMT.split("80s")[0] + "80s",
                               bytes(struct.calcsize(IO_FMT.split("80s")[0] + "80s"))))


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    out = {k: f[OUT_INDEX + n] for n, k in enumerate(OUT_KEYS)}
    t = _TXT_INDEX
    labels = ["name_in", "shortname_in", "desc_in", "name_row", "shortname_row", "desc_row",
              "name_res", "shortname_res", "desc_res"]
    for i, lab in enumerate(labels):
        out[lab] = u16_to_str(f[t + i * TXT_CAP: t + (i + 1) * TXT_CAP])
    p = t + 9 * TXT_CAP
    out["empty_textdata"] = ["0x%x" % f[p + i] for i in range(3)]
    out["our_textdata"] = ["0x%x" % f[p + 3 + i] for i in range(3)]
    out["row_textdata"] = ["0x%x" % f[p + 6 + i] for i in range(3)]
    out["out_remaining_invitem"] = c3d.decode_invitem(out["out_remaining_invitem"])
    ns = out["out_newitemslot"]
    out["out_newitemslot"] = {"InvComponent": "0x%x" % struct.unpack_from("<Q", ns, 0)[0],
                              "Index": struct.unpack_from("<i", ns, 8)[0]}
    return out


def observe(api, pid, r, mask):
    size = r["struct_size"]
    h = eri.open_process_read_only(api, pid)
    try:
        return {"itemlist_rows": len(rows_by_key(api, h, r["itemlist"])),
                "itemlist_exact": exact_hashes(api, h, r["itemlist"], size),
                "master_rows": len(rows_by_key(api, h, r["master"])),
                "master_semantic": semantic_digests(api, h, r["master"], size, mask),
                "parent_raw": parent_raw(api, h, r["master"]),
                "old_parent": old_parent_state(api, h, r["master"]),
                "itemlist_delegate": delegate_targets(api, h, r["itemlist"], r["objects_ptr"]),
                "inventory": c3d.read_inventory(api, h, r["player_inv"])}
    finally:
        api.close_handle(h)


def our_row_ptr(api, pid, table_ptr):
    h = eri.open_process_read_only(api, pid)
    try:
        rows, _ = rdr.read_rowmap(api, h, table_ptr)
        return (rows[0][2], (rows[0][0], rows[0][1])) if rows else (0, None)
    finally:
        api.close_handle(h)


def run(api, args, run_note):
    k, _ = gt._k32full()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    if ipp.sha256_of_file(exe) != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d build fingerprint confirmed" % pid)
    img = DiskImage(exe)
    addrs = verify_carrier_addresses(api, pid, base, img, run_note)

    h = eri.open_process_read_only(api, pid)
    try:
        r = resolve(api, h, base, size, img, run_note)
        offs, field_report = verify_fields(api, h, r["np"], r["row_struct"])
        for kk in field_report:
            field_report[kk]["value"] = VALUES[kk]
        toffs, text_report = text_fields(api, h, r["np"], r["row_struct"])
        run_note.append("FText fields verified: %s"
                        % {kk: text_report[kk]["offset"] for kk in text_report})
        mask = derive_copy_mask(api, h, r["itemlist"], r["master"], r["struct_size"])
        pm, cm = rows_by_key(api, h, r["itemlist"]), rows_by_key(api, h, r["master"])
        agree = sum(1 for kk in pm if kk in cm and
                    masked_digest(api.read_process_memory(h, pm[kk], r["struct_size"]), mask) ==
                    masked_digest(api.read_process_memory(h, cm[kk], r["struct_size"]), mask))
        if agree != len(pm):
            raise ipp.Blocked("copy mask does not explain the baseline: %d/%d" % (agree, len(pm)))
        inv0 = c3d.read_inventory(api, h, r["player_inv"])
    finally:
        api.close_handle(h)

    if not inv0["slots"]:
        raise ipp.Blocked("no allocated player inventory slot array -- respawn or load a save")
    if all(s["occupied"] for s in inv0["slots"]):
        raise ipp.Blocked("player inventory has no free slot")

    before = observe(api, pid, r, mask)
    report = {"pid": pid, "struct_size": r["struct_size"], "fields": field_report,
              "text_fields": text_report, "texts": dict(TEXTS),
              "copy_mask_window_count": len(mask),
              "objects": {kk: "0x%x" % r[kk] for kk in
                          ("itemlist", "master", "player_inv", "row_struct", "add_item",
                           "remove_item", "sgk_details", "str2txt", "txt2str")},
              "baseline": {"itemlist_rows": before["itemlist_rows"],
                           "master_rows": before["master_rows"],
                           "parent_raw": before["parent_raw"],
                           "inventory_slots": inv0["num"],
                           "inventory_occupied": sum(1 for s in inv0["slots"] if s["occupied"]),
                           "current_weight": inv0["current_weight"],
                           "item_count": inv0["item_count"]},
              "row_name": ROW_NAME}
    if not args.arm and not args.demo:
        report["armed"] = False
        report["outcome"] = "DRY RUN: all fail-closed checks passed, nothing written."
        return report

    dll = build_dll()
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
    hold = False
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
        io = pack_io(carrier, sigs, r, offs, toffs)
        rio = k.VirtualAllocEx(hp, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
        buf = ctypes.create_string_buffer(IO_SIZE); rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        def read_io_safe():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return {"wait_stopped_ok": struct.unpack_from("<I", buf.raw, WAIT_STOPPED_OK_OFFSET)[0],
                    "state": struct.unpack_from("<I", buf.raw, STATE_OFFSET)[0]}

        def call(export, field, timeout=25.0):
            before_v = read_io()[field]
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            st = read_io(); dl = time.time() + timeout
            while time.time() < dl and st[field] == before_v:
                time.sleep(0.05); st = read_io()
            return st

        if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("Init failed")

        # ---------------- PHASE 1: the metadata primitive -----------------
        st = call("RunCreate", "create_ran")
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
        table_ptr, row_fname = st["table_ptr"], st["row_fname"]

        st = call("RunPopulate", "populate_ran")
        if st["populate_ran"] != 1:
            raise ipp.Blocked("populate failed err=%d" % st["err"])
        if st["text_fields_written"] != 3:
            raise ipp.Blocked("only %d/3 FText fields were written" % st["text_fields_written"])
        if st["use_item_decay"]:
            raise ipp.Blocked("materialized definition has UseItemDecay=1")
        row_ptr, row_key = our_row_ptr(api, pid, table_ptr)
        if not row_ptr:
            raise ipp.Blocked("the Runtime table has no row after AddRow")

        # stage the row pointer and read the text back OUT OF THE ROW, after the
        # temp that built it was destroyed and freed
        k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, struct.pack("<Q", row_ptr), 8,
                             ctypes.byref(wr))
        st = call("RunVerifyText", "verifytext_ran")
        if st["verifytext_ran"] != 1:
            raise ipp.Blocked("text read-back failed err=%d" % st["err"])
        got = {"Name": st["name_row"], "ShortName": st["shortname_row"],
               "Description": st["desc_row"]}
        empty_shared = len(set(st["empty_textdata"])) == 1
        # FText(const FText&) = default (Text.h:386), so a copy copies the
        # TRefCountPtr and ADDREFS: the row is EXPECTED to share the same
        # ITextData as the source, exactly as CR-01C1 established. Sharing here
        # is correctness, not aliasing; the real lifecycle proof is that the text
        # still reads back after the source was destroyed and freed.
        row_shares = (list(st["row_textdata"]) == list(st["our_textdata"]))
        report["primitive"] = {
            "temp_freed": st["temp_freed"] == 1,
            "text_fields_written": st["text_fields_written"],
            "initializestruct_textdata": st["empty_textdata"],
            "initializestruct_textdata_is_one_shared_object": empty_shared,
            "our_textdata": st["our_textdata"],
            "row_textdata": st["row_textdata"],
            "row_shares_textdata_with_source": row_shares,
            "read_back_from_row": got,
            "matches_expected": got == TEXTS,
            "row_ptr": "0x%x" % row_ptr,
        }
        run_note.append("PRIMITIVE: read back from the row after DestroyStruct(temp): %r" % got)
        if got != TEXTS:
            raise ipp.Blocked("FText lifecycle NOT proven: read back %r, expected %r -- STOPPING "
                              "before any gameplay mutation" % (got, TEXTS))
        run_note.append("FText lifecycle proven; row shares ITextData with source=%s "
                        "(expected: FText copy is a refcount share); "
                        "InitializeStruct defaults one shared object=%s"
                        % (row_shares, empty_shared))

        if args.arm and not args.demo:
            # primitive-only mode: destroy the row and stop
            call("RunRemoveRow", "release_ran", timeout=5.0)
            time.sleep(0.4)
            rp2, _ = our_row_ptr(api, pid, table_ptr)
            report["primitive"]["row_removed_cleanly"] = (rp2 == 0)
            report["mode"] = "primitive-only"
        else:
            # ------------- PHASE 2: the controlled demo -------------------
            st = call("RunAttach", "attach_ran")
            if st["attach_ran"] != 1:
                raise ipp.Blocked("attach refused err=%d step=%d" % (st["err"], st["err_step"]))
            after_pub = observe(api, pid, r, mask)
            report["after_publish"] = {
                "master_rows": after_pub["master_rows"],
                "probe_in_master": row_key in after_pub["master_semantic"],
                "all_vanilla_present": all(kk in after_pub["master_semantic"]
                                           for kk in before["master_semantic"]),
                "all_vanilla_semantically_unchanged":
                    all(after_pub["master_semantic"].get(kk) == v
                        for kk, v in before["master_semantic"].items()),
                "itemlist_exact_unchanged": after_pub["itemlist_exact"] == before["itemlist_exact"]}
            if not report["after_publish"]["probe_in_master"]:
                raise RollbackNeeded("probe did not appear in MasterItemList")

            st = call("RunResolve", "resolve_ran")
            res_text = {"Name": st["name_res"], "ShortName": st["shortname_res"],
                        "Description": st["desc_res"]}
            report["resolver"] = {
                "found": st["resolve_found"], "weight": st["resolve_weight"],
                "width": st["resolve_width"], "height": st["resolve_height"],
                "maxstack": st["resolve_maxstack"], "text": res_text,
                "text_matches_expected": res_text == TEXTS}
            run_note.append("RESOLVER: found=%d text=%r" % (st["resolve_found"], res_text))
            if st["resolve_found"] != 1 or res_text != TEXTS:
                raise RollbackNeeded("SGK ItemDetails did not return the expected FText: %r" % res_text)

            st = call("RunAddItem", "additem_ran")
            if st["additem_ran"] != 1:
                raise RollbackNeeded("AddItem did not run err=%d" % st["err"])
            report["additem_out"] = {"RemainingItem": st["out_remaining_item"],
                                     "NewItemSlot": st["out_newitemslot"]}
            after_add = observe(api, pid, r, mask)
            inv1 = after_add["inventory"]
            ours = c3d.occupied_with(inv1, row_fname & 0xFFFFFFFF)
            report["inventory"] = {"entries_with_item": len(ours),
                                   "slot": ours[0] if ours else None,
                                   "item_count": inv1["item_count"],
                                   "current_weight": inv1["current_weight"],
                                   "changed_slots": c3d.slot_diff(inv0, inv1)}
            if len(ours) != 1:
                raise RollbackNeeded("expected one inventory entry, found %d" % len(ours))
            run_note.append("INVENTORY: item in slot %d, weight %r -> %r, count %d -> %d"
                            % (ours[0]["index"], inv0["current_weight"], inv1["current_weight"],
                               inv0["item_count"], inv1["item_count"]))
            hold = True
            report["mode"] = "demo"
            report["status"] = "READY_FOR_VISUAL_CHECK"
            with open(STATE_PATH, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"pid": pid, "rbase": rbase, "rio": rio, "rpath": rpath, "dll": dll,
                           "row_fname": row_fname, "table_ptr": table_ptr,
                           "player_inv": r["player_inv"], "master": r["master"],
                           "itemlist": r["itemlist"], "objects_ptr": r["objects_ptr"],
                           "struct_size": r["struct_size"], "row_name": ROW_NAME,
                           "baseline_inventory_sha256": inv0["slots_sha256"],
                           "baseline_weight": inv0["current_weight"],
                           "baseline_item_count": inv0["item_count"]}, f, indent=2, sort_keys=True)
                f.write("\n")
            report["state_file"] = STATE_PATH
    except RollbackNeeded as exc:
        report["rollback_reason"] = str(exc)
        run_note.append("ROLLBACK: %s" % exc)
        try:
            inv_now = observe(api, pid, r, mask)["inventory"]
            mine = c3d.occupied_with(inv_now, row_fname & 0xFFFFFFFF)
            if mine:
                k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, bytes.fromhex(mine[0]["raw"]), 80,
                                     ctypes.byref(wr))
                call("RunRemoveItem", "removeitem_ran")
            call("RunDetach", "detach_ran")
            call("RunZeroSlot", "zero_ran")
        except Exception as e2:  # noqa: BLE001
            report["rollback_error"] = repr(e2)
    finally:
        if not hold:
            try:
                call("RunRelease", "release_ran")
            except Exception:  # noqa: BLE001
                pass
            td = probe_teardown.shutdown_then_unload(k, hp, rbase, dll, rio, read_io_safe, run_note)
            cleanup["teardown"] = td
            if td["safe_to_free_remote_memory"]:
                for b2 in (rpath, rio):
                    if b2 is not None:
                        k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
            else:
                cleanup["remote_memory_left_allocated"] = True
            try:
                cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
            except Exception:  # noqa: BLE001
                cleanup["dll_unloaded"] = None
        else:
            cleanup["held_for_visual_check"] = True
            run_note.append("HOLDING: module, IO, root and publication all left alive")
        k.CloseHandle(hp)
    report["cleanup"] = cleanup

    td = cleanup.get("teardown") or {}
    if td.get("attempted") and not td.get("unloaded"):
        report["verdict"] = "BLOCKED-TEARDOWN"
        report["teardown_blocked"] = td.get("left_loaded_reason")
        return report
    if hold:
        report["verdict"] = "HELD"
        return report
    pr = report.get("primitive", {})
    report["verdict"] = "PASS" if (
        not report.get("rollback_reason") and pr.get("matches_expected")
        and pr.get("temp_freed") and pr.get("text_fields_written") == 3
        and pr.get("row_shares_textdata_with_source")
        and (report.get("mode") != "primitive-only" or pr.get("row_removed_cleanly"))
        and cleanup.get("dll_unloaded")) else "NOT-PASS"
    return report


def run_cleanup(api, run_note):
    """The already-proven rollback, against the module the demo left loaded.

    RemoveItem is skipped when no inventory entry carries the id -- which is the
    case if the item left the inventory by any other route. The registry rollback
    is unchanged and is the part that matters: detach, rebuild, zero the spare
    slot, release the root, then the teardown handshake.
    """
    k, _ = gt._k32full()
    if not os.path.isfile(STATE_PATH):
        raise ipp.Blocked("no demo state at %s" % STATE_PATH)
    with open(STATE_PATH, encoding="utf-8") as f:
        state = json.load(f)
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    if i01["pid"] != state["pid"]:
        raise ipp.Blocked("the game was restarted (pid %d, demo held %d); the demo state died "
                          "with the old process" % (i01["pid"], state["pid"]))
    pid, dll, rbase, rio = state["pid"], state["dll"], state["rbase"], state["rio"]
    if ipp.find_remote_module_base(k, pid, DLL_NAME) != rbase:
        raise ipp.Blocked("the probe module is no longer loaded at the recorded base")
    hp = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hp:
        raise ipp.Blocked("OpenProcess failed")
    buf = ctypes.create_string_buffer(IO_SIZE)
    rd = ctypes.c_size_t(0)
    wr = ctypes.c_size_t(0)
    fid = state["row_fname"] & 0xFFFFFFFF

    def read_io():
        k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
        return unpack_io(buf.raw)

    def read_io_safe():
        k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
        return {"wait_stopped_ok": struct.unpack_from("<I", buf.raw, WAIT_STOPPED_OK_OFFSET)[0],
                "state": struct.unpack_from("<I", buf.raw, STATE_OFFSET)[0]}

    def call(export, field, timeout=25.0):
        before_v = read_io()[field]
        p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io()
        dl = time.time() + timeout
        while time.time() < dl and st[field] == before_v:
            time.sleep(0.05); st = read_io()
        return st

    report = {"mode": "cleanup", "pid": pid, "row_name": state["row_name"]}
    h = eri.open_process_read_only(api, pid)
    try:
        inv = c3d.read_inventory(api, h, state["player_inv"])
    finally:
        api.close_handle(h)
    mine = c3d.occupied_with(inv, fid)
    report["inventory_entries_before_cleanup"] = len(mine)
    if mine:
        k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, bytes.fromhex(mine[0]["raw"]), 80,
                             ctypes.byref(wr))
        st = call("RunRemoveItem", "removeitem_ran")
        report["removeitem_ran"] = st["removeitem_ran"]
    else:
        run_note.append("no inventory entry carries the id; RemoveItem skipped")
        report["removeitem_skipped"] = True

    st = call("RunDetach", "detach_ran"); report["detach_ran"] = st["detach_ran"]
    st = call("RunZeroSlot", "zero_ran"); report["zero_ran"] = st["zero_ran"]
    st = call("RunRelease", "release_ran")
    report["release"] = {"release_ran": st["release_ran"],
                         "rooted_after_release": st["rooted_after_release"],
                         "owned_count": st["owned_count"],
                         "item_flags": st["item_flags"]}

    h = eri.open_process_read_only(api, pid)
    try:
        inv2 = c3d.read_inventory(api, h, state["player_inv"])
        report["final"] = {
            "master_rows": len(rows_by_key(api, h, state["master"])),
            "itemlist_rows": len(rows_by_key(api, h, state["itemlist"])),
            "parent_raw": parent_raw(api, h, state["master"]),
            "old_parent": old_parent_state(api, h, state["master"]),
            "itemlist_delegate": delegate_targets(api, h, state["itemlist"], state["objects_ptr"]),
            "runtime_table_delegate": delegate_targets(api, h, state["table_ptr"],
                                                       state["objects_ptr"]),
            "inventory_entries_with_id": len(c3d.occupied_with(inv2, fid)),
            "inventory_item_count": inv2["item_count"],
            "inventory_current_weight": inv2["current_weight"],
            "inventory_slots_restored": inv2["slots_sha256"] == state["baseline_inventory_sha256"]}
    finally:
        api.close_handle(h)

    td = probe_teardown.shutdown_then_unload(k, hp, rbase, dll, rio, read_io_safe, run_note)
    report["teardown"] = td
    if td["safe_to_free_remote_memory"]:
        for b2 in (state.get("rpath"), rio):
            if b2:
                k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
        report["remote_memory_freed"] = True
    else:
        report["remote_memory_left_allocated"] = True
    try:
        report["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
    except Exception:  # noqa: BLE001
        report["dll_unloaded"] = None
    k.CloseHandle(hp)

    if td["attempted"] and not td["unloaded"]:
        report["verdict"] = "BLOCKED-TEARDOWN"
        report["teardown_blocked"] = td["left_loaded_reason"]
    else:
        fi = report["final"]
        report["verdict"] = "CLEAN" if (
            report["detach_ran"] == 1 and report["zero_ran"] == 1
            and report["release"]["release_ran"] == 1
            and report["release"]["rooted_after_release"] == 0
            and fi["master_rows"] == 496 and fi["itemlist_rows"] == 496
            and fi["parent_raw"]["num"] == 1 and fi["parent_raw"]["slots"][1] == "0x0"
            and fi["runtime_table_delegate"]["num"] == 0
            and fi["inventory_entries_with_id"] == 0
            and fi["inventory_slots_restored"]
            and report["dll_unloaded"]) else "NOT-CLEAN"
        if report["verdict"] == "CLEAN" and os.path.isfile(STATE_PATH):
            os.remove(STATE_PATH)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arm", action="store_true", help="run phase 1, the metadata primitive")
    ap.add_argument("--demo", action="store_true",
                    help="run phase 1 AND phase 2, then HOLD for a visual check")
    ap.add_argument("--cleanup", action="store_true",
                    help="roll back a held demo")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    rid = (a.run_dir and os.path.basename(a.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    rdir = a.run_dir or os.path.join(REPO, "research", "instrument-runs", rid)
    os.makedirs(rdir, exist_ok=True)
    note, arts = [], []
    vb = va = None
    caps = ["CR-01C4A"] if (a.arm or a.demo or a.cleanup) else ["I-01"]
    code = 0
    try:
        api = eri.Win32Api()
        if a.arm or a.demo or a.cleanup:
            vb = ipp.run_verify_install(rdir, "before")
            if vb.get("report_artifact"):
                arts.append(vb["report_artifact"])
            if vb["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before")
        rep = run_cleanup(api, note) if a.cleanup else run(api, a, note)
        rep["run_note"] = note
        if a.arm or a.demo or a.cleanup:
            va = ipp.run_verify_install(rdir, "after")
            if va.get("report_artifact"):
                arts.append(va["report_artifact"])
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        if rep.get("verdict") == "BLOCKED-TEARDOWN":
            code = 2
            print("BLOCKED (teardown): %s -- the probe is STILL LOADED; restart the game."
                  % rep.get("teardown_blocked"), file=sys.stderr)
        print(json.dumps({kk: rep[kk] for kk in rep if kk not in ("run_note", "baseline")},
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
                           instrument_level=("ipp" if (a.arm or a.demo or a.cleanup) else "eri"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
