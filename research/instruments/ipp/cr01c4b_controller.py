#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C4B -- custom inventory icon from a mod-owned PNG.

    mod-owned Texture2D in an external cooked container
      -> reflected UKismetSystemLibrary::LoadAsset_Blocking
      -> rooted in the SAME RuntimeAssetStore as every other runtime-owned object
      -> S_ItemDetails.UIDetails.InventoryIcon (hard FObjectProperty)
      -> published through the Runtime aggregate table into MasterItemList
      -> AddItem
      -> held for a visual check

THE ICON FIELD WAS DERIVED, NOT NAMED. BP_InventoryItemIcon_C::UpdateIcon embeds
the FProperty pointer of S_UIDetails::InventoryIcon and no other member of that
struct; BP_QuickSlot_C::UpdateItemIcon embeds QuickSlotIcon and no other. The
control landing on a different field is what makes it an identification.

Modes: --arm (through the icon-in-row proof, then unwind), --demo (all the way
to AddItem and HOLD), --cleanup (the proven rollback).
"""
import argparse
import ctypes
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
from cr01c3b_controller import (DiskImage, verify_carrier_addresses, verify_fields,  # noqa: E402
                                OFF_ROWSTRUCT, OFF_PARENT_TABLES)  # noqa: E402
from cr01c3c_controller import (rows_by_key, derive_copy_mask, masked_digest,  # noqa: E402
                                semantic_digests, exact_hashes, delegate_targets,
                                parent_raw, old_parent_state)
from cr01c4a_controller import text_fields, u16_to_str, str_to_u16, TEXTS as _C4A_TEXTS  # noqa: E402

DLL_NAME = "CR01C4BProbe.dll"
ROW_NAME = "mbpl__radio"
TRIGGER_NAME = "mbpl__c4b_neutral_trigger"
STATE_PATH = os.path.join(REPO, "workspace", "c4b-demo-state.json")

ICON_PACKAGE = "/Game/MBPLTest/Items/Radio/T_MBPL_Radio_Icon"
ICON_ASSET = "T_MBPL_Radio_Icon"
ICON_EXPECTED_PATH = "%s.%s" % (ICON_PACKAGE, ICON_ASSET)

TEXTS = {"Name": "MBPL Radio", "ShortName": "Radio",
         "Description": "A runtime-defined MBPL test radio."}
VALUES = {"Weight": 0.5, "Width": 1, "Height": 1, "MaxStack": 1, "AllowStacking": 0}
TXT_CAP = 128

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQ QQQ QQQQ QQQ QQQ QQ QQQQ QQ Q QQQQ QQ IIII IIII IIIIII d "
          "iiiB3s iiiiii f I 96H 96H 80s 128H128H128H 128H128H128H 128H128H128H 128H128H128H "
          "QQQ QQQ QQQ QQQQ QQQQ IIII IIII "
          "IIII IIII IIII IIII IIII IIII IIII IIII IIII QQQQQ QQQQQ QQQQ 48s 16s IIII dII QQ"
          ).replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 4544, "C4BIo wire format drifted (%d)" % IO_SIZE
SLOT_IN_OFFSET = struct.calcsize(IO_FMT.split("80s")[0])
assert SLOT_IN_OFFSET == 856, "slot_in offset drifted (%d)" % SLOT_IN_OFFSET
_INPUT_PREFIX = IO_FMT.rsplit("QQQQ IIII IIII".replace(" ", ""), 1)[0] + "QQQQIIIIIIII"
_OUTPUT_BLOCK_OFFSET = struct.calcsize(_INPUT_PREFIX)
STATE_OFFSET = _OUTPUT_BLOCK_OFFSET + 8
WAIT_STOPPED_OK_OFFSET = _OUTPUT_BLOCK_OFFSET + 12
OUT_INDEX = len(struct.unpack(_INPUT_PREFIX, bytes(struct.calcsize(_INPUT_PREFIX))))
_TXT_INDEX = len(struct.unpack(IO_FMT.split("80s")[0] + "80s",
                               bytes(struct.calcsize(IO_FMT.split("80s")[0] + "80s"))))


class RollbackNeeded(Exception):
    pass


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C4BProbeDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    bat = os.path.join(bd, "_build_c4bctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C4BProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


def icon_field_offset(api, h, np, row_struct, objs):
    """FAIL CLOSED. Resolves S_ItemDetails.UIDetails and, inside it,
    S_UIDetails.InventoryIcon -- the field BP_InventoryItemIcon_C::UpdateIcon was
    shown to read. Every hop is checked: struct identity, property class, size."""
    cp = eri._read_u64(api, h, row_struct + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    ui_off = ui_struct = None
    for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=row_struct,
                                      objects_by_address=objs).get("accepted", []):
        if (pr.get("raw_name") or "").split("_")[0] != "UIDetails":
            continue
        if pr.get("property_class") != "FStructProperty":
            raise ipp.Blocked("UIDetails is %s, not FStructProperty" % pr.get("property_class"))
        ui_off = pr.get("offset")
        ui_struct = eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)
    if ui_off is None:
        raise ipp.Blocked("S_ItemDetails.UIDetails not found")
    if (objs.get(ui_struct) or {}).get("name_text") != "S_UIDetails":
        raise ipp.Blocked("UIDetails struct is %r, expected S_UIDetails"
                          % (objs.get(ui_struct) or {}).get("name_text"))
    cp2 = eri._read_u64(api, h, ui_struct + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    icon_off = None
    for pr in eri.walk_property_chain(api, h, cp2, namepool_live_va=np, owner_address=ui_struct,
                                      objects_by_address=objs).get("accepted", []):
        if (pr.get("raw_name") or "").split("_")[0] != "InventoryIcon":
            continue
        if pr.get("property_class") != "FObjectProperty":
            raise ipp.Blocked("InventoryIcon is %s, not FObjectProperty"
                              % pr.get("property_class"))
        if pr.get("size") != 8:
            raise ipp.Blocked("InventoryIcon size %r != 8" % pr.get("size"))
        pc = eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)
        if (objs.get(pc) or {}).get("name_text") != "Texture2D":
            raise ipp.Blocked("InventoryIcon PropertyClass is %r, expected Texture2D"
                              % (objs.get(pc) or {}).get("name_text"))
        icon_off = pr.get("offset")
    if icon_off is None:
        raise ipp.Blocked("S_UIDetails.InventoryIcon not found")
    return {"uidetails_offset": ui_off, "inventoryicon_offset_in_uidetails": icon_off,
            "absolute_offset": ui_off + icon_off, "property_class": "FObjectProperty",
            "size": 8, "reference": "hard TObjectPtr<UTexture2D>"}


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    keys = ["activated", "initialized", "state", "wait_stopped_ok",
            "create_ran", "populate_ran", "attach_ran", "detach_ran",
            "zero_ran", "release_ran", "resolve_ran", "additem_ran",
            "removeitem_ran", "gt_tid", "fstring_ok", "err",
            "err_step", "internal_index", "temp_freed", "rooted_after_acquire",
            "rooted_after_release", "owned_count", "item_flags", "table_addrow_matches",
            "table_removerow_matches", "resolve_found", "use_item_decay", "use_durability",
            "parent_num_before", "parent_max", "parent_num_after_attach",
            "parent_num_after_detach",
            "verifytext_ran", "resolvetext_ran", "text_fields_written", "pad4",
            "table_ptr", "table_item_ptr", "table_class", "table_outer", "table_vtable",
            "table_rowstruct_after", "row_fname", "trigger_fname", "temp_ptr", "store_handle",
            "parent_data", "parent_elem0", "parent_elem1_before", "parent_elem1_after",
            "out_remaining_invitem", "out_newitemslot",
            "out_remaining_item", "resolve_width", "resolve_height", "resolve_maxstack",
            "resolve_weight", "resolve_allowstacking"]
    out = {k: f[OUT_INDEX + n] for n, k in enumerate(keys)}
    t = _TXT_INDEX
    labels = ["name_in", "shortname_in", "desc_in", "name_row", "shortname_row", "desc_row",
              "name_res", "shortname_res", "desc_res",
              "icon_pkg_in", "icon_asset_in", "icon_path_roundtrip"]
    for i, lab in enumerate(labels):
        out[lab] = u16_to_str(f[t + i * TXT_CAP: t + (i + 1) * TXT_CAP])
    p = t + 12 * TXT_CAP
    out["empty_textdata"] = ["0x%x" % f[p + i] for i in range(3)]
    out["our_textdata"] = ["0x%x" % f[p + 3 + i] for i in range(3)]
    out["row_textdata"] = ["0x%x" % f[p + 6 + i] for i in range(3)]
    q = p + 9
    for i, lab in enumerate(["icon_object", "icon_item_ptr", "icon_class", "icon_outer",
                             "icon_store_handle", "row_icon_ptr", "resolve_icon_ptr",
                             "icon_reserved"]):
        out[lab] = f[q + i]
    r = q + 8
    for i, lab in enumerate(["icon_size_x", "icon_size_y", "icon_rooted_after_acquire",
                             "icon_rooted_after_release", "loadicon_ran", "verifyicon_ran",
                             "releaseicon_ran", "soft_roundtrip_ok"]):
        out[lab] = f[r + i]
    out["out_remaining_invitem"] = c3d.decode_invitem(out["out_remaining_invitem"])
    ns = out["out_newitemslot"]
    out["out_newitemslot"] = {"InvComponent": "0x%x" % struct.unpack_from("<Q", ns, 0)[0],
                              "Index": struct.unpack_from("<i", ns, 8)[0]}
    return out


def resolve(api, h, base, size, img, run_note):
    np, objs = recon.universe(api, h, base, size)
    fmeta = recon.find_function_meta(objs)

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
    tex_class = one("Texture2D", "Class", "UTexture2D UClass")
    gs_cdo = one("Default__GameplayStatics", "GameplayStatics", "GameplayStatics CDO")
    sl_cdo = one("Default__KismetStringLibrary", "KismetStringLibrary", "KismetStringLibrary CDO")
    tl_cdo = one("Default__KismetTextLibrary", "KismetTextLibrary", "KismetTextLibrary CDO")
    sy_cdo = one("Default__KismetSystemLibrary", "KismetSystemLibrary", "KismetSystemLibrary CDO")
    sgk_cdo = one("Default__BP_SGKFunctions_C", "BP_SGKFunctions_C", "BP_SGKFunctions CDO")
    gs_cls = one("GameplayStatics", "Class", "GameplayStatics UClass")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary UClass")
    tl_cls = one("KismetTextLibrary", "Class", "KismetTextLibrary UClass")
    sy_cls = one("KismetSystemLibrary", "Class", "KismetSystemLibrary UClass")
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
    load_blocking = fn_on(sy_cls, "LoadAsset_Blocking", "KismetSystemLibrary")
    soft2str = fn_on(sy_cls, "Conv_SoftObjectReferenceToString", "KismetSystemLibrary")
    sgk_details = fn_on(sgk_cls, "SGK ItemDetails", "BP_SGKFunctions")
    add_item = fn_on(mi_cls, "AddItem", "BP_MasterInventory_C")
    remove_item = fn_on(mi_cls, "RemoveItem", "BP_MasterInventory_C")

    def gate(fn, label, parms, rvo=None, need=0):
        fl = eri._read_u32(api, h, fn + 0xB0)
        ps = eri._read_u16(api, h, fn + 0xB6)
        got_rvo = eri._read_u16(api, h, fn + 0xB8)
        if ps != parms:
            raise ipp.Blocked("%s ParmsSize %d != %d" % (label, ps, parms))
        if rvo is not None and got_rvo != rvo:
            raise ipp.Blocked("%s ReturnValueOffset %d != %d" % (label, got_rvo, rvo))
        if need and (fl & need) != need:
            raise ipp.Blocked("%s flags 0x%x lack 0x%x" % (label, fl, need))
        if fl & 0x0138C0C4:
            raise ipp.Blocked("%s carries a net/authority flag 0x%x" % (label, fl))
        if eri._read_u64(api, h, fn + 0xC8):
            raise ipp.Blocked("%s EventGraphFunction non-null" % label)
        run_note.append("%s: flags=0x%x ParmsSize=%d RVO=%d EG=null" % (label, fl, ps, got_rvo))

    gate(spawn, "SpawnObject", 24, need=0x2400)
    gate(add_item, "AddItem", 120)
    gate(remove_item, "RemoveItem", 83)
    gate(sgk_details, "SGK ItemDetails", 2336)
    gate(str2txt, "Conv_StringToText", 32, rvo=16, need=0x2400)
    gate(txt2str, "Conv_TextToString", 32, rvo=16, need=0x2400)
    gate(load_blocking, "LoadAsset_Blocking", 48, rvo=40, need=0x2400)
    gate(soft2str, "Conv_SoftObjectReferenceToString", 56, rvo=40, need=0x2400)

    # the soft-object parameter must be exactly the 40-byte shape we build
    for fn, label in ((load_blocking, "LoadAsset_Blocking"), (soft2str, "Conv_SoftObjectReferenceToString")):
        cp = eri._read_u64(api, h, fn + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        seen = {}
        for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=fn,
                                          objects_by_address=objs).get("accepted", []):
            raw = pr.get("property_flags_raw")
            pf = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
            if pf & 0x80:
                seen[pr.get("raw_name")] = (pr.get("property_class"), pr.get("offset"), pr.get("size"))
        soft = [v for k, v in seen.items() if v[0] == "FSoftObjectProperty"]
        if len(soft) != 1 or soft[0][1] != 0 or soft[0][2] != 40:
            raise ipp.Blocked("%s soft parameter shape is %r, expected one FSoftObjectProperty "
                              "at offset 0 size 40" % (label, soft))
    run_note.append("soft-object parameter shape verified for both loader functions")

    owner = eri._read_u64(api, h, player_inv + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
    role = eri._read_u8(api, h, owner + 336)
    if role != 3:
        raise ipp.Blocked("owning actor Role=%d, not ROLE_Authority" % role)
    nets = [a for a, r in objs.items() if r.get("name_ok")
            and "NetDriver" in ((objs.get(r.get("class_ptr") or 0) or {}).get("name_text") or "")
            and not (r.get("name_text") or "").startswith("Default__")]
    if nets:
        raise ipp.Blocked("live NetDriver instances present (%d)" % len(nets))

    if eri._read_u64(api, h, master + eri.DEFAULT_CLASS_PRIVATE_OFFSET) != cdt_class:
        raise ipp.Blocked("MasterItemList is not a UCompositeDataTable")
    composite_vt = eri._read_u64(api, h, master)
    plain_vt = eri._read_u64(api, h, itemlist)
    rs = eri._read_u64(api, h, itemlist + OFF_ROWSTRUCT)
    if rs != eri._read_u64(api, h, master + OFF_ROWSTRUCT):
        raise ipp.Blocked("RowStruct mismatch")
    struct_size = struct.unpack("<i", api.read_process_memory(h, rs + 0x58, 4))[0]
    add_row = eri._read_u64(api, h, plain_vt + 95 * 8)
    rem_row = eri._read_u64(api, h, plain_vt + 94 * 8)
    svt = eri._read_u64(api, h, rs)
    init_va = eri._read_u64(api, h, svt + 96 * 8)
    dest_va = eri._read_u64(api, h, svt + 97 * 8)
    pe = eri._read_u64(api, h, eri._read_u64(api, h, sl_cdo) + c1.PE_SLOT * 8)
    set_root, clr_root, free_va = base + 0x1210E60, base + 0x11BB340, base + 0xFA0090
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
            "dt_class": dt_class, "cdt_class": cdt_class, "tex_class": tex_class,
            "gs_cdo": gs_cdo, "sl_cdo": sl_cdo, "tl_cdo": tl_cdo, "sy_cdo": sy_cdo,
            "sgk_cdo": sgk_cdo, "spawn": spawn, "conv": conv, "str2txt": str2txt,
            "txt2str": txt2str, "load_blocking": load_blocking, "soft2str": soft2str,
            "sgk_details": sgk_details, "add_item": add_item, "remove_item": remove_item,
            "player_inv": player_inv, "owner": owner, "row_struct": rs,
            "struct_size": struct_size, "plain_vtable": plain_vt, "composite_vtable": composite_vt,
            "add_row": add_row, "remove_row": rem_row, "init": init_va, "destroy": dest_va,
            "pe": pe, "set_root": set_root, "clear_root": clr_root, "free": free_va,
            "objects_ptr": i02["objects_ptr_live_va"], "parent_raw": praw}


def pack_io(carrier, sigs, r, offs, toffs, icon_off):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    tg = [ord(c) for c in TRIGGER_NAME] + [0] * (96 - len(TRIGGER_NAME))
    return struct.pack(
        IO_FMT, 0x4950502D43344200, 1, r["struct_size"],
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"], r["free"],
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["sl_cdo"], r["conv"],
        r["gs_cdo"], r["spawn"],
        r["tl_cdo"], r["str2txt"], r["txt2str"],
        r["sy_cdo"], r["load_blocking"], r["soft2str"], r["tex_class"],
        r["dt_class"], r["transient"], r["row_struct"],
        r["itemlist"], r["master"], r["plain_vtable"],
        r["composite_vtable"], r["cdt_class"],
        r["add_row"], r["remove_row"], r["init"], r["destroy"],
        r["set_root"], r["clear_root"],
        r["objects_ptr"],
        r["player_inv"], r["add_item"], r["remove_item"], r["sgk_details"],
        r["sgk_cdo"], 0,
        OFF_PARENT_TABLES, OFF_ROWSTRUCT, 0x98, c3d.OFF_INVENTORY_ARRAY,
        toffs["Name"], toffs["ShortName"], toffs["Description"], icon_off,
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"], b"\0\0\0",
        c3d.INVITEM["amount"], c3d.INVITEM["quickbind"], c3d.INVITEM["useamount"],
        c3d.INVITEM["decaytime"], c3d.INVITEM["rotated"], c3d.INVITEM["inuse"],
        c3d.INVITEM["durability"], 0,
        *nm, *tg, b"\0" * 80,
        *str_to_u16(TEXTS["Name"]), *str_to_u16(TEXTS["ShortName"]),
        *str_to_u16(TEXTS["Description"]),
        *([0] * TXT_CAP), *([0] * TXT_CAP), *([0] * TXT_CAP),
        *([0] * TXT_CAP), *([0] * TXT_CAP), *([0] * TXT_CAP),
        *str_to_u16(ICON_PACKAGE), *str_to_u16(ICON_ASSET), *([0] * TXT_CAP),
        0, 0, 0,  0, 0, 0,  0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,
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


def our_row(api, pid, table_ptr):
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
        offs, field_report = verify_fields(api, h, r["np"], r["row_struct"], VALUES)
        for kk in field_report:
            field_report[kk]["value"] = VALUES[kk]
        toffs, text_report = text_fields(api, h, r["np"], r["row_struct"], TEXTS)
        for kk in text_report:
            text_report[kk]["value"] = TEXTS[kk]
        icon = icon_field_offset(api, h, r["np"], r["row_struct"], r["objs"])
        run_note.append("icon field: UIDetails@%d + InventoryIcon@%d = absolute %d (%s)"
                        % (icon["uidetails_offset"], icon["inventoryicon_offset_in_uidetails"],
                           icon["absolute_offset"], icon["reference"]))
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

    if not inv0["slots"] or all(s["occupied"] for s in inv0["slots"]):
        raise ipp.Blocked("no free player inventory slot -- respawn or free a slot")
    before = observe(api, pid, r, mask)
    report = {"pid": pid, "icon_field": icon, "fields": field_report, "text_fields": text_report,
              "texts": dict(TEXTS), "icon_package": ICON_PACKAGE, "row_name": ROW_NAME,
              "baseline": {"itemlist_rows": before["itemlist_rows"],
                           "master_rows": before["master_rows"],
                           "parent_raw": before["parent_raw"],
                           "inventory_slots": inv0["num"],
                           "inventory_occupied": sum(1 for s in inv0["slots"] if s["occupied"]),
                           "current_weight": inv0["current_weight"],
                           "item_count": inv0["item_count"]}}
    if not (args.arm or args.demo):
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
        io = pack_io(carrier, sigs, r, offs, toffs, icon["absolute_offset"])
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

        def call(export, field, timeout=60.0):
            before_v = read_io()[field]
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            st = read_io(); dl = time.time() + timeout
            while time.time() < dl and st[field] == before_v:
                time.sleep(0.05); st = read_io()
            return st

        if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("Init failed")
        st = call("RunCreate", "create_ran")
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
        table_ptr, row_fname = st["table_ptr"], st["row_fname"]

        # ---- load the mod-owned texture and take ownership of it ----------
        st = call("RunLoadIcon", "loadicon_ran")
        report["icon_load"] = {
            "loadicon_ran": st["loadicon_ran"], "err": st["err"], "err_step": st["err_step"],
            "soft_path_roundtrip": st["icon_path_roundtrip"],
            "soft_path_expected": ICON_EXPECTED_PATH,
            "soft_path_matches": st["icon_path_roundtrip"] == ICON_EXPECTED_PATH,
            "object": "0x%x" % st["icon_object"], "class": "0x%x" % st["icon_class"],
            "class_is_texture2d": st["icon_class"] == r["tex_class"],
            "rooted": st["icon_rooted_after_acquire"] == 1,
            "owned_count": st["owned_count"]}
        if st["loadicon_ran"] != 1:
            raise ipp.Blocked("icon load failed err=%d step=%d" % (st["err"], st["err_step"]))
        if not report["icon_load"]["soft_path_matches"]:
            raise ipp.Blocked("soft-object round trip returned %r, expected %r"
                              % (st["icon_path_roundtrip"], ICON_EXPECTED_PATH))
        icon_obj = st["icon_object"]
        run_note.append("icon loaded: %s at 0x%x, Texture2D=%s, rooted=%s"
                        % (st["icon_path_roundtrip"], icon_obj,
                           report["icon_load"]["class_is_texture2d"],
                           report["icon_load"]["rooted"]))

        st = call("RunPopulate", "populate_ran")
        if st["populate_ran"] != 1:
            raise ipp.Blocked("populate failed err=%d" % st["err"])
        row_ptr, row_key = our_row(api, pid, table_ptr)
        if not row_ptr:
            raise ipp.Blocked("no row after AddRow")
        k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, struct.pack("<Q", row_ptr), 8,
                             ctypes.byref(wr))
        st = call("RunVerifyRow", "verifytext_ran")
        got = {"Name": st["name_row"], "ShortName": st["shortname_row"],
               "Description": st["desc_row"]}
        report["row"] = {"texts": got, "texts_match": got == TEXTS,
                         "icon_ptr": "0x%x" % st["row_icon_ptr"],
                         "icon_survived_temp_destroy": st["row_icon_ptr"] == icon_obj,
                         "verifyicon_ran": st["verifyicon_ran"]}
        run_note.append("row after DestroyStruct(temp): texts=%s icon_ptr=0x%x (matches=%s)"
                        % (got == TEXTS, st["row_icon_ptr"], st["row_icon_ptr"] == icon_obj))
        if got != TEXTS or st["row_icon_ptr"] != icon_obj:
            raise ipp.Blocked("row did not carry the expected metadata/icon")

        if args.arm and not args.demo:
            p04.call_export(k, hp, rbase, dll, "RunRemoveRow", rio, ipp.WAIT_TIMEOUT_MS)
            dl = time.time() + 20.0
            while time.time() < dl and our_row(api, pid, table_ptr)[0]:
                time.sleep(0.1)
            report["row"]["row_removed_cleanly"] = our_row(api, pid, table_ptr)[0] == 0
            report["mode"] = "primitive-only"
        else:
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
                "text": res_text, "text_matches": res_text == TEXTS,
                "icon_ptr": "0x%x" % st["resolve_icon_ptr"],
                "icon_matches": st["resolve_icon_ptr"] == icon_obj}
            run_note.append("resolver: found=%d text_ok=%s icon=0x%x icon_ok=%s"
                            % (st["resolve_found"], res_text == TEXTS, st["resolve_icon_ptr"],
                               st["resolve_icon_ptr"] == icon_obj))
            if st["resolve_found"] != 1 or res_text != TEXTS or st["resolve_icon_ptr"] != icon_obj:
                raise RollbackNeeded("resolver did not return our definition with our icon")

            st = call("RunAddItem", "additem_ran")
            if st["additem_ran"] != 1:
                raise RollbackNeeded("AddItem did not run err=%d" % st["err"])
            report["additem_out"] = {"RemainingItem": st["out_remaining_item"],
                                     "NewItemSlot": st["out_newitemslot"]}
            inv1 = observe(api, pid, r, mask)["inventory"]
            ours = c3d.occupied_with(inv1, row_fname & 0xFFFFFFFF)
            report["inventory"] = {"entries_with_item": len(ours),
                                   "slot": ours[0] if ours else None,
                                   "item_count": inv1["item_count"],
                                   "current_weight": inv1["current_weight"]}
            if len(ours) != 1:
                raise RollbackNeeded("expected one inventory entry, found %d" % len(ours))
            run_note.append("INVENTORY: slot %d, weight %r -> %r, count %d -> %d"
                            % (ours[0]["index"], inv0["current_weight"], inv1["current_weight"],
                               inv0["item_count"], inv1["item_count"]))
            hold = True
            report["mode"] = "demo"
            report["status"] = "READY_FOR_VISUAL_CHECK"
            with open(STATE_PATH, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"pid": pid, "rbase": rbase, "rio": rio, "rpath": rpath, "dll": dll,
                           "row_fname": row_fname, "table_ptr": table_ptr, "icon_object": icon_obj,
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
            for exp, fld in (("RunReleaseIcon", "releaseicon_ran"), ("RunRelease", "release_ran")):
                try:
                    call(exp, fld)
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
            run_note.append("HOLDING: module, IO, table root, ICON root and publication alive")
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
    rw = report.get("row", {})
    report["verdict"] = "PASS" if (
        not report.get("rollback_reason")
        and report.get("icon_load", {}).get("class_is_texture2d")
        and report.get("icon_load", {}).get("soft_path_matches")
        and rw.get("texts_match") and rw.get("icon_survived_temp_destroy")
        and (report.get("mode") != "primitive-only" or rw.get("row_removed_cleanly"))
        and cleanup.get("dll_unloaded")) else "NOT-PASS"
    return report


def run_cleanup(api, run_note):
    """The proven rollback, plus one new step and one ordering constraint.

    The icon root may only be released AFTER the row that references it is gone,
    so the order is: RemoveItem -> Detach -> ZeroSlot -> RemoveRow (destroys the
    row and with it the only reference to the texture) -> ReleaseIcon -> Release.
    Releasing the icon earlier would unroot an object the row still points at.
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

    report = {"mode": "cleanup", "pid": pid, "row_name": state["row_name"],
              "icon_object": "0x%x" % state["icon_object"]}
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

    st = call("RunDetach", "detach_ran")
    report["detach_ran"] = st["detach_ran"]
    st = call("RunZeroSlot", "zero_ran")
    report["zero_ran"] = st["zero_ran"]

    p04.call_export(k, hp, rbase, dll, "RunRemoveRow", rio, ipp.WAIT_TIMEOUT_MS)
    dl = time.time() + 20.0
    while time.time() < dl and our_row(api, pid, state["table_ptr"])[0]:
        time.sleep(0.1)
    report["runtime_row_destroyed"] = our_row(api, pid, state["table_ptr"])[0] == 0
    if not report["runtime_row_destroyed"]:
        raise ipp.Blocked("the runtime row survived RemoveRow; refusing to unroot a texture it "
                          "may still reference")
    run_note.append("runtime row destroyed; the only reference to the texture is gone")

    st = call("RunReleaseIcon", "releaseicon_ran")
    report["icon_release"] = {"releaseicon_ran": st["releaseicon_ran"],
                              "icon_rooted_after_release": st["icon_rooted_after_release"],
                              "owned_count": st["owned_count"]}
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
            and report["icon_release"]["releaseicon_ran"] == 1
            and report["icon_release"]["icon_rooted_after_release"] == 0
            and report["release"]["release_ran"] == 1
            and report["release"]["rooted_after_release"] == 0
            and report["release"]["owned_count"] == 0
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
    ap.add_argument("--arm", action="store_true",
                    help="run the icon primitive on the Runtime table only, then unwind")
    ap.add_argument("--demo", action="store_true",
                    help="run the primitive AND publish + AddItem, then HOLD for a visual check")
    ap.add_argument("--cleanup", action="store_true", help="roll back a held demo")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    rid = (a.run_dir and os.path.basename(a.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ",
                                                                      time.gmtime())
    rdir = a.run_dir or os.path.join(REPO, "research", "instrument-runs", rid)
    os.makedirs(rdir, exist_ok=True)
    note, arts = [], []
    vb = va = None
    armed = a.arm or a.demo or a.cleanup
    caps = ["CR-01C4B"] if armed else ["I-01"]
    code = 0
    try:
        api = eri.Win32Api()
        if armed:
            vb = ipp.run_verify_install(rdir, "before")
            if vb.get("report_artifact"):
                arts.append(vb["report_artifact"])
            if vb["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before")
        rep = run_cleanup(api, note) if a.cleanup else run(api, a, note)
        rep["run_note"] = note
        if armed:
            va = ipp.run_verify_install(rdir, "after")
            if va.get("report_artifact"):
                arts.append(va["report_artifact"])
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
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
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(rdir, arguments=arguments, capabilities_enabled=caps,
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=arts,
                           instrument_level=("ipp" if armed else "eri"))
    return code


if __name__ == "__main__":
    sys.exit(main())
