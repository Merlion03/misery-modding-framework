#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C3D -- First real inventory-visible mod item.

    [C3B] spawn -> root -> RowStruct -> materialize -> AddRow into OUR table
    [C3C] attach as a second parent of MasterItemList, publish
    resolve : BP_SGKFunctions_C::"SGK ItemDetails" must FIND our definition
    additem : exactly ONE vanilla BP_MasterInventory_C::AddItem on the real
              player inventory
    observe : the player's Inventory array must actually contain our FName --
              a successful ProcessEvent with no observable entry is NOT PASS
    remove  : BP_MasterInventory_C::RemoveItem on exactly the observed slot
    [C3C] detach, zero the spare slot, release the root

Cleanup order is load-bearing: the inventory entry is removed FIRST, and the
definition is only unpublished once no S_InvItem carries its ID.

Any failure after AddItem runs the full rollback (remove item -> detach -> zero
-> release) before propagating. Gated behind --arm.
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
                                bool_semantics, RVA_FREE, RVA_SET_ROOT_FLAGS,
                                RVA_CLEAR_ROOT_FLAGS, INIT_SLOT, DESTROY_SLOT,
                                ADDROW_SLOT, REMOVEROW_SLOT, USTRUCT_PROPERTIES_SIZE,
                                OFF_ROWSTRUCT, OFF_PARENT_TABLES, ITEMLIST_BASELINE)
from cr01c3c_controller import (rows_by_key, derive_copy_mask, masked_digest,  # noqa: E402
                                semantic_digests, exact_hashes, delegate_targets,
                                parent_raw, old_parent_state, OFF_OLD_PARENT_TABLES,
                                OFF_DELEGATE)

DLL_NAME = "CR01C3DProbe.dll"
ROW_NAME = "misery__c3d_first_mod_item"
TRIGGER_NAME = "misery__c3d_neutral_trigger"

OFF_INVENTORY_ARRAY = 336
OFF_USING_PLAYERS = 168
OFF_CURRENT_WEIGHT = 184
OFF_ITEM_COUNT = 192
SLOT_SIZE = 80
S_INVITEM_OFF_IN_SLOT = 24

# Definition fields -- only the ones already proven safe and required by the path.
VALUES = {"Weight": 0.5, "Width": 1, "Height": 1, "MaxStack": 1, "AllowStacking": 0}
# S_InvItem initial mutable state, derived from 1036 live vanilla inventory
# entries (see the evidence record). QuickBindIndex is -1 in every single one of
# them; a zeroed struct would read as "bound to quick slot 0".
INVITEM = {"amount": 1, "quickbind": -1, "useamount": 0, "decaytime": 0,
           "rotated": 0, "inuse": 0, "durability": 100.0}

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQ QQQ QQQ QQ QQQQ QQ Q QQQQ QQ IIII IIIIII d iiiB3s "
          "iiiiii f I 96H 96H 80s "
          "IIII IIII IIII IIII IIII IIII IIII IIII QQQQQ QQQQQ QQQQ 48s 16s IIII dII QQ"
          ).replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 1216, "C3DIo wire format drifted (%d)" % IO_SIZE
# byte offset of the staged S_InvSlot the controller writes between steps
SLOT_IN_OFFSET = struct.calcsize(IO_FMT.split("80s")[0])
assert SLOT_IN_OFFSET == 784, "slot_in offset drifted (%d)" % SLOT_IN_OFFSET
IO_MAGIC = 0x4950502D43334400
IO_PROTO = 1


class RollbackNeeded(Exception):
    """A post-mutation invariant failed; the full rollback must run now."""


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C3DProbeDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    bat = os.path.join(bd, "_build_c3dctl.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C3DProbeDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


def decode_invitem(raw, off=0):
    return {"ID": struct.unpack_from("<I", raw, off + 0)[0],
            "ID_number": struct.unpack_from("<I", raw, off + 4)[0],
            "Amount": struct.unpack_from("<i", raw, off + 8)[0],
            "MasterInventory": "0x%x" % struct.unpack_from("<Q", raw, off + 16)[0],
            "QuickBindIndex": struct.unpack_from("<i", raw, off + 24)[0],
            "Rotated": raw[off + 28],
            "UseAmount": struct.unpack_from("<i", raw, off + 32)[0],
            "InUse": raw[off + 36],
            "Durability": struct.unpack_from("<f", raw, off + 40)[0],
            "DecayTime": struct.unpack_from("<i", raw, off + 44)[0]}


def read_inventory(api, h, inv):
    data = eri._read_u64(api, h, inv + OFF_INVENTORY_ARRAY)
    num = struct.unpack("<i", api.read_process_memory(h, inv + OFF_INVENTORY_ARRAY + 8, 4))[0]
    mx = struct.unpack("<i", api.read_process_memory(h, inv + OFF_INVENTORY_ARRAY + 12, 4))[0]
    slots, raw = [], b""
    if data and 0 < num < 4096:
        raw = api.read_process_memory(h, data, num * SLOT_SIZE)
        for i in range(num):
            s = raw[i * SLOT_SIZE:(i + 1) * SLOT_SIZE]
            slots.append({"index": i, "occupied": s[0], "blocked": s[76],
                          "root_index": struct.unpack_from("<i", s, 16)[0],
                          "self_index": struct.unpack_from("<i", s, 20)[0],
                          "clump": struct.unpack_from("<i", s, 72)[0],
                          "inventory_ptr": "0x%x" % struct.unpack_from("<Q", s, 8)[0],
                          "item": decode_invitem(s, S_INVITEM_OFF_IN_SLOT),
                          "raw": s.hex()})
    up_num = struct.unpack("<i", api.read_process_memory(h, inv + OFF_USING_PLAYERS + 8, 4))[0]
    return {"data": "0x%x" % data, "num": num, "max": mx, "slots": slots,
            "slots_sha256": hashlib.sha256(raw).hexdigest(),
            "current_weight": struct.unpack("<d", api.read_process_memory(
                h, inv + OFF_CURRENT_WEIGHT, 8))[0],
            "item_count": struct.unpack("<i", api.read_process_memory(
                h, inv + OFF_ITEM_COUNT, 4))[0],
            "using_players_num": up_num}


def occupied_with(inv_state, fname_id):
    return [s for s in inv_state["slots"] if s["occupied"] and s["item"]["ID"] == fname_id]


def slot_diff(a, b):
    """Which slots changed, and in which fields -- so any residue is reported
    concretely instead of being hidden behind a mask."""
    out = []
    for x, y in zip(a["slots"], b["slots"]):
        if x["raw"] == y["raw"]:
            continue
        d = {"index": x["index"], "fields": {}}
        for kk in ("occupied", "blocked", "root_index", "self_index", "clump", "inventory_ptr"):
            if x[kk] != y[kk]:
                d["fields"][kk] = [x[kk], y[kk]]
        for kk in x["item"]:
            if x["item"][kk] != y["item"][kk]:
                d["fields"]["item." + kk] = [x["item"][kk], y["item"][kk]]
        out.append(d)
    return out


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
    sgk_cdo = one("Default__BP_SGKFunctions_C", "BP_SGKFunctions_C", "BP_SGKFunctions CDO")
    gs_cls = one("GameplayStatics", "Class", "GameplayStatics UClass")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary UClass")
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
    sgk_details = fn_on(sgk_cls, "SGK ItemDetails", "BP_SGKFunctions")
    add_item = fn_on(mi_cls, "AddItem", "BP_MasterInventory_C")
    remove_item = fn_on(mi_cls, "RemoveItem", "BP_MasterInventory_C")

    # ---- ABI gate: re-verify live, do not re-derive -----------------------
    def gate(fn, label, parms, need_flags=0, forbid_net=True):
        fl = eri._read_u32(api, h, fn + 0xB0)
        ps = eri._read_u16(api, h, fn + 0xB6)
        if ps != parms:
            raise ipp.Blocked("%s ParmsSize %d != %d" % (label, ps, parms))
        if need_flags and (fl & need_flags) != need_flags:
            raise ipp.Blocked("%s flags 0x%x lack 0x%x" % (label, fl, need_flags))
        if forbid_net and (fl & 0x0138C0C4):
            raise ipp.Blocked("%s carries a net/authority flag: 0x%x" % (label, fl))
        if eri._read_u64(api, h, fn + 0xC8):
            raise ipp.Blocked("%s EventGraphFunction non-null; Parms would be discarded" % label)
        run_note.append("%s: flags=0x%x ParmsSize=%d EventGraphFunction=null" % (label, fl, ps))
        return fl

    gate(spawn, "SpawnObject", 24, need_flags=0x2400)
    gate(add_item, "AddItem", 120)
    gate(remove_item, "RemoveItem", 83)
    gate(sgk_details, "SGK ItemDetails", 2336)

    # AddItem parameter struct identity, re-verified live
    want = {"Item": ("FStructProperty", 0, "S_InvItem"),
            "StackSearch": ("FBoolProperty", 48, None),
            "ShowNotifications": ("FBoolProperty", 49, None),
            "RemainingItem": ("FBoolProperty", 50, None),
            "RemainingInvItem": ("FStructProperty", 56, "S_InvItem"),
            "NewItemSlot": ("FStructProperty", 104, "S_InvSlotID")}
    cp = eri._read_u64(api, h, add_item + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    seen = {}
    for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=add_item,
                                      objects_by_address=objs).get("accepted", []):
        raw = pr.get("property_flags_raw")
        pf = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
        if not (pf & 0x80):
            continue
        sn = None
        if pr.get("property_class") == "FStructProperty" and pr.get("address_hex"):
            sn = (objs.get(eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)) or {}).get("name_text")
        seen[pr.get("raw_name")] = (pr.get("property_class"), pr.get("offset"), sn)
    for nm, exp in want.items():
        if seen.get(nm) != exp:
            raise ipp.Blocked("AddItem param %s is %r, expected %r" % (nm, seen.get(nm), exp))
    run_note.append("AddItem parameter ABI re-verified live: %s" % sorted(seen))

    # RemoveItem parameter struct identity
    cp = eri._read_u64(api, h, remove_item + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    rseen = {}
    for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=remove_item,
                                      objects_by_address=objs).get("accepted", []):
        raw = pr.get("property_flags_raw")
        pf = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
        if not (pf & 0x80):
            continue
        sn = None
        if pr.get("property_class") == "FStructProperty" and pr.get("address_hex"):
            sn = (objs.get(eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)) or {}).get("name_text")
        rseen[pr.get("raw_name")] = (pr.get("property_class"), pr.get("offset"), sn)
    if rseen.get("InvSlot") != ("FStructProperty", 0, "S_InvSlot"):
        raise ipp.Blocked("RemoveItem InvSlot is %r" % (rseen.get("InvSlot"),))
    for nm, off in (("RemoveWeight", 80), ("RemoveInvAmount", 81), ("SpecialSlot", 82)):
        if rseen.get(nm) != ("FBoolProperty", off, None):
            raise ipp.Blocked("RemoveItem param %s is %r" % (nm, rseen.get(nm)))
    run_note.append("RemoveItem parameter ABI re-verified live: %s" % sorted(rseen))

    # ---- authority --------------------------------------------------------
    owner = eri._read_u64(api, h, player_inv + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
    role = eri._read_u8(api, h, owner + 336)
    remote_role = eri._read_u8(api, h, owner + 96)
    if role != 3:
        raise ipp.Blocked("owning actor Role=%d, not ROLE_Authority(3)" % role)
    nets = [a for a, r in objs.items() if r.get("name_ok")
            and "NetDriver" in ((objs.get(r.get("class_ptr") or 0) or {}).get("name_text") or "")
            and not (r.get("name_text") or "").startswith("Default__")]
    if nets:
        raise ipp.Blocked("live NetDriver instances present (%d); not handled by this gate" % len(nets))
    run_note.append("authority: owner 0x%x Role=%d RemoteRole=%d, 0 live NetDriver instances"
                    % (owner, role, remote_role))

    # ---- composite identity ----------------------------------------------
    if eri._read_u64(api, h, master + eri.DEFAULT_CLASS_PRIVATE_OFFSET) != cdt_class:
        raise ipp.Blocked("MasterItemList ClassPrivate is not UCompositeDataTable")
    composite_vt = eri._read_u64(api, h, master)
    plain_vt = eri._read_u64(api, h, itemlist)
    if composite_vt == plain_vt:
        raise ipp.Blocked("composite and plain vtables identical")
    rs_item = eri._read_u64(api, h, itemlist + OFF_ROWSTRUCT)
    if rs_item != eri._read_u64(api, h, master + OFF_ROWSTRUCT):
        raise ipp.Blocked("ItemList and MasterItemList RowStruct differ")
    if (objs.get(rs_item) or {}).get("name_text") != "S_ItemDetails":
        raise ipp.Blocked("RowStruct is not S_ItemDetails")
    struct_size = struct.unpack("<i", api.read_process_memory(
        h, rs_item + USTRUCT_PROPERTIES_SIZE, 4))[0]

    add_row = eri._read_u64(api, h, plain_vt + ADDROW_SLOT * 8)
    rem_row = eri._read_u64(api, h, plain_vt + REMOVEROW_SLOT * 8)
    svt = eri._read_u64(api, h, rs_item)
    init_va = eri._read_u64(api, h, svt + INIT_SLOT * 8)
    dest_va = eri._read_u64(api, h, svt + DESTROY_SLOT * 8)
    pe = eri._read_u64(api, h, eri._read_u64(api, h, sl_cdo) + c1.PE_SLOT * 8)
    set_root, clr_root, free_va = base + RVA_SET_ROOT_FLAGS, base + RVA_CLEAR_ROOT_FLAGS, base + RVA_FREE
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
    if praw["max"] - praw["num"] < 1:
        raise ipp.Blocked("no spare ParentTables capacity; NO growth authorised")

    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    return {"np": np, "objs": objs, "itemlist": itemlist, "master": master, "transient": transient,
            "dt_class": dt_class, "cdt_class": cdt_class, "gs_cdo": gs_cdo, "sl_cdo": sl_cdo,
            "sgk_cdo": sgk_cdo, "spawn": spawn, "conv": conv, "sgk_details": sgk_details,
            "add_item": add_item, "remove_item": remove_item, "player_inv": player_inv,
            "owner": owner, "row_struct": rs_item, "struct_size": struct_size,
            "plain_vtable": plain_vt, "composite_vtable": composite_vt,
            "add_row": add_row, "remove_row": rem_row, "init": init_va, "destroy": dest_va,
            "pe": pe, "set_root": set_root, "clear_root": clr_root, "free": free_va,
            "objects_ptr": i02["objects_ptr_live_va"], "parent_raw": praw}


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
        r["player_inv"], r["add_item"], r["remove_item"], r["sgk_details"],
        r["sgk_cdo"], 0,
        OFF_PARENT_TABLES, OFF_ROWSTRUCT, OFF_DELEGATE, OFF_INVENTORY_ARRAY,
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"], offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"], b"\0\0\0",
        INVITEM["amount"], INVITEM["quickbind"], INVITEM["useamount"], INVITEM["decaytime"],
        INVITEM["rotated"], INVITEM["inuse"],
        INVITEM["durability"], 0,
        *nm, *tg, b"\0" * 80,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
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
            "table_ptr", "table_item_ptr", "table_class", "table_outer", "table_vtable",
            "table_rowstruct_after", "row_fname", "trigger_fname", "temp_ptr", "store_handle",
            "parent_data", "parent_elem0", "parent_elem1_before", "parent_elem1_after",
            "out_remaining_invitem", "out_newitemslot",
            "out_remaining_item", "resolve_width", "resolve_height", "resolve_maxstack",
            "resolve_weight", "resolve_allowstacking"]


# Index of the first OUTPUT field, computed from the format itself. Counting
# these by hand is exactly how the first armed attempt broke: an off-by-one made
# read_io() raise, the run never reached Shutdown, and unloading the DLL with the
# ticker still registered crashed the game.
_INPUT_PREFIX = IO_FMT.split("80s")[0] + "80s"
OUT_INDEX = len(struct.unpack(_INPUT_PREFIX, bytes(struct.calcsize(_INPUT_PREFIX))))


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    i = OUT_INDEX
    out = {k: f[i + n] for n, k in enumerate(OUT_KEYS)}
    out["out_remaining_invitem"] = decode_invitem(out["out_remaining_invitem"])
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
                "inventory": read_inventory(api, h, r["player_inv"])}
    finally:
        api.close_handle(h)


def runtime_table(api, pid, table_ptr, r, offs):
    h = eri.open_process_read_only(api, pid)
    try:
        out = {"row_struct": "0x%x" % eri._read_u64(api, h, table_ptr + OFF_ROWSTRUCT),
               "delegate": delegate_targets(api, h, table_ptr, r["objects_ptr"])}
        rows, _ = rdr.read_rowmap(api, h, table_ptr)
        out["row_count"] = len(rows)
        if rows:
            a, b, p = rows[0]
            out["row_key"] = [a, b]
            raw = api.read_process_memory(h, p, r["struct_size"])
            out["values"] = {"Weight": struct.unpack_from("<d", raw, offs["Weight"])[0],
                             "Width": struct.unpack_from("<i", raw, offs["Width"])[0],
                             "Height": struct.unpack_from("<i", raw, offs["Height"])[0],
                             "MaxStack": struct.unpack_from("<i", raw, offs["MaxStack"])[0],
                             "AllowStacking": raw[offs["AllowStacking"]]}
            out["UseDurability"] = raw[1928]
            out["UseItemDecay"] = raw[1928 + 48]
        return out
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
        boolsem = bool_semantics(api, h, r["np"], r["row_struct"], "AllowStacking")
        mask = derive_copy_mask(api, h, r["itemlist"], r["master"], r["struct_size"])
        pm, cm = rows_by_key(api, h, r["itemlist"]), rows_by_key(api, h, r["master"])
        agree = sum(1 for kk in pm if kk in cm and
                    masked_digest(api.read_process_memory(h, pm[kk], r["struct_size"]), mask) ==
                    masked_digest(api.read_process_memory(h, cm[kk], r["struct_size"]), mask))
        if agree != len(pm):
            raise ipp.Blocked("copy mask does not explain the baseline: %d/%d" % (agree, len(pm)))
        run_note.append("copy mask: %d windows, masked(parent)==masked(composite) %d/%d"
                        % (len(mask), agree, len(pm)))
    finally:
        api.close_handle(h)

    before = observe(api, pid, r, mask)
    if before["itemlist_rows"] != ITEMLIST_BASELINE or before["master_rows"] != ITEMLIST_BASELINE:
        raise ipp.Blocked("baseline rows ItemList=%d Master=%d" %
                          (before["itemlist_rows"], before["master_rows"]))
    inv0 = before["inventory"]
    run_note.append("inventory baseline: %d slots, %d occupied, weight=%r count=%d using_players=%d"
                    % (inv0["num"], sum(1 for s in inv0["slots"] if s["occupied"]),
                       inv0["current_weight"], inv0["item_count"], inv0["using_players_num"]))

    report = {"pid": pid, "struct_size": r["struct_size"], "fields": field_report,
              "allowstacking_bool_semantics": boolsem,
              "invitem_initial_state": dict(INVITEM),
              "copy_mask_window_count": len(mask),
              "objects": {kk: "0x%x" % r[kk] for kk in
                          ("itemlist", "master", "player_inv", "owner", "row_struct",
                           "add_item", "remove_item", "sgk_details")},
              "baseline": {"itemlist_rows": before["itemlist_rows"],
                           "master_rows": before["master_rows"],
                           "parent_raw": before["parent_raw"],
                           "inventory": inv0},
              "probe_row": ROW_NAME, "trigger_row": TRIGGER_NAME}
    if not args.arm:
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

        def call(export, field, timeout=25.0):
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            st = read_io(); dl = time.time() + timeout
            while time.time() < dl and st[field] == 0:
                time.sleep(0.05); st = read_io()
            return st

        if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("Init failed")

        st = call("RunCreate", "create_ran")
        report["create"] = st
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
        table_ptr, row_fname = st["table_ptr"], st["row_fname"]

        st = call("RunPopulate", "populate_ran")
        report["populate"] = st
        if st["populate_ran"] != 1:
            raise ipp.Blocked("populate failed err=%d" % st["err"])
        rt = runtime_table(api, pid, table_ptr, r, offs)
        report["runtime_table"] = rt
        if rt["row_count"] != 1:
            raise ipp.Blocked("runtime table has %d rows" % rt["row_count"])
        # DecayTime only matters if the definition enables decay; ours must not.
        if st["use_item_decay"]:
            raise ipp.Blocked("materialized definition has UseItemDecay=1; DecayTime=0 would be "
                              "an unproven choice -- failing closed before AddItem")
        run_note.append("materialized definition: UseDurability=%d UseItemDecay=%d -> the "
                        "per-instance Durability/DecayTime fields are inert"
                        % (st["use_durability"], st["use_item_decay"]))
        probe_key = tuple(rt["row_key"])
        if probe_key in before["master_semantic"]:
            raise ipp.Blocked("probe row collides with a vanilla MasterItemList row")
        if occupied_with(inv0, row_fname & 0xFFFFFFFF):
            raise ipp.Blocked("probe FName already present in the player inventory")

        published = item_added = False
        try:
            st = call("RunAttach", "attach_ran")
            report["attach"] = st
            if st["attach_ran"] != 1:
                raise ipp.Blocked("attach refused err=%d step=%d" % (st["err"], st["err_step"]))
            published = True
            after_pub = observe(api, pid, r, mask)
            report["after_publish"] = {
                "master_rows": after_pub["master_rows"],
                "probe_in_master": probe_key in after_pub["master_semantic"],
                "all_vanilla_present": all(kk in after_pub["master_semantic"]
                                           for kk in before["master_semantic"]),
                "all_vanilla_semantically_unchanged":
                    all(after_pub["master_semantic"].get(kk) == v
                        for kk, v in before["master_semantic"].items()),
                "itemlist_exact_unchanged": after_pub["itemlist_exact"] == before["itemlist_exact"],
                "parent_raw": after_pub["parent_raw"], "old_parent": after_pub["old_parent"],
            }
            if not report["after_publish"]["probe_in_master"]:
                raise RollbackNeeded("probe did not appear in MasterItemList after publication")

            st = call("RunResolve", "resolve_ran")
            report["resolve"] = {kk: st[kk] for kk in
                                 ("resolve_ran", "resolve_found", "resolve_weight", "resolve_width",
                                  "resolve_height", "resolve_maxstack", "resolve_allowstacking", "err")}
            resolved_ok = (st["resolve_ran"] == 1 and st["resolve_found"] == 1 and
                           abs(st["resolve_weight"] - VALUES["Weight"]) < 1e-9 and
                           st["resolve_width"] == VALUES["Width"] and
                           st["resolve_height"] == VALUES["Height"] and
                           st["resolve_maxstack"] == VALUES["MaxStack"] and
                           st["resolve_allowstacking"] == VALUES["AllowStacking"])
            report["resolve"]["matches_definition"] = resolved_ok
            run_note.append("resolver: found=%d weight=%r width=%d height=%d maxstack=%d"
                            % (st["resolve_found"], st["resolve_weight"], st["resolve_width"],
                               st["resolve_height"], st["resolve_maxstack"]))
            if not resolved_ok:
                raise RollbackNeeded("SGK ItemDetails did not resolve our definition correctly")

            # ------------------ the one gameplay mutation ------------------
            st = call("RunAddItem", "additem_ran")
            report["additem"] = {kk: st[kk] for kk in
                                 ("additem_ran", "err", "out_remaining_item",
                                  "out_remaining_invitem", "out_newitemslot")}
            if st["additem_ran"] != 1:
                raise RollbackNeeded("AddItem job did not run (err=%d)" % st["err"])
            item_added = True
            run_note.append("AddItem returned: RemainingItem=%d NewItemSlot=%r"
                            % (st["out_remaining_item"], st["out_newitemslot"]))

            after_add = observe(api, pid, r, mask)
            inv1 = after_add["inventory"]
            ours = occupied_with(inv1, row_fname & 0xFFFFFFFF)
            others_before = [s for s in inv0["slots"] if s["occupied"]]
            others_after = [s for s in inv1["slots"]
                            if s["occupied"] and s["item"]["ID"] != (row_fname & 0xFFFFFFFF)]
            report["inventory_after_add"] = {
                "num_slots": inv1["num"],
                "entries_with_probe_id": len(ours),
                "probe_slot": ours[0] if ours else None,
                "current_weight": inv1["current_weight"], "item_count": inv1["item_count"],
                "using_players_num": inv1["using_players_num"],
                "preexisting_entries_preserved": len(others_after) == len(others_before),
                "changed_slots": slot_diff(inv0, inv1),
                "definition_still_resolves": probe_key in after_add["master_semantic"],
            }
            if len(ours) != 1:
                raise RollbackNeeded(
                    "expected exactly one inventory entry carrying the probe FName, found %d "
                    "-- a successful ProcessEvent with no observable entry is NOT PASS" % len(ours))
            slot = ours[0]
            run_note.append("INVENTORY OBSERVATION: probe present in slot %d, Amount=%d, "
                            "weight %r -> %r, count %d -> %d"
                            % (slot["index"], slot["item"]["Amount"], inv0["current_weight"],
                               inv1["current_weight"], inv0["item_count"], inv1["item_count"]))

            # ------------------ remove exactly our item --------------------
            k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, bytes.fromhex(slot["raw"]), 80,
                                 ctypes.byref(wr))
            st = call("RunRemoveItem", "removeitem_ran")
            report["removeitem"] = {kk: st[kk] for kk in ("removeitem_ran", "err")}
            item_added = False
            if st["removeitem_ran"] != 1:
                item_added = True
                raise RollbackNeeded("RemoveItem job failed err=%d" % st["err"])
            after_rm = observe(api, pid, r, mask)
            inv2 = after_rm["inventory"]
            report["inventory_after_remove"] = {
                "entries_with_probe_id": len(occupied_with(inv2, row_fname & 0xFFFFFFFF)),
                "current_weight": inv2["current_weight"], "item_count": inv2["item_count"],
                "using_players_num": inv2["using_players_num"],
                "weight_restored": abs(inv2["current_weight"] - inv0["current_weight"]) < 1e-9,
                "count_restored": inv2["item_count"] == inv0["item_count"],
                "slots_sha256_restored": inv2["slots_sha256"] == inv0["slots_sha256"],
                "changed_slots_vs_baseline": slot_diff(inv0, inv2),
            }
            if report["inventory_after_remove"]["entries_with_probe_id"] != 0:
                item_added = True
                raise RollbackNeeded("probe still present in the inventory after RemoveItem")
            run_note.append("after RemoveItem: probe absent, weight_restored=%s count_restored=%s "
                            "slots_identical=%s"
                            % (report["inventory_after_remove"]["weight_restored"],
                               report["inventory_after_remove"]["count_restored"],
                               report["inventory_after_remove"]["slots_sha256_restored"]))
        except RollbackNeeded as exc:
            report["rollback_reason"] = str(exc)
            run_note.append("ROLLBACK TRIGGERED: %s" % exc)
            if item_added:
                inv_now = observe(api, pid, r, mask)["inventory"]
                mine = occupied_with(inv_now, row_fname & 0xFFFFFFFF)
                if mine:
                    k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET,
                                         bytes.fromhex(mine[0]["raw"]), 80, ctypes.byref(wr))
                    report["emergency_removeitem"] = call("RunRemoveItem", "removeitem_ran")
        finally:
            if published:
                st = call("RunDetach", "detach_ran")
                report["detach"] = st
                st = call("RunZeroSlot", "zero_ran")
                report["zero_slot"] = st

        st = call("RunRelease", "release_ran")
        report["release"] = st
        final = observe(api, pid, r, mask)
        rt_final = runtime_table(api, pid, table_ptr, r, offs)
        report["final"] = {
            "itemlist_rows": final["itemlist_rows"], "master_rows": final["master_rows"],
            "master_is_vanilla_count": final["master_rows"] == ITEMLIST_BASELINE,
            "probe_absent_from_master": probe_key not in final["master_semantic"],
            "all_vanilla_semantically_unchanged":
                all(final["master_semantic"].get(kk) == v
                    for kk, v in before["master_semantic"].items()),
            "itemlist_exact_unchanged": final["itemlist_exact"] == before["itemlist_exact"],
            "parent_raw": final["parent_raw"],
            "parent_raw_equals_baseline": final["parent_raw"] == before["parent_raw"],
            "old_parent": final["old_parent"],
            "itemlist_delegate_unchanged":
                final["itemlist_delegate"] == before["itemlist_delegate"],
            "runtime_table_delegate": rt_final["delegate"],
            "inventory_probe_absent":
                len(occupied_with(final["inventory"], row_fname & 0xFFFFFFFF)) == 0,
            "inventory_slots_restored":
                final["inventory"]["slots_sha256"] == inv0["slots_sha256"],
            "inventory_weight_restored":
                abs(final["inventory"]["current_weight"] - inv0["current_weight"]) < 1e-9,
            "inventory_count_restored": final["inventory"]["item_count"] == inv0["item_count"],
            "inventory_changed_slots": slot_diff(inv0, final["inventory"]),
        }
        released = p04.call_export(k, hp, rbase, dll, "Shutdown", rio, 20000)
        report["shutdown"] = read_io()
        report["shutdown"]["released_at_shutdown"] = released
    finally:
        if rbase is not None:
            # ALWAYS stop the dispatcher before unloading. The carrier registers
            # an FTSTicker callback that lives in THIS module; unloading while it
            # is still registered makes the engine tick into freed code and takes
            # the game down. Shutdown is idempotent (it early-returns once g_disp
            # is null), so calling it here is safe on the normal path too, and it
            # is the only thing standing between a controller-side exception and
            # a crashed game.
            try:
                p04.call_export(k, hp, rbase, dll, "Shutdown", rio, 20000)
            except Exception:  # noqa: BLE001
                pass
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

    ap_ = report.get("after_publish", {}); ia = report.get("inventory_after_add", {})
    ir = report.get("inventory_after_remove", {}); fi = report.get("final", {})
    rv = report.get("resolve", {})
    report["verdict"] = "PASS" if (
        not report.get("rollback_reason") and
        report["attach"]["attach_ran"] == 1 and
        ap_.get("probe_in_master") and ap_.get("all_vanilla_present") and
        ap_.get("all_vanilla_semantically_unchanged") and ap_.get("itemlist_exact_unchanged") and
        rv.get("resolve_found") == 1 and rv.get("matches_definition") and
        report["additem"]["additem_ran"] == 1 and
        ia.get("entries_with_probe_id") == 1 and ia.get("preexisting_entries_preserved") and
        ia.get("definition_still_resolves") and
        report["removeitem"]["removeitem_ran"] == 1 and
        ir.get("entries_with_probe_id") == 0 and ir.get("weight_restored") and
        ir.get("count_restored") and ir.get("slots_sha256_restored") and
        report["detach"]["detach_ran"] == 1 and report["zero_slot"]["zero_ran"] == 1 and
        report["release"]["release_ran"] == 1 and
        report["release"]["rooted_after_release"] == 0 and
        report["release"]["owned_count"] == 0 and
        fi.get("master_is_vanilla_count") and fi.get("probe_absent_from_master") and
        fi.get("all_vanilla_semantically_unchanged") and fi.get("itemlist_exact_unchanged") and
        fi.get("parent_raw_equals_baseline") and fi.get("itemlist_delegate_unchanged") and
        fi.get("runtime_table_delegate", {}).get("num") == 0 and
        fi.get("inventory_probe_absent") and fi.get("inventory_slots_restored") and
        fi.get("inventory_weight_restored") and fi.get("inventory_count_restored") and
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
    caps = ["CR-01C3D"] if a.arm else ["I-01"]
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
                           instrument_level=("ipp" if a.arm else "eri"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
