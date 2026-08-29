#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C4B follow-up: a UI-only patch of the already-held row.

The CR-01C4B demo probe is still loaded and still owns the runtime UDataTable
root, the icon UTexture2D root and the MasterItemList publication. This
controller does NOT disturb any of that. It:

  1. re-runs the seven read-only post-drop safety conditions,
  2. loads a second, ownership-free module (CR01C4BPatchDll.cpp),
  3. sets S_UIDetails.MoveIcon to the SAME already-rooted texture that
     InventoryIcon holds, and turns on the vanilla-supported 1x1 drag size
     override (100x100),
  4. republishes with the proven data-neutral trigger so the composite's own
     copy of the row is refreshed,
  5. verifies through the game's own SGK ItemDetails resolver,
  6. adds exactly one instance through the proven AddItem path,
  7. unloads ONLY the patch module, through the same teardown invariant, and
     holds everything else.

No second texture, no second load, no second root: the patch module has no
asset store at all, so it has nothing to release.
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
import cr01c3_recon as recon  # noqa: E402
import probe_teardown  # noqa: E402
import cr01c3d_controller as c3d  # noqa: E402
import cr01c1_controller as c1  # noqa: E402
from cr01c3b_controller import DiskImage, verify_carrier_addresses, bool_semantics  # noqa: E402
from cr01c4b_controller import (DLL_NAME as DEMO_DLL_NAME, STATE_PATH, ROW_NAME,  # noqa: E402
                                TRIGGER_NAME, TEXTS, VALUES, u16_to_str, str_to_u16)

PATCH_DLL = "CR01C4BPatchProbe.dll"
WANT_SIZE = (100, 100)
TXT_CAP = 128
ROOTSET = 1 << 30
FUOBJECTITEM = 0x18

IO_FMT = ("<QII QQQQ 16s16s16s QQQ QQQ QQ QQQ QQQQ QQQ QQ IIII IIII IIIIII IIII d iiiiii fI "
          "96H 96H 80s 128H128H128H "
          "IIII IIII IIII IIII IIII IIII IIII QQ QQ QQ QQ dd 48s 16s QQ").replace(" ", "")
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 1872, "PatchIo wire format drifted (%d)" % IO_SIZE
SLOT_IN_OFFSET = struct.calcsize(IO_FMT.split("80s")[0])
assert SLOT_IN_OFFSET == 752, "slot_in offset drifted (%d)" % SLOT_IN_OFFSET
_INPUT_PREFIX = IO_FMT.rsplit("128H", 1)[0] + "128H"
_OUTPUT_BLOCK_OFFSET = struct.calcsize(_INPUT_PREFIX)
STATE_OFFSET = _OUTPUT_BLOCK_OFFSET + 8
WAIT_STOPPED_OK_OFFSET = _OUTPUT_BLOCK_OFFSET + 12
OUT_INDEX = len(struct.unpack(_INPUT_PREFIX, bytes(_OUTPUT_BLOCK_OFFSET)))
_TXT_INDEX = len(struct.unpack(IO_FMT.split("80s")[0] + "80s",
                               bytes(struct.calcsize(IO_FMT.split("80s")[0] + "80s"))))


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, PATCH_DLL)
    srcs = [os.path.join(rdir, "CR01C4BPatchDll.cpp"), os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    bat = os.path.join(bd, "_build_c4bpatch.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        f.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s\\CR01C4BPatchDll.cpp" '
                '"%s\\UE54TickerCarrier.cpp" /Fe:"%s" /link /INCREMENTAL:NO\r\n'
                % (defs, inc, rdir, rdir, out))
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (PATCH_DLL, r.stdout, r.stderr))
    return out


def unpack_io(raw):
    f = struct.unpack(IO_FMT, raw)
    keys = ["activated", "initialized", "state", "wait_stopped_ok",
            "find_ran", "patch_ran", "resolve_ran", "additem_ran",
            "removeitem_ran", "gt_tid", "fstring_ok", "err",
            "err_step", "resolve_found", "resolve_override", "resolve_sizex",
            "resolve_sizey", "resolve_width", "resolve_height", "trigger_fired",
            "before_override", "before_sizex", "before_sizey", "after_override",
            "after_sizex", "after_sizey", "out_remaining_item", "pad2",
            "row_fname", "trigger_fname",
            "before_inventory_icon", "before_move_icon",
            "after_inventory_icon", "after_move_icon",
            "resolve_inventory_icon", "resolve_move_icon",
            "before_weight", "resolve_weight",
            "out_remaining_invitem", "out_newitemslot"]
    out = {k: f[OUT_INDEX + n] for n, k in enumerate(keys)}
    t = _TXT_INDEX
    for i, lab in enumerate(["name_res", "shortname_res", "desc_res"]):
        out[lab] = u16_to_str(f[t + i * TXT_CAP: t + (i + 1) * TXT_CAP])
    out["out_remaining_invitem"] = c3d.decode_invitem(out["out_remaining_invitem"])
    ns = out["out_newitemslot"]
    out["out_newitemslot"] = {"InvComponent": "0x%x" % struct.unpack_from("<Q", ns, 0)[0],
                              "Index": struct.unpack_from("<i", ns, 8)[0]}
    return out


def ui_offsets(api, h, np, row_struct, objs):
    """FAIL CLOSED for every field the patch writes. Each hop checks identity,
    property class and size; a name alone is never enough to authorize a store."""
    def chain(owner):
        cp = eri._read_u64(api, h, owner + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        return eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=owner,
                                       objects_by_address=objs).get("accepted", [])

    ui_off = ui_struct = None
    for pr in chain(row_struct):
        if (pr.get("raw_name") or "").split("_")[0] != "UIDetails":
            continue
        if pr.get("property_class") != "FStructProperty":
            raise ipp.Blocked("UIDetails is %s" % pr.get("property_class"))
        ui_off = pr.get("offset")
        ui_struct = eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)
    if ui_off is None or (objs.get(ui_struct) or {}).get("name_text") != "S_UIDetails":
        raise ipp.Blocked("S_ItemDetails.UIDetails did not resolve to S_UIDetails")

    icons, ov_off, ov_struct = {}, None, None
    for pr in chain(ui_struct):
        nm = (pr.get("raw_name") or "").split("_")[0]
        if nm in ("InventoryIcon", "MoveIcon"):
            if pr.get("property_class") != "FObjectProperty" or pr.get("size") != 8:
                raise ipp.Blocked("%s is %s size %r, expected FObjectProperty size 8"
                                  % (nm, pr.get("property_class"), pr.get("size")))
            pc = eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)
            if (objs.get(pc) or {}).get("name_text") != "Texture2D":
                raise ipp.Blocked("%s PropertyClass is %r, expected Texture2D"
                                  % (nm, (objs.get(pc) or {}).get("name_text")))
            icons[nm] = pr.get("offset")
        elif nm == "MoveIconSizeOverride":
            if pr.get("property_class") != "FStructProperty":
                raise ipp.Blocked("MoveIconSizeOverride is %s" % pr.get("property_class"))
            ov_off = pr.get("offset")
            ov_struct = eri._read_u64(api, h, int(pr["address_hex"], 16) + 0x70)
    if set(icons) != {"InventoryIcon", "MoveIcon"}:
        raise ipp.Blocked("icon fields missing: %r" % sorted(icons))
    if ov_off is None or (objs.get(ov_struct) or {}).get("name_text") != "S_SizeOverride":
        raise ipp.Blocked("MoveIconSizeOverride did not resolve to S_SizeOverride")

    sub = {}
    for pr in chain(ov_struct):
        nm = (pr.get("raw_name") or "").split("_")[0]
        if nm in ("SizeX", "SizeY"):
            if pr.get("property_class") != "FIntProperty" or pr.get("size") != 4:
                raise ipp.Blocked("%s is %s size %r" % (nm, pr.get("property_class"),
                                                        pr.get("size")))
            sub[nm] = pr.get("offset")
        elif nm == "OverrideImageSize":
            sub[nm] = pr.get("offset")
    if set(sub) != {"SizeX", "SizeY", "OverrideImageSize"}:
        raise ipp.Blocked("S_SizeOverride members missing: %r" % sorted(sub))
    # a bitfield would make a whole-byte store wrong; refuse rather than mask
    boolsem = bool_semantics(api, h, np, ov_struct, "OverrideImageSize")

    return {"uidetails": ui_off,
            "inventory_icon": ui_off + icons["InventoryIcon"],
            "move_icon": ui_off + icons["MoveIcon"],
            "override_flag": ui_off + ov_off + sub["OverrideImageSize"],
            "override_sizex": ui_off + ov_off + sub["SizeX"],
            "override_sizey": ui_off + ov_off + sub["SizeY"],
            "moveiconsizeoverride": ui_off + ov_off,
            "bool_semantics": boolsem,
            "relative": {"UIDetails": ui_off, "InventoryIcon": icons["InventoryIcon"],
                         "MoveIcon": icons["MoveIcon"], "MoveIconSizeOverride": ov_off,
                         "OverrideImageSize": sub["OverrideImageSize"],
                         "SizeX": sub["SizeX"], "SizeY": sub["SizeY"]}}


def rows_named(api, h, np, table):
    """(row_count, {name: ptr}, undecoded). The count comes from the row list --
    rows whose FName fails to decode would collapse onto one dict key."""
    rows, _ = rdr.read_rowmap(api, h, table)
    out, undecoded = {}, 0
    for eid, num, ptr in rows:
        try:
            t = eri.decode_fname_entry_id(api, h, np, eid).get("text")
        except Exception:  # noqa: BLE001
            t = None
        if t is None:
            undecoded += 1
            continue
        out[t] = ptr
    return len(rows), out, undecoded


def read_ui(api, h, ptr, offs, objs=None):
    b = api.read_process_memory(h, ptr + offs["uidetails"], 64)
    rel = offs["relative"]
    return {"InventoryIcon": "0x%x" % struct.unpack_from("<Q", b, rel["InventoryIcon"])[0],
            "MoveIcon": "0x%x" % struct.unpack_from("<Q", b, rel["MoveIcon"])[0],
            "OverrideImageSize": bool(b[rel["MoveIconSizeOverride"] + rel["OverrideImageSize"]]),
            "SizeX": struct.unpack_from("<i", b, rel["MoveIconSizeOverride"] + rel["SizeX"])[0],
            "SizeY": struct.unpack_from("<i", b, rel["MoveIconSizeOverride"] + rel["SizeY"])[0]}


def reconcile_counters(api, h, np, inv, st, fid):
    """Explain ItemCount and CurrentWeight slot by slot.

    Sums Amount and Weight x Amount over every occupied slot, resolving each
    slot's FName against MasterItemList for its Weight. Reports how much of each
    total comes from our row -- which must be zero -- and whether the totals are
    fully accounted for, so an unexplained remainder cannot hide behind a
    matching subtotal.
    """
    _, mrows, _ = rows_named(api, h, np, st["master"])
    weight_by_name = {}
    for nm, ptr in mrows.items():
        weight_by_name[nm] = struct.unpack(
            "<d", api.read_process_memory(h, ptr + 48, 8))[0]
    name_by_id = {}
    # map comparison-index -> name once, from the composite's own row keys
    rows, _ = rdr.read_rowmap(api, h, st["master"])
    for eid, num, ptr in rows:
        try:
            t = eri.decode_fname_entry_id(api, h, np, eid).get("text")
        except Exception:  # noqa: BLE001
            t = None
        if t is not None:
            name_by_id[eid] = t
    amount = 0
    weight = 0.0
    our_amount, our_weight = 0, 0.0
    unresolved, continuation = [], 0
    for slot in inv["slots"]:
        if not slot["occupied"]:
            continue
        iid = slot["item"]["ID"]
        amt = slot["item"]["Amount"]
        if iid == 0:
            # a continuation cell of a multi-cell item: the grid marks every cell
            # the item covers as occupied, but only the root cell carries the
            # S_InvItem. Counting these would double-count the item.
            continuation += 1
            continue
        nm = name_by_id.get(iid)
        if nm is None or nm not in weight_by_name:
            unresolved.append({"index": slot["index"], "ID": iid, "Amount": amt})
            continue
        amount += amt
        weight += weight_by_name[nm] * amt
        if iid == fid:
            our_amount += amt
            our_weight += weight_by_name[nm] * amt
    return {"occupied_slots": sum(1 for x in inv["slots"] if x["occupied"]),
            "continuation_cells": continuation,
            "item_carrying_slots": sum(1 for x in inv["slots"]
                                       if x["occupied"] and x["item"]["ID"]),
            "summed_amount": amount, "summed_weight": round(weight, 6),
            "our_amount": our_amount, "our_weight": our_weight,
            "unresolved_slots": unresolved,
            # ItemCount's exact semantics were NOT derived -- that would be new
            # investigation this gate excludes. Reported, never asserted.
            "ItemCount_semantics": "not modelled; reported for information only",
            "current_weight_explained":
                abs(weight - inv["current_weight"]) < 1e-6 and not unresolved}


def safety_check(api, h, np, objs, st, offs, run_note):
    """The seven read-only post-drop conditions. Nothing is written."""
    fid = st["row_fname"] & 0xFFFFFFFF
    rep = {}

    inv = c3d.read_inventory(api, h, st["player_inv"])
    mine = c3d.occupied_with(inv, fid)
    rep["1_no_entry_in_player_inventory"] = {
        "entries": len(mine), "holds": len(mine) == 0}
    # The recorded baseline is only meaningful while the player has not touched
    # the inventory. They have. So the counters are RECONCILED instead of
    # compared: every occupied slot is resolved against MasterItemList and its
    # Weight x Amount summed. If the totals are fully explained by items that
    # are not ours, our item contributes nothing -- which is what "returned to
    # baseline" was asking, and is a stronger statement than an equality that
    # only holds while nobody plays.
    recon_rep = reconcile_counters(api, h, np, inv, st, fid)
    rep["2_counters_carry_nothing_of_ours"] = dict(
        recon_rep,
        ItemCount=inv["item_count"], recorded_baseline_ItemCount=st["baseline_item_count"],
        CurrentWeight=inv["current_weight"],
        recorded_baseline_CurrentWeight=st["baseline_weight"],
        at_recorded_baseline=(inv["item_count"] == st["baseline_item_count"]
                              and inv["current_weight"] == st["baseline_weight"]
                              and inv["slots_sha256"] == st["baseline_inventory_sha256"]),
        holds=(recon_rep["our_amount"] == 0 and recon_rep["our_weight"] == 0.0
               and recon_rep["current_weight_explained"]))

    master_cls = [a for a, r in objs.items() if r.get("name_ok")
                  and r.get("name_text") == "BP_MasterInventory_C"
                  and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                  == "BlueprintGeneratedClass"]
    if len(master_cls) != 1:
        raise ipp.Blocked("BP_MasterInventory_C class not uniquely resolved")
    master_cls = master_cls[0]
    derived = set()
    for a, r in objs.items():
        if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") not in (
                "BlueprintGeneratedClass", "Class"):
            continue
        sup, hops = a, 0
        while sup and hops < 24:
            if sup == master_cls:
                derived.add(a)
                break
            sup = eri._read_u64(api, h, sup + 0x40)   # UStruct::SuperStruct
            hops += 1
    scanned, slots, carriers = 0, 0, []
    for a, r in objs.items():
        if r.get("class_ptr") not in derived:
            continue
        if (r.get("name_text") or "").startswith("Default__"):
            continue
        scanned += 1
        try:
            s = c3d.read_inventory(api, h, a)
        except Exception:  # noqa: BLE001
            continue
        slots += s["num"]
        if c3d.occupied_with(s, fid):
            carriers.append({"object": "0x%x" % a, "name": r.get("name_text")})
    rep["3_no_other_live_inventory"] = {
        "inventory_components_scanned": scanned, "slots_examined": slots,
        "carriers": carriers, "holds": not carriers}

    world = {}
    for cname in ("BP_StaticMasterItem_C", "BP_SkeletalMasterItem_C"):
        cls = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == cname
               and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
               == "BlueprintGeneratedClass"]
        if len(cls) != 1:
            raise ipp.Blocked("%s class not uniquely resolved" % cname)
        cls = cls[0]
        off = None
        cp = eri._read_u64(api, h, cls + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=cls,
                                          objects_by_address=objs).get("accepted", []):
            if (pr.get("raw_name") or "").split("_")[0] == "InvItem":
                off = pr.get("offset")
        if off is None:
            raise ipp.Blocked("%s.InvItem not found" % cname)
        live, hits = 0, []
        for a, r in objs.items():
            if r.get("class_ptr") != cls or (r.get("name_text") or "").startswith("Default__"):
                continue
            live += 1
            if struct.unpack("<I", api.read_process_memory(h, a + off, 4))[0] == fid:
                hits.append({"actor": "0x%x" % a, "name": r.get("name_text")})
        world[cname] = {"InvItem_offset": off, "live_actors": live, "carrying": hits}
    rep["4_no_world_pickup_carries_it"] = dict(world, holds=all(
        not v["carrying"] for v in world.values()))

    rt_n, rt, rt_u = rows_named(api, h, np, st["table_ptr"])
    mt_n, mt, mt_u = rows_named(api, h, np, st["master"])
    il_n, il, il_u = rows_named(api, h, np, st["itemlist"])
    rep["5_runtime_table_still_has_row"] = {
        "rows": rt_n, "undecoded_names": rt_u, "contains": ROW_NAME in rt,
        "row_ptr": "0x%x" % rt[ROW_NAME] if ROW_NAME in rt else None,
        "ui": read_ui(api, h, rt[ROW_NAME], offs) if ROW_NAME in rt else None,
        "holds": ROW_NAME in rt}
    rep["6_master_item_list_still_resolves"] = {
        "rows": mt_n, "itemlist_rows": il_n, "undecoded_names": mt_u,
        "contains": ROW_NAME in mt,
        "row_ptr": "0x%x" % mt[ROW_NAME] if ROW_NAME in mt else None,
        "ui": read_ui(api, h, mt[ROW_NAME], offs) if ROW_NAME in mt else None,
        "composite_copy_is_a_distinct_buffer":
            ROW_NAME in mt and ROW_NAME in rt and mt[ROW_NAME] != rt[ROW_NAME],
        "holds": ROW_NAME in mt}

    tex = st["icon_object"]
    idx = struct.unpack("<I", api.read_process_memory(h, tex + 0x0C, 4))[0]
    # resolved exactly as CR01C4BProbeDll::ItemForObject does -- objects_ptr IS
    # the chunk pointer array, not a pointer to it
    chunk = eri._read_u64(api, h, st["objects_ptr"] + (idx >> 16) * 8)
    item = chunk + (idx & 0xFFFF) * FUOBJECTITEM
    flags = struct.unpack("<i", api.read_process_memory(h, item + 8, 4))[0]
    eid = eri._read_u32(api, h, tex + eri.DEFAULT_NAME_PRIVATE_OFFSET)
    cls = eri._read_u64(api, h, tex + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
    rep["7_icon_still_rooted"] = {
        "address": "0x%x" % tex, "internal_index": idx,
        "name": eri.decode_fname_entry_id(api, h, np, eid).get("text"),
        "class": eri.decode_fname_entry_id(
            api, h, np, eri._read_u32(api, h, cls + eri.DEFAULT_NAME_PRIVATE_OFFSET)).get("text"),
        "uobject_item_points_back": eri._read_u64(api, h, item) == tex,
        "flags": "0x%x" % (flags & 0xFFFFFFFF), "rooted": bool(flags & ROOTSET),
        "holds": bool(flags & ROOTSET) and eri._read_u64(api, h, item) == tex}

    rep["all_hold"] = all(v["holds"] for k, v in rep.items() if k != "all_hold")
    for k in sorted(rep):
        if k != "all_hold":
            run_note.append("safety %s: %s" % (k, "HOLDS" if rep[k]["holds"] else "FAILS"))
    return rep, rt.get(ROW_NAME), inv


def resolve(api, h, base, size, img, run_note):
    np, objs = recon.universe(api, h, base, size)
    fmeta = recon.find_function_meta(objs)

    def one(nm, clsname, label):
        c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
             and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
        if len(c) != 1:
            raise ipp.Blocked("%s: expected one %s named %s, got %d" % (label, clsname, nm, len(c)))
        return c[0]

    itemlist = one("ItemList", "DataTable", "ItemList")
    sl_cdo = one("Default__KismetStringLibrary", "KismetStringLibrary", "StringLibrary CDO")
    tl_cdo = one("Default__KismetTextLibrary", "KismetTextLibrary", "TextLibrary CDO")
    sgk_cdo = one("Default__BP_SGKFunctions_C", "BP_SGKFunctions_C", "SGK CDO")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary")
    tl_cls = one("KismetTextLibrary", "Class", "KismetTextLibrary")
    sgk_cls = one("BP_SGKFunctions_C", "BlueprintGeneratedClass", "BP_SGKFunctions")
    mi_cls = one("BP_MasterInventory_C", "BlueprintGeneratedClass", "BP_MasterInventory_C")
    player_inv = one("BP_PlayerInventory", "BP_PlayerInventory_C", "live player inventory")

    def fn_on(cls_addr, want, label):
        for f in recon.class_functions(api, h, np, cls_addr, fmeta):
            if f.get("raw_name") == want:
                return f["address"]
        raise ipp.Blocked("%s not found on %s" % (want, label))

    conv = fn_on(sl_cls, "Conv_StringToName", "KismetStringLibrary")
    str2txt = fn_on(tl_cls, "Conv_StringToText", "KismetTextLibrary")
    txt2str = fn_on(tl_cls, "Conv_TextToString", "KismetTextLibrary")
    sgk_details = fn_on(sgk_cls, "SGK ItemDetails", "BP_SGKFunctions")
    add_item = fn_on(mi_cls, "AddItem", "BP_MasterInventory_C")
    remove_item = fn_on(mi_cls, "RemoveItem", "BP_MasterInventory_C")

    def gate(fn, label, parms, rvo=None, need=0):
        fl = eri._read_u32(api, h, fn + 0xB0)
        ps = eri._read_u16(api, h, fn + 0xB6)
        got = eri._read_u16(api, h, fn + 0xB8)
        if ps != parms:
            raise ipp.Blocked("%s ParmsSize %d != %d" % (label, ps, parms))
        if rvo is not None and got != rvo:
            raise ipp.Blocked("%s ReturnValueOffset %d != %d" % (label, got, rvo))
        if need and (fl & need) != need:
            raise ipp.Blocked("%s flags 0x%x lack 0x%x" % (label, fl, need))
        if fl & 0x0138C0C4:
            raise ipp.Blocked("%s carries a net/authority flag 0x%x" % (label, fl))
        if eri._read_u64(api, h, fn + 0xC8):
            raise ipp.Blocked("%s EventGraphFunction non-null" % label)
        run_note.append("%s: flags=0x%x ParmsSize=%d RVO=%d EG=null" % (label, fl, ps, got))

    gate(add_item, "AddItem", 120)
    gate(remove_item, "RemoveItem", 83)
    gate(sgk_details, "SGK ItemDetails", 2336)
    gate(str2txt, "Conv_StringToText", 32, rvo=16, need=0x2400)
    gate(txt2str, "Conv_TextToString", 32, rvo=16, need=0x2400)

    owner = eri._read_u64(api, h, player_inv + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
    role = eri._read_u8(api, h, owner + 336)
    if role != 3:
        raise ipp.Blocked("owning actor Role=%d, not ROLE_Authority" % role)
    nets = [a for a, r in objs.items() if r.get("name_ok")
            and "NetDriver" in ((objs.get(r.get("class_ptr") or 0) or {}).get("name_text") or "")
            and not (r.get("name_text") or "").startswith("Default__")]
    if nets:
        raise ipp.Blocked("live NetDriver instances present (%d)" % len(nets))

    rs = eri._read_u64(api, h, itemlist + 40)
    plain_vt = eri._read_u64(api, h, itemlist)
    rem_row = eri._read_u64(api, h, plain_vt + 94 * 8)
    svt = eri._read_u64(api, h, rs)
    init_va = eri._read_u64(api, h, svt + 96 * 8)
    dest_va = eri._read_u64(api, h, svt + 97 * 8)
    # ProcessEvent's vtable slot is CR-01C1's derived constant, never a literal
    # here. And the slot alone is not trusted: UObject::ProcessEvent is not
    # overridden by any of these classes, so the same slot must yield the SAME
    # address through several unrelated CDOs. A wrong slot would disagree.
    pe_cdos = {"KismetStringLibrary": sl_cdo, "KismetTextLibrary": tl_cdo,
               "BP_SGKFunctions_C": sgk_cdo}
    pe_seen = {}
    for label, cdo in pe_cdos.items():
        pe_seen[label] = eri._read_u64(api, h, eri._read_u64(api, h, cdo) + c1.PE_SLOT * 8)
    if len(set(pe_seen.values())) != 1:
        raise ipp.Blocked("ProcessEvent slot %d disagrees across CDOs: %r"
                          % (c1.PE_SLOT, {k: hex(v) for k, v in pe_seen.items()}))
    pe = next(iter(pe_seen.values()))
    run_note.append("ProcessEvent slot %d agrees across %d unrelated CDOs -> 0x%x"
                    % (c1.PE_SLOT, len(pe_seen), pe))
    for label, va in (("ProcessEvent", pe), ("RemoveRow", rem_row),
                      ("InitializeStruct", init_va), ("DestroyStruct", dest_va)):
        if not (base <= va < base + size):
            raise ipp.Blocked("%s outside module" % label)
        if api.read_process_memory(h, va, 16) != img.bytes_at(va - base, 16):
            raise ipp.Blocked("%s bytes live != disk" % label)
    run_note.append("4 engine addresses byte-verified live==disk")

    return {"np": np, "objs": objs, "itemlist": itemlist, "sl_cdo": sl_cdo, "tl_cdo": tl_cdo,
            "sgk_cdo": sgk_cdo, "conv": conv, "str2txt": str2txt, "txt2str": txt2str,
            "sgk_details": sgk_details, "add_item": add_item, "remove_item": remove_item,
            "player_inv": player_inv, "row_struct": rs, "remove_row": rem_row,
            "init": init_va, "destroy": dest_va, "pe": pe}


def pack_io(carrier, sigs, r, st, offs, dt_offs):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    tg = [ord(c) for c in TRIGGER_NAME] + [0] * (96 - len(TRIGGER_NAME))
    return struct.pack(
        IO_FMT, 0x4950502D43345000, 1, st["struct_size"],
        carrier["add_ticker"], carrier["get_core_ticker"], carrier["fmemory_malloc"],
        carrier["fmemory_free"],
        sigs["add"], sigs["get"], sigs["malloc"],
        r["pe"], r["sl_cdo"], r["conv"],
        r["tl_cdo"], r["str2txt"], r["txt2str"],
        r["sgk_cdo"], r["sgk_details"],
        r["player_inv"], r["add_item"], r["remove_item"],
        st["itemlist"], st["master"], st["table_ptr"], r["remove_row"],
        r["init"], r["destroy"], r["row_struct"],
        st["runtime_row"], st["icon_object"],
        dt_offs["Name"], dt_offs["ShortName"], dt_offs["Description"], offs["inventory_icon"],
        offs["move_icon"], offs["override_flag"], offs["override_sizey"], offs["override_sizex"],
        dt_offs["Weight"], dt_offs["Width"], dt_offs["Height"], dt_offs["MaxStack"],
        dt_offs["AllowStacking"], 0,
        WANT_SIZE[0], WANT_SIZE[1], VALUES["Width"], VALUES["Height"],
        VALUES["Weight"],
        c3d.INVITEM["amount"], c3d.INVITEM["quickbind"], c3d.INVITEM["useamount"],
        c3d.INVITEM["decaytime"], c3d.INVITEM["rotated"], c3d.INVITEM["inuse"],
        c3d.INVITEM["durability"], 0,
        *nm, *tg, b"\0" * 80,
        *([0] * TXT_CAP), *([0] * TXT_CAP), *([0] * TXT_CAP),
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0,  0, 0,  0, 0,  0, 0,
        0.0, 0.0,
        b"\0" * 48, b"\0" * 16,
        0, 0)


def run(api, args, run_note):
    k, _ = gt._k32full()
    if not os.path.isfile(STATE_PATH):
        raise ipp.Blocked("no held demo state at %s" % STATE_PATH)
    st = json.load(open(STATE_PATH, encoding="utf-8"))

    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    if ipp.sha256_of_file(exe) != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    if pid != st["pid"]:
        raise ipp.Blocked("the game was restarted (pid %d, demo held %d); the held state died "
                          "with the old process" % (pid, st["pid"]))
    demo_base = ipp.find_remote_module_base(k, pid, DEMO_DLL_NAME)
    if demo_base != st["rbase"]:
        raise ipp.Blocked("the CR-01C4B demo probe is no longer loaded at its recorded base "
                          "(%r vs %r); the held roots cannot be assumed"
                          % (demo_base, st["rbase"]))
    run_note.append("pid=%d build confirmed; demo probe still loaded at 0x%x" % (pid, demo_base))
    img = DiskImage(exe)
    addrs = verify_carrier_addresses(api, pid, base, img, run_note)

    h = eri.open_process_read_only(api, pid)
    try:
        r = resolve(api, h, base, size, img, run_note)
        offs = ui_offsets(api, h, r["np"], r["row_struct"], r["objs"])
        run_note.append("UI offsets: InventoryIcon@%d MoveIcon@%d Override@%d SizeX@%d SizeY@%d "
                        "(OverrideImageSize mask %s, not a bitfield)"
                        % (offs["inventory_icon"], offs["move_icon"], offs["override_flag"],
                           offs["override_sizex"], offs["override_sizey"],
                           offs["bool_semantics"]["field_mask"]))
        from cr01c3b_controller import verify_fields
        from cr01c4a_controller import text_fields
        vf, _ = verify_fields(api, h, r["np"], r["row_struct"])
        tf, _ = text_fields(api, h, r["np"], r["row_struct"])
        dt_offs = dict(vf)
        dt_offs.update(tf)
        # The recorded player-inventory pointer does NOT survive a death and save
        # reload -- the component is destroyed and a new one spawned. Always use
        # the one just resolved from the live universe, never the recorded one.
        if r["player_inv"] != st.get("player_inv"):
            run_note.append("player inventory changed since the state was written: "
                            "0x%x -> 0x%x (death/reload); using the live object"
                            % (st.get("player_inv") or 0, r["player_inv"]))
        st = dict(st, player_inv=r["player_inv"])
        safety, runtime_row, inv0 = safety_check(api, h, r["np"], r["objs"], st, offs, run_note)
    finally:
        api.close_handle(h)

    report = {"pid": pid, "mode": "patch", "row_name": ROW_NAME, "texts": dict(TEXTS),
              "ui_offsets": {kk: v for kk, v in offs.items() if kk != "relative"},
              "ui_offsets_relative": offs["relative"],
              "safety_check": safety,
              "observed_at_safety_check": {"ItemCount": inv0["item_count"],
                                          "CurrentWeight": inv0["current_weight"],
                                          "slots_sha256": inv0["slots_sha256"]}}
    if not safety["all_hold"]:
        report["verdict"] = "BLOCKED-SAFETY"
        report["outcome"] = ("one or more post-drop safety conditions failed; nothing was "
                             "written and the held state was left untouched")
        return report
    if runtime_row is None:
        raise ipp.Blocked("the runtime row vanished between checks")
    if not args.apply:
        report["armed"] = False
        report["outcome"] = ("DRY RUN: safety conditions all hold and every offset resolved "
                             "fail-closed; nothing was written.")
        report["verdict"] = "DRY-RUN"
        return report

    st = dict(st, runtime_row=runtime_row)
    dll = build_dll()
    sigs = {"add": img.bytes_at(fts.RVA_ADD_TICKER, 16),
            "get": img.bytes_at(fts.RVA_GET_CORE_TICKER, 16),
            "malloc": img.bytes_at(fts.RVA_FMEMORY_MALLOC, 16)}
    carrier = {"add_ticker": addrs["add_ticker"], "get_core_ticker": addrs["get_core_ticker"],
               "fmemory_malloc": addrs["fmemory_malloc"], "fmemory_free": base + 0xFA0090}
    hp = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hp:
        raise ipp.Blocked("OpenProcess failed")
    rpath = rio = rbase = None
    hold = False
    try:
        pth = (dll + "\x00").encode("utf-16-le")
        rpath = k.VirtualAllocEx(hp, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                 ipp.PAGE_READWRITE)
        wr = ctypes.c_size_t(0)
        k.WriteProcessMemory(hp, rpath, pth, len(pth), ctypes.byref(wr))
        pll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        t = k.CreateRemoteThread(hp, None, 0, pll, rpath, 0, None)
        k.WaitForSingleObject(t, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(t)
        rbase = ipp.find_remote_module_base(k, pid, PATCH_DLL)
        if rbase is None:
            raise ipp.Blocked("patch module not loaded")
        io = pack_io(carrier, sigs, r, st, offs, dt_offs)
        rio = k.VirtualAllocEx(hp, None, IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                               ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
        buf = ctypes.create_string_buffer(IO_SIZE)
        rd = ctypes.c_size_t(0)

        def read_io():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return unpack_io(buf.raw)

        def read_io_safe():
            k.ReadProcessMemory(hp, rio, buf, IO_SIZE, ctypes.byref(rd))
            return {"wait_stopped_ok": struct.unpack_from("<I", buf.raw, WAIT_STOPPED_OK_OFFSET)[0],
                    "state": struct.unpack_from("<I", buf.raw, STATE_OFFSET)[0]}

        def call(export, field, timeout=60.0):
            before = read_io()[field]
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            s = read_io()
            dl = time.time() + timeout
            while time.time() < dl and s[field] == before:
                time.sleep(0.05)
                s = read_io()
            return s

        if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("patch Init failed")

        s = call("RunFind", "find_ran")
        report["find"] = {"find_ran": s["find_ran"], "err": s["err"], "err_step": s["err_step"],
                          "before": {"InventoryIcon": "0x%x" % s["before_inventory_icon"],
                                     "MoveIcon": "0x%x" % s["before_move_icon"],
                                     "OverrideImageSize": bool(s["before_override"]),
                                     "SizeX": s["before_sizex"], "SizeY": s["before_sizey"],
                                     "Weight": s["before_weight"]}}
        if s["find_ran"] != 1:
            raise ipp.Blocked("row identity check failed err=%d step=%d"
                              % (s["err"], s["err_step"]))
        run_note.append("row identified by content: InventoryIcon already == our texture")

        s = call("RunPatch", "patch_ran")
        report["patch"] = {"patch_ran": s["patch_ran"], "err": s["err"],
                           "err_step": s["err_step"], "trigger_fired": s["trigger_fired"],
                           "after": {"InventoryIcon": "0x%x" % s["after_inventory_icon"],
                                     "MoveIcon": "0x%x" % s["after_move_icon"],
                                     "OverrideImageSize": bool(s["after_override"]),
                                     "SizeX": s["after_sizex"], "SizeY": s["after_sizey"]},
                           "both_icons_same_object":
                               s["after_inventory_icon"] == s["after_move_icon"]
                               == st["icon_object"]}
        if s["patch_ran"] != 1:
            raise ipp.Blocked("patch refused err=%d step=%d" % (s["err"], s["err_step"]))
        run_note.append("row patched: MoveIcon = InventoryIcon = 0x%x, override %dx%d; "
                        "publication trigger fired"
                        % (st["icon_object"], s["after_sizex"], s["after_sizey"]))

        h = eri.open_process_read_only(api, pid)
        try:
            rt_n, rt, _ = rows_named(api, h, r["np"], st["table_ptr"])
            mt_n, mt, _ = rows_named(api, h, r["np"], st["master"])
            il_n, il, _ = rows_named(api, h, r["np"], st["itemlist"])
            report["after_republish"] = {
                "runtime_table_rows": rt_n, "master_rows": mt_n, "itemlist_rows": il_n,
                "runtime_row_ui": read_ui(api, h, rt[ROW_NAME], offs),
                "composite_row_ui": read_ui(api, h, mt[ROW_NAME], offs),
                "composite_row_ptr": "0x%x" % mt[ROW_NAME],
                "composite_row_reallocated_by_rebuild":
                    mt[ROW_NAME] != safety["6_master_item_list_still_resolves"]["row_ptr"],
                "vanilla_rows_still_present": all(n in mt for n in il)}
        finally:
            api.close_handle(h)
        cui = report["after_republish"]["composite_row_ui"]
        if not (cui["InventoryIcon"] == cui["MoveIcon"] == "0x%x" % st["icon_object"]
                and cui["OverrideImageSize"] and (cui["SizeX"], cui["SizeY"]) == WANT_SIZE):
            raise ipp.Blocked("the composite copy did not pick up the patch: %r" % cui)
        if not report["after_republish"]["vanilla_rows_still_present"]:
            raise ipp.Blocked("a vanilla row went missing from the composite after the rebuild")
        run_note.append("composite copy refreshed and all %d vanilla rows still present" % il_n)

        s = call("RunResolve", "resolve_ran")
        res_text = {"Name": s["name_res"], "ShortName": s["shortname_res"],
                    "Description": s["desc_res"]}
        report["resolver"] = {
            "found": s["resolve_found"],
            "InventoryIcon": "0x%x" % s["resolve_inventory_icon"],
            "MoveIcon": "0x%x" % s["resolve_move_icon"],
            "icons_are_the_same_object":
                s["resolve_inventory_icon"] == s["resolve_move_icon"] == st["icon_object"],
            "OverrideImageSize": bool(s["resolve_override"]),
            "SizeX": s["resolve_sizex"], "SizeY": s["resolve_sizey"],
            "drag_size_override_is_100x100":
                bool(s["resolve_override"])
                and (s["resolve_sizex"], s["resolve_sizey"]) == WANT_SIZE,
            "Weight": s["resolve_weight"], "Width": s["resolve_width"],
            "Height": s["resolve_height"],
            "text": res_text, "text_matches": res_text == TEXTS}
        run_note.append("resolver: found=%d icons_same=%s override=%s %dx%d text_ok=%s"
                        % (s["resolve_found"],
                           report["resolver"]["icons_are_the_same_object"],
                           bool(s["resolve_override"]), s["resolve_sizex"], s["resolve_sizey"],
                           res_text == TEXTS))
        if (s["resolve_found"] != 1 or not report["resolver"]["icons_are_the_same_object"]
                or not report["resolver"]["drag_size_override_is_100x100"]
                or res_text != TEXTS):
            raise ipp.Blocked("resolver did not return the patched definition")

        h = eri.open_process_read_only(api, pid)
        try:
            inv0 = c3d.read_inventory(api, h, r["player_inv"])
        finally:
            api.close_handle(h)
        if not any(not x["occupied"] for x in inv0["slots"]):
            raise ipp.Blocked("no free player inventory slot")
        report["pre_additem"] = {"ItemCount": inv0["item_count"],
                                 "CurrentWeight": inv0["current_weight"],
                                 "occupied": sum(1 for x in inv0["slots"] if x["occupied"]),
                                 "slots": inv0["num"],
                                 "slots_sha256": inv0["slots_sha256"]}
        s = call("RunAddItem", "additem_ran")
        if s["additem_ran"] != 1:
            raise ipp.Blocked("AddItem did not run err=%d" % s["err"])
        report["additem_out"] = {"RemainingItem": s["out_remaining_item"],
                                 "NewItemSlot": s["out_newitemslot"]}

        h = eri.open_process_read_only(api, pid)
        try:
            inv1 = c3d.read_inventory(api, h, r["player_inv"])
        finally:
            api.close_handle(h)
        ours = c3d.occupied_with(inv1, st["row_fname"] & 0xFFFFFFFF)
        changed = c3d.slot_diff(inv0, inv1)
        # The gate's "CurrentWeight = 0.5 / ItemCount = 1" was written for an
        # EMPTY inventory. The player has since picked up unrelated loot, so the
        # same assertion is made as a DELTA against the state measured moments
        # before AddItem. The invariants themselves are unchanged and no weaker:
        # exactly one entry, Amount 1, +0.5 weight, +1 count, no other slot
        # touched.
        report["inventory"] = {
            "entries_with_item": len(ours),
            "slot": ours[0] if ours else None,
            "Amount": ours[0]["item"]["Amount"] if ours else None,
            "ItemCount_before": inv0["item_count"], "ItemCount_after": inv1["item_count"],
            "ItemCount_delta": inv1["item_count"] - inv0["item_count"],
            "CurrentWeight_before": inv0["current_weight"],
            "CurrentWeight_after": inv1["current_weight"],
            "CurrentWeight_delta": round(inv1["current_weight"] - inv0["current_weight"], 6),
            "occupied_before": sum(1 for x in inv0["slots"] if x["occupied"]),
            "occupied_after": sum(1 for x in inv1["slots"] if x["occupied"]),
            "slots_changed": [c["index"] for c in changed],
            "only_our_slot_changed": (len(changed) == 1 and bool(ours)
                                      and changed[0]["index"] == ours[0]["index"]),
            "note": ("absolute 0.5 / 1 were the gate's numbers for an empty "
                     "inventory; the player has unrelated loot now, so this is "
                     "asserted as a delta")}
        if len(ours) != 1:
            raise ipp.Blocked("expected exactly one inventory entry, found %d" % len(ours))
        if ours[0]["item"]["Amount"] != 1:
            raise ipp.Blocked("Amount is %r, expected 1" % ours[0]["item"]["Amount"])
        if report["inventory"]["ItemCount_delta"] != 1:
            raise ipp.Blocked("ItemCount delta is %r, expected +1"
                              % report["inventory"]["ItemCount_delta"])
        if abs(report["inventory"]["CurrentWeight_delta"] - 0.5) > 1e-9:
            raise ipp.Blocked("CurrentWeight delta is %r, expected +0.5"
                              % report["inventory"]["CurrentWeight_delta"])
        if not report["inventory"]["only_our_slot_changed"]:
            raise ipp.Blocked("slots other than ours changed: %r"
                              % report["inventory"]["slots_changed"])
        run_note.append("INVENTORY: slot %d, Amount 1, ItemCount %d->%d (+1), CurrentWeight "
                        "%r->%r (+0.5), no other slot changed"
                        % (ours[0]["index"], inv0["item_count"], inv1["item_count"],
                           inv0["current_weight"], inv1["current_weight"]))
        hold = True
        report["status"] = "READY_FOR_DRAG_VISUAL_CHECK"
    finally:
        # The PATCH module is always unloaded -- it owns nothing, so unloading it
        # cannot disturb the held roots or the publication.
        td = probe_teardown.shutdown_then_unload(k, hp, rbase, dll, rio, read_io_safe, run_note) \
            if rbase else {"attempted": False, "unloaded": False,
                           "safe_to_free_remote_memory": False, "left_loaded_reason": "not loaded"}
        report["patch_module_teardown"] = td
        if td.get("safe_to_free_remote_memory"):
            for b2 in (rpath, rio):
                if b2 is not None:
                    k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
        try:
            report["patch_module_unloaded"] = ipp.confirm_dll_unloaded(pid, PATCH_DLL)
        except Exception:  # noqa: BLE001
            report["patch_module_unloaded"] = None
        report["demo_probe_still_loaded"] = (
            ipp.find_remote_module_base(k, pid, DEMO_DLL_NAME) == st["rbase"])
        k.CloseHandle(hp)

    td = report.get("patch_module_teardown") or {}
    if td.get("attempted") and not td.get("unloaded"):
        report["verdict"] = "BLOCKED-TEARDOWN"
        report["teardown_blocked"] = td.get("left_loaded_reason")
        return report
    if hold and report.get("demo_probe_still_loaded"):
        report["verdict"] = "HELD"
        with open(STATE_PATH, "w", encoding="utf-8", newline="\n") as f:
            json.dump(dict(st, patched=True, move_icon=st["icon_object"],
                           drag_size_override=list(WANT_SIZE)),
                      f, indent=2, sort_keys=True)
            f.write("\n")
    else:
        report["verdict"] = "NOT-HELD"
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="write the three UI fields, republish, resolve and AddItem")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    rid = (a.run_dir and os.path.basename(a.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ",
                                                                      time.gmtime())
    rdir = a.run_dir or os.path.join(REPO, "research", "instrument-runs", rid)
    os.makedirs(rdir, exist_ok=True)
    note, arts = [], []
    vb = va = None
    code = 0
    try:
        api = eri.Win32Api()
        if a.apply:
            vb = ipp.run_verify_install(rdir, "before")
            if vb.get("report_artifact"):
                arts.append(vb["report_artifact"])
            if vb["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before")
        rep = run(api, a, note)
        rep["run_note"] = note
        if a.apply:
            va = ipp.run_verify_install(rdir, "after")
            if va.get("report_artifact"):
                arts.append(va["report_artifact"])
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        if rep.get("verdict") in ("BLOCKED-TEARDOWN", "BLOCKED-SAFETY"):
            code = 2
            print("BLOCKED: %s" % rep.get("verdict"), file=sys.stderr)
        print(json.dumps({kk: rep[kk] for kk in rep if kk != "run_note"},
                         indent=2, sort_keys=True, default=str))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": note}
        if a.apply and va is None:
            try:
                va = ipp.run_verify_install(rdir, "after")
                if va.get("report_artifact"):
                    arts.append(va["report_artifact"])
                note.append("run aborted; verify_install after-check still performed")
            except Exception as e2:  # noqa: BLE001
                note.append("run aborted and the after-check also failed: %r" % (e2,))
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(rdir, arguments=arguments,
                           capabilities_enabled=(["CR-01C4B"] if a.apply else ["I-01"]),
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=arts,
                           instrument_level=("ipp" if a.apply else "eri"))
    return code


if __name__ == "__main__":
    sys.exit(main())
