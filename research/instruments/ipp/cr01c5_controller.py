#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C5 -- a runtime-defined item with a real world representation.

Everything here rides on already-proven mechanisms; what is new is only the set
of fields written, and each of those was traced in phase 1 rather than guessed:

  WorldClass  = BP_StaticMasterItem_C, the VANILLA generic world-item class that
                472 of 496 vanilla rows already use. Referencing a vanilla class
                is not copying a vanilla asset, and it is what keeps the unproven
                custom-Blueprint-parent problem off this path entirely.
  StaticMesh  = a soft reference to our own cooked mesh. BP_StaticMasterItem_C
                loads it itself, so it must resolve by soft path -- which the
                mounted container provides.
  ItemOffsets = written explicitly, because Scale3D sits at +64 of the
                FTransform and a zeroed value is scale (0,0,0): an invisible
                actor.

The item is added to the inventory and then HELD. This controller never drops
it: the drop is the owner's manual visual test.
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
from cr01c3b_controller import (DiskImage, verify_carrier_addresses, verify_fields,  # noqa: E402
                                bool_semantics, OFF_ROWSTRUCT, OFF_PARENT_TABLES)
from cr01c3c_controller import (rows_by_key, derive_copy_mask, masked_digest,  # noqa: E402
                                semantic_digests, exact_hashes, parent_raw)
from cr01c4a_controller import text_fields, u16_to_str, str_to_u16  # noqa: E402
import cr01c4b_controller as _c4b  # noqa: E402

DLL_NAME = "CR01C5Probe.dll"
ROW_NAME = "mbpl__radio"
TRIGGER_NAME = "mbpl__c5_neutral_trigger"
STATE_PATH = os.path.join(REPO, "workspace", "c5-demo-state.json")

ICON_PACKAGE = "/Game/MBPLTest/Items/Radio/T_MBPL_Radio_Icon"
ICON_ASSET = "T_MBPL_Radio_Icon"
MESH_PACKAGE = "/Game/MBPLTest/Items/Radio/SM_MBPL_Radio"
MESH_ASSET = "SM_MBPL_Radio"
WORLD_CLASS = "BP_StaticMasterItem_C"

TEXTS = {"Name": "MBPL Radio", "ShortName": "Radio",
         "Description": "A runtime-defined MBPL test radio."}
VALUES = {"Weight": 0.5, "Width": 1, "Height": 1, "MaxStack": 1, "AllowStacking": 0}
DRAG_SIZE = (100, 100)
# identity scale, and the small +Z lift ordinary vanilla 1x1 rows use so the mesh
# does not spawn intersecting the ground
WANT_SCALE = (1.0, 1.0, 1.0)
WANT_TRANS = (0.0, 0.0, 5.0)
TXT_CAP = 128
ROOTSET = 1 << 30
FUOBJECTITEM = 0x18

# The C4B format is DERIVED from the C4B controller rather than retyped. Retyping
# it once already cost three Q's in the pointer block -- a 24-byte drift that the
# probe's own static_assert would have caught only after a build, and that a
# hand-comparison would not have caught at all.
_C4B = _c4b.IO_FMT
_PRE = _C4B.rsplit("QQQQIIIIIIII", 1)[0] + "QQQQIIIIIIII"   # C4B inputs
_C4B_REST = _C4B[len(_PRE):]
assert _C4B_REST.endswith("QQ"), "C4B format no longer ends with reserved[2]"
_OUTS = _C4B_REST[:-2]                                       # C4B outputs
_END = "QQ"                                                  # reserved[2]
_C5IN = "QQQQ IIII IIII IIII dddddd 128H128H128H".replace(" ", "")
_C5OUT = "QQQQ QQ QQQQ IIII IIII IIII ddd ddd QQ QQ".replace(" ", "")
IO_FMT = _PRE + _C5IN + _OUTS + _C5OUT + _END
IO_SIZE = struct.calcsize(IO_FMT)
assert IO_SIZE == 5648, "C5Io wire format drifted (%d)" % IO_SIZE
SLOT_IN_OFFSET = struct.calcsize(IO_FMT.split("80s")[0])
_INPUT_PREFIX = _PRE + _C5IN
_OUTPUT_BLOCK_OFFSET = struct.calcsize(_INPUT_PREFIX)
STATE_OFFSET = _OUTPUT_BLOCK_OFFSET + 8
WAIT_STOPPED_OK_OFFSET = _OUTPUT_BLOCK_OFFSET + 12
OUT_INDEX = len(struct.unpack(_INPUT_PREFIX, bytes(_OUTPUT_BLOCK_OFFSET)))
_TXT_INDEX = len(struct.unpack(IO_FMT.split("80s")[0] + "80s",
                               bytes(struct.calcsize(IO_FMT.split("80s")[0] + "80s"))))
_MESH_PREFIX = _PRE + "QQQQIIIIIIIIIIIIdddddd"
_MESH_TXT_INDEX = len(struct.unpack(_MESH_PREFIX, bytes(struct.calcsize(_MESH_PREFIX))))


class RollbackNeeded(Exception):
    pass


def build_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    rdir = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    bd = os.path.join(REPO, "workspace", "msvc-probe")
    out = os.path.join(bd, DLL_NAME)
    srcs = [os.path.join(rdir, "CR01C5ProbeDll.cpp"),
            os.path.join(rdir, "UE54TickerCarrier.cpp")]
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
    inc = '/I"{0}\\Core\\Public" /I"{0}\\TraceLog\\Public" /I"{0}\\Core\\Internal"'.format(ue)
    bat = os.path.join(bd, "_build_c5ctl.bat")
    lines = ["@echo off",
             'call "{0}" -vcvars_ver=14.38 >nul 2>&1'.format(vcvars),
             'cl /nologo /LD /MT /EHsc /std:c++17 {0} {1} "{2}" "{3}" /Fe:"{4}" '
             '/link /INCREMENTAL:NO'.format(defs, inc, srcs[0], srcs[1], out)]
    with open(bat, "w", newline="\r\n") as f:
        f.write("\r\n".join(lines) + "\r\n")
    r = subprocess.run([bat], capture_output=True, text=True, cwd=bd, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("%s did not build:\n%s\n%s" % (DLL_NAME, r.stdout, r.stderr))
    return out


def world_offsets(api, h, np, row_struct, objs):
    """FAIL CLOSED for every field this gate writes.

    Each hop checks the reflected identity, the property class and the size, and
    for WorldClass also the MetaClass -- because the value being stored there is
    a UClass pointer, and storing a class that does not satisfy the MetaClass
    would be a type error the engine cannot catch for us.
    """
    def chain(owner):
        cp = eri._read_u64(api, h, owner + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
        return eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=owner,
                                       objects_by_address=objs).get("accepted", [])

    out = {}
    ui_off = ui_struct = None
    for pr in chain(row_struct):
        nm = (pr.get("raw_name") or "").split("_")[0]
        addr = int(pr["address_hex"], 16)
        if nm == "UIDetails":
            if pr.get("property_class") != "FStructProperty":
                raise ipp.Blocked("UIDetails is %s" % pr.get("property_class"))
            ui_off = pr.get("offset")
            ui_struct = eri._read_u64(api, h, addr + 0x70)
        elif nm == "WorldClass":
            if pr.get("property_class") != "FClassProperty" or pr.get("size") != 8:
                raise ipp.Blocked("WorldClass is %s size %r, expected FClassProperty size 8"
                                  % (pr.get("property_class"), pr.get("size")))
            meta = eri._read_u64(api, h, addr + 0x78)
            out["worldclass_metaclass"] = (objs.get(meta) or {}).get("name_text")
            out["worldclass_metaclass_addr"] = meta
            out["off_worldclass"] = pr.get("offset")
        elif nm == "StaticMesh":
            if pr.get("property_class") != "FSoftObjectProperty" or pr.get("size") != 40:
                raise ipp.Blocked("StaticMesh is %s size %r, expected FSoftObjectProperty size 40"
                                  % (pr.get("property_class"), pr.get("size")))
            pc = eri._read_u64(api, h, addr + 0x70)
            if (objs.get(pc) or {}).get("name_text") != "StaticMesh":
                raise ipp.Blocked("StaticMesh PropertyClass is %r, expected StaticMesh"
                                  % (objs.get(pc) or {}).get("name_text"))
            out["off_staticmesh"] = pr.get("offset")
        elif nm == "ItemOffsets":
            if pr.get("property_class") != "FStructProperty" or pr.get("size") != 96:
                raise ipp.Blocked("ItemOffsets is %s size %r, expected FStructProperty size 96"
                                  % (pr.get("property_class"), pr.get("size")))
            ts = eri._read_u64(api, h, addr + 0x70)
            if (objs.get(ts) or {}).get("name_text") != "Transform":
                raise ipp.Blocked("ItemOffsets struct is %r, expected Transform"
                                  % (objs.get(ts) or {}).get("name_text"))
            out["off_itemoffsets"] = pr.get("offset")
            sub = {}
            for q in chain(ts):
                qn = (q.get("raw_name") or "").split("_")[0]
                if qn in ("Rotation", "Translation", "Scale3D"):
                    sub[qn] = q.get("offset")
            if set(sub) != {"Rotation", "Translation", "Scale3D"}:
                raise ipp.Blocked("Transform members missing: %r" % sorted(sub))
            out["off_rot"], out["off_trans"], out["off_scale"] = (
                sub["Rotation"], sub["Translation"], sub["Scale3D"])
    for k in ("off_worldclass", "off_staticmesh", "off_itemoffsets"):
        if k not in out:
            raise ipp.Blocked("%s not found on S_ItemDetails" % k)
    if out["worldclass_metaclass"] != "Actor":
        raise ipp.Blocked("WorldClass MetaClass is %r, expected Actor"
                          % out["worldclass_metaclass"])

    if ui_off is None or (objs.get(ui_struct) or {}).get("name_text") != "S_UIDetails":
        raise ipp.Blocked("UIDetails did not resolve to S_UIDetails")
    icons, ov_off, ov_struct = {}, None, None
    for pr in chain(ui_struct):
        nm = (pr.get("raw_name") or "").split("_")[0]
        addr = int(pr["address_hex"], 16)
        if nm in ("InventoryIcon", "MoveIcon"):
            if pr.get("property_class") != "FObjectProperty" or pr.get("size") != 8:
                raise ipp.Blocked("%s is %s size %r" % (nm, pr.get("property_class"),
                                                        pr.get("size")))
            pc = eri._read_u64(api, h, addr + 0x70)
            if (objs.get(pc) or {}).get("name_text") != "Texture2D":
                raise ipp.Blocked("%s PropertyClass is %r, expected Texture2D"
                                  % (nm, (objs.get(pc) or {}).get("name_text")))
            icons[nm] = pr.get("offset")
        elif nm == "MoveIconSizeOverride":
            ov_off = pr.get("offset")
            ov_struct = eri._read_u64(api, h, addr + 0x70)
    if set(icons) != {"InventoryIcon", "MoveIcon"} or ov_off is None:
        raise ipp.Blocked("S_UIDetails members missing")
    if (objs.get(ov_struct) or {}).get("name_text") != "S_SizeOverride":
        raise ipp.Blocked("MoveIconSizeOverride did not resolve to S_SizeOverride")
    sub = {}
    for q in chain(ov_struct):
        qn = (q.get("raw_name") or "").split("_")[0]
        if qn in ("SizeX", "SizeY", "OverrideImageSize"):
            sub[qn] = q.get("offset")
    if set(sub) != {"SizeX", "SizeY", "OverrideImageSize"}:
        raise ipp.Blocked("S_SizeOverride members missing")
    out["bool_semantics"] = bool_semantics(api, h, np, ov_struct, "OverrideImageSize")
    out["off_inventory_icon"] = ui_off + icons["InventoryIcon"]
    out["off_move_icon"] = ui_off + icons["MoveIcon"]
    out["off_override_flag"] = ui_off + ov_off + sub["OverrideImageSize"]
    out["off_override_sizex"] = ui_off + ov_off + sub["SizeX"]
    out["off_override_sizey"] = ui_off + ov_off + sub["SizeY"]
    return out


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
            "resolve_weight", "resolve_allowstacking",
            # C4B's own key list stopped here, so its trailing pad3 never needed a
            # name. The C5 outputs continue in the SAME list, so it does: leaving
            # it out shifts every C5 key by one item.
            "resolve_pad3",
            # --- C5 outputs ---
            "mesh_object", "mesh_item_ptr", "mesh_class", "mesh_store_handle",
            "mesh_pkg_name", "mesh_asset_name",
            "row_move_icon", "row_worldclass", "resolve_worldclass", "c5_pad1",
            "loadmesh_ran", "verifymesh_ran", "releasemesh_ran", "mesh_soft_roundtrip_ok",
            "mesh_rooted_after_acquire", "mesh_rooted_after_release", "row_override",
            "row_sizex", "row_sizey", "resolve_override", "resolve_sizex", "resolve_sizey",
            "row_scale_x", "row_scale_y", "row_scale_z",
            "resolve_scale_x", "resolve_scale_y", "resolve_scale_z",
            "row_staticmesh_pkg", "row_staticmesh_asset",
            "resolve_staticmesh_pkg", "resolve_staticmesh_asset"]
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
    m = _MESH_TXT_INDEX
    for i, lab in enumerate(["mesh_pkg_in", "mesh_asset_in", "mesh_path_roundtrip"]):
        out[lab] = u16_to_str(f[m + i * TXT_CAP: m + (i + 1) * TXT_CAP])
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
            raise ipp.Blocked("%s: expected one %s named %s, got %d" % (label, clsname, nm, len(c)))
        return c[0]

    itemlist = one("ItemList", "DataTable", "ItemList")
    master = one("MasterItemList", "CompositeDataTable", "MasterItemList")
    transient = one("/Engine/Transient", "Package", "transient package")
    dt_class = one("DataTable", "Class", "UDataTable UClass")
    cdt_class = one("CompositeDataTable", "Class", "UCompositeDataTable UClass")
    tex_class = one("Texture2D", "Class", "UTexture2D UClass")
    sm_class = one("StaticMesh", "Class", "UStaticMesh UClass")
    actor_class = one("Actor", "Class", "AActor UClass")
    world_class = one(WORLD_CLASS, "BlueprintGeneratedClass", "world item class")
    gs_cdo = one("Default__GameplayStatics", "GameplayStatics", "GameplayStatics CDO")
    sl_cdo = one("Default__KismetStringLibrary", "KismetStringLibrary", "StringLibrary CDO")
    tl_cdo = one("Default__KismetTextLibrary", "KismetTextLibrary", "TextLibrary CDO")
    sy_cdo = one("Default__KismetSystemLibrary", "KismetSystemLibrary", "SystemLibrary CDO")
    sgk_cdo = one("Default__BP_SGKFunctions_C", "BP_SGKFunctions_C", "SGK CDO")
    gs_cls = one("GameplayStatics", "Class", "GameplayStatics")
    sl_cls = one("KismetStringLibrary", "Class", "KismetStringLibrary")
    tl_cls = one("KismetTextLibrary", "Class", "KismetTextLibrary")
    sy_cls = one("KismetSystemLibrary", "Class", "KismetSystemLibrary")
    sgk_cls = one("BP_SGKFunctions_C", "BlueprintGeneratedClass", "BP_SGKFunctions")
    mi_cls = one("BP_MasterInventory_C", "BlueprintGeneratedClass", "BP_MasterInventory_C")

    # the live player inventory, resolved by class and never from a recorded pointer
    pi_cls = one("BP_PlayerInventory_C", "BlueprintGeneratedClass", "BP_PlayerInventory_C")
    live = []
    for a, r in objs.items():
        if r.get("class_ptr") != pi_cls:
            continue
        nm = r.get("name_text") or ""
        if nm.startswith("Default__") or "GEN_VARIABLE" in nm:
            continue
        owner = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
        ocls = (objs.get(eri._read_u64(api, h, owner + eri.DEFAULT_CLASS_PRIVATE_OFFSET))
                or {}).get("name_text") if owner else None
        if ocls == "BP_SGKController_C":
            live.append(a)
    if len(live) != 1:
        raise ipp.Blocked("expected exactly one live player inventory on a live "
                          "BP_SGKController_C, found %d" % len(live))
    player_inv = live[0]

    # WorldClass must satisfy the property's MetaClass. Walk the super chain.
    sup, chain, hops = world_class, [], 0
    while sup and hops < 24:
        chain.append((objs.get(sup) or {}).get("name_text"))
        if sup == actor_class:
            break
        sup = eri._read_u64(api, h, sup + 0x40)
        hops += 1
    if sup != actor_class:
        raise ipp.Blocked("%s does not derive from Actor (chain %r)" % (WORLD_CLASS, chain))
    run_note.append("%s super chain to Actor: %s" % (WORLD_CLASS, " -> ".join(
        x for x in chain if x)))

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

    gate(spawn, "SpawnObject", 24, need=0x2400)
    gate(add_item, "AddItem", 120)
    gate(remove_item, "RemoveItem", 83)
    gate(sgk_details, "SGK ItemDetails", 2336)
    gate(str2txt, "Conv_StringToText", 32, rvo=16, need=0x2400)
    gate(txt2str, "Conv_TextToString", 32, rvo=16, need=0x2400)
    gate(load_blocking, "LoadAsset_Blocking", 48, rvo=40, need=0x2400)
    gate(soft2str, "Conv_SoftObjectReferenceToString", 56, rvo=40, need=0x2400)

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

    pe_seen = {}
    for label, cdo in (("KismetStringLibrary", sl_cdo), ("KismetTextLibrary", tl_cdo),
                       ("BP_SGKFunctions_C", sgk_cdo)):
        pe_seen[label] = eri._read_u64(api, h, eri._read_u64(api, h, cdo) + c1.PE_SLOT * 8)
    if len(set(pe_seen.values())) != 1:
        raise ipp.Blocked("ProcessEvent slot %d disagrees across CDOs: %r"
                          % (c1.PE_SLOT, {k: hex(v) for k, v in pe_seen.items()}))
    pe = next(iter(pe_seen.values()))
    run_note.append("ProcessEvent slot %d agrees across %d unrelated CDOs -> 0x%x"
                    % (c1.PE_SLOT, len(pe_seen), pe))

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
    return {"np": np, "objs": objs, "itemlist": itemlist, "master": master,
            "transient": transient, "dt_class": dt_class, "cdt_class": cdt_class,
            "tex_class": tex_class, "sm_class": sm_class, "actor_class": actor_class,
            "world_class": world_class, "gs_cdo": gs_cdo, "sl_cdo": sl_cdo, "tl_cdo": tl_cdo,
            "sy_cdo": sy_cdo, "sgk_cdo": sgk_cdo, "spawn": spawn, "conv": conv,
            "str2txt": str2txt, "txt2str": txt2str, "load_blocking": load_blocking,
            "soft2str": soft2str, "sgk_details": sgk_details, "add_item": add_item,
            "remove_item": remove_item, "player_inv": player_inv, "row_struct": rs,
            "struct_size": struct_size, "plain_vtable": plain_vt,
            "composite_vtable": composite_vt, "add_row": add_row, "remove_row": rem_row,
            "init": init_va, "destroy": dest_va, "pe": pe, "set_root": set_root,
            "clear_root": clr_root, "free": free_va,
            "objects_ptr": i02["objects_ptr_live_va"], "parent_raw": praw,
            "world_class_chain": chain}


def pack_io(carrier, sigs, r, offs, toffs, woffs):
    nm = [ord(c) for c in ROW_NAME] + [0] * (96 - len(ROW_NAME))
    tg = [ord(c) for c in TRIGGER_NAME] + [0] * (96 - len(TRIGGER_NAME))
    z128 = [0] * TXT_CAP
    return struct.pack(
        IO_FMT, 0x4950502D43350000, 1, r["struct_size"],
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
        toffs["Name"], toffs["ShortName"], toffs["Description"], woffs["off_inventory_icon"],
        offs["Weight"], offs["Width"], offs["Height"], offs["MaxStack"],
        offs["AllowStacking"], 0,
        VALUES["Weight"],
        VALUES["Width"], VALUES["Height"], VALUES["MaxStack"], VALUES["AllowStacking"],
        b"\0\0\0",
        c3d.INVITEM["amount"], c3d.INVITEM["quickbind"], c3d.INVITEM["useamount"],
        c3d.INVITEM["decaytime"], c3d.INVITEM["rotated"], c3d.INVITEM["inuse"],
        c3d.INVITEM["durability"], 0,
        *nm, *tg, b"\0" * 80,
        *str_to_u16(TEXTS["Name"]), *str_to_u16(TEXTS["ShortName"]),
        *str_to_u16(TEXTS["Description"]),
        *z128, *z128, *z128,
        *z128, *z128, *z128,
        *str_to_u16(ICON_PACKAGE), *str_to_u16(ICON_ASSET), *z128,
        0, 0, 0,  0, 0, 0,  0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,
        # ---- CR-01C5 inputs ----
        r["sm_class"], r["world_class"], r["actor_class"], 0,
        woffs["off_move_icon"], woffs["off_override_flag"],
        woffs["off_override_sizey"], woffs["off_override_sizex"],
        woffs["off_worldclass"], woffs["off_staticmesh"], woffs["off_itemoffsets"],
        woffs["off_rot"],
        woffs["off_trans"], woffs["off_scale"], DRAG_SIZE[0], DRAG_SIZE[1],
        WANT_SCALE[0], WANT_SCALE[1], WANT_SCALE[2],
        WANT_TRANS[0], WANT_TRANS[1], WANT_TRANS[2],
        *str_to_u16(MESH_PACKAGE), *str_to_u16(MESH_ASSET), *z128,
        # ---- C4B output block, zeroed ----
        *([0] * 36),
        *([0] * 14),
        b"\0" * 48, b"\0" * 16,
        0, 0, 0, 0,
        0.0, 0, 0,
        # ---- CR-01C5 outputs, zeroed ----
        0, 0, 0, 0,
        0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0.0, 0.0, 0.0,
        0.0, 0.0, 0.0,
        0, 0,
        0, 0,
        # ---- reserved[2] ----
        0, 0)


EXPECT_MATERIALS = None

SMC_STATICMESH = 1376
SM_STATICMATERIALS = 344
MI_PARENT = 272
MI_TEXTURE = 408
MI_TEXTURE_STRIDE = 40


def verify_live_materials(api, pid, mesh_obj, expect, run_note):
    """Prove, against the LIVE process, that the loaded mesh's slots resolve to
    our MICs, that each MIC is really loaded, that its Parent resolves to the
    REAL vanilla material, and that every texture override resolves to our
    cooked Texture2D.

    This exists because the MIC -> vanilla parent import has never resolved
    successfully even once. Two probes were observed before anyone checked that
    the materials had loaded at all, and both were fallbacks.
    """
    h = eri.open_process_read_only(api, pid)
    try:
        np, objs = recon.universe(api, h, eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
                                  ["base_address"],
                                  eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
                                  ["image_size_bytes"])

        def path_of(a):
            if not a:
                return None
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objs).get("object_path"))
            except Exception:  # noqa: BLE001
                return None

        def fname(eid):
            try:
                return eri.decode_fname_entry_id(api, h, np, eid).get("text")
            except Exception:  # noqa: BLE001
                return None

        ss = [a for a, rr in objs.items() if rr.get("name_ok")
              and rr.get("name_text") == "StaticMaterial"
              and (objs.get(rr.get("class_ptr") or 0) or {}).get("name_text") == "ScriptStruct"]
        if len(ss) != 1:
            raise ipp.Blocked("StaticMaterial ScriptStruct not uniquely resolved")
        stride = struct.unpack("<i", api.read_process_memory(h, ss[0] + 0x58, 4))[0]

        data = eri._read_u64(api, h, mesh_obj + SM_STATICMATERIALS)
        num = struct.unpack("<i", api.read_process_memory(
            h, mesh_obj + SM_STATICMATERIALS + 8, 4))[0]
        if not data or num != len(expect["slots"]):
            raise ipp.Blocked("mesh has %r slots, expected %d" % (num, len(expect["slots"])))
        blob = api.read_process_memory(h, data, num * stride)

        out = []
        for i, want in enumerate(expect["slots"]):
            mi = struct.unpack_from("<Q", blob, i * stride)[0]
            slot_name = fname(struct.unpack_from("<I", blob, i * stride + 8)[0])
            if not mi:
                raise ipp.Blocked("slot %d MaterialInterface is NULL" % i)
            mpath = path_of(mi)
            if mpath != want["mic"]:
                raise ipp.Blocked("slot %d is %r, expected %r" % (i, mpath, want["mic"]))
            if slot_name != want["slot_name"]:
                raise ipp.Blocked("slot %d name is %r, expected %r"
                                  % (i, slot_name, want["slot_name"]))
            parent = eri._read_u64(api, h, mi + MI_PARENT)
            ppath = path_of(parent)
            if ppath != expect["parent"]:
                raise ipp.Blocked("slot %d MIC parent is %r, expected the real vanilla %r"
                                  % (i, ppath, expect["parent"]))
            pcls = (objs.get(eri._read_u64(api, h, parent
                                           + eri.DEFAULT_CLASS_PRIVATE_OFFSET)) or {}
                    ).get("name_text")
            if pcls != "Material":
                raise ipp.Blocked("slot %d parent class is %r, expected Material" % (i, pcls))
            tdata = eri._read_u64(api, h, mi + MI_TEXTURE)
            tnum = struct.unpack("<i", api.read_process_memory(
                h, mi + MI_TEXTURE + 8, 4))[0]
            got = {}
            if tdata and tnum > 0:
                tb = api.read_process_memory(h, tdata, tnum * MI_TEXTURE_STRIDE)
                for j in range(tnum):
                    pn = fname(struct.unpack_from("<I", tb, j * MI_TEXTURE_STRIDE)[0])
                    t = struct.unpack_from("<Q", tb, j * MI_TEXTURE_STRIDE + 16)[0]
                    got[pn] = path_of(t)
            for pn, wpath in want["textures"].items():
                if got.get(pn) != wpath:
                    raise ipp.Blocked("slot %d override %s is %r, expected %r"
                                      % (i, pn, got.get(pn), wpath))
            out.append({"slot": i, "slot_name": slot_name, "mic": mpath,
                        "mic_object": "0x%x" % mi, "parent": ppath,
                        "parent_object": "0x%x" % parent, "parent_class": pcls,
                        "textures": got})
            run_note.append("slot %d OK: %s -> parent %s" % (i, want["slot_name"], ppath))
        return out
    finally:
        api.close_handle(h)


def observe(api, pid, r, mask):
    size = r["struct_size"]
    h = eri.open_process_read_only(api, pid)
    try:
        return {"itemlist_rows": len(rows_by_key(api, h, r["itemlist"])),
                "itemlist_exact": exact_hashes(api, h, r["itemlist"], size),
                "master_rows": len(rows_by_key(api, h, r["master"])),
                "master_semantic": semantic_digests(api, h, r["master"], size, mask),
                "parent_raw": parent_raw(api, h, r["master"]),
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
        offs, field_report = verify_fields(api, h, r["np"], r["row_struct"])
        toffs, text_report = text_fields(api, h, r["np"], r["row_struct"])
        woffs = world_offsets(api, h, r["np"], r["row_struct"], r["objs"])
        run_note.append("world offsets: WorldClass@%d StaticMesh@%d ItemOffsets@%d "
                        "(Rot@%d Trans@%d Scale@%d) MoveIcon@%d"
                        % (woffs["off_worldclass"], woffs["off_staticmesh"],
                           woffs["off_itemoffsets"], woffs["off_rot"], woffs["off_trans"],
                           woffs["off_scale"], woffs["off_move_icon"]))
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

    # These are different failures and used to share one message: an inventory
    # whose slot array is still empty is mid-initialisation, not full.
    if not inv0["slots"]:
        raise ipp.Blocked("the player inventory has no slot array yet (%d slots) -- it is "
                          "still initialising; wait until the inventory is openable"
                          % inv0["num"])
    if all(s["occupied"] for s in inv0["slots"]):
        raise ipp.Blocked("player inventory is full: %d/%d slots occupied"
                          % (sum(1 for s in inv0["slots"] if s["occupied"]), inv0["num"]))
    before = observe(api, pid, r, mask)
    report = {"pid": pid, "row_name": ROW_NAME, "texts": dict(TEXTS),
              "world": {"WorldClass": WORLD_CLASS,
                        "WorldClass_addr": "0x%x" % r["world_class"],
                        "WorldClass_super_chain": [x for x in r["world_class_chain"] if x],
                        "WorldClass_metaclass": woffs["worldclass_metaclass"],
                        "StaticMesh_soft_path": "%s.%s" % (MESH_PACKAGE, MESH_ASSET),
                        "ItemOffsets_scale": list(WANT_SCALE),
                        "ItemOffsets_translation": list(WANT_TRANS)},
              "offsets": {kk: v for kk, v in woffs.items() if kk != "bool_semantics"},
              "bool_semantics": woffs["bool_semantics"],
              "fields": field_report, "text_fields": text_report,
              "baseline": {"itemlist_rows": before["itemlist_rows"],
                           "master_rows": before["master_rows"],
                           "parent_raw": before["parent_raw"],
                           "inventory_slots": inv0["num"],
                           "inventory_occupied": sum(1 for s in inv0["slots"] if s["occupied"]),
                           "ItemCount": inv0["item_count"],
                           "CurrentWeight": inv0["current_weight"]}}
    if not args.arm:
        report["armed"] = False
        report["verdict"] = "DRY-RUN"
        report["outcome"] = ("all fail-closed checks passed and every world offset resolved; "
                             "nothing was written.")
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
    hold = False
    cleanup = {}
    blocked_reason = None
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
        rbase = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if rbase is None:
            raise ipp.Blocked("probe DLL not loaded")
        io = pack_io(carrier, sigs, r, offs, toffs, woffs)
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

        def call(export, field, timeout=90.0):
            before_v = read_io()[field]
            p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
            st = read_io()
            dl = time.time() + timeout
            while time.time() < dl and st[field] == before_v:
                time.sleep(0.05)
                st = read_io()
            return st

        if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
            raise ipp.Blocked("Init failed")
        st = call("RunCreate", "create_ran")
        if st["create_ran"] != 1:
            raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
        table_ptr, row_fname = st["table_ptr"], st["row_fname"]

        st = call("RunLoadIcon", "loadicon_ran")
        report["icon_load"] = {"ran": st["loadicon_ran"], "err": st["err"],
                               "roundtrip": st["icon_path_roundtrip"],
                               "object": "0x%x" % st["icon_object"],
                               "is_texture2d": st["icon_class"] == r["tex_class"],
                               "rooted": st["icon_rooted_after_acquire"] == 1}
        if st["loadicon_ran"] != 1:
            raise ipp.Blocked("icon load failed err=%d step=%d" % (st["err"], st["err_step"]))

        st = call("RunLoadMesh", "loadmesh_ran")
        report["mesh_load"] = {
            "ran": st["loadmesh_ran"], "err": st["err"], "err_step": st["err_step"],
            "soft_path_roundtrip": st["mesh_path_roundtrip"],
            "soft_path_expected": "%s.%s" % (MESH_PACKAGE, MESH_ASSET),
            "soft_path_matches": st["mesh_path_roundtrip"] == "%s.%s" % (MESH_PACKAGE, MESH_ASSET),
            "object": "0x%x" % st["mesh_object"], "class": "0x%x" % st["mesh_class"],
            "is_staticmesh": st["mesh_class"] == r["sm_class"],
            "rooted": st["mesh_rooted_after_acquire"] == 1,
            "owned_count": st["owned_count"]}
        if st["loadmesh_ran"] != 1:
            raise ipp.Blocked("mesh load failed err=%d step=%d" % (st["err"], st["err_step"]))
        if not report["mesh_load"]["soft_path_matches"]:
            raise ipp.Blocked("mesh soft round trip returned %r" % st["mesh_path_roundtrip"])
        mesh_obj, icon_obj = st["mesh_object"], st["icon_object"]
        run_note.append("mesh loaded: %s at 0x%x, UStaticMesh=%s, rooted=%s, store owns %d"
                        % (st["mesh_path_roundtrip"], mesh_obj,
                           report["mesh_load"]["is_staticmesh"], report["mesh_load"]["rooted"],
                           st["owned_count"]))

        if EXPECT_MATERIALS:
            report["live_material_verification"] = verify_live_materials(
                api, pid, mesh_obj, EXPECT_MATERIALS, run_note)
            run_note.append("live material verification PASSED for all %d slots"
                            % len(EXPECT_MATERIALS["slots"]))

        st = call("RunPopulate", "populate_ran")
        if st["populate_ran"] != 1:
            raise ipp.Blocked("populate failed err=%d step=%d" % (st["err"], st["err_step"]))
        row_ptr, row_key = our_row(api, pid, table_ptr)
        if not row_ptr:
            raise ipp.Blocked("no row after AddRow")
        k.WriteProcessMemory(hp, rio + SLOT_IN_OFFSET, struct.pack("<Q", row_ptr), 8,
                             ctypes.byref(wr))
        st = call("RunVerifyRow", "verifytext_ran")
        got = {"Name": st["name_row"], "ShortName": st["shortname_row"],
               "Description": st["desc_row"]}
        report["row"] = {
            "texts": got, "texts_match": got == TEXTS,
            "InventoryIcon": "0x%x" % st["row_icon_ptr"],
            "MoveIcon": "0x%x" % st["row_move_icon"],
            "icons_are_the_same_object":
                st["row_icon_ptr"] == st["row_move_icon"] == icon_obj,
            "WorldClass": "0x%x" % st["row_worldclass"],
            "worldclass_matches": st["row_worldclass"] == r["world_class"],
            "StaticMesh_pkg_fname": st["row_staticmesh_pkg"],
            "StaticMesh_asset_fname": st["row_staticmesh_asset"],
            "staticmesh_fnames_match": (st["row_staticmesh_pkg"] == st["mesh_pkg_name"]
                                        and st["row_staticmesh_asset"] == st["mesh_asset_name"]),
            "OverrideImageSize": bool(st["row_override"]),
            "drag_size": [st["row_sizex"], st["row_sizey"]],
            "ItemOffsets_scale": [st["row_scale_x"], st["row_scale_y"], st["row_scale_z"]],
            "scale_is_not_zero": (st["row_scale_x"], st["row_scale_y"],
                                  st["row_scale_z"]) == WANT_SCALE,
            "verifymesh_ran": st["verifymesh_ran"]}
        run_note.append("row after DestroyStruct(temp): texts=%s icons_same=%s worldclass=%s "
                        "mesh_fnames=%s scale=%r"
                        % (got == TEXTS, report["row"]["icons_are_the_same_object"],
                           report["row"]["worldclass_matches"],
                           report["row"]["staticmesh_fnames_match"],
                           report["row"]["ItemOffsets_scale"]))
        if not (got == TEXTS and report["row"]["icons_are_the_same_object"]
                and report["row"]["worldclass_matches"]
                and report["row"]["staticmesh_fnames_match"]
                and report["row"]["scale_is_not_zero"]):
            raise ipp.Blocked("the row did not carry the expected world metadata")

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
            "found": st["resolve_found"], "text": res_text, "text_matches": res_text == TEXTS,
            "Weight": st["resolve_weight"], "Width": st["resolve_width"],
            "Height": st["resolve_height"],
            "InventoryIcon": "0x%x" % st["resolve_icon_ptr"],
            "WorldClass": "0x%x" % st["resolve_worldclass"],
            "worldclass_matches": st["resolve_worldclass"] == r["world_class"],
            "StaticMesh_pkg_fname": st["resolve_staticmesh_pkg"],
            "StaticMesh_asset_fname": st["resolve_staticmesh_asset"],
            "staticmesh_fnames_match":
                (st["resolve_staticmesh_pkg"] == st["mesh_pkg_name"]
                 and st["resolve_staticmesh_asset"] == st["mesh_asset_name"]),
            "OverrideImageSize": bool(st["resolve_override"]),
            "drag_size": [st["resolve_sizex"], st["resolve_sizey"]],
            "ItemOffsets_scale": [st["resolve_scale_x"], st["resolve_scale_y"],
                                  st["resolve_scale_z"]],
            "scale_is_not_zero": (st["resolve_scale_x"], st["resolve_scale_y"],
                                  st["resolve_scale_z"]) == WANT_SCALE}
        run_note.append("resolver: found=%d worldclass=%s mesh_fnames=%s scale=%r"
                        % (st["resolve_found"], report["resolver"]["worldclass_matches"],
                           report["resolver"]["staticmesh_fnames_match"],
                           report["resolver"]["ItemOffsets_scale"]))
        if (st["resolve_found"] != 1 or res_text != TEXTS
                or not report["resolver"]["worldclass_matches"]
                or not report["resolver"]["staticmesh_fnames_match"]
                or not report["resolver"]["scale_is_not_zero"]):
            raise RollbackNeeded("resolver did not return the expected world definition")

        h = eri.open_process_read_only(api, pid)
        try:
            inv0 = c3d.read_inventory(api, h, r["player_inv"])
        finally:
            api.close_handle(h)
        report["pre_additem"] = {"ItemCount": inv0["item_count"],
                                 "CurrentWeight": inv0["current_weight"],
                                 "occupied": sum(1 for s in inv0["slots"] if s["occupied"]),
                                 "slots": inv0["num"]}
        st = call("RunAddItem", "additem_ran")
        if st["additem_ran"] != 1:
            raise RollbackNeeded("AddItem did not run err=%d" % st["err"])
        report["additem_out"] = {"RemainingItem": st["out_remaining_item"],
                                 "NewItemSlot": st["out_newitemslot"]}
        h = eri.open_process_read_only(api, pid)
        try:
            inv1 = c3d.read_inventory(api, h, r["player_inv"])
        finally:
            api.close_handle(h)
        ours = c3d.occupied_with(inv1, row_fname & 0xFFFFFFFF)
        changed = c3d.slot_diff(inv0, inv1)
        report["inventory"] = {
            "entries_with_item": len(ours), "slot": ours[0] if ours else None,
            "Amount": ours[0]["item"]["Amount"] if ours else None,
            "ItemCount_delta": inv1["item_count"] - inv0["item_count"],
            "CurrentWeight_delta": round(inv1["current_weight"] - inv0["current_weight"], 6),
            "slots_changed": [c["index"] for c in changed],
            "only_our_slot_changed": (len(changed) == 1 and bool(ours)
                                      and changed[0]["index"] == ours[0]["index"])}
        if len(ours) != 1:
            raise RollbackNeeded("expected one inventory entry, found %d" % len(ours))
        if ours[0]["item"]["Amount"] != 1:
            raise RollbackNeeded("Amount is %r" % ours[0]["item"]["Amount"])
        if report["inventory"]["ItemCount_delta"] != 1:
            raise RollbackNeeded("ItemCount delta %r" % report["inventory"]["ItemCount_delta"])
        if abs(report["inventory"]["CurrentWeight_delta"] - 0.5) > 1e-9:
            raise RollbackNeeded("CurrentWeight delta %r"
                                 % report["inventory"]["CurrentWeight_delta"])
        run_note.append("INVENTORY: slot %d, Amount 1, +1 count, +0.5 weight, one slot changed"
                        % ours[0]["index"])
        hold = True
        report["status"] = "READY_FOR_WORLD_DROP_VISUAL_CHECK"
        with open(STATE_PATH, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"pid": pid, "rbase": rbase, "rio": rio, "rpath": rpath, "dll": dll,
                       "row_fname": row_fname, "table_ptr": table_ptr,
                       "icon_object": icon_obj, "mesh_object": mesh_obj,
                       "player_inv": r["player_inv"], "master": r["master"],
                       "itemlist": r["itemlist"], "objects_ptr": r["objects_ptr"],
                       "struct_size": r["struct_size"], "row_name": ROW_NAME,
                       "world_class": r["world_class"],
                       "baseline_inventory_sha256": inv0["slots_sha256"],
                       "baseline_item_count": inv0["item_count"],
                       "baseline_weight": inv0["current_weight"]}, f, indent=2, sort_keys=True)
            f.write("\n")
        report["state_file"] = STATE_PATH
    except ipp.Blocked as exc:
        # A mid-run Blocked used to propagate and main() would replace the whole
        # report with {blocked, reason}, throwing away icon_load / mesh_load /
        # row -- exactly the fields needed to tell WHY it stopped. Keep them.
        blocked_reason = str(exc)
        run_note.append("BLOCKED mid-run: %s" % exc)
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
            for exp, fld in (("RunReleaseMesh", "releasemesh_ran"),
                             ("RunReleaseIcon", "releaseicon_ran"),
                             ("RunRelease", "release_ran")):
                try:
                    call(exp, fld)
                except Exception:  # noqa: BLE001
                    pass
            td = probe_teardown.shutdown_then_unload(k, hp, rbase, dll, rio, read_io_safe,
                                                    run_note) if rbase else {}
            cleanup["teardown"] = td
            if td.get("safe_to_free_remote_memory"):
                for b2 in (rpath, rio):
                    if b2 is not None:
                        k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
            try:
                cleanup["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, DLL_NAME)
            except Exception:  # noqa: BLE001
                cleanup["dll_unloaded"] = None
        else:
            cleanup["held_for_visual_check"] = True
            run_note.append("HOLDING: module, IO, table root, icon root, MESH root and "
                            "publication alive")
        k.CloseHandle(hp)
    report["cleanup"] = cleanup
    td = cleanup.get("teardown") or {}
    if blocked_reason:
        report["blocked"] = True
        report["reason"] = blocked_reason
        report["verdict"] = "BLOCKED"
    elif td.get("attempted") and not td.get("unloaded"):
        report["verdict"] = "BLOCKED-TEARDOWN"
        report["teardown_blocked"] = td.get("left_loaded_reason")
    elif hold:
        report["verdict"] = "HELD"
    else:
        report["verdict"] = "NOT-HELD"
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arm", action="store_true",
                    help="materialize the world item, AddItem one, and HOLD")
    ap.add_argument("--probe", action="store_true",
                    help="materialize the TEMPORARY ARM/emissive probe item instead of the "
                         "production radio: a separate row, the probe mesh whose slots carry "
                         "the asymmetric ARM MICs, and its own state file")
    ap.add_argument("--probe4", action="store_true",
                    help="probe 4: the ARM A/B plus an emissive test isolated from specular "
                         "-- near-black base, metallic 0 and roughness 1 under EITHER ARM "
                         "reading, with an identical no-emissive control beside it")
    ap.add_argument("--probe3", action="store_true",
                    help="the CORRECTED probe: distinct package path, slot assignment "
                         "verified on disk, and a mandatory live material check before "
                         "AddItem")
    ap.add_argument("--probe2", action="store_true",
                    help="the SECOND ARM/emissive probe: four large separated boxes with a "
                         "known-metallic reference box, mirror-low roughness and a saturated "
                         "red base, after the first probe proved visually ambiguous")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    if a.probe4:
        g = globals()
        g["ROW_NAME"] = "mbpl__probe4"
        g["TRIGGER_NAME"] = "mbpl__probe4_neutral_trigger"
        g["STATE_PATH"] = os.path.join(REPO, "workspace", "probe4-demo-state.json")
        g["MESH_PACKAGE"] = "/Game/MBPLProbe4/SM_Probe4"
        g["MESH_ASSET"] = "SM_Probe4"
        g["TEXTS"] = {"Name": "MBPL Probe 4",
                      "ShortName": "Probe 4",
                      "Description": "REF / A / B are the ARM test; EM and CTRL are an "
                                     "identical near-black pair, EM emissive and CTRL not."}
        d = "/Game/MBPLProbe4"
        red, black, nrm = (d + "/T4_BC_Red.T4_BC_Red", d + "/T4_BC_Black.T4_BC_Black",
                           d + "/T4_N.T4_N")
        g["EXPECT_MATERIALS"] = {
            "parent": "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial."
                      "M_BasicMaterial",
            "slots": [
                {"slot_name": "M_P4_REF", "mic": d + "/MI_P4_REF.MI_P4_REF",
                 "textures": {"BaseColor": red, "ARM": d + "/T4_ARM_REF.T4_ARM_REF",
                              "Normal": nrm}},
                {"slot_name": "M_P4_A", "mic": d + "/MI_P4_A.MI_P4_A",
                 "textures": {"BaseColor": red, "ARM": d + "/T4_ARM_A.T4_ARM_A",
                              "Normal": nrm}},
                {"slot_name": "M_P4_B", "mic": d + "/MI_P4_B.MI_P4_B",
                 "textures": {"BaseColor": red, "ARM": d + "/T4_ARM_B.T4_ARM_B",
                              "Normal": nrm}},
                {"slot_name": "M_P4_EM", "mic": d + "/MI_P4_EM.MI_P4_EM",
                 "textures": {"BaseColor": black, "ARM": d + "/T4_ARM_DARK.T4_ARM_DARK",
                              "Normal": nrm}},
                {"slot_name": "M_P4_CTRL", "mic": d + "/MI_P4_CTRL.MI_P4_CTRL",
                 "textures": {"BaseColor": black, "ARM": d + "/T4_ARM_DARK.T4_ARM_DARK",
                              "Normal": nrm}},
            ]}
    elif a.probe3:
        g = globals()
        g["ROW_NAME"] = "mbpl__armprobe3"
        g["TRIGGER_NAME"] = "mbpl__armprobe3_neutral_trigger"
        g["STATE_PATH"] = os.path.join(REPO, "workspace", "armprobe3-demo-state.json")
        g["MESH_PACKAGE"] = "/Game/MBPLArmProbe3/SM_ArmProbe3"
        g["MESH_ASSET"] = "SM_ArmProbe3"
        g["TEXTS"] = {"Name": "MBPL ARM Probe 3",
                      "ShortName": "ARM Probe 3",
                      "Description": "Four boxes, left to right: REFERENCE (metallic under "
                                     "either reading), A (R-hot), B (B-hot), EMISSIVE probe."}
        # Every one of these is asserted against the LIVE process before AddItem.
        # The MIC -> vanilla parent import has never resolved successfully even
        # once, so it is checked rather than assumed.
        d = "/Game/MBPLArmProbe3"
        g["EXPECT_MATERIALS"] = {
            "parent": "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial."
                      "M_BasicMaterial",
            "slots": [
                {"slot_name": "M_Probe_REF", "mic": d + "/MI_P2_REF.MI_P2_REF",
                 "textures": {"BaseColor": d + "/T2_BC_Red.T2_BC_Red",
                              "ARM": d + "/T2_ARM_REF.T2_ARM_REF",
                              "Normal": d + "/T2_N.T2_N"}},
                {"slot_name": "M_Probe_A", "mic": d + "/MI_P2_A.MI_P2_A",
                 "textures": {"BaseColor": d + "/T2_BC_Red.T2_BC_Red",
                              "ARM": d + "/T2_ARM_A.T2_ARM_A",
                              "Normal": d + "/T2_N.T2_N"}},
                {"slot_name": "M_Probe_B", "mic": d + "/MI_P2_B.MI_P2_B",
                 "textures": {"BaseColor": d + "/T2_BC_Red.T2_BC_Red",
                              "ARM": d + "/T2_ARM_B.T2_ARM_B",
                              "Normal": d + "/T2_N.T2_N"}},
                {"slot_name": "M_Probe_EM", "mic": d + "/MI_P2_EM.MI_P2_EM",
                 "textures": {"BaseColor": d + "/T2_BC_Grey.T2_BC_Grey",
                              "ARM": d + "/T2_ARM_EM.T2_ARM_EM",
                              "Normal": d + "/T2_N.T2_N"}},
            ]}
    elif a.probe2:
        g = globals()
        g["ROW_NAME"] = "mbpl__armprobe2"
        g["TRIGGER_NAME"] = "mbpl__armprobe2_neutral_trigger"
        g["STATE_PATH"] = os.path.join(REPO, "workspace", "armprobe2-demo-state.json")
        g["MESH_PACKAGE"] = "/Game/MBPLArmProbe2/SM_ArmProbe2"
        g["MESH_ASSET"] = "SM_ArmProbe2"
        g["TEXTS"] = {"Name": "MBPL ARM Probe 2",
                      "ShortName": "ARM Probe 2",
                      "Description": "Four boxes, left to right: REFERENCE (metallic under "
                                     "either reading), A (R-hot), B (B-hot), EMISSIVE probe."}
    elif a.probe:
        # A distinct row and state file, so the probe can never be confused with
        # the production item or clean it up by accident.
        g = globals()
        g["ROW_NAME"] = "mbpl__armprobe"
        g["TRIGGER_NAME"] = "mbpl__armprobe_neutral_trigger"
        g["STATE_PATH"] = os.path.join(REPO, "workspace", "armprobe-demo-state.json")
        g["MESH_PACKAGE"] = "/Game/MBPLMatProbe/SM_MatProbe_Radio"
        g["MESH_ASSET"] = "SM_MatProbe_Radio"
        g["TEXTS"] = {"Name": "MBPL ARM Probe",
                      "ShortName": "ARM Probe",
                      "Description": "Temporary channel-order probe. Slot 0 is R-hot; "
                                     "the rest are B-hot; the last slot probes emissive."}
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
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        if rep.get("verdict") == "BLOCKED-TEARDOWN":
            code = 2
        print(json.dumps({kk: rep[kk] for kk in rep if kk not in ("run_note", "fields",
                                                                  "text_fields")},
                         indent=2, sort_keys=True, default=str))
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": note}
        if a.arm and va is None:
            try:
                va = ipp.run_verify_install(rdir, "after")
                if va.get("report_artifact"):
                    arts.append(va["report_artifact"])
                note.append("run aborted; verify_install after-check still performed")
            except Exception:  # noqa: BLE001
                pass
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str)
            f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(rdir, arguments=arguments,
                           capabilities_enabled=(["CR-01C5"] if a.arm else ["I-01"]),
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=arts,
                           instrument_level=("ipp" if a.arm else "eri"))
    return code


if __name__ == "__main__":
    sys.exit(main())
