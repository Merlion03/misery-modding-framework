#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C3 preconditions.

Answers, before any gameplay mutation is even considered:

  1. which UFunctions actually face AddItem, on which class, and their exact
     reflected parameter ABI (no guessed parameters -- reflection only),
  2. which live inventory instances exist and which one is the player's,
  3. the authority / networking context (NetMode, GameMode, role) and whether
     the candidate function carries any FUNC_Net* / FUNC_BlueprintAuthorityOnly
     flag,
  4. the current ItemList baseline and that the probe row name is absent,
  5. a snapshot of the target inventory's live slot array.

Opens the process PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only. It writes
nothing, calls nothing, and allocates nothing in the target.
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

# UObject/Script.h EFunctionFlags -- transcribed from the UE 5.4.4 source tree.
FUNC = {
    "FUNC_Final": 0x00000001, "FUNC_RequiredAPI": 0x00000002,
    "FUNC_BlueprintAuthorityOnly": 0x00000004, "FUNC_BlueprintCosmetic": 0x00000008,
    "FUNC_Net": 0x00000040, "FUNC_NetReliable": 0x00000080,
    "FUNC_NetRequest": 0x00000100, "FUNC_Exec": 0x00000200,
    "FUNC_Native": 0x00000400, "FUNC_Event": 0x00000800,
    "FUNC_NetResponse": 0x00001000, "FUNC_Static": 0x00002000,
    "FUNC_NetMulticast": 0x00004000, "FUNC_UbergraphFunction": 0x00008000,
    "FUNC_MulticastDelegate": 0x00010000, "FUNC_Public": 0x00020000,
    "FUNC_Private": 0x00040000, "FUNC_Protected": 0x00080000,
    "FUNC_Delegate": 0x00100000, "FUNC_NetServer": 0x00200000,
    "FUNC_HasOutParms": 0x00400000, "FUNC_HasDefaults": 0x00800000,
    "FUNC_NetClient": 0x01000000, "FUNC_DLLImport": 0x02000000,
    "FUNC_BlueprintCallable": 0x04000000, "FUNC_BlueprintEvent": 0x08000000,
    "FUNC_BlueprintPure": 0x10000000, "FUNC_EditorOnly": 0x20000000,
    "FUNC_Const": 0x40000000, "FUNC_NetValidate": 0x80000000,
}
NET_FLAGS = ("FUNC_Net", "FUNC_NetReliable", "FUNC_NetServer", "FUNC_NetClient",
             "FUNC_NetMulticast", "FUNC_NetRequest", "FUNC_NetResponse",
             "FUNC_NetValidate", "FUNC_BlueprintAuthorityOnly")

CPF = {
    "CPF_Parm": 0x0000000000000080, "CPF_OutParm": 0x0000000000000100,
    "CPF_ReturnParm": 0x0000000000000400, "CPF_ConstParm": 0x0000000000000002,
    "CPF_ReferenceParm": 0x0000000008000000,
}

# S_InvSlot / S_InvItem layouts, OBSERVED in CR-01B (architecture.json).
OFF_INVENTORY_ARRAY = 336        # BP_MasterInventory_C::Inventory  TArray<S_InvSlot>
S_INVITEM_SIZE = 48
INVITEM = {"ID": (0, "FName"), "Amount": (8, "int32"), "MasterInventory": (16, "ptr"),
           "QuickBindIndex": (24, "int32"), "Rotated": (28, "bool"),
           "UseAmount": (32, "int32"), "InUse": (36, "bool"),
           "Durability": (40, "float"), "DecayTime": (44, "int32")}

INVENTORY_KEYWORDS = ("Inventory",)
FUNCTION_NAME_HINTS = ("AddItem", "AttemptToAdd", "ChangeItemCount", "CloneItem",
                       "AttemptToAddItemToSlot", "AttemptToAddItemAmount",
                       "AddItemToSlot", "CreateItem", "GiveItem", "SpawnItem")


class Blocked(Exception):
    pass


def decode_func_flags(flags):
    return sorted(n for n, b in FUNC.items() if flags & b)


def universe(api, h, base, size, with_meta=False):
    """Walk the WHOLE GUObjectArray, and prove it.

    eri.DEFAULT_I02_MAX_SCAN_INDICES is 200_000, which was comfortably above the
    object count when it was chosen. It no longer is: a loaded MISERY session
    reaches ~263_000 objects, and everything spawned late -- the player pawn,
    the player controller, its inventory component, anything created after a
    save reload -- lands at the HIGH indices that the cap silently dropped. A
    truncated universe does not fail loudly; it just answers "not found", which
    reads exactly like "does not exist". That cost one wrong conclusion already.

    So the cap is derived from NumElements rather than from a constant, and the
    walker's own coverage is checked afterwards: if it looked at fewer indices
    than the array holds, that is an error, not a footnote.
    """
    i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    num = int(i02["num_elements"])
    i03 = eri.run_i03(api, h, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                      name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                      name_entry_id=0)
    np = i03["namepool_live_va"]
    w = eri.walk_object_universe(api, h, i02["objects_ptr_live_va"], num,
                                 base, size, np,
                                 class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                 name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                 outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                 max_scan_indices=num)
    scanned = w.get("scanned_indices", w.get("indices_scanned"))
    if scanned is not None and int(scanned) < num:
        raise Blocked("object universe truncated: walked %d of %d indices; every "
                      "'not found' from this snapshot would be unsound"
                      % (int(scanned), num))
    if with_meta:
        # The GUObjectArray base, so a caller can reach FUObjectItem for the
        # things that live there and nowhere else: the internal object flags
        # (is this object garbage?) and SerialNumber (is this the SAME object,
        # or a different one at a reused address?). Opt-in, so every existing
        # caller keeps the two-value contract it was written against.
        return np, w["objects_by_address"], {"objects_ptr": i02["objects_ptr_live_va"],
                                             "num_elements": num}
    return np, w["objects_by_address"]


def find_function_meta(objs):
    for a, r in objs.items():
        if r.get("name_ok") and r.get("name_text") == "Function":
            if eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objs).get("object_path")) == "/Script/CoreUObject.Function":
                return a
    return None


def class_functions(api, h, np, cls_addr, fmeta):
    ch = eri.walk_children_chain(
        api, h, eri._read_u64(api, h, cls_addr + eri.USTRUCT_CHILDREN_OFFSET),
        namepool_live_va=np, owner_address=cls_addr, function_class_address=fmeta)
    return ch.get("accepted", [])


def function_abi(api, h, np, faddr, objs=None):
    flags = eri._read_u32(api, h, faddr + eri.UFUNCTION_FUNCTION_FLAGS_OFFSET)
    num_parms = eri._read_u8(api, h, faddr + eri.UFUNCTION_NUM_PARMS_OFFSET)
    parms_size = eri._read_u16(api, h, faddr + eri.UFUNCTION_PARMS_SIZE_OFFSET)
    rvo = eri._read_u16(api, h, faddr + eri.UFUNCTION_RETURN_VALUE_OFFSET_OFFSET)
    cp = eri._read_u64(api, h, faddr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    props = eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=faddr,
                                    objects_by_address=objs)
    params = []
    for pr in props.get("accepted", []):
        raw = pr.get("property_flags_raw")
        pf = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
        if not (pf & CPF["CPF_Parm"]):
            continue
        params.append({
            "name": pr.get("raw_name"), "property_class": pr.get("property_class"),
            "offset": pr.get("offset"), "size": pr.get("size"),
            "total_size": pr.get("total_size"), "array_dim": pr.get("array_dim"),
            "type": pr.get("property_type"),
            "flags_hex": "0x%x" % pf,
            "is_return": bool(pf & CPF["CPF_ReturnParm"]),
            "is_out": bool(pf & CPF["CPF_OutParm"]),
            "is_ref": bool(pf & CPF["CPF_ReferenceParm"]),
            "is_const": bool(pf & CPF["CPF_ConstParm"]),
        })
    params.sort(key=lambda x: x["offset"] if x["offset"] is not None else 1 << 30)
    net = [n for n in NET_FLAGS if flags & FUNC[n]]
    return {"address": "0x%x" % faddr, "function_flags": "0x%x" % flags,
            "function_flags_decoded": decode_func_flags(flags),
            "net_or_authority_flags": net,
            "is_networked": bool(net),
            "num_parms": num_parms, "parms_size": parms_size,
            "return_value_offset": rvo, "parameters": params}


def read_tarray(api, h, addr):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    cap = struct.unpack("<i", api.read_process_memory(h, addr + 12, 4))[0]
    return data, num, cap


def decode_invitem(api, h, np, addr):
    raw = api.read_process_memory(h, addr, S_INVITEM_SIZE)
    fid = struct.unpack_from("<I", raw, 0)[0]
    name = None
    try:
        d = eri.decode_fname_entry_id(api, h, np, fid)
        name = d.get("text") if isinstance(d, dict) else None
    except Exception:  # noqa: BLE001
        name = None
    return {
        "ID_entry_id": fid, "ID_name": name,
        "Amount": struct.unpack_from("<i", raw, 8)[0],
        "MasterInventory": "0x%x" % struct.unpack_from("<Q", raw, 16)[0],
        "QuickBindIndex": struct.unpack_from("<i", raw, 24)[0],
        "Rotated": raw[28], "UseAmount": struct.unpack_from("<i", raw, 32)[0],
        "InUse": raw[36], "Durability": struct.unpack_from("<f", raw, 40)[0],
        "DecayTime": struct.unpack_from("<i", raw, 44)[0],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None)
    ap.add_argument("--slot-struct-size", type=int, default=None,
                    help="sizeof(S_InvSlot); resolved by reflection when omitted")
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size = i01["pid"], i01["base_address"], i01["image_size_bytes"]
    h = eri.open_process_read_only(api, pid)
    rep = {"pid": pid, "read_only": True}
    try:
        np, objs = universe(api, h, base, size)
        fmeta = find_function_meta(objs)
        if fmeta is None:
            raise Blocked("Function meta-class not found")

        # ---- 1. inventory classes and their live instances -------------------
        inv_classes, itemlist, scriptstructs = {}, None, {}
        by_class = {}
        for addr, r in objs.items():
            cp = r.get("class_ptr") or 0
            by_class.setdefault(cp, []).append(addr)
        for addr, r in objs.items():
            if not r.get("name_ok"):
                continue
            nm = r.get("name_text") or ""
            cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
            if cn in ("Class", "BlueprintGeneratedClass") and any(k in nm for k in INVENTORY_KEYWORDS):
                inv_classes[nm] = {
                    "address": "0x%x" % addr,
                    "object_path": eri.resolve_object_path(addr, objs).get("object_path"),
                    "class_meta": cn,
                    "live_instances": len([x for x in by_class.get(addr, []) if x != addr]),
                }
            if nm == "ItemList" and cn == "DataTable":
                itemlist = addr
            if cn in ("ScriptStruct", "UserDefinedStruct") and nm in (
                    "S_InvSlot", "S_InvItem", "S_ItemDetails", "DataTableRowHandle"):
                scriptstructs[nm] = addr
        rep["inventory_classes"] = inv_classes
        rep["scriptstructs"] = {k: "0x%x" % v for k, v in scriptstructs.items()}

        # sizeof(S_InvSlot) by reflection, never assumed
        slot_size = a.slot_struct_size
        if slot_size is None and "S_InvSlot" in scriptstructs:
            slot_size = struct.unpack("<i", api.read_process_memory(
                h, scriptstructs["S_InvSlot"] + 0x58, 4))[0]
        rep["s_invslot_size"] = slot_size
        if "S_InvItem" in scriptstructs:
            rep["s_invitem_size"] = struct.unpack("<i", api.read_process_memory(
                h, scriptstructs["S_InvItem"] + 0x58, 4))[0]

        # ---- 2. live instances of every inventory class ----------------------
        instances = []
        for nm, meta in inv_classes.items():
            caddr = int(meta["address"], 16)
            for obj in by_class.get(caddr, []):
                if obj == caddr:
                    continue
                orec = objs.get(obj) or {}
                instances.append({
                    "class": nm, "address": "0x%x" % obj,
                    "name": orec.get("name_text"),
                    "object_path": eri.resolve_object_path(obj, objs).get("object_path"),
                })
        rep["live_inventory_instances"] = instances

        # ---- 3. AddItem-facing functions on every inventory class -----------
        fns = {}
        for nm, meta in inv_classes.items():
            caddr = int(meta["address"], 16)
            try:
                chain = class_functions(api, h, np, caddr, fmeta)
            except Exception as exc:  # noqa: BLE001
                fns[nm] = {"error": str(exc)}
                continue
            names = sorted(f.get("raw_name") for f in chain if f.get("raw_name"))
            hits = {}
            for f in chain:
                fn_name = f.get("raw_name") or ""
                if any(hint.lower() in fn_name.lower() for hint in FUNCTION_NAME_HINTS):
                    hits[fn_name] = function_abi(api, h, np, f["address"], objs)
            fns[nm] = {"function_count": len(names), "all_function_names": names,
                       "add_item_candidates": hits}
        rep["functions"] = fns

        # ---- 4. ItemList baseline -------------------------------------------
        if itemlist:
            rows, diag = rdr.read_rowmap(api, h, itemlist)
            rep["itemlist"] = {"address": "0x%x" % itemlist, "row_count": len(rows),
                               "rowmap_diag": diag}
        else:
            rep["itemlist"] = None

        # ---- 5. authority / world context -----------------------------------
        ctx = {}
        for addr, r in objs.items():
            if not r.get("name_ok"):
                continue
            cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") or ""
            nm = r.get("name_text") or ""
            if cn == "World":
                ctx.setdefault("worlds", []).append(
                    {"address": "0x%x" % addr, "name": nm,
                     "path": eri.resolve_object_path(addr, objs).get("object_path")})
            elif cn.endswith("GameInstance") or nm.startswith("Default__") is False and cn == "GameInstance":
                ctx.setdefault("game_instances", []).append(
                    {"address": "0x%x" % addr, "name": nm, "class": cn})
            elif "GameMode" in cn and not nm.startswith("Default__"):
                ctx.setdefault("game_modes", []).append(
                    {"address": "0x%x" % addr, "name": nm, "class": cn})
            elif "PlayerController" in cn and not nm.startswith("Default__"):
                ctx.setdefault("player_controllers", []).append(
                    {"address": "0x%x" % addr, "name": nm, "class": cn})
            elif "NetDriver" in cn and not nm.startswith("Default__"):
                ctx.setdefault("net_drivers", []).append(
                    {"address": "0x%x" % addr, "name": nm, "class": cn})
        rep["world_context"] = ctx

        # ---- 6. slot arrays on every live inventory instance ----------------
        snaps = []
        for inst in instances:
            iaddr = int(inst["address"], 16)
            try:
                data, num, cap = read_tarray(api, h, iaddr + OFF_INVENTORY_ARRAY)
            except Exception as exc:  # noqa: BLE001
                snaps.append({**inst, "error": str(exc)})
                continue
            entry = {**inst, "inventory_array": {"data": "0x%x" % data, "num": num, "max": cap}}
            snaps.append(entry)
        rep["inventory_snapshots"] = snaps

        rep["blocked"] = False
    except Blocked as exc:
        rep["blocked"] = True
        rep["reason"] = str(exc)
    finally:
        api.close_handle(h)

    out = json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=False)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(out + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
