#!/usr/bin/env python3
"""STRICTLY READ-ONLY reconciliation after the owner's death + respawn.

The Shipping process was replaced (17036 -> a new pid), so NOTHING recorded in
workspace/c5-demo-state.json is usable: every address in it belonged to an image
that no longer exists, and FName comparison indices are allocation-ordered per
process, so even the row's numeric id is meaningless now. This script resolves
everything from scratch against the pid it finds, and proves the stale state is
stale rather than assuming it.

It answers, in order:
  1. process identity + build fingerprint
  2. is the recorded pid actually gone
  3. is our runtime DataTable / MasterItemList publication still in place
  4. does the row mbpl__radio exist in ItemList
  5. does ANY live inventory slot or world actor carry mbpl__radio
  6. are SM_MBPL_Radio / the 7 MICs / their textures currently loaded

Nothing is written into the game process. No pointer from the previous run is
dereferenced -- the old values are only compared, never followed.
"""
import json
import os
import struct
import sys

REPO = "D:/Dev/MiseryFramework"
for p in (os.path.join(REPO, "research", "instruments", "eri"),
          os.path.join(REPO, "research", "instruments", "ipp"),
          os.path.join(REPO, "tools", "reflection")):
    sys.path.insert(0, p)
import eri                                  # noqa: E402
import cr01c3_recon as recon                # noqa: E402
import cr01c3d_controller as c3d            # noqa: E402
import read_datatable_rows as rdr           # noqa: E402
from cr01c3b_controller import OFF_PARENT_TABLES  # noqa: E402

ROW_NAME = "mbpl__radio"
WORLD_CLASS = "BP_StaticMasterItem_C"
INVITEM_OFF = 704
SM_STATICMATERIALS = 344
MI_PARENT = 272
MI_TEXTURE = 408
MI_TEXTURE_STRIDE = 40

ORDER = ["Body", "Battery", "Metal", "Rubber", "Screen", "Emissive", "Tape"]
WANT_PARENT = ("/Game/PlayerElectricitySystem/Materials/M_BasicMaterial."
               "M_BasicMaterial")
DIR = "/Game/MBPLTest/Items/Radio"


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    rep = {"pid": i01["pid"], "build_sha256": i01.get("build_sha256"),
           "base_address": "0x%x" % i01["base_address"]}

    stale_path = os.path.join(REPO, "workspace", "c5-demo-state.json")
    stale = json.load(open(stale_path, encoding="utf-8")) if os.path.exists(stale_path) else {}
    rep["stale_state"] = {
        "file": stale_path,
        "recorded_pid": stale.get("pid"),
        "recorded_pid_is_the_live_pid": stale.get("pid") == i01["pid"],
        "recorded_row_fname": stale.get("row_fname"),
        "verdict": ("STALE -- recorded pid %r is not the live pid %d; every address and the "
                    "FName id in this file belong to a dead image and are NOT used below"
                    % (stale.get("pid"), i01["pid"]))}

    h = eri.open_process_read_only(api, i01["pid"])
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        rep["universe_objects"] = len(objs)

        def nm(a):
            return (objs.get(a) or {}).get("name_text") if a else None

        def cls_of(a):
            return nm(eri._read_u64(api, h, a + eri.DEFAULT_CLASS_PRIVATE_OFFSET)) if a else None

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

        def one(name, clsname):
            c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == name
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
            return c[0] if len(c) == 1 else None

        # ---- 3. publication state -------------------------------------------
        master = one("MasterItemList", "CompositeDataTable")
        itemlist = one("ItemList", "DataTable")
        if not master or not itemlist:
            raise SystemExit("MasterItemList/ItemList not uniquely resolved")
        data = eri._read_u64(api, h, master + OFF_PARENT_TABLES)
        pnum = struct.unpack("<i", api.read_process_memory(
            h, master + OFF_PARENT_TABLES + 8, 4))[0]
        parents = []
        if data and 0 < pnum <= 64:
            raw = api.read_process_memory(h, data, pnum * 8)
            for i in range(pnum):
                t = struct.unpack_from("<Q", raw, i * 8)[0]
                parents.append({"table": "0x%x" % t, "name": nm(t), "path": path_of(t)})
        rep["publication"] = {
            "MasterItemList": "0x%x" % master, "ItemList": "0x%x" % itemlist,
            "ParentTables_count": pnum, "ParentTables": parents,
            "foreign_parent_tables": [p for p in parents
                                      if (p["path"] or "").startswith("/Engine/Transient")]}
        rep["runtime_tables_in_transient"] = [
            {"object": "0x%x" % a, "name": nm(a), "path": path_of(a)}
            for a in objs
            if cls_of(a) == "DataTable" and (path_of(a) or "").startswith("/Engine/Transient")]

        # ---- 4. is the row present in ItemList? ------------------------------
        def keys_of(table):
            # read_rowmap returns (rows, diag); rows = [(cmp_index, number, value_ptr)]
            try:
                rows, diag = rdr.read_rowmap(api, h, table)
            except Exception as exc:  # noqa: BLE001
                return None, "unreadable: %s" % exc
            return [fname(cmp_index) for cmp_index, _num, _v in rows], diag

        il_keys, il_diag = keys_of(itemlist)
        ml_keys, ml_diag = keys_of(master)
        rep["ItemList_rows"] = {"count": None if il_keys is None else len(il_keys),
                                "diag": il_diag,
                                "contains_our_row": bool(il_keys) and ROW_NAME in il_keys}
        rep["MasterItemList_own_rows"] = {"count": None if ml_keys is None else len(ml_keys),
                                          "diag": ml_diag,
                                          "contains_our_row": bool(ml_keys)
                                          and ROW_NAME in ml_keys}
        rep["row_present_anywhere"] = (rep["ItemList_rows"]["contains_our_row"]
                                       or rep["MasterItemList_own_rows"]["contains_our_row"])

        # ---- 5. does anything live carry the row? ----------------------------
        # The FName id is NOT taken from the stale file. Every candidate id is
        # decoded to text in THIS process and compared as a string.
        pi_cls = one("BP_PlayerInventory_C", "BlueprintGeneratedClass")
        invs = []
        for a, r in objs.items():
            if r.get("class_ptr") != pi_cls:
                continue
            n = r.get("name_text") or ""
            if n.startswith("Default__") or "GEN_VARIABLE" in n:
                continue
            owner = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
            if cls_of(owner) == "BP_SGKController_C":
                invs.append(a)
        rep["live_player_inventories"] = ["0x%x" % a for a in invs]
        carriers = []
        for a in invs:
            st = c3d.read_inventory(api, h, a)
            for s in st["slots"]:
                if not s["occupied"]:
                    continue
                t = fname(s["item"]["ID"] & 0xFFFFFFFF)
                if t == ROW_NAME:
                    carriers.append({"where": "inventory 0x%x" % a, "slot": s["index"],
                                     "Amount": s["item"]["Amount"]})
            rep.setdefault("inventory_summary", []).append(
                {"inventory": "0x%x" % a, "slots": st["num"],
                 "occupied": sum(1 for s in st["slots"] if s["occupied"]),
                 "ItemCount": st["item_count"], "CurrentWeight": st["current_weight"]})

        wc = one(WORLD_CLASS, "BlueprintGeneratedClass")
        world_actors = 0
        if wc:
            for a, r in objs.items():
                if r.get("class_ptr") != wc:
                    continue
                if (r.get("name_text") or "").startswith("Default__"):
                    continue
                world_actors += 1
                try:
                    eid = struct.unpack("<I", api.read_process_memory(
                        h, a + INVITEM_OFF, 4))[0]
                except Exception:  # noqa: BLE001
                    continue
                if fname(eid) == ROW_NAME:
                    carriers.append({"where": "world actor 0x%x" % a, "name": nm(a)})
        rep["world_item_actors_live"] = world_actors
        rep["instances_carrying_our_row"] = carriers
        rep["no_instance_carries_our_row"] = not carriers

        # ---- 6. is the production content currently loaded? -------------------
        def loaded(name, want_cls=None):
            hits = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == name]
            if want_cls:
                hits = [a for a in hits if cls_of(a) == want_cls]
            return [{"object": "0x%x" % a, "class": cls_of(a), "path": path_of(a)} for a in hits]

        content = {"SM_MBPL_Radio": loaded("SM_MBPL_Radio", "StaticMesh")}
        for k in ORDER:
            content["MI_Radio_%s" % k] = loaded("MI_Radio_%s" % k, "MaterialInstanceConstant")
            content["T_Radio_%s_BC" % k] = loaded("T_Radio_%s_BC" % k, "Texture2D")
            content["T_Radio_%s_ARM" % k] = loaded("T_Radio_%s_ARM" % k, "Texture2D")
        content["T_Radio_Neutral_N"] = loaded("T_Radio_Neutral_N", "Texture2D")
        content["M_BasicMaterial"] = loaded("M_BasicMaterial", "Material")
        rep["content_currently_loaded"] = content
        rep["content_loaded_counts"] = {k: len(v) for k, v in content.items()}

        # If the mesh happens to be loaded, verify its slots right now.
        mesh_hits = [int(x["object"], 16) for x in content["SM_MBPL_Radio"]]
        if len(mesh_hits) == 1:
            mesh = mesh_hits[0]
            ss = [a for a, r in objs.items() if r.get("name_ok")
                  and r.get("name_text") == "StaticMaterial" and cls_of(a) == "ScriptStruct"]
            if len(ss) == 1:
                stride = struct.unpack("<i", api.read_process_memory(h, ss[0] + 0x58, 4))[0]
                d = eri._read_u64(api, h, mesh + SM_STATICMATERIALS)
                n = struct.unpack("<i", api.read_process_memory(
                    h, mesh + SM_STATICMATERIALS + 8, 4))[0]
                slots = []
                if d and 0 < n < 64:
                    blob = api.read_process_memory(h, d, n * stride)
                    for i in range(n):
                        mi = struct.unpack_from("<Q", blob, i * stride)[0]
                        sn = fname(struct.unpack_from("<I", blob, i * stride + 8)[0])
                        parent = eri._read_u64(api, h, mi + MI_PARENT) if mi else 0
                        tex = {}
                        if mi:
                            td = eri._read_u64(api, h, mi + MI_TEXTURE)
                            tn = struct.unpack("<i", api.read_process_memory(
                                h, mi + MI_TEXTURE + 8, 4))[0]
                            if td and 0 < tn < 32:
                                tb = api.read_process_memory(h, td, tn * MI_TEXTURE_STRIDE)
                                for j in range(tn):
                                    pn = fname(struct.unpack_from(
                                        "<I", tb, j * MI_TEXTURE_STRIDE)[0])
                                    t = struct.unpack_from(
                                        "<Q", tb, j * MI_TEXTURE_STRIDE + 16)[0]
                                    tex[pn] = path_of(t)
                        slots.append({"slot": i, "slot_name": sn, "mic": path_of(mi),
                                      "parent": path_of(parent),
                                      "parent_class": cls_of(parent), "textures": tex})
                rep["mesh_slots_now"] = slots
                rep["mesh_slots_all_correct"] = (
                    len(slots) == 7
                    and all(s["parent"] == WANT_PARENT and s["parent_class"] == "Material"
                            and s["mic"] == "%s/MI_Radio_%s.MI_Radio_%s"
                            % (DIR, ORDER[i], ORDER[i])
                            for i, s in enumerate(slots)))
        else:
            rep["mesh_slots_now"] = None
            rep["mesh_slots_note"] = (
                "SM_MBPL_Radio is not resident: %d live UStaticMesh objects with that name. "
                "Expected in a process that has never spawned the item -- nothing has "
                "referenced the package yet. The definitive slot/parent/texture check is the "
                "mandatory live verification the arm path runs AFTER LoadAsset_Blocking and "
                "BEFORE AddItem." % len(mesh_hits))
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reconcile_after_death.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    slim = dict(rep)
    slim.pop("content_currently_loaded", None)
    print(json.dumps(slim, indent=2, sort_keys=False, default=str))


if __name__ == "__main__":
    main()
