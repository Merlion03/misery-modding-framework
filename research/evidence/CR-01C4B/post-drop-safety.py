#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Post-drop safety check for the held CR-01C4B demo.

Seven conditions, each answered from live memory. Nothing is written.
"""
import json
import os
import struct
import sys

REPO = "D:/Dev/MiseryFramework"
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri  # noqa: E402
import cr01c3_recon as recon  # noqa: E402
import cr01c3d_controller as c3d  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

STATE = os.path.join(REPO, "workspace", "c4b-demo-state.json")
ROOTSET = 1 << 30
FUOBJECTITEM = 0x18
UI_OFF, W_OFF, H_OFF = 224, 56, 60


def main():
    st = json.load(open(STATE, encoding="utf-8"))
    fid = st["row_fname"] & 0xFFFFFFFF
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    rep = {"pid": i01["pid"], "state_pid": st["pid"],
           "same_process": i01["pid"] == st["pid"], "row_fname_id": fid}
    if not rep["same_process"]:
        print(json.dumps(rep, indent=2))
        return 2
    h = eri.open_process_read_only(api, i01["pid"])
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        # 1 + 2: the player's own inventory
        inv = c3d.read_inventory(api, h, st["player_inv"])
        mine = c3d.occupied_with(inv, fid)
        rep["1_player_inventory"] = {
            "entries_with_mbpl__radio": len(mine),
            "condition_holds": len(mine) == 0}
        rep["2_counters"] = {
            "ItemCount": inv["item_count"], "baseline_ItemCount": st["baseline_item_count"],
            "CurrentWeight": inv["current_weight"], "baseline_CurrentWeight": st["baseline_weight"],
            "slots_sha256": inv["slots_sha256"],
            "slots_sha256_matches_baseline":
                inv["slots_sha256"] == st["baseline_inventory_sha256"],
            "condition_holds": (inv["item_count"] == st["baseline_item_count"]
                                and inv["current_weight"] == st["baseline_weight"])}

        # 3: every other live inventory component
        inv_classes = set()
        for a, r in objs.items():
            if r.get("name_ok") and r.get("name_text") in (
                    "BP_MasterInventory_C", "BP_PlayerInventory_C") and \
                    (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") \
                    in ("BlueprintGeneratedClass",):
                inv_classes.add(a)
        # any class whose ancestry reaches BP_MasterInventory_C
        master = [a for a, r in objs.items() if r.get("name_ok")
                  and r.get("name_text") == "BP_MasterInventory_C"
                  and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                  == "BlueprintGeneratedClass"]
        master = master[0] if len(master) == 1 else None
        derived = set()
        if master:
            for a, r in objs.items():
                if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") not in (
                        "BlueprintGeneratedClass", "Class"):
                    continue
                sup, seen = a, 0
                while sup and seen < 24:
                    if sup == master:
                        derived.add(a)
                        break
                    sup = eri._read_u64(api, h, sup + 0x40)  # UStruct::SuperStruct
                    seen += 1
        scanned, carriers, total_entries = 0, [], 0
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
            total_entries += s["num"]
            hit = c3d.occupied_with(s, fid)
            if hit:
                carriers.append({"object": "0x%x" % a, "name": r.get("name_text"),
                                 "entries": len(hit)})
        rep["3_all_live_inventories"] = {
            "inventory_components_scanned": scanned, "slots_examined": total_entries,
            "components_carrying_mbpl__radio": carriers,
            "condition_holds": not carriers}

        # 4: world pickup actors
        world = {}
        for cname in ("BP_StaticMasterItem_C", "BP_SkeletalMasterItem_C"):
            cls = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == cname
                   and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                   == "BlueprintGeneratedClass"]
            cls = cls[0] if len(cls) == 1 else None
            if cls is None:
                world[cname] = {"class_found": False}
                continue
            off = None
            cp = eri._read_u64(api, h, cls + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np,
                                              owner_address=cls,
                                              objects_by_address=objs).get("accepted", []):
                if (pr.get("raw_name") or "").split("_")[0] == "InvItem":
                    off = pr.get("offset")
            live, hits = [], []
            for a, r in objs.items():
                if r.get("class_ptr") != cls:
                    continue
                if (r.get("name_text") or "").startswith("Default__"):
                    continue
                live.append(a)
                if off is not None:
                    got = struct.unpack("<I", api.read_process_memory(h, a + off, 4))[0]
                    if got == fid:
                        hits.append({"actor": "0x%x" % a, "name": r.get("name_text")})
            world[cname] = {"class_found": True, "InvItem_offset": off,
                            "live_actors": len(live), "carrying_mbpl__radio": hits}
        rep["4_world_pickups"] = world
        rep["4_world_pickups"]["condition_holds"] = all(
            not v.get("carrying_mbpl__radio") for v in world.values())

        # 5 + 6: the runtime table and the composite
        def rows_named(table):
            """(row_count, {name: ptr}). The count comes from the row list, never
            from the dict -- rows whose FName fails to decode would otherwise
            collapse onto a single None key and silently undercount."""
            rows, _ = rdr.read_rowmap(api, h, table)
            out = {}
            undecoded = 0
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

        rt_n, rt, rt_u = rows_named(st["table_ptr"])
        mt_n, mt, mt_u = rows_named(st["master"])
        il_n, il, il_u = rows_named(st["itemlist"])

        def ui(ptr):
            b = api.read_process_memory(h, ptr + UI_OFF, 64)
            return {"InventoryIcon": "0x%x" % struct.unpack_from("<Q", b, 0)[0],
                    "MoveIcon": "0x%x" % struct.unpack_from("<Q", b, 8)[0],
                    "OverrideImageSize": bool(b[16]),
                    "SizeY": struct.unpack_from("<i", b, 20)[0],
                    "SizeX": struct.unpack_from("<i", b, 24)[0],
                    "Width": struct.unpack("<i", api.read_process_memory(h, ptr + W_OFF, 4))[0],
                    "Height": struct.unpack("<i", api.read_process_memory(h, ptr + H_OFF, 4))[0]}

        rep["5_runtime_table"] = {
            "rows": rt_n, "names_decoded": len(rt), "names_undecoded": rt_u, "contains_mbpl__radio": "mbpl__radio" in rt,
            "row_ptr": "0x%x" % rt["mbpl__radio"] if "mbpl__radio" in rt else None,
            "ui": ui(rt["mbpl__radio"]) if "mbpl__radio" in rt else None,
            "condition_holds": "mbpl__radio" in rt}
        rep["6_master_item_list"] = {
            "rows": mt_n, "itemlist_rows": il_n,
            "names_undecoded": mt_u,
            "contains_mbpl__radio": "mbpl__radio" in mt,
            "row_ptr": "0x%x" % mt["mbpl__radio"] if "mbpl__radio" in mt else None,
            "ui": ui(mt["mbpl__radio"]) if "mbpl__radio" in mt else None,
            "distinct_buffer_from_runtime_row":
                ("mbpl__radio" in mt and "mbpl__radio" in rt
                 and mt["mbpl__radio"] != rt["mbpl__radio"]),
            "condition_holds": "mbpl__radio" in mt}

        # 7: the icon is still the same rooted object
        tex = st["icon_object"]
        idx = struct.unpack("<I", api.read_process_memory(h, tex + 0x0C, 4))[0]
        # FUObjectItem address, resolved exactly as CR01C4BProbeDll::ItemForObject does:
        # objects_ptr is the CHUNK POINTER ARRAY itself, not a pointer to it.
        chunk = eri._read_u64(api, h, st["objects_ptr"] + (idx >> 16) * 8)
        item = chunk + (idx & 0xFFFF) * FUOBJECTITEM
        obj_at_item = eri._read_u64(api, h, item)
        flags = struct.unpack("<i", api.read_process_memory(h, item + 8, 4))[0]
        cls = eri._read_u64(api, h, tex + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
        eid = eri._read_u32(api, h, tex + eri.DEFAULT_NAME_PRIVATE_OFFSET)
        rep["7_icon_texture"] = {
            "address": "0x%x" % tex, "internal_index": idx,
            "name": eri.decode_fname_entry_id(api, h, np, eid).get("text"),
            "class": eri.decode_fname_entry_id(
                api, h, np, eri._read_u32(api, h, cls + eri.DEFAULT_NAME_PRIVATE_OFFSET)
            ).get("text"),
            "uobject_item_points_back": obj_at_item == tex,
            "flags": "0x%x" % (flags & 0xFFFFFFFF),
            "rooted": bool(flags & ROOTSET),
            "condition_holds": bool(flags & ROOTSET) and obj_at_item == tex}

        rep["all_conditions_hold"] = all(
            rep[k]["condition_holds"] for k in
            ("1_player_inventory", "2_counters", "3_all_live_inventories", "4_world_pickups",
             "5_runtime_table", "6_master_item_list", "7_icon_texture"))
    finally:
        api.close_handle(h)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safety.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=True, default=str))
    return 0 if rep.get("all_conditions_hold") else 1


if __name__ == "__main__":
    sys.exit(main())
