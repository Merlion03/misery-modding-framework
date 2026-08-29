#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Post-death/reload reconciliation of the held CR-01C4B state.

Death plus a save reload is treated as LIFECYCLE-UNKNOWN. Every recorded pointer
is re-validated by identity before it is believed: its InternalIndex must still
address a FUObjectItem whose Object field points back at it, and its resolved
class and name must still be what we recorded. A pointer that merely "looks
mapped" proves nothing -- freed UObject memory is recycled.

Nothing is written.
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
OFF_PARENT_TABLES = 176
OFF_ROWSTRUCT = 40
UI = {"UIDetails": 224, "InventoryIcon": 0, "MoveIcon": 8,
      "MoveIconSizeOverride": 16, "OverrideImageSize": 0, "SizeY": 4, "SizeX": 8}
ROW = "mbpl__radio"


def main():
    st = json.load(open(STATE, encoding="utf-8"))
    fid = st["row_fname"] & 0xFFFFFFFF
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    rep = {"current_pid": i01["pid"], "state_pid": st["pid"],
           "same_process": i01["pid"] == st["pid"]}
    h = eri.open_process_read_only(api, i01["pid"])
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def fname_of(o):
            try:
                return eri.decode_fname_entry_id(
                    api, h, np, eri._read_u32(api, h, o + eri.DEFAULT_NAME_PRIVATE_OFFSET)
                ).get("text")
            except Exception:  # noqa: BLE001
                return None

        def identity(ptr, expect_class=None, expect_name=None, label=""):
            """Is this pointer still the live object we recorded?"""
            out = {"pointer": "0x%x" % ptr}
            try:
                idx = struct.unpack("<i", api.read_process_memory(h, ptr + 0x0C, 4))[0]
            except Exception:  # noqa: BLE001
                return dict(out, alive=False, why="unreadable")
            out["internal_index"] = idx
            if idx < 0:
                return dict(out, alive=False, why="negative InternalIndex")
            try:
                chunk = eri._read_u64(api, h, st["objects_ptr"] + (idx >> 16) * 8)
                item = chunk + (idx & 0xFFFF) * FUOBJECTITEM
                back = eri._read_u64(api, h, item)
                flags = struct.unpack("<i", api.read_process_memory(h, item + 8, 4))[0]
            except Exception:  # noqa: BLE001
                return dict(out, alive=False, why="FUObjectItem unreadable")
            out["uobject_item_points_back"] = back == ptr
            out["flags"] = "0x%x" % (flags & 0xFFFFFFFF)
            out["rooted"] = bool(flags & ROOTSET)
            cls = eri._read_u64(api, h, ptr + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
            out["name"] = fname_of(ptr)
            out["class"] = fname_of(cls) if cls else None
            ok = back == ptr
            if expect_class is not None and out["class"] != expect_class:
                ok = False
                out["why"] = "class is %r, recorded %r" % (out["class"], expect_class)
            if expect_name is not None and out["name"] != expect_name:
                ok = False
                out["why"] = "name is %r, recorded %r" % (out["name"], expect_name)
            out["alive"] = ok
            return out

        def one(nm, clsname):
            c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
            return c if len(c) == 1 else c

        # --- the two vanilla tables, re-resolved from the live universe -------
        il_live = one("ItemList", "DataTable")
        mi_live = one("MasterItemList", "CompositeDataTable")
        rep["itemlist"] = {"live_candidates": ["0x%x" % a for a in il_live],
                           "recorded": "0x%x" % st["itemlist"],
                           "same": len(il_live) == 1 and il_live[0] == st["itemlist"]}
        rep["master_item_list"] = {"live_candidates": ["0x%x" % a for a in mi_live],
                                   "recorded": "0x%x" % st["master"],
                                   "same": len(mi_live) == 1 and mi_live[0] == st["master"]}

        # --- the runtime table -----------------------------------------------
        rep["runtime_table"] = identity(st["table_ptr"], expect_class="DataTable",
                                        label="RuntimeTable")
        if rep["runtime_table"].get("alive"):
            rs = eri._read_u64(api, h, st["table_ptr"] + OFF_ROWSTRUCT)
            rep["runtime_table"]["rowstruct"] = fname_of(rs) if rs else None
            n, rows = 0, {}
            try:
                raw, _ = rdr.read_rowmap(api, h, st["table_ptr"])
                n = len(raw)
                for eid, num, ptr in raw:
                    try:
                        t = eri.decode_fname_entry_id(api, h, np, eid).get("text")
                    except Exception:  # noqa: BLE001
                        t = None
                    if t:
                        rows[t] = ptr
            except Exception as e:  # noqa: BLE001
                rep["runtime_table"]["rowmap_error"] = repr(e)
            rep["runtime_table"]["rows"] = n
            rep["runtime_table"]["contains_row"] = ROW in rows
            rep["runtime_table"]["row_ptr"] = "0x%x" % rows[ROW] if ROW in rows else None
            rep["_runtime_row"] = rows.get(ROW)

        # --- the publication --------------------------------------------------
        pt = st["master"] + OFF_PARENT_TABLES
        data = eri._read_u64(api, h, pt)
        num = struct.unpack("<i", api.read_process_memory(h, pt + 8, 4))[0]
        mx = struct.unpack("<i", api.read_process_memory(h, pt + 12, 4))[0]
        slots = []
        if data and 0 < num <= 8:
            for i in range(num):
                slots.append(eri._read_u64(api, h, data + i * 8))
        rep["publication"] = {
            "ParentTables_data": "0x%x" % data, "num": num, "max": mx,
            "slots": ["0x%x" % s for s in slots],
            "slot0_is_itemlist": bool(slots) and slots[0] == st["itemlist"],
            "runtime_table_is_a_parent": st["table_ptr"] in slots,
            "still_published": num == 2 and st["table_ptr"] in slots}

        # --- the composite's own copy ----------------------------------------
        mrows = {}
        try:
            raw, _ = rdr.read_rowmap(api, h, st["master"])
            for eid, numb, ptr in raw:
                try:
                    t = eri.decode_fname_entry_id(api, h, np, eid).get("text")
                except Exception:  # noqa: BLE001
                    t = None
                if t:
                    mrows[t] = ptr
            rep["master_rows"] = len(raw)
        except Exception as e:  # noqa: BLE001
            rep["master_rows_error"] = repr(e)
        rep["row_resolvable_in_master"] = ROW in mrows

        # --- the texture ------------------------------------------------------
        rep["icon_texture"] = identity(st["icon_object"], expect_class="Texture2D",
                                       expect_name="T_MBPL_Radio_Icon", label="icon")
        if rep["icon_texture"].get("alive"):
            x, y = struct.unpack("<ii", api.read_process_memory(h, st["icon_object"] + 312, 8))
            rep["icon_texture"]["ImportedSize"] = [x, y]

        # --- the UI fields on whichever copies survive ------------------------
        def read_ui(ptr):
            b = api.read_process_memory(h, ptr + UI["UIDetails"], 64)
            inv = struct.unpack_from("<Q", b, UI["InventoryIcon"])[0]
            mov = struct.unpack_from("<Q", b, UI["MoveIcon"])[0]
            ov = UI["MoveIconSizeOverride"]
            return {"InventoryIcon": "0x%x" % inv, "MoveIcon": "0x%x" % mov,
                    "icons_equal_and_ours": inv == mov == st["icon_object"],
                    "OverrideImageSize": bool(b[ov + UI["OverrideImageSize"]]),
                    "SizeX": struct.unpack_from("<i", b, ov + UI["SizeX"])[0],
                    "SizeY": struct.unpack_from("<i", b, ov + UI["SizeY"])[0]}

        if rep.get("_runtime_row"):
            rep["runtime_row_ui"] = read_ui(rep["_runtime_row"])
        if ROW in mrows:
            rep["master_row_ui"] = read_ui(mrows[ROW])
        rep.pop("_runtime_row", None)

        # --- the player inventory --------------------------------------------
        pi_live = one("BP_PlayerInventory", "BP_PlayerInventory_C")
        rep["player_inventory"] = {
            "live_candidates": ["0x%x" % a for a in pi_live],
            "recorded": "0x%x" % st["player_inv"],
            "same_object_as_recorded": len(pi_live) == 1 and pi_live[0] == st["player_inv"]}
        if len(pi_live) == 1:
            s = c3d.read_inventory(api, h, pi_live[0])
            rep["player_inventory"].update(
                slots=s["num"], occupied=sum(1 for x in s["slots"] if x["occupied"]),
                free=sum(1 for x in s["slots"] if not x["occupied"]),
                ItemCount=s["item_count"], CurrentWeight=s["current_weight"],
                entries_with_row=len(c3d.occupied_with(s, fid)))

        # --- nothing anywhere carries the row --------------------------------
        master_cls = one("BP_MasterInventory_C", "BlueprintGeneratedClass")
        derived = set()
        if len(master_cls) == 1:
            mc = master_cls[0]
            for a, r in objs.items():
                if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") not in (
                        "BlueprintGeneratedClass", "Class"):
                    continue
                sup, hops = a, 0
                while sup and hops < 24:
                    if sup == mc:
                        derived.add(a)
                        break
                    sup = eri._read_u64(api, h, sup + 0x40)
                    hops += 1
        scanned, carriers = 0, []
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
            if c3d.occupied_with(s, fid):
                carriers.append({"object": "0x%x" % a, "name": r.get("name_text")})
        world = {}
        for cname in ("BP_StaticMasterItem_C", "BP_SkeletalMasterItem_C"):
            cls = one(cname, "BlueprintGeneratedClass")
            if len(cls) != 1:
                world[cname] = {"class_resolved": False}
                continue
            cls = cls[0]
            off = None
            cp = eri._read_u64(api, h, cls + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=cls,
                                              objects_by_address=objs).get("accepted", []):
                if (pr.get("raw_name") or "").split("_")[0] == "InvItem":
                    off = pr.get("offset")
            hits, live = [], 0
            for a, r in objs.items():
                if r.get("class_ptr") != cls or (r.get("name_text") or "").startswith("Default__"):
                    continue
                live += 1
                if off is not None and struct.unpack(
                        "<I", api.read_process_memory(h, a + off, 4))[0] == fid:
                    hits.append("0x%x" % a)
            world[cname] = {"InvItem_offset": off, "live_actors": live, "carrying": hits}
        rep["no_instance_carries_row"] = {
            "inventories_scanned": scanned, "inventory_carriers": carriers,
            "world": world,
            "holds": not carriers and all(not v.get("carrying") for v in world.values())}
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reconcile.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
