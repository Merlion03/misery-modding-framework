#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Final CR-01C4B comparison: our materialized row against
the vanilla rows, over exactly the fields the traced code paths consume.

Nothing is written to the target.
"""
import io
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
import read_datatable_rows as rdr  # noqa: E402

ROW = "mbpl__radio"
UI_OFF = 224          # S_ItemDetails.UIDetails, reflected
W_OFF, H_OFF = 56, 60  # S_ItemDetails.Width / Height, reflected
FIELDS = [("InventoryIcon", 0), ("MoveIcon", 8), ("QuickSlotIcon", 32),
          ("VenderIcon", 40), ("EquipmentSlotIcon", 48), ("WeaponSlotIcon", 56)]
OV = 16  # MoveIconSizeOverride: OverrideImageSize@+0, SizeY@+4, SizeX@+8


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"]}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def one(nm, clsname):
            c = [x for x, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
            return c[0] if len(c) == 1 else None

        cache = {}

        def fname(eid):
            if eid not in cache:
                try:
                    cache[eid] = eri.decode_fname_entry_id(api, h, np, eid).get("text")
                except Exception:  # noqa: BLE001
                    cache[eid] = None
            return cache[eid]

        def texname(p):
            if not p:
                return None
            r = objs.get(p)
            if not r:
                return "0x%x" % p
            sz = api.read_process_memory(h, p + 312, 8)
            x, y = struct.unpack("<ii", sz)
            return {"name": r.get("name_text"),
                    "path": eri.canonicalize_object_path(
                        eri.resolve_object_path(p, objs).get("object_path")),
                    "ImportedSize": [x, y]}

        def readrow(ptr):
            b = api.read_process_memory(h, ptr + UI_OFF, 64)
            out = {k: texname(struct.unpack_from("<Q", b, o)[0]) for k, o in FIELDS}
            out["MoveIconSizeOverride"] = {
                "OverrideImageSize": bool(b[OV]),
                "SizeY": struct.unpack_from("<i", b, OV + 4)[0],
                "SizeX": struct.unpack_from("<i", b, OV + 8)[0]}
            out["Width"] = struct.unpack("<i", api.read_process_memory(h, ptr + W_OFF, 4))[0]
            out["Height"] = struct.unpack("<i", api.read_process_memory(h, ptr + H_OFF, 4))[0]
            return out

        master = one("MasterItemList", "CompositeDataTable")
        il = one("ItemList", "DataTable")
        mrows, _ = rdr.read_rowmap(api, h, master)
        ours = None
        for eid, num, ptr in mrows:
            if fname(eid) == ROW:
                ours = ptr
        rep["our_row_found"] = ours is not None
        if ours:
            rep["our_row"] = readrow(ours)

        # vanilla population, grouped by grid size
        irows, _ = rdr.read_rowmap(api, h, il)
        groups = {}
        sample = {}
        for eid, num, ptr in irows:
            b = api.read_process_memory(h, ptr + UI_OFF, 64)
            w = struct.unpack("<i", api.read_process_memory(h, ptr + W_OFF, 4))[0]
            hh = struct.unpack("<i", api.read_process_memory(h, ptr + H_OFF, 4))[0]
            key = "%dx%d" % (w, hh)
            g = groups.setdefault(key, {"n": 0, "moveicon_set": 0, "moveicon_eq_inv": 0,
                                        "override_on": 0, "override_sizes": {}})
            g["n"] += 1
            iic = struct.unpack_from("<Q", b, 0)[0]
            mic = struct.unpack_from("<Q", b, 8)[0]
            if mic:
                g["moveicon_set"] += 1
                if mic == iic:
                    g["moveicon_eq_inv"] += 1
            if b[OV]:
                g["override_on"] += 1
                sy = struct.unpack_from("<i", b, OV + 4)[0]
                sx = struct.unpack_from("<i", b, OV + 8)[0]
                k2 = "%dx%d" % (sx, sy)
                g["override_sizes"][k2] = g["override_sizes"].get(k2, 0) + 1
            if key == "1x1" and len(sample) < 4 and iic:
                sample[fname(eid) or str(eid)] = readrow(ptr)
        rep["vanilla_by_grid_size"] = dict(sorted(groups.items()))
        rep["vanilla_1x1_samples"] = sample

        # every distinct ImportedSize among vanilla inventory icons
        sizes = {}
        for eid, num, ptr in irows:
            p = struct.unpack("<Q", api.read_process_memory(h, ptr + UI_OFF, 8))[0]
            if not p:
                continue
            x, y = struct.unpack("<ii", api.read_process_memory(h, p + 312, 8))
            sizes["%dx%d" % (x, y)] = sizes.get("%dx%d" % (x, y), 0) + 1
        rep["vanilla_inventory_icon_ImportedSize_histogram"] = dict(
            sorted(sizes.items(), key=lambda kv: -kv[1]))

        # BP_MoveIcon_C::ImageScale on the CDO
        mcls = one("BP_MoveIcon_C", "WidgetBlueprintGeneratedClass")
        cdo = one("Default__BP_MoveIcon_C", "BP_MoveIcon_C")
        rep["move_icon_class"] = "0x%x" % mcls if mcls else None
        if mcls and cdo:
            cp = eri._read_u64(api, h, mcls + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np,
                                              owner_address=mcls,
                                              objects_by_address=objs).get("accepted", []):
                nm = (pr.get("raw_name") or "").split("_")[0]
                if nm in ("ImageScale", "Rotate", "PendingKill"):
                    off, cls = pr.get("offset"), pr.get("property_class")
                    raw = api.read_process_memory(h, cdo + off, pr.get("size") or 8)
                    val = (struct.unpack("<d", raw[:8])[0] if cls == "FDoubleProperty"
                           else (struct.unpack("<f", raw[:4])[0] if cls == "FFloatProperty"
                                 else raw.hex()))
                    rep.setdefault("move_icon_cdo", {})[nm] = {
                        "class": cls, "offset": off, "value": val}
        # BP_InventoryItemIcon_C::IconSize on its CDO (per-cell pixel size)
        icls = one("BP_InventoryItemIcon_C", "WidgetBlueprintGeneratedClass")
        icdo = one("Default__BP_InventoryItemIcon_C", "BP_InventoryItemIcon_C")
        if icls and icdo:
            cp = eri._read_u64(api, h, icls + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np,
                                              owner_address=icls,
                                              objects_by_address=objs).get("accepted", []):
                if (pr.get("raw_name") or "").split("_")[0] == "IconSize":
                    raw = api.read_process_memory(h, icdo + pr["offset"], 16)
                    rep["inventory_icon_cdo_IconSize"] = {
                        "offset": pr["offset"], "type": pr.get("struct_name"),
                        "value": list(struct.unpack("<2d", raw))}
    finally:
        api.close_handle(h)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compare.json")
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
