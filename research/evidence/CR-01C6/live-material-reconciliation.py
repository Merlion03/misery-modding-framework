#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Why did the probe render as a grey checker instead of the
intended saturated red?

This reconciles the LIVE spawned actor rather than the offline cooked metadata:
the component's own material list, the mesh asset's slot list, and for whatever
material is actually bound, its class, its Parent, and every texture override
resolved back to a real Texture2D object path.

The three failure shapes it is written to tell apart:
  * the mesh asset never carried the instances (assignment did not persist),
  * the instances are there but their Parent import did not resolve, so the
    renderer fell back,
  * the instances and parent are fine and the fault is elsewhere.

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

INVITEM_OFF = 704
SMC_STATICMESH = 1376
MC_OVERRIDE_MATERIALS = 1304
SM_STATICMATERIALS = 344
# FStaticMaterial's stride is DERIVED from the reflected ScriptStruct rather
# than counted by hand -- counting it by hand is what produced a garbage
# pointer on the first attempt.
STATICMATERIAL_STRIDE = None
MI_PARENT = 272
MI_TEXTURE = 408
TEXTURE_STRIDE = 40
TEX_COMP, TEX_SRGB, TEX_SIZE = 240, 254, 312
ROW = "mbpl__armprobe2"


def tarray(api, h, addr, stride, cap=4096):
    d = eri._read_u64(api, h, addr)
    n = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not d or n <= 0 or n > cap:
        return b"", 0
    return api.read_process_memory(h, d, n * stride) or b"", n


def main():
    st_path = os.path.join(REPO, "workspace", "armprobe2-demo-state.json")
    st = json.load(open(st_path, encoding="utf-8"))
    fid = st["row_fname"] & 0xFFFFFFFF
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"], "row": ROW}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def nm(a):
            return (objs.get(a) or {}).get("name_text")

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

        def describe_material(m):
            if not m:
                return None
            d = {"object": "0x%x" % m, "name": nm(m), "class": cls_of(m), "path": path_of(m)}
            c = d["class"] or ""
            if "MaterialInstance" in c:
                p = eri._read_u64(api, h, m + MI_PARENT)
                d["Parent"] = {"object": "0x%x" % p if p else None, "name": nm(p),
                               "class": cls_of(p), "path": path_of(p)} if p else None
                d["parent_is_null"] = not p
                tb, tn = tarray(api, h, m + MI_TEXTURE, TEXTURE_STRIDE)
                ov = []
                for i in range(tn):
                    pn = fname(struct.unpack_from("<I", tb, i * TEXTURE_STRIDE)[0])
                    t = struct.unpack_from("<Q", tb, i * TEXTURE_STRIDE + 16)[0]
                    ti = None
                    if t:
                        try:
                            x, y = struct.unpack(
                                "<ii", api.read_process_memory(h, t + TEX_SIZE, 8))
                            ti = {"texture": nm(t), "path": path_of(t),
                                  "SRGB": bool(eri._read_u8(api, h, t + TEX_SRGB) & 1),
                                  "ImportedSize": [x, y]}
                        except Exception:  # noqa: BLE001
                            ti = {"texture": nm(t), "unreadable": True}
                    ov.append({"parameter": pn, "resolved": ti})
                d["texture_overrides"] = ov
            return d

        ss = [a for a, r in objs.items() if r.get("name_ok")
              and r.get("name_text") == "StaticMaterial"
              and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == "ScriptStruct"]
        if len(ss) != 1:
            raise SystemExit("StaticMaterial ScriptStruct not uniquely resolved")
        stride = struct.unpack("<i", api.read_process_memory(h, ss[0] + 0x58, 4))[0]
        rep["FStaticMaterial_size_reflected"] = stride

        # --- the spawned actor -------------------------------------------------
        cls = [a for a, r in objs.items() if r.get("name_ok")
               and r.get("name_text") == "BP_StaticMasterItem_C"
               and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
               == "BlueprintGeneratedClass"]
        if len(cls) != 1:
            raise SystemExit("BP_StaticMasterItem_C not uniquely resolved")
        cls = cls[0]
        actors = [a for a, r in objs.items()
                  if r.get("class_ptr") == cls
                  and not (r.get("name_text") or "").startswith("Default__")
                  and struct.unpack("<I", api.read_process_memory(
                      h, a + INVITEM_OFF, 4))[0] == fid]
        rep["spawned_actors_carrying_row"] = len(actors)
        if not actors:
            rep["note"] = ("no world actor carries the probe row -- drop it first, or it "
                           "was picked up again")
            print(json.dumps(rep, indent=2))
            return
        actor = actors[0]
        rep["actor"] = {"object": "0x%x" % actor, "name": nm(actor)}

        # --- its StaticMeshComponent(s) ---------------------------------------
        smc_cls = [a for a, r in objs.items() if r.get("name_ok")
                   and r.get("name_text") == "StaticMeshComponent"
                   and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == "Class"][0]
        derived = set()
        for a, r in objs.items():
            if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") not in (
                    "Class", "BlueprintGeneratedClass"):
                continue
            s, k = a, 0
            while s and k < 24:
                if s == smc_cls:
                    derived.add(a)
                    break
                s = eri._read_u64(api, h, s + 0x40)
                k += 1
        comps = [a for a, r in objs.items()
                 if r.get("class_ptr") in derived
                 and eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET) == actor]
        rep["static_mesh_components"] = len(comps)

        rep["components"] = []
        for c in comps:
            mesh = eri._read_u64(api, h, c + SMC_STATICMESH)
            entry = {"component": "0x%x" % c, "name": nm(c), "class": cls_of(c),
                     "StaticMesh": {"object": "0x%x" % mesh if mesh else None,
                                    "name": nm(mesh), "path": path_of(mesh)}}
            ob, on = tarray(api, h, c + MC_OVERRIDE_MATERIALS, 8)
            entry["OverrideMaterials_count"] = on
            entry["OverrideMaterials"] = [
                describe_material(struct.unpack_from("<Q", ob, i * 8)[0]) for i in range(on)]
            slots = []
            if mesh:
                sb, sn = tarray(api, h, mesh + SM_STATICMATERIALS, stride)
                for i in range(sn):
                    mi = struct.unpack_from("<Q", sb, i * stride)[0]
                    slot_name = fname(struct.unpack_from("<I", sb, i * stride + 8)[0])
                    slots.append({"slot": i, "MaterialSlotName": slot_name,
                                  "mesh_asset_material": describe_material(mi)})
            entry["mesh_asset_slots"] = slots
            # what the renderer would actually use per slot
            eff = []
            for i, s in enumerate(slots):
                o = (entry["OverrideMaterials"][i]
                     if i < len(entry["OverrideMaterials"]) else None)
                eff.append({"slot": i,
                            "effective_source": "component override" if o else "mesh asset",
                            "effective_material": o or s["mesh_asset_material"]})
            entry["effective_per_slot"] = eff
            rep["components"].append(entry)

        # --- is the REAL vanilla parent present and loaded? --------------------
        cands = [a for a, r in objs.items() if r.get("name_ok")
                 and r.get("name_text") == "M_BasicMaterial"]
        rep["M_BasicMaterial_objects_live"] = [
            {"object": "0x%x" % a, "class": cls_of(a), "path": path_of(a)} for a in cands]
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_material_recon.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=False, default=str)[:7000])


if __name__ == "__main__":
    main()
