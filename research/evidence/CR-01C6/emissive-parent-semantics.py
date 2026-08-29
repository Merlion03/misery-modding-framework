#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Can any shipped parent carry the radio's two emissive
slots without a new shader permutation?

For each candidate this reads the material's own MODE fields -- MaterialDomain,
BlendMode, ShadingModel, TwoSided -- because a parent that is Unlit/Additive is
a glow sprite, not a shaded surface, and that decides whether it suits the
Screen slot, the LED slot, or neither.

It also dumps every parameter of every instance WITH ITS VALUE, including
entries whose ParameterInfo.Name decodes to None. An unnamed entry is reported
as unnamed rather than dropped: a parameter that cannot be addressed by name is
a real finding, not an absence.

Nothing is written.
"""
import collections
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

OFF_PARENT, OFF_SCALAR, OFF_VECTOR, OFF_TEXTURE, OFF_STATIC = 272, 360, 376, 408, 504
OFF_HASPERM = 336
S_STRIDE, V_STRIDE, T_STRIDE, ST_STRIDE = 40, 48, 40, 40
M_DOMAIN, M_BLEND, M_SHADING, M_TWOSIDED = 296, 297, 368, 376
TEX_COMP, TEX_SRGB, TEX_SIZE = 240, 254, 312

DOMAIN = {0: "MD_Surface", 1: "MD_DeferredDecal", 2: "MD_LightFunction", 3: "MD_Volume",
          4: "MD_PostProcess", 5: "MD_UI"}
BLEND = {0: "BLEND_Opaque", 1: "BLEND_Masked", 2: "BLEND_Translucent", 3: "BLEND_Additive",
         4: "BLEND_Modulate", 5: "BLEND_AlphaComposite", 6: "BLEND_AlphaHoldout"}
SHADING = {0: "MSM_Unlit", 1: "MSM_DefaultLit", 2: "MSM_Subsurface", 3: "MSM_PreintegratedSkin",
           4: "MSM_ClearCoat", 5: "MSM_SubsurfaceProfile", 6: "MSM_TwoSidedFoliage",
           7: "MSM_Hair", 8: "MSM_Cloth", 9: "MSM_Eye", 10: "MSM_SingleLayerWater",
           11: "MSM_ThinTranslucent"}
TC = {0: "TC_Default", 1: "TC_Normalmap", 2: "TC_Masks", 3: "TC_Grayscale", 7: "TC_EditorIcon"}


def tarray(api, h, addr, stride, cap=8192):
    d = eri._read_u64(api, h, addr)
    n = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not d or n <= 0 or n > cap:
        return b"", 0
    return api.read_process_memory(h, d, n * stride) or b"", n


def main():
    want = sys.argv[1:] or ["M_Glow_C", "MM_Fire", "M_BasicMaterial"]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"], "candidates": want, "materials": []}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def fn(e):
            try:
                return eri.decode_fname_entry_id(api, h, np, e).get("text")
            except Exception:  # noqa: BLE001
                return None

        mi = [a for a, r in objs.items() if r.get("name_text") == "MaterialInstance"
              and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == "Class"][0]
        der = set()
        for a, r in objs.items():
            if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") != "Class":
                continue
            s, k = a, 0
            while s and k < 24:
                if s == mi:
                    der.add(a)
                    break
                s = eri._read_u64(api, h, s + 0x40)
                k += 1

        for a, r in objs.items():
            if not r.get("name_ok") or r.get("name_text") not in want:
                continue
            cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
            if cn != "Material":
                continue
            entry = {
                "material": r.get("name_text"), "address": "0x%x" % a,
                "path": eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objs).get("object_path")),
                "MaterialDomain": DOMAIN.get(eri._read_u8(api, h, a + M_DOMAIN),
                                             eri._read_u8(api, h, a + M_DOMAIN)),
                "BlendMode": BLEND.get(eri._read_u8(api, h, a + M_BLEND),
                                       eri._read_u8(api, h, a + M_BLEND)),
                "ShadingModel": SHADING.get(eri._read_u8(api, h, a + M_SHADING),
                                            eri._read_u8(api, h, a + M_SHADING)),
                "TwoSided": bool(eri._read_u8(api, h, a + M_TWOSIDED) & 1),
                "instances": [],
            }
            for b, rb in objs.items():
                if rb.get("class_ptr") not in der:
                    continue
                if eri._read_u64(api, h, b + OFF_PARENT) != a:
                    continue
                inst = {"instance": rb.get("name_text"),
                        "own_permutation": bool(eri._read_u8(api, h, b + OFF_HASPERM) & 1),
                        "scalars": [], "vectors": [], "textures": [], "statics": []}
                sb, sn = tarray(api, h, b + OFF_SCALAR, S_STRIDE)
                for i in range(sn):
                    nm = fn(struct.unpack_from("<I", sb, i * S_STRIDE)[0])
                    val = struct.unpack_from("<f", sb, i * S_STRIDE + 16)[0]
                    inst["scalars"].append({"name": nm, "named": nm not in (None, "None"),
                                            "value": round(val, 5)})
                vb, vn = tarray(api, h, b + OFF_VECTOR, V_STRIDE)
                for i in range(vn):
                    nm = fn(struct.unpack_from("<I", vb, i * V_STRIDE)[0])
                    rgba = struct.unpack_from("<4f", vb, i * V_STRIDE + 16)
                    inst["vectors"].append({"name": nm, "named": nm not in (None, "None"),
                                            "value": [round(x, 5) for x in rgba]})
                tb, tn = tarray(api, h, b + OFF_TEXTURE, T_STRIDE)
                for i in range(tn):
                    nm = fn(struct.unpack_from("<I", tb, i * T_STRIDE)[0])
                    t = struct.unpack_from("<Q", tb, i * T_STRIDE + 16)[0]
                    ti = None
                    if t:
                        trec = objs.get(t) or {}
                        try:
                            x, y = struct.unpack("<ii",
                                                 api.read_process_memory(h, t + TEX_SIZE, 8))
                            ti = {"texture": trec.get("name_text"),
                                  "CompressionSettings": TC.get(
                                      eri._read_u8(api, h, t + TEX_COMP),
                                      eri._read_u8(api, h, t + TEX_COMP)),
                                  "SRGB": bool(eri._read_u8(api, h, t + TEX_SRGB) & 1),
                                  "ImportedSize": [x, y]}
                        except Exception:  # noqa: BLE001
                            ti = {"texture": trec.get("name_text"), "unreadable": True}
                    inst["textures"].append({"name": nm, "named": nm not in (None, "None"),
                                             "bound": ti})
                stb, stn = tarray(api, h, b + OFF_STATIC, ST_STRIDE)
                for i in range(stn):
                    nm = fn(struct.unpack_from("<I", stb, i * ST_STRIDE)[0])
                    inst["statics"].append({"name": nm,
                                            "value": bool(stb[i * ST_STRIDE + 36])})
                entry["instances"].append(inst)
            rep["materials"].append(entry)
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emissive_scan.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    for m in rep["materials"]:
        print("=== %s" % m["material"])
        print("    path        :", m["path"])
        print("    domain/blend/shading/twosided: %s / %s / %s / %s" % (
            m["MaterialDomain"], m["BlendMode"], m["ShadingModel"], m["TwoSided"]))
        for i in m["instances"]:
            print("    instance %s  own_permutation=%s" % (i["instance"], i["own_permutation"]))
            for k in ("scalars", "vectors", "textures", "statics"):
                if i[k]:
                    print("       %-8s %s" % (k, json.dumps(i[k])[:400]))


if __name__ == "__main__":
    main()
