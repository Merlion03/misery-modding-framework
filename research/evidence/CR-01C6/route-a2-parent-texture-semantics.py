#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C6 route A2: can a texture-driven shipped parent
carry spatially-constant PBR values through tiny uniform textures?

Semantics are NOT taken from parameter names. For every texture parameter of a
candidate parent, this reads what the shipped instances actually BIND to it and
then reads that texture's own format fields -- CompressionSettings, SRGB,
LODGroup. Those are the engine's own declarations of what a texture means:
TC_Normalmap is a tangent-space normal, TC_Masks is a non-colour packed mask,
sRGB is a colour map. A parameter whose bound textures are unanimously
TC_Normalmap is the normal input regardless of what it is called, and a name
that says "Color" while every bound texture is TC_Masks would be caught here.

Static switches are read too: an instance that overrides one needs its own
shader permutation, so the set that shipped instances actually use bounds what
we could adopt for free.

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

OFF_PARENT = 272
OFF_SCALAR, OFF_VECTOR, OFF_TEXTURE = 360, 376, 408
OFF_STATIC = 504
OFF_HASPERM = 336
SCALAR_STRIDE, VECTOR_STRIDE, TEXTURE_STRIDE, STATIC_STRIDE = 40, 48, 40, 40
# UTexture reflected fields
TEX_COMPRESSION, TEX_FILTER, TEX_LODGROUP, TEX_SRGB = 240, 241, 245, 254
TEX_IMPORTED_SIZE = 312  # UTexture2D

TC = {0: "TC_Default", 1: "TC_Normalmap", 2: "TC_Masks", 3: "TC_Grayscale",
      4: "TC_Displacementmap", 5: "TC_VectorDisplacementmap", 6: "TC_HDR",
      7: "TC_EditorIcon", 8: "TC_Alpha", 9: "TC_DistanceFieldFont",
      10: "TC_HDR_Compressed", 11: "TC_BC7", 12: "TC_HalfFloat",
      13: "TC_EncodedReflectionCapture", 14: "TC_SingleFloat", 15: "TC_HDR_F32"}


def tarray(api, h, addr, stride, cap=8192):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not data or num <= 0 or num > cap:
        return b"", 0
    return api.read_process_memory(h, data, num * stride) or b"", num


def main():
    want_parents = sys.argv[1:] or ["M_Mesh_Master"]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"], "parents_requested": want_parents}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def fname(eid):
            try:
                return eri.decode_fname_entry_id(api, h, np, eid).get("text")
            except Exception:  # noqa: BLE001
                return None

        def path_of(a):
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objs).get("object_path"))
            except Exception:  # noqa: BLE001
                return None

        mi_cls = [a for a, r in objs.items() if r.get("name_ok")
                  and r.get("name_text") == "MaterialInstance"
                  and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == "Class"][0]
        derived = set()
        for a, r in objs.items():
            if (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") != "Class":
                continue
            sup, hops = a, 0
            while sup and hops < 24:
                if sup == mi_cls:
                    derived.add(a)
                    break
                sup = eri._read_u64(api, h, sup + 0x40)
                hops += 1

        targets = {}
        for a, r in objs.items():
            if r.get("name_ok") and r.get("name_text") in want_parents:
                cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                if cn in ("Material", "MaterialInstanceConstant"):
                    targets[a] = r.get("name_text")

        def texinfo(t):
            if not t:
                return None
            rec = objs.get(t) or {}
            try:
                comp = eri._read_u8(api, h, t + TEX_COMPRESSION)
                srgb = bool(eri._read_u8(api, h, t + TEX_SRGB) & 1)
                lod = eri._read_u8(api, h, t + TEX_LODGROUP)
                x, y = struct.unpack("<ii", api.read_process_memory(h, t + TEX_IMPORTED_SIZE, 8))
            except Exception:  # noqa: BLE001
                return {"name": rec.get("name_text"), "unreadable": True}
            return {"name": rec.get("name_text"),
                    "class": (objs.get(rec.get("class_ptr") or 0) or {}).get("name_text"),
                    "CompressionSettings": TC.get(comp, str(comp)), "SRGB": srgb,
                    "LODGroup": lod, "ImportedSize": [x, y]}

        out_parents = []
        for paddr, pname in targets.items():
            per_param = collections.defaultdict(lambda: collections.Counter())
            per_param_examples = collections.defaultdict(dict)
            statics = collections.Counter()
            static_true = collections.Counter()
            n_inst = 0
            perm = collections.Counter()
            scalars, vectors = collections.Counter(), collections.Counter()
            for a, r in objs.items():
                if r.get("class_ptr") not in derived:
                    continue
                if eri._read_u64(api, h, a + OFF_PARENT) != paddr:
                    continue
                n_inst += 1
                perm[bool(eri._read_u8(api, h, a + OFF_HASPERM) & 1)] += 1
                blob, n = tarray(api, h, a + OFF_TEXTURE, TEXTURE_STRIDE)
                for i in range(n):
                    nm = fname(struct.unpack_from("<I", blob, i * TEXTURE_STRIDE)[0])
                    tex = struct.unpack_from("<Q", blob, i * TEXTURE_STRIDE + 16)[0]
                    ti = texinfo(tex)
                    if nm and ti:
                        key = "%s|%s" % (ti.get("CompressionSettings"), ti.get("SRGB"))
                        per_param[nm][key] += 1
                        if len(per_param_examples[nm]) < 3:
                            per_param_examples[nm][ti.get("name")] = ti
                for off, stride, ctr in ((OFF_SCALAR, SCALAR_STRIDE, scalars),
                                         (OFF_VECTOR, VECTOR_STRIDE, vectors)):
                    b2, n2 = tarray(api, h, a + off, stride)
                    for i in range(n2):
                        nm = fname(struct.unpack_from("<I", b2, i * stride)[0])
                        if nm:
                            ctr[nm] += 1
                sb, sn = tarray(api, h, a + OFF_STATIC, STATIC_STRIDE)
                for i in range(sn):
                    nm = fname(struct.unpack_from("<I", sb, i * STATIC_STRIDE)[0])
                    if nm:
                        statics[nm] += 1
                        if sb[i * STATIC_STRIDE + 36]:
                            static_true[nm] += 1
            out_parents.append({
                "parent": pname, "address": "0x%x" % paddr, "path": path_of(paddr),
                "parent_class": (objs.get((objs.get(paddr) or {}).get("class_ptr") or 0)
                                 or {}).get("name_text"),
                "instances": n_inst,
                "bHasStaticPermutationResource": {str(k): v for k, v in perm.items()},
                "texture_parameters": {
                    k: {"bound_texture_formats": dict(v),
                        "examples": per_param_examples[k]}
                    for k, v in sorted(per_param.items())},
                "scalar_parameters": dict(scalars.most_common()),
                "vector_parameters": dict(vectors.most_common()),
                "static_switch_parameters": dict(statics.most_common()),
                "static_switch_set_true": dict(static_true.most_common()),
            })
        rep["parents"] = out_parents
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "route_a2.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    for p in rep["parents"]:
        print("=== %s (%s)  instances=%d" % (p["parent"], p["parent_class"], p["instances"]))
        print("    path:", p["path"])
        print("    bHasStaticPermutationResource:", p["bHasStaticPermutationResource"])
        print("    static switches overridden by instances:", p["static_switch_parameters"])
        for k, v in p["texture_parameters"].items():
            print("    TEX  %-28s %s" % (k, v["bound_texture_formats"]))
            for tn, ti in v["examples"].items():
                print("           e.g. %-34s %s SRGB=%s size=%s" % (
                    tn, ti.get("CompressionSettings"), ti.get("SRGB"), ti.get("ImportedSize")))


if __name__ == "__main__":
    main()
