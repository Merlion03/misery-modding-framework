#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C6 route A: does an ALREADY-SHIPPED parent material
expose enough non-static parameters to represent the seven authored GLB slots?

UMaterial does not reflect its parameter list -- CachedExpressionData is not a
UPROPERTY and MaterialCachedParameterEntry::ParameterInfoSet is a TSet the
walker cannot decode. So the question is answered from the other side, which is
fully reflected: every live UMaterialInstance carries Parent plus
ScalarParameterValues / VectorParameterValues, each entry naming the parameter
it overrides. The union of names seen across a parent's instances is a LOWER
BOUND on what that parent exposes -- and a lower bound is exactly what proving
existence needs.

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

# reflected on MaterialInstance
OFF_PARENT = 272
OFF_SCALAR = 360
OFF_VECTOR = 376
OFF_TEXTURE = 408
SCALAR_STRIDE = 40      # ParameterInfo(16) + float(4) + pad + Guid(16)
VECTOR_STRIDE = 48      # ParameterInfo(16) + LinearColor(16) + Guid(16)
TEXTURE_STRIDE = 40

WANTED = {
    "basecolor": ("basecolor", "base_color", "color", "albedo", "diffuse", "tint"),
    "metallic": ("metallic", "metalness", "metal"),
    "roughness": ("roughness", "rough", "gloss"),
    "emissive": ("emissive", "emission", "glow"),
}


def tarray(api, h, addr, stride, cap=4096):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not data or num <= 0 or num > cap:
        return b"", 0
    return api.read_process_memory(h, data, num * stride) or b"", num


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"]}
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

        # every class deriving from MaterialInstance
        mi_cls = [a for a, r in objs.items() if r.get("name_ok")
                  and r.get("name_text") == "MaterialInstance"
                  and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == "Class"]
        if len(mi_cls) != 1:
            raise SystemExit("MaterialInstance class not uniquely resolved")
        mi_cls = mi_cls[0]
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
        rep["material_instance_classes"] = sorted(
            (objs.get(a) or {}).get("name_text") for a in derived)

        by_parent = collections.defaultdict(lambda: {"instances": 0, "scalars": set(),
                                                     "vectors": set(), "textures": set()})
        scanned = 0
        for a, r in objs.items():
            if r.get("class_ptr") not in derived:
                continue
            scanned += 1
            parent = eri._read_u64(api, h, a + OFF_PARENT)
            if not parent:
                continue
            key = parent
            e = by_parent[key]
            e["instances"] += 1
            for off, stride, bucket in ((OFF_SCALAR, SCALAR_STRIDE, "scalars"),
                                        (OFF_VECTOR, VECTOR_STRIDE, "vectors"),
                                        (OFF_TEXTURE, TEXTURE_STRIDE, "textures")):
                blob, n = tarray(api, h, a + off, stride)
                for i in range(n):
                    nm = fname(struct.unpack_from("<I", blob, i * stride)[0])
                    if nm:
                        e[bucket].add(nm)
        rep["material_instances_scanned"] = scanned
        rep["distinct_parents"] = len(by_parent)

        parents = []
        for p, e in by_parent.items():
            prec = objs.get(p) or {}
            allnames = e["scalars"] | e["vectors"]
            low = {n.lower() for n in allnames}
            covered = {}
            for want, keys in WANTED.items():
                hit = sorted(n for n in allnames if any(k in n.lower() for k in keys))
                covered[want] = hit
            parents.append({
                "parent": prec.get("name_text"),
                "parent_class": (objs.get(prec.get("class_ptr") or 0) or {}).get("name_text"),
                "path": path_of(p),
                "instances": e["instances"],
                "scalar_params": sorted(e["scalars"]),
                "vector_params": sorted(e["vectors"]),
                "texture_params": sorted(e["textures"]),
                "covers": covered,
                "coverage_count": sum(1 for v in covered.values() if v),
            })
        parents.sort(key=lambda x: (-x["coverage_count"], -x["instances"]))
        rep["parents"] = parents
        rep["parents_covering_all_four"] = [
            p for p in parents if p["coverage_count"] == 4]
        rep["parents_covering_three_or_more"] = [
            {"parent": p["parent"], "path": p["path"], "instances": p["instances"],
             "covers": p["covers"]}
            for p in parents if p["coverage_count"] >= 3]
    finally:
        api.close_handle(h)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "route_a.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("instances scanned:", rep["material_instances_scanned"],
          "| distinct parents:", rep["distinct_parents"],
          "| covering all four:", len(rep["parents_covering_all_four"]),
          "| covering >=3:", len(rep["parents_covering_three_or_more"]))
    for p in rep["parents"][:12]:
        print("  %-42s cov=%d inst=%-4d %s" % (
            (p["parent"] or "?")[:42], p["coverage_count"], p["instances"],
            {k: v for k, v in p["covers"].items() if v}))


if __name__ == "__main__":
    main()
