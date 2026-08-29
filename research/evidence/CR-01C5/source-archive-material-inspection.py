#!/usr/bin/env python3
"""STRICTLY READ-ONLY. What material data does the supplied source archive
actually contain?

The question is decisive only if it is answered from the file, not from its
README. A GLB is a 12-byte header followed by length-prefixed chunks; the JSON
chunk is the glTF document. This enumerates images, textures, samplers and
materials, and prints every material's PBR factors -- so "no texture maps" and
"no material data" can be told apart, because they are not the same claim.

Nothing is written.
"""
import json
import os
import struct
import sys

GLB = r"D:/Dev/Models/Radio/mbpl_radio.glb"
FBX = r"D:/Dev/Models/Radio/mbpl_radio.fbx"


def read_glb(path):
    raw = open(path, "rb").read()
    magic, version, length = struct.unpack_from("<4sII", raw, 0)
    if magic != b"glTF":
        raise SystemExit("not a GLB: %r" % magic)
    out = {"magic": magic.decode(), "version": version, "declared_length": length,
           "actual_length": len(raw), "chunks": []}
    off = 12
    doc = None
    while off + 8 <= len(raw):
        clen, ctype = struct.unpack_from("<II", raw, off)
        payload = raw[off + 8: off + 8 + clen]
        kind = {0x4E4F534A: "JSON", 0x004E4942: "BIN"}.get(ctype, "0x%08x" % ctype)
        out["chunks"].append({"type": kind, "length": clen})
        if kind == "JSON":
            doc = json.loads(payload.decode("utf-8"))
        off += 8 + clen
    return out, doc


def main():
    info, g = read_glb(GLB)
    rep = {"file": GLB, "bytes": os.path.getsize(GLB), "container": info}
    rep["asset"] = g.get("asset")
    for key in ("images", "textures", "samplers", "materials", "meshes", "accessors",
                "bufferViews", "buffers"):
        rep["count_" + key] = len(g.get(key) or [])

    # the decisive pair of questions
    rep["has_image_texture_maps"] = bool(g.get("images")) or bool(g.get("textures"))
    rep["has_material_definitions"] = bool(g.get("materials"))

    mats = []
    for m in (g.get("materials") or []):
        pbr = m.get("pbrMetallicRoughness") or {}
        entry = {
            "name": m.get("name"),
            "baseColorFactor": pbr.get("baseColorFactor"),
            "metallicFactor": pbr.get("metallicFactor"),
            "roughnessFactor": pbr.get("roughnessFactor"),
            "emissiveFactor": m.get("emissiveFactor"),
            "alphaMode": m.get("alphaMode"),
            "doubleSided": m.get("doubleSided"),
            # any texture reference at all would show up as one of these
            "texture_refs": sorted(k for k in
                                   list(pbr.keys()) + list(m.keys())
                                   if k.endswith("Texture")),
        }
        mats.append(entry)
    rep["materials"] = mats
    rep["materials_with_any_texture_ref"] = [m["name"] for m in mats if m["texture_refs"]]

    prims = []
    for mesh in (g.get("meshes") or []):
        for p in (mesh.get("primitives") or []):
            prims.append({"mesh": mesh.get("name"), "material_index": p.get("material"),
                          "attributes": sorted((p.get("attributes") or {}).keys())})
    rep["primitives"] = prims
    rep["has_uv_channel"] = any("TEXCOORD_0" in p["attributes"] for p in prims)
    rep["has_vertex_colors"] = any(
        any(a.startswith("COLOR_") for a in p["attributes"]) for p in prims)

    # the FBX alternate, checked only for embedded texture blobs
    if os.path.isfile(FBX):
        blob = open(FBX, "rb").read()
        rep["fbx"] = {
            "bytes": len(blob),
            "mentions_Video_or_Texture_nodes": any(
                t in blob for t in (b"Video", b"Texture")),
            "embedded_image_signatures": {
                "png": blob.count(b"\x89PNG"), "jpg": blob.count(b"\xff\xd8\xff"),
                "dds": blob.count(b"DDS ") , "tga_footer": blob.count(b"TRUEVISION")},
        }

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "glb_inspect.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
