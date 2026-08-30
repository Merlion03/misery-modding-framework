#!/usr/bin/env python3
"""Synthetic source assets, generated from nothing.

Stage 3's claim is that ORDINARY source material travels through the pipeline
without asset-specific research code. Proving that with the radio alone would be
weak: the radio is the asset every previous gate was built around, and a pipeline
tuned to it could pass while being useless to anyone else.

So this generates genuinely new sources -- a two-slot cube as glTF-binary and a
couple of PNGs -- with no dependency on the radio, on MISERY, or on any
authoring tool. They are ordinary files of ordinary formats; the pipeline has no
idea they were generated.

Two material slots on purpose: one slot would not exercise slot mapping at all,
and slot mapping is where the previous material work actually went wrong.
"""
import json
import os
import struct
import zlib


# ---------------------------------------------------------------------- PNG
def write_png(path, width, height, rgb, *, alpha=255):
    """A minimal, valid 8-bit RGBA PNG of one solid colour.

    Written by hand rather than with an imaging library so the Mod Kit's own
    test fixtures do not add a dependency the pipeline itself does not have.
    """
    red, green, blue = [max(0, min(255, int(round(c)))) for c in rgb]
    raw = b"".join(b"\x00" + bytes([red, green, blue, alpha]) * width
                   for _ in range(height))

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)   # 8-bit RGBA
    data = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def srgb_encode(linear):
    """Linear 0..1 -> sRGB 0..255.

    A colour texture is sampled through the sRGB transfer function, so a value
    written raw would come back darker than authored. Encoding here means the
    number in the spec is the number the shader sees.
    """
    out = []
    for value in linear:
        value = max(0.0, min(1.0, float(value)))
        srgb = 12.92 * value if value <= 0.0031308 else 1.055 * (value ** (1 / 2.4)) - 0.055
        out.append(srgb * 255.0)
    return out


# --------------------------------------------------------------------- GLB
def _cube_geometry():
    """24 vertices, 6 faces, flat normals, split into TWO primitives.

    Flat normals need per-face vertices, which is why there are 24 and not 8.
    The split is 3 faces to each primitive so the importer must produce two
    material slots.
    """
    faces = [
        ((-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1), (0, 0, 1)),      # +Z
        ((1, -1, -1), (-1, -1, -1), (-1, 1, -1), (1, 1, -1), (0, 0, -1)),  # -Z
        ((1, -1, 1), (1, -1, -1), (1, 1, -1), (1, 1, 1), (1, 0, 0)),      # +X
        ((-1, -1, -1), (-1, -1, 1), (-1, 1, 1), (-1, 1, -1), (-1, 0, 0)),  # -X
        ((-1, 1, 1), (1, 1, 1), (1, 1, -1), (-1, 1, -1), (0, 1, 0)),      # +Y
        ((-1, -1, -1), (1, -1, -1), (1, -1, 1), (-1, -1, 1), (0, -1, 0)),  # -Y
    ]
    positions, normals, uvs = [], [], []
    indices_a, indices_b = [], []
    for face_index, face in enumerate(faces):
        base = len(positions)
        corners, normal = face[:4], face[4]
        for corner in corners:
            positions.append(corner)
            normals.append(normal)
        uvs.extend([(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)])
        tri = [base, base + 1, base + 2, base, base + 2, base + 3]
        (indices_a if face_index < 3 else indices_b).extend(tri)
    return positions, normals, uvs, indices_a, indices_b


def write_cube_glb(path, *, half_extent=1.0):
    """A two-primitive cube as glTF-binary 2.0."""
    positions, normals, uvs, indices_a, indices_b = _cube_geometry()
    positions = [tuple(c * half_extent for c in p) for p in positions]

    pos_bytes = b"".join(struct.pack("<fff", *p) for p in positions)
    nrm_bytes = b"".join(struct.pack("<fff", *n) for n in normals)
    uv_bytes = b"".join(struct.pack("<ff", *t) for t in uvs)
    idx_a_bytes = b"".join(struct.pack("<H", i) for i in indices_a)
    idx_b_bytes = b"".join(struct.pack("<H", i) for i in indices_b)

    blobs, offset, views = [], 0, []
    for payload, target in ((pos_bytes, 34962), (nrm_bytes, 34962), (uv_bytes, 34962),
                            (idx_a_bytes, 34963), (idx_b_bytes, 34963)):
        pad = (-len(payload)) % 4
        views.append({"buffer": 0, "byteOffset": offset,
                      "byteLength": len(payload), "target": target})
        blobs.append(payload + b"\x00" * pad)
        offset += len(payload) + pad
    binary = b"".join(blobs)

    mins = [min(p[i] for p in positions) for i in range(3)]
    maxs = [max(p[i] for p in positions) for i in range(3)]
    gltf = {
        "asset": {"version": "2.0", "generator": "MISERY Mod Kit fixture generator"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0, "name": "Cube"}],
        "buffers": [{"byteLength": len(binary)}],
        "bufferViews": views,
        "accessors": [
            {"bufferView": 0, "componentType": 5126, "count": len(positions),
             "type": "VEC3", "min": mins, "max": maxs},
            {"bufferView": 1, "componentType": 5126, "count": len(normals),
             "type": "VEC3"},
            {"bufferView": 2, "componentType": 5126, "count": len(uvs), "type": "VEC2"},
            {"bufferView": 3, "componentType": 5123, "count": len(indices_a),
             "type": "SCALAR"},
            {"bufferView": 4, "componentType": 5123, "count": len(indices_b),
             "type": "SCALAR"},
        ],
        # Two materials so the importer creates two slots. They carry no textures:
        # the Mod Kit assigns its own MICs, and a source material here would only
        # compete with them.
        "materials": [
            {"name": "SlotA", "pbrMetallicRoughness": {
                "baseColorFactor": [0.8, 0.2, 0.2, 1.0], "metallicFactor": 0.0,
                "roughnessFactor": 0.7}},
            {"name": "SlotB", "pbrMetallicRoughness": {
                "baseColorFactor": [0.2, 0.4, 0.8, 1.0], "metallicFactor": 0.0,
                "roughnessFactor": 0.4}},
        ],
        "meshes": [{"name": "Cube", "primitives": [
            {"attributes": {"POSITION": 0, "NORMAL": 1, "TEXCOORD_0": 2},
             "indices": 3, "material": 0},
            {"attributes": {"POSITION": 0, "NORMAL": 1, "TEXCOORD_0": 2},
             "indices": 4, "material": 1},
        ]}],
    }

    json_bytes = json.dumps(gltf, separators=(",", ":")).encode("utf-8")
    json_bytes += b" " * ((-len(json_bytes)) % 4)
    total = 12 + 8 + len(json_bytes) + 8 + len(binary)
    out = (b"glTF" + struct.pack("<II", 2, total)
           + struct.pack("<I", len(json_bytes)) + b"JSON" + json_bytes
           + struct.pack("<I", len(binary)) + b"BIN\x00" + binary)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(out)
    return path


def build_fixture_mod(root, mod_id, *, mesh_filename="shape.glb",
                      icon_filename="icon.png"):
    """A complete, buildable mod source tree.

    The filenames are parameters and default to generic ones on purpose: the
    collision test builds TWO mods from IDENTICAL filenames, and that only means
    anything if the names really are the same on disk.
    """
    source_root = os.path.join(root, mod_id)
    os.makedirs(source_root, exist_ok=True)
    write_cube_glb(os.path.join(source_root, "meshes", mesh_filename))
    write_png(os.path.join(source_root, "textures", icon_filename), 32, 32,
              srgb_encode([0.55, 0.15, 0.10]))
    write_png(os.path.join(source_root, "textures", "basecolor.png"), 4, 4,
              srgb_encode([0.20, 0.35, 0.15]))
    spec = {
        "mod_id": mod_id,
        "unreal_version": "5.4.4",
        "textures": [
            {"name": "Icon", "source": "textures/%s" % icon_filename, "usage": "color"},
            {"name": "ShapeBase", "source": "textures/basecolor.png", "usage": "color"},
        ],
        "materials": [
            {"name": "ShapeA",
             "parent": "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial",
             "base_color": {"texture": "ShapeBase"},
             "ao": 1.0, "roughness": 0.65, "metallic": 0.05},
            {"name": "ShapeB",
             "parent": "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial",
             "base_color": {"constant": [0.10, 0.20, 0.45]},
             "ao": 1.0, "roughness": 0.30, "metallic": 0.60},
        ],
        "meshes": [
            {"name": "Shape", "source": "meshes/%s" % mesh_filename,
             "uniform_scale": 1.0,
             "slots": [{"material": "ShapeA"}, {"material": "ShapeB"}]},
        ],
    }
    spec_path = os.path.join(source_root, "modkit.json")
    with open(spec_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(spec, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return spec_path
