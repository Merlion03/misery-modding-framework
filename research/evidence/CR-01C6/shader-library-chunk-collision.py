#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Does a mod container's shader library actually collide
with the shipped game's -- as bytes, not as an argument?

Shader libraries are NOT addressed by filename in an IoStore build. The shipped
containers contain no "ShaderArchive-*" string at all. They are addressed by
chunk id:

    FIoStoreShaderCodeArchive::GetShaderCodeArchiveChunkId   (ShaderCodeArchive.cpp:1345)
        Name = lower("<LibraryName>-<FormatName>")
        CreateIoChunkId(CityHash64(Name), 0, EIoChunkType::ShaderCodeLibrary)

so the collision question is decided by the LIBRARY NAME, and it is answerable
without reimplementing CityHash: list the ShaderCodeLibrary chunk ids (type byte
8, IoChunkId.h:36) in the shipped container and in ours, and intersect them.

Nothing is written.
"""
import json
import os
import struct
import sys

SHIPPED = r"D:/Games/Steam/steamapps/common/MISERY/MISERY/Content/Paks/MISERY-Windows.utoc"
SHIPPED_GLOBAL = r"D:/Games/Steam/steamapps/common/MISERY/MISERY/Content/Paks/global.utoc"
HDR = "<16s B B H IIIII I I I I Q 16s B B H I Q I I 40s"
MAGIC = b"-==--==--==--==-"
SHADER_CODE_LIBRARY = 8
SHADER_CODE = 9


def chunk_ids(path):
    raw = open(path, "rb").read()
    f = struct.unpack_from(HDR, raw, 0)
    (magic, version, _r0, _r1, hdr_size, entry_count, blk_count, blk_entry_size,
     cm_count, cm_len, cblock, dir_size, part_count, cid, guid, flags, _r3, _r4,
     phash, part_size, no_phash, _r7, _r8) = f
    if magic != MAGIC:
        raise SystemExit("not a utoc: %s" % path)
    ids = []
    for i in range(entry_count):
        off = hdr_size + i * 12
        ids.append(raw[off:off + 12])
    return {"file": os.path.basename(path), "version": version,
            "entry_count": entry_count, "ids": ids}


def summarize(label, path):
    info = chunk_ids(path)
    by_type = {}
    for cid in info["ids"]:
        by_type.setdefault(cid[11], []).append(cid)
    out = {"label": label, "file": info["file"], "entry_count": info["entry_count"],
           "chunks_by_type": {str(k): len(v) for k, v in sorted(by_type.items())},
           "shader_code_library_chunks": [c.hex() for c in
                                          by_type.get(SHADER_CODE_LIBRARY, [])],
           "shader_code_chunk_count": len(by_type.get(SHADER_CODE, []))}
    return out, set(c.hex() for c in by_type.get(SHADER_CODE_LIBRARY, []))


def main():
    rep = {}
    ours_path = sys.argv[1] if len(sys.argv) > 1 else None

    shipped, shipped_lib = summarize("shipped MISERY-Windows", SHIPPED)
    rep["shipped"] = shipped
    g, g_lib = summarize("shipped global", SHIPPED_GLOBAL)
    rep["shipped_global"] = g
    shipped_all = shipped_lib | g_lib

    if ours_path and os.path.isfile(ours_path):
        ours, ours_lib = summarize("mod container", ours_path)
        rep["mod"] = ours
        rep["collision"] = {
            "shipped_shader_library_chunk_ids": sorted(shipped_all),
            "mod_shader_library_chunk_ids": sorted(ours_lib),
            "colliding_ids": sorted(shipped_all & ours_lib),
            "collides": bool(shipped_all & ours_lib),
        }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chunk_collision.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
