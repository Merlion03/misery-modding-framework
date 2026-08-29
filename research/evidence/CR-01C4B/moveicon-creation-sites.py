#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Two last checks for the CR-01C4B comparison:
  1. our texture's reflected ImportedSize, read straight from the object we
     already own;
  2. every live UFunction that embeds the BP_MoveIcon_C class pointer, so the
     claim "the move ghost is only ever created by a drag path" is enumerated
     rather than assumed.
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

OUR_TEX = 0x2682324fe80
IMPORTED_SIZE = 312
SCRIPT = 0x60


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"]}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        fmeta = recon.find_function_meta(objs)
        x, y = struct.unpack("<ii", api.read_process_memory(h, OUR_TEX + IMPORTED_SIZE, 8))
        cls = eri._read_u64(api, h, OUR_TEX + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
        rep["our_texture"] = {
            "address": "0x%x" % OUR_TEX, "ImportedSize": [x, y],
            "class": (objs.get(cls) or {}).get("name_text"),
            "in_universe_snapshot": OUR_TEX in objs,
            "path": eri.canonicalize_object_path(
                eri.resolve_object_path(OUR_TEX, objs).get("object_path"))
            if OUR_TEX in objs else None}

        mcls = [a for a, r in objs.items()
                if r.get("name_ok") and r.get("name_text") == "BP_MoveIcon_C"
                and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                == "WidgetBlueprintGeneratedClass"]
        rep["move_icon_class_candidates"] = ["0x%x" % a for a in mcls]
        target = mcls[0] if len(mcls) == 1 else None
        hits = []
        if target:
            for a, r in objs.items():
                if r.get("class_ptr") != fmeta or not r.get("name_ok"):
                    continue
                data = eri._read_u64(api, h, a + SCRIPT)
                num = struct.unpack("<i", api.read_process_memory(h, a + SCRIPT + 8, 4))[0]
                if not data or num <= 0 or num > (1 << 24):
                    continue
                code = api.read_process_memory(h, data, num) or b""
                for off in range(0, max(0, len(code) - 7)):
                    if struct.unpack_from("<Q", code, off)[0] == target:
                        outer = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
                        hits.append({"owner": (objs.get(outer) or {}).get("name_text"),
                                     "function": r.get("name_text"), "at": off})
        rep["functions_embedding_BP_MoveIcon_C"] = hits
    finally:
        api.close_handle(h)
    print(json.dumps(rep, indent=2, sort_keys=True, default=str))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "final.json"),
              "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")


if __name__ == "__main__":
    main()
