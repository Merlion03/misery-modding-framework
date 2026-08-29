#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C5 phase 1: who actually consumes the world-related
S_ItemDetails fields, and what do the world-item classes look like?

Names are not evidence. Every field below is located by reflection, and its
consumers are found by scanning the Script bytecode of EVERY live UFunction for
that field's FProperty pointer -- so "WorldClass" is identified by who reads it,
not by what it is called.
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

SCRIPT = 0x60
WANT_ITEMDETAILS = ("WorldClass", "StaticMesh", "SkeletalMesh", "ItemOffsets",
                    "PickupAnimation", "Weight", "Name")


def tarray_bytes(api, h, addr, cap=1 << 24):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not data or num <= 0 or num > cap:
        return b""
    return api.read_process_memory(h, data, num) or b""


def members(api, h, np, owner, objs):
    cp = eri._read_u64(api, h, owner + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    out = []
    for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=owner,
                                      objects_by_address=objs).get("accepted", []):
        rec = {"name": (pr.get("raw_name") or "").split("_")[0],
               "fproperty": int(pr["address_hex"], 16),
               "offset": pr.get("offset"), "size": pr.get("size"),
               "class": pr.get("property_class")}
        inner = eri._read_u64(api, h, rec["fproperty"] + 0x70)
        rec["inner"] = (objs.get(inner) or {}).get("name_text")
        out.append(rec)
    return out


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"]}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        fmeta = recon.find_function_meta(objs)
        rep["objects_in_snapshot"] = len(objs)

        def one(nm, cls):
            c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == cls]
            return c[0] if len(c) == 1 else None

        it = one("S_ItemDetails", "UserDefinedStruct")
        it_m = members(api, h, np, it, objs)
        rep["S_ItemDetails_world_fields"] = [
            {k: v for k, v in m.items() if k != "fproperty"}
            for m in it_m if m["name"] in WANT_ITEMDETAILS]

        wanted = {m["fproperty"]: "S_ItemDetails." + m["name"]
                  for m in it_m if m["name"] in WANT_ITEMDETAILS}

        # the two world-item classes and their own properties
        for cname in ("BP_StaticMasterItem_C", "BP_SkeletalMasterItem_C",
                      "BP_MasterItem_C", "BP_MasterWorldItem_C"):
            cls = one(cname, "BlueprintGeneratedClass")
            if cls is None:
                rep.setdefault("world_classes", {})[cname] = {"resolved": False}
                continue
            sup = eri._read_u64(api, h, cls + 0x40)
            chain = []
            s = sup
            while s and len(chain) < 8:
                chain.append((objs.get(s) or {}).get("name_text"))
                s = eri._read_u64(api, h, s + 0x40)
            props = members(api, h, np, cls, objs)
            rep.setdefault("world_classes", {})[cname] = {
                "resolved": True, "address": "0x%x" % cls, "super_chain": chain,
                "properties": [{k: v for k, v in p.items() if k != "fproperty"}
                               for p in props],
                "live_instances": len([a for a, r in objs.items() if r.get("class_ptr") == cls
                                       and not (r.get("name_text") or "").startswith("Default__")])}
            for p in props:
                wanted[p["fproperty"]] = "%s.%s" % (cname, p["name"])

        hits, scanned = {v: [] for v in wanted.values()}, 0
        for a, r in objs.items():
            if r.get("class_ptr") != fmeta or not r.get("name_ok"):
                continue
            scanned += 1
            code = tarray_bytes(api, h, a + SCRIPT)
            if not code:
                continue
            found = set()
            for off in range(0, len(code) - 7):
                p = struct.unpack_from("<Q", code, off)[0]
                lab = wanted.get(p)
                if lab is not None:
                    found.add((lab, off))
            if found:
                owner = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
                on = (objs.get(owner) or {}).get("name_text")
                for lab, off in sorted(found):
                    hits[lab].append({"fn": "%s::%s" % (on, r.get("name_text")), "at": off})
        rep["functions_scanned"] = scanned
        rep["consumers"] = {k: v for k, v in sorted(hits.items()) if v}
        rep["fields_with_no_consumer"] = sorted(k for k, v in hits.items() if not v)
    finally:
        api.close_handle(h)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "world_consumers.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    print("wrote", out, "| functions scanned:", rep["functions_scanned"],
          "| objects:", rep["objects_in_snapshot"])


if __name__ == "__main__":
    main()
