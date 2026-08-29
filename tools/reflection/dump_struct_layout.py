#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Dump the reflected field layout of named UScriptStructs
(or UClasses) from the live process, resolving field types.

Reuses ERI's proven walkers (I-01..I-04 + walk_property_chain). Opens the process
through ERI's single read-only open call site; writes nothing.
"""
import argparse, json, os, sys
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
import eri  # noqa: E402


def typename(p):
    pc = p.get("property_class") or ""
    if pc == "FStructProperty":
        return "struct %s" % p.get("struct_name")
    if pc == "FArrayProperty":
        inn = p.get("inner")
        if isinstance(inn, dict):
            s = inn.get("struct_name")
            return "TArray<%s>" % (("struct " + s) if s else
                                   (inn.get("class_name") or inn.get("property_class")))
        return "TArray<?>"
    if pc in ("FObjectProperty", "FClassProperty", "FSoftObjectProperty", "FSoftClassProperty"):
        return "%s(%s)" % (pc, p.get("class_name"))
    if pc == "FByteProperty" and p.get("enum_name"):
        return "enum %s" % p.get("enum_name")
    if pc in ("FMapProperty", "FSetProperty"):
        def leaf(x):
            if not isinstance(x, dict): return str(x)
            return x.get("struct_name") or x.get("class_name") or x.get("property_class")
        if pc == "FMapProperty":
            return "TMap<%s,%s>" % (leaf(p.get("key_type")), leaf(p.get("value_type")))
        return "TSet<%s>" % leaf(p.get("key_type"))
    return pc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("name", nargs="+", help="UScriptStruct/UClass name(s), e.g. S_InvItem")
    ap.add_argument("--out")
    ap.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    a = ap.parse_args(argv)
    want = set(a.name)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, a.process_name)
    h = eri.open_process_read_only(api, i01["pid"])
    try:
        base, size = i01["base_address"], i01["image_size_bytes"]
        i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(api, h, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        np = i03["namepool_live_va"]
        walk = eri.walk_object_universe(api, h, i02["objects_ptr_live_va"], i02["num_elements"],
                                        base, size, np,
                                        class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                        name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                        outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                        max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objs = walk["objects_by_address"]
        out = {}
        for addr, rec in objs.items():
            if not rec.get("name_ok"):
                continue
            nm = rec.get("name_text")
            if nm not in want or nm in out:
                continue
            cls = objs.get(rec.get("class_ptr") or 0) or {}
            if cls.get("name_text") not in ("ScriptStruct", "Class", "BlueprintGeneratedClass",
                                            "UserDefinedStruct"):
                continue
            cp = eri._read_u64(api, h, addr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            pr = eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=addr)
            fields = [{"name": p.get("raw_name"), "type": typename(p),
                       "offset": p.get("offset"), "size": p.get("size"),
                       "property_class": p.get("property_class"),
                       "struct_name": p.get("struct_name"),
                       "class_name": p.get("class_name")}
                      for p in pr.get("accepted", [])]
            fields.sort(key=lambda x: x["offset"] if x["offset"] is not None else 1 << 30)
            out[nm] = {"kind": cls.get("name_text"), "address_hex": "0x%x" % addr,
                       "object_path": eri.resolve_object_path(addr, objs).get("object_path"),
                       "fields": fields}
        for nm in sorted(want):
            r = out.get(nm)
            if not r:
                print("\n=== %s : NOT FOUND" % nm); continue
            print("\n=== %s (%s) %s" % (nm, r["kind"], r["object_path"]))
            for f in r["fields"]:
                print("   %-30s %-44s off=%-5s size=%s" % (f["name"], f["type"], f["offset"], f["size"]))
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(out, fh, indent=2, sort_keys=True, ensure_ascii=False); fh.write("\n")
            print("\nwritten:", a.out)
        return 0
    finally:
        api.close_handle(h)


if __name__ == "__main__":
    raise SystemExit(main())
