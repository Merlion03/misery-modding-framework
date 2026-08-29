#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Dump UStruct::ScriptAndPropertyObjectReferences for named
UFunctions, with every entry resolved to name / class / object path.

This array is maintained by the ENGINE ITSELF ("Array of object references
embedded in script code and referenced by FProperties", Class.h:419) so it is
authoritative about which UObjects a function's bytecode touches -- unlike a
naive opcode byte scan, which cannot tell an opcode from an identical byte
inside an operand and therefore over-reports. Anything that is a UObject
literal, a prebound UFunction* call target, or a referenced FProperty's object
is in here; anything dispatched purely by FName is NOT, and that absence is a
real limit of this view, not a proof of absence of a call.

Opens the process PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only.
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
import eri  # noqa: E402

USTRUCT_SPOR_OFFSET = 0x90
USTRUCT_SCRIPT_OFFSET = 0x60


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--function", action="append", required=True,
                    help="Owner::Function (repeatable)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    base, size = i01["base_address"], i01["image_size_bytes"]
    h = eri.open_process_read_only(api, i01["pid"])
    try:
        i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(api, h, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        np = i03["namepool_live_va"]
        w = eri.walk_object_universe(api, h, i02["objects_ptr_live_va"], i02["num_elements"],
                                     base, size, np,
                                     class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                     name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                     outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                     max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objs = w["objects_by_address"]

        fmeta = None
        for addr, r in objs.items():
            if r.get("name_ok") and r.get("name_text") == "Function" and eri.canonicalize_object_path(
                    eri.resolve_object_path(addr, objs).get("object_path")) == "/Script/CoreUObject.Function":
                fmeta = addr
                break
        index = {}
        for addr, r in objs.items():
            if r.get("class_ptr") != fmeta:
                continue
            path = eri.resolve_object_path(addr, objs).get("object_path") or ""
            owner = path.rsplit(":", 1)[0].rsplit(".", 1)[-1]
            index["%s::%s" % (owner, r.get("name_text"))] = addr

        result = {"pid": i01["pid"], "functions": {}}
        for spec in a.function:
            addr = index.get(spec)
            if addr is None:
                result["functions"][spec] = {"found": False}
                continue
            data = eri._read_u64(api, h, addr + USTRUCT_SPOR_OFFSET)
            num = struct.unpack("<i", api.read_process_memory(
                h, addr + USTRUCT_SPOR_OFFSET + 8, 4))[0]
            script_num = struct.unpack("<i", api.read_process_memory(
                h, addr + USTRUCT_SCRIPT_OFFSET + 8, 4))[0]
            refs = []
            if data and 0 < num < 8192:
                raw = api.read_process_memory(h, data, num * 8)
                for i in range(num):
                    p = struct.unpack_from("<Q", raw, i * 8)[0]
                    rec = objs.get(p) or {}
                    cls = (objs.get(rec.get("class_ptr") or 0) or {}).get("name_text")
                    refs.append({
                        "index": i, "address": "0x%x" % p,
                        "name": rec.get("name_text"),
                        "class": cls,
                        "object_path": eri.resolve_object_path(p, objs).get("object_path")
                        if p in objs else None,
                    })
            result["functions"][spec] = {
                "found": True, "address": "0x%x" % addr,
                "script_bytes": script_num, "object_reference_count": num,
                "object_references": refs,
            }
        out = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(out + "\n")
        print("wrote %d function(s)" % len(result["functions"]))
        return 0
    finally:
        api.close_handle(h)


if __name__ == "__main__":
    raise SystemExit(main())
