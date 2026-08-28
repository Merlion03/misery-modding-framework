#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Targeted P-04 option-C query: among the UFunctions ALREADY
LOADED in the running process, find any that could initiate an object/asset load
for our target while accepting an input we can construct WITHOUT constructing an
FString, without interning a new FName, and without allocator-dependent UE object
construction.

Not a survey: it filters live UFunctions by a small set of load/path/conversion
name patterns, then dumps each candidate's exact reflected parameter ABI and
classifies every input by whether our already-proven ABI can supply it.

Opens the process read-only through ERI's single open call site; writes nothing.
"""
import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
import eri  # noqa: E402

CPF_PARM = 0x0000000000000080
CPF_RETURN = 0x0000000000000400
CPF_OUT = 0x0000000000000100

# Narrow, load/path/conversion oriented name patterns only.
NAME_RE = re.compile(
    r"(load|tryload|resolve|stream|getasset|getobject|makesoft|tosoft|fromsoft"
    r"|staticload|requestasync|findobject|findasset|conv_|packageid|primaryasset"
    r"|softobject|assetpath|objectpath)",
    re.IGNORECASE)

# Property classes that carry a full path/name identity -- these are exactly the
# ones we cannot supply for our target (FString needs the allocator; every
# FName-bearing type needs names that are NOT interned, proven by the FName gate).
IDENTITY_BLOCKED = {
    "FStrProperty": "FString -- requires allocator-dependent construction (blocked)",
    "FNameProperty": "FName -- our target's names are NOT interned (blocked)",
    "FTextProperty": "FText -- strictly worse than FString (blocked)",
}
# Struct properties that are FName-bearing for our target.
STRUCT_BLOCKED_NAMES = {
    "SoftObjectPath": "contains FTopLevelAssetPath (2 FNames) -- not interned (blocked)",
    "SoftClassPath": "same as FSoftObjectPath (blocked)",
    "TopLevelAssetPath": "2 FNames -- not interned (blocked)",
    "PrimaryAssetId": "2 FNames -- not interned (blocked)",
    "PrimaryAssetType": "FName -- not interned (blocked)",
}
POD_OK = {
    "FIntProperty", "FInt64Property", "FUInt32Property", "FUInt64Property",
    "FFloatProperty", "FDoubleProperty", "FBoolProperty", "FByteProperty",
    "FEnumProperty", "FInt8Property", "FInt16Property", "FUInt16Property",
}


def classify(prop):
    pc = prop.get("property_class") or ""
    if pc in IDENTITY_BLOCKED:
        return "BLOCKED", IDENTITY_BLOCKED[pc]
    if pc in ("FSoftObjectProperty", "FSoftClassProperty"):
        return "BLOCKED", "FSoftObjectPtr -- embeds FNames that are not interned (blocked)"
    if pc == "FStructProperty":
        return "BLOCKED?", "struct parameter -- inspect: FName-bearing structs are blocked"
    if pc in ("FObjectProperty", "FClassProperty", "FInterfaceProperty"):
        return "NEEDS-OBJECT", "requires a live UObject* -- our target is not loaded yet"
    if pc in POD_OK:
        return "OK", "plain POD, constructible with the proven ABI"
    if pc in ("FArrayProperty", "FMapProperty", "FSetProperty"):
        return "BLOCKED", "container -- allocator-dependent construction (blocked)"
    if pc in ("FDelegateProperty", "FMulticastInlineDelegateProperty",
              "FMulticastSparseDelegateProperty"):
        return "BLOCKED", "delegate -- needs a bound UObject+FName (blocked)"
    return "UNKNOWN", "unclassified property type"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=None)
    p.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    p.add_argument("--max-candidates", type=int, default=400)
    args = p.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        base, size = i01["base_address"], i01["image_size_bytes"]
        i02 = eri.run_i02(api, handle, base, size,
                          guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(api, handle, base, size,
                          namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        namepool = i03["namepool_live_va"]
        walk = eri.walk_object_universe(
            api, handle, i02["objects_ptr_live_va"], i02["num_elements"], base, size, namepool,
            class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
            name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
            outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objs = walk["objects_by_address"]

        # every live UFunction whose name matches the narrow load/path patterns
        cands = []
        for addr, rec in objs.items():
            if not rec.get("name_ok"):
                continue
            cls = objs.get(rec.get("class_ptr") or 0) or {}
            if cls.get("name_text") != "Function":
                continue
            nm = rec.get("name_text") or ""
            if not NAME_RE.search(nm):
                continue
            cands.append((addr, nm))
        cands.sort(key=lambda x: x[1])

        results = []
        for addr, nm in cands[:args.max_candidates]:
            try:
                parms_size = eri._read_u16(api, handle, addr + eri.UFUNCTION_PARMS_SIZE_OFFSET)
                num_parms = eri._read_u8(api, handle, addr + eri.UFUNCTION_NUM_PARMS_OFFSET)
                cp = eri._read_u64(api, handle, addr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
                props = eri.walk_property_chain(api, handle, cp, namepool_live_va=namepool,
                                                owner_address=addr)
            except Exception:  # noqa: BLE001
                continue
            inputs, ret = [], None
            for pr in props.get("accepted", []):
                raw = pr.get("property_flags_raw")
                fl = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
                if not (fl & CPF_PARM):
                    continue
                entry = {"name": pr.get("raw_name"), "property_class": pr.get("property_class"),
                         "offset": pr.get("offset"), "size": pr.get("size")}
                if fl & CPF_RETURN:
                    ret = entry
                else:
                    verdict, why = classify(pr)
                    entry["verdict"], entry["why"] = verdict, why
                    inputs.append(entry)
            path = eri.resolve_object_path(addr, objs).get("object_path")
            supplyable = bool(inputs) and all(i["verdict"] == "OK" for i in inputs)
            results.append({
                "function": nm, "object_path": path, "parms_size": parms_size,
                "num_parms": num_parms, "inputs": inputs, "return": ret,
                "all_inputs_constructible": supplyable,
            })

        viable = [r for r in results if r["all_inputs_constructible"]]
        out = {
            "pid": i01["pid"],
            "live_functions_matching_patterns": len(cands),
            "analyzed": len(results),
            "candidates_with_all_inputs_constructible": viable,
            "all_results": results,
        }
        print("matched %d live UFunctions by load/path patterns; analyzed %d"
              % (len(cands), len(results)))
        print("candidates whose inputs are ALL constructible with our proven ABI: %d"
              % len(viable))
        for v in viable:
            print("   VIABLE?: %s  ParmsSize=%d  inputs=%s"
                  % (v["object_path"], v["parms_size"],
                     [(i["name"], i["property_class"]) for i in v["inputs"]]))
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                json.dump(out, f, indent=2, sort_keys=True, ensure_ascii=False)
                f.write("\n")
            print("written:", args.out)
        return 0
    finally:
        api.close_handle(handle)


if __name__ == "__main__":
    raise SystemExit(main())
