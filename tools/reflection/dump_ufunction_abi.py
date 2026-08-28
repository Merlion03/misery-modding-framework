#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Dump the exact, runtime-reflected parameter ABI of named
UFunctions on a named UClass -- the P-04 ABI gate.

Nothing here is hand-authored layout: the UClass is found by walking
GUObjectArray (ERI I-01..I-04), its UFunction children by UStruct::Children
(I-05's own walk_children_chain), and each function's parameters by
UStruct::ChildProperties (I-06's own walk_property_chain). ParmsSize / NumParms /
ReturnValueOffset / FunctionFlags are read from the live UFunction with ERI's own
live-verified offsets. Every parameter's own Offset_Internal, ElementSize and
PropertyFlags come from the live FProperty.

Opens the process with PROCESS_QUERY_INFORMATION|PROCESS_VM_READ only (ERI's
single open_process call site). Writes nothing to the target.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
import eri  # noqa: E402

# ObjectMacros.h property flags relevant to a Parms buffer.
CPF = {
    "CPF_Parm": 0x0000000000000080,
    "CPF_OutParm": 0x0000000000000100,
    "CPF_ReturnParm": 0x0000000000000400,
    "CPF_ConstParm": 0x0000000000000002,
    "CPF_ReferenceParm": 0x0000000008000000,
    "CPF_ZeroConstructor": 0x0000000000000200,
    "CPF_IsPlainOldData": 0x0000000040000000,
    "CPF_NoDestructor": 0x0000001000000000,
}


def decode_flags(flags: int) -> list:
    return [n for n, bit in CPF.items() if flags & bit]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--class-path", default="/Script/Engine.KismetSystemLibrary",
                   help="object path of the UClass that owns the functions")
    p.add_argument("--function", action="append", default=None,
                   help="UFunction name to dump (repeatable)")
    p.add_argument("--out", default=None)
    p.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    args = p.parse_args(argv)
    wanted = set(args.function or ["MakeSoftObjectPath", "LoadAsset_Blocking"])

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    pid, base, size = i01["pid"], i01["base_address"], i01["image_size_bytes"]
    handle = eri.open_process_read_only(api, pid)
    try:
        i02 = eri.run_i02(
            api, handle, base, size,
            guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
            sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(
            api, handle, base, size,
            namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
            name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
            name_entry_id=0)
        namepool = i03["namepool_live_va"]
        walk = eri.walk_object_universe(
            api, handle, i02["objects_ptr_live_va"], i02["num_elements"],
            base, size, namepool,
            class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
            name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
            outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objects_by_address = walk["objects_by_address"]

        # locate the target UClass and the "Function" meta-class by object path.
        # Cheap name compare first, then pay for full path resolution (the same
        # cost discipline find_live_object.py uses).
        target_cls = None
        function_meta = None
        want_cls_name = args.class_path.rsplit(".", 1)[-1]
        for address, record in objects_by_address.items():
            if not record.get("name_ok"):
                continue
            nm = record.get("name_text")
            if nm == want_cls_name and target_cls is None:
                path = eri.resolve_object_path(address, objects_by_address).get("object_path")
                if eri.canonicalize_object_path(path) == eri.canonicalize_object_path(args.class_path):
                    target_cls = {"address": address, "object_path": path}
            elif nm == "Function" and function_meta is None:
                path = eri.resolve_object_path(address, objects_by_address).get("object_path")
                if eri.canonicalize_object_path(path) == "/Script/CoreUObject.Function":
                    function_meta = {"address": address, "object_path": path}
            if target_cls is not None and function_meta is not None:
                break
        if target_cls is None:
            print("BLOCKED: class %s not found in GUObjectArray" % args.class_path,
                  file=sys.stderr)
            return 2
        if function_meta is None:
            print("BLOCKED: /Script/CoreUObject.Function meta-class not found", file=sys.stderr)
            return 2

        cls_addr = target_cls["address"]
        children_ptr = eri._read_u64(api, handle, cls_addr + eri.USTRUCT_CHILDREN_OFFSET)
        chain = eri.walk_children_chain(
            api, handle, children_ptr, namepool_live_va=namepool,
            owner_address=cls_addr, function_class_address=function_meta["address"])

        found = {}
        for fn in chain.get("accepted", []):
            name = fn.get("raw_name")
            if name in wanted:
                found[name] = fn

        result = {"class_path": args.class_path, "class_address": "0x%x" % cls_addr,
                  "pid": pid, "build_sha256": None, "functions": {}}
        for name in sorted(wanted):
            fn = found.get(name)
            if fn is None:
                result["functions"][name] = {"found": False}
                continue
            faddr = fn["address"]
            # UFunction header fields, read live with ERI's own verified offsets.
            function_flags = eri._read_u32(api, handle, faddr + eri.UFUNCTION_FUNCTION_FLAGS_OFFSET)
            num_parms = eri._read_u8(api, handle, faddr + eri.UFUNCTION_NUM_PARMS_OFFSET)
            parms_size = eri._read_u16(api, handle, faddr + eri.UFUNCTION_PARMS_SIZE_OFFSET)
            return_value_offset = eri._read_u16(
                api, handle, faddr + eri.UFUNCTION_RETURN_VALUE_OFFSET_OFFSET)
            cp = eri._read_u64(api, handle, faddr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            props = eri.walk_property_chain(api, handle, cp, namepool_live_va=namepool,
                                            owner_address=faddr)
            params = []
            for pr in props.get("accepted", []):
                raw = pr.get("property_flags_raw")
                flags = int(raw, 16) if isinstance(raw, str) else int(raw or 0)
                if not (flags & CPF["CPF_Parm"]):
                    continue  # only true parameters live in the Parms buffer
                params.append({
                    "name": pr.get("raw_name"),
                    "property_class": pr.get("property_class"),
                    "offset": pr.get("offset"),
                    "size": pr.get("size"),
                    "total_size": pr.get("total_size"),
                    "array_dim": pr.get("array_dim"),
                    "flags_hex": "0x%x" % flags,
                    "flags": decode_flags(flags),
                    "is_return": bool(flags & CPF["CPF_ReturnParm"]),
                    "is_out": bool(flags & CPF["CPF_OutParm"]),
                })
            params.sort(key=lambda x: (x["offset"] if x["offset"] is not None else 1 << 30))
            result["functions"][name] = {
                "found": True,
                "address": "0x%x" % faddr,
                "function_flags": "0x%x" % function_flags,
                "num_parms": num_parms,
                "parms_size": parms_size,
                "return_value_offset": return_value_offset,
                "parameters": params,
                "property_chain_rejected": props.get("rejected_counts"),
            }

        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                json.dump(result, f, indent=2, sort_keys=True, ensure_ascii=False)
                f.write("\n")
        missing = [n for n in wanted if not result["functions"][n].get("found")]
        return 0 if not missing else 3
    finally:
        api.close_handle(handle)


if __name__ == "__main__":
    raise SystemExit(main())
