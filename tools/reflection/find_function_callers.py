#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Which live UFunctions call a named UFunction?

Two independent detections, because Blueprint bytecode encodes a call in two
different ways and each one is invisible to the other detector:

  (1) POINTER form -- EX_FinalFunction / EX_LocalFinalFunction embed the callee
      UFunction* directly in the bytecode. Every such pointer is also recorded
      in the caller's UStruct::ScriptAndPropertyObjectReferences array (+0x90,
      the offset CR-01B's lookup closure already forced and used), so scanning
      that array finds these calls without decoding a single opcode.

  (2) NAME form -- EX_VirtualFunction / EX_LocalVirtualFunction embed an FName
      instead of a pointer, so no object reference exists to scan. These are
      found by searching the caller's own Script bytecode for the callee's
      FNameEntryId, always immediately preceded by the corresponding opcode
      byte so a coincidental integer in an unrelated operand is not counted.

Reporting both, and reporting them separately, is the point: a single detector
would silently under-report and make "nothing calls this" look proven when it
is only unobserved.

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

# UStruct members, past the ERI-verified ChildProperties@0x50. SPOR is the
# offset CR-01B's lookup closure derived and used for exactly this array.
# UStruct member offsets, forced by exact prefix sums from the ERI-verified
# ChildProperties@0x50 over the source order in Class.h:394-424, and closing
# exactly on the ERI-verified Shipping UStruct size 0xB0:
#   0x50 ChildProperties (verified)     0x58 PropertiesSize (used by CR-01C2R)
#   0x5C MinAlignment                   0x60 Script          TArray<uint8>, 16B
#   0x70 PropertyLink   0x78 RefLink    0x80 DestructorLink  0x88 PostConstructLink
#   0x90 ScriptAndPropertyObjectReferences (used by CR-01B)  TArray, 16B
#   0xA0 UnresolvedScriptProperties     0xA8 UnversionedGameSchema (!WITH_EDITORONLY_DATA)
#   0xB0 == verified total size
USTRUCT_SCRIPT_OFFSET = 0x60          # TArray<uint8> Script
USTRUCT_SPOR_OFFSET = 0x90            # TArray<UObject*> ScriptAndPropertyObjectReferences

# Script.h EExprToken -- the four call opcodes that take a name, not a pointer.
EX_VIRTUAL_FUNCTION = 0x1B
EX_FINAL_FUNCTION = 0x1C
EX_LOCAL_VIRTUAL_FUNCTION = 0x45
EX_LOCAL_FINAL_FUNCTION = 0x46
NAME_CALL_OPCODES = {EX_VIRTUAL_FUNCTION: "EX_VirtualFunction",
                     EX_LOCAL_VIRTUAL_FUNCTION: "EX_LocalVirtualFunction"}
PTR_CALL_OPCODES = {EX_FINAL_FUNCTION: "EX_FinalFunction",
                    EX_LOCAL_FINAL_FUNCTION: "EX_LocalFinalFunction"}


def read_tarray_bytes(api, h, addr, elem, cap):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not data or num <= 0 or num > cap:
        return None, num
    try:
        return api.read_process_memory(h, data, num * elem), num
    except Exception:  # noqa: BLE001
        return None, num


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", action="append", required=True,
                    help="UFunction name to find callers of (repeatable)")
    ap.add_argument("--owner", action="append", default=None,
                    help="restrict targets to functions owned by this class name (repeatable)")
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
            if r.get("name_ok") and r.get("name_text") == "Function":
                if eri.canonicalize_object_path(
                        eri.resolve_object_path(addr, objs).get("object_path")) \
                        == "/Script/CoreUObject.Function":
                    fmeta = addr
                    break
        if fmeta is None:
            print("BLOCKED: Function meta-class not found", file=sys.stderr)
            return 2

        wanted = set(a.target)
        owners = set(a.owner or [])
        # 1. locate every target UFunction object and its FNameEntryId
        targets = {}
        for addr, r in objs.items():
            if r.get("class_ptr") != fmeta or not r.get("name_ok"):
                continue
            nm = r.get("name_text")
            if nm not in wanted:
                continue
            path = eri.resolve_object_path(addr, objs).get("object_path") or ""
            owner = path.rsplit(":", 1)[0].rsplit(".", 1)[-1]
            if owners and owner not in owners:
                continue
            eid = eri._read_u32(api, h, addr + eri.DEFAULT_NAME_PRIVATE_OFFSET)
            targets["%s::%s" % (owner, nm)] = {
                "address": addr, "name": nm, "owner": owner,
                "object_path": path, "name_entry_id": eid,
                "script_bytes": None, "spor_count": None,
            }
        if not targets:
            print("BLOCKED: no target UFunction matched", file=sys.stderr)
            return 3

        by_addr = {v["address"]: k for k, v in targets.items()}
        by_eid = {}
        for k, v in targets.items():
            by_eid.setdefault(v["name_entry_id"], []).append(k)

        # target's own body size, useful to tell a real implementation from a stub
        for k, v in targets.items():
            sc, n = read_tarray_bytes(api, h, v["address"] + USTRUCT_SCRIPT_OFFSET, 1, 1 << 22)
            v["script_bytes"] = n
            sp = eri._read_u64(api, h, v["address"] + USTRUCT_SPOR_OFFSET)
            v["spor_count"] = struct.unpack("<i", api.read_process_memory(
                h, v["address"] + USTRUCT_SPOR_OFFSET + 8, 4))[0] if sp else 0

        # 2. scan every live UFunction for both call forms
        callers = {k: {"pointer_form": [], "name_form": [], "bytecode_pointer_form": []}
                   for k in targets}
        scanned = 0
        for addr, r in objs.items():
            if r.get("class_ptr") != fmeta:
                continue
            scanned += 1
            caller_path = None

            raw, cnt = read_tarray_bytes(api, h, addr + USTRUCT_SPOR_OFFSET, 8, 8192)
            if raw:
                for i in range(cnt):
                    p = struct.unpack_from("<Q", raw, i * 8)[0]
                    key = by_addr.get(p)
                    if key and p != addr:
                        if caller_path is None:
                            caller_path = eri.resolve_object_path(addr, objs).get("object_path")
                        callers[key]["pointer_form"].append(
                            {"caller": caller_path, "caller_name": r.get("name_text")})

            script, snum = read_tarray_bytes(api, h, addr + USTRUCT_SCRIPT_OFFSET, 1, 1 << 22)
            if script:
                # FScriptName is 12 bytes (NameTypes.h: ComparisonIndex,
                # DisplayIndex, Number), so a name call needs 13 bytes.
                for i in range(len(script) - 13):
                    op = script[i]
                    if op in NAME_CALL_OPCODES:
                        eid = struct.unpack_from("<I", script, i + 1)[0]
                        for key in by_eid.get(eid, ()):
                            if addr == targets[key]["address"]:
                                continue
                            if caller_path is None:
                                caller_path = eri.resolve_object_path(addr, objs).get("object_path")
                            callers[key]["name_form"].append(
                                {"caller": caller_path, "caller_name": r.get("name_text"),
                                 "opcode": NAME_CALL_OPCODES[op], "script_offset": i})
                    elif op in PTR_CALL_OPCODES:
                        ptr = struct.unpack_from("<Q", script, i + 1)[0]
                        key = by_addr.get(ptr)
                        if key and ptr != addr:
                            if caller_path is None:
                                caller_path = eri.resolve_object_path(addr, objs).get("object_path")
                            callers[key]["bytecode_pointer_form"].append(
                                {"caller": caller_path, "caller_name": r.get("name_text"),
                                 "opcode": PTR_CALL_OPCODES[op], "script_offset": i})

        result = {"pid": i01["pid"], "ufunctions_scanned": scanned, "targets": {}}
        for k, v in targets.items():
            pf = callers[k]["pointer_form"]
            nf = callers[k]["name_form"]
            bpf = callers[k]["bytecode_pointer_form"]
            result["targets"][k] = {
                "address": "0x%x" % v["address"],
                "object_path": v["object_path"],
                "name_entry_id": v["name_entry_id"],
                "own_script_bytes": v["script_bytes"],
                "own_object_reference_count": v["spor_count"],
                "caller_count_object_reference_form": len(pf),
                "caller_count_bytecode_pointer_form": len(bpf),
                "caller_count_name_form": len(nf),
                "callers_object_reference_form": pf,
                "callers_bytecode_pointer_form": bpf,
                "callers_name_form": nf,
            }
        out = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(out + "\n")
        print(out)
        return 0
    finally:
        api.close_handle(h)


if __name__ == "__main__":
    raise SystemExit(main())
