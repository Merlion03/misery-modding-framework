#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Expand the Blueprint call graph below a named UFunction
and report, per reachable function, whether its bytecode references a given
UObject (by default the live ItemList UDataTable).

Why: "does the inventory path resolve the item definition, and where" cannot be
answered from one function's own object-reference array -- the reference may sit
several BP calls deeper. This walks the callee edges the same two ways
find_function_callers.py detects caller edges (EX_*VirtualFunction by FName,
EX_*FinalFunction by embedded UFunction*), so a name-dispatched edge is not
silently missed.

An FName edge is resolved against the live universe by name; when several
UFunctions share a name the edge is reported as ambiguous and every candidate is
listed rather than one being picked. Nothing is written to the target.
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
import eri  # noqa: E402

USTRUCT_SCRIPT_OFFSET = 0x60
USTRUCT_SPOR_OFFSET = 0x90
NAME_CALL = {0x1B: "EX_VirtualFunction", 0x45: "EX_LocalVirtualFunction"}
PTR_CALL = {0x1C: "EX_FinalFunction", 0x46: "EX_LocalFinalFunction"}


def tarray(api, h, addr, elem, cap):
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
    ap.add_argument("--root", action="append", required=True,
                    help="Owner::Function to expand from (repeatable)")
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--watch-object", action="append",
                    default=None, help="object name to flag references to (default ItemList)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    watch_names = set(a.watch_object or ["ItemList"])

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
        watched = {}
        for addr, r in objs.items():
            if not r.get("name_ok"):
                continue
            nm = r.get("name_text")
            if nm == "Function" and fmeta is None and eri.canonicalize_object_path(
                    eri.resolve_object_path(addr, objs).get("object_path")) \
                    == "/Script/CoreUObject.Function":
                fmeta = addr
            if nm in watch_names:
                cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                watched[addr] = {"name": nm, "class": cn}
        if fmeta is None:
            print("BLOCKED: Function meta-class not found", file=sys.stderr)
            return 2

        # index every live UFunction by address and by name
        fns_by_addr, fns_by_name = {}, {}
        for addr, r in objs.items():
            if r.get("class_ptr") != fmeta:
                continue
            path = eri.resolve_object_path(addr, objs).get("object_path") or ""
            owner = path.rsplit(":", 1)[0].rsplit(".", 1)[-1]
            nm = r.get("name_text")
            key = "%s::%s" % (owner, nm)
            fns_by_addr[addr] = {"key": key, "name": nm, "owner": owner, "path": path}
            fns_by_name.setdefault(nm, []).append(addr)

        cache = {}

        def analyse(addr):
            if addr in cache:
                return cache[addr]
            info = dict(fns_by_addr[addr])
            script, snum = tarray(api, h, addr + USTRUCT_SCRIPT_OFFSET, 1, 1 << 22)
            info["script_bytes"] = snum if script else 0
            refs, cnt = tarray(api, h, addr + USTRUCT_SPOR_OFFSET, 8, 8192)
            hits = []
            if refs:
                for i in range(cnt):
                    p = struct.unpack_from("<Q", refs, i * 8)[0]
                    if p in watched:
                        hits.append(watched[p]["name"])
            info["references_watched"] = sorted(set(hits))
            callee_names, callee_ptrs = set(), set()
            if script:
                for i in range(len(script) - 13):
                    op = script[i]
                    if op in NAME_CALL:
                        eid = struct.unpack_from("<I", script, i + 1)[0]
                        try:
                            d = eri.decode_fname_entry_id(api, h, np, eid)
                            t = d.get("text") if isinstance(d, dict) else None
                        except Exception:  # noqa: BLE001
                            t = None
                        if t:
                            callee_names.add(t)
                    elif op in PTR_CALL:
                        p = struct.unpack_from("<Q", script, i + 1)[0]
                        if p in fns_by_addr:
                            callee_ptrs.add(p)
            info["callee_names"] = sorted(callee_names)
            info["callee_pointers"] = sorted(fns_by_addr[p]["key"] for p in callee_ptrs)
            info["_callee_name_set"] = callee_names
            info["_callee_ptr_set"] = callee_ptrs
            cache[addr] = info
            return info

        roots = []
        for spec in a.root:
            owner, _, fn = spec.partition("::")
            for addr in fns_by_name.get(fn, ()):
                if fns_by_addr[addr]["owner"] == owner:
                    roots.append(addr)
        if not roots:
            print("BLOCKED: no root matched", file=sys.stderr)
            return 3

        seen, frontier, out_nodes, ambiguous = set(roots), list(roots), {}, {}
        for level in range(a.depth):
            nxt = []
            for addr in frontier:
                info = analyse(addr)
                out_nodes[info["key"]] = {
                    "depth": level, "path": info["path"],
                    "script_bytes": info["script_bytes"],
                    "references_watched": info["references_watched"],
                    "callee_names": info["callee_names"],
                    "callee_pointers": info["callee_pointers"],
                }
                for p in info["_callee_ptr_set"]:
                    if p not in seen:
                        seen.add(p)
                        nxt.append(p)
                for nm in info["_callee_name_set"]:
                    cands = fns_by_name.get(nm, [])
                    if len(cands) > 1:
                        ambiguous.setdefault(nm, sorted(fns_by_addr[c]["key"] for c in cands))
                    for c in cands:
                        if c not in seen:
                            seen.add(c)
                            nxt.append(c)
            frontier = nxt
            if not frontier:
                break

        result = {
            "pid": i01["pid"], "roots": a.root, "depth": a.depth,
            "watched_objects": {"%s" % v["name"]: {"address": "0x%x" % k, "class": v["class"]}
                                for k, v in watched.items()},
            "nodes_expanded": len(out_nodes),
            "nodes_referencing_watched": sorted(
                k for k, v in out_nodes.items() if v["references_watched"]),
            "ambiguous_name_edges": ambiguous,
            "nodes": out_nodes,
        }
        out = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(out + "\n")
        print(json.dumps({k: result[k] for k in
                          ("pid", "roots", "nodes_expanded", "nodes_referencing_watched")},
                         indent=2, sort_keys=True))
        return 0
    finally:
        api.close_handle(h)


if __name__ == "__main__":
    raise SystemExit(main())
