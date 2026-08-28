#!/usr/bin/env python3
"""Search the live UObject universe for objects whose name or object path
matches a substring (CT-05 observation support).

WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM I-14

CT-05 has to keep three claims apart, because they are routinely conflated and
only the first is cheap to see:

    container mounted   !=   package resolved   !=   UObject loaded

I-14 answers the first and ONLY the first: it reads the engine's list of
mounted `.pak` containers. It says nothing about whether any package inside
such a container was resolved, and nothing about whether anything was loaded.

This tool answers the third. When a package is genuinely loaded, real UObjects
exist for it -- a `UPackage` named for the package path, plus the objects it
contains -- and those live in `GUObjectArray`, which ERI capability I-04
already walks and validates. So "did our asset actually load" is answerable
with read-only reflection we already have, provided something triggered the
load. Finding nothing here is therefore evidence about the OBJECT GRAPH, not
about the container: a package can sit resolvable in a mounted container
forever without ever being loaded, because nothing referenced it.

The middle claim -- resolved but not yet loaded -- is deliberately NOT
answered here. It lives in the package store, which is a different structure
reached a different way, and pretending this tool covers it would be exactly
the conflation the tool exists to prevent.

Strictly read-only: reuses eri.py's own audited single OpenProcess and single
ReadProcessMemory call sites via run_i01..run_i04 and adds no Win32 surface.
"""
import argparse
import json
import os
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
import eri  # noqa: E402


def find(api, handle, base_address, image_size_bytes, needles, *, max_outer_depth):
    """Walk I-04's already-validated object universe and return every object
    whose decoded name, or whose resolved object path, contains any needle
    (case-insensitive)."""
    i02 = eri.run_i02(
        api, handle, base_address, image_size_bytes,
        guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
        sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
        max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03 = eri.run_i03(
        api, handle, base_address, image_size_bytes,
        namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
        name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
        name_entry_id=0)
    walk = eri.walk_object_universe(
        api, handle, i02["objects_ptr_live_va"], i02["num_elements"],
        base_address, image_size_bytes, i03["namepool_live_va"],
        class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
        name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
        outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
        max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    objects = walk["objects_by_address"]

    lowered = [n.lower() for n in needles]
    hits = []
    for address, record in objects.items():
        if not record.get("name_ok"):
            continue
        name = record.get("name_text") or ""
        path = None
        name_hit = any(n in name.lower() for n in lowered)
        if not name_hit:
            # Resolving a path is far more expensive than a name compare, so
            # only pay for it when the cheap test already failed.
            resolved = eri.resolve_object_path(address, objects,
                                               max_depth=max_outer_depth)
            path = resolved.get("object_path")
            if not path or not any(n in path.lower() for n in lowered):
                continue
        if path is None:
            resolved = eri.resolve_object_path(address, objects,
                                               max_depth=max_outer_depth)
            path = resolved.get("object_path")
        class_record = objects.get(record.get("class_ptr") or 0) or {}
        hits.append({
            "address_hex": "0x%x" % address,
            "raw_name": name,
            "object_path": path,
            "class_name": class_record.get("name_text"),
        })
    hits.sort(key=lambda h: (h["object_path"] or "", h["raw_name"]))
    return {"universe_size": len(objects), "hits": hits}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("needle", nargs="+",
                        help="substring(s) to look for in an object's name or path")
    parser.add_argument("--out", help="write the result as JSON here")
    parser.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    parser.add_argument("--max-outer-depth", type=int,
                        default=eri.DEFAULT_I04_MAX_OUTER_DEPTH)
    args = parser.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        result = find(api, handle, i01["base_address"], i01["image_size_bytes"],
                      args.needle, max_outer_depth=args.max_outer_depth)
    finally:
        api.close_handle(handle)

    document = {
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": i01["pid"],
        "needles": args.needle,
        "object_universe_size": result["universe_size"],
        "hit_count": len(result["hits"]),
        "hits": result["hits"],
        "note": ("finding nothing here means no matching UObject is LOADED; it is "
                 "not evidence about whether a container is mounted (that is I-14) "
                 "nor about whether a package is resolvable but unloaded."),
    }
    print("pid %d, %d objects walked, %d hit(s) for %s"
          % (i01["pid"], result["universe_size"], len(result["hits"]), args.needle))
    for hit in result["hits"]:
        print("  %-28s %-22s %s" % (hit["raw_name"], hit["class_name"] or "?",
                                    hit["object_path"] or ""))
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle_out:
            json.dump(document, handle_out, indent=2, sort_keys=True)
            handle_out.write("\n")
        print("written:", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
