#!/usr/bin/env python3
"""CR-01 gameplay semantic reconnaissance (plan.md 14.4 / M3 exit criterion 5).

Read-only. Reuses research/instruments/eri/eri.py's own already-tested
I-01..I-06 functions as a library (same reuse pattern as
research/instruments/ipp/ipp_controller.py's resolve_target()) -- makes no
Win32 write/execute call of any kind, never opens a handle with
PROCESS_VM_WRITE/PROCESS_VM_OPERATION.

What this does that a plain I-04 run does not:
  1. Uses classify_classes_by_module()'s own FULL 'game' bucket (every class
     whose package starts with /Game/), not select_game_sample()'s bounded,
     capped sample -- I-04's own committed classes.jsonl output is
     deliberately capped at DEFAULT_I04_GAME_SAMPLE_CAP (25) for the
     COMMITTED artifact; this script needs the true count to find rare,
     semantically-relevant classes a small cap would miss.
  2. Cross-references any class whose module is NEITHER /Script/MISERY NOR
     /Game/* against research/evidence/RF-02/module-classification.tsv
     (M2s's own engine/game-plugin split of all 394 root /Script/* modules
     from global.ucas) -- catches a class living in a genuine game-plugin
     module (e.g. a native gameplay plugin), which classify_classes_by_module()
     itself deliberately leaves "unclassified" (out of its own stated scope).
  3. Filters every candidate by a case-insensitive substring match against a
     fixed list of gameplay-domain keywords (Item, Inventory, Weapon, ...).
  4. For each surviving candidate, additionally reads UStruct::SuperStruct
     (+0x40, HYPOTHESIS in research/unreal/structures.md -- not decoded by
     any existing I-0N capability) to resolve one level of parent class,
     walking up to --max-parent-depth levels, resolving each parent's own
     name/object_path against the SAME already-walked objects_by_address
     universe (no new GUObjectArray read).
  5. Counts live instances: how many objects in this run's own object
     universe have ClassPrivate == the candidate's own address.

Everything above is read-only positional memory reading via
api.read_process_memory(), the exact same primitive every I-0N capability
already uses -- this script adds no new Win32 API surface whatsoever.
"""
import argparse
import json
import os
import re
import struct
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
import eri  # noqa: E402

# UStruct::SuperStruct, Class.h:394 -- see research/unreal/structures.md,
# HYPOTHESIS (source-derived, not yet independently live-confirmed the way
# Children/ChildProperties/ClassDefaultObject were). Reading it here is
# itself part of what would promote it: every resolved parent name that
# round-trips through the SAME live object universe (i.e. the parent address
# is itself a real classified UClass already in class_address_universe) is
# corroborating evidence, recorded explicitly in this script's own output.
SUPERSTRUCT_OFFSET = 0x40

DEFAULT_KEYWORDS = [
    "Item", "Inventory", "Weapon", "Equipment", "Loot", "Pickup", "Player",
    "Character", "Interact", "Craft", "Container", "Save", "GameInstance",
    "World", "Actor", "DataAsset", "DataTable",
]

RF02_TSV = os.path.join(REPO_ROOT, "research", "evidence", "RF-02", "module-classification.tsv")


def load_rf02_classification():
    """module -> bucket ('engine'/'game-misery'/'game-plugin'/'unclassified'),
    from M2s's own RF-02 artifact. Read-only, static file, no live read."""
    mapping = {}
    if not os.path.isfile(RF02_TSV):
        return mapping
    with open(RF02_TSV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                mapping[parts[0]] = parts[1]
    return mapping


def keyword_match(name: str, keywords: list) -> list:
    lname = name.lower()
    return [kw for kw in keywords if kw.lower() in lname]


def resolve_parent_chain(address: int, objects_by_address: dict, api, handle: int,
                         max_depth: int) -> list:
    """Reads SuperStruct at *address*+SUPERSTRUCT_OFFSET, resolves it against
    the ALREADY-walked objects_by_address universe (no new GUObjectArray
    read), repeats up to max_depth times. Returns a list of
    {'address_hex', 'raw_name', 'object_path', 'in_class_universe'} dicts,
    outermost (nearest) parent first. Stops early on a null pointer, an
    unresolvable address, or max_depth."""
    chain = []
    current = address
    for _ in range(max_depth):
        try:
            raw = api.read_process_memory(handle, current + SUPERSTRUCT_OFFSET, 8)
        except eri.ReadProcessMemoryFailedError:
            break
        parent_addr = struct.unpack("<Q", raw)[0]
        if parent_addr == 0:
            break
        record = objects_by_address.get(parent_addr)
        if record is None or not record.get("valid"):
            chain.append({"address_hex": "0x%x" % parent_addr, "raw_name": None,
                          "object_path": None, "in_class_universe": False})
            break
        chain.append({
            "address_hex": "0x%x" % parent_addr,
            "raw_name": record.get("name_text"),
            "object_path": None,
            "in_class_universe": True,
        })
        current = parent_addr
    return chain


def count_live_instances(address: int, objects_by_address: dict) -> int:
    return sum(1 for record in objects_by_address.values()
              if record.get("valid") and record.get("class_ptr") == address)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keywords", nargs="*", default=DEFAULT_KEYWORDS)
    parser.add_argument("--max-parent-depth", type=int, default=6)
    parser.add_argument("--out", required=True)
    parser.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    args = parser.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    pid = i01["pid"]
    base_address = i01["base_address"]
    image_size_bytes = i01["image_size_bytes"]

    i02_handle = eri.open_process_read_only(api, pid)
    try:
        i02_result = eri.run_i02(
            api, i02_handle, base_address, image_size_bytes,
            guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
            sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    finally:
        api.close_handle(i02_handle)

    handle = eri.open_process_read_only(api, pid)
    try:
        i03_result = eri.run_i03(
            api, handle, base_address, image_size_bytes,
            namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
            name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
            name_entry_id=0)

        i04_result = eri.run_i04(
            api, handle, base_address, image_size_bytes,
            i02_result["objects_ptr_live_va"], i02_result["num_elements"],
            i03_result["namepool_live_va"],
            class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
            name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
            outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
            max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES,
            max_outer_depth=eri.DEFAULT_I04_MAX_OUTER_DEPTH,
            max_fixed_point_passes=eri.DEFAULT_I04_MAX_FIXED_POINT_PASSES)

        if not i04_result["seed_found"]:
            print("I-04 seed not found this run -- aborting", file=sys.stderr)
            return 2

        objects_by_address = i04_result["objects_by_address"]
        all_classes = i04_result["classes"]
        buckets = eri.classify_classes_by_module(all_classes)
        rf02 = load_rf02_classification()

        # "other" bucket, cross-referenced against RF-02: keep only classes
        # whose module RF-02 did NOT already establish as a real engine
        # module (bucket == 'engine'). Modules RF-02 never saw at all
        # (module is None, or a /Script/* name absent from the TSV) are
        # kept too -- absence from a STATIC (offline, older-build) list is
        # not proof of "engine", only silence.
        other_candidates = []
        for record in buckets["other"]:
            module = record.get("module")
            rf02_bucket = rf02.get(module) if module else None
            if rf02_bucket == "engine":
                continue
            other_candidates.append(dict(record, rf02_module_bucket=rf02_bucket))

        pools = {
            "misery": buckets["misery"],
            "game": buckets["game"],
            "other_non_engine": other_candidates,
        }

        matches = []
        for pool_name, records in pools.items():
            for record in records:
                hits = keyword_match(record["raw_name"], args.keywords)
                # misery + game are always small (single/double digits observed
                # this session) -- dump them in full regardless of keyword
                # match, not only the filtered subset, so nothing gets missed
                # by an incomplete keyword list. other_non_engine can be large
                # (100+), so it stays keyword-filtered only.
                always_dump = pool_name in ("misery", "game")
                if not hits and not always_dump:
                    continue
                address = record["address"]
                parent_chain = resolve_parent_chain(
                    address, objects_by_address, api, handle, args.max_parent_depth)
                live_count = count_live_instances(address, objects_by_address)
                matches.append({
                    "pool": pool_name,
                    "address_hex": "0x%x" % address,
                    "raw_name": record["raw_name"],
                    "object_path": record.get("object_path"),
                    "package": record.get("package"),
                    "module": record.get("module"),
                    "is_blueprint_generated": record.get("is_blueprint_generated"),
                    "keyword_hits": hits,
                    "parent_chain": parent_chain,
                    "live_instance_count": live_count,
                })

        document = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": pid,
            "keywords": args.keywords,
            "class_universe_size": len(objects_by_address),
            "pool_sizes": {k: len(v) for k, v in pools.items()},
            "match_count": len(matches),
            "matches": matches,
        }
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document, f, indent=2, sort_keys=True)
            f.write("\n")
        print("pool sizes:", {k: len(v) for k, v in pools.items()})
        print("matches:", len(matches))
        print("written:", args.out)
    finally:
        api.close_handle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
