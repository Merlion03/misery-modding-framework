#!/usr/bin/env python3
"""STRICTLY READ-ONLY. What the live process actually declares for the
lifecycle chain World -> GameInstance -> LocalPlayer -> PlayerController -> Pawn.

This is deliberately NOT a resolver. It is the measurement that a resolver is
allowed to be built from. The difference matters: a resolver that reaches for
``OwningGameInstance`` because that is what Unreal is *supposed* to call it is
guessing, and this project has already paid twice for reporting an intention as
a result. So this tool asks the live class what it declares, by walking the
reflected property chain, and prints the answer.

Nothing here is written into the game. No offset is a constant: every offset
printed was read out of the live ``FProperty`` the engine itself is using.

    python census.py [--out FILE]
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "tools", "reflection")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                       # noqa: E402
import cr01c3_recon as recon     # noqa: E402
import readiness                 # noqa: E402

# The classes whose declared shape decides how a resolver may walk the chain.
# Given by ENGINE path, never by bare name: a bare name can collide with a
# Blueprint class, and "the class named World" is not the same claim as "the
# class at /Script/Engine.World".
CHAIN_CLASSES = [
    "/Script/Engine.World",
    "/Script/Engine.GameInstance",
    "/Script/Engine.LocalPlayer",
    "/Script/Engine.Player",
    "/Script/Engine.PlayerController",
    "/Script/Engine.Controller",
    "/Script/Engine.Pawn",
    "/Script/Engine.Level",
    "/Script/Engine.Actor",
    "/Script/Engine.GameViewportClient",
    "/Script/Engine.Engine",
    "/Script/Engine.GameModeBase",
]

# Property names worth calling out if they exist. This list does NOT drive
# resolution -- the full declared list is dumped regardless. It only marks which
# of the names an Unreal reader would expect are actually present in THIS build,
# so that "expected but absent" is visible instead of silently assumed present.
NAMES_OF_INTEREST = {
    "/Script/Engine.World": ["OwningGameInstance", "PersistentLevel", "Levels", "GameState",
                             "AuthorityGameMode", "WorldType", "NetDriver", "StreamingLevels"],
    "/Script/Engine.GameInstance": ["LocalPlayers", "WorldContext", "OnlineSession"],
    "/Script/Engine.LocalPlayer": ["ViewportClient", "PendingLevelPlayerControllerClass",
                                   "SlateOperations", "PlayerController"],
    "/Script/Engine.Player": ["PlayerController", "CurrentNetSpeed"],
    "/Script/Engine.PlayerController": ["Player", "AcknowledgedPawn", "PlayerCameraManager",
                                        "NetConnection", "MyHUD"],
    "/Script/Engine.Controller": ["Pawn", "PlayerState", "Character"],
    "/Script/Engine.Pawn": ["Controller", "PlayerState"],
    "/Script/Engine.Level": ["OwningWorld", "Actors", "ActorsForGC"],
    "/Script/Engine.Actor": ["Owner", "Instigator", "RootComponent", "Role"],
    "/Script/Engine.GameViewportClient": ["World", "GameInstance"],
    "/Script/Engine.Engine": ["GameViewport", "GameInstance"],
    "/Script/Engine.GameModeBase": ["GameSession", "DefaultPawnClass"],
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None, help="write the full JSON census here")
    args = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    report = {"pid": i01["pid"], "base_address": "0x%x" % i01["base_address"]}
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
        report["objects_total"] = len(objects)
        cache = {}

        def name_of(address):
            return (objects.get(address) or {}).get("name_text") if address else None

        def class_of(address):
            return (objects.get(address) or {}).get("class_ptr") if address else None

        def class_name_of(address):
            return name_of(class_of(address))

        def path_of(address):
            if not address:
                return None
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(address, objects).get("object_path"))
            except Exception:                                  # noqa: BLE001
                return None

        def is_cdo(address):
            return (name_of(address) or "").startswith("Default__")

        # ---- the classes themselves, found BY PATH ------------------------
        by_path = {}
        for address, record in objects.items():
            if not record.get("valid"):
                continue
            if class_name_of(address) not in ("Class", "BlueprintGeneratedClass"):
                continue
            p = path_of(address)
            if p in CHAIN_CLASSES:
                by_path.setdefault(p, []).append(address)

        report["chain_classes"] = {}
        for wanted in CHAIN_CLASSES:
            found = by_path.get(wanted, [])
            entry = {"resolved": len(found) == 1,
                     "candidates": ["0x%x" % a for a in found]}
            if len(found) != 1:
                entry["why"] = ("expected exactly one class at this path, found %d -- "
                                "a resolver may not proceed from an ambiguous class"
                                % len(found))
                report["chain_classes"][wanted] = entry
                continue
            cls = found[0]
            entry["address"] = "0x%x" % cls

            # Walk the full declared property chain of this class only (not its
            # supers): what THIS class adds. Supers are reported separately by
            # walking the chain, so the reader can see where each edge is
            # declared rather than being told a flattened list.
            declared, cursor, depth = [], cls, 0
            while cursor and depth < 32:
                owner = name_of(cursor)
                try:
                    child = eri._read_u64(api, handle,
                                          cursor + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
                    walked = eri.walk_property_chain(
                        api, handle, child, namepool_live_va=namepool,
                        owner_address=cursor, objects_by_address=objects)
                except Exception:                              # noqa: BLE001
                    walked = {"accepted": []}
                for prop in walked.get("accepted", []):
                    declared.append({"declared_on": owner,
                                     "name": prop.get("raw_name"),
                                     "offset": prop.get("offset"),
                                     "size": prop.get("size"),
                                     "property_class": prop.get("property_class")})
                cursor = eri._read_u64(api, handle,
                                       cursor + readiness.USTRUCT_SUPER_STRUCT_OFFSET)
                depth += 1
            entry["declared_property_count"] = len(declared)
            entry["object_properties"] = [d for d in declared
                                          if (d["property_class"] or "").startswith(
                                              ("FObjectProperty", "FWeakObjectProperty",
                                               "FClassProperty", "FArrayProperty",
                                               "FSoftObjectProperty"))]
            entry["all_properties"] = declared
            present = {d["name"] for d in declared}
            wanted_names = NAMES_OF_INTEREST.get(wanted, [])
            entry["names_of_interest"] = {
                n: next((d for d in declared if d["name"] == n), None) for n in wanted_names}
            entry["names_of_interest_absent"] = [n for n in wanted_names if n not in present]
            report["chain_classes"][wanted] = entry

        # ---- the live instances -------------------------------------------
        def instances_of(path, include_cdo=False):
            out = []
            for address, record in objects.items():
                if not record.get("valid") or not record.get("class_ptr"):
                    continue
                if not include_cdo and is_cdo(address):
                    continue
                if path in readiness.ancestor_paths(eri, api, handle, record["class_ptr"],
                                                    objects, cache):
                    out.append(address)
            return out

        report["instances"] = {}
        for path in ("/Script/Engine.World", "/Script/Engine.GameInstance",
                     "/Script/Engine.LocalPlayer", "/Script/Engine.PlayerController",
                     "/Script/Engine.GameViewportClient", "/Script/Engine.Engine",
                     "/Script/Engine.GameModeBase"):
            found = instances_of(path)
            report["instances"][path] = {
                "count": len(found),
                "objects": [{"address": "0x%x" % a, "name": name_of(a),
                             "class": class_name_of(a), "path": path_of(a),
                             "outer": path_of(eri._read_u64(
                                 api, handle, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET))}
                            for a in found]}

        # ---- for every live World, read whatever it declares ---------------
        # This is the M4 problem in one place: the runner already reports eight
        # live Worlds. Naming the active one is the work.
        world_cls = by_path.get("/Script/Engine.World", [None])[0]
        worlds = instances_of("/Script/Engine.World")
        report["worlds"] = []
        for w in worlds:
            entry = {"address": "0x%x" % w, "name": name_of(w), "path": path_of(w),
                     "class": class_name_of(w), "fields": {}}
            wcls = class_of(w)
            for field in NAMES_OF_INTEREST["/Script/Engine.World"]:
                found = readiness.resolve_property(eri, api, handle, wcls, objects,
                                                   namepool, (field,))
                if not found:
                    entry["fields"][field] = {"resolved": False}
                    continue
                info = {"resolved": True, "offset": found["offset"],
                        "property_class": found["property_class"],
                        "size": found["size"], "declared_on": found["declared_on"]}
                try:
                    if found["property_class"] == "FObjectProperty" and found["size"] == 8:
                        v = eri._read_u64(api, handle, w + int(found["offset"]))
                        info["value"] = "0x%x" % v
                        info["value_name"] = name_of(v)
                        info["value_class"] = class_name_of(v)
                        info["value_path"] = path_of(v)
                    elif found["property_class"] == "FArrayProperty":
                        data = eri._read_u64(api, handle, w + int(found["offset"]))
                        num = struct.unpack("<i", api.read_process_memory(
                            handle, w + int(found["offset"]) + 8, 4))[0]
                        info["array"] = {"data": "0x%x" % data, "num": num}
                        if data and 0 < num <= 256:
                            raw = api.read_process_memory(handle, data, num * 8)
                            info["array"]["elements"] = [
                                {"address": "0x%x" % e, "name": name_of(e),
                                 "class": class_name_of(e)}
                                for e in struct.unpack("<%dQ" % num, raw)]
                    else:
                        raw = api.read_process_memory(handle, w + int(found["offset"]),
                                                      min(int(found["size"]) or 1, 8))
                        info["raw_bytes"] = raw.hex()
                        if int(found["size"]) == 1:
                            info["as_uint8"] = raw[0]
                except Exception as exc:                       # noqa: BLE001
                    info["read_error"] = repr(exc)
                entry["fields"][field] = info
            report["worlds"].append(entry)

        # ---- the EWorldType enum, read from live reflection ----------------
        # Reading the enum rather than trusting a remembered value: the numeric
        # meaning of WorldType is the whole basis for "which world is the game".
        enums = [a for a, r in objects.items()
                 if r.get("valid") and r.get("name_text") == "EWorldType"]
        report["EWorldType_objects"] = [{"address": "0x%x" % a, "class": class_name_of(a),
                                         "path": path_of(a)} for a in enums]
    finally:
        api.close_handle(handle)

    out = args.out or os.path.join(
        REPO, "research", "instruments", "lifecycle", "census-latest.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=False, default=str)
        f.write("\n")

    # A short human summary; the JSON is the record.
    print("pid %d, %d objects" % (report["pid"], report["objects_total"]))
    print("\nchain classes:")
    for path, entry in report["chain_classes"].items():
        if not entry.get("resolved"):
            print("  %-42s UNRESOLVED (%s)" % (path, entry.get("why")))
            continue
        absent = entry["names_of_interest_absent"]
        print("  %-42s %3d props%s" % (path, entry["declared_property_count"],
                                       ("  ABSENT: %s" % ", ".join(absent)) if absent else ""))
    print("\ninstances:")
    for path, entry in report["instances"].items():
        print("  %-42s %d" % (path, entry["count"]))
    print("\nworlds:")
    for w in report["worlds"]:
        f = w["fields"]
        def show(k):
            v = f.get(k, {})
            if not v.get("resolved"):
                return "%s=UNRESOLVED" % k
            if "value_name" in v:
                return "%s=%s" % (k, v["value_name"])
            if "array" in v:
                return "%s[%d]" % (k, v["array"]["num"])
            if "as_uint8" in v:
                return "%s=%d" % (k, v["as_uint8"])
            return "%s=?" % k
        print("  %-28s %s" % (w["name"], "  ".join(
            show(k) for k in ("WorldType", "OwningGameInstance", "PersistentLevel",
                              "AuthorityGameMode", "GameState", "Levels"))))
    print("\nwrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
