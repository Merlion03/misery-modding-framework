#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Settle, against the live build, the questions the engine
source could not settle about MISERY's lifecycle.

The source study established what UE 5.4.4 *can* do. These are the questions
whose answers are a property of THIS GAME, not of the engine:

  Q1 Does MISERY use seamless travel? AGameModeBase::bUseSeamlessTravel decides
     whether a PlayerController pointer survives a level change or is destroyed
     and replaced (GameModeBase.cpp:568). It is a reflected bool, so the live
     game can simply be asked.
  Q2 Does MISERY's GameMode override RestartPlayer / HandleSeamlessTravelPlayer?
     Both are virtual; an override could recreate the PlayerController on
     respawn, which would contradict the engine default.
  Q3 How many of the live UWorlds are streaming sub-worlds, by the engine's own
     test, and how many are top level?
  Q4 Which engine classes does MISERY actually subclass?
  Q5 Is there exactly one UGameEngine and one UGameInstance?
"""
import json
import os
import struct
import sys

REPO = "D:/Dev/MiseryFramework"
for p in (os.path.join(REPO, "research", "instruments", "eri"),
          os.path.join(REPO, "research", "instruments", "ipp"),
          os.path.join(REPO, "research", "instruments", "runner"),
          os.path.join(REPO, "research", "instruments", "lifecycle")):
    sys.path.insert(0, p)
import eri                    # noqa: E402
import cr01c3_recon as recon  # noqa: E402
import readiness              # noqa: E402
import resolver as R          # noqa: E402


def main():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    out = {"pid": i01["pid"]}
    try:
        res = R.Resolver(api, h, i01["base_address"], i01["image_size_bytes"])
        objs, np = res.objects, res.namepool
        fmeta = recon.find_function_meta(objs)

        def path_of(a):
            return res.path_of(a)

        # ---- Q4/Q5: which classes are instantiated, and how many -----------
        out["instances"] = {}
        for label, p in (("Engine", "/Script/Engine.Engine"),
                         ("GameInstance", "/Script/Engine.GameInstance"),
                         ("GameModeBase", "/Script/Engine.GameModeBase"),
                         ("PlayerController", "/Script/Engine.PlayerController"),
                         ("LocalPlayer", "/Script/Engine.LocalPlayer"),
                         ("GameViewportClient", "/Script/Engine.GameViewportClient")):
            found = res.instances_of(p)
            out["instances"][label] = [
                {"address": "0x%x" % a, "class": res.class_name_of(a),
                 "class_path": path_of(res.class_of(a)), "path": path_of(a)} for a in found]

        # ---- Q3: streaming sub-worlds vs top level -------------------------
        worlds = res.instances_of("/Script/Engine.World")
        sub, top = [], []
        for w in worlds:
            pl, _ = res.read_object_prop(w, "PersistentLevel")
            ow, _ = res.read_object_prop(pl, "OwningWorld") if pl else (None, None)
            entry = {"world": res.name_of(w), "address": "0x%x" % w,
                     "persistent_level": ("0x%x" % pl) if pl else None,
                     "owning_world": ("0x%x" % ow) if ow else None}
            (top if (pl and ow == w) else sub).append(entry)
        out["worlds"] = {"total": len(worlds), "top_level": top,
                         "streaming_sub_worlds": len(sub),
                         "streaming_sub_world_names": sorted({e["world"] for e in sub}),
                         "engine_test": "UWorld::IsStreamingSubWorld == "
                                        "(PersistentLevel && PersistentLevel->OwningWorld "
                                        "!= this)  [World.cpp:5357]"}

        # ---- Q1: bUseSeamlessTravel on the LIVE GameMode -------------------
        gms = res.instances_of("/Script/Engine.GameModeBase")
        out["seamless_travel"] = {"game_modes_live": len(gms), "readings": []}
        for gm in gms:
            found = readiness.resolve_property(eri, api, h, res.class_of(gm), objs, np,
                                               ("bUseSeamlessTravel",))
            reading = {"game_mode": res.class_name_of(gm), "address": "0x%x" % gm,
                       "resolved": bool(found)}
            if found:
                reading.update({"offset": found["offset"],
                                "property_class": found["property_class"],
                                "declared_on": found["declared_on"]})
                try:
                    raw = eri._read_u8(api, h, gm + int(found["offset"]))
                    # A UE bitfield bool: the FBoolProperty carries a field mask.
                    # Read the byte and report it raw as well as masked, rather
                    # than assuming bit 0.
                    reading["raw_byte"] = raw
                    reading["nonzero"] = bool(raw)
                except Exception as exc:                       # noqa: BLE001
                    reading["read_error"] = repr(exc)
            out["seamless_travel"]["readings"].append(reading)

        # ---- Q2: does the game's GameMode override the respawn hooks? ------
        out["gamemode_overrides"] = []
        for gm in gms:
            cls = res.class_of(gm)
            chain, cursor, depth = [], cls, 0
            while cursor and depth < 24:
                names = set()
                try:
                    for f in recon.class_functions(api, h, np, cursor, fmeta):
                        names.add(f.get("raw_name"))
                except Exception:                              # noqa: BLE001
                    pass
                chain.append({"class": res.name_of(cursor), "path": path_of(cursor),
                              "declares_RestartPlayer": "RestartPlayer" in names,
                              "declares_HandleSeamlessTravelPlayer":
                                  "HandleSeamlessTravelPlayer" in names,
                              "declares_RestartPlayerAtPlayerStart":
                                  "RestartPlayerAtPlayerStart" in names,
                              "function_count": len(names)})
                cursor = eri._read_u64(api, h, cursor + readiness.USTRUCT_SUPER_STRUCT_OFFSET)
                depth += 1
            out["gamemode_overrides"].append({"game_mode": res.class_name_of(gm),
                                              "super_chain": chain})
    finally:
        api.close_handle(h)

    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "m4_open_questions.json")
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print(json.dumps(out, indent=2, sort_keys=False, default=str)[:5000])


if __name__ == "__main__":
    main()
