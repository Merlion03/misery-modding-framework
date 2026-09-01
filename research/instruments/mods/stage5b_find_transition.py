#!/usr/bin/env python3
"""RESEARCH ONLY. Find a way to make the live game load a level.

WHY
---
Step 3's second acceptance needs a real content transition with a GAMEPLAY
generation on both sides:

    generation N (gameplay), item live and resolvable
      -> a real transition
      -> N revoked, nothing stale consumable
      -> generation N+1 (gameplay), declaration reapplied, resolvable again

Driving that through the UI is not available: the runner's screen classifier
identifies a screen by which Blueprint classes have LIVE instances, and a UMG
pause menu is typically constructed once and then shown and hidden, so it
changes no signature at all. One Escape from gameplay, with focus verified,
moved not a single class (research/evidence/STAGE5B, pause probe).

So the transition is caused directly instead, by calling the engine's own level
transition through reflection -- the same ProcessEvent path CR-01C5 already
uses. This instrument only LOOKS: it reports which candidate functions exist in
this build, what they cost to call, and which live object could receive them.
It calls nothing.

WHAT IT LOOKS FOR
-----------------
A zero-parameter transition is worth a great deal here, because a call with no
parameter block cannot get a parameter block wrong. APlayerController's
RestartLevel is the first candidate for exactly that reason. Everything else is
recorded so the choice is made from what this build actually has.
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "mods")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                              # noqa: E402
import cr01c3_recon as recon                            # noqa: E402
import lifecycle                                        # noqa: E402

# Names worth having, most preferred first. RestartLevel leads because it takes
# no parameters; the others are recorded for completeness and as fallbacks.
WANTED = ("RestartLevel", "ServerTravel", "OpenLevel", "ClientTravel",
          "ExecuteConsoleCommand", "LoadStreamLevel")

# Classes whose live instances could receive one of these.
RECEIVERS = ("PlayerController", "GameplayStatics", "KismetSystemLibrary")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    live = lifecycle.find_processes()
    if len(live) != 1:
        raise SystemExit("expected exactly one live MISERY process, found %d"
                         % len(live))
    pid = live[0]["pid"]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    base, size = i01["base_address"], i01["image_size_bytes"]
    handle = eri.open_process_read_only(api, pid)

    report = {"pid": pid, "functions": [], "receivers": []}
    try:
        namepool, objects = recon.universe(api, handle, base, size)
        meta = recon.find_function_meta(objects)
        if meta is None:
            raise SystemExit("the Function meta-class was not found")

        classes = [address for address, record in objects.items()
                   if record.get("valid") and
                   (objects.get(record.get("class_ptr") or 0) or {})
                   .get("name_text") in ("Class", "BlueprintGeneratedClass")]
        print("walking %d class(es)" % len(classes))

        for class_address in classes:
            class_name = (objects.get(class_address) or {}).get("name_text") or ""
            try:
                functions = recon.class_functions(api, handle, namepool,
                                                  class_address, meta)
            except Exception:                              # noqa: BLE001
                continue
            for function in functions:
                name = function.get("raw_name") or ""
                if name not in WANTED:
                    continue
                try:
                    abi = recon.function_abi(api, handle, namepool,
                                             function["address"], objects)
                except Exception as error:                 # noqa: BLE001
                    abi = {"error": str(error)}
                report["functions"].append({
                    "name": name,
                    "class": class_name,
                    "address": "0x%x" % function["address"],
                    "num_parms": abi.get("num_parms"),
                    "parms_size": abi.get("parms_size"),
                    "flags": abi.get("flags") if isinstance(abi.get("flags"), str)
                    else ("0x%x" % abi["flags"] if abi.get("flags") else None)})

        # Live, non-CDO instances that could receive the call.
        for address, record in objects.items():
            if not record.get("valid"):
                continue
            name = record.get("name_text") or ""
            if name.startswith("Default__"):
                continue
            class_name = (objects.get(record.get("class_ptr") or 0) or {}) \
                .get("name_text") or ""
            if any(r in class_name for r in RECEIVERS):
                report["receivers"].append({
                    "address": "0x%x" % address, "name": name,
                    "class": class_name})

        report["functions"].sort(
            key=lambda f: (WANTED.index(f["name"]) if f["name"] in WANTED
                           else 99, f["class"]))
        for f in report["functions"]:
            print("  %-22s %-28s parms=%s size=%s  %s"
                  % (f["name"], f["class"], f["num_parms"], f["parms_size"],
                     f["address"]))
        print("receivers: %d" % len(report["receivers"]))
        for r in report["receivers"][:12]:
            print("  %-40s %s  %s" % (r["class"], r["address"], r["name"]))
    finally:
        try:
            api.close_handle(handle)
        except Exception:                                  # noqa: BLE001
            pass

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        json.dump(report, out, indent=2, default=str)
        out.write("\n")
    print("-> %s" % a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
