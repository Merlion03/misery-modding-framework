#!/usr/bin/env python3
"""A game-side observable for C4 that is not a class census.

The first attempt at C4's observable counted live objects by class, and it found
nothing for Tab, I or M. That is not evidence that the keys did nothing: MISERY's
widgets are PRE-INSTANTIATED -- the runner's own save-entry machine records the
same limit for the main menu, where class presence cannot separate the menu from
its sub-panel. Constructing nothing is what opening a panel looks like here.

So the observable is state on objects that already exist, read by reflection:

  * ``APlayerController::bShowMouseCursor`` -- flips when a game hands the mouse
    to a panel, and is a plain reflected bool on an object already resolved.
  * ``APlayerController::bEnableClickEvents`` / ``bEnableMouseOverEvents`` --
    the same family, read together because which one a build uses is a fact
    about the build.
  * The pawn's ``RootComponent -> RelativeLocation`` -- the fallback for a key
    with no UI effect at all, e.g. a movement key.

Nothing here writes. Every offset comes from the live FProperty chain, never
from a constant.

    python research/instruments/input/observable.py read --out obs.json
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _path in (os.path.join(REPO, "research", "instruments", "eri"),
              os.path.join(REPO, "research", "instruments", "ipp"),
              os.path.join(REPO, "research", "instruments", "runner")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import eri                                                         # noqa: E402
import cr01c3_recon as recon                                       # noqa: E402
import readiness                                                   # noqa: E402

CURSOR_FLAGS = ("bShowMouseCursor", "bEnableClickEvents",
                "bEnableMouseOverEvents")


def read(expect=None):
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    out = {"pid": i01["pid"]}
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
        gameplay = readiness.prove_gameplay(eri, api, handle, objects,
                                            namepool=namepool,
                                            expect=expect or {}, note=[])
        out["gameplay_ok"] = bool(gameplay.get("ready"))
        out["not_ready_because"] = gameplay.get("reasons")
        facts = gameplay.get("facts") or {}
        controllers = facts.get("player_controllers") or []
        controller_text = controllers[0]["address"] if len(controllers) == 1 else None
        out["player_controller_count"] = len(controllers)
        pawn_text = (facts.get("player_pawn") or {}).get("address")
        out["controller"] = controller_text
        out["pawn"] = pawn_text

        flags = {}
        if controller_text:
            controller = int(controller_text, 16)
            class_ptr = (objects.get(controller) or {}).get("class_ptr")
            for name in CURSOR_FLAGS:
                found = readiness.resolve_property(eri, api, handle, class_ptr,
                                                   objects, namepool, {name})
                if found and found.get("offset") is not None:
                    value = eri._read_u8(api, handle, controller + found["offset"])
                    flags[name] = {"offset": found["offset"], "value": int(value),
                                   "declared_on": found.get("declared_on")}
        out["controller_flags"] = flags

        location = None
        if pawn_text:
            pawn = int(pawn_text, 16)
            class_ptr = (objects.get(pawn) or {}).get("class_ptr")
            root = readiness.resolve_property(eri, api, handle, class_ptr, objects,
                                              namepool, {"RootComponent"})
            if root and root.get("offset") is not None:
                component = eri._read_u64(api, handle, pawn + root["offset"])
                if component:
                    component_class = (objects.get(component) or {}).get("class_ptr")
                    rel = readiness.resolve_property(eri, api, handle,
                                                     component_class, objects,
                                                     namepool, {"RelativeLocation"})
                    if rel and rel.get("offset") is not None:
                        raw = b"".join(
                            struct.pack("<B", eri._read_u8(api, handle,
                                                           component + rel["offset"] + i))
                            for i in range(24))
                        x, y, z = struct.unpack("<ddd", raw)
                        location = {"offset": rel["offset"], "x": x, "y": y, "z": z,
                                    "component": "0x%x" % component}
        out["pawn_location"] = location
    finally:
        api.close_handle(handle)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    reader = sub.add_parser("read")
    reader.add_argument("--out")
    args = parser.parse_args()
    document = read()
    text = json.dumps(document, indent=2, sort_keys=True)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
