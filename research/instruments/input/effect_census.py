#!/usr/bin/env python3
"""C4's game-side observable: did the game react to a key, or not?

The pre-registration requires a controlled differential -- the same key, in the
same state, with capture on and with capture off -- and it requires BOTH
directions. "Nothing happened while capturing" is only evidence when the same
press demonstrably does something when not capturing, so this measures the
game's reaction independently of the console, by class census.

WHY A CLASS CENSUS AND NOT A SCREENSHOT. The screen is not readable evidence:
a pixel diff cannot say whether the game acted or a cloud moved. The live object
graph can. Opening a panel constructs widget objects; the runner's own save-entry
state machine already discriminates screens exactly this way, and this reuses
that walker rather than inventing a second one.

    python research/instruments/input/effect_census.py snapshot --out a.json
    python research/instruments/input/effect_census.py diff a.json b.json
"""
import argparse
import collections
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _path in (os.path.join(REPO, "research", "instruments", "eri"),
              os.path.join(REPO, "research", "instruments", "ipp")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import eri                                                         # noqa: E402
import cr01c3_recon as recon                                       # noqa: E402


def snapshot():
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
    finally:
        api.close_handle(handle)
    counts = collections.Counter()
    for obj in objects.values():
        name = obj.get("class_name")
        if name:
            counts[name] += 1
    return {"pid": i01["pid"], "objects": len(objects), "classes": dict(counts)}


def diff(before, after, floor=1):
    """What appeared, what vanished, and by how much.

    `floor` exists because a live game constructs and frees objects constantly;
    a differential that called every transient a reaction would report a change
    for doing nothing at all. The floor is stated in the output rather than
    applied silently.
    """
    keys = set(before["classes"]) | set(after["classes"])
    appeared, vanished, changed = {}, {}, {}
    for key in sorted(keys):
        was = before["classes"].get(key, 0)
        now = after["classes"].get(key, 0)
        if now == was:
            continue
        if was == 0:
            appeared[key] = now
        elif now == 0:
            vanished[key] = was
        elif abs(now - was) >= floor:
            changed[key] = [was, now]
    return {
        "objects_before": before["objects"], "objects_after": after["objects"],
        "objects_delta": after["objects"] - before["objects"],
        "appeared": appeared, "vanished": vanished, "changed": changed,
        "distinct_classes_changed": len(appeared) + len(vanished) + len(changed),
        "floor": floor,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--out", required=True)
    delta = sub.add_parser("diff")
    delta.add_argument("before")
    delta.add_argument("after")
    delta.add_argument("--out")
    args = parser.parse_args()

    if args.command == "snapshot":
        document = snapshot()
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
        print(json.dumps({"objects": document["objects"],
                          "distinct_classes": len(document["classes"]),
                          "out": args.out}, indent=2))
        return 0

    with open(args.before, encoding="utf-8") as handle:
        before = json.load(handle)
    with open(args.after, encoding="utf-8") as handle:
        after = json.load(handle)
    document = diff(before, after)
    text = json.dumps(document, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
