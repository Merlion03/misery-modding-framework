#!/usr/bin/env python3
"""Record the S_ItemDetails field offsets the Items backend writes through.

WHY THESE HAVE TO BE MEASURED ONCE AND THEN CARRIED IN THE PROFILE
------------------------------------------------------------------
The CR-01C5 registration path writes into a row by offset: the three FText
fields, the scalars, the soft-object paths for mesh and icon, the world class,
and the nested UIDetails/Transform members. The research controller resolves all
of those by live reflection every run, with fail-closed checks on property class,
size, and -- for WorldClass -- the MetaClass.

Porting that reflection into the production runtime would be the wrong split.
Stage 5B's architecture is explicit: build-specific MEASURED facts belong in the
binding profile, and only per-run DYNAMIC facts are resolved in-process. A field's
offset inside a cooked struct is as build-specific as an RVA -- it cannot change
without the build changing.

So the reflection runs HERE, once, with all of its type checking intact, and its
answer is committed as evidence for the emitter to read. The runtime then carries
the offsets and validates the one thing that would catch a mismatch: the live row
struct's total width against the width recorded beside them.

STRICTLY READ-ONLY. This resolves and reports; it writes nothing to the game.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import ipp_controller as ipp                      # noqa: E402
import cr01c3d_controller as c3d                  # noqa: E402
import cr01c5_controller as c5                    # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(
        REPO, "research", "evidence", "CR-01C5", "row-struct-offsets.json"))
    a = ap.parse_args(argv)

    note = []
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size = i01["pid"], i01["base_address"], i01["image_size_bytes"]
    with open(i01["exe_path"], "rb") as handle:
        image = handle.read()
    img = c5.DiskImage(i01["exe_path"])
    handle = eri.open_process_read_only(api, pid)
    try:
        resolved = c5.resolve(api, handle, base, size, img, note)
        # The controller's own resolvers, unchanged, with their type checks.
        offs, field_report = c5.verify_fields(api, handle, resolved["np"],
                                              resolved["row_struct"], c5.VALUES)
        toffs, text_report = c5.text_fields(api, handle, resolved["np"],
                                            resolved["row_struct"], c5.TEXTS)
        woffs = c5.world_offsets(api, handle, resolved["np"],
                                 resolved["row_struct"], resolved["objs"])
    finally:
        api.close_handle(handle)

    document = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_by": "research/instruments/mods/stage5b_dump_row_offsets.py",
        "build_key": "sha256:" + ipp.sha256_of_file(i01["exe_path"]),
        "struct": "S_ItemDetails",
        "struct_size": resolved["struct_size"],
        "note": "Resolved by live reflection with the CR-01C5 controller's own "
                "type, size and MetaClass checks. Committed so the binding "
                "profile can carry them instead of the runtime re-deriving "
                "them: a field offset inside a cooked struct is a "
                "build-specific measured fact, exactly like an RVA.",
        "text_fields": {k: int(v) for k, v in toffs.items()},
        "scalar_fields": {k: int(v) for k, v in offs.items()},
        "world_fields": {k: int(v) for k, v in woffs.items()
                         if k.startswith("off_")},
        "worldclass_metaclass": woffs.get("worldclass_metaclass"),
        "bool_semantics": woffs.get("bool_semantics"),
        # Not part of S_ItemDetails, but the same class of measured fact and
        # needed by the same code path.
        "inventory": {
            "off_inventory_array": c3d.OFF_INVENTORY_ARRAY,
            "off_invitem_in_slot": c3d.S_INVITEM_OFF_IN_SLOT,
            "off_delegate": 0x98,
        },
        "new_item_values": {k: v for k, v in c3d.INVITEM.items()},
        "run_note": note[-12:],
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        json.dump(document, out, indent=2, sort_keys=True)
        out.write("\n")
    print(json.dumps({"out": a.out, "struct_size": document["struct_size"],
                      "text": document["text_fields"],
                      "scalar": document["scalar_fields"],
                      "world": document["world_fields"],
                      "inventory": document["inventory"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
