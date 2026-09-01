#!/usr/bin/env python3
"""What is on screen after Escape, asked of a game already in gameplay.

WHY THIS EXISTS
---------------
Step 3's second acceptance needs a real content transition WHILE the managed
path is live:

    generation N (gameplay) -> load -> N revoked -> N+1 -> items work again

The runner can already drive main menu -> gameplay, and that is a real
transition -- but it is the wrong one here, because at the main menu no item can
be live, so "Items worked at N" is never true beforehand.

The transition that gives both halves is gameplay -> main menu -> gameplay, and
the second leg is already calibrated. Only the first leg is unknown: the
runner's UI table knows THANK_YOU_SCREEN, LOAD_GAME_MENU and MAIN_MENU, and
stops the moment it sees gameplay. Nothing in it describes a pause menu.

So this measures rather than guesses. It sends ONE Escape and reports the
screen signature before and after, plus whether the existing classifier names
either. Two possible outcomes, both useful:

* the signature changes and is nameable -> a UI_STATES entry can be written for
  it, and the existing machine drives the rest;
* it does not -> that is recorded, and the gameplay -> menu leg needs something
  other than a key press.

READ-ONLY EXCEPT FOR ONE KEY
----------------------------
It walks the object graph read-only and sends a single Escape. It does not
click, does not confirm anything, and does not attempt to leave the session --
Escape opens a menu, and every control that would discard progress needs a
further deliberate action this probe never takes.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "mods")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                          # noqa: E402
import lifecycle                                    # noqa: E402
import cr01c3_recon as recon                        # noqa: E402
import saveentry                                    # noqa: E402


def snapshot(api, handle, base, size):
    """The live screen signature and whatever the classifier makes of it."""
    _namepool, objects = recon.universe(api, handle, base, size)
    signature = sorted(saveentry.screen_signature(objects))
    state = saveentry.classify_state(objects)
    return {"signature": signature,
            "state": state["name"] if state else None,
            "worlds": sorted(saveentry.live_world_names(objects))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--settle", type=float, default=3.0,
                    help="seconds to let the screen change after the key")
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

    report = {"pid": pid}
    try:
        report["before"] = snapshot(api, handle, base, size)
        print("before: state=%s, %d signature class(es)"
              % (report["before"]["state"], len(report["before"]["signature"])))

        hwnd = saveentry.find_game_window(pid) \
            if hasattr(saveentry, "find_game_window") else None
        if hwnd:
            saveentry.focus_window(hwnd)
        saveentry.send_key("escape")
        time.sleep(a.settle)

        report["after"] = snapshot(api, handle, base, size)
        print("after:  state=%s, %d signature class(es)"
              % (report["after"]["state"], len(report["after"]["signature"])))

        before = set(report["before"]["signature"])
        after = set(report["after"]["signature"])
        report["appeared"] = sorted(after - before)
        report["disappeared"] = sorted(before - after)
        report["changed"] = bool(report["appeared"] or report["disappeared"])
        print("appeared:    %s" % ", ".join(report["appeared"]) or "(none)")
        print("disappeared: %s" % ", ".join(report["disappeared"]) or "(none)")
    finally:
        try:
            api.close_handle(handle)
        except Exception:                                      # noqa: BLE001
            pass

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle_out:
        json.dump(report, handle_out, indent=2, default=str)
        handle_out.write("\n")
    print("-> %s" % a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
