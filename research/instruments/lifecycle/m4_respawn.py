#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Capture the death -> respawn transition.

This is the one M4 transition that could not be manufactured: the runner is
deliberately fail-closed on the death screen and will not press
"ВОЗРОДИТЬСЯ В БУНКЕРЕ", because respawning is a gameplay decision that changes
someone's save, not a navigation step. So this harness watches, and a human
presses the button.

THE SAMPLING PROBLEM, AND WHAT IS DONE ABOUT IT
-----------------------------------------------
A full object-graph walk takes about ten seconds on this game. Every earlier M4
observation was therefore of a SETTLED state, and an adversarial review pointed
out -- correctly -- that "during the transition" had never actually been
observed. A respawn is far faster than ten seconds, so polling full resolves
would almost certainly miss it entirely and then report the miss as if it were
the event.

So this harness works at two speeds:

  SLOW  a complete Resolver pass, ~10 s, giving every anchor with the engine's
        own identity. Taken before the respawn and after possession settles.

  FAST  a three-pointer poll, ~50 ms, reading only
            ULocalPlayer -> UPlayer::PlayerController
            AController::Pawn
            APlayerController::AcknowledgedPawn
        at offsets RESOLVED BY REFLECTION during the slow pass. No walk, no
        allocation, no interpretation -- just the three pointers whose changes
        ARE the transition.

The fast poll is anchored on the ULocalPlayer address rather than on the
PlayerController, because the LocalPlayer has survived every transition observed
so far while the controller has not. If the controller is recreated during the
respawn, the poll sees it change through UPlayer::PlayerController rather than
following a dangling pointer -- which is the whole reason for anchoring there.
The anchor is re-validated on every slow pass.

NOTHING IS ASSUMED ABOUT THE OUTCOME. Whether the PlayerController and the
inventory survive or are recreated is what this measures; the code has no
expectation either way and records what it reads.
"""
import argparse
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "lifecycle")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                       # noqa: E402
import readiness                 # noqa: E402
import saveentry                 # noqa: E402
import resolver as R             # noqa: E402

ANCHORS = ("world", "game_instance", "local_player", "player_controller",
           "pawn", "player_inventory")


def now():
    return time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())


def slow_pass(api, pid, base, size, label):
    """One complete resolve, plus the offsets the fast poll needs."""
    handle = eri.open_process_read_only(api, pid)
    try:
        res = R.Resolver(api, handle, base, size)
        snap = res.resolve()
        snap["label"] = label
        snap["observed_at"] = now()
        snap["pid"] = pid
        # The verdict tool refuses to compare object identity across processes,
        # and rightly so. This pass builds its snapshot from Resolver directly
        # rather than through resolve_live(), which is where process_start_time
        # was being set -- so it was missing here and the first verdict run
        # could not establish same-process. Recorded at capture time now.
        try:
            import lifecycle as _lc
            live = [p for p in _lc.find_processes() if p.get("pid") == pid]
            snap["process_start_time"] = live[0].get("start_time") if live else None
        except Exception:                                      # noqa: BLE001
            snap["process_start_time"] = None
        state = saveentry.classify_state(res.objects)
        snap["screen"] = state.get("name") if isinstance(state, dict) else state
        snap["death_screen_live"] = len([
            a for a, r in res.objects.items()
            if r.get("valid") and (res.class_name_of(a) or "") == "BP_DeathScreen_C"
            and not res.is_cdo(a)])

        # the three offsets the fast poll needs, all resolved by reflection
        wiring = {}
        lp = snap["anchors"]["local_player"]
        pc = snap["anchors"]["player_controller"]
        if lp.get("resolved"):
            addr = int(lp["address"], 16)
            found = res.prop(addr, "PlayerController",
                             expect_class="FObjectProperty", expect_size=8)
            if found:
                wiring["local_player"] = addr
                wiring["off_lp_playercontroller"] = int(found["offset"])
        if pc.get("resolved"):
            addr = int(pc["address"], 16)
            for name, key in (("Pawn", "off_pc_pawn"),
                              ("AcknowledgedPawn", "off_pc_acknowledged")):
                found = res.prop(addr, name, expect_class="FObjectProperty", expect_size=8)
                if found:
                    wiring[key] = int(found["offset"])
        snap["fast_poll_wiring"] = wiring
        return snap, res
    finally:
        api.close_handle(handle)


def fast_watch(api, pid, wiring, *, seconds, interval, note):
    """Poll the three pointers that define possession. Returns a timeline of
    every DISTINCT tuple seen, with the time it was first seen."""
    if "local_player" not in wiring or "off_lp_playercontroller" not in wiring:
        return [], "no LocalPlayer anchor: the fast poll cannot be wired"
    handle = eri.open_process_read_only(api, pid)
    timeline, last = [], object()
    started = time.time()
    deadline = started + seconds
    try:
        while time.time() < deadline:
            try:
                pc = eri._read_u64(api, handle,
                                   wiring["local_player"] + wiring["off_lp_playercontroller"])
                pawn = ack = None
                if pc and "off_pc_pawn" in wiring:
                    pawn = eri._read_u64(api, handle, pc + wiring["off_pc_pawn"])
                if pc and "off_pc_acknowledged" in wiring:
                    ack = eri._read_u64(api, handle, pc + wiring["off_pc_acknowledged"])
            except Exception as exc:                           # noqa: BLE001
                pc = pawn = ack = None
                timeline.append({"t": round(time.time() - started, 3), "error": repr(exc)})
                last = object()
                time.sleep(interval)
                continue
            tup = (pc, pawn, ack)
            if tup != last:
                last = tup
                entry = {"t": round(time.time() - started, 3), "at": now(),
                         "PlayerController": ("0x%x" % pc) if pc else None,
                         "Controller_Pawn": ("0x%x" % pawn) if pawn else None,
                         "AcknowledgedPawn": ("0x%x" % ack) if ack else None,
                         "possession_agrees": bool(pawn) and pawn == ack}
                timeline.append(entry)
                note(entry)
                # possession has settled on a NEW, non-null pawn
                if entry["possession_agrees"]:
                    stable = 0
                    while stable < 6 and time.time() < deadline:
                        time.sleep(interval)
                        p2 = eri._read_u64(api, handle, pc + wiring["off_pc_pawn"])
                        a2 = eri._read_u64(api, handle, pc + wiring["off_pc_acknowledged"])
                        if p2 == pawn and a2 == ack:
                            stable += 1
                        else:
                            break
                    if stable >= 6:
                        return timeline, None
            time.sleep(interval)
        return timeline, "the watch window elapsed"
    finally:
        api.close_handle(handle)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=os.path.join(REPO, "research", "evidence", "M4"))
    ap.add_argument("--wait-death-s", type=float, default=0.0,
                    help="if >0, wait this long for the death screen before arming")
    ap.add_argument("--watch-s", type=float, default=3600.0)
    ap.add_argument("--interval", type=float, default=0.05)
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size = i01["pid"], i01["base_address"], i01["image_size_bytes"]
    out = {"pid": pid, "started_at": now(), "interval_s": a.interval}

    print("pid %d -- taking the BEFORE pass (a full resolve, ~10s)" % pid)
    before, _res = slow_pass(api, pid, base, size, "before-respawn")
    out["before"] = before
    print("  screen=%s  death_screen_live=%s  pawn=%s"
          % (before.get("screen"), before.get("death_screen_live"),
             before["anchors"]["pawn"].get("resolved")))
    if before["anchors"]["pawn"].get("resolved"):
        print("  NOTE: a pawn is currently resolved -- this is not the death state.")
    wiring = before.get("fast_poll_wiring") or {}
    print("  fast-poll wiring (all offsets reflection-resolved): %s"
          % {k: v for k, v in wiring.items() if k != "local_player"})

    with open(os.path.join(a.out_dir, "respawn-before.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(before, f, indent=2, sort_keys=False, default=str)
        f.write("\n")

    print("\nARMED. Watching possession at %.0f ms. Press respawn when ready."
          % (a.interval * 1000))
    sys.stdout.flush()

    def note(entry):
        print("  [%8.3fs] PC=%-16s Pawn=%-16s Ack=%-16s agree=%s"
              % (entry["t"], entry["PlayerController"], entry["Controller_Pawn"],
                 entry["AcknowledgedPawn"], entry["possession_agrees"]))
        sys.stdout.flush()

    timeline, why = fast_watch(api, pid, wiring, seconds=a.watch_s,
                               interval=a.interval, note=note)
    out["transition_timeline"] = timeline
    out["watch_ended_because"] = why or "possession settled on a new pawn"
    with open(os.path.join(a.out_dir, "respawn-transition.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"pid": pid, "interval_s": a.interval, "timeline": timeline,
                   "ended_because": out["watch_ended_because"]}, f,
                  indent=2, sort_keys=False, default=str)
        f.write("\n")

    print("\ntaking the AFTER pass (a full resolve, ~10s)")
    after, _res2 = slow_pass(api, pid, base, size, "after-respawn")
    out["after"] = after
    with open(os.path.join(a.out_dir, "respawn-after.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(after, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("  screen=%s  complete=%s  gameplay_oracle=%s"
          % (after.get("screen"), after.get("complete"), after.get("runner_gameplay_ready")))
    for k in ANCHORS:
        anchor = after["anchors"][k]
        print("    %-18s %-6s %s" % (k, "OK" if anchor["resolved"] else "FAIL",
                                     anchor.get("name")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
