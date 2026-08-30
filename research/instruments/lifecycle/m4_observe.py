#!/usr/bin/env python3
"""STRICTLY READ-ONLY observer. Records the lifecycle chain at every state the
game passes through, while something ELSE drives the game.

This exists so that M4's transition evidence can be collected without changing
the runner. The runner is the single mutator; this process only reads. That
separation is deliberate: two things driving one live game is how you get
evidence that describes a state nobody was actually in.

It tolerates the process disappearing and a different one appearing -- that IS
the transition it is here to record -- and it never carries an address across
that boundary. Each observation constructs a brand new Resolver against the pid
it just found, and the timeline compares object IDENTITIES, never addresses.

    python m4_observe.py --seconds 900 --out timeline.json
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "lifecycle")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri            # noqa: E402
import lifecycle as lc  # noqa: E402
import saveentry      # noqa: E402
import resolver as R  # noqa: E402

ANCHORS = ("world", "game_instance", "local_player", "player_controller",
           "pawn", "player_inventory")


def observe_once(api):
    """One read-only observation, or a reason there could not be one."""
    live = lc.find_processes()
    if len(live) != 1:
        return {"process_count": len(live),
                "why": "expected exactly one live MISERY process, found %d" % len(live)}
    process = live[0]
    pid = process["pid"]
    try:
        i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    except Exception as exc:                                   # noqa: BLE001
        return {"pid": pid, "why": "process identity unreadable: %r" % exc}
    handle = None
    try:
        handle = eri.open_process_read_only(api, i01["pid"])
        res = R.Resolver(api, handle, i01["base_address"], i01["image_size_bytes"])
        screen = saveentry.classify_state(res.objects)
        snap = res.resolve()
    except Exception as exc:                                   # noqa: BLE001
        return {"pid": pid, "why": "observation failed: %r" % exc}
    finally:
        if handle:
            try:
                api.close_handle(handle)
            except Exception:                                  # noqa: BLE001
                pass
    snap["pid"] = i01["pid"]
    snap["process_start_time"] = process.get("start_time")
    snap["screen"] = screen if isinstance(screen, str) else (
        (screen or {}).get("name") if isinstance(screen, dict) else screen)
    return snap


def fingerprint(snap):
    """What makes this observation DIFFERENT from the previous one.

    Deliberately built from identities and resolution status, not addresses: an
    address changing inside one process is ordinary GC/realloc noise, while an
    identity changing is a real lifecycle event.
    """
    if "anchors" not in snap:
        return ("no-observation", snap.get("why"))
    parts = [snap.get("pid"), snap.get("screen")]
    for key in ANCHORS:
        a = snap["anchors"].get(key) or {}
        parts.append((key, a.get("resolved"), (a.get("identity") or {}).get("object_path")))
    return tuple(parts)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=900.0)
    ap.add_argument("--interval", type=float, default=6.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default=None)
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    timeline = []
    last = None
    started = time.time()
    deadline = started + a.seconds
    while time.time() < deadline:
        t0 = time.time()
        snap = observe_once(api)
        snap["observed_at"] = time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
        snap["seconds_since_start"] = round(t0 - started, 1)
        fp = fingerprint(snap)
        if fp != last:
            last = fp
            timeline.append(snap)
            anchors = snap.get("anchors") or {}
            print("[%6.1fs] pid=%-6s screen=%-16s %s"
                  % (snap["seconds_since_start"], snap.get("pid"),
                     snap.get("screen") or "-",
                     " ".join("%s=%s" % (k[:4], "OK" if (anchors.get(k) or {}).get("resolved")
                                         else "--") for k in ANCHORS)
                     if anchors else (snap.get("why") or "")))
            sys.stdout.flush()
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"label": a.label, "observations": timeline}, f,
                          indent=2, sort_keys=False, default=str)
                f.write("\n")
        spent = time.time() - t0
        if spent < a.interval:
            time.sleep(a.interval - spent)

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"label": a.label, "observations": timeline}, f,
                  indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("\n%d distinct states recorded -> %s" % (len(timeline), a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
