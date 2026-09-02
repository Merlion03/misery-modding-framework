#!/usr/bin/env python3
"""C1 -- watch the window across the whole launch, not at three chosen moments.

window_census.py answers "what is true now". This samples the same census on a
timer and writes one JSON line per sample, so that C1's "the same HWND in all
three lifecycle states" is read off a continuous record instead of three
snapshots I chose. If the window is ever recreated -- which is the failure C1
names -- the recreation lands in this file with a timestamp, and the transition
it happened at can be named rather than guessed.

Samples where the process is absent are recorded too, as {"present": false},
because "the game was not running yet" and "the census failed" are different
facts and the reading later must be able to tell them apart.

    python research/instruments/input/window_watch.py --out watch.jsonl \
        --interval 2 --duration 900
"""
import argparse
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import window_census as wc                                        # noqa: E402


def sample():
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    pids = wc.find_pids(wc.PROCESS_NAME)
    if len(pids) != 1:
        return {"at": now, "present": False, "pid_count": len(pids)}
    pid = pids[0]
    windows = wc.top_level_windows(pid)
    unreal = [w for w in windows if w["class"] == wc.UNREAL_WINDOW_CLASS]
    visible = [w for w in unreal if w["visible"]]
    row = {
        "at": now,
        "present": True,
        "pid": pid,
        "top_level_windows": len(windows),
        "unreal_windows": len(unreal),
        "visible_unreal_windows": len(visible),
        "classes": sorted({w["class"] for w in windows}),
        "hwnd": visible[0]["hwnd"] if len(visible) == 1 else None,
        "owning_thread_id": (visible[0]["owning_thread_id"]
                             if len(visible) == 1 else None),
        "title": visible[0]["title"] if len(visible) == 1 else None,
        "window_rect": visible[0]["window_rect"] if len(visible) == 1 else None,
        "covers_monitor_exactly": (visible[0]["covers_monitor_exactly"]
                                   if len(visible) == 1 else None),
        "foreground_hwnd": int(wc.user32.GetForegroundWindow() or 0),
    }
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--duration", type=float, default=1200.0)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    deadline = time.time() + args.duration
    seen_hwnds = []
    with open(args.out, "w", encoding="utf-8") as handle:
        while time.time() < deadline:
            row = sample()
            if row.get("hwnd") and row["hwnd"] not in seen_hwnds:
                seen_hwnds.append(row["hwnd"])
                row["new_hwnd"] = True
            handle.write(json.dumps(row) + "\n")
            handle.flush()
            time.sleep(args.interval)
    print(json.dumps({"ok": True, "distinct_hwnds": seen_hwnds,
                      "out": args.out}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
