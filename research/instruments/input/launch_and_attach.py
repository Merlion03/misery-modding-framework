#!/usr/bin/env python3
"""Launch MISERY and attach the input probe AT THE MENU, before any save loads.

C5 is the claim that one attach spans menu -> loading -> gameplay. The runner's
cycle drives all the way to gameplay in one go, so attaching after it finishes
would only ever test gameplay. This does the launch half, stops at the menu, and
attaches there; the save entry is then driven separately, with the probe already
in place and counting across the transition.

Nothing here decides anything. It closes the game, launches it through Steam the
way the runner does, waits for the window, fingerprints the process, and attaches.

    python research/instruments/input/launch_and_attach.py --run-dir DIR
"""
import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "runner"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lifecycle                                                   # noqa: E402
import window_census as wc                                         # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--settle-s", type=float, default=45.0,
                        help="how long to let the menu come up before attaching")
    args = parser.parse_args()

    note = []
    report = {"note": note}

    live = lifecycle.find_processes()
    old_pids = [p["pid"] for p in live]
    for process in live:
        lifecycle.close_process(process["pid"], note=note)
    lifecycle.prove_gone(old_pids, note=note)

    requested_at = lifecycle.launch_through_steam(note=note)
    process = lifecycle.wait_for_new_process(excluded_pids=old_pids,
                                             requested_at=requested_at,
                                             timeout_s=300, note=note)
    report["process"] = process
    pid = process["pid"]

    # Wait for the window, then let the menu settle. A settle wait is not a
    # measurement and is not treated as one -- the census below is.
    deadline = time.time() + 300
    hwnd = None
    while time.time() < deadline:
        windows = [w for w in wc.top_level_windows(pid)
                   if w["class"] == wc.UNREAL_WINDOW_CLASS and w["visible"]]
        if len(windows) == 1:
            hwnd = windows[0]["hwnd"]
            break
        time.sleep(2)
    if hwnd is None:
        raise SystemExit(json.dumps({"ok": False,
                                     "error": "no visible UnrealWindow appeared"}))
    note.append("window 0x%x appeared" % hwnd)
    time.sleep(args.settle_s)

    census = subprocess.run(
        [sys.executable, os.path.join(REPO, "research", "instruments", "input",
                                      "window_census.py"),
         "--label", "menu",
         "--out", os.path.join(args.run_dir or ".", "census-menu.json")],
        capture_output=True, text=True)
    report["census_menu"] = json.loads(census.stdout)

    attach = subprocess.run(
        [sys.executable, os.path.join(REPO, "research", "instruments", "input",
                                      "input_probe_controller.py"), "attach"],
        capture_output=True, text=True)
    report["attach"] = json.loads(attach.stdout) if attach.stdout.strip() else {
        "ok": False, "stderr": attach.stderr[-2000:]}
    report["ok"] = bool(report["attach"].get("ok"))

    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "launch-and-attach.json"), "w",
                  encoding="utf-8") as handle:
            handle.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 4


if __name__ == "__main__":
    sys.exit(main())
