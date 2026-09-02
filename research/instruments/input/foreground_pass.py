#!/usr/bin/env python3
"""The two measurements that genuinely need the game in front, done in one grab.

Taking the foreground away from whoever is using the machine is a real cost, so
it is paid once. Two claims need it and the rest do not:

  C3 in gameplay -- a posted message cannot be used here. TranslateMessage is
      what turns WM_KEYDOWN into WM_CHAR, and it only runs for messages the
      game's own pump retrieves, so real synthesized input is the only way to
      see whether characters arrive in gameplay as they did in the menu.

  C9 with the game in front -- the first overlay sample was taken while a
      browser held the foreground. It proved the overlay is topmost. It did NOT
      prove the overlay draws above THE GAME, which is the claim, and reporting
      it as if it had would have been the easy mistake.

The game is left in the foreground afterwards, which is where the manual
acceptance pass needs it anyway.
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import input_probe_controller as probe                             # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)


def run(script, *arguments):
    result = subprocess.run([sys.executable, os.path.join(HERE, script)]
                            + list(arguments), capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except Exception:                                              # noqa: BLE001
        return {"ok": False, "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-2000:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    session = probe.load_session()
    k32, handle = probe.open_game(session["pid"])
    state, _ = probe.read_state(k32, handle, session["state_address"])
    hwnd = state["hwnd"]

    report = {"hwnd": "0x%x" % hwnd}
    if not probe.bring_to_foreground(hwnd, attempts=10):
        report["blocked"] = ("could not bring the game to the foreground; both "
                             "measurements below need it and neither is being "
                             "reported from a run that did not have it")
        print(json.dumps(report, indent=2))
        return 3
    report["foreground_taken"] = True
    time.sleep(1.0)

    # --- C3 in gameplay ---------------------------------------------------
    probe.write_remote(k32, handle, session["state_address"] + probe.OFF_CAPTURE,
                       b"\x01\x00\x00\x00")
    keys = run("input_probe_controller.py", "--run-dir", args.run_dir,
               "keys", "--label", "gameplay")
    report["c3_gameplay"] = {
        "clean_run": keys.get("clean_run"),
        "foreign_events": keys.get("foreign_events"),
        "presses": [
            {"label": press["label"],
             "events": ["%s:0x%04X%s" % (event["message"].replace("WM_", ""),
                                         event["vkey"],
                                         "=" + repr(event["char"]) if event["char"]
                                         else "")
                        for event in press["produced"]],
             "all_suppressed": all(event["suppressed"] for event in press["produced"])}
            for press in keys.get("presses", [])],
    }
    probe.write_remote(k32, handle, session["state_address"] + probe.OFF_CAPTURE,
                       b"\x00\x00\x00\x00")

    # --- C9 with the game in front ---------------------------------------
    if int(user32.GetForegroundWindow() or 0) != hwnd:
        probe.bring_to_foreground(hwnd, attempts=10)
    report["foreground_is_game_before_overlay"] = (
        int(user32.GetForegroundWindow() or 0) == hwnd)
    overlay = run("overlay_controller.py", "--run-dir", args.run_dir, "show")
    report["c9_over_game"] = {
        "verdict": overlay.get("verdict"),
        "status_name": overlay.get("status_name"),
        "bands_matched": overlay.get("bands_matched"),
        "bands_bled_outside": overlay.get("bands_bled_outside"),
        "sampled_inside": overlay.get("sampled_inside"),
        "sampled_outside": overlay.get("sampled_outside"),
        "foreground_unchanged": overlay.get("foreground_unchanged"),
        "foreground_before": overlay.get("foreground_before"),
        "game_hwnd": overlay.get("game_hwnd"),
        "overlay_was_over_the_game": (
            overlay.get("foreground_before") == overlay.get("game_hwnd")),
    }
    time.sleep(2.0)
    report["c9_hide"] = run("overlay_controller.py", "hide")

    probe.bring_to_foreground(hwnd, attempts=6)
    report["left_in_foreground"] = int(user32.GetForegroundWindow() or 0) == hwnd

    os.makedirs(args.run_dir, exist_ok=True)
    with open(os.path.join(args.run_dir, "foreground-pass.json"), "w",
              encoding="utf-8") as out:
        out.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
