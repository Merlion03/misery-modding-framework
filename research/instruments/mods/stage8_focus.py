#!/usr/bin/env python3
"""Stage 8 live acceptance: the console's focus lifecycle.

THE BUG THIS EXISTS FOR. Minimising MISERY hid the console overlay and Alt+Tab
did not, so a topmost console sat over whatever the user switched to. The reason
minimise appeared to work is worth keeping: nothing tracked window state at all,
the overlay simply follows the game's client rect, and a minimised window's rect
collapses. A rule that is an accident of geometry holds for the one case that
happens to collapse a rect and fails for every other one.

WHAT IS MEASURED, AND WHY NOT PIXELS. The screen acceptance in stage8_console.py
reads pixels because the claim there is "something is drawn". The claim here is
about a window's state, and `IsWindowVisible` on the overlay answers it exactly,
with no palette, no tolerance and no dependence on what is behind it. The
overlay is found from outside by its class name, so this measures the real
window rather than asking the framework about itself.

Three states, kept separate exactly as the console keeps them:

    open + active + not minimised   -> visible
    open + INACTIVE                 -> hidden, and still open
    open + MINIMISED                -> hidden, and still open

and the content has to survive both: what was typed before is still there after.

    python research/instruments/mods/stage8_focus.py --out focus.json
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _path in (os.path.join(REPO, "research", "instruments", "input"),
              os.path.join(REPO, "research", "instruments", "mods")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import input_probe_controller as probe                             # noqa: E402
import window_census as wc                                         # noqa: E402
import stage8_console as s8                                        # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)

CONSOLE_CLASS = "MiseryDeveloperConsole"
VK_OEM_3 = 0xC0
SW_MINIMIZE, SW_RESTORE = 6, 9
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def find_windows(pid):
    """The game window and the console overlay, both by class, from outside."""
    game = console = None
    found = []

    def callback(hwnd, _lparam):
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if int(owner.value) != pid:
            return True
        name = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, name, 256)
        found.append((name.value, hwnd))
        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)
    for name, hwnd in found:
        if name == wc.UNREAL_WINDOW_CLASS and user32.IsWindowVisible(hwnd):
            game = hwnd
        elif name == CONSOLE_CLASS:
            console = hwnd
    return game, console, found


def overlay_visible(console_hwnd):
    if not console_hwnd:
        return False
    return bool(user32.IsWindowVisible(wt.HWND(console_hwnd)))


def make_decoy():
    """A window to switch to, so 'inactive' is produced rather than waited for.

    Created by THIS process, so activating it is an ordinary application switch
    from MISERY's point of view -- which is what Alt+Tab is.
    """
    hwnd = user32.CreateWindowExW(
        0x00000008 | 0x00000080,          # WS_EX_TOPMOST | WS_EX_TOOLWINDOW
        "STATIC", "MBPL focus decoy",
        0x10000000 | 0x00800000,          # WS_VISIBLE | WS_BORDER
        40, 40, 320, 120, None, None, None, None)
    time.sleep(0.4)
    return hwnd


def activate(hwnd):
    probe.bring_to_foreground(hwnd, attempts=8)
    time.sleep(1.0)
    return int(user32.GetForegroundWindow() or 0) == hwnd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out")
    args = parser.parse_args()

    pids = wc.find_pids(wc.PROCESS_NAME)
    if len(pids) != 1:
        raise SystemExit("expected exactly one MISERY process, found %d" % len(pids))
    pid = pids[0]
    game, _console, _all = find_windows(pid)
    if not game:
        raise SystemExit("no visible UnrealWindow")

    report = {"claim": "the console's focus lifecycle", "pid": pid,
              "game_hwnd": "0x%x" % game}
    rect = [w for w in wc.top_level_windows(pid)
            if w["hwnd"] == game][0]["window_rect"]

    if not activate(game):
        raise SystemExit("could not bring MISERY to the foreground")

    # ---- open the console and type something worth preserving -----------
    _game, console, _ = find_windows(pid)
    if console and overlay_visible(console):
        probe.post_key(game, VK_OEM_3, hold_ms=40, character="`")
        time.sleep(1.0)

    probe.post_key(game, VK_OEM_3, hold_ms=40, character="`")
    time.sleep(1.2)
    s8.type_line(game, "misery:caps")
    time.sleep(0.5)
    game, console, every = find_windows(pid)
    report["console_hwnd"] = "0x%x" % console if console else None
    report["window_classes"] = sorted({name for name, _ in every})
    if not console:
        raise SystemExit("the console overlay window does not exist; is the "
                         "framework installed and the console started?")
    report["open_and_active"] = {"overlay_visible": overlay_visible(console)}
    ink_open, _ = s8.ink_counts(rect)
    report["open_and_active"]["ink"] = ink_open["ink"]

    # ---- Alt+Tab: activation lost, NOT minimised ------------------------
    decoy = make_decoy()
    activate(decoy)
    time.sleep(1.2)
    report["inactive"] = {
        "overlay_visible": overlay_visible(console),
        "game_minimised": bool(user32.IsIconic(wt.HWND(game))),
        "foreground_is_game": int(user32.GetForegroundWindow() or 0) == game,
    }

    # ---- back to the game: it must come back, with what was typed -------
    activate(game)
    time.sleep(1.2)
    report["reactivated"] = {"overlay_visible": overlay_visible(console)}
    ink_back, _ = s8.ink_counts(rect)
    report["reactivated"]["ink"] = ink_back["ink"]

    # ---- minimise: the other state, still separate ----------------------
    user32.ShowWindow(wt.HWND(game), SW_MINIMIZE)
    time.sleep(1.5)
    report["minimised"] = {
        "overlay_visible": overlay_visible(console),
        "game_minimised": bool(user32.IsIconic(wt.HWND(game))),
    }
    user32.ShowWindow(wt.HWND(game), SW_RESTORE)
    activate(game)
    time.sleep(1.5)
    report["restored"] = {"overlay_visible": overlay_visible(console)}

    # ---- leave the game as it was found ---------------------------------
    probe.post_key(game, VK_OEM_3, hold_ms=40, character="`")
    time.sleep(1.0)
    report["closed_again"] = {"overlay_visible": overlay_visible(console)}
    if decoy:
        user32.DestroyWindow(wt.HWND(decoy))
    activate(game)

    report["checks"] = {
        "open and active: the overlay is on screen":
            report["open_and_active"]["overlay_visible"],
        "activation lost WITHOUT minimising: the overlay is hidden":
            not report["inactive"]["overlay_visible"]
            and not report["inactive"]["game_minimised"],
        "reactivating brings it back":
            report["reactivated"]["overlay_visible"],
        "and what was typed survived the round trip":
            abs(report["reactivated"]["ink"] -
                report["open_and_active"]["ink"]) <= max(
                    60, report["open_and_active"]["ink"] // 8),
        "minimised: the overlay is hidden":
            not report["minimised"]["overlay_visible"]
            and report["minimised"]["game_minimised"],
        "restoring brings it back":
            report["restored"]["overlay_visible"],
        "closing it hides it again":
            not report["closed_again"]["overlay_visible"],
    }
    report["verdict"] = "PASS" if all(report["checks"].values()) else "FAIL"

    text = json.dumps(report, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
