#!/usr/bin/env python3
"""Stage 8 live acceptance: the developer console, in a real Steam launch.

WHAT THIS PROVES, AND HOW
-------------------------
A log line saying "console ready" proves the code ran. It does not prove a key
opens anything, that anything is drawn, or that a command does something. So the
acceptance is done on the SCREEN, the same way C9 was: the console's own
background is an exact colour nothing in a survival game's palette produces, and
the pixels are read back rather than looked at.

    baseline        the game's scene         -> no console colour
    toggle          post the toggle key      -> the console colour is there
    type + Enter    post a command           -> what is drawn CHANGES
    toggle again    post the toggle key      -> the console colour is gone

Keys are delivered with PostMessage, which puts a genuine WM_KEYDOWN in the
game's own window queue -- the path the input source reads. TranslateMessage
does not run for a posted message, so the WM_CHAR is posted deliberately; that
is exactly what the console consumes, so the pipeline being exercised is the
real one. What it does NOT cover is the OS key state, which is why the manual
checklist exists and is run on a real keyboard.

    python research/instruments/mods/stage8_console.py --install --launch
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _path in (os.path.join(REPO, "research", "instruments", "mods"),
              os.path.join(REPO, "research", "instruments", "input"),
              os.path.join(REPO, "research", "instruments", "runner"),
              os.path.join(REPO, "tools", "modplatform")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import stage5b_bindings as sb                                      # noqa: E402
import stage7_reference as s7                                      # noqa: E402
import install as installer                                        # noqa: E402
import window_census as wc                                         # noqa: E402
import input_probe_controller as probe                             # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

VK_OEM_3 = 0xC0
VK_RETURN = 0x0D

# THE FIRST DISCRIMINATOR WAS WRONG, AND IT IS WORTH SAYING WHY.
#
# It counted pixels near ConsoleUi's background colour (12,14,18). MISERY's menu
# screen is very nearly black, so 57 of 63 sampled points already matched it
# BEFORE the console was opened -- the metric could not tell the console from a
# dark screen, and "the console is not on screen to begin with" failed for that
# reason rather than because anything was wrong.
#
# What cannot appear on a dark screen is the console's own TEXT. So the region is
# captured whole and its distinctive colours are counted: the prompt's yellow,
# the banner's green, the body's near-white. None of those is a colour a survival
# game's night palette produces, and text pixels are sparse enough that a grid of
# sample points would miss them -- which is why this reads every pixel rather
# than sampling.
CONSOLE_BACKGROUND = (12, 14, 18)
CONSOLE_INK = {
    "prompt": (240, 220, 140),
    "notice": (150, 200, 140),
    "output": (206, 212, 220),
    "echo": (120, 170, 235),
    "error": (240, 110, 110),
}
# Drawn at alpha 232 over whatever is behind, so every colour arrives blended.
INK_TOLERANCE = 40


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def capture(rect):
    """Every pixel of the console's area, as (b, g, r) triples."""
    width, height = rect["width"], int(rect["height"] * 0.42)
    screen = user32.GetDC(None)
    memory = gdi32.CreateCompatibleDC(screen)
    bitmap = gdi32.CreateCompatibleBitmap(screen, width, height)
    previous = gdi32.SelectObject(memory, bitmap)
    gdi32.BitBlt(memory, 0, 0, width, height, screen,
                 rect["left"], rect["top"], 0x00CC0020)   # SRCCOPY
    info = BITMAPINFO()
    info.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    info.bmiHeader.biWidth = width
    info.bmiHeader.biHeight = -height          # top-down
    info.bmiHeader.biPlanes = 1
    info.bmiHeader.biBitCount = 32
    info.bmiHeader.biCompression = 0           # BI_RGB
    buffer = (ctypes.c_ubyte * (width * height * 4))()
    gdi32.GetDIBits(memory, bitmap, 0, height, buffer, ctypes.byref(info), 0)
    gdi32.SelectObject(memory, previous)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(memory)
    user32.ReleaseDC(None, screen)
    return bytes(bytearray(buffer)), width, height


def ink_counts(rect):
    """How many pixels are each of the console's own colours, and a digest."""
    raw, width, height = capture(rect)
    counts = {name: 0 for name in CONSOLE_INK}
    background = 0
    for index in range(0, len(raw), 4):
        blue, green, red = raw[index], raw[index + 1], raw[index + 2]
        if (abs(red - CONSOLE_BACKGROUND[0]) <= 24 and
                abs(green - CONSOLE_BACKGROUND[1]) <= 24 and
                abs(blue - CONSOLE_BACKGROUND[2]) <= 24):
            background += 1
            continue
        for name, (r, g, b) in CONSOLE_INK.items():
            if (abs(red - r) <= INK_TOLERANCE and abs(green - g) <= INK_TOLERANCE
                    and abs(blue - b) <= INK_TOLERANCE):
                counts[name] += 1
                break
    counts["background"] = background
    counts["total"] = width * height
    counts["ink"] = sum(counts[name] for name in CONSOLE_INK)
    return counts, hashlib.sha256(raw).hexdigest()[:16]


def post_key(hwnd, vk, character=None, hold_ms=40):
    probe.post_key(hwnd, vk, hold_ms=hold_ms, character=character)


def type_line(hwnd, text):
    for character in text:
        # The virtual key is irrelevant to the console -- it reads the CHARACTER,
        # which is the whole reason this mechanism was chosen over Slate's.
        probe.post_key(hwnd, ord(character.upper()), hold_ms=12,
                       character=character)
        time.sleep(0.03)


def game_window():
    pids = wc.find_pids(wc.PROCESS_NAME)
    if len(pids) != 1:
        raise SystemExit("expected exactly one MISERY process, found %d" % len(pids))
    windows = [w for w in wc.top_level_windows(pids[0])
               if w["class"] == wc.UNREAL_WINDOW_CLASS and w["visible"]]
    if len(windows) != 1:
        raise SystemExit("expected exactly one visible UnrealWindow")
    return pids[0], windows[0]


def read_runtime_log(install_root):
    path = sb.fc.framework_path(install_root, "runtime.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def do_install(install_root):
    payload = s7.install_everything(install_root)
    neighbours = s7.install_neighbours(install_root)
    return {"payload": payload, "neighbours": neighbours}


def screen_acceptance(hwnd_record, report):
    hwnd = hwnd_record["hwnd"]
    rect = hwnd_record["window_rect"]

    probe.bring_to_foreground(hwnd, attempts=8)
    time.sleep(1.0)
    report["foreground_is_game"] = int(user32.GetForegroundWindow() or 0) == hwnd

    def step(label):
        counts, sha = ink_counts(rect)
        report[label] = {"ink": counts, "digest": sha}
        return counts

    baseline = step("baseline")

    post_key(hwnd, VK_OEM_3, character="`")
    time.sleep(1.2)
    opened = step("after_toggle")

    type_line(hwnd, "misery:caps")
    post_key(hwnd, VK_RETURN, character="\r")
    time.sleep(1.8)
    after_command = step("after_command")

    post_key(hwnd, VK_OEM_3, character="`")
    time.sleep(1.2)
    closed = step("after_close")

    # THE SECOND THRESHOLD WAS ALSO WRONG, and the data said so rather than the
    # console being broken: it required 200 prompt-coloured pixels, and "> "
    # plus a blinking caret at an 18px font is about 44 of them, half the time.
    #
    # What discriminates by four orders of magnitude is the GAME's own content
    # disappearing behind the console: the menu's light text is ~76,000 pixels
    # and drops to single digits the moment the overlay is up. That is the check,
    # and the margin is not a threshold anyone has to tune.
    report["measured"] = {
        "game_text_pixels_before": baseline["output"],
        "game_text_pixels_with_console_open": opened["output"],
        "game_text_pixels_after_close": closed["output"],
        "console_ink_open": opened["ink"],
        "console_ink_after_command": after_command["ink"],
    }
    report["checks"] = {
        "the game's own screen is what is showing to begin with":
            baseline["output"] > 1000,
        "the toggle key covers it with the console":
            opened["output"] < baseline["output"] // 100 and
            opened["background"] >= int(opened["total"] * 0.98),
        "running a command adds text to the console":
            after_command["ink"] > opened["ink"] * 1.15,
        "the toggle key gives the game its screen back":
            closed["output"] > 1000,
    }
    report["verdict"] = "PASS" if all(report["checks"].values()) else "FAIL"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--settle-s", type=float, default=70.0)
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    report = {"install_root": args.install_root}

    if args.install:
        s7.build_managed()
        report["install"] = do_install(args.install_root)

    if args.launch:
        sb.fc.close_game()
        log_path = sb.fc.framework_path(args.install_root, "runtime.log")
        if os.path.isfile(log_path):
            os.remove(log_path)
        report["launch"] = sb.fc.launch_and_observe(args.install_root,
                                                    settle=args.settle_s)
        log = read_runtime_log(args.install_root)
        report["console_log_lines"] = [line for line in log.splitlines()
                                       if "console" in line.lower()
                                       or "input" in line.lower()]
        report["managed_log_lines"] = [line for line in log.splitlines()
                                       if "managed host" in line
                                       or "mod " in line][:20]

    _pid, window = game_window()
    report["window"] = {"hwnd": "0x%x" % window["hwnd"],
                        "rect": window["window_rect"]}
    screen_acceptance(window, report)

    text = json.dumps(report, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0 if report.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
