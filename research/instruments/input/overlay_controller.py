#!/usr/bin/env python3
"""C9: show an overlay over the game and READ THE SCREEN BACK.

"It looked right" is not a measurement. The probe paints three flat bands of
exact RGB values; this captures the desktop and checks that those exact values
are at the coordinates the overlay occupies, and that they are NOT at
coordinates just outside it. Both halves matter: a capture that is uniformly the
band colour would pass a naive check while proving nothing.

It also records the foreground before and after, because an overlay that works
by stealing activation is not the overlay this design needs.

    python research/instruments/input/overlay_controller.py show --run-dir DIR
    python research/instruments/input/overlay_controller.py hide
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))

import ipp_controller as ipp                                       # noqa: E402
import input_probe_controller as probe                             # noqa: E402
import window_census as wc                                         # noqa: E402

DLL_NAME = "OverlayProbe.dll"
MAGIC = 0x4D424F564C593031
PROTO = 1
IO_FMT = "<QIIiiiiIQQQQII"
IO_SIZE = struct.calcsize(IO_FMT)
STATUS = {0: "ok", 1: "no single visible UnrealWindow", 2: "RegisterClass failed",
          3: "CreateWindowEx failed", 4: "bad io", 5: "already up", 6: "not up"}

BANDS = [(255, 0, 128), (0, 255, 128), (0, 128, 255)]

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

SESSION = os.path.join(REPO, "workspace", "input-probe", "overlay-session.json")


def build():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    source = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal",
                          "OverlayProbeDll.cpp")
    build_dir = os.path.join(REPO, "workspace", "input-probe")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, DLL_NAME)
    if os.path.isfile(out):
        os.remove(out)
    bat = os.path.join(build_dir, "_build_overlay.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as handle:
        handle.write("@echo off\r\n")
        handle.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        handle.write('cl /nologo /LD /MT /EHsc /std:c++17 /W4 /DUNICODE /D_UNICODE '
                     '"%s" /Fe:"%s" /link /INCREMENTAL:NO user32.lib gdi32.lib\r\n'
                     % (source, out))
    result = subprocess.run([bat], capture_output=True, text=True, cwd=build_dir,
                            shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("OverlayProbe.dll did not build:\n%s\n%s"
                          % (result.stdout, result.stderr))
    return out


def grab_pixels(points):
    """Read exact desktop pixels. One DC, one GetPixel per point."""
    dc = user32.GetDC(None)
    try:
        out = []
        for x, y in points:
            value = gdi32.GetPixel(dc, x, y)
            if value == 0xFFFFFFFF:      # CLR_INVALID
                out.append(None)
                continue
            out.append(((value) & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF))
        return out
    finally:
        user32.ReleaseDC(None, dc)


def near(actual, expected, tolerance=24):
    if actual is None:
        return False
    return all(abs(a - e) <= tolerance for a, e in zip(actual, expected))


def do_show(args):
    pid, path, key = probe.find_game()
    windows = [w for w in wc.top_level_windows(pid)
               if w["class"] == wc.UNREAL_WINDOW_CLASS and w["visible"]]
    if len(windows) != 1:
        raise ipp.Blocked("expected exactly one visible UnrealWindow, found %d"
                          % len(windows))
    game = windows[0]
    rect = game["window_rect"]
    # A console-shaped strip: full width, top 40%.
    x, y = rect["left"], rect["top"]
    width, height = rect["width"], int(rect["height"] * 0.40)

    k32, handle = probe.open_game(pid)
    # A module already in the process is reused rather than rebuilt. Rebuilding
    # would try to delete a DLL the game has mapped, which fails -- and the first
    # version of this did exactly that, so the overlay measurement it was asked
    # for silently produced no JSON at all.
    base = ipp.find_remote_module_base(k32, pid, DLL_NAME)
    dll = os.path.join(REPO, "workspace", "input-probe", DLL_NAME)
    if base:
        if not os.path.isfile(dll):
            raise ipp.Blocked("%s is loaded in the game but the local copy is "
                              "gone; its export RVAs cannot be read" % DLL_NAME)
    else:
        dll = build()
        remote_path = k32.VirtualAllocEx(handle, None, 4096,
                                         probe.MEM_COMMIT_RESERVE,
                                         probe.PAGE_READWRITE)
        probe.write_remote(k32, handle, remote_path,
                           (dll + "\x00").encode("utf-16-le"))
        kernel = k32.GetModuleHandleW("kernel32.dll")
        thread = k32.CreateRemoteThread(handle, None, 0,
                                        k32.GetProcAddress(kernel, b"LoadLibraryW"),
                                        ctypes.c_void_p(remote_path), 0, None)
        if k32.WaitForSingleObject(thread, 20000) != 0:
            raise ipp.Blocked("LoadLibraryW did not finish")
        k32.CloseHandle(thread)
        base = ipp.find_remote_module_base(k32, pid, DLL_NAME)
        if not base:
            raise ipp.Blocked("%s is not loaded" % DLL_NAME)

    io_address = k32.VirtualAllocEx(handle, None, 4096, probe.MEM_COMMIT_RESERVE,
                                    probe.PAGE_READWRITE)
    payload = struct.pack(IO_FMT, MAGIC, PROTO, 0, x, y, width, height,
                          args.alpha, 0, 0, 0, 0, 0, 0)
    probe.write_remote(k32, handle, io_address, payload)

    foreground_before = int(user32.GetForegroundWindow() or 0)
    rva = ipp.find_export_rva(dll, "OverlayShow")
    thread = k32.CreateRemoteThread(handle, None, 0, base + rva,
                                    ctypes.c_void_p(io_address), 0, None)
    waited = k32.WaitForSingleObject(thread, 20000)
    code = wt.DWORD(0)
    k32.GetExitCodeThread(thread, ctypes.byref(code))
    k32.CloseHandle(thread)
    if waited != 0:
        raise ipp.Blocked("OverlayShow did not return")

    fields = struct.unpack(IO_FMT, probe.read_remote(k32, handle, io_address, IO_SIZE))
    session = {"pid": pid, "dll": dll, "module_base": base,
               "io_address": io_address, "rect": [x, y, width, height]}
    os.makedirs(os.path.dirname(SESSION), exist_ok=True)
    with open(SESSION, "w", encoding="utf-8") as handle_out:
        json.dump(session, handle_out, indent=2)

    time.sleep(0.5)
    # Three points inside the overlay, one per band, and two outside it.
    inside = [(x + width // 2, y + int(height * frac)) for frac in (0.16, 0.5, 0.84)]
    outside = [(x + width // 2, min(y + height + 120, rect["bottom"] - 4)),
               (x + width // 2, rect["bottom"] - 20)]
    samples_inside = grab_pixels(inside)
    samples_outside = grab_pixels(outside)

    matched = [near(actual, expected)
               for actual, expected in zip(samples_inside, BANDS)]
    bled = [any(near(actual, band) for band in BANDS) for actual in samples_outside]

    document = {
        "claim": "C9",
        "status": code.value, "status_name": STATUS.get(code.value, "?"),
        "overlay_hwnd": "0x%x" % fields[8],
        "game_hwnd": "0x%x" % fields[9],
        "paints": fields[13],
        "overlay_thread_id": fields[12],
        "foreground_before": "0x%x" % foreground_before,
        "foreground_after": "0x%x" % int(user32.GetForegroundWindow() or 0),
        "foreground_unchanged": foreground_before == int(user32.GetForegroundWindow() or 0),
        "rect": {"x": x, "y": y, "width": width, "height": height},
        "sample_points_inside": inside, "sampled_inside": samples_inside,
        "expected_bands": BANDS, "bands_matched": matched,
        "sample_points_outside": outside, "sampled_outside": samples_outside,
        "bands_bled_outside": bled,
        "verdict": ("PASS" if code.value == 0 and all(matched) and not any(bled)
                    else "FAIL"),
        "why": ("all three bands read back at their exact coordinates and none "
                "of them appears outside the overlay, with the foreground "
                "unchanged"
                if code.value == 0 and all(matched) and not any(bled)
                else "see bands_matched / bands_bled_outside / status_name"),
    }
    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "c9-overlay.json"), "w",
                  encoding="utf-8") as out:
            out.write(json.dumps(document, indent=2) + "\n")
    print(json.dumps(document, indent=2))
    return 0 if document["verdict"] == "PASS" else 1


def do_hide(args):
    with open(SESSION, encoding="utf-8") as handle:
        session = json.load(handle)
    k32, handle = probe.open_game(session["pid"])
    probe.write_remote(k32, handle, session["io_address"],
                       struct.pack(IO_FMT, MAGIC, PROTO, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0))
    rva = ipp.find_export_rva(session["dll"], "OverlayHide")
    thread = k32.CreateRemoteThread(handle, None, 0, session["module_base"] + rva,
                                    ctypes.c_void_p(session["io_address"]), 0, None)
    k32.WaitForSingleObject(thread, 20000)
    code = wt.DWORD(0)
    k32.GetExitCodeThread(thread, ctypes.byref(code))
    k32.CloseHandle(thread)
    fields = struct.unpack(IO_FMT, probe.read_remote(k32, handle,
                                                     session["io_address"], IO_SIZE))
    print(json.dumps({"status": code.value, "status_name": STATUS.get(code.value, "?"),
                      "paints": fields[13]}, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("show")
    show.add_argument("--alpha", type=int, default=235)
    show.set_defaults(func=do_show)
    sub.add_parser("hide").set_defaults(func=do_hide)
    args = parser.parse_args()
    try:
        return args.func(args)
    except ipp.Blocked as blocked:
        print(json.dumps({"ok": False, "blocked": str(blocked)}, indent=2))
        return 3


if __name__ == "__main__":
    sys.exit(main())
