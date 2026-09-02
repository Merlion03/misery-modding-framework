#!/usr/bin/env python3
"""C0 -- the read-only window census. Nothing is injected, nothing is changed.

The pre-registration (research/evidence/STAGE8-INPUT/preregistration.md) asks
what exists BEFORE anything attaches: which top-level windows the game process
owns, which one keyboard input would reach, which thread dispatches its
messages, and whether the window is borderless-over-the-monitor or something
else. C1's "exactly one visible top-level UnrealWindow, same handle in all three
lifecycle states" is answered by running this three times with --label.

WHY OUTSIDE THE PROCESS. Every question here is answerable with EnumWindows and
GetWindowLongPtr from another process, so none of it needs injection and none of
it is invasive. The claims that DO need to be inside (C2's game-thread identity,
C3's messages) are a separate, armed instrument. Keeping the read-only half here
means the baseline for the differential is established before the process has
been touched at all.

The build is fingerprinted, not assumed: the sha256 of the image the OS actually
mapped for the pid is compared with the configured build_key, and a mismatch is
a refusal rather than a warning.

    python research/instruments/input/window_census.py --label menu --out x.json
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import hashlib
import json
import os
import sys

BUILD_KEY = ("sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21"
             "ea57a81f013331")
PROCESS_NAME = "MISERY-Win64-Shipping.exe"
UNREAL_WINDOW_CLASS = "UnrealWindow"

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
GWL_STYLE, GWL_EXSTYLE = -16, -20
MONITOR_DEFAULTTONEAREST = 2

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG),
                ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260)]


class MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT),
                ("rcWork", wt.RECT), ("dwFlags", wt.DWORD)]


# Named so a reader does not have to look them up. Only the bits that matter to
# "is this the window keyboard input reaches" are listed.
STYLE_BITS = [(0x10000000, "WS_VISIBLE"), (0x20000000, "WS_MINIMIZE"),
              (0x01000000, "WS_MAXIMIZE"), (0x00C00000, "WS_CAPTION"),
              (0x00800000, "WS_BORDER"), (0x00040000, "WS_THICKFRAME"),
              (0x80000000, "WS_POPUP"), (0x40000000, "WS_CHILD")]
EXSTYLE_BITS = [(0x00000008, "WS_EX_TOPMOST"), (0x00080000, "WS_EX_LAYERED"),
                (0x08000000, "WS_EX_NOACTIVATE"),
                (0x00000080, "WS_EX_TOOLWINDOW"),
                (0x00000020, "WS_EX_TRANSPARENT"),
                (0x00040000, "WS_EX_APPWINDOW")]


def decode_bits(value, table):
    return [name for bit, name in table if (value & bit) == bit]


def find_pids(name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        raise SystemExit("CreateToolhelp32Snapshot failed")
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    found = []
    try:
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return found
        while True:
            if entry.szExeFile.lower() == name.lower():
                found.append(int(entry.th32ProcessID))
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return found


def image_path(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wt.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        fn = kernel32.QueryFullProcessImageNameW
        fn.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        if not fn(handle, 0, buf, ctypes.byref(size)):
            return None
        return buf.value
    finally:
        kernel32.CloseHandle(handle)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def rect_of(hwnd, client=False):
    rect = wt.RECT()
    ok = (user32.GetClientRect(hwnd, ctypes.byref(rect)) if client
          else user32.GetWindowRect(hwnd, ctypes.byref(rect)))
    if not ok:
        return None
    return {"left": rect.left, "top": rect.top, "right": rect.right,
            "bottom": rect.bottom, "width": rect.right - rect.left,
            "height": rect.bottom - rect.top}


def monitor_of(hwnd):
    handle = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
    info = MONITORINFO()
    info.cbSize = ctypes.sizeof(MONITORINFO)
    if not user32.GetMonitorInfoW(handle, ctypes.byref(info)):
        return None
    rect = info.rcMonitor
    return {"left": rect.left, "top": rect.top, "right": rect.right,
            "bottom": rect.bottom, "width": rect.right - rect.left,
            "height": rect.bottom - rect.top}


def describe(hwnd):
    cls = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, cls, 256)
    title = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, title, 512)
    tid = wt.DWORD()
    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    tid.value = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    style = user32.GetWindowLongW(hwnd, GWL_STYLE) & 0xFFFFFFFF
    exstyle = user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF
    window_rect = rect_of(hwnd)
    monitor = monitor_of(hwnd)
    covers_monitor = bool(window_rect and monitor
                          and window_rect["left"] == monitor["left"]
                          and window_rect["top"] == monitor["top"]
                          and window_rect["right"] == monitor["right"]
                          and window_rect["bottom"] == monitor["bottom"])
    return {
        "hwnd": int(hwnd),
        "class": cls.value,
        "title": title.value,
        "pid": int(pid.value),
        "owning_thread_id": int(tid.value),
        "visible": bool(user32.IsWindowVisible(hwnd)),
        "enabled": bool(user32.IsWindowEnabled(hwnd)),
        "owner_hwnd": int(user32.GetWindow(hwnd, 4) or 0),   # GW_OWNER
        "style": "0x%08X" % style,
        "style_bits": decode_bits(style, STYLE_BITS),
        "exstyle": "0x%08X" % exstyle,
        "exstyle_bits": decode_bits(exstyle, EXSTYLE_BITS),
        "window_rect": window_rect,
        "client_rect": rect_of(hwnd, client=True),
        "monitor_rect": monitor,
        "covers_monitor_exactly": covers_monitor,
    }


def top_level_windows(pid):
    out = []

    def callback(hwnd, _lparam):
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if int(owner.value) == pid:
            out.append(describe(hwnd))
        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)
    return out


def display_mode(candidates):
    """What the window geometry says the game is running as.

    Named conservatively. Exclusive fullscreen cannot be distinguished from
    borderless by geometry alone from outside the process -- both cover the
    monitor -- so this reports the geometry and says which readings remain open
    rather than picking one.
    """
    if not candidates:
        return {"verdict": "no-window"}
    win = candidates[0]
    if not win["covers_monitor_exactly"]:
        return {"verdict": "windowed",
                "note": "window rect is smaller than the monitor"}
    borderless = "WS_CAPTION" not in win["style_bits"]
    return {
        "verdict": "covers-monitor",
        "has_caption": not borderless,
        "note": ("geometry alone cannot separate borderless-fullscreen from "
                 "exclusive fullscreen; the overlay test (C9) is what settles "
                 "which one this is"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True,
                        help="lifecycle state: menu | loading | gameplay")
    parser.add_argument("--out", help="write the census here as JSON")
    args = parser.parse_args()

    pids = find_pids(PROCESS_NAME)
    if len(pids) != 1:
        print(json.dumps({"ok": False, "label": args.label,
                          "error": "expected exactly one %s, found %d"
                                   % (PROCESS_NAME, len(pids)),
                          "pids": pids}, indent=2))
        return 2
    pid = pids[0]

    path = image_path(pid)
    build_key = sha256_of(path) if path else None
    if build_key != BUILD_KEY:
        print(json.dumps({"ok": False, "label": args.label, "pid": pid,
                          "error": "build fingerprint mismatch",
                          "expected": BUILD_KEY, "actual": build_key},
                         indent=2))
        return 3

    windows = top_level_windows(pid)
    unreal = [w for w in windows if w["class"] == UNREAL_WINDOW_CLASS]
    visible_unreal = [w for w in unreal if w["visible"]]
    foreground = int(user32.GetForegroundWindow() or 0)

    document = {
        "ok": True,
        "claim": "C0/C1",
        "label": args.label,
        "observed_at": datetime.datetime.now(datetime.timezone.utc)
                               .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pid": pid,
        "image_path": path,
        "build_key": build_key,
        "top_level_window_count": len(windows),
        "unreal_window_count": len(unreal),
        "visible_unreal_window_count": len(visible_unreal),
        "windows": windows,
        "foreground_hwnd": foreground,
        "foreground_is_game": any(w["hwnd"] == foreground for w in windows),
        "display_mode": display_mode(visible_unreal),
        # C1's own predicate, evaluated here so the reading cannot drift later.
        "c1_single_visible_unreal_window": len(visible_unreal) == 1,
        "c1_hwnd": visible_unreal[0]["hwnd"] if len(visible_unreal) == 1 else None,
        "c1_owning_thread_id": (visible_unreal[0]["owning_thread_id"]
                                if len(visible_unreal) == 1 else None),
    }
    text = json.dumps(document, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
