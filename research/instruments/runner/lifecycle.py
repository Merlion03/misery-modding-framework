#!/usr/bin/env python3
"""Process lifecycle: close MISERY, prove it is gone, launch it through Steam,
find the NEW process, and fingerprint it.

Everything here treats "the process" as an identity of ``(pid, start_time)``,
never a bare pid. Windows reuses pids, and a workflow whose entire purpose is
to kill and restart the same executable is exactly the workflow that makes
reuse likely rather than theoretical.

LAUNCHING. Only through Steam, ``steam://run/2119830``. Not a preference:
launching ``MISERY-Win64-Shipping.exe`` directly was measured (LOG-0048) and
the process exits almost immediately -- the Steamworks wrapper expects to be
started by the client. The URL is handed to ShellExecute, which is what
clicking the link in a browser or the Play button in the Steam UI does.

CLOSING. Graceful first: WM_CLOSE to the game's top-level window, which is the
same event as clicking the X, so the engine runs its own shutdown and writes
its settings. Only when that does not finish inside the window does this
escalate to TerminateProcess, and the report says which of the two happened --
a terminate is not a failure, but it IS a different thing from a clean exit and
the evidence should not blur them.

WHY IT IS SAFE TO KILL A PROCESS WITH A PROBE STILL LOADED. It is not safe to
FreeLibrary a probe module while the engine can still reach its code -- that is
what research/instruments/ipp/probe_teardown.py exists to prevent, and it cost
this project a session once. Killing the whole process is the opposite case:
the ticker, the dispatcher and the module all cease to exist together, so there
is no window in which the engine ticks into freed memory. LOG-0093 finding 9
records that ending through process death, rather than through an unload, is
what made a previous cycle's teardown sound.
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import time

STEAM_APP_ID = 2119830
STEAM_RUN_URL = "steam://run/%d" % STEAM_APP_ID
PROCESS_NAME = "MISERY-Win64-Shipping.exe"

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
WM_CLOSE = 0x0010
STILL_ACTIVE = 259


class LifecycleError(Exception):
    pass


class ProcessEntry32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260)]


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    k.Process32FirstW.restype = wt.BOOL
    k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    k.Process32NextW.restype = wt.BOOL
    k.CloseHandle.argtypes = [wt.HANDLE]
    k.CloseHandle.restype = wt.BOOL
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.OpenProcess.restype = wt.HANDLE
    k.GetProcessTimes.argtypes = [wt.HANDLE, ctypes.POINTER(wt.FILETIME),
                                  ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME),
                                  ctypes.POINTER(wt.FILETIME)]
    k.GetProcessTimes.restype = wt.BOOL
    k.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR,
                                             ctypes.POINTER(wt.DWORD)]
    k.QueryFullProcessImageNameW.restype = wt.BOOL
    k.TerminateProcess.argtypes = [wt.HANDLE, ctypes.c_uint]
    k.TerminateProcess.restype = wt.BOOL
    k.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    k.WaitForSingleObject.restype = wt.DWORD
    k.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    k.GetExitCodeProcess.restype = wt.BOOL
    k.GetCurrentThreadId.argtypes = []
    k.GetCurrentThreadId.restype = wt.DWORD
    return k


def _u32():
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
    u.EnumWindows.restype = wt.BOOL
    u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    u.GetWindowThreadProcessId.restype = wt.DWORD
    u.IsWindowVisible.argtypes = [wt.HWND]
    u.IsWindowVisible.restype = wt.BOOL
    u.GetWindow.argtypes = [wt.HWND, wt.UINT]
    u.GetWindow.restype = wt.HWND
    u.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    u.PostMessageW.restype = wt.BOOL
    u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    u.GetWindowTextW.restype = ctypes.c_int
    u.SetForegroundWindow.argtypes = [wt.HWND]
    u.SetForegroundWindow.restype = wt.BOOL
    u.GetForegroundWindow.argtypes = []
    u.GetForegroundWindow.restype = wt.HWND
    u.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
    u.ShowWindow.restype = wt.BOOL
    u.BringWindowToTop.argtypes = [wt.HWND]
    u.BringWindowToTop.restype = wt.BOOL
    u.AttachThreadInput.argtypes = [wt.DWORD, wt.DWORD, wt.BOOL]
    u.AttachThreadInput.restype = wt.BOOL
    return u


def _filetime_to_iso(ft):
    """FILETIME -> ISO8601 UTC. 100ns ticks since 1601-01-01."""
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if ticks == 0:
        return None
    seconds = ticks / 10_000_000 - 11644473600
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def process_identity(pid, k=None):
    """``(start_time_iso, image_path)`` for *pid*, or None if it is not running.

    Uses PROCESS_QUERY_LIMITED_INFORMATION only -- enough for the two facts,
    and nothing that could write to or inject into the target.
    """
    k = k or _k32()
    handle = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        creation, exit_t, kernel, user = (wt.FILETIME(), wt.FILETIME(),
                                          wt.FILETIME(), wt.FILETIME())
        if not k.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_t),
                                 ctypes.byref(kernel), ctypes.byref(user)):
            return None
        size = wt.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        path = buf.value if k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)) else None
        return _filetime_to_iso(creation), path
    finally:
        k.CloseHandle(handle)


def find_processes(name=PROCESS_NAME, k=None):
    """Every live process with this image name, as ``[{pid, start_time, exe_path}]``."""
    k = k or _k32()
    snapshot = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wt.HANDLE(-1).value or not snapshot:
        raise LifecycleError("CreateToolhelp32Snapshot failed: %d" % ctypes.get_last_error())
    found = []
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(ProcessEntry32W)
        ok = k.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == name.lower():
                identity = process_identity(entry.th32ProcessID, k) or (None, None)
                found.append({"pid": int(entry.th32ProcessID),
                              "start_time": identity[0], "exe_path": identity[1]})
            ok = k.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k.CloseHandle(snapshot)
    return found


def find_main_window(pid, u=None):
    """The game's top-level, visible, owner-less window, or None.

    Owner-less matters: UE creates transient owned windows (splash, dialogs) that
    are visible and belong to the same pid. Sending WM_CLOSE to a splash is a
    no-op that looks like a graceful close request and is not one.
    """
    u = u or _u32()
    result = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def callback(hwnd, _lparam):
        owner_pid = wt.DWORD(0)
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
        if owner_pid.value != int(pid):
            return True
        if not u.IsWindowVisible(hwnd):
            return True
        if u.GetWindow(hwnd, 4):        # GW_OWNER -- an owned window is not the main one
            return True
        title = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(hwnd, title, 512)
        result.append((int(hwnd), title.value))
        return True

    u.EnumWindows(callback, 0)
    return result[0] if result else None


def close_process(pid, *, graceful_timeout_s=45, terminate_timeout_s=15, note=None):
    """Close ONE process. Returns a dict describing how it ended.

    ``method`` is ``"wm_close"``, ``"terminate"`` or ``"already_gone"``.
    ``exited`` is the fact that matters; ``method`` is how we got there.
    """
    say = note.append if note is not None else (lambda _m: None)
    k, u = _k32(), _u32()
    out = {"pid": int(pid), "method": None, "exited": False, "exit_code": None,
           "window": None, "graceful_timeout_s": graceful_timeout_s}

    handle = k.OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                           False, int(pid))
    if not handle:
        out["method"] = "already_gone"
        out["exited"] = True
        say("pid %d was already gone" % pid)
        return out
    try:
        window = find_main_window(pid, u)
        if window:
            out["window"] = {"hwnd": "0x%x" % window[0], "title": window[1]}
            u.PostMessageW(window[0], WM_CLOSE, 0, 0)
            say("WM_CLOSE posted to %r (hwnd 0x%x)" % (window[1], window[0]))
            if k.WaitForSingleObject(handle, int(graceful_timeout_s * 1000)) == 0:
                out["method"] = "wm_close"
                out["exited"] = True
        else:
            say("pid %d has no top-level window; going straight to terminate" % pid)

        if not out["exited"]:
            # Escalation. Safe here in a way that unloading a probe module is
            # not: everything the engine could still reach dies with the
            # process, in one step, with no window in between.
            k.TerminateProcess(handle, 1)
            out["method"] = "terminate"
            out["exited"] = k.WaitForSingleObject(handle, int(terminate_timeout_s * 1000)) == 0
            say("terminated pid %d (exited=%s)" % (pid, out["exited"]))

        code = wt.DWORD(0)
        if k.GetExitCodeProcess(handle, ctypes.byref(code)):
            out["exit_code"] = int(code.value)
            if out["exit_code"] == STILL_ACTIVE:
                out["exited"] = False
    finally:
        k.CloseHandle(handle)
    return out


def prove_gone(old_pids, *, timeout_s=30, interval_s=0.5, name=PROCESS_NAME, note=None,
               clock=time.time, sleeper=time.sleep):
    """Prove no process with *name* is running any more, and specifically that
    none of *old_pids* is. Raises LifecycleError on timeout.

    Both halves are needed. "None of the old pids is running" alone would pass
    while a second copy of the game sits there; "no process by that name" alone
    would pass on a snapshot taken a moment before a dying process is reaped.
    """
    say = note.append if note is not None else (lambda _m: None)
    old = {int(p) for p in old_pids}
    deadline = clock() + timeout_s
    remaining = None
    while clock() < deadline:
        live = find_processes(name)
        remaining = [p["pid"] for p in live]
        if not remaining:
            say("proved gone: no %s process, old pids %r are dead" % (name, sorted(old)))
            return {"proved": True, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "old_pids": sorted(old)}
        sleeper(interval_s)
    raise LifecycleError("%s still running after %ds: pids %r" % (name, timeout_s, remaining))


def steam_is_running():
    return bool(find_processes("steam.exe"))


def launch_through_steam(*, note=None, url=STEAM_RUN_URL):
    """Ask Steam to run the app, the same way the Play button does.

    Returns the wall-clock instant the request was made, which the new-process
    detector uses as a lower bound on the new process's start time -- so a
    stale copy of the game that was already running can never be mistaken for
    the one this cycle launched.
    """
    say = note.append if note is not None else (lambda _m: None)
    if not steam_is_running():
        raise LifecycleError("steam.exe is not running: %s cannot be served" % url)
    requested_at = time.time()
    # ShellExecute via the shell's URL handler. os.startfile would do the same
    # but gives no exit status at all; `cmd /c start` at least fails loudly if
    # the protocol handler is missing.
    result = subprocess.run(["cmd", "/c", "start", "", url], capture_output=True, text=True)
    if result.returncode != 0:
        raise LifecycleError("launching %s failed: rc=%d %s"
                             % (url, result.returncode, (result.stderr or "").strip()))
    say("launch requested through Steam: %s" % url)
    return requested_at


def wait_for_new_process(*, excluded_pids=(), requested_at=None, timeout_s=180,
                         interval_s=1.0, name=PROCESS_NAME, note=None,
                         clock=time.time, sleeper=time.sleep):
    """Wait for exactly one NEW process of *name*.

    "New" is three conditions, all required: the pid is not in *excluded_pids*;
    the process started at or after *requested_at*; and it is the only one. More
    than one live copy is an error rather than a pick-the-first, because "which
    of these two is mine" has no honest answer and a probe aimed at the wrong
    one would produce clean-looking nonsense.
    """
    say = note.append if note is not None else (lambda _m: None)
    excluded = {int(p) for p in excluded_pids if p}
    floor = None
    if requested_at is not None:
        # One second of slack: process creation time and our own clock reading
        # are not the same clock, and rounding to whole seconds can put a
        # genuinely-new process a fraction of a second "before" the request.
        floor = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(requested_at - 1))
    deadline = clock() + timeout_s
    last = None
    while clock() < deadline:
        live = [p for p in find_processes(name) if p["pid"] not in excluded]
        if floor:
            live = [p for p in live if p["start_time"] and p["start_time"] >= floor]
        last = live
        if len(live) == 1:
            say("new process: pid %d started %s" % (live[0]["pid"], live[0]["start_time"]))
            return live[0]
        if len(live) > 1:
            raise LifecycleError("%d live %s processes (%r): refusing to guess which one "
                                 "this cycle launched" % (len(live), name,
                                                          [p["pid"] for p in live]))
        sleeper(interval_s)
    raise LifecycleError("no new %s process within %ds (last seen: %r)" % (name, timeout_s, last))


def fingerprint_process(ipp, process, *, expected_sha256, note=None):
    """Hash the image the OS actually mapped for this process and compare.

    The path is the live process's own ``QueryFullProcessImageNameW`` result --
    not a configured path, not the previous run's. That is what makes this a
    fingerprint of the thing we are about to instrument rather than of a file
    that happens to be nearby.
    """
    say = note.append if note is not None else (lambda _m: None)
    exe_path = process.get("exe_path")
    if not exe_path or not os.path.isfile(exe_path):
        raise LifecycleError("cannot read the live image path for pid %s (%r)"
                             % (process.get("pid"), exe_path))
    observed = ipp.sha256_of_file(exe_path)
    out = {"pid": process["pid"], "exe_path": exe_path, "observed_sha256": observed,
           "expected_sha256": expected_sha256, "matches": observed == expected_sha256}
    if not out["matches"]:
        raise LifecycleError(
            "build identity mismatch: live=%s expected=%s. Steam may have updated the "
            "game (this has happened once already, LOG-0048); re-fingerprint before "
            "running anything against it." % (observed, expected_sha256))
    say("build identity confirmed sha256:%s" % observed)
    return out
