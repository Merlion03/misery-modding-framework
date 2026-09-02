#!/usr/bin/env python3
"""Drive InputProbeDll and answer C1-C8 from what it records.

The probe is the only thing inside the process. Everything here is outside:
build, inject, call Init once, then poll ProbeState with ReadProcessMemory and
flip capture with WriteProcessMemory. No remote thread is created per keystroke
or per toggle, because a measurement whose own cost is a thread creation is not
a measurement of the input path.

    ... input_probe_controller.py attach   --run-dir DIR
    ... input_probe_controller.py keys     --run-dir DIR --label gameplay
    ... input_probe_controller.py capture  --on | --off
    ... input_probe_controller.py poll     --run-dir DIR --label X
    ... input_probe_controller.py detach   --run-dir DIR

SYNTHETIC PRESSES, AND WHAT THAT DOES AND DOES NOT PROVE. `keys` drives the
scripted set with SendInput. At the window procedure a synthesized press is
indistinguishable from a physical one -- the injected flag is visible only to
low-level hooks and raw input -- so C3's message shapes are established by this.
What it cannot establish is anything about a path that filters injected input,
which is why the manual acceptance pass repeats the toggle and the typing on a
real keyboard.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import json
import os
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))

import ipp_controller as ipp                                       # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window_census as wc                                        # noqa: E402

DLL_NAME = "InputProbe.dll"
MAGIC = 0x4D42494E50525031
PROTO = 1
RING_CAPACITY = 512

# ProbeIo, matching the #pragma pack(1) struct in InputProbeDll.cpp.
IO_FMT = "<QIIQII"
IO_SIZE = struct.calcsize(IO_FMT)

# ProbeState header up to (not including) the ring.
STATE_FMT = "<QIIIIIQQQIIIIIIIQQQQQQII"
STATE_SIZE = struct.calcsize(STATE_FMT)
EVENT_FMT = "<IIIIIIII"
EVENT_SIZE = struct.calcsize(EVENT_FMT)

STATUS_NAMES = {
    0: "ok", 1: "no visible UnrealWindow", 2: "more than one visible UnrealWindow",
    3: "already attached", 4: "SetWindowLongPtrW failed", 5: "not attached",
    6: "a foreign window procedure is installed -- refusing to unlink it",
    7: "restore failed", 8: "bad io block",
}

MESSAGE_NAMES = {
    0x0100: "WM_KEYDOWN", 0x0101: "WM_KEYUP", 0x0102: "WM_CHAR",
    0x0103: "WM_DEADCHAR", 0x0104: "WM_SYSKEYDOWN", 0x0105: "WM_SYSKEYUP",
    0x0106: "WM_SYSCHAR", 0x0107: "WM_SYSDEADCHAR", 0x0109: "WM_UNICHAR",
}

VK_NAMES = {
    0x08: "VK_BACK", 0x09: "VK_TAB", 0x0D: "VK_RETURN", 0x10: "VK_SHIFT",
    0x1B: "VK_ESCAPE", 0x21: "VK_PRIOR", 0x22: "VK_NEXT", 0x25: "VK_LEFT",
    0x26: "VK_UP", 0x27: "VK_RIGHT", 0x28: "VK_DOWN", 0xC0: "VK_OEM_3",
}

MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000
PROCESS_ALL = 0x1F0FFF

user32 = ctypes.WinDLL("user32", use_last_error=True)


# ---------------------------------------------------------------- build

def build_probe_dll():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if not os.path.isfile(vcvars):
        raise ipp.Blocked("MSVC vcvars64 not found at %s" % vcvars)
    source = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal",
                          "InputProbeDll.cpp")
    build_dir = os.path.join(REPO, "workspace", "input-probe")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, DLL_NAME)
    if os.path.isfile(out):
        os.remove(out)
    bat = os.path.join(build_dir, "_build_input_probe.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as handle:
        handle.write("@echo off\r\n")
        handle.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        handle.write('cl /nologo /LD /MT /EHsc /std:c++17 /W4 /DUNICODE /D_UNICODE '
                     '"%s" /Fe:"%s" /link /INCREMENTAL:NO user32.lib\r\n'
                     % (source, out))
    result = subprocess.run([bat], capture_output=True, text=True,
                            cwd=build_dir, shell=True)
    if not os.path.isfile(out):
        raise ipp.Blocked("InputProbe.dll did not build:\n%s\n%s"
                          % (result.stdout, result.stderr))
    return out


# ---------------------------------------------------------- process access

def find_game():
    pids = wc.find_pids(wc.PROCESS_NAME)
    if len(pids) != 1:
        raise ipp.Blocked("expected exactly one %s, found %d"
                          % (wc.PROCESS_NAME, len(pids)))
    pid = pids[0]
    path = wc.image_path(pid)
    key = wc.sha256_of(path)
    if key != wc.BUILD_KEY:
        raise ipp.Blocked("build fingerprint mismatch: %s" % key)
    return pid, path, key


def session_path():
    return os.path.join(REPO, "workspace", "input-probe", "session.json")


def save_session(document):
    os.makedirs(os.path.dirname(session_path()), exist_ok=True)
    with open(session_path(), "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)


def load_session():
    if not os.path.isfile(session_path()):
        raise ipp.Blocked("no probe session; run `attach` first")
    with open(session_path(), encoding="utf-8") as handle:
        return json.load(handle)


def open_game(pid):
    k32 = ipp._k32()
    handle = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not handle:
        raise ipp.Blocked("OpenProcess failed: %d" % ctypes.get_last_error())
    return k32, handle


def read_remote(k32, handle, address, size):
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size,
                                 ctypes.byref(got)):
        raise ipp.Blocked("ReadProcessMemory(0x%x, %d) failed: %d"
                          % (address, size, ctypes.get_last_error()))
    return bytes(bytearray(buf))[:got.value]


def write_remote(k32, handle, address, payload):
    put = ctypes.c_size_t(0)
    if not k32.WriteProcessMemory(handle, ctypes.c_void_p(address), payload,
                                  len(payload), ctypes.byref(put)):
        raise ipp.Blocked("WriteProcessMemory failed: %d" % ctypes.get_last_error())


# ------------------------------------------------------------- state decode

STATE_FIELDS = [
    "magic", "proto", "state_size", "capture_request", "reset_request", "status",
    "hwnd", "original_proc", "our_proc", "window_thread_id", "attach_thread_id",
    "attached", "detached", "top_level_windows", "unreal_windows",
    "visible_unreal_windows", "seen", "suppressed", "forwarded", "all_messages",
    "nanos_total", "nanos_max", "ring_capacity", "ring_write",
]
# Offsets computed once from the format, so a field added on the C++ side that is
# not added here shows up as a size mismatch rather than as shifted numbers.
OFF_CAPTURE = struct.calcsize("<QII")
OFF_RESET = OFF_CAPTURE + 4


def decode_state(raw):
    values = struct.unpack(STATE_FMT, raw[:STATE_SIZE])
    state = dict(zip(STATE_FIELDS, values))
    if state["magic"] != MAGIC:
        raise ipp.Blocked("probe state magic is 0x%x, not the probe's"
                          % state["magic"])
    expected = STATE_SIZE + RING_CAPACITY * EVENT_SIZE
    if state["state_size"] != expected:
        raise ipp.Blocked(
            "the probe reports sizeof(ProbeState)=%d, this reader expects %d -- "
            "the two halves have drifted and every number below would be shifted"
            % (state["state_size"], expected))
    state["status_name"] = STATUS_NAMES.get(state["status"], "?")
    return state


def decode_ring(raw, state):
    """Newest-last, and only the records the writer finished.

    A record whose seq is 0 was mid-write when the page was read; it is dropped
    rather than reported, because a half-written event is not an observation.
    """
    events = []
    body = raw[STATE_SIZE:STATE_SIZE + RING_CAPACITY * EVENT_SIZE]
    for index in range(RING_CAPACITY):
        seq, message, vkey, scancode, flags, tid, suppressed, nanos = (
            struct.unpack_from(EVENT_FMT, body, index * EVENT_SIZE))
        if seq == 0:
            continue
        events.append({
            "seq": seq,
            "message": MESSAGE_NAMES.get(message, "0x%04X" % message),
            "message_id": message,
            "vkey": vkey,
            "vkey_name": VK_NAMES.get(vkey),
            "char": (chr(vkey) if message in (0x0102, 0x0106) and 32 <= vkey < 0x110000
                     else None),
            "scancode": scancode,
            "extended": bool(flags & 1),
            # lParam bit 30 is the PREVIOUS key state, which is set on every
            # key-up by definition. It only means auto-repeat on a key-down.
            "repeat": bool(flags & 2) and message in (0x0100, 0x0104, 0x0102, 0x0106),
            "alt_down": bool(flags & 4),
            "thread_id": tid,
            "suppressed": bool(suppressed),
            "nanos": nanos,
        })
    events.sort(key=lambda e: e["seq"])
    return events


def read_state(k32, handle, address):
    raw = read_remote(k32, handle, address, STATE_SIZE + RING_CAPACITY * EVENT_SIZE)
    state = decode_state(raw)
    return state, decode_ring(raw, state)


# ----------------------------------------------------------------- commands

def do_attach(args):
    pid, path, key = find_game()
    dll = build_probe_dll()
    k32, handle = open_game(pid)

    remote_path = k32.VirtualAllocEx(handle, None, 4096, MEM_COMMIT_RESERVE,
                                     PAGE_READWRITE)
    if not remote_path:
        raise ipp.Blocked("VirtualAllocEx(path) failed")
    encoded = (dll + "\x00").encode("utf-16-le")
    write_remote(k32, handle, remote_path, encoded)

    kernel = k32.GetModuleHandleW("kernel32.dll")
    load_library = k32.GetProcAddress(kernel, b"LoadLibraryW")
    thread = k32.CreateRemoteThread(handle, None, 0, load_library,
                                    ctypes.c_void_p(remote_path), 0, None)
    if not thread:
        raise ipp.Blocked("CreateRemoteThread(LoadLibraryW) failed: %d"
                          % ctypes.get_last_error())
    if k32.WaitForSingleObject(thread, 20000) != 0:
        raise ipp.Blocked("LoadLibraryW remote thread did not finish; its outcome "
                          "is unknown, so nothing further is attempted")
    k32.CloseHandle(thread)

    base = ipp.find_remote_module_base(k32, pid, DLL_NAME)
    if not base:
        raise ipp.Blocked("%s is not loaded in the game after LoadLibraryW" % DLL_NAME)

    io_address = k32.VirtualAllocEx(handle, None, 4096, MEM_COMMIT_RESERVE,
                                    PAGE_READWRITE)
    write_remote(k32, handle, io_address, struct.pack(IO_FMT, MAGIC, PROTO, 0, 0, 0, 0))

    rva = ipp.find_export_rva(dll, "InputProbeInit")
    thread = k32.CreateRemoteThread(handle, None, 0, base + rva,
                                    ctypes.c_void_p(io_address), 0, None)
    if not thread:
        raise ipp.Blocked("CreateRemoteThread(InputProbeInit) failed")
    waited = k32.WaitForSingleObject(thread, 20000)
    code = wt.DWORD(0)
    k32.GetExitCodeThread(thread, ctypes.byref(code))
    k32.CloseHandle(thread)
    if waited != 0:
        raise ipp.Blocked("InputProbeInit did not return in time")

    io = struct.unpack(IO_FMT, read_remote(k32, handle, io_address, IO_SIZE))
    state_address = io[3]
    document = {
        "ok": code.value == 0,
        "pid": pid, "build_key": key, "dll": dll, "module_base": base,
        "io_address": io_address, "state_address": state_address,
        "init_status": code.value,
        "init_status_name": STATUS_NAMES.get(code.value, "?"),
    }
    if code.value == 0:
        state, _ = read_state(k32, handle, state_address)
        document["state"] = state
    save_session(document)
    print(json.dumps(document, indent=2))
    return 0 if code.value == 0 else 4


def _session_handles():
    session = load_session()
    k32, handle = open_game(session["pid"])
    return session, k32, handle


def do_capture(args):
    session, k32, handle = _session_handles()
    value = 1 if args.on else 0
    write_remote(k32, handle, session["state_address"] + OFF_CAPTURE,
                 struct.pack("<I", value))
    state, _ = read_state(k32, handle, session["state_address"])
    print(json.dumps({"capture_request": state["capture_request"]}, indent=2))
    return 0


def request_reset(k32, handle, session, hwnd=None):
    """Ask for a reset and WAIT for the probe to acknowledge it.

    The reset runs inside the window procedure, so it only happens when a
    message arrives. Assuming it had happened after a sleep is how the second
    scripted run ended up reading the first run's tail as if it were new: a
    WM_NULL is posted to guarantee the procedure runs, and the request flag
    clearing is the acknowledgement.
    """
    write_remote(k32, handle, session["state_address"] + OFF_RESET,
                 struct.pack("<I", 1))
    if hwnd is None:
        state, _ = read_state(k32, handle, session["state_address"])
        hwnd = state["hwnd"]
    deadline = time.time() + 3.0
    while time.time() < deadline:
        user32.PostMessageW(wt.HWND(hwnd), 0x0000, 0, 0)   # WM_NULL
        time.sleep(0.05)
        state, _ = read_state(k32, handle, session["state_address"])
        if state["reset_request"] == 0 and state["ring_write"] == 0:
            return state
    raise ipp.Blocked("the probe did not acknowledge the ring reset; without a "
                      "clean ring the next run would read the previous one")


def do_reset(args):
    session, k32, handle = _session_handles()
    state = request_reset(k32, handle, session)
    print(json.dumps({"reset_acknowledged": True,
                      "ring_write": state["ring_write"]}, indent=2))
    return 0


def do_poll(args):
    session, k32, handle = _session_handles()
    state, events = read_state(k32, handle, session["state_address"])
    document = {"label": args.label, "state": state, "events": events,
                "observed_at": datetime.datetime.now(datetime.timezone.utc)
                                       .strftime("%Y-%m-%dT%H:%M:%SZ")}
    text = json.dumps(document, indent=2)
    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "poll-%s.json" % args.label), "w",
                  encoding="utf-8") as out:
            out.write(text + "\n")
    print(text)
    return 0


def do_detach(args):
    session, k32, handle = _session_handles()
    rva = ipp.find_export_rva(session["dll"], "InputProbeShutdown")
    write_remote(k32, handle, session["io_address"],
                 struct.pack(IO_FMT, MAGIC, PROTO, 0, 0, 0, 0))
    thread = k32.CreateRemoteThread(handle, None, 0,
                                    session["module_base"] + rva,
                                    ctypes.c_void_p(session["io_address"]), 0, None)
    waited = k32.WaitForSingleObject(thread, 30000)
    code = wt.DWORD(0)
    k32.GetExitCodeThread(thread, ctypes.byref(code))
    k32.CloseHandle(thread)
    if waited != 0:
        raise ipp.Blocked("InputProbeShutdown did not return; the module STAYS "
                          "LOADED and this run is BLOCKED")
    io = struct.unpack(IO_FMT, read_remote(k32, handle, session["io_address"], IO_SIZE))
    state, _ = read_state(k32, handle, session["state_address"])
    document = {
        "shutdown_status": code.value,
        "shutdown_status_name": STATUS_NAMES.get(code.value, "?"),
        "quiescent_ms": io[4], "quiescent_ok": bool(io[5]),
        "attached": state["attached"], "detached": state["detached"],
        "module_left_loaded": True,
        "note": ("the module is deliberately not FreeLibrary'd: the standing rule "
                 "is that an unproven unload is a BLOCKED report, not an attempt"),
    }
    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "detach.json"), "w",
                  encoding="utf-8") as out:
            out.write(json.dumps(document, indent=2) + "\n")
    print(json.dumps(document, indent=2))
    return 0 if code.value == 0 else 5


# ------------------------------------------------------------ scripted keys

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("padding", ctypes.c_ubyte * 32)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", INPUT_UNION)]


MODIFIERS = (0x10, 0x11, 0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x5B, 0x5C)


def release_modifiers():
    """Put every modifier down before the scripted set starts.

    The first run of this was polluted by an Alt that arrived from outside the
    script; with Alt held, every arrow became WM_SYSKEYDOWN and the Tab press
    became Alt+Tab, which took the foreground away and silently dropped the last
    three presses. Clearing first is cheap; discovering it afterwards was not.
    """
    items = []
    for vk in MODIFIERS:
        item = INPUT()
        item.type = INPUT_KEYBOARD
        item.u.ki = KEYBDINPUT(vk, 0, KEYEVENTF_KEYUP, 0, None)
        items.append(item)
    array = (INPUT * len(items))(*items)
    user32.SendInput(len(items), array, ctypes.sizeof(INPUT))
    time.sleep(0.15)


def send_key(vk, shift=False, hold_ms=40):
    events = []

    def make(code, up):
        item = INPUT()
        item.type = INPUT_KEYBOARD
        item.u.ki = KEYBDINPUT(code, 0, KEYEVENTF_KEYUP if up else 0, 0, None)
        return item

    if shift:
        events.append(make(0x10, False))
    events.append(make(vk, False))
    array = (INPUT * len(events))(*events)
    user32.SendInput(len(events), array, ctypes.sizeof(INPUT))
    time.sleep(hold_ms / 1000.0)
    ups = [make(vk, True)]
    if shift:
        ups.append(make(0x10, True))
    array = (INPUT * len(ups))(*ups)
    user32.SendInput(len(ups), array, ctypes.sizeof(INPUT))
    time.sleep(hold_ms / 1000.0)


MAPVK_VK_TO_VSC = 0
EXTENDED_VKS = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E,
                0x5B, 0x5C, 0x5D, 0x6F, 0x90, 0xA3, 0xA5}


def post_key(hwnd, vk, hold_ms=60, character=None):
    """Deliver a key straight to the window queue, without taking the foreground.

    WHY THIS EXISTS AND WHAT IT COSTS. SendInput needs the game in front, and
    taking the foreground away from whoever is using the machine is not something
    a measurement should do casually. PostMessage puts a genuine WM_KEYDOWN in
    the window's queue, so DispatchMessage delivers it to the window procedure --
    which is exactly the path under test.

    What it is NOT: a keystroke. The OS key state is not updated, so anything
    reading GetAsyncKeyState sees the key as up, and TranslateMessage never runs,
    so WM_CHAR must be posted deliberately rather than arriving on its own. Both
    differences are stated wherever a result from this path is reported.
    """
    scan = user32.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC) & 0xFF
    extended = 1 if vk in EXTENDED_VKS else 0
    down = 0x00000001 | (scan << 16) | (extended << 24)
    up = down | (1 << 30) | (1 << 31)
    handle = wt.HWND(hwnd)
    user32.PostMessageW(handle, 0x0100, vk, down)              # WM_KEYDOWN
    if character is not None:
        user32.PostMessageW(handle, 0x0102, ord(character), down)   # WM_CHAR
    time.sleep(hold_ms / 1000.0)
    user32.PostMessageW(handle, 0x0101, vk, up)                # WM_KEYUP
    time.sleep(0.05)


# The C3 set, exactly as pre-registered. `label` is what the evidence calls it.
SCRIPTED = [
    ("a", 0x41, False), ("Shift+a", 0x41, True),
    ("1", 0x31, False), ("Shift+1", 0x31, True),
    ("VK_OEM_3", 0xC0, False),
    ("Backspace", 0x08, False), ("Enter", 0x0D, False),
    ("Left", 0x25, False), ("Right", 0x27, False),
    ("Up", 0x26, False), ("Down", 0x28, False),
    ("Tab", 0x09, False),
    ("PageUp", 0x21, False), ("PageDown", 0x22, False),
]


SW_RESTORE = 9


def bring_to_foreground(hwnd, attempts=6):
    """Put the game in front, and say whether it worked.

    SetForegroundWindow alone is refused by Windows depending on which process
    currently owns the foreground -- and a refusal is silent, which is how a
    scripted press ends up in another window and the run reports nothing rather
    than reporting a problem. So: restore, ask, and if that is not enough,
    attach this thread's input queue to the window's, which is the documented
    way for one thread to hand the foreground to another. Every attempt is
    checked; the caller gets a boolean, not a hope.
    """
    hwnd_handle = wt.HWND(hwnd)
    window_thread = user32.GetWindowThreadProcessId(hwnd_handle, None)
    this_thread = kernel32_tid()
    for attempt in range(attempts):
        if user32.IsIconic(hwnd_handle):
            user32.ShowWindow(hwnd_handle, SW_RESTORE)
        user32.SetForegroundWindow(hwnd_handle)
        if int(user32.GetForegroundWindow() or 0) == hwnd:
            time.sleep(0.4)
            return True
        if attempt >= 1:
            attached = user32.AttachThreadInput(this_thread, window_thread, True)
            try:
                user32.BringWindowToTop(hwnd_handle)
                user32.SetForegroundWindow(hwnd_handle)
                user32.SetActiveWindow(hwnd_handle)
            finally:
                if attached:
                    user32.AttachThreadInput(this_thread, window_thread, False)
            if int(user32.GetForegroundWindow() or 0) == hwnd:
                time.sleep(0.4)
                return True
        time.sleep(0.4)
    return int(user32.GetForegroundWindow() or 0) == hwnd


def kernel32_tid():
    return ctypes.WinDLL("kernel32", use_last_error=True).GetCurrentThreadId()


def focus_game(session):
    hwnd = session.get("state", {}).get("hwnd")
    if not hwnd:
        _, k32, handle = _session_handles()
        state, _ = read_state(k32, handle, session["state_address"])
        hwnd = state["hwnd"]
    return bring_to_foreground(hwnd), hwnd


def do_keys(args):
    session, k32, handle = _session_handles()
    focused, hwnd = focus_game(session)
    if not focused:
        raise ipp.Blocked("could not bring the game window to the foreground; a "
                          "scripted press would have gone somewhere else")
    request_reset(k32, handle, session, hwnd)
    release_modifiers()
    request_reset(k32, handle, session, hwnd)

    marks = []
    foreign_total = 0
    for label, vk, shift in SCRIPTED:
        if int(user32.GetForegroundWindow() or 0) != hwnd:
            raise ipp.Blocked(
                "the game lost the foreground before the %r press; every press "
                "after that would have gone to another window, so this run is "
                "not evidence and is not being salvaged" % label)
        state, _ = read_state(k32, handle, session["state_address"])
        before = state["ring_write"]
        send_key(vk, shift)
        time.sleep(0.25)
        state, events = read_state(k32, handle, session["state_address"])
        produced = [e for e in events if e["seq"] > before]
        # A press is only evidence if everything that arrived belongs to it: the
        # key itself, the Shift the script held, or a character the key produced.
        expected_vks = {vk} | ({0x10} if shift else set())
        foreign = [e for e in produced
                   if not (e["message_id"] in (0x0102, 0x0106, 0x0103, 0x0107)
                           or e["vkey"] in expected_vks)]
        foreign_total += len(foreign)
        marks.append({"label": label, "vk": vk, "shift": shift,
                      "produced": produced, "foreign": foreign,
                      "clean": not foreign})

    state, events = read_state(k32, handle, session["state_address"])
    document = {
        "label": args.label, "hwnd": hwnd, "capture_request": state["capture_request"],
        "observed_at": datetime.datetime.now(datetime.timezone.utc)
                               .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "presses": marks, "state": state,
        "foreign_events": foreign_total,
        "clean_run": foreign_total == 0,
        "clean_run_note": ("a run with foreign events is not evidence about the "
                           "scripted key; the first attempt had an Alt arrive "
                           "from outside and every arrow became WM_SYSKEYDOWN"),
        "synthetic": True,
        "synthetic_note": ("SendInput. Indistinguishable from a physical press at "
                           "the window procedure; a path that filters injected "
                           "input would not be, which the manual pass covers."),
    }
    text = json.dumps(document, indent=2)
    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "keys-%s.json" % args.label), "w",
                  encoding="utf-8") as out:
            out.write(text + "\n")
    print(text)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("attach").set_defaults(func=do_attach)

    capture = sub.add_parser("capture")
    group = capture.add_mutually_exclusive_group(required=True)
    group.add_argument("--on", action="store_true")
    group.add_argument("--off", action="store_true")
    capture.set_defaults(func=do_capture)

    sub.add_parser("reset").set_defaults(func=do_reset)

    poll = sub.add_parser("poll")
    poll.add_argument("--label", default="poll")
    poll.set_defaults(func=do_poll)

    keys = sub.add_parser("keys")
    keys.add_argument("--label", default="keys")
    keys.set_defaults(func=do_keys)

    sub.add_parser("detach").set_defaults(func=do_detach)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ipp.Blocked as blocked:
        print(json.dumps({"ok": False, "blocked": str(blocked)}, indent=2))
        return 3


if __name__ == "__main__":
    sys.exit(main())
