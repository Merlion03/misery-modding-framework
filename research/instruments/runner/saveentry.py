#!/usr/bin/env python3
"""Getting from "the game is running" to "the configured save is loaded".

THE LADDER, IN THE ORDER IT MUST BE TRIED
-----------------------------------------
1. **A supported game or Steam mechanism.** Cheapest, most durable, no input
   synthesis, nothing to recalibrate when a menu moves. Two candidates exist and
   both are *investigated by this module rather than assumed*:
   (a) command-line arguments passed through ``steam://run/<appid>//<args>``;
   (b) an engine console command -- MISERY's Shipping build does have a working
       UE console (``%LOCALAPPDATA%\\MISERY\\Saved\\Config\\Windows\\Input.ini``
       carries a populated ``[/Script/Engine.Console] HistoryBuffer``), and a
       Blueprint or native function carrying ``FUNC_Exec`` is, by definition, a
       command the game itself supports. ``find_exec_commands`` enumerates them
       from the live object graph, so the answer is measured, not guessed.
2. **Deterministic keyboard navigation.** Implemented here, and driven by a
   configured sequence rather than a hardcoded one -- a menu that moves must
   cost a config edit, not a code change.
3. **Screenshot / template-matched input.** NOT implemented. It is the last
   rung for a reason: it introduces an image-matching dependency and a whole
   class of "it matched something else" failures, and nothing so far has needed
   it. If it is ever needed, it belongs behind this same ``Strategy`` interface.

WHAT NONE OF THESE ARE
----------------------
Evidence. Every strategy here is a way to *cause* a state change; whether the
state changed is decided by ``readiness.prove_gameplay`` reading the live
object graph. A strategy that reports success while the runtime says otherwise
is a failed strategy, and the runner fails closed on the runtime's answer.

Equally, no strategy here writes memory or calls a UFunction. Loading a save by
invoking the game's own save-loading function through ProcessEvent would work,
and it is deliberately not done: it would be a new gameplay ABI primitive
introduced to automate a menu, which is precisely the trade this task refuses.

WHAT KEYBOARD NAVIGATION REQUIRES OF THE MACHINE
------------------------------------------------
``SendInput`` delivers to the foreground window on the current interactive
desktop. That has three consequences, all documented in README.md and all
enforced here rather than left to be discovered:
  * the Windows session must be unlocked -- a locked session has no interactive
    desktop to receive input, and the runner says so instead of timing out;
  * the game must actually be foreground -- ``focus_window`` verifies it and
    fails closed if Windows refuses the foreground change;
  * nothing else may steal focus during the sequence -- each step re-verifies.
"""
import ctypes
import ctypes.wintypes as wt
import time

import lifecycle

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_SCANCODE = 0x0008
KEYEVENTF_EXTENDEDKEY = 0x0001
SW_RESTORE = 9

# Scan codes (set 1). Scan codes rather than virtual keys because UE reads raw
# input for gameplay and a virtual-key-only injection is ignored by a
# surprising share of games.
SCANCODES = {
    "escape": 0x01, "enter": 0x1C, "space": 0x39, "tab": 0x0F, "backspace": 0x0E,
    "up": 0x48, "down": 0x50, "left": 0x4B, "right": 0x4D,
    "w": 0x11, "a": 0x1E, "s": 0x1F, "d": 0x20, "e": 0x12, "f": 0x21,
    "tilde": 0x29, "f1": 0x3B, "f5": 0x3F, "f10": 0x44,
    "1": 0x02, "2": 0x03, "3": 0x04, "4": 0x05, "5": 0x06,
}
EXTENDED_KEYS = frozenset({"up", "down", "left", "right"})


class SaveEntryError(Exception):
    pass


class _KeyboardInput(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class _InputUnion(ctypes.Union):
    _fields_ = [("ki", _KeyboardInput), ("padding", ctypes.c_byte * 32)]


class _Input(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", _InputUnion)]


def session_is_interactive():
    """Is there an interactive desktop we can send input to?

    ``OpenInputDesktop`` succeeding is the direct test: on a locked
    workstation, or from a service session, it fails. This is checked before a
    sequence starts so the failure reads "the session is locked" rather than
    "the menu did not respond".
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.OpenInputDesktop.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    user32.OpenInputDesktop.restype = wt.HANDLE
    user32.CloseDesktop.argtypes = [wt.HANDLE]
    user32.CloseDesktop.restype = wt.BOOL
    desktop = user32.OpenInputDesktop(0, False, 0x0100)   # DESKTOP_READOBJECTS
    if not desktop:
        return False
    user32.CloseDesktop(desktop)
    return True


def foreground_window():
    """The current foreground hwnd as an int. NEVER None.

    ``GetForegroundWindow`` legitimately returns NULL -- no window has focus,
    or focus is mid-transfer -- and ctypes turns a NULL HWND into ``None``, not
    ``0``. An earlier draft compared that straight to an int and crashed with a
    TypeError against the live game instead of simply retrying. Measured, not
    hypothesised: it happened on the first live run.
    """
    return int(lifecycle._u32().GetForegroundWindow() or 0)


def focus_window(hwnd, *, attempts=8, interval_s=0.4, note=None):
    """Bring *hwnd* to the foreground and PROVE it got there.

    Windows refuses ``SetForegroundWindow`` from a process that does not already
    own the foreground window, and it refuses SILENTLY. Two consequences, both
    handled here rather than hoped away:

      * the result is verified by reading the foreground window back, so a
        refusal raises instead of letting keys go to whatever else had focus --
        which, for a runner driving a live game, is the difference between
        pressing Space at a menu and pressing it into someone's editor;

      * the documented way for a background process to be *allowed* the change
        is to attach its input queue to the current foreground thread's
        (``AttachThreadInput``), which puts the two threads in the same input
        state and lifts the restriction. That is a documented Win32 mechanism,
        not a trick, and the attachment is always undone in a ``finally``.

    The cheap case is checked first: if the game is already foreground, nothing
    is touched at all.
    """
    say = note.append if note is not None else (lambda _m: None)
    user32 = lifecycle._u32()
    kernel32 = lifecycle._k32()
    our_tid = kernel32.GetCurrentThreadId()
    for attempt in range(attempts):
        current = foreground_window()
        if current == int(hwnd):
            if attempt:
                say("game window 0x%x is foreground (after %d attempt(s))" % (hwnd, attempt))
            return True
        foreign_tid = 0
        if current:
            owner_pid = wt.DWORD(0)
            foreign_tid = user32.GetWindowThreadProcessId(current, ctypes.byref(owner_pid))
        attached = False
        try:
            if foreign_tid and foreign_tid != our_tid:
                attached = bool(user32.AttachThreadInput(our_tid, foreign_tid, True))
            user32.ShowWindow(hwnd, SW_RESTORE)
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
        finally:
            if attached:
                user32.AttachThreadInput(our_tid, foreign_tid, False)
        time.sleep(interval_s)
    raise SaveEntryError(
        "could not bring the game window (0x%x) to the foreground after %d attempts; "
        "the foreground window is 0x%x. Synthesized input would go there instead, so "
        "nothing was sent. Is the session locked, or is another application holding "
        "focus?" % (hwnd, attempts, foreground_window()))


def send_key(name, *, hold_s=0.05):
    """One key press+release by scan code, to whatever is foreground."""
    key = name.lower()
    if key not in SCANCODES:
        raise SaveEntryError("unknown key %r (known: %s)" % (name, ", ".join(sorted(SCANCODES))))
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(_Input), ctypes.c_int]
    user32.SendInput.restype = wt.UINT
    scan = SCANCODES[key]
    flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if key in EXTENDED_KEYS else 0)
    for extra in (0, KEYEVENTF_KEYUP):
        item = _Input(type=INPUT_KEYBOARD)
        item.u.ki = _KeyboardInput(wVk=0, wScan=scan, dwFlags=flags | extra,
                                   time=0, dwExtraInfo=None)
        sent = user32.SendInput(1, ctypes.byref(item), ctypes.sizeof(_Input))
        if sent != 1:
            raise SaveEntryError("SendInput rejected %s (err %d)"
                                 % (name, ctypes.get_last_error()))
        time.sleep(hold_s)


# --------------------------------------------------------------------------
# rung 3 -- pointer input, in NORMALISED window coordinates
# --------------------------------------------------------------------------
#
# Reached only because rungs 1 and 2 were tried and MEASURED to fail on this
# build: there is no game-provided load/continue console command (all 88 live
# FUNC_Exec functions are stock engine ones plus one unrelated Blueprint
# command), and the main menu does not respond to Down or Tab at all -- it is a
# pointer-driven UMG menu whose highlight follows the cursor. See README.md.
#
# Two things keep this from being the brittle pixel-poking the ladder warns
# about:
#
#   * coordinates are NORMALISED to the window's client area (0..1), so they
#     survive a resolution change; a raw pixel pair would not;
#   * a click is never assumed to have worked. Every pointer action in the
#     state table is followed by the same observable transition check as a key
#     action, and the machine then RECLASSIFIES from the live object graph. A
#     click that lands on the wrong control produces either a known state (and
#     the machine continues correctly from there) or an unknown one (and the
#     machine stops with the signature).

MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


class _MouseInput(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class _MouseInputUnion(ctypes.Union):
    _fields_ = [("mi", _MouseInput), ("padding", ctypes.c_byte * 32)]


class _MouseInputEvent(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", _MouseInputUnion)]


INPUT_MOUSE = 0


def client_rect_on_screen(hwnd):
    """The window's client area in SCREEN coordinates: (left, top, width, height).

    The client area, not the window rect: normalised coordinates must be
    relative to what the game renders into, or a border or title bar would
    shift every point.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetClientRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
    user32.GetClientRect.restype = wt.BOOL
    user32.ClientToScreen.argtypes = [wt.HWND, ctypes.POINTER(wt.POINT)]
    user32.ClientToScreen.restype = wt.BOOL
    rect = wt.RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(rect)):
        raise SaveEntryError("GetClientRect failed for 0x%x" % hwnd)
    origin = wt.POINT(0, 0)
    if not user32.ClientToScreen(hwnd, ctypes.byref(origin)):
        raise SaveEntryError("ClientToScreen failed for 0x%x" % hwnd)
    return origin.x, origin.y, rect.right - rect.left, rect.bottom - rect.top


def normalised_to_screen(hwnd, point):
    nx, ny = float(point[0]), float(point[1])
    if not (0.0 <= nx <= 1.0 and 0.0 <= ny <= 1.0):
        raise SaveEntryError("pointer coordinates must be normalised to 0..1, got %r" % (point,))
    left, top, width, height = client_rect_on_screen(hwnd)
    return int(left + nx * width), int(top + ny * height)


def move_pointer(hwnd, point):
    """Move the cursor to a normalised point in the window. Returns screen coords."""
    x, y = normalised_to_screen(hwnd, point)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    user32.SetCursorPos.restype = wt.BOOL
    if not user32.SetCursorPos(x, y):
        raise SaveEntryError("SetCursorPos(%d, %d) failed (err %d)"
                             % (x, y, ctypes.get_last_error()))
    return x, y


def click_pointer(hwnd, point, *, hover_s=0.35, hold_s=0.06):
    """Hover, settle, then click. Returns the screen coordinates used.

    The hover pause is not superstition: this menu highlights on hover, and the
    widget under the cursor must have taken the hover before the press, or the
    press lands on a control that has not yet accepted focus.
    """
    x, y = move_pointer(hwnd, point)
    time.sleep(hover_s)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(_MouseInputEvent), ctypes.c_int]
    user32.SendInput.restype = wt.UINT
    for flag in (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP):
        event = _MouseInputEvent(type=INPUT_MOUSE)
        event.u.mi = _MouseInput(dx=0, dy=0, mouseData=0, dwFlags=flag, time=0,
                                 dwExtraInfo=None)
        if user32.SendInput(1, ctypes.byref(event), ctypes.sizeof(_MouseInputEvent)) != 1:
            raise SaveEntryError("SendInput rejected a mouse event (err %d)"
                                 % ctypes.get_last_error())
        time.sleep(hold_s)
    return x, y


# --------------------------------------------------------------------------
# rung 1 -- supported mechanisms, investigated rather than assumed
# --------------------------------------------------------------------------

FUNC_EXEC = 0x00000200
UFUNCTION_FLAGS_OFFSET = 0xB0      # same offset the CR-01C controllers gate on


def find_exec_commands(eri, recon, api, handle, namepool, objects, *, limit=None):
    """Every live UFunction carrying FUNC_Exec -- i.e. every console command
    this build actually supports right now.

    This is rung 1(b) of the ladder, and it is the reason the ladder starts
    where it does: if the game itself exposes a command that loads the
    configured save, using it is a supported mechanism with no input synthesis,
    no menu calibration and no dependence on what is on screen.

    Read-only: reads UFunction::FunctionFlags at the offset the CR-01C
    controllers already gate on, for functions reached through the same class
    walk they use.
    """
    meta = recon.find_function_meta(objects)
    if meta is None:
        raise SaveEntryError("Function meta-class not found; the graph is not walkable")
    classes = [a for a, r in objects.items()
               if r.get("valid")
               and (objects.get(r.get("class_ptr") or 0) or {}).get("name_text")
               in ("Class", "BlueprintGeneratedClass")]
    found = []
    for class_address in classes:
        try:
            functions = recon.class_functions(api, handle, namepool, class_address, meta)
        except Exception:                              # noqa: BLE001
            continue
        for function in functions:
            try:
                flags = eri._read_u32(api, handle, function["address"] + UFUNCTION_FLAGS_OFFSET)
            except Exception:                          # noqa: BLE001
                continue
            if flags & FUNC_EXEC:
                found.append({
                    "command": function.get("raw_name"),
                    "class": (objects.get(class_address) or {}).get("name_text"),
                    "flags": "0x%x" % flags,
                    "address": "0x%x" % function["address"]})
                if limit and len(found) >= limit:
                    return found
    return found


# --------------------------------------------------------------------------
# strategies
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# UI state classification -- from the live object graph, never from pixels
# --------------------------------------------------------------------------
#
# A screen is identified by which Blueprint classes have LIVE, non-CDO instances
# at that moment. That is a far better discriminator than an image: it is exact,
# it costs no template matching, it cannot be fooled by resolution or language,
# and it is the same read the readiness gate already performs.
#
# The signatures below were MEASURED against this build, not guessed. The
# thank-you screen's own reading is recorded in the table.
#
# The rule this table encodes: a key is sent ONLY from a positively classified
# state. An unrecognised screen is captured and reported, never guessed at --
# blind input into an unknown screen is how automation deletes a save.

SIGNATURE_CLASS_SUFFIX = "_C"


def screen_signature(objects):
    """The set of Blueprint classes with live, non-CDO instances right now.

    Widgets, pawns, game modes and HUD objects all appear here, and it is their
    COMBINATION that names a screen. Engine-level classes are excluded: they are
    present in every state and discriminate nothing.
    """
    live = set()
    for address, record in objects.items():
        if not record.get("valid"):
            continue
        name = record.get("name_text") or ""
        if name.startswith("Default__"):
            continue
        class_record = objects.get(record.get("class_ptr") or 0) or {}
        class_name = class_record.get("name_text") or ""
        if class_name.endswith(SIGNATURE_CLASS_SUFFIX):
            live.add(class_name)
    return live


# Load-game row geometry, normalised to the client area. Measured on build
# bace50f7185d at 2560x1440: the four rows' centres sit at y = 424, 564, 702,
# 840 px and the row text starts around x = 1090 px -- deliberately far left of
# the red delete cross at x ~ 1740, which is the one control on this screen that
# must never be hit. Normalising rather than storing pixels is what keeps this
# correct at another resolution.
SAVE_ROW_GEOMETRY = {"x": 0.4258, "first_row_y": 0.2944, "row_pitch": 0.0965,
                     "max_visible_rows": 6}

# The main menu's backdrop level is CHOSEN AT RANDOM per launch: two consecutive
# launches on this build gave L_MenuMap07 and L_MenuMap03. Pinning the exact name
# is therefore wrong, and it was wrong in the first draft -- the classifier fell
# through to the fallback state at a perfectly ordinary main menu. What is stable
# is the prefix, so that is what is matched.
MENU_WORLD_PREFIX = "L_MenuMap"

UI_STATES = [
    {
        "name": "THANK_YOU_SCREEN",
        # Measured 2026-08-29 against build bace50f7185d, pid 8524, 26 263 live
        # objects: WD_PlaytestNote01_C is the note widget itself, and the pawn
        # and game mode behind it are the "playtest hub" RESEARCH_LOG LOG-0060
        # finding 5 recorded -- that finding was describing THIS screen.
        "require": ["WD_PlaytestNote01_C"],
        "action": {
            "do": [{"key": "space"}],
            "why": "the screen itself prompts 'НАЖМИТЕ [SPACE] ПРОДОЛЖИТЬ'; the game "
                   "exposes exactly one deterministic keyboard action here, so no "
                   "pointer input is used",
        },
    },
    {
        # MUST be matched before MAIN_MENU: the load list is drawn over the main
        # menu, so BP_MainMenu_C is live in both. BP_SGKSaveGameMetaData_C is the
        # discriminator, and it is a real one -- the object is constructed when
        # the list is populated (measured: 0 -> 1, with BP_LoadGameMenuPanel_C
        # 4 -> 8, one panel per listed save).
        "name": "LOAD_GAME_MENU",
        "require": ["BP_SGKSaveGameMetaData_C"],
        "world_prefix_include": MENU_WORLD_PREFIX,
        "action": {
            "do": [{"click_save_row": True}],
            "why": "click the configured save's row, at the index computed from "
                   "SaveGameMetaData.sav rather than hardcoded",
        },
    },
    {
        "name": "MAIN_MENU",
        # The menu map's widgets are ALL pre-instantiated, so class presence
        # cannot separate the main menu from its singleplayer sub-panel. That is
        # a real limit and it is handled rather than papered over: this one state
        # carries the whole click path through the menu, and the step is verified
        # by the sub-state it produces (LOAD_GAME_MENU), which IS runtime-visible.
        "require": ["BP_MainMenu_C", "BP_SGKMenuGameMode_C"],
        "forbid": ["WD_PlaytestNote01_C", "BP_SGKSaveGameMetaData_C"],
        "world_prefix_include": MENU_WORLD_PREFIX,
        "action": {
            "do": [{"click": [0.5039, 0.7708]},     # ОДИНОЧНАЯ ИГРА
                   {"click": [0.1445, 0.4861]}],    # ЗАГРУЗИТЬ ИГРУ
            "why": "ОДИНОЧНАЯ ИГРА then ЗАГРУЗИТЬ ИГРУ. Two clicks in one action "
                   "because the runtime cannot see the panel change between them; "
                   "the pair is verified by BP_SGKSaveGameMetaData_C appearing. "
                   "Both points are far from НОВАЯ ИГРА and from any delete control.",
        },
    },
    {
        # LAST, deliberately: this is the fallback for "not on the note screen
        # and not in the menu map", i.e. a world transition is in flight or the
        # game world is up but the player is not ready yet.
        #
        # WHY A PERMISSIVE FALLBACK IS SAFE HERE, when an unrecognised screen is
        # otherwise a hard stop: this state SENDS NOTHING. The rule that makes
        # the machine safe is "never act on a screen you have not positively
        # identified", and a wait state does not act. Being generous about when
        # to WAIT costs at most a timeout with a clear message; being generous
        # about when to CLICK is what could start a new game over a save.
        #
        # It also has to exist. Two separate measured transitions land here:
        # the note screen dissolving into the menu map, and the save click
        # starting a level load -- during which BP_SGKSaveGameMetaData_C stays
        # live, so without this the machine reclassified as LOAD_GAME_MENU
        # mid-load and clicked the save row a second time.
        "name": "WORLD_LOADING",
        "world_prefix_exclude": MENU_WORLD_PREFIX,
        "forbid": ["WD_PlaytestNote01_C"],
        "action": None,
        "why": "a world transition is in flight; the only correct action is none",
    },
]


def live_world_names(objects):
    """Names of every live, non-CDO UWorld. The menu map and the game map are
    different worlds, which makes this the sturdiest screen discriminator
    available -- far sturdier than class presence, because the menu map
    pre-instantiates every menu widget it owns."""
    names = set()
    for address, record in objects.items():
        if not record.get("valid"):
            continue
        name = record.get("name_text") or ""
        if name.startswith("Default__"):
            continue
        class_record = objects.get(record.get("class_ptr") or 0) or {}
        if class_record.get("name_text") == "World":
            names.add(name)
    return names


def classify_state(objects, states=None):
    """Name the current screen, or return None.

    A state matches when every class in ``require`` is live, no class in
    ``forbid`` is, every name in ``worlds_include`` is a live World, and no name
    in ``worlds_exclude`` is. Matching is by presence, not exact set equality:
    the graph carries plenty of classes irrelevant to which screen is up, and
    demanding an exact set would make every signature brittle to the first
    unrelated actor that spawns.

    Order matters and is part of the table: the first match wins, so a state
    that overlaps another must be listed before it.
    """
    signature = screen_signature(objects)
    worlds = live_world_names(objects)
    for state in (states or UI_STATES):
        required = set(state.get("require") or ())
        forbidden = set(state.get("forbid") or ())
        worlds_in = set(state.get("worlds_include") or ())
        worlds_out = set(state.get("worlds_exclude") or ())
        prefix_in = state.get("world_prefix_include")
        prefix_out = state.get("world_prefix_exclude")
        if required and not required.issubset(signature):
            continue
        if forbidden & signature:
            continue
        if worlds_in and not worlds_in.issubset(worlds):
            continue
        if worlds_out & worlds:
            continue
        if prefix_in and not any(n.startswith(prefix_in) for n in worlds):
            continue
        if prefix_out and any(n.startswith(prefix_out) for n in worlds):
            continue
        return state
    return None


class UnknownScreen(SaveEntryError):
    """An unclassified screen. Carries the signature so the table can be extended.

    Deliberately its own exception type: "I do not know what is on screen" is a
    different outcome from "the sequence failed", and the runner reports it
    differently -- with the measured signature attached, which is exactly what a
    new entry in UI_STATES needs.
    """

    def __init__(self, signature, note=None):
        self.signature = sorted(signature)
        super().__init__(
            "unrecognised screen. No key was sent: sending input into an unclassified "
            "screen is refused by construction. Live signature (add an entry to "
            "saveentry.UI_STATES to teach the runner this screen): %s"
            % ", ".join(self.signature))


class Strategy:
    """A way to cause the configured save to be loaded. Not a way to know it was."""

    name = "abstract"

    def run(self, context):
        raise NotImplementedError


class AlreadyInSession(Strategy):
    """Do nothing; the caller believes the session is already loaded.

    Used by ``--save-entry none``, which is the right choice when re-probing a
    session the runner did not restart. It is a declaration, not a check: the
    check is still prove_gameplay.
    """
    name = "none"

    def run(self, context):
        return {"strategy": self.name, "acted": False,
                "note": "no entry action taken; the runtime gate decides"}


class ManualEntry(Strategy):
    """A person loads the save while the runner watches the runtime.

    This is not a cop-out rung and it is not rung 3 in disguise: it is what
    keeps the runner honest before a keyboard sequence has been calibrated on
    this build. Everything else in the cycle is automatic; the runner simply
    waits on the SAME runtime invariant it would otherwise wait on, with no
    timer standing in for it.
    """
    name = "manual"

    def run(self, context):
        context["note"].append(
            "MANUAL SAVE ENTRY: load the configured save now. The runner is watching "
            "the live object graph and will continue by itself the moment the player "
            "runtime invariants hold; it will not continue on a timer.")
        return {"strategy": self.name, "acted": False,
                "note": "waiting for a human to reach the session"}


class KeyboardEntry(Strategy):
    """A configured, deterministic key sequence with a runtime check per step.

    A step is::

        {"keys": ["down", "enter"],       # sent in order
         "await": {"objects_at_least": 200000} | {"object_named": "BP_PlayerInventory"}
                  | {"settle": true} | null,
         "timeout_s": 60,
         "why": "select Continue on the main menu"}

    The ``await`` clause is what makes the sequence deterministic rather than
    hopeful: after pressing the keys, the runner polls the live object graph for
    the declared condition and only then sends the next step. A step with
    ``await: null`` advances immediately -- legitimate for keys within one menu
    screen, and the config should say so in ``why``.

    There is no fallback "wait 5 seconds and assume". A step whose condition
    never holds fails the cycle and names the step.
    """
    name = "keyboard"

    def __init__(self, steps):
        self.steps = list(steps or [])

    def run(self, context):
        note = context["note"]
        if not self.steps:
            raise SaveEntryError(
                "the keyboard save-entry sequence is not configured for this build. "
                "Run `runner.py calibrate` to capture the menu state and the supported "
                "commands, then fill in save_entry.keyboard_steps in the runner config. "
                "No sequence is shipped by default on purpose: a guessed key sequence "
                "that lands somewhere unexpected is exactly the failure this runner is "
                "meant to make impossible.")
        if not session_is_interactive():
            raise SaveEntryError(
                "no interactive desktop: the Windows session is locked or this is a "
                "non-interactive session. Synthesized input cannot be delivered.")
        hwnd = context["hwnd"]
        focus_window(hwnd, note=note)

        performed = []
        for index, step in enumerate(self.steps):
            focus_window(hwnd, note=note)         # re-verified per step; focus can be stolen
            for key in step.get("keys", []):
                send_key(key)
                time.sleep(step.get("key_interval_s", 0.15))
            entry = {"index": index, "keys": step.get("keys", []),
                     "why": step.get("why"), "awaited": step.get("await")}
            condition = step.get("await")
            if condition:
                entry["satisfied"] = context["await_condition"](
                    condition, timeout_s=step.get("timeout_s", 60), label="step %d" % index)
            performed.append(entry)
            note.append("save-entry step %d %r -> %s"
                        % (index, step.get("keys"), step.get("why") or "(no rationale given)"))
        return {"strategy": self.name, "acted": True, "steps": performed}


class UiStateMachine(Strategy):
    """Classify the screen, act on it, observe the transition, repeat.

    This is rung 2 done properly. A fixed key sequence assumes the screens
    arrive in a known order and that each one accepted the last key; a state
    machine assumes nothing and checks everything:

        classify  ->  known state?  ->  focus  ->  send its ONE action
                                    ->  wait for the signature to CHANGE
                                    ->  classify again
                          |
                          +-- unknown -> capture the signature, stop, report

    The transition wait is observational: it polls the live class signature and
    continues the moment it differs. There is no "press and hope"; a screen that
    swallowed the key produces no signature change and the step times out with
    the state named.

    Loop safety is explicit. The same state is acted on at most
    ``max_visits_per_state`` times, and the whole machine is bounded by
    ``max_steps``. A menu that bounces back to a screen we already handled is a
    real possibility and must not become an infinite key-press loop at a live
    game.
    """
    name = "ui"

    def __init__(self, config):
        self.states = config.get("ui_states") or UI_STATES
        self.max_steps = int(config.get("max_steps", 12))
        self.max_visits_per_state = int(config.get("max_visits_per_state", 2))
        self.transition_timeout_s = float(config.get("transition_timeout_s", 45))

    def run(self, context):
        note = context["note"]
        if not session_is_interactive():
            raise SaveEntryError(
                "no interactive desktop: the Windows session is locked or this is a "
                "non-interactive session. Synthesized input cannot be delivered.")
        hwnd = context["hwnd"]
        if not hwnd:
            raise SaveEntryError("the game has no top-level window to send input to")

        visits = {}
        performed = []
        last_acted = None
        for step in range(self.max_steps):
            objects = context["snapshot"]()
            if context["is_gameplay"](objects):
                note.append("ui state machine: gameplay reached after %d step(s)" % step)
                return {"strategy": self.name, "acted": bool(performed), "steps": performed,
                        "final_state": "GAMEPLAY"}

            state = classify_state(objects, self.states)
            if state is None:
                raise UnknownScreen(screen_signature(objects))

            action = state.get("action")

            # A state with no action is a WAIT state, not a dead end -- e.g.
            # WORLD_LOADING, where the right thing to do is nothing. And a state
            # we just acted on is also a wait: the action was delivered, so
            # repeating it would be a second click at a live game. Both cases
            # watch the runtime instead of pressing anything.
            if action is None or state["name"] == last_acted:
                why = (state.get("why") if action is None
                       else "already acted on this state; waiting rather than repeating")
                note.append("ui state %s -> waiting (%s)" % (state["name"], why))
                reached, final = self._wait_for_change(context, state, note)
                performed.append({"step": step, "state": state["name"], "waited": True,
                                  "why": why, "resolved_to": final})
                if reached:
                    note.append("ui state machine: gameplay reached from %s" % state["name"])
                    return {"strategy": self.name, "acted": bool(performed),
                            "steps": performed, "final_state": "GAMEPLAY"}
                continue

            visits[state["name"]] = visits.get(state["name"], 0) + 1
            if visits[state["name"]] > self.max_visits_per_state:
                raise SaveEntryError(
                    "state %s reached %d times: the machine is looping rather than "
                    "advancing, so it stops instead of pressing keys at a live game"
                    % (state["name"], visits[state["name"]]))

            before = screen_signature(objects)
            focus_window(hwnd, note=note)
            note.append("ui state %s -> %s" % (state["name"], action.get("why") or "(no rationale)"))
            done = self._perform(action, hwnd, context, note)

            changed, after = self._await_transition(context, before)
            entry = {"step": step, "state": state["name"], "did": done,
                     "why": action.get("why"), "transitioned": changed,
                     "signature_gained": sorted(after - before),
                     "signature_lost": sorted(before - after)}
            performed.append(entry)
            if not changed:
                raise SaveEntryError(
                    "screen %s did not change within %.0fs after %r. The input was "
                    "delivered but nothing observable happened; refusing to repeat it."
                    % (state["name"], self.transition_timeout_s, done))
            last_acted = state["name"]
            note.append("ui state %s transitioned: +%r -%r"
                        % (state["name"], entry["signature_gained"], entry["signature_lost"]))

        raise SaveEntryError("the ui state machine used its %d-step budget without "
                             "reaching gameplay" % self.max_steps)

    def _wait_for_change(self, context, state, note):
        """Watch the runtime until gameplay is proven or the screen changes.

        Returns ``(gameplay_reached, final_state_name)``. This is the only place
        the machine spends time without acting, and it is spent watching the
        authoritative signal rather than a clock: a level load takes as long as
        it takes, and the way to know it finished is that the player runtime
        invariants hold, not that N seconds elapsed.
        """
        deadline = time.time() + self.transition_timeout_s
        while time.time() < deadline:
            time.sleep(2.0)
            objects = context["snapshot"]()
            if context["is_gameplay"](objects):
                return True, "GAMEPLAY"
            other = classify_state(objects, self.states)
            if other is not None and other["name"] != state["name"]:
                return False, other["name"]
            if other is None:
                raise UnknownScreen(screen_signature(objects))
        raise SaveEntryError(
            "state %s neither reached gameplay nor changed within %.0fs of waiting"
            % (state["name"], self.transition_timeout_s))

    def _perform(self, action, hwnd, context, note):
        """Execute one state's declared action. Returns what was actually done.

        Three step kinds, and no fourth: a key, a click at a normalised point,
        and the computed save row. ``click_save_row`` is the only one that
        depends on anything outside the table, and what it depends on is a file
        on disk -- see saves.py for why the row is computed rather than
        configured.
        """
        done = []
        for item in action.get("do", []):
            if "key" in item:
                send_key(item["key"])
                done.append({"key": item["key"]})
            elif "click" in item:
                done.append({"click": item["click"],
                             "screen": click_pointer(hwnd, item["click"])})
            elif item.get("click_save_row"):
                point, detail = self._save_row_point(context)
                done.append({"save_row": detail,
                             "click": point, "screen": click_pointer(hwnd, point)})
                note.append("clicking save %r at row %d (%s)"
                            % (detail["slot"], detail["row"], detail["time"]))
            else:
                raise SaveEntryError("unknown action step %r" % (item,))
            time.sleep(action.get("step_interval_s", 0.25))
        return done

    def _save_row_point(self, context):
        """Where the configured save's row is, computed fresh for this cycle."""
        import saves
        wanted = context["save_slot"]
        if not wanted:
            raise SaveEntryError(
                "no save slot configured: expect.save_slot must name the save to "
                "load. The runner will not pick a row for you -- 'the second one' "
                "stops being the right one the first time the game autosaves.")
        entry, all_slots = saves.row_of_slot(wanted, context.get("save_dir"))
        geometry = context.get("save_row_geometry") or SAVE_ROW_GEOMETRY
        if entry["row"] >= geometry["max_visible_rows"]:
            raise SaveEntryError(
                "save %r is at row %d, beyond the %d rows this screen shows without "
                "scrolling; the runner does not scroll and will not click a row it "
                "cannot see. Saves present: %s"
                % (wanted, entry["row"], geometry["max_visible_rows"],
                   ", ".join("%s(%s)" % (s["slot"], s["time"]) for s in all_slots)))
        y = geometry["first_row_y"] + entry["row"] * geometry["row_pitch"]
        return [geometry["x"], y], entry

    def _await_transition(self, context, before):
        """Wait for the live class signature to differ. Observational, not timed."""
        deadline = time.time() + self.transition_timeout_s
        after = before
        while time.time() < deadline:
            time.sleep(1.5)
            after = screen_signature(context["snapshot"]())
            if after != before:
                return True, after
        return False, after


STRATEGIES = {
    AlreadyInSession.name: lambda config: AlreadyInSession(),
    ManualEntry.name: lambda config: ManualEntry(),
    KeyboardEntry.name: lambda config: KeyboardEntry(config.get("keyboard_steps")),
    UiStateMachine.name: UiStateMachine,
}


def build(name, config):
    if name not in STRATEGIES:
        raise SaveEntryError("unknown save-entry strategy %r (known: %s)"
                             % (name, ", ".join(sorted(STRATEGIES))))
    return STRATEGIES[name](config or {})
