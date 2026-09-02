#!/usr/bin/env python3
"""C4: is the capture real? The same key, in the same state, twice.

The pre-registration is explicit that "nothing happened while capturing" is not
evidence on its own. So this runs BOTH directions in one session, in one state,
against one save:

    capture OFF -> census, press, census   (the key must DO something)
    capture ON  -> census, press, census   (the same key must do NOTHING)

and reports a pass only when the first direction moved and the second did not.
If the OFF direction produces no reaction, the run is inconclusive rather than a
pass -- a key the game ignores would otherwise "prove" capture works.

A discovery mode finds a key with a reaction in the first place, because which
key opens which panel is a fact about MISERY's bindings, not something to assume.

    ... c4_capture_differential.py discover --keys TAB I M --run-dir DIR
    ... c4_capture_differential.py differential --key TAB --run-dir DIR
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import effect_census                                               # noqa: E402
import input_probe_controller as probe                             # noqa: E402
import observable                                                  # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)

KEYS = {
    "TAB": 0x09, "I": 0x49, "M": 0x4D, "B": 0x42, "C": 0x43, "J": 0x4A,
    "ESCAPE": 0x1B, "F": 0x46, "P": 0x50, "N": 0x4E, "V": 0x56,
    "W": 0x57, "S": 0x53, "A": 0x41, "D": 0x44,
}

# How far the character may drift while standing still, in Unreal units. Not a
# guess: it is measured in the same run, as the movement between two reads with
# no key pressed at all, and the differential refuses to call anything smaller
# than that a reaction.
IDLE_FLOOR_UU = 5.0


def observe():
    """The game-side state a key press might move.

    Class census was tried first and found nothing, because MISERY's widgets are
    pre-instantiated -- see observable.py. What is left is state on objects that
    already exist: the PlayerController's packed input/cursor bitfield, and the
    pawn's world location.
    """
    reading = observable.read()
    flags = reading.get("controller_flags") or {}
    any_flag = next(iter(flags.values()), None)
    location = reading.get("pawn_location")
    return {
        "cursor_bits": (any_flag or {}).get("value"),
        "location": None if not location else (location["x"], location["y"],
                                               location["z"]),
        "raw": reading,
    }


def distance(a, b):
    if not a or not b:
        return None
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def compare(before, after, floor):
    moved = distance(before["location"], after["location"])
    bits_changed = (before["cursor_bits"] != after["cursor_bits"]
                    and before["cursor_bits"] is not None)
    return {
        "cursor_bits_before": before["cursor_bits"],
        "cursor_bits_after": after["cursor_bits"],
        "cursor_bits_changed": bits_changed,
        "moved_uu": moved,
        "moved_beyond_floor": bool(moved is not None and moved > floor),
        "floor_uu": floor,
        "reacted": bool(bits_changed or (moved is not None and moved > floor)),
    }

# How long to let the game react. A panel is constructed within a frame or two;
# this is generous, and it is the SAME wait on both sides of the differential,
# which is what matters -- an asymmetric wait would be the measurement.
REACT_S = 2.5


def set_capture(k32, handle, session, on):
    probe.write_remote(k32, handle, session["state_address"] + probe.OFF_CAPTURE,
                       struct_pack_u32(1 if on else 0))
    state, _ = probe.read_state(k32, handle, session["state_address"])
    if state["capture_request"] != (1 if on else 0):
        raise probe.ipp.Blocked("the probe did not take the capture request")
    return state


def struct_pack_u32(value):
    import struct
    return struct.pack("<I", value)


def focus(session, k32, handle, delivery):
    state, _ = probe.read_state(k32, handle, session["state_address"])
    hwnd = state["hwnd"]
    if delivery == "post":
        # PostMessage addresses the window directly; the foreground is not part
        # of the delivery, so it is recorded rather than demanded.
        return hwnd
    if not probe.bring_to_foreground(hwnd):
        raise probe.ipp.Blocked("the game does not have the foreground; a press "
                                "would have gone to another window")
    return hwnd


def press(vk, hold_ms=60, delivery="sendinput", hwnd=None):
    if delivery == "post":
        probe.post_key(hwnd, vk, hold_ms=hold_ms)
        return
    probe.release_modifiers()
    probe.send_key(vk, shift=False, hold_ms=hold_ms)


def measure_idle_floor():
    """How much the reading moves when NOTHING is pressed.

    Measured in the same run, at the same moment, rather than assumed. A
    character standing on uneven ground settles; without this the settle would
    read as a reaction and the differential would pass for the wrong reason.
    """
    first = observe()
    time.sleep(REACT_S)
    second = observe()
    drift = distance(first["location"], second["location"])
    return {
        "drift_uu": drift,
        "cursor_bits_stable": first["cursor_bits"] == second["cursor_bits"],
        "floor_uu": max(IDLE_FLOOR_UU, (drift or 0) * 2.0),
    }


def one_direction(session, k32, handle, vk, capture, run_dir, tag, floor,
                  hold_ms=60, delivery="sendinput"):
    """Observe, press, observe -- with capture in the given position."""
    hwnd = focus(session, k32, handle, delivery)
    set_capture(k32, handle, session, capture)
    probe.request_reset(k32, handle, session)

    before = observe()
    press(vk, hold_ms, delivery, hwnd)
    time.sleep(REACT_S)
    after = observe()

    state, events = probe.read_state(k32, handle, session["state_address"])
    verdict = compare(before, after, floor)
    record = {
        "tag": tag, "capture": capture, "vk": vk, "hold_ms": hold_ms,
        "delivery": delivery,
        "foreground_was_game": int(user32.GetForegroundWindow() or 0) == hwnd,
        "effect": verdict,
        "reacted": verdict["reacted"],
        "probe_events": events,
        "probe_seen": state["seen"], "probe_suppressed": state["suppressed"],
        "probe_forwarded": state["forwarded"],
    }
    if run_dir:
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "c4-%s.json" % tag), "w",
                  encoding="utf-8") as handle_out:
            json.dump(record, handle_out, indent=2, sort_keys=True)
    return record


def session_hwnd(k32, handle, session):
    state, _ = probe.read_state(k32, handle, session["state_address"])
    return state["hwnd"]


def do_discover(args):
    session = probe.load_session()
    k32, handle = probe.open_game(session["pid"])
    idle = measure_idle_floor()
    results = []
    for name in args.keys:
        vk = KEYS[name.upper()]
        record = one_direction(session, k32, handle, vk, False, args.run_dir,
                               "discover-%s" % name.upper(), idle["floor_uu"],
                               hold_ms=args.hold_ms, delivery=args.delivery)
        results.append({"key": name.upper(), "vk": vk,
                        "reacted": record["reacted"],
                        "effect": record["effect"],
                        "keyboard_events": len(record["probe_events"])})
        # Put the game back: the same key closes what it opened, for a toggle.
        if record["reacted"] and record["effect"]["cursor_bits_changed"]:
            press(vk, args.hold_ms, args.delivery, session_hwnd(k32, handle, session))
            time.sleep(REACT_S)
    print(json.dumps({"idle": idle, "results": results}, indent=2))
    return 0


def do_differential(args):
    session = probe.load_session()
    k32, handle = probe.open_game(session["pid"])
    vk = KEYS[args.key.upper()]
    idle = measure_idle_floor()

    off = one_direction(session, k32, handle, vk, False, args.run_dir,
                        "off-%s" % args.key.upper(), idle["floor_uu"],
                        hold_ms=args.hold_ms, delivery=args.delivery)
    # Close whatever opened, so the ON direction starts from the same screen.
    if off["reacted"] and off["effect"]["cursor_bits_changed"]:
        press(vk, args.hold_ms, args.delivery, session_hwnd(k32, handle, session))
        time.sleep(REACT_S)
    on = one_direction(session, k32, handle, vk, True, args.run_dir,
                       "on-%s" % args.key.upper(), idle["floor_uu"],
                       hold_ms=args.hold_ms, delivery=args.delivery)
    set_capture(k32, handle, session, False)

    verdict = ("PASS" if off["reacted"] and not on["reacted"]
               else "INCONCLUSIVE" if not off["reacted"]
               else "FAIL")
    document = {
        "claim": "C4",
        "key": args.key.upper(), "vk": vk, "delivery": args.delivery,
        "delivery_note": (None if args.delivery == "sendinput" else
                          "PostMessage: a real WM_KEYDOWN in the window queue, "
                          "but the OS key state is not updated and no WM_CHAR is "
                          "generated by TranslateMessage"),
        "capture_off_reacted": off["reacted"],
        "capture_on_reacted": on["reacted"],
        "verdict": verdict,
        "why": {
            "PASS": "the same key moved the game with capture off and did not "
                    "with capture on",
            "INCONCLUSIVE": "the key does nothing in this state even without "
                            "capture, so suppressing it proves nothing",
            "FAIL": "the game reacted even though the message was suppressed; "
                    "something other than this window procedure delivers input",
        }[verdict],
        "idle_floor": idle,
        "off": {"effect": off["effect"], "suppressed": off["probe_suppressed"],
                "forwarded": off["probe_forwarded"]},
        "on": {"effect": on["effect"], "suppressed": on["probe_suppressed"],
               "forwarded": on["probe_forwarded"]},
    }
    if args.run_dir:
        os.makedirs(args.run_dir, exist_ok=True)
        with open(os.path.join(args.run_dir, "c4-differential-%s.json"
                               % args.key.upper()), "w", encoding="utf-8") as out:
            json.dump(document, out, indent=2, sort_keys=True)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if verdict == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--delivery", choices=("sendinput", "post"),
                        default="sendinput",
                        help="sendinput needs the foreground; post addresses the "
                             "window queue directly and does not")
    sub = parser.add_subparsers(dest="command", required=True)
    discover = sub.add_parser("discover")
    discover.add_argument("--keys", nargs="+", required=True)
    discover.add_argument("--hold-ms", type=int, default=60)
    discover.set_defaults(func=do_discover)
    differential = sub.add_parser("differential")
    differential.add_argument("--key", required=True)
    differential.add_argument("--hold-ms", type=int, default=60)
    differential.set_defaults(func=do_differential)
    args = parser.parse_args()
    try:
        return args.func(args)
    except probe.ipp.Blocked as blocked:
        print(json.dumps({"ok": False, "blocked": str(blocked)}, indent=2))
        return 3


if __name__ == "__main__":
    sys.exit(main())
