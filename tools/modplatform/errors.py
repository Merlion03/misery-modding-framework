#!/usr/bin/env python3
"""Structured errors: one shape, every subsystem, and it survives the ABI.

WHY NOT EXCEPTIONS ALL THE WAY DOWN
-----------------------------------
An error raised inside a mod has to reach three audiences that cannot share a
representation:

  * the mod author, in C#, who wants something they can catch and read;
  * the framework, in C++, which cannot let a managed exception cross the ABI
    and must not lose the reason;
  * the log and the developer console, which need a stable, greppable code
    rather than a sentence someone may reword.

So an error is DATA -- subsystem, code, detail, and the mod it is attributed to
-- and each side wraps that data in whatever its language calls an error. The
data is what crosses; the exception is what each side builds locally.

WHY subsystem AND code, RATHER THAN ONE FLAT ENUM
-------------------------------------------------
A flat enum makes every subsystem's error space one namespace, so adding an
error to the event bus renumbers the input registry's. Splitting it means a
subsystem owns its own codes and can add one without coordinating. The pair is
what is stable; neither half is meaningful alone.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import modid as _modid                                             # noqa: E402

# ---- subsystems -----------------------------------------------------------
# Each owns its own code space. The numbers are part of the ABI: they are
# duplicated in the C header and the C# enum, and a test compares all three.
SUB_PLATFORM = 1
SUB_LIFECYCLE = 2
SUB_LOG = 3
SUB_EVENTS = 4
SUB_SETTINGS = 5
SUB_INPUT = 6
SUB_SERVICES = 7
SUB_ITEMS = 8
SUB_CAPABILITIES = 9
SUB_CONSOLE = 10

SUBSYSTEM_NAMES = {
    SUB_PLATFORM: "platform",
    SUB_LIFECYCLE: "lifecycle",
    SUB_LOG: "log",
    SUB_EVENTS: "events",
    SUB_SETTINGS: "settings",
    SUB_INPUT: "input",
    SUB_SERVICES: "services",
    SUB_ITEMS: "items",
    SUB_CAPABILITIES: "capabilities",
    SUB_CONSOLE: "console",
}

# ---- codes ----------------------------------------------------------------
# Per-subsystem, starting at 1. 0 is reserved for "no error" so that a caller
# reading a raw pair can never mistake a real failure for success.
OK = 0

# platform
E_NOT_INITIALISED = 1
E_ALREADY_INITIALISED = 2
E_SHUTTING_DOWN = 3

# lifecycle
E_UNKNOWN_MOD = 1
E_MOD_ALREADY_LOADED = 2
E_MOD_NOT_LOADED = 3
E_OWNER_DISPOSED = 4
E_LOAD_FAILED = 5
E_REENTRANT_UNLOAD = 6

# generic, reused inside each subsystem's own space
E_INVALID_ARGUMENT = 10
E_NOT_FOUND = 11
E_ALREADY_EXISTS = 12
E_NOT_OWNED = 13
E_WRONG_THREAD = 14
E_CAPABILITY_NOT_GRANTED = 15
E_LIMIT_EXCEEDED = 16
E_HANDLER_FAULTED = 17

CODE_NAMES = {
    OK: "ok",
    E_NOT_INITIALISED: "not_initialised",
    E_ALREADY_INITIALISED: "already_initialised",
    E_SHUTTING_DOWN: "shutting_down",
    E_INVALID_ARGUMENT: "invalid_argument",
    E_NOT_FOUND: "not_found",
    E_ALREADY_EXISTS: "already_exists",
    E_NOT_OWNED: "not_owned",
    E_WRONG_THREAD: "wrong_thread",
    E_CAPABILITY_NOT_GRANTED: "capability_not_granted",
    E_LIMIT_EXCEEDED: "limit_exceeded",
    E_HANDLER_FAULTED: "handler_faulted",
}

LIFECYCLE_CODE_NAMES = {
    E_UNKNOWN_MOD: "unknown_mod",
    E_MOD_ALREADY_LOADED: "mod_already_loaded",
    E_MOD_NOT_LOADED: "mod_not_loaded",
    E_OWNER_DISPOSED: "owner_disposed",
    E_LOAD_FAILED: "load_failed",
    E_REENTRANT_UNLOAD: "reentrant_unload",
}


def code_name(subsystem, code):
    """A stable, greppable name for a (subsystem, code) pair."""
    if subsystem == SUB_LIFECYCLE and code in LIFECYCLE_CODE_NAMES:
        return LIFECYCLE_CODE_NAMES[code]
    return CODE_NAMES.get(code, "code_%d" % code)


class PlatformError(Exception):
    """A structured error, and the exception the Python side raises.

    ``as_wire()`` is the representation that crosses the boundary; the exception
    is only how this language happens to carry it.
    """

    __slots__ = ("subsystem", "code", "detail", "mod_id")

    def __init__(self, subsystem, code, detail, mod_id=None):
        self.subsystem = subsystem
        self.code = code
        self.detail = detail
        self.mod_id = mod_id
        super().__init__(str(self))

    @property
    def name(self):
        return "%s.%s" % (SUBSYSTEM_NAMES.get(self.subsystem,
                                              "subsystem_%d" % self.subsystem),
                          code_name(self.subsystem, self.code))

    def as_wire(self):
        """Exactly what crosses the ABI: two integers and two strings."""
        return {"subsystem": self.subsystem, "code": self.code,
                "detail": self.detail, "mod_id": self.mod_id}

    def as_dict(self):
        payload = self.as_wire()
        payload["name"] = self.name
        return payload

    def __str__(self):
        who = " [%s]" % self.mod_id if self.mod_id else ""
        return "%s%s: %s" % (self.name, who, self.detail)


def raise_for(subsystem, code, detail, mod_id=None):
    raise PlatformError(subsystem, code, detail, mod_id)


def check_mod_id(mod_id, subsystem=SUB_LIFECYCLE):
    """Validate through the canonical contract, report as a platform error."""
    try:
        return _modid.check(mod_id)
    except _modid.ModIdError as error:
        raise PlatformError(subsystem, E_INVALID_ARGUMENT, error.detail,
                            mod_id if isinstance(mod_id, str) else None) from error
