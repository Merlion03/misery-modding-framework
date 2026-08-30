#!/usr/bin/env python3
"""Per-mod logging.

NAMED ``modlog`` AND NOT ``logging``
------------------------------------
These directories go on ``sys.path`` side by side, so a module called
``logging`` here would shadow the standard library's for every consumer in the
process. That class of defect has already cost this repository twice --
``fixtures`` shadowing ``fixtures``, and ``validate`` shadowing ``validate`` --
and shadowing a STDLIB name would be considerably worse than either.

WHAT A LOG RECORD IS
--------------------
A record always carries the mod it came from, and the mod does not get to say
which mod that is: the logger is handed out per-owner and stamps the id itself.
Otherwise the first misbehaving mod would be able to attribute its noise to
somebody else, and the console's "which mod is spamming" answer would be a lie.

Records are DATA, not formatted strings, for the same reason errors are: the
console, the file sink and the C# side each want a different rendering, and
whoever formats first destroys the others' options.

RATE LIMITING IS A FEATURE, NOT A NICETY
----------------------------------------
A mod in a tight loop can emit faster than any sink can write, and the failure
mode is the game stalling rather than the log being untidy. Each owner gets a
budget per window; beyond it, records are counted and dropped, and the drop is
itself reported once. Dropping loudly beats stalling silently.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402

# Levels are ints so they cross the ABI unchanged and compare cheaply.
TRACE, DEBUG, INFO, WARN, ERROR = 0, 1, 2, 3, 4
LEVEL_NAMES = {TRACE: "trace", DEBUG: "debug", INFO: "info",
               WARN: "warn", ERROR: "error"}
LEVELS_BY_NAME = {v: k for k, v in LEVEL_NAMES.items()}

MAX_MESSAGE = 4096
DEFAULT_BUDGET = 2000          # records per window, per mod
DEFAULT_WINDOW = 1000          # in monotonic ticks supplied by the caller


class Record(object):
    __slots__ = ("sequence", "tick", "level", "mod_id", "message", "fields")

    def __init__(self, sequence, tick, level, mod_id, message, fields):
        self.sequence = sequence
        self.tick = tick
        self.level = level
        self.mod_id = mod_id
        self.message = message
        self.fields = fields

    def as_dict(self):
        return {"sequence": self.sequence, "tick": self.tick,
                "level": LEVEL_NAMES.get(self.level, str(self.level)),
                "mod_id": self.mod_id, "message": self.message,
                "fields": dict(self.fields) if self.fields else {}}

    def __repr__(self):
        return "[%s] %s: %s" % (LEVEL_NAMES.get(self.level, self.level),
                                self.mod_id or "platform", self.message)


class LogBuffer(object):
    """A bounded ring the developer console reads from.

    Bounded because an unbounded log in a long session is a memory leak with a
    respectable name. The buffer is the console's source; durable sinks are a
    separate concern and are attached alongside it.
    """

    def __init__(self, capacity=4096):
        self.capacity = capacity
        self._records = []

    def append(self, record):
        self._records.append(record)
        if len(self._records) > self.capacity:
            del self._records[:len(self._records) - self.capacity]

    def tail(self, count=50, level=None, mod_id=None):
        chosen = [r for r in self._records
                  if (level is None or r.level >= level)
                  and (mod_id is None or r.mod_id == mod_id)]
        return chosen[-count:]

    def __len__(self):
        return len(self._records)


class LogRouter(object):
    """Where records go, and the budget that stops one mod drowning the rest."""

    def __init__(self, buffer=None, sinks=(), budget=DEFAULT_BUDGET,
                 window=DEFAULT_WINDOW, min_level=TRACE):
        self.buffer = buffer if buffer is not None else LogBuffer()
        self.sinks = list(sinks)
        self.budget = budget
        self.window = window
        self.min_level = min_level
        self._sequence = 0
        self._tick = 0
        self._spent = {}         # mod_id -> (window_index, used, dropped)
        self.dropped_total = 0

    def advance(self, ticks=1):
        """Time is supplied, never read.

        The platform runs on the game thread and its notion of "now" is the
        frame it is in. Reading a wall clock here would make the same sequence
        of calls produce different behaviour between runs, which is exactly what
        the rest of this codebase has been at pains to avoid.
        """
        self._tick += ticks
        return self._tick

    def _allowed(self, mod_id):
        index = self._tick // max(1, self.window)
        state = self._spent.get(mod_id)
        if state is None or state[0] != index:
            self._spent[mod_id] = [index, 0, 0]
            state = self._spent[mod_id]
        if state[1] < self.budget:
            state[1] += 1
            return True, False
        state[2] += 1
        self.dropped_total += 1
        # Report the FIRST drop of each window, once. Reporting every drop would
        # be the same flood wearing a different hat.
        return False, state[2] == 1

    def emit(self, level, mod_id, message, fields=None):
        if level < self.min_level:
            return None
        allowed, first_drop = self._allowed(mod_id)
        if not allowed:
            if first_drop:
                self._write(Record(self._next(), self._tick, WARN, None,
                                   "log budget exceeded for %r; further records "
                                   "this window are dropped" % mod_id,
                                   {"mod_id": mod_id, "budget": self.budget}))
            return None
        record = Record(self._next(), self._tick, level, mod_id,
                        message[:MAX_MESSAGE], fields or {})
        self._write(record)
        return record

    def _next(self):
        self._sequence += 1
        return self._sequence

    def _write(self, record):
        self.buffer.append(record)
        for sink in self.sinks:
            try:
                sink(record)
            except Exception:                                      # noqa: BLE001
                # A sink that throws must not take down the caller's logging
                # call, which is very often inside somebody's error handler.
                pass

    def drops_for(self, mod_id):
        state = self._spent.get(mod_id)
        return state[2] if state else 0


class ModLogger(object):
    """The handle a single mod gets. It cannot name a different mod."""

    __slots__ = ("_router", "_mod_id")

    def __init__(self, router, mod_id):
        self._router = router
        self._mod_id = mod_id

    def log(self, level, message, **fields):
        if not isinstance(message, str):
            raise E.PlatformError(E.SUB_LOG, E.E_INVALID_ARGUMENT,
                                  "log message must be a string, got %s"
                                  % type(message).__name__, self._mod_id)
        if level not in LEVEL_NAMES:
            raise E.PlatformError(E.SUB_LOG, E.E_INVALID_ARGUMENT,
                                  "unknown log level %r" % (level,), self._mod_id)
        return self._router.emit(level, self._mod_id, message, fields)

    def trace(self, message, **fields):
        return self.log(TRACE, message, **fields)

    def debug(self, message, **fields):
        return self.log(DEBUG, message, **fields)

    def info(self, message, **fields):
        return self.log(INFO, message, **fields)

    def warn(self, message, **fields):
        return self.log(WARN, message, **fields)

    def error(self, message, **fields):
        return self.log(ERROR, message, **fields)

    def platform_error(self, error):
        """Log a structured error without losing its structure."""
        payload = error.as_dict() if isinstance(error, E.PlatformError) else {
            "detail": str(error), "name": type(error).__name__}
        return self.log(ERROR, payload.get("detail", str(error)),
                        **{k: v for k, v in payload.items() if k != "detail"})
