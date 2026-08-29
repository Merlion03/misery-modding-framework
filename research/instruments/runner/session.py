#!/usr/bin/env python3
"""Runner session state that survives a game restart -- and the rule that
almost nothing is allowed to.

WHY THIS FILE EXISTS AT ALL. A cycle spans two different MISERY processes: the
one being torn down and the one being launched. Exactly one thing genuinely
needs to cross that boundary -- what the previous cycle left loaded in the OLD
process, so this cycle can stop it gracefully instead of guessing. Everything
else that a naive implementation would cache (a base address, a resolved
UClass, a UFunction pointer, a GUObjectArray VA) is not merely stale after a
restart: it is *actively misleading*, because ASLR will hand the new process a
different image base and the old numbers still look like plausible pointers.

So the state file is address-carrying BY PROCESS, and this module enforces it
structurally rather than by convention:

  * ``ProcessScopedState`` holds pid + the addresses that belong to that pid.
  * ``load()`` returns it ONLY when the recorded pid still names a live
    process whose start time matches what was recorded. A recycled pid --
    Windows reuses them, and a cycle that restarts the game makes reuse far
    more likely than in ordinary use -- is rejected on the start-time check,
    not merely on the pid.
  * ``carry_across_restart()`` returns a NEW state object containing only the
    non-address fields. There is no code path that copies an address into the
    next process's state, because the function that would have to do it does
    not exist.

The pid+start_time pair is the process identity used throughout. A pid alone is
not an identity: the whole point of this runner is that processes die and are
replaced, which is exactly the condition under which pid reuse happens.
"""
import json
import os
import time

SCHEMA_VERSION = 1

# Fields that describe a live address space. They are recorded per-process and
# are never carried forward. Keep this list and ProcessScopedState in sync --
# the round-trip test in tests/test_runner.py asserts they are.
ADDRESS_FIELDS = ("base_address", "image_size_bytes", "remote_module_base",
                  "remote_io", "remote_path")


class ProcessScopedState:
    """What we know about ONE MISERY process. Never valid for another one."""

    def __init__(self, pid=None, start_time=None, exe_path=None, build_sha256=None,
                 loaded_probe_module=None, **addresses):
        self.pid = pid
        self.start_time = start_time          # ISO8601, from the OS, not from us
        self.exe_path = exe_path
        self.build_sha256 = build_sha256
        # The name of a probe DLL this runner loaded into THIS process and has
        # not yet unloaded. Carried across a restart (it is a name, not an
        # address) so a later cycle can at least report what was left behind.
        self.loaded_probe_module = loaded_probe_module
        for field in ADDRESS_FIELDS:
            setattr(self, field, addresses.get(field))

    def to_dict(self):
        out = {"pid": self.pid, "start_time": self.start_time,
               "exe_path": self.exe_path, "build_sha256": self.build_sha256,
               "loaded_probe_module": self.loaded_probe_module}
        for field in ADDRESS_FIELDS:
            out[field] = getattr(self, field)
        return out

    @classmethod
    def from_dict(cls, raw):
        raw = dict(raw or {})
        addresses = {f: raw.get(f) for f in ADDRESS_FIELDS}
        return cls(pid=raw.get("pid"), start_time=raw.get("start_time"),
                   exe_path=raw.get("exe_path"), build_sha256=raw.get("build_sha256"),
                   loaded_probe_module=raw.get("loaded_probe_module"), **addresses)

    def has_addresses(self):
        return any(getattr(self, f) is not None for f in ADDRESS_FIELDS)

    def carry_across_restart(self):
        """The ONLY way state moves to the next process. Addresses do not.

        Note what is dropped and what is kept: pid, start_time and every
        address belong to the process that is going away. ``loaded_probe_module``
        is kept because it is a *name*, and a name still describes something
        true after the process dies -- namely that a cycle ended with a module
        loaded, which the next cycle's report should say out loud even though
        the module itself died with its host.
        """
        return ProcessScopedState(loaded_probe_module=self.loaded_probe_module)


def default_path(repo_root):
    return os.path.join(repo_root, "workspace", "runner", "session-state.json")


def save(path, state, extra=None):
    """Write the state file. ``extra`` is free-form bookkeeping (last run id,
    last verdict) that is NOT process-scoped and carries no addresses."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    payload = {"schema_version": SCHEMA_VERSION,
               "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "process": state.to_dict(),
               "extra": dict(extra or {})}
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def load(path, live_process_identity):
    """Return ``(state, extra, reason)``.

    *live_process_identity* is a callable ``pid -> (start_time, exe_path)`` or
    ``None`` when no such process exists. It is injected rather than imported so
    this module stays testable without a running game -- and so the identity
    check cannot silently degrade to "the pid exists", which is the check that
    pid reuse defeats.

    ``state`` is process-scoped ONLY when the recorded process is still the same
    live process. Otherwise the returned state is the carried-forward one (no
    addresses, no pid) and *reason* says why -- so the caller reports "the state
    did not apply, here is why" instead of quietly acting on stale numbers.
    """
    if not os.path.isfile(path):
        return ProcessScopedState(), {}, "no session state file"
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError) as exc:
        return ProcessScopedState(), {}, "session state unreadable: %r" % (exc,)
    if payload.get("schema_version") != SCHEMA_VERSION:
        return (ProcessScopedState(), {},
                "session state schema %r != %d" % (payload.get("schema_version"), SCHEMA_VERSION))

    recorded = ProcessScopedState.from_dict(payload.get("process"))
    extra = dict(payload.get("extra") or {})
    if recorded.pid is None:
        return recorded, extra, "session state records no process"

    live = live_process_identity(recorded.pid)
    if live is None:
        return (recorded.carry_across_restart(), extra,
                "recorded pid %d is not running" % recorded.pid)
    live_start, live_exe = live
    if recorded.start_time and live_start and recorded.start_time != live_start:
        return (recorded.carry_across_restart(), extra,
                "pid %d was reused: recorded start %s, live start %s"
                % (recorded.pid, recorded.start_time, live_start))
    if recorded.exe_path and live_exe and os.path.normcase(recorded.exe_path) != os.path.normcase(live_exe):
        return (recorded.carry_across_restart(), extra,
                "pid %d runs a different image: %s" % (recorded.pid, live_exe))
    return recorded, extra, None
