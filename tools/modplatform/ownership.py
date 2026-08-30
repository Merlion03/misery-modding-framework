#!/usr/bin/env python3
"""Per-mod ownership, and the guarantee that unloading really releases things.

THE REQUIREMENT, RESTATED
-------------------------
    Mod load   -> registrations/subscriptions/input actions/services owned by ModId
    Mod unload -> the framework releases all owned resources
               -> no callback may target unloaded mod code

The second line is easy. The third is the hard one, and it is hard for a reason
worth writing down: the dangerous moment is not "after unload", it is DURING
one. An event dispatch already in progress holds a list of handlers it captured
before the unload started. A mod can unload itself from inside its own handler.
A subsystem can raise an event while releasing a resource. In every one of those
the naive implementation calls into a mod that is already gone.

HOW THIS SOLVES IT
------------------
Two mechanisms, and the second is the one that actually carries the guarantee.

1. **A registry of releasables per owner.** Everything a mod acquires is
   recorded against its owner and released in REVERSE acquisition order on
   unload -- reverse because a later resource may depend on an earlier one, and
   releasing a dependency first is how a teardown crashes.

2. **A revocable token in front of every callback.** A mod never hands a raw
   callable to a subsystem. It hands one wrapped in a token whose owner it
   belongs to. Dispatch goes through the token, and the token checks liveness at
   CALL time, not at capture time. Revocation is therefore instantaneous and
   retroactive: a handler list captured a microsecond before the unload will
   simply skip every revoked entry when it gets there.

That second mechanism is what makes "no callback may target unloaded mod code" a
property of the design rather than a rule everybody has to remember. There is no
window between "the mod is unloading" and "its callbacks stop firing", because
the check is on the calling side of every single invocation.

DETERMINISM
-----------
Release order is reverse-acquisition, and acquisition order is the order the mod
made the calls. Two runs of the same mod release in the same order. Owners are
iterated by mod_id when the platform needs to touch several.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402


class Releasable(object):
    """One owned resource: what it is, and how to give it back.

    ``kind`` is a coarse label used by the developer console ("event_handler",
    "input_action", "service", "item"), and ``key`` identifies it within that
    kind. Both exist so tooling can ANSWER "what does this mod own" without the
    subsystems having to agree on a class hierarchy.
    """

    __slots__ = ("kind", "key", "_release", "released", "detail")

    def __init__(self, kind, key, release, detail=None):
        self.kind = kind
        self.key = key
        self._release = release
        self.released = False
        self.detail = detail

    def release(self):
        """Idempotent. A resource released twice is a no-op, not an error.

        Idempotent because a subsystem may release something itself (a mod
        unsubscribing normally) and the owner will release it again at unload.
        Making the second call an error would turn correct code into a fault.
        """
        if self.released:
            return False
        self.released = True
        self._release()
        return True

    def as_dict(self):
        return {"kind": self.kind, "key": self.key, "released": self.released,
                "detail": self.detail}

    def __repr__(self):
        return "Releasable(%s/%s%s)" % (self.kind, self.key,
                                        " released" if self.released else "")


class Token(object):
    """A revocable indirection in front of one mod callback.

    Every call site asks ``live`` first. That is the whole trick: liveness is
    checked when the callback is about to run, so a list of handlers captured
    before a revocation is still safe to walk afterwards.
    """

    __slots__ = ("owner_id", "callback", "_revoked", "kind", "key")

    def __init__(self, owner_id, callback, kind, key):
        self.owner_id = owner_id
        self.callback = callback
        self.kind = kind
        self.key = key
        self._revoked = False

    @property
    def live(self):
        return not self._revoked

    def revoke(self):
        # The callback reference is dropped as well as flagged. Keeping it would
        # hold a mod's objects alive after unload, which is the managed-side
        # version of the same leak.
        self._revoked = True
        self.callback = None

    def invoke(self, *args, **kwargs):
        """Call the callback, or do nothing if it has been revoked.

        Returns (called, result). Never raises on revocation -- a revoked token
        is a normal, expected state during teardown, not a fault.
        """
        if self._revoked or self.callback is None:
            return (False, None)
        return (True, self.callback(*args, **kwargs))

    def __repr__(self):
        return "Token(%s %s/%s%s)" % (self.owner_id, self.kind, self.key,
                                      "" if self.live else " REVOKED")


class Owner(object):
    """Everything one mod holds. Created at load, disposed at unload.

    A mod never constructs this; the platform hands it one. The mod's own view
    of it is the ModContext, which is deliberately a smaller surface.
    """

    __slots__ = ("mod_id", "_resources", "_tokens", "_disposed", "_disposing")

    def __init__(self, mod_id):
        self.mod_id = E.check_mod_id(mod_id)
        self._resources = []
        self._tokens = []
        self._disposed = False
        self._disposing = False

    @property
    def disposed(self):
        return self._disposed

    @property
    def alive(self):
        return not self._disposed and not self._disposing

    def _require_alive(self, what):
        # Acquiring during teardown is refused rather than allowed-and-leaked:
        # a resource acquired after the release loop has passed its kind would
        # never be released at all.
        if self._disposed:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_OWNER_DISPOSED,
                                  "cannot %s: the owner has been disposed" % what,
                                  self.mod_id)
        if self._disposing:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_OWNER_DISPOSED,
                                  "cannot %s while the owner is being disposed"
                                  % what, self.mod_id)

    def own(self, kind, key, release, detail=None):
        """Record a resource. Returns the Releasable so a caller may release early."""
        self._require_alive("acquire %s/%s" % (kind, key))
        resource = Releasable(kind, key, release, detail)
        self._resources.append(resource)
        return resource

    def token(self, callback, kind, key):
        """Wrap a mod callback so it can be revoked instantly and retroactively."""
        self._require_alive("register a %s callback" % kind)
        if not callable(callback):
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_INVALID_ARGUMENT,
                                  "callback for %s/%s is not callable" % (kind, key),
                                  self.mod_id)
        handle = Token(self.mod_id, callback, kind, key)
        self._tokens.append(handle)
        return handle

    def resources(self):
        return list(self._resources)

    def tokens(self):
        return list(self._tokens)

    def owned_summary(self):
        """What this mod owns, for the developer console. Deterministic order."""
        by_kind = {}
        for resource in self._resources:
            entry = by_kind.setdefault(resource.kind, {"held": [], "released": []})
            entry["released" if resource.released else "held"].append(resource.key)
        for entry in by_kind.values():
            entry["held"].sort()
            entry["released"].sort()
        return {"mod_id": self.mod_id, "disposed": self._disposed,
                "resources": {k: by_kind[k] for k in sorted(by_kind)},
                "live_tokens": sorted(t.key for t in self._tokens if t.live),
                "revoked_tokens": sorted(t.key for t in self._tokens if not t.live)}

    def dispose(self):
        """Revoke every callback FIRST, then release every resource.

        The order is the point. Revoking first means that anything the release
        functions themselves do -- raising an event, unregistering an item,
        touching a subsystem that notifies -- can no longer reach this mod's
        code. Releasing first would leave a window in which a mod's handler runs
        while its resources are half gone, which is a worse state than either
        end of the operation.

        Returns a report rather than nothing, because "unload released
        everything" is a claim the developer console has to be able to show.
        """
        if self._disposed:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_REENTRANT_UNLOAD,
                                  "the owner has already been disposed",
                                  self.mod_id)
        if self._disposing:
            # A mod unloading itself from inside its own handler lands here.
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_REENTRANT_UNLOAD,
                                  "dispose() re-entered while already disposing",
                                  self.mod_id)
        self._disposing = True
        revoked = 0
        for handle in self._tokens:
            if handle.live:
                handle.revoke()
                revoked += 1

        released, faults = [], []
        # Reverse acquisition order: a later resource may depend on an earlier
        # one, so releasing the earliest first is how a teardown breaks.
        for resource in reversed(self._resources):
            try:
                if resource.release():
                    released.append({"kind": resource.kind, "key": resource.key})
            except Exception as error:                             # noqa: BLE001
                # One resource that will not release must not strand the rest.
                # The fault is recorded and the loop continues, because the
                # alternative is a mod that is half unloaded forever.
                faults.append({"kind": resource.kind, "key": resource.key,
                               "error": "%s: %s" % (type(error).__name__, error)})
        self._disposing = False
        self._disposed = True
        return {"mod_id": self.mod_id, "revoked_callbacks": revoked,
                "released": released, "faults": faults,
                "resources_total": len(self._resources)}


def live_tokens(tokens):
    """Filter a captured list down to those still live, at CALL time.

    Every dispatch site goes through this. It exists as a named function so the
    rule has one place to be read, and so a grep for it finds every site that
    has to obey it.
    """
    return [t for t in tokens if t.live]
