#!/usr/bin/env python3
"""The event bus.

WHAT SHIPS WITH IT: ALMOST NOTHING, ON PURPOSE
----------------------------------------------
The owner's instruction was explicit -- establish the infrastructure, do not
invent unmeasured gameplay events to populate it. So this bus ships with exactly
the events the platform itself can honestly raise, all of them about mod
lifecycle, and not one about the game. "Player took damage" and friends require
research that has not been done, and an event that fires from nowhere is worse
than an absent one: a mod author would build on it and discover later that it
never actually fires.

NAMESPACING
-----------
An event name is ``<owner>:<name>``. ``platform:`` is the framework's, and a mod
owns ``<its mod_id>:``. A mod cannot declare an event in another mod's namespace,
for the same reason it cannot register an item there.

DISPATCH SAFETY IS THE WHOLE DESIGN
-----------------------------------
Three things happen on every publish and each one is deliberate:

  * The handler list is COPIED before dispatch. Subscribing or unsubscribing
    during a dispatch is legal and takes effect on the NEXT publish, so the list
    cannot mutate underneath the loop.
  * Every handler is invoked THROUGH ITS TOKEN, which checks liveness at call
    time. A mod unloaded halfway through a dispatch simply stops being called
    for the remainder of that same dispatch -- there is no window.
  * A handler that raises is caught, reported as a structured error against the
    mod that owns it, and does not stop the other handlers. One broken mod must
    not swallow an event for every other mod.

Re-entrancy is allowed but bounded. A handler may publish, because forbidding it
would make ordinary composition impossible, but the depth is capped so that a
mod publishing the event it is handling fails with a structured error instead of
consuming the stack.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402
import ownership                                                   # noqa: E402

PLATFORM_NAMESPACE = "platform"
NAME_SEPARATOR = ":"
MAX_DEPTH = 8

# The only events this stage is entitled to define. Every one is something the
# platform itself does, so every one really fires.
EVENT_MOD_LOADED = "platform:mod_loaded"
EVENT_MOD_UNLOADING = "platform:mod_unloading"
EVENT_MOD_UNLOADED = "platform:mod_unloaded"
EVENT_MOD_FAILED = "platform:mod_failed"

PLATFORM_EVENTS = (EVENT_MOD_LOADED, EVENT_MOD_UNLOADING, EVENT_MOD_UNLOADED,
                   EVENT_MOD_FAILED)


def split_event_name(name):
    """``owner:name`` -> the pair, or None."""
    if not isinstance(name, str) or NAME_SEPARATOR not in name:
        return None
    owner, _, local = name.partition(NAME_SEPARATOR)
    if not owner or not local or NAME_SEPARATOR in local:
        return None
    return (owner, local)


def check_event_name(name, declaring_mod=None):
    """Validate a name, and that its namespace belongs to the declarer."""
    parts = split_event_name(name)
    if parts is None:
        raise E.PlatformError(
            E.SUB_EVENTS, E.E_INVALID_ARGUMENT,
            "event name %r must be '<owner>%s<name>' with exactly one separator"
            % (name, NAME_SEPARATOR), declaring_mod)
    owner, local = parts
    if not _modid.PATTERN.match(local):
        raise E.PlatformError(E.SUB_EVENTS, E.E_INVALID_ARGUMENT,
                              "event local name %r must match %s"
                              % (local, _modid.PATTERN_TEXT), declaring_mod)
    if owner != PLATFORM_NAMESPACE and not _modid.is_valid(owner):
        raise E.PlatformError(E.SUB_EVENTS, E.E_INVALID_ARGUMENT,
                              "event namespace %r is neither %r nor a valid "
                              "mod id" % (owner, PLATFORM_NAMESPACE),
                              declaring_mod)
    if declaring_mod is not None and owner != declaring_mod:
        raise E.PlatformError(
            E.SUB_EVENTS, E.E_INVALID_ARGUMENT,
            "%r may not declare %r: an event belongs to the namespace that "
            "declares it, so a mod cannot define events in another mod's"
            % (declaring_mod, name), declaring_mod)
    return name


class EventBus(object):
    def __init__(self, logger=None):
        self._declared = {}          # name -> {"owner": mod_id or None, "detail": ...}
        self._handlers = {}          # name -> [Token]
        self._depth = 0
        self._logger = logger
        self.dispatch_count = 0
        self.fault_count = 0
        for name in PLATFORM_EVENTS:
            self._declared[name] = {"owner": None, "detail": "platform lifecycle"}

    # ---- declaration ---------------------------------------------------
    def declare(self, owner, name, detail=None):
        """A mod declares an event in its own namespace. Owned, so unload removes it."""
        check_event_name(name, owner.mod_id)
        if name in self._declared:
            raise E.PlatformError(E.SUB_EVENTS, E.E_ALREADY_EXISTS,
                                  "event %r is already declared" % name,
                                  owner.mod_id)
        self._declared[name] = {"owner": owner.mod_id, "detail": detail}

        def release():
            self._declared.pop(name, None)
            # Handlers for a vanished event go too: leaving them would keep a
            # subscriber's callback reachable through a name nothing can raise.
            self._handlers.pop(name, None)

        return owner.own("event_declaration", name, release, detail)

    def declared(self):
        return {name: dict(meta) for name, meta in sorted(self._declared.items())}

    # ---- subscription --------------------------------------------------
    def subscribe(self, owner, name, handler):
        """Subscribe *owner*'s handler to *name*. Returns an owned Releasable.

        Subscribing to an undeclared event is refused. The alternative -- create
        it implicitly -- means a typo in an event name silently produces a
        subscription that can never fire, which is the single most common way a
        bus like this wastes somebody's afternoon.
        """
        if name not in self._declared:
            raise E.PlatformError(
                E.SUB_EVENTS, E.E_NOT_FOUND,
                "no event %r is declared; subscribing to an undeclared event "
                "would silently never fire" % name, owner.mod_id)
        token = owner.token(handler, "event_handler", name)
        self._handlers.setdefault(name, []).append(token)

        def release():
            token.revoke()
            handlers = self._handlers.get(name)
            if handlers:
                self._handlers[name] = [t for t in handlers if t is not token]
        return owner.own("event_handler", name, release)

    def subscriber_count(self, name):
        return len(ownership.live_tokens(self._handlers.get(name, [])))

    # ---- dispatch ------------------------------------------------------
    def publish(self, name, payload=None, source=None):
        """Raise *name*. Returns how many handlers actually ran.

        Never raises because of a handler: a publisher is not responsible for
        other mods' bugs.
        """
        if name not in self._declared:
            raise E.PlatformError(E.SUB_EVENTS, E.E_NOT_FOUND,
                                  "no event %r is declared" % name, source)
        if self._depth >= MAX_DEPTH:
            raise E.PlatformError(
                E.SUB_EVENTS, E.E_LIMIT_EXCEEDED,
                "event dispatch nested %d deep at %r; a handler is very likely "
                "publishing the event it handles" % (self._depth, name), source)

        # Copied BEFORE dispatch. Subscribing or unsubscribing inside a handler
        # is legal and lands on the next publish.
        captured = list(self._handlers.get(name, ()))
        self._depth += 1
        ran = 0
        try:
            for token in captured:
                # Liveness at CALL time, not at capture time. This is what makes
                # "no callback may target unloaded mod code" true even for a mod
                # unloaded midway through this very loop.
                called, _result = token.invoke(payload)
                if called:
                    ran += 1
        finally:
            self._depth -= 1
        self.dispatch_count += 1
        return ran

    def publish_guarded(self, name, payload=None, source=None):
        """Dispatch, catching each handler's fault separately.

        Separate from ``publish`` because the guarding costs a try/except per
        handler and the platform's own lifecycle events want it while a hot path
        may not. Faults are attributed to the mod that owns the handler, never
        to the publisher.
        """
        if name not in self._declared:
            raise E.PlatformError(E.SUB_EVENTS, E.E_NOT_FOUND,
                                  "no event %r is declared" % name, source)
        if self._depth >= MAX_DEPTH:
            raise E.PlatformError(E.SUB_EVENTS, E.E_LIMIT_EXCEEDED,
                                  "event dispatch nested %d deep at %r"
                                  % (self._depth, name), source)
        captured = list(self._handlers.get(name, ()))
        self._depth += 1
        ran, faults = 0, []
        try:
            for token in captured:
                try:
                    called, _result = token.invoke(payload)
                    if called:
                        ran += 1
                except Exception as error:                         # noqa: BLE001
                    self.fault_count += 1
                    fault = E.PlatformError(
                        E.SUB_EVENTS, E.E_HANDLER_FAULTED,
                        "handler for %r raised %s: %s"
                        % (name, type(error).__name__, error), token.owner_id)
                    faults.append(fault)
                    if self._logger is not None:
                        self._logger.platform_error(fault)
        finally:
            self._depth -= 1
        self.dispatch_count += 1
        return {"event": name, "ran": ran, "faults": [f.as_dict() for f in faults]}

    def summary(self):
        """For the developer console."""
        return {
            "declared": len(self._declared),
            "events": {name: {"owner": meta["owner"],
                              "subscribers": self.subscriber_count(name)}
                       for name, meta in sorted(self._declared.items())},
            "dispatches": self.dispatch_count,
            "handler_faults": self.fault_count,
        }
