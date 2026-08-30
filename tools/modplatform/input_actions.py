#!/usr/bin/env python3
"""The input action registry.

WHAT THIS IS, AND WHAT IT HONESTLY IS NOT
-----------------------------------------
It is a place for a mod to DECLARE a named action -- "alphamod:toggle_scanner",
a display name, a suggested default binding -- and for the framework to own that
declaration, list it, and revoke it on unload.

It is NOT a route from a key press to a mod's handler. The engine's input path
in this build has not been researched: no key state source has been measured, no
binding table located, no dispatch point proven. Wiring a handler to something
unmeasured would produce a subsystem that looks finished and never fires, which
is materially worse than one that says plainly what it does not do.

So handlers ARE accepted and owned -- because the ownership and revocation
contract is exactly what Stage 4.5 exists to fix in place, and it must be the
same contract when real input arrives -- and this module records that they are
currently only reachable through ``deliver()``, which the framework calls and no
engine path yet calls. ``capabilities.CAP_INPUT_REGISTRY`` is versioned 0.1.0
and says so in its own description, so a mod can ask and be told.

WHY DECLARE ANYTHING AT ALL THEN
--------------------------------
Because the declarations are what a future binding UI, a settings file and the
engine wiring will all need to exist BEFORE they can be built, and because
getting the ownership semantics right is cheap now and expensive later. A mod
written today against this registry will not need rewriting when input is
researched; only the framework's side gets filled in.

A SUGGESTED BINDING IS A STRING, NOT A KEY CODE
-----------------------------------------------
Deliberately. A key code is an engine concept with a build-specific
representation, and inventing a mapping before measuring the engine's would be
inventing a fact. The string is a hint for a future binding UI and for the user's
config; nothing in the framework interprets it yet.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402
import ownership                                                   # noqa: E402

NAME_SEPARATOR = ":"
MAX_ACTIONS_PER_MOD = 64
MAX_DISPLAY_NAME = 64
MAX_SUGGESTED_BINDING = 64

# What an action reports when it fires. Ints, so they cross the ABI unchanged.
PHASE_PRESSED, PHASE_RELEASED = 1, 2
PHASE_NAMES = {PHASE_PRESSED: "pressed", PHASE_RELEASED: "released"}


class InputAction(object):
    __slots__ = ("name", "mod_id", "display_name", "suggested_binding")

    def __init__(self, name, mod_id, display_name, suggested_binding):
        self.name = name
        self.mod_id = mod_id
        self.display_name = display_name
        self.suggested_binding = suggested_binding

    def as_dict(self):
        return {"name": self.name, "mod_id": self.mod_id,
                "display_name": self.display_name,
                "suggested_binding": self.suggested_binding}


def check_action_name(name, declaring_mod=None):
    if not isinstance(name, str) or NAME_SEPARATOR not in name:
        raise E.PlatformError(E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                              "action name %r must be '<mod_id>%s<name>'"
                              % (name, NAME_SEPARATOR), declaring_mod)
    owner, _, local = name.partition(NAME_SEPARATOR)
    if not _modid.is_valid(owner) or not _modid.PATTERN.match(local or ""):
        raise E.PlatformError(E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                              "action name %r is not '<mod_id>%s<name>' with "
                              "both parts matching %s"
                              % (name, NAME_SEPARATOR, _modid.PATTERN_TEXT),
                              declaring_mod)
    if declaring_mod is not None and owner != declaring_mod:
        raise E.PlatformError(
            E.SUB_INPUT, E.E_INVALID_ARGUMENT,
            "%r may not declare %r: an action belongs to the namespace that "
            "declares it" % (declaring_mod, name), declaring_mod)
    return name


class InputRegistry(object):
    def __init__(self, logger=None):
        self._actions = {}       # name -> InputAction
        self._handlers = {}      # name -> [Token]
        self._counts = {}        # mod_id -> int
        self._logger = logger
        self.delivered = 0
        self.faults = 0

    def register(self, owner, name, display_name, suggested_binding=None,
                 handler=None):
        """Declare an action, optionally with a handler. Owned by the declarer."""
        check_action_name(name, owner.mod_id)
        if name in self._actions:
            raise E.PlatformError(E.SUB_INPUT, E.E_ALREADY_EXISTS,
                                  "action %r is already registered" % name,
                                  owner.mod_id)
        if self._counts.get(owner.mod_id, 0) >= MAX_ACTIONS_PER_MOD:
            raise E.PlatformError(E.SUB_INPUT, E.E_LIMIT_EXCEEDED,
                                  "a mod may register at most %d input actions"
                                  % MAX_ACTIONS_PER_MOD, owner.mod_id)
        if not isinstance(display_name, str) or not display_name.strip():
            raise E.PlatformError(E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                                  "action %r needs a non-empty display name"
                                  % name, owner.mod_id)
        if len(display_name) > MAX_DISPLAY_NAME:
            raise E.PlatformError(E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                                  "display name for %r exceeds %d characters"
                                  % (name, MAX_DISPLAY_NAME), owner.mod_id)
        if suggested_binding is not None:
            if (not isinstance(suggested_binding, str)
                    or len(suggested_binding) > MAX_SUGGESTED_BINDING):
                raise E.PlatformError(
                    E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                    "suggested binding for %r must be a short string; it is a "
                    "hint for a future binding UI, not an engine key code"
                    % name, owner.mod_id)

        self._actions[name] = InputAction(name, owner.mod_id,
                                          display_name.strip(), suggested_binding)
        self._counts[owner.mod_id] = self._counts.get(owner.mod_id, 0) + 1
        token = None
        if handler is not None:
            token = owner.token(handler, "input_handler", name)
            self._handlers.setdefault(name, []).append(token)

        def release():
            if token is not None:
                token.revoke()
                remaining = [t for t in self._handlers.get(name, ()) if t is not token]
                if remaining:
                    self._handlers[name] = remaining
                else:
                    self._handlers.pop(name, None)
            self._actions.pop(name, None)
            self._counts[owner.mod_id] = max(0, self._counts.get(owner.mod_id, 1) - 1)

        return owner.own("input_action", name, release, display_name)

    def deliver(self, name, phase):
        """Fire an action.

        Called by the FRAMEWORK. No engine path calls this yet -- see the module
        docstring. It exists now so the ownership and revocation semantics are
        the ones already proven, rather than something bolted on later.
        """
        if name not in self._actions:
            raise E.PlatformError(E.SUB_INPUT, E.E_NOT_FOUND,
                                  "no action %r is registered" % name)
        if phase not in PHASE_NAMES:
            raise E.PlatformError(E.SUB_INPUT, E.E_INVALID_ARGUMENT,
                                  "unknown input phase %r" % (phase,))
        ran, faults = 0, []
        for token in ownership.live_tokens(list(self._handlers.get(name, ()))):
            try:
                called, _ = token.invoke(name, phase)
                if called:
                    ran += 1
            except Exception as error:                             # noqa: BLE001
                self.faults += 1
                fault = E.PlatformError(
                    E.SUB_INPUT, E.E_HANDLER_FAULTED,
                    "input handler for %r raised %s: %s"
                    % (name, type(error).__name__, error), token.owner_id)
                faults.append(fault.as_dict())
                if self._logger is not None:
                    self._logger.platform_error(fault)
        self.delivered += 1
        return {"action": name, "phase": PHASE_NAMES[phase], "ran": ran,
                "faults": faults}

    def actions(self):
        return [self._actions[name].as_dict() for name in sorted(self._actions)]

    def summary(self):
        return {
            "actions": self.actions(),
            "handlers": {name: len(ownership.live_tokens(tokens))
                         for name, tokens in sorted(self._handlers.items())},
            "delivered": self.delivered,
            "handler_faults": self.faults,
            "engine_input_wired": False,
            "note": ("declaration and ownership only; the engine input path is "
                     "unresearched, so nothing in the game delivers these yet"),
        }
