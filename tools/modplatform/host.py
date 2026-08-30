#!/usr/bin/env python3
"""The platform host: mod lifecycle, and the state machine behind it.

WHAT THIS OWNS
--------------
The list of mods, each one's state, each one's Owner, and the guarantee that
load and unload are the only two ways in and out. Every subsystem is constructed
here and handed to contexts already bound; nothing reaches a subsystem except
through a context, which means nothing reaches a subsystem un-attributed.

THE STATE MACHINE, AND WHY FAILURE IS A STATE
---------------------------------------------
    DISCOVERED -> LOADING -> LOADED -> UNLOADING -> UNLOADED
                     |                     |
                     +------> FAILED <-----+

FAILED is a real state rather than "absent", because a mod that failed to load
has often already acquired resources -- that is usually WHY it failed -- and the
framework has to release them and then be able to say what happened. The
transition into FAILED runs exactly the same teardown as a normal unload. There
is no second, less-tested cleanup path: the owner's ``dispose()`` is the only
teardown in the system, and both roads reach it.

A MOD'S OWN CODE RUNS INSIDE A GUARD
------------------------------------
``load`` calls into mod code. That code can raise, and it can raise after having
registered things. So the call is wrapped, and on any exception the owner is
disposed and the mod goes to FAILED with the structured error attached. A mod
that half-loads and stays half-loaded is the failure mode this exists to make
impossible.

RE-ENTRANCY
-----------
A mod unloading itself from inside its own handler is a real thing that happens.
``unload`` is therefore guarded against re-entry per mod: the second call gets a
structured error rather than a half-completed double teardown. The Owner has the
same guard, so the invariant holds even if some future subsystem reaches
``dispose`` another way.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import capabilities as CAP                                         # noqa: E402
import context as CTX                                              # noqa: E402
import errors as E                                                 # noqa: E402
import events as EV                                                # noqa: E402
import input_actions                                               # noqa: E402
import modid as _modid                                             # noqa: E402
import modlog                                                      # noqa: E402
import ownership                                                   # noqa: E402
import services as SVC                                             # noqa: E402
import settings as SET                                             # noqa: E402

DISCOVERED = "discovered"
LOADING = "loading"
LOADED = "loaded"
UNLOADING = "unloading"
UNLOADED = "unloaded"
FAILED = "failed"

STATES = (DISCOVERED, LOADING, LOADED, UNLOADING, UNLOADED, FAILED)


class ModRecord(object):
    """One mod's entry in the host. Its state, owner, context and last error."""

    __slots__ = ("mod_id", "state", "owner", "context", "error", "grant",
                 "load_order_index", "teardown")

    def __init__(self, mod_id, load_order_index):
        self.mod_id = mod_id
        self.state = DISCOVERED
        self.owner = None
        self.context = None
        self.error = None
        self.grant = None
        self.load_order_index = load_order_index
        self.teardown = None

    def as_dict(self):
        return {
            "mod_id": self.mod_id, "state": self.state,
            "load_order_index": self.load_order_index,
            "error": self.error.as_dict() if self.error else None,
            "capabilities": self.grant.as_dict() if self.grant else None,
            "owned": self.owner.owned_summary() if self.owner else None,
            "teardown": self.teardown,
        }


class Platform(object):
    def __init__(self, settings_root, items_backend=None, log_capacity=4096):
        self.log_router = modlog.LogRouter(modlog.LogBuffer(log_capacity))
        self.log = modlog.ModLogger(self.log_router, None)
        self.events = EV.EventBus(self.log)
        self.settings = SET.SettingsStore(settings_root, self.log)
        self.input = input_actions.InputRegistry(self.log)
        self.services = SVC.ServiceRegistry(self.log)
        self.items_backend = items_backend
        self._mods = {}          # mod_id -> ModRecord
        self._unloading = set()
        self._shutting_down = False

    # ---- registration of intent ----------------------------------------
    def declare_plan(self, load_order):
        """Tell the host which mods exist and in what order they will load.

        Taken from the Stage 4 load plan. The host does not do discovery: that
        layer is already proven, and duplicating its rules here is how a fifth
        opinion about identity would get started.
        """
        for index, mod_id in enumerate(load_order):
            _modid.check(mod_id)
            if mod_id in self._mods:
                raise E.PlatformError(E.SUB_LIFECYCLE, E.E_MOD_ALREADY_LOADED,
                                      "%r is already known to the host" % mod_id,
                                      mod_id)
            self._mods[mod_id] = ModRecord(mod_id, index)
        return [self._mods[m].mod_id for m in load_order]

    def record(self, mod_id):
        entry = self._mods.get(mod_id)
        if entry is None:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_UNKNOWN_MOD,
                                  "%r is not known to the host" % mod_id, mod_id)
        return entry

    def state_of(self, mod_id):
        return self.record(mod_id).state

    # ---- load ------------------------------------------------------------
    def load(self, mod_id, entry_point=None, api_requirement="^%s" % CAP.API_VERSION,
             required=(), optional=()):
        """Bring one mod up.

        *entry_point* is the mod's own code: called with its ModContext, and
        anything it raises puts the mod in FAILED with its resources released.
        """
        if self._shutting_down:
            raise E.PlatformError(E.SUB_PLATFORM, E.E_SHUTTING_DOWN,
                                  "the platform is shutting down", mod_id)
        entry = self.record(mod_id)
        if entry.state == LOADED:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_MOD_ALREADY_LOADED,
                                  "%r is already loaded" % mod_id, mod_id)
        if entry.state in (LOADING, UNLOADING):
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_REENTRANT_UNLOAD,
                                  "%r is already %s" % (mod_id, entry.state),
                                  mod_id)

        entry.state = LOADING
        entry.error = None
        owner = ownership.Owner(mod_id)
        entry.owner = owner
        try:
            grant = CAP.negotiate(mod_id, api_requirement, required, optional)
            entry.grant = grant
            logger = modlog.ModLogger(self.log_router, mod_id)
            entry.context = CTX.ModContext(
                owner, logger, grant, self, self.events, self.settings,
                self.input, self.services, self.items_backend)
            if entry_point is not None:
                entry_point(entry.context)
        except E.PlatformError as error:
            return self._fail(entry, error)
        except BaseException as error:                             # noqa: BLE001
            return self._fail(entry, E.PlatformError(
                E.SUB_LIFECYCLE, E.E_LOAD_FAILED,
                "the mod's entry point raised %s: %s"
                % (type(error).__name__, error), mod_id))

        entry.state = LOADED
        self.log.info("loaded %s" % mod_id, mod_id=mod_id)
        self.events.publish_guarded(EV.EVENT_MOD_LOADED, {"mod_id": mod_id})
        return entry.context

    def _fail(self, entry, error):
        """Failure takes the SAME teardown path as a normal unload."""
        entry.error = error
        self.log.platform_error(error)
        try:
            entry.teardown = entry.owner.dispose()
        except E.PlatformError as dispose_error:
            entry.teardown = {"mod_id": entry.mod_id,
                              "dispose_error": dispose_error.as_dict()}
        entry.state = FAILED
        entry.context = None
        self.events.publish_guarded(EV.EVENT_MOD_FAILED,
                                    {"mod_id": entry.mod_id,
                                     "error": error.as_dict()})
        raise error

    # ---- unload ----------------------------------------------------------
    def unload(self, mod_id):
        """Take one mod down and release everything it owns."""
        entry = self.record(mod_id)
        # The re-entrancy guard is checked FIRST, and the order matters for the
        # DIAGNOSTIC rather than for the behaviour. `unload` sets the state to
        # UNLOADING before it announces anything, so a mod that calls unload on
        # itself from inside its own handler would otherwise fail the state test
        # and be told "not loaded" -- which is true in a useless way and sends
        # the author looking for the wrong bug. Re-entrancy is the real reason,
        # so it is the one reported.
        if mod_id in self._unloading:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_REENTRANT_UNLOAD,
                                  "%r is already being unloaded; a mod cannot "
                                  "unload itself from inside its own handler"
                                  % mod_id, mod_id)
        if entry.state not in (LOADED, FAILED):
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_MOD_NOT_LOADED,
                                  "%r is %s, not loaded" % (mod_id, entry.state),
                                  mod_id)
        self._unloading.add(mod_id)
        entry.state = UNLOADING
        try:
            # Announced BEFORE teardown, so a mod that wants to react to a
            # neighbour going away still can. The unloading mod's own handlers
            # are still live at this instant, which is correct: it has not been
            # disposed yet.
            self.events.publish_guarded(EV.EVENT_MOD_UNLOADING,
                                        {"mod_id": mod_id})
            entry.teardown = entry.owner.dispose()
        finally:
            self._unloading.discard(mod_id)
        entry.state = UNLOADED
        entry.context = None
        self.log.info("unloaded %s" % mod_id, mod_id=mod_id,
                      released=len(entry.teardown.get("released", [])))
        self.events.publish_guarded(EV.EVENT_MOD_UNLOADED, {"mod_id": mod_id})
        return entry.teardown

    def shutdown(self):
        """Unload everything, in REVERSE load order.

        Reverse because a mod later in the order may depend on an earlier one --
        the load plan guarantees dependencies load first, so taking them down
        last is the only order that never removes something still in use.
        """
        self._shutting_down = True
        reports = []
        live = [e for e in self._mods.values() if e.state in (LOADED, FAILED)]
        for entry in sorted(live, key=lambda e: -e.load_order_index):
            try:
                reports.append(self.unload(entry.mod_id))
            except E.PlatformError as error:
                reports.append({"mod_id": entry.mod_id,
                                "error": error.as_dict()})
        self._shutting_down = False
        return reports

    # ---- diagnostics -----------------------------------------------------
    def mods(self):
        return [self._mods[m].as_dict()
                for m in sorted(self._mods,
                                key=lambda k: self._mods[k].load_order_index)]

    def diagnostics(self):
        """Everything the developer console needs, in one deterministic shape."""
        states = {}
        for entry in self._mods.values():
            states[entry.state] = states.get(entry.state, 0) + 1
        return {
            "api_version": str(CAP.API_VERSION),
            "capabilities": CAP.describe()["capabilities"],
            "mods": self.mods(),
            "states": {state: states.get(state, 0) for state in STATES},
            "events": self.events.summary(),
            "input": self.input.summary(),
            "services": self.services.summary(),
            "settings": self.settings.summary(),
            "log": {"buffered": len(self.log_router.buffer),
                    "dropped": self.log_router.dropped_total},
            "items_backend_attached": self.items_backend is not None,
        }

    def errors(self):
        """Every structured error the host has recorded, per mod."""
        return [{"mod_id": entry.mod_id, "state": entry.state,
                 "error": entry.error.as_dict()}
                for entry in sorted(self._mods.values(),
                                    key=lambda e: e.load_order_index)
                if entry.error is not None]
