#!/usr/bin/env python3
"""``ModContext`` -- the entire surface one mod is given.

WHY A CONTEXT AND NOT A SET OF GLOBALS
--------------------------------------
Every call a mod makes has to be attributable to that mod, and every resource it
acquires has to be owned by it. A global ``Events.Subscribe(...)`` cannot do
either without the mod telling the framework who it is -- and anything the mod
tells the framework about its own identity is something a buggy or hostile mod
can get wrong. So the framework hands each mod an object that already knows, and
the mod never names itself again.

That is also what makes the C# surface safe later: the managed side hands out one
context per mod, every method on it is pre-bound to an owner, and there is no
static entry point that could be called from the wrong mod's code.

CAPABILITY CHECKS ARE ON THE ACCESSOR, NOT ON EVERY CALL
--------------------------------------------------------
Asking for ``ctx.Events`` when ``core.events`` was not granted fails there, once,
with a structured error naming the capability. Checking on every individual call
would be the same answer arrived at more slowly and in a worse place -- halfway
through a mod's initialisation instead of at the first line that needed it.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import capabilities as CAP                                         # noqa: E402
import errors as E                                                 # noqa: E402


class EventsFacade(object):
    """Events, pre-bound to one owner."""

    __slots__ = ("_bus", "_owner")

    def __init__(self, bus, owner):
        self._bus, self._owner = bus, owner

    def declare(self, name, detail=None):
        return self._bus.declare(self._owner, name, detail)

    def subscribe(self, name, handler):
        return self._bus.subscribe(self._owner, name, handler)

    def publish(self, name, payload=None):
        return self._bus.publish_guarded(name, payload, source=self._owner.mod_id)

    def declared(self):
        return self._bus.declared()


class SettingsFacade(object):
    __slots__ = ("_store", "_owner")

    def __init__(self, store, owner):
        self._store, self._owner = store, owner

    def declare(self, definitions):
        return self._store.declare(self._owner, definitions)

    def get(self, key):
        return self._store.get(self._owner.mod_id, key)

    def set(self, key, value):
        return self._store.set(self._owner.mod_id, key, value)

    def all(self):
        return self._store.all_for(self._owner.mod_id)

    def save(self):
        return self._store.save(self._owner.mod_id)


class InputFacade(object):
    __slots__ = ("_registry", "_owner")

    def __init__(self, registry, owner):
        self._registry, self._owner = registry, owner

    def register(self, name, display_name, suggested_binding=None, handler=None):
        return self._registry.register(self._owner, name, display_name,
                                       suggested_binding, handler)

    def actions(self):
        return self._registry.actions()


class ServicesFacade(object):
    __slots__ = ("_registry", "_owner")

    def __init__(self, registry, owner):
        self._registry, self._owner = registry, owner

    def publish(self, name, version, methods):
        return self._registry.publish(self._owner, name, version, methods)

    def bind(self, name, requirement=">=0.0.0"):
        return self._registry.bind(self._owner, name, requirement)

    def published(self):
        return self._registry.published()


class ItemsFacade(object):
    """Item registration, scoped to the mod's own namespace.

    The backend is injected rather than imported. The platform must be testable
    with no game attached, and the real backend is the Stage 2 live session --
    which needs MISERY running. Injection is also what stops this package
    acquiring a dependency on the research instruments.
    """

    __slots__ = ("_backend", "_owner", "_registered")

    def __init__(self, backend, owner):
        self._backend, self._owner = backend, owner
        self._registered = []

    def _require_backend(self):
        if self._backend is None:
            raise E.PlatformError(
                E.SUB_ITEMS, E.E_NOT_FOUND,
                "no items backend is attached to this platform instance; item "
                "registration needs the live game", self._owner.mod_id)
        return self._backend

    def register(self, declaration):
        """Register one item. ``mod_id`` comes from the owner, never the caller."""
        backend = self._require_backend()
        payload = dict(declaration)
        if "mod_id" in payload and payload["mod_id"] != self._owner.mod_id:
            raise E.PlatformError(
                E.SUB_ITEMS, E.E_INVALID_ARGUMENT,
                "an item declaration may not name a mod_id other than its "
                "owner's", self._owner.mod_id)
        payload["mod_id"] = self._owner.mod_id
        row_name = backend.register(self._owner.mod_id, payload)
        self._registered.append(row_name)

        def release():
            backend.unregister(self._owner.mod_id, row_name)
            if row_name in self._registered:
                self._registered.remove(row_name)

        self._owner.own("item", row_name, release,
                        payload.get("display_name"))
        return row_name

    def registered(self):
        return list(self._registered)


class ModContext(object):
    """One mod's whole view of the framework.

    Deliberately small. Everything reachable from here is either the mod's own
    identity, its own log, or a facade already bound to its owner.
    """

    __slots__ = ("mod_id", "log", "grant", "_owner", "_platform",
                 "_events", "_settings", "_input", "_services", "_items")

    def __init__(self, owner, logger, grant, platform, bus, settings_store,
                 input_registry, service_registry, items_backend):
        self.mod_id = owner.mod_id
        self.log = logger
        self.grant = grant
        self._owner = owner
        self._platform = platform
        self._events = EventsFacade(bus, owner)
        self._settings = SettingsFacade(settings_store, owner)
        self._input = InputFacade(input_registry, owner)
        self._services = ServicesFacade(service_registry, owner)
        self._items = ItemsFacade(items_backend, owner)

    def _gated(self, capability, facade):
        self.grant.require(capability)
        if not self._owner.alive:
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_OWNER_DISPOSED,
                                  "the mod context is no longer usable",
                                  self.mod_id)
        return facade

    @property
    def events(self):
        return self._gated(CAP.CAP_EVENTS, self._events)

    @property
    def settings(self):
        return self._gated(CAP.CAP_SETTINGS, self._settings)

    @property
    def input(self):
        return self._gated(CAP.CAP_INPUT_REGISTRY, self._input)

    @property
    def services(self):
        return self._gated(CAP.CAP_SERVICES, self._services)

    @property
    def items(self):
        return self._gated(CAP.CAP_ITEMS, self._items)

    @property
    def alive(self):
        return self._owner.alive

    def owned(self):
        """What this mod currently holds. The console's per-mod answer."""
        return self._owner.owned_summary()

    def __repr__(self):
        return "ModContext(%s%s)" % (self.mod_id,
                                     "" if self.alive else " DISPOSED")
