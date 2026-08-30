#!/usr/bin/env python3
"""Adapts the Stage 2 live Items session to the platform's items backend.

WHY THIS IS AN ADAPTER AND NOT A DEPENDENCY
-------------------------------------------
``tools/modplatform`` must be testable with no game, no Unreal and no research
instruments -- that is most of what makes the platform's guarantees checkable at
all. So the platform declares what it needs of an items backend (two methods)
and never imports one. This file is where the real backend gets plugged in, and
it lives on the research side because that is where the live session lives.

THE CONTRACT
------------
    register(mod_id, declaration) -> row_name
    unregister(mod_id, row_name)  -> None

``mod_id`` is passed separately and is the authority. The declaration's own
``mod_id`` has already been forced to match by the platform's ItemsFacade; this
layer asserts it again rather than trusting that, because an adapter that
assumes its caller validated is an adapter that stops being safe the day
somebody calls it from somewhere else.
"""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import definition as ItemsAPI                    # noqa: E402
import errors as E                               # noqa: E402
import materializer                              # noqa: E402
import modid                                     # noqa: E402

WORLD_ITEM_CLASS = "BP_StaticMasterItem_C"


class SessionItemsBackend(object):
    """Registers platform item declarations through the proven Stage 2 path.

    Every registration goes through ``ItemDefinition`` -> ``materializer`` ->
    the live ``AggregateSession``, which is exactly the path that passed Stage 2
    and Stage 3. Nothing here reaches the game any other way.
    """

    def __init__(self, session, world_class=WORLD_ITEM_CLASS):
        self.session = session
        self.world_class = world_class
        self._flat = {}          # row_name -> the flattened spec, for unregister
        self.registered = []
        self.unregistered = []

    def _definition(self, mod_id, declaration):
        modid.check(mod_id)
        declared = declaration.get("mod_id")
        if declared is not None and declared != mod_id:
            raise E.PlatformError(
                E.SUB_ITEMS, E.E_INVALID_ARGUMENT,
                "declaration names mod_id %r but is being registered for %r"
                % (declared, mod_id), mod_id)
        return ItemsAPI.ItemDefinition(
            ItemsAPI.ItemId(mod_id, declaration["local_id"]),
            display_name=declaration["display_name"],
            short_name=declaration["short_name"],
            description=declaration["description"],
            weight=declaration["weight"],
            width=declaration.get("width", 1),
            height=declaration.get("height", 1),
            inventory_icon=ItemsAPI.AssetRef(declaration["icon"]),
            world_mesh=ItemsAPI.AssetRef(declaration["mesh"]),
            world_class=declaration.get("world_class") or self.world_class,
            transform=ItemsAPI.Transform(
                translation=tuple(declaration.get("translation") or (0.0, 0.0, 5.0))))

    def register(self, mod_id, declaration):
        definition = self._definition(mod_id, declaration)
        flat = materializer.flatten(definition)
        result = self.session.register(flat)
        if not result.get("ok"):
            raise E.PlatformError(
                E.SUB_ITEMS, E.E_INVALID_ARGUMENT,
                "the items session refused %r: %s (%s)"
                % (definition.row_name, result.get("code"), result.get("detail")),
                mod_id)
        self._flat[definition.row_name] = flat
        self.registered.append(definition.row_name)
        return definition.row_name

    def unregister(self, mod_id, row_name):
        flat = self._flat.get(row_name)
        if flat is None:
            raise E.PlatformError(E.SUB_ITEMS, E.E_NOT_FOUND,
                                  "%r was not registered through this backend"
                                  % row_name, mod_id)
        result = self.session.unregister(flat)
        if not result.get("ok"):
            raise E.PlatformError(
                E.SUB_ITEMS, E.E_NOT_OWNED,
                "the items session refused to unregister %r: %s (%s)"
                % (row_name, result.get("code"), result.get("detail")), mod_id)
        self._flat.pop(row_name, None)
        self.unregistered.append(row_name)
        return None

    def live_rows(self):
        return sorted(self.session.table_rows())

    def summary(self):
        return {"registered": list(self.registered),
                "unregistered": list(self.unregistered),
                "held": sorted(self._flat)}


class RecordingItemsBackend(object):
    """A backend that records instead of touching the game.

    For proving the platform's ownership semantics without MISERY running. It is
    NOT a mock of convenience: the live acceptance uses the real one, and this
    exists so the OFFLINE tests can assert that unload releases items at all.
    """

    def __init__(self):
        self.rows = {}
        self.calls = []

    def register(self, mod_id, declaration):
        row_name = modid.row_name(mod_id, declaration["local_id"])
        if row_name in self.rows:
            raise E.PlatformError(E.SUB_ITEMS, E.E_ALREADY_EXISTS,
                                  "%r is already registered" % row_name, mod_id)
        self.rows[row_name] = dict(declaration)
        self.calls.append(("register", row_name))
        return row_name

    def unregister(self, mod_id, row_name):
        if row_name not in self.rows:
            raise E.PlatformError(E.SUB_ITEMS, E.E_NOT_FOUND,
                                  "%r is not registered" % row_name, mod_id)
        del self.rows[row_name]
        self.calls.append(("unregister", row_name))
        return None
