#!/usr/bin/env python3
"""``Misery.Items`` -- Register / Unregister / Find.

The public surface a mod uses. It owns POLICY: identity, namespacing, collision
arbitration, duplicate handling, registration bookkeeping and the ownership
lifetime of referenced content. It owns no MECHANISM: everything that touches
the running game goes through a ``Materializer``, which is build-specific and
replaceable, and which this module only ever talks to through the protocol at
the bottom of this file.

That split is the whole point of the stage. ``S_ItemDetails`` changes shape
between game builds; ``ItemDefinition`` must not. Keeping the policy here and
the game contact there is what lets the second sentence stay true.

THERE IS NOTHING RADIO-SPECIFIC IN THIS FILE, and there must never be. The radio
is one definition among others, authored the same way any mod would author one
-- see ``examples.py``. If something here ever needs to know about a radio, the
abstraction has failed and the fix is here, not a special case.

WHAT "NEVER SHADOW A VANILLA ID" MEANS HERE
-------------------------------------------
It is true by construction, not by vigilance. Every mod row name is
``<mod_id>__<local_id>`` and therefore contains ``__``; the derived name is not
authored, so a mod cannot ask for a bare vanilla name. The explicit collision
check below is a second, independent line -- it would catch a vanilla row that
somehow contained ``__``, and it catches mod-vs-mod collisions, which
construction cannot.

Shadowing is technically possible in the engine -- the composite would prefer
whichever parent it consults first -- and is deliberately unused. A collision is
rejected, never resolved by precedence, because silently winning over another
mod's item is worse than refusing to load.
"""
import time

from definition import (DefinitionError, ItemDefinition, ItemId, SEPARATOR)

# --------------------------------------------------------------------------
# Result codes. Structured, never a bare bool and never a prose-only failure.
# --------------------------------------------------------------------------
OK = "ok"
ERR_INVALID_DEFINITION = "invalid_definition"
ERR_ALREADY_REGISTERED = "already_registered"
ERR_COLLIDES_WITH_VANILLA = "collides_with_vanilla"
ERR_COLLIDES_WITH_MOD = "collides_with_mod"
ERR_NOT_REGISTERED = "not_registered"
ERR_BACKEND_UNAVAILABLE = "backend_unavailable"
ERR_MATERIALIZE_FAILED = "materialize_failed"
ERR_RELEASE_FAILED = "release_failed"


class Result(object):
    """The outcome of a registry operation.

    Truthy only on success, so ``if not result:`` is a correct guard -- but the
    code and detail are always present, because a loader needs to distinguish
    "that id is taken by another mod" from "the game refused the write", and
    those demand different responses from a mod author.
    """

    __slots__ = ("code", "item_id", "detail", "data")

    def __init__(self, code, item_id=None, detail=None, data=None):
        self.code = code
        self.item_id = item_id
        self.detail = detail
        self.data = data or {}

    @property
    def ok(self):
        return self.code == OK

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return "Result(%s%s)" % (self.code,
                                 "" if self.item_id is None else ", %r" % self.item_id.row_name)

    def as_dict(self):
        return {"code": self.code, "ok": self.ok,
                "item_id": self.item_id.as_dict() if self.item_id else None,
                "detail": self.detail, "data": self.data}


class Registration(object):
    """One live registration: the definition, and what the runtime owns for it."""

    __slots__ = ("definition", "registered_at", "handle", "content_handles")

    def __init__(self, definition, handle=None, content_handles=None):
        self.definition = definition
        self.registered_at = time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
        self.handle = handle
        self.content_handles = content_handles or {}

    def as_dict(self):
        return {"definition": self.definition.as_dict(),
                "registered_at": self.registered_at,
                "handle": self.handle,
                "content_handles": dict(self.content_handles)}


class Registry(object):
    """Holds registrations and enforces the policy around them.

    A registry is bound to one materializer. It never assumes the materializer
    succeeded: every mutation is applied only after the materializer reports
    success, so a failed registration leaves the registry exactly as it was.
    """

    def __init__(self, materializer):
        self._materializer = materializer
        self._registrations = {}          # ItemId -> Registration

    # ---- queries -----------------------------------------------------------
    def find(self, item_id):
        """The registration for *item_id*, or None.

        Accepts an ItemId or a derived row name, because a caller holding only
        what the game showed it should not have to reconstruct the pair.
        """
        key = self._coerce_id(item_id)
        if key is None:
            return None
        registration = self._registrations.get(key)
        return registration.definition if registration else None

    def registrations(self):
        return {k.row_name: v.as_dict() for k, v in self._registrations.items()}

    def is_registered(self, item_id):
        key = self._coerce_id(item_id)
        return key is not None and key in self._registrations

    @staticmethod
    def _coerce_id(value):
        if isinstance(value, ItemId):
            return value
        if isinstance(value, str):
            return ItemId.parse(value)
        return None

    # ---- register ----------------------------------------------------------
    def register(self, definition):
        """Register one item. Returns a ``Result``; never raises for a policy
        failure, because "this id is taken" is an outcome a loader handles, not
        an exception it should have to catch.
        """
        if not isinstance(definition, ItemDefinition):
            return Result(ERR_INVALID_DEFINITION, None,
                          "register() takes an ItemDefinition; got %s"
                          % type(definition).__name__)
        item_id = definition.item_id

        # DUPLICATE REGISTRATION IS DEFINED, NOT LEFT TO CHANCE. Re-registering
        # a held id is refused rather than silently replacing the previous one:
        # a replace would orphan the previous registration's owned content and
        # leave the game holding a row nobody in the registry claims. A mod that
        # wants to change an item unregisters first, and says so.
        if item_id in self._registrations:
            return Result(ERR_ALREADY_REGISTERED, item_id,
                          "%r is already registered; unregister it first if you mean to "
                          "replace it" % item_id.row_name,
                          {"registered_at": self._registrations[item_id].registered_at})

        existing = self._materializer.existing_row_names()
        if existing is None:
            return Result(ERR_BACKEND_UNAVAILABLE, item_id,
                          "the materializer could not enumerate existing rows, so a "
                          "collision cannot be ruled out. Refusing rather than risking a "
                          "silent overwrite.")
        row_name = definition.row_name
        if row_name in existing:
            # Which KIND of collision matters: a mod author fixes them
            # differently, and conflating them would send them looking in the
            # wrong place.
            if SEPARATOR in row_name and ItemId.parse(row_name):
                claimed_by = ItemId.parse(row_name)
                if claimed_by and claimed_by.mod_id != item_id.mod_id:
                    return Result(ERR_COLLIDES_WITH_MOD, item_id,
                                  "%r is already present and belongs to mod %r"
                                  % (row_name, claimed_by.mod_id))
                return Result(ERR_COLLIDES_WITH_MOD, item_id,
                              "%r is already present in the game's tables, though this "
                              "registry does not own it" % row_name)
            return Result(ERR_COLLIDES_WITH_VANILLA, item_id,
                          "%r collides with an existing non-namespaced row. Shadowing is "
                          "not used as override behaviour: a collision is rejected."
                          % row_name)

        outcome = self._materializer.materialize(definition)
        if not outcome.get("ok"):
            return Result(ERR_MATERIALIZE_FAILED, item_id,
                          outcome.get("detail") or "the materializer refused the write",
                          {k: v for k, v in outcome.items() if k != "ok"})

        self._registrations[item_id] = Registration(
            definition, handle=outcome.get("handle"),
            content_handles=outcome.get("content_handles"))
        return Result(OK, item_id, "registered", {"row_name": row_name,
                                                  "handle": outcome.get("handle")})

    # ---- unregister --------------------------------------------------------
    def unregister(self, item_id):
        """Remove one registration and release everything it owned.

        Idempotence is DEFINED and is not silence: unregistering something that
        is not registered returns ERR_NOT_REGISTERED rather than pretending to
        succeed. A loader tearing down in a loop can ignore that code
        deliberately; one that has lost track of its own state finds out.
        """
        key = self._coerce_id(item_id)
        if key is None:
            return Result(ERR_NOT_REGISTERED, None,
                          "%r is not an item id this registry could own" % (item_id,))
        registration = self._registrations.get(key)
        if registration is None:
            return Result(ERR_NOT_REGISTERED, key,
                          "%r is not registered" % key.row_name)

        outcome = self._materializer.dematerialize(registration)
        if not outcome.get("ok"):
            # The registration is KEPT on failure. Dropping it would leave the
            # game holding a row and rooted content that nothing in the registry
            # any longer claims -- an unreachable leak instead of a reported
            # error.
            return Result(ERR_RELEASE_FAILED, key,
                          outcome.get("detail") or "the materializer could not release it",
                          {"registration_kept": True,
                           **{k: v for k, v in outcome.items() if k != "ok"}})

        del self._registrations[key]
        return Result(OK, key, "unregistered",
                      {k: v for k, v in outcome.items() if k != "ok"})

    def unregister_all(self, mod_id=None):
        """Tear down every registration, or every one belonging to one mod.

        Deterministic order -- by row name -- so two runs of the same teardown
        do the same thing in the same sequence. Failures do not abort the rest;
        each is reported.
        """
        targets = sorted((k for k in self._registrations
                          if mod_id is None or k.mod_id == mod_id),
                         key=lambda k: k.row_name)
        return [self.unregister(k) for k in targets]


class Materializer(object):
    """The build-specific half. This class documents the contract; it does not
    implement it.

    Everything that knows what ``S_ItemDetails`` looks like on a particular game
    build lives behind these three methods, and nothing above this line does.
    """

    def existing_row_names(self):
        """Every row name the game currently resolves, or None if it cannot be
        determined. None must mean "unknown", never "none" -- the registry
        treats it as a refusal to proceed."""
        raise NotImplementedError

    def materialize(self, definition):
        """Write one definition into the running game.

        Returns ``{"ok": bool, "detail": str, "handle": ..., "content_handles": {...}}``.
        Must be all-or-nothing: on failure nothing is left registered, published
        or rooted.
        """
        raise NotImplementedError

    def dematerialize(self, registration):
        """Remove one registration's row and release the content it owned.

        Returns ``{"ok": bool, "detail": str, ...}``.
        """
        raise NotImplementedError
