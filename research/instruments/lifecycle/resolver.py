#!/usr/bin/env python3
"""The semantic lifecycle resolver: M4's deliverable.

Returns the *current* World, GameInstance, LocalPlayer, PlayerController, Pawn
and player-inventory anchor of a live MISERY process, together with the evidence
for each -- and refuses to answer when the evidence disagrees with itself.

WHY IT LOOKS LIKE THIS
----------------------
The census (``census.py``) measured what this build's classes actually declare,
instead of assuming what Unreal usually declares. Two of the assumptions a
reader would most likely have made turned out to be false here:

  * ``UWorld::WorldType`` is NOT a reflected property in this build. The
    obvious "find the world whose WorldType is Game" cannot be written at all.
  * ``ULevel::Actors`` is NOT reflected either, so a level cannot be asked for
    its actors.

What IS reflected is every edge of the ownership chain, so the resolver is built
entirely out of reflected edges and uses no unreflected offset anywhere:

    UGameViewportClient::World          -> the engine's own answer
    UGameViewportClient::GameInstance
    UWorld::OwningGameInstance
    UWorld::AuthorityGameMode
    UGameInstance::LocalPlayers         (TArray)
    UPlayer::PlayerController
    APlayerController::Player
    AController::Pawn
    APlayerController::AcknowledgedPawn
    ULevel::OwningWorld

EVERY OFFSET IS RESOLVED AT CALL TIME from the live ``FProperty`` the engine is
using. There is not one gameplay offset constant in this file, and there must
never be: an address or an offset carried across a process restart is the
failure this project has already been bitten by.

AGREEMENT, NOT PREFERENCE
-------------------------
Each anchor is reached by at least two independent routes and the routes must
agree. (The player-inventory anchor gained its second route only after an
independent verifier pointed out that one route cannot confirm itself.) A single route that happens to be right is indistinguishable from one
that happens to be wrong, and this resolver is supposed to be trustworthy after
a transition -- exactly the moment when a stale or half-built graph looks most
like a healthy one. Disagreement produces ``resolved=False`` with a stated
reason, never a best guess.

IDENTITY IS NOT AN ADDRESS
--------------------------
Every anchor carries an ``identity`` made of its object path and class path.
Addresses are reported for debugging but are meaningless across a restart and
are never used to decide anything across one. Comparing two snapshots compares
identities; comparing addresses is only ever valid inside one process.
"""
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "runner")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                       # noqa: E402
import cr01c3_recon as recon     # noqa: E402
import readiness                 # noqa: E402

PATH_WORLD = "/Script/Engine.World"
PATH_GAME_INSTANCE = "/Script/Engine.GameInstance"
PATH_LOCAL_PLAYER = "/Script/Engine.LocalPlayer"
PATH_PLAYER_CONTROLLER = "/Script/Engine.PlayerController"
PATH_VIEWPORT_CLIENT = "/Script/Engine.GameViewportClient"
PATH_PAWN = "/Script/Engine.Pawn"
PATH_LEVEL = "/Script/Engine.Level"
PATH_ACTOR = "/Script/Engine.Actor"

# The player-owned runtime state this game keeps per player. Named, not
# hardcoded as an offset: it is a MISERY class, so it is looked up by class name
# and then proved to be OWNED BY the controller rather than merely present.
DEFAULT_INVENTORY_CLASS = "BP_PlayerInventory_C"

# --- object liveness and identity, both read from the engine's own fields ---
#
# UObjectBase::ObjectFlags sits at +0x08 (eri's own layout note, cross-confirmed
# there by disassembly). RF_MirroredGarbage is documented in the engine as
# "Garbage from logical point of view and should not be referenced. This flag is
# mirrored in EInternalObjectFlags as Garbage for performance"
# (ObjectMacros.h:576, :583). So garbage can be detected with a direct read on an
# address we already hold -- no GUObjectArray arithmetic required.
#
# This matters because DestroyActor does NOT remove anything from GUObjectArray;
# it marks the object and the slot survives until the next GC. Counting those as
# live is what let "exactly one live PlayerController" be true of a graph holding
# two, one of them destroyed.
UOBJECT_OBJECTFLAGS_OFFSET = 0x08
UOBJECT_INTERNALINDEX_OFFSET = 0x0C          # eri's layout note, +0x0C, twice confirmed
RF_MIRRORED_GARBAGE = 0x40000000             # ObjectMacros.h:576

# FUObjectItem, UObjectArray.h:42-50 -- Object, Flags, ClusterRootIndex,
# SerialNumber, in that order, stride 0x18 (eri.SIZEOF_FUOBJECTITEM).
FUOBJECTITEM_FLAGS_OFFSET = 0x08
FUOBJECTITEM_SERIALNUMBER_OFFSET = 0x10
EINTERNAL_GARBAGE = 1 << 21                  # ObjectMacros.h:616
EINTERNAL_UNREACHABLE = 1 << 28              # ObjectMacros.h:643


class Anchor(dict):
    """One resolved object: what it is, how it was reached, and whether the
    independent routes to it agreed."""


def _agree(answers, label):
    """Decide one anchor from several route answers.

    *answers* is a list of ``(evidence, value)``. ``evidence["resolved"]`` says
    whether that route could be READ at all, which is a different thing from
    what it read. That distinction is the whole point of this function.

    THE BUG THIS EXISTS TO PREVENT, found live on MISERY's death screen:
    the previous code did ``[x for x in (a, b) if x]`` and then asked whether
    the surviving candidates were all equal. On the death screen
    ``AController::Pawn`` is null while ``AcknowledgedPawn`` still names the
    corpse, so the null was FILTERED OUT and the single survivor trivially
    "agreed" with itself. The resolver then reported a possessed pawn for a
    controller that had already un-possessed it -- while its own cross-check
    said the pawn did not point back. Two routes cannot agree if one of them
    was thrown away.

    A route that resolved and returned null has given a real answer -- null --
    and null disagrees with a pointer. So nulls are kept and compared.
    """
    answered = [(ev, v) for ev, v in answers if (ev or {}).get("resolved")]
    if not answered:
        return None, False, ("no route to %s could be read on this class" % label)
    values = {v for _ev, v in answered}
    if len(values) != 1:
        detail = ", ".join("%s=%s" % ((ev or {}).get("property", "?"),
                                      ("0x%x" % v) if v else "null")
                           for ev, v in answered)
        return None, False, ("the routes to %s disagree (%s) -- refusing to pick one; a null "
                             "from a route that WAS readable is an answer, not an absence"
                             % (label, detail))
    only = values.pop()
    if not only:
        return None, False, ("every route that could be read returned null for %s" % label)
    return only, True, None


def _anchor(address, objects, eri_mod, *, routes, agreed, why=None, extra=None,
            identity=None):
    record = objects.get(address) or {}
    class_ptr = record.get("class_ptr")
    class_record = objects.get(class_ptr or 0) or {}

    def path_of(a):
        if not a:
            return None
        try:
            return eri_mod.canonicalize_object_path(
                eri_mod.resolve_object_path(a, objects).get("object_path"))
        except Exception:                                      # noqa: BLE001
            return None

    # F2, from the red team: the object graph is walked over ~10 seconds and is
    # NOT atomic, while the property reads that follow happen after it. An
    # object created during or after the walk is simply absent from `objects`,
    # and the previous code happily reported it as resolved with a null name,
    # null class and null object_path -- which the survival table then consumed
    # as an identity. An address the walk never saw is not a resolution; it is
    # proof the snapshot is torn.
    record_missing = bool(address) and not (objects.get(address) or {}).get("valid")
    if record_missing:
        agreed = False
        why = ("the agreed pointer 0x%x names an object that is absent from (or invalid in) "
               "the walked universe: this snapshot is torn -- the graph walk and the property "
               "reads did not see the same moment" % address)
        address = None

    out = Anchor({
        "resolved": bool(address) and agreed,
        "address": ("0x%x" % address) if address else None,
        "name": record.get("name_text"),
        "class": class_record.get("name_text"),
        # identity is what survives comparison across a restart; address is not
        "identity": {"object_path": path_of(address), "class_path": path_of(class_ptr),
                     "engine_identity": identity},
        "routes": routes,
        "routes_agreed": agreed,
    })
    if why:
        out["why"] = why
    if extra:
        out.update(extra)
    return out


class Resolver(object):
    """Resolves the lifecycle chain against ONE live process snapshot.

    A Resolver instance is valid only for the process and the object-graph
    snapshot it was constructed with. It deliberately holds no state that could
    outlive a restart -- construct a new one after every transition.
    """

    def __init__(self, api, handle, base_address, image_size, *,
                 inventory_class=DEFAULT_INVENTORY_CLASS):
        self.api = api
        self.handle = handle
        self.inventory_class = inventory_class
        self.namepool, self.objects, meta = recon.universe(
            api, handle, base_address, image_size, with_meta=True)
        self.objects_ptr = meta["objects_ptr"]
        self._identity_cache = {}
        self._ancestor_cache = {}
        self._prop_cache = {}

    # ---- small helpers ---------------------------------------------------
    def name_of(self, a):
        return (self.objects.get(a) or {}).get("name_text") if a else None

    def class_of(self, a):
        return (self.objects.get(a) or {}).get("class_ptr") if a else None

    def class_name_of(self, a):
        return self.name_of(self.class_of(a))

    def path_of(self, a):
        if not a:
            return None
        try:
            return eri.canonicalize_object_path(
                eri.resolve_object_path(a, self.objects).get("object_path"))
        except Exception:                                      # noqa: BLE001
            return None

    def is_cdo(self, a):
        return (self.name_of(a) or "").startswith("Default__")

    def outer_of(self, a):
        return eri._read_u64(self.api, self.handle,
                             a + eri.DEFAULT_OUTER_PRIVATE_OFFSET) if a else 0

    def derives_from(self, address, wanted_path):
        cls = self.class_of(address)
        if not cls:
            return False
        return wanted_path in readiness.ancestor_paths(
            eri, self.api, self.handle, cls, self.objects, self._ancestor_cache)

    def instances_of(self, wanted_path, _excluded=None):
        """Live, non-CDO, NON-GARBAGE instances deriving from *wanted_path*.

        The garbage exclusion is the point. Without it this counted objects the
        engine had already destroyed, which is how "exactly one live
        PlayerController" could be true of a graph containing two.
        """
        out = []
        for address, record in self.objects.items():
            if not record.get("valid") or not record.get("class_ptr"):
                continue
            if self.is_cdo(address):
                continue
            if not self.derives_from(address, wanted_path):
                continue
            if self.is_garbage(address):
                if _excluded is not None:
                    _excluded.append(address)
                continue
            out.append(address)
        return out

    def prop(self, address, name, *, expect_class=None, expect_size=None):
        """Resolve *name* on the live class of *address* BY REFLECTION.

        Returns the FProperty record, or None. The type is checked when the
        caller says what it expects: a property that resolved to the wrong kind
        is a different build, not a usable offset.
        """
        cls = self.class_of(address)
        if not cls:
            return None
        key = (cls, name)
        if key not in self._prop_cache:
            self._prop_cache[key] = readiness.resolve_property(
                eri, self.api, self.handle, cls, self.objects, self.namepool, (name,))
        found = self._prop_cache[key]
        if not found:
            return None
        if expect_class and found.get("property_class") != expect_class:
            return None
        if expect_size is not None and found.get("size") != expect_size:
            return None
        return found

    def read_object_prop(self, address, name):
        """Follow a reflected FObjectProperty edge. Returns (value, evidence)."""
        found = self.prop(address, name, expect_class="FObjectProperty", expect_size=8)
        if not found:
            return None, {"property": name, "resolved": False,
                          "why": "not declared as an 8-byte FObjectProperty on this class"}
        try:
            value = eri._read_u64(self.api, self.handle, address + int(found["offset"]))
        except Exception as exc:                               # noqa: BLE001
            return None, {"property": name, "resolved": False, "why": repr(exc)}
        return (value or None), {"property": name, "resolved": True,
                                 "offset": found["offset"],
                                 "declared_on": found["declared_on"],
                                 "value": ("0x%x" % value) if value else None,
                                 "value_name": self.name_of(value)}

    def read_array_prop(self, address, name, cap=256):
        found = self.prop(address, name, expect_class="FArrayProperty")
        if not found:
            return [], {"property": name, "resolved": False,
                        "why": "not declared as an FArrayProperty on this class"}
        base = address + int(found["offset"])
        try:
            data = eri._read_u64(self.api, self.handle, base)
            num = struct.unpack("<i", self.api.read_process_memory(self.handle, base + 8, 4))[0]
        except Exception as exc:                               # noqa: BLE001
            return [], {"property": name, "resolved": False, "why": repr(exc)}
        if not data or num <= 0 or num > cap:
            return [], {"property": name, "resolved": True, "offset": found["offset"],
                        "num": num, "elements": []}
        raw = self.api.read_process_memory(self.handle, data, num * 8)
        elements = list(struct.unpack("<%dQ" % num, raw))
        return elements, {"property": name, "resolved": True, "offset": found["offset"],
                          "declared_on": found["declared_on"], "num": num,
                          "elements": ["0x%x" % e for e in elements]}

    # ---- the chain -------------------------------------------------------
    def is_garbage(self, address):
        """Has this object been destroyed but not yet collected?

        DestroyActor only marks; the object stays in GUObjectArray until the
        next GC. Read via RF_MirroredGarbage on UObjectBase::ObjectFlags, which
        the engine keeps mirrored from the internal flag precisely so it can be
        tested without touching FUObjectItem (ObjectMacros.h:576).
        """
        if not address:
            return False
        try:
            flags = eri._read_u32(self.api, self.handle,
                                  address + UOBJECT_OBJECTFLAGS_OFFSET)
        except Exception:                                      # noqa: BLE001
            return False
        return bool(flags & RF_MIRRORED_GARBAGE)

    def identity_of(self, address):
        """(InternalIndex, SerialNumber) -- the engine's own object identity.

        This is what FWeakObjectPtr uses to answer "is this still the same
        object?", and it is the honest replacement for comparing addresses: an
        address can be handed back by the allocator for a different object of
        the same size class, and then a recreated object is indistinguishable
        from a survivor.

        SELF-CHECKED, not assumed. InternalIndex is read from the object, used
        to locate its FUObjectItem, and the item's Object pointer must point
        back at the object we started from. If that round trip does not close,
        the offsets are wrong for this build and this returns None rather than a
        number that looks like an answer.
        """
        if not address:
            return None
        if address in self._identity_cache:
            return self._identity_cache[address]
        result = None
        try:
            index = eri._read_i32(self.api, self.handle,
                                  address + UOBJECT_INTERNALINDEX_OFFSET)
            if index is not None and 0 <= index < (1 << 26):
                chunk = eri._read_u64(self.api, self.handle,
                                      self.objects_ptr + (index >> 16) * 8)
                if chunk:
                    item = chunk + (index & 0xFFFF) * eri.SIZEOF_FUOBJECTITEM
                    back = eri._read_u64(self.api, self.handle,
                                         item + eri.FUOBJECTITEM_OFFSET_OBJECT)
                    if back == address:                        # the round trip closed
                        result = {
                            "internal_index": index,
                            "serial_number": eri._read_i32(
                                self.api, self.handle,
                                item + FUOBJECTITEM_SERIALNUMBER_OFFSET),
                            "internal_flags": "0x%x" % eri._read_u32(
                                self.api, self.handle, item + FUOBJECTITEM_FLAGS_OFFSET),
                            "round_trip_verified": True}
        except Exception:                                      # noqa: BLE001
            result = None
        self._identity_cache[address] = result
        return result

    def _object_properties_pointing_at(self, owner, target):
        """Which reflected FObjectProperties of *owner* currently hold *target*.

        Used as a genuinely independent second route: the first route finds a
        component by scanning for Outer == owner, this one asks the owner's own
        class what it declares and what those declarations currently point at.
        """
        if not owner or not target:
            return []
        out, cursor, depth = [], self.class_of(owner), 0
        while cursor and depth < 32:
            try:
                child = eri._read_u64(self.api, self.handle,
                                      cursor + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
                walked = eri.walk_property_chain(
                    self.api, self.handle, child, namepool_live_va=self.namepool,
                    owner_address=cursor, objects_by_address=self.objects)
            except Exception:                                  # noqa: BLE001
                walked = {"accepted": []}
            for prop in walked.get("accepted", []):
                if prop.get("property_class") != "FObjectProperty" or prop.get("size") != 8:
                    continue
                try:
                    if eri._read_u64(self.api, self.handle,
                                     owner + int(prop["offset"])) == target:
                        out.append({"name": prop.get("raw_name"),
                                    "offset": prop.get("offset"),
                                    "declared_on": self.name_of(cursor)})
                except Exception:                              # noqa: BLE001
                    continue
            cursor = eri._read_u64(self.api, self.handle,
                                   cursor + readiness.USTRUCT_SUPER_STRUCT_OFFSET)
            depth += 1
        return out

    def verify_tarray_layout(self, world):
        """Self-check the ONE container-layout constant this file relies on.

        Reading a TArray uses Data at +0 and ArrayNum as int32 at +8. That is
        engine container layout, not a reflected offset and not a UObjectBase
        field -- so it is the single structural assumption here that reflection
        cannot derive. Rather than assert it, prove it against this build:
        UWorld::Levels is an FArrayProperty that must contain UWorld's own
        PersistentLevel (UWorld::InitWorld, World.cpp:2067). If the layout were
        wrong, the count would be nonsense and PersistentLevel would not be in
        the decoded elements.
        """
        pl, _ev = self.read_object_prop(world, "PersistentLevel")
        levels, ev = self.read_array_prop(world, "Levels")
        ok = bool(pl) and bool(levels) and pl in levels
        return {"checked": "UWorld::Levels must contain UWorld::PersistentLevel",
                "citation": "UWorld::InitWorld, Private/World.cpp:2067",
                "persistent_level": ("0x%x" % pl) if pl else None,
                "levels_decoded": ev.get("num"),
                "persistent_level_is_among_them": ok,
                "verdict": "the TArray layout (Data@+0, ArrayNum:int32@+8) is CONFIRMED against "
                           "this build" if ok else
                           "the TArray layout could NOT be confirmed -- array reads are not "
                           "trustworthy on this build"}

    def resolve(self):
        """Resolve the whole chain. Never raises; every failure is explained."""
        snap = {"anchors": {}, "cross_checks": [], "notes": []}

        # -- identity anchor: the snapshot is a UE object graph at all ------
        selfref = [a for a, r in self.objects.items()
                   if r.get("valid") and r.get("name_text") == eri.UCLASS_SELF_REFERENCE_NAME
                   and r.get("class_ptr") == a]
        # F10, from the red team: this test exercised ClassPrivate and
        # NamePrivate only. ERI's own version additionally requires the object
        # PATH to be /Script/CoreUObject.Class, and the path is built by walking
        # OuterPrivate -- which makes it the one live check that would fail loudly
        # if UE_STORE_OBJECT_LIST_INTERNAL_INDEX were compiled on and shifted
        # OuterPrivate from 0x20 to 0x28. Without it, this file's whole
        # Outer-based reasoning rested on an unverified constant.
        anchor_path = self.path_of(selfref[0]) if len(selfref) == 1 else None
        snap["object_graph_trusted"] = (len(selfref) == 1
                                        and anchor_path == eri.UCLASS_SELF_REFERENCE_OBJECT_PATH)
        snap["object_graph_anchor_path"] = anchor_path
        snap["objects_total"] = len(self.objects)
        if not snap["object_graph_trusted"]:
            snap["why_not"] = (
                "the object-identity anchor did not hold: %d self-referential UClass objects, "
                "and its object path resolved to %r rather than %r. Either the graph is not a "
                "UE object graph, or OuterPrivate is not where this build puts it -- and every "
                "Outer-based conclusion below would be unsound. Refusing."
                % (len(selfref), anchor_path, eri.UCLASS_SELF_REFERENCE_OBJECT_PATH))
            return snap

        # Garbage exclusions are REPORTED, not silently applied: "I ignored two
        # destroyed controllers" is a materially different statement from "there
        # was one controller", and only one of them is true.
        garbage_excluded = []
        snap["garbage_excluded"] = garbage_excluded

        # -- the viewport client: the engine's own opinion -------------------
        viewports = self.instances_of(PATH_VIEWPORT_CLIENT, garbage_excluded)
        viewport = viewports[0] if len(viewports) == 1 else None
        snap["notes"].append("live GameViewportClient instances: %d" % len(viewports))

        # -- route A to the World: the viewport client -----------------------
        world_routes = []
        world_a = world_a_ev = None
        if viewport:
            world_a, world_a_ev = self.read_object_prop(viewport, "World")
            world_routes.append({"route": "GameViewportClient::World", "evidence": world_a_ev,
                                 "world": ("0x%x" % world_a) if world_a else None})
        else:
            world_routes.append({"route": "GameViewportClient::World", "evidence": None,
                                 "why": "no unique live GameViewportClient"})

        # -- route B: the only World that owns a GameInstance ----------------
        # WorldType is not reflected in this build, so "the world the engine is
        # actually running" has to come from a reflected edge instead. A world
        # that is merely loaded for streaming has OwningGameInstance null.
        worlds = self.instances_of(PATH_WORLD, garbage_excluded)
        owning = []
        for w in worlds:
            gi, _ev = self.read_object_prop(w, "OwningGameInstance")
            if gi:
                owning.append((w, gi))
        world_b = owning[0][0] if len(owning) == 1 else None
        world_routes.append({
            "route": "the unique UWorld whose OwningGameInstance is non-null",
            "worlds_live": len(worlds),
            "worlds_with_owning_game_instance": len(owning),
            "world": ("0x%x" % world_b) if world_b else None,
            "why": None if world_b else
                   ("expected exactly one world owning a GameInstance, found %d" % len(owning))})

        # -- route C: up from the PlayerController through its Level ---------
        controllers = self.instances_of(PATH_PLAYER_CONTROLLER, garbage_excluded)
        controller = controllers[0] if len(controllers) == 1 else None
        world_c = world_c_ev = None
        if controller:
            # An AActor's Outer is its ULevel; ULevel::OwningWorld is reflected.
            # This never touches an unreflected member: the Outer pointer is a
            # UObjectBase field ERI already resolves structurally.
            level = self.outer_of(controller)
            if level and self.derives_from(level, PATH_LEVEL):
                world_c, world_c_ev = self.read_object_prop(level, "OwningWorld")
                world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                              "ULevel::OwningWorld",
                                     "level": "0x%x" % level, "evidence": world_c_ev,
                                     "world": ("0x%x" % world_c) if world_c else None})
            else:
                world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                              "ULevel::OwningWorld",
                                     "why": "the controller's Outer is not a ULevel"})
        else:
            world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                          "ULevel::OwningWorld",
                                 "why": "no unique live PlayerController"})

        # -- route E: the engine's OWN test for a streaming sub-world --------
        # UWorld::IsStreamingSubWorld is written in the engine as
        #     PersistentLevel && PersistentLevel->OwningWorld != this
        # (World.cpp:5357). Both members are reflected, so the same test can be
        # run from outside. This is the discriminator that separates a real
        # top-level world from the vestigial worlds that streamed sub-levels
        # leave in the object graph -- of which this game has many.
        top_level = []
        for w in worlds:
            pl, _ev = self.read_object_prop(w, "PersistentLevel")
            if not pl:
                continue
            ow, _ev2 = self.read_object_prop(pl, "OwningWorld")
            if ow == w:
                top_level.append(w)
        world_routes.append({
            "route": "the engine's own streaming-sub-world test: "
                     "PersistentLevel->OwningWorld == self  (UWorld::IsStreamingSubWorld)",
            "top_level_worlds": len(top_level),
            "of_worlds_live": len(worlds),
            "note": "used as a FILTER, not as a sole route: more than one top-level world "
                    "can exist, so this narrows the field rather than naming the answer"})

        # -- route D: the only World with an AuthorityGameMode ---------------
        # Restricted to top-level worlds on purpose. It also disarms a trap the
        # engine sets for us: UGameInstance::InitializeStandalone builds a dummy
        # EWorldType::Game world BEFORE any map is loaded (GameInstance.cpp:189)
        # -- one with no GameMode and an empty PersistentLevel. Requiring an
        # AuthorityGameMode is exactly what filters that world out.
        with_gm = []
        for w in (top_level or worlds):
            gm, _ev = self.read_object_prop(w, "AuthorityGameMode")
            if gm:
                with_gm.append(w)
        world_d = with_gm[0] if len(with_gm) == 1 else None
        world_routes.append({
            "route": "the unique top-level UWorld whose AuthorityGameMode is non-null",
            "worlds_with_authority_game_mode": len(with_gm),
            "world": ("0x%x" % world_d) if world_d else None,
            "what_this_route_can_and_cannot_do":
                "it CONTRIBUTES an answer; it cannot VETO one. A route that finds nothing "
                "abstains, so during UGameInstance::InitializeStandalone (GameInstance.cpp:189) "
                "the dummy pre-map world is still named by routes A and B and this route merely "
                "stays silent. An earlier comment here claimed it 'filters that world out', "
                "which was wrong -- no route in this resolver has veto power."})

        # A DIRECT READ and a SEARCH are different kinds of answer, and the
        # earlier code conflated them by filtering every falsy value out.
        #
        #   Routes A and C are direct FProperty reads. A read that succeeds and
        #   yields null has ANSWERED -- "there is no world here" -- and that
        #   answer disagrees with a pointer. Dropping it is the exact bug the
        #   death screen exposed on the Pawn, left sitting in the anchor every
        #   other anchor hangs off.
        #
        #   Routes B, D and E are searches over the object graph. A search that
        #   finds nothing has NOT answered; it has failed to find. Those are
        #   correctly contributed only when they identify exactly one world.
        world_answers = []
        for ev, value, label in ((world_a_ev, world_a, "GameViewportClient::World"),
                                 (world_c_ev, world_c, "ULevel::OwningWorld")):
            if ev is not None:
                world_answers.append((ev, value))
        for value, label in ((world_b, "the unique world owning a GameInstance"),
                             (world_d, "the unique top-level world with an AuthorityGameMode")):
            if value:
                world_answers.append(({"resolved": True, "property": label}, value))
        world, agreed, world_why = _agree(world_answers, "the active World")
        if agreed and not self.derives_from(world, PATH_WORLD):
            world, agreed, world_why = None, False, (
                "the agreed world pointer does not name a live UWorld")
        candidates = [w for w in (world_a, world_b, world_c, world_d) if w]
        snap["anchors"]["world"] = _anchor(
            world, self.objects, eri, identity=self.identity_of(world), routes=world_routes, agreed=agreed, why=world_why,
            extra={"worlds_live": len(worlds),
                   "top_level_worlds": len(top_level),
                   "world_names": sorted({self.name_of(w) for w in worlds})})

        # -- GameInstance ----------------------------------------------------
        gi_routes, gi_answers = [], []
        if world:
            v, ev = self.read_object_prop(world, "OwningGameInstance")
            gi_routes.append({"route": "UWorld::OwningGameInstance", "evidence": ev})
            gi_answers.append((ev, v))
        if viewport:
            v, ev = self.read_object_prop(viewport, "GameInstance")
            gi_routes.append({"route": "UGameViewportClient::GameInstance", "evidence": ev})
            gi_answers.append((ev, v))
        live_gis = self.instances_of(PATH_GAME_INSTANCE, garbage_excluded)
        gi_routes.append({"route": "live UGameInstance instances", "count": len(live_gis),
                          "objects": ["0x%x" % a for a in live_gis]})
        game_instance, gi_agreed, gi_why = _agree(gi_answers, "the GameInstance")
        if gi_agreed and not (len(live_gis) == 1 and game_instance == live_gis[0]):
            game_instance, gi_agreed, gi_why = None, False, (
                "the agreed GameInstance is not the single live UGameInstance (%d live)"
                % len(live_gis))
        snap["anchors"]["game_instance"] = _anchor(
            game_instance, self.objects, eri, identity=self.identity_of(game_instance), routes=gi_routes, agreed=gi_agreed, why=gi_why)

        # -- LocalPlayer -----------------------------------------------------
        lp_routes, lp_answers = [], []
        if game_instance:
            players, ev = self.read_array_prop(game_instance, "LocalPlayers")
            lp_routes.append({"route": "UGameInstance::LocalPlayers", "evidence": ev})
            if len(players) == 1:
                lp_answers.append((ev, players[0]))
            elif ev.get("resolved") and len(players) == 0:
                # An array that WAS readable and is empty has answered: there is
                # no local player. That is not the same as being unable to read
                # it, and dropping it let the one remaining route agree with
                # itself.
                lp_answers.append((ev, None))
                lp_routes[-1]["why"] = "LocalPlayers is readable and EMPTY: there is no local player"
            else:
                lp_routes[-1]["why"] = ("expected exactly one local player, found %d -- "
                                        "splitscreen is not handled and is not guessed at"
                                        % len(players))
        if controller:
            v, ev = self.read_object_prop(controller, "Player")
            lp_routes.append({"route": "APlayerController::Player", "evidence": ev})
            lp_answers.append((ev, v))
        live_lps = self.instances_of(PATH_LOCAL_PLAYER, garbage_excluded)
        lp_routes.append({"route": "live ULocalPlayer instances", "count": len(live_lps)})
        local_player, lp_agreed, lp_why = _agree(lp_answers, "the LocalPlayer")
        if lp_agreed and not self.derives_from(local_player, PATH_LOCAL_PLAYER):
            local_player, lp_agreed, lp_why = None, False, (
                "the agreed pointer does not name a live ULocalPlayer")
        snap["anchors"]["local_player"] = _anchor(
            local_player, self.objects, eri, identity=self.identity_of(local_player), routes=lp_routes, agreed=lp_agreed, why=lp_why)

        # -- PlayerController ------------------------------------------------
        pc_routes = [{"route": "live APlayerController instances", "count": len(controllers),
                      "objects": ["0x%x" % a for a in controllers]}]
        pc_b, pc_ev = None, None
        if local_player:
            # The reverse edge. UPlayer::PlayerController is reflected, so the
            # LocalPlayer can be asked who its controller is instead of us
            # assuming the single live controller is the right one.
            pc_b, pc_ev = self.read_object_prop(local_player, "PlayerController")
            pc_routes.append({"route": "UPlayer::PlayerController", "evidence": pc_ev})
        if controller:
            # A reflected boolean that says the controller is the LOCAL one.
            # Recorded rather than gated on: MISERY runs standalone, so it is
            # expected true, and an unexpected value should be visible in the
            # evidence instead of silently failing a resolution that is
            # otherwise cross-checked from both directions.
            flag = self.prop(controller, "bIsLocalPlayerController")
            pc_routes.append({"route": "APlayerController::bIsLocalPlayerController",
                              "resolved": bool(flag),
                              "offset": (flag or {}).get("offset")})
        # F4a, from the red team: `controllers[0] if len(controllers) == 1 else None`
        # made a count of 0 or 2 vanish silently, leaving UPlayer::PlayerController
        # to agree with itself. A count IS an answer about the object graph. Two
        # live PlayerControllers is not hypothetical -- SwapPlayerControllers
        # destroys the old one (GameModeBase.cpp:566-568) and it stays in
        # GUObjectArray until the next GC.
        pc_answers = [({"resolved": True,
                        "property": "live APlayerController count = %d" % len(controllers)},
                       controllers[0] if len(controllers) == 1 else None)]
        if pc_ev is not None:
            pc_answers.append((pc_ev, pc_b))
        player_controller, pc_agreed, pc_why = _agree(pc_answers, "the PlayerController")
        if pc_agreed and not self.derives_from(player_controller, PATH_PLAYER_CONTROLLER):
            player_controller, pc_agreed, pc_why = None, False, (
                "the agreed pointer does not name a live APlayerController")
        snap["anchors"]["player_controller"] = _anchor(
            player_controller, self.objects, eri, identity=self.identity_of(player_controller), routes=pc_routes, agreed=pc_agreed, why=pc_why)

        # -- Pawn -------------------------------------------------------------
        pawn_routes, pawn_answers = [], []
        if player_controller:
            for field, label in (("Pawn", "AController::Pawn"),
                                 ("AcknowledgedPawn", "APlayerController::AcknowledgedPawn")):
                v, ev = self.read_object_prop(player_controller, field)
                pawn_routes.append({"route": label, "evidence": ev})
                pawn_answers.append((ev, v))
        # Disagreement here is meaningful, not pedantic: it means the player is
        # dead, or possession has not settled. MISERY's death screen is exactly
        # this state -- Pawn null, AcknowledgedPawn still naming the corpse.
        pawn, pawn_agreed, pawn_why = _agree(pawn_answers, "the possessed Pawn")
        if pawn_agreed and not (self.derives_from(pawn, PATH_PAWN) and not self.is_cdo(pawn)):
            pawn, pawn_agreed, pawn_why = None, False, (
                "the agreed pawn pointer does not name a live non-CDO Pawn")
        snap["anchors"]["pawn"] = _anchor(
            pawn, self.objects, eri, identity=self.identity_of(pawn), routes=pawn_routes, agreed=pawn_agreed, why=pawn_why)

        # -- the player-owned runtime state anchor ----------------------------
        inv_routes = []
        inventory = None
        if player_controller:
            owned = []
            for address, record in self.objects.items():
                if not record.get("valid"):
                    continue
                if self.class_name_of(address) != self.inventory_class:
                    continue
                if self.is_cdo(address):
                    continue
                if self.outer_of(address) == player_controller:
                    owned.append(address)
            inv_routes.append({"route": "instances of %s whose Outer IS the resolved "
                                        "PlayerController" % self.inventory_class,
                               "count": len(owned),
                               "objects": ["0x%x" % a for a in owned]})
            if len(owned) == 1:
                inventory = owned[0]
            else:
                inv_routes[-1]["why"] = ("expected exactly one player inventory owned by the "
                                         "controller, found %d" % len(owned))
            # Second, independent route: ask the controller's own reflected
            # object properties which one points at that component. The first
            # route is an ownership scan; this one is the controller's own
            # declaration. Added because the verifier correctly pointed out that
            # a single route contradicts this module's stated contract.
            named = self._object_properties_pointing_at(controller, inventory) if inventory \
                else []
            inv_routes.append({"route": "reflected FObjectProperty on the PlayerController "
                                        "whose value IS that component",
                               "properties": named})
            if inventory and not named:
                inventory = None
                inv_routes[-1]["why"] = ("no reflected property on the controller points at the "
                                         "component found by the ownership scan -- one route "
                                         "cannot confirm itself")
        inv_agreed = inventory is not None
        snap["anchors"]["player_inventory"] = _anchor(
            inventory, self.objects, eri, identity=self.identity_of(inventory), routes=inv_routes, agreed=inv_agreed,
            why=None if inv_agreed else
                "no unique player inventory owned by the resolved PlayerController")

        # -- cross-checks that must hold if the chain is really a chain -------
        # F5, from the red team: two of these were the literal constant True.
        # One of them -- "Player and PlayerController are inverses" -- was
        # reporting PASS for a comparison that had not been performed. A check
        # that does not read anything is not a check. Every check below now
        # performs its own read, and a check whose operands are missing is
        # recorded as SKIPPED rather than silently omitted, because
        # all([]) is True and "all cross-checks passed" over nothing is a claim
        # about tests that never ran.
        def check(label, ok, detail):
            snap["cross_checks"].append({"check": label, "pass": bool(ok), "detail": detail})

        def skip(label, why):
            snap["cross_checks_skipped"].append({"check": label, "why": why})

        snap["cross_checks_skipped"] = []

        if pawn and player_controller:
            back, ev = self.read_object_prop(pawn, "Controller")
            check("APawn::Controller points back at the resolved PlayerController",
                  back == player_controller,
                  {"pawn_controller": ("0x%x" % back) if back else None, "evidence": ev})
        else:
            skip("APawn::Controller points back at the resolved PlayerController",
                 "no resolved pawn and/or controller to compare")

        if player_controller and local_player:
            fwd, ev1 = self.read_object_prop(player_controller, "Player")
            back, ev2 = self.read_object_prop(local_player, "PlayerController")
            check("APlayerController::Player and UPlayer::PlayerController are inverses",
                  fwd == local_player and back == player_controller,
                  {"pc_Player": ("0x%x" % fwd) if fwd else None,
                   "lp_PlayerController": ("0x%x" % back) if back else None,
                   "evidence": [ev1, ev2]})
        else:
            skip("APlayerController::Player and UPlayer::PlayerController are inverses",
                 "no resolved controller and/or local player to compare")

        if world and game_instance:
            owning, ev = self.read_object_prop(world, "OwningGameInstance")
            check("the resolved World is the one the resolved GameInstance is bound to",
                  owning == game_instance,
                  {"world_OwningGameInstance": ("0x%x" % owning) if owning else None,
                   "evidence": ev})
        else:
            skip("the resolved World is the one the resolved GameInstance is bound to",
                 "no resolved world and/or game instance to compare")

        if player_controller and world:
            lvl = self.outer_of(player_controller)
            ow, _ev = self.read_object_prop(lvl, "OwningWorld") if lvl else (None, None)
            check("the PlayerController lives in a Level owned by the resolved World",
                  ow == world, {"level": ("0x%x" % lvl) if lvl else None,
                                "owning_world": ("0x%x" % ow) if ow else None})
        else:
            skip("the PlayerController lives in a Level owned by the resolved World",
                 "no resolved controller and/or world to compare")

        snap["all_anchors_resolved"] = all(snap["anchors"][k]["resolved"] for k in
                                            ("world", "game_instance", "local_player",
                                             "player_controller", "pawn", "player_inventory"))
        run = snap["cross_checks"]
        snap["cross_checks_run"] = len(run)
        snap["cross_checks_passed"] = sum(1 for c in run if c["pass"])
        snap["cross_checks_all_pass"] = all(c["pass"] for c in run)
        # A cross-check is only RUN when both its operands resolved, so "all
        # passed" over an empty or short list is a claim about checks that never
        # happened. The count is reported beside the verdict for exactly that
        # reason -- the reader can see how much "all" covered.
        snap["cross_checks_skipped_count"] = len(snap["cross_checks_skipped"])
        snap["cross_checks_note"] = (
            "%d of 4 cross-checks ran, %d passed, %d were SKIPPED because an operand did not "
            "resolve. A skipped check is not a passed check, and all([]) is True -- which is "
            "why the counts are reported beside the verdict instead of the verdict alone."
            % (snap["cross_checks_run"], snap["cross_checks_passed"],
               snap["cross_checks_skipped_count"]))
        # "complete" now REQUIRES the cross-checks, because the alternative was
        # observed in the wild: a run that reported complete=True beside
        # cross_checks_all_pass=False and still exited 0.
        snap["garbage_excluded"] = [
            {"address": "0x%x" % a, "name": self.name_of(a), "class": self.class_name_of(a)}
            for a in garbage_excluded]
        snap["garbage_excluded_count"] = len(garbage_excluded)
        snap["complete"] = snap["all_anchors_resolved"] and snap["cross_checks_all_pass"]
        if world:
            snap["tarray_layout_self_check"] = self.verify_tarray_layout(world)

        # F3, from the red team, and it was right: the "gameplay was
        # independently proven" flag used to be hand-inserted into the JSON
        # afterwards -- and a later re-run of this very script silently
        # overwrote the file and erased it, leaving the acceptance verdict
        # underivable from the committed evidence. A verdict nobody can
        # re-derive is not evidence.
        #
        # So the independent oracle is now RUN HERE, every time, and recorded
        # with its reasons. It is still independent: readiness.prove_gameplay
        # belongs to the runner, resolves its own properties, and reaches its
        # verdict by class-name enumeration plus ownership -- it shares no
        # decision logic with this file.
        try:
            proof = readiness.prove_gameplay(eri, self.api, self.handle, self.objects,
                                             namepool=self.namepool)
            snap["runner_gameplay_ready"] = bool(proof.get("ready"))
            snap["runner_gameplay_proof"] = {
                "oracle": "research/instruments/runner/readiness.prove_gameplay",
                "independent_of": "this resolver -- shares no decision logic with it",
                "ready": proof.get("ready"), "reasons": proof.get("reasons")}
        except Exception as exc:                               # noqa: BLE001
            snap["runner_gameplay_ready"] = False
            snap["runner_gameplay_proof"] = {"error": repr(exc)}
        return snap


def resolve_live(api=None, *, process_name=None, inventory_class=DEFAULT_INVENTORY_CLASS):
    """Convenience: open the live game read-only and resolve the chain once."""
    api = api or eri.Win32Api()
    i01 = eri.run_i01(api, process_name or eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        r = Resolver(api, handle, i01["base_address"], i01["image_size_bytes"],
                     inventory_class=inventory_class)
        snap = r.resolve()
        snap["pid"] = i01["pid"]
        snap["exe_path"] = i01["exe_path"]
        # F6, from the red team: m4_analyze compares process_start_time to decide
        # whether two observations are the same process, but this path never set
        # it -- so every snapshot-vs-timeline pair failed the test and one
        # same-process transition was published as "RECREATED (new process)".
        try:
            import lifecycle as _lc
            live = [p for p in _lc.find_processes() if p.get("pid") == i01["pid"]]
            snap["process_start_time"] = live[0].get("start_time") if live else None
        except Exception:                                      # noqa: BLE001
            snap["process_start_time"] = None
        return snap
    finally:
        api.close_handle(handle)


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Resolve the live lifecycle chain, read-only.")
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default=None, help="tag this snapshot (e.g. 'before-death')")
    a = ap.parse_args(argv)
    snap = resolve_live()
    if a.label:
        snap["label"] = a.label
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(snap, f, indent=2, sort_keys=False, default=str)
            f.write("\n")
    print("pid %s  complete=%s  cross_checks_all_pass=%s"
          % (snap.get("pid"), snap.get("complete"), snap.get("cross_checks_all_pass")))
    for key in ("world", "game_instance", "local_player", "player_controller",
                "pawn", "player_inventory"):
        anchor = snap["anchors"][key]
        print("  %-18s %-7s %-30s %s"
              % (key, "OK" if anchor["resolved"] else "FAIL",
                 anchor.get("name"), anchor["identity"].get("object_path")))
        if not anchor["resolved"]:
            print("       why: %s" % anchor.get("why"))
    for c in snap.get("cross_checks", []):
        print("  cross-check %-70s %s" % (c["check"], "PASS" if c["pass"] else "FAIL"))
    return 0 if snap.get("complete") else 1


if __name__ == "__main__":
    sys.exit(_main())
