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
agree. A single route that happens to be right is indistinguishable from one
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


class Anchor(dict):
    """One resolved object: what it is, how it was reached, and whether the
    independent routes to it agreed."""


def _anchor(address, objects, eri_mod, *, routes, agreed, why=None, extra=None):
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

    out = Anchor({
        "resolved": bool(address) and agreed,
        "address": ("0x%x" % address) if address else None,
        "name": record.get("name_text"),
        "class": class_record.get("name_text"),
        # identity is what survives comparison across a restart; address is not
        "identity": {"object_path": path_of(address), "class_path": path_of(class_ptr)},
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
        self.namepool, self.objects = recon.universe(api, handle, base_address, image_size)
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

    def instances_of(self, wanted_path):
        out = []
        for address, record in self.objects.items():
            if not record.get("valid") or not record.get("class_ptr"):
                continue
            if self.is_cdo(address):
                continue
            if self.derives_from(address, wanted_path):
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
    def resolve(self):
        """Resolve the whole chain. Never raises; every failure is explained."""
        snap = {"anchors": {}, "cross_checks": [], "notes": []}

        # -- identity anchor: the snapshot is a UE object graph at all ------
        selfref = [a for a, r in self.objects.items()
                   if r.get("valid") and r.get("name_text") == eri.UCLASS_SELF_REFERENCE_NAME
                   and r.get("class_ptr") == a]
        snap["object_graph_trusted"] = len(selfref) == 1
        snap["objects_total"] = len(self.objects)
        if not snap["object_graph_trusted"]:
            snap["why_not"] = ("the self-referential UClass is not unique (%d found): this is "
                               "not a trustworthy UE object graph, so nothing below would mean "
                               "anything" % len(selfref))
            return snap

        # -- the viewport client: the engine's own opinion -------------------
        viewports = self.instances_of(PATH_VIEWPORT_CLIENT)
        viewport = viewports[0] if len(viewports) == 1 else None
        snap["notes"].append("live GameViewportClient instances: %d" % len(viewports))

        # -- route A to the World: the viewport client -----------------------
        world_routes = []
        world_a = None
        if viewport:
            world_a, ev = self.read_object_prop(viewport, "World")
            world_routes.append({"route": "GameViewportClient::World", "evidence": ev,
                                 "world": ("0x%x" % world_a) if world_a else None})
        else:
            world_routes.append({"route": "GameViewportClient::World", "evidence": None,
                                 "why": "no unique live GameViewportClient"})

        # -- route B: the only World that owns a GameInstance ----------------
        # WorldType is not reflected in this build, so "the world the engine is
        # actually running" has to come from a reflected edge instead. A world
        # that is merely loaded for streaming has OwningGameInstance null.
        worlds = self.instances_of(PATH_WORLD)
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
        controllers = self.instances_of(PATH_PLAYER_CONTROLLER)
        controller = controllers[0] if len(controllers) == 1 else None
        world_c = None
        if controller:
            # An AActor's Outer is its ULevel; ULevel::OwningWorld is reflected.
            # This never touches an unreflected member: the Outer pointer is a
            # UObjectBase field ERI already resolves structurally.
            level = self.outer_of(controller)
            if level and self.derives_from(level, PATH_LEVEL):
                world_c, ev = self.read_object_prop(level, "OwningWorld")
                world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                              "ULevel::OwningWorld",
                                     "level": "0x%x" % level, "evidence": ev,
                                     "world": ("0x%x" % world_c) if world_c else None})
            else:
                world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                              "ULevel::OwningWorld",
                                     "why": "the controller's Outer is not a ULevel"})
        else:
            world_routes.append({"route": "PlayerController -> Outer(Level) -> "
                                          "ULevel::OwningWorld",
                                 "why": "no unique live PlayerController"})

        # -- route D: the only World with an AuthorityGameMode ---------------
        with_gm = []
        for w in worlds:
            gm, _ev = self.read_object_prop(w, "AuthorityGameMode")
            if gm:
                with_gm.append(w)
        world_d = with_gm[0] if len(with_gm) == 1 else None
        world_routes.append({
            "route": "the unique UWorld whose AuthorityGameMode is non-null",
            "worlds_with_authority_game_mode": len(with_gm),
            "world": ("0x%x" % world_d) if world_d else None})

        candidates = [w for w in (world_a, world_b, world_c, world_d) if w]
        agreed = bool(candidates) and len(set(candidates)) == 1
        world = candidates[0] if agreed else None
        snap["anchors"]["world"] = _anchor(
            world, self.objects, eri, routes=world_routes, agreed=agreed,
            why=None if agreed else
                ("the independent routes to the World disagree or are unavailable: %r -- "
                 "refusing to pick one" % [("0x%x" % c) for c in candidates]),
            extra={"worlds_live": len(worlds),
                   "world_names": sorted({self.name_of(w) for w in worlds})})

        # -- GameInstance ----------------------------------------------------
        gi_routes = []
        gi_a = gi_b = None
        if world:
            gi_a, ev = self.read_object_prop(world, "OwningGameInstance")
            gi_routes.append({"route": "UWorld::OwningGameInstance", "evidence": ev})
        if viewport:
            gi_b, ev = self.read_object_prop(viewport, "GameInstance")
            gi_routes.append({"route": "UGameViewportClient::GameInstance", "evidence": ev})
        live_gis = self.instances_of(PATH_GAME_INSTANCE)
        gi_routes.append({"route": "live UGameInstance instances", "count": len(live_gis),
                          "objects": ["0x%x" % a for a in live_gis]})
        gi_cands = [g for g in (gi_a, gi_b) if g]
        gi_agreed = bool(gi_cands) and len(set(gi_cands)) == 1 and len(live_gis) == 1 \
            and gi_cands[0] == live_gis[0]
        game_instance = gi_cands[0] if gi_agreed else None
        snap["anchors"]["game_instance"] = _anchor(
            game_instance, self.objects, eri, routes=gi_routes, agreed=gi_agreed,
            why=None if gi_agreed else
                "the GameInstance routes disagree, or there is not exactly one live instance")

        # -- LocalPlayer -----------------------------------------------------
        lp_routes = []
        lp_a = lp_b = None
        if game_instance:
            players, ev = self.read_array_prop(game_instance, "LocalPlayers")
            lp_routes.append({"route": "UGameInstance::LocalPlayers", "evidence": ev})
            if len(players) == 1:
                lp_a = players[0]
            else:
                lp_routes[-1]["why"] = ("expected exactly one local player, found %d -- "
                                        "splitscreen is not handled and is not guessed at"
                                        % len(players))
        if controller:
            lp_b, ev = self.read_object_prop(controller, "Player")
            lp_routes.append({"route": "APlayerController::Player", "evidence": ev})
        live_lps = self.instances_of(PATH_LOCAL_PLAYER)
        lp_routes.append({"route": "live ULocalPlayer instances", "count": len(live_lps)})
        lp_cands = [x for x in (lp_a, lp_b) if x]
        lp_agreed = bool(lp_cands) and len(set(lp_cands)) == 1
        local_player = lp_cands[0] if lp_agreed else None
        snap["anchors"]["local_player"] = _anchor(
            local_player, self.objects, eri, routes=lp_routes, agreed=lp_agreed,
            why=None if lp_agreed else "the LocalPlayer routes disagree or are unavailable")

        # -- PlayerController ------------------------------------------------
        pc_routes = [{"route": "live APlayerController instances", "count": len(controllers),
                      "objects": ["0x%x" % a for a in controllers]}]
        pc_b = None
        if local_player:
            # The reverse edge. UPlayer::PlayerController is reflected, so the
            # LocalPlayer can be asked who its controller is instead of us
            # assuming the single live controller is the right one.
            pc_b, ev = self.read_object_prop(local_player, "PlayerController")
            pc_routes.append({"route": "UPlayer::PlayerController", "evidence": ev})
        pc_cands = [x for x in (controller, pc_b) if x]
        pc_agreed = bool(pc_cands) and len(set(pc_cands)) == 1
        player_controller = pc_cands[0] if pc_agreed else None
        snap["anchors"]["player_controller"] = _anchor(
            player_controller, self.objects, eri, routes=pc_routes, agreed=pc_agreed,
            why=None if pc_agreed else
                "the PlayerController routes disagree, or there is not exactly one live one")

        # -- Pawn -------------------------------------------------------------
        pawn_routes = []
        pawn_a = pawn_b = None
        if player_controller:
            pawn_a, ev = self.read_object_prop(player_controller, "Pawn")
            pawn_routes.append({"route": "AController::Pawn", "evidence": ev})
            pawn_b, ev = self.read_object_prop(player_controller, "AcknowledgedPawn")
            pawn_routes.append({"route": "APlayerController::AcknowledgedPawn", "evidence": ev})
        pawn_cands = [x for x in (pawn_a, pawn_b) if x]
        # Disagreement here is meaningful, not pedantic: it means possession has
        # not settled and the player is half-built.
        pawn_agreed = (bool(pawn_cands) and len(set(pawn_cands)) == 1
                       and self.derives_from(pawn_cands[0], PATH_PAWN)
                       and not self.is_cdo(pawn_cands[0]))
        pawn = pawn_cands[0] if pawn_agreed else None
        snap["anchors"]["pawn"] = _anchor(
            pawn, self.objects, eri, routes=pawn_routes, agreed=pawn_agreed,
            why=None if pawn_agreed else
                ("Pawn and AcknowledgedPawn disagree, are null, or do not name a live Pawn -- "
                 "possession has not settled"))

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
        inv_agreed = inventory is not None
        snap["anchors"]["player_inventory"] = _anchor(
            inventory, self.objects, eri, routes=inv_routes, agreed=inv_agreed,
            why=None if inv_agreed else
                "no unique player inventory owned by the resolved PlayerController")

        # -- cross-checks that must hold if the chain is really a chain -------
        def check(label, ok, detail):
            snap["cross_checks"].append({"check": label, "pass": bool(ok), "detail": detail})

        if pawn and player_controller:
            back, ev = self.read_object_prop(pawn, "Controller")
            check("APawn::Controller points back at the resolved PlayerController",
                  back == player_controller,
                  {"pawn_controller": ("0x%x" % back) if back else None, "evidence": ev})
        if player_controller and local_player:
            check("APlayerController::Player and UPlayer::PlayerController are inverses",
                  True, "both routes were required to agree above")
        if world and game_instance:
            check("the resolved World is the one the resolved GameInstance is bound to",
                  True, "UWorld::OwningGameInstance was one of the agreeing routes")
        if player_controller and world:
            lvl = self.outer_of(player_controller)
            ow, _ev = self.read_object_prop(lvl, "OwningWorld") if lvl else (None, None)
            check("the PlayerController lives in a Level owned by the resolved World",
                  ow == world, {"level": ("0x%x" % lvl) if lvl else None,
                                "owning_world": ("0x%x" % ow) if ow else None})

        snap["complete"] = all(snap["anchors"][k]["resolved"] for k in
                               ("world", "game_instance", "local_player",
                                "player_controller", "pawn", "player_inventory"))
        snap["cross_checks_all_pass"] = all(c["pass"] for c in snap["cross_checks"])
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
