#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Is the new process actually ready, and are we actually
in the configured gameplay session?

This is the authoritative gate of the runner. UI automation may get us through
menus; nothing it observes is evidence. The evidence is here, and it is read
out of the live object graph of the process we are about to probe.

TWO LEVELS, ASKED IN ORDER
--------------------------
1. ``wait_runtime_inspectable`` -- can the runtime be *inspected* at all?
   GUObjectArray located, FNamePool initialised, and the object count settled.
   "Settled" is a measured predicate, not a timer: the census is taken
   repeatedly and the runtime is called inspectable only once consecutive
   readings stop growing. A sleep between readings is how often we ask; it is
   never itself the answer.

2. ``prove_gameplay`` -- are we in a *session*, with a real player? Every
   invariant below is decided from fields whose offsets this project has
   confirmed against the live process (ClassPrivate +0x10, NamePrivate +0x18,
   OuterPrivate +0x20 -- I-04) plus UStruct::SuperStruct (+0x40), which is
   self-checked on every run rather than trusted: see ``class_super_chain``.

WHY THE INVARIANTS ARE THE ONES THEY ARE
----------------------------------------
The failure this gate exists to prevent is not "the game did not start". It is
the far quieter one: the game started, something plausible was on screen, a
probe ran, and the answer described a state nobody meant to be in. Two states
look like "running MISERY" and are not a loaded save:

  * the main menu -- a World, and even a PlayerController, but no player;
  * the thank-you / playtest screen (``WD_PlaytestNote01_C``, the state
    RESEARCH_LOG LOG-0060 finding 5 recorded), which has a real World, a real
    Pawn (``BP_PlaytestBeginPlyer_C``) and a real GameMode -- so every naive
    "is there a pawn?" check passes and none of the actual game is loaded.

So the pawn is not merely required to exist. In the loaded session measured on
this build there are 34 live non-CDO Pawn-derived actors and 33 of them are AI
(``BP_CrayFish_C``, ``BP_ZombieSoilder_C``, ``BP_Twins_C``). "A pawn exists"
means almost nothing here. What is required is the POSSESSED pawn, and it is
obtained the way this project obtains everything else -- by reflection:

    the one live PlayerController
        -> its class chain is walked, and the ``Pawn`` property is RESOLVED on
           it (AController::Pawn -- offset read from the live FProperty, never
           hardcoded)
        -> that pointer is dereferenced and the target is required to be a
           live, non-CDO object whose class derives from /Script/Engine.Pawn
        -> ``AcknowledgedPawn`` (APlayerController's own, separately resolved)
           must point at the SAME object -- two independent fields agreeing,
           not one field trusted

    the one live BP_PlayerInventory
        -> its Outer must be that same PlayerController

That last link was MEASURED, not assumed, and the first draft of this file had
it wrong: it expected the inventory to hang off the pawn. In MISERY (SGK) the
inventory component is owned by the CONTROLLER --
``/Game/NewMapGENTEST.NewMapGENTEST:PersistentLevel:BP_SGKController_C:BP_PlayerInventory``.
The check is written from the observation, not from the expectation.

No offset in this file is guessed. ClassPrivate (+0x10), NamePrivate (+0x18)
and OuterPrivate (+0x20) are I-04's own, confirmed live; ``Pawn`` and
``AcknowledgedPawn`` are resolved per-run through eri.walk_property_chain, the
same decoder CR-01C4B used to resolve S_UIDetails.InventoryIcon; and
UStruct::SuperStruct (+0x40) is self-checked on every class it touches -- see
``class_super_chain``.

AUTHORITY. A live, non-CDO ``AGameModeBase``-derived actor exists only on the
authority in Unreal -- clients get ``AGameStateBase``, never the GameMode. That
is the authority test, and it is a structural engine fact rather than a guess
about MISERY. Net mode is read the same way: a live non-CDO ``UNetDriver``
means a networked session, its absence means standalone. Both are compared
against what the caller declared it expected, and a mismatch fails closed.
"""
import time

# UStruct::SuperStruct. The neighbouring members of the same struct --
# Children (+0x48) and ChildProperties (+0x50) -- were both confirmed against
# this live build during I-06 (RESEARCH_LOG LOG-0053..LOG-0057), and +0x40
# comes from the same corrected layout derivation that produced them. It is
# still not itself a live-confirmed number, so class_super_chain() below
# verifies it on every single run instead of assuming it: a wrong SuperStruct
# offset cannot produce a chain that terminates exactly at
# /Script/CoreUObject.Object.
USTRUCT_SUPER_STRUCT_OFFSET = 0x40

OBJECT_ROOT_PATH = "/Script/CoreUObject.Object"
CDO_NAME_PREFIX = "Default__"

# Class paths the invariants are stated in terms of. Engine types, so these are
# /Script/Engine paths, not names -- a name match would also accept a Blueprint
# that happens to be called "Pawn".
PATH_PAWN = "/Script/Engine.Pawn"
PATH_PLAYER_CONTROLLER = "/Script/Engine.PlayerController"
PATH_GAME_MODE_BASE = "/Script/Engine.GameModeBase"
PATH_NET_DRIVER = "/Script/Engine.NetDriver"
PATH_WORLD = "/Script/Engine.World"
PATH_LEVEL = "/Script/Engine.Level"

# Known non-session states, named so the report can say WHICH one we are in
# rather than only that we are not in gameplay.
PLAYTEST_HUB_CLASS_NAMES = frozenset({"BP_PlaytestBeginPlyer_C", "PlaytestBeginPGmaemode_C"})

DEFAULT_PLAYER_INVENTORY_OBJECT = "BP_PlayerInventory"
DEFAULT_PLAYER_INVENTORY_CLASS = "BP_PlayerInventory_C"


class NotReady(Exception):
    """Raised only by the wait helpers. prove_gameplay never raises: it returns
    a verdict with reasons, because "why not" is the whole value of the run."""


# --------------------------------------------------------------------------
# level 1 -- can the runtime be inspected
# --------------------------------------------------------------------------

def probe_runtime_once(eri, api, handle, base, size):
    """One census reading. Returns a dict, or raises the ERI error unchanged.

    Deliberately thin: I-02 locates GUObjectArray and reports NumElements,
    I-03 locates FNamePool and reports whether the engine has initialised it.
    Early in start-up both legitimately fail; that failure is the signal, so it
    is allowed to propagate to the poller rather than being smoothed over.
    """
    i02 = eri.run_i02(api, handle, base, size,
                      guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                      sample_size=eri.DEFAULT_I02_SAMPLE_SIZE,
                      poll_interval_seconds=0,
                      max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03 = eri.run_i03(api, handle, base, size,
                      namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                      name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                      name_entry_id=0)
    return {"num_elements": int(i02["num_elements"]),
            "objects_ptr_live_va": i02["objects_ptr_live_va"],
            "namepool_live_va": i03["namepool_live_va"],
            "name_pool_initialized": bool(i03.get("name_pool_initialized", True))}


def wait_runtime_inspectable(eri, api, handle, base, size, *, timeout_s=180,
                             interval_s=2.0, settle_readings=3, min_objects=15000,
                             note=None, clock=time.time, sleeper=time.sleep):
    """Poll until the runtime is inspectable AND the object census has settled.

    *settle_readings* consecutive readings must be non-decreasing and differ by
    less than ``max(64, 0.1%)`` of the count for the census to count as settled.

    *min_objects* is a coarse floor and nothing more: it rejects a half-built
    object graph. The SETTLE window is the actual predicate. The floor default
    was originally set to 50 000 from a misread of an older log and was WRONG --
    measured against this build, the first screen after launch (the thank-you
    note, WD_PlaytestNote01_C) carries only 26 263 live objects, so a 50 000
    floor could never be satisfied there and the wait timed out at a fully
    started engine. Measured points for this build: 26 263 at the thank-you
    screen, 62 711 at the main menu, 230 007 at the moment the gameplay gate
    passed. The floor is deliberately far below
    the lower of those: separating menu from gameplay is level 2's job, not
    this one's.

    Raises NotReady on timeout. Never returns a partial "probably ready".
    """
    say = note.append if note is not None else (lambda _m: None)
    deadline = clock() + timeout_s
    readings = []
    last_error = None
    while clock() < deadline:
        try:
            reading = probe_runtime_once(eri, api, handle, base, size)
        except Exception as exc:                      # noqa: BLE001
            last_error = "%s: %s" % (type(exc).__name__, exc)
            readings = []
            sleeper(interval_s)
            continue
        if not reading["name_pool_initialized"]:
            last_error = "FNamePool not initialised yet"
            readings = []
            sleeper(interval_s)
            continue
        if reading["num_elements"] < min_objects:
            last_error = "object count %d below floor %d" % (reading["num_elements"], min_objects)
            readings = []
            sleeper(interval_s)
            continue

        readings.append(reading)
        if len(readings) >= settle_readings:
            window = [r["num_elements"] for r in readings[-settle_readings:]]
            spread = max(window) - min(window)
            tolerance = max(64, int(max(window) * 0.001))
            monotonic = all(window[i] <= window[i + 1] for i in range(len(window) - 1))
            if monotonic and spread <= tolerance:
                say("runtime inspectable: %d objects, settled over %d readings "
                    "(spread %d <= %d)" % (window[-1], settle_readings, spread, tolerance))
                out = dict(readings[-1])
                out["settle_window"] = window
                out["settle_tolerance"] = tolerance
                return out
            last_error = ("census still moving: window=%r spread=%d tolerance=%d"
                          % (window, spread, tolerance))
        sleeper(interval_s)
    raise NotReady("runtime did not become inspectable within %ds (%s)"
                   % (timeout_s, last_error or "no reading succeeded"))


# --------------------------------------------------------------------------
# class ancestry
# --------------------------------------------------------------------------

def class_super_chain(eri, api, handle, class_address, objects, *, max_depth=64):
    """Walk UStruct::SuperStruct from *class_address* up to UObject.

    Returns ``{"chain": [(address, object_path), ...], "terminated_at_object":
    bool, "truncated": bool}``. The caller is expected to check
    ``terminated_at_object``: a chain that does NOT end at
    /Script/CoreUObject.Object means the SuperStruct offset is wrong for this
    build, and every ancestry answer derived from it is worthless. That check is
    this module's live self-verification of USTRUCT_SUPER_STRUCT_OFFSET, run on
    every class it touches rather than once at start-up.
    """
    chain = []
    seen = set()
    addr = class_address
    truncated = False
    while addr and addr not in seen and len(chain) < max_depth:
        seen.add(addr)
        record = objects.get(addr)
        path = None
        if record is not None:
            path = eri.canonicalize_object_path(
                eri.resolve_object_path(addr, objects).get("object_path"))
        chain.append((addr, path))
        if path == OBJECT_ROOT_PATH:
            return {"chain": chain, "terminated_at_object": True, "truncated": False}
        try:
            addr = eri._read_u64(api, handle, addr + USTRUCT_SUPER_STRUCT_OFFSET)
        except Exception:                             # noqa: BLE001
            truncated = True
            break
    if len(chain) >= max_depth:
        truncated = True
    return {"chain": chain, "terminated_at_object": False, "truncated": truncated}


def ancestor_paths(eri, api, handle, class_address, objects, cache=None):
    """The set of object paths in a class's own SuperStruct chain, cached.

    Cached per CLASS, not per (class, question): a build has a few thousand
    loaded classes and this module asks several ancestry questions about each,
    so walking once and answering from a set turns thousands of pointer chases
    into thousands of dict lookups.

    A chain that fails its own termination self-check yields the EMPTY set, so
    every ancestry question about it answers False. An unverifiable ancestry
    must never read as a satisfied invariant.
    """
    if cache is not None and class_address in cache:
        return cache[class_address]
    walked = class_super_chain(eri, api, handle, class_address, objects)
    paths = frozenset(p for _a, p in walked["chain"] if p) \
        if walked["terminated_at_object"] else frozenset()
    if cache is not None:
        cache[class_address] = paths
    return paths


def derives_from(eri, api, handle, class_address, objects, wanted_path, cache=None):
    """True iff *wanted_path* appears in the class's own SuperStruct chain."""
    return wanted_path in ancestor_paths(eri, api, handle, class_address, objects, cache)


# --------------------------------------------------------------------------
# level 2 -- are we in the configured session, with a real player
# --------------------------------------------------------------------------

def resolve_property(eri, api, handle, class_address, objects, namepool, wanted_names):
    """Find a property by name anywhere in a class's chain, BY REFLECTION.

    Returns ``{"name", "offset", "size", "property_class", "declared_on"}`` for
    the first of *wanted_names* found, or None. The offset comes from the live
    FProperty the engine itself is using -- it is never a constant in this file,
    which is the whole point: a hardcoded gameplay offset is exactly the kind of
    "guessed UObject access" this runner is required not to introduce.
    """
    cursor = class_address
    for _depth in range(32):
        if not cursor:
            return None
        owner_name = (objects.get(cursor) or {}).get("name_text")
        try:
            child = eri._read_u64(api, handle, cursor + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
            walked = eri.walk_property_chain(api, handle, child, namepool_live_va=namepool,
                                             owner_address=cursor, objects_by_address=objects)
        except Exception:                              # noqa: BLE001
            walked = {"accepted": []}
        for prop in walked.get("accepted", []):
            if prop.get("raw_name") in wanted_names:
                return {"name": prop.get("raw_name"), "offset": prop.get("offset"),
                        "size": prop.get("size"), "property_class": prop.get("property_class"),
                        "declared_on": owner_name}
        try:
            cursor = eri._read_u64(api, handle, cursor + USTRUCT_SUPER_STRUCT_OFFSET)
        except Exception:                              # noqa: BLE001
            return None
    return None


def _describe(eri, address, objects):
    record = objects.get(address) or {}
    class_record = objects.get(record.get("class_ptr") or 0) or {}
    return {"address": "0x%x" % address,
            "name": record.get("name_text"),
            "class": class_record.get("name_text"),
            "object_path": eri.canonicalize_object_path(
                eri.resolve_object_path(address, objects).get("object_path"))}




def prove_gameplay(eri, api, handle, objects, *, namepool=None, expect=None, note=None):
    """The gameplay-readiness verdict. Never raises; always explains itself.

    *namepool* is the live FNamePool address. It is required for the
    reflection-resolved possession check; without it that check is recorded as
    skipped and the verdict fails, rather than an invariant quietly vanishing.

    *expect* overrides the defaults::

        {"player_inventory_object": "BP_PlayerInventory",
         "player_inventory_class":  "BP_PlayerInventory_C",
         "authority": "standalone" | "networked" | None,
         "world_name": "<a World name that must be live>" | None,
         "player_pawn_class": "BP_SGKMasterCharacter_C" | None}

    Returns ``{"ready": bool, "reasons": [...], "facts": {...}}``.
    """
    say = note.append if note is not None else (lambda _m: None)
    expect = dict(expect or {})
    inv_object = expect.get("player_inventory_object", DEFAULT_PLAYER_INVENTORY_OBJECT)
    inv_class = expect.get("player_inventory_class", DEFAULT_PLAYER_INVENTORY_CLASS)
    reasons = []
    facts = {}
    cache = {}

    def class_name_of(address):
        return (objects.get((objects.get(address) or {}).get("class_ptr") or 0) or {}).get("name_text")

    def is_cdo(address):
        name = (objects.get(address) or {}).get("name_text") or ""
        return name.startswith(CDO_NAME_PREFIX)

    # --- 0. object identities are decodable at all -------------------------
    valid = [a for a, r in objects.items() if r.get("valid")]
    facts["objects_total"] = len(objects)
    facts["objects_valid"] = len(valid)
    if not valid:
        return {"ready": False, "reasons": ["no valid objects in the universe"], "facts": facts}

    # The UClass self-reference is the identity anchor ERI itself relies on: the
    # object named "Class" whose own ClassPrivate points at itself. If that is
    # not present and self-consistent, the snapshot is not a UE object graph and
    # nothing below means anything.
    class_self = [a for a, r in objects.items()
                  if r.get("valid") and r.get("name_text") == eri.UCLASS_SELF_REFERENCE_NAME
                  and r.get("class_ptr") == a]
    facts["uclass_self_reference"] = ["0x%x" % a for a in class_self]
    if len(class_self) != 1:
        reasons.append("UClass self-reference is not unique (%d found) -- object "
                       "identities cannot be trusted" % len(class_self))
        return {"ready": False, "reasons": reasons, "facts": facts}
    anchor_path = eri.canonicalize_object_path(
        eri.resolve_object_path(class_self[0], objects).get("object_path"))
    if anchor_path != eri.UCLASS_SELF_REFERENCE_OBJECT_PATH:
        reasons.append("UClass self-reference resolves to %r, not %s"
                       % (anchor_path, eri.UCLASS_SELF_REFERENCE_OBJECT_PATH))
        return {"ready": False, "reasons": reasons, "facts": facts}
    say("object identity anchor OK: unique self-referential UClass at 0x%x" % class_self[0])

    live_objects = [a for a, r in objects.items() if r.get("valid") and r.get("class_ptr")]

    def instances_deriving_from(path):
        found = []
        for address in live_objects:
            if is_cdo(address):
                continue
            class_ptr = (objects.get(address) or {}).get("class_ptr")
            if path in ancestor_paths(eri, api, handle, class_ptr, objects, cache):
                found.append(address)
        return found

    # --- 1. a World ---------------------------------------------------------
    worlds = [a for a in live_objects if class_name_of(a) == "World" and not is_cdo(a)]
    world_names = sorted({(objects.get(a) or {}).get("name_text") for a in worlds})
    facts["world_count"] = len(worlds)
    facts["world_names"] = world_names
    if not worlds:
        reasons.append("no live World: the engine is not in any level")
        return {"ready": False, "reasons": reasons, "facts": facts}

    # --- 2. exactly one PlayerController -------------------------------------
    controllers = instances_deriving_from(PATH_PLAYER_CONTROLLER)
    facts["player_controllers"] = [_describe(eri, a, objects) for a in controllers]
    controller = None
    if len(controllers) != 1:
        reasons.append("expected exactly one live non-CDO PlayerController, found %d"
                       % len(controllers))
    else:
        controller = controllers[0]
        say("live PlayerController at 0x%x (%s)" % (controller, class_name_of(controller)))

    # --- 3. the POSSESSED pawn, resolved by reflection -----------------------
    # Not "a pawn exists": in a loaded MISERY session 34 pawn-derived actors are
    # live and 33 of them are AI. The player's pawn is the one the controller
    # actually possesses, and the only sound way to that pointer without a
    # hardcoded offset is to resolve AController::Pawn on the live class.
    pawn = None
    if controller is not None:
        if namepool is None:
            reasons.append("no FNamePool address supplied: the possessed-pawn check "
                           "needs reflection and is not silently skipped")
        else:
            controller_class = (objects.get(controller) or {}).get("class_ptr")
            resolved = {}
            for field in ("Pawn", "AcknowledgedPawn"):
                found = resolve_property(eri, api, handle, controller_class, objects,
                                         namepool, (field,))
                if found is None:
                    continue
                if found.get("property_class") != "FObjectProperty" or found.get("size") != 8:
                    reasons.append("%s resolved to %s of size %s, not an 8-byte "
                                   "FObjectProperty" % (field, found.get("property_class"),
                                                        found.get("size")))
                    continue
                try:
                    value = eri._read_u64(api, handle, controller + int(found["offset"]))
                except Exception as exc:               # noqa: BLE001
                    reasons.append("could not read %s at +%s: %r"
                                   % (field, found.get("offset"), exc))
                    continue
                resolved[field] = {"offset": found["offset"],
                                   "declared_on": found["declared_on"],
                                   "value": "0x%x" % value, "raw": value}
            facts["possession"] = resolved
            if "Pawn" not in resolved:
                reasons.append("AController::Pawn could not be resolved by reflection on %s"
                               % class_name_of(controller))
            else:
                candidate = resolved["Pawn"]["raw"]
                record = objects.get(candidate) if candidate else None
                if not candidate:
                    reasons.append("the PlayerController possesses no pawn "
                                   "(AController::Pawn is null): the player has not "
                                   "spawned yet")
                elif record is None or not record.get("valid"):
                    reasons.append("AController::Pawn points at 0x%x, which is not a live "
                                   "object in this snapshot" % candidate)
                elif is_cdo(candidate):
                    reasons.append("AController::Pawn points at a CDO, not an instance")
                elif PATH_PAWN not in ancestor_paths(eri, api, handle,
                                                     record.get("class_ptr"), objects, cache):
                    reasons.append("AController::Pawn points at %s, which does not derive "
                                   "from %s" % (class_name_of(candidate), PATH_PAWN))
                else:
                    pawn = candidate
                    say("possessed pawn 0x%x (%s), via AController::Pawn@+%s"
                        % (pawn, class_name_of(pawn), resolved["Pawn"]["offset"]))

            # The second, independently resolved field. Disagreement is not a
            # detail: it means the controller is mid-possession, and a probe run
            # now would be looking at a half-built player.
            if pawn is not None and "AcknowledgedPawn" in resolved:
                if resolved["AcknowledgedPawn"]["raw"] != pawn:
                    reasons.append("AcknowledgedPawn (%s) disagrees with Pawn (0x%x): the "
                                   "controller is mid-possession"
                                   % (resolved["AcknowledgedPawn"]["value"], pawn))
                else:
                    say("AcknowledgedPawn agrees with Pawn -- possession has settled")
    facts["player_pawn"] = _describe(eri, pawn, objects) if pawn else None

    expected_pawn_class = expect.get("player_pawn_class")
    if expected_pawn_class and pawn is not None and class_name_of(pawn) != expected_pawn_class:
        reasons.append("possessed pawn is %s, expected %s"
                       % (class_name_of(pawn), expected_pawn_class))

    # --- 4. the player's inventory, owned by that same controller ------------
    # MEASURED, not assumed: in MISERY (SurvivalGameKit) the inventory component
    # is owned by the CONTROLLER, not the pawn --
    # /Game/NewMapGENTEST.NewMapGENTEST:PersistentLevel:BP_SGKController_C:BP_PlayerInventory
    inventories = [a for a, r in objects.items()
                   if r.get("valid") and r.get("name_text") == inv_object
                   and class_name_of(a) == inv_class]
    facts["player_inventories"] = [_describe(eri, a, objects) for a in inventories]
    if len(inventories) != 1:
        reasons.append("expected exactly one live %s of class %s, found %d"
                       % (inv_object, inv_class, len(inventories)))
    elif controller is not None:
        owner = (objects.get(inventories[0]) or {}).get("outer_ptr")
        facts["inventory_owner"] = _describe(eri, owner, objects) if owner else None
        if owner != controller:
            reasons.append("the player inventory's Outer is %s, not the live "
                           "PlayerController -- it is not this player's inventory"
                           % (class_name_of(owner) if owner else "null"))
        else:
            say("live player inventory 0x%x is owned by the PlayerController" % inventories[0])

    # --- 5. not a known non-session state -----------------------------------
    live_hub_classes = sorted({r.get("name_text") for r in objects.values()
                               if r.get("valid")
                               and r.get("name_text") in PLAYTEST_HUB_CLASS_NAMES})
    facts["playtest_hub_classes_live"] = live_hub_classes
    if pawn is not None and class_name_of(pawn) in PLAYTEST_HUB_CLASS_NAMES:
        reasons.append("the possessed pawn is a playtest-hub pawn (%s): this is the intro "
                       "screen, not the configured save" % class_name_of(pawn))

    # --- 6. authority --------------------------------------------------------
    game_modes = instances_deriving_from(PATH_GAME_MODE_BASE)
    net_drivers = instances_deriving_from(PATH_NET_DRIVER)
    facts["game_modes"] = [_describe(eri, a, objects) for a in game_modes]
    facts["net_drivers"] = [_describe(eri, a, objects) for a in net_drivers]
    facts["has_authority"] = bool(game_modes)
    facts["net_mode_observed"] = "networked" if net_drivers else "standalone"
    if not game_modes:
        reasons.append("no live GameMode: this process does not hold authority "
                       "(a client sees only GameState)")
    expected_authority = expect.get("authority")
    if expected_authority and expected_authority != facts["net_mode_observed"]:
        reasons.append("authority mismatch: expected %s, observed %s"
                       % (expected_authority, facts["net_mode_observed"]))

    # --- 7. the configured world, when one is configured --------------------
    expected_world = expect.get("world_name")
    if expected_world and expected_world not in world_names:
        reasons.append("expected a live World named %r; live worlds are %r"
                       % (expected_world, world_names[:8]))

    ready = not reasons
    if ready:
        say("GAMEPLAY READY: controller 0x%x -> possessed pawn 0x%x (%s); inventory owned "
            "by that controller; authority=%s; net=%s"
            % (controller, pawn, class_name_of(pawn), facts["has_authority"],
               facts["net_mode_observed"]))
    return {"ready": ready, "reasons": reasons, "facts": facts}
