# Stage 7 — the first reference mod, and what it exposes

## Purpose

Not to make one mod work. To run a mod through the whole platform with no
special cases anywhere, and let whatever is genuinely missing show itself.

A capability the reference mod needs is only added to the framework if it is a
**universal MISERY primitive**. Anything specific to what this particular mod
does stays inside the mod. That rule is what stops a reference mod from turning
into a pile of `Radio`-shaped holes in the core.

## The shape being exercised

    mod folder
      -> mod.json
      -> content built by the Mod Kit
      -> a Blueprint class derived through the proven E-3c route
      -> a C# assembly against the public Misery.ModAPI
      -> a normal Steam launch
      -> discovery and load plan
      -> mount and content load
      -> C# OnLoad
      -> item registration
      -> world behaviour, as far as is currently supported
      -> clean unload and shutdown

## Acceptance criteria

Fixed before implementation. Each is a separate fact; passing some is not
passing the stage.

1. **Nothing about the mod is known to the framework.** No id, folder, class,
   asset path or capability of this mod appears anywhere in runtime or Mod Kit
   source. Checked by grep, as a test.
2. **The Mod Kit builds its content** — container, cooked packages, and the
   E-3c child class — from the mod's own sources, with no experiment-specific
   step.
3. **The surrogate parent is not distributed.** Read back from the container,
   as E-3c requires.
4. **Discovery and planning admit it** on its manifest alone, in a plan
   computed with other mods present.
5. **The container mounts and its packages register** on a normal Steam launch.
6. **`OnLoad` runs against the public API only** — the assembly references
   `Misery.ModAPI` and nothing else.
7. **The item registers** and the game's own SGK `ItemDetails` resolves it.
8. **The item's world class is the mod's own Blueprint class**, and that class's
   `SuperStruct` is the game's real `BP_StaticMasterItem_C` — pointer identity,
   the E-3c standard, not a name match.
9. **The item reaches the player** through the game's own inventory path, and
   the inventory reports it.
10. **Unload is clean**: the mod's rows are withdrawn, its resources released,
    its context collected, and the installation returns to the vanilla baseline
    after uninstall.
11. **One broken mod beside it changes none of the above** — the Stage 5A
    isolation invariant, re-checked with a real second mod present.

## The generic primitives this needs, and their classification

Two capabilities the platform does not currently expose. Both are universal;
neither mentions anything this mod does.

### P1 — an item's world representation may be a class the mod ships

    universal MISERY primitive -> candidate for MBPL

Today the Items backend writes the row's world-class field with the anchor it
resolved for the game's own `BP_StaticMasterItem_C`. Every mod item is therefore
the vanilla world actor with a different mesh, and a mod cannot give its item
behaviour of its own.

E-3c proved a mod can ship a genuine subclass of exactly that class. Joining the
two is the smallest possible generic addition:

* `ItemDeclaration` gains an optional world-class package path;
* the backend resolves it and writes it to the same row field it already writes;
* the class is **required** to derive from the game's world item class, checked
  by walking `SuperStruct` to the resolver's own anchor, and registration is
  refused otherwise.

That refusal matters more than the feature: without it a mod could put any
class in a row the game will later construct.

### P2 — a mod may put its own item into the player's inventory

    universal MISERY primitive -> candidate for MBPL

`BP_MasterInventory_C::AddItem` is already driven by the proven CR-01C5 path and
was exercised with differential inventory verification in Stage 3. It is not
reachable from C#. Exposing it is what lets any item mod be observed at all,
and it is not specific to any mechanic.

Bounded deliberately: a mod may add an item **it declared itself**. Granting
arbitrary rows, or another mod's rows, is not part of it.

## What is NOT in Stage 7, and why

`equip` and `use` are not implemented. LOG-0063 *identified* the interaction
surface — `Pickup`, `Interact`, `Hold`, `Consume`, `EquipWeapon`,
`EquipClothing`, gated by `SGK PossibleActions` / `ActionCheck` — but
identifying a function is not measuring how it behaves, what it requires, or
what it does to game state.

The instruction stands: behaviour that is not already measured must be
researched and evidenced, not guessed. So Stage 7 goes as far as *world
representation and inventory presence*, both of which rest on measured paths,
and stops at the equip/use boundary. That boundary is a research checkpoint, not
a failure.

Also excluded: world spawning via `BP_MasterItemSpawner_C::SpawnNewItem` or
`SpawnItemAtLocation`. Both were identified by LOG-0063 and neither has been
exercised.

## Deferred, still recorded

    New Game -> preparation area -> generated main zone

The stronger natural map-to-map lifecycle regression from Stage 5B (`9f778df`).
Stage 7 does not block on it.

### The row verification is computed and not load-bearing

`JobVerifyRow` (`CR01C5ProbeDll.cpp`) reads the written row back and forms a
verdict -- `verifyicon_ran`, `verifymesh_ran` -- that **nothing consumes**. The
production registration sequence is InternRow, LoadIcon, LoadMesh, Populate,
Resolve; it never calls the job at all, so those `row_*` fields stay zero and the
verdict is never reached, let alone read.

That is how a one-pixel drag image shipped: the row's *pointer* fields had a
check nobody ran, and its *size* fields had no check at all.

Deliberately NOT fixed as part of the drag-image change. Wiring the existing
verdict in would refuse the reference mod outright, because
`verifymesh_ran` still asserts `row_worldclass == io->world_class` -- the game's
own class -- and P1 now lets a mod supply its own. The predicate is stale with
respect to a capability that shipped after it was written, and repairing it is a
separate piece of work with its own evidence, not a rider on a narrow fix.
