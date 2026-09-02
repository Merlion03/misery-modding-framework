# Stage 7 — what the reference mod actually demonstrated

Instrument: `research/instruments/mods/stage7_reference.py`
Evidence: `acceptance-run.log`, `acceptance-run.json` (34 checks, 0 failures)

## The shape of the measurement

The mod grants its item on `misery:content_ready`, which fires the moment the
world is published — the same condition the save-entry machine uses to report
gameplay. A before/after differential inside one session therefore starts its
"before" read *after* the grant has already happened, losing that race by about
twenty milliseconds. No change to the framework fixes that; it is the wrong
experiment.

So the differential is across configurations, from a pinned input:

```
snapshot the configured save's files (one-time backup of the originals kept)
  → restore + sha256 → vanilla pass (no framework installed) → dwell → settled read → sha256
  → restore + sha256 → modded pass                           → dwell → settled read → sha256
  → restore + sha256 → modded pass + two broken mods beside it → dwell → settled read
```

Each pass holds the world for the same fixed dwell before it is read, so the
comparison is between like and like.

Both sides are required to start from byte-identical files, and each side is
checked for the game having rewritten the save during the pass. In the recorded
run all three tracked files hashed identically on both sides
(`123.sav 13f0ba879e7f…`) and neither pass rewrote them.

## The result

```
vanilla:  Holdable_Flashlight x1, None x1
modded:   Holdable_Flashlight x1, None x1, refmod__sample x1
delta:    {'refmod__sample': 1}
```

Reproduced across three independent controlled runs, and again in the
third pass with two broken mods installed beside the reference mod.

## Criteria, and how each was answered

| # | criterion | evidence |
| --- | --- | --- |
| 1 | the framework knows nothing about this mod | `tests/test_no_mod_specific_core.py` |
| 2 | the Mod Kit builds its content from the mod's sources | the container is built each run |
| 3 | the surrogate parent is not distributed | package list read back from the **installed** `.utoc`: 7 packages, all under `/Game/Mods/refmod/` |
| 4 | discovery and planning admit it on its manifest | `planned == ['refmod']` |
| 5 | the container mounts and its packages register | the world class loads at runtime |
| 6 | `OnLoad` runs against the public API only | only `Misery.ModAPI` named in `RefMod.dll` |
| 7 | the item registers and SGK `ItemDetails` resolves it | the game's own lookup, in the runtime log |
| 8 | the world class inherits the game's class | `BP_WorldItem_C → SuperStruct 0x1451d04b300 = BP_StaticMasterItem_C` — pointer identity, read out of process |
| 9 | the item reaches the player | the differential above |
| 10 | unload is clean; vanilla baseline after uninstall | every file under the game's `Win64` hashed before install and after uninstall: 8 → 8, added=0 removed=0 changed=0 |
| 11 | one broken mod beside it changes none of the above | a third pass with two broken mods installed; same delta |

Criterion 6's check is conservative and worth naming as such: it scans the
assembly's ASCII strings rather than decoding the `AssemblyRef` table, so it can
over-report but cannot miss a reference.

Criterion 8's parent class is read from the mod's own `modkit.json` — the value
the Mod Kit cooked against — rather than written a second time in the
instrument, which could otherwise agree with nothing and still look right.

## Criterion 11, and what it actually adversarially tests

Two broken mods are installed beside the reference mod as real mod folders:

- `throwonloadmod` — an existing Stage 5A fixture that throws during `OnLoad`.
- `brokenreadymod` (`ThrowOnContentReadyMod`) — **new**, and aimed at a gap
  Stage 7 created itself: it subscribes to `misery:content_ready` and throws
  from the handler. Its mod id sorts before `refmod` on purpose, because mods
  load in id order and subscribers are dispatched in registration order; an id
  after `refmod` would put the throwing handler last and prove nothing.

Results with both installed:

```
plan admits every mod, broken ones included   ['brokenreadymod','refmod','throwonloadmod']
the reference mod still loaded
the mod that throws on load is reported as failed      (not silently dropped)
the readiness event reached a mod that declared no items   2 subscriber(s)
the reference mod was still notified and still granted
delta vs vanilla: {'refmod__sample': 1}
```

## What the adversarial audit found

An audit of this instrument and the crash fix returned 7 confirmed findings
against 17 refuted. Four mattered:

**`misery:content_ready` was keyed to the items subsystem.** It is raised inside
`ApplyPendingItems`, which returned early when no items were declared — so a
"generic lifecycle event" reached only mods that had registered an *item*. A mod
subscribing in order to spawn an actor or read the player would have waited
forever, and the reference mod was notified only because of a subsystem it
happens to use. That is the exact coupling the primitive was specified not to
have. The announcement now runs on its own account, and the run above proves it
in the live game: the event reached a mod that declared nothing.

**An all-empty pack read as a good measurement.** `read_inventory` promised to
keep "empty" and "could not be read" distinct and returned `{}` for a pack with
zero occupied slots. Every consumer tests `is not None`, and the settle rule
compares `{} == {}` and calls it stable — so two reads taken before the save had
restored would have settled instantly on *both* sides, and the differential
would have passed green having observed none of the save's own rows. This is
also a mechanism for the earlier 0-row vanilla reading that does not require any
manual interaction.

**The success regex matched one of two wordings.** `ApplyLocked` logs "is live
in generation N; … resolved it" only when the game's lookup succeeds in the same
tick; its own comment says the usual case is the other branch, confirmed later
by `VerifyLocked` with different words. On that documented path the check FAILED
on a working run and the wait loop spun its full 450 s.

**Dwell was wildly asymmetric.** The vanilla side read immediately; the modded
side read after its log wait. Both sides now hold a fixed 90 s (`dwell_vanilla`,
`dwell_modded`, `dwell_neighbours` all exactly 90.0), so anything the game
itself consumes or spawns applies equally.

Separately, the native `framework_api` gate said `0.4.0` while
`capabilities.API_VERSION` and `Contracts.cs` both said `0.5.0`, so a mod written
against the documented contract was refused. Aligned to `0.5.0`; caret here is
"at least this, same major", so mods declaring `^0.4.0` are unaffected.

## The drag image, found by looking at the screen

After Stage 7 was accepted, the owner reported that the item drew correctly in
the inventory grid but its image did not follow the cursor while being dragged.

The materialization did write `MoveIcon` -- that half of CR-01C4B's fix survived
the port. What did not was the size. `want_sizex`/`want_sizey` are PIXELS, and
they were initialised to `1` in the backend's Init, in the same block as the
world-transform identity defaults, where `1` is exactly right for a scale factor
and meaningless for a pixel dimension. Every mod item was therefore registered
as "override the drag image size, and make it one pixel square". The grid image
was unaffected because it does not read the override, which is precisely why
this could look correct and be broken.

The size is now derived per declaration from the item's grid footprint at
`kDragPixelsPerCell = 100`, the convention C4B measured and the size its
owner-confirmed visual used. For the 1x1 reference item that is exactly 100x100.
Only the 1x1 case has ever been confirmed on screen; the per-cell scaling is
this project's generalisation of the convention and is commented as such.

The game's own `SGK ItemDetails` now returns, for the reference item:

```
inventory 0x237922b3700, drag 0x237922b3700 (the same texture), override on 100x100
```

which matches C4B's recorded verification field for field. The owner confirmed
visually that the drag image follows the cursor.

`MoveIcon` remains invisible to mod authors: one `ItemDefinition.Icon` still
feeds both representations, and no drag-image field was added to the public API.

### The first version of this proof read dead memory

The regression check initially reported from `JobVerifyRow`'s read-back fields.
Production never calls that job, so those fields are always zero, and the check
duly announced a null inventory icon for an item that visibly renders. It failed
on a run where the truth was independently known, which is the good case; a
proof reading an unwritten buffer would otherwise go green the first time the
zeros happened to look plausible.

Reporting now comes from the resolver -- the same route C4B verified through --
so the log states what the game will hand the widget rather than what the
framework believes it wrote. See the deferred note in `STAGE7-ACCEPTANCE.md`
about the verification that exists and is not wired in.

## Two claims withdrawn

**Progressive inventory restoration is not established.** Across separate runs
the vanilla read returned 0, 2 and 8 rows, and this was initially reported as
evidence that a live inventory object does not imply restored contents. It is
not. Those readings came from three different launches; one may have been a
different save entered manually. Differences observed across separate runs are
not evidence about what happens within one load.

The settling loop — read repeatedly until two consecutive readings agree — is
kept as cheap insurance, and every reading is recorded. Across four passes it
has **never observed a change**: both sides matched on the first comparison
every time. The phenomenon it guards against is therefore currently unevidenced.
Only repeated snapshots within a single uninterrupted load that actually show
the inventory changing would establish it.

**The save bytes were not varying.** `123.sav` and `SaveGameMetaData.sav` were
unchanged on disk throughout, so whatever produced the differing vanilla
readings, it was not the save file changing between runs.

## What this exposed

Three defects, none of them in the mod:

1. A **crash in the framework** that killed the game at a content transition —
   see `research/evidence/CRASH-2026-09-01`. Found because a run failed.
2. The **missing lifecycle primitive**: a mod had no way to learn its
   declarations were live. Now `misery:content_ready`.
3. Several instrument defects that produced false verdicts — an inventory reader
   that matched a class by name and so counted 1683 world containers while
   excluding the player's, and a build-output selector that picked a reference
   assembly out of `obj/` and silently shipped an install missing three files.
