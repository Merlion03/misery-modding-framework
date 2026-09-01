# Stage 7 — what the reference mod actually demonstrated

Instrument: `research/instruments/mods/stage7_reference.py`
Evidence: `acceptance-run.log`, `acceptance-run.json` (20 checks, 0 failures)

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
  → restore + sha256 → vanilla pass (no framework installed) → settled read → sha256
  → restore + sha256 → modded pass                           → settled read → sha256
```

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

Reproduced across two independent controlled runs.

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
| 10 | unload is clean; vanilla baseline after uninstall | **not yet demonstrated** |
| 11 | one broken mod beside it changes none of the above | **not yet demonstrated** |

Criterion 6's check is conservative and worth naming as such: it scans the
assembly's ASCII strings rather than decoding the `AssemblyRef` table, so it can
over-report but cannot miss a reference.

Criterion 8's parent class is read from the mod's own `modkit.json` — the value
the Mod Kit cooked against — rather than written a second time in the
instrument, which could otherwise agree with nothing and still look right.

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
3. Two instrument defects that produced false verdicts — an inventory reader
   that matched a class by name and so counted 1683 world containers while
   excluding the player's, and a build-output selector that picked a reference
   assembly out of `obj/` and silently shipped an install missing three files.
