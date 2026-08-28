# CT-05 (cooked content) — pre-registration, written BEFORE the experiment ran

Written 2026-08-28, before any cook was attempted and before anything was placed
where the game could find it. Same discipline as `research/evidence/CT-03/preregistration.md`,
for the same reason: a content-loading experiment has one cheap failure mode —
deciding after the fact what the result "really" showed — and one expensive one,
mistaking a packaging mistake of ours for a limit of the game.

## Question

Can Shipping MISERY, from an automatically-mounted external container, **resolve
and load a new cooked package/UObject that we produced ourselves**?

## Authorisation and its conditions

`research/decisions.md` D-10, `ACCEPTED 2026-08-28`, eleven conditions. The ones
that shape this experiment's design rather than merely constraining it:

* the first test uses **only our own minimal assets** — nothing derived from the
  game's own cooked content, no keys, no decrypted containers (conditions 4–6);
* cook/stage output stays in `workspace/` first; only a deliberately prepared
  test container is ever copied to `%LOCALAPPDATA%\MISERY\Saved\Paks\`
  (conditions 7–8);
* the game installation is never written to (conditions 1, 2, 9);
* the exact engine fingerprint is recorded in evidence (condition 10);
* **a negative result from one cooker/package route is not "external content is
  impossible" until a packaging error on our side has been excluded**
  (condition 11). This is the single most important line in the whole design.

## Three states that must not be conflated

The whole experiment is built around keeping these apart, because they are
separate events and only the first is cheap to see:

| State | Observed by | Meaning if true |
|---|---|---|
| **container mounted** | I-14, `mounted_paks` contains our container | the file was discovered and mounted |
| **packages registered** | I-14, `has_io_container_header` true for our container | the `.utoc` sibling was found and its header registered, so the container contributes *packages*, not merely files |
| **UObject loaded** | `find_live_object.py` finds our object/package in `GUObjectArray` | something actually resolved and loaded it |

CT-03 already proved the first, and **only** the first, for a container of ours.
A bare `.pak` with no `.utoc` neighbour mounts perfectly well and registers
nothing — so "mounted" is not evidence of anything about packages.

## Ladder (do not skip ahead)

1. Our own minimal, dependency-free asset — no shaders, no textures, no audio.
2. Cook it with the exact engine the game was built from (UE 5.4.4, CL 35576357).
3. Package into a `.pak` + sibling `.utoc`/`.ucas` trio.
4. Verify **our own output** before the game ever sees it (see below).
5. Place, restart, observe the three states separately.
6. Only after that: `BP_ProbeActor : AActor`. Only after *that*: SGK / E-3c.

Deliberately **not** starting with Radio/SGK/Weapon: those add inheritance from
game classes on top of the question of whether any external package loads at
all, and a failure would not say which half broke.

## Controls

* **Bare-pak control.** Alongside the trio, a `.pak` with no `.utoc` sibling.
  Expected: mounts, `has_io_container_header` false. This proves the middle
  signal actually discriminates rather than being always-true.
* **Pre-cook baseline, already recorded** — `baseline-no-probe-objects.json`:
  zero hits for `CT05Probe`/`CT03Probe` across 61,586 live objects, so any later
  hit is attributable.
* **Our container is well-formed** — established independently of the game, per
  step 4, so a failure to load cannot be silently blamed on the game.
* **`UnrealPak -Test` is not used as evidence.** A negative control already
  showed it returns silent success on a deliberately corrupted container
  (`LOG-0066` finding 3).

## Readings committed in advance

| Observation | Reading |
|---|---|
| container mounted, packages registered, our UObject found loaded | **PASS.** External cooked content loads. Proceed to `BP_ProbeActor`. |
| mounted + registered, but nothing loaded | **PARTIAL — resolvable but unreferenced.** Expected-ish: nothing in the game references our asset, so nothing loads it. Not a failure of the mechanism. Next question becomes how to trigger a load, which is a separate decision (it may require a level-2 capability). |
| mounted, but packages NOT registered | **FAIL-REGISTRATION.** The `.utoc` was not accepted. Diagnose the container header before concluding anything about the game. Condition 11 applies in full. |
| container not even mounted | **FAIL-MOUNT**, and it contradicts CT-03, so the first suspect is our own packaging, not the game. |
| cook or package step never produces a trio | **BLOCKED-TOOLING.** A fact about our pipeline, not about MISERY. Must be reported as such and must not be written up as a limit of the game. |

## Out of scope for this experiment

No ProcessEvent-driven load, no `P-03`/`P-04` escalation, no overwriting any
shipped package, no inheritance from game classes. Those are later rungs and
each needs its own decision.
