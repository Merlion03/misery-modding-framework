# STAGE 4.5 — Core Mod Platform

**Verdict: PASS.** The platform contracts are defined, implemented against a
reference, exercised on the live game, and stated identically on all three
surfaces (C header, C# API, Python reference) with a test that compares them.

**Build:** `misery-24953925-ue5.4.4-bace50f7185d`, UE **5.4.4** CL **35576357**.
**API version:** `0.5.0`. **ABI epoch:** 1.

## Results

| | |
|---|---|
| Live acceptance | **42 / 42** |
| Offline acceptance | 41 / 41 |
| Platform unit tests | 62 |
| Bridge-contract tests | 26 |
| Full repository suite | **2419 passed**, 1 skipped |
| `Misery.ModAPI` build | 0 warnings, 0 errors (docs required, warnings-as-errors) |

Live state after the run: `MasterItemList` 496, `ItemList` 496,
`ParentTables.Num` 1, no mod rows, no transient tables.

## One canonical ModId contract

The cross-stage drift found in Stage 4 is now closed at the source rather than
worked around. `tools/modplatform/modid.py` is the single rule; Stage 3's
`namespace.check_mod_id` and Stage 2's `ItemId` both **delegate** to it, and
their `RESERVED`, `PATTERN` and `MAX_LENGTH` constants are now the canonical
objects (`is` identity, asserted by test). A fourth validator cannot be added
without editing that file and seeing what depends on it.

The consolidation was allowed to be a **superset** of the two rules it replaced
and nothing else. A first draft also reserved the framework's own vocabulary —
and reserved `mbpl`, which is the mod_id the **proven production radio actually
uses**, breaking every Stage 2 definition. Reserving a new name is a separate
decision that has to be taken against a survey of ids in use; it is not this
stage's to take. A test now pins the superset property.

## The architecture, as built

```text
MISERY
  └─ MiseryRuntime (C++)
       └─ MiseryBridge.h            ← stable semantic native bridge (this stage)
            └─ Misery.ModAPI (C#)   ← public contracts (this stage)
                 └─ third-party C# mods
```

Alongside it, `tools/modplatform` is the **reference implementation** of the same
contracts in Python: it is what the 62 unit tests and both acceptances run
against, and it is what proves the semantics before any C++ exists.
`research/instruments/mods/reference_host.py` is explicitly **the one file Stage
5 replaces** — its `_load_module` becomes "start CoreCLR, create a collectible
`AssemblyLoadContext`, instantiate `IMod`", and nothing else moves.

## The primitives

| primitive | module | notes |
|---|---|---|
| lifecycle + ownership | `ownership.py`, `host.py` | `DISCOVERED→LOADING→LOADED→UNLOADING→UNLOADED`, plus `FAILED` |
| logging | `modlog.py` | per-mod, rate-limited, structured |
| structured errors | `errors.py` | `(subsystem, code, detail, mod_id)` |
| diagnostics | `host.diagnostics()` | one deterministic shape |
| developer console | `console.py` | 13 built-in commands |
| event bus | `events.py` | platform lifecycle events only |
| settings | `settings.py` | declared, typed, persisted per ModId |
| input actions | `input_actions.py` | declaration + ownership only |
| inter-mod services | `services.py` | versioned, revocable |
| capability negotiation | `capabilities.py` | 8 named, independently versioned |

## The lifecycle guarantee, and why it is structural

> Mod unload/failure → the framework releases all owned resources → **no callback
> may target unloaded mod code**

The easy case is boring. The guarantee is carried by two mechanisms, and the
second is the one that does the work:

1. **A registry of releasables per owner**, released in **reverse acquisition
   order** — a later resource may depend on an earlier one.
2. **A revocable token in front of every callback.** A mod never hands a raw
   callable to a subsystem. Dispatch goes through the token, which checks
   liveness **at call time, not at capture time**. Revocation is therefore
   instantaneous and retroactive: a handler list captured a microsecond before
   an unload simply skips every revoked entry when it reaches it.

`dispose()` revokes **before** releasing, so anything the release functions
themselves do — raising an event, unregistering an item — can no longer reach
that mod's code.

Four hard cases each have a test by name:

* a mod unloaded **midway through a dispatch** whose handler list was captured
  before the unload started;
* a mod that **unloads itself from inside its own handler** (refused as
  `reentrant_unload`; the outer unload still completes);
* an **event raised while a mod is being torn down**;
* a **service handle a consumer kept past its provider's unload** — it becomes a
  structured error immediately, for every consumer that ever took one.

`FAILED` runs **exactly the same teardown** as a normal unload. There is no
second, less-tested cleanup path — `Owner.dispose()` is the only one, and both
roads reach it. A test asserts the two teardown reports have the same shape.

## The bridge, and the two decisions that matter most

**No aggregate crosses by value in the frozen root.** `MbRoot`'s own functions
take `const char* name, int32_t len` — never a struct. A 16-byte struct by value
is implemented differently by different ABIs; every current toolchain agrees,
but the root is the one thing that could never be fixed if one ever did not.
Capability tables use `MbStr` freely — a table *can* be revised.

**No function pointer into mod code ever crosses into native.** The obvious
design passes a callback per subscription. It is also the design that makes a
managed host unable to unload a mod: a native table holding a pointer into a
collectible `AssemblyLoadContext` roots it forever, so `ALC.Unload()` never
completes no matter how carefully everything else was released. So callbacks go
the other way — the managed host registers **one** trampoline, once, in the
default load context, and dispatch carries the **subscription handle**. Native
holds integers; the managed side resolves them in its own table. Tests assert no
capability table takes a per-mod callback and that `MbTrampoline` appears exactly
once.

Also: a frozen root plus per-capability versioned tables (items can reach v3
while log stays v1); handles are `kind:8|slot:24|tag:32` with tags never reused
and **mod slots never recycled**, so a stale handle is detected rather than
dereferenced; `MB_MODSTATE_LEAKED` names the state Stage 5 needs vocabulary for;
and `mod_is_reclaimable` is the exact predicate `ALC.Unload()` gates on, exposed
here so the managed host does not have to reimplement the ownership model.

## Three surfaces, one contract, compared mechanically

`tests/test_bridge_contract.py` parses the real files — no generator, because a
generator would just be a fourth copy — and asserts agreement on: the API
version (including the `.csproj`), all 10 subsystem numbers, all 14 error codes,
log levels, setting type codes, input phases, mod states, capability names, and
the whole ModId rule **by behaviour** as well as by constant.

It also asserts the negative properties: no `UObject`, `FName`, `ProcessEvent`,
`UClass`, `FProperty` or `RVA` in the header's declarations; no `UObject`,
`FName`, `ProcessEvent`, `IntPtr`, `DllImport` or `unsafe` anywhere in the C#.

## Independent design review

Three independent designs for the bridge and C# API were produced, then judged
from three lenses — the Stage 5 implementer, a mod author, and an adversary
hunting lifecycle holes — with the closing condition as the scoring criterion.
Evidence in `api-design-panel.json`.

The Stage-5 and adversary lenses both chose the capability-table design; the
author lens chose the ergonomic one. Two of its findings changed what shipped:

* the winning design **passed `MbStr` by value in its frozen root** — the flaw
  above, fixed here;
* the ergonomic design's best idea — **optional capabilities reachable only
  through a `Try` method**, so using an un-required subsystem is a *compile*
  error rather than a null reference on a player's machine — was adopted into
  `IModContext`.

## Honest scope

* **C# is defined, not hosted.** `Misery.ModAPI` compiles and is
  `netstandard2.0` so the runtime choice stays Stage 5's. There is no P/Invoke,
  no CoreCLR and no binding layer in this stage — deliberately, as instructed.
* **The event bus ships no gameplay events.** Only `platform:mod_loaded`,
  `mod_unloading`, `mod_unloaded`, `mod_failed` — all four of which the platform
  really raises. Inventing unmeasured events would produce a subsystem a mod
  author builds on and later discovers never fires.
* **Input is declaration and ownership only.** Nothing in the engine delivers
  these: the engine input path is unresearched. `CAP_INPUT_REGISTRY` is versioned
  `0.1.0`, its description says so, `engine_input_wired` returns false, and a
  test asserts that flag stays false until the research is done.
* **The developer console is a command registry and renderer, not a UI.** Drawing
  inside MISERY needs engine work that has not been done; a console that looked
  finished but could not be opened would be the same dishonesty.
* **No async surface.** What happens to an in-flight continuation when its mod
  unloads is bound up with how Stage 5 builds its `AssemblyLoadContext`.
  Committing before that is answered would commit the part hardest to change.
* **Not started:** Stage 5 Steam/bootstrap, Stage 6 Blueprint inheritance.
* Stage 3's material capabilities are untouched — emissive, custom shader
  graphs, WPO, blend mode and subsurface remain explicit diagnostics.

## Defect found and fixed during the stage

**A diagnostic that named the wrong problem.** A mod unloading itself from inside
its own handler was told `mod_not_loaded` — true in a useless way — because the
state check ran before the re-entrancy guard. `unload` sets `UNLOADING` before it
announces anything, so the state test fired first and sent the author looking for
the wrong bug. The guard now runs first. Same defect class the Stage 4
adversarial review found twice.
