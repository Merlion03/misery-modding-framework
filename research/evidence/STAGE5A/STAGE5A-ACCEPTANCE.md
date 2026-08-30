# STAGE 5A — Managed hosting gate

**Verdict: PASS.** The Stage 4.5 contracts survive real CoreCLR-hosted C# mods
inside live MISERY. Nothing in the public API had to change to make hosting
work.

**Build:** `misery-24953925-ue5.4.4-bace50f7185d`, UE **5.4.4** CL **35576357**.
**ABI epoch:** 1. **API:** 0.5.0. **Runtime:** .NET 8.0.25, hosted via
nethost/hostfxr.

## The architecture that actually ran

```text
MISERY Shipping (pid 5400, game thread 12056)
  └─ MiseryRuntimeStage5.dll        injected; bridge + CR-01C5 + host starter
       └─ MiseryBridgeAcquire       frozen root, host handle minted in-process
       └─ nethost → hostfxr → CoreCLR       started ON the game thread
            └─ Misery.ModHost       trampoline registered once
                 └─ Misery.ModAPI   the only thing mods reference
                      ├─ AlphaManagedMod.dll   independently built
                      └─ BetaManagedMod.dll    independently built
```

## Results

| | |
|---|---|
| In-game controller checks | **15 / 15** |
| Managed acceptance, inside MISERY | **46 / 46** |
| Off-game harness (same code, recording backend) | **46 / 46** |
| Native ownership model, host-side | **30 / 30** |
| Repository suite | 2419 passed, 1 skipped; validator 0 |

**The game's own lookup found every item a C# mod registered: 28 attempts, 28
found.** `BP_SGKFunctions::"SGK ItemDetails"` — the function MISERY itself uses —
was called after each registration. That is the difference between "the engine
accepted our write" and "the game can find the item", and only the second one
matters.

Final live state: `MasterItemList` 496, `ItemList` 496, `ParentTables.Num` 1, no
mod rows, no transient tables. `alphamod` ended at **epoch 28** with **108
resources revoked, 0 faults**, reclaimable.

## The chain the gate asked for

**Forward — discovery to a live item:**
Stage 4 load plan (`['alphamod','betamod']`) → managed assembly load into a
per-mod collectible context → `OnLoad` → C# logging through the bridge → C# →
native semantic call → the proven Stage 2 registration → the game's own
`SGK ItemDetails` finds the row.

**Backward — native to managed:**
host-raised event → the **single** trampoline → the correct mod's callback, and
only that mod's. Measured: 6 delivered, 0 orphaned, 1 fault (the deliberately
throwing fixture), 0 registrations left at the end. No gameplay event was
invented for this; a framework event was sufficient.

## Lifecycle, in one MISERY process

Load A, load B → unload A (revoke first, resources released, callbacks dead, B
still receiving events, A's `AssemblyLoadContext` **collected**) → reload A into
a new context, working again.

**Collection is proven through the runtime, not inferred from calling
`Unload()`.** A `WeakReference` to the context is asked after forced collection;
the answer is the GC's, not the host's.

**25 further load/unload cycles** retained nothing: no context, no managed
delegate, no native slot, no item row, no service, no subscription, no asset. The
native slot table did not grow — slots are reused, tags never are.

## Failure isolation, one mode at a time

A first version asserted all six fixtures would fail *at load*. Three do not, so
that version tested nothing for those three and left two of them loaded.

| fixture | what actually happens |
| --- | --- |
| throws from `OnLoad` | refused; everything it had already acquired is released |
| throws from a callback | loads; the fault is **contained at the trampoline**; B unharmed |
| throws from `OnUnload` | loads; teardown completes anyway |
| no `IMod` type | refused, with a diagnostic naming the real cause |
| future API + unknown capability | refused by **negotiation**, before its constructor runs |

No managed exception ever crossed the native ABI. The trampoline catches
everything before returning, and the native dispatch loop counts the fault
against the owning mod and continues to the next handle.

## Threading

Every bridge call is refused off the game thread, **on both sides** — the managed
host checks before the call and the native side checks again, because a contract
enforced on one side only holds while both sides are correct.

Refuse rather than marshal, deliberately: marshalling would either deadlock the
first time a mod called from inside a game-thread callback, or require an async
contract this epoch does not have. CoreCLR itself is started on the game thread,
which costs one visible stall — accepted, because a host whose notion of "the
game thread" is a thread the engine never heard of would make every threading
guarantee meaningless.

## Bridge invariants: all preserved

* No raw `UObject`/`FName`/`ProcessEvent` in any public surface — asserted by test.
* No native pointer ownership in mod code: `Misery.ModAPI` has no `IntPtr`, no
  `DllImport`, no `unsafe` — asserted by test. All interop is in
  `Misery.ModHost`.
* **No per-mod function pointer retained by native.** One trampoline, in the
  host's own context, for the process.
* Root ABI still aggregate-free: pointer + length, never a struct.
* ModId and lifecycle ownership unchanged and still canonical.

**The public C# API was not redesigned to make hosting easier.** No conflict
between the Stage 4.5 contract and safe implementation appeared.

## Four real defects found

1. **Two copies of the contract assembly.** hostfxr's
   `load_assembly_and_get_function_pointer` does **not** load the host into the
   Default context — it creates an `IsolatedComponentLoadContext`. Deferring a
   mod's shared-contract resolution to Default therefore loaded a *second*
   `Misery.ModAPI` from the same file, and the mod's `IMod` stopped being the
   host's `IMod`. The symptom read as *"contains no public type implementing
   IMod"* about an assembly whose only type implements exactly that. Mod contexts
   now return the host's own `Assembly` object: one object, therefore one type.
   Found only because the diagnostic was made to name the real cause.
2. **Capabilities were never read.** `Load()` invented a fixed list, so a mod
   declaring a nonexistent capability and API `^9.0.0` loaded anyway. The
   `[ModCapabilities]` attribute is now read from the mod's own assembly
   **before its type is constructed**, and negotiation goes through the frozen
   root's `query_capability`.
3. **Reference invalidation in the native core.** `EnsureMod` and `Resolve`
   hand out references into containers that were `std::vector`; registering a
   second mod reallocated and invalidated the first. It segfaulted immediately.
   Both are `std::deque` now, which never invalidates existing elements.
4. **The package/asset split was wrong.** An Unreal package path is the *whole*
   path (`/Game/Mods/alphamod/Textures/T_Icon`), not the directory containing the
   asset. The first version stripped the last element, named a package that does
   not exist, and every icon load failed at step 31.

## Scope and honest limits

* **The controller still bootstraps this.** Injection and address resolution come
  from the proven Stage 2 session. That is Stage 5A's remit — Stage 5B is the
  normal-Steam-launch path, and the final acceptance there must need no research
  controller at all.
* **Item registration reuses the CR-01C5 path rather than porting it.** The
  bridge's items backend is a function pointer into the code that already passed
  the world/drop/pickup gate. Reimplementing it in the bridge would have been a
  second copy of the one mechanism that is proven.
* **The off-game harness and the in-game run differ by exactly one function
  pointer** — a recording backend versus the real one. That is what makes the
  harness evidence rather than a mock.
* **Settings storage is not implemented** in this epoch's native table; only
  `Declare` is, and get/set refuse with a structured error rather than silently
  doing something per-process that looks persistent.
* **Input delivery is still unwired** — the engine input path remains
  unresearched, and `engine_input_wired` still reports false.
* **Not started:** Stage 5B production bootstrap, Stage 6 Blueprint inheritance.
