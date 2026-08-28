# P-04 — first controlled UObject/content load (pre-registration)

**Written before the live call. Outcomes are fixed here so the reading cannot drift.**
Gates D1/D2/D3 are closed (`gateD-fixedbuffer-fstring.json`). **Nothing has been
called live yet.**

## Question

Can the current MISERY build natively **resolve and load** our already-mounted
external cooked package `/Game/ModKit/MK_Canary` through the Unreal object-loading
path? This is **not** item registration, not a Mod Kit gameplay gate, not E-3c.

Target object: `/Game/ModKit/MK_Canary.MK_Canary`

## Planned live chain (one pass, POD-only inputs)

```
Misery::GameThread::Enqueue                 (proven dispatcher, LOG-0076)
      ↓
GameThread                                  (proven identity, E1==E2)
      ↓
build FString in a game-FMemory buffer      (fixed-buffer, gate D3)
      ↓
ProcessEvent(CDO, MakeSoftObjectPath, P1)   (reflected, ABI from live reflection)
      ↓
ProcessEvent(CDO, LoadAsset_Blocking, P2)   (reflected)
      ↓
read returned UObject* (POD, 8 bytes)
      ↓
FMemory::Free(FString buffer) + zero fields
```

Everything runs inside one dispatcher job on the GameThread. No UObject work is
performed from the controller or a worker thread.

## Exact ABI (from runtime reflection, `ufunction-abi.json` — not hand-edited)

| Function | ParmsSize | Inputs | Return |
|---|---|---|---|
| `MakeSoftObjectPath` | 48 | `PathString` **FStrProperty** @0 (16) | `ReturnValue` **FStructProperty** @16 (32) = `FSoftObjectPath` |
| `LoadAsset_Blocking` | 48 | `Asset` **FSoftObjectProperty** @0 (40) | `ReturnValue` **FObjectProperty** @40 (8) = `UObject*` |

P2 is built by copying the 32-byte `FSoftObjectPath` the engine produced at
`P1+16` into `P2+8` (the `ObjectID` sub-object of `FSoftObjectPtr`, offsets proven
in `layout-and-fname-gate.json`), leaving `WeakPtr` at `P2+0` zeroed. We never
interpret those 32 bytes.

## Addresses (all fingerprint-gated; live bytes re-verified == disk before use)

| What | Resolution | Provenance |
|---|---|---|
| `ProcessEvent` | live CDO vtable slot 77 | proven, ESC-01 |
| `MakeSoftObjectPath`, `LoadAsset_Blocking` | live reflection, by name | proven |
| CDO `Default__KismetSystemLibrary` | live reflection, by name | proven |
| `FMemory::Malloc` | `base+0xfab790` | proven thunk |
| `FMemory::Free` | `GMalloc` (`base+0x7960030`) → vtable **slot 9** | DERIVED: symbolized same-version UE oracle + Shipping call-shape corroboration + proven slot-5 anchor; live-resolved to RVA `0xf87b70`, bytes live==disk |

If any address fails its byte check, or `GMalloc` is null, the run **aborts before
any call**.

## Pre-call baseline (re-checked immediately before the call)

- same game PID and build fingerprint (`sha256:bace50f…f013331`)
- `MiseryModKit_P.pak` mounted, ReadOrder 101, **IoContainerHeader registered**
- expected `FPackageId 0xf6620d12509f26d7` still present in the `.utoc`
- `MK_Canary` / `ModKit` **absent** from `GUObjectArray`
- dispatcher available; callback thread == proven GameThread

## Pre-registered outcomes

**PASS** requires *all* of:
1. `MakeSoftObjectPath` returns an `FSoftObjectPath` whose `PackageName`/`AssetName`
   FNames are now **interned** (they were provably absent — `fname-pool-check.json`),
   i.e. the identity was constructed correctly;
2. `LoadAsset_Blocking` returns a **non-null** `UObject*`;
3. after the call, an object appears in `GUObjectArray` with exact object path
   `/Game/ModKit/MK_Canary.MK_Canary`;
4. its class is **`UDataTable`**;
5. the input FString buffer is freed and its fields zeroed; dispatcher healthy;
   game healthy; `verify_install` MATCH before/after.

Then, read-only and only if reachable without new ABI branches:
6. `RowStruct == FMirrorTableRow`; row `CT05Row` present; `MirrorEntryType == Curve (2)`;
   `Name == CT05CANARY8F4A2E1C`.

**Split rule (pre-agreed):** if 6 needs a new/unproven ABI branch, it does **not**
block the verdict — record **P-04 core = PASS (package/object resolved and loaded)**
and **P-04 content-depth = pending**, stating the limitation explicitly.

**Non-PASS readings, kept apart (never collapsed into one "FAIL"):**
- `MakeSoftObjectPath` returns an empty/None path ⇒ **identity construction failed**
  (our FString was malformed) — not a statement about the loader.
- Path constructed but `LoadAsset_Blocking` returns null ⇒ **package not resolvable**
  by the PackageStore, or resolvable but the object was not found. Distinguish by
  checking afterwards whether a `UPackage` for `/Game/ModKit/MK_Canary` appeared
  without the `UDataTable`.
- Non-null return but wrong path/class ⇒ **resolved to the wrong object**.
- Exception / no return ⇒ **construction or dispatch fault**; contained by the
  probe's guard, reported, no retry.

## Negative control (same run, after the positive)

`/Game/ModKit/CT05_DOES_NOT_EXIST.CT05_DOES_NOT_EXIST` through the identical
chain. REQUIRED: returns **null**, creates no target object, does not crash, and
leaves the dispatcher healthy. If the negative control also "succeeds", the
positive result is void. No malformed-input fuzzing.

## Ownership / lifetime (stated in advance)

- The input FString buffer is **ours**: game-allocated, game-freed, fields zeroed.
  ProcessEvent does not destroy caller parameters (gate D2).
- The `FSoftObjectPath` the engine wrote into P1 has an **empty** `SubPathString`
  (no `:` in our path), so it owns no heap buffer; we copy it byte-wise and never
  destruct it.
- **The loaded package/object legitimately stays resident** until GC or process
  exit. We will **not** force-unload it. Newly interned FNames also stay — name
  interning is permanent by design. Both are expected and documented, not leaks
  to be "cleaned up".

## Out of scope (unchanged prohibitions)

Inventory, item/recipe registration, spawning, Blueprint gameplay calls,
DataTable mutation, package/world mutation, network/RPC, E-3b/E-3c, native
`LoadPackage`, NamePool mutation, vtable/`.text` hooks, HW-BP.

## Build fingerprint

`build_key = sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
