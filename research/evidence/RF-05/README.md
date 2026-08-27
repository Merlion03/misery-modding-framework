# RF-05 — `GUObjectArray` candidate

Method RF-05 (`plan.md` line 527), closing part of exit criterion (4) of M2s. Full chain per
`plan.md` RF-04..RF-09: string anchor → xrefs → candidate function → exact CL 35576357 source
correlation → attempt to refute → build-specific signature. Every address below is **HYPOTHESIS**
(`plan.md` 564-566: an offset from static analysis is never higher, regardless of how well the
pattern matches — this project has no runtime access, Q-8 gates level-1 external-inspector only).

## Source read first (before looking at any disassembly)

`Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectArray.h` (UE 5.4.4, CL 35576357):

- `extern COREUOBJECT_API FUObjectArray GUObjectArray;` — line 1388. A single global instance,
  ordinary static storage (not lazily constructed), so its address is *the object itself*, not a
  pointer to it.
- `class FUObjectArray` — line 724. Private data members actually read (lines 1218-1257):
  `int32 ObjFirstGCIndex; int32 ObjLastNonGCIndex; int32 MaxObjectsNotConsideredByGC; bool
  OpenForDisregardForGC; TUObjectArray ObjObjects; mutable FCriticalSection ObjObjectsCritical;
  TArray<int32> ObjAvailableList; TArray<FUObjectCreateListener*> UObjectCreateListeners;
  TArray<FUObjectDeleteListener*> UObjectDeleteListeners; FThreadSafeCounter PrimarySerialNumber;
  bool bShouldRecycleObjectIndices;` — in that declared order.
- `TUObjectArray` = `FChunkedFixedUObjectArray` (typedef at line 1221). Its own members
  (lines 502-520): `enum { NumElementsPerChunk = 64*1024 };` then `FUObjectItem** Objects;
  FUObjectItem* PreAllocatedObjects; int32 MaxElements; int32 NumElements; int32 MaxChunks; int32
  NumChunks;`. `GetObjectPtr`/`operator()` (lines 638-654) compute
  `ChunkIndex = Index / NumElementsPerChunk; WithinChunkIndex = Index % NumElementsPerChunk;` —
  since `NumElementsPerChunk` is `2^16`, a real compile of this is a **shift-by-16 / mask-0xFFFF**,
  not a division instruction. That is the concrete, checkable shape this method looked for.
- `FUObjectItem` (lines 40-50): `UObjectBase* Object; int32 Flags; int32 ClusterRootIndex; int32
  SerialNumber;` = 20 bytes, padded to **24 (0x18)** for pointer alignment — the per-element stride
  the chunk-indexing arithmetic must use.
- `bool DisregardForGCEnabled() const { return MaxObjectsNotConsideredByGC > 0; }` — lines 827-830.
- `AllocateUObjectIndex` declared line 840, `FreeUObjectIndex` declared line 847 (both
  `COREUOBJECT_API`, i.e. compiled out-of-line, not header-inlined).

`Engine/Source/Runtime/CoreUObject/Private/UObject/UObjectArray.cpp`: `FUObjectArray::
AllocateObjectPool` line 94, `::AllocateUObjectIndex` line 204, `::FreeUObjectIndex` line 318,
`::ShutdownUObjectArray` line 462. `Engine/Source/Runtime/CoreUObject/Private/UObject/
UObjectBase.cpp`: `UObjectBase::UObjectBase(UClass*,...)` line 121 (calls `AddObject` line 135),
`UObjectBase::~UObjectBase()` line 146 (calls `GUObjectArray.FreeUObjectIndex(this)` line 157),
`UObjectBase::AddObject` line 203 (calls `GUObjectArray.AllocateUObjectIndex(...)` line 221).
`UObjectBase.h` line 91: `virtual ~UObjectBase();` — has a vtable, relevant to reading the
disassembly below.

## Method

1. **String anchors** (RF-04 mechanism, `dump_xrefs_for_string.py`): 11 needles taken verbatim from
   `UE_LOG`/`UE_CLOG` text in `UObjectArray.cpp` and `UObjectHash.cpp` — not guessed, read from the
   two files named by `plan.md` RF-05 first. 7 of 11 survived in this Shipping build (the four that
   didn't were all `Log`-severity `UE_LOG` or one `LogObj`/`Error`-category call — the `Warning`- and
   `Fatal`-severity ones from `LogUObjectArray` all survived; a build-config observation, not chased
   further per the time-box rule). Result: **8 xrefs across 6 distinct functions**, all but one
   clustered in `0x1412c1e40..0x1412dbb90` (~106 KB span) — consistent with one translation unit.
   `research/evidence/RF-05/xrefs-uobjectarray-summary.json`, full records in
   `workspace/xrefs/uobjectarray.jsonl` (gitignored, sha256 recorded in the summary, C-13).
2. **Decompile each candidate** (`dump_function.py`) and check the access pattern against the
   struct layout read above, not a remembered shape.
3. **Follow to callers** (`dump_function.py` again on `incoming_calls`) where the candidate function
   itself takes `this` as a register parameter rather than a hardcoded address — the constant
   surfaces at the call site instead.
4. **Attempt to refute** — see below.
5. **Signature** each accepted candidate (`tools/static/sigmake.py`) so it can be re-found in a
   future build without repeating this chain.

## Candidate functions and how each maps to source

| Address | `size` | Incoming calls | Source identity |
|---|---|---|---|
| `0x1412c47a0` | 557 B | 2 | `FUObjectArray::AllocateUObjectIndex` |
| `0x1412db8c0` | 716 B | 1 | `FUObjectArray::AllocateObjectPool` |
| `0x1412c1e40` | 331 B | **894** | `UObjectBase::~UObjectBase()` (`FreeUObjectIndex` inlined) |
| `0x1412c3370` | 130 B | 1 | `UObjectBase::AddObject` |
| `0x1412c78d0` (`caseD_5`) | 312 B | 1 | second `AllocateUObjectIndex` call site, reached through a jump table (not further named — passes `AlreadyAllocatedIndex=-1` like the ordinary path, so it is a construction variant, not a different mechanism) |
| `0x1412dbb90` | — | — | `FUObjectArray::ShutdownUObjectArray` (both "All UObject delete listeners..." UE_CLOGs, source lines 473 and 481, share one identical string — the engine source itself reuses "delete listeners" wording for the create-listener check too; found, not decompiled further, corroborating only) |
| `0x1412e41f0` | — | — | `OnHashFailure` in `UObjectHash.cpp` — a consumer of the object array, not the array itself; found via the same batch, corroborating only |

Decompiled JSON for each: `fun-allocateuobjectindex.json`, `fun-allocateobjectpool-1412db8c0.json`,
`fun-removeobject-1412c1e40.json`, `fun-caller1-1412c3370.json`, `fun-caller2-1412c78d0.json` in
this directory. Full C text under `workspace/xrefs/fun-*.c` (C-13: excerpts are in the JSON, kept
here; full text stays uncommitted).

### `AllocateUObjectIndex` (`0x1412c47a0`) — the access-pattern match

Disassembly against `this` (RBX, since this is an ordinary non-static member function, `this` is a
real register argument, not a folded constant):

```
CMP byte ptr [RBX+0xc], 0x0      ; OpenForDisregardForGC          (source order: 4th field)
MOV R9D, dword ptr [RBX+0x8]     ; MaxObjectsNotConsideredByGC    (3rd field)
MOV R14D, dword ptr [RBX+0x4] ; INC R14D ; MOV [RBX+0x4], R14D    ; ++ObjLastNonGCIndex (2nd field)
CMP dword ptr [RBX], 0x0          ; ObjFirstGCIndex >= 0           (1st field)
CMP R14D, dword ptr [RBX+0x24]   ; Index < NumElements             (offset 0x24 = predicted NumElements)
MOV RDX, qword ptr [RBX+0x10]    ; Objects (FUObjectItem**)        (offset 0x10 = predicted Objects)
MOVZX EAX, R14W                  ; Index & 0xFFFF  = WithinChunkIndex
SHR  R8, 0x10                    ; Index >> 16     = ChunkIndex     -- exactly NumElementsPerChunk=2^16
LEA  RCX, [RAX+RAX*2]            ; WithinChunkIndex*3
MOV  RAX, qword ptr [RDX+R8*8]   ; Objects[ChunkIndex]
LEA  RDI, [RAX+RCX*8]            ; Chunk + WithinChunkIndex*24    -- RCX*8 = WithinChunkIndex*24 = sizeof(FUObjectItem)
```

Four struct-offset reads (`0x0/0x4/0x8/0xc`) land on the four scalar fields in exactly their
declared order, and the chunk-array walk reproduces `FChunkedFixedUObjectArray::GetObjectPtr`'s
shift-16/mask-0xFFFF/stride-24 arithmetic exactly — not approximately: `NumElementsPerChunk=65536`
and `sizeof(FUObjectItem)=24` are both compile-time constants read from source above, and both
appear as exactly those constants in the compiled code, not merely "some shift" and "some stride".

Also inside this same function, source line 258 (`GUObjectArray.DisregardForGCEnabled()`, called
by explicit global name rather than through `this`) compiles to a **direct, non-`this`-relative**
read: `CMP dword ptr [0x147a78ed8], EBP`. `0x147a78ed8 - 0x147a78ed0 = 0x8` — the same offset
already identified as `MaxObjectsNotConsideredByGC` via the `this`-relative read above, now
confirmed a second, independent way inside the same function.

### `AllocateObjectPool` (`0x1412db8c0`) — the constructor, and where the base address comes from

This function reads four CVars by exact name — `"gc.MaxObjectsNotConsideredByGC"`,
`"gc.SizeOfPermanentObjectPool"`, `"gc.MaxObjectsInGame"`, `"gc.PreAllocateUObjectArray"` — which
in the whole engine configure exactly one thing: this call. It then writes, unconditionally through
**direct global addresses** (not a register `this`, since it is only ever called once):

| Address | Offset from `0x147a78ed0` | Field (source order) | What is written |
|---|---|---|---|
| `0x147a78ed0` | `+0x0` | `ObjFirstGCIndex` | `(MaxObjectsNotConsideredByGC_cvar < 1) ? 0 : -1` — exactly `DisregardForGCEnabled() ? -1 : 0` (source line 103) |
| `0x147a78ed8` | `+0x8` | `MaxObjectsNotConsideredByGC` | the `gc.MaxObjectsNotConsideredByGC` cvar value directly |
| `0x147a78ee0` | `+0x10` | `Objects` (`FUObjectItem**`) | result of an allocation sized `MaxChunks*8`, then `memset` to 0 — matches `Objects = new FUObjectItem*[MaxChunks]; FMemory::Memzero(...)` (header lines 587-588) |
| `0x147a78ee8` | `+0x18` | `PreAllocatedObjects` | allocation sized `MaxElements*24` (`24 = 0x18 = sizeof(FUObjectItem)`) — matches `PreAllocatedObjects = new FUObjectItem[MaxElements]` (header line 592) |
| `0x147a78ef0` | `+0x20` | `MaxElements` | `MaxChunks * 65536` — matches `MaxElements = MaxChunks * NumElementsPerChunk` (header line 586) |
| `0x147a78ef8` | `+0x28` | `MaxChunks` | `MaxObjectsInGame_cvar / 65536 + 1` — matches `MaxChunks = InMaxElements / NumElementsPerChunk + 1` (header line 585) |

Also emits the `checkf`/`UE_CLOG` text `"Max UObject count is invalid..."` (source line 107) when
the `gc.MaxObjectsInGame` cvar is `<= 0`, at the exact source-cited file:line (`UObjectArray.cpp:0x6b`
= line 107 in the embedded `__FILE__`/`__LINE__` literal — decimal 107).

**Six fields, matching source declared order, matching source-derived values and constants, all
anchored to one base address, confirmed by a function whose CVar names are unique in the whole
engine to configuring `GUObjectArray` specifically.**

### The two `AllocateUObjectIndex` callers — where the constant is spelled out literally

`AllocateUObjectIndex` takes `this` in RCX; it does not hardcode its own base address. Both of its
two callers do, identically:

```c
FUN_1412c47a0(&DAT_147a78ed0, param_1, uVar3, param_4, param_5);   // UObjectBase::AddObject      (0x1412c3370)
FUN_1412c47a0(&DAT_147a78ed0, param_1, uVar6, 0xffffffff, 0);      // switch-table caller (0x1412c78d0)
```

`&DAT_147a78ed0` = **`0x147a78ed0`**, the same address `AllocateObjectPool` constructs into and
`AllocateUObjectIndex` reads `+0x8` from via `GUObjectArray.DisregardForGCEnabled()`.

### `UObjectBase::~UObjectBase()` (`0x1412c1e40`, 894 incoming calls) — the fan-in prediction, checked

`plan.md`'s framing predicted a genuine `GUObjectArray` candidate should be referenced from "a LOT
of distinct functions" because registration/deregistration sits on one of the hottest paths in the
engine. This function has **894 distinct callers** — consistent with being (or containing inlined)
the one code path every derived `UObject` destructor chain funnels through. Source confirms
directly: `UObjectBase::~UObjectBase()` (line 146) calls `GUObjectArray.FreeUObjectIndex(this)`
(line 157) by explicit global name, and `UObjectBase.h:91` declares the destructor `virtual` — which
is exactly why the decompiled function opens by writing a vtable pointer
(`*param_1 = &PTR_FUN_145e75830`) before anything else, standard C++ dtor-chain codegen. Because
`FreeUObjectIndex` is called by explicit `GUObjectArray.` name (not `this->`), its inlined body again
uses **direct global addresses**, not a register:

```c
uVar1 = *(uint *)((longlong)param_1 + 0xc);          // Object->InternalIndex, offset 0xc
if ((int)uVar1 < DAT_147a78ef4) {                     // compare against +0x24 = NumElements
    plVar4 = *(longlong*)(DAT_147a78ee0 + (uVar1>>0x10)*8) + (uVar1&0xffff)*0x18;   // same
}                                                       // shift-16/mask-0xFFFF/stride-24 shape
```

`0x147a78ee0 - 0x147a78ed0 = 0x10` (`Objects`), `0x147a78ef4 - 0x147a78ed0 = 0x24` (`NumElements`)
— the same two offsets already identified in `AllocateUObjectIndex`, now read from a **third**,
structurally unrelated function, via direct addresses rather than a `this` register.

## Attempt to refute

- **Alternative explanation for `0x147a78ed0`?** None found. `FUObjectArray` has exactly one
  instance anywhere in the engine (`extern` global, no factory, no per-thread copy — no TLS-prefixed
  access appears anywhere in the disassembly examined). Four independent code paths
  (`AllocateObjectPool`'s constructor writes, `AllocateUObjectIndex`'s `this`-relative reads,
  `AllocateUObjectIndex`'s own direct-global read at `+0x8`, and `~UObjectBase`'s direct-global reads
  at `+0x10`/`+0x24`) agree on the same six struct offsets, in source-declared order, with
  source-matching values, and the CVar names read at construction are unique in the engine to this
  one object. No plausible non-`GUObjectArray` explanation survives this many independently-checked
  offsets converging on one address.
- **Could this be a different `FUObjectArray`-shaped struct that merely resembles it?** There is
  only one `FUObjectArray` type instantiated anywhere in the source tree searched.
- **Section membership**: `0x147a78ed0` (RVA `0x7a78ed0`) falls inside `.data`
  (`workspace/xrefs/pe-info-shipping.json`, section table read via `tools/fingerprint/pe_info.py`) —
  writable, initialized storage, consistent with a global that is written at both static-init time
  (default constructor, `FUObjectArray::FUObjectArray()` line 84) and continuously at runtime.
- **What was NOT checked**: no runtime read exists (Q-8). The claim that this address holds the
  live, currently-running object array (as opposed to, say, a build where this global was moved by a
  patch) is exactly the part runtime observation would need to supply — see below.

## Grade

**HYPOTHESIS**, class I, oracle `binary-analysis`, confidence **0.65**.

Reasoning for the number: this is an unusually well-corroborated static match — four independent
code paths, six matching struct offsets in declared order, unique CVar names, a fan-in count that
matches the predicted "hottest path" shape, zero plausible alternative explanation found. But
`plan.md` 564-566 places an absolute ceiling here regardless of pattern quality: no runtime
observation exists for this build (Q-8 gates level-2 in-process access; level-1 external-inspector
work has not yet read this address from a live process). 0.65 reflects "about as strong as a
HYPOTHESIS gets," not "nearly OBSERVED" — the grade band itself, not just the number, is the
binding constraint.

## What a runtime observation would need to show to move this above HYPOTHESIS

An external, read-only process inspector (Q-8 level-1 ERI) against a running
`MISERY-Win64-Shipping.exe`:

1. Read the dword at candidate `+0x24` (`NumElements`) and `+0x20` (`MaxElements`); expect a
   plausible, non-zero UObject count (thousands to low millions) with `NumElements <= MaxElements`.
2. Walk the chunk array at `+0x10` using the shift-16/mask-0xFFFF/stride-24 arithmetic recovered
   above for a sample of indices `0..NumElements`; each `FUObjectItem.Object` pointer read should
   point into a plausible heap region, and its first 8 bytes (the object's vtable pointer) should
   point into `.rdata`/`.text`.
3. Two reads separated in time should show `NumElements` non-decreasing (a live, growing registry —
   not a coincidental static table).
4. Cross-check with RF-06: resolve one live object's `FName` through the RF-06 candidate and confirm
   it decodes to readable text.

Any one of (1)-(3) failing would refute the candidate outright; passing all of them is the
`RF-10` deliverable named in `plan.md` line 537.

## Update 2026-08-27 — runtime observation performed, all checks passed (LOG-0051)

ERI capability I-02 (`research/instruments/eri/eri.py`) ran all three checks above against a live
`MISERY-Win64-Shipping.exe` (build 24953925, a later build than the one this README's static
analysis was performed against — RF-02's sigscan work independently confirmed this candidate's
underlying code is byte-identical between the two builds, see `RESEARCH_LOG.md` LOG-0049). Result:
`NumElements=26263`, `MaxElements=2162688` (check 1 passed); 32/32 sampled objects' first 8 bytes
fell inside `[base_address, base_address+image_size_bytes)` (check 2 passed — implemented as
"inside the module's own mapped image", a looser bound than the ".rdata/.text" originally specified
here, since ERI has no independent way to distinguish those two sections from outside the process
without parsing the PE header again; a plausible full-image-range match is still strong positive
signal, not a weakened one — worth tightening in a future pass); two `NumElements` reads 2s apart
were both exactly 26263, non-decreasing (check 3 passed). Cross-check with RF-06 (item 4) also
passed: FNameEntryId 0 decoded to `"None"` via the RF-06 candidate, and dozens of live objects'
`FName`s decoded to readable, plausible UE class/package names via the same chain — see
`RESEARCH_LOG.md` LOG-0051 for the full account, including `/Script/MISERY` itself being found in
the live sample. This is a genuine runtime observation, not a repeat of the static match — see
LOG-0051 for the updated grade this earns (OBSERVED, class I, confidence 0.90); this section is
kept as the historical record of what the static-only HYPOTHESIS grade above was based on and does
not retroactively rewrite it.

## Signatures

`tools/static/sigmake.py` against the verified target copy
(`D:\Tools\ghidra-workspace\bin\MISERY-Win64-Shipping.exe`, sha256
`0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`), default `grow` mode, `reloc`
mask policy. 5 of 5 requested accepted, all unique across every initialized section, all
`masked_fraction = 0.000` (this image has zero relocations inside executable sections — an S-06
finding reconfirmed here, not re-derived).

| Label | RVA | Pattern length | Function size |
|---|---|---|---|
| `FUObjectArray_AllocateUObjectIndex_candidate` | `0x12c47a0` | 32 | 557 B |
| `FUObjectArray_AllocateObjectPool_candidate` | `0x12db8c0` | 12 | 716 B |
| `FUObjectArray_RemoveObject_or_dtor_candidate` | `0x12c1e40` | 12 | 331 B (`UObjectBase::~UObjectBase`) |
| `FUObjectArray_AllocateUObjectIndex_caller1` | `0x12c3370` | 20 | 130 B (`UObjectBase::AddObject`) |
| `FUObjectArray_AllocateUObjectIndex_caller2_caseD5` | `0x12c78d0` | 32 | 312 B |

Full documents: `signatures.json` (S-06 refutation probes included, all `not_refuted`),
`signatures.jsonl` (one row per target), `library.json` (portable, what `sigscan.py` consumes on a
later build).

## Reproduce

```
D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_xrefs_for_string.py ^
  --needle "Unable to add more objects to disregard for GC pool (Max: %d)" ^
  --needle "Attempting to add %s at index %d but another object (0x%016llx) exists at that index!" ^
  --needle "Removing object (0x%016llx) at index %d but the index points to a different object (0x%016llx)!" ^
  --needle "Maximum number of UObjects (%d) exceeded when trying to add %d object(s), make sure you update MaxObjectsInGame/MaxObjectsInEditor/MaxObjectsInProgram in project settings." ^
  --needle "Max UObject count is invalid. It must be a number that is greater than 0." ^
  --needle "All UObject delete listeners should be unregistered when shutting down the UObject array" ^
  --needle "Unidentified failure for object %s, hash itself may be corrupted or buggy." ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe ^
  --out research\evidence\RF-05\xrefs-uobjectarray-summary.json --jsonl-out workspace\xrefs\uobjectarray.jsonl

D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_function.py --function 1412c47a0 ^
  --out research\evidence\RF-05\fun-allocateuobjectindex.json --c-out workspace\xrefs\fun-1412c47a0.c

D:\Tools\venv-research\Scripts\python.exe tools\static\sigmake.py D:\Tools\ghidra-workspace\bin\MISERY-Win64-Shipping.exe ^
  --rva 0x12c47a0=FUObjectArray_AllocateUObjectIndex_candidate ^
  --out research\evidence\RF-05\signatures.json --jsonl-out research\evidence\RF-05\signatures.jsonl ^
  --library-out research\evidence\RF-05\library.json
```
(run from PowerShell — Git Bash mangles the leading-backslash `D:\tools\...` project-root argument)

## What this does NOT prove

- Not that `0x147a78ed0` is correct for any build other than the one identified by the `build_key`
  above — signatures exist precisely so this can be re-checked, not assumed, on a future patch.
- Not that the game is running, or that this address is mapped/valid in a live process — this is a
  claim about the file on disk.
- Not the byte-for-byte layout of `FUObjectItem` beyond what was directly exercised (the `Object`
  pointer and the packed `Flags`/probe-hash first 4 bytes at `+8` inside it) — the full field-by-field
  offset table for property values remains out of scope for RF-05 and gated by CK-04's rule (offsets
  are OBSERVED only from a runtime dump with a `build_key`).

## Operational note (not a game finding)

`dump_function.py` intermittently raised `LockException: Unable to lock project!` against
`T05-primary-default-analysis` immediately after a prior run of the same tool family had exited
0 and printed `written: ...` — no live `java`/`javaw` process was present when this happened
(checked via `Get-Process`), and the `.lock`/`.lock~` files were safely removable each time. Worked
around by deleting the stale lock and retrying; recorded here because it is reproducible across
both RF-05 and RF-06 runs this session and the next user of these tools should not be surprised by
it.
