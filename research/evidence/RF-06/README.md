# RF-06 — `FNamePool` candidate

Method RF-06 (`plan.md` line 528), closing part of exit criterion (4) of M2s. Same chain as RF-05:
string anchor → xrefs → candidate function → exact CL 35576357 source correlation → attempt to
refute → build-specific signature. Every address below is **HYPOTHESIS**, never higher — no runtime
access exists for this project (`plan.md` 564-566, Q-8).

## Source read first — and a correction to the named anchor

`plan.md` RF-06 names `NameTypes.cpp` as the anchor file. **At UE 5.4.4 (CL 35576357) this file does
not contain the `FNamePool` implementation** — `Engine/Source/Runtime/Core/Public/UObject/
NameTypes.h` only forward-declares `FNamePool`/`FNameEntryAllocator`/`FNamePoolShardBase` as friend
classes (lines 306-308) and defines a separate, Natvis-only mirror of a few constants
(`FNameDebugVisualizer`, lines 1565-1575) that the engine's own `static_assert`s
(`UnrealNames.cpp:5341-5343`) keep in sync with the real ones. **The actual implementation is in
`Engine/Source/Runtime/Core/Private/UObject/UnrealNames.cpp`** (5600 lines) — read in full for this
task rather than assumed from the plan's file name, per the task's own instruction not to
pattern-match on a remembered/named location.

Constants read from `UnrealNames.cpp` (not guessed, each with its own line):

```
234: static constexpr uint32 FNameMaxBlockBits    = 13;
235: static constexpr uint32 FNameBlockOffsetBits  = 16;
236: static constexpr uint32 FNameMaxBlocks        = 1 << FNameMaxBlockBits;     // 8192
237: static constexpr uint32 FNameBlockOffsets     = 1 << FNameBlockOffsetBits;  // 65536
256: Block  = Id.ToUnstableInt() >> FNameBlockOffsetBits    (FNameEntryHandle)
443: enum { Stride = alignof(FNameEntry) };                 (FNameEntryAllocator)
444: enum { BlockSizeBytes = Stride * FNameBlockOffsets };
697: uint8* Blocks[FNameMaxBlocks] = {};                     (FNameEntryAllocator's block table)
706/708: FNamePoolShardBits = 10 (WITH_CASE_PRESERVING_NAME) or 8 (else)
711: FNamePoolShards = 1 << FNamePoolShardBits
990: class alignas(PLATFORM_CACHE_LINE_SIZE) FNamePoolShardBase
1069: class FNamePoolShard
1514: class FNamePool
1571: FNamePoolShard<CaseSensitive> DisplayShards[FNamePoolShards];
1573: FNamePoolShard<IgnoreCase>   ComparisonShards[FNamePoolShards];
1577: FTracedBitSet TracedNames[FNameMaxBlocks];
```

The lazy-singleton accessor, `FNamePool::FNamePool()`'s registration tail, and the exact idiom this
method chased (lines 1600-1630, 2002-2026):

```cpp
// 1600-1603: every hardcoded EName gets registered in a macro-driven loop
#define REGISTER_NAME(num, name) ENameToEntry[num] = Store(FNameStringView(#name, FCStringAnsi::Strlen(#name)));
#include "UObject/UnrealNames.inl"
// 1616-1630: duplicate check, NOT gated by DO_CHECK/logging -- runs unconditionally
if (NumAnsiEntries() != EntryToEName.Num()) {
    ...
    FMessageDialog::Open(EAppMsgType::Ok, NSLOCTEXT("UnrealEd", "DuplicatedHardcodedName", "Duplicate hardcoded name"));
    FPlatformMisc::RequestExit(false, TEXT("FNamePool.DuplicateHardcodedName"));
}

// 2002-2019
static bool bNamePoolInitialized;
alignas(FNamePool) static uint8 NamePoolData[sizeof(FNamePool)];
static FNamePool& GetNamePool()
{
    if (bNamePoolInitialized) { return *(FNamePool*)NamePoolData; }
    FNamePool* Singleton = new (NamePoolData) FNamePool;
    bNamePoolInitialized = true;
    return *Singleton;
}
```

`NamePoolData` and `bNamePoolInitialized` are both `static` at file scope — internal linkage, no
`extern`, so every reference to them anywhere in the binary must originate inside this one
translation unit, and the constructor call is textually reachable from exactly one place
(`GetNamePool()`), which is the shape this method looked for and found.

## Method

1. **String anchors**: 7 needles from `UnrealNames.cpp`'s own `checkf`/log/dialog text (not guessed
   — read from the file first). 2 of 7 survived in this Shipping build: `"Duplicate hardcoded
   name"` (the `NSLOCTEXT` source text at line 1627) and `"FName length is too long; HashLowerCase
   value is undefined..."` (a `checkf` inside the hashing path). Notably, the sibling string on the
   *same source line* as the surviving one — `"FNamePool.DuplicateHardcodedName"` (the
   `RequestExit` reason, line 1628) — did **not** survive, even though both are unconditionally
   compiled (neither is behind `DO_CHECK`/logging); a build-config/dedup quirk noted, not chased
   further. Result: **3 xrefs across 3 distinct functions**, addresses `0x1410bc.. 0x1410c1..`
   region. `xrefs-fnamepool-summary.json`, full records in `workspace/xrefs/fnamepool.jsonl`
   (gitignored, sha256 in the summary, C-13).
2. **Decompile the candidate** containing `"Duplicate hardcoded name"` and check it against the
   constructor shape read above.
3. **Follow to callers**, since (exactly as in RF-05) the candidate takes its target as a register
   parameter rather than a hardcoded address inside itself.
4. **Attempt to refute.**
5. **Signature** the accepted candidates.

## Candidate functions and how each maps to source

| Address | Size | Incoming calls | Source identity |
|---|---|---|---|
| `0x1410be2c0` | 13 007 B | 26 | `FNamePool::FNamePool()` (the constructor) |
| `0x1410bc2f0` | 494 B | 1 | `GetNamePool()` inlined at one FName-API call site, followed by an `FNameEntryHandle`-shaped comparison/lookup (not further named) |
| `0x1410d2920` | 336 B | 1 | `GetNamePool()` inlined at a second, different call site, followed by name-to-string logic (`"_"` + number suffix, matching `AppendString`-family source at line 3455/3575) — checked for cross-validation only, not signed |
| `0x1410bd290`, `0x1410bcfa0` | — | — | both contain `"FName length is too long; HashLowerCase..."` — two distinct functions with the identical string, consistent with case-sensitive/case-insensitive (or ANSI/WIDE) hash variants; found via the same batch, not decompiled further, corroborating only |

Decompiled JSON: `fun-fnamepool-ctor-1410be2c0.json`, `fun-caller-1410bc2f0.json`,
`fun-caller2-1410d2920.json`. Full C text under `workspace/xrefs/fun-*.c`.

### The constructor (`0x1410be2c0`) — matches the predicted shape at its very first instructions

```c
InitializeSRWLock(param_1);                 // first shard-adjacent lock in the object
param_1[1].Ptr = (PVOID)0x0;
memset(param_1 + 2, 0, 0x10000);             // zero exactly 8192 * 8 = 0x10000 bytes at offset 0x10
...
pRVar6 = param_1 + 0x2008;                   // offset 0x10040, right after the Blocks[] region
do {
    InitializeSRWLock(pRVar6); ...            // 256 iterations, 64-byte (cache-line) stride
    pRVar6 = pRVar6 + 8;
} while (--lVar15 != 0);
```

`0x10000 = FNameMaxBlocks(8192) * sizeof(pointer)(8)` — the exact size of `Blocks[FNameMaxBlocks]`
(source line 697), zeroed at the position `FNameEntryAllocator` occupies as `FNamePool`'s first
member. The 256-iteration loop immediately after, each iteration calling `InitializeSRWLock` and
advancing by 64 bytes, matches `FNamePoolShard` being `alignas(PLATFORM_CACHE_LINE_SIZE)`
(source line 990) with `FNamePoolShards = 1 << FNamePoolShardBits`; 256 matches
`FNamePoolShardBits = 8` (the `#else` branch of source line 708), i.e. this build was **not**
compiled with `WITH_CASE_PRESERVING_NAME`) — an incidental, checkable build-config fact this match
also pins down, not assumed going in.

The `"Duplicate hardcoded name"` string sits, per source, inside the tail of this same constructor
(after the `REGISTER_NAME` loop, lines 1616-1630) — and this is exactly where
`dump_xrefs_for_string.py` found its one reference, inside this one function.

### The two callers — where the fixed address is spelled out

`FNamePool::FNamePool()` takes `this` as a parameter (RCX); it does not hardcode its own address —
expected, since C++ constructors always take `this` by parameter regardless of how many callers
exist. Both of the two callers checked show the **identical** lazy-init idiom, byte-for-byte the
same two addresses:

```c
// 0x1410bc2f0
if (DAT_147995e5e == '\0') {
    puVar15 = (undefined *)FUN_1410be2c0(&DAT_1479c2180);
    DAT_147995e5e = '\x01';
} else {
    puVar15 = &DAT_1479c2180;
}
puVar10 = (ushort *)((param_1&0xffff)*2 + *(longlong*)(puVar15 + (param_1>>0x10)*8 + 0x10));

// 0x1410d2920 -- a different function entirely (builds a "_<number>" string suffix), same idiom:
if (DAT_147995e5e == '\0') {
    puVar4 = (undefined *)FUN_1410be2c0(&DAT_1479c2180);
    DAT_147995e5e = '\x01';
} else {
    puVar4 = &DAT_1479c2180;
}
... *(longlong *)(puVar4 + uVar2 * 8 + 0x10) ...     // uVar2 = (param_1>>0x10 & 0xffff), same shape
```

This is a byte-for-byte match of the source idiom quoted above (`if (bNamePoolInitialized) return
cached; else construct, set flag, return`), found **identically in two structurally unrelated
functions** — one that looks like a name comparator, one that looks like a name-to-string builder.
Both also immediately use the resolved pointer the same way: `(Block>>16 or param>>0x10) * 8`
indexes a pointer array at `+0x10` (matching `Blocks[FNameMaxBlocks]` at the same offset identified
inside the constructor above), and `(Offset&0xFFFF)*2` scales the low 16 bits by the entry stride —
exactly the `FNameEntryHandle`/`FNameEntryAllocator` shape read from source (lines 256, 443-444,
697), with the same `FNameBlockOffsetBits=16` split confirmed a second, independent way.

- `DAT_1479c2180` = **`0x1479c2180`** — **`NamePoolData`**, the static byte buffer that becomes the
  live `FNamePool` object once constructed.
- `DAT_147995e5e` = **`0x147995e5e`** — **`bNamePoolInitialized`**, the lazy-init guard byte.

## Attempt to refute

- **Alternative explanation for `0x1479c2180`/`0x147995e5e`?** None found. Both are `static`
  (internal linkage, file-scope) in one translation unit, so every reference anywhere in the binary
  to either must be this exact pair — there is no `extern` variant and no factory. Two structurally
  different callers (out of 26 found; checking all 26 was not attempted — see below) reproduce the
  identical two-address idiom and the identical immediately-following block-array access shape.
- **Could this be some other lazily-initialized singleton that happens to look the same?** The
  specific combination — a byte flag, an `alignas(T)` buffer sized `sizeof(T)`, a placement-new
  call, immediately followed by shift-16/mask/×2 indexing into a pointer array at `+0x10` — is the
  `FNamePool`/`FNameEntryAllocator` shape specifically (`FNameBlockOffsetBits=16` is not a generic
  constant; it was read from this exact source file for this exact purpose). No other UE singleton
  uses this exact bit-split.
- **Section membership**: both `0x1479c2180` (RVA `0x39c2180`) and `0x147995e5e` (RVA `0x395e5e`)
  fall inside `.data` — consistent with mutable, lazily-initialized storage (not `.rdata`/const).
- **What was NOT checked**: only 2 of the 26 distinct callers of the constructor were decompiled;
  the other 24 were left unchecked (time-box, and the two checked already show independent
  structural agreement from functionally unrelated code paths — a comparator and a stringifier).
  This is weaker cross-validation than RF-05's (which checked 4 of its candidate's access paths and
  matched 6 distinct struct fields); reflected in the confidence number below, not silently equalized
  with RF-05's.

## Grade

**HYPOTHESIS**, class I, oracle `binary-analysis`, confidence **0.60**.

Slightly below RF-05's 0.65: the match is still strong (two independently-structured callers agree
byte-for-byte on both addresses and on the immediately-following access shape, and the anchor string
is unconditionally compiled rather than logging-gated), but fewer distinct `FNamePool` struct fields
were exercised and confirmed (effectively one — the `Blocks[]`-at-`+0x10` array — versus RF-05's
six), and only 2 of 26 available callers were cross-checked rather than a wider sample. Same
absolute ceiling applies regardless: no runtime observation exists for this build.

## What a runtime observation would need to show to move this above HYPOTHESIS

1. Read the byte at `bNamePoolInitialized` (`0x147995e5e`); expect `1` on any process that has
   completed engine bootstrap (true almost immediately after process start — thousands of FNames
   are constructed during static init).
2. Using a **known** `FNameEntryId` — `0` (`EName::None`, guaranteed to exist, source: `ENameToEntry[NAME_None]`
   registered first) is the cheapest one — apply the recovered arithmetic (`Block = Id>>16`,
   `Offset = Id&0xFFFF`, dereference `Blocks[Block]` at `NamePoolData+0x10`, index by `Offset` at the
   recovered entry stride) and decode the resulting bytes as an `FNameEntry` (length/wide-flag header
   per `NameTypes.h`, then the characters). **Confirmation is reading out the literal text `"None"`.**
3. Cross-check with RF-05: resolve the `FName` of a live `UObject` found via the RF-05 candidate
   through this same arithmetic and confirm the decoded text is a plausible class/object name.

Failing (2) — decoding garbage instead of `"None"` — would refute the candidate outright. This is
the `RF-11` deliverable named in `plan.md` line 538.

## Signatures

`tools/static/sigmake.py`, same image/build as RF-05, default `grow` mode, `reloc` mask policy. 2 of
2 requested accepted, unique across every initialized section, `masked_fraction = 0.000`.

| Label | RVA | Pattern length | Function size |
|---|---|---|---|
| `FNamePool_ctor_candidate` | `0x10be2c0` | 32 | 13 007 B |
| `GetNamePool_inlined_caller_candidate` | `0x10bc2f0` | 20 | 494 B |

Full documents: `signatures.json` (refutation probes, all `not_refuted`), `signatures.jsonl`,
`library.json`.

## Reproduce

```
D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_xrefs_for_string.py ^
  --needle "FNamePool.DuplicateHardcodedName" --needle "Duplicate hardcoded name" ^
  --needle "FName overflow, allocated" ^
  --needle "FName length is too long; HashLowerCase value is undefined" ^
  --needle "Failed to align numbered FName data" ^
  --needle "Cannot make a string view for a name-with-number entry" ^
  --needle "FName's %d max length exceeded. Got %d characters excluding null-terminator:" ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe ^
  --out research\evidence\RF-06\xrefs-fnamepool-summary.json --jsonl-out workspace\xrefs\fnamepool.jsonl

D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_function.py --function 1410be2c0 ^
  --out research\evidence\RF-06\fun-fnamepool-ctor-1410be2c0.json --c-out workspace\xrefs\fun-1410be2c0.c

D:\Tools\venv-research\Scripts\python.exe tools\static\sigmake.py D:\Tools\ghidra-workspace\bin\MISERY-Win64-Shipping.exe ^
  --rva 0x10be2c0=FNamePool_ctor_candidate --rva 0x10bc2f0=GetNamePool_inlined_caller_candidate ^
  --out research\evidence\RF-06\signatures.json --jsonl-out research\evidence\RF-06\signatures.jsonl ^
  --library-out research\evidence\RF-06\library.json
```
(run from PowerShell — Git Bash mangles the leading-backslash `D:\tools\...` project-root argument)

## What this does NOT prove

- Not that `0x1479c2180` is correct for any build other than the one identified by the `build_key`
  above.
- Not the full field layout of `FNamePool`/`FNameEntryAllocator`/`FNameEntry` beyond the one array
  (`Blocks[]` at `+0x10`) and the two bit-split constants (`Block = id>>16`, `Offset = id&0xFFFF`)
  directly exercised by the two checked callers. `FNamePoolShards`, `DisplayShards`/
  `ComparisonShards` offsets, and `FNameEntry`'s own header bit layout were read from source (cited
  above) but not independently located in the disassembly this pass — a cheaper next step (grep the
  24 unchecked callers for the same idiom, or decompile `FNameEntryAllocator::Create` directly) if
  this candidate needs to be strengthened before RF-11.
- Not that the game is running or that this address is mapped in a live process.

## Operational note (not a game finding)

Same stale-lock behavior as recorded in `research/evidence/RF-05/README.md` was hit twice more
while producing this evidence (`LockException` immediately after a prior clean exit, no live `java`
process present, `.lock`/`.lock~` safely removable). Not re-documented in full here; see RF-05's
README for the one write-up.
