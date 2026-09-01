# The framework killed the game

On 2026-09-01, during a Stage 7 acceptance run, MISERY died with an unhandled
access violation while entering gameplay. Every frame of the call stack was
`MiseryRuntime`. This is the record of what happened and what was wrong.

## What the game said

```
Unhandled Exception: EXCEPTION_ACCESS_VIOLATION reading address 0x000001502958e08c

MiseryRuntime  +87d6a
MiseryRuntime  +3a07d
MiseryRuntime  +3243
MiseryRuntime  +364c7
MiseryRuntime  +6f14
MiseryRuntime  +1bb8
MiseryRuntime  +2c36
KERNEL32       +2e8d7
```

The full context is in `CrashContext.runtime-xml`.

## Symbolising it

The production runtime ships without a PDB, so the addresses were resolved by
rebuilding the same sources with the same flags plus `/MAP` and **proving the
rebuild was the same code**: the `.text` section of the rebuilt DLL is
byte-identical to the DLL that crashed. Without that comparison the names below
would be guesses.

```
+087d6a  MoveSmall4                             (the CRT's small memcpy)
+03a07d  misery::resolve::ReadBytes             +0x14d
+003243  misery::resolve::Read<unsigned int>    +0x23
+0364c7  misery::resolve::CheckSlotIdentity     +0x67
+006f14  misery::content::Acquire               +0x1b4
+001bb8  ContentLifecycle                       +0x68
+002c36  RuntimeThread                          +0xae6
```

`KERNEL32` at the bottom means this is the framework's own worker thread, not
the game thread.

## What the faulting address was

The runtime log for that session records, one second earlier:

```
runtime: generation 1 anchor ItemList: index 53319, serial 0, 0x1502958e080
```

The fault was at `0x1502958e08c` — that anchor **+0x0C**, which is
`UObjectBase::InternalIndex`, read as a `uint32_t`. The game thread had freed
the content generation's objects; the worker thread read one of them.

## The two defects

**1. `CheckSlotIdentity` asked the object before it asked the array.**

Its first act was to read the object's own `InternalIndex` in order to find the
slot to validate it against. So the check for *"has this object been freed"*
began by dereferencing the object it was asking about. During a content
transition that is precisely the object being freed.

The dereference was never necessary: `AnchorIdentity::internal_index` is
recorded when the anchor is captured, and the function already compared against
it. `GUObjectArray`'s chunks are stable for the life of the process, so the slot
can be read with no risk. The fix reverses the order — the array decides, and
the object's memory is not touched until the slot still names that address. The
object's own claim is kept as a cross-check, now made safely.

`Resolver.h` carried the assumption that made this look safe:

> Name and class are what the object CLAIMS to be and survive its destruction,
> because freed UObject memory keeps its bytes until something reuses them.

Freed memory keeps its bytes only while the pages remain committed. They need
not.

**2. `ReadBytes` could not be made safe by `VirtualQuery` alone.**

`ReadBytes` validates with `VirtualQuery` before copying, and caches validated
regions so repeat reads skip the query. Neither helps here: the framework reads
memory owned by the game, from a thread the game does not know about, and the
game may release it between the answer and the copy. No ordering of
`VirtualQuery` and `memcpy` closes that window.

A faulting read is now caught and turned into a refused read — `false`, a value
`ReadBytes` already returns and every caller already handles — and counted in
`resolve::GuardedFaultCount()`, which the runtime logs whenever it is non-zero.
A guarded fault is not normal: it means the framework raced the game and lost.

## Why both fixes, and not just the second

The guard alone would have converted a crash into a silent wrong answer on a
path that is *expected* to run at every transition. The ordering fix removes the
routine case; the guard covers the residual race that cannot be designed away.

## The regression guards, and proof they guard something

Both are in `runtime/tests/slot_validation_harness.cpp`.

| case | what it pins |
| --- | --- |
| `the slot decides with the object unreadable` | an object on an unreadable page whose slot is marked Garbage must still report `kGarbage` |
| `a page freed under a cached region is refused` | a decommitted page inside a cached region must return `false`, not fault |
| `and the fault was counted, not swallowed` | `GuardedFaultCount()` increments |

A test that also passes against the broken code guards nothing, so each was run
against a build with only its own fix reverted:

- ordering reverted → `[FAIL] the slot decides with the object unreadable
  got=its InternalIndex is unreadable` (the old behaviour exactly)
- `CopyGuarded` replaced by a plain `memcpy` → the harness is killed with exit
  code `0xC0000005`, the same access violation that killed the game

## Note on the run this came from

The crash aborted a Stage 7 acceptance whose earlier, successful run had already
demonstrated the item reaching the player's inventory. The transition being
executed was the same one in both runs; the difference is timing. This was not
reproduced on demand — it was caught once, and the harness now reproduces its
mechanism deterministically.
