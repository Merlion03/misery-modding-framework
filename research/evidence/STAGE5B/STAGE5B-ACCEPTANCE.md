# STAGE 5B — Production launch path (in progress)

**Status: the launch path and the resolver are proven; the stage is NOT closed.**
An ordinary Steam launch now starts the framework with no research controller,
no injection step and no manual action, and the in-process C++ resolver has
replaced the Python oracle for every fact the Items backend needs. Steps 2–5 of
the stage plan — native subsystems, CoreCLR, the Stage 4 load-plan port, and C#
mod execution on this path — have not been done.

**Build:** `misery-24953925-ue5.4.4-bace50f7185d`, UE **5.4.4** CL **35576357**,
Shipping x64. **Bindings profile version:** 1.

## The path that actually ran

```text
Steam Play
  └─ MISERY-Win64-Shipping.exe
       └─ dwmapi.dll                 our proxy: forwards 44 exports, nothing else
            ├─ binds the real dwmapi from System32 by absolute path
            └─ bootstrap thread
                 ├─ SHA-256 of the running executable        (CryptoAPI)
                 ├─ bindings.json must claim that digest     (cheap substring check)
                 └─ MiseryRuntime.dll → MiseryRuntimeBootstrap(...)
                      ├─ profile loaded + validated against THIS executable
                      ├─ every recorded code address compared to mapped bytes
                      ├─ waits on the engine's own bNamePoolInitialized guard
                      ├─ game-thread carrier activated (FTSTicker, signature-gated)
                      └─ startup anchors resolved ON THE GAME THREAD
```

## Results

| Run | Checks | Verdict |
|---|---|---|
| `stage5b-resolver-oracle-crosscheck.json` — C++ resolver vs the Python oracle, same live process | 9 | **PASS** |
| `stage5b-resolver-lifecycle.json` — 3 fresh launches, menu → load → gameplay | 72 | **PASS** |
| `stage5b-bindings-acceptance.json` — 3 normal Steam launches + 5 refusals + install audit | 63 | **PASS** |
| `stage5b-failclosed.json` — proxy-layer refusals, 5 launches | 24 | **PASS** |

Offline: full suite **2445 passed**, 1 skipped, 533 subtests; `tools/kb/validate.py`
exit 0.

## What the launches established

**The framework starts from Steam with nothing else involved.** Three
consecutive launches: the proxy handed over, the runtime loaded, read the profile
for this build, matched every recorded code address against mapped memory,
waited for the engine rather than sleeping at it, and resolved the startup
anchors. The game kept running in all three.

**Resolution runs on the game thread, and the log proves it rather than
asserting it.** Production records both the thread that executed the walk and
the thread that asked:

```
runtime: resolved on thread 13888 (this thread is 18844) -- cost 6691us queued
         + 19102us walk + 10525us anchors; 210975 reads, 3596 VirtualQuery, 207379 cached
```

Across the sweep, every resolution in a process — menu, mid-load and gameplay —
reported the same single thread, and a different one per process.

**The second lock works.** Five profiles were built to PASS the proxy's cheap
digest check and be refused by the runtime's own validation: one wrong recorded
code byte, a `build_key` for another build, an unknown `bindings_version`, an
RVA outside the image, and another engine version. All five were refused, each
naming its actual reason, with the game still running vanilla. A profile that
only failed the cheap check would have proven nothing about this layer.

**The game installation is unchanged except for the designed surface.** Audited
against the committed baseline inventory rather than by inspection: seven
differences, every one an addition, all inside `MiseryFramework/` or the proxy
itself. No original game file was modified, resized, rehashed or removed.

## Facts the sweep measured that changed the design

**Content identity does not survive a load.** The item tables, the game's own
Blueprint classes, their CDOs and the three UFunctions on them are destroyed and
recreated when the menu world is replaced by the game world. Each holds one
address while content is loaded without a player and a different one once
gameplay is reached — one change, at the phase boundary, then constant across
every gameplay sample. A content pointer resolved before gameplay is therefore
dangling by the time the player exists.

**Content availability at the main menu is not deterministic.** Two launches had
no item tables at the menu; a third, same build and same save with nothing loaded
by the player, had the *entire* content set resolvable there. An earlier version
of the sweep asserted the absence as a rule on the strength of two observations.
It is now recorded as an observation, and only what holds every time is checked.

Together these two are why phase scoping is physical rather than advisory. A
result scoped to startup has content and gameplay anchors cleared even when the
walk found them, and they are reported in `observed_out_of_phase` — deliberately
NOT in `missing`, because calling a present object absent would be a lie in the
diagnostics. `reached` is computed before scoping, so a caller is still told the
truth about the process while being refused pointers whose lifetime ends at the
next transition.

**A half-linked class is not a wrong class.** One sample in thirteen caught
`BP_StaticMasterItem_C` existing and named while its `Super` was still null,
mid-swap. The first version of the derivation check called that "does not derive
from Actor" and hard-failed — from survey mode, whose contract is to report
everything and fail at nothing. `DerivesFrom` now distinguishes a chain that
stops at its first hop (unfinished, transient) from one that reaches a different
root (a real type error); neither is fatal in survey, neither is fatal below the
phase that needs the class, and in both cases the anchor is reported rather than
accepted.

## The frame cost, and what is owed on it

A whole walk on the game thread costs, measured and reproducible to within a
millisecond across six runs at the menu:

| | |
|---|---|
| objects | 26 263 |
| reads | 210 975 |
| `VirtualQuery` issued | ~3 500 |
| cache hit rate | 98.3 % |
| walk | ~20 ms |
| anchor resolution | ~10 ms |

The per-walk region cache is what makes this affordable at all: without it every
field read is its own syscall, ~211 000 of them. It is reset at the start of
every walk so a stale "this region is readable" answer cannot outlive one
resolution.

**~30 ms is still roughly two frames at 60 fps, and this is not yet resolved.**
The gameplay phase carries ~208 000 objects rather than 26 000, which
extrapolates to ~160 ms on the same per-read cost — a number that has NOT been
measured, because the cost was only instrumented in the menu block. The next
work is to capture that number and chunk or budget the walk across ticks. The
rule is recorded in `ResolveOnGameThread.h`: traversal does not move back to an
arbitrary thread to buy frame time.

## What is NOT established

**The launch-3 process death is unexplained.** During an earlier run a game
process died during a level load while the resolver was being polled from a
remote thread. No crash dump and no Application-log entry were produced. The
off-thread walk is a **suspect, not a cause**: the mechanism was never
reproduced or independently established. The invocation model was changed
because it is unsafe by construction during object churn — validation of a page
and the dereference of an address in it cannot be one atomic step — and not
because this death was accounted for. It should not be cited as evidence that
the change was necessary.

**Steps 2–5 of the stage plan are not done.** The runtime consumes bindings and
resolves; it does not yet start the native subsystems, CoreCLR, the Stage 4 load
plan, or run C# mods on this path. The final Stage 5B acceptance — Steam Play to
a C# item the game's own SGK lookup resolves, with no controller — remains open.

**Content and gameplay anchors have never been resolved on this path.** The
production runtime asks only for the startup phase. Whatever consumes content
must re-resolve after every load rather than caching, which follows directly
from the identity measurement above and has no implementation yet.

**The carrier is never torn down on this path.** `Teardown` exists and is not
called; the pump holds this module for the process lifetime. That is acceptable
while the framework does not unload itself mid-game, and is a real constraint on
any future in-game unload.
