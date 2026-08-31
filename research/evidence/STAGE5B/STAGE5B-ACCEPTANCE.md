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
| `stage5b-resolver-lifecycle.json` — 3 fresh launches, menu → load → gameplay, chunked resolver | 87 | **PASS** |
| `stage5b-bindings-acceptance.json` — 3 normal Steam launches + 5 refusals + install audit | 63 | **PASS** |
| `stage5b-failclosed.json` — proxy-layer refusals, 5 launches | 24 | **PASS** |
| `stage5b-gamethread-cost.json` — the measured cost curve the slice budget was sized from | — | evidence |

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
runtime: resolved on thread 16332 (this thread is 12408) over 25 slice(s);
         LONGEST SLICE 2034us (slice #13) -- walk 45164us + anchors 299us
         + validate 42us, 6866 queued; 26263 objects processed,
         0 restart(s), 0 revalidation failure(s)
runtime: 211201 reads, 1422 VirtualQuery, 209779 cached;
         phase requested startup, completed startup
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

## The frame cost, measured and then bounded

A whole walk on the game thread was measured before anything was changed, at
both ends of the range. The extrapolation that preceded it was wrong by 3x,
which is why the budget was sized from the measurement instead:

| | menu | gameplay |
|---|---|---|
| objects | 26 263 | **194 701** |
| walk | 20.4 ms | **265.5 ms** |
| anchor resolution | 10.3 ms | **215.7 ms** |
| total, in ONE slice | 30.7 ms | **481.2 ms** |
| reads | 210 975 | 1 558 765 |
| `VirtualQuery` | 3 552 | 106 802 |
| cache hits | 98.3 % | 93.1 % |

481 ms is ~29 frames at 60 fps. Two things came out of the breakdown that an
extrapolation would never have shown: anchor resolution was 45 % of the cost,
and it was one call — `AllOfClass`, scanning every object to find the player
inventory — so slicing the walk alone would have left a 216 ms hitch immediately
before publish.

### What the chunked resolver then measured, 3 launches each

| | menu (26k objects) | gameplay (~200k objects) |
|---|---|---|
| slices | 23–25 | 152–183 |
| **longest slice** | **2 008 / 2 054 / 2 027 µs** | **6 460 / 6 223 / 6 204 µs** |
| longest slice was | a walk slice (= the budget) | slice 0, the map allocation |
| walk, summed | 41–45 ms | 301–363 ms |
| anchor resolution | 0.25 ms | 1.2–3.4 ms |
| live re-validation | 0.04 ms | 0.08–0.21 ms |
| restarts | 0 | 0 |

Every walk slice sits on the 2 ms budget to within 3 %. The only slice above it
is the one-off allocation that sizes the maps for the process, reproducible to
4 %, and it does nothing else. Production's own log shows the same machinery at
menu counts: 25 slices, longest 2 034 µs, on thread 16332 while the requesting
thread was 12408.

**Total CPU went UP, deliberately** — 301–363 ms of walk against 265 ms
unchunked. Indexing objects by name and by class during the walk is what costs
that, and it is what deleted a 215.7 ms anchor step no amount of slicing could
have hidden. Total CPU is not the property being bought; a frame nobody notices
is.

### The trade, stated

* **frame time**: ≤ ~2 ms per walk slice, one ~6.5 ms setup slice at gameplay
  object counts, against a single 481 ms stall before.
* **latency**: ~150–200 ticks for a gameplay resolution, so ~3 s at 60 fps;
  ~25 ticks (~0.4 s) at menu counts. Resolution happens at startup and after a
  load, and nothing waits on it interactively.
* **memory**: three hash maps sized for the object count, which is what the
  setup slice spends its 6.5 ms allocating and zeroing.

### Four defects found here, each by a number rather than by reasoning

1. **A 3x-wrong extrapolation.** ~160 ms predicted, 481 ms measured.
2. **Move-to-front on the region cache was blamed for a walk regression it did
   not cause.** Replacing it barely moved the menu figure (52.0 → 50.3 ms); the
   cost was the per-object index inserts. It was kept because it did help at
   gameplay (425.7 → 349.9 ms).
3. **A 14.1 ms slice** — the anchor step sharing a tick with the walk's tail.
   Each step now gets its own tick.
4. **Mid-walk spikes of 3.3–7.8 ms** — `by_name_`/`by_class_` rehashing, found
   only because `max_slice_index` reported the longest slice was in the MIDDLE
   of the walk. Reserving them took the menu maximum to the budget itself.

`max_slice_index` also exposed that it was being reported 1-based, which had
produced a confident and wrong correction about slice 0. Both are fixed.

## What is owed on it

Two levers are deliberately unused, because the property holds without them and
neither is needed: `by_name_.reserve(n)` over-allocates (distinct names are well
below object count), and the three reserves could be split across three slices to
take slice 0 from ~6.5 ms to ~2–3 ms.

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

**The restart and re-validation paths have never fired.** Across every live run
— menu, mid-load and gameplay, on every launch — `restarts` and
`revalidation_failures` were both 0. The machinery that detects the object graph
moving under a multi-tick walk, the refusal to publish a result whose phase fell
below the request, and the cancel/restart loop are therefore correct by
construction and exercised by NO live evidence. They are untested, not proven.
Provoking them needs a resolution deliberately raced against a level load.
