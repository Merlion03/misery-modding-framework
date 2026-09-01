# STAGE 5B — Production launch path (in progress)

**Status: steps 1 and 2 are proven; the stage is NOT closed.** An ordinary Steam
launch starts the framework with no research controller, no injection step and no
manual action; the in-process C++ resolver has replaced the Python oracle; and
the runtime now declares the game thread, acquires the frozen bridge root, and
reaches the CONTENT phase by itself. Steps 3–5 — CoreCLR, the Stage 4 load-plan
port, and C# mod execution on this path — have not been done.

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
| `stage5b-resolver-race.json` — resolutions fired continuously across a real transition | 8 | **PASS** |
| `stage5b-subsystems.json` — step 2: game thread, bridge, content phase, on a Steam launch driven to gameplay | 12 | **PASS** |

Offline: full suite **2448 passed**, 1 skipped, 533 subtests; `tools/kb/validate.py`
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

## Step 2 — the proven native subsystems, started by the runtime

Verified on a Steam launch driven into gameplay, because content does not exist
at a main menu and a run that settled there would prove nothing about it:

```
runtime: game thread declared as 14748 (measured, not assumed)
runtime: bridge acquired, ABI epoch 1, root 40 bytes
runtime: content not available yet (attempt 1/20): ItemList: no object named
         'ItemList' of class 'DataTable' exists in this process [content phase]
runtime: content not available yet (attempt 2/20) ...
runtime: content not available yet (attempt 3/20) ...
runtime: content resolved on attempt 4 -- reached content over 57 slice(s),
         longest 2016us, 61410 objects, 0 restart(s)
runtime: ItemList 0x1421f20c7c0, MasterItemList 0x1421c7e7320,
         RowStruct 0x1421dee3b20 (2264 bytes)
runtime: native subsystems ready
```

**The game thread is declared from a measurement.** Every bridge call is
thread-checked, so a wrong declaration would refuse every legitimate call and
admit every illegitimate one, silently. The runtime declares the thread the
resolver reported actually running the walk, and the acceptance requires those
two independent log statements to name the same id.

**Waiting for content ASKS rather than infers.** Presence could be guessed from
the live object count — measured, the menu sits at ~26k and content at ~63k —
but a threshold between two measurements is a tuned constant standing in for an
answer the resolver already gives authoritatively. Three attempts refused with a
named reason and the fourth resolved, which is the wait working rather than
succeeding by luck.

**Never reaching content is not a failure.** A player who stays at the main menu
is an ordinary process; the framework logs that it stopped asking and remains
loaded and harmless. Only a *wrong* answer is fail-closed, never an absent one.

The chunking holds here too: 57 slices, longest 2 016 µs at 61 410 objects, and
the live row struct is 2 264 bytes — the width the binding profile records, so
the resolved content and the profile describe the same build.

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

**Steps 3–5 of the stage plan are not done.** The runtime consumes bindings,
resolves, declares the game thread, acquires the bridge and reaches content. It
does not yet install the items backend, start CoreCLR, port the Stage 4 load
plan, or run C# mods on this path. The final Stage 5B acceptance — Steam Play to
a C# item the game's own SGK lookup resolves, with no controller — remains open.

**Content is resolved ONCE and not re-resolved after a later load.** The runtime
holds no load signal, so a second transition would leave anything derived from
those anchors dangling. Nothing consumes them yet, which is why this is a
constraint on step 3 rather than a defect today.

**Content and gameplay anchors have never been resolved on this path.** The
production runtime asks only for the startup phase. Whatever consumes content
must re-resolve after every load rather than caching, which follows directly
from the identity measurement above and has no implementation yet.

**The carrier is never torn down on this path.** `Teardown` exists and is not
called; the pump holds this module for the process lifetime. That is acceptable
while the framework does not unload itself mid-game, and is a real constraint on
any future in-game unload.

**The destruction window has never been hit live, and that is now a stated
limitation rather than an open question.** Resolutions were fired back-to-back
across three real menu → gameplay transitions — 253 attempts, with validation
confirmed executing on all of them — and `restarts` and `revalidation_failures`
were 0 every time. The reason is structural: the transition destroys the old
generation and creates the new one with a gap between, so a resolution landing
there sees *absent*, which is a legitimate answer, rather than *stale*.

What that hunt DID expose was a real safety hole. The original post-walk check,
`StillIs`, re-reads an object's own name and class — and both survive
destruction untouched until the memory is reused. It therefore detected RECYCLED
memory, not FREED memory, and would have published a destroyed object as live.
Prior lifecycle work had already documented the same trap: *"DestroyActor does
not remove anything from GUObjectArray; it marks the object and the slot
survives until the next GC."*

Validation now asks the engine's own bookkeeping first. For every anchor whose
lifetime matters, the walk captures `InternalIndex` and `SerialNumber` while the
slot is already under the cursor, and publication requires all of: the object
still claims that index, `FUObjectItem.Object` still points back at it, the
serial still matches, and neither `Garbage` (ObjectMacros.h:616), `Unreachable`
(:643) nor the mirrored `RF_Garbage` (:576) is set. `StillIs` is kept as a
second, independent identity check — no longer the liveness test.

Because the timing cannot be forced, the refusal itself is proven
deterministically instead, by `tests/test_slot_validation.py` driving the real
`Universe` against a synthetic object array the harness owns. Every branch is
covered, including the case that motivated the change: **a destroyed object with
intact bytes passes the semantic check and is refused by the slot check.**

So the honest split is:

* **proven deterministically** — every liveness refusal branch;
* **proven live** — validation executes; no refused attempt publishes anchors;
  engine-lifetime anchors identical across every attempt; content generations
  published in clean succession, never interleaved, across a real world swap;
* **not proven** — a destruction landing inside a resolution's own walk. The
  cancel/restart loop and the phase-fell-below refusal have still never executed
  in a live process.

**Selection may still count garbage objects as live.** The same lifecycle note
applies to `One()` and `AllOfClass`, which look for objects without consulting
the slot flags — so a destroyed-but-uncollected duplicate could make a lookup
ambiguous, or put a dead instance in a candidate set. Publication is now safe
either way, because nothing reaches a consumer without passing the slot check.
Tightening selection was deliberately left out of scope and is unaddressed.

## Step 3 — a C# mod registers an item a player could find

The chain, with no controller anywhere in it:

    Steam Play
      -> MiseryBootstrap (dwmapi proxy)   -> exact build fingerprint
      -> MiseryRuntime                    -> binding profile verified against live code
      -> content generation 1 published   -> CoreCLR + Misery.ModHost
      -> alphamod OnLoad                  -> ctx.Items.Register(...)
      -> a real world                     -> the game's own SGK ItemDetails resolves the row

`research/evidence/STAGE5B/stage5b-managed-items.json`, 11 of 11.

### A registration is a declaration, not a write

The first design wrote the row inside `Register`. That is wrong twice over, and
the live run showed both:

* A mod's `OnLoad` runs when the managed host starts, which is when the first
  content generation exists — the **main menu**. There is no player inventory
  there, so the registration path cannot even initialise, and every mod died on
  load with an error that said nothing about the mod.
* An item row lives in a DataTable belonging to one world. Written once, it
  would vanish at the first level load and never return.

So a mod declares an item once and the framework owns applying it: to the
current world if one can hold it, and to each world that follows. The row name
is derived from `(mod_id, local_id)`, so the mod is told its name immediately
even when the row cannot exist yet.

This is also why proving a transition needs no invented gameplay event. The mod
says nothing at transition time; the framework re-applies.

    generation 1 published -- content, 61458 objects
    'alphamod__managedshape' declared; deferred until a world exists to hold it
    generation 1 is revoked: 'ItemList' it no longer claims the slot it was found in
    generation 2 published -- gameplay, 198153 objects, 218 slice(s), longest 7053us
    items: backend bound to content generation 2
    'alphamod__managedshape' is live in generation 2; the game's own SGK ItemDetails resolved it

### Phase scoping nearly defeated this, and was not weakened

The content lifecycle asked for `kContent`, and a phase request is a lifetime
contract: anchors above it are **physically cleared**. A generation whose
`reached` was gameplay therefore carried no player inventory, and no declared
item could ever have been written.

The fix is `Request::prefer_gameplay` — try for the higher scope, fall back to
what the caller requires. It costs a second pass of hash probes, not a second
walk, because `ResolveAnchors` is a pure function of the already-built universe.
Whichever attempt succeeds, the result is still physically scoped to the phase
it was granted.

### Four defects, each reachable only once the previous was fixed

1. **Discovery invented a layout.** Directory name as both mod id and assembly
   stem, when Stage 4 had long since established `mod.json` + `Code/`. It
   rejected the framework's own fixture, whose id (`alphamod`) and assembly
   (`AlphaManagedMod.dll`) legitimately differ. Now reads Stage 4's own layout;
   `tests/test_mod_discovery.py` covers it, including an ambiguous id loading
   nothing rather than letting enumeration order pick a winner.
2. **The host reported success having loaded nothing.** `{"ok":true}` with an
   empty `loaded` list, and the acceptance's `"ok":true` check passed on it.
   `ok` now means the host is up; `all_loaded` and the counts answer the
   question a caller actually has.
3. **A 43-way null check returning one code.** `0xfffffffd` said nothing about
   which input was absent. It names the field now — `player_inventory`, which is
   what exposed the menu problem above.
4. **Two ordering rules that lived only in Stage 5A's controller.**
   `Init -> RunCreate -> RunAttach -> register`. Production knew none of it.
   Create builds the aggregate table; **Attach** makes it `MasterItemList`'s
   second parent and fires the neutral trigger that rebuilds the composite.
   Without Attach the rows were written correctly into a table the game's own
   lookup had never been told about — five verification attempts over a minute
   all returned not-found. Both steps are now ensured inside the registration
   itself: a caller cannot forget a step the function takes for itself.

And `EnsureForGeneration` re-`Init`ed without `Shutdown`, which `Init` refuses.
That path had never executed, because nothing had ever succeeded before it; its
first execution would have been the level transition this backend exists to
survive.

### The write and the lookup are different claims

`Stage5VerifyRow` asks the game's own lookup about a row without registering
anything, on later polls, up to five times. It earned itself immediately: by
returning not-found five times over a minute it ruled out composite-rebuild
latency and forced the search for a structural cause, which was Attach.

### Two guards that were missing, not wrong

* The offline harnesses had no build recipe — they were compiled by hand, so
  `tests/` skipped silently wherever nobody had run the right command from
  memory. `nativebuild.build_harnesses` now records all three.
* `build_exe` never called `_check_warnings`. `FATAL_WARNINGS` existed and
  covered only DLL builds, so `discovery_harness.cpp` compiled with a dropped
  `\*` escape — the exact C4129 the project already treats as fatal, for the
  exact reason it was made fatal. Verified the guard now fires.

### Step 3, second acceptance — a real transition, survived

    gameplay generation N   item live, the game's own SGK lookup resolves it
      -> one controlled REAL transition
    generation N revoked    'live player inventory' no longer claims its slot
      -> a production consumer is refused by the gate
    gameplay generation N+1 fresh anchors, declaration reapplied, resolvable again

`research/evidence/STAGE5B/stage5b-transition.json`, 15 of 15.

    research probe        CAUSES the transition, and nothing else
    production runtime    detects / revokes / resolves / reapplies

The probe registers one ticker callback and makes one ProcessEvent call to
`APlayerController::RestartLevel` -- zero parameters, measured on this build and
re-measured live before the call, because a wild call into the engine is not a
thing to discover empirically. It contains no code that can read an anchor,
write a row, reach the items backend, or learn that content generations exist.
Its recorded effect is exactly `called: 1, callback_count: 1`, on the game
thread. Everything after that is the production runtime's own doing, read out of
its own log.

#### An address is not an identity, and this transition proves it

The first version of the "N and N+1 are genuinely different" check compared the
three table addresses and required all three to differ. It failed, and it
deserved to:

    N    ItemList 0x19e8b0b1d80  MasterItemList 0x19e91f04680  RowStruct 0x19ed5b6aba0
    N+1  ItemList 0x19e8b0b1d80  MasterItemList 0x19e91f04680  RowStruct 0x19ed5b6aba0

A RestartLevel replaces the world while leaving those persistent tables exactly
where they were. The engine's own slot is where the truth lives, which is
precisely why the resolver validates `InternalIndex` and `SerialNumber` rather
than pointers -- so the runtime now logs them, and the check reads them:

    31 anchors compared, exactly 1 changed
    live player inventory  N   index 76537,  serial 21977,  0x19e923f3b20
                           N+1 index 183902, serial 102664, 0x19f484bc4f0

and the revocation names that same anchor. The other 30 legitimately survived.

#### The bug this found: a dangling parent in a live object

`EnsureForGeneration` tore down for a new generation by calling `Shutdown`,
which releases the aggregate table's root. That was written believing the old
world's `MasterItemList` was gone. It is not: the measurement above shows it
surviving. So the sequence left a live composite holding `parent[1]` to a table
nothing rooted any more -- a crash waiting for the next rebuild.

Teardown now detaches first, and only after asking the engine whether the old
`MasterItemList` is still alive, by slot: if it genuinely died, reading it to
detach would itself be the use-after-free. The address cannot answer that
question, for the reason above.

Detaching turned out to be two operations, not one. `JobDetach` shrinks
ParentTables from 2 to 1 and leaves the dropped element still pointing at the
old table; `Attach` refuses a non-zero slot. The first fix reported a clean
detach and the next generation's attach still failed. `JobZeroSlot` is the other
half, and leaving that slot populated would have been the very dangling
reference the teardown exists to remove.

Both were reachable only because the earlier `Stage5RegisterItem` change made a
missing attach a NAMED refusal (step 28) instead of a silent corruption.

#### What the gate refusal rests on

The revoke-to-republish window measured under four seconds and the Items
backend polls every twenty, so catching that backend mid-window is luck, not
evidence, and the check does not pretend otherwise. The consumer that
necessarily meets a revoked generation is the lifecycle's own `content::Acquire`
-- its failure is what emits the revocation line. The properties that must hold
are then checked structurally: the backend rebound to N+1 before writing
anything, no row was ever applied to the revoked generation, and the
declaration count stayed at 1 of 1 rather than becoming 2.

#### The installation

While the framework is active, verified against this build's recorded vanilla
inventory: 16 findings, all `added`, none modified and none removed. Fifteen are
inside `MiseryFramework/`; the sixteenth is the `dwmapi.dll` proxy. After
`uninstall`, a full re-hash of all 52 baseline files reports **MATCH --
installation is identical to the baseline**.

`stage5b-install-while-active.json`, `stage5b-install-after-uninstall.json`.

#### Deferred: a stronger lifecycle test than RestartLevel

RestartLevel replaces the world and the player but leaves the persistent item
tables alive -- the measurement above shows all three surviving at identical
addresses. The generation machinery handled that partial case correctly, and it
is a real transition, but it is not the hardest one.

The harder one is the game's own:

    New Game -> preparation/start area -> the game's natural transfer to the
    generated main zone

That is a map-to-map transfer the game performs by itself, and it should
replace the item tables too, exercising the anchors this run saw survive.
Wanted as a later lifecycle regression. Recorded here rather than attempted
now: Step 4 does not depend on it, and the transition gate it would strengthen
has already passed on the evidence available.

### Step 4 -- Stage 4's discovery and load plan, in the runtime

    Steam Play
      -> MiseryRuntime
      -> discover real mod folders from Mods/
      -> validate manifests
      -> canonical ModId / semver
      -> dependencies + conflicts + deterministic arbitration
      -> deterministic load plan
      -> CoreCLR
      -> only planned C# mods load

`research/evidence/STAGE5B/stage5b-step4-loadplan.json`, 16 of 16.

    managed: skipped .../Mods/BrokenJson (malformed_manifest) -- the manifest could not be read
    managed: skipped ghostdep (missing_dependency) -- requires 'nobodyhasthis' ^1.0.0, ...
    managed: 2 mod(s) to load: alphamod betamod
    managed: 2 of 2 planned mod(s) loaded, 0 failed: alphamod betamod

Nothing in the runtime names a mod. Every id, folder, assembly, dependency and
version came out of a mod.json at run time. `betamod`'s folder is deliberately
named to sort FIRST on disk while its manifest says it loads SECOND, so folder
order and plan order disagree and only one of them can be the one being used.

#### A port, and a checkable claim that it is one

tools/modframework/ is the source of truth. Where the two could disagree, the
Python is right. That is not left as an intention: `tests/test_mod_plan.py`
builds mod trees with Stage 4's OWN fixture builders, runs both planners over
them, and requires the load order and every exclusion to match. Stage 4's
`ALL_NEGATIVE` is iterated rather than listed, so a failure class added there
later is demanded of the port automatically.

The differential was verified to be capable of failing: injecting the single
most tempting wrong behaviour -- a duplicate mod_id keeping the first claimant
instead of refusing both -- turned four tests red, including the Stage 4
fixture subtest. A differential that has never failed is one nobody knows works.

It caught two places where the port had already drifted, both of them the port
being STRICTER than the thing it was porting, which is still a fork:

* a version requirement was demanded only of required dependencies; Stage 4
  demands one on every entry, optional included;
* every path separator in `content`/`code` was refused; Stage 4 permits a
  relative path and refuses only absolute paths, drive letters and `..`
  components.

#### The adversarial properties, preserved

Proven against both planners on the same trees: a duplicate id refuses BOTH
claimants; a case-collision refuses every member of the group; a broken folder
cannot evict an unrelated mod; an unreadable manifest does not poison the scan;
dependency, version, conflict and cycle failures all fail closed and propagate
transitively; and shuffling the creation order of folders whose names sort
against their ids changes nothing.

The live run adds the half a unit test cannot: `ghostdep` carries a real
assembly, so a plan that wrongly admitted it would show it LOADED rather than
merely listed, and the run asserts the loaded set is exactly the planned set.

#### One thing the summary was not saying

"2 of 2 planned mod(s) loaded" does not say WHICH two, and the check meant to
assert that read the loaded list from a JSON report the host logs only when
something has failed -- so on a clean run it compared nothing to nothing and
passed vacuously. The runtime now names the mods it loaded on every run.
