# Stage 8 — input delivery: findings

Read against `preregistration.md`, which was committed at `7042976` **before**
anything was loaded into the game. Every claim below is reported against the
predicate and the failure interpretation that document fixed in advance.

**Build:** `sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`,
UE 5.4.4 CL 35576357, Shipping x64.
**Sessions:** pid 3128 (menu only, first attach/detach), pid 9104 (menu →
loading → gameplay, save `123`).
**Instruments:** `research/instruments/input/`, probe
`runtime/MiseryRuntime/Internal/InputProbeDll.cpp`, overlay
`runtime/MiseryRuntime/Internal/OverlayProbeDll.cpp`.

## Verdict

**H-A is proven and adopted.** Keyboard input in MISERY is reachable by
subclassing the game's own top-level window procedure, with no engine address,
no engine type layout, no vtable replaced and no code patched. The pre-committed
decision rule said C1–C5 all passing selects H-A; they all pass.

| Claim | | What was measured |
|---|---|---|
| C0 | — | 3 top-level windows: one `UnrealWindow`, plus hidden `IME` and `MSCTFIME UI`. `WS_POPUP` without `WS_CAPTION`, rect exactly the monitor (0,0–2560×1440) → **borderless fullscreen**, which is what makes C9 possible. |
| C1 | **PASS** | Exactly one visible top-level `UnrealWindow` at the menu and in gameplay, the same handle in both (`0xaa064a`, session 9104). |
| C2 | **PASS** | The window's message thread is **8300**. The FTSTicker carrier, run independently in the same process, put 800/800 dispatcher jobs on game thread **8300**. Same thread. Keyboard handlers need no marshalling. |
| C3 | **PASS** | Both key and character messages arrive, with the shift- and layout-correct character. Detail below. |
| C4 | **PASS** | Same key, same state, one run: forwarded → the character moved **245.5 uu**; suppressed → **0.0 uu**, against a measured idle drift of **0.0 uu**. |
| C5 | **PASS** | One attach made at the main menu survived the level load into gameplay: same handle, message counter 3209 → 6304 across the transition, still attached. |
| C6 | **PASS** | Detach restored the exact original procedure, read back and compared, twice (both sessions), each followed by a ~1.5 s window with zero messages. |
| C7 | **PASS** | 200 keyboard messages timed inside our procedure: **median 100 ns, p95 100 ns, max 200 ns** against a 50 µs budget. |
| C8 | **PASS** | `VK_OEM_3` is delivered and the game does nothing with it — and it is the same virtual key for both of the keys named in the brief. |
| C9 | **PASS** | An overlay owned by our module draws above the game **while the game is in the foreground**, without taking activation. |

## C3 in detail — and why it is the finding that chose the design

The static pass had already established, from the version-identical engine tree,
that Slate's `IInputProcessor` has no character handler and that a Windows
key-down carries `MapVirtualKey(VK, MAPVK_VK_TO_CHAR)` — the **unshifted**
character. So the discriminating test is whether `a` and `Shift+a` are
distinguishable at the attach point. They are:

| scripted press | at the window procedure | |
|---|---|---|
| `a` | `WM_KEYDOWN 0x41`, `WM_CHAR 0x0444` = `ф` | |
| `Shift+a` | `WM_KEYDOWN 0x41`, `WM_CHAR 0x0424` = `Ф` | **different** |
| `1` / `Shift+1` | `WM_CHAR 0x31` = `1` / `WM_CHAR 0x21` = `!` | shifted symbol correct |
| `VK_OEM_3` (US layout) | `WM_CHAR 0x0060` = `` ` `` | |
| `VK_OEM_3` (RU layout) | `WM_CHAR 0x0451` = `ё` | same VK, both bindings |
| Backspace | `WM_CHAR 0x08` | |
| Enter | `WM_CHAR 0x0D` | |
| Tab | `WM_CHAR 0x09` | |
| Left / Right / Up / Down | `WM_KEYDOWN` only, **no `WM_CHAR`** | |
| PageUp / PageDown | `WM_KEYDOWN` only | |

Where the Slate layer would have reported one value for both `a` and `Shift+a`,
the window procedure reports two. That is the whole reason H-B was rejected on
evidence rather than overlooked.

The keyboard layout changed from US to Russian partway through the research —
not deliberately; an Alt+Shift arrived from outside the script and switched it.
It turned out to be the layout half of C3 for free: **one virtual key, `VK_OEM_3`,
produced `` ` `` under one layout and `ё` under the other**, which is exactly the
"~ / Ё or another configurable binding" the brief asked for, from a single
default.

### Run quality, stated rather than glossed

The menu run is **clean: zero foreign events**. The gameplay run recorded **35
foreign events** and is therefore *not* clean by the instrument's own gate — the
machine was in use and a person was pressing WASD, Space and Shift while the
scripted set ran. Every scripted press still produced exactly its registered
messages, and the foreign events are all movement keys, which cannot be confused
with any key in the scripted set. The honest statement is: C3's predicates all
hold in gameplay, in a run whose strict cleanliness gate failed for an
identifiable and unrelated reason.

Two instrument faults were found and fixed on the way, both of which had produced
misleading output first:

* **A stale ring.** The reset rewound the write cursor but left the previous
  run's records in place with sequence numbers that interleaved with the new
  ones. The second scripted run therefore read the first run's tail as if it
  were current. Fixed by zeroing every slot's sequence on reset, and by making
  the reset *acknowledged* — a `WM_NULL` is posted so the procedure certainly
  runs, and the controller waits for the flag to clear instead of sleeping.
* **A silent foreground loss.** An externally-held Alt turned every arrow into
  `WM_SYSKEYDOWN` and turned the scripted Tab into Alt+Tab, which took the
  foreground away and dropped the last three presses with no error. Fixed by
  releasing every modifier before the set and by checking the foreground before
  each press, so the run stops rather than producing a partial record.

## C4 in detail — the controlled differential

The first observable tried was a live class census, and it found nothing for
Tab, I or M. That is **not** evidence that the keys did nothing: MISERY's widgets
are pre-instantiated, exactly as the runner's own save-entry machine records for
the main menu, so opening a panel constructs no objects. Reporting "no reaction"
from that would have been a false negative dressed as a result.

The observable that works is state on objects that already exist, read by
reflection: the pawn's `RootComponent → RelativeLocation`.

| direction | messages | forwarded | suppressed | movement |
|---|---|---|---|---|
| idle, nothing pressed | — | — | — | **0.0 uu** |
| capture **off**, `W` | 3 | 3 | 0 | **245.5 uu** |
| capture **on**, `W` | 3 | 0 | 3 | **0.0 uu** |

Both directions, one run, one save, one screen. The floor was measured in the
same run rather than assumed, and it came out at exactly zero.

**Delivery caveat, recorded because it is a real limit.** These presses were
delivered with `PostMessage` rather than `SendInput`, because a person was using
the machine and taking the foreground for a measurement is a cost worth avoiding
when it can be. A posted `WM_KEYDOWN` is a genuine message in the window's queue
and reaches the window procedure by the same path — but the OS key state is not
updated, and `TranslateMessage` never runs, so no `WM_CHAR` is generated. C4 is
therefore proven for key messages; the character half of the path is proven by
C3, which used real synthesized input.

A second fact fell out of this: **MISERY processes window-message input while it
does not have the foreground.** The `W` that moved the character 245 uu was
delivered while a browser was in front.

## C9 in detail — the UI can be drawn

The overlay is a `WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_NOACTIVATE |
WS_EX_TOOLWINDOW` popup owned by our module, painting three flat bands of exact
RGB values, and the screen is read back rather than looked at.

With the game in the foreground (`foreground_before == game_hwnd == 0xaa064a`):

* all three bands read back at their exact coordinates — `(240,5,122)`,
  `(5,240,122)`, `(7,125,241)` for `(255,0,128)`, `(0,255,128)`, `(0,128,255)`;
* neither sample point below the overlay carries any band colour — they read
  `(103,105,92)` and `(24,24,21)`, which is the game's own scene;
* `GetForegroundWindow()` is unchanged across show and hide.

The first overlay sample was taken while a **browser** held the foreground. It
proved the window is topmost; it did not prove it draws above the game, which is
the claim. It is recorded here as what it was and the measurement was repeated
with the game in front.

## What is not proven

* **The loading state was not censused separately.** C1 and C3 were measured at
  the menu and in gameplay. The transition is covered only by C5's counter
  continuity — 3209 → 6304 across the level load with the same handle — which is
  strong evidence that the attach survives it, and is not the same thing as a
  census taken mid-load. The console UI does not need one; the claim is simply
  not made.
* **Exclusive fullscreen is untested.** This machine runs the game borderless.
  An overlay cannot composite over an exclusive-fullscreen swapchain, and if a
  user runs that way the console will not be visible. That is a known limit of
  the mechanism, to be stated to users rather than discovered by them.
* **Injected input is not physical input.** Nothing here was typed by a human on
  purpose. At the window procedure a synthesized press is indistinguishable from
  a physical one, and a posted one differs only as described above — but the
  manual acceptance pass is where a real keyboard settles it.
* **`GetAsyncKeyState`-style polling is unaffected by capture.** Suppressing a
  message does not clear the OS key state. Anything in the game that polls key
  state directly would still see the key down. Nothing observed suggests MISERY
  does this for the keys that matter, and UE registers raw input for the
  **mouse only** (`WindowsApplication.cpp:546`, `StandardMouse`), but it is a
  limit of the mechanism and not something the differential ruled out.

## Consequences for the design

1. **The input primitive is a window-message source**, attached to the one
   visible top-level `UnrealWindow`, delivering on the game thread with no
   marshalling. It needs nothing from the engine, so it cannot be broken by an
   engine layout change and it fails closed on a window it cannot identify.
2. **Capture is a first-class concept**, with the key-up rule the
   pre-registration fixed in advance: an up whose down the engine already saw is
   always forwarded, or that key stays held down inside the game.
3. **The console UI is an overlay window**, not a Slate or UMG widget. It works
   at the main menu, during loading and in gameplay, because none of the three
   things it depends on — a window, a message thread, an FTSTicker pump — is
   tied to a `UWorld`, a `PlayerController` or `content_ready`. The ticker was
   observed running at the main menu with no world loaded (25 ticks).
4. **`MB_CAP_INPUT_REGISTRY` stays generic.** The console registers as one
   consumer of the input source. Nothing about the source's shape is owed to the
   console.

## Side effects of this research, disclosed

* The character in save `123` finished about **7 m** from where it started: the
  C4 differential walked it forward and the correction walked it back along a
  different heading. Nothing else in the world was touched.
* For roughly ten seconds during the gameplay C3 run, capture was on while a
  person was pressing movement keys, so those presses did not reach the game.
* `InputProbe.dll` and `OverlayProbe.dll` remain loaded in that game process.
  Neither is attached to anything: the window procedure was restored and proven
  quiescent, and the overlay window is destroyed. They are not unloaded because
  the standing rule is that an unproven unload is a BLOCKED report, not an
  attempt; they die with the process.

---

# Part two: the production console, live

Written after the implementation, against the same build, through a **normal
Steam launch** with the framework installed — not a probe, not a research
harness. `research/evidence/STAGE8-INPUT/live-acceptance.json`,
`live-acceptance-gameplay.json`, `live-capture.json`.

## What the runtime log says on its own

```
runtime: the game-thread carrier is active
runtime: developer console ready on window 0x35007da (thread 5652); toggle key 0xC0
...
runtime: game thread declared as 5652 (measured, not assumed)
```

C2, re-measured in production and from two independent directions: the window
the console attached to is dispatched by thread 5652, and the runtime's own
carrier declared the game thread to be 5652. The console line is printed
**before** the first content generation is published, which is the lifetime
claim stated as a log ordering rather than as an intention.

## What the screen says

A log line proves code ran; it does not prove anything is drawn. So the
acceptance reads the screen back, counting the console's own colours over the
whole region rather than sampling a grid.

| | at the main menu | in gameplay |
|---|---|---|
| the game's own text, before | 76,672 px | 10,770 px |
| the same, with the console open | **9 px** | **9 px** |
| the console's ink, open | 1,647 px | 2,104 px |
| after typing a command and Enter | 2,084 px | 2,722 px |
| the game's own text, after closing | 76,672 px | 10,581 px |

Both states pass all four checks: the game's screen is what shows to begin with,
the toggle covers it, a command adds text, the toggle gives it back. The command
typed in gameplay was `misery:generations`; at the menu, `misery:caps`.

**Two thresholds were wrong before this was right, and both were the metric
rather than the console.** The first counted pixels near the console's
background colour — but MISERY's menu is nearly black, so 57 of 63 sampled
points matched it *before* the console opened. The second required 200
prompt-coloured pixels, and `"> "` plus a blinking caret at an 18px font is
about 44 of them, half the time. What discriminates by four orders of magnitude
is the game's own content vanishing behind the overlay, and that is what the
check now reads.

## Capture, in production

| | |
|---|---|
| idle drift, measured in the same run | 0.0 uu |
| console **open**, a posted movement key | 0.0 uu, twice |
| console **closed**, the same key | 172.1 uu, then 2977.4 uu |

The second closed measurement came *after* a full open/close cycle, which is
what rules out the console having broken input permanently.

A third leg — close, press again, expect movement — is **not** reported as a
result. It read 15.7 uu and then 0.0, and measuring rather than adjusting the
threshold showed why: `W` was against an obstacle in that spot (`W→0.0`,
`W→0.0`, `S→195.7` from the same position), and a later `S` slid the character
2977 uu into somewhere it is now wedged. None of that is about the console, and
calling it a capture failure would have been wrong. The message-level
differential in Part one — 3 forwarded → 245.5 uu, 3 suppressed → 0.0 uu — is
the stronger evidence, and the production console routes through the same rules.

## What the implementation added beyond the input path

`IModConsole` was in the accepted Stage 8 public API (§3) and had **no managed
half at all**. The trampoline's `DispatchCommand` invoked an `Action<string>`
and completed nothing, so a mod's command would have run and then been reported
as "the command handler returned no result". It now mirrors the services path
exactly, and the reference mod registers `refmod:status` through the ordinary
public API with no framework knowledge of it.

`misery:input` no longer says "declared and not dispatched". It reports the
source's real counters **and** `mod_bindings: false`, because a mod still cannot
bind a key to a declared action, and reporting "input works" without that would
leave an author to discover the silence at runtime — the exact failure
`engine_input_wired` exists to prevent.

## Still not proven, still not claimed

* Nothing here was typed by a human. Keys were posted to the window queue, which
  is the real path but not a real keystroke: the OS key state is not updated and
  `TranslateMessage` does not run, so the `WM_CHAR` was posted deliberately. The
  manual checklist is where a keyboard settles it.
* Exclusive fullscreen remains untested and cannot work; it is stated as a limit.
* The reference mod's **item** is not live in this session, because its content
  container was unstaged during this work to get past the runner's consistency
  gate. That is reversed in the staging plan for the next run and is not a
  framework regression.

## A sixth discrepancy with the reference, classified not resolved

`console.py`'s `input` builtin answers with `InputRegistry.summary()`, which
carries `"engine_input_wired": false` and a note saying nothing in the game
delivers input. The native builtin now answers with something else.

**Why it differs.** The reference's statement was true when it was written and
is now half false: an engine input path exists and the console runs on it. But
the *other* half is still true — a mod cannot bind a key to a declared action.
Reporting `engine_input_wired: false` would now be a lie, and reporting it true
would be a worse one, because a mod author would read it as "I can have key
events" and get silence.

**What was chosen, and on what ground.** The native builtin reports the source's
real state (`attached`, message counters, window re-arms, whether the console is
open) **and** `mod_bindings: false` with a note naming exactly what is missing.
That preserves the reference's *purpose* — tell the author what is not available
rather than let them discover it at runtime — in a world where the single
boolean it used to say that with no longer has a single answer.

**Not resolved by changing the reference.** `input_actions.py` is untouched, per
the standing rule; the reference platform still describes a registry with no
delivery, which is what it is. The two disagree, deliberately, and this is the
record of it.

The console differential (`tests/test_console.py`) compares the empty line,
whitespace, an unknown command, and the envelope shapes — not this builtin's
body — so it neither catches nor hides the difference. Saying so here is the
point: an unexamined green suite is not evidence about a field no test reads.

---

# Part three: the focus lifecycle, found in manual acceptance

Reported from the manual pass: minimising MISERY hid the console overlay,
**Alt+Tab did not**, and a topmost console was left sitting over whatever the
user switched to.

## The cause, which is not what the symptom suggests

Nothing was tracking window state at all. There was no `WM_ACTIVATEAPP` handler,
no `SIZE_MINIMIZED` handler, no `IsIconic` call — the words did not appear in the
source. Minimise *appeared* to work for an entirely incidental reason: the
overlay is positioned each frame over the game's client rect, and a minimised
window's client rect collapses, so the overlay collapsed with it.

That is the shape of the finding worth keeping. **A rule that is an accident of
geometry holds for the one case that happens to collapse a rect and fails for
every other one.** Activation loss does not resize anything, so nothing hid the
overlay, and the two cases looked like one working feature and one bug when in
fact neither was implemented.

## What replaced it

Three independent facts, and the console is on screen only when all three agree:
the developer opened it, MISERY is the active application, and it is not
minimised. `ConsoleUi`'s `ApplyVisibility()` is the single place that decides,
because the absence of a single place is what the bug was.

* **`open` and `visible` are now separate**, in the state and in `Status`.
  Losing activation suppresses the presentation and the input; the line being
  typed, the history and the scrollback are untouched, which is what the brief
  asked for and what the round-trip check measures.
* **Delivery is synchronous, from the window procedure**, not polled from the
  frame pump. A background or minimised game may not be getting frames, and a
  console that waited for one to hide itself would still be on screen while the
  user was looking at something else — the same failure by a different route.
* **Deactivating clears every held-key mark.** A key whose down was swallowed
  has its up delivered to whoever has focus now, so the mark would survive; the
  next press of that key with the console *closed* would send its down to the
  game and have its up eaten by the stale mark, holding that key down inside the
  game forever. Clearing risks the opposite and far milder thing — a key-up the
  engine never saw a down for.

## A second bug, in the fix

The first reconciliation compared the console's copy of the activation flag
against the **input source's copy of the same flag**. Both were stale together,
so it could not correct anything — and it mattered immediately: `WM_ACTIVATEAPP`
only arrives on a *change*, and the framework attaches while the game is
already in front, so no activation message ever arrives and a flag seeded at
attach time stays wrong for the whole session. The source now re-reads the OS
(`GetForegroundWindow`, `IsIconic`) once a frame and fires the watcher on a
change, which makes the console's reconciliation mean something.

## Measured

`research/evidence/STAGE8-INPUT/live-focus.json`. The claim is about a window's
state, so it is measured on the overlay window's own `IsWindowVisible`, found
from outside by class name — no palette, no tolerance, no dependence on what is
behind it.

| state | overlay visible | game minimised |
|---|---|---|
| open, active | **yes** | no |
| **activation lost, not minimised** | **no** | **no** |
| reactivated | **yes** | no |
| minimised | **no** | **yes** |
| restored | **yes** | no |
| closed | **no** | no |

The typed line survived the Alt+Tab round trip: 52,640 ink pixels before, 52,638
after — a two-pixel difference, which is the caret blinking.

## Two acceptance defects found on the way, both mine

* **The screen acceptance did not fail closed on the foreground.** One run
  measured a browser's pixels: the game never came forward, the sampled region
  was half the size, and "the game's own screen is showing" failed against
  another application's content. It now refuses and reports BLOCKED rather than
  producing numbers.
* **It sampled the window rect, not the client rect.** This session's game
  launched *windowed* at 1680×1050, so the window rect included a title bar the
  overlay never covers, and the console read as not opening. Fixed — and the
  windowed launch is worth having: the console is now proven in both display
  modes rather than only the borderless one.
