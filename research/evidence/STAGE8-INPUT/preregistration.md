# Stage 8 — input delivery: pre-registration

**Written before any live experiment that changes anything in the game process.**
Claims, instruments and *failure interpretations* are fixed here so that a
negative result cannot be re-read as a positive one afterwards. Where a claim
fails, the paragraph headed **"A failure here means"** is the only reading I am
allowed to give it.

## 1. Goal

> receive keyboard/text input in MISERY, from the main menu and gameplay,
> without depending on `content_ready` or a live player/world

with four sub-questions kept separate: **(1)** key/toggle delivery, **(2)**
text/character input including backspace, enter and arrows, **(3)** focus and
capture, so that opening the console does not also fire gameplay or menu
actions, and **(4)** lifecycle across menu → loading → gameplay.

The console is a *consumer* of whatever primitive this establishes. It is not
the reason the primitive exists, and nothing below is shaped around it.

## 2. Constraints this track inherits

* No hardware breakpoints, no vtable hooks, no `.text` detours, no guessed RVAs.
* The Steam installation stays read-only apart from the designed bootstrap surface.
* Exact UE 5.4.4 / CL 35576357 only; an unknown build fails closed.
* If teardown cannot be proven safe, leave the module loaded and report BLOCKED.
* No public gameplay input bindings are designed in this track. The deliverable
  is the smallest correct *delivery* primitive.

## 3. What is already known, and by which oracle

The engine source for this exact version is installed at
`D:\Program Files\UE_5.4` (`Engine/Build/Build.version`: MajorVersion 5,
MinorVersion 4, PatchVersion 4, Changelist **35576357**) — the same version and
changelist the MISERY build reports. That makes the following **source-derived**,
which is a real oracle and a weak one: it says what Epic's code does, not what
this shipped executable does. MISERY ships its own native module
(`/Script/MISERY`, gameinstance.md §4) and may have overridden any of it.
Every source-derived fact that the design leans on is re-measured live below.

| # | Fact | Where | Oracle |
|---|---|---|---|
| F1 | `IInputProcessor` has **no character handler**. Its full surface is Tick, KeyDown, KeyUp, AnalogInput, MouseMove, MouseButton{Down,Up,DoubleClick}, MouseWheelOrGesture, MotionDetected, GetDebugName. | `Slate/Public/Framework/Application/IInputProcessor.h` | source, version-identical |
| F2 | The character code carried by a Windows key-down is `::MapVirtualKey(Win32Key, MAPVK_VK_TO_CHAR)` — **unshifted**, so the `a` key reports `A` whether or not Shift is held. | `ApplicationCore/Private/Windows/WindowsApplication.cpp:2073` | source, version-identical |
| F3 | Real text arrives as `WM_CHAR` -> `MessageHandler->OnKeyChar(Character, bIsRepeat)`, a path input pre-processors never see (F1 gives them no hook on it). | same file, `:1987-1997` | source, version-identical |
| F4 | The pump is `PeekMessage(PM_REMOVE)` -> `TranslateMessage` -> `DispatchMessage`. `WM_CHAR` is therefore **posted by TranslateMessage before** `DispatchMessage` delivers the originating `WM_KEYDOWN` to the window procedure, and the two are separately observable and separately suppressible at that procedure. | `WindowsPlatformApplicationMisc.cpp:113-117`, `WindowsApplication.cpp:2759-2762` | source, version-identical |
| F5 | UE registers one window class, `TEXT("UnrealWindow")`, with `wc.lpfnWndProc = AppWndProc`. | `WindowsWindow.cpp:37`, `WindowsApplication.cpp:328-343` | source, version-identical |
| F6 | `FSlateApplication::RegisterInputPreProcessor(TSharedPtr<IInputProcessor>, int32)` is `SLATE_API` and exists in this version. | `SlateApplication.h:1425` | source, version-identical |
| F7 | `UGameInstance` and `ULocalPlayer` survive every observed in-process transition, menu -> load -> gameplay; `APlayerController` does **not** and is nulled on map load. | `research/systems/{gameinstance,localplayer}.md` | live, M4 |
| F8 | A persistent per-frame game-thread callback exists in production via `FTSTicker` and is already the framework's carrier. | LOG-0075, `UE54TickerCarrier.cpp` | live, production |

**F1 + F2 + F3 together are the pivotal finding of the static pass**, and they
are what rules the obvious answer out: a Slate input pre-processor is offered by
the engine as *the* global input extension point, it has exactly the lifetime we
want — and it cannot deliver typed text. Its key-down character is the unshifted
`MapVirtualKey` value, so `Shift+a` and `a` are indistinguishable at that layer,
and dead keys, the numpad and IME composition never appear there at all.

## 4. Candidate mechanisms

| | Mechanism | Toggle | Text | Capture | Lifetime | Engine addresses needed |
|---|---|---|---|---|---|---|
| **H-A** | Subclass the game's top-level `UnrealWindow` procedure (`SetWindowLongPtrW(GWLP_WNDPROC)`), chain with `CallWindowProcW` | yes | yes (`WM_CHAR`, F3/F4) | total — the message never reaches the engine | window lifetime, superset of world | **none** |
| **H-A2** | `SetWindowsHookEx(WH_GETMESSAGE, ..., GetCurrentThreadId())` — thread-local, mutates nothing | yes | see below | coarse: nulling `WM_KEYDOWN` also suppresses the `WM_CHAR` `TranslateMessage` would have made (F4) | thread lifetime | none |
| **H-B** | `FSlateApplication::RegisterInputPreProcessor` | yes | **no** (F1/F2) | key routing only; `WM_CHAR` still reaches the focused widget | program | `FSlateApplication::Get`, register, unregister |
| **H-C** | Wrap `GenericApplication::SetMessageHandler`, forwarding to the previous handler | yes | yes (`OnKeyChar`) | total | program | `Get`, `GetPlatformApplication`, plus a faithful forward of every virtual on a ~60-method interface |
| **H-D** | Poll `GetAsyncKeyState` from the F8 ticker | yes | no | none | process | none |

**Pre-committed preference: H-A.** It is the only candidate that answers all
four sub-questions, and it is the one that needs no engine address, no engine
type layout and no shared-pointer lifetime coupling into our module. Its failure
mode is contained: four message ids are inspected and everything else is handed
to `CallWindowProcW` unmodified. H-C answers all four too but interposes on a
~60-method interface where a single mis-forward is a subtle break in a shipped
game; it is held as the fallback, not the default. H-B is recorded as
*researched and rejected on evidence*, not overlooked.

H-A is not one of the four banned techniques. It patches no code, replaces no
vtable, and guesses no address: `SetWindowLongPtrW(GWLP_WNDPROC)` is the
documented Win32 facility for exactly this, operating on a window our own
process owns, and the previous procedure is kept and chained.

## 5. Claims

Every claim is measured in **three lifecycle states** — main menu (no save
loaded), loading/transition, gameplay — because the whole point of the goal
statement is that the console must not be a gameplay-only tool.

### C0 — read-only pre-observation (not invasive)

What exists before anything is attached: every top-level window of the game
process with its class, styles, rect and owning thread; whether the window rect
equals the monitor rect (borderless vs exclusive fullscreen); whether a live
`UConsole` or a non-null `UGameViewportClient::ViewportConsole` exists in this
Shipping build; the live `FUNC_Exec` census the runner already produces.

No pass/fail. This is the baseline the later claims are read against, and it
settles whether the `~` key is already spoken for.

### C1 — one stable window

**Claim.** The game process has exactly one visible top-level window of class
`UnrealWindow`, and it is the same `HWND` in all three lifecycle states.

**Instrument.** Read-only `EnumWindows` filtered by pid; `GetClassNameW`,
`GetWindowLongPtrW`, `GetWindowRect`, `IsWindowVisible`, `GetWindowThreadProcessId`.

**Pass.** Exactly one such window in each state; the same handle value in all three.

**A failure here means** the window is not a stable anchor — nothing more. It
does not weaken H-A's ability to see input; it means the attach point must be
re-established on a measured trigger, and I must record *which* transition
recreated the window rather than re-attaching on a timer.

### C2 — the message thread is the game thread

**Claim.** `GetWindowThreadProcessId` of that window returns the thread id the
framework's F8 ticker pump already records as the game thread.

**Instrument.** The probe reports both numbers from inside the process.

**Pass.** Equal, in all three states.

**A failure here means** keystrokes arrive off the game thread and every handler
must be marshalled through the existing dispatcher before touching the bridge,
whose game-thread affinity is enforced (`MB_E_WRONG_THREAD`). It is a design
change, not a blocker, and it must be *measured* rather than assumed either way:
handling input inline on the strength of an assumption is precisely the class of
error the bridge's thread check exists to catch.

### C3 — both key and character messages are observable at the window procedure

**Claim.** With the subclass installed and everything forwarded, pressing keys
produces, at our procedure: `WM_KEYDOWN` with the correct virtual key, followed
by `WM_CHAR` with the **layout- and shift-correct** character for printable keys,
and no `WM_CHAR` for arrows.

**Instrument.** Armed probe. Deliberate, scripted key presses; the probe records
`(message, wParam, lParam, tid, frame)` into an in-process ring which the
controller reads.

**The scripted set**, chosen to separate the things F2 says the Slate layer
cannot distinguish: `a`; `Shift+a`; `1`; `Shift+1`; `VK_OEM_3` on the US layout
(backquote / tilde); `VK_OEM_3` on the Russian layout (`Ё`); `Backspace`;
`Enter`; `Left`/`Right`/`Up`/`Down`; `Tab`; `PageUp`/`PageDown`.

**Pass.** `a` and `Shift+a` yield `WM_CHAR` 0x61 and 0x41 respectively —
*different* — where F2 predicts the Slate layer would report 0x41 for both;
`Backspace` yields `WM_CHAR` 0x08, `Enter` 0x0D; the arrows yield `WM_KEYDOWN`
with VK_LEFT/RIGHT/UP/DOWN and no `WM_CHAR`; `VK_OEM_3` arrives under both
layouts with the same virtual key.

**A failure here means** the engine receives keyboard input by a route that does
not pass through this window's procedure — raw input, or a device API. The
correct conclusion is then narrow: *messages are absent at this attach point*,
recorded with exactly which of the messages were missing. It does **not** license
"Windows messages are unavailable"; H-A2 and H-C attach elsewhere and would have
to be tried before the mechanism class is written off.

### C4 — capture is real (controlled differential)

**Claim.** While the probe is capturing, a key press produces **no** game-side
effect; with capture off, the same key press in the same state produces the
effect. Same key, same save, same screen — two configurations, not two moments.

**Instrument.** The probe carries a capture flag the controller toggles. While
capturing it suppresses `WM_KEYDOWN`, `WM_KEYUP`, `WM_CHAR`, `WM_SYSKEYDOWN`,
`WM_SYSCHAR` and returns 0 without calling the previous procedure. Game-side
effect is read by the existing live resolver, not by looking at the screen.

**Pass.** A movement key with capture on: player location unchanged beyond the
idle noise floor measured in the same run. With capture off: location changes.
Both directions required — "nothing happened" while capturing is only evidence
if the same press demonstrably does something when not capturing.

**The key-up rule, registered now so it is not invented later.** Suppressing a
key-up whose key-down the engine already saw would leave that key stuck down in
the engine. The probe therefore tracks which keys it suppressed the *down* of,
and passes through the up of any key it did not. This rule is part of the claim:
after a capture window that begins while a movement key is held, the player must
not still be moving.

**A failure here means** a second input path reaches the game. Capture is then
incomplete, and the honest report is that H-A can carry console input but cannot
promise that opening the console leaves gameplay untouched — which is a genuine
architecture finding and would move the decision to H-C.

### C5 — one attach spans the whole lifecycle

**Claim.** An attach made at the **main menu**, before any save is loaded,
survives into gameplay: same `HWND`, our procedure still installed, message
counter still advancing, with no `content_ready`, no `UWorld`, no
`APlayerController` and no `ULocalPlayer` consulted anywhere in the path.

**Instrument.** Attach at the menu; hold a monotonic counter; load a save; read
`GetWindowLongPtrW(GWLP_WNDPROC)` back and compare to our own function; sample
the counter in all three states.

**Pass.** Handle unchanged, procedure still ours, counter strictly increasing
across the transition, and the probe's source contains no reference to world or
player state.

**A failure here means** the transition recreates the window, and the finding is
*which* transition — recorded, then answered with a re-arm on that measured
event. It does not mean the lifetime requirement is unmeetable.

### C6 — detach is provably safe

**Claim.** Detach restores the exact previous procedure, and afterwards no
message reaches our code.

**Instrument.** The original pointer is kept from `SetWindowLongPtrW`'s return.
Detach reads the current procedure first: if it is no longer ours, someone
chained after us and **restoring would unlink them**, so detach refuses and
reports rather than restoring. On success, a quiescence handshake — N frames
with zero observed messages — must complete before the module may be unloaded.

**Pass.** Restore succeeds, read-back equals the original, quiescence window
clean.

**A failure here means** the module stays loaded and the run reports BLOCKED.
That is the standing rule and it is not negotiable by anything found here.

### C7 — closed costs nothing

**Claim.** With the console closed, the pass-through is behaviourally identical
to vanilla, and its cost is small enough to state.

**Instrument.** Time spent inside our procedure per keyboard message, sampled;
plus the Stage 8 acceptance pass itself as the behavioural check.

**Pass.** Median added time per keyboard message under 50 microseconds, and no
behavioural difference observed in the acceptance pass.

### C8 — a toggle key exists that the game does not want

**Claim.** `VK_OEM_3` is delivered, and the game does nothing with it.
It is the same virtual key for backquote/tilde on the US layout and `Ё` on the
Russian layout — one binding covers both of the user's named keys.

**Pass.** C3 shows it arriving under both layouts; with capture off, pressing it
in menu and in gameplay produces no observable game-side effect.

**A failure here means** the default binding must be something else, and the
binding must be configurable from the start rather than after a complaint.

### C9 — the UI can be drawn at all

**Claim.** An overlay window owned by our module can be shown above the game's
client area without taking focus, in the display mode the user actually plays in.

**Instrument.** After C0 establishes the display mode: create
`WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST` (layered) over the game's
client rect, draw a test pattern, never call `SetForegroundWindow`.

**Pass.** The pattern is visible over the game; `GetForegroundWindow` still
returns the game window; the game keeps rendering and keeps input.

**A failure here means** — and this is the one outcome I am pre-committing to
call a genuine architecture blocker rather than route around — that a thin UI
frontend cannot be drawn outside the engine, and the console UI needs an
in-engine drawing path, which is a research track of its own and not a Stage 8
implementation detail. I would report that, not improvise a substitute.

## 6. Pre-committed decision rule

* C1–C5 all pass -> **H-A**, and the primitive is built on it.
* C3 fails on characters only -> H-A for keys, and characters are re-sought at
  H-C; a design that types via F2's unshifted code is **not** acceptable.
* C4 fails -> H-C, and the incompleteness of H-A's capture is reported as a
  measured fact.
* C3 fails entirely -> H-A2, then H-C, in that order.
* C9 fails -> stop and report; do not substitute a different UI.

Nothing in this list is "try the next one until something works". Each fallback
is entered only with the previous mechanism's failure recorded.

## 7. Privacy boundary, registered before the first keystroke is read

A component that can see every keystroke is a keylogger unless it is
deliberately not one.

* **In production**, while the console is closed, the only thing examined is
  whether the message is the toggle key. No character is stored, logged,
  counted per-key, or included in any diagnostic or support bundle. While the
  console is open, the line being typed lives in the console's own buffer and
  goes nowhere else.
* **In this research probe**, keystrokes *are* recorded — that is the
  measurement. The capture therefore goes only to an untracked run directory
  under `research/instrument-runs/`, the game is driven with a scripted set of
  keys pressed deliberately, and nothing is typed into it that is not on the C3
  list. What gets committed as evidence is the aggregate and the specific
  scripted characters, never a raw capture.
* The support bundle's closed allowlist (D6) is not extended by this track. No
  input field is added to it.

## 8. What I may not conclude from any of this

* That input works *in general* because a probe saw messages. The claims are
  per-lifecycle-state, and a pass in gameplay is not a pass in the menu.
* That capture is complete because a key appeared to do nothing. C4 requires the
  same key to demonstrably do something with capture off, in the same run.
* That the source-derived facts F1–F6 describe this executable. They are the
  reason the design is shaped this way; they are not evidence about MISERY, and
  each one the design depends on is re-measured.
* That an absent message means an unavailable mechanism class.
