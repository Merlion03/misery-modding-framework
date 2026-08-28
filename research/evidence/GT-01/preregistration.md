# GT-01 — one-shot GameThread execution proof (pre-registration)

**Written before the run. Outcomes are fixed here so the reading cannot drift.**

## Question

Can we cause **exactly one** callback of our own to execute **on the Unreal
GameThread** of the live `MISERY-Win64-Shipping.exe`, initiated from an
injected/instrument thread, have it record its own thread identity, and then
remove every trace — with the callback doing **no** UObject, ProcessEvent, or
load operation? This is the capability gate that must pass before any Phase-2
content-load carrier is chosen.

## Mechanism (narrowest available; decoupled from Phase-2 by owner decision 2026-08-28)

An **execute hardware breakpoint** (debug register `Dr0`) on the verified
address of `UObject::ProcessEvent` (RVA `0x12AC1F0`, three agreeing derivations
— `processevent-address-verification.json` / LOG-0072), set **only on the
GameThread** (debug registers are per-thread, so no other thread can trap), with
a Vectored Exception Handler inside an injected DLL that:

1. fires when the GameThread next executes `ProcessEvent`;
2. records POD only: `GetCurrentThreadId()`, the faulting `Rip`, the return
   address at `[Rsp]` (a function-entry #DB means `[Rsp]` is the caller's return
   address), `QueryPerformanceCounter`, and a hit counter;
3. **clears `Dr0`/`Dr7` in the delivered `ContextRecord`** so the breakpoint is
   one-shot (the cleared debug state is loaded when the handler returns
   `EXCEPTION_CONTINUE_EXECUTION`);
4. writes nothing to any engine memory — **zero** bytes of the game's code or
   data are modified; `ProcessEvent`'s bytes are never touched (an execute HW
   breakpoint is CPU state, not a code patch, so even a code-integrity check
   would see unmodified bytes).

### Why this mechanism and not the others (Phase-1 only)

- **vs. Func-swap (8-byte `UFunction::Func` write):** Func-swap mutates engine
  heap and needs the **unmeasured** `UFunction::Func` offset (a gate that can
  BLOCK). HW-BP writes zero engine bytes and needs no such offset. Narrower for a
  pure proof. (Func-swap remains a *candidate carrier* for Phase-2, to be decided
  separately, and only after its offset measurement gate is closed.)
- **vs. SuspendThread+SetThreadContext RIP hijack:** that forcibly redirects the
  GameThread's execution pointer; HW-BP lets the thread trap naturally at a known
  instruction. Less invasive.
- **vs. Ticker/AsyncTask/TaskGraph enqueue:** all take a `TFunction`/delegate
  **by value**, unconstructable across the MinGW→MSVC ABI boundary; several also
  leave a persistent registration. Disqualified for this build.
- **vs. console/deferred-command sinks:** execute none of our code and give no
  thread-identity channel.

### New capability class — declared honestly

HW-BP requires briefly **suspending the GameThread** to arm `Dr0` via
`SetThreadContext(CONTEXT_DEBUG_REGISTERS)` (suspend → get → set → resume;
microseconds) and manipulating **debug registers** — a capability the IPP tooling
did not previously have, and the canonical anti-debug/anti-cheat tripwire. The
protection assessment found no anti-cheat on 8 tested surfaces (owner
risk-accepted, `docs/protection-assessment.md` §9.1/§9.2, LOG-0058/0059), and
`GetThreadContext` in the image resolves to benign callers — but the surface is
`NOT FOUND WITHIN TESTED SURFACE`, not cleared. This is the principal residual
risk and is recorded in ESC-03.

## Proof oracle

**Method 1 — external OS-thread identity (read-only, before the callback exists):**
- E1: enumerate all threads; exactly one is named `L"GameThread"` via
  `GetThreadDescription` (`FWindowsPlatformProcess::SetupGameThread` →
  `SetThreadName` → `SetThreadDescription`, WindowsPlatformProcess.cpp:2329/2445)
  ⇒ `TID_E1`.
- E2: the process **initial thread** (earliest creation time) whose
  `Win32StartAddress == liveBase + AddressOfEntryPoint` ⇒ `TID_E2`. On Win64 the
  UE game thread is the initial thread (GuardedMain wraps the tick loop in
  `FTaskTagScope(EGameThread)`).
- **REQUIRE `TID_E1 == TID_E2`.** Fingerprint that TID's TEB (TebBase, StackBase,
  DeallocationStack) for the RSP-range check.

**Method 2 — internal provenance (recorded by the callback, independent proposition):**
- (a) `GetCurrentThreadId() == TID_E1`.
- (b) the faulting `Rip == 0x1412AC1F0` (the trap fired at `ProcessEvent`) **and**
  the return address at `[Rsp]` lies inside MISERY `.text` `[0x1000, 0x5DCAA9C)`
  — proving the GameThread reached `ProcessEvent` by normal engine dispatch, not
  by our thread. (b) is not a restatement of (a): a fabricated TID satisfies (a)
  but fails (b).

Method 1 establishes *which OS thread is the GameThread* (single source of truth:
the engine's own naming); Method 2 establishes *our code ran there, reached by
engine dispatch*. These are two different propositions, not two measurements of
one fact — stated honestly (per the completeness critique).

**Negative controls:**
- N1: before arming, call the identical recorder **directly on our injected
  thread**. REQUIRE it records `selfTid != TID_E1` and `selfRsp` outside
  `[DeallocationStack, StackBase)` of the GameThread. If the recorder cannot tell
  our thread from the GameThread, the instrument is invalid ⇒ ABORT.
- N2: structural — `Dr0` is set on the GameThread **only**, so no other thread
  can trap even if it calls `ProcessEvent`. Confirm read-only that all of
  `Dr0..Dr3, Dr7` on the GameThread are **zero before arming** (if not, something
  else uses them ⇒ ABORT — do not fight for the register).
- N3: read the record page **before** the trap fires; REQUIRE `count == 0` and
  `tid == sentinel 0xFFFFFFFF` (proves the page is written only by the callback).

## Pre-registered outcomes (fixed before the run)

- **PASS** ⇔ `count == 1` **and** `tid == TID_E1 == TID_E2` **and** faulting
  `Rip == 0x1412AC1F0` **and** `[Rsp]` return address in `.text` **and** N1
  distinguished **and** N2/N3 held **and** a re-run of E1/E2 after the fire is
  unchanged **and** cleanup confirmed (`Dr0==0`, VEH removed, DLL unloaded).
  ⇒ GT-01 confirmed; Phase-2 carrier selection is authorized as a **separate**
  decision.
- **count == 0 at timeout** ⇒ callback never fired. Disarm externally (clear
  `Dr0`), report. Means: GameThread not executing `ProcessEvent` in the window
  (implausible — BP ticks call it every frame), or arming failed. **Not** a
  refutation of the mechanism by itself; investigate arming. BLOCKS Phase-2.
- **count > 1** ⇒ the one-shot clear did not take (a second trap before the
  cleared `Dr0` loaded). Flag and investigate; the recorded slot's `tid`
  consistency still informs, but do not call it a clean PASS.
- **tid != TID_E1** ⇒ fired on the wrong thread. FAIL (should be impossible given
  N2's per-thread arming; would indicate a misunderstanding of the arm).
- **`[Rsp]` not in `.text`** ⇒ provenance not established. FAIL.
- **N1 fails to distinguish, or N2 finds non-zero debug regs** ⇒ ABORT; no
  positive result is trustworthy.

## Cleanup / rollback

`Dr0`/`Dr7` cleared inside the handler (one-shot) and re-confirmed zero
externally after the fire; on timeout, cleared externally under suspend. VEH
removed (`RemoveVectoredExceptionHandler`) once no trap can re-enter, then
`FreeLibrary` — safe here because, unlike a Func-swap trampoline, once `Dr0` is
cleared and the single trap has returned, **no engine thread holds a pointer into
our code**. The record page (injector-owned `VirtualAllocEx`) is freed by the
controller. The game process is left running and, apart from the single trap,
unperturbed. No install file is touched (the game runs from the read-only Steam
install; all our state is in the injected DLL + one allocated page).

## Build fingerprint

`build_key = sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
(`misery-24953925-ue5.4.4-bace50f7185d`). ProcessEvent RVA `0x12AC1F0` is
guaranteed by that hash equality (whole-image identity) **and** independently
triple-derived (LOG-0072).
