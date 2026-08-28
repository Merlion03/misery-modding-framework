# MiseryRuntime GameThread Dispatcher

Production foundation for running work on the Unreal game thread from
worker/mod threads, built on the proven FTSTicker carrier (LOG-0075, commit
`9596b12`). Live-proven at LOG-0076. **POD jobs only at this stage — no
UObject/gameplay operations** (that is a separate, later gate).

```
worker / mod threads
        │  Misery::GameThread::Enqueue(fn, ctx)
        ▼
MiseryRuntime queue  (Runtime-owned, thread-safe)
        ▼
one persistent FTSTicker pump callback
        ▼
GameThread  ──►  bounded drain of pending jobs
```

## Architecture boundary (so a carrier swap never touches mods)

| Layer | Files | Sees |
|-------|-------|------|
| **Public** | `runtime/MiseryRuntime/Public/MiseryGameThread.h` | `Misery::GameThread::Enqueue`, `IsAvailable`. POD `JobFn = void(*)(void*)`. **No** UE types, RVAs, FMemory, FTSTicker, or UObject pointers. |
| **Internal — dispatcher** | `Internal/GameThreadDispatcher.h`, `Internal/IGameThreadCarrier.h` | Queue + lifecycle, carrier-agnostic. No UE headers → host-testable. |
| **Internal — carrier (build-specific)** | `Internal/UE54TickerCarrier.{h,cpp}` | The one build-coupled surface: FTSTicker/GetCoreTicker/FMemory bindings, fingerprint gate, TFunction construction. Swapping the carrier (new build, or a non-ticker mechanism) changes only this. |

A future C#/Python bridge can sit above the Public layer; the architecture does
not preclude it, but none is built now.

## Queue and ordering semantics (proven, not aspirational)

A `std::mutex`-guarded `std::deque`, owned by the Runtime (the carrier registers
**one** persistent pump, never one `AddTicker` per job). Each `Enqueue` is a
single atomic lock/push/unlock.

- **Total order = the order in which `Enqueue` calls acquired the lock.** A
  single producer's own jobs therefore keep program order (per-producer FIFO).
- **No stronger cross-producer guarantee.** A producer that *began* enqueuing
  earlier but took the lock later runs later. There is no global FIFO by
  wall-clock — only by lock acquisition.

## Bounded drain (frame safety)

Each pump tick moves at most `max_jobs_per_tick` jobs out of the queue under the
lock into a local batch, releases the lock, then runs the batch. Per-frame
game-thread work is therefore bounded by that budget: a flooding background
producer can grow the backlog (a memory cost the producer controls) but can
**never stall the frame** beyond the budget. Overflow waits for later ticks.

**Nested enqueue policy:** a job that enqueues another job puts it on the queue,
so nested work runs on the **next** drain, never same-frame. This is the safer,
deterministic choice (no unbounded same-frame recursion) and is proven by test
(nested job executes on a strictly later tick).

## Lifecycle

- **`Initialize`** once. A duplicate `Initialize` **fails closed** (returns
  false, no effect). If the carrier does not activate for this build,
  initialization fails closed and the game runs vanilla.
- **`Enqueue`** — thread-safe, any thread; rejects (fails closed) once not
  accepting (not initialized / shutting down / carrier inactive).
- **`Tick` (pump)** — runs only on the game thread (proven: recorded
  `exec_thread_id` equals the independently identified GameThread; producer
  thread ids differ).
- **`Shutdown`** — stops accepting, then an **explicit handshake** (not a sleep):
  the pump arms a destroy signal and returns `false`; when FTSTicker destroys the
  element (which holds our pump code) on the game thread, the pump functor's
  destructor signals `WaitFullyStopped`. Only after that returns is the module
  safe to unload — no carrier code can re-enter it. **Drop policy:** any job
  still queued when the pump has stopped is dropped (counted), never run during
  shutdown.

## Version resilience (fail closed)

Every runtime address stays build/fingerprint-gated. The controller resolves
`base + RVA` only after a whole-image sha256 match and byte-verifies each live
address against the on-disk image; it then passes the addresses **and their
expected first bytes** to the DLL. `UE54TickerCarrier::Activate()` re-verifies
those bytes live and **fails closed** on any mismatch: nothing is bound, no
guessed address is ever used, and the game continues vanilla. RVAs are never
unconditional constants for an unknown build.

## What is proven (LOG-0076, live)

`research/instrument-runs/2026-08-28T191959Z-runtime-armed/`: 800 jobs from 4
concurrent producers, every one executed exactly once on the GameThread
(tid 15552 == E1 == E2), producer tids all distinct; bounded drain (25 ticks at
budget 32); clean Shutdown handshake (`wait_stopped_ok`, `ticks_after_shutdown=0`);
DLL unloaded; game healthy; `verify_install` MATCH before/after. Host-side
unit tests (`runtime/tests/dispatcher_host_test.cpp`) cover duplicate-Initialize,
fail-closed activation, exactly-once, per-producer FIFO, bounded drain,
nested-enqueue-next-tick, post-shutdown rejection, and drop-on-shutdown.

## Residual notes

- POD jobs have no failure/exception mode by construction; if a future job type
  could throw, the pump would need a per-job guard. Documented, not yet needed.
- Backlog is unbounded if producers persistently outpace the drain budget — the
  frame stays safe, but memory is the producer's responsibility.
- A production dispatcher would normally keep the DLL resident; unload here is a
  tested capability, gated on the destroy handshake.
- Anti-cheat surface is `NOT FOUND` (not cleared); this mechanism writes zero
  engine memory beyond the standard FTSTicker queue registration.
