#include "ResolveOnGameThread.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <atomic>

#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"

namespace misery {
namespace gamethread {
namespace {

Misery::Internal::IGameThreadCarrier* g_carrier = nullptr;
Misery::Internal::GameThreadDispatcher* g_dispatcher = nullptr;
CarrierInput g_bindings;
bool g_ready = false;

uint64_t Ticks() {
  LARGE_INTEGER now;
  QueryPerformanceCounter(&now);
  return static_cast<uint64_t>(now.QuadPart);
}

uint32_t Micros(uint64_t from, uint64_t to) {
  static double scale = 0.0;
  if (scale == 0.0) {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    scale = 1000000.0 / static_cast<double>(frequency.QuadPart);
  }
  if (to <= from) {
    return 0;
  }
  double micros = static_cast<double>(to - from) * scale;
  return micros > 4294967295.0 ? 4294967295u : static_cast<uint32_t>(micros);
}

void Say(std::string* error, const char* format, ...) {
  if (error == nullptr) {
    return;
  }
  char buffer[512];
  va_list args;
  va_start(args, format);
  _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
  va_end(args);
  *error = buffer;
}

// Everything one resolution needs, and OWNS.
//
// WHY THE JOB TOUCHES NOTHING BELONGING TO THE CALLER
// ---------------------------------------------------
// The caller can stop waiting -- there is a timeout, and there has to be, since
// a pump that is not running would otherwise block forever. But the job stays
// queued and may run at any later point. If it held pointers into the caller's
// frame, a timeout followed by a late drain would write into a stack that has
// already returned: a memory-corruption bug whose trigger is a slow frame.
//
// So Work owns its inputs AND its outputs. The job reads and writes only Work.
// The caller copies the results out after `done`, and the LAST of the two to
// finish with the allocation frees it, decided by `owners`. There is no window
// in which both sides can touch it and no window in which neither frees it.
struct Work {
  uint64_t guobjectarray = 0;
  uint64_t namepool = 0;
  resolve::Request request;          // copied, not referenced
  resolve::Anchors anchors;          // filled here, copied out by the caller
  resolve::Failure failure;
  Cost cost;
  uint64_t queued_at = 0;
  std::atomic<uint32_t> done{0};
  std::atomic<uint32_t> ok{0};
  // Two owners: the caller and the queued job CHAIN. A chain re-enqueues itself
  // many times but is one owner throughout, releasing once when it stops.
  std::atomic<uint32_t> owners{2};

  // ---- chunked-walk state, owned by the job chain -----------------------
  // Heap-allocated because it must survive between slices, and held here so the
  // ownership rule that protects the results protects the walk too.
  resolve::Layout layout;
  resolve::Universe* universe = nullptr;
  bool begun = false;
  // The walk is finished and the anchor step is owed its OWN slice.
  //
  // Without this the last walk slice and the anchor step shared a tick, and
  // their costs added: measured at 1.5ms of walk remainder plus 12.6ms of
  // anchors = a 14.1ms slice, which is the hitch this whole design exists to
  // avoid. One slice now does one kind of work.
  bool walk_done = false;
  uint32_t restarts = 0;
  uint64_t walk_ticks = 0;      // accumulated across slices
  // Slots examined over the WHOLE resolution, restarts included. The cursor
  // resets on a restart, so counting it directly would under-report exactly the
  // runs that did the most work.
  uint32_t processed_total = 0;
  uint64_t carried_reads = 0;         // from attempts a restart threw away
  uint64_t carried_vqueries = 0;
  uint64_t carried_cache_hits = 0;

  ~Work() { delete universe; }
};

void ReleaseWork(Work* work) {
  if (work->owners.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    delete work;
  }
}

// One slice of one resolution, on the game thread.
//
// The state machine, and every exit from it:
//
//   begin  -> scan -> scan -> ... -> anchors -> revalidate -> scope -> publish
//               |                                   |
//               +-- graph moved ----> restart <------+
//                                        |
//                                        +-- too many restarts -> refuse
//
// Each call does at most kSliceBudgetUs of work and then either re-enqueues
// itself or finishes. Nothing here blocks, and nothing here runs longer than one
// slice: the whole point is that no individual tick is a visible hitch.
void ResolveSlice(void* ctx) {
  Work* work = static_cast<Work*>(ctx);
  const uint64_t slice_began = Ticks();
  work->cost.thread_id = GetCurrentThreadId();
  ++work->cost.slices;

  auto finish = [&](bool ok) {
    const uint32_t slice_us = Micros(slice_began, Ticks());
    if (slice_us > work->cost.max_slice_us) {
      work->cost.max_slice_us = slice_us;
      // slices was already incremented for this call, so it is a count;
      // subtract one to report a 0-based index.
      work->cost.max_slice_index = work->cost.slices - 1;
    }
    const resolve::ReadStats stats = resolve::ReadStatsSnapshot();
    work->cost.reads =
        static_cast<uint32_t>(work->carried_reads + stats.reads);
    work->cost.vqueries =
        static_cast<uint32_t>(work->carried_vqueries + stats.queries);
    work->cost.cache_hits =
        static_cast<uint32_t>(work->carried_cache_hits + stats.cache_hits);
    work->cost.restarts = work->restarts;
    work->ok.store(ok ? 1u : 0u, std::memory_order_release);
    work->done.store(1u, std::memory_order_release);
    ReleaseWork(work);
  };

  auto yield_slice = [&]() {
    const uint32_t slice_us = Micros(slice_began, Ticks());
    if (slice_us > work->cost.max_slice_us) {
      work->cost.max_slice_us = slice_us;
      // slices was already incremented for this call, so it is a count;
      // subtract one to report a 0-based index.
      work->cost.max_slice_index = work->cost.slices - 1;
    }
    if (!g_dispatcher->Enqueue(&ResolveSlice, work)) {
      // The dispatcher stopped accepting: the pump is going away, so this
      // resolution cannot continue. Reported, not silently abandoned.
      work->failure.Set("the game-thread pump stopped before the resolution "
                        "completed");
      finish(false);
    }
  };

  auto restart = [&]() -> bool {
    // Fold the discarded attempt's read counts into the totals before
    // BeginBuild zeroes them, or a restart would erase the evidence of the work
    // that provoked it.
    const resolve::ReadStats stats = resolve::ReadStatsSnapshot();
    work->carried_reads += stats.reads;
    work->carried_vqueries += stats.queries;
    work->carried_cache_hits += stats.cache_hits;
    if (++work->restarts > kMaxRestarts) {
      work->failure.Set("the object graph kept changing under the walk (" +
                        std::to_string(work->restarts) +
                        " restarts); it did not hold still long enough to "
                        "resolve");
      return false;
    }
    work->begun = false;
    work->walk_done = false;
    work->walk_ticks = 0;
    delete work->universe;
    work->universe = nullptr;
    return true;
  };

  // ---- begin, or re-begin after a restart -------------------------------
  if (!work->begun) {
    if (work->cost.queued_us == 0) {
      work->cost.queued_us = Micros(work->queued_at, slice_began);
    }
    work->universe = new resolve::Universe(work->guobjectarray, work->namepool,
                                          work->layout);
    resolve::Failure local;
    if (!work->universe->BeginBuild(&local)) {
      work->failure.Set(local.what);
      finish(false);
      return;
    }
    work->begun = true;
    // BeginBuild is not free: it reserves a hash bucket array sized for every
    // object in the process, which is megabytes at gameplay counts. Doing that
    // and then walking in the same tick made slice 0 the longest slice of the
    // whole resolution. It gets its own tick, for the same reason the anchor
    // step does -- one slice, one kind of work.
    yield_slice();
    return;
  }

  // ---- one bounded slice of the walk -----------------------------------
  if (work->walk_done) {
    goto anchors;   // this tick belongs to the anchor step, not the walk
  }
  {
  const uint64_t walk_from = Ticks();
  const uint32_t cursor_before = work->universe->Cursor();
  resolve::Failure walk_failure;
  const resolve::Universe::Step step = work->universe->StepBuild(
      kSliceBudgetUs, kSliceMaxObjects, &walk_failure);
  work->walk_ticks += Ticks() - walk_from;
  work->processed_total += work->universe->Cursor() - cursor_before;
  work->cost.objects_processed = work->processed_total;

  if (step == resolve::Universe::Step::kRestartNeeded) {
    if (!restart()) {
      finish(false);
      return;
    }
    yield_slice();
    return;
  }
  if (step == resolve::Universe::Step::kMore) {
    yield_slice();
    return;
  }
  if (walk_failure.failed) {
    work->failure.Set(walk_failure.what);
    finish(false);
    return;
  }

  // The walk finished. Hand the anchor step its own tick rather than doing it
  // on the end of this one.
  work->walk_done = true;
  work->cost.build_us = Micros(0, work->walk_ticks);
  yield_slice();
  return;
  }

anchors:
  // ---- the walk is complete: anchors, in a slice of their own -----------
  //
  // Cheap now. Anchor lookups used to scan the whole universe per anchor, which
  // cost 215.7 ms in gameplay; objects are indexed by name during the walk, so
  // this is a hash probe per anchor and stays well inside one slice. max_slice_us
  // is the check on that claim.
  const uint64_t anchors_from = Ticks();
  resolve::Anchors candidate;
  resolve::Request attempt = work->request;
  if (attempt.prefer_gameplay && attempt.require < resolve::Phase::kGameplay) {
    attempt.require = resolve::Phase::kGameplay;
  }
  bool resolved = resolve::ResolveAnchors(*work->universe, attempt, &candidate,
                                          &work->failure);
  if (!resolved && attempt.require != work->request.require) {
    // Not in gameplay. Fall back to what the caller actually requires, against
    // the same universe -- see Request::prefer_gameplay. Both outputs are reset
    // rather than reused: a failed attempt's partial anchors and its failure
    // text must not survive into the result that gets published.
    candidate = resolve::Anchors();
    work->failure = resolve::Failure();
    resolved = resolve::ResolveAnchors(*work->universe, work->request,
                                       &candidate, &work->failure);
  }
  work->cost.resolve_us = Micros(anchors_from, Ticks());
  work->cost.objects = static_cast<uint32_t>(work->universe->Count());
  work->cost.objects_ptr = work->universe->ObjectsPointer();
  work->cost.completed_phase = static_cast<uint32_t>(candidate.reached);

  if (!resolved) {
    work->anchors = candidate;
    finish(false);
    return;
  }

  // ---- final live re-validation, in ONE uninterrupted slice -------------
  //
  // Everything above is an observation of some earlier moment. This is the only
  // place the result is checked against the process as it is NOW, and it is
  // deliberately not sliced: a validation spread over ticks would have the same
  // problem it exists to solve.
  const uint64_t validate_from = Ticks();
  for (const resolve::AnchorIdentity& identity : candidate.identities) {
    // LIVENESS FIRST, from the engine's own bookkeeping. StillIs re-reads the
    // object's name and class, and both survive destruction untouched until the
    // memory is reused -- so on its own it detects RECYCLED memory, not FREED
    // memory, and would publish a destroyed object as live. The slot check is
    // the authoritative one; StillIs stays as a second, independent identity
    // check on top of it.
    const resolve::Universe::Liveness liveness =
        work->universe->CheckSlot(identity);
    if (liveness != resolve::Universe::Liveness::kAlive) {
      ++work->cost.revalidation_failures;
      work->cost.validate_us = Micros(validate_from, Ticks());
      if (!restart()) {
        work->failure.Set("'" + identity.label + "' is not publishable: " +
                          resolve::Universe::LivenessName(liveness) +
                          ", and the graph would not hold still long enough to "
                          "resolve again");
        finish(false);
        return;
      }
      yield_slice();
      return;
    }
    if (!work->universe->StillIs(identity.address, identity.name,
                                 identity.class_name)) {
      ++work->cost.revalidation_failures;
      work->cost.validate_us = Micros(validate_from, Ticks());
      if (!restart()) {
        work->failure.Set("'" + identity.label +
                          "' was destroyed while the walk was in progress, and "
                          "the graph would not hold still long enough to "
                          "resolve again");
        finish(false);
        return;
      }
      yield_slice();
      return;
    }
    if (!identity.check_outer_class.empty() &&
        work->universe->LiveOuterClassName(identity.address) !=
            identity.check_outer_class) {
      ++work->cost.revalidation_failures;
      work->cost.validate_us = Micros(validate_from, Ticks());
      if (!restart()) {
        work->failure.Set("'" + identity.label +
                          "' is no longer owned by a " +
                          identity.check_outer_class);
        finish(false);
        return;
      }
      yield_slice();
      return;
    }
  }
  work->cost.validate_us = Micros(validate_from, Ticks());

  // ---- the phase must not have moved under us --------------------------
  //
  // A resolution that began before content existed and completed after it
  // appeared describes neither state. Publishing it would be publishing a mixed
  // view, so it restarts instead.
  if (!work->request.survey &&
      work->cost.completed_phase < work->cost.requested_phase) {
    work->failure.Set("the process fell below the requested phase during the "
                      "walk (asked for " +
                      std::string(resolve::PhaseName(work->request.require)) +
                      ", completed at " +
                      std::string(resolve::PhaseName(candidate.reached)) + ")");
    work->anchors = candidate;
    finish(false);
    return;
  }

  work->anchors = candidate;
  finish(true);
}

}  // namespace

bool Ensure(const CarrierInput& carrier, std::string* error) {
  if (g_ready) {
    // Idempotent, but only for the SAME build. Different bindings would mean
    // somebody is trying to re-point the carrier at another process image.
    if (memcmp(&carrier, &g_bindings, sizeof(CarrierInput)) != 0) {
      Say(error, "the game-thread carrier is already active with different "
                 "bindings; refusing to re-point it");
      return false;
    }
    return true;
  }
  if (carrier.add_ticker == 0 || carrier.get_core_ticker == 0 ||
      carrier.fmemory_malloc == 0) {
    Say(error, "the carrier bindings are incomplete");
    return false;
  }

  Misery::Internal::CarrierBindings bindings;
  bindings.add_ticker = carrier.add_ticker;
  bindings.get_core_ticker = carrier.get_core_ticker;
  bindings.fmemory_malloc = carrier.fmemory_malloc;
  memcpy(bindings.sig_add, carrier.sig_add, sizeof(bindings.sig_add));
  memcpy(bindings.sig_get, carrier.sig_get, sizeof(bindings.sig_get));
  memcpy(bindings.sig_malloc, carrier.sig_malloc, sizeof(bindings.sig_malloc));

  g_carrier = Misery::Internal::CreateUE54TickerCarrier(bindings);
  if (g_carrier == nullptr) {
    Say(error, "the carrier could not be created");
    return false;
  }
  g_dispatcher = new Misery::Internal::GameThreadDispatcher();
  Misery::Internal::GameThreadDispatcher::Config config;
  // One resolution per tick. A walk is the expensive thing in this module, and
  // running two in one frame would double a cost we are trying to keep visible.
  config.max_jobs_per_tick = 1;
  if (!g_dispatcher->Initialize(g_carrier, config)) {
    // Fails closed: the carrier re-verifies the build's own bytes and binds
    // nothing on a mismatch.
    Say(error, "the game-thread carrier did not activate for this build; the "
               "recorded signature bytes do not match what is mapped");
    delete g_dispatcher;
    g_dispatcher = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier);
    g_carrier = nullptr;
    return false;
  }
  g_bindings = carrier;
  g_ready = true;
  return true;
}

bool IsReady() { return g_ready; }

bool Resolve(uint64_t guobjectarray, uint64_t namepool,
             const resolve::Request& request, resolve::Anchors* out,
             resolve::Failure* failure, uint32_t timeout_ms, Cost* cost,
             std::string* error) {
  if (!g_ready || g_dispatcher == nullptr) {
    Say(error, "the game-thread carrier is not active; resolution will not run "
               "off the game thread");
    return false;
  }

  Work* work = new Work();
  work->guobjectarray = guobjectarray;
  work->namepool = namepool;
  work->request = request;              // copied: the job must not need it alive
  work->queued_at = Ticks();
  // Captured at REQUEST time, before any slice runs. The completion phase is
  // compared against this so a walk that spanned a transition is refused rather
  // than published as if it described one state.
  work->cost.requested_phase = static_cast<uint32_t>(request.require);

  if (!g_dispatcher->Enqueue(&ResolveSlice, work)) {
    work->owners.store(1u, std::memory_order_release);   // no job will run
    ReleaseWork(work);
    Say(error, "the dispatcher refused the job (not accepting work)");
    return false;
  }

  // Poll rather than block on an event: the job runs on the game thread's pump,
  // and the wait is short by design.
  const DWORD deadline = GetTickCount() + timeout_ms;
  while (work->done.load(std::memory_order_acquire) == 0) {
    if (GetTickCount() > deadline) {
      // Give up waiting, but do NOT free: the job is still queued and may run.
      // Dropping this owner leaves the allocation to the job, which owns
      // everything it touches, so a late drain writes only into memory that is
      // still alive.
      ReleaseWork(work);
      Say(error, "the game thread did not drain the resolution within %ums; it "
                 "may be blocked or the pump may not be running",
          timeout_ms);
      return false;
    }
    Sleep(1);
  }

  const bool ok = work->ok.load(std::memory_order_acquire) != 0;
  // Copy out before releasing: after ReleaseWork the allocation may be gone.
  if (out != nullptr) {
    *out = work->anchors;
  }
  if (failure != nullptr) {
    *failure = work->failure;
  }
  if (cost != nullptr) {
    *cost = work->cost;
  }
  const std::string why = work->failure.what;
  ReleaseWork(work);

  if (!ok && error != nullptr && error->empty()) {
    Say(error, "resolution ran on the game thread and failed: %s", why.c_str());
  }
  return ok;
}

namespace {

// One arbitrary job, with the same two-owner rule Work uses.
struct Blocking {
  void (*job)(void*) = nullptr;
  void* ctx = nullptr;
  std::atomic<uint32_t> done{0};
  std::atomic<uint32_t> owners{2};
};

void ReleaseBlocking(Blocking* work) {
  if (work->owners.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    delete work;
  }
}

void BlockingThunk(void* ctx) {
  Blocking* work = static_cast<Blocking*>(ctx);
  work->job(work->ctx);
  work->done.store(1u, std::memory_order_release);
  ReleaseBlocking(work);
}

}  // namespace

bool RunBlocking(void (*job)(void* ctx), void* ctx, uint32_t timeout_ms,
                 std::string* error) {
  if (!g_ready || g_dispatcher == nullptr || job == nullptr) {
    Say(error, "the game-thread carrier is not active");
    return false;
  }
  Blocking* work = new Blocking();
  work->job = job;
  work->ctx = ctx;
  if (!g_dispatcher->Enqueue(&BlockingThunk, work)) {
    work->owners.store(1u, std::memory_order_release);
    ReleaseBlocking(work);
    Say(error, "the dispatcher refused the job");
    return false;
  }
  const DWORD deadline = GetTickCount() + timeout_ms;
  while (work->done.load(std::memory_order_acquire) == 0) {
    if (GetTickCount() > deadline) {
      ReleaseBlocking(work);
      Say(error, "the game thread did not run the job within the timeout");
      return false;
    }
    Sleep(1);
  }
  ReleaseBlocking(work);
  return true;
}

void SetFrameCallback(void (*fn)(void* ctx), void* ctx) {
  if (g_dispatcher == nullptr) return;
  g_dispatcher->SetFrameCallback(fn, ctx);
}

void Teardown(uint32_t timeout_ms) {
  // Drop the frame callback BEFORE stopping the pump. Leaving it installed
  // through teardown would leave one more chance for the pump to call into a
  // module that is being taken apart.
  if (g_dispatcher != nullptr) g_dispatcher->SetFrameCallback(nullptr, nullptr);
  if (g_dispatcher != nullptr) {
    g_dispatcher->Shutdown(timeout_ms);
    delete g_dispatcher;
    g_dispatcher = nullptr;
  }
  if (g_carrier != nullptr) {
    Misery::Internal::DestroyCarrier(g_carrier);
    g_carrier = nullptr;
  }
  g_ready = false;
}

}  // namespace gamethread
}  // namespace misery
