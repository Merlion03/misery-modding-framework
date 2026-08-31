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
  // Two owners: the caller and the queued job. Whichever releases last frees.
  std::atomic<uint32_t> owners{2};
};

void ReleaseWork(Work* work) {
  if (work->owners.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    delete work;
  }
}

void ResolveJob(void* ctx) {
  Work* work = static_cast<Work*>(ctx);
  const uint64_t started = Ticks();

  const resolve::Layout layout;
  resolve::Universe universe(work->guobjectarray, work->namepool, layout);
  bool ok = universe.Build(&work->failure);
  const uint64_t built = Ticks();

  if (ok) {
    ok = resolve::ResolveAnchors(universe, work->request, &work->anchors,
                                 &work->failure);
  }
  const uint64_t finished = Ticks();

  const resolve::ReadStats stats = resolve::ReadStatsSnapshot();
  work->cost.queued_us = Micros(work->queued_at, started);
  work->cost.build_us = Micros(started, built);
  work->cost.resolve_us = Micros(built, finished);
  work->cost.objects = static_cast<uint32_t>(universe.Count());
  work->cost.reads = static_cast<uint32_t>(stats.reads);
  work->cost.vqueries = static_cast<uint32_t>(stats.queries);
  work->cost.cache_hits = static_cast<uint32_t>(stats.cache_hits);
  work->cost.thread_id = GetCurrentThreadId();

  work->ok.store(ok ? 1u : 0u, std::memory_order_release);
  work->done.store(1u, std::memory_order_release);
  ReleaseWork(work);
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

  if (!g_dispatcher->Enqueue(&ResolveJob, work)) {
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

void Teardown(uint32_t timeout_ms) {
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
