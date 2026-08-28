// MiseryRuntime -- INTERNAL. Injected-DLL entry + public-API backing + the live
// dispatcher test driver. Wires GameThreadDispatcher to the UE54TickerCarrier and
// exposes Init/RunTest/Shutdown for the controller. POD jobs only -- no UObject /
// gameplay operations (that is a separate, later gate).
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"
#include "../Public/MiseryGameThread.h"

using Misery::Internal::CarrierBindings;
using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;

namespace {

constexpr uint64_t kMagic = 0x4950502D4D525452ULL;  // "IPP-MRTR"
constexpr uint32_t kProto = 1;
constexpr uint32_t kMaxJobs = 2048;

#pragma pack(push, 1)
struct RuntimeIo {
  // input
  uint64_t magic;
  uint32_t proto;
  uint32_t max_jobs_per_tick;
  uint64_t add_ticker, get_core_ticker, fmemory_malloc;
  uint8_t sig_add[16], sig_get[16], sig_malloc[16];
  uint32_t num_producers;       // <= 8
  uint32_t jobs_per_producer;   // total <= kMaxJobs
  uint32_t test_timeout_ms;
  uint32_t shutdown_timeout_ms;
  // output
  uint32_t activated;
  uint32_t initialized;
  uint32_t submitted, executed, dropped, rejected, ticks;
  uint32_t exec_thread_id;
  uint32_t worker_tids[8];
  int32_t state;
  uint32_t wait_stopped_ok;
  uint32_t exactly_once;
  uint32_t all_on_gamethread;
  uint32_t ticks_after_shutdown_delta;  // should be 0 -> pump stopped
  uint32_t reserved[7];
};
#pragma pack(pop)
static_assert(sizeof(RuntimeIo) == 216, "RuntimeIo layout must match the controller");

// ---- runtime singletons (this module's own state) ----
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
RuntimeIo* g_io = nullptr;

// per-job execution records (POD)
std::atomic<uint32_t> g_exec_count[kMaxJobs];
std::atomic<uint32_t> g_exec_tid[kMaxJobs];
struct JobArg { uint32_t id; };
JobArg g_args[kMaxJobs];

void RunJob(void* ctx) {
  const uint32_t id = static_cast<JobArg*>(ctx)->id;
  if (id < kMaxJobs) {
    g_exec_count[id].fetch_add(1, std::memory_order_relaxed);
    g_exec_tid[id].store(static_cast<uint32_t>(GetCurrentThreadId()), std::memory_order_relaxed);
  }
}

}  // namespace

// ---- public API backing ----
namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp != nullptr && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp != nullptr && g_disp->Enqueue(fn, ctx); }
}}  // namespace Misery::GameThread

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
  RuntimeIo* io = static_cast<RuntimeIo*>(param);
  if (io == nullptr || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
  g_io = io;
  for (uint32_t i = 0; i < kMaxJobs; ++i) { g_exec_count[i].store(0); g_exec_tid[i].store(0); }

  CarrierBindings b;
  b.add_ticker = io->add_ticker;
  b.get_core_ticker = io->get_core_ticker;
  b.fmemory_malloc = io->fmemory_malloc;
  std::memcpy(b.sig_add, io->sig_add, 16);
  std::memcpy(b.sig_get, io->sig_get, 16);
  std::memcpy(b.sig_malloc, io->sig_malloc, 16);

  g_carrier = Misery::Internal::CreateUE54TickerCarrier(b);
  g_disp = new GameThreadDispatcher();
  GameThreadDispatcher::Config cfg;
  cfg.max_jobs_per_tick = io->max_jobs_per_tick ? io->max_jobs_per_tick : 64;
  bool ok = g_disp->Initialize(g_carrier, cfg);
  io->activated = g_disp->stats().state.load() != GameThreadDispatcher::kUninit ? 1u : 0u;
  io->initialized = ok ? 1u : 0u;
  io->state = g_disp->stats().state.load();
  return ok ? 0u : 0xFFFFFFFEu;
}

extern "C" __declspec(dllexport) unsigned long RunTest(void* param) {
  RuntimeIo* io = static_cast<RuntimeIo*>(param);
  if (io == nullptr || io != g_io || g_disp == nullptr) return 0xFFFFFFFFu;
  uint32_t P = io->num_producers ? io->num_producers : 2;
  if (P > 8) P = 8;
  uint32_t M = io->jobs_per_producer ? io->jobs_per_producer : 100;
  if (P * M > kMaxJobs) M = kMaxJobs / P;
  const uint32_t total = P * M;

  std::vector<std::thread> producers;
  std::atomic<uint32_t> ready{0};
  for (uint32_t p = 0; p < P; ++p) {
    producers.emplace_back([p, M, io] {
      io->worker_tids[p] = static_cast<uint32_t>(GetCurrentThreadId());
      for (uint32_t i = 0; i < M; ++i) {
        uint32_t id = p * M + i;
        g_args[id].id = id;
        while (!g_disp->Enqueue(&RunJob, &g_args[id])) std::this_thread::yield();
      }
    });
  }
  for (auto& t : producers) t.join();

  const uint32_t deadline_ms = io->test_timeout_ms ? io->test_timeout_ms : 8000;
  for (uint32_t waited = 0; waited < deadline_ms && g_disp->stats().executed.load() < total; waited += 2)
    std::this_thread::sleep_for(std::chrono::milliseconds(2));

  // compute exactly-once + all-on-gamethread over the accepted jobs
  const uint32_t gt = g_disp->stats().exec_thread_id.load();
  uint32_t once = 1, on_gt = 1;
  for (uint32_t id = 0; id < total; ++id) {
    if (g_exec_count[id].load() != 1) once = 0;
    if (g_exec_tid[id].load() != gt) on_gt = 0;
  }
  io->submitted = g_disp->stats().submitted.load();
  io->executed = g_disp->stats().executed.load();
  io->dropped = g_disp->stats().dropped.load();
  io->rejected = g_disp->stats().rejected.load();
  io->ticks = g_disp->stats().ticks.load();
  io->exec_thread_id = gt;
  io->exactly_once = once;
  io->all_on_gamethread = on_gt;
  io->state = g_disp->stats().state.load();
  return 0u;
}

extern "C" __declspec(dllexport) unsigned long Shutdown(void* param) {
  RuntimeIo* io = static_cast<RuntimeIo*>(param);
  if (io == nullptr || io != g_io || g_disp == nullptr) return 0xFFFFFFFFu;
  const uint32_t ticks_before = g_disp->stats().ticks.load();
  g_disp->Shutdown(io->shutdown_timeout_ms ? io->shutdown_timeout_ms : 5000);
  io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
  io->state = g_disp->stats().state.load();
  // corroboration: pump must not advance after the handshake
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  io->ticks_after_shutdown_delta = g_disp->stats().ticks.load() - ticks_before;
  io->submitted = g_disp->stats().submitted.load();
  io->executed = g_disp->stats().executed.load();
  io->dropped = g_disp->stats().dropped.load();
  // release runtime state (safe: WaitFullyStopped guaranteed no re-entry)
  delete g_disp; g_disp = nullptr;
  Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
  return 0u;
}
