// MiseryRuntime -- INTERNAL. The dispatcher: a runtime-owned thread-safe queue
// plus the game-thread pump lifecycle. Carrier-agnostic (depends only on
// IGameThreadCarrier), so this whole file is host-testable with a fake carrier,
// with no UE headers.
//
// QUEUE + ORDERING. A std::mutex-guarded std::deque. Every Enqueue is one atomic
// lock/push/unlock, so the total execution order is exactly the order in which
// Enqueue calls acquired the lock; a single producer's own jobs therefore keep
// program order. No stronger cross-producer ordering is promised (a producer
// that "began" enqueuing earlier but took the lock later runs later). This is
// the documented, proven semantics -- not a global FIFO by wall-clock.
//
// BOUNDED DRAIN (frame safety). Each pump tick moves at most max_jobs_per_tick
// jobs out of the queue under the lock into a local batch, releases the lock,
// then runs the batch. Work per game-thread frame is bounded by that budget, so
// a flooding background producer can never stall the frame; overflow simply
// waits for later ticks. A job that enqueues another job puts it back on the
// queue, so NESTED work runs on the NEXT drain, never same-frame -- the safer,
// deterministic policy (no unbounded same-frame recursion).
#ifndef MISERY_GAMETHREADDISPATCHER_H
#define MISERY_GAMETHREADDISPATCHER_H

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "IGameThreadCarrier.h"
#include "../Public/MiseryGameThread.h"

// Declared by hand to keep <windows.h> out of a header this widely included.
//
// `dllimport` is not decoration: the SDK declares this as an import, and a
// translation unit that saw <windows.h> first got two declarations that
// disagreed about linkage (C4273). It resolved to the same function anyway,
// which is why it went unnoticed -- the warning was being printed into output
// that only appeared when a build failed.
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);

namespace Misery {
namespace Internal {

class GameThreadDispatcher {
 public:
  enum State : int32_t { kUninit = 0, kRunning = 1, kStopping = 2, kStopped = 3 };

  struct Config {
    uint32_t max_jobs_per_tick = 64;  // per-frame work budget (bounded drain)
  };

  struct Stats {
    std::atomic<uint32_t> submitted{0};
    std::atomic<uint32_t> executed{0};
    std::atomic<uint32_t> dropped{0};    // pending-at-shutdown, per drop policy
    std::atomic<uint32_t> rejected{0};   // Enqueue while not accepting
    std::atomic<uint32_t> ticks{0};
    std::atomic<uint32_t> exec_thread_id{0};  // last game-thread id the pump saw
    std::atomic<int32_t> state{kUninit};
  };

  struct Job {
    Misery::GameThread::JobFn fn;
    void* ctx;
  };

  // Initialize once. A duplicate Initialize fails closed (returns false, no
  // effect). If the carrier does not activate for this build, initialization
  // fails closed and the game runs vanilla.
  bool Initialize(IGameThreadCarrier* carrier, Config cfg) {
    bool expected = false;
    if (!initialized_.compare_exchange_strong(expected, true)) {
      return false;  // duplicate Initialize
    }
    carrier_ = carrier;
    cfg_ = cfg;
    if (cfg_.max_jobs_per_tick == 0) cfg_.max_jobs_per_tick = 1;
    if (!carrier_->Activate()) {  // unknown build -> vanilla
      initialized_.store(false);
      stats_.state.store(kUninit);
      return false;
    }
    {
      std::lock_guard<std::mutex> lk(mtx_);
      accepting_ = true;
    }
    stats_.state.store(kRunning);
    if (!carrier_->Start(&GameThreadDispatcher::PumpThunk, this)) {
      std::lock_guard<std::mutex> lk(mtx_);
      accepting_ = false;
      stats_.state.store(kUninit);
      initialized_.store(false);
      return false;
    }
    return true;
  }

  // Thread-safe; any thread. Rejects (fails closed) when not accepting.
  bool Enqueue(Misery::GameThread::JobFn fn, void* ctx) {
    if (fn == nullptr) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    if (!accepting_) {
      stats_.rejected.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    queue_.push_back(Job{fn, ctx});
    stats_.submitted.fetch_add(1, std::memory_order_relaxed);
    return true;
  }

  // Explicit shutdown handshake. Stops accepting, tears the pump down, and blocks
  // until no carrier code can re-enter this module. Drop policy: any job still
  // queued when the pump has stopped is dropped (counted), never run during
  // shutdown.
  void Shutdown(uint32_t timeout_ms) {
    {
      std::lock_guard<std::mutex> lk(mtx_);
      if (stats_.state.load() == kStopped) return;
      accepting_ = false;
    }
    stats_.state.store(kStopping);
    if (carrier_ != nullptr) {
      carrier_->Stop();
      wait_stopped_ok_ = carrier_->WaitFullyStopped(timeout_ms);  // element destroyed -> no re-entry
    }
    {
      std::lock_guard<std::mutex> lk(mtx_);
      stats_.dropped.fetch_add(static_cast<uint32_t>(queue_.size()), std::memory_order_relaxed);
      queue_.clear();
    }
    stats_.state.store(kStopped);
    initialized_.store(false);
  }

  const Stats& stats() const { return stats_; }
  uint32_t max_jobs_per_tick() const { return cfg_.max_jobs_per_tick; }
  bool wait_stopped_ok() const { return wait_stopped_ok_; }

 private:
  static bool PumpThunk(void* self, float dt) {
    return static_cast<GameThreadDispatcher*>(self)->Pump(dt);
  }

  // Runs on the game thread, once per frame. Bounded drain.
  bool Pump(float /*dt*/) {
    stats_.exec_thread_id.store(GetCurrentThreadId(), std::memory_order_relaxed);
    stats_.ticks.fetch_add(1, std::memory_order_relaxed);

    batch_.clear();
    {
      std::lock_guard<std::mutex> lk(mtx_);
      const uint32_t budget = cfg_.max_jobs_per_tick;
      while (batch_.size() < budget && !queue_.empty()) {
        batch_.push_back(queue_.front());
        queue_.pop_front();
      }
    }
    for (const Job& j : batch_) {
      j.fn(j.ctx);  // a nested Enqueue lands on queue_ -> next tick (bounded)
      stats_.executed.fetch_add(1, std::memory_order_relaxed);
    }
    return true;  // stay registered; Stop() drives removal via the carrier
  }

  IGameThreadCarrier* carrier_ = nullptr;
  Config cfg_;
  std::mutex mtx_;
  std::deque<Job> queue_;
  std::vector<Job> batch_;  // reused per tick (game thread only)
  bool accepting_ = false;
  std::atomic<bool> initialized_{false};
  bool wait_stopped_ok_ = false;
  Stats stats_;
};

}  // namespace Internal
}  // namespace Misery

#endif  // MISERY_GAMETHREADDISPATCHER_H
