// MiseryRuntime -- host-side unit tests for GameThreadDispatcher, driven by a
// fake carrier (a controllable "game thread" that ticks the pump). No UE, no
// game. Validates queue/lifecycle/ordering/bounded-drain/nested-enqueue/shutdown
// semantics before the live FTSTicker carrier is exercised in MISERY.
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

#include "../MiseryRuntime/Internal/GameThreadDispatcher.h"

using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;
using Misery::Internal::PumpFn;

// A fake carrier whose "game thread" is a std::thread the test spins, calling the
// pump each simulated frame. Models the FTSTicker lifecycle: on Stop() the next
// frame runs no pump and confirms teardown (as if the ticker element -- holding
// our code -- was destroyed on the game thread), then signals WaitFullyStopped.
class FakeCarrier : public IGameThreadCarrier {
 public:
  bool Activate() override { return activate_result_; }
  bool Start(PumpFn pump, void* ctx) override {
    pump_ = pump; ctx_ = ctx;
    running_.store(true); stop_.store(false); torn_down_.store(false);
    game_thread_ = std::thread([this] { GameLoop(); });
    return true;
  }
  void Stop() override { stop_.store(true); }
  bool WaitFullyStopped(uint32_t timeout_ms) override {
    std::unique_lock<std::mutex> lk(cv_m_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this] { return torn_down_.load(); });
  }
  bool IsRunning() const override { return running_.load(); }

  // test controls
  void set_activate(bool v) { activate_result_ = v; }
  void JoinGameThread() { if (game_thread_.joinable()) game_thread_.join(); }
  uint32_t game_tid() const { return game_tid_.load(); }

 private:
  void GameLoop() {
    game_tid_.store(GetCurrentThreadId());
    for (;;) {
      if (stop_.load()) {
        // Shutdown frame: pump is NOT invoked; the ticker element (our code) is
        // considered destroyed here on the game thread -> confirm teardown.
        running_.store(false);
        {
          std::lock_guard<std::mutex> lk(cv_m_);
          torn_down_.store(true);
        }
        cv_.notify_all();
        return;
      }
      if (pump_) pump_(ctx_, 0.016f);
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  PumpFn pump_ = nullptr;
  void* ctx_ = nullptr;
  std::atomic<bool> running_{false}, stop_{false}, torn_down_{false};
  std::atomic<uint32_t> game_tid_{0};
  bool activate_result_ = true;
  std::thread game_thread_;
  std::mutex cv_m_;
  std::condition_variable cv_;
};

// ---- shared test job context ----
struct JobRec {
  std::atomic<uint32_t> exec_count[4096];
  std::atomic<uint32_t> exec_tid[4096];
  std::atomic<uint32_t> exec_tick[4096];
  GameThreadDispatcher* disp = nullptr;
  JobRec() { reset(); }
  void reset() { disp = nullptr; for (int i = 0; i < 4096; ++i) { exec_count[i] = 0; exec_tid[i] = 0; exec_tick[i] = 0; } }
};
struct JobArg { JobRec* rec; uint32_t id; uint32_t nested_id; };  // nested_id==0 => no nested

static JobRec g_rec;
static std::vector<JobArg> g_args;

static void RunJob(void* ctx) {
  JobArg* a = static_cast<JobArg*>(ctx);
  a->rec->exec_count[a->id].fetch_add(1);
  a->rec->exec_tid[a->id].store(GetCurrentThreadId());
  a->rec->exec_tick[a->id].store(a->rec->disp->stats().ticks.load());
  if (a->nested_id != 0) {
    // enqueue a nested job DURING drain -> must run on a LATER tick
    a->rec->disp->Enqueue(&RunJob, &g_args[a->nested_id]);
  }
}

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; } } while (0)

int main() {
  // ---------- Test A: duplicate Initialize fails closed ----------
  {
    FakeCarrier carrier; GameThreadDispatcher d;
    bool a = d.Initialize(&carrier, {64});
    bool b = d.Initialize(&carrier, {64});  // duplicate
    CHECK(a, "A: first Initialize");
    CHECK(!b, "A: duplicate Initialize fails closed");
    d.Shutdown(2000); carrier.JoinGameThread();
    CHECK(d.stats().state.load() == GameThreadDispatcher::kStopped, "A: state==stopped");
  }

  // ---------- Test B: unknown-build carrier -> fail closed ----------
  {
    FakeCarrier carrier; carrier.set_activate(false);
    GameThreadDispatcher d;
    bool a = d.Initialize(&carrier, {64});
    CHECK(!a, "B: Initialize fails closed on inactive carrier");
    CHECK(!d.Enqueue(&RunJob, nullptr), "B: Enqueue rejected when not initialized");
  }

  // ---------- Test C: multi-producer, exactly-once, thread proof, ordering ----------
  {
    g_rec.reset();
    FakeCarrier carrier; GameThreadDispatcher d;
    g_rec.disp = &d;
    d.Initialize(&carrier, {16});  // small budget -> bounded drain over many ticks
    const uint32_t P = 4, M = 200;  // 800 jobs
    g_args.clear(); g_args.resize(P * M + 1);
    std::vector<std::thread> producers;
    std::atomic<uint32_t> producer_tids[8] = {};
    for (uint32_t p = 0; p < P; ++p) {
      producers.emplace_back([&, p] {
        producer_tids[p].store(GetCurrentThreadId());
        for (uint32_t i = 0; i < M; ++i) {
          uint32_t id = p * M + i + 1;  // ids 1..P*M (0 reserved)
          g_args[id] = JobArg{&g_rec, id, 0};
          while (!d.Enqueue(&RunJob, &g_args[id])) std::this_thread::yield();
        }
      });
    }
    for (auto& t : producers) t.join();
    // wait until all executed
    for (int spin = 0; spin < 5000 && d.stats().executed.load() < P * M; ++spin)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(d.stats().submitted.load() == P * M, "C: submitted == P*M");
    CHECK(d.stats().executed.load() == P * M, "C: executed == P*M");
    bool once = true, on_gt = true, ord = true;
    for (uint32_t id = 1; id <= P * M; ++id) {
      if (g_rec.exec_count[id].load() != 1) once = false;
      if (g_rec.exec_tid[id].load() != carrier.game_tid()) on_gt = false;
    }
    // per-producer FIFO: within a producer, exec_tick is non-decreasing in id order
    for (uint32_t p = 0; p < P; ++p) {
      uint32_t last = 0;
      for (uint32_t i = 0; i < M; ++i) {
        uint32_t id = p * M + i + 1;
        uint32_t tk = g_rec.exec_tick[id].load();
        if (tk < last) ord = false;
        last = tk;
      }
    }
    CHECK(once, "C: every job executed exactly once");
    CHECK(on_gt, "C: every job executed on the game thread");
    CHECK(carrier.game_tid() != producer_tids[0].load(), "C: game thread != producer thread");
    CHECK(ord, "C: per-producer FIFO preserved (non-decreasing tick per producer)");
    // bounded drain: no tick ran more than budget jobs (executed <= ticks*budget)
    CHECK(d.stats().executed.load() <= d.stats().ticks.load() * d.max_jobs_per_tick(),
          "C: per-tick work bounded by budget");
    d.Shutdown(2000); carrier.JoinGameThread();
    CHECK(d.stats().dropped.load() == 0, "C: nothing dropped (all drained before shutdown)");
  }

  // ---------- Test D: nested enqueue runs on a LATER tick ----------
  {
    g_rec.reset();
    FakeCarrier carrier; GameThreadDispatcher d;
    g_rec.disp = &d;
    d.Initialize(&carrier, {64});
    g_args.clear(); g_args.resize(4);
    g_args[1] = JobArg{&g_rec, 1, 2};  // job 1 enqueues job 2
    g_args[2] = JobArg{&g_rec, 2, 0};
    d.Enqueue(&RunJob, &g_args[1]);
    for (int spin = 0; spin < 3000 && g_rec.exec_count[2].load() == 0; ++spin)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(g_rec.exec_count[1].load() == 1 && g_rec.exec_count[2].load() == 1, "D: both ran once");
    CHECK(g_rec.exec_tick[2].load() > g_rec.exec_tick[1].load(),
          "D: nested job ran on a strictly later tick (not same-frame)");
    d.Shutdown(2000); carrier.JoinGameThread();
  }

  // ---------- Test E: Enqueue after Shutdown is rejected; handshake state ----------
  {
    FakeCarrier carrier; GameThreadDispatcher d;
    d.Initialize(&carrier, {64});
    d.Shutdown(2000); carrier.JoinGameThread();
    CHECK(d.stats().state.load() == GameThreadDispatcher::kStopped, "E: state==stopped after shutdown");
    JobArg dummy{&g_rec, 1, 0};
    CHECK(!d.Enqueue(&RunJob, &dummy), "E: Enqueue rejected after shutdown");
    CHECK(d.stats().rejected.load() >= 1, "E: rejected counter incremented");
  }

  // ---------- Test F: shutdown with pending jobs -> dropped, not run ----------
  {
    g_rec.reset();
    FakeCarrier carrier; GameThreadDispatcher d;
    g_rec.disp = &d;
    carrier.set_activate(true);
    d.Initialize(&carrier, {1});  // tiny budget so a backlog persists
    g_args.clear(); g_args.resize(2000);
    for (uint32_t id = 1; id <= 1500; ++id) { g_args[id] = JobArg{&g_rec, id, 0}; d.Enqueue(&RunJob, &g_args[id]); }
    d.Shutdown(2000); carrier.JoinGameThread();
    uint32_t ex = d.stats().executed.load(), dr = d.stats().dropped.load();
    CHECK(ex + dr == 1500, "F: executed + dropped == submitted");
    CHECK(dr > 0, "F: some jobs dropped at shutdown (bounded budget left a backlog)");
  }

  printf("\nHOST DISPATCHER TESTS: %s (%d failure(s))\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
  return g_fail == 0 ? 0 : 1;
}
