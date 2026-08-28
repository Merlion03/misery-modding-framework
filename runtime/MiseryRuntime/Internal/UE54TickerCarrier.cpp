// MiseryRuntime -- INTERNAL. FTSTicker carrier implementation (build-specific).
//
// Compiled with MSVC + genuine UE 5.4.4 headers. Registers ONE persistent pump
// on the game thread via the proven FTSTicker::AddTicker path (LOG-0075), and
// implements the unload-safety handshake: on Stop() the pump arms a destroy
// signal and returns false; when the ticker element (which holds our pump code)
// is destroyed on the game thread, the pump functor's destructor fires and
// signals WaitFullyStopped -- so no carrier code can re-enter this module after
// the handshake completes.
#include "UE54TickerCarrier.h"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>

#include "Containers/Ticker.h"

// Member+sret ABI (LOG-0074): RCX=this, RDX=&sret(TWeakPtr), R8=name, XMM3=delay,
// [stack]=&TFunction. TFunction (non-trivial) passed by hidden pointer.
using GetCoreTickerFn = void* (*)();
using AddTickerRaw = void(__fastcall*)(void* thisTicker, void* sretHandle,
                                       const wchar_t* name, float delay, void* fnPtr);
using MallocFn = void* (*)(size_t, uint32_t);

// The one FMemory symbol our owned-object code references; forward to the game's.
static MallocFn g_game_malloc = nullptr;
void* FMemory::Malloc(SIZE_T Count, uint32 Alignment) {
  return g_game_malloc(static_cast<size_t>(Count), static_cast<uint32_t>(Alignment));
}

namespace Misery {
namespace Internal {
namespace {

struct FTickerElementOpaque;  // TWeakPtr ctor/dtor are type-independent

class UE54Carrier : public IGameThreadCarrier {
 public:
  explicit UE54Carrier(const CarrierBindings& b) : b_(b) {}

  bool Activate() override {
    if (b_.add_ticker == 0 || b_.get_core_ticker == 0 || b_.fmemory_malloc == 0) return false;
    // Re-verify the live bytes match the expected signatures. Fail CLOSED.
    if (std::memcmp(reinterpret_cast<const void*>(b_.add_ticker), b_.sig_add, 16) != 0) return false;
    if (std::memcmp(reinterpret_cast<const void*>(b_.get_core_ticker), b_.sig_get, 16) != 0) return false;
    if (std::memcmp(reinterpret_cast<const void*>(b_.fmemory_malloc), b_.sig_malloc, 16) != 0) return false;
    g_game_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(b_.fmemory_malloc));
    activated_ = true;
    return true;
  }

  bool Start(PumpFn pump, void* ctx) override {
    if (!activated_ || running_.load()) return false;
    pump_ = pump;
    pump_ctx_ = ctx;
    stop_.store(false);
    arm_.store(false);
    torn_down_.store(false);
    running_.store(true);

    void* ticker = reinterpret_cast<GetCoreTickerFn>(static_cast<uintptr_t>(b_.get_core_ticker))();
    if (ticker == nullptr) { running_.store(false); return false; }

    TFunction<bool(float)> fn = PumpFunctor{this};      // captureless-size functor, inline
    TWeakPtr<FTickerElementOpaque> handle;              // 16-byte sret, released here
    reinterpret_cast<AddTickerRaw>(static_cast<uintptr_t>(b_.add_ticker))(
        ticker, &handle, L"MiseryRuntimePump", 0.0f, &fn);
    return true;
  }

  void Stop() override { stop_.store(true, std::memory_order_release); }

  bool WaitFullyStopped(uint32_t timeout_ms) override {
    if (!activated_) return true;
    std::unique_lock<std::mutex> lk(m_);
    return cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                        [this] { return torn_down_.load(); });
  }

  bool IsRunning() const override { return running_.load(); }

  // --- called from the pump functor, on the game thread ---
  bool OnTick(float dt) {
    if (stop_.load(std::memory_order_acquire)) {
      arm_.store(true, std::memory_order_release);  // element will be destroyed after we return false
      return false;
    }
    return pump_(pump_ctx_, dt);
  }
  void OnFunctorDestroyed() {
    // Fires for every functor copy. Only the armed one (the live element's,
    // destroyed after Stop) completes the handshake; registration-time
    // temporaries destruct with arm_==false and are ignored.
    if (arm_.load(std::memory_order_acquire)) {
      running_.store(false);
      {
        std::lock_guard<std::mutex> lk(m_);
        torn_down_.store(true);
      }
      cv_.notify_all();
    }
  }

 private:
  struct PumpFunctor {
    UE54Carrier* c;
    bool operator()(float dt) { return c->OnTick(dt); }
    ~PumpFunctor() { if (c) c->OnFunctorDestroyed(); }
  };

  CarrierBindings b_;
  PumpFn pump_ = nullptr;
  void* pump_ctx_ = nullptr;
  std::atomic<bool> stop_{false};
  std::atomic<bool> arm_{false};
  std::atomic<bool> torn_down_{false};
  std::atomic<bool> running_{false};
  bool activated_ = false;
  std::mutex m_;
  std::condition_variable cv_;
};

}  // namespace

IGameThreadCarrier* CreateUE54TickerCarrier(const CarrierBindings& b) { return new UE54Carrier(b); }
void DestroyCarrier(IGameThreadCarrier* c) { delete c; }

}  // namespace Internal
}  // namespace Misery
