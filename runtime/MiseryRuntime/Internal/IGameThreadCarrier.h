// MiseryRuntime -- INTERNAL. Carrier abstraction.
//
// A "carrier" is whatever actually gets a per-frame callback onto the Unreal
// game thread. The dispatcher (queue + lifecycle) is written entirely against
// this interface and knows nothing about FTSTicker, engine addresses, or UE
// types -- so the build-specific binding lives in exactly one place
// (UE54TickerCarrier) and can be swapped without touching the dispatcher or the
// public API.
#ifndef MISERY_IGAMETHREADCARRIER_H
#define MISERY_IGAMETHREADCARRIER_H

#include <cstdint>

namespace Misery {
namespace Internal {

// The pump the dispatcher hands the carrier. Invoked on the game thread once per
// frame while the carrier is running. Returns true to keep running, false to
// stop (the dispatcher only returns false as part of Stop()).
using PumpFn = bool (*)(void* ctx, float delta_seconds);

class IGameThreadCarrier {
 public:
  virtual ~IGameThreadCarrier() = default;

  // Verify this carrier is valid for the running build (fingerprint / signature
  // gate). MUST fail closed: on any mismatch return false and bind nothing, so
  // the game keeps running vanilla. No effect on success beyond readiness.
  virtual bool Activate() = 0;

  // Register ONE persistent per-frame pump on the game thread. `pump(ctx, dt)` is
  // called every frame until Stop(). Returns false if not activated or if
  // registration failed. Exactly one pump per carrier.
  virtual bool Start(PumpFn pump, void* ctx) = 0;

  // Ask the pump to stop. After this, the pump returns false on its next game
  // thread invocation and the carrier tears its registration down. Idempotent.
  virtual void Stop() = 0;

  // Block until the pump is fully torn down AND any carrier resource that holds
  // this module's code (e.g. the ticker element wrapping our callback) has been
  // destroyed on the game thread -- i.e. no carrier code can re-enter this module
  // afterwards. This is the unload-safety handshake; returns false on timeout.
  virtual bool WaitFullyStopped(uint32_t timeout_ms) = 0;

  // True between a successful Start() and the pump's confirmed teardown.
  virtual bool IsRunning() const = 0;
};

}  // namespace Internal
}  // namespace Misery

#endif  // MISERY_IGAMETHREADCARRIER_H
