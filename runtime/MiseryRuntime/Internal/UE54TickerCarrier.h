// MiseryRuntime -- INTERNAL. Build-specific carrier bindings (UE-free header).
//
// This is the ONLY build-coupled surface. The addresses and their expected first
// bytes are supplied per run by the controller after a whole-image fingerprint
// check; the carrier re-verifies the bytes live before activating and fails
// CLOSED (Activate() returns false, nothing bound, game runs vanilla) on any
// mismatch or unknown build. No RVA is ever treated as an unconditional constant.
#ifndef MISERY_UE54TICKERCARRIER_H
#define MISERY_UE54TICKERCARRIER_H

#include <cstdint>

#include "IGameThreadCarrier.h"

namespace Misery {
namespace Internal {

// Everything build-specific lives here, kept apart from the stable dispatcher /
// public API so a future carrier (or build) changes only this struct + the .cpp.
struct CarrierBindings {
  uint64_t add_ticker = 0;        // FTSTicker::AddTicker(name,delay,TFunction) VA
  uint64_t get_core_ticker = 0;   // FTSTicker::GetCoreTicker VA
  uint64_t fmemory_malloc = 0;    // FMemory::Malloc VA (forward target)
  uint8_t sig_add[16] = {};       // expected first 16 bytes at each VA
  uint8_t sig_get[16] = {};
  uint8_t sig_malloc[16] = {};
};

// Factory: returns a heap-allocated carrier the caller owns (DestroyCarrier).
IGameThreadCarrier* CreateUE54TickerCarrier(const CarrierBindings& bindings);
void DestroyCarrier(IGameThreadCarrier* carrier);

}  // namespace Internal
}  // namespace Misery

#endif  // MISERY_UE54TICKERCARRIER_H
