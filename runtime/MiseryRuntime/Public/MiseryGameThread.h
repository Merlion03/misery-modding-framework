// MiseryRuntime -- PUBLIC API (mod-facing).
//
// This is the ONLY surface a mod should touch to run work on the Unreal game
// thread. It deliberately exposes NO engine internals: no FTSTicker, no engine
// RVAs, no FMemory, no UObject pointers, no UE types at all. The carrier that
// actually reaches the game thread (currently an FTSTicker binding for one
// specific build) is an implementation detail behind this boundary, so a future
// carrier swap changes nothing here.
//
// Contract at this stage: POD jobs only. A job is a plain C function pointer plus
// an opaque context pointer the caller owns. No gameplay/UObject operations are
// performed by the runtime itself -- that is a separate, later gate.
#ifndef MISERY_GAMETHREAD_H
#define MISERY_GAMETHREAD_H

#include <cstdint>

namespace Misery {
namespace GameThread {

// A unit of work. `fn(ctx)` is invoked exactly once, on the game thread, during a
// later drain. `ctx` lifetime is the caller's responsibility (must outlive the
// job's execution). Keep the body POD/allocation-light: it runs inside the game
// thread's per-frame pump.
using JobFn = void (*)(void* ctx);

// True once the runtime is initialized AND its carrier activated for this build.
// On an unknown/unsupported build the carrier fails closed: this returns false,
// Enqueue rejects, and the game runs vanilla.
bool IsAvailable();

// Queue one job. Thread-safe; callable from any thread (worker/mod threads).
// Returns false if the runtime is not accepting work (not initialized, shutting
// down, or carrier inactive). Never blocks on the game thread.
bool Enqueue(JobFn fn, void* ctx);

}  // namespace GameThread
}  // namespace Misery

#endif  // MISERY_GAMETHREAD_H
