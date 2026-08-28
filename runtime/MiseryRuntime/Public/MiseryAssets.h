// MiseryRuntime -- PUBLIC API (mod-facing) for asset ownership.
//
// A mod says "the runtime owns this asset while my registration is active" and
// nothing more. It never sees AddToRoot, FGCObject, GC flags, GUObjectArray, or
// any raw UObject lifetime internal -- those live behind Internal/RuntimeAssetStore.
// Swapping the underlying GC-integration strategy must not change this header.
//
// Handles are opaque and runtime-assigned; a mod holds a handle, not a pointer.
#ifndef MISERY_ASSETS_H
#define MISERY_ASSETS_H

#include <cstdint>

namespace Misery {
namespace Assets {

// Opaque ownership handle. 0 == invalid.
using Handle = uint64_t;

// Take runtime ownership of an already-loaded asset, keeping it alive until
// Release. Acquiring the same asset twice returns the SAME handle and refcounts
// (see RuntimeAssetStore for the exact semantics). Returns 0 on failure.
Handle Acquire(const void* asset);

// Drop one ownership reference. Returns true if the handle was known and the
// reference was dropped. Releasing an unknown/stale handle is a no-op returning
// false -- never a crash.
bool Release(Handle handle);

// How many assets the runtime currently owns.
uint32_t OwnedCount();

}  // namespace Assets
}  // namespace Misery

#endif  // MISERY_ASSETS_H
