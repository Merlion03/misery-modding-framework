// ContentGeneration.h -- content anchors, and the only way to use them.
//
// THE PROBLEM THIS EXISTS FOR
// ---------------------------
// Measured on this build: the item tables, the game's own Blueprint classes,
// their CDOs and the UFunctions on them are DESTROYED AND RECREATED when the
// world is replaced. A content pointer resolved before a load is dangling after
// it. Until now nothing consumed those pointers, so that was a note in a
// document; the Items backend is the first consumer, and a note is not a
// mechanism.
//
// WHY THIS DOES NOT TRY TO DETECT A LOAD
// --------------------------------------
// "Notice LoadMap and invalidate" is the obvious design and it is the weaker
// one. It needs a hook this project will not take, it is one signal that can be
// missed, and missing it once is silent corruption -- the consumer gets a
// pointer that looks fine. Worse, detection is a race by construction: the load
// begins, and between the signal and the invalidation there is a window.
//
// The property that actually matters is not "we noticed the load". It is that
// NO CONSUMER CAN USE ANCHORS FROM A REVOKED GENERATION. So the check moved to
// the point of use. Anchors are not reachable except through Acquire, and
// Acquire re-validates every one of them against the engine's own slot
// bookkeeping before handing anything over. A generation whose objects have
// been destroyed cannot be acquired, whether or not anybody noticed the load
// that destroyed them.
//
// That is cheap enough to do every time: a handful of reads per anchor, the
// same InternalIndex / Object / SerialNumber / garbage-flag check that
// tests/test_slot_validation.py proves refuses every dead state. It is not a
// walk.
//
// THE STATES, AND WHO MOVES BETWEEN THEM
// --------------------------------------
//   (none)      -- nothing resolved yet; Acquire fails, consumers defer
//   published   -- a generation is current and every anchor validated when
//                  it was published
//   revoked     -- an Acquire found a dead anchor, or the runtime revoked it
//                  deliberately. Acquire fails with the reason. The runtime
//                  re-resolves and publishes the next generation.
//
// A consumer never sees the transition, only a refusal, which is the point: it
// cannot be holding a stale pointer because it was never given one.
#pragma once

#include <stdint.h>

#include <string>

#include "Resolver.h"

namespace misery {
namespace content {

// One generation's worth of content, handed out only by Acquire.
struct Snapshot {
  uint64_t generation = 0;
  resolve::Anchors anchors;
};

// Make a freshly resolved set current. *objects_ptr* is the chunk table the walk
// was built against, kept so later validation needs no Universe. Returns the new
// generation id, which is monotonic and never reused.
uint64_t Publish(uint64_t objects_ptr, const resolve::Layout& layout,
                 const resolve::Anchors& anchors);

// THE ONLY WAY TO READ CONTENT ANCHORS.
//
// Re-validates every identity in the current generation before copying anything
// out. On any failure the generation is revoked, *why* says which anchor and how
// it died, and false is returned -- the caller gets nothing, not a partial set.
//
// Must be called on the game thread: it reads the object graph.
bool Acquire(Snapshot* out, std::string* why);

// Revoke deliberately, e.g. because the runtime is about to re-resolve. Safe to
// call when nothing is published.
void Revoke(const char* why);

uint64_t CurrentGeneration();
bool IsPublished();
const char* LastRevokeReason();

// How many times a generation has been revoked, and how many published. Kept so
// a run can show the lifecycle actually cycled rather than merely not crashing.
uint32_t PublishCount();
uint32_t RevokeCount();

}  // namespace content
}  // namespace misery
