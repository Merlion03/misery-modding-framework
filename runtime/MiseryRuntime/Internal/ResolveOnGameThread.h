// ResolveOnGameThread.h -- object resolution runs on the game thread. Only.
//
// WHY THE INVOCATION MODEL CHANGED
// --------------------------------
// The resolver walks the whole UObject array and dereferences pointers it reads
// out of it. Doing that from an arbitrary thread means racing the engine: while
// the walk is in flight, the game thread may be destroying the very objects
// being read. Every read is validated against its page first, but validation and
// dereference cannot be one atomic step, so the model is unsafe BY
// CONSTRUCTION during object churn -- independently of whether that race has
// ever been observed to bite.
//
// WHAT IS AND IS NOT ESTABLISHED HERE
// -----------------------------------
// A game process did die during a level load while the resolver was being polled
// from a remote thread, and no crash dump or Application-log entry was produced.
// That is recorded as an observation. It is NOT recorded as a cause: the
// mechanism was never reproduced or independently established, and the off-thread
// walk is a suspect, not a finding. This file exists because the invocation model
// is wrong on its own terms, not because the crash was explained.
//
// WHAT REPLACES IT
// ----------------
// The already-proven game-thread carrier: a per-frame pump reached through
// FTSTicker, gated on the build's own signature bytes, behind the same
// dispatcher Stage 5A used to start CoreCLR on the game thread. Resolution
// becomes a job on that queue. The engine is not concurrently tearing down
// objects while our code holds the game thread, so the race is removed rather
// than narrowed.
//
// BOUNDED, BECAUSE THE GAME THREAD IS NOT OURS TO SPEND
// -----------------------------------------------------
// A full walk on the game thread is a frame cost, so it is measured rather than
// assumed: every resolution reports how long it took and how many VirtualQuery
// syscalls it issued. If that cost is too high the answer is to chunk or budget
// the walk across ticks -- never to move the traversal back onto an arbitrary
// thread, which would trade a measurable frame cost for an unbounded safety one.
#pragma once

#include <stdint.h>

#include <string>

#include "Resolver.h"

namespace misery {
namespace gamethread {

// Build-specific carrier addresses, with the bytes each must hold. These come
// from the binding profile: the carrier refuses to activate on any mismatch, so
// an unsupported build never gets a pump registered.
struct CarrierInput {
  uint64_t add_ticker = 0;
  uint64_t get_core_ticker = 0;
  uint64_t fmemory_malloc = 0;
  uint8_t sig_add[16] = {};
  uint8_t sig_get[16] = {};
  uint8_t sig_malloc[16] = {};
};

// The per-slice budget, in microseconds of game thread per tick.
//
// CHOSEN FROM THE MEASUREMENT, NOT PICKED
// ---------------------------------------
// A complete resolution was measured on this build at both ends of the range:
//
//     main menu   26 263 objects   walk  20.4 ms + anchors  10.3 ms
//     gameplay   194 701 objects   walk 265.5 ms + anchors 215.7 ms  = 481 ms
//
// 481 ms is roughly 29 frames at 60 fps, so the whole-walk form cannot run on
// the game thread in gameplay at all.
//
// WHAT THE CHUNKED FORM THEN MEASURED, same build, same save
// ----------------------------------------------------------
//                        menu (26k objects)   gameplay (196k objects)
//   slices                     26                    173
//   longest slice            3.6 ms                 6.0 ms
//   walk, summed            50.3 ms                349.9 ms
//   anchor resolution        0.7 ms                  2.0 ms
//   live re-validation       0.1 ms                  0.1 ms
//
// THE TRADE, STATED
// -----------------
//   frame time: a bounded slice instead of one 481 ms stall. The budget is 2 ms;
//               the observed maximum is higher because a slice may finish an
//               object past the deadline, and because two steps are inherently
//               whole -- see below.
//   latency:    ~175 ticks for a gameplay resolution, so ~3 s at 60 fps, and
//               ~0.5 s at menu object counts.
//   total CPU:  HIGHER, not lower -- 350 ms of walk against 265 ms unchunked.
//               Indexing objects by name and by class during the walk is what
//               costs that, and it is what removed a 215.7 ms anchor step that
//               no amount of slicing could have hidden. Total CPU is not the
//               property being bought; a frame nobody notices is.
//
// Latency is the right thing to spend. Resolution happens at startup and after a
// load, not per frame, and nothing waits on it interactively: a 29-frame stall is
// a defect a player sees, three seconds of background work before mods finish
// initialising is not.
//
// TWO STEPS ARE NOT SLICED, DELIBERATELY
// --------------------------------------
// The live re-validation of selected anchors, and the anchor resolution that
// precedes it, each run whole -- but each in a slice of its OWN, never sharing a
// tick with the walk. Validation cannot be split without reintroducing the
// staleness it exists to detect. Anchor resolution could be, and does not need
// to be: it is 2 ms once indexed. Sharing a tick was measured at 14.1 ms, which
// is exactly the hitch being avoided, so they were separated.
constexpr uint32_t kSliceBudgetUs = 2000;

// A backstop, not the governor. The time budget normally decides; this only
// matters if the performance counter misbehaves, and it must not let one slice
// become the whole walk.
constexpr uint32_t kSliceMaxObjects = 8192;

// How many times a resolution may restart before giving up. Restarts happen when
// the object graph moved under the walk, which during a level load is normal --
// but a process that never holds still long enough must fail with a reason
// rather than retry forever.
constexpr uint32_t kMaxRestarts = 4;

// What one resolution cost, and how it was spread.
struct Cost {
  uint32_t queued_us = 0;    // enqueue -> first slice: how long the frame took
  uint32_t build_us = 0;     // the object walk, summed across slices
  uint32_t resolve_us = 0;   // anchor resolution
  uint32_t validate_us = 0;  // the final live re-check of selected anchors
  uint32_t objects = 0;      // objects in the universe at publish
  uint32_t reads = 0;
  uint32_t vqueries = 0;     // VirtualQuery syscalls actually issued
  uint32_t cache_hits = 0;

  // The property that matters: not that the work finished, but that no single
  // game-thread slice was long enough to be seen as a hitch.
  uint32_t slices = 0;
  uint32_t max_slice_us = 0;
  // WHICH slice was the longest, 0-based. Added because explaining a 6ms slice
  // by reasoning had already gone wrong twice in this file, and a number settles
  // what an argument does not.
  //
  // It earned that immediately: it showed the spike sitting in the MIDDLE of the
  // walk, which pointed at by_name_/by_class_ rehashing rather than at anything
  // in the slice machinery, and reserving those maps took the menu's longest
  // slice from 3.6ms to 2.0ms -- the budget itself.
  //
  // What remains longest at gameplay counts is slice 0, where BeginBuild sizes
  // the maps for the whole process (~219k buckets x2, plus the class index):
  // 5.4ms of allocation and zeroing. That is the design's one-off setup cost
  // rather than a spike, it happens once per resolution, and it is why slice 0
  // does nothing else.
  uint32_t max_slice_index = 0;
  uint32_t objects_processed = 0;   // slots examined, restarts included
  uint32_t restarts = 0;           // graph moved under the walk
  uint32_t revalidation_failures = 0;

  // Phase at request vs at completion. A resolution that started before content
  // existed and finished after is not a resolution of either state, so these
  // two disagreeing is a reason to refuse rather than publish.
  uint32_t requested_phase = 0;
  uint32_t completed_phase = 0;

  // The thread the walk actually ran on. Reported because "resolution moved to
  // the game thread" is a claim, and a claim about which thread ran the code is
  // only checkable if the code says which thread ran it. Identical across every
  // resolution in a process means the work really is serialised onto one
  // engine-owned thread rather than onto whichever caller asked.
  uint32_t thread_id = 0;
};

// Activate the carrier and dispatcher, once per process. Idempotent: a second
// call with the same bindings is a no-op returning true. Fails CLOSED -- on any
// signature mismatch nothing is bound and false is returned with a reason.
bool Ensure(const CarrierInput& carrier, std::string* error);

bool IsReady();

// Resolve on the game thread and wait for the answer.
//
// Callable from any thread EXCEPT the game thread (it would deadlock waiting for
// a pump it is itself blocking). Returns false if the carrier is not ready, if
// the job was not drained within *timeout_ms*, or if resolution itself failed --
// the three are distinguished in *error*.
bool Resolve(uint64_t guobjectarray, uint64_t namepool,
             const resolve::Request& request, resolve::Anchors* out,
             resolve::Failure* failure, uint32_t timeout_ms, Cost* cost,
             std::string* error);

// Stop the pump and wait until no carrier resource can re-enter this module.
// Must complete before the module is unloaded.
void Teardown(uint32_t timeout_ms);

}  // namespace gamethread
}  // namespace misery
