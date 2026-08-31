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

// What one resolution cost. The reason the walk can stay whole: if these numbers
// say otherwise, the walk gets chunked.
struct Cost {
  uint32_t queued_us = 0;    // enqueue -> job start: how long the frame took to come
  uint32_t build_us = 0;     // the object walk
  uint32_t resolve_us = 0;   // anchor resolution on top of the walk
  uint32_t objects = 0;
  uint32_t reads = 0;
  uint32_t vqueries = 0;     // VirtualQuery syscalls actually issued
  uint32_t cache_hits = 0;
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
