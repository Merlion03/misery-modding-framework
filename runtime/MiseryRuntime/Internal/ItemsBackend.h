// ItemsBackend.h -- the bridge's items backend, in production.
//
// Stage 5A installed a RECORDING backend off-game and the real CR-01C5 path
// in-game, and the difference between the harness and the live run was one
// function pointer. This is the production side of that pointer: it feeds the
// same proven path from the binding profile and the current content generation
// instead of from a Python controller.
//
// The invariant this file exists to hold: a registration is only possible
// against a LIVE content generation. Not "usually", not "unless a load is in
// flight" -- the anchors it writes through are obtained by content::Acquire on
// every call, so a revoked generation makes registration impossible rather than
// merely inadvisable.
#pragma once

#include <stdint.h>

#include "Bindings.h"

namespace misery {
namespace items {

// Returned to the bridge, which turns them into a structured error for the mod.
// Distinct from the CR-01C5 path's own step codes, which start at 1 and mean
// "the registration itself went wrong"; these mean it never started.
constexpr int kItemsNoContent = 100;          // no live generation to register into
constexpr int kItemsBackendUnavailable = 101; // the path could not be brought up

using LogFn = void (*)(const char* line);

// Install as the bridge's items backend. Takes the profile by value: the
// backend outlives any particular resolution and must not depend on the
// caller's copy staying alive.
void Install(const bindings::Profile& profile, uint64_t module_base,
             uint64_t guobjectarray, LogFn log);

// Which content generation the backend is currently bound to, or 0 if none.
// Reported so a run can show the binding FOLLOWED a revocation rather than
// surviving one.
uint64_t BoundGeneration();

}  // namespace items
}  // namespace misery
