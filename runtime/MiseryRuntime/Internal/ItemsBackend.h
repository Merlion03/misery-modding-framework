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
#include "ContentGeneration.h"

namespace misery {
namespace items {

// Returned to the bridge, which turns them into a structured error for the mod.
// Distinct from the CR-01C5 path's own step codes, which start at 1 and mean
// "the registration itself went wrong"; these mean it never started.
constexpr int kItemsNoContent = 100;          // no live generation to register into
constexpr int kItemsBackendUnavailable = 101; // the path could not be brought up
constexpr int kItemsAlreadyDeclared = 102;    // this mod already declared that row
constexpr int kItemsNotDeclared = 103;        // nothing to withdraw
constexpr int kItemsNotOwned = 104;           // another mod's row
constexpr int kItemsNotLive = 105;            // declared, not in this world

using LogFn = void (*)(const char* line);

// Install as the bridge's items backend. Takes the profile by value: the
// backend outlives any particular resolution and must not depend on the
// caller's copy staying alive.
void Install(const bindings::Profile& profile, uint64_t module_base,
             uint64_t guobjectarray, LogFn log);

// Apply every declaration that is not already live in *snapshot*.
//
// Called by the runtime each time a generation is published. This is what makes
// a mod's item survive a level transition: the rows died with the previous
// world, and this puts them into the new one without the mod being told
// anything happened. Does nothing for a generation that cannot hold items --
// see CanHostItems in the .cpp.
//
// Must be called on the game thread: it writes DataTable rows.
void OnGenerationPublished(const content::Snapshot& snapshot);

// How many declarations exist, and how many are live in *generation*. Reported
// so a run can show re-application happening rather than infer it.
unsigned DeclaredCount();
unsigned LiveCount(uint64_t generation);

// Which content generation the backend is currently bound to, or 0 if none.
// Reported so a run can show the binding FOLLOWED a revocation rather than
// surviving one.
uint64_t BoundGeneration();

}  // namespace items
}  // namespace misery
