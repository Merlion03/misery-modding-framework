// bridge_core_test.cpp -- the native ownership model, tested off the game.
//
// tools/modplatform proved these semantics in Python and 62 unit tests hold it
// there. This asserts the C++ implementation behind MiseryBridge.h agrees, on
// the cases that decide the lifecycle guarantee -- before any of it is loaded
// into MISERY, and before CoreCLR is involved at all.
//
// Two implementations of one model is a drift risk, and this repository has
// paid for drift twice already. The mitigation is that the cases are named the
// same on both sides, so a divergence shows up as one suite failing and the
// other passing rather than as a mod behaving oddly in a player's game.
//
// Build and run:
//   cl /nologo /EHsc /std:c++17 bridge_core_test.cpp /Fe:bridge_core_test.exe
#include "../MiseryRuntime/Internal/BridgeCore.h"

#include <stdio.h>

#include <string>
#include <vector>

using misery::bridge::Core;
using misery::bridge::ModRecord;
using misery::bridge::Slot;

static int g_failures = 0;
static int g_checks = 0;

static void Check(bool ok, const char* label) {
  g_checks += 1;
  if (!ok) {
    g_failures += 1;
    printf("  [FAIL] %s\n", label);
  } else {
    printf("  [PASS] %s\n", label);
  }
}

// A release function that records that it ran, so "released" is observed rather
// than assumed.
static std::vector<std::string>* g_released = nullptr;

static void RecordRelease(void* body, uint64_t payload) {
  (void)payload;
  if (g_released != nullptr && body != nullptr) {
    g_released->push_back(*static_cast<std::string*>(body));
  }
}

static void ThrowingRelease(void* body, uint64_t payload) {
  (void)body;
  (void)payload;
  throw std::string("this resource refuses to release");
}

int main() {
  printf("\n=== native ownership model ===\n");

  {
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    std::vector<std::string> released;
    g_released = &released;

    std::string a = "first", b = "second", c = "third";
    core.Acquire(mod, misery::bridge::kKindSubscription, "first",
                 RecordRelease, &a, 0);
    core.Acquire(mod, misery::bridge::kKindInputAction, "second",
                 RecordRelease, &b, 0);
    core.Acquire(mod, misery::bridge::kKindService, "third",
                 RecordRelease, &c, 0);

    Check(mod.owned_count == 3, "three resources are owned");
    Core::TeardownReport report = core.Dispose(mod);
    Check(report.released == 3, "teardown released all three");
    Check(released.size() == 3 && released[0] == "third" &&
              released[1] == "second" && released[2] == "first",
          "resources released in REVERSE acquisition order");
    Check(mod.owned_count == 0, "nothing is owned after teardown");
    g_released = nullptr;
  }

  {
    // The case the whole design exists for: a handle captured while the mod was
    // live must fail to resolve the instant the mod is unloaded, with no scan
    // and no window.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    std::string key = "handler";
    MbHandle captured = core.Acquire(mod, misery::bridge::kKindSubscription,
                                     "handler", nullptr, &key, 0);
    Check(core.Resolve(captured, misery::bridge::kKindSubscription) != nullptr,
          "a live handle resolves");
    core.Dispose(mod);
    Check(core.Resolve(captured, misery::bridge::kKindSubscription) == nullptr,
          "a handle captured BEFORE the unload no longer resolves");
  }

  {
    // Revocation is retroactive across a whole captured list, which is what a
    // dispatch loop holds.
    Core core;
    ModRecord& alpha = core.EnsureMod("alphamod");
    ModRecord& beta = core.EnsureMod("betamod");
    std::vector<MbHandle> captured;
    for (int i = 0; i < 5; ++i) {
      captured.push_back(core.Acquire(alpha, misery::bridge::kKindSubscription,
                                      "a" + std::to_string(i), nullptr,
                                      nullptr, 0));
    }
    MbHandle survivor = core.Acquire(beta, misery::bridge::kKindSubscription,
                                     "b", nullptr, nullptr, 0);
    core.Dispose(alpha);
    int still_live = 0;
    for (MbHandle handle : captured) {
      if (core.Resolve(handle, misery::bridge::kKindSubscription) != nullptr) {
        still_live += 1;
      }
    }
    Check(still_live == 0, "every captured handle of the unloaded mod is dead");
    Check(core.Resolve(survivor, misery::bridge::kKindSubscription) != nullptr,
          "the other mod's handle is untouched");
  }

  {
    // A resource that will not release must not strand the rest, and the mod
    // must end up in a state that says so -- LEAKED, which is what tells a
    // managed host not to collect the context.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    std::vector<std::string> released;
    g_released = &released;
    std::string ok1 = "ok1", ok2 = "ok2";
    core.Acquire(mod, misery::bridge::kKindSubscription, "ok1", RecordRelease,
                 &ok1, 0);
    core.Acquire(mod, misery::bridge::kKindService, "bad", ThrowingRelease,
                 nullptr, 0);
    core.Acquire(mod, misery::bridge::kKindItem, "ok2", RecordRelease, &ok2, 0);
    Core::TeardownReport report = core.Dispose(mod);
    Check(report.faults == 1, "the faulting release is counted");
    Check(released.size() == 2, "the other two still released");
    Check(mod.state == MB_MODSTATE_LEAKED,
          "a mod with an unreleasable resource is LEAKED, not UNLOADED");
    std::string reason;
    Check(!core.IsReclaimable(mod, &reason),
          "a LEAKED mod is not reclaimable");
    g_released = nullptr;
  }

  {
    // Reload: the same slot, a new epoch. Identity is stable for diagnostics
    // while every old handle stays dead.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    uint32_t slot_before = mod.slot;
    MbHandle old_handle = core.Acquire(mod, misery::bridge::kKindSubscription,
                                       "h", nullptr, nullptr, 0);
    MbHandle old_mod_handle = core.ModHandle(mod);
    core.Dispose(mod);

    ModRecord& again = core.EnsureMod("alphamod");
    again.state = MB_MODSTATE_LOADED;
    MbHandle new_mod_handle = core.ModHandle(again);
    MbHandle new_handle = core.Acquire(again, misery::bridge::kKindSubscription,
                                       "h", nullptr, nullptr, 0);

    Check(again.slot == slot_before, "a reloaded mod keeps its slot");
    Check(old_mod_handle != new_mod_handle,
          "but its handle differs, because the epoch moved");
    Check(core.ResolveMod(old_mod_handle) == nullptr,
          "the pre-unload mod handle is dead");
    Check(core.ResolveMod(new_mod_handle) != nullptr,
          "the post-reload mod handle is live");
    Check(core.Resolve(old_handle, misery::bridge::kKindSubscription) == nullptr,
          "a resource handle from the previous life stays dead");
    Check(core.Resolve(new_handle, misery::bridge::kKindSubscription) != nullptr,
          "the new life's resource handle works");
  }

  {
    // Many cycles must not grow the slot table without bound: a leak here would
    // be a leak in a player's multi-hour session.
    Core core;
    size_t capacity_after_first = 0;
    for (int cycle = 0; cycle < 200; ++cycle) {
      ModRecord& mod = core.EnsureMod("alphamod");
      mod.state = MB_MODSTATE_LOADED;
      for (int i = 0; i < 8; ++i) {
        core.Acquire(mod, misery::bridge::kKindSubscription,
                     "s" + std::to_string(i), nullptr, nullptr, 0);
      }
      core.Dispose(mod);
      if (cycle == 0) {
        capacity_after_first = core.SlotCapacity();
      }
    }
    Check(core.LiveSlotCount() == 0, "no slot is live after 200 cycles");
    Check(core.SlotCapacity() == capacity_after_first,
          "the slot table did not grow across 200 cycles -- slots are reused");
    Check(core.ModCount() == 1,
          "a reloaded mod does not accumulate mod records");
  }

  {
    // Reclaimability, which is the predicate a managed host gates on.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    mod.state = MB_MODSTATE_LOADED;
    core.Acquire(mod, misery::bridge::kKindSubscription, "h", nullptr,
                 nullptr, 0);
    std::string reason;
    Check(!core.IsReclaimable(mod, &reason), "a loaded mod is not reclaimable");
    core.Dispose(mod);
    Check(core.IsReclaimable(mod, &reason),
          "an unloaded mod with nothing owned is reclaimable");

    mod.state = MB_MODSTATE_UNLOADED;
    mod.active_frames = 1;
    Check(!core.IsReclaimable(mod, &reason),
          "a mod with a dispatch still on the stack is NOT reclaimable");
    mod.active_frames = 0;
  }

  {
    // Re-entrancy: disposing while disposing must be refused, not doubled.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    mod.state = MB_MODSTATE_UNLOADING;
    Core::TeardownReport report = core.Dispose(mod);
    Check(report.reentered, "a re-entered dispose is refused");
  }

  {
    // A handle of the wrong KIND must be refused before anything reads the slot
    // it names.
    Core core;
    ModRecord& mod = core.EnsureMod("alphamod");
    MbHandle handle = core.Acquire(mod, misery::bridge::kKindSubscription, "h",
                                   nullptr, nullptr, 0);
    Check(core.Resolve(handle, misery::bridge::kKindService) == nullptr,
          "a handle used as the wrong kind does not resolve");
    Check(core.Resolve(MB_INVALID_HANDLE, misery::bridge::kKindSubscription) ==
              nullptr,
          "the invalid handle never resolves");
    Check(core.Resolve(handle + 1, misery::bridge::kKindSubscription) == nullptr,
          "a fabricated handle does not resolve");
  }

  {
    // The frozen root must be the size both sides compiled against.
    Check(sizeof(MbRoot) == MB_ROOT_EXPECTED_SIZE,
          "sizeof(MbRoot) matches MB_ROOT_EXPECTED_SIZE");
    Check(sizeof(MbHandle) == 8, "a handle is 8 bytes");
  }

  printf("\n%d checks, %d failed\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
