// arena_harness.cpp -- the reply arena must refuse, not invent.
//
// The arena backs every out-string the bridge returns. Its previous Put()
// returned the literal "<detail too long>" when a value did not fit and had no
// way to say so, and every caller was a SUCCESS path -- so an oversized reply
// became a call that returned MB_STATUS_OK carrying seventeen bytes that were
// not the document its signature promised.
//
// These cases pin the replacement: refusal is visible, refusal consumes
// nothing, and the boundary is exactly where the capacity says it is.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "../MiseryRuntime/Public/MiseryBridge.h"
#include "../MiseryRuntime/Internal/BridgeCore.h"

namespace {

int g_failures = 0;

void Check(const char* what, bool ok) {
  if (!ok) ++g_failures;
  printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
}

}  // namespace

int main() {
  using misery::bridge::StringArena;
  printf("the reply arena:\n");

  {
    StringArena arena;
    MbStr out{nullptr, 0};
    Check("a small value is placed", arena.TryPut("hello", &out));
    Check("and reads back intact",
          out.length == 5 && memcmp(out.data, "hello", 5) == 0);
  }
  {
    // Capacity is private, so the boundary is found rather than assumed: grow
    // until it refuses. A harness that hardcoded 64K would keep passing if the
    // capacity changed underneath it.
    StringArena arena;
    MbStr out{nullptr, 0};
    size_t placed = 0;
    while (arena.TryPut(std::string(1024, 'x'), &out)) {
      ++placed;
      if (placed > 1024) break;      // never loops forever
    }
    Check("it eventually refuses rather than overrunning", placed <= 1024);
    Check("something was placed before it refused", placed > 0);

    // THE POINT: a refusal must leave room for the short error detail that
    // reports it. Nothing may be consumed by a failed attempt.
    MbStr detail{nullptr, 0};
    Check("a short detail still fits after a refusal",
          arena.TryPut("refused", &detail));
  }
  {
    StringArena arena;
    MbStr out{nullptr, 0};
    const std::string huge(128 * 1024, 'y');
    Check("an oversized value is refused outright", !arena.TryPut(huge, &out));
    Check("and the out-parameter is left untouched", out.data == nullptr);
  }
  {
    // PutOrSentinel exists for Fail() alone, which cannot report its own
    // failure. It must still behave for values that fit.
    StringArena arena;
    const MbStr ok = arena.PutOrSentinel("fits");
    Check("PutOrSentinel places a value that fits",
          ok.length == 4 && memcmp(ok.data, "fits", 4) == 0);
    const MbStr over = arena.PutOrSentinel(std::string(128 * 1024, 'z'));
    Check("and degrades visibly when it cannot",
          over.length == 17 && memcmp(over.data, "<detail too long>", 17) == 0);
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
