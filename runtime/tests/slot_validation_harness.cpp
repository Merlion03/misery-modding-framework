// slot_validation_harness.cpp -- prove every liveness refusal, deterministically.
//
// WHY THIS EXISTS INSTEAD OF MORE TIMING ATTEMPTS
// ----------------------------------------------
// The post-walk liveness check refuses to publish an anchor whose slot no longer
// vouches for it. Provoking that on a live game means catching a destruction
// inside the seconds-long window of one resolution, and three runs of
// back-to-back resolutions across real menu -> gameplay transitions -- 253
// attempts, validation confirmed executing on all of them -- never hit it. The
// transition destroys the old generation and creates the new one with a gap
// between, so resolutions land on "absent", not on "stale".
//
// Absence of a hit is not evidence the refusal works. So the refusal is proven
// here instead, on an object array this harness builds and owns, where every
// FUObjectItem field can be set to exactly the state under test.
//
// WHAT IS REAL AND WHAT IS SYNTHETIC
// ----------------------------------
// The CODE under test is the real one: misery::resolve::Universe, unmodified,
// the same translation unit the game loads. Only the object graph is synthetic
// -- a chunk table, FUObjectItems and UObjects laid out at the offsets the
// binding profile records, so Universe cannot tell it from a process image.
//
// That is the honest boundary: this proves the refusal LOGIC is correct and
// complete across every branch. It does not prove the timing window is
// reachable in a real game, and the evidence document says so.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <string>
#include <vector>

#include "../MiseryRuntime/Internal/Resolver.h"

namespace {

using misery::resolve::AnchorIdentity;
using misery::resolve::Layout;
using misery::resolve::Universe;

constexpr uint32_t kObjectCount = 2048;   // over StepBuild's 1000 floor
constexpr size_t kFakeObjectStride = 0x40;

// A whole fake process image: the array header, one chunk table, one chunk of
// FUObjectItems, and the UObjects they point at.
struct FakeGraph {
  std::vector<uint8_t> header;    // stands in for GUObjectArray
  std::vector<uint64_t> chunks;   // the chunk table
  std::vector<uint8_t> items;     // one chunk of FUObjectItem
  std::vector<uint8_t> objects;   // the UObjects themselves
  Layout layout;

  uint64_t HeaderAddress() { return reinterpret_cast<uint64_t>(header.data()); }
  uint64_t ItemAddress(uint32_t index) {
    return reinterpret_cast<uint64_t>(items.data()) +
           static_cast<uint64_t>(index) * layout.fuobjectitem_size;
  }
  uint64_t ObjectAddress(uint32_t index) {
    return reinterpret_cast<uint64_t>(objects.data()) +
           static_cast<uint64_t>(index) * kFakeObjectStride;
  }

  template <typename T>
  void PokeItem(uint32_t index, uint32_t offset, T value) {
    *reinterpret_cast<T*>(ItemAddress(index) + offset) = value;
  }
  template <typename T>
  void PokeObject(uint32_t index, uint32_t offset, T value) {
    *reinterpret_cast<T*>(ObjectAddress(index) + offset) = value;
  }

  void Build() {
    header.assign(0x40, 0);
    chunks.assign(4, 0);
    items.assign(static_cast<size_t>(kObjectCount) * layout.fuobjectitem_size, 0);
    objects.assign(static_cast<size_t>(kObjectCount) * kFakeObjectStride, 0);

    chunks[0] = reinterpret_cast<uint64_t>(items.data());
    *reinterpret_cast<uint64_t*>(header.data() + layout.guobjectarray_objects) =
        reinterpret_cast<uint64_t>(chunks.data());
    *reinterpret_cast<int32_t*>(header.data() +
                                layout.guobjectarray_num_elements) =
        static_cast<int32_t>(kObjectCount);

    for (uint32_t i = 0; i < kObjectCount; ++i) {
      const uint64_t object = ObjectAddress(i);
      PokeItem<uint64_t>(i, layout.fuobjectitem_object, object);
      PokeItem<int32_t>(i, layout.fuobjectitem_flags, 0);
      // A distinct serial per slot, so a mixed-up comparison cannot pass by
      // everything happening to be zero.
      PokeItem<int32_t>(i, layout.fuobjectitem_serial,
                        static_cast<int32_t>(1000 + i));
      PokeObject<int32_t>(i, layout.object_internal_index,
                          static_cast<int32_t>(i));
      PokeObject<int32_t>(i, layout.object_flags, 0);
      PokeObject<uint64_t>(i, layout.object_class_private, ObjectAddress(0));
    }
  }
};

int g_failures = 0;

void Expect(const char* what, Universe::Liveness got, Universe::Liveness want) {
  const bool ok = got == want;
  if (!ok) {
    ++g_failures;
  }
  printf("  [%s] %-46s got=%s\n", ok ? "PASS" : "FAIL", what,
         Universe::LivenessName(got));
}

}  // namespace

int main() {
  FakeGraph graph;
  graph.Build();

  Universe universe(graph.HeaderAddress(), 0 /* no name pool needed */,
                    graph.layout);
  misery::resolve::Failure failure;
  if (!universe.BeginBuild(&failure)) {
    printf("{\"ok\":false,\"error\":\"BeginBuild refused the synthetic graph: "
           "%s\"}\n", failure.what.c_str());
    return 2;
  }
  // One unbounded pass: this graph is tiny and the point is the validator, not
  // the slicing.
  if (universe.StepBuild(0xFFFFFFFFu, 0xFFFFFFFFu, &failure) !=
      Universe::Step::kDone) {
    printf("{\"ok\":false,\"error\":\"the synthetic walk did not complete\"}\n");
    return 3;
  }

  const uint32_t subject = 500;
  AnchorIdentity identity;
  identity.address = graph.ObjectAddress(subject);
  identity.name = "Subject";
  identity.class_name = "Class";
  identity.label = "the anchor under test";
  identity.internal_index = static_cast<int32_t>(subject);
  identity.serial_number = static_cast<int32_t>(1000 + subject);

  printf("liveness refusals, on a graph this harness owns:\n");
  Expect("an untouched anchor is alive", universe.CheckSlot(identity),
         Universe::Liveness::kAlive);

  // Each case mutates ONE field and puts it back, so no case can pass because a
  // previous one left the graph broken.
  {
    graph.PokeItem<uint64_t>(subject, graph.layout.fuobjectitem_object,
                             graph.ObjectAddress(subject + 1));
    Expect("slot now holds a different object -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kSlotRecycled);
    graph.PokeItem<uint64_t>(subject, graph.layout.fuobjectitem_object,
                             graph.ObjectAddress(subject));
  }
  {
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_serial, 999999);
    Expect("slot serial number changed -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kSerialChanged);
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_serial,
                            static_cast<int32_t>(1000 + subject));
  }
  {
    graph.PokeObject<int32_t>(subject, graph.layout.object_internal_index, 7);
    Expect("object no longer claims its slot -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kIndexChanged);
    graph.PokeObject<int32_t>(subject, graph.layout.object_internal_index,
                              static_cast<int32_t>(subject));
  }
  {
    graph.PokeObject<int32_t>(subject, graph.layout.object_internal_index, -1);
    Expect("a negative InternalIndex -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kIndexUnreadable);
    graph.PokeObject<int32_t>(subject, graph.layout.object_internal_index,
                              static_cast<int32_t>(subject));
  }
  {
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags,
                            misery::resolve::kInternalGarbage);
    Expect("FUObjectItem marked Garbage -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kGarbage);
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags, 0);
  }
  {
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags,
                            misery::resolve::kInternalUnreachable);
    Expect("FUObjectItem marked Unreachable -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kUnreachable);
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags, 0);
  }
  {
    graph.PokeObject<int32_t>(subject, graph.layout.object_flags,
                              misery::resolve::kObjectFlagsGarbage);
    Expect("UObject::ObjectFlags mirrored garbage -> refused",
           universe.CheckSlot(identity), Universe::Liveness::kGarbage);
    graph.PokeObject<int32_t>(subject, graph.layout.object_flags, 0);
  }

  // THE POINT OF THE WHOLE CHANGE, stated as its own case: an object that is
  // destroyed but whose bytes are untouched passes the semantic check and must
  // still be refused. This is the exact hole the live gate exposed.
  {
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags,
                            misery::resolve::kInternalGarbage);
    const bool bytes_still_look_right =
        universe.StillIs(identity.address, universe.NameOf(identity.address),
                         universe.ClassNameOf(identity.address));
    const Universe::Liveness liveness = universe.CheckSlot(identity);
    const bool ok = bytes_still_look_right &&
                    liveness == Universe::Liveness::kGarbage;
    if (!ok) {
      ++g_failures;
    }
    printf("  [%s] %-46s semantic=%s slot=%s\n", ok ? "PASS" : "FAIL",
           "destroyed-but-intact bytes: semantic passes, slot refuses",
           bytes_still_look_right ? "passes" : "refuses",
           Universe::LivenessName(liveness));
    graph.PokeItem<int32_t>(subject, graph.layout.fuobjectitem_flags, 0);
  }

  Expect("the graph was left as it started", universe.CheckSlot(identity),
         Universe::Liveness::kAlive);

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
