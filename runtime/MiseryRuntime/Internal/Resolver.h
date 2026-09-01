// Resolver.h -- the per-run half of "what is in this process, right now".
//
// THE SPLIT THIS FILE EXISTS TO HONOUR
// ------------------------------------
//   build-specific MEASURED facts  ->  the binding profile (RVAs, property
//                                      offsets, vtable slot indices, expected
//                                      ParmsSize values)
//   per-run DYNAMIC facts          ->  here (object pointers, UFunction
//                                      addresses, vtables, live instances)
//
// Nothing in this file searches for a build it does not already have bindings
// for. It is handed a base address and a set of measured offsets and it finds
// the objects that exist only once the process is running. It is not a scanner,
// it has no signatures, and it will not guess: if the bindings do not describe
// this build, the bootstrap has already refused before anything here runs.
//
// AMBIGUITY IS A FAILURE, NEVER A CHOICE
// --------------------------------------
// Every lookup returns one of three answers, and the middle one is the only
// success:
//
//   zero matches      -> a defined failure, naming what was looked for
//   exactly one       -> accept
//   more than one     -> refuse, UNLESS a discriminator that has already been
//                        proven distinguishes them (the live player inventory
//                        is the only such case, and its discriminator is the
//                        class of its Outer)
//
// There is deliberately no "take the first" anywhere. First-match is how a
// resolver silently picks the CDO instead of the live instance, or one of two
// worlds, and then writes to it.
//
// THIS RUNS IN-PROCESS
// --------------------
// So a "read" is a dereference, not a ReadProcessMemory. That removes an entire
// class of failure the Python oracle had to handle, but adds a worse one: a
// wrong pointer is an access violation inside a shipping game rather than a
// failed read. Every dereference of a pointer that came from the game therefore
// goes through Read<T>, which validates the address is in a committed,
// readable page first. Slower, and worth it.
#pragma once

#include <stdint.h>
#include <windows.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace misery {
namespace resolve {

// ---- measured layout facts -------------------------------------------------
// These are the SAME constants the Python oracle uses, and a cross-check test
// compares the two resolvers' answers on one live process. They are compiled in
// rather than read from bindings because they are properties of UE 5.4's own
// type layout, not of MISERY's build -- the binding profile carries what is
// specific to the build.
struct Layout {
  // FChunkedFixedUObjectArray
  uint32_t guobjectarray_objects = 0x10;
  uint32_t guobjectarray_num_elements = 0x24;
  uint32_t fuobjectitem_size = 0x18;
  uint32_t fuobjectitem_object = 0x00;
  // FUObjectItem, UObjectArray.h:42-50: Object, Flags, ClusterRootIndex,
  // SerialNumber, in that order, 20 bytes padded to the 0x18 stride above.
  // Same offsets research/instruments/lifecycle/resolver.py already uses.
  uint32_t fuobjectitem_flags = 0x08;
  uint32_t fuobjectitem_serial = 0x10;

  // UObjectBase
  uint32_t object_class_private = 0x10;
  uint32_t object_name_private = 0x18;
  uint32_t object_outer_private = 0x20;
  uint32_t object_flags = 0x08;
  uint32_t object_internal_index = 0x0C;

  // UStruct
  uint32_t ustruct_super = 0x40;
  uint32_t ustruct_children = 0x48;
  uint32_t ustruct_properties_size = 0x58;
  uint32_t ufield_next = 0x28;

  // UFunction
  uint32_t ufunction_flags = 0xB0;
  uint32_t ufunction_parms_size = 0xB6;
  uint32_t ufunction_return_value_offset = 0xB8;
  uint32_t ufunction_event_graph = 0xC8;

  // FNamePool
  uint32_t namepool_blocks = 0x10;
  uint32_t fname_block_offset_bits = 16;
  uint32_t fname_entry_stride = 2;
  uint32_t fname_entry_header_size = 2;
  uint32_t fname_header_is_wide_mask = 0x1;
  uint32_t fname_header_len_shift = 6;
  uint32_t fname_header_len_mask = 0x3FF;

  // UDataTable
  uint32_t datatable_rowstruct = 40;
  uint32_t datatable_parent_tables = 176;
};

// Flags that mean an object is no longer a thing to hand anybody.
//
// Taken from what prior lifecycle work already established with citations, not
// from a fresh reading: EInternalObjectFlags in ObjectMacros.h:616 and :643 for
// the FUObjectItem flags, and the mirrored garbage bit in UObject::ObjectFlags
// at ObjectMacros.h:576.
//
// This matters because DESTRUCTION DOES NOT REMOVE THE SLOT. DestroyActor marks
// an object and its FUObjectItem survives until the next GC, so a walk that
// only asks "is there a pointer here" counts destroyed objects as live. That is
// documented in research/instruments/lifecycle/resolver.py as the defect that
// once made "exactly one live PlayerController" true of a graph holding two.
constexpr int32_t kInternalGarbage = 1 << 21;       // ObjectMacros.h:616
constexpr int32_t kInternalUnreachable = 1 << 28;   // ObjectMacros.h:643
constexpr int32_t kObjectFlagsGarbage = 0x40000000; // ObjectMacros.h:576

// One live object, as this resolver sees it.
struct ObjectInfo {
  uint64_t address = 0;
  uint64_t class_ptr = 0;
  uint64_t outer_ptr = 0;
  uint32_t name_id = 0;
  std::string name;      // empty when the name could not be decoded
  bool name_ok = false;
  // Slot identity, captured while the slot is under the cursor anyway. This is
  // what makes a later liveness check authoritative rather than a guess about
  // whether some bytes still look right.
  int32_t internal_index = -1;
  int32_t serial_number = 0;
};

// What went wrong, in words a log line can carry.
struct Failure {
  bool failed = false;
  std::string what;

  void Set(const std::string& text) {
    if (!failed) {
      failed = true;
      what = text;
    }
  }
};

// What one selected anchor must still be, checked two independent ways.
//
// Declared here rather than inside Anchors because Universe needs it: the
// liveness check lives with the object graph, and the anchor set lives with the
// result.
struct AnchorIdentity {
  uint64_t address = 0;
  std::string name;
  std::string class_name;
  std::string label;
  std::string check_outer_class;   // empty when the Outer is not part of it
  // The authoritative half. Name and class are what the object CLAIMS to be and
  // survive its destruction, because freed UObject memory keeps its bytes until
  // something reuses them. The slot is what the engine SAYS about it.
  int32_t internal_index = -1;
  int32_t serial_number = 0;
};

// Liveness, asked WITHOUT a Universe.
//
// A resolved generation outlives the walk that produced it -- that is the whole
// point of publishing one -- so the check that keeps it honest cannot depend on
// the Universe still existing. It needs only the chunk table the walk was built
// against and the measured layout, both of which are cheap to keep.
enum class Liveness {
  kAlive,
  kIndexUnreadable,
  kIndexChanged,      // the object no longer claims the slot it was found in
  kSlotRecycled,      // the slot holds a different object now
  kSerialChanged,     // same address, different generation of the slot
  kGarbage,           // marked destroyed; the slot outlives it until GC
  kUnreachable,
};

const char* LivenessName(Liveness state);

Liveness CheckSlotIdentity(uint64_t objects_ptr, const Layout& layout,
                           const AnchorIdentity& identity);

class Universe {
 public:
  Universe(uint64_t guobjectarray, uint64_t namepool, const Layout& layout)
      : guobjectarray_(guobjectarray), namepool_(namepool), layout_(layout) {}

  // Walk every allocated slot once and decode every name. One pass, because the
  // array is large and the alternative is re-walking it per lookup.
  //
  // This is the WHOLE walk in one call, and on the game thread that is a frame
  // hitch proportional to the object count. Kept for callers that are not on a
  // frame budget (the off-game harness); the game-thread path uses the chunked
  // form below.
  bool Build(Failure* failure);

  // ---- the chunked walk -------------------------------------------------
  //
  // WHY THE WALK IS SPLIT AT ALL
  // ----------------------------
  // Measured on this build, a complete walk costs tens of milliseconds -- more
  // than a frame. Resolution has to happen on the game thread (see
  // ResolveOnGameThread.h), so the only remaining way to keep it off the frame
  // budget is to do it a slice at a time.
  //
  // WHAT SPLITTING COSTS, AND WHAT PAYS FOR IT
  // ------------------------------------------
  // A walk spread over many ticks is a walk during which the object graph
  // changes. An object seen in slice 1 can be destroyed before slice 40, so the
  // accumulated map is a set of observations of DIFFERENT moments, not a
  // snapshot. That is the price, and it is paid in two places:
  //
  //   * StepBuild watches the array itself and asks for a restart when it sees
  //     evidence the graph moved under it -- the element count shrinking, or a
  //     chunk pointer changing beneath a region already scanned;
  //   * every anchor finally selected is RE-VALIDATED against live memory in
  //     one uninterrupted game-thread slice before the result is published, so
  //     nothing is published on the strength of an old observation alone.
  //
  // Identity, not the address, is what survives a slice boundary: an anchor is
  // remembered as "the object called X whose class is called Y", and the
  // address is only accepted if it still answers to that at validation time.
  enum class Step {
    kMore,             // budget spent, more slots remain
    kDone,             // every slot scanned
    kRestartNeeded,    // the array moved under the walk; start over
  };

  // Read the array's roots and reset the cursor. Cheap; call once per attempt.
  bool BeginBuild(Failure* failure);

  // Scan until *budget_us* has elapsed or *max_objects* slots were examined,
  // whichever comes first. The object cap is a backstop: a clock that misbehaves
  // must not turn one slice into the whole walk.
  Step StepBuild(uint32_t budget_us, uint32_t max_objects, Failure* failure);

  uint32_t Cursor() const { return cursor_; }
  // The chunk table this walk was built against, so a published
  // generation can keep validating after the walk is gone.
  uint64_t ObjectsPointer() const { return objects_ptr_; }
  uint32_t NumElements() const { return num_elements_; }

  // Does *address* STILL hold an object with this name, whose class has this
  // name? Read live, now -- not from the accumulated map. This is the check
  // that makes a multi-tick result publishable.
  bool StillIs(uint64_t address, const std::string& name,
               const std::string& class_name) const;

  // Kept as the name the existing call sites use; the work is the free function
  // above, so a published generation can run the same check without a Universe.
  using Liveness = misery::resolve::Liveness;
  static const char* LivenessName(Liveness state) {
    return misery::resolve::LivenessName(state);
  }

  // Is this anchor still LIVE, by the engine's own bookkeeping?
  //
  // THE CHECK THAT StillIs CANNOT MAKE. StillIs re-reads the object's own name
  // and class, and both of those survive destruction untouched until the memory
  // is reused -- so it detects RECYCLED memory, not FREED memory. This asks the
  // GUObjectArray instead: the object's InternalIndex must still address a slot
  // whose Object points back at it, with the serial number it was captured
  // with, and without the garbage or unreachable marks.
  Liveness CheckSlot(const AnchorIdentity& identity) const;

  // The class name of *address*'s Outer, read live. Used to re-validate the one
  // anchor whose identity depends on its owner.
  std::string LiveOuterClassName(uint64_t address) const;

  size_t Count() const { return objects_.size(); }

  const ObjectInfo* At(uint64_t address) const {
    auto it = objects_.find(address);
    return it == objects_.end() ? nullptr : &it->second;
  }

  std::string NameOf(uint64_t address) const {
    const ObjectInfo* info = At(address);
    return info != nullptr ? info->name : std::string();
  }

  std::string ClassNameOf(uint64_t address) const {
    const ObjectInfo* info = At(address);
    return info != nullptr ? NameOf(info->class_ptr) : std::string();
  }

  // THE lookup. Exactly one object whose own name is *name* and whose class's
  // name is *class_name*. Anything else is a failure that says which.
  uint64_t One(const std::string& name, const std::string& class_name,
               const char* label, Failure* failure) const;

  // Every object of a class, unfiltered. Callers apply their own proven
  // discriminator and must still end at exactly one.
  std::vector<uint64_t> AllOfClass(uint64_t class_ptr) const;

  // Does *derived* reach *base* through its Super chain? Bounded, because a
  // corrupt chain must terminate rather than hang a game frame.
  //
  // *incomplete*, when given, distinguishes the two ways this returns false,
  // and the distinction is load-bearing. MEASURED during a menu -> gameplay
  // load: at the instant the game replaces its content, a Blueprint class
  // object exists and is named while its Super link is still null. "Not linked
  // yet" is a transition state that will resolve on its own; "linked, but to a
  // different root" is a type error that never will. Collapsing them made the
  // resolver report a healthy game as broken for one sample out of thirteen.
  bool DerivesFrom(uint64_t derived, uint64_t base, int max_hops,
                   std::string* chain, bool* incomplete = nullptr) const;

  // A UFunction on a class, by name, from the Children/Next chain.
  uint64_t FunctionOn(uint64_t class_ptr, const std::string& name,
                      const char* label, Failure* failure) const;

  std::string DecodeName(uint32_t name_id) const;

  const Layout& layout() const { return layout_; }

 private:
  uint64_t guobjectarray_;
  uint64_t namepool_;
  Layout layout_;
  std::unordered_map<uint64_t, ObjectInfo> objects_;

  // name -> the objects carrying it.
  //
  // MEASURED, and the reason this exists: One() used to scan every object for
  // every anchor. At the main menu that cost 10ms; in gameplay, with 195k
  // objects and ~28 anchors, it cost 216ms -- 45% of the whole resolution, and
  // a hitch that would have sat immediately before publish no matter how finely
  // the WALK was sliced. Indexing by name during the walk turns each lookup
  // into one hash probe plus a filter over a handful of candidates, which
  // removes the work rather than spreading it over more frames.
  std::unordered_map<std::string, std::vector<uint64_t>> by_name_;

  // class pointer -> its instances.
  //
  // MEASURED, second round: indexing by name cut anchor resolution from 215.7ms
  // to 12.6ms, and the 12.6ms that remained was ONE call -- AllOfClass, which
  // still scanned every object to find instances of BP_PlayerInventory_C. At
  // 200k objects that single scan was the whole residual cost, and it landed in
  // the same slice as the end of the walk, producing a 14.1ms hitch. Indexed
  // here for the same reason as by_name_: remove the scan, do not budget it.
  std::unordered_map<uint64_t, std::vector<uint64_t>> by_class_;

  // Chunked-walk state. See BeginBuild/StepBuild.
  uint64_t objects_ptr_ = 0;
  uint32_t num_elements_ = 0;
  uint32_t cursor_ = 0;
};

// When an anchor comes into existence. Measured, not assumed: survey mode below
// is what established the assignment, and the lifecycle sweep re-checks it.
enum class Phase {
  kStartup = 0,   // engine classes and Kismet libraries: present from process start
  kContent = 1,   // the item tables, the row struct, the game's own Blueprints
  kGameplay = 2,  // the live player inventory
};

inline const char* PhaseName(Phase phase) {
  switch (phase) {
    case Phase::kStartup: return "startup";
    case Phase::kContent: return "content";
    case Phase::kGameplay: return "gameplay";
  }
  return "unknown";
}

// Everything the proven Items backend needs, resolved for THIS run.
struct Anchors {
  uint64_t item_list = 0;
  uint64_t master_item_list = 0;
  uint64_t row_struct = 0;
  uint64_t transient_package = 0;

  uint64_t datatable_class = 0;
  uint64_t composite_class = 0;
  uint64_t texture2d_class = 0;
  uint64_t staticmesh_class = 0;
  uint64_t actor_class = 0;
  uint64_t world_class = 0;

  uint64_t cdo_gameplaystatics = 0;
  uint64_t cdo_stringlib = 0;
  uint64_t cdo_textlib = 0;
  uint64_t cdo_syslib = 0;
  uint64_t cdo_sgkfunctions = 0;

  uint64_t fn_spawn_object = 0;
  uint64_t fn_conv_str_to_name = 0;
  uint64_t fn_str_to_text = 0;
  uint64_t fn_text_to_str = 0;
  uint64_t fn_load_asset_blocking = 0;
  uint64_t fn_soft_to_string = 0;
  uint64_t fn_sgk_itemdetails = 0;
  uint64_t fn_additem = 0;
  uint64_t fn_removeitem = 0;

  uint64_t player_inventory = 0;      // absent before gameplay
  bool player_inventory_present = false;
  // The Outer the discriminator matched. Reported because it is the thing that
  // makes the anchor survive a pawn dying: the inventory hangs off the
  // CONTROLLER, which outlives the character.
  uint64_t player_inventory_outer = 0;

  // Which anchors were not found, and the highest phase fully satisfied. Both
  // are reported on success as well as failure: "resolved, at content phase,
  // player inventory absent" is a legitimate and useful answer.
  std::vector<std::string> missing;

  // OBSERVED, BUT NOT VALID FOR THE PHASE THAT WAS ASKED FOR.
  //
  // These two are different claims and this project needed a measurement to
  // learn it. An anchor listed here EXISTS in the process right now -- the walk
  // found it, named it, and could have returned its address. It is withheld
  // because its lifetime is known to end at the next transition, so a caller
  // that asked for an earlier phase must not be able to keep it.
  //
  // It is deliberately NOT folded into `missing`: saying "absent" about an
  // object that is demonstrably present would be a lie in the diagnostics, and
  // the difference is exactly what a reader needs to understand why a
  // startup-scoped result looks empty at a main menu that visibly has content.
  std::vector<std::string> observed_out_of_phase;

  Phase reached = Phase::kStartup;   // the highest phase actually OBSERVED

  uint64_t plain_vtable = 0;
  uint64_t composite_vtable = 0;
  uint64_t struct_vtable = 0;
  uint32_t row_struct_size = 0;

  // WHAT EACH SELECTED ANCHOR MUST STILL BE.
  //
  // A chunked walk accumulates observations from many different moments, so an
  // address it selected is a claim about the past. These records carry the
  // IDENTITY the address was selected for -- the object's own name and its
  // class's name -- so the address can be re-checked against live memory before
  // anything is published. An address that no longer answers to its identity is
  // a destroyed object, and publishing it would hand the Items backend a
  // dangling pointer that looked resolved.
  //
  // Populated for every anchor found by name+class. `check_outer_class` is set
  // for the one anchor whose identity depends on its owner rather than only on
  // itself: the live player inventory, discriminated by its controller.
  std::vector<AnchorIdentity> identities;
};

// What the caller wants resolved.
//
// This is what lets one resolver answer at the main menu and in gameplay
// without either lying. An anchor above the requested phase that is absent is
// REPORTED absent; an anchor at or below it that is absent is a failure. A
// resolver that could not tell those apart would either refuse to start on a
// healthy game or claim success on a process that cannot host a mod yet.
//
// A PHASE IS A LIFETIME CONTRACT, NOT A FILTER ON WHAT EXISTS
// -----------------------------------------------------------
// Asking for a phase says what you intend to KEEP, and the result is scoped to
// it physically: anchors above the requested phase are cleared and recorded in
// `observed_out_of_phase`, even when the walk found them.
//
// The measurement that forced this: the main menu was expected to have no game
// content, and on two launches it had none -- but a third launch of the same
// build, with no save loaded, had the entire content set resolvable at the menu.
// Those pointers are not startup-stable. Every one of them is destroyed and
// recreated when the world is replaced, which the same sweep measured directly.
// So "it was resolvable" and "you may hold on to it" are separate questions, and
// a caller must not be able to answer the second by accident.
//
// Survey mode is exempt, because reporting what exists regardless of phase is
// precisely what it is for -- and it is how the phase column was measured.
struct Request {
  Phase require = Phase::kGameplay;
  // Try for a GAMEPLAY-scoped result, and fall back to `require` when the
  // process is not in gameplay.
  //
  // For a caller whose work needs gameplay anchors when they exist but which
  // must still function without them -- the runtime's content lifecycle is the
  // one that does. It cannot simply ask for kContent: scoping would then clear
  // the player inventory even in gameplay, and item rows could never be
  // written. Nor can it simply ask for kGameplay: that fails at the main menu,
  // where there is still content worth publishing.
  //
  // Costs a second pass of hash probes, NOT a second walk. ResolveAnchors is a
  // pure function of the already-built universe, so both attempts read the same
  // one. The phase contract is untouched: whichever attempt succeeds, the result
  // is still physically scoped to the phase it was granted.
  bool prefer_gameplay = false;
  // Resolve everything, fail nothing, report presence per anchor. Used to
  // MEASURE which anchor belongs to which phase.
  bool survey = false;
  std::string world_item_class = "BP_StaticMasterItem_C";
};

// Resolves the anchors. Returns false and fills *failure* on the first
// unambiguous failure; a missing-but-optional player inventory is not one.
bool ResolveAnchors(const Universe& universe, const Request& request,
                    Anchors* out, Failure* failure);

// Safe read of an address that came from the game. Returns false rather than
// faulting, because an access violation inside a shipping game is not an error
// anybody can act on.
bool ReadBytes(uint64_t address, void* out, size_t size);

// What the last walk cost. Kept because "is a full walk too expensive to do on
// the game thread?" is a question to MEASURE, not to guess at -- and because
// `queries` is the direct read-out of whether the region cache below is doing
// anything.
struct ReadStats {
  uint64_t reads = 0;        // calls into ReadBytes
  uint64_t queries = 0;      // VirtualQuery syscalls actually issued
  uint64_t cache_hits = 0;   // reads satisfied by an already-validated region
  uint64_t rejected = 0;     // reads refused (unmapped, guarded, out of region)
};

ReadStats ReadStatsSnapshot();

// Reads that FAULTED despite passing validation.
//
// VirtualQuery's answer is stale the instant it returns: the framework reads
// memory the game thread is free to release, so a validated read can still hit
// a page that is gone by the time the copy runs. CopyGuarded turns that into a
// refused read instead of a dead game, and counts it here.
//
// Process-wide and monotonic, so a non-zero value is a fact about the session
// rather than about one walk. Non-zero is not normal: it means the framework
// raced the game and lost, and the run should be read in that light.
uint64_t GuardedFaultCount();

// Clear the per-walk region cache and zero the counters.
//
// WHY THE CACHE IS PER-WALK AND NOT LONGER-LIVED
// ----------------------------------------------
// Validating every read with its own VirtualQuery costs one syscall per field,
// which for a full object walk is hundreds of thousands of them -- the reason a
// complete walk is expensive enough to matter on the game thread. UObjects live
// in a handful of large regions, so remembering the regions already validated
// removes almost all of that.
//
// A cached "this region is committed and readable" answer can go stale if the
// region is freed. Scoping the cache to ONE walk bounds that staleness to the
// same window the walk itself already has, rather than introducing a new and
// longer one. It is reset here at the start of every walk, deliberately, rather
// than being allowed to persist between them.
void ResetReadCache();

template <typename T>
bool Read(uint64_t address, T* out) {
  return ReadBytes(address, out, sizeof(T));
}

}  // namespace resolve
}  // namespace misery
