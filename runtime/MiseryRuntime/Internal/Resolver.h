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

  // UObjectBase
  uint32_t object_class_private = 0x10;
  uint32_t object_name_private = 0x18;
  uint32_t object_outer_private = 0x20;

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

// One live object, as this resolver sees it.
struct ObjectInfo {
  uint64_t address = 0;
  uint64_t class_ptr = 0;
  uint64_t outer_ptr = 0;
  uint32_t name_id = 0;
  std::string name;      // empty when the name could not be decoded
  bool name_ok = false;
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

class Universe {
 public:
  Universe(uint64_t guobjectarray, uint64_t namepool, const Layout& layout)
      : guobjectarray_(guobjectarray), namepool_(namepool), layout_(layout) {}

  // Walk every allocated slot once and decode every name. One pass, because the
  // array is large and the alternative is re-walking it per lookup.
  bool Build(Failure* failure);

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
