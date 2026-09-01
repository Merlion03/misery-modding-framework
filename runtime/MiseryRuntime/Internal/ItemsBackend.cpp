// ItemsBackend.cpp -- the proven registration path, fed from production.
//
// WHAT IS AND IS NOT NEW HERE
// ---------------------------
// The registration itself is NOT new and is deliberately not rewritten:
// CR01C5ProbeDll.cpp owns it, it is the path that put 28 of 28 items where the
// game's own SGK lookup found them, and it stays byte-for-byte what it was. All
// this file does is fill the input block that path has always been handed --
// which until now only a Python controller ever filled, from outside the
// process.
//
// So the question this file answers is narrow: where does each of those ~40
// addresses and ~25 offsets come from, without a controller?
//
//   build-specific, cannot be resolved   -> the binding profile
//     RVAs, vtable slot indices, every S_ItemDetails write offset
//   per-run, cannot be in a profile      -> the current content generation
//     the tables, the row struct, the CDOs, the reflected UFunctions
//   derived from both                    -> computed here
//     AddRow/RemoveRow from a vtable and a slot, ProcessEvent from a CDO's
//
// EVERY REGISTRATION ACQUIRES. THAT IS THE POINT.
// ------------------------------------------------
// The anchors in the input block belong to one content generation, and a
// generation dies when the world is replaced. So the backend does not fill the
// block once and trust it: every call goes through content::Acquire first, and
// a refusal there is a refusal here. A revoked generation cannot be registered
// against, because the pointers to register against are not obtainable.
//
// When Acquire hands back a DIFFERENT generation than the block was built for,
// the block is rebuilt before anything is written. A consumer never sees that
// happen -- it either gets a registration against the current world or an error
// naming why it could not have one.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <mutex>
#include <string>
#include <vector>

#include "Bindings.h"
#include "C5Io.h"
#include "ContentGeneration.h"
#include "ItemsBackend.h"
#include "Resolver.h"

// Owned by CR01C5ProbeDll.cpp. Declared, not redefined: this file feeds the
// proven path, it does not reimplement it.
// Same module, so plain extern "C" -- not dllimport.
extern "C" unsigned long Init(void* param);
extern "C" unsigned long Shutdown(void* param);
// (found << 16) | attempts, tallied across every registration.
extern "C" unsigned long Stage5ResolveStats(void);
// Which required input was absent when Init last refused, or nullptr.
extern "C" const char* Stage5InitMissing(void);
extern "C" int Stage5RegisterItem(const char* mod_id,
                                  const char* declaration_json,
                                  char* out_row_name, int out_capacity);
extern "C" int Stage5UnregisterItem(const char* mod_id, const char* row_name);
extern "C" int Stage5AddItem(const char* row_name, int amount,
                             int* out_added);
extern "C" int Stage5DeriveRowName(const char* mod_id,
                                   const char* declaration_json, char* out,
                                   int capacity);
// 0 = the game's own SGK lookup found the row, 36 = it did not.
extern "C" int Stage5VerifyRow(const char* mod_id,
                               const char* declaration_json);
// Detach the aggregate from MasterItemList. Only safe while it is still alive.
extern "C" int Stage5DetachAggregate(void);
extern "C" void MiseryBridgeInstallItemsBackend(
    int (*register_item)(const char*, const char*, char*, int),
    int (*unregister_item)(const char*, const char*),
    int (*grant_item)(const char*, const char*, int, int*));

namespace misery {
namespace items {
namespace {

// WHAT A MOD'S REGISTRATION ACTUALLY IS
// -------------------------------------
// A DECLARATION, not a write. The write is a consequence.
//
// A row lives in a DataTable that belongs to one content generation, i.e. to
// one loaded world. Two facts follow, and the first draft of this file honoured
// neither:
//
//   1. A mod calls Register from OnLoad, and OnLoad happens when the managed
//      host starts -- at the main menu. There is no player inventory there, so
//      the CR-01C5 path cannot even initialise, and every mod died on load with
//      an error that said nothing about the mod.
//   2. When the world is replaced, that table goes with it. A registration
//      applied once would vanish at the first level transition and never come
//      back, which no player would call working.
//
// So a mod declares an item once and the framework owns applying it: to the
// current world if there is one that can hold it, and to each world that
// follows. The mod is told its row name immediately, because the name is
// derived from (mod_id, local_id) and does not depend on a world existing.
//
// This is also why no gameplay event has to be invented to prove a transition
// works. The mod says nothing at transition time; the framework re-applies.
struct Declaration {
  std::string mod_id;
  std::string json;
  std::string row_name;
  // The generation this declaration's row is currently live in. Zero means it
  // is declared but not present in any world -- either not applied yet, or the
  // world it was in is gone. Compared against the current generation rather
  // than cleared on revocation, so a missed revocation cannot leave it looking
  // applied.
  uint64_t applied_in = 0;
  // The generation this declaration last failed to apply to. Without it a
  // permanently unwritable declaration is retried on every poll, forever,
  // filling the log with the same line every 20 seconds -- which is how this
  // was noticed.
  uint64_t failed_in = 0;
  // Whether the game's own lookup has found this row in `applied_in`, and how
  // many times it has been asked. Separate from applied_in because the write
  // succeeding and the game being able to find the result are different
  // claims, and only the second is the one a player would notice.
  bool confirmed = false;
  unsigned asked = 0;
};

// How many polls a row gets to become findable before the answer is final.
// Five polls is a hundred seconds, which is far longer than any table rebuild
// and short enough that a genuinely absent row is reported the same session.
constexpr unsigned kMaxVerifyAttempts = 5;

std::mutex g_mutex;
std::vector<Declaration> g_declared;
// MasterItemList's slot identity in the generation the block was built for.
//
// Kept because tearing down for a NEW generation has to know whether the OLD
// generation's MasterItemList still exists: if it does, our aggregate must be
// detached from it first, and if it does not, touching it would be a read of a
// freed object. The address alone cannot answer that -- a transition was
// measured leaving ItemList, MasterItemList and RowStruct at exactly the same
// addresses while the world around them was replaced -- so the authoritative
// slot identity is what gets kept.
resolve::AnchorIdentity g_master_identity;
bool g_have_master_identity = false;
C5Io g_io;                       // the block the proven path reads
uint64_t g_built_for = 0;        // which generation g_io describes; 0 = none
bool g_initialised = false;
bindings::Profile g_profile;
uint64_t g_module_base = 0;
uint64_t g_guobjectarray = 0;
LogFn g_log = nullptr;

void Say(const char* format, ...) {
  if (g_log == nullptr) {
    return;
  }
  char buffer[512];
  va_list args;
  va_start(args, format);
  _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
  va_end(args);
  g_log(buffer);
}

// A pointer out of a vtable: *(vtable + slot*8). Both halves are checked --
// the profile's slot index and the anchor's vtable -- because a zero either
// side would otherwise produce a plausible-looking address near zero.
bool FromVtable(uint64_t vtable, const char* slot_name, uint64_t* out) {
  uint32_t slot = 0;
  if (vtable == 0 || !g_profile.Slot(slot_name, &slot)) {
    return false;
  }
  return resolve::Read(vtable + static_cast<uint64_t>(slot) * 8, out) &&
         *out != 0;
}

bool Rva(const char* name, uint64_t* out) {
  std::string error;
  return bindings::Resolve(g_profile, name, g_module_base,
                           g_profile.image_size_bytes, out, &error);
}

uint32_t WriteOffset(const char* name) {
  uint32_t value = 0;
  return g_profile.WriteOffset(name, &value) ? value : 0xFFFFFFFFu;
}

// Fill the block for THIS generation. Every failure is named, because a
// half-filled block would be a registration writing through a zero.
bool Build(const content::Snapshot& snapshot, std::string* why) {
  const resolve::Anchors& a = snapshot.anchors;
  memset(&g_io, 0, sizeof(g_io));
  g_io.magic = kC5Magic;
  g_io.proto = kC5Proto;
  g_io.struct_size = a.row_struct_size;

  // ---- the carrier, from the profile -----------------------------------
  struct Wanted { const char* name; uint64_t* slot; uint8_t* sig; };
  const Wanted carrier[] = {
      {"add_ticker", &g_io.add_ticker, g_io.sig_add},
      {"get_core_ticker", &g_io.get_core_ticker, g_io.sig_get},
      {"fmemory_malloc", &g_io.fmemory_malloc, g_io.sig_malloc},
  };
  for (const Wanted& item : carrier) {
    auto found = g_profile.addresses.find(item.name);
    if (found == g_profile.addresses.end() || !Rva(item.name, item.slot)) {
      *why = std::string("the profile does not describe ") + item.name;
      return false;
    }
    memcpy(item.sig, found->second.expected, 16);
  }
  if (!Rva("fmemory_free", &g_io.fmemory_free) ||
      !Rva("set_root_flags", &g_io.set_root_flags) ||
      !Rva("clear_root_flags", &g_io.clear_root_flags)) {
    *why = "the profile does not describe the engine allocator or root flags";
    return false;
  }

  // ---- the generation's own anchors ------------------------------------
  g_io.cdo_stringlib = a.cdo_stringlib;
  g_io.fn_conv_str_to_name = a.fn_conv_str_to_name;
  g_io.cdo_gameplaystatics = a.cdo_gameplaystatics;
  g_io.fn_spawn_object = a.fn_spawn_object;
  g_io.cdo_textlib = a.cdo_textlib;
  g_io.fn_str_to_text = a.fn_str_to_text;
  g_io.fn_text_to_str = a.fn_text_to_str;
  g_io.cdo_syslib = a.cdo_syslib;
  g_io.fn_load_asset_blocking = a.fn_load_asset_blocking;
  g_io.fn_soft_to_string = a.fn_soft_to_string;
  g_io.texture2d_class = a.texture2d_class;
  g_io.datatable_class = a.datatable_class;
  g_io.transient_package = a.transient_package;
  g_io.row_struct = a.row_struct;
  g_io.item_list = a.item_list;
  g_io.master_item_list = a.master_item_list;
  g_have_master_identity = false;
  for (const resolve::AnchorIdentity& identity : a.identities) {
    if (identity.address == a.master_item_list) {
      g_master_identity = identity;
      g_have_master_identity = true;
      break;
    }
  }
  g_io.expected_plain_vtable = a.plain_vtable;
  g_io.expected_composite_vtable = a.composite_vtable;
  g_io.master_class = a.composite_class;
  g_io.player_inventory = a.player_inventory;
  g_io.fn_additem = a.fn_additem;
  g_io.fn_removeitem = a.fn_removeitem;
  g_io.fn_sgk_itemdetails = a.fn_sgk_itemdetails;
  g_io.cdo_sgkfunctions = a.cdo_sgkfunctions;
  g_io.staticmesh_class = a.staticmesh_class;
  g_io.world_class = a.world_class;
  g_io.actor_class = a.actor_class;

  // ---- derived from a vtable and a profile slot ------------------------
  if (!FromVtable(a.plain_vtable, "datatable_add_row", &g_io.add_row) ||
      !FromVtable(a.plain_vtable, "datatable_remove_row", &g_io.remove_row)) {
    *why = "AddRow/RemoveRow are not at the recorded DataTable vtable slots";
    return false;
  }
  if (!FromVtable(a.struct_vtable, "scriptstruct_initialize",
                  &g_io.initialize_struct) ||
      !FromVtable(a.struct_vtable, "scriptstruct_destroy",
                  &g_io.destroy_struct)) {
    *why = "InitializeStruct/DestroyStruct are not at the recorded "
           "ScriptStruct vtable slots";
    return false;
  }
  // ProcessEvent comes off a CDO's own vtable. Read from three unrelated CDOs
  // and required to agree, which is how CR-01C1 established the slot in the
  // first place -- one read could be a coincidence.
  uint64_t pe[3] = {0, 0, 0};
  const uint64_t cdos[3] = {a.cdo_stringlib, a.cdo_textlib, a.cdo_sgkfunctions};
  for (int i = 0; i < 3; ++i) {
    uint64_t vtable = 0;
    if (!resolve::Read(cdos[i], &vtable) ||
        !FromVtable(vtable, "process_event", &pe[i])) {
      *why = "ProcessEvent could not be read from a CDO vtable";
      return false;
    }
  }
  if (pe[0] != pe[1] || pe[1] != pe[2]) {
    *why = "the ProcessEvent slot disagrees across unrelated CDOs";
    return false;
  }
  g_io.process_event = pe[0];

  if (!resolve::Read(g_guobjectarray + resolve::Layout().guobjectarray_objects,
                     &g_io.guobjectarray_objects_ptr) ||
      g_io.guobjectarray_objects_ptr == 0) {
    *why = "the object array's chunk table is not readable";
    return false;
  }

  // ---- every write offset, from the profile ----------------------------
  struct Field { const char* name; uint32_t* slot; };
  const Field fields[] = {
      {"Name", &g_io.off_name}, {"ShortName", &g_io.off_shortname},
      {"Description", &g_io.off_description},
      {"inventory_icon", &g_io.off_inventory_icon},
      {"Weight", &g_io.off_weight}, {"Width", &g_io.off_width},
      {"Height", &g_io.off_height}, {"MaxStack", &g_io.off_maxstack},
      {"AllowStacking", &g_io.off_allowstacking},
      {"move_icon", &g_io.off_move_icon},
      {"override_flag", &g_io.off_override_flag},
      {"override_sizey", &g_io.off_override_sizey},
      {"override_sizex", &g_io.off_override_sizex},
      {"worldclass", &g_io.off_worldclass},
      {"staticmesh", &g_io.off_staticmesh},
      {"itemoffsets", &g_io.off_itemoffsets},
      {"rot", &g_io.off_rot}, {"trans", &g_io.off_trans},
      {"scale", &g_io.off_scale},
  };
  for (const Field& field : fields) {
    const uint32_t value = WriteOffset(field.name);
    if (value == 0xFFFFFFFFu) {
      *why = std::string("the profile does not record the write offset for ") +
             field.name;
      return false;
    }
    *field.slot = value;
  }
  uint32_t layout_value = 0;
  g_io.off_parent_tables =
      g_profile.object_layout.count("datatable_parent_tables")
          ? g_profile.object_layout.at("datatable_parent_tables") : 0;
  g_io.off_rowstruct = g_profile.object_layout.count("datatable_rowstruct")
                           ? g_profile.object_layout.at("datatable_rowstruct")
                           : 0;
  g_io.off_delegate = g_profile.InventoryOffset("off_delegate", &layout_value)
                          ? layout_value : 0;
  g_io.off_inventory_array =
      g_profile.InventoryOffset("off_inventory_array", &layout_value)
          ? layout_value : 0;
  if (g_io.off_parent_tables == 0 || g_io.off_rowstruct == 0 ||
      g_io.off_delegate == 0 || g_io.off_inventory_array == 0) {
    *why = "the profile does not record the DataTable/inventory member offsets";
    return false;
  }

  // ---- defaults for the world representation ---------------------------
  //
  // The declaration carries weight, width and height; it does not carry a world
  // transform, and inventing a mod-facing API for one is Stage 6's business.
  // Identity scale at the origin is the neutral choice, and it is a DEFAULT
  // rather than a measurement, so it is written where a reader will see that.
  g_io.want_scale_x = g_io.want_scale_y = g_io.want_scale_z = 1.0;
  g_io.want_trans_x = g_io.want_trans_y = g_io.want_trans_z = 0.0;
  g_io.want_sizex = 1;
  g_io.want_sizey = 1;

  // ---- the values a freshly created inventory item carries -------------
  g_io.inv_amount = 1;
  g_io.inv_quickbind = -1;
  g_io.inv_useamount = 0;
  g_io.inv_decaytime = 0;
  g_io.inv_rotated = 0;
  g_io.inv_inuse = 0;
  g_io.inv_durability = 0.0f;
  return true;
}

// Bring the proven path up for a generation, building the block first.
bool EnsureForGeneration(const content::Snapshot& snapshot, std::string* why) {
  if (g_initialised && g_built_for == snapshot.generation) {
    return true;
  }
  // The previous world's state goes first, or Init refuses.
  //
  // Init guards against being run twice over live state and returns
  // 0xFFFFFFFA. Until a registration actually succeeded there was never any
  // live state to trip it, so this path looked fine while being unreachable --
  // and the first thing that would have exercised it is the level transition
  // this backend exists to survive. Shutdown releases the rooted assets, stops
  // the dispatcher and clears the binding, which is what lets a later Init
  // through; it says so itself.
  if (g_initialised) {
    // Detach BEFORE Shutdown, and only if there is still something to detach
    // from. Shutdown releases the aggregate's root; if MasterItemList outlived
    // the transition it would then be holding parent[1] to a table nothing
    // roots, which is a dangling pointer inside a live object and a crash the
    // next time the composite rebuilds.
    //
    // Whether it outlived the transition is decided by the slot, not the
    // address: a measured RestartLevel left all three table anchors at
    // identical addresses while replacing the world. Asking the engine's own
    // bookkeeping is the only answer that distinguishes "still there" from
    // "something else is there now".
    if (g_have_master_identity) {
      uint64_t objects_ptr = 0;
      const resolve::Layout& layout = resolve::Layout();
      if (resolve::Read(g_guobjectarray + layout.guobjectarray_objects,
                        &objects_ptr) && objects_ptr != 0) {
        const resolve::Liveness state =
            resolve::CheckSlotIdentity(objects_ptr, layout, g_master_identity);
        if (state == resolve::Liveness::kAlive) {
          const int rc = Stage5DetachAggregate();
          Say("items: MasterItemList survived the transition; the aggregate "
              "was detached from it (%s)",
              rc == 0 ? "clean" : "REFUSED -- see the IO block");
        } else {
          Say("items: MasterItemList did not survive the transition (%s); "
              "nothing to detach", resolve::LivenessName(state));
        }
      }
    }
    Shutdown(&g_io);
    g_initialised = false;
    g_have_master_identity = false;
  }
  if (!Build(snapshot, why)) {
    return false;
  }
  const unsigned long rc = Init(&g_io);
  if (rc != 0) {
    const char* missing = Stage5InitMissing();
    char buffer[192];
    if (missing != nullptr) {
      _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                  "the CR-01C5 path refused its input block (0x%lx): '%s' is "
                  "not available", rc, missing);
    } else {
      _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                  "the CR-01C5 path refused its input block (0x%lx)", rc);
    }
    *why = buffer;
    return false;
  }
  g_initialised = true;
  g_built_for = snapshot.generation;
  Say("items: backend bound to content generation %llu",
      static_cast<unsigned long long>(snapshot.generation));
  return true;
}

// Write one declaration's row into the generation the block is already built
// for. Caller holds g_mutex and has confirmed the generation can host items.
bool ApplyLocked(Declaration* declaration, uint64_t generation) {
  // Bracketed by the SGK tally so the log can state the only thing that finally
  // matters: not "the engine accepted our write", but "the game can find it".
  //
  // Stage5RegisterItem already asks BP_SGKFunctions::"SGK ItemDetails" -- the
  // game's own lookup -- on every registration, and deliberately does not fail
  // a registration when the answer is no, because that lookup needs a live
  // player inventory. The counters are therefore the only place the answer
  // exists, and a proof nobody records is not a proof.
  const unsigned long before = Stage5ResolveStats();
  char row[192];
  const int rc = Stage5RegisterItem(declaration->mod_id.c_str(),
                                    declaration->json.c_str(), row,
                                    static_cast<int>(sizeof(row)));
  if (rc != 0) {
    Say("items: '%s' could not be written into generation %llu (step %d)",
        declaration->row_name.c_str(),
        static_cast<unsigned long long>(generation), rc);
    return false;
  }
  declaration->applied_in = generation;
  declaration->confirmed = false;
  declaration->asked = 1;
  const unsigned long after = Stage5ResolveStats();
  if ((after >> 16) != (before >> 16)) {
    declaration->confirmed = true;
    Say("items: '%s' is live in generation %llu; the game's own SGK "
        "ItemDetails resolved it", row,
        static_cast<unsigned long long>(generation));
  } else {
    // Not a failure yet. See Stage5VerifyRow: a composite table need not
    // rebuild within the tick that changed one of its parents, so the row is
    // asked about again on later polls before anything is concluded.
    Say("items: '%s' is live in generation %llu; the game's own SGK "
        "ItemDetails has not found it yet", row,
        static_cast<unsigned long long>(generation));
  }
  return true;
}

// True when this generation is a world that can hold item rows.
//
// Phrased as a phase rather than as "player_inventory is non-zero" on purpose.
// The resolver DEFINES reached == kGameplay as player_inventory_present, so the
// two are the same fact today, and saying it in the resolver's own vocabulary
// keeps this correct if what constitutes gameplay is ever refined.
bool CanHostItems(const content::Snapshot& snapshot) {
  return snapshot.anchors.reached == resolve::Phase::kGameplay;
}

// Ask the game's own lookup about a row that is already written.
//
// Called on later polls rather than only at write time, because the answer can
// legitimately change from no to yes once a frame has passed -- see
// Stage5VerifyRow. Gives up after kMaxVerifyAttempts so a row that really is
// unfindable produces one clear verdict instead of a line every poll forever.
void VerifyLocked(Declaration* declaration, uint64_t generation) {
  if (declaration->confirmed || declaration->asked >= kMaxVerifyAttempts) {
    return;
  }
  ++declaration->asked;
  const int rc = Stage5VerifyRow(declaration->mod_id.c_str(),
                                 declaration->json.c_str());
  if (rc == 0) {
    declaration->confirmed = true;
    Say("items: '%s' in generation %llu: the game's own SGK ItemDetails "
        "resolved it (attempt %u)", declaration->row_name.c_str(),
        static_cast<unsigned long long>(generation), declaration->asked);
    return;
  }
  if (declaration->asked >= kMaxVerifyAttempts) {
    Say("items: '%s' is written into generation %llu but the game's own SGK "
        "ItemDetails still cannot find it after %u attempts (last code %d)",
        declaration->row_name.c_str(),
        static_cast<unsigned long long>(generation), declaration->asked, rc);
  }
}

// Apply every declaration not already live in *snapshot*. Caller holds g_mutex.
void ApplyPendingLocked(const content::Snapshot& snapshot) {
  if (g_declared.empty() || !CanHostItems(snapshot)) {
    return;
  }
  std::string why;
  if (!EnsureForGeneration(snapshot, &why)) {
    Say("items: %u declaration(s) cannot be applied to generation %llu -- %s",
        static_cast<unsigned>(g_declared.size()),
        static_cast<unsigned long long>(snapshot.generation), why.c_str());
    return;
  }
  unsigned applied = 0;
  for (Declaration& declaration : g_declared) {
    if (declaration.applied_in == snapshot.generation) {
      VerifyLocked(&declaration, snapshot.generation);
      continue;
    }
    if (declaration.failed_in == snapshot.generation) {
      continue;
    }
    if (ApplyLocked(&declaration, snapshot.generation)) {
      ++applied;
    } else {
      declaration.failed_in = snapshot.generation;
    }
  }
  if (applied > 0) {
    Say("items: %u declaration(s) applied to generation %llu", applied,
        static_cast<unsigned long long>(snapshot.generation));
  }
}

int RegisterItem(const char* mod_id, const char* declaration_json,
                 char* out_row_name, int out_capacity) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (mod_id == nullptr || declaration_json == nullptr) {
    return 2;
  }
  char row[192];
  const int derived = Stage5DeriveRowName(mod_id, declaration_json, row,
                                          static_cast<int>(sizeof(row)));
  if (derived != 0) {
    return derived;
  }
  // A mod cannot declare the same row twice, and two mods cannot collide here:
  // the row name carries the mod id, so a collision is a mod against itself.
  // Collision with a VANILLA row is a different question and stays where it
  // was -- inside the CR-01C5 path, against the canonical row list.
  for (const Declaration& existing : g_declared) {
    if (existing.row_name == row) {
      Say("items: '%s' is already declared", row);
      return kItemsAlreadyDeclared;
    }
  }
  if (out_row_name != nullptr &&
      _snprintf_s(out_row_name, out_capacity, _TRUNCATE, "%s", row) < 0) {
    return 9;
  }

  Declaration declaration;
  declaration.mod_id = mod_id;
  declaration.json = declaration_json;
  declaration.row_name = row;
  g_declared.push_back(declaration);

  // Applied now if a world exists that can hold it, and otherwise left for the
  // next one. NOT an error either way: a mod loading at the main menu is the
  // ordinary case, and failing it there would make every mod fail on every
  // launch for a reason that has nothing to do with the mod.
  content::Snapshot snapshot;
  std::string why;
  if (!content::Acquire(&snapshot, &why)) {
    Say("items: '%s' declared; deferred -- %s", row, why.c_str());
    return 0;
  }
  if (!CanHostItems(snapshot)) {
    Say("items: '%s' declared; deferred until a world exists to hold it "
        "(generation %llu reached %s)", row,
        static_cast<unsigned long long>(snapshot.generation),
        resolve::PhaseName(snapshot.anchors.reached));
    return 0;
  }
  if (!EnsureForGeneration(snapshot, &why)) {
    // The declaration STAYS: the backend could not be brought up against this
    // world, and the next one gets another go.
    Say("items: '%s' declared; deferred -- %s", row, why.c_str());
    return 0;
  }
  if (!ApplyLocked(&g_declared.back(), snapshot.generation)) {
    g_declared.back().failed_in = snapshot.generation;
  }
  return 0;
}

int GrantItem(const char* mod_id, const char* row_name, int amount,
              int* out_added) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (mod_id == nullptr || row_name == nullptr) {
    return 2;
  }
  // The declaration must be this mod's, and must actually be live in the
  // current world. Granting a row that was declared but never applied would
  // put an id into an inventory that no table can resolve.
  const Declaration* owned = nullptr;
  for (const Declaration& declaration : g_declared) {
    if (declaration.row_name == row_name && declaration.mod_id == mod_id) {
      owned = &declaration;
      break;
    }
  }
  if (owned == nullptr) {
    return kItemsNotOwned;
  }

  content::Snapshot snapshot;
  std::string why;
  if (!content::Acquire(&snapshot, &why)) {
    Say("items: grant refused -- %s", why.c_str());
    return kItemsNoContent;
  }
  if (owned->applied_in != snapshot.generation) {
    Say("items: grant refused -- '%s' is not live in generation %llu",
        row_name, static_cast<unsigned long long>(snapshot.generation));
    return kItemsNotLive;
  }
  if (!EnsureForGeneration(snapshot, &why)) {
    return kItemsBackendUnavailable;
  }
  const int rc = Stage5AddItem(row_name, amount, out_added);
  if (rc == 0) {
    Say("items: '%s' -- %d of %d added to the player's inventory", row_name,
        out_added != nullptr ? *out_added : -1, amount);
  } else {
    Say("items: '%s' could not be added to the inventory (step %d)", row_name,
        rc);
  }
  return rc;
}

int UnregisterItem(const char* mod_id, const char* row_name) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (mod_id == nullptr || row_name == nullptr) {
    return 2;
  }
  // The declaration goes first, and unconditionally. Whatever then happens to
  // the row, the mod has withdrawn the item; leaving the declaration behind
  // would re-apply a withdrawn item to the next world, which is the one way a
  // failure here could resurrect something a mod asked to remove.
  bool was_applied = false;
  bool found = false;
  for (size_t i = 0; i < g_declared.size(); ++i) {
    if (g_declared[i].row_name != row_name) {
      continue;
    }
    if (g_declared[i].mod_id != mod_id) {
      // Not this mod's row to withdraw. The row name carries its owner, so
      // this is only reachable by a caller bypassing the bridge.
      return kItemsNotOwned;
    }
    was_applied = g_declared[i].applied_in != 0;
    g_declared.erase(g_declared.begin() + static_cast<ptrdiff_t>(i));
    found = true;
    break;
  }
  if (!found) {
    return kItemsNotDeclared;
  }
  if (!was_applied) {
    // Declared but never written into any world. Nothing to remove, and that
    // is a success: the caller asked for the item to be gone, and it is.
    return 0;
  }

  content::Snapshot snapshot;
  std::string why;
  if (!content::Acquire(&snapshot, &why)) {
    // The row belonged to a world that no longer exists, so it went with that
    // world. The declaration is withdrawn either way, which is what was asked.
    Say("items: '%s' withdrawn; its row went with its world -- %s", row_name,
        why.c_str());
    return 0;
  }
  if (!EnsureForGeneration(snapshot, &why)) {
    Say("items: '%s' withdrawn, but its row could not be removed -- %s",
        row_name, why.c_str());
    return kItemsBackendUnavailable;
  }
  return Stage5UnregisterItem(mod_id, row_name);
}

}  // namespace

void OnGenerationPublished(const content::Snapshot& snapshot) {
  std::lock_guard<std::mutex> lock(g_mutex);
  ApplyPendingLocked(snapshot);
}

unsigned DeclaredCount() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return static_cast<unsigned>(g_declared.size());
}

unsigned LiveCount(uint64_t generation) {
  std::lock_guard<std::mutex> lock(g_mutex);
  unsigned live = 0;
  for (const Declaration& declaration : g_declared) {
    if (declaration.applied_in == generation && generation != 0) {
      ++live;
    }
  }
  return live;
}

void Install(const bindings::Profile& profile, uint64_t module_base,
             uint64_t guobjectarray, LogFn log) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_profile = profile;
  g_module_base = module_base;
  g_guobjectarray = guobjectarray;
  g_log = log;
  g_built_for = 0;
  g_initialised = false;
  MiseryBridgeInstallItemsBackend(&RegisterItem, &UnregisterItem,
                                  &GrantItem);
}

uint64_t BoundGeneration() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_initialised ? g_built_for : 0;
}

}  // namespace items
}  // namespace misery
