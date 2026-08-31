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

#include "Bindings.h"
#include "C5Io.h"
#include "ContentGeneration.h"
#include "ItemsBackend.h"
#include "Resolver.h"

// Owned by CR01C5ProbeDll.cpp. Declared, not redefined: this file feeds the
// proven path, it does not reimplement it.
// Same module, so plain extern "C" -- not dllimport.
extern "C" unsigned long Init(void* param);
extern "C" int Stage5RegisterItem(const char* mod_id,
                                  const char* declaration_json,
                                  char* out_row_name, int out_capacity);
extern "C" int Stage5UnregisterItem(const char* mod_id, const char* row_name);
extern "C" void MiseryBridgeInstallItemsBackend(
    int (*register_item)(const char*, const char*, char*, int),
    int (*unregister_item)(const char*, const char*));

namespace misery {
namespace items {
namespace {

std::mutex g_mutex;
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
  if (!Build(snapshot, why)) {
    return false;
  }
  const unsigned long rc = Init(&g_io);
  if (rc != 0) {
    char buffer[128];
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                "the CR-01C5 path refused its input block (0x%lx)", rc);
    *why = buffer;
    return false;
  }
  g_initialised = true;
  g_built_for = snapshot.generation;
  Say("items: backend bound to content generation %llu",
      static_cast<unsigned long long>(snapshot.generation));
  return true;
}

int RegisterItem(const char* mod_id, const char* declaration_json,
                 char* out_row_name, int out_capacity) {
  std::lock_guard<std::mutex> lock(g_mutex);
  content::Snapshot snapshot;
  std::string why;
  // THE GATE. Not a courtesy check at the top of the function -- it is the only
  // way the anchors below are obtainable at all.
  if (!content::Acquire(&snapshot, &why)) {
    Say("items: registration refused -- %s", why.c_str());
    return kItemsNoContent;
  }
  if (!EnsureForGeneration(snapshot, &why)) {
    Say("items: registration refused -- %s", why.c_str());
    return kItemsBackendUnavailable;
  }
  return Stage5RegisterItem(mod_id, declaration_json, out_row_name,
                            out_capacity);
}

int UnregisterItem(const char* mod_id, const char* row_name) {
  std::lock_guard<std::mutex> lock(g_mutex);
  content::Snapshot snapshot;
  std::string why;
  if (!content::Acquire(&snapshot, &why)) {
    // A row belonging to a world that no longer exists went with that world.
    // Reporting success would be a lie; reporting the reason is not.
    Say("items: unregister refused -- %s", why.c_str());
    return kItemsNoContent;
  }
  if (!EnsureForGeneration(snapshot, &why)) {
    return kItemsBackendUnavailable;
  }
  return Stage5UnregisterItem(mod_id, row_name);
}

}  // namespace

void Install(const bindings::Profile& profile, uint64_t module_base,
             uint64_t guobjectarray, LogFn log) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_profile = profile;
  g_module_base = module_base;
  g_guobjectarray = guobjectarray;
  g_log = log;
  g_built_for = 0;
  g_initialised = false;
  MiseryBridgeInstallItemsBackend(&RegisterItem, &UnregisterItem);
}

uint64_t BoundGeneration() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_initialised ? g_built_for : 0;
}

}  // namespace items
}  // namespace misery
