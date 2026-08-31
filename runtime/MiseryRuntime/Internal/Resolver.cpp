// Resolver.cpp -- see Resolver.h for the contract this implements.
#include "Resolver.h"

#include <string.h>

#include <algorithm>

namespace misery {
namespace resolve {

// ---------------------------------------------------------------- reads ----
//
// Every pointer here came out of the game's own memory, so any of them can be
// stale, null, or garbage if a layout assumption is wrong. In-process that is
// an access violation in a game frame rather than a failed read, so each one is
// checked against the page's actual protection first. VirtualQuery per read is
// not cheap; it is bought once, during resolution, and never again on a hot
// path.
namespace {

// Regions already validated during THIS walk. Small and thread-local: the walk
// runs on one thread, and a handful of entries covers the object array's chunks
// plus .data, which is where essentially every read lands.
constexpr int kRegionCacheSize = 16;
struct CachedRegion {
  uint64_t begin = 0;
  uint64_t end = 0;
};
thread_local CachedRegion tls_regions[kRegionCacheSize];
thread_local int tls_region_next = 0;
thread_local ReadStats tls_stats;

bool InCachedRegion(uint64_t address, size_t size) {
  for (const CachedRegion& region : tls_regions) {
    if (region.end != 0 && address >= region.begin &&
        address + size <= region.end) {
      return true;
    }
  }
  return false;
}

void RememberRegion(uint64_t begin, uint64_t end) {
  tls_regions[tls_region_next] = CachedRegion{begin, end};
  tls_region_next = (tls_region_next + 1) % kRegionCacheSize;
}

}  // namespace

ReadStats ReadStatsSnapshot() { return tls_stats; }

void ResetReadCache() {
  for (CachedRegion& region : tls_regions) {
    region = CachedRegion{};
  }
  tls_region_next = 0;
  tls_stats = ReadStats{};
}

bool ReadBytes(uint64_t address, void* out, size_t size) {
  if (address == 0 || size == 0 || size > (1u << 20)) {
    return false;
  }
  ++tls_stats.reads;

  // Already inside a region this walk validated. Still bounded by that region's
  // end, so a read that would run off it falls through to a fresh query.
  if (InCachedRegion(address, size)) {
    ++tls_stats.cache_hits;
    memcpy(out, reinterpret_cast<const void*>(address), size);
    return true;
  }

  MEMORY_BASIC_INFORMATION info;
  ++tls_stats.queries;
  if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == 0) {
    ++tls_stats.rejected;
    return false;
  }
  if (info.State != MEM_COMMIT) {
    ++tls_stats.rejected;
    return false;
  }
  const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY;
  if ((info.Protect & readable) == 0 || (info.Protect & PAGE_GUARD) != 0) {
    ++tls_stats.rejected;
    return false;
  }
  // The read must not run off the end of the region VirtualQuery just described.
  uint64_t region_begin = reinterpret_cast<uint64_t>(info.BaseAddress);
  uint64_t region_end = region_begin + static_cast<uint64_t>(info.RegionSize);
  if (address + size > region_end) {
    ++tls_stats.rejected;
    return false;
  }
  RememberRegion(region_begin, region_end);
  memcpy(out, reinterpret_cast<const void*>(address), size);
  return true;
}

static bool ReadU64(uint64_t address, uint64_t* out) { return Read(address, out); }
static bool ReadU32(uint64_t address, uint32_t* out) { return Read(address, out); }
static bool ReadU16(uint64_t address, uint16_t* out) { return Read(address, out); }

// ----------------------------------------------------------- FName decode ----
std::string Universe::DecodeName(uint32_t name_id) const {
  uint32_t block = name_id >> layout_.fname_block_offset_bits;
  uint32_t offset = name_id & 0xFFFFu;
  uint64_t block_base = 0;
  if (!ReadU64(namepool_ + layout_.namepool_blocks + block * 8ull, &block_base) ||
      block_base == 0) {
    return std::string();
  }
  uint64_t entry = block_base +
                   static_cast<uint64_t>(offset) * layout_.fname_entry_stride;
  uint16_t header = 0;
  if (!ReadU16(entry, &header)) {
    return std::string();
  }
  bool wide = (header & layout_.fname_header_is_wide_mask) != 0;
  uint32_t length = (header >> layout_.fname_header_len_shift) &
                    layout_.fname_header_len_mask;
  if (length == 0) {
    return std::string();
  }
  // The 10-bit length field bounds this at 1023 by construction, so even a
  // garbage header cannot turn this into an unbounded read.
  uint64_t data = entry + layout_.fname_entry_header_size;
  if (wide) {
    std::vector<wchar_t> buffer(length + 1, 0);
    if (!ReadBytes(data, buffer.data(), static_cast<size_t>(length) * 2)) {
      return std::string();
    }
    std::string narrow;
    narrow.reserve(length);
    for (uint32_t i = 0; i < length; ++i) {
      wchar_t c = buffer[i];
      // Names that reach identity comparisons are ASCII by construction; a
      // non-ASCII character means this is not a name we are looking for, and
      // mangling it is better than pretending it decoded.
      narrow.push_back(c < 128 ? static_cast<char>(c) : '?');
    }
    return narrow;
  }
  std::string narrow(length, '\0');
  if (!ReadBytes(data, &narrow[0], length)) {
    return std::string();
  }
  return narrow;
}

// --------------------------------------------------------------- the walk ----
bool Universe::Build(Failure* failure) {
  objects_.clear();
  // One walk, one cache. See ResetReadCache's note on why it does not persist.
  ResetReadCache();
  uint64_t objects_ptr = 0;
  int32_t num_elements = 0;
  if (!ReadU64(guobjectarray_ + layout_.guobjectarray_objects, &objects_ptr) ||
      objects_ptr == 0) {
    failure->Set("GUObjectArray::Objects is not readable; the binding profile "
                 "does not describe this process");
    return false;
  }
  if (!Read(guobjectarray_ + layout_.guobjectarray_num_elements, &num_elements) ||
      num_elements <= 0 || num_elements > 40'000'000) {
    failure->Set("GUObjectArray::NumElements is out of range");
    return false;
  }

  objects_.reserve(static_cast<size_t>(num_elements));
  for (int32_t index = 0; index < num_elements; ++index) {
    // FChunkedFixedUObjectArray::GetObjectPtr's own arithmetic.
    uint32_t chunk = static_cast<uint32_t>(index) >> 16;
    uint32_t within = static_cast<uint32_t>(index) & 0xFFFFu;
    uint64_t chunk_base = 0;
    if (!ReadU64(objects_ptr + static_cast<uint64_t>(chunk) * 8, &chunk_base) ||
        chunk_base == 0) {
      // A never-allocated chunk is normal, not an error.
      index = ((static_cast<int32_t>(chunk) + 1) << 16) - 1;
      continue;
    }
    uint64_t item = chunk_base +
                    static_cast<uint64_t>(within) * layout_.fuobjectitem_size;
    uint64_t object = 0;
    if (!ReadU64(item + layout_.fuobjectitem_object, &object) || object == 0) {
      continue;   // a freed or never-used slot
    }

    ObjectInfo info;
    info.address = object;
    ReadU64(object + layout_.object_class_private, &info.class_ptr);
    ReadU64(object + layout_.object_outer_private, &info.outer_ptr);
    if (ReadU32(object + layout_.object_name_private, &info.name_id)) {
      info.name = DecodeName(info.name_id);
      info.name_ok = !info.name.empty();
    }
    objects_.emplace(object, info);
  }

  if (objects_.size() < 1000) {
    failure->Set("only " + std::to_string(objects_.size()) +
                 " objects were readable; the object array is not where the "
                 "bindings say it is");
    return false;
  }
  return true;
}

// -------------------------------------------------------------- lookups ----
uint64_t Universe::One(const std::string& name, const std::string& class_name,
                       const char* label, Failure* failure) const {
  std::vector<uint64_t> hits;
  for (const auto& entry : objects_) {
    const ObjectInfo& info = entry.second;
    if (!info.name_ok || info.name != name) {
      continue;
    }
    if (ClassNameOf(info.address) != class_name) {
      continue;
    }
    hits.push_back(info.address);
    if (hits.size() > 4) {
      break;   // enough to report ambiguity; no reason to keep counting
    }
  }
  if (hits.empty()) {
    failure->Set(std::string(label) + ": no object named '" + name +
                 "' of class '" + class_name + "' exists in this process");
    return 0;
  }
  if (hits.size() > 1) {
    // Refused, not chosen. There is no discriminator for this lookup, and
    // taking the first would mean the answer depends on hash-table order.
    failure->Set(std::string(label) + ": " + std::to_string(hits.size()) +
                 " objects named '" + name + "' of class '" + class_name +
                 "' -- ambiguous, and no proven discriminator distinguishes "
                 "them, so this is refused rather than guessed");
    return 0;
  }
  return hits.front();
}

std::vector<uint64_t> Universe::AllOfClass(uint64_t class_ptr) const {
  std::vector<uint64_t> out;
  if (class_ptr == 0) {
    return out;
  }
  for (const auto& entry : objects_) {
    if (entry.second.class_ptr == class_ptr) {
      out.push_back(entry.second.address);
    }
  }
  // Sorted so a report of an ambiguous set is the same on every run.
  std::sort(out.begin(), out.end());
  return out;
}

bool Universe::DerivesFrom(uint64_t derived, uint64_t base, int max_hops,
                           std::string* chain, bool* incomplete) const {
  if (incomplete != nullptr) {
    *incomplete = false;
  }
  uint64_t current = derived;
  for (int hop = 0; hop < max_hops && current != 0; ++hop) {
    if (chain != nullptr) {
      if (!chain->empty()) {
        chain->append(" -> ");
      }
      chain->append(NameOf(current));
    }
    if (current == base) {
      return true;
    }
    uint64_t super = 0;
    if (!ReadU64(current + layout_.ustruct_super, &super)) {
      // The link is not readable: the chain stops here without having been
      // walked to a root. That is unfinished, not wrong.
      if (incomplete != nullptr) {
        *incomplete = true;
      }
      return false;
    }
    if (super == 0) {
      // Reached a class with no Super without meeting *base*. UObject itself
      // legitimately has none -- so this is only "unfinished" when the walk
      // stopped at its very first hop, which is what a class whose Super has
      // not been populated yet looks like.
      if (incomplete != nullptr && hop == 0) {
        *incomplete = true;
      }
      return false;
    }
    current = super;
  }
  return false;
}

uint64_t Universe::FunctionOn(uint64_t class_ptr, const std::string& name,
                              const char* label, Failure* failure) const {
  if (class_ptr == 0) {
    failure->Set(std::string(label) + ": no class to search");
    return 0;
  }
  uint64_t child = 0;
  if (!ReadU64(class_ptr + layout_.ustruct_children, &child)) {
    failure->Set(std::string(label) + ": the class has no readable Children");
    return 0;
  }
  std::vector<uint64_t> hits;
  // Bounded: a corrupt Next chain must terminate rather than spin in a frame.
  for (int hop = 0; hop < 4096 && child != 0; ++hop) {
    const ObjectInfo* info = At(child);
    if (info != nullptr && info->name_ok && info->name == name) {
      hits.push_back(child);
    }
    uint64_t next = 0;
    if (!ReadU64(child + layout_.ufield_next, &next)) {
      break;
    }
    child = next;
  }
  if (hits.empty()) {
    failure->Set(std::string(label) + ": '" + name +
                 "' is not on that class's Children chain");
    return 0;
  }
  if (hits.size() > 1) {
    failure->Set(std::string(label) + ": '" + name + "' appears " +
                 std::to_string(hits.size()) + " times on one class");
    return 0;
  }
  return hits.front();
}

// -------------------------------------------------------------- anchors ----
bool ResolveAnchors(const Universe& universe, const Request& request,
                    Anchors* out, Failure* failure) {
  const Layout& layout = universe.layout();
  out->missing.clear();

  // One place decides whether a missing anchor is fatal: it is fatal only when
  // its phase is at or below what the caller asked for. Survey mode never
  // fails, which is how the phase column below was measured in the first place.
  auto need = [&](uint64_t* slot, const char* name, const char* class_name,
                  Phase phase, const char* label) {
    Failure local;
    uint64_t found = universe.One(name, class_name, label, &local);
    if (local.failed) {
      out->missing.push_back(label);
      if (!request.survey && phase <= request.require) {
        failure->Set(local.what + " [" + PhaseName(phase) + " phase]");
      }
      *slot = 0;
      return false;
    }
    *slot = found;
    return true;
  };

  // ---- startup: engine types and the Kismet libraries ------------------
  need(&out->transient_package, "/Engine/Transient", "Package", Phase::kStartup,
       "transient package");
  need(&out->datatable_class, "DataTable", "Class", Phase::kStartup, "UDataTable");
  need(&out->composite_class, "CompositeDataTable", "Class", Phase::kStartup,
       "UCompositeDataTable");
  need(&out->texture2d_class, "Texture2D", "Class", Phase::kStartup, "UTexture2D");
  need(&out->staticmesh_class, "StaticMesh", "Class", Phase::kStartup,
       "UStaticMesh");
  need(&out->actor_class, "Actor", "Class", Phase::kStartup, "AActor");
  need(&out->cdo_gameplaystatics, "Default__GameplayStatics", "GameplayStatics",
       Phase::kStartup, "GameplayStatics CDO");
  need(&out->cdo_stringlib, "Default__KismetStringLibrary", "KismetStringLibrary",
       Phase::kStartup, "StringLibrary CDO");
  need(&out->cdo_textlib, "Default__KismetTextLibrary", "KismetTextLibrary",
       Phase::kStartup, "TextLibrary CDO");
  need(&out->cdo_syslib, "Default__KismetSystemLibrary", "KismetSystemLibrary",
       Phase::kStartup, "SystemLibrary CDO");

  uint64_t gs_class = 0, sl_class = 0, tl_class = 0, sy_class = 0;
  need(&gs_class, "GameplayStatics", "Class", Phase::kStartup, "GameplayStatics");
  need(&sl_class, "KismetStringLibrary", "Class", Phase::kStartup,
       "KismetStringLibrary");
  need(&tl_class, "KismetTextLibrary", "Class", Phase::kStartup,
       "KismetTextLibrary");
  need(&sy_class, "KismetSystemLibrary", "Class", Phase::kStartup,
       "KismetSystemLibrary");

  // ---- content: the game's own tables and Blueprints --------------------
  need(&out->item_list, "ItemList", "DataTable", Phase::kContent, "ItemList");
  need(&out->master_item_list, "MasterItemList", "CompositeDataTable",
       Phase::kContent, "MasterItemList");
  need(&out->world_class, request.world_item_class.c_str(),
       "BlueprintGeneratedClass", Phase::kContent, "world item class");
  need(&out->cdo_sgkfunctions, "Default__BP_SGKFunctions_C", "BP_SGKFunctions_C",
       Phase::kContent, "SGK CDO");

  uint64_t sgk_class = 0, mi_class = 0, pi_class = 0;
  need(&sgk_class, "BP_SGKFunctions_C", "BlueprintGeneratedClass",
       Phase::kContent, "BP_SGKFunctions");
  need(&mi_class, "BP_MasterInventory_C", "BlueprintGeneratedClass",
       Phase::kContent, "BP_MasterInventory_C");
  need(&pi_class, "BP_PlayerInventory_C", "BlueprintGeneratedClass",
       Phase::kContent, "BP_PlayerInventory_C");

  if (failure->failed) {
    return false;
  }

  // A function is only resolvable once its class is. Each is tagged with the
  // phase of the class that owns it, for the same reason.
  auto need_fn = [&](uint64_t* slot, uint64_t cls, const char* name,
                     Phase phase, const char* label) {
    if (cls == 0) {
      out->missing.push_back(label);
      if (!request.survey && phase <= request.require) {
        failure->Set(std::string(label) + ": its class did not resolve");
      }
      *slot = 0;
      return;
    }
    Failure local;
    uint64_t found = universe.FunctionOn(cls, name, label, &local);
    if (local.failed) {
      out->missing.push_back(label);
      if (!request.survey && phase <= request.require) {
        failure->Set(local.what);
      }
      *slot = 0;
      return;
    }
    *slot = found;
  };

  need_fn(&out->fn_spawn_object, gs_class, "SpawnObject", Phase::kStartup,
          "GameplayStatics::SpawnObject");
  need_fn(&out->fn_conv_str_to_name, sl_class, "Conv_StringToName",
          Phase::kStartup, "KismetStringLibrary::Conv_StringToName");
  need_fn(&out->fn_str_to_text, tl_class, "Conv_StringToText", Phase::kStartup,
          "KismetTextLibrary::Conv_StringToText");
  need_fn(&out->fn_text_to_str, tl_class, "Conv_TextToString", Phase::kStartup,
          "KismetTextLibrary::Conv_TextToString");
  need_fn(&out->fn_load_asset_blocking, sy_class, "LoadAsset_Blocking",
          Phase::kStartup, "KismetSystemLibrary::LoadAsset_Blocking");
  need_fn(&out->fn_soft_to_string, sy_class, "Conv_SoftObjectReferenceToString",
          Phase::kStartup, "KismetSystemLibrary::Conv_SoftObjectReferenceToString");
  need_fn(&out->fn_sgk_itemdetails, sgk_class, "SGK ItemDetails", Phase::kContent,
          "BP_SGKFunctions::SGK ItemDetails");
  need_fn(&out->fn_additem, mi_class, "AddItem", Phase::kContent,
          "BP_MasterInventory_C::AddItem");
  need_fn(&out->fn_removeitem, mi_class, "RemoveItem", Phase::kContent,
          "BP_MasterInventory_C::RemoveItem");

  if (failure->failed) {
    return false;
  }

  // The world class must actually be an Actor, or the property holding it would
  // contain a class its MetaClass forbids -- a type error the engine cannot
  // catch on our behalf. Only checkable once both resolved.
  //
  // TWO WAYS TO FAIL THIS, AND THEY ARE NOT THE SAME THING
  // ------------------------------------------------------
  // MEASURED, and this block is the fix for what it found: sampling the
  // resolver across a menu -> gameplay load caught one instant, out of
  // thirteen samples, where BP_StaticMasterItem_C existed and was named while
  // its Super link was still null. The first version of this check called that
  // "does not derive from Actor" and returned a hard failure -- reporting a
  // perfectly healthy game as broken, and doing it from SURVEY mode, whose
  // entire contract is to report what is present and fail at nothing.
  //
  // So the two outcomes are now separated. A chain that stops at its first hop
  // is a class the engine has not finished linking: transient, and the honest
  // answer is that the anchor is not resolved YET. A chain that reaches a
  // different root is a real type error. Neither is fatal in survey mode, and
  // neither is fatal below the phase that needs the class -- because a caller
  // that did not ask for content should not be stopped by a fact about content.
  if (out->world_class != 0 && out->actor_class != 0) {
    std::string chain;
    bool incomplete = false;
    if (!universe.DerivesFrom(out->world_class, out->actor_class, 24, &chain,
                              &incomplete)) {
      const std::string reason =
          incomplete
              ? request.world_item_class +
                    " is present but not yet linked to its Super (chain: " +
                    chain + "); the engine is still building it"
              : request.world_item_class +
                    " does not derive from Actor (chain: " + chain + ")";
      // Not resolved. Reported, never accepted: a half-linked class handed to
      // the Items backend would be worse than one reported absent.
      out->world_class = 0;
      out->missing.push_back(reason);
      if (!request.survey && Phase::kContent <= request.require) {
        failure->Set(reason + " [content phase]");
        return false;
      }
    }
  }

  // ---- gameplay: the live player inventory ------------------------------
  //
  // Resolved by CLASS, then narrowed by a discriminator already proven: its
  // Outer is a live BP_SGKController_C. Neither half alone is enough -- the
  // class has a CDO and template instances, and the controller is what makes
  // one of them the player's.
  out->player_inventory = 0;
  out->player_inventory_present = false;
  out->player_inventory_outer = 0;
  if (pi_class != 0) {
    std::vector<uint64_t> live;
    for (uint64_t candidate : universe.AllOfClass(pi_class)) {
      std::string name = universe.NameOf(candidate);
      if (name.rfind("Default__", 0) == 0 ||
          name.find("GEN_VARIABLE") != std::string::npos) {
        continue;
      }
      const ObjectInfo* info = universe.At(candidate);
      if (info == nullptr || info->outer_ptr == 0) {
        continue;
      }
      if (universe.ClassNameOf(info->outer_ptr) == "BP_SGKController_C") {
        live.push_back(candidate);
      }
    }
    if (live.size() == 1) {
      out->player_inventory = live.front();
      out->player_inventory_present = true;
      const ObjectInfo* found = universe.At(out->player_inventory);
      out->player_inventory_outer = found != nullptr ? found->outer_ptr : 0;
    } else if (live.size() > 1) {
      // Two live player inventories is not a state this framework understands,
      // and picking one would be picking which player to write to.
      failure->Set("expected at most one live player inventory on a live "
                   "BP_SGKController_C, found " + std::to_string(live.size()));
      return false;
    }
  }
  if (!out->player_inventory_present) {
    out->missing.push_back("live player inventory");
    if (!request.survey && request.require >= Phase::kGameplay) {
      failure->Set("no live player inventory: the process is not in gameplay");
      return false;
    }
  }

  // ---- table facts, only once the tables exist --------------------------
  if (out->item_list != 0 && out->master_item_list != 0) {
    uint64_t master_class = 0;
    if (!ReadU64(out->master_item_list + layout.object_class_private,
                 &master_class) || master_class != out->composite_class) {
      failure->Set("MasterItemList is not a UCompositeDataTable");
      return false;
    }
    if (!ReadU64(out->item_list, &out->plain_vtable) ||
        !ReadU64(out->master_item_list, &out->composite_vtable)) {
      failure->Set("a table vtable pointer is not readable");
      return false;
    }
    uint64_t master_row_struct = 0;
    if (!ReadU64(out->item_list + layout.datatable_rowstruct, &out->row_struct) ||
        !ReadU64(out->master_item_list + layout.datatable_rowstruct,
                 &master_row_struct)) {
      failure->Set("a table RowStruct pointer is not readable");
      return false;
    }
    if (out->row_struct == 0 || out->row_struct != master_row_struct) {
      failure->Set("ItemList and MasterItemList disagree about their RowStruct");
      return false;
    }
    if (!Read(out->row_struct + layout.ustruct_properties_size,
              &out->row_struct_size) || out->row_struct_size == 0) {
      failure->Set("the RowStruct has no readable size");
      return false;
    }
    if (!ReadU64(out->row_struct, &out->struct_vtable)) {
      failure->Set("the RowStruct vtable is not readable");
      return false;
    }
  }

  // The highest phase actually OBSERVED. Computed before scoping, because it
  // describes the process, not the request -- a caller asking for startup at a
  // menu that carries content should still be told the content is there.
  out->reached = Phase::kStartup;
  if (out->item_list != 0 && out->master_item_list != 0 && out->row_struct != 0) {
    out->reached = Phase::kContent;
  }
  if (out->player_inventory_present) {
    out->reached = Phase::kGameplay;
  }

  // ---- phase scoping: a result carries only what its phase guarantees ----
  //
  // See Resolver.h. Anchors above the requested phase are withheld even when
  // present, and recorded as observed-but-out-of-phase rather than as missing,
  // because they are not missing -- their lifetime simply ends before the
  // caller's does.
  //
  // Survey is exempt by contract.
  auto withhold = [&](uint64_t* slot, const char* label) {
    if (*slot != 0) {
      out->observed_out_of_phase.push_back(label);
      *slot = 0;
    }
  };

  if (!request.survey && request.require < Phase::kContent) {
    withhold(&out->item_list, "ItemList");
    withhold(&out->master_item_list, "MasterItemList");
    withhold(&out->row_struct, "S_ItemDetails RowStruct");
    withhold(&out->world_class, "world item class");
    withhold(&out->cdo_sgkfunctions, "BP_SGKFunctions CDO");
    withhold(&out->fn_sgk_itemdetails, "BP_SGKFunctions::SGK ItemDetails");
    withhold(&out->fn_additem, "BP_MasterInventory_C::AddItem");
    withhold(&out->fn_removeitem, "BP_MasterInventory_C::RemoveItem");
    // Facts DERIVED from the tables go with the tables. Leaving a row width or
    // a vtable behind would let a caller believe it had validated a table it
    // was not given.
    withhold(&out->plain_vtable, "ItemList vtable");
    withhold(&out->composite_vtable, "MasterItemList vtable");
    withhold(&out->struct_vtable, "RowStruct vtable");
    if (out->row_struct_size != 0) {
      out->observed_out_of_phase.push_back("S_ItemDetails width");
      out->row_struct_size = 0;
    }
  }

  if (!request.survey && request.require < Phase::kGameplay) {
    withhold(&out->player_inventory, "live player inventory");
    if (out->player_inventory_present) {
      out->player_inventory_present = false;
      out->player_inventory_outer = 0;
    }
  }
  return !failure->failed;
}

}  // namespace resolve
}  // namespace misery
