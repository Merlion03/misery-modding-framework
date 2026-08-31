// ResolverDump.cpp -- run the in-process resolver and report what it found.
//
// WHY THIS EXPORT EXISTS
// ----------------------
// The C++ resolver replaces a Python oracle that has been correct for four
// stages. Replacing a working oracle with a rewrite is exactly the moment to be
// suspicious of the rewrite, so during development both run against the SAME
// live process and their answers are compared object-for-object.
//
// This export is the C++ half of that comparison and nothing else. The
// production path does not call it: the runtime bootstrap uses the resolver
// directly, and this file could be deleted without changing what ships. It is
// kept because a resolver that once agreed with the oracle, in a repository
// where the oracle still exists, can be re-checked after any change.
#include "Resolver.h"
#include "ResolveOnGameThread.h"

#include <stdint.h>
#include <string.h>
#include <windows.h>

#include <string>

#define RESOLVE_IO_MAGIC 0x4D42504C52535600ULL   // "MBPLRSV\0"
// Proto 2: resolution moved onto the game thread, so the carrier bindings are
// inputs and the frame cost is an output. Proto 1 callers are refused rather
// than reinterpreted -- a struct read at the wrong layout is worse than a
// rejection.
#define RESOLVE_IO_PROTO 2u

#pragma pack(push, 1)
struct ResolveIo {
  uint64_t magic;
  uint32_t proto;
  uint32_t struct_size;
  // Inputs: the two roots, as absolute addresses. In production these come from
  // the binding profile's RVAs plus the module base; here the controller
  // supplies them so both resolvers are given identical inputs and any
  // disagreement is about the RESOLUTION, not about where they started.
  uint64_t guobjectarray;
  uint64_t namepool;
  // The game-thread carrier, from the same binding profile production uses.
  // Without these nothing runs: resolution is not permitted off the game
  // thread, so a caller that cannot supply the carrier gets a refusal.
  uint64_t add_ticker;
  uint64_t get_core_ticker;
  uint64_t fmemory_malloc;
  uint8_t sig_add[16];
  uint8_t sig_get[16];
  uint8_t sig_malloc[16];
  uint32_t require_phase;      // 0 startup, 1 content, 2 gameplay, 3 survey
  uint32_t timeout_ms;         // how long to wait for the game thread to drain
  uint32_t done;
  int32_t rc;
  uint32_t object_count;
  // What the resolution cost on the game thread. Reported every call, because
  // "is a whole walk affordable here?" is a question to keep answering rather
  // than to settle once.
  uint32_t queued_us;
  uint32_t build_us;
  uint32_t resolve_us;
  uint32_t reads;
  uint32_t vqueries;
  uint32_t cache_hits;
  uint32_t game_thread_id;
  char world_item_class[128];
  char error[1024];
  char json[8192];
};
#pragma pack(pop)

namespace {

void Append(std::string* out, const char* key, uint64_t value) {
  char buffer[64];
  _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "\"%s\":%llu", key,
              static_cast<unsigned long long>(value));
  if (!out->empty() && out->back() != '{') {
    out->append(",");
  }
  out->append(buffer);
}

}  // namespace

extern "C" __declspec(dllexport) unsigned long Stage5ResolveDump(void* p) {
  ResolveIo* io = static_cast<ResolveIo*>(p);
  if (io == nullptr || io->magic != RESOLVE_IO_MAGIC ||
      io->proto != RESOLVE_IO_PROTO ||
      io->struct_size != static_cast<uint32_t>(sizeof(ResolveIo))) {
    return 0xFFFFFFFFu;
  }
  io->done = 0;
  io->rc = -1;
  io->error[0] = '\0';
  io->json[0] = '\0';

  // The carrier first. Resolution does not happen off the game thread, so this
  // is a precondition rather than an optimisation: no carrier, no answer.
  misery::gamethread::CarrierInput carrier;
  carrier.add_ticker = io->add_ticker;
  carrier.get_core_ticker = io->get_core_ticker;
  carrier.fmemory_malloc = io->fmemory_malloc;
  memcpy(carrier.sig_add, io->sig_add, sizeof(carrier.sig_add));
  memcpy(carrier.sig_get, io->sig_get, sizeof(carrier.sig_get));
  memcpy(carrier.sig_malloc, io->sig_malloc, sizeof(carrier.sig_malloc));

  std::string error;
  if (!misery::gamethread::Ensure(carrier, &error)) {
    strncpy_s(io->error, sizeof(io->error), error.c_str(), _TRUNCATE);
    io->rc = 3;
    io->done = 1;
    return 0;
  }

  misery::resolve::Request request;
  if (io->require_phase >= 3) {
    request.survey = true;
    request.require = misery::resolve::Phase::kStartup;
  } else {
    request.require = static_cast<misery::resolve::Phase>(io->require_phase);
  }
  if (io->world_item_class[0] != '\0') {
    request.world_item_class = io->world_item_class;
  }

  misery::resolve::Anchors anchors;
  misery::resolve::Failure failure;
  misery::gamethread::Cost cost;
  const uint32_t timeout = io->timeout_ms != 0 ? io->timeout_ms : 30000u;
  const bool ok = misery::gamethread::Resolve(
      io->guobjectarray, io->namepool, request, &anchors, &failure, timeout,
      &cost, &error);

  io->object_count = cost.objects;
  io->queued_us = cost.queued_us;
  io->build_us = cost.build_us;
  io->resolve_us = cost.resolve_us;
  io->reads = cost.reads;
  io->vqueries = cost.vqueries;
  io->cache_hits = cost.cache_hits;
  io->game_thread_id = cost.thread_id;

  if (!ok) {
    strncpy_s(io->error, sizeof(io->error),
              failure.failed ? failure.what.c_str() : error.c_str(), _TRUNCATE);
    // 1 = the walk itself refused (a root that does not describe this process);
    // 2 = anchors did not resolve; 4 = the game thread never drained it.
    io->rc = failure.failed ? 2 : 4;
    io->done = 1;
    return 0;
  }

  std::string json = "{";
  Append(&json, "object_count", cost.objects);
  Append(&json, "item_list", anchors.item_list);
  Append(&json, "master_item_list", anchors.master_item_list);
  Append(&json, "row_struct", anchors.row_struct);
  Append(&json, "row_struct_size", anchors.row_struct_size);
  Append(&json, "transient_package", anchors.transient_package);
  Append(&json, "datatable_class", anchors.datatable_class);
  Append(&json, "composite_class", anchors.composite_class);
  Append(&json, "texture2d_class", anchors.texture2d_class);
  Append(&json, "staticmesh_class", anchors.staticmesh_class);
  Append(&json, "actor_class", anchors.actor_class);
  Append(&json, "world_class", anchors.world_class);
  Append(&json, "cdo_gameplaystatics", anchors.cdo_gameplaystatics);
  Append(&json, "cdo_stringlib", anchors.cdo_stringlib);
  Append(&json, "cdo_textlib", anchors.cdo_textlib);
  Append(&json, "cdo_syslib", anchors.cdo_syslib);
  Append(&json, "cdo_sgkfunctions", anchors.cdo_sgkfunctions);
  Append(&json, "fn_spawn_object", anchors.fn_spawn_object);
  Append(&json, "fn_conv_str_to_name", anchors.fn_conv_str_to_name);
  Append(&json, "fn_str_to_text", anchors.fn_str_to_text);
  Append(&json, "fn_text_to_str", anchors.fn_text_to_str);
  Append(&json, "fn_load_asset_blocking", anchors.fn_load_asset_blocking);
  Append(&json, "fn_soft_to_string", anchors.fn_soft_to_string);
  Append(&json, "fn_sgk_itemdetails", anchors.fn_sgk_itemdetails);
  Append(&json, "fn_additem", anchors.fn_additem);
  Append(&json, "fn_removeitem", anchors.fn_removeitem);
  Append(&json, "player_inventory", anchors.player_inventory);
  Append(&json, "player_inventory_present",
         anchors.player_inventory_present ? 1u : 0u);
  Append(&json, "player_inventory_outer", anchors.player_inventory_outer);
  Append(&json, "plain_vtable", anchors.plain_vtable);
  Append(&json, "composite_vtable", anchors.composite_vtable);
  Append(&json, "struct_vtable", anchors.struct_vtable);
  Append(&json, "reached_phase", static_cast<uint64_t>(anchors.reached));
  Append(&json, "queued_us", cost.queued_us);
  Append(&json, "build_us", cost.build_us);
  Append(&json, "resolve_us", cost.resolve_us);
  Append(&json, "reads", cost.reads);
  Append(&json, "vqueries", cost.vqueries);
  Append(&json, "cache_hits", cost.cache_hits);
  Append(&json, "game_thread_id", cost.thread_id);
  json.append(",\"missing\":[");
  for (size_t i = 0; i < anchors.missing.size(); ++i) {
    if (i != 0) json.append(",");
    json.append("\"").append(anchors.missing[i]).append("\"");
  }
  // Present in the process, withheld because the caller asked for an earlier
  // phase. Kept separate from `missing` so the diagnostics never say "absent"
  // about something the walk demonstrably found.
  json.append("],\"observed_out_of_phase\":[");
  for (size_t i = 0; i < anchors.observed_out_of_phase.size(); ++i) {
    if (i != 0) json.append(",");
    json.append("\"").append(anchors.observed_out_of_phase[i]).append("\"");
  }
  json.append("]}");

  strncpy_s(io->json, sizeof(io->json), json.c_str(), _TRUNCATE);
  io->rc = 0;
  io->done = 1;
  return 0;
}

extern "C" __declspec(dllexport) unsigned long Stage5ResolveIoSize(void) {
  return static_cast<unsigned long>(sizeof(ResolveIo));
}
