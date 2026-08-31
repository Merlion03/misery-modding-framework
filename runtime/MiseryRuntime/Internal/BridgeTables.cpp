// BridgeTables.cpp -- the capability tables behind MiseryBridge.h.
//
// This is the native side of the Stage 4.5 contracts: the same subsystems the
// Python reference implements, reachable through the frozen root.
//
// THREE RULES HOLD AT EVERY ENTRY POINT, WITHOUT EXCEPTION
// --------------------------------------------------------
// 1. GAME THREAD ONLY. Every function checks the calling thread and returns
//    MB_E_WRONG_THREAD otherwise. The engine state behind these calls has
//    game-thread affinity and has been proven only there. A third-party mod
//    calling from a thread pool must get a defined diagnostic, not corruption
//    that shows up somewhere else half a second later.
// 2. NO EXCEPTION LEAVES. Every function body is wrapped, because a C++
//    exception reaching the CLR -- or a managed one reaching C++ frames not
//    compiled for it -- is undefined behaviour rather than an error.
// 3. THE ARENA RESETS. Each call resets this thread's string arena, which is
//    what implements "OUT strings are valid until your next call".
//
// THE ITEMS BACKEND IS INJECTED, NOT LINKED
// -----------------------------------------
// Registering an item means writing a row into MISERY's live aggregate
// DataTable through the path Stage 2 proved, and that path needs reflected
// offsets and resolved object pointers that the research instruments compute.
// So this file declares what it needs of an items backend and never links one:
// the standalone harness installs a recording backend and proves the lifecycle
// with no game at all, and the in-game runtime installs the real one. It is the
// same inversion the Python platform used, for the same reason -- most of the
// guarantees are checkable without MISERY, and they should be checked there.
#include "BridgeCore.h"

#include <string.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

extern "C" unsigned long __stdcall GetCurrentThreadId(void);

namespace misery {
namespace bridge {

// ---------------------------------------------------------------- arena ----
StringArena& ThreadArena() {
  static thread_local StringArena arena;
  return arena;
}

// ------------------------------------------------------------- utilities ----
static std::string ToStd(MbStr text) {
  if (text.data == nullptr || text.length <= 0) {
    return std::string();
  }
  return std::string(text.data, static_cast<size_t>(text.length));
}

// ---------------------------------------------------------------- state ----
struct EventDeclaration {
  std::string owner;                 // "" for platform events
  std::vector<MbHandle> subscribers;
};

struct ServiceRecord {
  std::string provider;
  std::string version;
  std::vector<std::string> methods;
};

struct Platform {
  Core core;
  MbTrampoline trampoline = nullptr;
  unsigned long game_thread = 0;
  bool shutting_down = false;

  std::map<std::string, EventDeclaration> events;
  std::map<std::string, ServiceRecord> services;
  std::map<std::string, std::string> settings;      // "<mod>/<key>" -> value
  std::map<std::string, std::string> commands;      // name -> owner

  // Counters the acceptance reads, so "nothing was retained" is measured
  // rather than asserted.
  uint64_t dispatches = 0;
  uint64_t trampoline_calls = 0;
  uint64_t handler_faults = 0;
  uint64_t log_records = 0;
  std::vector<std::string> log_tail;

  MbHandle host_handle = MB_INVALID_HANDLE;
};

static Platform& P() {
  static Platform platform;
  return platform;
}

// The injected items backend. See the header comment.
extern "C" {
typedef int (*MbItemsRegisterFn)(const char* mod_id, const char* declaration_json,
                                 char* out_row_name, int out_capacity);
typedef int (*MbItemsUnregisterFn)(const char* mod_id, const char* row_name);
}

struct ItemsBackend {
  MbItemsRegisterFn register_item = nullptr;
  MbItemsUnregisterFn unregister_item = nullptr;
};

static ItemsBackend& Items() {
  static ItemsBackend backend;
  return backend;
}

// ------------------------------------------------------------ guardrails ----
#define BRIDGE_ENTER(out_error)                                              \
  ThreadArena().Reset();                                                     \
  ClearError(out_error);                                                     \
  if (P().game_thread != 0 &&                                                \
      GetCurrentThreadId() != P().game_thread) {                             \
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_WRONG_THREAD,               \
                "this API must be called on the game thread; it was called " \
                "from another thread and the engine state behind it is not " \
                "valid there");                                              \
  }

#define BRIDGE_TRY try {
#define BRIDGE_CATCH(out_error)                                              \
  }                                                                          \
  catch (const std::exception& error) {                                      \
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_INVALID_ARGUMENT,           \
                std::string("native exception: ") + error.what());           \
  }                                                                          \
  catch (...) {                                                              \
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_INVALID_ARGUMENT,           \
                "unknown native exception");                                 \
  }

// ------------------------------------------------------------------ log ----
static MbStatus LogWrite(MbHandle mod_handle, int32_t level, MbStr message,
                         MbStr fields_json, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LOG, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  if (level < MB_LOG_TRACE || level > MB_LOG_ERROR) {
    return Fail(out_error, MB_SUB_LOG, MB_E_INVALID_ARGUMENT,
                "unknown log level", mod->mod_id);
  }
  // The mod_id is stamped from the RECORD, never from anything the caller
  // said, so a mod cannot attribute its noise to another.
  std::string line = mod->mod_id + "|" + std::to_string(level) + "|" +
                     ToStd(message);
  if (fields_json.length > 0) {
    line += "|" + ToStd(fields_json);
  }
  P().log_records += 1;
  P().log_tail.push_back(line);
  if (P().log_tail.size() > 512) {
    P().log_tail.erase(P().log_tail.begin());
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// --------------------------------------------------------------- events ----
static void ReleaseDeclaration(void* body, uint64_t payload) {
  (void)payload;
  std::string* name = static_cast<std::string*>(body);
  P().events.erase(*name);
  delete name;
}

static void ReleaseSubscription(void* body, uint64_t payload) {
  std::string* name = static_cast<std::string*>(body);
  auto it = P().events.find(*name);
  if (it != P().events.end()) {
    std::vector<MbHandle>& subscribers = it->second.subscribers;
    subscribers.erase(std::remove(subscribers.begin(), subscribers.end(),
                                  static_cast<MbHandle>(payload)),
                      subscribers.end());
  }
  delete name;
}

static bool NamespaceMatches(const std::string& name, const std::string& owner,
                             std::string* local) {
  size_t colon = name.find(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= name.size()) {
    return false;
  }
  if (name.compare(0, colon, owner) != 0) {
    return false;
  }
  *local = name.substr(colon + 1);
  return local->find(':') == std::string::npos;
}

static MbStatus EventsDeclare(MbHandle mod_handle, MbStr name, MbStr detail,
                              MbHandle* out_declaration, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  (void)detail;
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  std::string full = ToStd(name);
  std::string local;
  if (!NamespaceMatches(full, mod->mod_id, &local)) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_INVALID_ARGUMENT,
                "an event belongs to the namespace that declares it: '" + full +
                    "' is not '" + mod->mod_id + ":<name>'",
                mod->mod_id);
  }
  if (P().events.count(full) != 0) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_ALREADY_EXISTS,
                "'" + full + "' is already declared", mod->mod_id);
  }
  EventDeclaration declaration;
  declaration.owner = mod->mod_id;
  P().events[full] = declaration;
  *out_declaration = P().core.Acquire(*mod, kKindEventDeclaration, full,
                                      ReleaseDeclaration,
                                      new std::string(full), 0);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus EventsSubscribe(MbHandle mod_handle, MbStr name,
                                MbHandle* out_subscription, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  std::string full = ToStd(name);
  auto it = P().events.find(full);
  if (it == P().events.end()) {
    // Refused rather than created implicitly: a typo would otherwise produce a
    // subscription that can never fire, which is the single most common way a
    // bus like this wastes somebody's afternoon.
    return Fail(out_error, MB_SUB_EVENTS, MB_E_NOT_FOUND,
                "no event '" + full + "' is declared", mod->mod_id);
  }
  MbHandle handle = P().core.Acquire(*mod, kKindSubscription, full,
                                     ReleaseSubscription,
                                     new std::string(full), 0);
  // The payload carries the handle so the release can find its own entry.
  Slot* slot = P().core.Resolve(handle, kKindSubscription);
  if (slot != nullptr) {
    slot->payload = handle;
  }
  it->second.subscribers.push_back(handle);
  *out_subscription = handle;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus EventsUnsubscribe(MbHandle subscription, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  if (!P().core.ReleaseOne(subscription)) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_NOT_FOUND,
                "the subscription is not live");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// Dispatch. The shape of this loop IS the lifecycle guarantee.
static int32_t DispatchEvent(const std::string& full, const std::string& payload) {
  auto it = P().events.find(full);
  if (it == P().events.end()) {
    return 0;
  }
  // Copied BEFORE dispatch, so subscribing or unsubscribing inside a handler is
  // legal and lands on the next publish rather than mutating this loop.
  std::vector<MbHandle> captured = it->second.subscribers;
  int32_t ran = 0;
  for (MbHandle handle : captured) {
    // RE-RESOLVED IMMEDIATELY BEFORE THE CALL, not at the top of the loop. A
    // mod unloaded by an earlier handler in this very dispatch fails here.
    Slot* slot = P().core.Resolve(handle, kKindSubscription);
    if (slot == nullptr) {
      continue;
    }
    ModRecord* owner = P().core.FindModBySlot(slot->owner_slot);
    if (owner == nullptr || P().trampoline == nullptr) {
      continue;
    }
    owner->active_frames += 1;
    try {
      // ONE trampoline, in the default load context. Native never holds a
      // pointer into mod code, which is what lets a collectible assembly
      // context actually collect.
      P().trampoline_calls += 1;
      P().trampoline(MB_DISPATCH_EVENT, handle,
                     MbStr{full.c_str(), static_cast<int32_t>(full.size())},
                     MbStr{payload.c_str(),
                           static_cast<int32_t>(payload.size())},
                     0);
      ran += 1;
    } catch (...) {
      // A managed exception must never cross this boundary. The managed
      // trampoline catches its own, but if anything reaches here it is
      // contained and attributed rather than allowed to unwind a game frame.
      P().handler_faults += 1;
      owner->fault_count += 1;
    }
    owner->active_frames -= 1;
  }
  P().dispatches += 1;
  return ran;
}

static MbStatus EventsPublish(MbHandle mod_handle, MbStr name, MbStr payload,
                              int32_t* out_ran, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  std::string full = ToStd(name);
  if (P().events.count(full) == 0) {
    return Fail(out_error, MB_SUB_EVENTS, MB_E_NOT_FOUND,
                "no event '" + full + "' is declared", mod->mod_id);
  }
  int32_t ran = DispatchEvent(full, ToStd(payload));
  if (out_ran != nullptr) {
    *out_ran = ran;
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---------------------------------------------------------------- items ----
struct ItemBody {
  std::string mod_id;
  std::string row_name;
};

static void ReleaseItem(void* body, uint64_t payload) {
  (void)payload;
  ItemBody* item = static_cast<ItemBody*>(body);
  if (Items().unregister_item != nullptr) {
    Items().unregister_item(item->mod_id.c_str(), item->row_name.c_str());
  }
  delete item;
}

static MbStatus ItemsRegister(MbHandle mod_handle, MbStr declaration_json,
                              MbStr* out_row_name, MbHandle* out_item,
                              MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  if (Items().register_item == nullptr) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_NOT_FOUND,
                "no items backend is installed; item registration needs the "
                "live game", mod->mod_id);
  }
  char row[256] = {0};
  std::string declaration = ToStd(declaration_json);
  // The mod_id is passed SEPARATELY and from the record. The declaration cannot
  // choose a namespace, so it cannot register into another mod's.
  int rc = Items().register_item(mod->mod_id.c_str(), declaration.c_str(), row,
                                 static_cast<int>(sizeof(row)));
  if (rc != 0) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_INVALID_ARGUMENT,
                "the items backend refused the registration (code " +
                    std::to_string(rc) + ")",
                mod->mod_id);
  }
  ItemBody* body = new ItemBody();
  body->mod_id = mod->mod_id;
  body->row_name = row;
  *out_item = P().core.Acquire(*mod, kKindItem, body->row_name, ReleaseItem,
                               body, 0);
  if (out_row_name != nullptr) {
    *out_row_name = ThreadArena().Put(body->row_name);
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ItemsUnregister(MbHandle item, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  if (!P().core.ReleaseOne(item)) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_NOT_FOUND,
                "the item handle is not live");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// -------------------------------------------------------------- services ----
static void ReleaseService(void* body, uint64_t payload) {
  (void)payload;
  std::string* name = static_cast<std::string*>(body);
  P().services.erase(*name);
  delete name;
}

static void ReleaseBinding(void* body, uint64_t payload) {
  (void)payload;
  delete static_cast<std::string*>(body);
}

static MbStatus ServicesPublish(MbHandle mod_handle, MbStr name, MbStr version,
                                MbStr methods_json, MbHandle* out_service,
                                MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  std::string full = ToStd(name);
  std::string local;
  if (!NamespaceMatches(full, mod->mod_id, &local)) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_INVALID_ARGUMENT,
                "a service belongs to its publisher's namespace", mod->mod_id);
  }
  if (P().services.count(full) != 0) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_ALREADY_EXISTS,
                "'" + full + "' is already published", mod->mod_id);
  }
  ServiceRecord record;
  record.provider = mod->mod_id;
  record.version = ToStd(version);
  record.methods.push_back(ToStd(methods_json));
  P().services[full] = record;
  *out_service = P().core.Acquire(*mod, kKindService, full, ReleaseService,
                                  new std::string(full), 0);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ServicesBind(MbHandle mod_handle, MbStr name, MbStr requirement,
                             MbHandle* out_binding, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  (void)requirement;
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  std::string full = ToStd(name);
  auto it = P().services.find(full);
  if (it == P().services.end()) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_NOT_FOUND,
                "no service '" + full + "' is published", mod->mod_id);
  }
  // The binding is owned by the CONSUMER, so a consumer that unloads stops
  // holding a reference into the provider.
  *out_binding = P().core.Acquire(*mod, kKindServiceBinding, full,
                                  ReleaseBinding, new std::string(full), 0);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ServicesIsAvailable(MbHandle binding, int32_t* out_available,
                                    MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  Slot* slot = P().core.Resolve(binding, kKindServiceBinding);
  if (slot == nullptr) {
    // The CONSUMER unloaded, or the binding was released.
    if (out_available != nullptr) *out_available = 0;
    return MB_STATUS_OK;
  }
  // A binding is available only while the PROVIDER's service is still
  // published -- which its own teardown removes.
  const std::string* name = static_cast<const std::string*>(slot->body);
  if (out_available != nullptr) {
    *out_available = P().services.count(*name) != 0 ? 1 : 0;
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ------------------------------------------------------------- settings ----
static void ReleaseSettings(void* body, uint64_t payload) {
  (void)payload;
  delete static_cast<std::string*>(body);
}

static MbStatus SettingsDeclare(MbHandle mod_handle, MbStr schema_json,
                                MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  P().settings[mod->mod_id + "/__schema"] = ToStd(schema_json);
  P().core.Acquire(*mod, kKindSettingsSchema, mod->mod_id, ReleaseSettings,
                   new std::string(mod->mod_id), 0);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---------------------------------------------------------- diagnostics ----
static std::string Escape(const std::string& text) {
  std::string out;
  for (char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out += c;
    }
  }
  return out;
}

static MbStatus DiagSnapshot(MbStr* out_json, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  std::string json = "{\"mods\":[";
  bool first = true;
  for (ModRecord& mod : P().core.mods()) {
    if (!first) json += ",";
    first = false;
    std::string reason;
    bool reclaimable = P().core.IsReclaimable(mod, &reason);
    json += "{\"mod_id\":\"" + Escape(mod.mod_id) + "\",\"state\":" +
            std::to_string(mod.state) + ",\"epoch\":" +
            std::to_string(mod.epoch) + ",\"owned\":" +
            std::to_string(mod.owned_count) + ",\"released\":" +
            std::to_string(mod.released_count) + ",\"revoked\":" +
            std::to_string(mod.revoked_count) + ",\"faults\":" +
            std::to_string(mod.fault_count) + ",\"active_frames\":" +
            std::to_string(mod.active_frames) + ",\"reclaimable\":" +
            (reclaimable ? "true" : "false") + "}";
  }
  json += "],\"live_slots\":" + std::to_string(P().core.LiveSlotCount());
  json += ",\"slot_capacity\":" + std::to_string(P().core.SlotCapacity());
  json += ",\"events\":" + std::to_string(P().events.size());
  json += ",\"services\":" + std::to_string(P().services.size());
  json += ",\"commands\":" + std::to_string(P().commands.size());
  json += ",\"dispatches\":" + std::to_string(P().dispatches);
  json += ",\"trampoline_calls\":" + std::to_string(P().trampoline_calls);
  json += ",\"handler_faults\":" + std::to_string(P().handler_faults);
  json += ",\"log_records\":" + std::to_string(P().log_records);
  json += "}";
  if (out_json != nullptr) {
    *out_json = ThreadArena().Put(json);
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus DiagModState(MbStr mod_id, int32_t* out_state,
                             MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.FindMod(ToStd(mod_id));
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_UNKNOWN_MOD,
                "no such mod", ToStd(mod_id));
  }
  if (out_state != nullptr) *out_state = mod->state;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus DiagReclaimable(MbStr mod_id, int32_t* out_reclaimable,
                                MbStr* out_reason, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.FindMod(ToStd(mod_id));
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_UNKNOWN_MOD,
                "no such mod", ToStd(mod_id));
  }
  std::string reason;
  bool ok = P().core.IsReclaimable(*mod, &reason);
  if (out_reclaimable != nullptr) *out_reclaimable = ok ? 1 : 0;
  if (out_reason != nullptr) {
    *out_reason = ThreadArena().Put("{\"reason\":\"" + Escape(reason) + "\"}");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ----------------------------------------------------------------- host ----
static MbStatus HostSetTrampoline(MbTrampoline trampoline, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  if (trampoline == nullptr) {
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_INVALID_ARGUMENT,
                "the trampoline may not be null");
  }
  // Once, for the process. Replacing it would mean a second managed host, which
  // is not a thing this design supports.
  if (P().trampoline != nullptr && P().trampoline != trampoline) {
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_ALREADY_EXISTS,
                "a trampoline is already registered");
  }
  P().trampoline = trampoline;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus HostModBegin(MbStr mod_id, MbStr api_requirement,
                             MbStr required_caps, MbStr optional_caps,
                             MbHandle* out_mod, MbStr* out_grant,
                             MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  (void)api_requirement;
  (void)optional_caps;
  if (P().shutting_down) {
    return Fail(out_error, MB_SUB_PLATFORM, MB_E_SHUTTING_DOWN,
                "the platform is shutting down");
  }
  std::string id = ToStd(mod_id);
  if (id.empty()) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_INVALID_ARGUMENT,
                "a mod id is required");
  }
  ModRecord& mod = P().core.EnsureMod(id);
  if (mod.state == MB_MODSTATE_LOADED || mod.state == MB_MODSTATE_LOADING) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_MOD_ALREADY_LOADED,
                "'" + id + "' is already loaded", id);
  }
  mod.state = MB_MODSTATE_LOADING;
  mod.last_error.clear();
  *out_mod = P().core.ModHandle(mod);
  if (out_grant != nullptr) {
    *out_grant = ThreadArena().Put("{\"granted\":\"" +
                                   Escape(ToStd(required_caps)) + "\"}");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus HostModLoaded(MbHandle mod_handle, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_UNKNOWN_MOD,
                "the mod handle is not live");
  }
  mod->state = MB_MODSTATE_LOADED;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus HostModFailed(MbHandle mod_handle, MbStr reason,
                              MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_UNKNOWN_MOD,
                "the mod handle is not live");
  }
  mod->last_error = ToStd(reason);
  // Failure runs the SAME teardown as an unload. There is no second, less
  // tested cleanup path.
  Core::TeardownReport report = P().core.Dispose(*mod);
  mod->state = report.faults > 0 ? MB_MODSTATE_LEAKED : MB_MODSTATE_FAILED;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus HostModUnload(MbHandle mod_handle, MbStr* out_teardown,
                              MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_MOD_NOT_LOADED,
                "the mod handle is not live");
  }
  if (mod->state == MB_MODSTATE_UNLOADING) {
    return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_REENTRANT_UNLOAD,
                "'" + mod->mod_id + "' is already being unloaded", mod->mod_id);
  }
  std::string id = mod->mod_id;
  Core::TeardownReport report = P().core.Dispose(*mod);
  if (out_teardown != nullptr) {
    std::string json = "{\"mod_id\":\"" + Escape(id) + "\",\"revoked\":" +
                       std::to_string(report.revoked) + ",\"released\":" +
                       std::to_string(report.released) + ",\"faults\":" +
                       std::to_string(report.faults) + ",\"total\":" +
                       std::to_string(report.total) + ",\"reentered\":" +
                       (report.reentered ? "true" : "false") + "}";
    *out_teardown = ThreadArena().Put(json);
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus HostShutdown(MbStr* out_report, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  P().shutting_down = true;
  int unloaded = 0;
  for (ModRecord& mod : P().core.mods()) {
    if (mod.state == MB_MODSTATE_LOADED || mod.state == MB_MODSTATE_LOADING) {
      P().core.Dispose(mod);
      unloaded += 1;
    }
  }
  P().shutting_down = false;
  if (out_report != nullptr) {
    *out_report = ThreadArena().Put("{\"unloaded\":" + std::to_string(unloaded) +
                                    ",\"live_slots\":" +
                                    std::to_string(P().core.LiveSlotCount()) +
                                    "}");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---------------------------------------------------------------- tables ----
static MbLogTable g_log = {sizeof(MbLogTable), 1, 0, LogWrite};
static MbEventsTable g_events = {sizeof(MbEventsTable), 1, 0, EventsDeclare,
                                 EventsSubscribe, EventsUnsubscribe,
                                 EventsPublish};
static MbItemsTable g_items = {sizeof(MbItemsTable), 1, 0, ItemsRegister,
                               ItemsUnregister};
static MbDiagnosticsTable g_diag = {sizeof(MbDiagnosticsTable), 1, 0,
                                    DiagSnapshot, DiagModState,
                                    DiagReclaimable};
static MbHostTable g_host = {sizeof(MbHostTable), 1, 0, HostSetTrampoline,
                             HostModBegin, HostModLoaded, HostModFailed,
                             HostModUnload, HostShutdown};

static MbStatus QueryCapability(const char* name, int32_t name_len,
                                uint32_t* out_major, uint32_t* out_minor) {
  std::string wanted(name ? name : "", name_len > 0 ? name_len : 0);
  if (wanted == MB_CAP_LOG || wanted == MB_CAP_EVENTS ||
      wanted == MB_CAP_ITEMS || wanted == MB_CAP_DIAGNOSTICS ||
      wanted == MB_CAP_SERVICES || wanted == MB_CAP_SETTINGS ||
      wanted == MB_CAP_HOST) {
    if (out_major) *out_major = 1;
    if (out_minor) *out_minor = 0;
    return MB_STATUS_OK;
  }
  return static_cast<MbStatus>(MB_E_CAPABILITY_NOT_GRANTED);
}

static MbServicesTable g_services = {sizeof(MbServicesTable), 1, 0,
                                     ServicesPublish, ServicesBind,
                                     ServicesIsAvailable, nullptr, nullptr};
static MbSettingsTable g_settings = {sizeof(MbSettingsTable), 1, 0,
                                     SettingsDeclare, nullptr, nullptr, nullptr,
                                     nullptr, nullptr, nullptr, nullptr,
                                     nullptr, nullptr};

static MbStatus AcquireCapability(MbHandle owner, const char* name,
                                  int32_t name_len, uint32_t want_major,
                                  const void** out_table, MbError* out_error) {
  ThreadArena().Reset();
  ClearError(out_error);
  std::string wanted(name ? name : "", name_len > 0 ? name_len : 0);
  if (want_major != 1) {
    return Fail(out_error, MB_SUB_CAPABILITIES, MB_E_CAPABILITY_NOT_GRANTED,
                "'" + wanted + "' is not available at major " +
                    std::to_string(want_major));
  }
  // The host capability is refused to anything that is not the host handle
  // minted by MiseryBridgeAcquire, so a mod cannot begin or end a lifetime.
  if (wanted == MB_CAP_HOST) {
    if (owner != P().host_handle || P().host_handle == MB_INVALID_HANDLE) {
      return Fail(out_error, MB_SUB_CAPABILITIES, MB_E_CAPABILITY_NOT_GRANTED,
                  "core.host is reachable only by the managed host");
    }
    *out_table = &g_host;
    return MB_STATUS_OK;
  }
  if (wanted == MB_CAP_LOG) { *out_table = &g_log; return MB_STATUS_OK; }
  if (wanted == MB_CAP_EVENTS) { *out_table = &g_events; return MB_STATUS_OK; }
  if (wanted == MB_CAP_ITEMS) { *out_table = &g_items; return MB_STATUS_OK; }
  if (wanted == MB_CAP_SERVICES) { *out_table = &g_services; return MB_STATUS_OK; }
  if (wanted == MB_CAP_SETTINGS) { *out_table = &g_settings; return MB_STATUS_OK; }
  if (wanted == MB_CAP_DIAGNOSTICS) { *out_table = &g_diag; return MB_STATUS_OK; }
  return Fail(out_error, MB_SUB_CAPABILITIES, MB_E_CAPABILITY_NOT_GRANTED,
              "this framework does not provide '" + wanted + "'");
}

static MbStatus LastError(MbError* out_error) {
  ClearError(out_error);
  return MB_STATUS_OK;
}

static const MbRoot g_root = {sizeof(MbRoot), MB_ABI_EPOCH, MB_API_MAJOR,
                              MB_API_MINOR, QueryCapability, AcquireCapability,
                              LastError};

}  // namespace bridge
}  // namespace misery

// ------------------------------------------------------------- exports ----
extern "C" MB_EXPORT MbStatus MiseryBridgeAcquire(
    uint32_t abi_epoch, const MbRoot** out_root, MbHandle* out_host,
    MbError* out_error) {
  misery::bridge::ThreadArena().Reset();
  misery::bridge::ClearError(out_error);
  if (abi_epoch != MB_ABI_EPOCH) {
    return misery::bridge::Fail(
        out_error, MB_SUB_PLATFORM, MB_E_INVALID_ARGUMENT,
        "this runtime speaks ABI epoch " + std::to_string(MB_ABI_EPOCH) +
            ", the caller asked for " + std::to_string(abi_epoch));
  }
  if (out_root == nullptr || out_host == nullptr) {
    return misery::bridge::Fail(out_error, MB_SUB_PLATFORM,
                                MB_E_INVALID_ARGUMENT,
                                "out_root and out_host are required");
  }
  // The host handle is minted here, in-process. There is no discovery path and
  // nothing on disk a mod could read to obtain one.
  if (misery::bridge::P().host_handle == MB_INVALID_HANDLE) {
    misery::bridge::P().host_handle =
        misery::bridge::MakeHandle(misery::bridge::kKindMod, 0xFFFFFFu,
                                   0xC0FFEEu);
  }
  *out_root = &misery::bridge::g_root;
  *out_host = misery::bridge::P().host_handle;
  return MB_STATUS_OK;
}

// Installed by whoever owns the real item path: the in-game runtime installs
// the proven Stage 2 registration, the standalone harness installs a recorder.
extern "C" __declspec(dllexport) void MiseryBridgeInstallItemsBackend(
    misery::bridge::MbItemsRegisterFn register_item,
    misery::bridge::MbItemsUnregisterFn unregister_item) {
  misery::bridge::Items().register_item = register_item;
  misery::bridge::Items().unregister_item = unregister_item;
}

// Declares which thread the engine's game thread is. Until this is called the
// thread check is inert, which is what lets the standalone harness run on its
// own main thread without pretending to be a game.
extern "C" __declspec(dllexport) void MiseryBridgeSetGameThread(
    unsigned long thread_id) {
  misery::bridge::P().game_thread = thread_id;
}

extern "C" __declspec(dllexport) unsigned long MiseryBridgeGameThread(void) {
  return misery::bridge::P().game_thread;
}
