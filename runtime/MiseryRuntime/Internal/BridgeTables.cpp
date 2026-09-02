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
#include <windows.h>

#include "BridgeCore.h"
#include "Json.h"
#include "ModPlan.h"

#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

// GetCurrentThreadId used to be declared by hand here so this file could avoid
// <windows.h>. Settings persistence needs the file APIs, so the header is now
// included above and the hand-rolled prototype -- which the compiler flagged as
// inconsistent DLL linkage against the real one -- is gone.

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

// A console command. `owner` is empty and `handle` is 0 for the framework's
// own builtins, which nobody owns and nobody may release.
// ================================ settings =================================
//
// Ported from tools/modplatform/settings.py, whose docstring is the design:
// declared not free-form, four types that survive every boundary, one file per
// mod named by ModId, and a stored value that no longer fits its declaration
// falls back to the default and is REPORTED rather than either refusing the mod
// or staying silent.
//
// The file is flat -- {"key": value} -- because that is what the reference
// writes and what its tests read back. An earlier plan for this stage
// specified a framework envelope around it; that plan was written before the
// reference was found, and the reference wins on behaviour.

struct SettingSchema {
  int type = 0;                 // MB_SETTING_*
  bool default_bool = false;
  int64_t default_int = 0;
  double default_float = 0.0;
  std::string default_string;
  std::string description;
};

struct SettingValue {
  int type = 0;
  bool b = false;
  int64_t i = 0;
  double f = 0.0;
  std::string s;
};

struct ModSettings {
  std::map<std::string, SettingSchema> schema;   // key -> declaration
  std::map<std::string, SettingValue> values;    // key -> current value
  bool dirty = false;
};

struct Substitution {
  std::string mod_id;
  std::string key;                // empty when the whole file was unusable
  std::string detail;
};

struct SettingsStore {
  std::string root;               // injected; empty means "nowhere to persist"
  std::map<std::string, ModSettings> mods;
  std::vector<Substitution> substitutions;
};

// The reference's limits, mirrored. MAX_KEY is 64 there; the public C# contract
// refuses keys over 48 at construction (ModId.MaxLength), so no key in the
// 49..64 range can reach here from a mod written in C#. Native mirrors the
// reference so the differential compares like with like; the C# contract is
// the stricter of the two and stays so.
static const size_t kMaxSettingKey = 64;
static const size_t kMaxSettingString = 4096;

// The reference's cap, mirrored: console.py MAX_COMMANDS_PER_MOD.
static const unsigned kMaxCommandsPerMod = 32;

struct CommandRecord {
  std::string summary;
  std::string owner;
  MbHandle handle = MB_INVALID_HANDLE;
};

struct Platform {
  Core core;
  MbTrampoline trampoline = nullptr;
  unsigned long game_thread = 0;
  bool shutting_down = false;

  std::map<std::string, EventDeclaration> events;
  std::map<std::string, ServiceRecord> services;
  SettingsStore settings;
  std::map<std::string, CommandRecord> commands;    // name -> record

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
Platform& PlatformForExports() { return P(); }

// The injected items backend. See the header comment.
extern "C" {
typedef int (*MbItemsRegisterFn)(const char* mod_id, const char* declaration_json,
                                 char* out_row_name, int out_capacity);
typedef int (*MbItemsUnregisterFn)(const char* mod_id, const char* row_name);
typedef int (*MbItemsGrantFn)(const char* mod_id, const char* row_name,
                              int amount, int* out_added);
}

struct ItemsBackend {
  MbItemsRegisterFn register_item = nullptr;
  MbItemsUnregisterFn unregister_item = nullptr;
  MbItemsGrantFn grant_item = nullptr;
};

// WHERE `misery:generations` GETS ITS ANSWER.
//
// Injected rather than linked, for the same reason the items backend is: the
// bridge must stay buildable and testable without the resolver behind it, and
// runtime/tests/services_harness.cpp already depends on that.
//
// It is a PULL, not a pushed copy. The console runs on the game thread, which
// is where content::Acquire is legal, so the builtin reads the live generation
// through these at the moment it is asked. A pushed snapshot would be a second
// state model with its own staleness, which is exactly what the stage brief
// says not to build.
extern "C" {
typedef unsigned long long (*MbGenerationCurrentFn)();
typedef int (*MbGenerationPublishedFn)();
typedef const char* (*MbGenerationPhaseFn)();
typedef const char* (*MbGenerationLastRevokeFn)();
}

struct GenerationSource {
  MbGenerationCurrentFn current = nullptr;
  MbGenerationPublishedFn published = nullptr;
  MbGenerationPhaseFn phase = nullptr;
  MbGenerationLastRevokeFn last_revoke = nullptr;
};

static GenerationSource& Generations() {
  static GenerationSource source;
  return source;
}

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
int32_t DispatchEvent(const std::string& full, const std::string& payload) {
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

// The framework's own events, declared once and owned by nobody.
//
// Declared eagerly rather than on first publish so a mod can subscribe during
// OnLoad -- which is the only time it CAN subscribe and is strictly before the
// first generation is ready. An event that came into existence at publish time
// would be unsubscribable exactly when subscribing matters.
//
// There is no mod handle here, and that is the point: these are not any mod's
// to declare, publish or release, and the namespace is reserved so none can
// claim them.
void DeclareFrameworkEvents() {
  static const char* const kNames[] = {MB_EVENT_CONTENT_READY};
  for (const char* name : kNames) {
    if (P().events.count(name) == 0) {
      EventDeclaration declaration;
      declaration.owner = MB_EVENT_NS;
      P().events[name] = declaration;
    }
  }
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
    if (!ThreadArena().TryPut(body->row_name, out_row_name)) {
      return Fail(out_error, MB_SUB_ITEMS, MB_E_LIMIT_EXCEEDED,
                  "the registered row name did not fit the reply buffer; refusing rather "
                  "than returning a truncated document under a "
                  "successful status");
    }
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ItemsGrant(MbHandle item, int32_t amount,
                           int32_t* out_added, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  if (out_added != nullptr) {
    *out_added = 0;
  }
  if (amount <= 0) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_INVALID_ARGUMENT,
                "the amount to grant must be positive");
  }
  // Resolving the ITEM handle is the ownership rule. A mod holds handles only
  // for items it registered, so there is no path here for granting a vanilla
  // row or another mod's -- not as a check that could be forgotten, but
  // because no such handle exists to pass.
  Slot* slot = P().core.Resolve(item, kKindItem);
  if (slot == nullptr) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_OWNER_DISPOSED,
                "the item handle is not live");
  }
  ItemBody* body = static_cast<ItemBody*>(slot->body);
  if (body == nullptr) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_OWNER_DISPOSED,
                "the item handle has no body");
  }
  if (Items().grant_item == nullptr) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_NOT_FOUND,
                "no items backend is installed; granting needs the live game",
                body->mod_id);
  }
  int added = 0;
  const int rc = Items().grant_item(body->mod_id.c_str(),
                                    body->row_name.c_str(),
                                    static_cast<int>(amount), &added);
  if (rc != 0) {
    return Fail(out_error, MB_SUB_ITEMS, MB_E_INVALID_ARGUMENT,
                "the items backend refused the grant (code " +
                    std::to_string(rc) + ")",
                body->mod_id);
  }
  if (out_added != nullptr) {
    *out_added = added;
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
  // The version must parse HERE. Storing whatever string arrived would push
  // the failure to bind time, where it would surface as somebody else's mod
  // failing to bind against a provider that published nonsense -- the wrong
  // mod named in the wrong error. The reference refuses at publish for the
  // same reason (services.py: semver.Version(version) raises).
  misery::modplan::Version parsed_version;
  std::string version_error;
  if (!misery::modplan::ParseVersion(ToStd(version), &parsed_version,
                                  &version_error)) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_INVALID_ARGUMENT,
                "'" + full + "' cannot be published with version '" +
                    ToStd(version) + "': " + version_error,
                mod->mod_id);
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

  // THE REQUIREMENT IS ENFORCED, WHICH IT PREVIOUSLY WAS NOT.
  //
  // This function used to open with `(void)requirement;`. A mod could bind
  // ">=2.0.0" against a 1.0.0 provider and be told it had succeeded. That is
  // not a missing feature, it is the API answering a question it never asked:
  // the consumer stated a compatibility range and the framework agreed to it
  // without looking. The reference has always enforced it
  // (tools/modplatform/services.py Registry.bind).
  //
  // Refused HERE rather than at call time, because a mod that discovers the
  // mismatch mid-frame has no good options -- the reference's wording, and its
  // reasoning.
  const std::string requirement_text = ToStd(requirement);
  misery::modplan::Requirement want;
  std::string requirement_error;
  if (!misery::modplan::ParseRequirement(requirement_text, &want,
                                      &requirement_error)) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_INVALID_ARGUMENT,
                "the requirement '" + requirement_text +
                    "' is not a version requirement: " + requirement_error,
                mod->mod_id);
  }
  misery::modplan::Version published;
  std::string published_error;
  if (!misery::modplan::ParseVersion(it->second.version, &published,
                                  &published_error)) {
    // Unreachable while publish validates, and stated rather than assumed.
    return Fail(out_error, MB_SUB_SERVICES, MB_E_INVALID_ARGUMENT,
                "'" + full + "' is published with an unreadable version '" +
                    it->second.version + "'",
                mod->mod_id);
  }
  if (!want.Matches(published)) {
    return Fail(out_error, MB_SUB_SERVICES, MB_E_INVALID_ARGUMENT,
                "service '" + full + "' is version " + it->second.version +
                    ", which the requirement " + requirement_text +
                    " excludes. Refused now rather than at call time, because "
                    "a mod that finds out mid-frame has no good options.",
                mod->mod_id);
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
// ---- helpers ---------------------------------------------------------------

// Defined with the console, further down; both blocks render JSON and Python
// repr() text the same way, so one definition serves both.
static std::string Quoted(const std::string& text);
static std::string PyRepr(const std::string& text);

static const char* SettingTypeName(int type) {
  switch (type) {
    case MB_SETTING_BOOL: return "bool";
    case MB_SETTING_INT: return "int";
    case MB_SETTING_FLOAT: return "float";
    case MB_SETTING_STRING: return "string";
    default: return "?";
  }
}

static int SettingTypeFromName(const std::string& name) {
  if (name == "bool") return MB_SETTING_BOOL;
  if (name == "int") return MB_SETTING_INT;
  if (name == "float") return MB_SETTING_FLOAT;
  if (name == "string") return MB_SETTING_STRING;
  return 0;
}

// The reference's key rule: the identifier pattern, at most MAX_KEY. NOT
// CheckModId, which also refuses "__" and the reserved ids -- a setting key is
// namespaced by the mod that declared it, so neither restriction applies.
static bool CheckSettingKey(const std::string& key) {
  if (key.empty() || key.size() > kMaxSettingKey) return false;
  if (!(key[0] >= 'a' && key[0] <= 'z')) return false;
  for (char c : key) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
      return false;
    }
  }
  return true;
}

// The reference's _coerce, over a parsed JSON value. bool is checked before
// int throughout because a bool must never satisfy an int or float setting.
static bool CoerceJson(const misery::json::Value& in, int type, SettingValue* out,
                       std::string* why) {
  out->type = type;
  switch (type) {
    case MB_SETTING_BOOL:
      if (in.kind != misery::json::Kind::kBool) { *why = "expected bool"; return false; }
      out->b = in.boolean;
      return true;
    case MB_SETTING_INT:
      if (in.kind != misery::json::Kind::kInt) { *why = "expected int"; return false; }
      out->i = in.integer;
      return true;
    case MB_SETTING_FLOAT:
      if (in.kind == misery::json::Kind::kInt) { out->f = static_cast<double>(in.integer); return true; }
      if (in.kind != misery::json::Kind::kDouble) { *why = "expected float"; return false; }
      out->f = in.number;
      return true;
    case MB_SETTING_STRING:
      if (in.kind != misery::json::Kind::kString) { *why = "expected string"; return false; }
      if (in.text.size() > kMaxSettingString) {
        *why = "string longer than " + std::to_string(kMaxSettingString);
        return false;
      }
      out->s = in.text;
      return true;
    default:
      *why = "unknown setting type";
      return false;
  }
}

static SettingValue DefaultValue(const SettingSchema& schema) {
  SettingValue v;
  v.type = schema.type;
  v.b = schema.default_bool;
  v.i = schema.default_int;
  v.f = schema.default_float;
  v.s = schema.default_string;
  return v;
}

static bool SameValue(const SettingValue& a, const SettingValue& b) {
  if (a.type != b.type) return false;
  switch (a.type) {
    case MB_SETTING_BOOL: return a.b == b.b;
    case MB_SETTING_INT: return a.i == b.i;
    case MB_SETTING_FLOAT: return a.f == b.f;
    case MB_SETTING_STRING: return a.s == b.s;
    default: return false;
  }
}

// A JSON rendering of one value. Doubles are rendered the way Python's
// json.dump renders them -- repr(), the shortest round-tripping form -- so the
// file the runtime writes is the file the reference writes. "%.17g" round-trips
// but is not shortest; the loop below tries increasing precision until the
// value survives a round trip, which is what repr() guarantees.
static std::string RenderDouble(double value) {
  char buffer[64];
  for (int precision = 1; precision <= 17; ++precision) {
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%.*g", precision, value);
    if (strtod(buffer, nullptr) == value) break;
  }
  std::string text(buffer);
  // Python writes 0.5 as "0.5" and 1.0 as "1.0"; %g writes "1". A double that
  // rendered with no '.', 'e' or "inf"/"nan" gets ".0" so the reader sees a
  // float and the file matches the reference byte for byte.
  if (text.find_first_of(".eEn") == std::string::npos) text += ".0";
  return text;
}

static std::string RenderValue(const SettingValue& v) {
  switch (v.type) {
    case MB_SETTING_BOOL: return v.b ? "true" : "false";
    case MB_SETTING_INT: return std::to_string(v.i);
    case MB_SETTING_FLOAT: return RenderDouble(v.f);
    case MB_SETTING_STRING: return Quoted(v.s);
    default: return "null";
  }
}

static std::string SettingsPath(const std::string& mod_id) {
  return P().settings.root + "\\" + mod_id + ".json";
}

static bool ReadWholeFile(const std::string& path, std::string* out) {
  std::string error;
  return misery::json::ReadFile(path.c_str(), 4u * 1024u * 1024u, out, &error);
}

// A WARN attributed to the mod, in the same record shape LogWrite produces, so
// misery:log and the bundle show it beside the mod's own lines.
static void ReportSubstitution(const std::string& mod_id, const std::string& key,
                               const std::string& detail) {
  Substitution sub;
  sub.mod_id = mod_id;
  sub.key = key;
  sub.detail = detail;
  P().settings.substitutions.push_back(sub);
  std::string line = mod_id + "|" + std::to_string(MB_LOG_WARN) + "|" + detail;
  if (!key.empty()) line += "|{\"key\":" + Quoted(key) + "}";
  P().log_records += 1;
  P().log_tail.push_back(line);
  if (P().log_tail.size() > 512) P().log_tail.erase(P().log_tail.begin());
}

// The reference's _load_values: defaults, overlaid by whatever on disk still
// fits its declaration. Keys the mod no longer declares are left on disk and
// not exposed; a value that no longer fits falls back and is reported.
static void LoadValues(const std::string& mod_id, ModSettings* mod) {
  mod->values.clear();
  for (const auto& entry : mod->schema) {
    mod->values[entry.first] = DefaultValue(entry.second);
  }
  if (P().settings.root.empty()) return;
  const std::string path = SettingsPath(mod_id);
  std::string text;
  if (!ReadWholeFile(path, &text)) return;      // no file: defaults
  misery::json::Value stored;
  std::string error;
  if (!misery::json::Parse(text, &stored, &error)) {
    ReportSubstitution(mod_id, "",
                       "settings file could not be read (" + error +
                           "); defaults are in use for every key");
    return;
  }
  if (stored.kind != misery::json::Kind::kObject) {
    ReportSubstitution(mod_id, "",
                       "settings file is not a JSON object; defaults are in use");
    return;
  }
  for (const auto& entry : stored.object) {
    auto declared = mod->schema.find(entry.first);
    if (declared == mod->schema.end()) continue;   // kept on disk, not exposed
    SettingValue value;
    std::string why;
    if (CoerceJson(entry.second, declared->second.type, &value, &why)) {
      mod->values[entry.first] = value;
    } else {
      ReportSubstitution(
          mod_id, entry.first,
          "stored value for " + PyRepr(entry.first) +
              " does not fit declared type " +
              PyRepr(SettingTypeName(declared->second.type)) + " (" + why +
              "); the default is in use");
    }
  }
}

// FORGET, DO NOT FLUSH.
//
// This runs from Core::Dispose, which is the same teardown for an unload and
// for a mod that FAILED to load. Writing to disk from here would persist the
// settings of a mod that never worked, from a path that also runs when the
// process is being torn down. The reference's release() discards the schema,
// the values and the dirty flag and touches no file; so does this. Unsaved
// changes are lost on unload -- deliberately, and Save() is how a mod keeps
// them.
static void ReleaseSettings(void* body, uint64_t payload) {
  (void)payload;
  std::string* mod_id = static_cast<std::string*>(body);
  P().settings.mods.erase(*mod_id);
  delete mod_id;
}

// Resolves the mod, its declared settings and one key. Returns MB_STATUS_OK
// with every out-param set, or the status Fail() produced -- which callers
// return as-is, so the refusal reaches the caller with the code and detail
// intact rather than being re-described a second time here.
static MbStatus SettingsFor(MbHandle mod_handle, const std::string& key,
                            MbError* out_error, ModRecord** out_mod,
                            ModSettings** out_settings,
                            std::map<std::string, SettingSchema>::iterator* out_schema) {
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  *out_mod = mod;
  auto it = P().settings.mods.find(mod->mod_id);
  if (it == P().settings.mods.end()) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_NOT_FOUND,
                PyRepr(mod->mod_id) + " has declared no settings", mod->mod_id);
  }
  auto schema = it->second.schema.find(key);
  if (schema == it->second.schema.end()) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_NOT_FOUND,
                PyRepr(key) + " is not a declared setting of " +
                    PyRepr(mod->mod_id) +
                    ". Undeclared keys are refused so that a typo cannot read "
                    "as a default forever.",
                mod->mod_id);
  }
  *out_settings = &it->second;
  *out_schema = schema;
  return MB_STATUS_OK;
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
  if (P().settings.mods.count(mod->mod_id) != 0) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_ALREADY_EXISTS,
                "settings for " + PyRepr(mod->mod_id) + " are already declared",
                mod->mod_id);
  }

  // The schema arrives as the reference's shape: a JSON array of
  // {key, type, default, description}. Validated in the reference's order so
  // the same input is refused for the same reason with the same code.
  misery::json::Value parsed;
  std::string error;
  if (!misery::json::Parse(ToStd(schema_json), &parsed, &error) ||
      parsed.kind != misery::json::Kind::kArray) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                "the settings schema must be a JSON array: " + error,
                mod->mod_id);
  }
  ModSettings fresh;
  for (size_t index = 0; index < parsed.array.size(); ++index) {
    const misery::json::Value& raw = parsed.array[index];
    const std::string where = "settings[" + std::to_string(index) + "]";
    if (raw.kind != misery::json::Kind::kObject) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  where + " must be a dict", mod->mod_id);
    }
    for (const auto& member : raw.object) {
      if (member.first != "key" && member.first != "type" &&
          member.first != "default" && member.first != "description") {
        return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                    where + " has unknown key(s) [" + PyRepr(member.first) + "]",
                    mod->mod_id);
      }
    }
    const misery::json::Value* key = raw.Member("key");
    if (key == nullptr || key->kind != misery::json::Kind::kString ||
        !CheckSettingKey(key->text)) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  where + " key " +
                      PyRepr(key != nullptr && key->kind == misery::json::Kind::kString
                                 ? key->text : "") +
                      " must match ^[a-z][a-z0-9_]*$ and be at most " +
                      std::to_string(kMaxSettingKey) + " characters",
                  mod->mod_id);
    }
    if (fresh.schema.count(key->text) != 0) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_ALREADY_EXISTS,
                  where + " declares " + PyRepr(key->text) + " twice",
                  mod->mod_id);
    }
    const misery::json::Value* type = raw.Member("type");
    const int type_code =
        (type != nullptr && type->kind == misery::json::Kind::kString)
            ? SettingTypeFromName(type->text) : 0;
    if (type_code == 0) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  where + " type " +
                      PyRepr(type != nullptr && type->kind == misery::json::Kind::kString
                                 ? type->text : "") +
                      " is not one of ['bool', 'int', 'float', 'string']",
                  mod->mod_id);
    }
    const misery::json::Value* deflt = raw.Member("default");
    if (deflt == nullptr) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  where + " has no default; a setting with no default has no "
                          "value before the user sets one",
                  mod->mod_id);
    }
    SettingSchema schema;
    schema.type = type_code;
    SettingValue coerced;
    std::string why;
    if (!CoerceJson(*deflt, type_code, &coerced, &why)) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  where + " default does not match type " +
                      PyRepr(SettingTypeName(type_code)) + ": " + why,
                  mod->mod_id);
    }
    schema.default_bool = coerced.b;
    schema.default_int = coerced.i;
    schema.default_float = coerced.f;
    schema.default_string = coerced.s;
    const misery::json::Value* description = raw.Member("description");
    if (description != nullptr &&
        description->kind == misery::json::Kind::kString) {
      schema.description = description->text;
    }
    fresh.schema[key->text] = schema;
  }

  LoadValues(mod->mod_id, &fresh);
  P().settings.mods[mod->mod_id] = fresh;
  P().core.Acquire(*mod, kKindSettingsSchema, mod->mod_id, ReleaseSettings,
                   new std::string(mod->mod_id), 0);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---- typed access ------------------------------------------------------------

#define SETTINGS_GET(NAME, CTYPE, TYPECODE, FIELD)                              \
  static MbStatus NAME(MbHandle mod_handle, MbStr key, CTYPE* out_value,       \
                       MbError* out_error) {                                   \
    BRIDGE_ENTER(out_error);                                                   \
    BRIDGE_TRY                                                                 \
    ModRecord* mod = nullptr;                                                  \
    std::map<std::string, SettingSchema>::iterator schema;                     \
    ModSettings* settings = nullptr;                                          \
    {                                                                          \
      const MbStatus rc = SettingsFor(mod_handle, ToStd(key), out_error, &mod, \
                                      &settings, &schema);                     \
      if (rc != MB_STATUS_OK) return rc;                                       \
    }                                                                          \
    if (schema->second.type != TYPECODE) {                                     \
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,           \
                  PyRepr(ToStd(key)) + " is declared as " +                    \
                      SettingTypeName(schema->second.type) +                   \
                      ", not " + SettingTypeName(TYPECODE),                    \
                  mod->mod_id);                                                \
    }                                                                          \
    *out_value = settings->values[ToStd(key)].FIELD;                           \
    return MB_STATUS_OK;                                                       \
    BRIDGE_CATCH(out_error)                                                    \
  }

static MbStatus SettingsGetBool(MbHandle mod_handle, MbStr key, int32_t* out_value,
                                MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = nullptr;
  std::map<std::string, SettingSchema>::iterator schema;
  ModSettings* settings = nullptr;
  {
    const MbStatus rc = SettingsFor(mod_handle, ToStd(key), out_error, &mod,
                                    &settings, &schema);
    if (rc != MB_STATUS_OK) return rc;
  }
  if (schema->second.type != MB_SETTING_BOOL) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                PyRepr(ToStd(key)) + " is declared as " +
                    SettingTypeName(schema->second.type) + ", not bool",
                mod->mod_id);
  }
  *out_value = settings->values[ToStd(key)].b ? 1 : 0;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}
SETTINGS_GET(SettingsGetInt, int64_t, MB_SETTING_INT, i)
SETTINGS_GET(SettingsGetFloat, double, MB_SETTING_FLOAT, f)

static MbStatus SettingsGetString(MbHandle mod_handle, MbStr key, MbStr* out_value,
                                  MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = nullptr;
  std::map<std::string, SettingSchema>::iterator schema;
  ModSettings* settings = nullptr;
  {
    const MbStatus rc = SettingsFor(mod_handle, ToStd(key), out_error, &mod,
                                    &settings, &schema);
    if (rc != MB_STATUS_OK) return rc;
  }
  if (schema->second.type != MB_SETTING_STRING) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                PyRepr(ToStd(key)) + " is declared as " +
                    SettingTypeName(schema->second.type) + ", not string",
                mod->mod_id);
  }
  if (!ThreadArena().TryPut(settings->values[ToStd(key)].s, out_value)) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_LIMIT_EXCEEDED,
                "the setting's value did not fit the reply buffer; refusing "
                "rather than returning a truncated value under a successful "
                "status", mod->mod_id);
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// The reference's set(): coerce, refuse a mismatch, dirty only on change.
static MbStatus SettingsStore_Set(MbHandle mod_handle, MbStr key,
                                  const SettingValue& incoming, MbError* out_error) {
  ModRecord* mod = nullptr;
  std::map<std::string, SettingSchema>::iterator schema;
  ModSettings* settings = nullptr;
  {
    const MbStatus rc = SettingsFor(mod_handle, ToStd(key), out_error, &mod,
                                    &settings, &schema);
    if (rc != MB_STATUS_OK) return rc;
  }
  if (schema->second.type != incoming.type) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                PyRepr(ToStd(key)) + " expects " +
                    SettingTypeName(schema->second.type) + ": expected " +
                    SettingTypeName(schema->second.type),
                mod->mod_id);
  }
  if (incoming.type == MB_SETTING_STRING && incoming.s.size() > kMaxSettingString) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                PyRepr(ToStd(key)) + " expects string: string longer than " +
                    std::to_string(kMaxSettingString),
                mod->mod_id);
  }
  SettingValue& current = settings->values[ToStd(key)];
  if (!SameValue(current, incoming)) {
    current = incoming;
    settings->dirty = true;
  }
  return MB_STATUS_OK;
}

static MbStatus SettingsSetBool(MbHandle mod_handle, MbStr key, int32_t value,
                                MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  SettingValue v; v.type = MB_SETTING_BOOL; v.b = value != 0;
  return SettingsStore_Set(mod_handle, key, v, out_error);
  BRIDGE_CATCH(out_error)
}
static MbStatus SettingsSetInt(MbHandle mod_handle, MbStr key, int64_t value,
                               MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  SettingValue v; v.type = MB_SETTING_INT; v.i = value;
  return SettingsStore_Set(mod_handle, key, v, out_error);
  BRIDGE_CATCH(out_error)
}
static MbStatus SettingsSetFloat(MbHandle mod_handle, MbStr key, double value,
                                 MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  SettingValue v; v.type = MB_SETTING_FLOAT; v.f = value;
  return SettingsStore_Set(mod_handle, key, v, out_error);
  BRIDGE_CATCH(out_error)
}
static MbStatus SettingsSetString(MbHandle mod_handle, MbStr key, MbStr value,
                                  MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  SettingValue v; v.type = MB_SETTING_STRING; v.s = ToStd(value);
  return SettingsStore_Set(mod_handle, key, v, out_error);
  BRIDGE_CATCH(out_error)
}

// ---- persistence -----------------------------------------------------------
//
// The reference's save(): only a dirty mod is written; the payload is merged
// over whatever is already on disk so keys the mod no longer declares survive
// a downgrade; keys are sorted so a diff shows real changes.
//
// ATOMIC REPLACE is this port's one addition. The reference opens the file for
// writing in place; a crash mid-write there leaves a truncated file, which the
// next load reports and defaults around, so nothing is lost but the settings.
// Writing beside and renaming over closes even that window at no cost to the
// observable result: the bytes on disk afterwards are identical.
static MbStatus SettingsSave(MbHandle mod_handle, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  auto it = P().settings.mods.find(mod->mod_id);
  if (it == P().settings.mods.end()) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_NOT_FOUND,
                PyRepr(mod->mod_id) + " has declared no settings", mod->mod_id);
  }
  if (!it->second.dirty) {
    return MB_STATUS_OK;          // nothing changed: nothing written
  }
  if (P().settings.root.empty()) {
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_NOT_INITIALISED,
                "no settings root is attached, so there is nowhere to persist "
                "to; refusing rather than reporting a save that did not happen",
                mod->mod_id);
  }

  // Merge over the existing file's keys, when it is readable.
  std::map<std::string, std::string> rendered;     // key -> JSON text
  {
    std::string text;
    misery::json::Value existing;
    std::string error;
    if (ReadWholeFile(SettingsPath(mod->mod_id), &text) &&
        misery::json::Parse(text, &existing, &error) &&
        existing.kind == misery::json::Kind::kObject) {
      for (const auto& entry : existing.object) {
        // Re-rendered from the parsed value so the file stays canonical.
        SettingValue keep;
        std::string why;
        const misery::json::Value& v = entry.second;
        if (v.kind == misery::json::Kind::kBool) { keep.type = MB_SETTING_BOOL; keep.b = v.boolean; }
        else if (v.kind == misery::json::Kind::kInt) { keep.type = MB_SETTING_INT; keep.i = v.integer; }
        else if (v.kind == misery::json::Kind::kDouble) { keep.type = MB_SETTING_FLOAT; keep.f = v.number; }
        else if (v.kind == misery::json::Kind::kString) { keep.type = MB_SETTING_STRING; keep.s = v.text; }
        else continue;             // a shape this store never writes; dropped
        rendered[entry.first] = RenderValue(keep);
      }
    }
  }
  for (const auto& entry : it->second.values) {
    rendered[entry.first] = RenderValue(entry.second);
  }

  std::string document = "{";
  bool first = true;
  for (const auto& entry : rendered) {            // std::map: sorted keys
    document += first ? "\n" : ",\n";
    first = false;
    document += "  " + Quoted(entry.first) + ": " + entry.second;
  }
  document += first ? "}\n" : "\n}\n";

  CreateDirectoryA(P().settings.root.c_str(), nullptr);
  const std::string path = SettingsPath(mod->mod_id);
  const std::string temp = path + ".tmp";
  {
    FILE* handle = nullptr;
    if (fopen_s(&handle, temp.c_str(), "wb") != 0 || handle == nullptr) {
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  "the settings file could not be opened for writing: " + temp,
                  mod->mod_id);
    }
    const size_t written = fwrite(document.data(), 1, document.size(), handle);
    fclose(handle);
    if (written != document.size()) {
      DeleteFileA(temp.c_str());
      return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                  "the settings file could not be written completely: " + temp,
                  mod->mod_id);
    }
  }
  if (!MoveFileExA(temp.c_str(), path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileA(temp.c_str());
    return Fail(out_error, MB_SUB_SETTINGS, MB_E_INVALID_ARGUMENT,
                "the settings file could not be replaced: " + path, mod->mod_id);
  }
  it->second.dirty = false;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---------------------------------------------------------- diagnostics ----
// The one escaper, in the JSON module. This used to be a local implementation
// that handled '"', '\\' and '\n' and passed every other control byte through
// raw, which produced documents no conforming parser accepts. See
// misery::json::EscapeString.
static std::string Escape(const std::string& text) {
  return misery::json::EscapeString(text);
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
    if (!ThreadArena().TryPut(json, out_json)) {
      return Fail(out_error, MB_SUB_PLATFORM, MB_E_LIMIT_EXCEEDED,
                  "the diagnostics snapshot did not fit the reply buffer; refusing rather "
                  "than returning a truncated document under a "
                  "successful status");
    }
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
    if (!ThreadArena().TryPut("{\"reason\":\"" + Escape(reason) + "\"}", out_reason)) {
      return Fail(out_error, MB_SUB_PLATFORM, MB_E_LIMIT_EXCEEDED,
                  "the reclaim reason did not fit the reply buffer; refusing rather "
                  "than returning a truncated document under a "
                  "successful status");
    }
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
    if (!ThreadArena().TryPut("{\"granted\":\"" +
                                  Escape(ToStd(required_caps)) + "\"}",
                              out_grant)) {
      return Fail(out_error, MB_SUB_CAPABILITIES, MB_E_LIMIT_EXCEEDED,
                  "the capability grant did not fit the reply buffer; "
                  "refusing rather than returning a truncated document "
                  "under a successful status");
    }
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
    if (!ThreadArena().TryPut(json, out_teardown)) {
      return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_LIMIT_EXCEEDED,
                  "the teardown report did not fit the reply buffer; refusing rather "
                  "than returning a truncated document under a "
                  "successful status");
    }
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
    if (!ThreadArena().TryPut("{\"unloaded\":" + std::to_string(unloaded) +
                                  ",\"live_slots\":" +
                                  std::to_string(P().core.LiveSlotCount()) +
                                  "}",
                              out_report)) {
      return Fail(out_error, MB_SUB_LIFECYCLE, MB_E_LIMIT_EXCEEDED,
                  "the shutdown report did not fit the reply buffer; "
                  "refusing rather than returning a truncated document "
                  "under a successful status");
    }
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

// ---------------------------------------------------------------- tables ----
// ================================ console ==================================
//
// Ported from tools/modplatform/console.py, which has defined these semantics
// since Stage 4.5. The envelope, the refusal wording, the validation order and
// the builtin names are ITS decisions, mirrored here rather than re-invented,
// and tests/test_console.py drives the same lines through both.
//
// WHAT IS DELIBERATELY NOT THE REFERENCE'S
// ----------------------------------------
// The namespace. Framework builtins are "misery:<name>". The reference, which
// predates any reserved prefix, registers them bare. "mbpl" is NOT used and
// must not be: it is an ordinary mod_id -- the one the production radio mod
// uses -- and reserving it would invalidate existing item definitions.

// Defined below, beside acquire_capability; the caps builtin asks the same
// question a host would.
static MbStatus QueryCapability(const char* name, int32_t name_len,
                                uint32_t* out_major, uint32_t* out_minor);

// The result a mod's handler delivered during the dispatch now in flight.
// Empty when no dispatch is in flight, which is how complete_dispatch knows it
// is being called from somewhere it should not be.
static MbHandle g_dispatching_command = MB_INVALID_HANDLE;
static std::string g_dispatch_result;
static bool g_dispatch_completed = false;

static void ReleaseCommand(void* body, uint64_t payload) {
  (void)payload;
  std::string* name = static_cast<std::string*>(body);
  P().commands.erase(*name);
  delete name;
}

// ---- the JSON the builtins answer with ------------------------------------
static std::string Quoted(const std::string& text) {
  return "\"" + misery::json::EscapeString(text) + "\"";
}

// Python's %r on a str, which the reference's refusal wording goes through.
// Single quotes, so "unknown command 'foo'" matches byte for byte.
static std::string PyRepr(const std::string& text) {
  std::string out = "'";
  for (char c : text) {
    if (c == '\'' || c == '\\') out += '\\';
    out += c;
  }
  return out + "'";
}

static std::string CommandsJson() {
  std::string json = "[";
  bool first = true;
  for (const auto& entry : P().commands) {
    if (!first) json += ",";
    first = false;
    json += "{\"name\":" + Quoted(entry.first) + ",\"summary\":" +
            Quoted(entry.second.summary) + ",\"owner\":" +
            Quoted(entry.second.owner.empty() ? "platform"
                                              : entry.second.owner) + "}";
  }
  return json + "]";
}

static std::string BuiltinHelp() {
  return "{\"commands\":" + CommandsJson() + "}";
}

static std::string BuiltinMods() {
  std::string json = "{\"mods\":[";
  bool first = true;
  for (ModRecord& mod : P().core.mods()) {
    if (!first) json += ",";
    first = false;
    json += "{\"mod_id\":" + Quoted(mod.mod_id) + ",\"state\":" +
            std::to_string(mod.state) + ",\"epoch\":" +
            std::to_string(mod.epoch) + ",\"faults\":" +
            std::to_string(mod.fault_count) + "}";
  }
  // The reference reports how many folders discovery examined; the bridge is
  // not the discoverer, so it says so rather than guessing a number.
  return json + "],\"folders_examined\":null}";
}

static std::string BuiltinOwned(const std::string& wanted) {
  std::string json = "{\"mods\":[";
  bool first = true;
  for (ModRecord& mod : P().core.mods()) {
    if (!wanted.empty() && mod.mod_id != wanted) continue;
    if (!first) json += ",";
    first = false;
    std::string reason;
    json += "{\"mod_id\":" + Quoted(mod.mod_id) + ",\"owned\":" +
            std::to_string(mod.owned_count) + ",\"released\":" +
            std::to_string(mod.released_count) + ",\"revoked\":" +
            std::to_string(mod.revoked_count) + ",\"active_frames\":" +
            std::to_string(mod.active_frames) + ",\"reclaimable\":" +
            (P().core.IsReclaimable(mod, &reason) ? "true" : "false") + "}";
  }
  return json + "]}";
}

static std::string BuiltinEvents() {
  std::string json = "{\"events\":[";
  bool first = true;
  for (const auto& entry : P().events) {
    if (!first) json += ",";
    first = false;
    json += "{\"name\":" + Quoted(entry.first) + ",\"subscribers\":" +
            std::to_string(entry.second.subscribers.size()) + "}";
  }
  return json + "]}";
}

static std::string BuiltinServices() {
  std::string json = "{\"services\":[";
  bool first = true;
  for (const auto& entry : P().services) {
    if (!first) json += ",";
    first = false;
    json += "{\"name\":" + Quoted(entry.first) + ",\"version\":" +
            Quoted(entry.second.version) + ",\"provider\":" +
            Quoted(entry.second.provider) + "}";
  }
  return json + "]}";
}

// The reference's _cmd_settings: declared settings by mod, with type, default
// and current value, plus every substitution that was reported.
static std::string BuiltinSettings() {
  std::string json = "{\"mods\":[";
  bool first_mod = true;
  for (const auto& mod : P().settings.mods) {
    if (!first_mod) json += ",";
    first_mod = false;
    json += "{\"mod_id\":" + Quoted(mod.first) + ",\"dirty\":" +
            (mod.second.dirty ? "true" : "false") + ",\"settings\":[";
    bool first = true;
    for (const auto& entry : mod.second.schema) {
      if (!first) json += ",";
      first = false;
      auto value = mod.second.values.find(entry.first);
      json += "{\"key\":" + Quoted(entry.first) + ",\"type\":" +
              Quoted(SettingTypeName(entry.second.type)) + ",\"default\":" +
              RenderValue(DefaultValue(entry.second)) + ",\"value\":" +
              (value == mod.second.values.end() ? std::string("null")
                                                 : RenderValue(value->second)) +
              ",\"description\":" + Quoted(entry.second.description) + "}";
    }
    json += "]}";
  }
  json += "],\"substitutions\":[";
  bool first = true;
  for (const Substitution& sub : P().settings.substitutions) {
    if (!first) json += ",";
    first = false;
    json += "{\"mod_id\":" + Quoted(sub.mod_id) + ",\"key\":" +
            (sub.key.empty() ? std::string("null") : Quoted(sub.key)) +
            ",\"detail\":" + Quoted(sub.detail) + "}";
  }
  return json + "]}";
}

static std::string BuiltinLog() {
  std::string json = "{\"records\":[";
  bool first = true;
  for (const std::string& record : P().log_tail) {
    if (!first) json += ",";
    first = false;
    json += Quoted(record);
  }
  return json + "],\"total\":" + std::to_string(P().log_records) + "}";
}

static std::string BuiltinCaps() {
  std::string json = "{\"api\":{\"major\":" + std::to_string(MB_API_MAJOR) +
                     ",\"minor\":" + std::to_string(MB_API_MINOR) +
                     "},\"abi_epoch\":" + std::to_string(MB_ABI_EPOCH) +
                     ",\"capabilities\":[";
  static const char* kNames[] = {
      MB_CAP_LOG, MB_CAP_EVENTS, MB_CAP_SETTINGS, MB_CAP_INPUT_REGISTRY,
      MB_CAP_SERVICES, MB_CAP_ITEMS, MB_CAP_CONSOLE, MB_CAP_DIAGNOSTICS};
  bool first = true;
  for (const char* name : kNames) {
    uint32_t major = 0, minor = 0;
    const bool available =
        QueryCapability(name, static_cast<int32_t>(strlen(name)), &major,
                        &minor) == MB_STATUS_OK;
    if (!first) json += ",";
    first = false;
    json += "{\"name\":" + Quoted(name) + ",\"available\":" +
            (available ? "true" : "false");
    if (available) {
      json += ",\"major\":" + std::to_string(major) + ",\"minor\":" +
              std::to_string(minor);
    }
    json += "}";
  }
  return json + "]}";
}

// THE ONE NEW BUILTIN. Derived from the generation machinery through the
// injected accessors, not from a state model of its own.
static std::string BuiltinGenerations() {
  GenerationSource& source = Generations();
  if (source.current == nullptr) {
    return "{\"attached\":false,\"reason\":\"no generation source is attached; "
           "the bridge is running without the content runtime behind it\"}";
  }
  const unsigned long long current = source.current();
  const bool published =
      source.published != nullptr && source.published() != 0;
  std::string json = "{\"attached\":true,\"generation\":" +
                     std::to_string(current) + ",\"published\":" +
                     (published ? "true" : "false");
  if (source.phase != nullptr) {
    const char* phase = source.phase();
    json += ",\"phase\":" + Quoted(phase == nullptr ? "" : phase);
  }
  if (!published && source.last_revoke != nullptr) {
    const char* why = source.last_revoke();
    json += ",\"last_revoke\":" + Quoted(why == nullptr ? "" : why);
  }
  return json + "}";
}

// Subsystems whose data does not exist in this epoch answer with the shape the
// reference already uses for a missing load plan: an explicit statement that it
// is not attached, naming what would attach it. Silence, or an empty list that
// looks like "there are none", would both be worse than saying so.
static std::string NotAttached(const std::string& what) {
  return "{\"attached\":false,\"reason\":" + Quoted(what) + "}";
}

// ---- the registry ---------------------------------------------------------
static const char* kBuiltins[][2] = {
    {"misery:help", "list commands"},
    {"misery:mods", "loaded mods and their state"},
    {"misery:loadorder", "the resolved load order"},
    {"misery:why", "why a mod is not loaded"},
    {"misery:owned", "what a mod owns"},
    {"misery:items", "registered items, by mod"},
    {"misery:errors", "structured subsystem errors"},
    {"misery:caps", "API version and capabilities"},
    {"misery:events", "declared events and subscriber counts"},
    {"misery:services", "published services and their providers"},
    {"misery:input", "registered input actions"},
    {"misery:settings", "declared settings, by mod"},
    {"misery:log", "recent log records"},
    {"misery:generations", "the live content generation"},
};

static void DeclareBuiltins() {
  if (!P().commands.empty()) return;
  for (const auto& entry : kBuiltins) {
    CommandRecord record;
    record.summary = entry[1];
    P().commands[entry[0]] = record;
  }
}

static std::string RunBuiltin(const std::string& name,
                              const std::string& args) {
  if (name == "misery:help") return BuiltinHelp();
  if (name == "misery:mods") return BuiltinMods();
  if (name == "misery:owned") return BuiltinOwned(args);
  if (name == "misery:events") return BuiltinEvents();
  if (name == "misery:services") return BuiltinServices();
  if (name == "misery:settings") return BuiltinSettings();
  if (name == "misery:log") return BuiltinLog();
  if (name == "misery:caps") return BuiltinCaps();
  if (name == "misery:generations") return BuiltinGenerations();
  if (name == "misery:loadorder" || name == "misery:why") {
    return NotAttached("no load plan is attached to the bridge; discovery and "
                       "resolution run in the runtime, which does not hand its "
                       "plan to the console yet");
  }
  if (name == "misery:items") {
    return NotAttached("the items backend does not expose a listing yet");
  }
  if (name == "misery:errors") {
    return NotAttached("the structured error history arrives with the support "
                       "bundle");
  }
  if (name == "misery:input") {
    return NotAttached("core.input_registry is declared and not dispatched");
  }
  return NotAttached("unimplemented builtin");
}

static MbStatus ConsoleRegister(MbHandle mod_handle, MbStr name, MbStr summary,
                                MbHandle* out_command, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  DeclareBuiltins();
  ModRecord* mod = P().core.ResolveMod(mod_handle);
  if (mod == nullptr) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_OWNER_DISPOSED,
                "the mod handle is not live");
  }
  const std::string full = ToStd(name);
  // The reference's validation, in its order, so the same input is refused for
  // the same reason with the same code.
  std::string local;
  if (!NamespaceMatches(full, mod->mod_id, &local)) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_INVALID_ARGUMENT,
                PyRepr(mod->mod_id) + " may only register commands under " +
                    PyRepr(mod->mod_id + ":"),
                mod->mod_id);
  }
  if (P().commands.count(full) != 0) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_ALREADY_EXISTS,
                "command " + PyRepr(full) + " already exists", mod->mod_id);
  }
  unsigned owned_commands = 0;
  for (const auto& entry : P().commands) {
    if (entry.second.owner == mod->mod_id) ++owned_commands;
  }
  if (owned_commands >= kMaxCommandsPerMod) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_LIMIT_EXCEEDED,
                "a mod may register at most " +
                    std::to_string(kMaxCommandsPerMod) + " commands",
                mod->mod_id);
  }
  CommandRecord record;
  record.summary = ToStd(summary);
  record.owner = mod->mod_id;
  record.handle = P().core.Acquire(*mod, kKindCommand, full, ReleaseCommand,
                                   new std::string(full), 0);
  P().commands[full] = record;
  *out_command = record.handle;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ConsoleUnregister(MbHandle command, MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  // Resolved WITH the kind first, so a handle of some other kind is refused
  // rather than released: ReleaseOne does not check what it is being handed.
  if (P().core.Resolve(command, kKindCommand) == nullptr) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_NOT_OWNED,
                "that is not a live command handle");
  }
  P().core.ReleaseOne(command);
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ConsoleCompleteDispatch(MbHandle command, MbStr result_json,
                                        MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  if (g_dispatching_command == MB_INVALID_HANDLE ||
      command != g_dispatching_command) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_NOT_OWNED,
                "complete_dispatch is only valid for the command dispatch "
                "currently in flight");
  }
  g_dispatch_result = ToStd(result_json);
  g_dispatch_completed = true;
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbStatus ConsoleRun(MbStr line, MbStr* out_result_json,
                           MbError* out_error) {
  BRIDGE_ENTER(out_error);
  BRIDGE_TRY
  DeclareBuiltins();

  // run() NEVER FAILS FOR A COMMAND'S SAKE.
  //
  // The reference's contract is "never raises; returns a result structure", so
  // an unknown command, an empty line and a handler that threw are all
  // MB_STATUS_OK with ok:false in the envelope. A non-zero status here means
  // the console itself could not run -- wrong thread, or the reply did not fit.
  // Callers that conflate the two would report a mod's bad command as a
  // framework failure.
  const std::string text = ToStd(line);
  std::string name, args;
  {
    size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
      const std::string envelope = "{\"ok\":false,\"error\":\"empty command\"}";
      if (!ThreadArena().TryPut(envelope, out_result_json)) {
        return Fail(out_error, MB_SUB_CONSOLE, MB_E_LIMIT_EXCEEDED,
                    "the console reply did not fit the reply buffer");
      }
      return MB_STATUS_OK;
    }
    size_t end = text.find_first_of(" \t\r\n", begin);
    name = text.substr(begin, end == std::string::npos ? std::string::npos
                                                       : end - begin);
    if (end != std::string::npos) {
      const size_t rest = text.find_first_not_of(" \t\r\n", end);
      if (rest != std::string::npos) {
        args = text.substr(rest);
        while (!args.empty() && (args.back() == ' ' || args.back() == '\t' ||
                                 args.back() == '\r' || args.back() == '\n')) {
          args.pop_back();
        }
      }
    }
  }

  auto it = P().commands.find(name);
  std::string envelope;
  if (it == P().commands.end()) {
    envelope = "{\"ok\":false,\"error\":\"unknown command " +
               misery::json::EscapeString(PyRepr(name)) +
               "\",\"hint\":\"try 'help'\"}";
  } else if (it->second.owner.empty()) {
    envelope = "{\"ok\":true,\"command\":" + Quoted(name) + ",\"result\":" +
               RunBuiltin(name, args) + "}";
  } else {
    // A MOD's command. Re-resolved immediately before the call, never from the
    // record captured above: the mod may have been unloaded since the map was
    // read, and the reference reports exactly that case.
    const MbHandle handle = it->second.handle;
    Slot* slot = P().core.Resolve(handle, kKindCommand);
    ModRecord* owner =
        slot == nullptr ? nullptr : P().core.FindModBySlot(slot->owner_slot);
    if (slot == nullptr || owner == nullptr || P().trampoline == nullptr) {
      envelope = "{\"ok\":false,\"error\":\"command " +
                 misery::json::EscapeString(PyRepr(name)) +
                 " is no longer available: its mod was unloaded\"}";
    } else {
      g_dispatching_command = handle;
      g_dispatch_result.clear();
      g_dispatch_completed = false;
      owner->active_frames += 1;
      bool faulted = false;
      try {
        P().trampoline_calls += 1;
        P().trampoline(MB_DISPATCH_COMMAND, handle,
                       MbStr{name.c_str(), static_cast<int32_t>(name.size())},
                       MbStr{args.c_str(), static_cast<int32_t>(args.size())},
                       0);
      } catch (...) {
        P().handler_faults += 1;
        owner->fault_count += 1;
        faulted = true;
      }
      owner->active_frames -= 1;
      g_dispatching_command = MB_INVALID_HANDLE;
      P().dispatches += 1;
      if (faulted) {
        envelope = "{\"ok\":false,\"command\":" + Quoted(name) +
                   ",\"error\":{\"detail\":\"the command handler faulted\"}}";
      } else if (!g_dispatch_completed) {
        envelope = "{\"ok\":false,\"command\":" + Quoted(name) +
                   ",\"error\":{\"detail\":\"the command handler returned no "
                   "result\"}}";
      } else {
        envelope = "{\"ok\":true,\"command\":" + Quoted(name) + ",\"result\":" +
                   g_dispatch_result + "}";
      }
      g_dispatch_result.clear();
    }
  }

  if (!ThreadArena().TryPut(envelope, out_result_json)) {
    return Fail(out_error, MB_SUB_CONSOLE, MB_E_LIMIT_EXCEEDED,
                "the console reply did not fit the reply buffer; refusing "
                "rather than returning a truncated document under a "
                "successful status");
  }
  return MB_STATUS_OK;
  BRIDGE_CATCH(out_error)
}

static MbConsoleTable g_console = {sizeof(MbConsoleTable), 1, 0,
                                   ConsoleRegister, ConsoleUnregister,
                                   ConsoleRun, ConsoleCompleteDispatch};
static MbLogTable g_log = {sizeof(MbLogTable), 1, 0, LogWrite};
static MbEventsTable g_events = {sizeof(MbEventsTable), 1, 0, EventsDeclare,
                                 EventsSubscribe, EventsUnsubscribe,
                                 EventsPublish};
static MbItemsTable g_items = {sizeof(MbItemsTable), 2, 0, ItemsRegister,
                               ItemsUnregister, ItemsGrant};
static MbDiagnosticsTable g_diag = {sizeof(MbDiagnosticsTable), 1, 0,
                                    DiagSnapshot, DiagModState,
                                    DiagReclaimable};
static MbHostTable g_host = {sizeof(MbHostTable), 1, 0, HostSetTrampoline,
                             HostModBegin, HostModLoaded, HostModFailed,
                             HostModUnload, HostShutdown};

static MbStatus QueryCapability(const char* name, int32_t name_len,
                                uint32_t* out_major, uint32_t* out_minor) {
  std::string wanted(name ? name : "", name_len > 0 ? name_len : 0);
  if (wanted == MB_CAP_CONSOLE || wanted == MB_CAP_LOG ||
      wanted == MB_CAP_EVENTS ||
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
                                     SettingsDeclare,
                                     SettingsGetBool, SettingsGetInt,
                                     SettingsGetFloat, SettingsGetString,
                                     SettingsSetBool, SettingsSetInt,
                                     SettingsSetFloat, SettingsSetString,
                                     SettingsSave};

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
  if (wanted == MB_CAP_CONSOLE) {
    *out_table = &g_console;
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
  // The framework's events exist before the first mod does.
  //
  // Subscribing requires the event to be declared, and a mod can only subscribe
  // during OnLoad -- which is strictly before the first content generation is
  // ready. Declaring these lazily at publish time would make them
  // unsubscribable exactly when subscribing matters.
  misery::bridge::DeclareFrameworkEvents();

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
// Raise a framework event. Called by the runtime, never by a mod.
//
// Dispatch goes through the same DispatchEvent every mod publish uses, so it
// inherits the lifecycle guarantees rather than restating them: subscribers are
// captured before the loop, each subscription is re-resolved immediately before
// its call so a mod unloaded mid-dispatch is skipped, and a fault is attributed
// to its owner instead of unwinding a game frame.
extern "C" __declspec(dllexport) int MiseryBridgeRaiseFrameworkEvent(
    const char* name, const char* payload_json) {
  if (name == nullptr) {
    return 0;
  }
  misery::bridge::DeclareFrameworkEvents();
  return misery::bridge::DispatchEvent(
      name, payload_json != nullptr ? payload_json : "{}");
}

extern "C" __declspec(dllexport) void MiseryBridgeInstallItemsBackend(
    misery::bridge::MbItemsRegisterFn register_item,
    misery::bridge::MbItemsUnregisterFn unregister_item,
    misery::bridge::MbItemsGrantFn grant_item) {
  misery::bridge::Items().register_item = register_item;
  misery::bridge::Items().unregister_item = unregister_item;
  misery::bridge::Items().grant_item = grant_item;
}

// Declares which thread the engine's game thread is. Until this is called the
// thread check is inert, which is what lets the standalone harness run on its
// own main thread without pretending to be a game.
// Where settings files live. Injected by the runtime, which resolves it from
// the user's profile; set by the harness to a temporary directory. Empty means
// nowhere, and Save() refuses rather than pretending.
extern "C" __declspec(dllexport) void MiseryBridgeSetSettingsRoot(
    const char* root) {
  misery::bridge::PlatformForExports().settings.root =
      root == nullptr ? "" : root;
}

extern "C" __declspec(dllexport) void MiseryBridgeSetGenerationSource(
    misery::bridge::MbGenerationCurrentFn current,
    misery::bridge::MbGenerationPublishedFn published,
    misery::bridge::MbGenerationPhaseFn phase,
    misery::bridge::MbGenerationLastRevokeFn last_revoke) {
  misery::bridge::GenerationSource& source = misery::bridge::Generations();
  source.current = current;
  source.published = published;
  source.phase = phase;
  source.last_revoke = last_revoke;
}

extern "C" __declspec(dllexport) void MiseryBridgeSetGameThread(
    unsigned long thread_id) {
  misery::bridge::P().game_thread = thread_id;
}

extern "C" __declspec(dllexport) unsigned long MiseryBridgeGameThread(void) {
  return misery::bridge::P().game_thread;
}
