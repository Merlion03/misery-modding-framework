// RuntimeBootstrap.cpp -- what MiseryRuntime does when the proxy hands over.
//
// THE HANDOFF, AND WHY THE SPLIT IS HERE
// --------------------------------------
// The proxy (dwmapi.dll) fingerprints the executable and finds a bindings file
// that claims that fingerprint. That is all it does, on purpose: it runs early,
// partly under the loader lock, and it is the piece a user cannot uninstall
// without deleting a file. Everything else is this file's job.
//
// So the entry point below is where the framework actually starts, and it is
// split in two deliberately:
//
//   MiseryRuntimeBootstrap  synchronous, cheap, and the last place a refusal
//                           is free: read the profile, check it really
//                           describes THIS executable, and compare every code
//                           address against the bytes that are actually mapped.
//                           A non-zero return here means the proxy logs
//                           FAIL CLOSED and the game runs vanilla.
//
//   the runtime thread      everything that has to wait. The engine is not up
//                           when the proxy hands over -- there is no name pool
//                           and no object array yet -- so nothing that reads
//                           the object graph can run on the calling thread.
//
// WHY THE SECOND HALF WAITS ON A MEASURED SIGNAL RATHER THAN A SLEEP
// ------------------------------------------------------------------
// "Sleep three seconds and hope" is how a framework becomes flaky on a slow
// disk and broken on a fast one. The profile carries the address of the
// engine's own bNamePoolInitialized guard byte, so readiness is READ, and the
// object array is then required to be non-empty before anything is resolved.
// A machine that never becomes ready times out and says so; it does not
// proceed with an empty universe and report success.
//
// OBJECT RESOLUTION RUNS ON THE GAME THREAD, NOT ON THIS ONE
// ----------------------------------------------------------
// The runtime thread waits for the engine and then hands the walk to the proven
// game-thread carrier. It does not walk the object array itself: doing that from
// a worker thread races the engine's own teardown, which is unsafe by
// construction during object churn regardless of whether the race has ever been
// seen to bite. See ResolveOnGameThread.h, which also records what is and is
// not established about the one process death observed under the old model.
//
// WHAT THIS FILE DOES NOT DO YET
// ------------------------------
// It does not start the items backend or CoreCLR. Those attach at the seam
// marked below, once the startup anchors have resolved. Keeping them out means
// the "do the bindings work" question is answered on its own evidence.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <string>

#include "../Public/MiseryBridge.h"
#include "Bindings.h"
#include "ContentGeneration.h"
#include "ItemsBackend.h"
#include "ManagedHost.h"
#include "ResolveOnGameThread.h"
#include "Resolver.h"

// Declared here because they are INTERNAL exports of BridgeTables.cpp, not part
// of the mod-facing header. MiseryBridge.h is the surface a mod compiles
// against, and "tell the bridge which thread is the game thread" is a thing only
// the runtime that owns the process may do -- so it deliberately does not appear
// there.
extern "C" void MiseryBridgeSetGameThread(unsigned long thread_id);
extern "C" unsigned long MiseryBridgeGameThread(void);

namespace {

// How long the engine is given to come up before the runtime gives up. Chosen
// to be longer than any observed start on this machine by a wide margin: the
// cost of waiting too long is a late start, the cost of waiting too little is a
// framework that fails on somebody else's slower disk.
constexpr DWORD kEngineReadyTimeoutMs = 180000;
constexpr DWORD kEnginePollMs = 250;
// One resolution, waited on from this thread.
//
// Sized for the CHUNKED walk, not the old whole-walk form: ~130 slices at one
// slice per tick is ~2.2s at 60fps, but a level load runs far below 60fps and a
// restart starts the count again. Four restarts at 15fps is on the order of a
// minute, so the timeout has to be minutes rather than seconds -- while still
// being finite, because a pump that never runs must be reported rather than
// waited on forever.
constexpr uint32_t kResolveTimeoutMs = 180000;

// How the runtime waits for content to exist. Slow on purpose: a content-phase
// resolution is a few hundred game-thread slices, so a tight poll would be a
// permanent drain on a player sitting in a menu. Twenty attempts twenty seconds
// apart covers a leisurely main-menu visit and then stops asking.
constexpr DWORD kContentPollMs = 20000;
constexpr int kContentAttempts = 20;

const MbRoot* g_root = nullptr;
bool g_managed_started = false;
MbHandle g_host_handle = MB_INVALID_HANDLE;

char g_log_path[MAX_PATH] = {0};
std::string g_framework_dir;
std::string g_bindings_path;
std::string g_build_key;
misery::bindings::Profile g_profile;
uint64_t g_module_base = 0;
uint64_t g_module_size = 0;

// The items backend logs through the runtime's log, so one file tells the whole
// story rather than two halves of it.
void LogLine(const char* line);

void Log(const char* format, ...) {
  if (g_log_path[0] == '\0') {
    return;
  }
  FILE* file = nullptr;
  if (fopen_s(&file, g_log_path, "a") != 0 || file == nullptr) {
    return;
  }
  SYSTEMTIME now;
  GetLocalTime(&now);
  fprintf(file, "[%02d:%02d:%02d.%03d] ", now.wHour, now.wMinute, now.wSecond,
          now.wMilliseconds);
  va_list args;
  va_start(args, format);
  vfprintf(file, format, args);
  va_end(args);
  fprintf(file, "\n");
  fclose(file);
}

void LogLine(const char* line) { Log("%s", line); }

// The running executable's mapped base and size, from its own PE headers. Read
// rather than assumed because ASLR moves the base every launch and the profile
// records an image size the loaded module must match.
bool ThisImage(uint64_t* base, uint64_t* size) {
  HMODULE module = GetModuleHandleA(nullptr);
  if (module == nullptr) {
    return false;
  }
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(module);
  const IMAGE_DOS_HEADER* dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }
  const IMAGE_NT_HEADERS64* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }
  *base = reinterpret_cast<uint64_t>(module);
  *size = nt->OptionalHeader.SizeOfImage;
  return true;
}

// The engine's own "the name pool exists" guard byte, plus a non-empty object
// array. Both, because either alone has a window where it is misleading: the
// guard flips before the array is populated, and an array that reads as
// non-empty on an uninitialised page is exactly the sort of accident the
// resolver must not build a universe from.
bool WaitForEngine(std::string* why) {
  uint64_t guard = 0;
  uint64_t guobjectarray = 0;
  std::string error;
  if (!misery::bindings::Resolve(g_profile, "name_pool_initialized",
                                 g_module_base, g_module_size, &guard,
                                 &error) ||
      !misery::bindings::Resolve(g_profile, "guobjectarray", g_module_base,
                                 g_module_size, &guobjectarray, &error)) {
    *why = error;
    return false;
  }

  const misery::resolve::Layout layout;
  DWORD waited = 0;
  while (waited < kEngineReadyTimeoutMs) {
    uint8_t initialized = 0;
    int32_t elements = 0;
    if (misery::resolve::Read(guard, &initialized) && initialized != 0 &&
        misery::resolve::Read(
            guobjectarray + layout.guobjectarray_num_elements, &elements) &&
        elements > 0) {
      Log("runtime: the engine is up after %lums (%d objects in the array)",
          static_cast<unsigned long>(waited), elements);
      return true;
    }
    Sleep(kEnginePollMs);
    waited += kEnginePollMs;
  }
  char buffer[256];
  _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
              "the engine was still not up after %lums",
              static_cast<unsigned long>(kEngineReadyTimeoutMs));
  *why = buffer;
  return false;
}

// Resolve content, publish it as a generation, and keep it honest for as long
// as the process lives.
//
// THE LIFECYCLE, AND WHERE EACH STEP HAPPENS
// ------------------------------------------
//   resolve + publish      here, once content exists
//   revoked                in content::Acquire, the moment a consumer asks and
//                          an anchor no longer passes the slot check
//   consumers fail/defer   also in Acquire: they get a refusal, never a pointer
//   re-resolve + republish here, when the poll below sees nothing published
//
// Note what is NOT in that list: detecting the load. Nothing here watches for a
// transition. Revocation happens because an anchor is dead, which is the fact
// that actually matters, and it is noticed by whoever tries to use it -- so the
// window between "the world was replaced" and "consumers stopped being able to
// use the old world" is zero by construction rather than small by luck.
//
// This loop's own Acquire is what drives revocation when nothing else is asking,
// so a generation cannot sit stale-but-unnoticed while no mods are loaded.
// Apply any declared-but-not-live items, on the game thread.
//
// The Acquire happens INSIDE the job, not before it. Acquiring on this loop's
// own thread and handing the snapshot to a game-thread job would leave a window
// where the generation is revoked between the two, and the job would then write
// rows into a world that had just been thrown away. Doing both on the game
// thread makes "the generation is live" and "the rows are written" one step.
struct ApplyOutcome {
  bool acquired = false;
  uint64_t generation = 0;
  unsigned live = 0;
  std::string why;
};

void ApplyPendingJob(void* ctx) {
  ApplyOutcome* out = static_cast<ApplyOutcome*>(ctx);
  misery::content::Snapshot snapshot;
  if (!misery::content::Acquire(&snapshot, &out->why)) {
    return;
  }
  out->acquired = true;
  out->generation = snapshot.generation;
  misery::items::OnGenerationPublished(snapshot);
  out->live = misery::items::LiveCount(snapshot.generation);
}

// Returns the number of declarations live in the current generation. Cheap and
// a no-op when every declaration is already applied, so it is safe to call on
// every poll.
unsigned ApplyPendingItems() {
  if (misery::items::DeclaredCount() == 0) {
    return 0;
  }
  ApplyOutcome outcome;
  std::string error;
  if (!misery::gamethread::RunBlocking(&ApplyPendingJob, &outcome,
                                       kResolveTimeoutMs, &error)) {
    Log("runtime: items could not be applied on the game thread: %s",
        error.c_str());
    return 0;
  }
  if (!outcome.acquired) {
    // The window between a world being torn down and the next generation being
    // published. Logged rather than passed over: this is the production Items
    // path declining to touch a revoked generation, and it is the property the
    // whole content-generation mechanism exists to provide.
    Log("runtime: %u declared item(s) not applied -- %s",
        misery::items::DeclaredCount(), outcome.why.c_str());
    return 0;
  }
  return outcome.live;
}

void ContentLifecycle(uint64_t guobjectarray, uint64_t namepool) {
  int consecutive_failures = 0;
  while (true) {
    std::string why;
    misery::content::Snapshot snapshot;
    if (misery::content::Acquire(&snapshot, &why)) {
      consecutive_failures = 0;
      const unsigned declared = misery::items::DeclaredCount();
      const unsigned live = ApplyPendingItems();
      if (declared == 0 || live == declared ||
          snapshot.anchors.reached == misery::resolve::Phase::kGameplay) {
        // Either nothing is waiting, or everything that can be applied has
        // been. Check again later.
        Sleep(kContentPollMs);
        continue;
      }
      // Declarations are waiting for a world that can hold them, and this
      // generation is not one -- a mod declared an item at the main menu.
      //
      // Falling through to re-resolve is the safety net for a case revocation
      // alone does not cover: entering a world normally destroys the menu's
      // ItemList, which revokes the generation and takes the path below, but
      // nothing GUARANTEES that. Without this, a menu generation that happened
      // to stay valid would leave every declared item unapplied forever.
      //
      // The cost is one chunked walk per poll -- 20s apart, ~400ms of work in
      // slices of at most 2ms, so no frame hitch -- and only in the window
      // between a mod declaring an item and the player entering a world. The
      // result is published only if it reaches gameplay, so a player sitting at
      // the menu does not churn a new generation every poll.
    }
    if (misery::content::CurrentGeneration() == 0 &&
        misery::content::RevokeCount() > 0) {
      Log("runtime: %s", why.c_str());
    }

    misery::resolve::Request request;
    request.require = misery::resolve::Phase::kContent;
    // Content is the minimum worth publishing; gameplay is what item rows need.
    // Asking for content alone would scope the player inventory away even in
    // gameplay, and no declared item could ever be written. See
    // Request::prefer_gameplay -- this does not cost a second walk.
    request.prefer_gameplay = true;
    misery::resolve::Anchors anchors;
    misery::resolve::Failure failure;
    misery::gamethread::Cost cost;
    std::string error;
    if (!misery::gamethread::Resolve(guobjectarray, namepool, request, &anchors,
                                     &failure, kResolveTimeoutMs, &cost,
                                     &error)) {
      // Absent content is ordinary -- a player at a main menu. Only log the
      // first of a run of identical refusals, or a menu visit fills the log.
      if (consecutive_failures == 0) {
        Log("runtime: content not available: %s",
            failure.failed ? failure.what.c_str() : error.c_str());
      }
      ++consecutive_failures;
      Sleep(kContentPollMs);
      continue;
    }
    consecutive_failures = 0;

    // A generation still current is only replaced by one that can do more.
    // Reached here from the safety net above, this discards a re-resolve that
    // found the player still at the menu instead of publishing a fresh, equally
    // itemless generation every 20 seconds.
    if (misery::content::CurrentGeneration() != 0 &&
        anchors.reached != misery::resolve::Phase::kGameplay) {
      Sleep(kContentPollMs);
      continue;
    }

    const uint64_t generation = misery::content::Publish(
        cost.objects_ptr, misery::resolve::Layout(), anchors);
    Log("runtime: content generation %llu published -- %s, %u objects, %u "
        "slice(s), longest %uus, %u anchor identities",
        static_cast<unsigned long long>(generation),
        misery::resolve::PhaseName(anchors.reached), cost.objects, cost.slices,
        cost.max_slice_us,
        static_cast<unsigned>(anchors.identities.size()));
    Log("runtime: generation %llu: ItemList 0x%llx, MasterItemList 0x%llx, "
        "RowStruct 0x%llx (%u bytes)",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(anchors.item_list),
        static_cast<unsigned long long>(anchors.master_item_list),
        static_cast<unsigned long long>(anchors.row_struct),
        anchors.row_struct_size);

    // The authoritative identity of every anchor, not just where it lives.
    //
    // An address is not an identity, and this build proves it: a measured
    // RestartLevel left ItemList, MasterItemList and RowStruct at byte-identical
    // addresses while destroying the world around them. Two generations can only
    // be told apart -- and a revocation can only be justified -- by the slot the
    // engine itself keeps: InternalIndex and SerialNumber. Logging them makes
    // "these are different generations" a readable fact rather than an inference
    // from an address that may well be reused.
    for (const misery::resolve::AnchorIdentity& identity : anchors.identities) {
      Log("runtime: generation %llu anchor %s: index %d, serial %d, 0x%llx",
          static_cast<unsigned long long>(generation), identity.label.c_str(),
          identity.internal_index, identity.serial_number,
          static_cast<unsigned long long>(identity.address));
    }

    // The new world gets the declared items. This is what makes a mod's item
    // survive a transition: the rows died with the previous world, and these
    // are written into the new one without the mod being told anything
    // happened -- which is why proving a transition needs no invented event.
    if (misery::items::DeclaredCount() > 0) {
      const unsigned live = ApplyPendingItems();
      Log("runtime: %u of %u declared item(s) live in generation %llu", live,
          misery::items::DeclaredCount(),
          static_cast<unsigned long long>(generation));
    }

    // CoreCLR starts AFTER the first generation exists, and only once.
    //
    // A mod registers items from OnLoad, and waiting for a generation means the
    // bridge is answering real questions by the time it does.
    //
    // It does NOT mean the item can be written yet. The first generation is
    // usually the main menu, which has no world to hold item rows, so a
    // registration there is recorded as a declaration and applied when a world
    // arrives. Waiting for a GAMEPLAY generation instead would be the wrong
    // fix: mods would not load until the player entered a save, and a mod
    // platform that cannot run at the main menu cannot host a settings screen.
    if (!g_managed_started) {
      std::string managed_error;
      if (misery::managed::Start(g_framework_dir, g_root, g_host_handle,
                                 &LogLine, &managed_error)) {
        g_managed_started = true;
        Log("runtime: managed host started against content generation %llu",
            static_cast<unsigned long long>(generation));
      } else {
        // Not fail-closed. An install with no mods, or a managed host that
        // refuses, leaves the native side running and the game playable.
        Log("runtime: managed host not started -- %s", managed_error.c_str());
        g_managed_started = true;   // do not retry every poll
      }
    }
  }
}

DWORD WINAPI RuntimeThread(LPVOID) {
  std::string why;
  if (!WaitForEngine(&why)) {
    Log("FAIL CLOSED: %s", why.c_str());
    return 1;
  }

  uint64_t guobjectarray = 0, namepool = 0;
  std::string error;
  if (!misery::bindings::Resolve(g_profile, "guobjectarray", g_module_base,
                                 g_module_size, &guobjectarray, &error) ||
      !misery::bindings::Resolve(g_profile, "namepool", g_module_base,
                                 g_module_size, &namepool, &error)) {
    Log("FAIL CLOSED: %s", error.c_str());
    return 2;
  }

  // ---- the game-thread carrier ------------------------------------------
  //
  // Resolution does not run on this thread. It walks the UObject array and
  // dereferences pointers read out of it, and doing that from a worker thread
  // means racing the engine's own teardown -- unsafe by construction whenever
  // objects are churning, whatever has or has not been observed to go wrong.
  //
  // So the walk goes onto the game thread through the proven carrier, and this
  // thread only waits for the answer. The carrier re-verifies the build's own
  // signature bytes and binds nothing on a mismatch, so an unsupported build
  // gets no pump and no resolution.
  misery::gamethread::CarrierInput carrier;
  struct Wanted { const char* name; uint64_t* address; uint8_t* signature; };
  const Wanted wanted[] = {
      {"add_ticker", &carrier.add_ticker, carrier.sig_add},
      {"get_core_ticker", &carrier.get_core_ticker, carrier.sig_get},
      {"fmemory_malloc", &carrier.fmemory_malloc, carrier.sig_malloc},
  };
  for (const Wanted& item : wanted) {
    auto found = g_profile.addresses.find(item.name);
    if (found == g_profile.addresses.end() || !found->second.has_expected) {
      Log("FAIL CLOSED: the profile does not describe the carrier address %s",
          item.name);
      return 5;
    }
    if (!misery::bindings::Resolve(g_profile, item.name, g_module_base,
                                   g_module_size, item.address, &error)) {
      Log("FAIL CLOSED: %s", error.c_str());
      return 5;
    }
    memcpy(item.signature, found->second.expected, 16);
  }
  if (!misery::gamethread::Ensure(carrier, &error)) {
    Log("FAIL CLOSED: %s", error.c_str());
    return 6;
  }
  Log("runtime: the game-thread carrier is active");

  // Only the STARTUP phase here. Content the game loads with a save is not
  // guaranteed present, and -- measured -- content that IS present before
  // gameplay is destroyed and recreated when the world is replaced. Asking for
  // startup means the result physically cannot carry those pointers, so nothing
  // downstream can cache one by accident.
  misery::resolve::Request request;
  request.require = misery::resolve::Phase::kStartup;
  misery::resolve::Anchors anchors;
  misery::resolve::Failure failure;
  misery::gamethread::Cost cost;
  if (!misery::gamethread::Resolve(guobjectarray, namepool, request, &anchors,
                                   &failure, kResolveTimeoutMs, &cost,
                                   &error)) {
    Log("FAIL CLOSED: the startup anchors did not resolve: %s",
        failure.failed ? failure.what.c_str() : error.c_str());
    return 4;
  }
  Log("runtime: %u live objects", cost.objects);
  Log("runtime: startup anchors resolved (reached %s, %zu not present, %zu "
      "observed but out of phase)",
      misery::resolve::PhaseName(anchors.reached), anchors.missing.size(),
      anchors.observed_out_of_phase.size());
  // Kept in the log because it is the number that decides whether a whole walk
  // can stay whole. If it grows, the walk gets chunked across ticks -- it does
  // not move back off the game thread.
  Log("runtime: resolved on thread %u (this thread is %u) over %u slice(s); "
      "LONGEST SLICE %uus (slice #%u) -- walk %uus + anchors %uus + validate %uus, %u "
      "queued; %u objects processed, %u restart(s), %u revalidation failure(s)",
      cost.thread_id, GetCurrentThreadId(), cost.slices, cost.max_slice_us,
      cost.max_slice_index, cost.build_us, cost.resolve_us, cost.validate_us,
      cost.queued_us,
      cost.objects_processed, cost.restarts, cost.revalidation_failures);
  Log("runtime: %u reads, %u VirtualQuery, %u cached; phase requested %s, "
      "completed %s",
      cost.reads, cost.vqueries, cost.cache_hits,
      misery::resolve::PhaseName(
          static_cast<misery::resolve::Phase>(cost.requested_phase)),
      misery::resolve::PhaseName(
          static_cast<misery::resolve::Phase>(cost.completed_phase)));

  // ---- step 2: the proven native subsystems -----------------------------
  //
  // Order matters and is not arbitrary. The game thread must be DECLARED before
  // the bridge is acquired, because every bridge call is thread-checked against
  // it and a bridge acquired first would spend its first moments unable to say
  // whether a caller was legitimate.
  //
  // The thread declared is the one the resolution ACTUALLY ran on, reported by
  // the resolver rather than assumed by this code. That is the whole reason the
  // cost record carries a thread id: this is the consumer that needed it.
  MiseryBridgeSetGameThread(cost.thread_id);
  Log("runtime: game thread declared as %u (measured, not assumed)",
      cost.thread_id);

  const MbRoot* root = nullptr;
  MbHandle host_handle = MB_INVALID_HANDLE;
  MbError bridge_error = {};
  if (MiseryBridgeAcquire(MB_ABI_EPOCH, &root, &host_handle, &bridge_error) !=
          MB_STATUS_OK || root == nullptr) {
    Log("FAIL CLOSED: MiseryBridgeAcquire refused: %.*s",
        static_cast<int>(bridge_error.detail.length),
        bridge_error.detail.data ? bridge_error.detail.data : "");
    return 7;
  }
  if (root->struct_size != MB_ROOT_EXPECTED_SIZE) {
    // The frozen root is the one thing that cannot be fixed later, so a size
    // that is not the expected one is refused rather than read.
    Log("FAIL CLOSED: the bridge root is %u bytes, expected %u",
        root->struct_size, MB_ROOT_EXPECTED_SIZE);
    return 8;
  }
  g_root = root;
  g_host_handle = host_handle;
  Log("runtime: bridge acquired, ABI epoch %u, root %u bytes",
      static_cast<unsigned>(MB_ABI_EPOCH), root->struct_size);

  // ---- reaching the content phase ---------------------------------------
  //
  // Everything item-shaped needs content, and content does not exist at the
  // main menu on a launch that goes straight there. So the runtime waits for
  // it, by ASKING rather than by guessing from an object count: the resolver is
  // the authority on whether content is present, and a threshold on the number
  // of live objects would be a tuned constant standing in for a real answer.
  //
  // The cadence is deliberately slow. A content-phase resolution costs roughly
  // a third of a second of game thread spread over a few hundred slices, so
  // polling hard would be a permanent background drain for the whole time a
  // player sits in a menu.
  // The items backend, installed as the bridge's. It takes the profile and the
  // roots; it does NOT take anchors, because anchors belong to a generation and
  // it acquires one per call.
  misery::items::Install(g_profile, g_module_base, guobjectarray, &LogLine);
  Log("runtime: items backend installed; it will bind to a content generation "
      "on first use and rebind if that generation is revoked");

  Log("runtime: native subsystems ready; entering the content lifecycle");
  ContentLifecycle(guobjectarray, namepool);
  return 0;
}

}  // namespace

// The proxy's entry point. Returns 0 only when the profile has been read AND
// every code address it names holds the bytes it recorded.
extern "C" __declspec(dllexport) int MiseryRuntimeBootstrap(
    const char* framework_dir, const char* bindings_path,
    const char* build_key) {
  if (framework_dir == nullptr || bindings_path == nullptr ||
      build_key == nullptr) {
    return 1;
  }
  g_framework_dir = framework_dir;
  g_bindings_path = bindings_path;
  _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%s\\runtime.log",
              framework_dir);

  // The proxy hands over the bare hex digest; the profile writes it with the
  // algorithm named. Normalised here rather than in the reader, which stays
  // strict about the form it compares.
  g_build_key = build_key;
  if (g_build_key.rfind("sha256:", 0) != 0) {
    g_build_key = "sha256:" + g_build_key;
  }

  if (!ThisImage(&g_module_base, &g_module_size)) {
    Log("FAIL CLOSED: the running image's own PE headers could not be read");
    return 2;
  }

  std::string error;
  if (!misery::bindings::Load(bindings_path, g_build_key.c_str(), &g_profile,
                              &error)) {
    Log("FAIL CLOSED: %s", error.c_str());
    return 3;
  }
  Log("runtime: profile for %s loaded (engine %s CL %lld, %zu addresses)",
      g_profile.build_id.c_str(), g_profile.engine_version.c_str(),
      static_cast<long long>(g_profile.engine_cl), g_profile.addresses.size());

  if (!misery::bindings::VerifyCode(g_profile, g_module_base, g_module_size,
                                    &error)) {
    Log("FAIL CLOSED: %s", error.c_str());
    return 4;
  }
  Log("runtime: every code address in the profile matches live memory");

  // Everything from here needs the engine, so it goes on its own thread. The
  // proxy's bootstrap thread returns immediately and stops being involved.
  HANDLE thread = CreateThread(nullptr, 0, &RuntimeThread, nullptr, 0, nullptr);
  if (thread == nullptr) {
    Log("FAIL CLOSED: the runtime thread could not be created (%lu)",
        GetLastError());
    return 5;
  }
  CloseHandle(thread);
  return 0;
}
