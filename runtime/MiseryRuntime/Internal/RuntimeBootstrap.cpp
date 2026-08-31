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

#include "Bindings.h"
#include "ResolveOnGameThread.h"
#include "Resolver.h"

namespace {

// How long the engine is given to come up before the runtime gives up. Chosen
// to be longer than any observed start on this machine by a wide margin: the
// cost of waiting too long is a late start, the cost of waiting too little is a
// framework that fails on somebody else's slower disk.
constexpr DWORD kEngineReadyTimeoutMs = 180000;
constexpr DWORD kEnginePollMs = 250;
// One resolution, waited on from this thread. Long enough to survive a slow
// frame during a load; short enough that a pump that never runs is reported
// rather than waited on forever.
constexpr uint32_t kResolveTimeoutMs = 30000;

char g_log_path[MAX_PATH] = {0};
std::string g_framework_dir;
std::string g_bindings_path;
std::string g_build_key;
misery::bindings::Profile g_profile;
uint64_t g_module_base = 0;
uint64_t g_module_size = 0;

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
  Log("runtime: resolved on thread %u (this thread is %u) -- cost %uus queued "
      "+ %uus walk + %uus anchors; %u reads, %u VirtualQuery, %u cached",
      cost.thread_id, GetCurrentThreadId(), cost.queued_us, cost.build_us,
      cost.resolve_us, cost.reads, cost.vqueries, cost.cache_hits);

  // ---- the seam ---------------------------------------------------------
  // Next: the game-thread carrier, then the items backend, then CoreCLR and the
  // Stage 4 load plan. Each attaches here, and each keeps this property: it
  // runs only after the bindings above verified, so nothing downstream ever has
  // to re-ask whether this build is the one we were built against.
  Log("runtime: bindings consumed; subsystem start is the next step");
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
