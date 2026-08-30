// Stage5RuntimeDll.cpp -- starting the managed host inside live MISERY.
//
// This is the thin piece that turns the off-game harness into the in-game
// runtime. It does exactly four things, and the harness does the same four with
// one substitution:
//
//   1. declare which thread is the game thread
//   2. install the items backend        <-- the ONLY difference: the real
//                                           CR-01C5 path instead of a recorder
//   3. acquire the bridge root
//   4. start CoreCLR and call the managed host
//
// EVERYTHING RUNS ON THE GAME THREAD, AND THAT IS NOT A DETAIL
// ------------------------------------------------------------
// The managed host records "the game thread" as whichever thread calls
// Bootstrap, and every bridge call is then refused from anywhere else. So
// Bootstrap must run on the real game thread, which means going through the
// dispatcher rather than the injected thread the loader gives us.
//
// Starting CoreCLR on the game thread costs a visible stall -- hundreds of
// milliseconds, once. That is accepted deliberately: the alternative is a
// managed host whose notion of the game thread is a thread the engine has never
// heard of, which would make every threading guarantee in the stage meaningless.
//
// The caller polls `done` rather than blocking, for the same reason: the thread
// that must run the work is the one it would otherwise be waiting on.
#include <stdint.h>
#include <string.h>
#include <windows.h>

#include <string>

#include "../Public/MiseryBridge.h"
#include "../Public/MiseryGameThread.h"
#include "../../../managed/hostfxr_shim.h"

#define STAGE5_IO_MAGIC 0x35454741545300ULL   // "STAGE5"
#define STAGE5_IO_PROTO 1u

#pragma pack(push, 1)
struct Stage5Io {
  uint64_t magic;
  uint32_t proto;
  uint32_t struct_size;
  char nethost_path[512];
  char host_assembly[512];
  char plan[8192];
  uint32_t started;
  uint32_t done;
  int32_t rc;
  uint32_t game_thread_id;
  char error[1024];
  char report[32768];
};
#pragma pack(pop)

namespace {

Stage5Io* g_io = nullptr;
MiseryHost* g_host = nullptr;
bool g_ran = false;

void Say(Stage5Io* io, const char* text) {
  if (io == nullptr) {
    return;
  }
  strncpy_s(io->error, sizeof(io->error), text ? text : "", _TRUNCATE);
}

// The whole bootstrap, as one game-thread job.
void StartJob(void*) {
  Stage5Io* io = g_io;
  if (io == nullptr || g_ran) {
    return;
  }
  g_ran = true;
  io->game_thread_id = GetCurrentThreadId();

  HMODULE self = GetModuleHandleA(nullptr);
  (void)self;

  // The bridge lives in THIS module, so its exports are reachable by name.
  HMODULE me = nullptr;
  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     reinterpret_cast<LPCSTR>(&StartJob), &me);
  if (me == nullptr) {
    Say(io, "could not resolve the runtime module");
    io->rc = 10;
    io->done = 1;
    return;
  }

  typedef void (*SetThreadFn)(unsigned long);
  typedef void (*InstallFn)(int (*)(const char*, const char*, char*, int),
                            int (*)(const char*, const char*));
  typedef int (*RegisterFn)(const char*, const char*, char*, int);
  typedef int (*UnregisterFn)(const char*, const char*);

  auto set_thread =
      reinterpret_cast<SetThreadFn>(GetProcAddress(me, "MiseryBridgeSetGameThread"));
  auto install = reinterpret_cast<InstallFn>(
      GetProcAddress(me, "MiseryBridgeInstallItemsBackend"));
  auto register_item =
      reinterpret_cast<RegisterFn>(GetProcAddress(me, "Stage5RegisterItem"));
  auto unregister_item =
      reinterpret_cast<UnregisterFn>(GetProcAddress(me, "Stage5UnregisterItem"));
  auto acquire =
      reinterpret_cast<MbAcquireFn>(GetProcAddress(me, MB_ACQUIRE_SYMBOL));

  if (set_thread == nullptr || install == nullptr || register_item == nullptr ||
      unregister_item == nullptr || acquire == nullptr) {
    Say(io, "the runtime module is missing one of its own exports");
    io->rc = 11;
    io->done = 1;
    return;
  }

  // 1 and 2.
  set_thread(io->game_thread_id);
  install(register_item, unregister_item);

  // 3.
  const MbRoot* root = nullptr;
  MbHandle host_handle = MB_INVALID_HANDLE;
  MbError error = {};
  if (acquire(MB_ABI_EPOCH, &root, &host_handle, &error) != MB_OK ||
      root == nullptr) {
    Say(io, "MiseryBridgeAcquire refused");
    io->rc = 12;
    io->done = 1;
    return;
  }

  // 4. nethost has to be loadable by name once it is in the process, so it is
  // loaded from an explicit path first rather than left to the search order --
  // which inside a shipping game is not ours to predict.
  if (io->nethost_path[0] != '\0' && LoadLibraryA(io->nethost_path) == nullptr) {
    Say(io, "nethost.dll could not be loaded from the given path");
    io->rc = 13;
    io->done = 1;
    return;
  }

  g_host = new MiseryHost();
  std::string host_error;
  if (!g_host->Start(io->host_assembly, &host_error)) {
    Say(io, host_error.c_str());
    io->rc = 14;
    io->done = 1;
    return;
  }

  io->rc = g_host->Bootstrap(root, host_handle, io->plan);
  std::string report = g_host->FetchReport();
  strncpy_s(io->report, sizeof(io->report), report.c_str(), _TRUNCATE);
  io->done = 1;
}

}  // namespace

// Hand the runtime its parameters and ask for the bootstrap. Returns
// immediately; the caller polls `done`.
extern "C" __declspec(dllexport) unsigned long StartManagedHost(void* p) {
  Stage5Io* io = static_cast<Stage5Io*>(p);
  if (io == nullptr || io->magic != STAGE5_IO_MAGIC ||
      io->proto != STAGE5_IO_PROTO ||
      io->struct_size != static_cast<uint32_t>(sizeof(Stage5Io))) {
    return 0xFFFFFFFFu;
  }
  if (g_io != nullptr) {
    return 0xFFFFFFFEu;   // once per process
  }
  g_io = io;
  io->started = 1;
  io->done = 0;
  io->rc = -1;
  // Onto the GAME thread. See the header comment.
  return Misery::GameThread::Enqueue(&StartJob, nullptr) ? 0u : 1u;
}

extern "C" __declspec(dllexport) unsigned long Stage5IoSize(void) {
  return static_cast<unsigned long>(sizeof(Stage5Io));
}
