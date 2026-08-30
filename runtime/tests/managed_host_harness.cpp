// managed_host_harness.cpp -- native CoreCLR hosting, off the game.
//
// WHY THIS EXISTS BEFORE THE IN-GAME RUN
// -------------------------------------
// The Stage 5A gate asks whether the Stage 4.5 contracts survive a real
// CoreCLR-hosted C# mod. Almost all of that question -- assembly loading,
// per-mod collectible contexts, the trampoline, failure isolation, threading,
// and whether an AssemblyLoadContext actually collects -- has nothing to do with
// MISERY. Answering it here means the in-game run tests the ONE thing only the
// game can answer (does a real item appear), instead of debugging hostfxr
// inside a process that takes two minutes to reach gameplay and cannot be
// stepped through.
//
// This is the same architecture the in-game runtime uses:
//
//     this exe  ->  MiseryBridgeAcquire  ->  hostfxr/CoreCLR  ->  Misery.ModHost
//
// with a RECORDING items backend installed instead of the real one. The
// difference is one function pointer.
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <map>
#include <string>
#include <vector>

#include "../MiseryRuntime/Public/MiseryBridge.h"
#include "../../managed/hostfxr_shim.h"

// ---------------------------------------------------------------- items ----
// A recording backend. It derives the row name exactly the way Stage 2 does --
// "<mod_id>__<local_id>" -- because the row name is DERIVED and a backend that
// invented its own would be testing something else.
static std::map<std::string, std::string> g_rows;
static std::vector<std::string> g_item_log;

static std::string JsonField(const std::string& json, const std::string& key) {
  std::string needle = "\"" + key + "\":\"";
  size_t at = json.find(needle);
  if (at == std::string::npos) {
    return std::string();
  }
  size_t start = at + needle.size();
  size_t end = json.find('"', start);
  return end == std::string::npos ? std::string()
                                  : json.substr(start, end - start);
}

extern "C" int RecordingRegister(const char* mod_id, const char* declaration_json,
                                 char* out_row_name, int out_capacity) {
  std::string local = JsonField(declaration_json ? declaration_json : "",
                                "local_id");
  if (local.empty()) {
    return 1;
  }
  std::string row = std::string(mod_id) + "__" + local;
  if (g_rows.count(row) != 0) {
    return 2;   // already registered: the same refusal the live path gives
  }
  g_rows[row] = mod_id;
  g_item_log.push_back("register " + row);
  if (static_cast<int>(row.size()) + 1 > out_capacity) {
    return 3;
  }
  memcpy(out_row_name, row.c_str(), row.size() + 1);
  return 0;
}

extern "C" int RecordingUnregister(const char* mod_id, const char* row_name) {
  (void)mod_id;
  if (g_rows.erase(row_name ? row_name : "") == 0) {
    return 1;
  }
  g_item_log.push_back(std::string("unregister ") + row_name);
  return 0;
}

// ----------------------------------------------------------------- main ----
int main(int argc, char** argv) {
  if (argc < 4) {
    printf("usage: managed_host_harness <bridge.dll> <Misery.ModHost.dll> "
           "\"modId=path;modId=path;...\"\n");
    return 2;
  }
  const char* bridge_path = argv[1];
  const char* host_assembly = argv[2];
  const char* plan = argv[3];

  // 1. The bridge, and the host handle it mints in-process.
  HMODULE bridge = LoadLibraryA(bridge_path);
  if (bridge == nullptr) {
    printf("{\"ok\":false,\"error\":\"could not load %s (%lu)\"}\n", bridge_path,
           GetLastError());
    return 3;
  }
  MbAcquireFn acquire =
      reinterpret_cast<MbAcquireFn>(GetProcAddress(bridge, MB_ACQUIRE_SYMBOL));
  if (acquire == nullptr) {
    printf("{\"ok\":false,\"error\":\"%s has no %s\"}\n", bridge_path,
           MB_ACQUIRE_SYMBOL);
    return 4;
  }

  typedef void (*InstallFn)(int (*)(const char*, const char*, char*, int),
                            int (*)(const char*, const char*));
  InstallFn install = reinterpret_cast<InstallFn>(
      GetProcAddress(bridge, "MiseryBridgeInstallItemsBackend"));
  if (install != nullptr) {
    install(RecordingRegister, RecordingUnregister);
  }

  typedef void (*SetThreadFn)(unsigned long);
  SetThreadFn set_thread = reinterpret_cast<SetThreadFn>(
      GetProcAddress(bridge, "MiseryBridgeSetGameThread"));
  if (set_thread != nullptr) {
    // THIS thread stands in for the game thread. The whole point is that the
    // managed side must refuse calls from any other, and it cannot do that
    // unless somebody declares which one is privileged.
    set_thread(GetCurrentThreadId());
  }

  const MbRoot* root = nullptr;
  MbHandle host_handle = MB_INVALID_HANDLE;
  MbError error = {};
  MbStatus status = acquire(MB_ABI_EPOCH, &root, &host_handle, &error);
  if (status != MB_OK || root == nullptr) {
    printf("{\"ok\":false,\"error\":\"MiseryBridgeAcquire failed: %.*s\"}\n",
           error.detail.length, error.detail.data ? error.detail.data : "");
    return 5;
  }
  if (root->struct_size != MB_ROOT_EXPECTED_SIZE) {
    printf("{\"ok\":false,\"error\":\"root is %u bytes, expected %u\"}\n",
           root->struct_size, MB_ROOT_EXPECTED_SIZE);
    return 6;
  }

  // 2. CoreCLR, through hostfxr.
  MiseryHost host;
  std::string host_error;
  if (!host.Start(host_assembly, &host_error)) {
    printf("{\"ok\":false,\"error\":\"%s\"}\n", host_error.c_str());
    return 7;
  }

  // 3. Hand the managed side the root it must not have had to find itself.
  int rc = host.Bootstrap(root, host_handle, plan);
  std::string report = host.FetchReport();
  printf("%s\n", report.c_str());
  printf("{\"items_backend\":{\"rows_left\":%d,\"operations\":%d}}\n",
         static_cast<int>(g_rows.size()), static_cast<int>(g_item_log.size()));

  // Every row a mod registered must be gone once every mod is unloaded. This is
  // the harness checking the BACKEND, which the managed side cannot see.
  if (!g_rows.empty()) {
    printf("{\"ok\":false,\"error\":\"the items backend still holds %d row(s)\"}\n",
           static_cast<int>(g_rows.size()));
    return 8;
  }
  return rc == 0 && report.find("\"ok\":true") != std::string::npos ? 0 : 9;
}
