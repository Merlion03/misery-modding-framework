// ManagedHost.cpp -- CoreCLR and the managed host, started by the runtime.
//
// WHAT MOVED, AND WHAT DID NOT
// ----------------------------
// Stage 5A already started CoreCLR inside live MISERY and ran C# mods against
// the bridge. It did so from Stage5RuntimeDll.cpp, driven by a research
// controller that handed in three strings: where nethost is, where the managed
// host assembly is, and which mods to load. Those three strings were the last
// Python dependency on this path.
//
// This file supplies them from the installation instead. Nothing about the
// hosting changed -- same nethost/hostfxr shim, same Misery.ModHost, same
// single trampoline, same collectible contexts.
//
// IT RUNS ON THE GAME THREAD, AND THAT IS NOT AN OPTIMISATION
// -----------------------------------------------------------
// The managed host records "the game thread" as whichever thread calls
// Bootstrap, and every bridge call is then checked against it. Starting CoreCLR
// from the runtime's worker would hand the whole threading contract a thread the
// engine has never heard of -- every legitimate call refused, every
// illegitimate one allowed. So the bootstrap is a game-thread job, and the
// visible one-off stall that costs is accepted deliberately, exactly as Stage 5A
// accepted it.
//
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <string>
#include <vector>

#include "../Public/MiseryBridge.h"
#include "Json.h"
#include "ManagedHost.h"
#include "ModDiscovery.h"
#include "ResolveOnGameThread.h"
#include "../../../managed/hostfxr_shim.h"

namespace misery {
namespace managed {
namespace {

struct StartArgs {
  std::string nethost_path;
  std::string host_assembly;
  std::string plan;
  const MbRoot* root = nullptr;
  MbHandle host_handle = MB_INVALID_HANDLE;
  LogFn log = nullptr;
  bool ok = false;
  std::string error;
  std::string report;
};

MiseryHost* g_host = nullptr;

void StartJob(void* ctx) {
  StartArgs* args = static_cast<StartArgs*>(ctx);

  // nethost is loaded from an explicit absolute path first. Inside a shipping
  // game the DLL search order is not ours to predict, and the shim then finds it
  // by name.
  if (LoadLibraryA(args->nethost_path.c_str()) == nullptr) {
    args->error = "nethost.dll could not be loaded from " + args->nethost_path;
    return;
  }
  g_host = new MiseryHost();
  if (!g_host->Start(args->host_assembly, &args->error)) {
    return;
  }
  // Load, not Bootstrap: Bootstrap is the Stage 5A acceptance suite and needs
  // a fixed fixture set. Production loads whatever is installed.
  const int rc = g_host->Load(args->root, args->host_handle,
                              args->plan.c_str());
  args->report = g_host->FetchReport();
  if (rc != 0) {
    args->error = "the managed host refused the load plan (" +
                  std::to_string(rc) + ")";
    return;
  }
  args->ok = true;
}

// Turns the host's report into lines a person can act on.
//
// The report also carries a full native snapshot -- handle counts, slot census,
// fault tallies -- which is genuinely useful when something is wrong and pure
// noise when nothing is. It is logged verbatim only in the failing case.
void Summarise(const std::string& report, size_t planned, LogFn log) {
  if (log == nullptr || report.empty()) {
    return;
  }
  json::Value parsed;
  std::string why;
  if (!json::Parse(report, &parsed, &why)) {
    // Never silently dropped: an unreadable report is itself a finding.
    log(("managed: the host's report could not be read (" + why +
         "); verbatim: " + report).c_str());
    return;
  }
  const json::Value* loaded = parsed.Member("loaded_count");
  const json::Value* failed = parsed.Member("failed_count");
  if (loaded == nullptr || !loaded->Is(json::Kind::kInt) ||
      failed == nullptr || !failed->Is(json::Kind::kInt)) {
    log(("managed: report " + report).c_str());
    return;
  }
  log(("managed: " + std::to_string(loaded->integer) + " of " +
       std::to_string(planned) + " planned mod(s) loaded, " +
       std::to_string(failed->integer) + " failed").c_str());

  const json::Value* failures = parsed.Member("failed");
  if (failures != nullptr && failures->Is(json::Kind::kArray)) {
    for (const json::Value& entry : failures->array) {
      const json::Value* mod = entry.Member("mod");
      const json::Value* error = entry.Member("error");
      if (mod != nullptr && error != nullptr) {
        log(("managed: mod '" + mod->text + "' did not load: " + error->text)
                .c_str());
      }
    }
  }
  if (failed->integer > 0) {
    log(("managed: full report " + report).c_str());
  }
}

}  // namespace

bool Start(const std::string& framework_dir, const MbRoot* root,
           MbHandle host_handle, LogFn log, std::string* error) {
  std::vector<std::string> found;
  std::vector<std::string> skipped;
  StartArgs args;
  args.nethost_path = framework_dir + "\\nethost.dll";
  args.host_assembly = framework_dir + "\\Misery.ModHost.dll";
  args.plan = DiscoverPlan(framework_dir, &found, &skipped);
  args.root = root;
  args.host_handle = host_handle;
  args.log = log;

  if (GetFileAttributesA(args.host_assembly.c_str()) ==
      INVALID_FILE_ATTRIBUTES) {
    *error = "the managed host assembly is not installed at " +
             args.host_assembly;
    return false;
  }
  // Reported before the empty-plan check: "no managed mods are installed" is a
  // misleading thing to say when two were installed and both were refused.
  if (log != nullptr) {
    for (const std::string& why : skipped) {
      log(("managed: skipped " + why).c_str());
    }
  }
  if (args.plan.empty()) {
    // Not a failure. An installation with no mods is a perfectly ordinary one,
    // and starting CoreCLR to load nothing would be pure cost.
    *error = "no managed mods are installed; CoreCLR was not started";
    return false;
  }
  if (log != nullptr) {
    std::string line = "managed: " + std::to_string(found.size()) +
                       " mod(s) to load:";
    for (const std::string& name : found) {
      line += " " + name;
    }
    log(line.c_str());
  }

  std::string why;
  if (!gamethread::RunBlocking(&StartJob, &args, 180000, &why)) {
    *error = "the managed host could not be started on the game thread: " + why;
    return false;
  }
  if (!args.ok) {
    *error = args.error.empty() ? "the managed host failed to start"
                                : args.error;
    Summarise(args.report, found.size(), log);
    return false;
  }
  Summarise(args.report, found.size(), log);
  return true;
}

}  // namespace managed
}  // namespace misery
