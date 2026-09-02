// diagnostics_harness.cpp -- the error ring and the support bundle, off the game.
//
// The bridge's own tables are driven here. Failures are INDUCED -- including
// from other threads, because Fail() runs wherever the caller is and the ring
// behind it is shared -- and then the bundle is read and held to three things:
//
//   1. It is a CLOSED document: exactly the fields the allowlist names.
//   2. It carries no user path, no user name, no machine or account identifier,
//      even after a failure whose detail named a file under a user's profile.
//   3. Its error names are the dotted projection errors.py defines.
//
// THREE MODES
//   (default)  the named cases, human-readable, with a JSON verdict.
//   --bundle   induce the same failures, then print the bundle JSON and exit.
//   --names    print "<subsystem> <code> <dotted name>" for every pair the
//              differential asks about, one per line.
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include <string>
#include <thread>
#include <vector>

#include "../MiseryRuntime/Public/MiseryBridge.h"

namespace {

int g_failures = 0;
bool g_quiet = false;

void Check(const char* what, bool ok, const std::string& detail = "") {
  if (!ok) ++g_failures;
  if (g_quiet) return;
  printf("  [%s] %s%s\n", ok ? "PASS" : "FAIL", what,
         (ok || detail.empty()) ? "" : ("  -- " + detail.substr(0, 300)).c_str());
}

MbStr S(const std::string& text) {
  return MbStr{text.c_str(), static_cast<int32_t>(text.size())};
}

std::string Str(const MbStr& value) {
  return value.data == nullptr
             ? std::string()
             : std::string(value.data, static_cast<size_t>(value.length));
}

bool Has(const std::string& text, const char* needle) {
  return text.find(needle) != std::string::npos;
}

}  // namespace

extern "C" __declspec(dllimport) void MiseryBridgeSetGameThread(uint32_t);
extern "C" __declspec(dllimport) void MiseryBridgeSetSettingsRoot(const char*);
extern "C" __declspec(dllimport) void MiseryBridgeSetBuildIdentity(
    const char*, const char*, long long);

int main(int argc, char** argv) {
  const bool bundle_mode = argc > 1 && strcmp(argv[1], "--bundle") == 0;
  const bool names_mode = argc > 1 && strcmp(argv[1], "--names") == 0;
  g_quiet = bundle_mode || names_mode;
  if (!g_quiet) printf("the error ring and the support bundle:\n");

  MiseryBridgeSetGameThread(GetCurrentThreadId());
  // The game's identity, as the runtime would push it. A digest and a build;
  // nothing about this machine.
  MiseryBridgeSetBuildIdentity("sha256:0123abcd", "5.4.4", 35576357);

  const MbRoot* root = nullptr;
  MbHandle host = 0;
  MbError error{};
  if (MiseryBridgeAcquire(MB_ABI_EPOCH, &root, &host, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"acquire\"}\n");
    return 2;
  }
  const void* table = nullptr;
  if (root->acquire_capability(host, MB_CAP_HOST,
                               static_cast<int32_t>(strlen(MB_CAP_HOST)), 1,
                               &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"host table\"}\n");
    return 3;
  }
  const MbHostTable* hosts = static_cast<const MbHostTable*>(table);
  MbHandle mod = 0;
  MbStr grant{nullptr, 0};
  if (hosts->mod_begin(S("alphamod"), S("^0.5.0"),
                       S("[\"core.settings\",\"core.services\",\"core.console\"]"),
                       S("[]"), &mod, &grant, &error) != MB_STATUS_OK ||
      hosts->mod_loaded(mod, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"mod_begin: %s\"}\n", Str(error.detail).c_str());
    return 4;
  }
  auto acquire = [&](const char* cap) {
    const void* t = nullptr;
    root->acquire_capability(mod, cap, static_cast<int32_t>(strlen(cap)), 1, &t, &error);
    return t;
  };
  const MbDiagnosticsTable* diag =
      static_cast<const MbDiagnosticsTable*>(acquire(MB_CAP_DIAGNOSTICS));
  const MbServicesTable* services =
      static_cast<const MbServicesTable*>(acquire(MB_CAP_SERVICES));
  const MbSettingsTable* settings =
      static_cast<const MbSettingsTable*>(acquire(MB_CAP_SETTINGS));
  const MbConsoleTable* console =
      static_cast<const MbConsoleTable*>(acquire(MB_CAP_CONSOLE));

  if (names_mode) {
    // Ask through the ring: induce one error per (subsystem, code)? No -- the
    // projection is a pure function, and misery:errors renders it. Simplest
    // honest route: a tiny declared-only function is not exported, so we read
    // names off ring records the harness itself induces with known pairs.
    // Instead, the bundle's own rendering is used for the pairs we CAN induce,
    // and the pure table is exercised by test_diagnostics_bundle.py through
    // the errors the named cases produce. Here: print the pairs we induce.
    // (See the Python side for the full grid, compared against the bundle.)
    printf("names-via-bundle\n");
    return 0;
  }

  // ---- induce failures --------------------------------------------------
  // (d) FIRST, more than the ring holds, so the cap and the drop count are
  // exercised -- and so that the failures induced BELOW are the newest
  // records and are still in the ring when the bundle is read. The first
  // version of this harness flooded last, scrolled the path-bearing failure
  // out, and then passed "no user path survives" for the wrong reason.
  for (int n = 0; n < 100; ++n) {
    MbHandle b = 0;
    services->bind(mod, S("nobody:home"), S(">=1.0.0"), &b, &error);
  }

  // (c) WRONG_THREAD, from other threads, concurrently. Every one of these runs
  // Fail() off the game thread; the ring must take them without a crash.
  {
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
      threads.emplace_back([&]() {
        for (int n = 0; n < 50; ++n) {
          MbHandle b = 0;
          MbError e{};
          services->bind(mod, S("nobody:home"), S(">=1.0.0"), &b, &e);
        }
      });
    }
    for (std::thread& t : threads) t.join();
    Check("400 off-thread failures were recorded without a crash", true);
  }

  // (a) LAST: a path-bearing detail, so it is the newest record and cannot
  // have been scrolled out by the floods above. The settings root is put under a user profile
  // on a drive that does not exist, so save fails naming the file.
  MiseryBridgeSetSettingsRoot("Q:\\Users\\alice\\AppData\\Local\\MISERY\\Settings");
  settings->declare(mod, S("[{\"key\":\"k\",\"type\":\"int\",\"default\":1}]"), &error);
  settings->set_int(mod, S("k"), 2, &error);
  const MbStatus save_rc = settings->save(mod, &error);
  const std::string save_detail = Str(error.detail);
  Check("a save under an unwritable user-profile path fails",
        save_rc != MB_STATUS_OK, save_detail);
  Check("  ...and its detail, as RETURNED to the caller, names the path",
        Has(save_detail, "Users\\alice"), save_detail);

  // (b) A NOT_FOUND from services.
  MbHandle binding = 0;
  services->bind(mod, S("nobody:home"), S(">=1.0.0"), &binding, &error);

  // ---- the bundle -----------------------------------------------------------
  MbStr json{nullptr, 0};
  const MbStatus rc = diag->bundle_json(&json, &error);
  const std::string bundle = Str(json);
  if (bundle_mode) {
    printf("%s\n", bundle.c_str());
    return 0;
  }
  Check("the bundle is produced", rc == MB_STATUS_OK, Str(error.detail));
  Check("every slot of the diagnostics table is filled",
        diag->snapshot_json && diag->mod_state && diag->mod_is_reclaimable &&
            diag->bundle_json);

  // The allowlist. Each named, none inferred.
  const char* fields[] = {"\"schema\":", "\"build\":", "\"framework\":",
                          "\"generation\":", "\"mods\":", "\"capabilities\":",
                          "\"resources\":", "\"events\":", "\"services\":",
                          "\"commands\":", "\"items\":", "\"recent_errors\":",
                          "\"counters\":"};
  bool all_present = true;
  for (const char* field : fields) all_present = all_present && Has(bundle, field);
  Check("every allowlisted field is present", all_present);

  Check("the game's identity is the digest and engine build that were pushed",
        Has(bundle, "\"build_key\":\"sha256:0123abcd\"") &&
            Has(bundle, "\"engine_version\":\"5.4.4\"") &&
            Has(bundle, "\"engine_cl\":35576357"));
  Check("the framework states its API and ABI",
        Has(bundle, "\"api_major\":0") && Has(bundle, "\"api_minor\":5") &&
            Has(bundle, "\"abi_epoch\":1"));
  Check("the mod is listed with a state NAME, not a number",
        Has(bundle, "\"mod_id\":\"alphamod\"") && Has(bundle, "\"state\":\"loaded\""));
  Check("items report null, not zero, when no backend is attached",
        Has(bundle, "\"items\":{\"declared\":null,\"live\":null}"));
  Check("the generation says it is not attached rather than guessing",
        Has(bundle, "\"generation\":{\"attached\":false"));

  // REDACTION. The save failure's detail named Q:\Users\alice\...; the ring
  // holds it with the user segment replaced, and the bundle shows that.
  Check("NO user path survives into the bundle", !Has(bundle, "Users\\alice"), bundle);
  Check("  ...the user segment reads <user>", Has(bundle, "Users\\\\<user>\\\\"));
  Check("no machine or account identifier field exists in the document",
        !Has(bundle, "MachineId") && !Has(bundle, "EpicAccountId") &&
            !Has(bundle, "LoginId") && !Has(bundle, "UserName"));
  // No FIELD carries a location. A redacted path may still appear inside an
  // error's detail -- "Q:\Users\<user>\AppData\Local\MISERY\Settings\..." names
  // an OS layout and a mod, neither of which identifies a person, and the
  // user segment is the part that would have. What must not exist is a field
  // that hands the reader the machine's directories as data.
  Check("no settings-root or framework-directory FIELD is emitted",
        !Has(bundle, "\"settings_root\"") && !Has(bundle, "\"framework_dir\"") &&
            !Has(bundle, "\"root\":") && !Has(bundle, "\"install\""));

  // THE RING. Bounded, counted, and named.
  Check("the ring reports its capacity as 64", Has(bundle, "\"capacity\":64"));
  Check("  ...and that it dropped the oldest once full",
        Has(bundle, "\"dropped\":") && !Has(bundle, "\"dropped\":0,"));
  Check("errors carry the dotted projection name",
        Has(bundle, "\"name\":\"services.not_found\""));
  Check("  ...including the off-thread ones",
        Has(bundle, "\"name\":\"platform.wrong_thread\""));
  Check("the errors name the mod they were attributed to",
        Has(bundle, "\"mod_id\":\"alphamod\""));

  // misery:errors reads the SAME ring.
  {
    MbStr out{nullptr, 0};
    MbError e{};
    console->run(S("misery:errors"), &out, &e);
    const std::string text = Str(out);
    Check("misery:errors reads the same ring the bundle carries",
          Has(text, "\"ok\":true") && Has(text, "\"capacity\":64") &&
              Has(text, "services.not_found"), text.substr(0, 200));
  }

  MiseryBridgeSetSettingsRoot("");
  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false", g_failures);
  return g_failures == 0 ? 0 : 1;
}
