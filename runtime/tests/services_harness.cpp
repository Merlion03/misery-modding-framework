// services_harness.cpp -- bind enforces its requirement, off the game.
//
// The bridge's own tables are driven here: MiseryBridgeAcquire hands back the
// real root, MB_CAP_HOST registers mods the way the managed host does, and
// these cases call the same MbServicesTable function pointers a mod reaches
// through IModServices. Nothing is mocked and CoreCLR is not involved.
//
// The cases mirror tools/modplatform/services.py's Registry.bind, which has
// enforced the requirement since Stage 4.5. The native side did not: it opened
// with `(void)requirement;`, so a consumer could state ">=2.0.0", be handed a
// 1.2.0 provider, and be told it had succeeded.
//
// TWO MODES
//   (default)  the named cases above, human-readable, with a JSON verdict.
//   --matrix   the differential wire. Each stdin line is
//              "<published-version> <requirement>" and each reply is "ok" or
//              "<subsystem>,<code>". tests/test_services_bind.py feeds the same
//              matrix to the Python reference and requires identical answers,
//              so the port cannot quietly acquire semantics of its own.
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include <string>

#include "../MiseryRuntime/Public/MiseryBridge.h"

namespace {

int g_failures = 0;
bool g_quiet = false;

void Check(const char* what, bool ok, const std::string& detail = "") {
  if (!ok) ++g_failures;
  if (g_quiet) return;
  printf("  [%s] %s%s\n", ok ? "PASS" : "FAIL", what,
         (ok || detail.empty()) ? "" : ("  -- " + detail).c_str());
}

MbStr S(const char* text) {
  return MbStr{text, static_cast<int32_t>(strlen(text))};
}

std::string Detail(const MbError& error) {
  return error.detail.data == nullptr
             ? std::string()
             : std::string(error.detail.data,
                           static_cast<size_t>(error.detail.length));
}

}  // namespace

extern "C" __declspec(dllimport) void MiseryBridgeSetGameThread(uint32_t);

int main(int argc, char** argv) {
  const bool matrix = argc > 1 && strcmp(argv[1], "--matrix") == 0;
  g_quiet = matrix;
  if (!matrix) {
    printf("services.bind, against the real tables:\n");
  }

  MiseryBridgeSetGameThread(GetCurrentThreadId());

  const MbRoot* root = nullptr;
  MbHandle host = 0;
  MbError error{};
  if (MiseryBridgeAcquire(MB_ABI_EPOCH, &root, &host, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"acquire: %s\"}\n", Detail(error).c_str());
    return 2;
  }

  const void* table = nullptr;
  if (root->acquire_capability(host, MB_CAP_HOST,
                               static_cast<int32_t>(strlen(MB_CAP_HOST)), 1,
                               &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"host table: %s\"}\n",
           Detail(error).c_str());
    return 3;
  }
  const MbHostTable* hosts = static_cast<const MbHostTable*>(table);

  auto load = [&](const char* mod_id, MbHandle* out) {
    MbStr grant{nullptr, 0};
    return hosts->mod_begin(S(mod_id), S("^0.5.0"), S("[\"core.services\"]"),
                            S("[]"), out, &grant, &error) == MB_STATUS_OK &&
           hosts->mod_loaded(*out, &error) == MB_STATUS_OK;
  };

  MbHandle provider = 0, consumer = 0;
  if (!load("provider", &provider) || !load("consumer", &consumer)) {
    printf("{\"ok\":false,\"error\":\"mod_begin: %s\"}\n",
           Detail(error).c_str());
    return 4;
  }

  if (root->acquire_capability(provider, MB_CAP_SERVICES,
                               static_cast<int32_t>(strlen(MB_CAP_SERVICES)), 1,
                               &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"services table: %s\"}\n",
           Detail(error).c_str());
    return 5;
  }
  const MbServicesTable* services = static_cast<const MbServicesTable*>(table);

  if (matrix) {
    // A fresh provider and service per line, so each pair is judged alone.
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), stdin) != nullptr) {
      char version[128] = {0}, requirement[256] = {0};
      if (sscanf(line, "%127s %255[^\n\r]", version, requirement) != 2) {
        continue;
      }
      // A single dash means the empty string: the wire is whitespace
      // separated, so an empty field cannot be written literally, and empty
      // inputs are exactly the cases worth keeping in the grid.
      if (strcmp(version, "-") == 0) version[0] = 0;
      if (strcmp(requirement, "-") == 0) requirement[0] = 0;
      char mod_id[64], service[96];
      snprintf(mod_id, sizeof(mod_id), "p%d", n);
      snprintf(service, sizeof(service), "p%d:svc", n);
      ++n;
      MbHandle owner = 0;
      if (!load(mod_id, &owner)) {
        printf("load-failed\n");
        fflush(stdout);
        continue;
      }
      MbHandle svc = 0;
      if (services->publish(owner, S(service), S(version), S("[\"m\"]"), &svc,
                            &error) != MB_STATUS_OK) {
        printf("%d,%d\n", error.subsystem, error.code);
        fflush(stdout);
        continue;
      }
      MbHandle binding = 0;
      if (services->bind(consumer, S(service), S(requirement), &binding,
                         &error) == MB_STATUS_OK) {
        printf("ok\n");
      } else {
        printf("%d,%d\n", error.subsystem, error.code);
      }
      fflush(stdout);
    }
    return 0;
  }

  MbHandle published = 0;
  Check("a service publishes with a well-formed version",
        services->publish(provider, S("provider:radio"), S("1.2.0"),
                          S("[\"tune\"]"), &published, &error) == MB_STATUS_OK,
        Detail(error));

  {
    MbHandle rejected = 0;
    const MbStatus rc =
        services->publish(provider, S("provider:broken"), S("banana"),
                          S("[\"x\"]"), &rejected, &error);
    Check("a malformed version is refused AT PUBLISH", rc != MB_STATUS_OK);
    Check("  ...as SERVICES x INVALID_ARGUMENT",
          error.subsystem == MB_SUB_SERVICES &&
              error.code == MB_E_INVALID_ARGUMENT);
  }

  // THE CASE THIS HARNESS EXISTS FOR.
  {
    MbHandle binding = 0;
    const MbStatus rc = services->bind(consumer, S("provider:radio"),
                                       S(">=2.0.0"), &binding, &error);
    Check("a requirement the provider does not satisfy is REFUSED",
          rc != MB_STATUS_OK);
    Check("  ...as SERVICES x INVALID_ARGUMENT, as the reference has it",
          error.subsystem == MB_SUB_SERVICES &&
              error.code == MB_E_INVALID_ARGUMENT);
    const std::string detail = Detail(error);
    Check("  ...naming the published version and the requirement",
          detail.find("1.2.0") != std::string::npos &&
              detail.find(">=2.0.0") != std::string::npos,
          detail);
  }
  {
    MbHandle binding = 0;
    Check("a requirement the provider satisfies binds",
          services->bind(consumer, S("provider:radio"), S(">=1.0.0"), &binding,
                         &error) == MB_STATUS_OK,
          Detail(error));
    Check("  ...and yields a live handle", binding != 0);
  }
  {
    // Caret here is "at least this, same major": ^1.0.0 admits 1.2.0.
    MbHandle binding = 0;
    Check("^1.0.0 admits 1.2.0",
          services->bind(consumer, S("provider:radio"), S("^1.0.0"), &binding,
                         &error) == MB_STATUS_OK);
    Check("^2.0.0 does not",
          services->bind(consumer, S("provider:radio"), S("^2.0.0"), &binding,
                         &error) != MB_STATUS_OK);
  }
  {
    MbHandle binding = 0;
    Check("an unparseable requirement is refused rather than ignored",
          services->bind(consumer, S("provider:radio"), S("not a requirement"),
                         &binding, &error) != MB_STATUS_OK);
  }
  {
    MbHandle binding = 0;
    const MbStatus rc = services->bind(consumer, S("provider:absent"),
                                       S(">=1.0.0"), &binding, &error);
    Check("an unpublished service is NOT_FOUND, as the reference has it",
          rc != MB_STATUS_OK && error.subsystem == MB_SUB_SERVICES &&
              error.code == MB_E_NOT_FOUND);
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
