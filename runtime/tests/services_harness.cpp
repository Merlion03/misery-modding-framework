// services_harness.cpp -- publish, bind, call, release; off the game.
//
// The bridge's own tables are driven here: MiseryBridgeAcquire hands back the
// real root, MB_CAP_HOST registers mods the way the managed host does, and
// these cases call the same MbServicesTable function pointers a mod reaches
// through IModServices. A trampoline installed here stands in for the managed
// dispatcher: for MB_DISPATCH_SERVICE it delivers a result through
// complete_call exactly as the managed handler will.
//
// The cases mirror tools/modplatform/services.py. Stage 8.3 proved bind
// enforces its requirement (it used to ignore it); this file now also holds
// call, release and describe, which used to be nullptr slots.
//
// THREE MODES
//   (default)  the named cases, human-readable, with a JSON verdict.
//   --matrix   bind's differential wire: "<version> <requirement>" per stdin
//              line, "ok" or "<subsystem>,<code>" per reply.
//   --calls    the call differential wire, one command per stdin line:
//       publish <name> <version> <json-method-array>   ok | <sub>,<code>
//       bind <name> <requirement>                      ok | <sub>,<code>
//       call <method> <args-json>                      <result> | <sub>,<code>
//       available                                      true | false
//       describe                                       <json>
//       release                                        ok | <sub>,<code>
//       unload-provider                                ok
//       unload-consumer                                ok
//     (one provider "provider", one consumer "consumer", one binding at a time)
#include <windows.h>

#include <stdexcept>
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

MbStr S(const std::string& text) {
  return MbStr{text.c_str(), static_cast<int32_t>(text.size())};
}

std::string Str(const MbStr& value) {
  return value.data == nullptr
             ? std::string()
             : std::string(value.data, static_cast<size_t>(value.length));
}

std::string Code(const MbError& error) {
  return std::to_string(error.subsystem) + "," + std::to_string(error.code);
}

// The stand-in for the managed dispatcher.
const MbServicesTable* g_services = nullptr;
bool g_throw_next = false;
bool g_silent_next = false;
MbHandle g_nested_binding = MB_INVALID_HANDLE;   // when set, the handler calls it
int g_nesting_left = 0;

void Trampoline(int32_t kind, MbHandle service, MbStr method, MbStr args,
                int32_t phase) {
  (void)phase;
  if (kind != MB_DISPATCH_SERVICE || g_services == nullptr) return;
  if (g_throw_next) {
    g_throw_next = false;
    throw std::runtime_error("the provider's handler threw");
  }
  if (g_silent_next) {
    g_silent_next = false;
    return;                       // a handler that delivers nothing
  }
  std::string result;
  if (g_nested_binding != MB_INVALID_HANDLE && g_nesting_left > 0) {
    // A provider that calls a service from inside its own handler. The inner
    // result must land in the INNER frame, and the outer frame must still get
    // its own -- which is what the frame stack exists for.
    --g_nesting_left;
    MbStr inner{nullptr, 0};
    MbError error{};
    const MbStatus rc = g_services->call(g_nested_binding, S("inner"),
                                         S("{}"), &inner, &error);
    result = "{\"outer\":true,\"inner\":" +
             (rc == MB_STATUS_OK ? Str(inner) : "\"" + Code(error) + "\"") + "}";
  } else {
    result = "{\"method\":\"" + Str(method) + "\",\"args\":" +
             (args.length > 0 ? Str(args) : "null") + "}";
  }
  MbError error{};
  g_services->complete_call(service, S(result), &error);
}

}  // namespace

extern "C" __declspec(dllimport) void MiseryBridgeSetGameThread(uint32_t);

int main(int argc, char** argv) {
  const bool matrix = argc > 1 && strcmp(argv[1], "--matrix") == 0;
  const bool calls = argc > 1 && strcmp(argv[1], "--calls") == 0;
  g_quiet = matrix || calls;
  if (!g_quiet) printf("services, against the real tables:\n");

  MiseryBridgeSetGameThread(GetCurrentThreadId());

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
  hosts->set_trampoline(Trampoline, &error);

  auto load = [&](const char* mod_id, MbHandle* out) {
    MbStr grant{nullptr, 0};
    return hosts->mod_begin(S(mod_id), S("^0.5.0"), S("[\"core.services\"]"),
                            S("[]"), out, &grant, &error) == MB_STATUS_OK &&
           hosts->mod_loaded(*out, &error) == MB_STATUS_OK;
  };
  auto unload = [&](MbHandle mod) {
    MbStr teardown{nullptr, 0};
    return hosts->mod_unload(mod, &teardown, &error) == MB_STATUS_OK;
  };

  MbHandle provider = 0, consumer = 0;
  if (!load("provider", &provider) || !load("consumer", &consumer)) {
    printf("{\"ok\":false,\"error\":\"mod_begin: %s\"}\n",
           Str(error.detail).c_str());
    return 4;
  }
  if (root->acquire_capability(provider, MB_CAP_SERVICES,
                               static_cast<int32_t>(strlen(MB_CAP_SERVICES)), 1,
                               &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"services table\"}\n");
    return 5;
  }
  g_services = static_cast<const MbServicesTable*>(table);
  const MbServicesTable* services = g_services;

  // ---- --matrix: bind's differential (unchanged from 8.3) ------------------
  if (matrix) {
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), stdin) != nullptr) {
      char version[128] = {0}, requirement[256] = {0};
      if (sscanf(line, "%127s %255[^\n\r]", version, requirement) != 2) continue;
      if (strcmp(version, "-") == 0) version[0] = 0;
      if (strcmp(requirement, "-") == 0) requirement[0] = 0;
      char mod_id[64], service[96];
      snprintf(mod_id, sizeof(mod_id), "p%d", n);
      snprintf(service, sizeof(service), "p%d:svc", n);
      ++n;
      MbHandle owner = 0;
      if (!load(mod_id, &owner)) { printf("load-failed\n"); fflush(stdout); continue; }
      MbHandle svc = 0;
      if (services->publish(owner, S(service), S(version), S("[\"m\"]"), &svc,
                            &error) != MB_STATUS_OK) {
        printf("%s\n", Code(error).c_str()); fflush(stdout); continue;
      }
      MbHandle binding = 0;
      printf("%s\n", services->bind(consumer, S(service), S(requirement), &binding,
                                    &error) == MB_STATUS_OK ? "ok" : Code(error).c_str());
      fflush(stdout);
    }
    return 0;
  }

  // ---- --calls: the call differential -------------------------------------
  if (calls) {
    MbHandle binding = MB_INVALID_HANDLE;
    char line[8192];
    while (fgets(line, sizeof(line), stdin) != nullptr) {
      std::string text(line);
      while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
      if (text.empty()) continue;
      std::string answer;
      if (text.rfind("publish ", 0) == 0) {
        const size_t s1 = text.find(' ', 8), s2 = text.find(' ', s1 + 1);
        MbHandle svc = 0;
        answer = services->publish(provider, S(text.substr(8, s1 - 8)),
                                   S(text.substr(s1 + 1, s2 - s1 - 1)),
                                   S(text.substr(s2 + 1)), &svc,
                                   &error) == MB_STATUS_OK ? "ok" : Code(error);
      } else if (text.rfind("bind ", 0) == 0) {
        const size_t s1 = text.find(' ', 5);
        answer = services->bind(consumer, S(text.substr(5, s1 - 5)),
                                S(text.substr(s1 + 1)), &binding,
                                &error) == MB_STATUS_OK ? "ok" : Code(error);
      } else if (text.rfind("call ", 0) == 0) {
        const size_t s1 = text.find(' ', 5);
        MbStr result{nullptr, 0};
        answer = services->call(binding, S(text.substr(5, s1 - 5)),
                                S(text.substr(s1 + 1)), &result,
                                &error) == MB_STATUS_OK ? Str(result) : Code(error);
      } else if (text == "available") {
        int32_t available = 0;
        services->is_available(binding, &available, &error);
        answer = available ? "true" : "false";
      } else if (text == "describe") {
        MbStr json{nullptr, 0};
        answer = services->describe(binding, &json, &error) == MB_STATUS_OK
                     ? Str(json) : Code(error);
      } else if (text == "release") {
        answer = services->release(binding, &error) == MB_STATUS_OK ? "ok" : Code(error);
      } else if (text == "unload-provider") {
        answer = unload(provider) && load("provider", &provider) ? "ok" : Code(error);
      } else if (text == "unload-consumer") {
        answer = unload(consumer) && load("consumer", &consumer) ? "ok" : Code(error);
      } else {
        answer = "unknown-command";
      }
      printf("%s\n", answer.c_str());
      fflush(stdout);
    }
    return 0;
  }

  // ---- the named cases ------------------------------------------------------
  Check("every slot of the services table is filled",
        services->publish && services->bind && services->is_available &&
            services->call && services->release && services->complete_call &&
            services->describe);

  MbHandle published = 0;
  Check("a service publishes with a well-formed version and methods",
        services->publish(provider, S("provider:radio"), S("1.2.0"),
                          S("[\"tune\",\"inner\"]"), &published,
                          &error) == MB_STATUS_OK,
        Str(error.detail));
  {
    MbHandle rejected = 0;
    Check("a service with NO methods is refused",
          services->publish(provider, S("provider:empty"), S("1.0.0"), S("[]"),
                            &rejected, &error) != MB_STATUS_OK &&
              error.code == MB_E_INVALID_ARGUMENT);
    Check("a method name that is not an identifier is refused",
          services->publish(provider, S("provider:bad"), S("1.0.0"),
                            S("[\"Tune\"]"), &rejected, &error) != MB_STATUS_OK &&
              error.code == MB_E_INVALID_ARGUMENT);
  }

  MbHandle binding = 0;
  Check("a consumer binds", services->bind(consumer, S("provider:radio"), S("^1.0.0"),
                                           &binding, &error) == MB_STATUS_OK,
        Str(error.detail));
  {
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("tune"), S("{\"f\":1}"), &result, &error);
    Check("a call reaches the provider and carries the result back",
          rc == MB_STATUS_OK && Str(result) ==
              "{\"method\":\"tune\",\"args\":{\"f\":1}}", Str(result));
  }
  {
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("nope"), S("{}"), &result, &error);
    Check("an unknown method is NOT_FOUND, as the reference has it",
          rc != MB_STATUS_OK && error.subsystem == MB_SUB_SERVICES &&
              error.code == MB_E_NOT_FOUND);
    Check("  ...naming the service and the method",
          Str(error.detail).find("'nope'") != std::string::npos, Str(error.detail));
  }
  {
    MbStr json{nullptr, 0};
    const MbStatus rc = services->describe(binding, &json, &error);
    const std::string text = Str(json);
    Check("describe answers the reference's as_dict shape",
          rc == MB_STATUS_OK && text.find("\"version\":\"1.2.0\"") != std::string::npos &&
              text.find("\"provider\":\"provider\"") != std::string::npos &&
              text.find("\"available\":true") != std::string::npos &&
              // Sorted, as the reference's as_dict() reports them.
              text.find("\"methods\":[\"inner\",\"tune\"]") != std::string::npos,
          text);
  }
  {
    g_throw_next = true;
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("tune"), S("{}"), &result, &error);
    Check("a handler that throws is HANDLER_FAULTED, not a crash",
          rc != MB_STATUS_OK && error.code == MB_E_HANDLER_FAULTED, Str(error.detail));
  }
  {
    g_silent_next = true;
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("tune"), S("{}"), &result, &error);
    Check("a handler that delivers no result is reported the same way",
          rc != MB_STATUS_OK && error.code == MB_E_HANDLER_FAULTED);
  }
  {
    // NESTING. The provider's handler calls the service again through a second
    // binding; the inner result must not be mistaken for the outer's.
    MbHandle second = 0;
    services->bind(consumer, S("provider:radio"), S("^1.0.0"), &second, &error);
    g_nested_binding = second;
    g_nesting_left = 1;
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("tune"), S("{}"), &result, &error);
    const std::string text = Str(result);
    Check("a nested call lands its result in the INNER frame",
          rc == MB_STATUS_OK &&
              text == "{\"outer\":true,\"inner\":{\"method\":\"inner\",\"args\":{}}}",
          text);
    g_nested_binding = MB_INVALID_HANDLE;
  }
  {
    // Unbounded recursion is refused rather than run off the stack.
    MbHandle loop = 0;
    services->bind(consumer, S("provider:radio"), S("^1.0.0"), &loop, &error);
    g_nested_binding = loop;
    g_nesting_left = 1000;
    MbStr result{nullptr, 0};
    services->call(binding, S("tune"), S("{}"), &result, &error);
    const std::string text = Str(result);
    Check("runaway nesting is cut off with LIMIT_EXCEEDED inside the chain",
          text.find(std::to_string(MB_SUB_SERVICES) + "," +
                    std::to_string(MB_E_LIMIT_EXCEEDED)) != std::string::npos,
          text.substr(0, 120));
    g_nested_binding = MB_INVALID_HANDLE;
    g_nesting_left = 0;
  }
  {
    MbError local{};
    Check("complete_call outside a call is refused",
          services->complete_call(published, S("{}"), &local) != MB_STATUS_OK &&
              local.code == MB_E_NOT_OWNED);
  }

  // ---- ownership -----------------------------------------------------------
  {
    // THE PROVIDER UNLOADS. Every outstanding binding stops working, at once.
    int32_t available = 1;
    unload(provider);
    services->is_available(binding, &available, &error);
    Check("after the provider unloads the binding is unavailable", available == 0);
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(binding, S("tune"), S("{}"), &result, &error);
    Check("  ...and a call is NOT_FOUND 'no longer available', as the reference has it",
          rc != MB_STATUS_OK && error.code == MB_E_NOT_FOUND &&
              Str(error.detail).find("no longer available") != std::string::npos,
          Str(error.detail));

    // A DIFFERENT mod republishes the same name. The stale binding must NOT
    // come back to life against it: it holds a handle, not a name.
    MbHandle impostor = 0;
    load("provider", &impostor);   // same id, new epoch
    MbHandle republished = 0;
    services->publish(impostor, S("provider:radio"), S("9.0.0"), S("[\"tune\"]"),
                      &republished, &error);
    services->is_available(binding, &available, &error);
    Check("a republished name does NOT revive a stale binding", available == 0);
    provider = impostor;
  }
  {
    // THE CONSUMER RELEASES. Its binding is gone; the service is untouched.
    MbHandle fresh = 0;
    services->bind(consumer, S("provider:radio"), S("^9.0.0"), &fresh, &error);
    Check("release succeeds for a live binding",
          services->release(fresh, &error) == MB_STATUS_OK);
    MbStr result{nullptr, 0};
    const MbStatus rc = services->call(fresh, S("tune"), S("{}"), &result, &error);
    Check("  ...and the released binding cannot be called",
          rc != MB_STATUS_OK && error.code == MB_E_OWNER_DISPOSED);
    Check("  ...and releasing it again is refused, not double-freed",
          services->release(fresh, &error) != MB_STATUS_OK &&
              error.code == MB_E_NOT_OWNED);
    Check("  ...while the service itself is still published",
          services->bind(consumer, S("provider:radio"), S("^9.0.0"), &fresh, &error) ==
              MB_STATUS_OK);
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false", g_failures);
  return g_failures == 0 ? 0 : 1;
}
