// console_harness.cpp -- the production console, driven off the game.
//
// MiseryBridgeAcquire hands back the real root; MB_CAP_HOST registers mods the
// way the managed host does; MB_CAP_CONSOLE is the table a mod reaches through
// IModConsole. A trampoline is installed here that stands in for the managed
// dispatcher: it calls complete_dispatch with a result, exactly as the managed
// handler will.
//
// The envelope, the refusal wording and the validation order are
// tools/modplatform/console.py's. tests/test_console.py drives the same lines
// through both and requires the same envelopes.
//
// TWO MODES
//   (default)  the named cases, human-readable, with a JSON verdict.
//   --envelope one console line per stdin line, the raw envelope per reply, for
//              the differential.
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include <stdexcept>
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

std::string Str(const MbStr& value) {
  return value.data == nullptr
             ? std::string()
             : std::string(value.data, static_cast<size_t>(value.length));
}

// The stand-in for the managed dispatcher. A real handler runs mod code and
// hands back a result; this does the same through the same slot.
const MbConsoleTable* g_console = nullptr;
std::string g_next_result = "{\"from\":\"the mod\"}";
bool g_throw_next = false;
bool g_answer_next = true;

void Trampoline(int32_t kind, MbHandle handle, MbStr a, MbStr b,
                int32_t phase) {
  (void)a;
  (void)phase;
  if (kind != MB_DISPATCH_COMMAND || g_console == nullptr) return;
  if (g_throw_next) {
    g_throw_next = false;
    throw std::runtime_error("the handler threw");
  }
  if (!g_answer_next) {
    g_answer_next = true;
    return;                     // a handler that never delivers a result
  }
  MbError error{};
  // Echo the argument line back, so the differential can see args arrived.
  std::string result = g_next_result;
  if (b.length > 0) {
    result = "{\"args\":\"" + Str(b) + "\"}";
  }
  g_console->complete_dispatch(handle, S(result.c_str()), &error);
}

}  // namespace

extern "C" __declspec(dllimport) void MiseryBridgeSetGameThread(uint32_t);

int main(int argc, char** argv) {
  const bool envelope_mode = argc > 1 && strcmp(argv[1], "--envelope") == 0;
  g_quiet = envelope_mode;
  if (!envelope_mode) printf("the production console:\n");

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

  MbHandle mod = 0;
  MbStr grant{nullptr, 0};
  if (hosts->mod_begin(S("alphamod"), S("^0.5.0"), S("[\"core.console\"]"),
                       S("[]"), &mod, &grant, &error) != MB_STATUS_OK ||
      hosts->mod_loaded(mod, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"mod_begin: %s\"}\n",
           Str(error.detail).c_str());
    return 4;
  }
  if (root->acquire_capability(mod, MB_CAP_CONSOLE,
                               static_cast<int32_t>(strlen(MB_CAP_CONSOLE)), 1,
                               &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"console table: %s\"}\n",
           Str(error.detail).c_str());
    return 5;
  }
  g_console = static_cast<const MbConsoleTable*>(table);

  auto run = [&](const char* line) {
    MbStr out{nullptr, 0};
    MbError local{};
    const MbStatus rc = g_console->run(S(line), &out, &local);
    if (rc != MB_STATUS_OK) {
      return std::string("STATUS:") + std::to_string(local.code);
    }
    return Str(out);
  };

  if (envelope_mode) {
    // A mod command exists for the differential's benefit.
    MbHandle command = 0;
    g_console->register_command(mod, S("alphamod:ping"), S("say hello"),
                                &command, &error);
    char line[1024];
    while (fgets(line, sizeof(line), stdin) != nullptr) {
      std::string text(line);
      while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
      }
      printf("%s\n", run(text.c_str()).c_str());
      fflush(stdout);
    }
    return 0;
  }

  // ---- the envelope, which is the reference's shape --------------------
  Check("an empty line is refused in the envelope, not by status",
        run("") == "{\"ok\":false,\"error\":\"empty command\"}", run(""));
  Check("whitespace only is the same",
        run("   \t ") == "{\"ok\":false,\"error\":\"empty command\"}");
  Check("an unknown command names itself and hints",
        run("nope") ==
            "{\"ok\":false,\"error\":\"unknown command 'nope'\","
            "\"hint\":\"try 'help'\"}",
        run("nope"));

  // ---- the framework namespace ------------------------------------------
  {
    const std::string help = run("misery:help");
    Check("misery:help succeeds", help.find("\"ok\":true") == 0 ||
                                      help.find("\"ok\":true") !=
                                          std::string::npos, help);
    Check("  ...and is namespaced misery:, never mbpl:",
          help.find("\"misery:help\"") != std::string::npos &&
              help.find("mbpl:") == std::string::npos);
    Check("  ...and lists the builtins as owned by the platform",
          help.find("\"owner\":\"platform\"") != std::string::npos);
    Check("bare 'help' is NOT a command; the prefix is required",
          run("help").find("unknown command 'help'") != std::string::npos);
  }
  {
    const std::string caps = run("misery:caps");
    Check("misery:caps reports the API and the capabilities",
          caps.find("\"api\"") != std::string::npos &&
              caps.find("core.console") != std::string::npos, caps);
  }
  {
    const std::string generations = run("misery:generations");
    // No content runtime behind this harness, so the honest answer is that no
    // source is attached -- not an invented generation 0.
    Check("misery:generations says it is not attached rather than guessing",
          generations.find("\"attached\":false") != std::string::npos,
          generations);
  }
  {
    const std::string mods = run("misery:mods");
    Check("misery:mods reports the registered mod",
          mods.find("alphamod") != std::string::npos, mods);
  }

  // ---- a mod's own command ----------------------------------------------
  MbHandle command = 0;
  Check("a mod registers a command in its own namespace",
        g_console->register_command(mod, S("alphamod:ping"), S("say hello"),
                                    &command, &error) == MB_STATUS_OK,
        Str(error.detail));
  Check("  ...and it appears in misery:help",
        run("misery:help").find("alphamod:ping") != std::string::npos);
  {
    const std::string result = run("alphamod:ping");
    Check("running it reaches the handler and carries its result back",
          result.find("\"ok\":true") != std::string::npos &&
              result.find("from") != std::string::npos, result);
  }
  {
    const std::string result = run("alphamod:ping one two");
    Check("  ...and the argument line arrives",
          result.find("one two") != std::string::npos, result);
  }
  {
    MbHandle other = 0;
    const MbStatus rc = g_console->register_command(
        mod, S("betamod:ping"), S("not mine"), &other, &error);
    Check("a mod may NOT register outside its namespace", rc != MB_STATUS_OK);
    Check("  ...as CONSOLE x INVALID_ARGUMENT",
          error.subsystem == MB_SUB_CONSOLE &&
              error.code == MB_E_INVALID_ARGUMENT);
  }
  {
    MbHandle duplicate = 0;
    const MbStatus rc = g_console->register_command(
        mod, S("alphamod:ping"), S("again"), &duplicate, &error);
    Check("the same name twice is ALREADY_EXISTS",
          rc != MB_STATUS_OK && error.subsystem == MB_SUB_CONSOLE &&
              error.code == MB_E_ALREADY_EXISTS);
  }
  {
    MbHandle claimed = 0;
    const MbStatus rc = g_console->register_command(
        mod, S("misery:mine"), S("stealing the framework prefix"), &claimed,
        &error);
    Check("a mod may not claim the misery: prefix", rc != MB_STATUS_OK);
  }
  {
    g_throw_next = true;
    const std::string result = run("alphamod:ping");
    Check("a handler that throws becomes ok:false, not a crash",
          result.find("\"ok\":false") != std::string::npos &&
              result.find("faulted") != std::string::npos, result);
  }
  {
    g_answer_next = false;
    const std::string result = run("alphamod:ping");
    Check("a handler that delivers no result says so",
          result.find("no result") != std::string::npos, result);
  }
  {
    MbError local{};
    const MbStatus rc = g_console->complete_dispatch(command, S("{}"), &local);
    Check("complete_dispatch outside a dispatch is refused",
          rc != MB_STATUS_OK && local.code == MB_E_NOT_OWNED);
  }

  // ---- ownership: revocation makes it unreachable IMMEDIATELY -----------
  {
    MbStr teardown{nullptr, 0};
    hosts->mod_unload(mod, &teardown, &error);
    const std::string after = run("alphamod:ping");
    Check("after the mod unloads its command is gone from misery:help",
          run("misery:help").find("alphamod:ping") == std::string::npos);
    Check("  ...and running it is refused rather than dispatched",
          after.find("\"ok\":false") != std::string::npos, after);
    Check("  ...and the builtins still work",
          run("misery:help").find("\"ok\":true") != std::string::npos);
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
