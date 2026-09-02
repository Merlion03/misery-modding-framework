// settings_harness.cpp -- per-mod settings, driven off the game.
//
// MiseryBridgeAcquire hands back the real root; MB_CAP_HOST registers a mod the
// way the managed host does; MB_CAP_SETTINGS is the table a mod reaches through
// IModSettings. The settings root is a directory this harness owns, handed to
// the bridge through the same injection the runtime uses for the user's
// profile, so nothing here touches anything of the user's.
//
// The semantics are tools/modplatform/settings.py's. tests/test_settings.py
// drives the same scripts through both and requires the same answers and the
// same bytes on disk.
//
// TWO MODES
//   (default)          the named cases, human-readable, with a JSON verdict.
//   --script <root>    one command per stdin line, one answer per stdout line:
//       declare <json-array>          ok | <sub>,<code>
//       get <type> <key>              <value> | <sub>,<code>
//       set <type> <key> <value>      ok | <sub>,<code>
//       save                          ok | <sub>,<code>
//       reload                        ok    (unload, load again, re-declare)
//       fail                          ok    (the mod FAILS; teardown runs)
//       file                          <hex of the file> | none
//       subs                          <count of substitutions reported>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

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

// Python's repr() of a float, which is what the reference writes and answers
// with. Shortest round-tripping form, always with a fraction or exponent.
std::string RenderDouble(double value) {
  char buffer[64];
  for (int precision = 1; precision <= 17; ++precision) {
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%.*g", precision, value);
    if (strtod(buffer, nullptr) == value) break;
  }
  std::string text(buffer);
  if (text.find_first_of(".eEn") == std::string::npos) text += ".0";
  return text;
}

bool ReadFile(const std::string& path, std::string* out) {
  FILE* handle = nullptr;
  if (fopen_s(&handle, path.c_str(), "rb") != 0 || handle == nullptr) return false;
  char buffer[4096];
  size_t n;
  out->clear();
  while ((n = fread(buffer, 1, sizeof(buffer), handle)) > 0) out->append(buffer, n);
  fclose(handle);
  return true;
}

void WriteFile(const std::string& path, const std::string& text) {
  FILE* handle = nullptr;
  if (fopen_s(&handle, path.c_str(), "wb") == 0 && handle != nullptr) {
    fwrite(text.data(), 1, text.size(), handle);
    fclose(handle);
  }
}

std::string Hex(const std::string& raw) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : raw) {
    out += kHex[(c >> 4) & 0xF];
    out += kHex[c & 0xF];
  }
  return out;
}

}  // namespace

extern "C" __declspec(dllimport) void MiseryBridgeSetGameThread(uint32_t);
extern "C" __declspec(dllimport) void MiseryBridgeSetSettingsRoot(const char*);

int main(int argc, char** argv) {
  const bool script = argc > 2 && strcmp(argv[1], "--script") == 0;
  g_quiet = script;

  std::string root;
  if (script) {
    root = argv[2];
  } else {
    char temp[MAX_PATH] = {0};
    GetTempPathA(sizeof(temp), temp);
    root = std::string(temp) + "mbpl-settings-" + std::to_string(GetCurrentProcessId());
    printf("per-mod settings, against the real table (root %s):\n", root.c_str());
  }
  CreateDirectoryA(root.c_str(), nullptr);
  const std::string file = root + "\\alphamod.json";
  DeleteFileA(file.c_str());

  MiseryBridgeSetGameThread(GetCurrentThreadId());
  MiseryBridgeSetSettingsRoot(root.c_str());

  const MbRoot* bridge = nullptr;
  MbHandle host = 0;
  MbError error{};
  if (MiseryBridgeAcquire(MB_ABI_EPOCH, &bridge, &host, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"acquire\"}\n");
    return 2;
  }
  const void* table = nullptr;
  if (bridge->acquire_capability(host, MB_CAP_HOST,
                                 static_cast<int32_t>(strlen(MB_CAP_HOST)), 1,
                                 &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"host table\"}\n");
    return 3;
  }
  const MbHostTable* hosts = static_cast<const MbHostTable*>(table);

  MbHandle mod = 0;
  auto load = [&]() {
    MbStr grant{nullptr, 0};
    return hosts->mod_begin(S("alphamod"), S("^0.5.0"), S("[\"core.settings\"]"),
                            S("[]"), &mod, &grant, &error) == MB_STATUS_OK &&
           hosts->mod_loaded(mod, &error) == MB_STATUS_OK;
  };
  if (!load()) {
    printf("{\"ok\":false,\"error\":\"mod_begin: %s\"}\n", Str(error.detail).c_str());
    return 4;
  }
  if (bridge->acquire_capability(mod, MB_CAP_SETTINGS,
                                 static_cast<int32_t>(strlen(MB_CAP_SETTINGS)), 1,
                                 &table, &error) != MB_STATUS_OK) {
    printf("{\"ok\":false,\"error\":\"settings table\"}\n");
    return 5;
  }
  const MbSettingsTable* settings = static_cast<const MbSettingsTable*>(table);

  // Every slot is filled: this is the "no nullptr reachable" property, checked
  // once against the real table rather than assumed.
  const void* slots[] = {
      reinterpret_cast<const void*>(settings->declare),
      reinterpret_cast<const void*>(settings->get_bool),
      reinterpret_cast<const void*>(settings->get_int),
      reinterpret_cast<const void*>(settings->get_float),
      reinterpret_cast<const void*>(settings->get_string),
      reinterpret_cast<const void*>(settings->set_bool),
      reinterpret_cast<const void*>(settings->set_int),
      reinterpret_cast<const void*>(settings->set_float),
      reinterpret_cast<const void*>(settings->set_string),
      reinterpret_cast<const void*>(settings->save)};
  bool all_filled = true;
  for (const void* slot : slots) all_filled = all_filled && slot != nullptr;

  const std::string schema =
      "[{\"key\":\"enabled\",\"type\":\"bool\",\"default\":true,"
      "\"description\":\"on\"},"
      "{\"key\":\"threshold\",\"type\":\"float\",\"default\":0.5,"
      "\"description\":\"t\"}]";

  auto get_answer = [&](const std::string& type, const std::string& key) {
    if (type == "bool") {
      int32_t v = 0;
      if (settings->get_bool(mod, S(key), &v, &error) != MB_STATUS_OK) return Code(error);
      return std::string(v ? "true" : "false");
    }
    if (type == "int") {
      int64_t v = 0;
      if (settings->get_int(mod, S(key), &v, &error) != MB_STATUS_OK) return Code(error);
      return std::to_string(v);
    }
    if (type == "float") {
      double v = 0;
      if (settings->get_float(mod, S(key), &v, &error) != MB_STATUS_OK) return Code(error);
      return RenderDouble(v);
    }
    MbStr v{nullptr, 0};
    if (settings->get_string(mod, S(key), &v, &error) != MB_STATUS_OK) return Code(error);
    return Str(v);
  };
  auto set_answer = [&](const std::string& type, const std::string& key,
                        const std::string& value) {
    MbStatus rc;
    if (type == "bool") rc = settings->set_bool(mod, S(key), value == "true" ? 1 : 0, &error);
    else if (type == "int") rc = settings->set_int(mod, S(key), _strtoi64(value.c_str(), nullptr, 10), &error);
    else if (type == "float") rc = settings->set_float(mod, S(key), strtod(value.c_str(), nullptr), &error);
    else rc = settings->set_string(mod, S(key), S(value), &error);
    return rc == MB_STATUS_OK ? std::string("ok") : Code(error);
  };

  if (script) {
    std::string last_schema;
    char line[8192];
    while (fgets(line, sizeof(line), stdin) != nullptr) {
      std::string text(line);
      while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
      if (text.empty()) continue;
      std::string answer;
      if (text.rfind("declare ", 0) == 0) {
        last_schema = text.substr(8);
        answer = settings->declare(mod, S(last_schema), &error) == MB_STATUS_OK ? "ok" : Code(error);
      } else if (text.rfind("get ", 0) == 0) {
        const size_t sp = text.find(' ', 4);
        answer = get_answer(text.substr(4, sp - 4), text.substr(sp + 1));
      } else if (text.rfind("set ", 0) == 0) {
        const size_t sp1 = text.find(' ', 4);
        const size_t sp2 = text.find(' ', sp1 + 1);
        answer = set_answer(text.substr(4, sp1 - 4), text.substr(sp1 + 1, sp2 - sp1 - 1),
                            text.substr(sp2 + 1));
      } else if (text == "save") {
        answer = settings->save(mod, &error) == MB_STATUS_OK ? "ok" : Code(error);
      } else if (text == "reload" || text == "fail") {
        if (text == "fail") {
          hosts->mod_failed(mod, S("on purpose"), &error);
        } else {
          MbStr teardown{nullptr, 0};
          hosts->mod_unload(mod, &teardown, &error);
        }
        answer = load() ? "ok" : Code(error);
        if (answer == "ok" && !last_schema.empty()) {
          answer = settings->declare(mod, S(last_schema), &error) == MB_STATUS_OK ? "ok" : Code(error);
        }
      } else if (text == "file") {
        std::string contents;
        answer = ReadFile(file, &contents) ? Hex(contents) : "none";
      } else if (text == "subs") {
        // Substitutions surface through misery:settings; count them there.
        answer = "via-console";
      } else {
        answer = "unknown-command";
      }
      printf("%s\n", answer.c_str());
      fflush(stdout);
    }
    return 0;
  }

  Check("every slot of the settings table is filled", all_filled);

  Check("a valid schema declares", settings->declare(mod, S(schema), &error) == MB_STATUS_OK,
        Str(error.detail));
  {
    const MbStatus rc = settings->declare(mod, S(schema), &error);
    Check("declaring twice is ALREADY_EXISTS",
          rc != MB_STATUS_OK && error.subsystem == MB_SUB_SETTINGS &&
              error.code == MB_E_ALREADY_EXISTS);
  }
  Check("a declared bool reads its default", get_answer("bool", "enabled") == "true");
  Check("a declared float reads its default", get_answer("float", "threshold") == "0.5");
  {
    double v = 0;
    const MbStatus rc = settings->get_float(mod, S("thresold"), &v, &error);   // typo
    Check("an undeclared key is NOT_FOUND, not defaulted",
          rc != MB_STATUS_OK && error.code == MB_E_NOT_FOUND);
  }
  {
    int32_t v = 0;
    const MbStatus rc = settings->get_bool(mod, S("threshold"), &v, &error);
    Check("reading with the wrong type is INVALID_ARGUMENT",
          rc != MB_STATUS_OK && error.code == MB_E_INVALID_ARGUMENT);
  }
  Check("a bool does not satisfy a float setting",
        set_answer("bool", "threshold", "true") ==
            std::to_string(MB_SUB_SETTINGS) + "," + std::to_string(MB_E_INVALID_ARGUMENT));
  Check("a float setting takes a float", set_answer("float", "threshold", "0.9") == "ok");
  Check("  ...and reads it back", get_answer("float", "threshold") == "0.9");
  Check("save writes the file", settings->save(mod, &error) == MB_STATUS_OK, Str(error.detail));
  {
    std::string contents;
    Check("  ...and the file holds the value",
          ReadFile(file, &contents) && contents.find("\"threshold\": 0.9") != std::string::npos,
          contents);
  }
  {
    // Persistence, proven the only way it can be: through an unload and back.
    MbStr teardown{nullptr, 0};
    hosts->mod_unload(mod, &teardown, &error);
    Check("after unload the mod's settings are forgotten in memory",
          load() && settings->declare(mod, S(schema), &error) == MB_STATUS_OK);
    Check("  ...and the saved value comes back from disk",
          get_answer("float", "threshold") == "0.9");
  }
  {
    // A stored value that no longer fits: falls back, and is reported.
    MbStr teardown{nullptr, 0};
    hosts->mod_unload(mod, &teardown, &error);
    WriteFile(file, "{\"threshold\": \"not a number\"}\n");
    Check("a schema still declares over an ill-fitting stored value",
          load() && settings->declare(mod, S(schema), &error) == MB_STATUS_OK,
          Str(error.detail));
    Check("  ...and the default is in use", get_answer("float", "threshold") == "0.5");
  }
  {
    // A key the mod no longer declares survives a save.
    MbStr teardown{nullptr, 0};
    hosts->mod_unload(mod, &teardown, &error);
    WriteFile(file, "{\"old_key\": 7, \"threshold\": 0.25}\n");
    load();
    settings->declare(mod, S(schema), &error);
    set_answer("float", "threshold", "0.75");
    settings->save(mod, &error);
    std::string contents;
    ReadFile(file, &contents);
    Check("a key the mod no longer declares survives on disk",
          contents.find("\"old_key\": 7") != std::string::npos, contents);
    Check("  ...beside the new value",
          contents.find("\"threshold\": 0.75") != std::string::npos);
  }
  {
    // NEVER WRITTEN FROM TEARDOWN. A dirty, unsaved change followed by the
    // mod FAILING must leave the file exactly as it was.
    std::string before;
    ReadFile(file, &before);
    set_answer("float", "threshold", "0.1");            // dirty, not saved
    hosts->mod_failed(mod, S("on purpose"), &error);    // teardown runs
    std::string after;
    ReadFile(file, &after);
    Check("a failed mod's unsaved changes are NOT persisted by teardown",
          before == after);
    Check("  ...and the file still holds the last SAVED value",
          after.find("\"threshold\": 0.75") != std::string::npos);
    load();
  }
  {
    // Saving when nothing changed writes nothing -- the file's bytes stand.
    settings->declare(mod, S(schema), &error);
    std::string before;
    ReadFile(file, &before);
    settings->save(mod, &error);
    std::string after;
    ReadFile(file, &after);
    Check("save with nothing dirty leaves the file untouched", before == after);
  }
  {
    // No root: Save refuses rather than reporting a save that did not happen.
    MiseryBridgeSetSettingsRoot("");
    set_answer("float", "threshold", "0.2");
    const MbStatus rc = settings->save(mod, &error);
    Check("save with no settings root is refused, not silently skipped",
          rc != MB_STATUS_OK && error.code == MB_E_NOT_INITIALISED);
    MiseryBridgeSetSettingsRoot(root.c_str());
  }

  DeleteFileA(file.c_str());
  RemoveDirectoryA(root.c_str());
  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false", g_failures);
  return g_failures == 0 ? 0 : 1;
}
