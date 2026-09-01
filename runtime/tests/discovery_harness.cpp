// discovery_harness.cpp -- what the runtime considers an installed mod.
//
// WHY THIS TEST EXISTS
// --------------------
// The first version of DiscoverPlan invented its own layout: a mod's directory
// name was both its id and its assembly's stem. That rejected the framework's
// own fixture -- whose id is `alphamod` and whose assembly is
// `AlphaManagedMod.dll` -- and the failure surfaced in-game, as a managed mod
// dying on load, ten minutes into a Steam launch. It is pure filesystem logic
// and it never needed the game to say so.
//
// So every case is exercised here against a directory tree the harness builds,
// and the one that broke is the first of them.
//
// Prints one `case|expected|actual` line per case and a final PASS/FAIL, which
// tests/test_discovery.py parses.
#include <windows.h>

#include <stdio.h>

#include <string>
#include <vector>

#include "../MiseryRuntime/Internal/ModDiscovery.h"

namespace {

int g_failures = 0;

void Report(const char* name, const std::string& expected,
            const std::string& actual) {
  const bool ok = expected == actual;
  if (!ok) {
    ++g_failures;
  }
  printf("%s|%s|%s|%s\n", ok ? "ok" : "FAILED", name, expected.c_str(),
         actual.c_str());
}

std::string g_root;

// Delete a directory and everything under it. SHFileOperation and friends are
// not worth linking for a test fixture; this is two levels deep by construction.
void RemoveTree(const std::string& root) {
  WIN32_FIND_DATAA entry;
  HANDLE search = FindFirstFileA((root + "\\*").c_str(), &entry);
  if (search == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    const std::string name = entry.cFileName;
    if (name == "." || name == "..") {
      continue;
    }
    const std::string path = root + "\\" + name;
    if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      RemoveTree(path);
    } else {
      DeleteFileA(path.c_str());
    }
  } while (FindNextFileA(search, &entry) != 0);
  FindClose(search);
  RemoveDirectoryA(root.c_str());
}

void Write(const std::string& path, const std::string& text) {
  HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    printf("FAILED|setup|could not create %s\n", path.c_str());
    ++g_failures;
    return;
  }
  DWORD written = 0;
  WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written,
            nullptr);
  CloseHandle(file);
}

// Lay down one mod directory. Any argument may be empty to omit that part.
void MakeMod(const std::string& dir, const std::string& manifest,
             const std::string& assembly) {
  const std::string root = g_root + "\\Mods\\" + dir;
  CreateDirectoryA(root.c_str(), nullptr);
  if (!manifest.empty()) {
    Write(root + "\\mod.json", manifest);
  }
  if (!assembly.empty()) {
    const std::string code = root + "\\Code";
    CreateDirectoryA(code.c_str(), nullptr);
    Write(code + "\\" + assembly, "not a real assembly");
  }
}

std::string Manifest(const char* mod_id, const char* code) {
  std::string text = "{\"manifest_version\":1,\"mod_id\":\"";
  text += mod_id;
  text += "\",\"name\":\"n\",\"version\":\"1.0.0\",\"framework_api\":\"^0.4.0\"";
  if (code != nullptr) {
    text += ",\"code\":[\"";
    text += code;
    text += "\"]";
  }
  return text + "}";
}

// The plan with absolute paths reduced to their filenames, so an expectation
// can be written without the scratch directory in it.
std::string Shorten(const std::string& plan) {
  std::string out;
  size_t at = 0;
  while (at < plan.size()) {
    const size_t semi = plan.find(';', at);
    const std::string entry =
        plan.substr(at, semi == std::string::npos ? std::string::npos
                                                  : semi - at);
    const size_t equals = entry.find('=');
    const size_t slash = entry.rfind('\\');
    if (!out.empty()) {
      out += ";";
    }
    out += entry.substr(0, equals + 1) +
           (slash == std::string::npos ? entry.substr(equals + 1)
                                       : entry.substr(slash + 1));
    if (semi == std::string::npos) {
      break;
    }
    at = semi + 1;
  }
  return out;
}

}  // namespace

int main() {
  char temp[MAX_PATH];
  GetTempPathA(sizeof(temp), temp);
  g_root = std::string(temp) + "misery-discovery-test";
  CreateDirectoryA(g_root.c_str(), nullptr);
  CreateDirectoryA((g_root + "\\Mods").c_str(), nullptr);

  // THE CASE THAT BROKE. The id and the assembly stem legitimately differ, and
  // the id must come from the manifest rather than from the directory name.
  MakeMod("AlphaManagedMod", Manifest("alphamod", "AlphaManagedMod.dll"),
          "AlphaManagedMod.dll");

  // A directory that never claimed to be a mod. Authors keep scratch folders
  // under Mods/, so this is invisible -- not planned, and not reported skipped.
  MakeMod("scratch-notes", "", "");

  // Claimed to be a mod and could not be read. Reported, because a mod going
  // missing without anyone learning why is the failure mode to avoid.
  MakeMod("brokenjson", "{\"manifest_version\":1, oops", "x.dll");

  // Claimed to be a mod, declares no id.
  MakeMod("noid", "{\"manifest_version\":1,\"name\":\"n\"}", "x.dll");

  // Content-only: a real, legitimate mod with nothing for a MANAGED host to do.
  // Not planned and not an error.
  MakeMod("contentonly", Manifest("contentonly", nullptr), "");

  // Declares an assembly that is not there.
  MakeMod("missingcode", Manifest("missingcode", "absent.dll"), "");

  // An older copy of a mod left behind under its previous directory name, so
  // two directories declare the same id. Ambiguous: neither may silently win.
  MakeMod("alphamod-old", Manifest("alphamod", "AlphaManagedMod.dll"),
          "AlphaManagedMod.dll");

  std::vector<std::string> found;
  std::vector<std::string> skipped;
  const std::string plan =
      misery::managed::DiscoverPlan(g_root, &found, &skipped);

  // With the duplicate present, NEITHER copy of alphamod loads, so the only
  // mod planned is the one declared once. A separate pass below removes the
  // duplicate and checks that alphamod then loads normally.
  Report("an ambiguous id plans nothing at all", "",
         Shorten(plan));
  Report("no mod is planned while an id is ambiguous", "0",
         std::to_string(found.size()));

  // Five directories claimed to be mods and were refused -- three malformed,
  // and both halves of the ambiguous pair. Two more were legitimately not
  // planned without being refusals.
  Report("five directories are reported skipped", "5",
         std::to_string(skipped.size()));
  std::string reasons;
  for (const std::string& why : skipped) {
    reasons += (reasons.empty() ? "" : " / ") + why;
  }
  Report("a directory with no manifest is not reported at all", "0",
         std::to_string(reasons.find("scratch-notes") != std::string::npos
                            ? 1 : 0));
  Report("a content-only mod is not reported as skipped", "0",
         std::to_string(reasons.find("contentonly") != std::string::npos
                            ? 1 : 0));
  Report("an unreadable manifest is reported", "1",
         std::to_string(reasons.find("brokenjson") != std::string::npos
                            ? 1 : 0));
  Report("a manifest with no mod_id is reported", "1",
         std::to_string(reasons.find("noid") != std::string::npos ? 1 : 0));
  Report("a declared but absent assembly is reported", "1",
         std::to_string(reasons.find("missingcode") != std::string::npos
                            ? 1 : 0));
  Report("both directories of a duplicated id are named", "11",
         std::to_string(reasons.find("alphamod-old") != std::string::npos
                            ? 1 : 0) +
             std::to_string(reasons.find("AlphaManagedMod (") !=
                                    std::string::npos ? 1 : 0));

  // The same tree with the stale copy removed: the mod loads, under the id its
  // manifest declares. This is the case that broke in-game, and it has to still
  // pass once ambiguity is out of the way.
  RemoveTree(g_root + "\\Mods\\alphamod-old");
  std::vector<std::string> one_found;
  std::vector<std::string> one_skipped;
  const std::string one =
      misery::managed::DiscoverPlan(g_root, &one_found, &one_skipped);
  std::string one_reasons;
  for (const std::string& why : one_skipped) {
    one_reasons += (one_reasons.empty() ? "" : " / ") + why;
  }
  Report("with the duplicate gone nothing about alphamod is refused", "",
         one_reasons.find("alphamod") != std::string::npos ? one_reasons : "");
  Report("with the duplicate gone the mod is planned under its manifest id",
         "alphamod=AlphaManagedMod.dll", Shorten(one));
  Report("exactly one mod is planned", "1", std::to_string(one_found.size()));
  Report("the planned id is the manifest's", "alphamod",
         one_found.empty() ? std::string("(none)") : one_found[0]);

  // An installation with nothing in it is an ordinary installation.
  std::vector<std::string> none_found;
  std::vector<std::string> none_skipped;
  const std::string empty = misery::managed::DiscoverPlan(
      g_root + "\\does-not-exist", &none_found, &none_skipped);
  Report("a missing Mods directory plans nothing and reports nothing",
         "||0|0", "|" + empty + "|" + std::to_string(none_found.size()) + "|" +
                      std::to_string(none_skipped.size()));

  printf("%s\n", g_failures == 0 ? "PASS" : "FAIL");
  return g_failures == 0 ? 0 : 1;
}
