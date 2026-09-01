// ModDiscovery.cpp -- reading the installation, and nothing else.
//
// THE MOD LIST IS A PLACEHOLDER, BUT NOT AN INVENTED ONE
// -------------------------------------------------------
// Step 3 needs "a real C# mod loads and registers an item"; it does not need
// dependency resolution, conflict arbitration, version satisfaction or
// deterministic load ordering, all of which Stage 4 already implements and Step
// 4 will port. So this reads the smallest true subset of what Stage 4 reads:
// mod_id, and the first code artifact.
//
// It reads them from Stage 4's OWN layout -- mod.json beside a Code/ directory,
// with the id in mod_id -- rather than a shorter convention of its own. The
// first version of this file did invent one (directory name is both the id and
// the assembly stem), and that was a mistake twice over: it rejected the
// framework's own fixture, whose id and assembly name legitimately differ, and
// it would have left Step 4 migrating away from a layout that never should have
// existed. A placeholder may read less than the real thing. It should not
// disagree with it.
//
// What is still missing is deliberate: no dependency is honoured, no version is
// checked, no conflict is detected, and load order is whatever the filesystem
// enumerates. Step 4 supplies all of it.
#include <windows.h>

#include <string>
#include <vector>

#include "Json.h"
#include "ModDiscovery.h"

namespace misery {
namespace managed {

std::string DiscoverPlan(const std::string& framework_dir,
                         std::vector<std::string>* found,
                         std::vector<std::string>* skipped) {
  // Stage 4's layout, read shallowly. See the header comment.
  const std::string mods = framework_dir + "\\Mods";
  WIN32_FIND_DATAA entry;
  HANDLE search = FindFirstFileA((mods + "\\*").c_str(), &entry);
  if (search == INVALID_HANDLE_VALUE) {
    return std::string();
  }
  // (mod_id, assembly, directory) for every directory that claimed to be a
  // mod and was otherwise acceptable. Collected before the plan string is
  // built, because the duplicate rule below has to be able to reject an id
  // already accepted -- which a string being appended to cannot do.
  struct Candidate {
    std::string id;
    std::string assembly;
    std::string dir;
  };
  std::vector<Candidate> candidates;
  do {
    if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
      continue;
    }
    const std::string dir = entry.cFileName;
    if (dir == "." || dir == "..") {
      continue;
    }
    const std::string root = mods + "\\" + dir;

    // No manifest means not a mod. Stage 4 treats such a directory as invisible
    // rather than malformed -- authors keep scratch folders under Mods/ -- so
    // it is not reported as skipped either.
    const std::string manifest_path = root + "\\mod.json";
    std::string text;
    std::string why;
    if (!json::ReadFile(manifest_path.c_str(), 1u << 20, &text, &why)) {
      continue;
    }

    // From here on the directory CLAIMED to be a mod, so every refusal is
    // reported. A manifest that cannot be read is not silently skipped: that is
    // how a mod goes missing without anyone learning why.
    json::Value manifest;
    if (!json::Parse(text, &manifest, &why)) {
      skipped->push_back(dir + " (its mod.json could not be read: " + why + ")");
      continue;
    }
    const json::Value* id = manifest.Member("mod_id");
    if (id == nullptr || !id->Is(json::Kind::kString) || id->text.empty()) {
      skipped->push_back(dir + " (its mod.json declares no mod_id)");
      continue;
    }
    const json::Value* code = manifest.Member("code");
    if (code == nullptr || !code->Is(json::Kind::kArray) ||
        code->array.empty() || !code->array[0].Is(json::Kind::kString)) {
      // Content-only mods are perfectly legitimate and Stage 4 loads them. They
      // have nothing for a MANAGED host to do, so they are not an error here.
      continue;
    }

    const std::string assembly = root + "\\Code\\" + code->array[0].text;
    if (GetFileAttributesA(assembly.c_str()) == INVALID_FILE_ATTRIBUTES) {
      skipped->push_back(dir + " (its declared assembly " + code->array[0].text +
                         " is not present under Code\\)");
      continue;
    }
    // The id is NOT validated here. Misery.ModAPI's ModId owns that rule, it is
    // stricter than anything worth restating in C++, and a second copy of a
    // validation rule is a second chance to disagree with the first.
    Candidate candidate;
    candidate.id = id->text;
    candidate.assembly = assembly;
    candidate.dir = dir;
    candidates.push_back(candidate);
  } while (FindNextFileA(search, &entry) != 0);
  FindClose(search);

  // AN AMBIGUOUS ID LOADS NOTHING.
  //
  // Two directories declaring the same mod_id is not a thing to arbitrate.
  // Loading the first and reporting the second would make the outcome depend
  // on the order the filesystem happened to enumerate, and would silently pick
  // a winner between two copies of a mod that may well differ. Neither is
  // loaded, and both are named.
  //
  // Seen for real: an installation still holding an older copy of a mod under
  // its previous directory name, which produced two plan entries and a
  // confusing "'alphamod' is already loaded" from the host.
  std::string plan;
  for (const Candidate& candidate : candidates) {
    std::string clash;
    for (const Candidate& other : candidates) {
      if (&other != &candidate && other.id == candidate.id) {
        clash = other.dir;
        break;
      }
    }
    if (!clash.empty()) {
      skipped->push_back(candidate.dir + " (it and " + clash +
                         " both declare mod_id '" + candidate.id +
                         "'; neither is loaded)");
      continue;
    }
    if (!plan.empty()) {
      plan += ";";
    }
    plan += candidate.id + "=" + candidate.assembly;
    found->push_back(candidate.id);
  }
  return plan;
}

}  // namespace managed
}  // namespace misery
