// ModDiscovery.cpp -- find the mod folders under Mods/. Nothing else.
//
// A port of tools/modframework/discovery.py. See ModPlan.h.
//
// WHY DISCOVERY IS ITS OWN LAYER
// ------------------------------
// It is the only part of planning that touches the filesystem, and therefore
// the only part whose answer can depend on the machine. Isolating it means
// validation and resolution can be tested by handing them a list -- no temp
// directories, no ordering tricks, no game.
//
// DETERMINISM IS NOT "THE DIRECTORY HAPPENED TO ENUMERATE CONVENIENTLY"
// ---------------------------------------------------------------------
// FindFirstFile returns entries in whatever order the filesystem hands back. On
// NTFS that is usually alphabetical, and after enough renames it is not. Code
// that works today because a directory enumerated conveniently is code that
// reorders someone's mods after they rename a folder. So the result is sorted
// explicitly, and the sort key is the mod_id wherever one exists -- the folder
// name only orders things that could not be parsed and therefore have no id.
//
// WHAT REPLACED WHAT
// ------------------
// The first version of this file invented a convention of its own: a mod's
// directory name was both its id and its assembly's stem, with no manifest read
// at all. It rejected the framework's own fixture and would have left Step 4
// migrating away from a layout that never should have existed. Stage 4 had
// already decided all of this; this is that decision, where the game can reach
// it.
#include <windows.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "Json.h"
#include "ModDiscovery.h"
#include "ModPlan.h"

namespace misery {
namespace modplan {
namespace {

constexpr size_t kMaxManifestBytes = 1u << 20;
const char kManifestFilename[] = "mod.json";

std::string Lowered(const std::string& text) {
  std::string out = text;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(tolower(c));
  });
  return out;
}

}  // namespace

std::vector<Discovered> Discover(const std::string& mods_root) {
  // Every immediate subdirectory holding a mod.json, sorted by name.
  //
  // A subdirectory WITHOUT a manifest is not a candidate and is not reported:
  // users keep notes, backups and screenshots beside their mods, and a
  // discovery layer that called every stray folder a broken mod would train
  // them to ignore its output. A folder WITH one that cannot be parsed is a
  // different matter entirely, and is reported loudly.
  std::vector<std::pair<std::string, std::string>> candidates;
  WIN32_FIND_DATAA entry;
  HANDLE search = FindFirstFileA((mods_root + "\\*").c_str(), &entry);
  if (search != INVALID_HANDLE_VALUE) {
    do {
      if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        continue;
      }
      const std::string name = entry.cFileName;
      if (name == "." || name == "..") {
        continue;
      }
      const std::string root = mods_root + "\\" + name;
      const DWORD manifest =
          GetFileAttributesA((root + "\\" + kManifestFilename).c_str());
      if (manifest == INVALID_FILE_ATTRIBUTES ||
          (manifest & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        continue;
      }
      candidates.push_back({name, root});
    } while (FindNextFileA(search, &entry) != 0);
    FindClose(search);
  }
  std::sort(candidates.begin(), candidates.end());

  // Case-insensitive folder collisions are settled BEFORE anything is parsed,
  // and they refuse EVERY member of the colliding group.
  //
  // Refusing only the folder met second would leave the first accepted -- so on
  // a case-sensitive filesystem the mod that loaded would be whichever folder
  // name sorted first by codepoint, and renaming `alphamod/` to `Alphamod/`
  // would flip which of two unrelated mods reached the live plan. That is the
  // folder name deciding identity, and it fails OPEN. The duplicate-mod_id rule
  // drops both claimants for exactly this reason; so does this.
  std::map<std::string, std::vector<std::string>> by_key;
  for (const auto& candidate : candidates) {
    by_key[Lowered(candidate.first)].push_back(candidate.first);
  }

  std::vector<Discovered> found;
  for (const auto& candidate : candidates) {
    Discovered discovered;
    discovered.folder = candidate.first;
    discovered.root = candidate.second;

    std::vector<std::string>& siblings = by_key[Lowered(candidate.first)];
    std::string text;
    std::string why;
    const std::string manifest_path =
        discovered.root + "\\" + kManifestFilename;
    if (!json::ReadFile(manifest_path.c_str(), kMaxManifestBytes, &text,
                        &why)) {
      Diagnostic d;
      d.code = kMalformedManifest;
      d.subject = discovered.root;
      d.detail = "the manifest could not be read: " + why;
      discovered.diagnostics.push_back(d);
    } else {
      discovered.accepted =
          ParseManifest(text, discovered.root, &discovered.manifest,
                        &discovered.diagnostics, &discovered.declared_mod_id);
    }

    if (siblings.size() > 1) {
      std::vector<std::string> others;
      for (const std::string& name : siblings) {
        if (name != candidate.first) {
          others.push_back(name);
        }
      }
      std::sort(others.begin(), others.end());
      std::string list;
      for (size_t i = 0; i < others.size(); ++i) {
        list += (i ? ", " : "") + others[i];
      }
      Diagnostic d;
      d.code = kMalformedManifest;
      d.subject = discovered.root;
      d.detail =
          "the folder name collides case-insensitively with " + list +
          ". On Windows these are one folder and on Linux they are two, so "
          "which mod this is would depend on the machine reading the "
          "directory. EVERY folder in the group is refused: keeping the one "
          "whose name happens to sort first would let a rename decide which "
          "mod loads.";
      discovered.diagnostics.push_back(d);
      discovered.accepted = false;
    }

    if (discovered.accepted) {
      std::vector<Diagnostic> artifact_problems;
      CheckArtifacts(discovered.manifest, &artifact_problems);
      for (const Diagnostic& d : artifact_problems) {
        discovered.diagnostics.push_back(d);
        if (IsFatal(d.code)) {
          // A mod missing a declared artifact is not partially loadable.
          // Dropping the manifest here is what stops a half-present mod from
          // reaching the resolver as if it were whole.
          discovered.accepted = false;
        }
      }
    }
    found.push_back(discovered);
  }

  // Accepted mods by mod_id, then unparseable folders by folder name. Ordering
  // by mod_id rather than folder name is what makes renaming `AlphaMod` to
  // `ZZZ_AlphaMod` a cosmetic act.
  std::sort(found.begin(), found.end(),
            [](const Discovered& a, const Discovered& b) {
              const bool a_none = !a.accepted;
              const bool b_none = !b.accepted;
              if (a_none != b_none) {
                return b_none;
              }
              const std::string& a_id = a.accepted ? a.manifest.mod_id
                                                   : std::string();
              const std::string& b_id = b.accepted ? b.manifest.mod_id
                                                   : std::string();
              if (a_id != b_id) {
                return a_id < b_id;
              }
              return a.folder < b.folder;
            });
  return found;
}

}  // namespace modplan

namespace managed {

std::string DiscoverPlan(const std::string& framework_dir,
                         std::vector<std::string>* found,
                         std::vector<std::string>* skipped) {
  // The managed host's slice of the plan: the mods that load AND carry an
  // assembly, in the planned order.
  //
  // Order is the plan's, not the filesystem's, and not sorted again here: a
  // mod's dependencies load before it, which is the whole point of having
  // computed an order. Content-only mods are in the plan and simply have
  // nothing for this host to do.
  const modplan::Plan plan =
      modplan::PlanFromRoot(framework_dir + "\\Mods");

  std::string text;
  for (const std::string& mod_id : plan.load_order) {
    const modplan::Manifest& manifest = plan.manifests.at(mod_id);
    for (const std::string& assembly : manifest.code) {
      if (!text.empty()) {
        text += ";";
      }
      text += mod_id + "=" + manifest.root + "\\Code\\" + assembly;
    }
    if (!manifest.code.empty()) {
      found->push_back(mod_id);
    }
  }

  // Everything the plan refused, named with the reason IN FULL.
  //
  // The code alone is not enough for the person whose mod did not load.
  // "alphamod (duplicate_mod_id)" does not say which two folders claimed the
  // id, and finding that out would mean guessing at a directory listing. Stage
  // 4 writes a sentence for every refusal precisely so it can be read; carrying
  // the code and discarding the sentence would keep the machinery and throw
  // away the part a user acts on.
  for (const auto& entry : plan.excluded) {
    std::string codes;
    for (const std::string& code : entry.second) {
      codes += (codes.empty() ? "" : ", ") + code;
    }
    std::string line = entry.first + " (" + codes + ")";
    for (const modplan::Diagnostic& d : plan.diagnostics) {
      if (d.subject == entry.first && modplan::IsFatal(d.code)) {
        line += " -- " + d.detail;
      }
    }
    skipped->push_back(line);
  }
  return text;
}

}  // namespace managed
}  // namespace misery
