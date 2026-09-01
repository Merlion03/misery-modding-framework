// ModPlan.h -- Stage 4's discovery and load planning, in the runtime.
//
// WHAT THIS IS, AND WHAT IT IS NOT
// --------------------------------
// It is a PORT, not a design. Stage 4 already decided every rule in this file
// and proved each one against adversarial cases; tools/modframework/ is the
// source of truth and this is the same behaviour where the game can reach it.
// Where the two could disagree, the Python is right and this is wrong.
//
// That is not a claim to be taken on trust: tests/test_mod_plan.py builds mod
// trees with Stage 4's OWN fixture builders, runs both planners over them, and
// requires the load order and every exclusion to match exactly. A divergence is
// a failing test rather than a mystery in someone's install.
//
// WHY IT IS HERE AND NOT IN THE MANAGED HOST
// -------------------------------------------
// A content-only mod has no assembly at all, and it still takes part in
// dependencies, conflicts and ordering. Planning from inside CoreCLR would mean
// starting a runtime to plan mods that contain no code, and would put the
// decision downstream of the thing it decides. So the plan is made natively,
// before the host exists, and the host is handed its result.
//
// THE SHAPE OF THE ANSWER
// -----------------------
//   discover   every folder under Mods/ with a mod.json, parsed
//   resolve    identity, dependencies, conflicts, cycles, propagation, order
//   plan       an ordered list of mod ids, plus why everything else is absent
//
// A plan can be useful without being clean: two independent mods, one broken,
// still yields a valid plan for the other. `ok` says whether anything was
// refused; `load_order` says what to load regardless.
#pragma once

#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace misery {
namespace modplan {

// ---------------------------------------------------------------------------
// diagnostics -- the closed vocabulary Stage 4 reports problems in
// ---------------------------------------------------------------------------
//
// Closed because a caller decides what to show a user by branching on the
// reason, and free text cannot be branched on, counted, or tested. A code not
// in this list is a programming error, not a new kind of problem.
extern const char kMalformedManifest[];
extern const char kUnsupportedManifestVersion[];
extern const char kInvalidModId[];
extern const char kUnsupportedFrameworkApi[];
extern const char kMissingArtifact[];
extern const char kContentNamespaceMismatch[];
extern const char kDuplicateModId[];
extern const char kMissingDependency[];
extern const char kIncompatibleDependencyVersion[];
extern const char kDependencyCycle[];
extern const char kExplicitConflict[];
extern const char kDependencyExcluded[];
extern const char kOptionalDependencyAbsent[];

// Fatal means EXCLUDED, not "something went wrong": a fatal diagnostic removes
// its subject from the plan. Everything except an absent optional dependency
// is fatal.
bool IsFatal(const std::string& code);

struct Diagnostic {
  std::string code;
  // The mod_id when there is one, and the folder path when the manifest was
  // too broken to yield one -- two unreadable manifests must not both report
  // as nothing.
  std::string subject;
  std::string detail;
};

// ---------------------------------------------------------------------------
// semver
// ---------------------------------------------------------------------------

struct Version {
  int64_t major = 0;
  int64_t minor = 0;
  int64_t patch = 0;

  bool operator==(const Version& o) const;
  bool operator<(const Version& o) const;
  bool operator>=(const Version& o) const { return !(*this < o); }
  std::string ToString() const;
};

// MAJOR.MINOR.PATCH, no leading zeros. Leading zeros are refused rather than
// tolerated: "1.02.0" and "1.2.0" compare equal numerically while looking
// different in a manifest, and an author could not tell which was used.
bool ParseVersion(const std::string& text, Version* out, std::string* error);

struct Requirement {
  std::string op;        // "==", ">=", or "^"
  Version version;
  std::string text;

  bool Matches(const Version& v) const;
};

// `^` is the default, because that is the rule the framework's own API version
// lives by. A 0.x version gets NO special "0.x majors are breaking" case: that
// is a convention some ecosystems have and others do not, and applying it
// silently would refuse dependencies the author believed they allowed.
bool ParseRequirement(const std::string& text, Requirement* out,
                      std::string* error);

// ---------------------------------------------------------------------------
// mod ids
// ---------------------------------------------------------------------------

// The canonical contract: ^[a-z][a-z0-9_]*$, no "__", at most 48 characters,
// not reserved. The "__" rule is Stage 2's: a row name is <mod_id>__<local_id>,
// so an id containing the separator makes that decomposition ambiguous.
bool CheckModId(const std::string& mod_id, std::string* error);

// ---------------------------------------------------------------------------
// manifests
// ---------------------------------------------------------------------------

struct Dependency {
  std::string mod_id;
  Requirement requirement;
  bool has_requirement = false;   // optional deps may omit a version
  bool optional = false;
};

struct Conflict {
  std::string mod_id;
  Requirement requirement;
  bool has_requirement = false;   // absent means "any version conflicts"
};

struct Manifest {
  std::string mod_id;
  std::string name;
  Version version;
  Requirement framework_api;
  int64_t manifest_version = 0;
  std::vector<Dependency> dependencies;
  std::vector<Dependency> optional_dependencies;
  std::vector<Conflict> conflicts;
  std::vector<std::string> content;   // container stems
  std::vector<std::string> code;      // assembly filenames under Code/
  std::string root;                   // the mod's folder
};

// Parse a decoded mod.json body. *out* is filled only when nothing fatal was
// found -- Stage 4 never holds a half-accepted manifest, because that is
// exactly what leaks into a plan. *declared_mod_id* is what the file CLAIMED,
// returned even on refusal so the mod can be named in a report.
bool ParseManifest(const std::string& json_text, const std::string& root,
                   Manifest* out, std::vector<Diagnostic>* diagnostics,
                   std::string* declared_mod_id);

// Every declared artifact must exist: a mod missing one is not partially
// loadable.
void CheckArtifacts(const Manifest& manifest,
                    std::vector<Diagnostic>* diagnostics);

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

struct Discovered {
  std::string folder;                 // the folder NAME, never an identity
  std::string root;
  bool accepted = false;              // a manifest survived parsing
  Manifest manifest;
  std::string declared_mod_id;
  std::vector<Diagnostic> diagnostics;

  // How this folder is named in a report, accepted or not.
  const std::string& Identity() const {
    return declared_mod_id.empty() ? root : declared_mod_id;
  }
};

// Scan *mods_root*. Deterministic: accepted mods by mod_id, then unparseable
// folders by folder name -- never by the order the filesystem enumerated, so
// renaming a folder is a cosmetic act.
//
// A subdirectory without a mod.json is not a candidate and is not reported:
// users keep notes and backups beside their mods. A folder WITH one that
// cannot be parsed is reported loudly.
std::vector<Discovered> Discover(const std::string& mods_root);

// ---------------------------------------------------------------------------
// the plan
// ---------------------------------------------------------------------------

struct Plan {
  std::vector<std::string> load_order;               // mod ids, in order
  std::map<std::string, std::set<std::string>> excluded;   // subject -> codes
  std::vector<Diagnostic> diagnostics;
  std::map<std::string, Manifest> manifests;         // the ones that load

  bool ok() const { return excluded.empty(); }
};

// Discovery output -> a deterministic plan.
//
// The order of the checks is deliberate and is Stage 4's: identity first,
// because every later question is asked about a mod_id; then dependencies and
// conflicts, which are statements about the accepted set; then cycles, over
// what survives; then propagation, which needs every other exclusion known;
// then ordering, over a set with no cycles left in it.
Plan Resolve(const std::vector<Discovered>& discovered);

// The whole read-only pipeline.
Plan PlanFromRoot(const std::string& mods_root);

}  // namespace modplan
}  // namespace misery
