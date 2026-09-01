// ModManifest.cpp -- ids, versions and manifest validation.
//
// A port of tools/modplatform/modid.py, tools/modplatform/semverlib.py and
// tools/modframework/manifest.py. See ModPlan.h: those are the source of truth,
// and tests/test_mod_plan.py holds this to them.
//
// Every refusal here is decidable from ONE manifest. Nothing in this file
// compares two mods; that is ModResolve.cpp's job, and keeping the two apart is
// what lets a broken mod be refused without touching anybody else's.
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "Json.h"
#include "ModPlan.h"

namespace misery {
namespace modplan {

const char kMalformedManifest[] = "malformed_manifest";
const char kUnsupportedManifestVersion[] = "unsupported_manifest_version";
const char kInvalidModId[] = "invalid_mod_id";
const char kUnsupportedFrameworkApi[] = "unsupported_framework_api";
const char kMissingArtifact[] = "missing_artifact";
const char kContentNamespaceMismatch[] = "content_namespace_mismatch";
const char kDuplicateModId[] = "duplicate_mod_id";
const char kMissingDependency[] = "missing_dependency";
const char kIncompatibleDependencyVersion[] = "incompatible_dependency_version";
const char kDependencyCycle[] = "dependency_cycle";
const char kExplicitConflict[] = "explicit_conflict";
const char kDependencyExcluded[] = "dependency_excluded";
const char kOptionalDependencyAbsent[] = "optional_dependency_absent";

bool IsFatal(const std::string& code) {
  return code != kOptionalDependencyAbsent;
}

namespace {

// The framework's own API version, which every mod's framework_api is tested
// against. MAJOR is the promise: a bump says old mods stop working.
const Version kFrameworkApiVersion = {0, 4, 0};
constexpr int64_t kSupportedManifestVersion = 1;
constexpr size_t kMaxModIdLength = 48;
constexpr size_t kMaxNameLength = 96;
const char kRowNameSeparator[] = "__";
const char kCodeDirName[] = "Code";
const char kContentDirName[] = "Content";
const char* const kContainerSuffixes[] = {".pak", ".utoc", ".ucas"};

const char* const kReservedModIds[] = {
    "misery", "sgk", "engine", "core", "game", "vanilla",   // Stage 2 and 3
    "mods", "temp", "script",                               // Stage 3 only
};

const char* const kKnownFields[] = {
    "manifest_version", "mod_id", "name", "version", "framework_api",
    "dependencies", "optional_dependencies", "conflicts", "content", "code",
};

void Add(std::vector<Diagnostic>* out, const char* code,
         const std::string& subject, const std::string& detail) {
  Diagnostic d;
  d.code = code;
  d.subject = subject;
  d.detail = detail;
  out->push_back(d);
}

bool AnyFatal(const std::vector<Diagnostic>& diagnostics) {
  for (const Diagnostic& d : diagnostics) {
    if (IsFatal(d.code)) {
      return true;
    }
  }
  return false;
}

std::string Trim(const std::string& text) {
  size_t begin = text.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) {
    return std::string();
  }
  size_t end = text.find_last_not_of(" \t\r\n");
  return text.substr(begin, end - begin + 1);
}

bool FileExists(const std::string& path) {
  const DWORD attributes = GetFileAttributesA(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
         (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string Join(const std::vector<std::string>& items) {
  std::string out = "[";
  for (size_t i = 0; i < items.size(); ++i) {
    out += (i ? ", " : "") + ("'" + items[i] + "'");
  }
  return out + "]";
}

}  // namespace

// ---------------------------------------------------------------------------
// semver
// ---------------------------------------------------------------------------

bool Version::operator==(const Version& o) const {
  return major == o.major && minor == o.minor && patch == o.patch;
}

bool Version::operator<(const Version& o) const {
  if (major != o.major) return major < o.major;
  if (minor != o.minor) return minor < o.minor;
  return patch < o.patch;
}

std::string Version::ToString() const {
  char buffer[64];
  _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%lld.%lld.%lld",
              static_cast<long long>(major), static_cast<long long>(minor),
              static_cast<long long>(patch));
  return buffer;
}

namespace {

// One component of MAJOR.MINOR.PATCH: digits, and no leading zero unless the
// component IS zero.
bool ParseComponent(const std::string& text, int64_t* out) {
  if (text.empty() || text.size() > 18) {
    return false;
  }
  for (char c : text) {
    if (!isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  if (text.size() > 1 && text[0] == '0') {
    return false;
  }
  *out = _strtoi64(text.c_str(), nullptr, 10);
  return true;
}

}  // namespace

bool ParseVersion(const std::string& raw, Version* out, std::string* error) {
  const std::string text = Trim(raw);
  const size_t first = text.find('.');
  const size_t second = first == std::string::npos
                            ? std::string::npos
                            : text.find('.', first + 1);
  if (first == std::string::npos || second == std::string::npos ||
      text.find('.', second + 1) != std::string::npos) {
    *error = "'" + raw + "' is not MAJOR.MINOR.PATCH with no leading zeros";
    return false;
  }
  Version parsed;
  if (!ParseComponent(text.substr(0, first), &parsed.major) ||
      !ParseComponent(text.substr(first + 1, second - first - 1),
                      &parsed.minor) ||
      !ParseComponent(text.substr(second + 1), &parsed.patch)) {
    *error = "'" + raw + "' is not MAJOR.MINOR.PATCH with no leading zeros";
    return false;
  }
  *out = parsed;
  return true;
}

bool Requirement::Matches(const Version& v) const {
  if (op == "==") {
    return v == version;
  }
  if (op == ">=") {
    return v >= version;
  }
  // "^": at least this version, and not the next MAJOR.
  return v >= version && v.major == version.major;
}

bool ParseRequirement(const std::string& raw, Requirement* out,
                      std::string* error) {
  const std::string text = Trim(raw);
  if (text.empty()) {
    *error = "requirement must be a non-empty string";
    return false;
  }
  std::string op = "^";
  std::string rest = text;
  if (text.compare(0, 2, "==") == 0) {
    op = "==";
    rest = text.substr(2);
  } else if (text.compare(0, 2, ">=") == 0) {
    op = ">=";
    rest = text.substr(2);
  } else if (text[0] == '^') {
    op = "^";
    rest = text.substr(1);
  }
  rest = Trim(rest);
  if (rest.empty()) {
    *error = "'" + raw + "' is not a usable version requirement";
    return false;
  }
  // An operator this grammar does not have must say so, rather than being
  // reported as a malformed number: "<2.0.0" is an unsupported operator, not a
  // bad version.
  if (!isdigit(static_cast<unsigned char>(rest[0]))) {
    *error = "'" + text +
             "' uses an operator this framework does not support; Stage 4 "
             "understands only ==, >=, ^ and a bare version (which means ^)";
    return false;
  }
  Version version;
  if (!ParseVersion(rest, &version, error)) {
    return false;
  }
  out->op = op;
  out->version = version;
  out->text = text;
  return true;
}

// ---------------------------------------------------------------------------
// mod ids
// ---------------------------------------------------------------------------

bool CheckModId(const std::string& mod_id, std::string* error) {
  if (mod_id.empty()) {
    *error = "must not be empty";
    return false;
  }
  if (mod_id.size() > kMaxModIdLength) {
    char buffer[128];
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                "is %zu characters; the limit is %zu", mod_id.size(),
                kMaxModIdLength);
    *error = buffer;
    return false;
  }
  if (!(mod_id[0] >= 'a' && mod_id[0] <= 'z')) {
    *error = "must match ^[a-z][a-z0-9_]*$";
    return false;
  }
  for (char c : mod_id) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '_';
    if (!ok) {
      *error = "must match ^[a-z][a-z0-9_]*$";
      return false;
    }
  }
  if (mod_id.find(kRowNameSeparator) != std::string::npos) {
    *error = std::string("contains '") + kRowNameSeparator +
             "', which Stage 2 uses to separate a mod_id from a local item id";
    return false;
  }
  for (const char* reserved : kReservedModIds) {
    if (mod_id == reserved) {
      *error = "is reserved";
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// manifests
// ---------------------------------------------------------------------------

namespace {

// A dependency list: [{mod_id, version?}, ...].
void ParseDependencyList(const json::Value* raw, const char* field,
                         const std::string& subject, bool optional,
                         std::vector<Dependency>* out,
                         std::vector<Diagnostic>* diagnostics) {
  if (raw == nullptr || raw->kind == json::Kind::kNull) {
    return;
  }
  if (!raw->Is(json::Kind::kArray)) {
    Add(diagnostics, kMalformedManifest, subject,
        std::string("'") + field + "' must be a list");
    return;
  }
  std::set<std::string> seen;
  for (size_t i = 0; i < raw->array.size(); ++i) {
    const json::Value& entry = raw->array[i];
    if (!entry.Is(json::Kind::kObject)) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry " + std::to_string(i) +
              " must be an object");
      continue;
    }
    std::vector<std::string> unknown;
    for (const auto& member : entry.object) {
      if (member.first != "mod_id" && member.first != "version") {
        unknown.push_back(member.first);
      }
    }
    if (!unknown.empty()) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry " + std::to_string(i) +
              " has unknown field(s) " + Join(unknown));
      continue;
    }
    const json::Value* target = entry.Member("mod_id");
    if (target == nullptr || !target->Is(json::Kind::kString)) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry " + std::to_string(i) +
              " must name a mod_id");
      continue;
    }
    std::string why;
    if (!CheckModId(target->text, &why)) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry " + std::to_string(i) + ": '" +
              target->text + "' " + why);
      continue;
    }
    if (target->text == subject) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' names the mod itself");
      continue;
    }
    if (!seen.insert(target->text).second) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' names '" + target->text +
              "' more than once");
      continue;
    }

    Dependency dependency;
    dependency.mod_id = target->text;
    dependency.optional = optional;
    const json::Value* version = entry.Member("version");
    if (version == nullptr) {
      // EVERY entry states a version, optional dependencies included. No
      // silent default: the previous one was "0.0.0", which parses as ^0.0.0
      // -- "major must be 0" -- and so refused every dependency at 1.0.0 or
      // later while reading like "any version".
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry for '" + target->text +
              "' does not state a version requirement. Say so explicitly, "
              "e.g. \">=0.0.0\" for any version.");
      continue;
    }
    if (!version->Is(json::Kind::kString)) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry for '" + target->text +
              "' has a non-string version");
      continue;
    }
    {
      std::string error;
      if (!ParseRequirement(version->text, &dependency.requirement, &error)) {
        Add(diagnostics, kMalformedManifest, subject,
            std::string("'") + field + "' entry for '" + target->text +
                "': " + error);
        continue;
      }
      dependency.has_requirement = true;
    }
    out->push_back(dependency);
  }
  // Sorted by mod_id, so the order they were typed in cannot reach the plan.
  std::sort(out->begin(), out->end(),
            [](const Dependency& a, const Dependency& b) {
              return a.mod_id < b.mod_id;
            });
}

void ParseConflictList(const json::Value* raw, const std::string& subject,
                       std::vector<Conflict>* out,
                       std::vector<Diagnostic>* diagnostics) {
  if (raw == nullptr || raw->kind == json::Kind::kNull) {
    return;
  }
  if (!raw->Is(json::Kind::kArray)) {
    Add(diagnostics, kMalformedManifest, subject, "'conflicts' must be a list");
    return;
  }
  std::set<std::string> seen;
  for (size_t i = 0; i < raw->array.size(); ++i) {
    const json::Value& entry = raw->array[i];
    if (!entry.Is(json::Kind::kObject)) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' entry " + std::to_string(i) + " must be an object");
      continue;
    }
    std::vector<std::string> unknown;
    for (const auto& member : entry.object) {
      if (member.first != "mod_id" && member.first != "version") {
        unknown.push_back(member.first);
      }
    }
    if (!unknown.empty()) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' entry " + std::to_string(i) + " has unknown field(s) " +
              Join(unknown));
      continue;
    }
    const json::Value* target = entry.Member("mod_id");
    if (target == nullptr || !target->Is(json::Kind::kString)) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' entry " + std::to_string(i) + " must name a mod_id");
      continue;
    }
    std::string why;
    if (!CheckModId(target->text, &why)) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' entry " + std::to_string(i) + ": '" + target->text +
              "' " + why);
      continue;
    }
    if (target->text == subject) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' names the mod itself");
      continue;
    }
    if (!seen.insert(target->text).second) {
      Add(diagnostics, kMalformedManifest, subject,
          "'conflicts' names '" + target->text + "' more than once");
      continue;
    }
    Conflict conflict;
    conflict.mod_id = target->text;
    const json::Value* version = entry.Member("version");
    if (version != nullptr && version->kind != json::Kind::kNull) {
      if (!version->Is(json::Kind::kString)) {
        Add(diagnostics, kMalformedManifest, subject,
            "'conflicts' entry for '" + target->text +
                "' has a non-string version");
        continue;
      }
      std::string error;
      if (!ParseRequirement(version->text, &conflict.requirement, &error)) {
        Add(diagnostics, kMalformedManifest, subject,
            "'conflicts' entry for '" + target->text + "': " + error);
        continue;
      }
      conflict.has_requirement = true;
    }
    out->push_back(conflict);
  }
  std::sort(out->begin(), out->end(), [](const Conflict& a, const Conflict& b) {
    return a.mod_id < b.mod_id;
  });
}

void ParseStringList(const json::Value* raw, const char* field,
                     const std::string& subject,
                     std::vector<std::string>* out,
                     std::vector<Diagnostic>* diagnostics) {
  if (raw == nullptr || raw->kind == json::Kind::kNull) {
    return;
  }
  if (!raw->Is(json::Kind::kArray)) {
    Add(diagnostics, kMalformedManifest, subject,
        std::string("'") + field + "' must be a list of names");
    return;
  }
  std::set<std::string> seen;
  for (size_t i = 0; i < raw->array.size(); ++i) {
    const json::Value& entry = raw->array[i];
    if (!entry.Is(json::Kind::kString) || Trim(entry.text).empty()) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry " + std::to_string(i) +
              " must be a non-empty string");
      continue;
    }
    const std::string value = Trim(entry.text);
    // A declared artifact must stay inside the mod's own folder. Without this
    // an author could declare "../../OtherMod/Content/x" and have the
    // framework verify, and later mount, a file that is not theirs.
    //
    // A relative path IS allowed -- "sub/dir/x.dll" is a legitimate thing to
    // declare. Only escapes are refused: an absolute path, a drive letter, or
    // ".." as a whole path component. Rejecting every separator would be
    // stricter than Stage 4 and would refuse manifests it accepts.
    bool escapes = value[0] == '/' || value[0] == '\\' ||
                   value.find(':') != std::string::npos;
    if (!escapes) {
      std::string normalised = value;
      std::replace(normalised.begin(), normalised.end(), '\\', '/');
      size_t at = 0;
      while (!escapes && at <= normalised.size()) {
        const size_t slash = normalised.find('/', at);
        const std::string part =
            normalised.substr(at, slash == std::string::npos
                                      ? std::string::npos : slash - at);
        if (part == "..") {
          escapes = true;
        }
        if (slash == std::string::npos) {
          break;
        }
        at = slash + 1;
      }
    }
    if (escapes) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' entry '" + value +
              "' must be a relative path inside the mod folder; absolute "
              "paths and .. would let a mod declare another mod's files");
      continue;
    }
    if (!seen.insert(value).second) {
      Add(diagnostics, kMalformedManifest, subject,
          std::string("'") + field + "' names '" + value + "' more than once");
      continue;
    }
    out->push_back(value);
  }
  std::sort(out->begin(), out->end());
}

}  // namespace

bool ParseManifest(const std::string& json_text, const std::string& root,
                   Manifest* out, std::vector<Diagnostic>* diagnostics,
                   std::string* declared_mod_id) {
  declared_mod_id->clear();
  std::string subject = root;

  json::Value raw;
  std::string why;
  if (!json::Parse(json_text, &raw, &why)) {
    Add(diagnostics, kMalformedManifest, subject,
        "the manifest could not be read: " + why);
    return false;
  }
  if (!raw.Is(json::Kind::kObject)) {
    Add(diagnostics, kMalformedManifest, subject,
        "the manifest must be a JSON object");
    return false;
  }

  // manifest_version is read FIRST and alone. Every other field's meaning is
  // defined by it, so validating anything else against today's rules before
  // knowing the version would be reading a future file with the wrong grammar.
  const json::Value* manifest_version = raw.Member("manifest_version");
  if (manifest_version == nullptr || !manifest_version->Is(json::Kind::kInt)) {
    Add(diagnostics, kMalformedManifest, subject,
        "'manifest_version' must be an integer; without it the rest of the "
        "file has no defined meaning");
    return false;
  }
  if (manifest_version->integer != kSupportedManifestVersion) {
    Add(diagnostics, kUnsupportedManifestVersion, subject,
        "manifest_version " + std::to_string(manifest_version->integer) +
            " is not one this framework can read. Refusing rather than "
            "guessing: a newer layout may give an existing field a new "
            "meaning.");
    return false;
  }

  const json::Value* mod_id = raw.Member("mod_id");
  if (mod_id == nullptr || !mod_id->Is(json::Kind::kString)) {
    Add(diagnostics, kInvalidModId, subject, "'mod_id' must be a string");
    return false;
  }
  if (!CheckModId(mod_id->text, &why)) {
    Add(diagnostics, kInvalidModId, subject,
        "'" + mod_id->text + "': " + why);
    return false;
  }
  // From here the mod can be named, so everything is attributed to the id
  // rather than to a folder path.
  *declared_mod_id = mod_id->text;
  subject = mod_id->text;

  std::vector<std::string> unknown;
  for (const auto& member : raw.object) {
    bool known = false;
    for (const char* field : kKnownFields) {
      if (member.first == field) {
        known = true;
        break;
      }
    }
    if (!known) {
      unknown.push_back(member.first);
    }
  }
  if (!unknown.empty()) {
    std::sort(unknown.begin(), unknown.end());
    Add(diagnostics, kMalformedManifest, subject,
        "unknown field(s) " + Join(unknown) +
            ". Refused rather than ignored: a typo in a field name would "
            "otherwise silently disable what the author meant to say");
  }

  const json::Value* name = raw.Member("name");
  std::string trimmed_name;
  if (name == nullptr || !name->Is(json::Kind::kString) ||
      Trim(name->text).empty()) {
    Add(diagnostics, kMalformedManifest, subject,
        "'name' must be a non-empty string");
  } else if (name->text.size() > kMaxNameLength) {
    Add(diagnostics, kMalformedManifest, subject,
        "'name' is longer than " + std::to_string(kMaxNameLength) +
            " characters");
  } else {
    trimmed_name = Trim(name->text);
  }

  Version version;
  const json::Value* version_field = raw.Member("version");
  if (version_field == nullptr || !version_field->Is(json::Kind::kString)) {
    Add(diagnostics, kMalformedManifest, subject, "'version' must be a string");
  } else if (!ParseVersion(version_field->text, &version, &why)) {
    Add(diagnostics, kMalformedManifest, subject, "'version': " + why);
  }

  Requirement framework_api;
  const json::Value* api = raw.Member("framework_api");
  if (api == nullptr || !api->Is(json::Kind::kString)) {
    Add(diagnostics, kMalformedManifest, subject,
        "'framework_api' must be a string");
  } else if (!ParseRequirement(api->text, &framework_api, &why)) {
    Add(diagnostics, kMalformedManifest, subject, "'framework_api': " + why);
  } else if (!framework_api.Matches(kFrameworkApiVersion)) {
    Add(diagnostics, kUnsupportedFrameworkApi, subject,
        "the mod requires framework API " + framework_api.text +
            " and this framework is " + kFrameworkApiVersion.ToString());
  }

  std::vector<Dependency> dependencies;
  std::vector<Dependency> optional;
  ParseDependencyList(raw.Member("dependencies"), "dependencies", subject,
                      false, &dependencies, diagnostics);
  ParseDependencyList(raw.Member("optional_dependencies"),
                      "optional_dependencies", subject, true, &optional,
                      diagnostics);

  // A mod_id in both lists has two different answers to "must this be
  // present", and there is no defensible way to pick one.
  std::set<std::string> required_ids;
  for (const Dependency& d : dependencies) {
    required_ids.insert(d.mod_id);
  }
  std::vector<std::string> both;
  for (const Dependency& d : optional) {
    if (required_ids.count(d.mod_id)) {
      both.push_back(d.mod_id);
    }
  }
  if (!both.empty()) {
    std::sort(both.begin(), both.end());
    Add(diagnostics, kMalformedManifest, subject,
        Join(both) + " appear in both dependencies and optional_dependencies, "
                     "which states that they are simultaneously required and "
                     "not");
  }

  std::vector<Conflict> conflicts;
  ParseConflictList(raw.Member("conflicts"), subject, &conflicts, diagnostics);
  std::vector<std::string> contradictory;
  for (const Conflict& c : conflicts) {
    if (required_ids.count(c.mod_id)) {
      contradictory.push_back(c.mod_id);
      continue;
    }
    for (const Dependency& d : optional) {
      if (d.mod_id == c.mod_id) {
        contradictory.push_back(c.mod_id);
        break;
      }
    }
  }
  if (!contradictory.empty()) {
    std::sort(contradictory.begin(), contradictory.end());
    Add(diagnostics, kMalformedManifest, subject,
        Join(contradictory) +
            " are declared as both a dependency and a conflict");
  }

  std::vector<std::string> content;
  ParseStringList(raw.Member("content"), "content", subject, &content,
                  diagnostics);
  // A container stem names a file in the SHARED staging directory, so two mods
  // declaring one stem means the second silently replaces the first's
  // container. Stems are namespaced like everything else a mod owns.
  const std::string stem_prefix = "Mod_" + subject + "_";
  for (const std::string& stem : content) {
    if (stem.compare(0, stem_prefix.size(), stem_prefix) != 0) {
      Add(diagnostics, kContentNamespaceMismatch, subject,
          "declared content '" + stem + "' must be namespaced to this mod, "
          "i.e. begin with '" + stem_prefix + "'. Container stems share one "
          "staging directory, so an unnamespaced stem lets one mod overwrite "
          "another's container.");
    }
  }

  std::vector<std::string> code;
  ParseStringList(raw.Member("code"), "code", subject, &code, diagnostics);

  if (AnyFatal(*diagnostics)) {
    return false;
  }
  out->mod_id = subject;
  out->name = trimmed_name;
  out->version = version;
  out->framework_api = framework_api;
  out->manifest_version = manifest_version->integer;
  out->dependencies = dependencies;
  out->optional_dependencies = optional;
  out->conflicts = conflicts;
  out->content = content;
  out->code = code;
  out->root = root;
  return true;
}

void CheckArtifacts(const Manifest& manifest,
                    std::vector<Diagnostic>* diagnostics) {
  // A container ships as three files and the manifest names the stem once;
  // requiring an author to list all three would let them list two.
  const std::string content_dir =
      manifest.root + "\\" + kContentDirName + "\\";
  for (const std::string& stem : manifest.content) {
    for (const char* suffix : kContainerSuffixes) {
      const std::string path = content_dir + stem + suffix;
      if (!FileExists(path)) {
        Add(diagnostics, kMissingArtifact, manifest.mod_id,
            "declared content '" + stem + "' is missing " + stem + suffix +
                " under " + kContentDirName + "\\");
      }
    }
  }
  const std::string code_dir = manifest.root + "\\" + kCodeDirName + "\\";
  for (const std::string& assembly : manifest.code) {
    if (!FileExists(code_dir + assembly)) {
      Add(diagnostics, kMissingArtifact, manifest.mod_id,
          "declared code artifact '" + assembly + "' does not exist under " +
              kCodeDirName + "\\");
    }
  }
}

}  // namespace modplan
}  // namespace misery
