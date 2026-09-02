#include "Bindings.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "Json.h"
#include "Resolver.h"

namespace misery {
namespace bindings {

const char kSupportedEngineVersion[] = "5.4.4";

namespace {

// A profile is a few kilobytes. Anything larger is not the file we wrote.
constexpr size_t kMaxProfileBytes = 1u << 20;

void Say(std::string* error, const char* format, ...) {
  if (error == nullptr || !error->empty()) {
    return;
  }
  char buffer[512];
  va_list args;
  va_start(args, format);
  _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
  va_end(args);
  *error = buffer;
}

const json::Value* Need(const json::Value& parent, const char* key,
                        json::Kind kind, const char* where,
                        std::string* error) {
  const json::Value* member = parent.Member(key);
  if (member == nullptr) {
    Say(error, "the profile has no %s.%s", where, key);
    return nullptr;
  }
  if (!member->Is(kind)) {
    // THE PROFILE CARRIES ONLY INTEGERS, and this is where that is enforced.
    //
    // It used to be enforced one layer down: the JSON parser refused any
    // fractional number outright. The parser now reads floats, because a mod's
    // settings file has a float type (Stage 8.5) and one parser serves both
    // documents. The promise about the PROFILE did not change, so it moved to
    // the reader that made it -- and it names the reason, because "not of the
    // expected type" would hide that a number was written where an integer
    // belongs.
    if (kind == json::Kind::kInt && member->Is(json::Kind::kDouble)) {
      Say(error, "%s.%s is a fractional number; the profile carries only "
                 "integers", where, key);
      return nullptr;
    }
    Say(error, "%s.%s is not of the expected type", where, key);
    return nullptr;
  }
  return member;
}

bool NeedString(const json::Value& parent, const char* key, const char* where,
                std::string* out, std::string* error) {
  const json::Value* member = Need(parent, key, json::Kind::kString, where,
                                   error);
  if (member == nullptr) {
    return false;
  }
  *out = member->text;
  return true;
}

bool NeedU32(const json::Value& parent, const char* key, const char* where,
             uint32_t* out, std::string* error) {
  const json::Value* member = Need(parent, key, json::Kind::kInt, where, error);
  if (member == nullptr) {
    return false;
  }
  if (member->integer < 0 || member->integer > 0xFFFFFFFFll) {
    Say(error, "%s.%s does not fit in 32 bits", where, key);
    return false;
  }
  *out = static_cast<uint32_t>(member->integer);
  return true;
}

// "48895c..." -> 16 bytes. Exactly 32 hex digits; a short or odd-length string
// is a malformed profile, not something to pad.
//
// *which* is threaded through so the message names the address. Say() keeps the
// FIRST error, so a generic message here would be the one the user sees and a
// later "addresses.<name> is unreadable" would never land.
bool ParseHex16(const std::string& hex, const char* which, uint8_t* out,
                std::string* error) {
  if (hex.size() != 32) {
    Say(error, "addresses.%s: expected 32 hex characters of code bytes, got %zu",
        which, hex.size());
    return false;
  }
  for (size_t i = 0; i < 16; ++i) {
    uint32_t value = 0;
    for (size_t half = 0; half < 2; ++half) {
      char c = hex[i * 2 + half];
      uint32_t digit;
      if (c >= '0' && c <= '9') {
        digit = static_cast<uint32_t>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        digit = static_cast<uint32_t>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        digit = static_cast<uint32_t>(c - 'A' + 10);
      } else {
        Say(error, "addresses.%s: the expected code bytes contain a non-hex "
                   "character", which);
        return false;
      }
      value = (value << 4) | digit;
    }
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}

}  // namespace

bool Profile::Rva(const std::string& name, uint64_t* out) const {
  auto it = addresses.find(name);
  if (it == addresses.end()) {
    return false;
  }
  *out = it->second.rva;
  return true;
}

bool Profile::Slot(const std::string& name, uint32_t* out) const {
  auto it = vtable_slots.find(name);
  if (it == vtable_slots.end()) {
    return false;
  }
  *out = it->second;
  return true;
}

bool Profile::Field(const std::string& name, uint32_t* out) const {
  auto it = row_struct_fields.find(name);
  if (it == row_struct_fields.end()) {
    return false;
  }
  *out = it->second;
  return true;
}

bool Profile::WriteOffset(const std::string& name, uint32_t* out) const {
  auto it = write_offsets.find(name);
  if (it == write_offsets.end()) {
    return false;
  }
  *out = it->second;
  return true;
}

bool Profile::InventoryOffset(const std::string& name, uint32_t* out) const {
  auto it = inventory.find(name);
  if (it == inventory.end()) {
    return false;
  }
  *out = it->second;
  return true;
}

const FunctionGate* Profile::Gate(const std::string& qualified_name) const {
  auto it = function_gates.find(qualified_name);
  return it == function_gates.end() ? nullptr : &it->second;
}

bool Load(const char* path, const char* expected_build_key, Profile* out,
          std::string* error) {
  std::string sink;
  if (error == nullptr) {
    error = &sink;
  }
  error->clear();
  std::string text;
  if (!json::ReadFile(path, kMaxProfileBytes, &text, error)) {
    return false;
  }
  json::Value root;
  std::string parse_error;
  if (!json::Parse(text, &root, &parse_error)) {
    Say(error, "the profile is not readable JSON: %s", parse_error.c_str());
    return false;
  }
  if (!root.Is(json::Kind::kObject)) {
    Say(error, "the profile is not a JSON object");
    return false;
  }

  const json::Value* version = Need(root, "bindings_version", json::Kind::kInt,
                                    "the profile", error);
  if (version == nullptr) {
    return false;
  }
  if (version->integer != kSupportedBindingsVersion) {
    Say(error, "the profile states bindings_version %lld; this runtime "
               "understands %lld and will not read another version leniently",
        static_cast<long long>(version->integer),
        static_cast<long long>(kSupportedBindingsVersion));
    return false;
  }

  // ---- identity, checked against the digest the bootstrap measured -------
  const json::Value* build = Need(root, "build", json::Kind::kObject,
                                  "the profile", error);
  if (build == nullptr) {
    return false;
  }
  if (!NeedString(*build, "build_key", "build", &out->build_key, error) ||
      !NeedString(*build, "build_id", "build", &out->build_id, error) ||
      !NeedString(*build, "engine_version", "build", &out->engine_version,
                  error) ||
      !NeedString(*build, "build_configuration", "build",
                  &out->build_configuration, error)) {
    return false;
  }
  const json::Value* cl = Need(*build, "engine_cl", json::Kind::kInt, "build",
                               error);
  if (cl == nullptr) {
    return false;
  }
  out->engine_cl = cl->integer;
  const json::Value* image = Need(*build, "image_size_bytes", json::Kind::kInt,
                                  "build", error);
  if (image == nullptr || image->integer <= 0) {
    Say(error, "build.image_size_bytes is not a positive integer");
    return false;
  }
  out->image_size_bytes = static_cast<uint64_t>(image->integer);

  if (expected_build_key != nullptr && *expected_build_key != '\0' &&
      out->build_key != expected_build_key) {
    Say(error, "the profile describes %s, but this executable hashes to %s",
        out->build_key.c_str(), expected_build_key);
    return false;
  }
  if (out->engine_version != kSupportedEngineVersion) {
    Say(error, "the profile is for engine %s; this runtime's compiled-in type "
               "layout describes %s and the profile cannot correct it",
        out->engine_version.c_str(), kSupportedEngineVersion);
    return false;
  }

  // ---- addresses ---------------------------------------------------------
  const json::Value* addresses = Need(root, "addresses", json::Kind::kObject,
                                      "the profile", error);
  if (addresses == nullptr) {
    return false;
  }
  for (const auto& entry : addresses->object) {
    const json::Value& value = entry.second;
    if (!value.Is(json::Kind::kObject)) {
      Say(error, "addresses.%s is not an object", entry.first.c_str());
      return false;
    }
    std::string kind;
    if (!NeedString(value, "kind", entry.first.c_str(), &kind, error)) {
      return false;
    }
    const json::Value* rva = Need(value, "rva", json::Kind::kInt,
                                  entry.first.c_str(), error);
    if (rva == nullptr) {
      return false;
    }
    if (rva->integer < 0 || static_cast<uint64_t>(rva->integer) >=
                                out->image_size_bytes) {
      Say(error, "addresses.%s has an rva outside the image",
          entry.first.c_str());
      return false;
    }
    Address address;
    address.rva = static_cast<uint64_t>(rva->integer);
    if (kind == "code") {
      address.is_code = true;
      std::string hex;
      if (!NeedString(value, "bytes", entry.first.c_str(), &hex, error)) {
        return false;
      }
      if (!ParseHex16(hex, entry.first.c_str(), address.expected, error)) {
        return false;
      }
      address.has_expected = true;
    } else if (kind != "data") {
      Say(error, "addresses.%s has kind '%s', which is neither code nor data",
          entry.first.c_str(), kind.c_str());
      return false;
    }
    out->addresses[entry.first] = address;
  }

  // ---- vtable slots ------------------------------------------------------
  const json::Value* slots = Need(root, "vtable_slots", json::Kind::kObject,
                                  "the profile", error);
  if (slots == nullptr) {
    return false;
  }
  for (const auto& entry : slots->object) {
    if (!entry.second.Is(json::Kind::kObject)) {
      Say(error, "vtable_slots.%s is not an object", entry.first.c_str());
      return false;
    }
    uint32_t slot = 0;
    if (!NeedU32(entry.second, "slot", entry.first.c_str(), &slot, error)) {
      return false;
    }
    // A vtable index far past any plausible UObject vtable is a typo, and a
    // typo here reads an arbitrary pointer and calls it.
    if (slot > 512) {
      Say(error, "vtable_slots.%s is slot %u, past any plausible vtable",
          entry.first.c_str(), slot);
      return false;
    }
    out->vtable_slots[entry.first] = slot;
  }

  // ---- function gates ----------------------------------------------------
  const json::Value* functions = Need(root, "functions", json::Kind::kObject,
                                      "the profile", error);
  if (functions == nullptr) {
    return false;
  }
  if (!NeedU32(*functions, "forbid_flags", "functions",
               &out->function_forbid_flags, error)) {
    return false;
  }
  const json::Value* gates = Need(*functions, "gates", json::Kind::kObject,
                                  "functions", error);
  if (gates == nullptr) {
    return false;
  }
  for (const auto& entry : gates->object) {
    if (!entry.second.Is(json::Kind::kObject)) {
      Say(error, "functions.gates.%s is not an object", entry.first.c_str());
      return false;
    }
    FunctionGate gate;
    if (!NeedU32(entry.second, "parms_size", entry.first.c_str(),
                 &gate.parms_size, error) ||
        !NeedU32(entry.second, "require_flags", entry.first.c_str(),
                 &gate.require_flags, error)) {
      return false;
    }
    const json::Value* rvo = entry.second.Member("return_value_offset");
    if (rvo == nullptr) {
      Say(error, "functions.gates.%s states no return_value_offset (use null "
                 "to mean unconstrained)", entry.first.c_str());
      return false;
    }
    if (rvo->Is(json::Kind::kInt)) {
      gate.return_value_offset = rvo->integer;
    } else if (!rvo->Is(json::Kind::kNull)) {
      Say(error, "functions.gates.%s has a return_value_offset that is neither "
                 "an integer nor null", entry.first.c_str());
      return false;
    }
    out->function_gates[entry.first] = gate;
  }

  // ---- the row struct ----------------------------------------------------
  const json::Value* row = Need(root, "row_struct", json::Kind::kObject,
                                "the profile", error);
  if (row == nullptr) {
    return false;
  }
  if (!NeedString(*row, "name", "row_struct", &out->row_struct_name, error) ||
      !NeedU32(*row, "size", "row_struct", &out->row_struct_size, error)) {
    return false;
  }
  if (out->row_struct_size == 0) {
    Say(error, "row_struct.size is zero");
    return false;
  }
  const json::Value* fields = Need(*row, "fields", json::Kind::kObject,
                                   "row_struct", error);
  if (fields == nullptr) {
    return false;
  }
  for (const auto& entry : fields->object) {
    if (!entry.second.Is(json::Kind::kInt) || entry.second.integer < 0 ||
        static_cast<uint64_t>(entry.second.integer) >= out->row_struct_size) {
      Say(error, "row_struct.fields.%s is not an offset inside the struct",
          entry.first.c_str());
      return false;
    }
    out->row_struct_fields[entry.first] =
        static_cast<uint32_t>(entry.second.integer);
  }
  if (out->row_struct_fields.empty()) {
    Say(error, "row_struct.fields is empty");
    return false;
  }

  // The write offsets, and the inventory members beside them. Required, not
  // optional: a runtime that loaded a profile without them would come up and
  // then refuse every registration, which is a worse failure than not starting.
  const json::Value* written = Need(*row, "write_offsets", json::Kind::kObject,
                                    "row_struct", error);
  if (written == nullptr) {
    return false;
  }
  for (const auto& entry : written->object) {
    if (!entry.second.Is(json::Kind::kInt) || entry.second.integer < 0 ||
        static_cast<uint64_t>(entry.second.integer) >= out->row_struct_size) {
      Say(error, "row_struct.write_offsets.%s is not an offset inside the "
                 "struct", entry.first.c_str());
      return false;
    }
    out->write_offsets[entry.first] =
        static_cast<uint32_t>(entry.second.integer);
  }
  const json::Value* inventory = Need(root, "inventory", json::Kind::kObject,
                                      "the profile", error);
  if (inventory == nullptr) {
    return false;
  }
  for (const auto& entry : inventory->object) {
    if (!entry.second.Is(json::Kind::kInt) || entry.second.integer < 0 ||
        entry.second.integer > 0xFFFF) {
      Say(error, "inventory.%s is not a plausible member offset",
          entry.first.c_str());
      return false;
    }
    out->inventory[entry.first] =
        static_cast<uint32_t>(entry.second.integer);
  }

  // ---- object layout -----------------------------------------------------
  const json::Value* layout = Need(root, "object_layout", json::Kind::kObject,
                                   "the profile", error);
  if (layout == nullptr) {
    return false;
  }
  for (const auto& entry : layout->object) {
    uint32_t value = 0;
    if (!entry.second.Is(json::Kind::kInt) || entry.second.integer < 0 ||
        entry.second.integer > 0xFFFF) {
      Say(error, "object_layout.%s is not a plausible member offset",
          entry.first.c_str());
      return false;
    }
    value = static_cast<uint32_t>(entry.second.integer);
    out->object_layout[entry.first] = value;
  }

  // The compiled-in layout and the profile's copy must agree. They are the same
  // measurement recorded twice, and two records that disagree mean one of them
  // is describing a different build.
  const resolve::Layout compiled;
  struct Pair { const char* key; uint32_t compiled; };
  const Pair pairs[] = {
      {"datatable_rowstruct", compiled.datatable_rowstruct},
      {"datatable_parent_tables", compiled.datatable_parent_tables},
      {"ustruct_properties_size", compiled.ustruct_properties_size},
  };
  for (const Pair& pair : pairs) {
    auto it = out->object_layout.find(pair.key);
    if (it == out->object_layout.end()) {
      Say(error, "object_layout states no %s", pair.key);
      return false;
    }
    if (it->second != pair.compiled) {
      Say(error, "object_layout.%s is %u; this runtime was compiled for %u",
          pair.key, it->second, pair.compiled);
      return false;
    }
  }
  return true;
}

bool VerifyCode(const Profile& profile, uint64_t module_base,
                uint64_t module_size, std::string* error) {
  error->clear();
  if (module_size != profile.image_size_bytes) {
    Say(error, "the loaded image is %llu bytes; the profile describes one of "
               "%llu",
        static_cast<unsigned long long>(module_size),
        static_cast<unsigned long long>(profile.image_size_bytes));
    return false;
  }
  int verified = 0;
  for (const auto& entry : profile.addresses) {
    const Address& address = entry.second;
    if (!address.is_code) {
      continue;
    }
    if (!address.has_expected) {
      Say(error, "addresses.%s is code but carries no expected bytes",
          entry.first.c_str());
      return false;
    }
    uint64_t va = module_base + address.rva;
    if (address.rva + sizeof(address.expected) > module_size) {
      Say(error, "addresses.%s would read past the end of the module",
          entry.first.c_str());
      return false;
    }
    uint8_t live[sizeof(address.expected)] = {};
    if (!resolve::ReadBytes(va, live, sizeof(live))) {
      Say(error, "addresses.%s is not readable at 0x%llx",
          entry.first.c_str(), static_cast<unsigned long long>(va));
      return false;
    }
    if (memcmp(live, address.expected, sizeof(live)) != 0) {
      // Deliberately verbose: this is the message that will be in a user's log
      // the day Steam patches the game, and "bindings mismatch" would not tell
      // them what happened.
      Say(error, "addresses.%s does not hold the code the profile recorded. "
                 "This build is not the one these bindings describe; the "
                 "framework refuses rather than call an address that has moved.",
          entry.first.c_str());
      return false;
    }
    ++verified;
  }
  if (verified == 0) {
    Say(error, "the profile carries no code addresses to verify, so nothing "
               "would be checked before use");
    return false;
  }
  return true;
}

bool Resolve(const Profile& profile, const std::string& name,
             uint64_t module_base, uint64_t module_size, uint64_t* out,
             std::string* error) {
  auto it = profile.addresses.find(name);
  if (it == profile.addresses.end()) {
    Say(error, "the profile states no address called %s", name.c_str());
    return false;
  }
  if (it->second.rva >= module_size) {
    Say(error, "%s resolves outside the module", name.c_str());
    return false;
  }
  *out = module_base + it->second.rva;
  return true;
}

}  // namespace bindings
}  // namespace misery
