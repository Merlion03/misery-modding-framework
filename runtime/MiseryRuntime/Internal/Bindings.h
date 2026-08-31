// Bindings.h -- the build-specific half of "what is in this process".
//
// THE OTHER HALF OF THE SPLIT Resolver.h DESCRIBES
// ------------------------------------------------
// The resolver finds what exists only at runtime. This file carries what exists
// only because THIS executable was linked this way: RVAs, vtable slot indices,
// the ParmsSize a reflected function must have, the offset a struct field must
// sit at. Together they are a complete answer; separately, neither is safe.
//
// FAIL CLOSED IS THE WHOLE CONTRACT
// ---------------------------------
// Every load path here returns false with a reason rather than a partial
// profile. A missing key, a profile for another build, an address outside the
// module, sixteen bytes that do not match what was recorded -- each stops the
// runtime before a single binding is used. There is no "best effort" mode and
// no default value anywhere in this file: a fact the profile does not state is
// a fact the runtime does not have.
//
// WHY THE CODE BYTES MATTER MORE THAN THE ADDRESSES
// -------------------------------------------------
// An RVA is a number that was right once. A Steam patch moves functions without
// changing anything the bootstrap's digest check would miss -- except that the
// digest check DOES catch it, which is why this layer exists at all: it is the
// second lock. If the digest were ever spoofed, or a profile were hand-edited,
// the byte comparison is what still refuses. Verification is not optional and
// there is no flag to skip it.
#pragma once

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

namespace misery {
namespace bindings {

// The profile version this runtime understands. A profile stating anything else
// is refused rather than read leniently: a field that changed meaning between
// versions is exactly what a lenient reader would get wrong.
constexpr int64_t kSupportedBindingsVersion = 1;

// The engine this runtime's compiled-in type layout describes. The profile must
// agree, because Resolver.h's offsets are UE-5.4 facts and nothing in the
// profile can correct them.
extern const char kSupportedEngineVersion[];

struct Address {
  bool is_code = false;
  uint64_t rva = 0;
  uint8_t expected[16] = {};
  bool has_expected = false;
};

// What a reflected UFunction must look like before the runtime will call it.
// -1 in return_value_offset means the profile does not constrain it.
struct FunctionGate {
  uint32_t parms_size = 0;
  int64_t return_value_offset = -1;
  uint32_t require_flags = 0;
};

struct Profile {
  std::string build_key;          // "sha256:..."
  std::string build_id;
  std::string engine_version;
  int64_t engine_cl = 0;
  std::string build_configuration;
  uint64_t image_size_bytes = 0;

  std::map<std::string, Address> addresses;
  std::map<std::string, uint32_t> vtable_slots;
  std::map<std::string, FunctionGate> function_gates;
  uint32_t function_forbid_flags = 0;

  std::string row_struct_name;
  uint32_t row_struct_size = 0;
  std::map<std::string, uint32_t> row_struct_fields;

  std::map<std::string, uint32_t> object_layout;

  // Lookups that name what was missing rather than returning a zero that reads
  // like a valid answer.
  bool Rva(const std::string& name, uint64_t* out) const;
  bool Slot(const std::string& name, uint32_t* out) const;
  bool Field(const std::string& name, uint32_t* out) const;
  const FunctionGate* Gate(const std::string& qualified_name) const;
};

// Reads and validates the profile at *path*.
//
// *expected_build_key* is the digest the bootstrap already computed from the
// executable's own bytes. It is compared, not trusted: a profile that describes
// another build is refused here even though the bootstrap's cheaper substring
// check let it through.
bool Load(const char* path, const char* expected_build_key, Profile* out,
          std::string* error);

// Compares every code address against live memory. Must be called, and must
// have returned true, before any address in the profile is used.
bool VerifyCode(const Profile& profile, uint64_t module_base,
                uint64_t module_size, std::string* error);

// module_base + rva, refused when the result would leave the module. Every
// address the runtime forms goes through here so the arithmetic happens in one
// place and the bounds check cannot be forgotten at a call site.
bool Resolve(const Profile& profile, const std::string& name,
             uint64_t module_base, uint64_t module_size, uint64_t* out,
             std::string* error);

}  // namespace bindings
}  // namespace misery
