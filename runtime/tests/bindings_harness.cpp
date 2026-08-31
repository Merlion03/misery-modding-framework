// bindings_harness.cpp -- the profile reader, exercised off the game.
//
// WHY OFF THE GAME
// ----------------
// Almost everything the reader must get right is a property of the FILE, not of
// MISERY: a profile for another build, a version this runtime does not
// understand, an address outside the image, sixteen bytes that are not hex, a
// layout constant that disagrees with the one compiled in. Each of those must
// produce a refusal with a reason, and none of them needs a game running to
// prove it.
//
// So the fail-closed suite runs here, in a second, against files a test writes.
// What is left for the live run is the one thing only the live process can
// answer: whether the recorded code bytes are the bytes actually mapped.
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include <string>

#include "../MiseryRuntime/Internal/Bindings.h"

namespace {

// This process's own mapped base and size, from its own PE headers -- the same
// read RuntimeBootstrap does on the game.
//
// WHY THE HARNESS VERIFIES AGAINST ITSELF
// ---------------------------------------
// VerifyCode is the guard the whole bindings layer rests on: an RVA is only a
// promise, and the sixteen recorded bytes are what make it checkable. Testing
// it used to require launching MISERY, which left the one function that must
// never be wrong as the one function with no offline test.
//
// It does not actually need MISERY. It needs A mapped PE and a profile that
// describes it. So the test writes a profile describing THIS executable, with
// bytes read from this executable's own file, and the comparison path runs in
// full -- including the case where a single recorded byte is wrong.
bool ThisImage(uint64_t* base, uint64_t* size) {
  HMODULE module = GetModuleHandleA(nullptr);
  if (module == nullptr) {
    return false;
  }
  const unsigned char* bytes = reinterpret_cast<const unsigned char*>(module);
  const IMAGE_DOS_HEADER* dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }
  const IMAGE_NT_HEADERS64* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }
  *base = reinterpret_cast<uint64_t>(module);
  *size = nt->OptionalHeader.SizeOfImage;
  return true;
}

void PrintEscaped(const char* text) {
  for (const char* p = text; *p != '\0'; ++p) {
    if (*p == '"' || *p == '\\') {
      printf("\\%c", *p);
    } else if (*p == '\n') {
      printf("\\n");
    } else if (static_cast<unsigned char>(*p) < 0x20) {
      printf("\\u%04x", static_cast<unsigned>(*p));
    } else {
      putchar(*p);
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("usage: bindings_harness <bindings.json> [expected-build-key|-] "
           "[--verify-self]\n");
    return 2;
  }
  const char* path = argv[1];
  const char* key = (argc >= 3 && strcmp(argv[2], "-") != 0) ? argv[2] : "";
  bool verify_self = false;
  for (int i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "--verify-self") == 0) {
      verify_self = true;
    }
  }

  misery::bindings::Profile profile;
  std::string error;
  if (!misery::bindings::Load(path, key, &profile, &error)) {
    printf("{\"ok\":false,\"stage\":\"load\",\"error\":\"");
    PrintEscaped(error.c_str());
    printf("\"}\n");
    return 1;
  }

  if (verify_self) {
    // The profile describes THIS executable, so the real comparison can run.
    uint64_t base = 0, size = 0;
    if (!ThisImage(&base, &size)) {
      printf("{\"ok\":false,\"stage\":\"self\",\"error\":\"could not read this "
             "image's own PE headers\"}\n");
      return 1;
    }
    std::string verify_error;
    bool verified =
        misery::bindings::VerifyCode(profile, base, size, &verify_error);
    printf("{\"ok\":%s,\"stage\":\"verify\",\"image_size_bytes\":%llu,"
           "\"error\":\"",
           verified ? "true" : "false",
           static_cast<unsigned long long>(size));
    PrintEscaped(verify_error.c_str());
    printf("\"}\n");
    return verified ? 0 : 1;
  }

  // A profile that loaded but describes nothing is not a success. The harness
  // reports the counts so a test can assert the reader actually populated what
  // it claims to have read, rather than accepting an empty document.
  printf("{\"ok\":true,\"build_id\":\"");
  PrintEscaped(profile.build_id.c_str());
  printf("\",\"build_key\":\"");
  PrintEscaped(profile.build_key.c_str());
  printf("\",\"engine_version\":\"");
  PrintEscaped(profile.engine_version.c_str());
  printf("\",\"engine_cl\":%lld", static_cast<long long>(profile.engine_cl));
  printf(",\"image_size_bytes\":%llu",
         static_cast<unsigned long long>(profile.image_size_bytes));
  printf(",\"addresses\":%d,\"code_addresses\":%d,\"slots\":%d,\"gates\":%d",
         static_cast<int>(profile.addresses.size()),
         [&profile] {
           int n = 0;
           for (const auto& entry : profile.addresses) {
             n += entry.second.is_code ? 1 : 0;
           }
           return n;
         }(),
         static_cast<int>(profile.vtable_slots.size()),
         static_cast<int>(profile.function_gates.size()));
  printf(",\"forbid_flags\":%u", profile.function_forbid_flags);
  printf(",\"row_struct\":\"");
  PrintEscaped(profile.row_struct_name.c_str());
  printf("\",\"row_struct_size\":%u,\"row_fields\":%d",
         profile.row_struct_size,
         static_cast<int>(profile.row_struct_fields.size()));

  // Spot-read through the accessors, so the test checks the lookup path rather
  // than only the parse.
  uint64_t rva = 0;
  uint32_t slot = 0, field = 0;
  printf(",\"lookup\":{\"guobjectarray_rva\":%llu,\"add_row_slot\":%u,"
         "\"shortname_offset\":%u,\"absent_is_refused\":%s}",
         profile.Rva("guobjectarray", &rva) ? rva : 0ull,
         profile.Slot("datatable_add_row", &slot) ? slot : 0u,
         profile.Field("ShortName", &field) ? field : 0u,
         profile.Rva("no_such_address", &rva) ? "false" : "true");

  const misery::bindings::FunctionGate* gate =
      profile.Gate("KismetTextLibrary::Conv_StringToText");
  printf(",\"gate\":{\"present\":%s,\"parms_size\":%u,\"rvo\":%lld}",
         gate != nullptr ? "true" : "false",
         gate != nullptr ? gate->parms_size : 0u,
         gate != nullptr ? static_cast<long long>(gate->return_value_offset)
                         : -1LL);
  printf("}\n");
  return 0;
}
