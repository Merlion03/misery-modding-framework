// Json.h -- a deliberately small JSON reader for the binding profile.
//
// WHY THERE IS A PARSER HERE AT ALL
// ---------------------------------
// The binding profile has to be one file, and it has to be the file a human
// reads and a test validates. Emitting a second, binary copy for the runtime
// would mean two artifacts that can disagree, and the disagreement would be
// discovered inside a shipping game. So the runtime reads the same JSON.
//
// WHAT THIS IS NOT
// ----------------
// It is not a general JSON library and must not grow into one. It reads what
// tools/modplatform/bindings.py emits: objects, arrays, strings, integers,
// `true`/`false`/`null`. There are no floating-point numbers in the profile and
// none are accepted; there are no escapes beyond the handful below. Anything
// else is a parse failure, which is the correct outcome -- an input this reader
// does not fully understand is not an input the runtime should act on.
//
// It is bounded on purpose. Nesting is capped, so a malformed file cannot walk
// the stack down, and every failure returns a position and a reason rather than
// a partial value.
#pragma once

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

namespace misery {
namespace json {

enum class Kind { kNull, kBool, kInt, kString, kArray, kObject };

struct Value {
  Kind kind = Kind::kNull;
  bool boolean = false;
  int64_t integer = 0;
  std::string text;
  std::vector<Value> array;
  std::map<std::string, Value> object;

  bool Is(Kind want) const { return kind == want; }

  // Member lookup that never inserts and never throws. Returns nullptr when the
  // key is absent, which callers turn into a named failure.
  const Value* Member(const std::string& key) const {
    if (kind != Kind::kObject) {
      return nullptr;
    }
    auto it = object.find(key);
    return it == object.end() ? nullptr : &it->second;
  }
};

// Parses *text* entirely. Trailing content after the top-level value is an
// error: a profile with something appended is not a profile we understand.
bool Parse(const std::string& text, Value* out, std::string* error);

// Reads a file into *out*. Refuses anything above *max_bytes*, because the
// runtime should not be handed an arbitrarily large file to hold in a game
// process.
bool ReadFile(const char* path, size_t max_bytes, std::string* out,
              std::string* error);

// Escapes *text* for placing INSIDE a JSON string. The surrounding quotes are
// the caller's; this returns the body.
//
// WHY A WRITER LIVES IN A FILE THAT ANNOUNCES ITSELF AS A READER
// --------------------------------------------------------------
// The warning at the top of this header is about the PARSER's input surface and
// it stands. This exists for the opposite reason. The runtime already had an
// escaper, hand-rolled at its call site in BridgeTables.cpp, and it was wrong:
// it escaped only '"', '\' and '\n' and passed every other control byte through
// raw. RFC 8259 requires every U+0000..U+001F to be escaped, so a tab or a
// carriage return anywhere in a mod id, a log message or an error detail
// produced a document no conforming parser accepts -- and the diagnostics
// snapshot has been rendering caller-supplied text through it.
//
// One correct implementation in the JSON module beats a second hand-rolled one
// per call site, which is precisely the arrangement that produced the defect.
//
// WHAT IT GUARANTEES
// ------------------
// The result cannot make a document malformed. The two mandatory escapes are
// applied, the five shorthands RFC 8259 names are used where they apply and
// \u00XX otherwise, and DEL (0x7F) is left alone because it is legal unescaped.
// Input that is not valid UTF-8 is not passed through either: an ill-formed
// byte becomes U+FFFD. A string returned from here is about to be concatenated
// into a document somebody else has to parse, and "malformed in, malformed out"
// is not an acceptable contract for that.
//
// Matches Python's json.dumps(text, ensure_ascii=False) for every input that is
// valid UTF-8; tests/test_json_escape.py holds it to that differentially.
std::string EscapeString(const std::string& text);

}  // namespace json
}  // namespace misery
