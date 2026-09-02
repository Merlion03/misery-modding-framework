// json_escape_harness.cpp -- expose misery::json::EscapeString to a differential.
//
// The oracle is Python's json.dumps(text, ensure_ascii=False), which is a
// conforming RFC 8259 writer that this project already depends on. Comparing
// against it beats asserting a table of expected outputs written by the same
// person who wrote the escaper, which is how the previous escaper passed
// review while escaping three characters out of thirty-four.
//
// The wire is hex in, hex out, one case per line. Escaping is defined over
// BYTES -- including bytes that are not valid UTF-8, which is the whole point
// of one of the cases -- and a hex wire is the only way to hand those through a
// shell, an argv and a pipe without something helpfully re-encoding them.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "../MiseryRuntime/Internal/Json.h"

namespace {

int HexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool FromHex(const std::string& hex, std::string* out) {
  if (hex.size() % 2 != 0) return false;
  out->clear();
  out->reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = HexDigit(hex[i]);
    const int lo = HexDigit(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out->push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

std::string ToHex(const std::string& raw) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (unsigned char c : raw) {
    out += kHex[(c >> 4) & 0xF];
    out += kHex[c & 0xF];
  }
  return out;
}

}  // namespace

int main() {
  char line[1 << 16];
  while (fgets(line, sizeof(line), stdin) != nullptr) {
    std::string hex(line);
    while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r')) {
      hex.pop_back();
    }
    if (hex.empty()) continue;
    std::string input;
    if (!FromHex(hex, &input)) {
      printf("!bad-hex\n");
      continue;
    }
    printf("%s\n", ToHex(misery::json::EscapeString(input)).c_str());
    fflush(stdout);
  }
  return 0;
}
