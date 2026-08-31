#include "Json.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

namespace misery {
namespace json {
namespace {

// Deep enough for the profile (object -> addresses -> one address -> value is
// three), with headroom. Anything deeper is malformed rather than exotic.
constexpr int kMaxDepth = 16;

class Reader {
 public:
  Reader(const std::string& text, std::string* error)
      : text_(text), error_(error) {}

  bool Top(Value* out) {
    SkipSpace();
    if (!ParseValue(out, 0)) {
      return false;
    }
    SkipSpace();
    if (at_ != text_.size()) {
      return Fail("trailing content after the top-level value");
    }
    return true;
  }

 private:
  bool Fail(const char* why) {
    if (error_ != nullptr && error_->empty()) {
      char buffer[256];
      _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%s at byte %zu", why, at_);
      *error_ = buffer;
    }
    return false;
  }

  void SkipSpace() {
    while (at_ < text_.size()) {
      char c = text_[at_];
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        ++at_;
      } else {
        break;
      }
    }
  }

  bool Literal(const char* word) {
    size_t length = strlen(word);
    if (text_.compare(at_, length, word) != 0) {
      return false;
    }
    at_ += length;
    return true;
  }

  bool ParseString(std::string* out) {
    if (at_ >= text_.size() || text_[at_] != '"') {
      return Fail("expected a string");
    }
    ++at_;
    out->clear();
    while (at_ < text_.size()) {
      char c = text_[at_++];
      if (c == '"') {
        return true;
      }
      if (c != '\\') {
        out->push_back(c);
        continue;
      }
      if (at_ >= text_.size()) {
        return Fail("a string ended inside an escape");
      }
      char esc = text_[at_++];
      switch (esc) {
        case '"': out->push_back('"'); break;
        case '\\': out->push_back('\\'); break;
        case '/': out->push_back('/'); break;
        case 'b': out->push_back('\b'); break;
        case 'f': out->push_back('\f'); break;
        case 'n': out->push_back('\n'); break;
        case 'r': out->push_back('\r'); break;
        case 't': out->push_back('\t'); break;
        case 'u': {
          // The emitter writes ASCII. A \u escape is accepted only for
          // characters that fit in one byte, so nothing here has to invent an
          // encoding it cannot round-trip.
          if (at_ + 4 > text_.size()) {
            return Fail("a \\u escape was cut short");
          }
          unsigned code = 0;
          for (int i = 0; i < 4; ++i) {
            char digit = text_[at_ + i];
            unsigned value;
            if (digit >= '0' && digit <= '9') {
              value = static_cast<unsigned>(digit - '0');
            } else if (digit >= 'a' && digit <= 'f') {
              value = static_cast<unsigned>(digit - 'a' + 10);
            } else if (digit >= 'A' && digit <= 'F') {
              value = static_cast<unsigned>(digit - 'A' + 10);
            } else {
              return Fail("a \\u escape has a non-hex digit");
            }
            code = (code << 4) | value;
          }
          at_ += 4;
          if (code > 0x7F) {
            return Fail("a \\u escape names a character this reader will not "
                        "guess an encoding for");
          }
          out->push_back(static_cast<char>(code));
          break;
        }
        default:
          return Fail("unknown escape in a string");
      }
    }
    return Fail("a string was never closed");
  }

  bool ParseInt(Value* out) {
    size_t start = at_;
    if (at_ < text_.size() && (text_[at_] == '-' || text_[at_] == '+')) {
      ++at_;
    }
    size_t digits = at_;
    while (at_ < text_.size() && text_[at_] >= '0' && text_[at_] <= '9') {
      ++at_;
    }
    if (at_ == digits) {
      return Fail("expected a number");
    }
    if (at_ < text_.size() &&
        (text_[at_] == '.' || text_[at_] == 'e' || text_[at_] == 'E')) {
      return Fail("a fractional or exponent number appeared; the profile "
                  "carries only integers");
    }
    std::string token = text_.substr(start, at_ - start);
    // Bounded by hand rather than by strtoll's errno dance: a profile with a
    // number that does not fit is malformed, not clamped.
    if (token.size() > 20) {
      return Fail("a number is too long to be a 64-bit integer");
    }
    bool negative = token[0] == '-';
    size_t index = (token[0] == '-' || token[0] == '+') ? 1 : 0;
    uint64_t magnitude = 0;
    for (; index < token.size(); ++index) {
      uint64_t digit = static_cast<uint64_t>(token[index] - '0');
      if (magnitude > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
        return Fail("a number does not fit in 64 bits");
      }
      magnitude = magnitude * 10ull + digit;
    }
    if (negative) {
      if (magnitude > 0x8000000000000000ull) {
        return Fail("a negative number does not fit in 64 bits");
      }
      out->integer = -static_cast<int64_t>(magnitude);
    } else {
      if (magnitude > 0x7FFFFFFFFFFFFFFFull) {
        return Fail("a number does not fit in a signed 64-bit integer");
      }
      out->integer = static_cast<int64_t>(magnitude);
    }
    out->kind = Kind::kInt;
    return true;
  }

  bool ParseValue(Value* out, int depth) {
    if (depth > kMaxDepth) {
      return Fail("the document nests deeper than this reader will follow");
    }
    if (at_ >= text_.size()) {
      return Fail("the document ended where a value was expected");
    }
    char c = text_[at_];
    if (c == '{') {
      ++at_;
      out->kind = Kind::kObject;
      SkipSpace();
      if (at_ < text_.size() && text_[at_] == '}') {
        ++at_;
        return true;
      }
      while (true) {
        SkipSpace();
        std::string key;
        if (!ParseString(&key)) {
          return false;
        }
        SkipSpace();
        if (at_ >= text_.size() || text_[at_] != ':') {
          return Fail("expected ':' after an object key");
        }
        ++at_;
        SkipSpace();
        Value member;
        if (!ParseValue(&member, depth + 1)) {
          return false;
        }
        if (!out->object.emplace(key, member).second) {
          return Fail("an object repeats a key");
        }
        SkipSpace();
        if (at_ < text_.size() && text_[at_] == ',') {
          ++at_;
          continue;
        }
        if (at_ < text_.size() && text_[at_] == '}') {
          ++at_;
          return true;
        }
        return Fail("expected ',' or '}' in an object");
      }
    }
    if (c == '[') {
      ++at_;
      out->kind = Kind::kArray;
      SkipSpace();
      if (at_ < text_.size() && text_[at_] == ']') {
        ++at_;
        return true;
      }
      while (true) {
        SkipSpace();
        Value element;
        if (!ParseValue(&element, depth + 1)) {
          return false;
        }
        out->array.push_back(element);
        SkipSpace();
        if (at_ < text_.size() && text_[at_] == ',') {
          ++at_;
          continue;
        }
        if (at_ < text_.size() && text_[at_] == ']') {
          ++at_;
          return true;
        }
        return Fail("expected ',' or ']' in an array");
      }
    }
    if (c == '"') {
      out->kind = Kind::kString;
      return ParseString(&out->text);
    }
    if (Literal("true")) {
      out->kind = Kind::kBool;
      out->boolean = true;
      return true;
    }
    if (Literal("false")) {
      out->kind = Kind::kBool;
      out->boolean = false;
      return true;
    }
    if (Literal("null")) {
      out->kind = Kind::kNull;
      return true;
    }
    return ParseInt(out);
  }

  const std::string& text_;
  std::string* error_;
  size_t at_ = 0;
};

}  // namespace

bool Parse(const std::string& text, Value* out, std::string* error) {
  if (error != nullptr) {
    error->clear();
  }
  Reader reader(text, error);
  return reader.Top(out);
}

bool ReadFile(const char* path, size_t max_bytes, std::string* out,
              std::string* error) {
  out->clear();
  HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    char buffer[512];
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                "could not open %s (%lu)", path, GetLastError());
    *error = buffer;
    return false;
  }
  LARGE_INTEGER size = {};
  if (!GetFileSizeEx(file, &size)) {
    CloseHandle(file);
    *error = "could not size the file";
    return false;
  }
  if (size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) > max_bytes) {
    CloseHandle(file);
    char buffer[256];
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                "the file is %lld bytes, above the %zu-byte limit",
                static_cast<long long>(size.QuadPart), max_bytes);
    *error = buffer;
    return false;
  }
  out->resize(static_cast<size_t>(size.QuadPart));
  DWORD read = 0;
  // ::ReadFile, explicitly: this function is also called ReadFile, and the
  // unqualified name would resolve to it and recurse.
  bool ok = out->empty() ||
            (::ReadFile(file, &(*out)[0], static_cast<DWORD>(out->size()),
                        &read, nullptr) != FALSE &&
             read == out->size());
  CloseHandle(file);
  if (!ok) {
    *error = "the file could not be read in full";
    out->clear();
    return false;
  }
  return true;
}

}  // namespace json
}  // namespace misery
