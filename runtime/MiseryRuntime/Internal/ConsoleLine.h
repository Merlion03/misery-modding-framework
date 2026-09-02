// ConsoleLine.h -- the console's text state. Pure logic, no window, no bridge.
//
// Everything a developer console does that is not drawing or dispatching:
// a line being edited, a cursor in it, a history of what was submitted, a
// scrollback of what came out, and prefix completion over the command names the
// registry already has. None of it knows what a window is, so all of it is
// tested off the game.
//
// UTF-8 AND WHY THE CURSOR IS IN BYTES BUT NEVER LANDS MID-CHARACTER
// -------------------------------------------------------------------
// The research measured `WM_CHAR` arriving as UTF-16 code units, including
// Cyrillic -- the toggle key itself types 'e with diaeresis' on a Russian
// layout. The buffer is UTF-8 so that everything downstream (the JSON escaper,
// the bridge's MbStr, the log) sees the encoding it already speaks. The cursor
// is a byte index, and every movement steps over a whole character: a cursor
// that could land between the two bytes of a Cyrillic letter would let Backspace
// produce invalid UTF-8, which the escaper would then have to replace with
// U+FFFD -- corruption laundered into validity.
#ifndef MISERY_CONSOLELINE_H
#define MISERY_CONSOLELINE_H

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <string>
#include <vector>

namespace misery {
namespace console_ui {

constexpr size_t kMaxLineBytes = 1024;
constexpr size_t kMaxHistory = 100;
constexpr size_t kMaxScrollback = 500;

// A line of output, with the severity the renderer colours by. Deliberately
// coarse: a console that needs eight colours to be read is not being read.
enum class Severity : int32_t { kOutput = 0, kEcho = 1, kError = 2, kNotice = 3 };

struct OutputLine {
  std::string text;
  Severity severity = Severity::kOutput;
};

// Appends the UTF-8 encoding of one code point. Surrogate halves are held until
// their pair arrives, because WM_CHAR delivers UTF-16 and an emoji or any
// character above the BMP arrives as two messages.
class Utf8Sink {
 public:
  // Returns true when a complete code point was appended.
  bool Add(uint32_t unit, std::string* out) {
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      high_ = unit;
      return false;
    }
    uint32_t code = unit;
    if (unit >= 0xDC00 && unit <= 0xDFFF) {
      if (high_ == 0) return false;          // an orphan low half: dropped
      code = 0x10000 + ((high_ - 0xD800) << 10) + (unit - 0xDC00);
      high_ = 0;
    } else {
      high_ = 0;
    }
    Encode(code, out);
    return true;
  }

  void Reset() { high_ = 0; }

 private:
  static void Encode(uint32_t code, std::string* out) {
    if (code < 0x80) {
      out->push_back(static_cast<char>(code));
    } else if (code < 0x800) {
      out->push_back(static_cast<char>(0xC0 | (code >> 6)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else if (code < 0x10000) {
      out->push_back(static_cast<char>(0xE0 | (code >> 12)));
      out->push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else {
      out->push_back(static_cast<char>(0xF0 | (code >> 18)));
      out->push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    }
  }

  uint32_t high_ = 0;
};

inline bool IsContinuationByte(char byte) {
  return (static_cast<unsigned char>(byte) & 0xC0) == 0x80;
}

class ConsoleLine {
 public:
  const std::string& Text() const { return text_; }
  size_t Cursor() const { return cursor_; }
  const std::vector<std::string>& History() const { return history_; }
  const std::vector<OutputLine>& Scrollback() const { return scrollback_; }
  size_t ScrollOffset() const { return scroll_offset_; }

  // ---- editing --------------------------------------------------------
  void InsertCharacter(uint32_t unit) {
    std::string encoded;
    if (!utf8_.Add(unit, &encoded)) return;
    if (encoded.empty()) return;
    // A control character has no business in a command line. Backspace, Tab,
    // Enter and Escape all arrive as characters too, and the router already
    // acted on their key-downs; inserting them here would double them.
    if (encoded.size() == 1 &&
        static_cast<unsigned char>(encoded[0]) < 0x20) {
      return;
    }
    if (text_.size() + encoded.size() > kMaxLineBytes) return;
    text_.insert(cursor_, encoded);
    cursor_ += encoded.size();
    history_cursor_ = history_.size();
  }

  void Backspace() {
    if (cursor_ == 0) return;
    size_t begin = cursor_ - 1;
    while (begin > 0 && IsContinuationByte(text_[begin])) --begin;
    text_.erase(begin, cursor_ - begin);
    cursor_ = begin;
    history_cursor_ = history_.size();
  }

  void DeleteForward() {
    if (cursor_ >= text_.size()) return;
    size_t end = cursor_ + 1;
    while (end < text_.size() && IsContinuationByte(text_[end])) ++end;
    text_.erase(cursor_, end - cursor_);
    history_cursor_ = history_.size();
  }

  void CursorLeft() {
    if (cursor_ == 0) return;
    --cursor_;
    while (cursor_ > 0 && IsContinuationByte(text_[cursor_])) --cursor_;
  }

  void CursorRight() {
    if (cursor_ >= text_.size()) return;
    ++cursor_;
    while (cursor_ < text_.size() && IsContinuationByte(text_[cursor_])) ++cursor_;
  }

  void CursorHome() { cursor_ = 0; }
  void CursorEnd() { cursor_ = text_.size(); }

  void Clear() {
    text_.clear();
    cursor_ = 0;
    utf8_.Reset();
    history_cursor_ = history_.size();
  }

  // ---- history --------------------------------------------------------
  // Submitting records the line and hands it back for dispatch. A blank line is
  // not history and is not dispatched.
  bool Submit(std::string* out_line) {
    const std::string trimmed = Trim(text_);
    Clear();
    if (trimmed.empty()) return false;
    if (history_.empty() || history_.back() != trimmed) {
      history_.push_back(trimmed);
      if (history_.size() > kMaxHistory) {
        history_.erase(history_.begin());
      }
    }
    history_cursor_ = history_.size();
    *out_line = trimmed;
    return true;
  }

  void HistoryPrevious() {
    if (history_.empty() || history_cursor_ == 0) return;
    --history_cursor_;
    Set(history_[history_cursor_]);
  }

  void HistoryNext() {
    if (history_.empty()) return;
    if (history_cursor_ + 1 >= history_.size()) {
      // Past the newest entry is the empty line the user was typing before they
      // started walking back. Not the newest entry again.
      history_cursor_ = history_.size();
      Set("");
      return;
    }
    ++history_cursor_;
    Set(history_[history_cursor_]);
  }

  // ---- output ---------------------------------------------------------
  void Write(const std::string& text, Severity severity = Severity::kOutput) {
    size_t begin = 0;
    while (begin <= text.size()) {
      const size_t newline = text.find('\n', begin);
      const size_t end = (newline == std::string::npos) ? text.size() : newline;
      std::string piece = text.substr(begin, end - begin);
      if (!piece.empty() && piece.back() == '\r') piece.pop_back();
      scrollback_.push_back(OutputLine{piece, severity});
      if (newline == std::string::npos) break;
      begin = newline + 1;
    }
    while (scrollback_.size() > kMaxScrollback) {
      scrollback_.erase(scrollback_.begin());
    }
    scroll_offset_ = 0;   // any new output pins the view to the bottom
  }

  // How many lines the view is scrolled back from the newest. Bounded by what
  // there is to scroll: a console that lets the view run off the top of its own
  // buffer shows blank space and looks broken.
  void ScrollUp(size_t lines, size_t visible_rows) {
    const size_t furthest = scrollback_.size() > visible_rows
                                ? scrollback_.size() - visible_rows
                                : 0;
    // Parenthesised: windows.h defines min/max as macros, and this header is
    // included after it in ConsoleUi.cpp.
    scroll_offset_ = (std::min)(scroll_offset_ + lines, furthest);
  }

  void ScrollDown(size_t lines) {
    scroll_offset_ = scroll_offset_ > lines ? scroll_offset_ - lines : 0;
  }

  // The window of output to draw, oldest first.
  std::vector<OutputLine> Visible(size_t rows) const {
    if (scrollback_.empty() || rows == 0) return {};
    const size_t end = scrollback_.size() -
                      (std::min)(scroll_offset_, scrollback_.size());
    const size_t begin = end > rows ? end - rows : 0;
    return std::vector<OutputLine>(scrollback_.begin() + begin,
                                   scrollback_.begin() + end);
  }

  // ---- completion -----------------------------------------------------
  // Completes the FIRST word only. A console that tried to complete arguments
  // would need to know what each command's arguments mean, and the registry
  // does not carry that -- so it is not offered rather than half-offered.
  struct Completion {
    bool applied = false;
    std::vector<std::string> candidates;
  };

  Completion Complete(const std::vector<std::string>& names) {
    Completion result;
    if (text_.find(' ') != std::string::npos) return result;
    const std::string prefix = text_;
    for (const std::string& name : names) {
      if (name.size() >= prefix.size() &&
          name.compare(0, prefix.size(), prefix) == 0) {
        result.candidates.push_back(name);
      }
    }
    if (result.candidates.empty()) return result;
    // The longest common prefix of the candidates, which is the only completion
    // that cannot be wrong. With one candidate that is the whole name.
    std::string common = result.candidates.front();
    for (const std::string& candidate : result.candidates) {
      size_t index = 0;
      while (index < common.size() && index < candidate.size() &&
             common[index] == candidate[index]) {
        ++index;
      }
      common.resize(index);
    }
    if (common.size() > prefix.size()) {
      Set(common);
      result.applied = true;
    }
    if (result.candidates.size() == 1 && text_.size() + 1 <= kMaxLineBytes) {
      Set(text_ + " ");
      result.applied = true;
    }
    return result;
  }

 private:
  void Set(const std::string& value) {
    text_ = value;
    cursor_ = text_.size();
    utf8_.Reset();
  }

  static std::string Trim(const std::string& value) {
    const size_t begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return std::string();
    const size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
  }

  std::string text_;
  size_t cursor_ = 0;
  Utf8Sink utf8_;
  std::vector<std::string> history_;
  size_t history_cursor_ = 0;
  std::vector<OutputLine> scrollback_;
  size_t scroll_offset_ = 0;
};

}  // namespace console_ui
}  // namespace misery

#endif  // MISERY_CONSOLELINE_H
