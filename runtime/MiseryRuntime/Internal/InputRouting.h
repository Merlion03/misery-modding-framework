// InputRouting.h -- who gets a key, and who is denied it. Pure logic, no Win32.
//
// The Stage 8 input research (research/evidence/STAGE8-INPUT/findings.md) proved
// that keyboard input reaches MISERY through its own window procedure and that
// suppressing a message there keeps it from the game entirely. This file is the
// decision half of that: given a message, does it go on to the game, and what
// should the framework do with it. The Win32 half is InputSource.cpp, and it
// contains no policy at all, which is what makes every rule below testable
// without a game.
//
// THE KEY-UP RULE, WHICH IS NOT AN OPTIMISATION
// ---------------------------------------------
// Suppressing a key-up whose key-down the engine already saw leaves that key
// held down inside the game forever -- the character keeps walking after the
// console opens. So the router remembers which keys it swallowed the DOWN of,
// and forwards the up of every key it did not. This was written into the
// pre-registration before the first measurement, so that it could not be
// discovered as a bug and then described as a design.
//
// THE TOGGLE'S OWN CHARACTER
// --------------------------
// TranslateMessage turns the toggle key into a WM_CHAR before the console is
// told anything, so the key that opens the console also types itself into it --
// a backtick, or 'e' with diaeresis on a Russian layout. The router swallows
// exactly one character after a toggle, which is why kSwallowedChar exists as a
// distinct outcome rather than being folded into "suppressed".
#ifndef MISERY_INPUTROUTING_H
#define MISERY_INPUTROUTING_H

#include <stdint.h>

namespace misery {
namespace input {

// The Windows message ids this cares about, named here so the logic compiles
// and is testable without windows.h.
enum Message : uint32_t {
  kKeyDown = 0x0100,
  kKeyUp = 0x0101,
  kChar = 0x0102,
  kDeadChar = 0x0103,
  kSysKeyDown = 0x0104,
  kSysKeyUp = 0x0105,
  kSysChar = 0x0106,
  kSysDeadChar = 0x0107,
  kUniChar = 0x0109,
};

enum VirtualKey : uint32_t {
  kVkBack = 0x08, kVkTab = 0x09, kVkReturn = 0x0D, kVkShift = 0x10,
  kVkControl = 0x11, kVkEscape = 0x1B, kVkPageUp = 0x21, kVkPageDown = 0x22,
  kVkEnd = 0x23, kVkHome = 0x24, kVkLeft = 0x25, kVkUp = 0x26, kVkRight = 0x27,
  kVkDown = 0x28, kVkDelete = 0x2E, kVkOem3 = 0xC0,
};

// What the framework should do about a message. Distinct from whether the game
// sees it: a message can be forwarded and still mean nothing to us.
enum class Action : int32_t {
  kNothing = 0,
  kOpen,            // the toggle was pressed while closed
  kClose,           // the toggle was pressed while open
  kText,            // `character` is a character to insert
  kSubmit,          // Enter
  kBackspace,
  kDeleteForward,
  kCursorLeft,
  kCursorRight,
  kCursorHome,
  kCursorEnd,
  kHistoryPrevious,
  kHistoryNext,
  kScrollUp,
  kScrollDown,
  kComplete,        // Tab
  kSwallowedChar,   // the toggle key's own character; deliberately dropped
};

struct Decision {
  Action action = Action::kNothing;
  uint32_t character = 0;   // meaningful only for Action::kText
  bool forward_to_game = true;
};

// True for the messages a keyboard produces. Everything else is none of our
// business and is forwarded untouched.
inline bool IsKeyboardMessage(uint32_t message) {
  return message == kKeyDown || message == kKeyUp || message == kSysKeyDown ||
         message == kSysKeyUp || message == kChar || message == kSysChar ||
         message == kDeadChar || message == kSysDeadChar || message == kUniChar;
}

class KeyRouter {
 public:
  // The toggle. Configurable because a layout that cannot reach VK_OEM_3 is a
  // real keyboard, not a hypothetical one -- and because the research measured
  // that one virtual key covers both `~` and `Ё`, so a default that works for
  // both is possible without pretending it works for all.
  void SetToggleKey(uint32_t virtual_key) { toggle_ = virtual_key; }
  uint32_t ToggleKey() const { return toggle_; }

  bool IsOpen() const { return open_; }

  // Closing from outside the key path -- the window lost focus, the module is
  // shutting down. Every key still marked stays marked, so the ups the engine
  // never saw a down for are still swallowed.
  void ForceClose() { open_ = false; }

  Decision Route(uint32_t message, uint32_t wparam) {
    Decision decision;
    if (!IsKeyboardMessage(message)) {
      return decision;
    }

    const bool is_down = (message == kKeyDown || message == kSysKeyDown);
    const bool is_up = (message == kKeyUp || message == kSysKeyUp);
    const bool is_char = (message == kChar || message == kSysChar ||
                          message == kDeadChar || message == kSysDeadChar ||
                          message == kUniChar);

    if (is_down && wparam == toggle_) {
      open_ = !open_;
      Mark(wparam);
      swallow_char_ = true;
      decision.action = open_ ? Action::kOpen : Action::kClose;
      decision.forward_to_game = false;
      return decision;
    }

    if (is_up) {
      // The rule. Ours to swallow only if we swallowed its down.
      if (TakeMark(wparam)) {
        decision.forward_to_game = false;
      }
      return decision;
    }

    if (!open_) {
      // Closed: nothing is read, nothing is recorded, nothing is kept. The only
      // question asked of a message is whether it is the toggle, and that was
      // answered above.
      return decision;
    }

    if (is_char) {
      decision.forward_to_game = false;
      if (swallow_char_) {
        swallow_char_ = false;
        decision.action = Action::kSwallowedChar;
        return decision;
      }
      decision.action = Action::kText;
      decision.character = wparam;
      return decision;
    }

    // A key-down while open. Everything is ours; the game sees none of it.
    Mark(wparam);
    decision.forward_to_game = false;
    switch (wparam) {
      case kVkReturn:   decision.action = Action::kSubmit; break;
      case kVkBack:     decision.action = Action::kBackspace; break;
      case kVkDelete:   decision.action = Action::kDeleteForward; break;
      case kVkLeft:     decision.action = Action::kCursorLeft; break;
      case kVkRight:    decision.action = Action::kCursorRight; break;
      case kVkHome:     decision.action = Action::kCursorHome; break;
      case kVkEnd:      decision.action = Action::kCursorEnd; break;
      case kVkUp:       decision.action = Action::kHistoryPrevious; break;
      case kVkDown:     decision.action = Action::kHistoryNext; break;
      case kVkPageUp:   decision.action = Action::kScrollUp; break;
      case kVkPageDown: decision.action = Action::kScrollDown; break;
      case kVkTab:      decision.action = Action::kComplete; break;
      case kVkEscape:
        open_ = false;
        decision.action = Action::kClose;
        break;
      default:
        // A printable key: the character arrives separately as WM_CHAR, with
        // the layout and the shift state already applied. Nothing is guessed
        // from the virtual key here -- that guess is precisely what the Slate
        // path would have forced, and what the research rejected it for.
        decision.action = Action::kNothing;
        break;
    }
    // Backspace, Tab, Enter and Escape each also produce a WM_CHAR (0x08, 0x09,
    // 0x0D, 0x1B). Acting on the key-down AND inserting the character would
    // double every one of them, so the character is swallowed.
    if (wparam == kVkBack || wparam == kVkTab || wparam == kVkReturn ||
        wparam == kVkEscape) {
      swallow_char_ = true;
    }
    return decision;
  }

  // Diagnostics only. How many keys are still held whose down the game did not
  // see -- which should be zero shortly after the console closes.
  int32_t HeldCount() const {
    int32_t count = 0;
    for (int i = 0; i < 256; ++i) {
      if (marked_[i]) ++count;
    }
    return count;
  }

 private:
  void Mark(uint32_t vkey) {
    if (vkey < 256) marked_[vkey] = true;
  }

  bool TakeMark(uint32_t vkey) {
    if (vkey >= 256 || !marked_[vkey]) return false;
    marked_[vkey] = false;
    return true;
  }

  uint32_t toggle_ = kVkOem3;
  bool open_ = false;
  bool swallow_char_ = false;
  bool marked_[256] = {};
};

}  // namespace input
}  // namespace misery

#endif  // MISERY_INPUTROUTING_H
