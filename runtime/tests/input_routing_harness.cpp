// input_routing_harness.cpp -- the key router's rules, off the game.
//
// The rules being checked are the ones the Stage 8 input pre-registration fixed
// BEFORE anything was measured, plus the two the research then forced. Each is
// stated as a named case rather than as a table of numbers, because the reason a
// rule exists is the part that has to survive.
//
// TWO MODES
//   (default)  the named cases, human-readable, with a JSON verdict
//   --trace    feed a scripted message sequence and print one JSON line per
//              message, for the differential on the Python side
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "../MiseryRuntime/Internal/InputRouting.h"

using misery::input::Action;
using misery::input::Decision;
using misery::input::KeyRouter;
namespace mi = misery::input;

namespace {

int g_failures = 0;

void Check(const char* what, bool ok, const std::string& detail = "") {
  if (!ok) ++g_failures;
  printf("  [%s] %s%s\n", ok ? "PASS" : "FAIL", what,
         (ok || detail.empty()) ? "" : ("  -- " + detail).c_str());
}

const char* ActionName(Action action) {
  switch (action) {
    case Action::kNothing: return "nothing";
    case Action::kOpen: return "open";
    case Action::kClose: return "close";
    case Action::kText: return "text";
    case Action::kSubmit: return "submit";
    case Action::kBackspace: return "backspace";
    case Action::kDeleteForward: return "delete";
    case Action::kCursorLeft: return "left";
    case Action::kCursorRight: return "right";
    case Action::kCursorHome: return "home";
    case Action::kCursorEnd: return "end";
    case Action::kHistoryPrevious: return "history_previous";
    case Action::kHistoryNext: return "history_next";
    case Action::kScrollUp: return "scroll_up";
    case Action::kScrollDown: return "scroll_down";
    case Action::kComplete: return "complete";
    case Action::kSwallowedChar: return "swallowed_char";
  }
  return "?";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && strcmp(argv[1], "--trace") == 0) {
    // A scripted sequence, as (message, wparam) pairs on stdin. One JSON line
    // out per message: what we decided and whether the game sees it.
    KeyRouter router;
    unsigned message = 0, wparam = 0;
    printf("[\n");
    bool first = true;
    while (scanf("%u %u", &message, &wparam) == 2) {
      const Decision decision = router.Route(message, wparam);
      printf("%s{\"message\":%u,\"wparam\":%u,\"action\":\"%s\","
             "\"character\":%u,\"forward\":%s,\"open\":%s,\"held\":%d}",
             first ? "" : ",\n", message, wparam, ActionName(decision.action),
             decision.character, decision.forward_to_game ? "true" : "false",
             router.IsOpen() ? "true" : "false", router.HeldCount());
      first = false;
    }
    printf("\n]\n");
    return 0;
  }

  printf("the key router:\n");

  // ---- closed: nothing but the toggle is ours -------------------------
  {
    KeyRouter router;
    Check("a closed console forwards an ordinary key",
          router.Route(mi::kKeyDown, 'W').forward_to_game);
    Check("  ...and its character",
          router.Route(mi::kChar, 'w').forward_to_game);
    Check("  ...and reads NOTHING from it",
          router.Route(mi::kChar, 'w').action == Action::kNothing);
    Check("a closed console forwards the key-up too",
          router.Route(mi::kKeyUp, 'W').forward_to_game);
  }

  // ---- the toggle -----------------------------------------------------
  {
    KeyRouter router;
    const Decision down = router.Route(mi::kKeyDown, mi::kVkOem3);
    Check("the toggle opens the console", down.action == Action::kOpen);
    Check("  ...and the game never sees the key", !down.forward_to_game);
    Check("  ...and the console is open", router.IsOpen());

    const Decision character = router.Route(mi::kChar, 0x0451);  // Cyrillic yo
    Check("the toggle's OWN character is swallowed, not typed",
          character.action == Action::kSwallowedChar);
    Check("  ...and does not reach the game either",
          !character.forward_to_game);

    const Decision up = router.Route(mi::kKeyUp, mi::kVkOem3);
    Check("the toggle's key-up is swallowed, because its down was",
          !up.forward_to_game);

    const Decision again = router.Route(mi::kKeyDown, mi::kVkOem3);
    Check("the same key closes it again", again.action == Action::kClose);
    Check("  ...and the console is closed", !router.IsOpen());
  }

  // ---- THE KEY-UP RULE ------------------------------------------------
  // Registered before the first measurement: an up whose down the engine saw
  // must be forwarded, or that key stays held down inside the game.
  {
    KeyRouter router;
    Check("a key pressed BEFORE the console opened is forwarded",
          router.Route(mi::kKeyDown, 'W').forward_to_game);
    router.Route(mi::kKeyDown, mi::kVkOem3);            // open, mid-hold
    router.Route(mi::kChar, 0x60);
    router.Route(mi::kKeyUp, mi::kVkOem3);             // the toggle is released
    const Decision up = router.Route(mi::kKeyUp, 'W');
    Check("  ...and ITS key-up is still forwarded once the console is open",
          up.forward_to_game,
          "otherwise the character keeps walking with the console open");

    const Decision inside = router.Route(mi::kKeyDown, 'W');
    Check("a key pressed WHILE open is not forwarded", !inside.forward_to_game);
    const Decision inside_up = router.Route(mi::kKeyUp, 'W');
    Check("  ...and neither is its up", !inside_up.forward_to_game);
    Check("nothing is left held", router.HeldCount() == 0);
  }

  // ---- releasing capture with keys still down -------------------------
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);
    router.Route(mi::kChar, 0x60);
    router.Route(mi::kKeyUp, mi::kVkOem3);
    router.Route(mi::kKeyDown, 'A');                    // swallowed
    router.Route(mi::kKeyDown, mi::kVkOem3);            // close, A still down
    router.Route(mi::kChar, 0x60);
    router.Route(mi::kKeyUp, mi::kVkOem3);
    Check("closing does not release a key the game never saw go down",
          router.HeldCount() == 1);
    Check("  ...and that key's up is still swallowed after closing",
          !router.Route(mi::kKeyUp, 'A').forward_to_game);
    Check("  ...leaving nothing held", router.HeldCount() == 0);
  }

  // ---- editing keys ---------------------------------------------------
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);
    router.Route(mi::kChar, 0x60);
    struct Case { uint32_t vkey; Action action; const char* what; };
    const Case cases[] = {
        {mi::kVkReturn, Action::kSubmit, "Enter submits"},
        {mi::kVkBack, Action::kBackspace, "Backspace deletes back"},
        {mi::kVkDelete, Action::kDeleteForward, "Delete deletes forward"},
        {mi::kVkLeft, Action::kCursorLeft, "Left moves the cursor"},
        {mi::kVkRight, Action::kCursorRight, "Right moves the cursor"},
        {mi::kVkHome, Action::kCursorHome, "Home"},
        {mi::kVkEnd, Action::kCursorEnd, "End"},
        {mi::kVkUp, Action::kHistoryPrevious, "Up walks history back"},
        {mi::kVkDown, Action::kHistoryNext, "Down walks history forward"},
        {mi::kVkPageUp, Action::kScrollUp, "PageUp scrolls"},
        {mi::kVkPageDown, Action::kScrollDown, "PageDown scrolls"},
        {mi::kVkTab, Action::kComplete, "Tab completes"},
    };
    for (const Case& item : cases) {
      const Decision decision = router.Route(mi::kKeyDown, item.vkey);
      Check(item.what, decision.action == item.action, ActionName(decision.action));
      Check("  ...and the game does not see it", !decision.forward_to_game);
      router.Route(mi::kKeyUp, item.vkey);
    }
  }

  // ---- the characters those keys also produce -------------------------
  // Backspace, Tab, Enter and Escape each generate a WM_CHAR of their own. The
  // key-down already acted; inserting the character too would double each one.
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);
    router.Route(mi::kChar, 0x60);
    struct Pair { uint32_t vkey; uint32_t character; const char* what; };
    const Pair pairs[] = {
        {mi::kVkBack, 0x08, "Backspace's own character is swallowed"},
        {mi::kVkTab, 0x09, "Tab's own character is swallowed"},
        {mi::kVkReturn, 0x0D, "Enter's own character is swallowed"},
    };
    for (const Pair& pair : pairs) {
      router.Route(mi::kKeyDown, pair.vkey);
      const Decision character = router.Route(mi::kChar, pair.character);
      Check(pair.what, character.action == Action::kSwallowedChar,
            ActionName(character.action));
      router.Route(mi::kKeyUp, pair.vkey);
    }
  }

  // ---- text, in the encoding the research measured ---------------------
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);
    router.Route(mi::kChar, 0x0451);
    const Decision lower = router.Route(mi::kChar, 0x0444);   // Cyrillic ef
    Check("a Cyrillic character reaches the line as itself",
          lower.action == Action::kText && lower.character == 0x0444);
    const Decision upper = router.Route(mi::kChar, 0x0424);
    Check("  ...and its capital is a DIFFERENT character",
          upper.action == Action::kText && upper.character == 0x0424,
          "this is the distinction the Slate path could not make");
  }

  // ---- Escape closes ---------------------------------------------------
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);
    router.Route(mi::kChar, 0x60);
    const Decision escape = router.Route(mi::kKeyDown, mi::kVkEscape);
    Check("Escape closes the console", escape.action == Action::kClose);
    Check("  ...and the game does not get the Escape either",
          !escape.forward_to_game,
          "otherwise closing the console also opens the pause menu");
    Check("  ...and it is closed", !router.IsOpen());
  }

  // ---- a configurable toggle -------------------------------------------
  {
    KeyRouter router;
    router.SetToggleKey(0x77);                          // F8
    Check("VK_OEM_3 is no longer the toggle once one is configured",
          router.Route(mi::kKeyDown, mi::kVkOem3).forward_to_game);
    Check("  ...and the configured key is",
          router.Route(mi::kKeyDown, 0x77).action == Action::kOpen);
  }

  // ---- non-keyboard messages are none of our business ------------------
  {
    KeyRouter router;
    router.Route(mi::kKeyDown, mi::kVkOem3);            // open
    const Decision mouse = router.Route(0x0200, 0);     // WM_MOUSEMOVE
    Check("a mouse message is forwarded even with the console open",
          mouse.forward_to_game && mouse.action == Action::kNothing,
          "the console takes the keyboard, not the game");
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
