// console_ui_link_check.cpp -- the console UI compiles and links, off the game.
//
// The window, the painting and the window-procedure attach cannot be exercised
// without a game to attach to; the manual acceptance pass is where they are
// tested. What CAN be checked here, and is worth checking on every build, is
// that the UI still links against the real backend seam -- that
// console_backend::Run and CommandNames resolve to the same engine the ABI
// answers from, rather than to a stub someone added to make a build go green.
//
// It also asserts the two states that must hold before anything starts: nothing
// attached, and a toggle key that is the measured default.
#include <stdio.h>

#include "../MiseryRuntime/Internal/ConsoleBackend.h"
#include "../MiseryRuntime/Internal/ConsoleUi.h"
#include "../MiseryRuntime/Internal/InputSource.h"

int main() {
  int failures = 0;

  const misery::console_ui::Status ui = misery::console_ui::Read();
  const misery::input::Status source = misery::input::Read();
  if (ui.started) ++failures;
  if (source.attached) ++failures;
  if (ui.toggle_key != 0xC0) ++failures;   // VK_OEM_3: ` on US, e-diaeresis on RU

  // The seam reaches the real registry: the builtins are there before any mod.
  const std::vector<std::string> names = misery::console_backend::CommandNames();
  bool has_help = false;
  for (const std::string& name : names) {
    if (name == "misery:help") has_help = true;
  }
  if (!has_help) ++failures;

  // And running through it produces the same envelope shape the ABI door does.
  const misery::console_backend::RunResult result =
      misery::console_backend::Run("misery:caps");
  if (!result.ran) ++failures;
  if (result.envelope.find("\"ok\":true") == std::string::npos) ++failures;

  printf("{\"ok\":%s,\"failures\":%d,\"commands\":%d,\"toggle_key\":%u}\n",
         failures == 0 ? "true" : "false", failures,
         static_cast<int>(names.size()), ui.toggle_key);
  return failures == 0 ? 0 : 1;
}
