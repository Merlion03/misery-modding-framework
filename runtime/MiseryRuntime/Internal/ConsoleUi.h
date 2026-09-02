// ConsoleUi.h -- the in-game developer console, as a frontend and nothing more.
//
// It owns a window, a line of text and a scrollback. It does not own a command
// registry, a dispatcher, an envelope format or a notion of what any command
// means: every line it runs goes through console_backend::Run, which is the same
// engine MbConsoleTable::run answers from. A command registered by a mod behaves
// here exactly as it does through the ABI, because it IS the same call.
//
// WHY IT DOES NOT NEED A WORLD
// ----------------------------
// Three things carry it, and none is tied to a UWorld, a PlayerController or
// `misery:content_ready`: the game's top-level window, which exists from launch;
// the thread that dispatches its messages, measured to be the game thread; and
// the FTSTicker pump, observed running at the main menu with no world loaded.
// So the console opens on the title screen, survives the level load, and is
// there in gameplay. A command that needs a world is free to refuse -- the
// console does not go away with it.
#ifndef MISERY_CONSOLEUI_H
#define MISERY_CONSOLEUI_H

#include <stdint.h>

#include <string>

namespace misery {
namespace console_ui {

// Attaches the input source and prepares the overlay. The window itself is not
// created until the console is first opened: a developer who never presses the
// key pays for nothing but a window procedure that forwards.
bool Start(std::string* why);

// Closes the console, releases the input source, and waits for the window
// procedure to go quiet. Returns false when detach was refused -- which is a
// BLOCKED report, not a reason to unload anyway.
bool Stop(std::string* why);

// Once per frame, on the game thread.
void Tick();

bool IsOpen();
void SetToggleKey(uint32_t virtual_key);
uint32_t ToggleKey();

// Puts a line into the scrollback from outside -- what the framework wants a
// developer to see the moment they open the console, without having to have
// been watching a log file. Safe before Start().
void Announce(const std::string& text);

struct Status {
  bool started = false;
  bool open = false;
  uint64_t commands_run = 0;
  uint32_t toggle_key = 0;
  std::string last_refusal;
};

Status Read();

}  // namespace console_ui
}  // namespace misery

#endif  // MISERY_CONSOLEUI_H
