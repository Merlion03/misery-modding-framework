// InputSource.h -- keyboard delivery, from the game's own window procedure.
//
// The mechanism this implements is the one the Stage 8 input research measured
// and adopted (research/evidence/STAGE8-INPUT/findings.md): subclass the single
// visible top-level `UnrealWindow`, chain to the previous procedure, and decide
// per message whether the game sees it. It needs no engine address, no engine
// type layout, no vtable and no patched code, and it is the only route that
// delivers typed text -- Slate's input pre-processor has no character handler at
// all, and the character on a key-down there is the unshifted MapVirtualKey
// value, so `a` and `Shift+a` are the same event.
//
// GENERIC ON PURPOSE
// ------------------
// This is a delivery primitive with one consumer slot. The developer console is
// its first consumer and has no privileged position here: nothing in this file
// knows what a console is. When owned mod bindings arrive they become consumers
// of the same source rather than a second mechanism beside it.
//
// THREAD
// ------
// The window procedure runs on the thread that dispatches the window's
// messages, and that thread was measured to be the same one the FTSTicker
// carrier calls the game thread. So a consumer runs on the game thread with no
// marshalling -- but `WindowThreadId()` is published rather than assumed, so a
// consumer that cares can check rather than trust this comment.
#ifndef MISERY_INPUTSOURCE_H
#define MISERY_INPUTSOURCE_H

#include <stdint.h>

#include <string>

namespace misery {
namespace input {

// Returns true to let the game have the message, false to keep it. Runs on the
// window's message thread, inside the window procedure -- so it must be quick,
// and it must not block.
using Consumer = bool (*)(void* context, uint32_t message, uint32_t wparam,
                          uint32_t lparam);

// Window states a consumer has to know about, because they are not keyboard and
// cannot be inferred from keyboard.
//
// ACTIVATION AND MINIMISE ARE SEPARATE, deliberately. They were conflated once
// and it produced a real bug: minimising appeared to work only because the
// overlay follows the game's client rect and a minimised window's rect
// collapses, so nothing was ever tracking activation and Alt+Tab left a topmost
// console sitting over whatever the user switched to. A window can be inactive
// and not minimised, minimised and not inactive (briefly, mid-transition), or
// both, and a consumer that wants "is the game in front of the user" has to be
// told each independently rather than handed one flag that means neither.
enum class WindowEvent : int32_t {
  kActivated = 1,     // WM_ACTIVATEAPP, wParam TRUE
  kDeactivated = 2,   // WM_ACTIVATEAPP, wParam FALSE -- Alt+Tab lands here
  kMinimised = 3,     // WM_SIZE, SIZE_MINIMIZED
  kRestored = 4,      // WM_SIZE, anything else, after having been minimised
};

// Delivered from inside the window procedure, synchronously with the state
// change. NOT polled from the frame pump: a minimised or background game may
// have its tick throttled by the engine or the OS, and a console that waited
// for a frame to hide itself would still be on screen while the user was
// looking at something else -- which is exactly the shape of the bug this
// exists to fix.
using Watcher = void (*)(void* context, WindowEvent event);

struct Status {
  bool attached = false;
  bool application_active = true;   // WM_ACTIVATEAPP says MISERY is in front
  bool minimised = false;           // WM_SIZE said SIZE_MINIMIZED
  uint64_t window = 0;
  uint32_t window_thread_id = 0;
  uint64_t messages_seen = 0;     // keyboard messages only
  uint64_t messages_suppressed = 0;
  uint32_t rearms = 0;            // how often the window was replaced under us
  std::string last_refusal;
};

// Attaches to the one visible top-level UnrealWindow of this process. Refuses,
// with a reason, when there is not exactly one: picking among several would be
// a guess, and a guess here is a game whose input silently goes somewhere else.
bool Attach(std::string* why);

// Restores the previous procedure -- but only if ours is still installed.
// If something else has chained after us, restoring would unlink it, so this
// refuses and says so. After a successful detach the caller must still let the
// quiescence window pass before unloading anything.
bool Detach(std::string* why);

// True once no message has reached our procedure for `settle_ms`. The unload
// handshake: a module holding a window procedure cannot be freed on a hope.
bool WaitQuiescent(uint32_t settle_ms, uint32_t timeout_ms);

// Called once per frame from the game-thread pump. Re-attaches if the window
// was recreated -- a display-mode change destroys and rebuilds it -- which is
// a re-arm on a MEASURED condition, not a timer.
void Tick();

void SetConsumer(Consumer consumer, void* context);
void SetWatcher(Watcher watcher, void* context);
Status Read();

}  // namespace input
}  // namespace misery

#endif  // MISERY_INPUTSOURCE_H
