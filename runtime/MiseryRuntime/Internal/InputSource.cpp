// InputSource.cpp -- the Win32 half. No policy lives here.
//
// Every rule about which key belongs to whom is in InputRouting.h, which has no
// Win32 in it and is tested off the game. What is left here is the part that
// can only be done against a real window: find it, subclass it, chain, restore,
// and notice when it is replaced.
#include "InputSource.h"

#include <windows.h>

#include <atomic>
#include <mutex>

#include "InputRouting.h"

namespace misery {
namespace input {
namespace {

constexpr wchar_t kUnrealWindowClass[] = L"UnrealWindow";

std::mutex g_mutex;                 // guards attach/detach, never the hot path
HWND g_window = nullptr;
WNDPROC g_previous = nullptr;
Consumer g_consumer = nullptr;
void* g_consumer_context = nullptr;
Watcher g_watcher = nullptr;
void* g_watcher_context = nullptr;

std::atomic<bool> g_application_active{true};
std::atomic<bool> g_minimised{false};

std::atomic<uint64_t> g_seen{0};
std::atomic<uint64_t> g_suppressed{0};
std::atomic<uint64_t> g_any_message{0};
std::atomic<uint32_t> g_rearms{0};
std::string g_last_refusal;

struct Census {
  HWND window = nullptr;
  int count = 0;
};

BOOL CALLBACK CountWindows(HWND window, LPARAM param) {
  Census* census = reinterpret_cast<Census*>(param);
  DWORD pid = 0;
  GetWindowThreadProcessId(window, &pid);
  if (pid != GetCurrentProcessId() || !IsWindowVisible(window)) return TRUE;
  wchar_t name[64] = {};
  GetClassNameW(window, name, 64);
  if (lstrcmpW(name, kUnrealWindowClass) != 0) return TRUE;
  census->window = window;
  ++census->count;
  return TRUE;
}

Census FindWindow() {
  Census census;
  EnumWindows(CountWindows, reinterpret_cast<LPARAM>(&census));
  return census;
}

void Notify(WindowEvent event) {
  Watcher watcher = g_watcher;
  if (watcher == nullptr) return;
  // Same containment as the keyboard consumer: a throw escaping here would
  // unwind through the engine's own message pump.
  try {
    watcher(g_watcher_context, event);
  } catch (...) {
  }
}

// Observed, never consumed. Every one of these is passed on to the game
// untouched -- the framework is watching the window's state, not taking part
// in it.
void ObserveWindowState(UINT message, WPARAM wparam) {
  if (message == WM_ACTIVATEAPP) {
    const bool active = wparam != FALSE;
    if (g_application_active.exchange(active) != active) {
      Notify(active ? WindowEvent::kActivated : WindowEvent::kDeactivated);
    }
    return;
  }
  if (message == WM_SIZE) {
    const bool minimised = (wparam == SIZE_MINIMIZED);
    if (g_minimised.exchange(minimised) != minimised) {
      Notify(minimised ? WindowEvent::kMinimised : WindowEvent::kRestored);
    }
  }
}

LRESULT CALLBACK SourceProc(HWND window, UINT message, WPARAM wparam,
                            LPARAM lparam) {
  g_any_message.fetch_add(1, std::memory_order_relaxed);

  if (!IsKeyboardMessage(static_cast<uint32_t>(message))) {
    ObserveWindowState(message, wparam);
    return CallWindowProcW(g_previous, window, message, wparam, lparam);
  }
  g_seen.fetch_add(1, std::memory_order_relaxed);

  bool forward = true;
  Consumer consumer = g_consumer;
  if (consumer != nullptr) {
    // The consumer runs INSIDE the window procedure and may throw only over our
    // own code; a throw escaping into the engine's message pump would tear down
    // the game's stack. Caught here, the message is forwarded -- failing open,
    // because the failure mode of failing closed is a game that cannot be
    // played until it is restarted.
    try {
      forward = consumer(g_consumer_context, static_cast<uint32_t>(message),
                         static_cast<uint32_t>(wparam),
                         static_cast<uint32_t>(lparam));
    } catch (...) {
      forward = true;
    }
  }
  if (!forward) {
    g_suppressed.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  return CallWindowProcW(g_previous, window, message, wparam, lparam);
}

bool AttachLocked(std::string* why) {
  const Census census = FindWindow();
  if (census.count == 0) {
    *why = "no visible top-level UnrealWindow in this process";
    return false;
  }
  if (census.count > 1) {
    *why = "more than one visible top-level UnrealWindow; refusing to guess "
           "which one receives keyboard input";
    return false;
  }
  SetLastError(0);
  const LONG_PTR previous = SetWindowLongPtrW(
      census.window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(SourceProc));
  if (previous == 0 && GetLastError() != 0) {
    *why = "SetWindowLongPtrW(GWLP_WNDPROC) failed";
    return false;
  }
  g_window = census.window;
  g_previous = reinterpret_cast<WNDPROC>(previous);
  // WM_ACTIVATEAPP only arrives on a CHANGE, so a fresh attach has to read the
  // current state rather than assume the game is in front. It often is not: the
  // re-arm path runs when the window was recreated, which can happen while the
  // user is looking at something else entirely.
  const bool active = (GetForegroundWindow() == census.window);
  g_application_active.store(active, std::memory_order_relaxed);
  g_minimised.store(IsIconic(census.window) != FALSE, std::memory_order_relaxed);
  return true;
}

}  // namespace

bool Attach(std::string* why) {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_window != nullptr) {
    if (why != nullptr) *why = "already attached";
    return true;
  }
  std::string reason;
  if (!AttachLocked(&reason)) {
    g_last_refusal = reason;
    if (why != nullptr) *why = reason;
    return false;
  }
  g_last_refusal.clear();
  return true;
}

bool Detach(std::string* why) {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_window == nullptr) {
    if (why != nullptr) *why = "not attached";
    return false;
  }
  // If ours is no longer the installed procedure, someone chained after us and
  // restoring the original would unlink them. Refuse; the module stays.
  const LONG_PTR current = GetWindowLongPtrW(g_window, GWLP_WNDPROC);
  if (current != reinterpret_cast<LONG_PTR>(SourceProc)) {
    const char* reason =
        "another window procedure is installed after ours; restoring would "
        "unlink it, so this refuses rather than detaching";
    g_last_refusal = reason;
    if (why != nullptr) *why = reason;
    return false;
  }
  SetLastError(0);
  SetWindowLongPtrW(g_window, GWLP_WNDPROC,
                    reinterpret_cast<LONG_PTR>(g_previous));
  if (GetWindowLongPtrW(g_window, GWLP_WNDPROC) !=
      reinterpret_cast<LONG_PTR>(g_previous)) {
    const char* reason = "the original window procedure did not read back";
    g_last_refusal = reason;
    if (why != nullptr) *why = reason;
    return false;
  }
  g_window = nullptr;
  g_previous = nullptr;
  return true;
}

bool WaitQuiescent(uint32_t settle_ms, uint32_t timeout_ms) {
  const DWORD started = GetTickCount();
  uint64_t mark = g_any_message.load(std::memory_order_relaxed);
  DWORD quiet_since = started;
  while (GetTickCount() - started < timeout_ms) {
    Sleep(20);
    const uint64_t now = g_any_message.load(std::memory_order_relaxed);
    if (now != mark) {
      mark = now;
      quiet_since = GetTickCount();
      continue;
    }
    if (GetTickCount() - quiet_since >= settle_ms) return true;
  }
  return false;
}

void Tick() {
  HWND attached = nullptr;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    attached = g_window;
  }
  if (attached == nullptr) return;

  // RE-READ THE OS, do not re-read our own flag.
  //
  // WM_ACTIVATEAPP only arrives on a CHANGE. If the framework attached while
  // the game was already in front -- which is the ordinary case, since it
  // attaches during loading -- no activation message ever arrives and a cached
  // flag seeded at attach time stays wrong forever. The first version of this
  // "reconciliation" compared the console's copy of the flag against the
  // source's copy of the same flag, so both were stale together and it could
  // not correct anything. This asks the OS.
  const bool active_now = (GetForegroundWindow() == attached);
  const bool minimised_now = (IsIconic(attached) != FALSE);
  if (g_application_active.exchange(active_now) != active_now) {
    Notify(active_now ? WindowEvent::kActivated : WindowEvent::kDeactivated);
  }
  if (g_minimised.exchange(minimised_now) != minimised_now) {
    Notify(minimised_now ? WindowEvent::kMinimised : WindowEvent::kRestored);
  }
  // Two ways to lose the window: it is destroyed (a display-mode change
  // rebuilds it), or our procedure is replaced. Both are observable, so neither
  // is answered with a timer.
  const bool alive = IsWindow(attached) != FALSE;
  const bool ours = alive && GetWindowLongPtrW(attached, GWLP_WNDPROC) ==
                                 reinterpret_cast<LONG_PTR>(SourceProc);
  if (alive && ours) return;

  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_window != attached) return;      // someone else already handled it
  g_window = nullptr;
  g_previous = nullptr;
  std::string reason;
  if (AttachLocked(&reason)) {
    g_rearms.fetch_add(1, std::memory_order_relaxed);
    g_last_refusal.clear();
  } else {
    g_last_refusal = reason;
  }
}

void SetConsumer(Consumer consumer, void* context) {
  std::lock_guard<std::mutex> guard(g_mutex);
  g_consumer_context = context;
  g_consumer = consumer;               // written last; the context must be up first
}

void SetWatcher(Watcher watcher, void* context) {
  std::lock_guard<std::mutex> guard(g_mutex);
  g_watcher_context = context;
  g_watcher = watcher;                 // written last, for the same reason
}

Status Read() {
  std::lock_guard<std::mutex> guard(g_mutex);
  Status status;
  status.attached = g_window != nullptr;
  status.window = reinterpret_cast<uint64_t>(g_window);
  status.window_thread_id =
      g_window == nullptr ? 0 : GetWindowThreadProcessId(g_window, nullptr);
  status.messages_seen = g_seen.load(std::memory_order_relaxed);
  status.messages_suppressed = g_suppressed.load(std::memory_order_relaxed);
  status.rearms = g_rearms.load(std::memory_order_relaxed);
  status.application_active = g_application_active.load(std::memory_order_relaxed);
  status.minimised = g_minimised.load(std::memory_order_relaxed);
  status.last_refusal = g_last_refusal;
  return status;
}

}  // namespace input
}  // namespace misery
