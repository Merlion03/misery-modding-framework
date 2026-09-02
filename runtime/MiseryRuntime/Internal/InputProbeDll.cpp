// InputProbeDll.cpp -- the armed half of the Stage 8 input research.
//
// Executes exactly what research/evidence/STAGE8-INPUT/preregistration.md
// registered and nothing else: subclass the one visible top-level UnrealWindow,
// record keyboard messages, optionally suppress them, and detach under a rule
// that refuses rather than unlinking someone else.
//
// WHY THERE IS NO ENGINE ANYTHING IN THIS FILE
// --------------------------------------------
// No UE header, no engine address, no reflection, no UObject. That is the claim
// H-A makes -- that keyboard input is reachable with the OS's own window
// machinery and nothing from the game -- and a probe that quietly leaned on an
// engine fact would not be testing it. The only game-side thing this file knows
// is a window class name, and that is checked, not assumed.
//
// HOW THE CONTROLLER TALKS TO IT
// ------------------------------
// Init/Shutdown are remote-thread entry points, because attaching and detaching
// must happen once and be answered. Everything else is memory: Init publishes
// the address of the single static ProbeState, and the controller polls it with
// ReadProcessMemory and flips capture with WriteProcessMemory. Nothing about a
// per-keystroke measurement should require a remote thread, and a capture toggle
// that costs a thread creation would be measuring the toggle.
//
// THE ONE PLACE A RACE IS ACCEPTED, NAMED
// ---------------------------------------
// The controller reads the ring while the window thread writes it. Sequence
// numbers are written last and read first, so a torn record is detectable by the
// reader; the reader treats a record whose seq changed under it as not-yet-final
// rather than as data. No lock is taken in the window procedure, because a lock
// there would put the controller's scheduling on the game's input path.
#include <windows.h>

#include <stdint.h>

namespace {

constexpr uint64_t kMagic = 0x4D42494E50525031ULL;  // "MBINPRP1"
constexpr uint32_t kProto = 1;
constexpr int kRingCapacity = 512;
constexpr wchar_t kUnrealWindowClass[] = L"UnrealWindow";

// Status codes. Every refusal has its own, because "it did not work" is not a
// finding and the pre-registration asks which failure happened.
enum Status : uint32_t {
  kOk = 0,
  kNoWindow = 1,           // no visible top-level UnrealWindow in this process
  kManyWindows = 2,        // more than one -- C1's failure, reported not resolved
  kAlreadyAttached = 3,
  kSetProcFailed = 4,
  kNotAttached = 5,
  kForeignProcInstalled = 6,  // someone chained after us; restoring would unlink them
  kRestoreFailed = 7,
  kBadIo = 8,
};

#pragma pack(push, 1)
struct Event {
  uint32_t seq;          // written LAST; a reader that sees it change re-reads
  uint32_t message;
  uint32_t vkey;         // wParam for key messages, the character for WM_CHAR
  uint32_t scancode;     // (lParam >> 16) & 0xFF
  uint32_t flags;        // bit0 extended, bit1 repeat, bit2 alt-down (WM_SYS*)
  uint32_t thread_id;
  uint32_t suppressed;   // 1 = the engine never saw this message
  uint32_t nanos;        // time spent inside our procedure for this message
};

struct ProbeState {
  uint64_t magic;
  uint32_t proto;
  uint32_t state_size;

  // --- what the controller writes -------------------------------------
  volatile uint32_t capture_request;  // 0/1, read on every message
  volatile uint32_t reset_request;    // any non-zero clears the ring + counters

  // --- what the probe publishes ---------------------------------------
  uint32_t status;
  uint64_t hwnd;
  uint64_t original_proc;
  uint64_t our_proc;
  uint32_t window_thread_id;
  uint32_t attach_thread_id;
  uint32_t attached;
  uint32_t detached;
  uint32_t top_level_windows;
  uint32_t unreal_windows;
  uint32_t visible_unreal_windows;

  // Counters. Keyboard messages only -- nothing else is counted, and nothing
  // that is not a keyboard message is recorded anywhere in this file.
  uint64_t seen;
  uint64_t suppressed;
  uint64_t forwarded;
  uint64_t all_messages;   // every message through our procedure, keyboard or not
  uint64_t nanos_total;    // summed time inside our procedure, keyboard messages
  uint64_t nanos_max;

  uint32_t ring_capacity;
  uint32_t ring_write;     // monotonic; (ring_write - 1) % capacity is newest
  Event ring[kRingCapacity];
};

struct ProbeIo {
  uint64_t magic;
  uint32_t proto;
  uint32_t status;
  uint64_t state_address;   // where ProbeState lives, for the controller to poll
  uint32_t quiescent_ms;    // Shutdown: how long it watched for a late message
  uint32_t quiescent_ok;    // Shutdown: 1 if nothing arrived in that window
};
#pragma pack(pop)

ProbeState g_state = {};
WNDPROC g_original = nullptr;
LARGE_INTEGER g_qpc_frequency = {};

// Which keys we suppressed the DOWN of. The pre-registration commits to this
// rule before it could be invented afterwards: an up whose down the engine
// already saw must be forwarded, or that key stays held down inside the game
// forever.
bool g_suppressed_down[256] = {};

bool IsKeyboardMessage(UINT message) {
  return message == WM_KEYDOWN || message == WM_KEYUP ||
         message == WM_SYSKEYDOWN || message == WM_SYSKEYUP ||
         message == WM_CHAR || message == WM_SYSCHAR ||
         message == WM_DEADCHAR || message == WM_SYSDEADCHAR ||
         message == WM_UNICHAR;
}

void Record(UINT message, WPARAM wparam, LPARAM lparam, bool suppressed,
            uint32_t nanos) {
  const uint32_t index = g_state.ring_write % kRingCapacity;
  Event& slot = g_state.ring[index];
  slot.seq = 0;                       // mark in-flight before touching the body
  slot.message = static_cast<uint32_t>(message);
  slot.vkey = static_cast<uint32_t>(wparam);
  slot.scancode = static_cast<uint32_t>((lparam >> 16) & 0xFF);
  slot.flags = static_cast<uint32_t>(((lparam >> 24) & 1) |          // extended
                                     (((lparam >> 30) & 1) << 1) |   // repeat
                                     (((lparam >> 29) & 1) << 2));   // alt down
  slot.thread_id = GetCurrentThreadId();
  slot.suppressed = suppressed ? 1u : 0u;
  slot.nanos = nanos;
  slot.seq = g_state.ring_write + 1;  // written LAST
  ++g_state.ring_write;
}

// True when this message should be kept from the engine while capturing.
bool ShouldSuppress(UINT message, WPARAM wparam) {
  switch (message) {
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
      if (wparam < 256) g_suppressed_down[wparam] = true;
      return true;
    case WM_KEYUP:
    case WM_SYSKEYUP:
      // Only ours. An up for a key the engine saw go down must get through.
      if (wparam < 256 && g_suppressed_down[wparam]) {
        g_suppressed_down[wparam] = false;
        return true;
      }
      return false;
    case WM_CHAR:
    case WM_SYSCHAR:
    case WM_DEADCHAR:
    case WM_SYSDEADCHAR:
    case WM_UNICHAR:
      return true;
    default:
      return false;
  }
}

LRESULT CALLBACK ProbeWndProc(HWND window, UINT message, WPARAM wparam,
                              LPARAM lparam) {
  ++g_state.all_messages;

  if (g_state.reset_request) {
    g_state.reset_request = 0;
    g_state.ring_write = 0;
    g_state.seen = g_state.suppressed = g_state.forwarded = 0;
    g_state.nanos_total = g_state.nanos_max = 0;
    for (int i = 0; i < 256; ++i) g_suppressed_down[i] = false;
    // Every slot's seq, not just the write cursor. Rewinding the cursor alone
    // leaves the tail of the previous run in place with sequence numbers that
    // interleave with the new ones -- which is exactly what happened, and the
    // reader cannot tell the two runs apart once they are sorted together.
    for (int i = 0; i < kRingCapacity; ++i) g_state.ring[i].seq = 0;
  }

  if (!IsKeyboardMessage(message)) {
    return CallWindowProcW(g_original, window, message, wparam, lparam);
  }

  LARGE_INTEGER start = {};
  QueryPerformanceCounter(&start);

  const bool capturing = g_state.capture_request != 0;
  const bool suppress = capturing && ShouldSuppress(message, wparam);

  // On the release of capture, a key whose down we swallowed still has its flag
  // set; the branch above clears it when its up arrives, which is why the flag
  // is consulted even when not capturing.
  if (!capturing && (message == WM_KEYUP || message == WM_SYSKEYUP) &&
      wparam < 256) {
    g_suppressed_down[wparam] = false;
  }

  ++g_state.seen;
  if (suppress) {
    ++g_state.suppressed;
  } else {
    ++g_state.forwarded;
  }

  LARGE_INTEGER stop = {};
  QueryPerformanceCounter(&stop);
  uint64_t nanos = 0;
  if (g_qpc_frequency.QuadPart > 0) {
    nanos = static_cast<uint64_t>(stop.QuadPart - start.QuadPart) *
            1000000000ULL / static_cast<uint64_t>(g_qpc_frequency.QuadPart);
  }
  g_state.nanos_total += nanos;
  if (nanos > g_state.nanos_max) g_state.nanos_max = nanos;

  Record(message, wparam, lparam, suppress, static_cast<uint32_t>(nanos));

  if (suppress) {
    return 0;
  }
  return CallWindowProcW(g_original, window, message, wparam, lparam);
}

struct Census {
  HWND single_visible = nullptr;
  uint32_t top_level = 0;
  uint32_t unreal = 0;
  uint32_t visible_unreal = 0;
};

BOOL CALLBACK CountWindow(HWND window, LPARAM param) {
  Census* census = reinterpret_cast<Census*>(param);
  DWORD pid = 0;
  GetWindowThreadProcessId(window, &pid);
  if (pid != GetCurrentProcessId()) return TRUE;
  ++census->top_level;
  wchar_t name[64] = {};
  GetClassNameW(window, name, 64);
  if (lstrcmpW(name, kUnrealWindowClass) != 0) return TRUE;
  ++census->unreal;
  if (!IsWindowVisible(window)) return TRUE;
  ++census->visible_unreal;
  census->single_visible = window;
  return TRUE;
}

}  // namespace

extern "C" __declspec(dllexport) DWORD InputProbeInit(void* param) {
  ProbeIo* io = static_cast<ProbeIo*>(param);
  if (io == nullptr || io->magic != kMagic || io->proto != kProto) {
    if (io != nullptr) io->status = kBadIo;
    return kBadIo;
  }
  io->state_address = reinterpret_cast<uint64_t>(&g_state);

  if (g_state.attached) {
    io->status = g_state.status = kAlreadyAttached;
    return kAlreadyAttached;
  }

  QueryPerformanceFrequency(&g_qpc_frequency);
  g_state.magic = kMagic;
  g_state.proto = kProto;
  g_state.state_size = sizeof(ProbeState);
  g_state.ring_capacity = kRingCapacity;

  Census census;
  EnumWindows(CountWindow, reinterpret_cast<LPARAM>(&census));
  g_state.top_level_windows = census.top_level;
  g_state.unreal_windows = census.unreal;
  g_state.visible_unreal_windows = census.visible_unreal;

  if (census.visible_unreal == 0) {
    io->status = g_state.status = kNoWindow;
    return kNoWindow;
  }
  if (census.visible_unreal > 1) {
    // C1 failed. Reported, not resolved: picking one would be a guess.
    io->status = g_state.status = kManyWindows;
    return kManyWindows;
  }

  HWND window = census.single_visible;
  g_state.hwnd = reinterpret_cast<uint64_t>(window);
  g_state.window_thread_id = GetWindowThreadProcessId(window, nullptr);
  g_state.attach_thread_id = GetCurrentThreadId();
  g_state.our_proc = reinterpret_cast<uint64_t>(&ProbeWndProc);

  SetLastError(0);
  LONG_PTR previous = SetWindowLongPtrW(window, GWLP_WNDPROC,
                                        reinterpret_cast<LONG_PTR>(ProbeWndProc));
  if (previous == 0 && GetLastError() != 0) {
    io->status = g_state.status = kSetProcFailed;
    return kSetProcFailed;
  }
  g_original = reinterpret_cast<WNDPROC>(previous);
  g_state.original_proc = static_cast<uint64_t>(previous);
  g_state.attached = 1;
  io->status = g_state.status = kOk;
  return kOk;
}

extern "C" __declspec(dllexport) DWORD InputProbeShutdown(void* param) {
  ProbeIo* io = static_cast<ProbeIo*>(param);
  if (io == nullptr || io->magic != kMagic || io->proto != kProto) {
    if (io != nullptr) io->status = kBadIo;
    return kBadIo;
  }
  io->state_address = reinterpret_cast<uint64_t>(&g_state);

  if (!g_state.attached) {
    io->status = g_state.status = kNotAttached;
    return kNotAttached;
  }
  HWND window = reinterpret_cast<HWND>(g_state.hwnd);

  // C6's rule. If the current procedure is not ours, someone installed after us
  // and restoring the original would unlink them. Refuse; the module stays.
  LONG_PTR current = GetWindowLongPtrW(window, GWLP_WNDPROC);
  if (current != reinterpret_cast<LONG_PTR>(ProbeWndProc)) {
    io->status = g_state.status = kForeignProcInstalled;
    return kForeignProcInstalled;
  }

  g_state.capture_request = 0;
  SetLastError(0);
  LONG_PTR restored = SetWindowLongPtrW(window, GWLP_WNDPROC,
                                        static_cast<LONG_PTR>(g_state.original_proc));
  if (restored == 0 && GetLastError() != 0) {
    io->status = g_state.status = kRestoreFailed;
    return kRestoreFailed;
  }
  LONG_PTR now = GetWindowLongPtrW(window, GWLP_WNDPROC);
  if (now != static_cast<LONG_PTR>(g_state.original_proc)) {
    io->status = g_state.status = kRestoreFailed;
    return kRestoreFailed;
  }

  // Quiescence. Not a sleep for luck: the counter is watched, and the answer is
  // "nothing arrived in this window", which is what makes an unload safe.
  const uint64_t before = g_state.all_messages;
  const DWORD window_ms = 1500;
  const DWORD started = GetTickCount();
  while (GetTickCount() - started < window_ms) {
    Sleep(50);
    if (g_state.all_messages != before) break;
  }
  io->quiescent_ms = GetTickCount() - started;
  io->quiescent_ok = (g_state.all_messages == before) ? 1u : 0u;

  g_state.attached = 0;
  g_state.detached = 1;
  io->status = g_state.status = kOk;
  return kOk;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    QueryPerformanceFrequency(&g_qpc_frequency);
  }
  return TRUE;
}
