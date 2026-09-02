// OverlayProbeDll.cpp -- C9: can a thin UI be drawn over this game at all?
//
// The pre-registration names this the one outcome that would be a genuine
// architecture blocker rather than something to route around: if a window owned
// by our module cannot be shown above the game's client area without taking the
// foreground, then the console UI needs an in-engine drawing path, and that is
// its own research track.
//
// So this draws a deliberately unmistakable test pattern -- three flat bands of
// exact RGB values that nothing in a survival game's palette will coincidentally
// produce -- and the controller reads the screen back and looks for them. A
// screenshot that "looks right" is not the measurement; the pixel values are.
//
// WHAT IT REFUSES TO DO
//   * never SetForegroundWindow, never SetFocus, never SetActiveWindow
//   * WS_EX_NOACTIVATE, so a click could not activate it either
//   * no engine call, no engine address, exactly as with the input probe
#include <windows.h>

#include <stdint.h>

namespace {

constexpr uint64_t kMagic = 0x4D424F564C593031ULL;  // "MBOVLY01"
constexpr uint32_t kProto = 1;
constexpr wchar_t kOverlayClass[] = L"MiseryOverlayProbe";

// The pattern. Chosen to be findable, not pretty.
const COLORREF kBand[3] = {RGB(255, 0, 128), RGB(0, 255, 128), RGB(0, 128, 255)};

#pragma pack(push, 1)
struct OverlayIo {
  uint64_t magic;
  uint32_t proto;
  uint32_t status;
  // in
  int32_t x, y, width, height;
  uint32_t alpha;          // 0..255
  // out
  uint64_t overlay_hwnd;
  uint64_t game_hwnd;
  uint64_t foreground_before;
  uint64_t foreground_after;
  uint32_t thread_id;
  uint32_t painted;
};
#pragma pack(pop)

enum Status : uint32_t {
  kOk = 0, kNoGameWindow = 1, kClassFailed = 2, kCreateFailed = 3,
  kBadIo = 4, kAlreadyUp = 5, kNotUp = 6,
};

HWND g_overlay = nullptr;
HANDLE g_thread = nullptr;
DWORD g_thread_id = 0;
volatile LONG g_painted = 0;
RECT g_rect = {};
BYTE g_alpha = 220;

void Paint(HWND window) {
  PAINTSTRUCT paint;
  HDC dc = BeginPaint(window, &paint);
  RECT client;
  GetClientRect(window, &client);
  const int band = (client.bottom - client.top) / 3;
  for (int i = 0; i < 3; ++i) {
    RECT slice = {client.left, client.top + band * i, client.right,
                  (i == 2) ? client.bottom : client.top + band * (i + 1)};
    HBRUSH brush = CreateSolidBrush(kBand[i]);
    FillRect(dc, &slice, brush);
    DeleteObject(brush);
  }
  EndPaint(window, &paint);
  InterlockedIncrement(&g_painted);
}

LRESULT CALLBACK OverlayProc(HWND window, UINT message, WPARAM w, LPARAM l) {
  switch (message) {
    case WM_PAINT:
      Paint(window);
      return 0;
    case WM_NCHITTEST:
      return HTTRANSPARENT;   // clicks fall through to whatever is beneath
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(window, message, w, l);
  }
}

HWND FindGameWindow() {
  struct Found { HWND window = nullptr; int count = 0; };
  Found found;
  EnumWindows(
      [](HWND window, LPARAM param) -> BOOL {
        Found* out = reinterpret_cast<Found*>(param);
        DWORD pid = 0;
        GetWindowThreadProcessId(window, &pid);
        if (pid != GetCurrentProcessId() || !IsWindowVisible(window)) return TRUE;
        wchar_t name[64] = {};
        GetClassNameW(window, name, 64);
        if (lstrcmpW(name, L"UnrealWindow") != 0) return TRUE;
        out->window = window;
        ++out->count;
        return TRUE;
      },
      reinterpret_cast<LPARAM>(&found));
  return found.count == 1 ? found.window : nullptr;
}

DWORD WINAPI OverlayThread(LPVOID) {
  WNDCLASSEXW klass = {};
  klass.cbSize = sizeof(klass);
  klass.lpfnWndProc = OverlayProc;
  klass.hInstance = GetModuleHandleW(nullptr);
  klass.lpszClassName = kOverlayClass;
  klass.hbrBackground = nullptr;
  RegisterClassExW(&klass);   // an existing class is fine on a second run

  g_overlay = CreateWindowExW(
      WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
      kOverlayClass, L"", WS_POPUP,
      g_rect.left, g_rect.top, g_rect.right - g_rect.left,
      g_rect.bottom - g_rect.top, nullptr, nullptr,
      GetModuleHandleW(nullptr), nullptr);
  if (g_overlay == nullptr) return 1;

  SetLayeredWindowAttributes(g_overlay, 0, g_alpha, LWA_ALPHA);
  // SW_SHOWNOACTIVATE, never ShowWindow(SW_SHOW): showing normally would take
  // the activation this whole design exists to avoid.
  ShowWindow(g_overlay, SW_SHOWNOACTIVATE);
  UpdateWindow(g_overlay);

  MSG message;
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
  g_overlay = nullptr;
  return 0;
}

}  // namespace

extern "C" __declspec(dllexport) DWORD OverlayShow(void* param) {
  OverlayIo* io = static_cast<OverlayIo*>(param);
  if (io == nullptr || io->magic != kMagic || io->proto != kProto) {
    if (io) io->status = kBadIo;
    return kBadIo;
  }
  if (g_overlay != nullptr) {
    io->status = kAlreadyUp;
    return kAlreadyUp;
  }
  HWND game = FindGameWindow();
  if (game == nullptr) {
    io->status = kNoGameWindow;
    return kNoGameWindow;
  }
  io->game_hwnd = reinterpret_cast<uint64_t>(game);
  io->foreground_before = reinterpret_cast<uint64_t>(GetForegroundWindow());

  g_rect.left = io->x;
  g_rect.top = io->y;
  g_rect.right = io->x + io->width;
  g_rect.bottom = io->y + io->height;
  g_alpha = static_cast<BYTE>(io->alpha ? io->alpha : 220);
  g_painted = 0;

  g_thread = CreateThread(nullptr, 0, OverlayThread, nullptr, 0, &g_thread_id);
  if (g_thread == nullptr) {
    io->status = kCreateFailed;
    return kCreateFailed;
  }
  for (int i = 0; i < 100 && g_overlay == nullptr; ++i) Sleep(20);
  if (g_overlay == nullptr) {
    io->status = kCreateFailed;
    return kCreateFailed;
  }
  Sleep(300);
  io->overlay_hwnd = reinterpret_cast<uint64_t>(g_overlay);
  io->thread_id = g_thread_id;
  io->painted = static_cast<uint32_t>(g_painted);
  io->foreground_after = reinterpret_cast<uint64_t>(GetForegroundWindow());
  io->status = kOk;
  return kOk;
}

extern "C" __declspec(dllexport) DWORD OverlayHide(void* param) {
  OverlayIo* io = static_cast<OverlayIo*>(param);
  if (io == nullptr || io->magic != kMagic || io->proto != kProto) {
    if (io) io->status = kBadIo;
    return kBadIo;
  }
  if (g_overlay == nullptr) {
    io->status = kNotUp;
    return kNotUp;
  }
  io->painted = static_cast<uint32_t>(g_painted);
  PostMessageW(g_overlay, WM_CLOSE, 0, 0);
  if (g_thread != nullptr) {
    WaitForSingleObject(g_thread, 5000);
    CloseHandle(g_thread);
    g_thread = nullptr;
  }
  io->foreground_after = reinterpret_cast<uint64_t>(GetForegroundWindow());
  io->status = kOk;
  return kOk;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
