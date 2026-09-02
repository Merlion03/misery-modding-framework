// ConsoleUi.cpp -- the window, the painting, and the wiring to the backend.
//
// The overlay is a layered, topmost, never-activated popup over the game's
// client rect. The research established that this composites over MISERY as it
// actually runs -- borderless, covering the monitor -- and read the pixels back
// to prove it rather than looking at a screenshot. It will NOT be visible if a
// user runs exclusive fullscreen, and that is a stated limit rather than a
// surprise: nothing can composite over an exclusive swapchain from outside it.
//
// WHY THE WINDOW IS CREATED ON THE GAME THREAD
// --------------------------------------------
// A window belongs to the thread that creates it, and its messages are
// dispatched by that thread's pump. Creating it on the game thread means the
// game's own `PeekMessage`/`DispatchMessage` loop drives it -- no second pump,
// no second thread, and no lock between the input handler, the text state and
// the painting, because all three run on that one thread.
#include "ConsoleUi.h"

#include <windows.h>

#include <algorithm>
#include <string>
#include <vector>

#include "ConsoleBackend.h"
#include "ConsoleLine.h"
#include "InputRouting.h"
#include "InputSource.h"
#include "Json.h"

namespace misery {
namespace console_ui {
namespace {

constexpr wchar_t kClassName[] = L"MiseryDeveloperConsole";
constexpr int kPadding = 10;
constexpr int kFontHeight = 18;
constexpr double kHeightFraction = 0.42;
constexpr BYTE kAlpha = 232;

// Deliberately few. A console that needs a palette to be read is not being read.
constexpr COLORREF kBackground = RGB(12, 14, 18);
constexpr COLORREF kOutput = RGB(206, 212, 220);
constexpr COLORREF kEcho = RGB(120, 170, 235);
constexpr COLORREF kError = RGB(240, 110, 110);
constexpr COLORREF kNotice = RGB(150, 200, 140);
constexpr COLORREF kPrompt = RGB(240, 220, 140);
constexpr COLORREF kRule = RGB(48, 54, 64);

struct State {
  bool started = false;
  HWND window = nullptr;
  HFONT font = nullptr;
  int line_height = kFontHeight;
  int character_width = 8;
  misery::input::KeyRouter router;
  ConsoleLine line;
  uint64_t commands_run = 0;
  std::string last_refusal;
  bool dirty = true;
  bool caret_on = true;
  DWORD caret_at = 0;
  // The two window states, kept apart because they are two facts. `open` lives
  // in the router and is the developer's intent; these are the game's.
  bool active = true;
  bool minimised = false;
};

State& S() {
  static State state;
  return state;
}

// ---- text ---------------------------------------------------------------

std::wstring Widen(const std::string& utf8) {
  if (utf8.empty()) return std::wstring();
  const int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                         static_cast<int>(utf8.size()),
                                         nullptr, 0);
  if (needed <= 0) return std::wstring();
  std::wstring wide(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()),
                      &wide[0], needed);
  return wide;
}

// Renders a parsed JSON value as indented text. The envelope a command answers
// with is JSON, and a console that printed it on one line would be technically
// correct and unreadable.
void Render(const misery::json::Value& value, int indent, std::string* out) {
  const std::string pad(static_cast<size_t>(indent) * 2, ' ');
  switch (value.kind) {
    case misery::json::Kind::kNull:
      *out += "null";
      break;
    case misery::json::Kind::kBool:
      *out += value.boolean ? "true" : "false";
      break;
    case misery::json::Kind::kInt:
      *out += std::to_string(value.integer);
      break;
    case misery::json::Kind::kDouble: {
      char buffer[32];
      snprintf(buffer, sizeof(buffer), "%g", value.number);
      *out += buffer;
      break;
    }
    case misery::json::Kind::kString:
      *out += value.text;
      break;
    case misery::json::Kind::kArray: {
      if (value.array.empty()) {
        *out += "(none)";
        break;
      }
      for (const misery::json::Value& item : value.array) {
        *out += "\n" + pad + "- ";
        Render(item, indent + 1, out);
      }
      break;
    }
    case misery::json::Kind::kObject: {
      if (value.object.empty()) {
        *out += "(empty)";
        break;
      }
      for (const auto& entry : value.object) {
        *out += "\n" + pad + entry.first + ": ";
        Render(entry.second, indent + 1, out);
      }
      break;
    }
  }
}

// Turns an envelope into lines. Falls back to the raw document when it cannot
// be parsed -- showing the developer the actual bytes beats showing them a
// message about the bytes.
void WriteEnvelope(const std::string& envelope) {
  misery::json::Value document;
  std::string error;
  if (!misery::json::Parse(envelope, &document, &error)) {
    S().line.Write(envelope, Severity::kOutput);
    return;
  }
  const misery::json::Value* ok = document.Member("ok");
  const bool succeeded = ok != nullptr && ok->Is(misery::json::Kind::kBool) &&
                         ok->boolean;
  if (!succeeded) {
    const misery::json::Value* failure = document.Member("error");
    std::string text;
    if (failure != nullptr) {
      Render(*failure, 0, &text);
    } else {
      text = envelope;
    }
    const misery::json::Value* hint = document.Member("hint");
    if (hint != nullptr && hint->Is(misery::json::Kind::kString)) {
      text += "\n" + hint->text;
    }
    S().line.Write(text, Severity::kError);
    return;
  }
  const misery::json::Value* result = document.Member("result");
  std::string text;
  Render(result == nullptr ? document : *result, 0, &text);
  if (!text.empty() && text[0] == '\n') text.erase(0, 1);
  S().line.Write(text, Severity::kOutput);
}

// ---- painting -----------------------------------------------------------

COLORREF ColourOf(Severity severity) {
  switch (severity) {
    case Severity::kEcho: return kEcho;
    case Severity::kError: return kError;
    case Severity::kNotice: return kNotice;
    default: return kOutput;
  }
}

int VisibleRows() {
  if (S().window == nullptr) return 20;
  RECT client;
  GetClientRect(S().window, &client);
  const int usable = (client.bottom - client.top) - kPadding * 3 -
                     S().line_height;
  return usable > 0 ? usable / S().line_height : 1;
}

void Paint(HWND window) {
  PAINTSTRUCT paint;
  HDC screen = BeginPaint(window, &paint);
  RECT client;
  GetClientRect(window, &client);

  // Double-buffered: painting straight to the window over a game that is
  // redrawing behind it flickers badly.
  HDC dc = CreateCompatibleDC(screen);
  HBITMAP surface = CreateCompatibleBitmap(screen, client.right, client.bottom);
  HGDIOBJ old_surface = SelectObject(dc, surface);

  HBRUSH background = CreateSolidBrush(kBackground);
  FillRect(dc, &client, background);
  DeleteObject(background);

  HGDIOBJ old_font = SelectObject(dc, S().font);
  SetBkMode(dc, TRANSPARENT);

  const int rows = VisibleRows();
  const std::vector<OutputLine> visible = S().line.Visible(
      static_cast<size_t>(rows));
  int y = kPadding;
  for (const OutputLine& row : visible) {
    SetTextColor(dc, ColourOf(row.severity));
    const std::wstring wide = Widen(row.text);
    TextOutW(dc, kPadding, y, wide.c_str(), static_cast<int>(wide.size()));
    y += S().line_height;
  }

  // The rule and the prompt sit at the bottom, where a terminal puts them.
  const int prompt_y = client.bottom - kPadding - S().line_height;
  HPEN pen = CreatePen(PS_SOLID, 1, kRule);
  HGDIOBJ old_pen = SelectObject(dc, pen);
  MoveToEx(dc, kPadding, prompt_y - 5, nullptr);
  LineTo(dc, client.right - kPadding, prompt_y - 5);
  SelectObject(dc, old_pen);
  DeleteObject(pen);

  SetTextColor(dc, kPrompt);
  const std::wstring prompt = L"> ";
  TextOutW(dc, kPadding, prompt_y, prompt.c_str(),
           static_cast<int>(prompt.size()));
  const int text_x = kPadding + S().character_width * 2;
  SetTextColor(dc, kOutput);
  const std::wstring typed = Widen(S().line.Text());
  TextOutW(dc, text_x, prompt_y, typed.c_str(), static_cast<int>(typed.size()));

  if (S().caret_on) {
    const std::wstring before = Widen(S().line.Text().substr(0, S().line.Cursor()));
    SIZE extent = {};
    GetTextExtentPoint32W(dc, before.c_str(), static_cast<int>(before.size()),
                          &extent);
    RECT caret = {text_x + extent.cx, prompt_y, text_x + extent.cx + 2,
                  prompt_y + S().line_height};
    HBRUSH brush = CreateSolidBrush(kPrompt);
    FillRect(dc, &caret, brush);
    DeleteObject(brush);
  }

  if (S().line.ScrollOffset() > 0) {
    SetTextColor(dc, kNotice);
    const std::wstring marker =
        L"-- scrolled back " + std::to_wstring(S().line.ScrollOffset()) +
        L" line(s); PageDown to return --";
    TextOutW(dc, kPadding, client.bottom - kPadding - S().line_height * 2,
             marker.c_str(), static_cast<int>(marker.size()));
  }

  BitBlt(screen, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);
  SelectObject(dc, old_font);
  SelectObject(dc, old_surface);
  DeleteObject(surface);
  DeleteDC(dc);
  EndPaint(window, &paint);
}

LRESULT CALLBACK ConsoleProc(HWND window, UINT message, WPARAM w, LPARAM l) {
  switch (message) {
    case WM_PAINT:
      Paint(window);
      return 0;
    case WM_ERASEBKGND:
      return 1;                       // Paint fills everything; no flicker
    case WM_NCHITTEST:
      return HTTRANSPARENT;           // the mouse still belongs to the game
    case WM_MOUSEACTIVATE:
      return MA_NOACTIVATE;
    default:
      return DefWindowProcW(window, message, w, l);
  }
}

RECT GameRect() {
  RECT rect = {0, 0, 1280, 400};
  const misery::input::Status status = misery::input::Read();
  if (status.window == 0) return rect;
  HWND game = reinterpret_cast<HWND>(status.window);
  RECT client = {};
  POINT origin = {0, 0};
  if (GetClientRect(game, &client) && ClientToScreen(game, &origin)) {
    rect.left = origin.x;
    rect.top = origin.y;
    rect.right = origin.x + (client.right - client.left);
    rect.bottom = origin.y +
                  static_cast<int>((client.bottom - client.top) * kHeightFraction);
  }
  return rect;
}

bool EnsureWindow() {
  if (S().window != nullptr) return true;

  WNDCLASSEXW klass = {};
  klass.cbSize = sizeof(klass);
  klass.lpfnWndProc = ConsoleProc;
  klass.hInstance = GetModuleHandleW(nullptr);
  klass.lpszClassName = kClassName;
  RegisterClassExW(&klass);           // an already-registered class is fine

  const RECT rect = GameRect();
  S().window = CreateWindowExW(
      WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
      kClassName, L"", WS_POPUP, rect.left, rect.top, rect.right - rect.left,
      rect.bottom - rect.top, nullptr, nullptr, GetModuleHandleW(nullptr),
      nullptr);
  if (S().window == nullptr) {
    S().last_refusal = "the console window could not be created";
    return false;
  }
  SetLayeredWindowAttributes(S().window, 0, kAlpha, LWA_ALPHA);

  if (S().font == nullptr) {
    S().font = CreateFontW(kFontHeight, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           FIXED_PITCH | FF_MODERN, L"Consolas");
    HDC dc = GetDC(S().window);
    HGDIOBJ previous = SelectObject(dc, S().font);
    TEXTMETRICW metrics = {};
    GetTextMetricsW(dc, &metrics);
    S().line_height = metrics.tmHeight + 2;
    S().character_width = metrics.tmAveCharWidth;
    SelectObject(dc, previous);
    ReleaseDC(S().window, dc);
  }
  return true;
}

void Show() {
  if (!EnsureWindow()) return;
  const RECT rect = GameRect();
  SetWindowPos(S().window, HWND_TOPMOST, rect.left, rect.top,
               rect.right - rect.left, rect.bottom - rect.top,
               SWP_NOACTIVATE | SWP_SHOWWINDOW);
  S().dirty = true;
}

void Hide() {
  if (S().window != nullptr) ShowWindow(S().window, SW_HIDE);
}

// The whole visibility rule, in one place.
//
// Three independent facts, and the console is on screen only when all three
// agree: the developer opened it, MISERY is the active application, and it is
// not minimised. Losing activation hides the PRESENTATION and nothing else --
// the line being typed, the history and the scrollback are untouched, so
// Alt+Tab away and back leaves the console exactly as it was.
//
// This exists as one function because the bug it fixes was the absence of one.
// Minimise appeared to work while activation did not, and the reason was that
// nothing was deciding visibility at all: the overlay follows the game's client
// rect, a minimised window's rect collapses, and the overlay went with it. A
// rule that is an accident of geometry holds for the case that happens to
// collapse a rect and fails for every other one.
void ApplyVisibility() {
  const bool should_show = S().router.IsOpen() && S().active && !S().minimised;
  if (should_show) {
    Show();
    return;
  }
  Hide();
}

void Submit() {
  std::string command;
  if (!S().line.Submit(&command)) return;
  S().line.Write("> " + command, Severity::kEcho);
  const misery::console_backend::RunResult result =
      misery::console_backend::Run(command);
  if (!result.ran) {
    S().line.Write(result.refusal, Severity::kError);
    return;
  }
  ++S().commands_run;
  WriteEnvelope(result.envelope);
}

void CompleteNow() {
  const std::vector<std::string> names = misery::console_backend::CommandNames();
  const ConsoleLine::Completion completion = S().line.Complete(names);
  if (completion.candidates.size() > 1) {
    std::string listing;
    for (const std::string& candidate : completion.candidates) {
      listing += (listing.empty() ? "" : "  ") + candidate;
    }
    S().line.Write(listing, Severity::kNotice);
  } else if (completion.candidates.empty()) {
    S().line.Write("no command starts with that", Severity::kNotice);
  }
}

// The input source's watcher. Runs inside the window procedure, synchronously
// with the state change -- not from the frame pump, because a background or
// minimised game may not be getting frames, and a console that waited for one
// to hide itself would still be on screen over whatever the user switched to.
void OnWindowEvent(void*, misery::input::WindowEvent event) {
  switch (event) {
    case misery::input::WindowEvent::kActivated:
      S().active = true;
      break;
    case misery::input::WindowEvent::kDeactivated:
      S().active = false;
      break;
    case misery::input::WindowEvent::kMinimised:
      S().minimised = true;
      break;
    case misery::input::WindowEvent::kRestored:
      S().minimised = false;
      break;
  }
  // The router stops reading keys while the game is not the active application,
  // and keeps everything it already holds.
  S().router.SetActive(S().active && !S().minimised);
  ApplyVisibility();
  S().dirty = true;
}

// The input source's consumer. Returns whether the game gets the message.
bool OnMessage(void*, uint32_t message, uint32_t wparam, uint32_t) {
  using misery::input::Action;
  const misery::input::Decision decision = S().router.Route(message, wparam);
  switch (decision.action) {
    case Action::kNothing:
    case Action::kSwallowedChar:
      break;
    case Action::kOpen:
    case Action::kClose:
      ApplyVisibility();
      break;
    case Action::kText:
      S().line.InsertCharacter(decision.character);
      break;
    case Action::kSubmit:
      Submit();
      break;
    case Action::kBackspace:      S().line.Backspace(); break;
    case Action::kDeleteForward:  S().line.DeleteForward(); break;
    case Action::kCursorLeft:     S().line.CursorLeft(); break;
    case Action::kCursorRight:    S().line.CursorRight(); break;
    case Action::kCursorHome:     S().line.CursorHome(); break;
    case Action::kCursorEnd:      S().line.CursorEnd(); break;
    case Action::kHistoryPrevious: S().line.HistoryPrevious(); break;
    case Action::kHistoryNext:    S().line.HistoryNext(); break;
    case Action::kScrollUp:
      S().line.ScrollUp(static_cast<size_t>(VisibleRows()) / 2,
                        static_cast<size_t>(VisibleRows()));
      break;
    case Action::kScrollDown:
      S().line.ScrollDown(static_cast<size_t>(VisibleRows()) / 2);
      break;
    case Action::kComplete:
      CompleteNow();
      break;
  }
  if (decision.action != Action::kNothing) S().dirty = true;
  return decision.forward_to_game;
}

}  // namespace

bool Start(std::string* why) {
  if (S().started) return true;
  std::string reason;
  if (!misery::input::Attach(&reason)) {
    S().last_refusal = reason;
    if (why != nullptr) *why = reason;
    return false;
  }
  misery::input::SetConsumer(&OnMessage, nullptr);
  misery::input::SetWatcher(&OnWindowEvent, nullptr);
  {
    // WM_ACTIVATEAPP only arrives on a change, so the starting state is read
    // rather than assumed -- the framework starts while the game is loading,
    // which is a time a user may well be looking at something else.
    const misery::input::Status source = misery::input::Read();
    S().active = source.application_active;
    S().minimised = source.minimised;
    S().router.SetActive(S().active && !S().minimised);
  }
  S().started = true;
  S().line.Write("MISERY developer console. Tab completes, PageUp scrolls, "
                 "Escape closes.", Severity::kNotice);
  S().line.Write("misery:help lists the commands.", Severity::kNotice);
  return true;
}

bool Stop(std::string* why) {
  if (!S().started) return true;
  S().router.ForceClose();
  Hide();
  misery::input::SetConsumer(nullptr, nullptr);
  misery::input::SetWatcher(nullptr, nullptr);
  std::string reason;
  if (!misery::input::Detach(&reason)) {
    S().last_refusal = reason;
    if (why != nullptr) *why = reason;
    return false;                      // BLOCKED: the module must stay loaded
  }
  if (!misery::input::WaitQuiescent(500, 5000)) {
    const char* stuck = "the window procedure did not go quiet; the module is "
                        "not safe to unload";
    S().last_refusal = stuck;
    if (why != nullptr) *why = stuck;
    return false;
  }
  if (S().window != nullptr) {
    DestroyWindow(S().window);
    S().window = nullptr;
  }
  if (S().font != nullptr) {
    DeleteObject(S().font);
    S().font = nullptr;
  }
  S().started = false;
  return true;
}

void Tick() {
  misery::input::Tick();
  if (!S().started) return;

  // Reconcile against the source, which refreshed itself from the OS in the
  // Tick above. The watcher is the primary path and is synchronous; this is the
  // backstop for a state that produced no message we saw -- the framework
  // attaching while the game is ALREADY in front, so no WM_ACTIVATEAPP ever
  // arrives, or a re-arm onto a freshly created window.
  const misery::input::Status source = misery::input::Read();
  if (source.attached &&
      (source.application_active != S().active ||
       source.minimised != S().minimised)) {
    S().active = source.application_active;
    S().minimised = source.minimised;
    S().router.SetActive(S().active && !S().minimised);
    ApplyVisibility();
    S().dirty = true;
  }

  if (S().window == nullptr || !S().router.IsOpen() || !S().active ||
      S().minimised) {
    return;
  }

  // The overlay follows the game's client rect. A window that stayed where it
  // was after a resolution change would be a console hanging off the screen.
  const RECT want = GameRect();
  RECT have = {};
  GetWindowRect(S().window, &have);
  if (memcmp(&want, &have, sizeof(RECT)) != 0) {
    SetWindowPos(S().window, HWND_TOPMOST, want.left, want.top,
                 want.right - want.left, want.bottom - want.top,
                 SWP_NOACTIVATE);
    S().dirty = true;
  }

  const DWORD now = GetTickCount();
  if (now - S().caret_at >= 500) {
    S().caret_at = now;
    S().caret_on = !S().caret_on;
    S().dirty = true;
  }
  if (S().dirty) {
    S().dirty = false;
    InvalidateRect(S().window, nullptr, FALSE);
  }
}

bool IsOpen() { return S().router.IsOpen(); }

void SetToggleKey(uint32_t virtual_key) { S().router.SetToggleKey(virtual_key); }

uint32_t ToggleKey() { return S().router.ToggleKey(); }

void Announce(const std::string& text) {
  S().line.Write(text, Severity::kNotice);
  S().dirty = true;
}

Status Read() {
  Status status;
  status.started = S().started;
  status.open = S().router.IsOpen();
  status.visible = S().router.IsOpen() && S().active && !S().minimised;
  status.application_active = S().active;
  status.minimised = S().minimised;
  status.commands_run = S().commands_run;
  status.toggle_key = S().router.ToggleKey();
  status.last_refusal = S().last_refusal;
  return status;
}

}  // namespace console_ui
}  // namespace misery
