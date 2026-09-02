// console_line_harness.cpp -- the console's text state, off the game.
//
// THERE IS NO PYTHON ORACLE FOR THIS. The Stage 4.5 reference has a command
// registry and a dispatcher; it has no line editor, because it never had a UI.
// So these cases ARE the specification, and they are written as claims about
// behaviour rather than as expected strings, so that a change which breaks one
// tells you which promise it broke.
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "../MiseryRuntime/Internal/ConsoleLine.h"

using misery::console_ui::ConsoleLine;
using misery::console_ui::OutputLine;
using misery::console_ui::Severity;

namespace {

int g_failures = 0;

void Check(const char* what, bool ok, const std::string& detail = "") {
  if (!ok) ++g_failures;
  printf("  [%s] %s%s\n", ok ? "PASS" : "FAIL", what,
         (ok || detail.empty()) ? "" : ("  -- " + detail).c_str());
}

void Type(ConsoleLine* line, const char* ascii) {
  for (const char* c = ascii; *c; ++c) {
    line->InsertCharacter(static_cast<unsigned char>(*c));
  }
}

std::vector<std::string> Names() {
  return {"misery:help", "misery:mods", "misery:loadorder", "misery:log",
          "misery:caps", "misery:errors", "alphamod:scan"};
}

}  // namespace

int main() {
  printf("the console line:\n");

  // ---- typing and the cursor -------------------------------------------
  {
    ConsoleLine line;
    Type(&line, "misery:help");
    Check("typing builds the line", line.Text() == "misery:help", line.Text());
    Check("  ...with the cursor at the end", line.Cursor() == 11);
    line.CursorHome();
    Type(&line, "x");
    Check("typing at the cursor inserts there, not at the end",
          line.Text() == "xmisery:help", line.Text());
    line.Backspace();
    Check("Backspace removes the character before the cursor",
          line.Text() == "misery:help", line.Text());
    line.CursorEnd();
    line.Backspace();
    Check("  ...and at the end it removes the last one",
          line.Text() == "misery:hel", line.Text());
  }

  // ---- UTF-8, which is what the research measured arriving ---------------
  {
    ConsoleLine line;
    line.InsertCharacter(0x0444);          // Cyrillic ef
    Check("a Cyrillic character is stored as its two UTF-8 bytes",
          line.Text().size() == 2 && line.Cursor() == 2, line.Text());
    line.Backspace();
    Check("Backspace removes the whole character, not one byte",
          line.Text().empty() && line.Cursor() == 0,
          "a cursor between the two bytes would make invalid UTF-8");

    Type(&line, "ab");
    line.InsertCharacter(0x0451);          // the toggle key's own letter
    Type(&line, "cd");
    Check("mixed ASCII and Cyrillic round-trips",
          line.Text() == "ab\xd1\x91" "cd", line.Text());
    line.CursorHome();
    line.CursorRight();
    line.CursorRight();
    line.CursorRight();
    Check("Right steps OVER a multi-byte character, never into it",
          line.Cursor() == 4, std::to_string(line.Cursor()));
    line.CursorLeft();
    Check("  ...and Left steps back over it whole",
          line.Cursor() == 2, std::to_string(line.Cursor()));
    line.DeleteForward();
    Check("Delete removes the whole character at the cursor",
          line.Text() == "abcd", line.Text());
  }

  // ---- a surrogate pair is one character ---------------------------------
  {
    ConsoleLine line;
    line.InsertCharacter(0xD83D);          // high half alone: nothing yet
    Check("half a surrogate pair inserts nothing", line.Text().empty());
    line.InsertCharacter(0xDE00);          // low half completes it
    Check("  ...and the pair completes into one 4-byte character",
          line.Text().size() == 4, std::to_string(line.Text().size()));
    line.Backspace();
    Check("  ...which Backspace removes in one press", line.Text().empty());
  }

  // ---- control characters never enter the line ---------------------------
  {
    ConsoleLine line;
    Type(&line, "ab");
    line.InsertCharacter(0x08);            // Backspace's own character
    line.InsertCharacter(0x09);            // Tab's
    line.InsertCharacter(0x0D);            // Enter's
    line.InsertCharacter(0x1B);            // Escape's
    Check("no control character reaches the line", line.Text() == "ab",
          line.Text());
  }

  // ---- submitting and history --------------------------------------------
  {
    ConsoleLine line;
    std::string submitted;
    Check("a blank line is not submitted", !line.Submit(&submitted));
    Type(&line, "   ");
    Check("  ...nor is one that is only spaces", !line.Submit(&submitted));

    Type(&line, "  misery:mods  ");
    Check("submitting returns the trimmed line", line.Submit(&submitted) &&
          submitted == "misery:mods", submitted);
    Check("  ...and clears the line", line.Text().empty() && line.Cursor() == 0);
    Check("  ...and records it in history",
          line.History().size() == 1 && line.History()[0] == "misery:mods");

    Type(&line, "misery:mods");
    line.Submit(&submitted);
    Check("the same command twice in a row is one history entry",
          line.History().size() == 1,
          "a history full of repeats is a history nobody walks");

    Type(&line, "misery:caps");
    line.Submit(&submitted);
    line.HistoryPrevious();
    Check("Up recalls the newest entry", line.Text() == "misery:caps",
          line.Text());
    line.HistoryPrevious();
    Check("  ...and again recalls the one before", line.Text() == "misery:mods",
          line.Text());
    line.HistoryPrevious();
    Check("  ...and stops at the oldest rather than wrapping",
          line.Text() == "misery:mods", line.Text());
    line.HistoryNext();
    line.HistoryNext();
    Check("Down past the newest leaves an EMPTY line, not the newest again",
          line.Text().empty(), line.Text());
  }

  // ---- completion ---------------------------------------------------------
  {
    ConsoleLine line;
    Type(&line, "misery:l");
    ConsoleLine::Completion result = line.Complete(Names());
    Check("completion finds every command with the prefix",
          result.candidates.size() == 2,
          std::to_string(result.candidates.size()));
    Check("  ...and completes only as far as they agree",
          line.Text() == "misery:lo", line.Text());

    Type(&line, "g");
    result = line.Complete(Names());
    Check("a unique prefix completes to the whole name",
          line.Text() == "misery:log " && result.candidates.size() == 1,
          line.Text());
    Check("  ...with a trailing space, ready for an argument",
          line.Text().back() == ' ');

    ConsoleLine other;
    Type(&other, "zzz");
    result = other.Complete(Names());
    Check("a prefix nothing matches changes nothing",
          !result.applied && other.Text() == "zzz" && result.candidates.empty());

    ConsoleLine third;
    Type(&third, "misery:log extra");
    result = third.Complete(Names());
    Check("completion does not touch a line that already has an argument",
          !result.applied && third.Text() == "misery:log extra",
          "the registry does not describe arguments, so they are not guessed");
  }

  // ---- output and scrollback ----------------------------------------------
  {
    ConsoleLine line;
    line.Write("one\ntwo\nthree");
    Check("a multi-line write becomes separate lines",
          line.Scrollback().size() == 3, std::to_string(line.Scrollback().size()));
    Check("  ...in order", line.Scrollback()[0].text == "one" &&
                               line.Scrollback()[2].text == "three");
    line.Write("carriage\r\nreturn");
    Check("CRLF does not leave a stray carriage return",
          line.Scrollback()[3].text == "carriage", line.Scrollback()[3].text);

    ConsoleLine bounded;
    for (int i = 0; i < 600; ++i) bounded.Write("line " + std::to_string(i));
    Check("the scrollback is bounded", bounded.Scrollback().size() == 500,
          std::to_string(bounded.Scrollback().size()));
    Check("  ...and it is the OLDEST that were dropped",
          bounded.Scrollback().front().text == "line 100",
          bounded.Scrollback().front().text);
  }

  // ---- scrolling ----------------------------------------------------------
  {
    ConsoleLine line;
    for (int i = 0; i < 50; ++i) line.Write("line " + std::to_string(i));
    Check("the view starts at the bottom", line.ScrollOffset() == 0);
    std::vector<OutputLine> visible = line.Visible(10);
    Check("  ...showing the newest rows", visible.size() == 10 &&
          visible.back().text == "line 49", visible.back().text);

    line.ScrollUp(5, 10);
    visible = line.Visible(10);
    Check("scrolling up moves the window back", visible.back().text == "line 44",
          visible.back().text);

    line.ScrollUp(1000, 10);
    visible = line.Visible(10);
    Check("scrolling past the top stops at the oldest, not past it",
          visible.front().text == "line 0", visible.front().text);
    Check("  ...and still shows a full window", visible.size() == 10);

    line.ScrollDown(1000);
    Check("scrolling down returns to the bottom", line.ScrollOffset() == 0);

    line.ScrollUp(20, 10);
    line.Write("something new");
    Check("new output pins the view back to the bottom",
          line.ScrollOffset() == 0,
          "output you cannot see arriving is output you miss");
  }

  // ---- bounds --------------------------------------------------------------
  {
    ConsoleLine line;
    for (int i = 0; i < 2000; ++i) line.InsertCharacter('x');
    Check("the line is bounded", line.Text().size() == 1024,
          std::to_string(line.Text().size()));
    ConsoleLine history;
    std::string submitted;
    for (int i = 0; i < 150; ++i) {
      Type(&history, ("command" + std::to_string(i)).c_str());
      history.Submit(&submitted);
    }
    Check("history is bounded", history.History().size() == 100,
          std::to_string(history.History().size()));
    Check("  ...keeping the newest", history.History().back() == "command149",
          history.History().back());
  }

  printf("{\"ok\":%s,\"failures\":%d}\n", g_failures == 0 ? "true" : "false",
         g_failures);
  return g_failures == 0 ? 0 : 1;
}
