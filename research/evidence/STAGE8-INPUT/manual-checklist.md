# Stage 8 — the developer console: your manual pass

**The game is open and waiting**, in gameplay on save `123`, with the framework
installed and the console attached. Nothing needs starting.

## The key

**`` ` `` / `~` — the same physical key as `Ё` on the Russian layout.**
One virtual key (`VK_OEM_3`) covers both, which the research measured rather
than assumed: it produced `` ` `` under the US layout and `ё` under the Russian
one. Press it again to close, or press **Escape**.

The console appears as a dark panel across the top ~40% of the screen. While it
is open the game gets no keyboard input at all — that is the point, and it is
the thing most worth checking by hand.

## In gameplay (where you are now)

1. **Open it.** The banner and two hint lines should already be there from
   startup.
2. Type `misery:help` and press Enter. Fourteen framework commands, plus
   **`refmod:status`** — a command the reference mod registered through the
   ordinary public API, with no privileged path.
3. Run the ones you named:
   `misery:mods` · `misery:caps` · `misery:generations` · `misery:settings` ·
   `misery:services` · `misery:errors`
   `misery:generations` should show a **live generation with a number** here,
   where at the menu it says nothing is attached.
4. **Tab completion.** Type `misery:l` then Tab — it should complete as far as
   `misery:lo` (two commands share that) and list both. Type `g` then Tab and it
   should finish `misery:log ` with a trailing space.
5. **History.** Up and Down walk what you have run; Down past the newest leaves
   an empty line rather than repeating.
6. **Scrolling.** PageUp / PageDown, with a marker at the bottom saying how far
   back you are.
7. **Capture.** With the console open, hold `W` — the character must not move,
   and the `w` should appear in the console line instead. Close it and `W` must
   move again. *(The character is currently wedged against something after the
   automated tests moved it; if `W` does nothing either way, turn first.)*
8. **Typing.** `Shift` for capitals, Backspace, Delete, Left/Right, Home/End.
   Try Cyrillic if you have the layout — the line is UTF-8 and a Backspace
   removes a whole letter, not half of one.

## Across a transition

9. With the console **open**, load a different save or restart the level.
   The console can be left open through it; the runtime should log a new
   generation and the game should not stall.
10. Afterwards, open the console and run `misery:generations` again — the
    generation number must have **changed**.

## At the main menu

11. Quit to the main menu (or restart the game) and open the console **before
    loading anything**. `misery:help`, `misery:caps` and `misery:mods` must all
    work with no world loaded. `misery:generations` will correctly say nothing
    is attached — that is the honest answer at a menu, not a failure.

## What I already verified, so you do not have to

* The console comes up in a normal Steam launch, before any world exists
  (`developer console ready on window 0x35007da (thread 5652)`), and the runtime
  independently measured the game thread as that same 5652.
* On screen, at the menu and in gameplay: the toggle covers the game (its own
  text drops from 76,672 pixels to 9), a command adds text, the toggle restores
  the game.
* With the console open a posted movement key moved the character 0.0 uu against
  an idle drift of 0.0; closed, the same key moved it.

## Known limits, stated rather than left to be found

* **Exclusive fullscreen.** The console is an overlay window. Nothing can
  composite over an exclusive-fullscreen swapchain from outside it, so if you
  switch the game to that mode the console will still work and will not be
  visible. Borderless (what the game runs here) is fine.
* **A mod cannot bind a key yet.** `misery:input` says so in as many words —
  `mod_bindings: false`. The delivery primitive exists and the console consumes
  it; the mod-facing binding is deliberately not designed yet.
* **The full support bundle is host-only** by the accepted Stage 8 decision D6.
  What the console shows is `misery:errors` (the structured error ring),
  `misery:caps` and `misery:generations`; the bundle itself is not a command,
  on purpose.
* **The reference mod's item is not live in this session.** Its content
  container was unstaged during this work to get past the runner's consistency
  gate, so `refmod__sample` loads its code and cannot place its row. That is a
  research-environment change, now reversed in the staging plan, and not a
  framework regression — `refmod:status` will still answer.
* **Your character moved.** The automated capture differential walked it a few
  tens of metres and it is currently against an obstacle. Nothing else in the
  world was touched.
