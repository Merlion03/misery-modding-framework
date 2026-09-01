# Stage 5B — closure

The research controller is off the user's execution path. A player starts MISERY
from Steam and gets a modded game; nothing in that sequence involves Python, an
injector, or an address anybody typed in.

    Steam Play
      -> MiseryBootstrap (dwmapi proxy)     exact build fingerprint, fail closed
      -> MiseryRuntime                      binding profile verified against live code
      -> resolver on the game thread        bounded slices, published as generations
      -> content generation                 revocable, validated at point of use
      -> discovery + load plan              Stage 4 semantics, in-process
      -> CoreCLR + Misery.ModHost           only planned mods
      -> C# mods                            items the game's own lookup resolves

This record cites the checkpoints rather than restating them. Each was accepted
on live evidence at the time; none is re-run here.

## Checkpoints

| What was proven | Commit | Evidence |
|---|---|---|
| Bootstrap on the normal Steam launch path, fail-closed | `d576dfb` | `stage5b-failclosed.json` |
| Framework starts from a Steam launch; resolver on the game thread | `6c993c7` | `stage5b-resolver-oracle-crosscheck.json` |
| Bounded multi-tick resolver, measured rather than guessed | `6129815` | `stage5b-gamethread-cost.json` |
| Liveness from the engine's bookkeeping, not an object's own bytes | `d982ed6` | `tests/test_slot_validation.py` |
| Step 2: the runtime starts the native subsystems by itself | `49768a3` | `stage5b-subsystems.json`, `stage5b-bindings-acceptance.json` |
| Content anchors become revocable generations, across a real load | `4316b99` | `stage5b-resolver-lifecycle.json`, `stage5b-resolver-race.json` |
| Step 3 part 1: production Items backend, gated on the live generation | `1985318` | — |
| Step 3: a C# mod registers an item the game itself can find | `b660a82` | `stage5b-managed-items.json` (11/11) |
| Step 3 part 2: a real transition, caused and survived | `50d4f7c` | `stage5b-transition.json` (15/15) |
| Step 4: Stage 4's discovery and load plan, in the runtime | `e4ca753` | `stage5b-step4-loadplan.json` (16/16) |

Reasoning and measurements for each are in `STAGE5B-ACCEPTANCE.md`.

## The invariants Stage 5B leaves standing

* No Python, controller or injector on the production path.
* Unknown build fails closed; every code address re-checked against live bytes.
* No hardware breakpoints, vtable hooks, `.text` detours or guessed RVAs.
* Object resolution happens on the game thread, in bounded slices; the longest
  measured slice across these runs is ~7.2 ms and the walk is chunked at 2 ms.
* A content generation is validated at the point of use, so a consumer cannot
  hold anchors from a world that no longer exists.
* A mod's item registration is a declaration the framework re-applies per world.
* Discovery and planning are Stage 4's, held to it by a differential test.
* No raw `UObject`/`FName`/`ProcessEvent` in the public C# surface.
* The installation is additive only: `MiseryFramework/` plus the `dwmapi.dll`
  proxy. Verified while active (16 findings, all `added`, none modified or
  removed) and after uninstall — a full re-hash of all 52 baseline files reports
  **MATCH**. `stage5b-install-while-active.json`,
  `stage5b-install-after-uninstall.json`.

## Known limitation, deferred

    natural map-to-map lifecycle:
        New Game -> preparation area -> generated main zone

The transition gate was proven with a controlled `RestartLevel`
(`stage5b-transition.json`). That is a real transition — it destroyed and
recreated the player inventory, and the generation machinery revoked, re-resolved
and reapplied correctly — but it left the persistent item tables alive at
byte-identical addresses. The game's own transfer from the start area to the
generated main zone should replace those too, exercising anchors that run saw
survive.

Wanted as a later regression, recorded at `9f778df`. It does not block closure:
the property under test — that no consumer can use a revoked generation — was
proven on the evidence available, and the anchors that did change were verified
by slot identity rather than by address.

## What Stage 5B deliberately did not do

Nothing here touches gameplay classes, Blueprint inheritance, or the Mod Kit's
authoring path. Items were the vehicle because Stage 2 had already proven that
path end to end; they are not the boundary of what a mod should be able to do.
That is Stage 6's question.
