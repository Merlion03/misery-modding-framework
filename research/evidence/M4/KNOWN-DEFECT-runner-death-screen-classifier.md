# Known defect: the runner's DEATH_SCREEN classifier misfires after a death

**Status:** confirmed by measurement, **not fixed**. Recorded here rather than patched,
because the standing instruction is to extend Runner v1 only in response to a demonstrated
workflow blocker, and this has not blocked a run yet.

## What was measured

After a successful respawn, with the player alive and possessing a pawn:

- exactly one live non-CDO `BP_DeathScreen_C` at `0x200abde2700`
  (InternalIndex 228193, SerialNumber 109885);
- `UObject::ObjectFlags = 0x8` — `RF_MirroredGarbage (0x40000000)` is **not** set, so this
  is not a destroyed-but-uncollected object. It is genuinely alive;
- its Outer is the **GameInstance**
  (`/Engine/Transient.GameEngine:BP_SGKGameInstance_C:BP_DeathScreen_C`), so it outlives
  level transitions;
- it **survived a garbage collection**: the live object count fell from ~203,900 to
  ~175,500 across the respawn and the old pawn's slot was freed in that window, while this
  object was not. Something holds a real reference to it. No reflected `FObjectProperty` on
  either the GameInstance or the PlayerController points at it, so the holder was not
  identified.

## Why that is a defect

`saveentry.py`'s DEATH_SCREEN entry is `require: ["BP_DeathScreen_C"]`, with no `forbid`, no
world constraint, `halt: True`, and it sits ahead of the permissive WORLD_LOADING fallback.
Measured on the current healthy state, `classify_state()` returns DEATH_SCREEN, and it is
the only entry whose requirements are satisfied.

**It does not halt a cycle today**, because both call sites consult the gameplay oracle
first (`saveentry.py:746` and `:821` return GAMEPLAY before reaching the classifier). But
once a death has occurred in a process the widget persists, so DEATH_SCREEN is returned for
every in-world state that is not *yet* proven gameplay — in particular WORLD_LOADING while a
save is loading.

That is exactly the recovery the entry's own message recommends: *"Reload the save or
respawn by hand, then run the cycle again."* In the same process, that recovery would raise
`HaltingScreen("the player character is dead")` mid-load, with the player alive. The advice
only works after a process restart.

Menu states are unaffected: LOAD_GAME_MENU and MAIN_MENU precede DEATH_SCREEN and carry
`world_prefix_include: "L_MenuMap"`.

## The smallest fix, when it is wanted

Add a discriminator that is measured rather than assumed. At a real death the player
character class drops to **zero** live instances (the runner's own README records this), and
after a respawn there is exactly one. So `forbid: ["BP_SGKMasterCharacter_C"]` on the
DEATH_SCREEN entry separates the two states using a signal already present in the signature.

Trade-off to weigh before applying it: if a real death screen ever coexists with a live
player character — a corpse not yet destroyed — the runner would stop halting and instead
fall through to WORLD_LOADING and eventually time out. That is a softer failure than a wrong
halt, but it **is** a change to a fail-closed rule and should be an explicit decision, not a
side effect of tidying.

## Separately

`screen_signature()` (`saveentry.py:375-393`) filters on `valid` and non-`Default__` only,
and does not exclude garbage objects. That is a latent gap of the same family — a destroyed
widget could still name a screen — though it is not the cause here, since this object is not
garbage.
