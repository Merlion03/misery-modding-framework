# RUNNER — the unattended MISERY research cycle

```
python research/instruments/runner/runner.py cycle --probe recon
```

Automates the loop that has been done by hand between every probe since CR-01A:
tear down, close the game, prove it is gone, stage containers, verify integrity,
launch through Steam, find the new process, fingerprint it, wait for the runtime,
reach the configured save, **prove the player runtime from live objects**, and
only then start the probe.

> **RESEARCH ONLY.** Not a loader, not a mod framework, not a new gameplay
> capability. The runner introduces **no ABI primitive**, calls **no UFunction**,
> and writes **nothing** into the game process. Every game-side read it performs
> already existed in `research/instruments/eri` or in the CR-01C controllers.
> The Steam installation stays read-only (D-01); the one non-repository directory
> it may write to is `%LOCALAPPDATA%\MISERY\Saved\Paks`, and every write there
> goes through `tools/inventory/pathguard.check_output_path` first.
>
> Independent of CR-01C6. It does not touch the production-radio gate.

## Commands

| Command | What it does |
|---|---|
| `cycle --probe <name>` | The full lifecycle. `--skip-restart` reuses the running process. `--dry-run-staging` reports staging actions without performing them. `--verify-mode full` re-hashes the whole install instead of the fast size/mtime check. |
| `status` | Read-only: processes, staged containers, session state, registered probes. |
| `ready` | Prove the gameplay invariants against whatever is running now. Exit 0 = ready. |
| `calibrate [--exec-commands]` | Measure the current screen: object census, gameplay verdict, window, and every live `FUNC_Exec` function (i.e. the console commands this build supports). |

Registered probes are fail-closed by construction — a probe the runner can start
is one named in `runner.py`'s `PROBES`, not a path a caller passes in. Entries
marked `armed` mutate live game state and are refused without
`--allow-armed-probe` *and* their own escalation record (`plan.md` §8.4). The
runner never creates an escalation; it only refuses to bypass one.

## The twelve steps, and what proves each

| # | Step | Proof |
|---|---|---|
| 1 | Graceful probe shutdown | Attempted only when the recorded process is still live *and* the loading controller's addresses are in session state. Otherwise the module is left where it is and the report says so — it dies with the process in step 2. `probe_teardown.py`'s invariant (never `FreeLibrary` without a confirmed stop handshake) is respected by not being bypassed. |
| 2 | Close MISERY | `WM_CLOSE` to the top-level, owner-less window — the same event as clicking the X, so the engine runs its own shutdown. Escalates to `TerminateProcess` only on timeout, and the report names which happened. |
| 3 | Prove the old process is gone | Both halves: no process by that name, *and* none of the old pids alive. Identity is `(pid, start_time)`, never a bare pid — this workflow is exactly the one that makes pid reuse likely. |
| 4 | Container cleanup / staging | Declarative profile (`remove` / `stage` / `expect`). Every path passes the installation guard, and removal additionally requires the file to resolve to a direct child of the staging directory. `apply: false` (the default) verifies without changing anything. |
| 5 | Container + install integrity | Every `.utoc` in the staging directory is parsed: IoStore magic, version, unencrypted, unsigned, `TocCompressedBlockEntrySize == 12`, and **every compressed block inside the `.ucas` beside it** (a TOC/CAS pair from different builds fails exactly there). An *unexpected* container fails the gate too — the engine mounts a forgotten experiment as eagerly as an intended one. Then `verify_install.py` against this build's own baseline. |
| 6 | Launch | `steam://run/2119830` via ShellExecute. Not a preference: launching the exe directly was measured to exit immediately (LOG-0048). |
| 7 | Detect the NEW pid | Not in the excluded set, started at/after the launch request, and **exactly one** live copy. Two copies is an error, not a pick-the-first. |
| 8 | Fingerprint | sha256 of the image the OS actually mapped for that pid (`QueryFullProcessImageNameW`), compared to the configured build. A mismatch means Steam updated the game — which has happened once already. |
| 9 | Runtime inspection readiness | `GUObjectArray` located, `FNamePool` initialised, and the object census **settled**: three consecutive non-decreasing readings within `max(64, 0.1%)`. A measured predicate, never a sleep. |
| 10 | Reach the save | The UI state machine — see below. |
| 11 | **Prove gameplay** | See "The gate" below. This is the authoritative check; nothing the UI reports counts. |
| 12 | Start the probe | Registered probe, own subprocess, own run directory. |

## The gate (step 11)

Not "is there a pawn?". In a loaded MISERY session **34 live non-CDO
Pawn-derived actors** exist and **33 are AI** (`BP_CrayFish_C`,
`BP_ZombieSoilder_C`, `BP_Twins_C`). What is required is the *possessed* pawn:

```
unique self-referential UClass          identity anchor; without it the snapshot
                                        is not a UE object graph
exactly one live PlayerController       BP_SGKController_C
    -> AController::Pawn                RESOLVED by reflection on the live class
                                        (measured +720, never hardcoded)
    -> target is live, non-CDO,         derives from /Script/Engine.Pawn
    -> AcknowledgedPawn agrees          second, independently resolved field
                                        (+824); disagreement = mid-possession
exactly one live BP_PlayerInventory
    -> its Outer IS that controller     MEASURED: in MISERY (SurvivalGameKit) the
                                        inventory belongs to the CONTROLLER, not
                                        the pawn
a live GameModeBase-derived actor       authority: only the authority has one
no live NetDriver                       standalone; compared against `expect`
not a playtest-hub pawn                 the intro screen has a real pawn + real
                                        GameMode and is not the save
```

No offset here is guessed. `ClassPrivate` (+0x10), `NamePrivate` (+0x18) and
`OuterPrivate` (+0x20) are I-04's, confirmed live. `Pawn` and `AcknowledgedPawn`
are resolved per-run through `eri.walk_property_chain` — the same decoder
CR-01C4B used for `S_UIDetails.InventoryIcon`. `UStruct::SuperStruct` (+0x40) is
**self-checked on every class it touches**: a chain that does not terminate at
`/Script/CoreUObject.Object` yields the empty ancestor set, so every ancestry
question about it answers False rather than accidentally-True.

## Reaching the save — the ladder, and what was measured

The task's required order was followed, and each rung was **answered by
measurement** rather than assumed.

**Rung 1(a) — Steam / command-line launch.** Not closed. `steam://run/<appid>//<args>`
can pass arguments, but MISERY's save loading is SurvivalGameKit Blueprint logic
driven by the menu, not a map argument, so UE's own map-on-command-line would
land in a fresh world rather than the configured save. Recorded as untested and
low-yield rather than as a negative.

**Rung 1(b) — a supported console command. MEASURED, negative.**
`calibrate --exec-commands` enumerated every live `UFunction` carrying
`FUNC_Exec` at the main menu: **88 commands, all stock Unreal**
(`PlayerController`, `CheatManager`, `HUD`, `GameInstance`, `GameMode`,
`GameViewportClient`, `PlayerInput`, `AISystem`) plus exactly one game command,
`ModifyChanceFromSettings` on `BP_MasterInventory_C`. **There is no
game-provided continue/load-save console command.** `SwitchLevel` / `LocalTravel`
/ `OnlyLoadLevel` exist but travel to a map — they do not restore a save.

**Rung 2 — deterministic keyboard navigation. MEASURED, negative for the menu.**
`Down` and `Tab` at the main menu change nothing: the highlight does not move. It
is a pointer-driven UMG menu whose highlight follows the cursor (confirmed by
hovering — the highlight followed). Keyboard navigation *is* used where the game
offers it: the intro screen's own `НАЖМИТЕ [SPACE] ПРОДОЛЖИТЬ` prompt.

**Rung 3 — pointer input.** Required, and used only for the menu. Two things
keep it from being brittle pixel-poking: coordinates are **normalised to the
window client area** (0..1), so they survive a resolution change; and every
action is followed by an **observable transition check** plus a
**reclassification from the live object graph**.

### The state machine

A screen is identified by which Blueprint classes have live, non-CDO instances,
plus the live `World` names — not by pixels. First match wins, so order is part
of the table.

| State | Signature (measured) | Action |
|---|---|---|
| `THANK_YOU_SCREEN` | `WD_PlaytestNote01_C` live | one `Space` — the screen's own prompt |
| `LOAD_GAME_MENU` | `BP_SGKSaveGameMetaData_C` live + a `L_MenuMap*` world | click the configured save's row |
| `DEATH_SCREEN` | `BP_DeathScreen_C` live | **stops, by name** — see below |
| `MAIN_MENU` | `BP_MainMenu_C` + `BP_SGKMenuGameMode_C`, no note widget, no save metadata, `L_MenuMap*` world | ОДИНОЧНАЯ ИГРА, then ЗАГРУЗИТЬ ИГРУ |
| `WORLD_LOADING` | fallback: no `L_MenuMap*` world and no note widget | **nothing** — wait and watch the runtime |

`DEATH_SCREEN` was found the hard way: the acceptance session was left idle for
an hour and the character starved. MISERY is a survival game, so an unattended
loop **will** meet this screen. The runtime reported it precisely —
`BP_SGKMasterCharacter_C` dropped to zero live instances while the controller
survived, which is the gate's "the PlayerController possesses no pawn". The
screen offers *ВОЗРОДИТЬСЯ В БУНКЕРЕ* on Space and the runner **does not press
it**: respawning moves the character and changes what the next autosave records.
That is a gameplay decision, not a navigation step. The cycle stops with the
state named, and a human reloads or respawns.

Facts behind that table, each of which cost a wrong first draft:

* The intro screen **is** the "playtest hub" `RESEARCH_LOG` LOG-0060 finding 5
  recorded — same `BP_PlaytestBeginPlyer_C` / `PlaytestBeginPGmaemode_C`, 26 263
  live objects.
* The menu map's backdrop level is **chosen at random per launch**: `L_MenuMap07`
  and `L_MenuMap03` on consecutive launches. Pinning the exact name made the
  classifier fall through at an ordinary main menu, so it matches by prefix.
* The menu map **pre-instantiates every menu widget it owns**, so class presence
  cannot separate the main menu from its singleplayer sub-panel. That is why one
  state carries both clicks, verified by the sub-state they produce.
* `BP_SGKSaveGameMetaData_C` **stays live while the level loads**. Without the
  `WORLD_LOADING` fallback the machine reclassified as `LOAD_GAME_MENU` mid-load
  and clicked the save row a second time.

Two rules make it safe to run unattended:

1. **An unrecognised screen sends nothing.** It stops with the measured
   signature attached, which is exactly what a new table entry needs. The one
   permissive state is `WORLD_LOADING`, and it is permissive *because it never
   acts* — being generous about when to wait costs a timeout; being generous
   about when to click could start a new game over a save.
2. **The same state's action is never performed twice in a row.** A repeat
   becomes a wait.

### The save row is computed, not configured

`saves.py` parses `%LOCALAPPDATA%\MISERY\Saved\SaveGames\SaveGameMetaData.sav`
(a UE `GVAS` save) and orders the slots the way the menu does — **time
descending, verified against the rendered list**. The configured save is located
**by name**, and its row index is computed fresh each cycle.

This is not over-engineering. MISERY autosaves; an autosave updates its timestamp
and moves to the top of the list. A hardcoded row index would, sooner or later,
load a different save than the configured one, and **nothing downstream would
notice** — "a session loaded" looks identical either way.

The parser reads UE 5.4's real `FPropertyTag` layout, including
`FPropertyTypeName` (the pre-order `(FName, InnerCount)` node list introduced by
`PROPERTY_TAG_COMPLETE_TYPE_NAME`). Reading it as UE4's older single-`FName` type
is what makes a 5.4 save look corrupt. A save at a row beyond the visible list
fails closed: the runner does not scroll and will not click a row it cannot see.

## Environment: what the runner needs, and what it does not

**The Windows session must be unlocked.** `SendInput` delivers to the foreground
window on the current interactive desktop; a locked workstation has none. This is
checked *before* a sequence starts (`OpenInputDesktop`), so the failure reads
"the session is locked" rather than "the menu did not respond". Everything else
in the cycle — process control, memory reads, the whole gate — works on a locked
session; only the menu navigation does not.

**Focus.** The game must be foreground for input. Windows refuses
`SetForegroundWindow` from a background process and refuses *silently*, so the
runner (a) verifies the foreground window afterwards and raises if it did not
take, and (b) uses the documented `AttachThreadInput` mechanism to be permitted
the change. Focus is re-acquired and re-verified **before every step**, because
focus can be stolen mid-sequence. If it cannot be taken, nothing is sent — the
alternative is typing into whatever else had focus.

Focus is *not* needed for anything else: `ReadProcessMemory` works regardless, so
the census, the gate and the fingerprint are unaffected by which window is
active. Whether the engine itself throttles or pauses while unfocused was **not
measured**, and the runner does not depend on either answer — it waits on the
object graph, not on a frame rate.

**Resolution / window mode.** Measured on this machine: `FullscreenMode=1`
(windowed fullscreen) at 2560×1440, client rect `(0, 0, 2560, 1440)`. Pointer
coordinates are normalised to the client area, so they are resolution-independent
*by construction* — but that has **only been exercised at this one resolution**.
A different aspect ratio may move the menu panel relative to the client area;
`calibrate` plus one screenshot is the way to re-derive the four numbers in
`SAVE_ROW_GEOMETRY` and the two click points if it does.

**Timeouts and retries** (all in `runner-config.json`; every one bounds a
*measured predicate*, none stands in for evidence):

| Timeout | Default | Bounds |
|---|---|---|
| `prove_gone_s` | 30 | polling for process disappearance (WM_CLOSE gets 45 s before terminate) |
| `new_process_s` | 240 | Steam starting the game |
| `runtime_inspectable_s` | 300 | census settling |
| `save_entry_s` | 900 | the whole save-entry phase |
| `transition_timeout_s` | 240 | one screen transition — 240 because one of them is a level load |

Retry policy is deliberately narrow: `focus_window` retries (8 attempts) because
foreground acquisition is genuinely racy. **Nothing else retries.** An input that
produced no observable change is not repeated — it is reported. A cycle that
fails is a cycle that stops.

**Crash recovery.** The process is checked for liveness before every census, by
`(pid, start_time)`. If the game exited, the cycle stops with "the game process
exited during the cycle" and a pointer to `Saved/Crashes` — rather than surfacing
as an unreadable-memory error from inside the object walk, which reads like a
tool defect. A pid that is alive but is a *different* process is treated as a
crash plus a restart, not a survivor. No in-process state survives a crash by
construction (see below), so the next cycle starts clean; a probe module that was
loaded dies with its host, which is the safe direction.

**Addresses are never reused across a restart** — structurally, not by
discipline. `session.py`'s carry-across-restart method returns an object
containing only the non-address fields; there is no code path that copies an
address into the next process's state, because the function that would do it does
not exist. Session state is also rejected outright when the recorded pid's start
time does not match, which is how a reused pid is caught.

## Evidence per cycle

`research/instrument-runs/<timestamp>-runner/`:

| File | What |
|---|---|
| `manifest.json` | the project's existing instrument-run schema, via `ipp.write_manifest` (`capabilities_enabled: ["RUNNER-CYCLE"]`, `instrument_level: "eri"` — the runner reads and never writes) |
| `cycle.json` | every phase, its verdict, its facts: pids, start times, the fingerprint, the settle window, each UI state with what was sent and the signature it gained/lost, and the full gameplay facts (possession offsets, object paths, authority) |
| `containers.json` | the per-container parse and verdict |
| `verify_install_before.json` / `_after.json` | install integrity around the cycle |
| `probe-<name>.stdout.txt` | the probe's own output; the probe writes its own artifacts too |

Nothing about a cycle lives only in a terminal.

## What is NOT automated

* **Which save to load, and which containers to stage.** Declared in the config.
  The runner verifies; it does not decide.
* **Removing the accumulated probe containers** (`ArmProbe_P`, `ArmProbe2_P`,
  `ArmProbe3_P`, `Probe4_P`). `apply: false` by default — that is an open owner
  decision (LOG-0094), not the runner's.
* **Escalations.** An armed probe still needs its own `ESC-NN`.
* **Save-slot identity after loading.** The runner proves *a* gameplay session
  with a real player; it does not read back which save produced it. The row is
  computed by name from disk, which is what makes the click correct, but the
  loaded state itself is not fingerprinted. Pinning `expect.world_name` narrows
  this; it does not close it.

## What not to imitate in Phase 2

* **`SAVE_ROW_GEOMETRY` and the two menu click points** are four numbers measured
  from one build's UI at one resolution. A product does not navigate menus by
  coordinate.
* **The build sha256 in the config** is one build of one game, duplicated from
  `research/builds/index.json`. Fail-closed is right for research; a product
  resolves identity rather than declaring it.
* **The screen table is this build's**, including a developer typo
  (`BP_PlaytestBeginPlyer_C`) and a randomised backdrop-level prefix. It is a
  measurement, not an interface.
* **Everything stops on the first failure.** Correct for research — an honest
  stop beats a guess — and unacceptable for a product that needs graceful
  degradation.
