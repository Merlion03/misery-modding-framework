# CT-03 — pre-registration (written BEFORE the experiment ran)

Written 2026-08-28, before any snapshot was taken and before the test container
was placed anywhere the game could find it. The point of writing this first is
that a mounting experiment has exactly one cheap failure mode — deciding after
the fact what the result "really" showed — and the project's own rule for a
first-contact experiment is that the expectation is recorded in advance
(`docs/protection-assessment.md` §9.1 uses the same discipline for the first
ERI run).

## Question

Does the Shipping MISERY process discover and mount an external `.pak`
container placed in `%LOCALAPPDATA%\MISERY\Saved\Paks\`?

This is the *mounting* half of CT-05 and nothing more. It cannot and will not
answer whether a *package* loads: a `.pak` carries files, not packages, and in
this build packages come only from an IoStore container header
(`sp1-static-proxy.md` §8 п. 1). Any reading of a CT-03 pass as "external
content works" is out of scope by construction.

## Why this location needs no D-01 exception

`FPakPlatformFile::GetPakFolders` (`IPlatformFilePak.cpp:8132-8150`) scans
exactly three directories in Shipping, one of which is
`FPaths::ProjectSavedDir()/Paks/`. For this game `ProjectSavedDir()` resolves to
`%LOCALAPPDATA%\MISERY\Saved\` — outside the Steam installation — established
two ways in `LOG-0064`. So nothing is written into the game folder, D-01 is not
weakened, no `D-12` ADR is required, and `verify_install.py` stays clean by
construction rather than by inspection.

## The container

`workspace/ct03/CT03Probe20260828_P.pak`, produced by `tools/content/pak_writer.py`
(CT-01, `LOG-0066`) and independently accepted by `UnrealPak.exe -List`, which
reports one file:

    MISERY/Content/CT03Probe/ct03_marker.txt   104 bytes
    sha1 90C6EE19F8DF18FE9E0240FD3E4FEDD9BC4B7B05

Non-asset payload by design. The marker string `CT03-MOUNT-PROBE-8F4A2E1C`
appears nowhere else in this project or in the game, so a hit on it is
unambiguous.

The `_P` suffix is deliberate: it adds `100 × ChunkVersionNumber`
(`IPlatformFilePak.cpp:8486-8511`) to the base order of 1 that a path under
`ProjectSavedDir()` receives (`:8888-8891`), so a mounted probe should show
order **101** — a value no shipped container can have, since
`MISERY-Windows.pak` gets 4 (`:8876-8878`). The order is therefore a second,
independent identifying signal alongside the filename.

## Procedure

- **A — baseline.** Test container absent from every discovery directory.
  Snapshot the mounted-pak list of the running process with I-14.
- **B — candidate.** Copy the container to
  `%LOCALAPPDATA%\MISERY\Saved\Paks\CT03Probe20260828_P.pak`. Full restart of
  the game (paks are discovered at startup, so a running process cannot show
  it). Snapshot again with I-14.
- **C — compare.** Is our container present by filename? What mount point and
  what order did it receive?
- **D — removal control** (if B is positive and it is cheap): delete only our
  container, restart, snapshot, confirm the entry is gone.

## Expected outcomes, committed in advance

| Observation | Reading |
|---|---|
| A shows only `MISERY-Windows.pak`; B additionally shows `CT03Probe20260828_P.pak` with order 101; D shows it gone again | **PASS.** External containers are discovered and mounted from `Saved/Paks`. |
| A and B identical — our container absent in B | **FAIL-DISCOVERY.** Either the directory is not scanned as the source says, or the file was rejected before entering the list. Diagnose discovery/mount; do NOT start the cooker track. |
| B shows the container but with an unexpected order or mount point | **PASS-WITH-ANOMALY.** Mounting works; the priority model needs correcting. Record the observed values, do not retrofit the model. |
| I-14 cannot produce a trustworthy list at all | **INCONCLUSIVE.** Not a result about the game. Fix the instrument first; report no verdict on mounting. |

## What would make the result uninterpretable, and how each is prevented

- *Our container is malformed* — excluded in advance by CT-01: `UnrealPak.exe`
  itself parses it (`-Info`, `-List`), and a byte-diff against a container
  UnrealPak generated from identical input matched in total size and in all
  five region sizes (`LOG-0066`).
- *`UnrealPak -Test` "passing"* — explicitly not used as evidence. A negative
  control showed it returns a silent 0 on a deliberately corrupted payload
  (`LOG-0066` finding 3).
- *I-14 reporting garbage that looks plausible* — the instrument must first
  reproduce the known ground truth on the untouched process: exactly one pak,
  filename ending `MISERY-Windows.pak`, mount point `../../../`. I-14 is not
  trusted for B until it passes that on A.
- *Confusing "file visible" with "pak mounted"* — CT-03 observes the engine's
  own mounted-pak list, not the filesystem.

## Explicitly out of scope

No asset loading, no `ProcessEvent`-driven mount, no `P-03`, no cook, no
IoStore container. D-10 stays `OPEN BY DESIGN` and is revisited only after a
factual mounting verdict exists.
