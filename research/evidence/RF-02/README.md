# RF-02 — engine vs game split of RF-01's 394 `/Script/<Module>` modules

Method RF-02 (`plan.md` line 519), closing exit criterion (7) of M2s. Ground truth is read live
from the first-party UE 5.4.4 source tree (`D:\Program Files\UE_5.4\Engine`, changelist 35576357),
not remembered — see `tools/reflection/engine_split.py`'s module docstring for the full citation
of every field and every quirk it accounts for (case-insensitive `.build.cs`, `ModuleRules`
subclasses, 34 `.uplugin` files with a non-standard trailing comma UE's own JSON reader tolerates).

## Rule

1. Bare name `MISERY` → `game-misery`.
2. Exact-string match (case-sensitive) against a module UE 5.4.4 itself declares
   (`Engine/Source/**/*.Build.cs` class names, `Engine/Plugins/**/*.uplugin` `Modules[].Name`) →
   `engine`.
3. Exact-string match against the filename (no extension) of a `.uplugin` staged under
   `MISERY/Plugins/` → `game-plugin`.
4. Else → `unclassified`, reported by name and count, never guessed.

## Result

| Class | Count |
|---|---|
| `engine` | 385 |
| `game-plugin` | 4 |
| `game-misery` | 1 |
| `unclassified` | 4 |

Zero collisions (no name matched two rules), all four internal consistency checks passed
(`build_cs_file_count_equals_module_count`, `classification_row_count_equals_input_count`,
`count_sum_equals_total`, `no_engine_or_plugin_name_is_literally_MISERY`).

**Unclassified (4):** `OnlineSubsystemSteamCore`, `OptimizationToolsEditor`, `SteamCoreShared`,
`SteamCoreSockets`. These are exactly the modules RF-01's adversarial review flagged as an
unverified "same plugin family" attribution — reported honestly as unclassified rather than
assigned, because `MISERY/Plugins/*.uplugin`'s own `Modules[]` arrays are **not reachable**
(`game-side .uplugin Modules[] arrays reachable: False` — those files are entries in
`MISERY-Windows.pak`, and per CK-01 every entry in that pak is encrypted; D-02/D-11 forbid
decryption).

**RF-01's "43 unmatched by filename" — partially closed, honestly.** For the `Engine/Plugins/`
side (readable, first-party, no encryption involved), the tool read each candidate plugin's real
`Modules[]` array and checked EVERY declared module name, not just the plugin's own top-level
name, against the 394. Result: 18 of 43 resolved (the plugin IS present, under a differently-named
module — e.g. `ChaosEditor` the plugin is present via its `FractureEditor` module, not a module
named `ChaosEditor`), 25 remain open (every declared module checked, none among the 394 — the most
coherent reading is "staged but not enabled for this cook", recorded as an INFERENCE per
plan.md 10.5, not a second observation), 0 not found at all. Full detail in
`engine-split.json:closing_rf01_43_unmatched`.

## What this does NOT prove

`engine` does not mean unmodified — a modified engine build could keep the same names. `game-plugin`
does not mean "MISERY's own gameplay code" — a licensed third-party plugin is neither the engine
nor the developer's own code (why `game-misery` is kept separate rather than folded into
`game-plugin`). `unclassified` is the explicit absence of a claim, not a claim about what those
four names are.

## Files

- `engine-split.json` — full document: rule, inputs, per-module classification, the 43-unmatched
  closing detail, checks, warnings, limitations.
- `module-classification.tsv` — the 394-row classification, one line per `/Script/<Module>`.
- `engine-module-index.tsv` — the full authoritative UE 5.4.4 module name index this tool built
  from the source tree (the ground truth the classification was checked against).
- `research/reflection/misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl` — patched in place:
  every row gained a `module_origin` field (all 5 rows are `/Script/MISERY` → `game-misery`, since
  RF-01's structured decode currently only covers that one module in JSONL form).

*(Classification claims: INFERRED, confidence 0.90, oracle: `global-ucas` + `external-doc`, class
I — two independent methods: (1) RF-01's structural decode of `global.ucas` for what names exist;
(2) live parse of the first-party UE 5.4.4 source tree for what UE itself declares. Neither read
the other's output; a match is a coincidence-checked join, not a restatement. Ceiling not higher
because a same-named-but-different module is possible in principle and was not separately ruled
out here — noted as an open edge case, not tested. build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383.)*

## How to reproduce

```
D:\Tools\venv-research\Scripts\python.exe tools\reflection\engine_split.py ^
  --ue-engine-root "D:\Program Files\UE_5.4\Engine" ^
  --script-modules research\evidence\RF-01\script-modules.tsv ^
  --staged-plugins research\evidence\V-07\staged-plugins.txt ^
  --pak-paths research\evidence\CK-01\pak-paths.txt ^
  --rf01-json research\evidence\RF-01\global-ucas.json ^
  --engine-version-json research\unreal\engine-version.json ^
  --out research\evidence\RF-02\engine-split.json ^
  --modules-out research\evidence\RF-02\module-classification.tsv ^
  --engine-index-out research\evidence\RF-02\engine-module-index.tsv ^
  --classes-jsonl research\reflection\misery-24826585-ue5.4.4-0eef3715244b\classes.jsonl ^
  --build-key sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383 ^
  --recorded-at 2026-08-23T00:00:00Z
```

Determinism: verified by a second run into a scratch directory with `--no-timestamp`. Both TSVs
matched byte for byte; the full JSON document matched field for field except the two timestamp
fields, which differed by design (one run used `--recorded-at`, the other `--no-timestamp`).
`tests/test_engine_split.py` (32 tests) covers the scanning and classification logic against
synthetic fixtures independent of the live UE tree or the game container.
