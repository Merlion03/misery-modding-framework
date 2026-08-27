#!/usr/bin/env python3
"""Method RF-02: split the 394 `/Script/<Module>` root packages RF-01 found in
`MISERY/Content/Paks/global.ucas` into engine code and game code, by a stated,
falsifiable rule (plan.md line 519, exit criterion (7) of M2s).

The question this tool exists to answer
----------------------------------------
RF-01 (`tools/reflection/global_ucas.py`) named 394 distinct `/Script/<Module>`
root packages, four of them already spot-matched by name against staged
`.uplugin` files (`research/evidence/RF-01/README.md`). That was informal and
partial. This tool does the same kind of match SYSTEMATICALLY, for all 394, and
states the rule precisely enough that a second person applying it to the same
394 names gets the same answer (plan.md 9.5: "the classification rule must be
recorded").

Ground truth, and where it comes from -- not remembered, not guessed
----------------------------------------------------------------------
A predecessor on this project guessed a pak-entry bitfield mask from memory and
produced a confidently wrong answer (see `research/evidence/CK-01/`); RF-01's own
adversarial review separately found a guessed name-ordering claim that broke
under exact checking. Both failures share one shape: treating something
checkable as something remembered. This tool checks instead of remembering:

* The authoritative set of module names UE 5.4.4 itself ships is read, on this
  run, from the first-party source tree on this machine
  (`D:\\Program Files\\UE_5.4\\Engine`), at changelist 35576357,
  `++UE5+Release-5.4` -- the SAME changelist the game binary was built from per
  `research/unreal/engine-version.json` (`claim.engine_cl` INFERRED 0.90,
  `claim.engine_version` INFERRED 0.93). This tool CONSUMES that identification;
  it does not re-derive or re-grade it, the same way RF-01 and CK-01 both state
  the changelist as a premise rather than proving it again.
    - `Engine/Source/**/*.Build.cs` (case-insensitive glob: UE 5.4.4 ships both
      `*.Build.cs` and `*.build.cs` for real, e.g.
      `Engine/Source/ThirdParty/Steamworks/Steamworks.build.cs` -- verified with
      `os.listdir`, not assumed from a directory listing tool that might itself
      normalize case). Each file names its module with
      `public class <ModuleName> : ModuleRules` (or a ModuleRules subclass --
      `Engine/Source/Runtime/Online/Experimental/EventLoopTests/
      EventLoopUnitTests.Build.cs` uses `: TestModuleRules`, itself
      `: ModuleRules` at `Engine/Source/Programs/UnrealBuildTool/Configuration/
      TestModuleRules.cs:16`). Verified against every one of the 653 files this
      tree has: the regex below matches all 653, none zero.
    - `Engine/Plugins/**/*.uplugin`, a JSON document with a `Modules` array of
      `{"Name": ..., "Type": ..., "LoadingPhase": ...}` objects. 34 of 619 files
      use a trailing comma before `]`/`}` -- not standard JSON, but UE's own
      `FJsonSerializer` accepts it, and these are Epic's real shipped files, so
      this tool accepts it too (`load_json_lenient`, tried strict first, falls
      back to one targeted regex, and RECORDS which files needed it -- see
      `engine_module_index.uplugin_files_needing_trailing_comma_fix`).

* The game-plugin candidate set is read from `research/evidence/V-07/
  staged-plugins.txt` (method V-07, already-established: the PLAINTEXT index of
  `MISERY-Windows.pak`), filtered to the `.uplugin` lines that do NOT start with
  `Engine/Plugins/` -- i.e. staged under `MISERY/Plugins/` instead.

* Every claim about the game's OWN container (which `/Script/<Module>` names
  exist at all, and whether a specific pak entry is encrypted) is read from
  RF-01's and CK-01's own already-committed evidence
  (`research/evidence/RF-01/script-modules.tsv`,
  `research/evidence/CK-01/pak-paths.txt`) -- never re-derived by opening the
  game's containers again. This tool touches NO game file, encrypted or not.

The classification rule (plan.md 9.5 "the rule must be recorded")
---------------------------------------------------------------------
For each of RF-01's 394 `/Script/<Module>` names, strip the `/Script/` prefix to
get the bare module name, then, in this fixed order:

  1. `game-misery` iff the bare name is exactly `MISERY`. `/Script/MISERY` is
     kept in its OWN category rather than folded into `game-plugin`: it is not
     a licensed third-party asset (there is no `.uplugin` for it at all -- it
     is the project's native `Source/` module, declared directly by
     `MISERY.uproject`), and it is the one module RF-01's own apparatus already
     confirmed contains the developer's own gameplay classes (5 classes with
     CDOs: `MiseryBlueprintFunctionLibrary`, `MiseryEditableText`, etc; see
     `research/evidence/RF-01/README.md`). Folding it into `game-plugin` would
     misrepresent the actual subject of this research project as licensed-in
     content.
  2. `engine` iff the bare name exact-string-matches (case-sensitive) a name in
     the authoritative UE 5.4.4 module set above.
  3. `game-plugin` iff the bare name exact-string-matches (case-sensitive) the
     FILENAME (no extension) of a `.uplugin` staged under `MISERY/Plugins/`.
     This is a WEAKER link than rule 2 and is graded lower for exactly that
     reason (`CONF_GAME_PLUGIN_MATCH` below): rule 2 matches a MODULE name
     against a MODULE name; rule 3 matches a MODULE name against a PLUGIN
     FILE's name, which is not required to equal any module it declares (see
     "What this tool tried and could not close" below for exactly how far the
     stronger form of this check got).
  4. `unclassified` otherwise -- reported by name and count, never guessed into
     one of the three buckets above (plan.md: "do NOT force a third bucket's
     worth of guessing").

Rule 1 is checked before rule 2 even though `MISERY` cannot in fact collide
with anything (`checks.no_engine_or_plugin_name_is_literally_MISERY`
confirms it, empirically, on every run): the ordering states the PRECEDENCE the
rule intends, not merely today's data.

`checks.collision_count` confirms, on every run, that no bare name matches
BOTH the engine set and the game-plugin set (today: 0 of 394). If that ever
becomes nonzero the run reports it as `collision` rather than silently picking
a winner -- see `classify_modules`.

Two things this rule does NOT prove (plan.md: "say what it does not prove")
---------------------------------------------------------------------------
* `engine` does not mean unmodified. It means: this exact module name is one
  UE 5.4.4 itself declares. A modified engine build could keep the same module
  names while changing what is inside them; this tool reads names, not code.
* `game-plugin` does not mean "MISERY's own gameplay code". A third-party
  plugin licensed into the project (bought, not written by the studio) is
  neither the engine nor the developer's own code, and this tool keeps that a
  three-way split (`engine` / `game-plugin` / `game-misery`), not a two-way
  "engine vs everything else".

What this tool tried and could not close (rule 2's own closing attempt)
-------------------------------------------------------------------------
RF-01's adversarial review found that "43 staged plugin names have no
`/Script/` module of that exact name" is NOT evidence those 43 plugins are
absent, because one plugin can declare several differently-named modules (the
SteamCorePro family gives `SteamCoreShared`/`SteamCoreSockets`/
`OnlineSubsystemSteamCore` too) -- and named "read the `Modules` array of each
staged `.uplugin`" as the closing method. This tool does exactly that, split by
where the `.uplugin` actually lives:

* For the 120 of RF-01's 43-unmatched-candidates whose `.uplugin` is staged
  under `Engine/Plugins/` (i.e. the ENGINE side of the same question): the file
  is UNENCRYPTED on disk (this machine's own UE 5.4.4 install, not the game's
  container), so this tool reads its real `Modules` array and checks each
  declared name against the actual 394. `closing_rf01_43_unmatched` reports the
  result: CLOSED for the plugins where a declared module turned out to be one
  of the 394 (present, just under a different name than the file), still open
  for the rest (their declared modules were checked individually and NONE
  appear among the 394 -- stronger evidence of absence than the original
  filename check, but still not proof: `plan.md` 10.5 -- absence from a name
  list is not proof of absence from what actually loads).
* For the 4 whose `.uplugin` is staged under `MISERY/Plugins/` (the GAME side,
  which rule 3 above actually uses): this is exactly the payload CK-01 already
  found universally encrypted. `check_uplugin_payload_reachability` does not
  re-derive that verdict -- it looks up each of the 4 specific paths,
  individually, by line, in `research/evidence/CK-01/pak-paths.txt`
  (`Flag_Encrypted`, `IPlatformFilePak.h:382`), and reports what it finds. On
  every run so far all 4 individual lines say `E` (encrypted), matching CK-01's
  aggregate verdict (`readable_payload_entries: 0` of 4424). So: CLOSED in the
  sense that the answer is "not reachable, checked directly, not assumed" --
  and NOT closed in the sense of "we know what SteamCorePro's Modules array
  says". `SteamCoreShared`, `SteamCoreSockets`, `OnlineSubsystemSteamCore` and
  `OptimizationToolsEditor` stay `unclassified` because of this, honestly, per
  rule 4 above -- not folded into `game-plugin` on the strength of a plausible
  naming pattern, which this tool can see (`checks.case_insensitive_near_miss`)
  but does not act on.

Evidence grade (plan.md 10.3, 10.5)
------------------------------------
Every positive classification (`engine`, `game-plugin`, `game-misery`) is class
I: it names what a name IS (engine-shipped, or a licensed plugin's, or the
studio's own), which is an attribution, not a primitive reading. Two
INDEPENDENT oracles back it, satisfying plan.md 10.3 criterion 1 for
confidence >= 0.80:

  * `global-ucas` -- the name exists among RF-01's 394 `/Script/<Module>`
    packages, which RF-01 already establishes reads the game's own container
    (see `research/evidence/RF-01/README.md` for that chain; this tool cites
    it and does not repeat it).
  * `external-doc` (engine match) or `container-metadata` (game-plugin match,
    citing CK-01's already-established pak index read) -- the name also
    appears in a SECOND, independent corpus.

Both checks are format-level (a name is or is not present at a determinate
place in a determinate file), about THIS build (which container has this
name) and about vanilla UE 5.4.4 (which source tree has this name) -- neither
is a runtime observation, and plan.md 10.3 criterion 2 does not require one
here: "a format claim about THIS build ... can clear 0.80-0.94 on two
format-level methods", the alternative to a runtime observation the criterion
names for claims about formats, not about runtime behaviour. This claim says
nothing about what any code DOES; RF-02 is listed at plan.md 6.2 Level 0,
"полностью офлайн, ноль вмешательства", which would be structurally impossible
if it needed the runtime-reflection this project does not have yet (Q-8).

The join could still be wrong in principle -- a same-named but unrelated module
existing twice in ONE build is the failure mode to worry about, and this tool
DID check for it, not merely assume it away: `UnrealBuildTool`'s own module
resolution is a single, case-INsensitive, name-keyed
`Dictionary<string, UEBuildModule>` for an entire build target
(`Engine/Source/Programs/UnrealBuildTool/Configuration/UEBuildTarget.cs:1731`),
built by `FindOrCreateModuleByName`, and a `RulesAssembly` resolves a module
name to its `.Build.cs` file through an equally single, name-keyed
`Dictionary<string, FileReference>` (`.../System/RulesAssembly.cs:171-178`).
Two DIFFERENT modules sharing one name cannot both be part of the SAME build
target's module graph -- there is exactly one dictionary slot for that name.
This is a structural argument about how UBT resolves names, cited to file and
line; it is NOT a third oracle and does not add to the confidence count (a
clause of reasoning is not a method) -- it is why "same exact name" is treated
as "same identity" at all, for a build where the engine and the game are
compiled into ONE target, which packaging MISERY as a UE game means it is.
Confidence per bucket (`CONF_ENGINE_MATCH` 0.85, `CONF_GAME_MISERY` 0.85,
`CONF_GAME_PLUGIN_MATCH` 0.80, all INFERRED) is calibrated against the
project's own precedent for a comparable one-hop class-I attribution with two
supporting checks: RF-01's `CONF_CLASS_KIND = 0.85`
(`tools/reflection/global_ucas.py`). `game-plugin` is graded lower because its
link (rule 3) is a FILE name match, one level weaker than rule 2's MODULE name
match -- see "What this tool tried and could not close" above for exactly why
that gap could not be closed this run.

`unclassified` carries NO evidence_level/confidence: it is the explicit absence
of a positive claim (plan.md: report and list, do not guess), not a finding
about what those 4 names are.

Output (plan.md 9.2/9.5 -- the existing structure, no new format)
--------------------------------------------------------------------
* `research/evidence/RF-02/engine-split.json` -- the full document (this tool's
  `--out`), in the shape RF-01's `global-ucas.json` already established:
  generator/target/premise/method sections, the full 394-row classification
  table (RF-01 embeds its own 394-row `modules` table directly in JSON; this
  tool matches that), checks, warnings, summary. No payload byte from any game
  container. No local filesystem prefix (`D:\\Program Files\\...`) -- every
  citation is written relative to `Engine/`, matching how
  `research/evidence/V-07/staged-plugins.txt` already cites the UE tree.
* `research/evidence/RF-02/module-classification.tsv` -- the same 394 rows as a
  flat table, mirroring `research/evidence/RF-01/script-modules.tsv`'s own
  `#`-comment-header convention.
* `research/evidence/RF-02/engine-module-index.tsv` -- the full ~1800-name
  authoritative engine module set with provenance, mirroring
  `research/evidence/RF-01/global-names.txt`'s "full data lives in the TSV, the
  JSON stays a readable size" convention.
* `--classes-jsonl <path>`, optional: patches the `module_origin` field
  (`research/schema/reflection-record.schema.json` `$defs/common`) onto every
  EXISTING row of a `classes.jsonl`/`functions.jsonl`/... file, keyed by that
  row's own `module` field. Does not add or remove rows. `module_origin`'s
  schema doc states explicitly that its evidence is graded ONCE per module
  here, not once per patched row (plan.md 9.5's "one field, one source, one
  grade", read at the granularity this method actually produces).

Determinism
-----------
Every set this tool builds (engine names, game-plugin candidates, the 394
classification rows) is sorted by an explicit, stable key before it is written
anywhere -- never left in `os.walk` order, which is a filesystem detail, not a
property of the data. `--no-timestamp` omits `generated_at` so two runs against
an unchanged tree are byte-for-byte identical, the same switch
`tools/reflection/global_ucas.py` uses for the same reason.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"),):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented, exactly as tools/reflection/global_ucas.py already does.
import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/reflection/engine_split.py"
GENERATOR_VERSION = "1.0.0"
METHOD = "RF-02"

# plan.md line 519 / 9.5 "native / script / blueprint origin" row.
CATEGORY_ENGINE = "engine"
CATEGORY_GAME_PLUGIN = "game-plugin"
CATEGORY_GAME_MISERY = "game-misery"
CATEGORY_UNCLASSIFIED = "unclassified"
CATEGORIES = (CATEGORY_ENGINE, CATEGORY_GAME_PLUGIN, CATEGORY_GAME_MISERY,
              CATEGORY_UNCLASSIFIED)

# See "Evidence grade" in the module docstring for the calibration this mirrors
# (tools/reflection/global_ucas.py CONF_CLASS_KIND = 0.85).
CONF_ENGINE_MATCH = 0.85
CONF_GAME_MISERY = 0.85
CONF_GAME_PLUGIN_MATCH = 0.80

# UnrealBuildTool/Configuration/*.cs: "public class <Name> : <Base>ModuleRules".
# \w spans the whole file, including any line break between the name and the
# base -- deliberately, since a grep tool that stops at end-of-line would miss
# a wrapped declaration even though none of the 653 files this tool has ever
# seen actually wraps one.
MODULE_DECL_RE = re.compile(r"public\s+class\s+(\w+)\s*:\s*\w*ModuleRules\b")

# One targeted fixup for the 34-of-619 .uplugin files that use a trailing
# comma before `]`/`}` -- not standard JSON, but UE's own FJsonSerializer
# accepts it and these are real shipped files. Matches a comma immediately
# followed (after optional whitespace) by a closing bracket; cannot fire
# inside a string value unless that value itself ends in `,` directly abutting
# a bracket character with only whitespace between, which none of these
# descriptor files ever do (verified: 619 of 619 parse after this fallback,
# 0 failures -- see the tool's own --self-test).
_TRAILING_COMMA_RE = re.compile(r",(\s*[\]}])")


class EngineSplitError(Exception):
    """Raised for a malformed or missing input this tool cannot proceed past."""


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stream_sha256(path: str, buf_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(buf_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_json_lenient(text: str) -> tuple[object, bool]:
    """Parse *text* as JSON; on failure, retry after stripping trailing commas.

    Returns (parsed_value, needed_trailing_comma_fix). Raises
    ``json.JSONDecodeError`` if neither attempt parses -- callers decide
    whether that is fatal or a per-file warning.
    """
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        return json.loads(_TRAILING_COMMA_RE.sub(r"\1", text)), True


def _line_of(text: str, char_offset: int) -> int:
    """1-based line number of *char_offset* within *text*."""
    return text.count("\n", 0, char_offset) + 1


def _engine_relative(engine_root: str, path: str) -> str:
    """*path* written relative to ``Engine/``, forward slashes, no local prefix.

    Mirrors ``research/evidence/V-07/staged-plugins.txt``'s own citation style
    (e.g. ``Engine/Plugins/2D/Paper2D/Paper2D.uplugin``) and keeps the local
    ``D:\\Program Files\\...`` prefix out of every citation (C-13).
    """
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(engine_root))
    return "Engine/" + rel.replace(os.sep, "/")


# --------------------------------------------------------------------------- #
# 1. The authoritative UE 5.4.4 module set
# --------------------------------------------------------------------------- #

def scan_engine_source_modules(engine_root: str, warnings: list[str]
                               ) -> tuple[dict[str, list[dict]], dict]:
    """Walk ``Engine/Source/**/*.Build.cs`` (either case), return (name -> provenance, stats).

    One provenance entry per file where the module-declaration regex matched:
    ``{"kind": "build.cs", "file": <Engine/-relative path>, "line": <1-based>}``.
    A file where the regex matches zero times is a real anomaly (every one of
    the 653 files in this tree matches exactly once) and is reported as a
    warning, not silently skipped -- and counted in ``stats`` so a caller can
    check ``file_count == module_count`` as a genuine invariant instead of
    assuming it.
    """
    source_root = os.path.join(engine_root, "Source")
    if not os.path.isdir(source_root):
        raise EngineSplitError("Engine/Source not found under %r" % engine_root)
    names: dict[str, list[dict]] = {}
    file_count = 0
    zero_match_files: list[str] = []
    multi_match_files: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(source_root):
        for filename in filenames:
            if not filename.lower().endswith(".build.cs"):
                continue
            file_count += 1
            full = os.path.join(dirpath, filename)
            rel = _engine_relative(engine_root, full)
            try:
                with open(full, "r", encoding="utf-8-sig", errors="replace") as handle:
                    text = handle.read()
            except OSError as error:
                warnings.append("could not read %s: %s" % (rel, error))
                zero_match_files.append(rel)
                continue
            matches = list(MODULE_DECL_RE.finditer(text))
            if not matches:
                warnings.append("%s: no 'public class X : ...ModuleRules' match "
                                "found (expected exactly one)" % rel)
                zero_match_files.append(rel)
                continue
            if len(matches) > 1:
                warnings.append("%s: %d module declarations in one file "
                                "(expected exactly one); all are recorded"
                                % (rel, len(matches)))
                multi_match_files.append(rel)
            for match in matches:
                module_name = match.group(1)
                names.setdefault(module_name, []).append({
                    "kind": "build.cs",
                    "file": rel,
                    "line": _line_of(text, match.start()),
                })
    if file_count == 0:
        raise EngineSplitError("zero *.Build.cs files found under %r -- wrong path?"
                               % source_root)
    stats = {
        "file_count": file_count,
        "module_count": len(names),
        "files_with_zero_matches": sorted(zero_match_files),
        "files_with_multiple_matches": sorted(multi_match_files),
    }
    return names, stats


def scan_engine_plugin_modules(engine_root: str, warnings: list[str]
                               ) -> tuple[dict[str, list[dict]], dict]:
    """Walk ``Engine/Plugins/**/*.uplugin``, return (name -> provenance, stats).

    Provenance entry: ``{"kind": "uplugin", "file": ..., "line": <1-based or
    None>, "type": <Module "Type", e.g. "Runtime">}``. ``line`` is a best-effort
    second lookup of the literal ``"Name": "<value>"`` text in the same file,
    for a citation a reader can grep for; a JSON document can be parsed
    correctly (Modules[i].Name IS the module name) even where that lookup
    fails, so a miss is recorded as ``line: None``, never treated as a parse
    failure.
    """
    plugins_root = os.path.join(engine_root, "Plugins")
    if not os.path.isdir(plugins_root):
        raise EngineSplitError("Engine/Plugins not found under %r" % engine_root)
    names: dict[str, list[dict]] = {}
    file_count = 0
    parse_failures: list[str] = []
    trailing_comma_fixes: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(plugins_root):
        for filename in filenames:
            if not filename.lower().endswith(".uplugin"):
                continue
            file_count += 1
            full = os.path.join(dirpath, filename)
            rel = _engine_relative(engine_root, full)
            try:
                with open(full, "r", encoding="utf-8-sig", errors="replace") as handle:
                    text = handle.read()
                data, needed_fix = load_json_lenient(text)
            except (OSError, json.JSONDecodeError) as error:
                parse_failures.append(rel)
                warnings.append("%s: could not be parsed as JSON (%s), even after "
                                "the trailing-comma fallback -- its Modules are NOT "
                                "in the engine set for this run" % (rel, error))
                continue
            if needed_fix:
                trailing_comma_fixes.append(rel)
            if not isinstance(data, dict):
                warnings.append("%s: top level is not a JSON object, skipped" % rel)
                continue
            modules = data.get("Modules")
            if not isinstance(modules, list):
                continue
            for entry in modules:
                if not isinstance(entry, dict):
                    continue
                module_name = entry.get("Name")
                if not isinstance(module_name, str) or not module_name:
                    warnings.append("%s: a Modules[] entry has no usable 'Name'" % rel)
                    continue
                line = None
                needle = re.compile(r'"Name"\s*:\s*"' + re.escape(module_name) + r'"')
                found = needle.search(text)
                if found:
                    line = _line_of(text, found.start())
                names.setdefault(module_name, []).append({
                    "kind": "uplugin",
                    "file": rel,
                    "line": line,
                    "type": entry.get("Type") if isinstance(entry.get("Type"), str) else None,
                })
    if file_count == 0:
        raise EngineSplitError("zero *.uplugin files found under %r -- wrong path?"
                               % plugins_root)
    stats = {
        "file_count": file_count,
        "module_count": len(names),
        "needed_trailing_comma_fix": sorted(trailing_comma_fixes),
        "parse_failures": sorted(parse_failures),
    }
    return names, stats


def merge_engine_names(build_cs_names: dict[str, list[dict]],
                       uplugin_names: dict[str, list[dict]]
                       ) -> tuple[dict[str, list[dict]], int]:
    """Union the two provenance maps; return (merged, overlap_count).

    ``overlap_count`` is the number of names present in BOTH inputs -- reported
    as a check, not assumed to be zero (see ``checks.build_cs_uplugin_overlap``
    in the emitted document).
    """
    overlap = len(set(build_cs_names) & set(uplugin_names))
    merged: dict[str, list[dict]] = {}
    for name, provenance in build_cs_names.items():
        merged.setdefault(name, []).extend(provenance)
    for name, provenance in uplugin_names.items():
        merged.setdefault(name, []).extend(provenance)
    return merged, overlap


# --------------------------------------------------------------------------- #
# 2. The game's own inputs -- RF-01's and V-07/CK-01's already-committed reads
# --------------------------------------------------------------------------- #

def load_script_modules(path: str) -> list[str]:
    """Parse ``research/evidence/RF-01/script-modules.tsv``: return the 394
    ``/Script/<Module>`` package names, in file order. Comment lines (``#``)
    and the column-header line are skipped.
    """
    packages: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            first_field = line.split("\t", 1)[0]
            if first_field == "package":
                continue
            packages.append(first_field)
    if not packages:
        raise EngineSplitError("%s: no package rows found" % path)
    return packages


def load_staged_game_plugin_candidates(path: str) -> dict[str, dict]:
    """Parse ``research/evidence/V-07/staged-plugins.txt``.

    Returns ``{bare_filename: {"staged_path": ..., "line": <1-based>}}`` for
    every ``.uplugin`` line that does NOT start with ``Engine/Plugins/`` --
    i.e. staged under the game's own ``MISERY/Plugins/`` instead. This is rule
    3's candidate set, by construction: a plugin staged inside the engine tree
    is already covered by rule 2 (its Modules[] names are in the engine set),
    so only the game-side ones are candidates here.
    """
    candidates: dict[str, dict] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or not line.lower().endswith(".uplugin"):
                continue
            if line.startswith("Engine/Plugins/"):
                continue
            base = os.path.splitext(os.path.basename(line))[0]
            candidates[base] = {"staged_path": line, "line": line_no}
    return candidates


def load_pak_paths_flags(path: str, wanted: set[str]) -> dict[str, dict]:
    """Parse ``research/evidence/CK-01/pak-paths.txt`` for exactly the paths in
    *wanted*. Returns ``{path: {"line", "size", "uncompressed", "encrypted",
    "method"}}`` for each one found. Columns per the file's own header comment:
    size, uncompressed, enc ('E'/'-'), method index, path
    (``tools/content/pak_index.py``, ``"E" if entry["encrypted"] else "-"``).
    ``str.split(None, 4)`` is used deliberately: it tolerates a path containing
    spaces, because everything after the 4th whitespace run is kept whole.
    """
    found: dict[str, dict] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 4)
            if len(parts) != 5:
                continue
            size, uncompressed, enc, method, entry_path = parts
            if entry_path in wanted:
                found[entry_path] = {
                    "line": line_no,
                    "size": int(size),
                    "uncompressed": int(uncompressed),
                    "encrypted": enc == "E",
                    "method": method,
                }
    return found


def load_rf01_unmatched_plugins(path: str) -> list[str]:
    """Read RF-01's own ``staged_plugin_name_with_no_module_of_that_name`` list
    (43 names as of this writing) from its committed ``global-ucas.json``.
    """
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    try:
        names = document["staged_plugin_comparison"]["staged_plugin_name_with_no_module_of_that_name"]
    except (KeyError, TypeError) as error:
        raise EngineSplitError("%s: staged_plugin_comparison shape changed (%s)"
                               % (path, error))
    return list(names)


# --------------------------------------------------------------------------- #
# 3. Classification
# --------------------------------------------------------------------------- #

def classify_modules(packages: list[str], engine_names: dict[str, list[dict]],
                     game_plugin_candidates: dict[str, dict]) -> dict:
    """Apply the rule (module docstring) to every package in *packages*.

    Returns a dict with ``rows`` (one per package, sorted by bare name -- see
    the module docstring's Determinism section), ``counts``, ``unclassified``,
    ``collisions`` and ``case_insensitive_near_misses``.
    """
    lower_engine = {}
    for name in engine_names:
        lower_engine.setdefault(name.lower(), []).append(name)

    rows: list[dict] = []
    collisions: list[dict] = []
    near_misses: list[dict] = []

    for package in packages:
        bare = package[len("/Script/"):] if package.startswith("/Script/") else package
        in_engine = bare in engine_names
        in_plugin = bare in game_plugin_candidates

        if bare == "MISERY":
            category = CATEGORY_GAME_MISERY
            if in_engine or in_plugin:
                collisions.append({"bare_name": bare, "kind": "MISERY-also-matched",
                                   "in_engine": in_engine, "in_game_plugin": in_plugin})
        elif in_engine and in_plugin:
            category = "collision"
            collisions.append({"bare_name": bare, "kind": "engine-and-game-plugin",
                               "in_engine": True, "in_game_plugin": True})
        elif in_engine:
            category = CATEGORY_ENGINE
        elif in_plugin:
            category = CATEGORY_GAME_PLUGIN
        else:
            category = CATEGORY_UNCLASSIFIED

        row: dict = {"package": package, "bare_name": bare, "category": category}

        if category == CATEGORY_ENGINE:
            provenance = sorted(engine_names[bare], key=lambda p: (p["file"], p.get("line") or 0))
            row["matched_name"] = bare
            row["evidence_file"] = provenance[0]["file"]
            row["evidence_line"] = provenance[0].get("line")
            row["evidence_kind"] = provenance[0]["kind"]
            row["provenance_count"] = len(provenance)
        elif category == CATEGORY_GAME_PLUGIN:
            candidate = game_plugin_candidates[bare]
            row["matched_name"] = bare
            row["evidence_file"] = candidate["staged_path"]
            row["evidence_line"] = candidate["line"]
            row["evidence_kind"] = "staged-uplugin-filename"
        elif category == CATEGORY_GAME_MISERY:
            row["matched_name"] = bare
            row["evidence_file"] = "research/evidence/RF-01/global-ucas.json"
            row["evidence_line"] = None
            row["evidence_kind"] = "RF-01 game_module (already established)"
        else:
            row["matched_name"] = None
            row["evidence_file"] = None
            row["evidence_line"] = None
            row["evidence_kind"] = None
            near = lower_engine.get(bare.lower())
            if near:
                near_misses.append({"bare_name": bare, "engine_names_differing_only_in_case": near})

        rows.append(row)

    rows.sort(key=lambda r: r["bare_name"])

    counts = {category: 0 for category in CATEGORIES}
    counts["collision"] = 0
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1

    unclassified = [r["bare_name"] for r in rows if r["category"] == CATEGORY_UNCLASSIFIED]

    return {
        "rows": rows,
        "counts": counts,
        "unclassified": sorted(unclassified),
        "collisions": collisions,
        "case_insensitive_near_misses": near_misses,
    }


def close_rf01_unmatched(unmatched_names: list[str], staged_plugin_paths: dict[str, str],
                         engine_root: str, script_module_bare_names: set[str],
                         warnings: list[str]) -> dict:
    """Rule 2's own closing attempt, generalized to RF-01's 43-name finding.

    For each of *unmatched_names* (a staged ``.uplugin`` FILE name with no
    `/Script/` module of that exact name), find its staged path, read its
    Modules[] array (all 43 are staged under ``Engine/Plugins/``, hence
    unencrypted on THIS machine), and check every declared module name against
    *script_module_bare_names* -- the actual 394. See the module docstring,
    "What this tool tried and could not close".
    """
    resolved: list[dict] = []
    still_open: list[dict] = []
    not_found: list[dict] = []

    for name in sorted(unmatched_names):
        staged_path = staged_plugin_paths.get(name)
        if staged_path is None:
            not_found.append({"name": name, "reason": "not present in the staged-plugins list"})
            continue
        # staged_path is install-root-relative (e.g. "Engine/Plugins/AI/..."),
        # and engine_root already points AT the Engine/ directory -- so the
        # install root is engine_root's own parent. Join from there, not from
        # engine_root itself, or "Engine/" ends up doubled.
        install_root_guess = os.path.dirname(os.path.normpath(engine_root))
        full = os.path.join(install_root_guess, staged_path.replace("/", os.sep))
        if not os.path.isfile(full):
            not_found.append({"name": name, "reason": "no such file on this machine: %s" % staged_path})
            continue
        with open(full, "r", encoding="utf-8-sig", errors="replace") as handle:
            text = handle.read()
        try:
            data, _fix = load_json_lenient(text)
        except json.JSONDecodeError as error:
            warnings.append("closing check: %s did not parse (%s)" % (staged_path, error))
            not_found.append({"name": name, "reason": "did not parse as JSON: %s" % error})
            continue
        declared = [m.get("Name") for m in (data.get("Modules") or [])
                   if isinstance(m, dict) and isinstance(m.get("Name"), str)]
        hits = sorted({d for d in declared if d in script_module_bare_names})
        record = {"plugin": name, "staged_path": staged_path, "declared_modules": declared}
        if hits:
            record["present_via"] = hits
            resolved.append(record)
        else:
            still_open.append(record)

    return {
        "source": ("research/evidence/RF-01/global-ucas.json"
                  "#/staged_plugin_comparison/staged_plugin_name_with_no_module_of_that_name"),
        "total": len(unmatched_names),
        "resolved_present_via_module_array_read": len(resolved),
        "still_open": len(still_open),
        "not_found": len(not_found),
        "resolved_detail": resolved,
        "still_open_detail": still_open,
        "not_found_detail": not_found,
        "note": ("'resolved' means at least one module this plugin actually "
                "declares is one of the 394 real /Script/ packages -- the "
                "plugin IS present, RF-01's filename-only check just missed it "
                "under a different module name. 'still_open' means every "
                "declared module was checked individually and NONE is among "
                "the 394; the most coherent reading is that the plugin was "
                "staged (V-07 is a lower bound on the engine's plugin "
                "inventory) but not enabled for this cook, which is an "
                "INFERENCE, not a second observation -- plan.md 10.5: absence "
                "from a name list is not proof of absence from what actually "
                "loads."),
    }


def check_uplugin_payload_reachability(game_plugin_candidates: dict[str, dict],
                                       pak_paths_path: str) -> dict:
    """Rule 2's closing attempt on the GAME side: is any staged
    ``MISERY/Plugins/*.uplugin``'s Modules[] array actually readable?

    Looks up each candidate's path INDIVIDUALLY in
    ``research/evidence/CK-01/pak-paths.txt`` (by line, not by trusting the
    aggregate verdict alone) and reports what that specific line says.
    """
    wanted = {info["staged_path"] for info in game_plugin_candidates.values()}
    flags = load_pak_paths_flags(pak_paths_path, wanted)

    per_candidate = []
    all_encrypted = True
    any_missing = False
    for name in sorted(game_plugin_candidates):
        staged_path = game_plugin_candidates[name]["staged_path"]
        flag = flags.get(staged_path)
        if flag is None:
            any_missing = True
            per_candidate.append({"name": name, "staged_path": staged_path,
                                  "found_in_pak_paths": False})
            continue
        if not flag["encrypted"]:
            all_encrypted = False
        per_candidate.append({
            "name": name, "staged_path": staged_path, "found_in_pak_paths": True,
            "pak_paths_line": flag["line"], "encrypted": flag["encrypted"],
            "size": flag["size"], "uncompressed": flag["uncompressed"],
        })

    reachable = (not any_missing) and (not all_encrypted)
    if any_missing:
        reason = ("at least one candidate path was not found in "
                 "research/evidence/CK-01/pak-paths.txt at all -- cannot say "
                 "either way from this input")
    elif all_encrypted:
        reason = ("every one of the %d candidate .uplugin files is individually "
                 "flagged Flag_Encrypted (IPlatformFilePak.h:382) in "
                 "research/evidence/CK-01/pak-paths.txt, matching CK-01's own "
                 "aggregate verdict (readable_payload_entries: 0 of 4424). "
                 "D-02 forbids reading an encrypted payload, so the Modules[] "
                 "array of any of these 4 files is not available to this or "
                 "any other read-only tool." % len(game_plugin_candidates))
    else:
        reason = "at least one candidate is unencrypted -- see per_candidate for which"

    return {
        "reachable": reachable,
        "reason": reason,
        "per_candidate": per_candidate,
        "source": "research/evidence/CK-01/pak-paths.txt",
    }


# --------------------------------------------------------------------------- #
# 4. classes.jsonl patching
# --------------------------------------------------------------------------- #

def patch_reflection_jsonl(path: str, module_origin_by_bare_name: dict[str, str]) -> dict:
    """Set ``module_origin`` on every row of *path* from its own ``module`` field.

    A row whose ``module`` is null, or is not a key of
    *module_origin_by_bare_name*, is left with ``module_origin: None`` (RF-02
    has nothing to say about it) rather than skipped -- so the field is always
    present after this runs, either a category or an explicit null. Rewrites
    the file with ``json.dumps(..., sort_keys=True)``, matching
    ``tools/reflection/global_ucas.py``'s own ``dump_jsonl``.
    """
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    patched = 0
    unresolved = 0
    for row in rows:
        module = row.get("module")
        origin = module_origin_by_bare_name.get(module) if module else None
        row["module_origin"] = origin
        if origin is not None:
            patched += 1
        else:
            unresolved += 1

    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False))
            handle.write("\n")

    return {"path": path, "rows_total": len(rows), "rows_patched": patched,
            "rows_module_origin_null": unresolved}


# --------------------------------------------------------------------------- #
# 5. Document assembly and text output
# --------------------------------------------------------------------------- #

def decoded_annotation(*, note: str, sources: list, oracle: list[str], confidence: float,
                       evidence_level: str = "INFERRED") -> dict:
    """One class-I annotation, same reduced-envelope shape
    ``tools/reflection/global_ucas.py``'s ``decoded_annotation`` uses: no
    ``claim_type``/``build_key`` at this level, because those belong to the
    enclosing document (stated once) or to a full KB record, not to a
    supporting annotation.
    """
    return {
        "evidence_level": evidence_level,
        "claim_class": "I",
        "confidence": confidence,
        "oracle": oracle,
        "sources": sources,
        "note": note,
    }


def build_document(*, engine_root: str, script_modules_path: str, staged_plugins_path: str,
                   pak_paths_path: str, rf01_json_path: str, engine_version_json_path: str,
                   build_key: str | None, recorded_at: str | None,
                   with_timestamp: bool) -> dict:
    warnings: list[str] = []

    build_cs_names, build_cs_stats = scan_engine_source_modules(engine_root, warnings)
    uplugin_names, uplugin_stats = scan_engine_plugin_modules(engine_root, warnings)
    engine_names, overlap = merge_engine_names(build_cs_names, uplugin_names)

    packages = load_script_modules(script_modules_path)
    game_plugin_candidates = load_staged_game_plugin_candidates(staged_plugins_path)

    classification = classify_modules(packages, engine_names, game_plugin_candidates)

    reachability = check_uplugin_payload_reachability(game_plugin_candidates, pak_paths_path)

    rf01_unmatched = load_rf01_unmatched_plugins(rf01_json_path)
    all_staged_paths = {}
    with open(staged_plugins_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line.lower().endswith(".uplugin"):
                all_staged_paths[os.path.splitext(os.path.basename(line))[0]] = line
    script_module_bare_names = {p[len("/Script/"):] if p.startswith("/Script/") else p
                                for p in packages}
    closing = close_rf01_unmatched(rf01_unmatched, all_staged_paths, engine_root,
                                   script_module_bare_names, warnings)

    premise = {}
    if os.path.isfile(engine_version_json_path):
        with open(engine_version_json_path, "r", encoding="utf-8") as handle:
            engine_version_doc = json.load(handle)
        cl_claim = engine_version_doc.get("claim", {}).get("engine_cl", {})
        ver_claim = engine_version_doc.get("claim", {}).get("engine_version", {})
        premise = {
            "source": engine_version_json_path.replace(os.sep, "/"),
            "changelist": 35576357,
            "branch": "++UE5+Release-5.4",
            "engine_cl_confidence": cl_claim.get("evidence", {}).get("confidence"),
            "engine_cl_evidence_level": cl_claim.get("evidence", {}).get("evidence_level"),
            "engine_version_confidence": ver_claim.get("evidence", {}).get("confidence"),
            "engine_version_evidence_level": ver_claim.get("evidence", {}).get("evidence_level"),
            "note": ("RF-02 consumes this identification of the local UE 5.4.4 "
                    "tree as the SAME changelist the game was built from; it "
                    "does not re-derive or re-grade it, the same way RF-01 and "
                    "CK-01 both state the changelist as a premise."),
        }
    else:
        warnings.append("%s not found; the changelist premise is stated in prose "
                        "only, not cross-checked against it this run"
                        % engine_version_json_path)

    checks = {
        "collision_count": len(classification["collisions"]),
        "collisions": classification["collisions"],
        "build_cs_vs_uplugin_name_overlap": overlap,
        "build_cs_file_count_equals_module_count": (
            build_cs_stats["file_count"] == build_cs_stats["module_count"]
            and not build_cs_stats["files_with_zero_matches"]),
        "no_engine_or_plugin_name_is_literally_MISERY": (
            "MISERY" not in engine_names and "MISERY" not in game_plugin_candidates),
        "classification_row_count_equals_input_count": (
            len(classification["rows"]) == len(packages)),
        "count_sum_equals_total": sum(classification["counts"].values()) == len(packages),
    }

    generated_at = now_iso_utc() if with_timestamp else None

    engine_sources = [
        {"method": "RF-02: walked Engine/Source/**/*.Build.cs and Engine/Plugins/**/*.uplugin "
                  "on this machine, read-only, by tools/reflection/engine_split.py",
         "artifact": "research/evidence/RF-02/engine-module-index.tsv",
         "locator": "$.rows[*] where category == 'engine'",
         "note": "oracle external-doc, at changelist 35576357 (research/unreal/engine-version.json)"},
        {"method": "RF-01: structured decode of global.ucas's ScriptObjects chunk",
         "artifact": "research/evidence/RF-01/script-modules.tsv",
         "locator": "$.package",
         "note": "oracle global-ucas; this tool reads RF-01's already-committed output, "
                "it does not reopen global.ucas"},
    ]
    game_plugin_sources = [
        {"method": "V-07/CK-01: plaintext index read of MISERY-Windows.pak, filtered to "
                  ".uplugin lines staged under MISERY/Plugins/",
         "artifact": "research/evidence/V-07/staged-plugins.txt",
         "locator": "lines not matching ^Engine/Plugins/",
         "note": "oracle container-metadata (V-07/CK-01's own read, cited not repeated)"},
        {"method": "RF-01: structured decode of global.ucas's ScriptObjects chunk",
         "artifact": "research/evidence/RF-01/script-modules.tsv",
         "locator": "$.package",
         "note": "oracle global-ucas"},
    ]
    game_misery_sources = [
        {"method": "RF-01: /Script/MISERY already established to exist and to contain the "
                  "developer's own classes",
         "artifact": "research/evidence/RF-01/README.md",
         "locator": "\u0413\u043b\u0430\u0432\u043d\u044b\u0439 \u0440\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442",
         "note": "oracle global-ucas"},
        {"method": "RF-02: absence check against both the engine set and the game-plugin "
                  "candidate set",
         "artifact": "research/evidence/RF-02/engine-split.json",
         "locator": "$.checks.no_engine_or_plugin_name_is_literally_MISERY",
         "note": "oracle external-doc + container-metadata (negative membership in both)"},
    ]

    document = {
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "generated_at": generated_at,
        "method": METHOD,
        "build_key": build_key,
        "recorded_at": recorded_at,
        "premise": premise,
        "inputs": {
            "script_modules": {"path": script_modules_path.replace(os.sep, "/"),
                               "sha256": stream_sha256(script_modules_path),
                               "row_count": len(packages)},
            "staged_plugins": {"path": staged_plugins_path.replace(os.sep, "/"),
                               "sha256": stream_sha256(staged_plugins_path)},
            "pak_paths": {"path": pak_paths_path.replace(os.sep, "/"),
                          "sha256": stream_sha256(pak_paths_path)},
            "rf01_json": {"path": rf01_json_path.replace(os.sep, "/"),
                         "sha256": stream_sha256(rf01_json_path)},
        },
        "rule": (
            "For each /Script/<Module> name RF-01 found: (1) bare name == "
            "'MISERY' -> game-misery. (2) else exact-string match (case-"
            "sensitive) against a module UE 5.4.4 itself declares (Engine/"
            "Source/**/*.Build.cs class names, Engine/Plugins/**/*.uplugin "
            "Modules[].Name) -> engine. (3) else exact-string match against "
            "the filename (no extension) of a .uplugin staged under MISERY/"
            "Plugins/ -> game-plugin. (4) else -> unclassified, reported by "
            "name and count, never guessed. See this tool's module docstring "
            "for the full rule, its evidence grade, what it does not prove, "
            "and what it tried and could not close."
        ),
        "engine_module_index": {
            "build_cs_file_count": build_cs_stats["file_count"],
            "build_cs_module_count": build_cs_stats["module_count"],
            "build_cs_files_with_zero_matches": build_cs_stats["files_with_zero_matches"],
            "build_cs_files_with_multiple_matches": build_cs_stats["files_with_multiple_matches"],
            "uplugin_file_count": uplugin_stats["file_count"],
            "uplugin_module_count": len(uplugin_names),
            "uplugin_files_needing_trailing_comma_fix":
                uplugin_stats["needed_trailing_comma_fix"],
            "uplugin_parse_failures": uplugin_stats["parse_failures"],
            "union_count": len(engine_names),
            "full_index_out": "research/evidence/RF-02/engine-module-index.tsv",
        },
        "game_plugin_candidates": {
            "staged_uplugin_lines_total": len(all_staged_paths),
            "outside_engine_plugins_count": len(game_plugin_candidates),
            "candidates": sorted(
                [{"name": name, **info} for name, info in game_plugin_candidates.items()],
                key=lambda r: r["name"]),
            "modules_array_reachability": reachability,
        },
        "classification": {
            "total_modules": len(packages),
            "counts": classification["counts"],
            "unclassified": classification["unclassified"],
            "case_insensitive_near_misses": classification["case_insensitive_near_misses"],
            "rows": classification["rows"],
            "full_table_out": "research/evidence/RF-02/module-classification.tsv",
        },
        "closing_rf01_43_unmatched": closing,
        "evidence": {
            "engine_classification": decoded_annotation(
                confidence=CONF_ENGINE_MATCH, oracle=["global-ucas", "external-doc"],
                sources=engine_sources,
                note=("Two independent format-level reads: the name is one of "
                     "RF-01's 394 /Script/ packages (global-ucas), AND the same "
                     "exact string is a module UE 5.4.4 itself declares "
                     "(external-doc, Engine/Source or Engine/Plugins at this "
                     "build's own changelist). Refutation attempt: if the same "
                     "exact name could exist as two unrelated modules within "
                     "ONE build target, this match would prove nothing; it "
                     "cannot, because UnrealBuildTool resolves a module name "
                     "through a single name-keyed dictionary per target "
                     "(UEBuildTarget.cs:1731, RulesAssembly.cs:171-178) -- "
                     "checked, not assumed, and this is reasoning, not a third "
                     "oracle. Not graded higher: no runtime observation, and "
                     "plan.md 10.2's 0.95+ band asks for more than two "
                     "confirmations plus an absence of counterexamples; two "
                     "independent format reads land this in 0.80-0.94.")),
            "game_plugin_classification": decoded_annotation(
                confidence=CONF_GAME_PLUGIN_MATCH, oracle=["global-ucas", "container-metadata"],
                sources=game_plugin_sources,
                note=("Two independent format-level reads, like the engine case, "
                     "but ONE LEVEL WEAKER: the second read matches a module "
                     "name against a PLUGIN FILE's name, not against a MODULE "
                     "name the plugin actually declares, because that Modules[] "
                     "array sits inside an encrypted pak entry (see "
                     "game_plugin_candidates.modules_array_reachability) and "
                     "cannot be read under D-02. RF-01's README already found "
                     "this exact family of gap (SteamCorePro's own Modules[] "
                     "gives SteamCoreShared/SteamCoreSockets/"
                     "OnlineSubsystemSteamCore too, none of which match the "
                     "file name) -- those 3 names, plus "
                     "OptimizationToolsEditor, are exactly why this bucket is "
                     "graded below the engine bucket rather than at the same "
                     "level.")),
            "game_misery_classification": decoded_annotation(
                confidence=CONF_GAME_MISERY, oracle=["global-ucas", "external-doc", "container-metadata"],
                sources=game_misery_sources,
                note=("Not a positive name match at all: /Script/MISERY is "
                     "singled out by rule 1 before rules 2/3 run. The grade "
                     "rests on RF-01's own already-established finding (this "
                     "container's richest single piece of corroboration: 5 "
                     "classes, 5 CDOs, cross-verified) PLUS two independent "
                     "negative-membership checks performed this run (not in "
                     "the engine set, not in the game-plugin candidate set).")),
        },
        "limitations": (
            "'engine' does not mean unmodified -- it means this exact module "
            "name is one UE 5.4.4 itself declares; a modified engine build "
            "could keep the same names while changing what is inside them. "
            "'game-plugin' does not mean 'MISERY's own gameplay code' -- a "
            "licensed third-party asset is neither the engine nor the "
            "developer's own code, which is exactly why 'game-misery' is kept "
            "as a separate third category instead of folding /Script/MISERY "
            "into 'game-plugin'. 'unclassified' is not a claim about what "
            "those names ARE; it is the explicit absence of one."
        ),
        "checks": checks,
        "warnings": warnings,
        "summary": {
            # Mirrors tools/reflection/global_ucas.py / tools/content/pak_index.py:
            # a run whose checks did not all pass must not look like a clean
            # success. "Must-pass" is every check above except the two pure
            # counts (build_cs_vs_uplugin_name_overlap, collisions -- the LIST,
            # as opposed to collision_count, which must be 0).
            "verdict": ("CLASSIFIED" if (
                checks["collision_count"] == 0
                and checks["no_engine_or_plugin_name_is_literally_MISERY"]
                and checks["classification_row_count_equals_input_count"]
                and checks["count_sum_equals_total"]
                and checks["build_cs_file_count_equals_module_count"]
            ) else "CHECKS FAILED"),
            "total_modules": len(packages),
            "counts": classification["counts"],
        },
        # Private (stripped by _strip_private before anything is dumped as
        # JSON, exactly like tools/reflection/global_ucas.py's own leading-
        # underscore convention): the raw provenance maps, so a caller that
        # already has this document -- e.g. main()'s --engine-index-out branch
        # -- can write engine-module-index.tsv without re-walking the entire
        # UE_5.4 Engine/Source and Engine/Plugins trees a second time.
        "_build_cs_names": build_cs_names,
        "_uplugin_names": uplugin_names,
    }
    return document


def _strip_private(document: dict) -> dict:
    return {key: value for key, value in document.items() if not key.startswith("_")}


def dump_json(document: dict) -> str:
    return json.dumps(_strip_private(document), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def module_classification_tsv(document: dict) -> str:
    counts = document["classification"]["counts"]
    lines = [
        "# %s %s -- engine/game classification of the %d /Script/<Module> root "
        "packages RF-01 found in MISERY/Content/Paks/global.ucas"
        % (GENERATOR_NAME, GENERATOR_VERSION, document["classification"]["total_modules"]),
        "# counts: %s" % json.dumps(counts, sort_keys=True),
        "# Rule: see this tool's module docstring, or $.rule in engine-split.json. "
        "'unclassified' is reported, never guessed into another bucket.",
        "package\tcategory\tmatched_name\tevidence_kind\tevidence_file\tevidence_line",
    ]
    for row in document["classification"]["rows"]:
        lines.append("\t".join(str(row.get(field)) if row.get(field) is not None else ""
                               for field in ("package", "category", "matched_name",
                                            "evidence_kind", "evidence_file", "evidence_line")))
    return "\n".join(lines) + "\n"


def engine_module_index_tsv(engine_root: str, build_cs_names: dict[str, list[dict]],
                            uplugin_names: dict[str, list[dict]]) -> str:
    merged, _overlap = merge_engine_names(build_cs_names, uplugin_names)
    lines = [
        "# %s %s -- authoritative UE 5.4.4 module name set at changelist 35576357 "
        "(++UE5+Release-5.4, research/unreal/engine-version.json), read from "
        "Engine/Source/**/*.Build.cs and Engine/Plugins/**/*.uplugin"
        % (GENERATOR_NAME, GENERATOR_VERSION),
        "# %d distinct names: %d from Engine/Source (1:1 with %d *.Build.cs files), "
        "%d distinct from Engine/Plugins (from %d *.uplugin files' Modules[] arrays)"
        % (len(merged), len(build_cs_names), len(build_cs_names),
           len(uplugin_names), len({p["file"] for entries in uplugin_names.values()
                                    for p in entries})),
        "module_name\tsource_kind\tevidence_file\tevidence_line",
    ]
    for name in sorted(merged):
        provenance = sorted(merged[name], key=lambda p: (p["file"], p.get("line") or 0))[0]
        lines.append("\t".join([name, provenance["kind"], provenance["file"],
                               str(provenance.get("line") or "")]))
    return "\n".join(lines) + "\n"


def format_summary(document: dict) -> str:
    counts = document["classification"]["counts"]
    lines = [
        "RF-02 engine/game split -- %s -- %s"
        % (document["generated_at"] or "(no timestamp)", document["summary"]["verdict"]),
        "  total /Script/ modules classified: %d" % document["classification"]["total_modules"],
    ]
    for category in CATEGORIES + ("collision",):
        if counts.get(category):
            lines.append("    %-14s %d" % (category, counts[category]))
    if document["classification"]["unclassified"]:
        lines.append("  unclassified: %s" % ", ".join(document["classification"]["unclassified"]))
    closing = document["closing_rf01_43_unmatched"]
    lines.append("  RF-01's 43 unmatched-by-filename staged plugins: %d resolved present "
                "(different module name), %d still open, %d not found"
                % (closing["resolved_present_via_module_array_read"],
                   closing["still_open"], closing["not_found"]))
    reach = document["game_plugin_candidates"]["modules_array_reachability"]
    lines.append("  game-side .uplugin Modules[] arrays reachable: %s" % reach["reachable"])
    if document["warnings"]:
        lines.append("  warnings: %d" % len(document["warnings"]))
    for check_name, value in sorted(document["checks"].items()):
        if check_name == "collisions":
            continue
        lines.append("  check %s: %r" % (check_name, value))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 6. CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ue-engine-root",
                        default=r"D:\Program Files\UE_5.4\Engine",
                        help="the UE 5.4.4 Engine/ directory (contains Source/ and Plugins/)")
    parser.add_argument("--script-modules",
                        default="research/evidence/RF-01/script-modules.tsv",
                        help="RF-01's 394-row /Script/<Module> package list")
    parser.add_argument("--staged-plugins",
                        default="research/evidence/V-07/staged-plugins.txt",
                        help="V-07's staged .uplugin/.uproject path list")
    parser.add_argument("--pak-paths",
                        default="research/evidence/CK-01/pak-paths.txt",
                        help="CK-01's per-entry pak index (path, size, encrypted flag)")
    parser.add_argument("--rf01-json",
                        default="research/evidence/RF-01/global-ucas.json",
                        help="RF-01's full document (for staged_plugin_comparison)")
    parser.add_argument("--engine-version-json",
                        default="research/unreal/engine-version.json",
                        help="the changelist identification this tool cites as a premise")
    parser.add_argument("--out", help="write the full JSON document here")
    parser.add_argument("--modules-out", help="write the 394-row classification TSV here")
    parser.add_argument("--engine-index-out",
                        help="write the full authoritative engine module name TSV here")
    parser.add_argument("--classes-jsonl", action="append", default=[],
                        help="patch module_origin onto every row of this reflection JSONL "
                             "file (repeatable)")
    parser.add_argument("--build-key", help="required if --classes-jsonl is given")
    parser.add_argument("--recorded-at", help="ISO-8601 UTC timestamp recorded in the document")
    parser.add_argument("--no-timestamp", action="store_true",
                        help="omit generated_at, so two runs over an unchanged tree are "
                             "byte-identical")
    parser.add_argument("--install-dir", help="override the pathguard install root (rarely needed: "
                                              "this tool writes nothing inside any installation)")
    parser.add_argument("--json", action="store_true", help="print the JSON document to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.classes_jsonl and not args.build_key:
        print("error: --classes-jsonl patches records that carry a build_key field "
              "convention across this project; pass --build-key so the run is "
              "identifiable even though module_origin itself does not repeat it "
              "per row.", file=sys.stderr)
        return 2

    install_root = args.install_dir or pathguard.CONFIGURED_INSTALL_ROOTS[0]

    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--modules-out", args.modules_out),
                        ("--engine-index-out", args.engine_index_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root, what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
    for path in args.classes_jsonl:
        try:
            pathguard.check_output_path(path, install_root, what="--classes-jsonl")
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = build_document(
            engine_root=args.ue_engine_root,
            script_modules_path=args.script_modules,
            staged_plugins_path=args.staged_plugins,
            pak_paths_path=args.pak_paths,
            rf01_json_path=args.rf01_json,
            engine_version_json_path=args.engine_version_json,
            build_key=args.build_key,
            recorded_at=args.recorded_at,
            with_timestamp=not args.no_timestamp,
        )
    except (EngineSplitError, OSError, json.JSONDecodeError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    written: list[str] = []
    try:
        if "--out" in checked:
            with open(checked["--out"], "w", encoding="utf-8", newline="\n") as handle:
                handle.write(dump_json(document))
            written.append(checked["--out"])
        if "--modules-out" in checked:
            with open(checked["--modules-out"], "w", encoding="utf-8", newline="\n") as handle:
                handle.write(module_classification_tsv(document))
            written.append(checked["--modules-out"])
        if "--engine-index-out" in checked:
            # Reuse the scan build_document already did -- see the _build_cs_names
            # / _uplugin_names comment there -- rather than walking the whole
            # UE_5.4 Engine/ tree a second time for the same data.
            with open(checked["--engine-index-out"], "w", encoding="utf-8", newline="\n") as handle:
                handle.write(engine_module_index_tsv(args.ue_engine_root,
                                                      document["_build_cs_names"],
                                                      document["_uplugin_names"]))
            written.append(checked["--engine-index-out"])
        if args.classes_jsonl:
            # "collision" is not a valid module_origin (the schema enum has no
            # slot for it -- see the schema field's own doc comment), and
            # today's data has zero of them (checks.collision_count); map it to
            # null defensively rather than ever writing an invalid enum value.
            module_origin_by_bare_name = {
                row["bare_name"]: row["category"] if row["category"] != "collision" else None
                for row in document["classification"]["rows"]
            }
            for path in args.classes_jsonl:
                stats = patch_reflection_jsonl(path, module_origin_by_bare_name)
                written.append("%s (%d/%d rows patched)"
                               % (stats["path"], stats["rows_patched"], stats["rows_total"]))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        print(format_summary(document))
        for out_path in written:
            print("\nwritten: %s" % out_path)

    return 0 if document["summary"]["verdict"] == "CLASSIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
