#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Knowledge-base validator for the MISERY Phase 1 research repository.

Implements plan.md task K-03 (section 9.4) plus the evidence-model linters
EV-03 and EV-04 (section 10.4), the oracle matrix of section 10.5 and the
hard constraint C-11 (section 0.2 / A-08).

Three layers run over the repository.  Layers 1 and 2 cover the machine-
readable artifacts under research/; layer 3 covers the markdown documents
under research/, docs/ AND the repository root (plan.md, AGENTS.md, README.md,
NOTICE.md), where 100% of the M0 facts actually live:

  1. JSON Schema validation against research/schema/*.schema.json.
     Uses the `jsonschema` package when it is importable; otherwise falls
     back to a small built-in validator (required / type / enum / bounds /
     pattern / items / contains / uniqueItems / allOf / anyOf / oneOf / not /
     if-then-else, and $ref both local and to a sibling schema file).  A
     missing `jsonschema` is NOT an error: the backend actually used, and
     every schema keyword it had to ignore, are printed in the report.

  2. Project-specific lint rules.  This is the part that carries the real
     value, because a JSON Schema cannot express "this oracle does not
     prove this class of claim".  TWO evidence-bearing shapes are recognised
     here and each gets its own rule set: the FULL knowledge-base record
     (lint_record) and the REDUCED evidence annotation attached to a
     sub-object of a larger artifact (lint_annotation, section 5b).  The
     annotation is held to every rule its schema can satisfy and to none it
     forbids, and the number of annotations linted is printed in the summary.

  3. Markdown fact extraction and linting (section 6b below).  Every *.md
     file under research/, docs/ and the repository root is parsed for the
     three fact notations the documents actually use - fact tables, inline
     annotations and RESEARCH_LOG entry blocks - and the same evidence rules
     are applied to what is found.  A candidate that cannot be read is
     counted and reported as a violation, never skipped.

Claim classes (plan.md 10.3 v2.2).  Confirmation criteria are split by claim
class: class P (a single reading of a primitive property - existence, path,
name, size, mtime, hash, a count of those, or a literal field value of a
structured text format) needs ONE method plus five criteria; class I (anything
with a decoding, attribution or inference step) needs >= 2 independent methods
at confidence >= 0.80.  The class is DERIVED from oracle + claim_type (plus the
wording of the claim, for criterion 3); an explicit `claim_class` that
contradicts the derived one is itself a violation (EV-05), and a record packing
a primitive and an interpretive claim together is rejected with a demand to
split it (MIX-SPLIT).  Where no oracle is named the class is UNDETERMINED and
the class-dependent criteria are not applied - the run says so per record
instead of inferring a class from missing data.  What this file can and cannot
check mechanically is printed in the report's DISCLOSURES block on every run -
not buried in a docstring.

Exemptions are named, counted and printed (EXEMPTIONS block).  There is exactly
one: DEF-TABLE, a table whose level column enumerates the level VOCABULARY
(plan.md 10.1 `Уровень | Определение | Примеры`) rather than grading claims.
Nothing in plan.md is exempt as a graded fact: 10.2 states that the 1.00 ban
applies to the tables inside plan.md itself, Appendix A included.

Exit codes:
    0  no violations (warnings may still be present)
    1  at least one violation
    2  bad invocation / internal error

Severities:
    ERROR  a violation; always fails the run
    WARN   a defect that a document CAN fix; --strict turns it into a violation
    NOTE   a by-design disclosure that no document can fix (e.g. the inline
           notation has nowhere to put a second method).  NOTEs are printed
           and counted, and --strict deliberately does NOT escalate them,
           because a gate that cannot be satisfied is switched off within a
           week.  See the DISCLOSURES block of the report.

Usage:
    python tools/kb/validate.py
    python tools/kb/validate.py --json
    python tools/kb/validate.py research/builds/index.json
    python tools/kb/validate.py --strict          # warnings become violations
    python tools/kb/validate.py --no-markdown     # JSON layers only
    python tools/kb/validate.py --require-jsonschema   # degraded backend fails
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Collection, Iterator, Sequence

VALIDATOR_VERSION = "3.4.0"
PLAN_REFERENCE = (
    "plan.md: 9.1, 9.3, 9.4/K-03, 10.1, 10.2 v2.3 (the 0.99 ceiling as a "
    "COMPARISON), 10.3 v2.3 (evidence_level decides the claim class), "
    "10.3 v2.4 (class P by the NATURE of the claim: binary-analysis and "
    "container-metadata are admissible only with a stated offset AND length), "
    "10.4/EV-03..EV-05, 10.5 v2.1 (nine-oracle vocabulary), 17.3/C-12, "
    "0.2/C-11, 18.3 item 5"
)

# ---------------------------------------------------------------------------
# Optional dependency: jsonschema
# ---------------------------------------------------------------------------

try:  # pragma: no cover - depends on the environment, both paths are exercised
    import jsonschema as _jsonschema  # type: ignore
except Exception:  # noqa: BLE001 - any import failure means "not available"
    _jsonschema = None

HAVE_JSONSCHEMA = _jsonschema is not None
SCHEMA_BACKEND = "jsonschema" if HAVE_JSONSCHEMA else "builtin-minimal"


# ---------------------------------------------------------------------------
# 1. Artifact -> schema mapping table (explicit, no magic)
# ---------------------------------------------------------------------------
# Patterns are POSIX-style, relative to the research/ root.
# "*" matches inside one path segment only; segment count must match.
# First matching rule wins.
# File list source: plan.md section 19 ("Expected artifacts", research/).

KIND_JSON = "json"          # whole file is one JSON document
KIND_JSONL = "jsonl"        # one JSON object per line
KIND_MARKDOWN = "markdown"  # prose document carrying facts in the 6b notations


@dataclass(frozen=True)
class ArtifactRule:
    pattern: str
    schema: str | None      # None = deliberately schema-free artifact
    kind: str
    note: str = ""


ARTIFACT_SCHEMA_MAP: tuple[ArtifactRule, ...] = (
    # --- build identity (sections 2.2, 3.1, 3.2) ---
    ArtifactRule("builds/index.json", "build-index.schema.json", KIND_JSON,
                 "build_key -> build_id registry, plan.md 3.2"),
    ArtifactRule("builds/*/install.json", "install.schema.json", KIND_JSON,
                 "plan.md 2.2"),
    ArtifactRule("builds/*/install-inventory.json", "install-inventory.schema.json", KIND_JSON,
                 "plan.md 1.5 layer 3"),
    ArtifactRule("builds/*/fingerprint.json", "fingerprint.schema.json", KIND_JSON,
                 "plan.md 3.1"),
    # --- engine identity (section 4.3) ---
    ArtifactRule("unreal/engine-version.json", "engine-version.schema.json", KIND_JSON,
                 "plan.md 4.3"),
    # --- containers / packages (section 5.4) ---
    ArtifactRule("packages/containers.json", "containers.schema.json", KIND_JSON,
                 "plan.md 5.4"),
    ArtifactRule("packages/plugins.json", "plugins.schema.json", KIND_JSON,
                 "plan.md 5.4"),
    ArtifactRule("packages/package-index.jsonl", "package-index.schema.json", KIND_JSONL,
                 "one line per package, plan.md 5.4"),
    # --- reflection dumps (section 6.3) ---
    # research/schema/reflection-record.schema.json covers one line of any of
    # these files and selects the entity branch by its own `kind` field.
    ArtifactRule("reflection/*/classes.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 6.3"),
    ArtifactRule("reflection/*/functions.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 6.3"),
    ArtifactRule("reflection/*/properties.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 6.3"),
    ArtifactRule("reflection/*/enums.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 6.3"),
    ArtifactRule("reflection/*/relations.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 6.3"),
    ArtifactRule("reflection/*/replicated-properties.jsonl", "reflection-record.schema.json",
                 KIND_JSONL,
                 "plan.md 12.4; assumed to be covered by the property/function branches "
                 "of reflection-record - revisit if K-02 adds a dedicated schema"),
    ArtifactRule("reflection/*/rpcs.jsonl", "reflection-record.schema.json", KIND_JSONL,
                 "plan.md 12.4; same assumption as replicated-properties.jsonl"),
    # --- experiment verdicts (sections 5.3, 14.7, 14A.5) ---
    ArtifactRule("packages/experiments/*/result.json", "experiment-result.schema.json",
                 KIND_JSON, "plan.md 5.4 lists result.md; result.json is its "
                            "machine-readable companion"),
    ArtifactRule("modkit/*/result.json", "experiment-result.schema.json", KIND_JSON,
                 "plan.md 14A.5 stages MK-1..MK-5"),
    # --- instrument runs (section 8) ---
    ArtifactRule("instrument-runs/*/manifest.json", "instrument-run-manifest.schema.json",
                 KIND_JSON, "plan.md 8 / 19"),
    # --- standalone knowledge-base records (plan.md 10, task EV-02) ---
    # kb-record.schema.json used to be referenced by NO map entry, which made
    # the whole envelope - including recorded_at - dead code.  Two things fix
    # that: these rules, so a standalone record file is validated against the
    # strict root of the envelope schema, and ENVELOPE_SCHEMA below, which
    # applies the same envelope to every record EXTRACTED from any artifact.
    ArtifactRule("kb/*.jsonl", "kb-record.schema.json", KIND_JSONL,
                 "one standalone knowledge-base record per line (plan.md 10 / EV-02)"),
    ArtifactRule("kb/*.json", "kb-record.schema.json", KIND_JSON,
                 "one standalone knowledge-base record (plan.md 10 / EV-02)"),
    # --- generic fallbacks, kept last on purpose ---
    ArtifactRule("evidence/*/*.json", None, KIND_JSON,
                 "raw evidence extract: no schema by design (plan.md 9.2 evidence/)"),
    ArtifactRule("evidence/*/*.jsonl", None, KIND_JSONL,
                 "raw evidence extract: no schema by design (plan.md 9.2 evidence/)"),
)

# Paths under research/ that are never treated as knowledge-base artifacts.
# research/schema/ holds the rulers, not the ruled: those files are checked for
# being parseable JSON (see check_schema_dir) and never linted as records.
IGNORED_PATH_PREFIXES: tuple[str, ...] = (
    "schema/",
)
# Derived caches (plan.md 9.1: SQLite is a cache built from JSONL, gitignored).
IGNORED_SUFFIXES: tuple[str, ...] = (
    ".sqlite",
    ".sqlite-journal",
)


# ---------------------------------------------------------------------------
# 2. Evidence-model vocabularies (plan.md 10.1, 10.5)
# ---------------------------------------------------------------------------

# plan.md 10.1 + the extra REFUTED level defined right below the table.
EVIDENCE_LEVELS: tuple[str, ...] = (
    "OBSERVED",
    "INFERRED",
    "HYPOTHESIS",
    "UNKNOWN",
    "REFUTED",
)

# plan.md 10.5: "Каждая запись ... обязана нести поле `oracle` с одним или
# несколькими из: ...".  This list is closed; anything else is a violation.
#
# NINE values since plan.md 10.5 "Правка v2.1 (2026-08-22)".  The first
# edition closed the list at six, and none of the six covered the most common
# way an M0 fact is obtained - reading the file tree - which is why draft
# documents invented `filesystem`, `steam-metadata`, `appmanifest`, `git` and
# `n/a` locally.  That was a defect of the plan, and the plan fixed it.  The
# validator therefore no longer routes a filesystem observation onto
# container-metadata or binary-analysis: doing so labelled a plain directory
# walk as a native-code result, which is precisely the source mixing that
# 10.5 exists to prevent.
ORACLES: tuple[str, ...] = (
    "filesystem",
    "steam-metadata",
    "vcs-history",
    "global-ucas",
    "asset-registry",
    "runtime-reflection",
    "binary-analysis",
    "container-metadata",
    "external-doc",
)

# The "what it does NOT prove" column of the plan.md 10.5 table, quoted in
# findings so a message names the boundary instead of only the rule id.
ORACLE_BOUNDARIES: dict[str, str] = {
    "filesystem":
        "proves existence, path, name, size, mtime and hash of a file, and the "
        "absence of a path; proves NOTHING about the meaning of the content",
    "steam-metadata":
        "proves what Steam RECORDED (appid, depot, manifest, buildid, size, "
        "installdir); proves nothing about what is actually on disk",
    "vcs-history":
        "proves what the repository records NOW; history is rewritable, so a "
        "cited commit must be reachable from HEAD at the time of writing",
    "global-ucas":
        "proves existence of NAMES only; nothing about /Game assets, Blueprint "
        "structure, offsets, sizes or property order",
    "asset-registry":
        "proves which packages/assets exist; nothing about memory layout or "
        "what is loaded right now",
    "runtime-reflection":
        "proves what the engine sees as loaded types/objects; nothing about "
        "what exists but is not loaded, and nothing about native semantics",
    "binary-analysis":
        "proves what native code does; nothing about the existence of BP assets "
        "or about concrete runtime values",
    "container-metadata":
        "proves format, versions, flags, counters, mount point, encryption "
        "status; nothing about encrypted chunk contents (D-02) and nothing "
        "about what the game actually mounts",
    "external-doc":
        "proves how vanilla UE works; nothing about THIS build, and always "
        "needs confirmation by another oracle (C-12), confidence <= 0.7",
}

# Draft spellings that appeared in the documents before 10.5 v2.1 closed the
# gap, mapped onto the canonical value.  These are ACCEPTED for linting (so
# the remaining rules can still run) and simultaneously REPORTED, because the
# document text itself has to be normalised.
ORACLE_ALIASES: dict[str, str] = {
    "appmanifest": "steam-metadata",
    "appmanifest.acf": "steam-metadata",
    "steam metadata": "steam-metadata",
    "steam-метаданные": "steam-metadata",
    "git": "vcs-history",
    "git history": "vcs-history",
    "git-history": "vcs-history",
    "vcs history": "vcs-history",
    "global.ucas": "global-ucas",
    "global ucas": "global-ucas",
    "assetregistry": "asset-registry",
    "asset registry": "asset-registry",
    "runtime reflection": "runtime-reflection",
    "binary analysis": "binary-analysis",
    "container metadata": "container-metadata",
    "external doc": "external-doc",
    "external-docs": "external-doc",
    "файловая система": "filesystem",
    "фс": "filesystem",
}

# Values that assert "no oracle applies".  plan.md 10.5 v2.1 removed the last
# excuse for them: a fact about our own file tree is `filesystem`, about Steam
# bookkeeping `steam-metadata`, about our own history `vcs-history`.
ORACLE_NOT_APPLICABLE: frozenset[str] = frozenset({
    "n/a", "n/д", "na", "нет", "не применим", "не применимо", "не применяется",
    "вне матрицы", "вне матрицы 10.5", "none", "-", "—",
})

# plan.md 10.2: confidence 1.00 is explicitly "не используется никогда", and
# the v2.1 wording makes the ceiling 0.99 EVEN FOR DIRECT MEASUREMENTS - the
# headroom stands for "we measured correctly but measured the wrong thing".
#
# plan.md 10.2 "Правка v2.3": THE CEILING IS A COMPARISON, NOT A PHRASE.  The
# checkable condition is 0.00 <= confidence <= 0.99.  Until validator 3.2.0
# CONFIDENCE_CEILING appeared only inside a message string while both EV-CONF
# paths compared against MAX_CONFIDENCE_EXCLUSIVE, so 0.995 and 0.999 passed
# with no finding while the message asserted the scale was capped at 0.99.  A
# rule that is stated and not compared is worse than an absent one: the message
# convinces the reader that a check happened.
CONFIDENCE_FLOOR = 0.0
CONFIDENCE_CEILING = 0.99
# Kept as the name of the value the plan bans outright, so a finding can say
# "1.00" where the author wrote 1.00 instead of describing it as "> 0.99".
MAX_CONFIDENCE_EXCLUSIVE = 1.0
# Binary floats: 0.99 parsed from text is not exactly 99/100, so a bare
# `value > CONFIDENCE_CEILING` could reject the very value the plan allows.
CONFIDENCE_EPSILON = 1e-9


def exceeds_ceiling(value: float) -> bool:
    """True when `value` is above the plan.md 10.2 ceiling of 0.99.

    plan.md 10.2 v2.3: 1.00 and every value in the open interval (0.99, 1.00)
    are forbidden alike, because they express a precision the scale does not
    have.  This is the single place that decides it, so the two EV-CONF paths
    cannot drift apart again.
    """
    return value > CONFIDENCE_CEILING + CONFIDENCE_EPSILON


def ceiling_message(value: float) -> str:
    """The EV-CONF text for a confidence above the ceiling."""
    if value >= MAX_CONFIDENCE_EXCLUSIVE:
        what = (f"confidence {value:.2f} is forbidden: plan.md 10.2 marks 1.00 "
                "\"не используется никогда\"")
    else:
        what = (f"confidence {value} lies in the open interval "
                f"({CONFIDENCE_CEILING}, {MAX_CONFIDENCE_EXCLUSIVE:.2f}), which plan.md "
                "10.2 v2.3 forbids exactly as it forbids 1.00: such a value expresses a "
                "precision the scale does not have")
    return (f"{what}. The checkable condition is "
            f"{CONFIDENCE_FLOOR:.2f} <= confidence <= {CONFIDENCE_CEILING} EVEN FOR "
            "DIRECT MEASUREMENTS - the headroom stands for \"we measured correctly but "
            "measured the wrong thing\"")

# plan.md 17.3 / C-12 rule 1: a third-party tool or public documentation on
# its own never yields confidence above 0.7 *for this build*.
EXTERNAL_DOC_ONLY_MAX_CONFIDENCE = 0.7

# plan.md 10.5 "Обязательное правило": a name found only in the global name
# pool gives at most HYPOTHESIS with confidence <= 0.4 about a /Game asset.
GLOBAL_UCAS_ASSET_MAX_CONFIDENCE = 0.4

# plan.md 10.4 / EV-03.
EV03_CONFIDENCE_THRESHOLD = 0.8
EV03_MIN_SOURCES = 2
# plan.md 10.3: the band where every class criterion becomes mandatory.
CRITERIA_STRICT_THRESHOLD = 0.95


# ---------------------------------------------------------------------------
# 2b. Claim classes (plan.md 10.3 v2.2, task EV-05)
# ---------------------------------------------------------------------------
# 10.3 v2.2 split the confirmation criteria by CLASS OF CLAIM.  Before that
# split the "two independent methods for confidence >= 0.80" rule was applied
# to everything, so "the install has 53 files" was held to the standard written
# for "this function registers item definitions" - 20 of 29 violations landed
# on facts nobody doubts.  The plan did not weaken the rule; it made it
# class-dependent, and made the interpretive side STRICTER.
#
# Class P - primitive measurement: ONE reading of a primitive property with no
# decoding step.  One method suffices up to the 0.99 ceiling, because
# re-reading the same primitive is not an independent method.
# Class I - interpretive claim: any decoding, attribution or inference about
# meaning, behaviour, mechanism or cause.  Two independent methods from 0.80.

CLASS_P = "P"
CLASS_I = "I"
CLAIM_CLASSES: tuple[str, ...] = (CLASS_P, CLASS_I)
# Not a third class.  It marks "the class cannot be derived from this record",
# which happens when no oracle is named at all.  Calling such a record class I
# and then holding it to the interpretive criteria would be inferring a class
# from missing data - the exact move this project forbids elsewhere.  The
# record still fails on EV-04 for the missing oracle, and the report says
# plainly that the 10.3 criteria were not applied to it.
CLASS_UNDETERMINED = "?"

# plan.md 10.3 row "Допустимые oracle" for class P, first edition: a white list
# of three oracles that need no further condition.  Reading any of them is a
# reading of a primitive property by construction.
CLASS_P_ORACLES_UNCONDITIONAL: frozenset[str] = frozenset({
    "filesystem", "steam-metadata", "vcs-history",
})

# plan.md 10.3 правка v2.4: "класс определяется характером утверждения, а не
# белым списком oracle".
#
# The white list above was a convenient proxy for "there is no interpretation
# step", and it leaked in both directions.  What it leaked OUT was every literal
# read of binary CONTENT: no admitted oracle covered a byte of a PE header, a
# field of a container header, a string out of a name pool, so every such
# reading was forced into class I - and an interpretive claim resting on one
# file and one tool cannot honestly exceed 0.79.  Twelve confidences in plan.md
# Appendix A were lowered for that reason alone, three of them to 0.75, not
# because the facts were weak but because the model had no cell for them.
#
# That was wrong on the merits.  "The four bytes at offset 48 are a0 e4 0c 00"
# contains no interpretation at all: a determinate location, a determinate
# length, a reproducible read.  The interpretation begins at the NEXT step -
# when the field is named DirectoryIndexSize and the layout is taken from a
# public header.
#
# So these two oracles are admissible in class P, under one ADDITIONAL
# MANDATORY CONDITION written into the plan: the claim must state the offset
# (or another determinate address) AND the length.  Without a stated offset the
# read is not reproducible as written, and class P is inadmissible.  See
# states_determinate_address() for exactly what counts.
CLASS_P_ORACLES_OFFSET_CONDITIONAL: frozenset[str] = frozenset({
    "binary-analysis", "container-metadata",
})

# The set an oracle must fall inside for class P to be POSSIBLE.  Falling
# inside it is necessary and not sufficient: the conditional half additionally
# has to clear the offset condition (derive_claim_class step 3b).
CLASS_P_ORACLES: frozenset[str] = (
    CLASS_P_ORACLES_UNCONDITIONAL | CLASS_P_ORACLES_OFFSET_CONDITIONAL)

# The other half of the same row: class I admits "любые, включая перечисленные -
# но ВМЕСТЕ с источником, несущим семантику".  These are the semantics-bearing
# oracles; an interpretive claim resting only on primitive readings has no
# source for the step that makes it interpretive.
#
# Deliberately computed from the UNCONDITIONAL set, so v2.4 does not move
# binary-analysis and container-metadata out of it.  v2.4 says those two oracles
# CAN carry a literal read; it does not say they cannot carry semantics - a
# container header read against a public layout is the paradigm case of a source
# that does.  Subtracting them here would have silently switched off the
# class I "нужен источник, несущий семантику" check for exactly the records it
# was written for.
SEMANTIC_ORACLES: frozenset[str] = frozenset(ORACLES) - CLASS_P_ORACLES_UNCONDITIONAL

# plan.md 10.5 matrix row "на диске лежит то, что Steam обещает": the ONLY
# reason to name both of these is the cross-check between the two, and the
# cross-check is a conclusion about both sources rather than a reading of
# either (10.3 class P criterion 5).
CROSS_CHECK_ORACLES: frozenset[str] = frozenset({"filesystem", "steam-metadata"})

# plan.md 10.3 "Уровень доказательства определяет класс, а не наоборот"
# (правка v2.3): class P is admissible ONLY at evidence_level = OBSERVED.
CLASS_P_EVIDENCE_LEVEL = "OBSERVED"
# INFERRED and HYPOTHESIS mean "мы заключили нечто сверх прямого наблюдения" -
# the interpretation step has already happened by definition.  REFUTED is the
# same shape: a refutation is a conclusion about what the evidence means.
CLASS_I_EVIDENCE_LEVELS: frozenset[str] = frozenset({
    "INFERRED", "HYPOTHESIS", "REFUTED",
})
# UNKNOWN claims nothing, so there is no class to derive.  Calling it I and
# then holding it to the interpretive criteria would be inferring a class from
# an absence - the move this project forbids elsewhere.
CLASS_UNDETERMINED_LEVELS: frozenset[str] = frozenset({"UNKNOWN"})

# claim_type values whose matrix row is itself a primitive measurement.
CLASS_P_CLAIM_TYPES: frozenset[str] = frozenset({
    "file-exists",
    "install-file-count",
    "steam-metadata-fact",
    "commit-content",
})

# Accepted spellings of the field value.
CLAIM_CLASS_ALIASES: dict[str, str] = {
    "p": CLASS_P,
    "i": CLASS_I,
    "class p": CLASS_P,
    "class i": CLASS_I,
    "класс p": CLASS_P,
    "класс i": CLASS_I,
    "primitive": CLASS_P,
    "primitive-measurement": CLASS_P,
    "примитивное измерение": CLASS_P,
    "interpretive": CLASS_I,
    "interpretive-claim": CLASS_I,
    "интерпретирующее утверждение": CLASS_I,
}

# plan.md 10.3 criterion 3: "Утверждение сформулировано в примитивных терминах
# и не содержит семантического вывода".  These are the markers of a step the
# primitive reading cannot have taken: a conclusion, an attribution, a decoded
# meaning.  The list is deliberately made of explicit conclusion connectives
# and named interpretive acts, not of every word that could hint at inference,
# because this test raises a violation and a noisy violation gets switched off.
SEMANTIC_CONCLUSION_RE = re.compile(
    # "вывод о ..." / "Вывод:" - a conclusion ABOUT something.  The word
    # boundaries are load-bearing and were missing until validator 3.2.1:
    # `вывод\s*(?:о|:)` also matched "вывод**ов**", "вывод **о**бязан" and
    # "вывод**ом**", so a sentence stating a REQUIREMENT about conclusions
    # ("каждый вывод обязан быть перепроверен", research/unknowns.md L92) read
    # as a conclusion being drawn.  That is the "role of the word" defect
    # research/RESEARCH_LOG.md LOG-0008i names, in its smallest form: a marker
    # matching the first two letters of the next word.
    r"(?:следовательно|отсюда следует|поэтому\b|значит,|означает|подразумевает|"
    r"вывод\w*\s+о\b|вывод\s*:|при\s+трактовке|трактовка|интерпретация|указывает\s+на|"
    r"свидетельствует|зашифрован|расшифров|декодирова|механизм\b|"
    r"это\s+(?:Shipping|Development)|therefore|hence\b|it\s+follows\s+that|"
    r"implies|indicates\s+that|is\s+encrypted|decoded)",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# 2c. plan.md 10.3 v2.4: the determinate-address condition
# ---------------------------------------------------------------------------
# "Для `binary-analysis` и `container-metadata` это означает дополнительное
# обязательное условие: в утверждении указано смещение (или иной
# детерминированный адрес) И длина.  Без указанного смещения чтение не
# воспроизводимо как написано, и класс P недопустим."
#
# WHICH DIRECTION THIS ERRS, AND WHY.  Deliberately STRICT.  A false negative
# costs an author one clause - they add "по смещению 48, четыре байта" and the
# row grades as P.  A false positive admits an interpretation as a measurement,
# which is the entire defect class v2.4 exists to prevent and which no later
# reader can detect from the record itself.  So every doubtful shape is refused,
# and BOTH halves of the plan's condition are required separately: an address
# alone ("смещение 20 = 144") does not pass, because the length of the read is
# then left to the reader, and a length alone ("файл размером 134 658 048 байт")
# is a size claim and not a read at an address at all.

# A number that can name a place or a width: hexadecimal (0x-prefixed) or
# decimal, with the thin/nbsp thousands separators these documents actually use.
_ADDR_NUMBER = r"(?:0x[0-9a-fA-F]+|[0-9]+(?:[   ][0-9]{3})*)"

# The words this repository uses to name a place inside a file.  Keyword FIRST,
# number immediately after, separated by nothing but space, colon, equals, № or
# #.  The order and the tight separator are what keep "134 658 048 байт" (a
# size) from reading as "byte number 048": there the number precedes the word.
# The leading \b is load-bearing: without it "va" matches inside "Java 25" and
# a JDK version number reads as a virtual address.
_ADDRESS_KEYWORD = (
    r"\b(?:смещени\w*|смещень\w*|сдвиг\w*|адрес\w*|позици\w*|"
    r"offsets?|address(?:es)?|rva|va|position|"
    r"байт\w*|bytes?)")
DETERMINATE_ADDRESS_RE = re.compile(
    _ADDRESS_KEYWORD + r"[\s:=№#]{0,3}" + _ADDR_NUMBER,
    re.IGNORECASE)

# A byte RANGE states the address and the length in one breath: "байты 48-51",
# "bytes 0x30..0x33", "смещения 48–51".  Accepted as satisfying both halves at
# once, because a range is exactly a determinate start plus a determinate
# extent.
#
# The address keyword is MANDATORY here, and that is the whole design of this
# regex.  A bare "N-M" is the shape of a date ("номинально 2030-10-19"), an
# engine version ("++UE5+Release-5.4-CL-35576357") and a changelist, and the
# first draft of this rule read plan.md A-13's nominal PE date as a byte range
# and derived an interpretive PE-section claim as a measurement - the exact
# false positive v2.4 exists to prevent, produced by the code enforcing it.
BYTE_RANGE_RE = re.compile(
    _ADDRESS_KEYWORD + r"[\s:=№#]{0,3}" + _ADDR_NUMBER
    + r"\s*(?:\.\.\.?|-|–|—|:|‥)\s*" + _ADDR_NUMBER,
    re.IGNORECASE)

# Russian and English number words, so "четыре байта по смещению 48" - the
# plan's own canonical class P example - is recognised without forcing the
# author to write the digit.  A closed list; genitive and nominative forms
# both appear in the documents.
_COUNT_WORD = (
    r"(?:один|одного|одна|одну|два|две|двух|три|трёх|трех|четыре|четырёх|"
    r"четырех|пять|пяти|шесть|шести|семь|семи|восемь|восьми|"
    r"one|two|three|four|five|six|seven|eight|sixteen|thirty-two|sixty-four)")

# The length half.  Either a count of bytes, or a fixed-width primitive whose
# name IS its width.  Naming a width is not naming a meaning: "8 байт по
# смещению 56" and "uint64 по смещению 56" state the same extent, and refusing
# the second would be a false negative with no compensating safety.  The list
# of width names is closed on purpose - a TYPE from an external layout
# (`FIoStoreTocHeader`, `EIoContainerFlags`) is not a width and is caught by
# BINARY_NAMING_RE below as an interpretation.
DETERMINATE_LENGTH_RE = re.compile(
    r"(?:(?:" + _ADDR_NUMBER + r"|" + _COUNT_WORD + r")\s*"
    r"(?:байт\w*|bytes?|б\b)"
    r"|\b(?:u?int(?:8|16|32|64)|[uif](?:8|16|32|64)|byte|word|dword|qword)\b"
    r"|\bбайт\w*\s*[\s:=№#]{0,3}" + _ADDR_NUMBER + r")",
    re.IGNORECASE)

# plan.md 10.3 v2.4, the class I half of the same rule: "как только утверждение
# называет, ЧЕМ прочитанное является, что оно значит, или опирается на внешнюю
# раскладку".
#
# SEMANTIC_CONCLUSION_RE does not cover this and must not be widened to: it is
# a list of conclusion CONNECTIVES ("следовательно", "означает"), and the shape
# v2.4 forbids has no connective in it.  "Поле DirectoryIndexSize по смещению 48
# равно 844 960" draws no visible conclusion and names the field outright, and
# under the offset condition alone it would have derived as a measurement - the
# precise false positive this rule exists to stop.
#
# Two markers, either of them enough:
#   * naming vocabulary - поле/field/структура/раскладка/layout/называется, and
#     the words for a signature or a magic value, which name what bytes ARE;
#   * an identifier in the CamelCase shape that external layouts are written in
#     (DirectoryIndexSize, TocEntryCount, FIoStoreTocHeader, EIoContainerFlags).
#     The pattern requires at least two humps AND a lowercase run, so a file
#     name (MISERY-Windows.utoc) and an all-caps token (RVA, PE) do not match.
#     It does match a tool name written that way (PowerShell); that is a false
#     negative for class P admission, i.e. the safe direction.
BINARY_NAMING_RE = re.compile(
    # the vocabulary half, case-insensitive.  Every entry names WHAT a value
    # is, or the layout it was read against; none of them merely locates it.
    # "перечислени" and not "перечислен\\w*" on purpose: the second also
    # matches "перечислены" ("are listed"), which says nothing about a layout,
    # and it was the accidental trigger on plan.md A-05 in the first draft.
    r"(?i:пол[ея]\b|полем\b|поля\b|полей\b|field\b|fields\b|"
    r"структур\w*|struct\b|раскладк\w*|layout\b|схем[аы]\b|"
    r"называется|именуется|is\s+named|is\s+the\s+field|"
    r"magic\b|сигнатур\w*|signature\b|enum\b|перечислени\w*|"
    r"флаг\w*|flags?\b|тип\b|типа\b|типом\b|type\b|"
    r"секци\w*|section\b|sections\b|"
    r"timestamp|метк[аи]\s+времени|unix-?врем\w*|unix\s+time|"
    r"аномали\w*|anomaly)"
    # the identifier half, case-SENSITIVE: the shape is the signal
    r"|\b[A-Z]{1,2}[a-z]+(?:[A-Z][A-Za-z0-9]*)+\b")


def states_determinate_address(claim_text: str) -> bool:
    """True when a claim states a determinate address AND a determinate length.

    plan.md 10.3 v2.4, the additional mandatory condition for the
    `binary-analysis` and `container-metadata` oracles.  Accepted forms, and
    they are documented here because an author has to be able to predict this
    function without reading it:

      * an address keyword followed immediately by a number - "по смещению 48",
        "смещение 0x30", "offset 48", "адрес 0x140001000", "RVA 0x1000",
        "байт 16" (byte number 16), hexadecimal or decimal, thousands
        separators allowed;
      * a byte range - "байты 48-51", "bytes 0x30..0x33", "48:52" - which
        satisfies the address and the length at once;
      * a length - "четыре байта", "16 байт", "4 bytes", or a fixed-width
        primitive name (uint32, dword, ...).

    NOT accepted, on purpose:

      * an address with no length ("смещение 20 = 144"): the plan requires both,
        and without the extent the read is under-specified as written;
      * a length with no address ("файл размером 134 658 048 байт"): that is a
        size claim, which is `filesystem` and needs no offset;
      * the word "смещение" with no number, or a number with no keyword: neither
        names a place.
    """
    text = _clean_md(str(claim_text or ""))
    if not text:
        return False
    if BYTE_RANGE_RE.search(text):
        return True
    return bool(DETERMINATE_ADDRESS_RE.search(text)
                and DETERMINATE_LENGTH_RE.search(text))


def names_what_the_bytes_are(claim_text: str) -> bool:
    """True when a binary claim names WHAT it read, not only where and how much.

    plan.md 10.3 v2.4 class I: naming the field, its meaning, or the external
    layout it came from is the interpretation step, and it disqualifies class P
    however precise the offset is.
    """
    return bool(BINARY_NAMING_RE.search(_clean_md(str(claim_text or ""))))


# The primitive half of a claim: existence, path, name, size, mtime, hash, or a
# count of those (plan.md 10.3 class P definition).
PRIMITIVE_CLAIM_RE = re.compile(
    r"(?:существует|отсутствует|наличие|размер|байт|файл|хэш|хеш|sha-?256|mtime|"
    r"путь|количество|счётчик|счетчик|строк[аи]\s+по\s+смещению|"
    r"exists?|absent|size|bytes|hash|path|count|filename)",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# 2d. MIX-SCOPE: is the conclusion ASSERTED in this record, or only MENTIONED?
# ---------------------------------------------------------------------------
# plan.md 10.3 "Смешанные утверждения обязаны разделяться" is a rule about what
# a record GRADES.  MIX-SPLIT fires when ONE level/confidence pair covers both a
# primitive reading and a semantic conclusion.  Until validator 3.2.1 the test
# for the second half was `SEMANTIC_CONCLUSION_RE.search(claim_text)`: a
# conclusion MARKER anywhere in the record's text.  That is a test for the word,
# not for the claim, and it produced two false positives on records that had
# done exactly what the plan asks:
#
#   research/RESEARCH_LOG.md L395 (LOG-0004) and L491 (LOG-0005).  Both were
#   flagged by the SAME token, "расшифров", and in both the token sits inside a
#   RESTATEMENT OF A PROHIBITION - "в публичный репозиторий не попадают ...
#   ничего производного от расшифрованных контейнеров" (constraint C-13) and
#   "NOTICE.md формулирует прямо: чего в репозитории нет и не будет (... что-либо
#   производное от расшифрованного контента)".  Neither record concludes that
#   anything is encrypted or decrypted.  Both record what a rule forbids.
#
# The remedy explicitly NOT used here is the `quoted-example` marker.  That
# marker means "this grade belongs to somebody else's record" and it removes the
# record from the linted set entirely.  LOG-0004 and LOG-0005 are LIVE records
# with live grades; marking them would delete two real records from the lint,
# which is a strictly worse defect than the false positive it hides.  The other
# rejected remedy is rewording the two documents: a correct record must not be
# rewritten to satisfy the parser that reads it.
#
# THE STRUCTURAL DIFFERENCE, which is what this section implements.  Three
# shapes contain a conclusion marker and only the first grades a conclusion:
#
#   1. ASSERTED   "Четыре байта по смещению 48 равны a0 e4 0c 00, значит
#                  контейнер зашифрован."       -> MIX-SPLIT, correctly
#   2. QUOTED RULE "Внесено ограничение C-13: в репозиторий не попадает ничего
#                  производного от расшифрованных контейнеров."
#                  -> the clause states a REQUIREMENT.  A prohibition opened
#                     BEFORE the marker governs it; the record asserts that the
#                     rule exists, not that something was decrypted.
#   3. DELEGATED  "Общий методологический вывод градуирован отдельно в
#                  LOG-0004i."
#                  -> the clause hands the conclusion to a NAMED counterpart
#                     record.  This is the shape the split rule itself produces:
#                     an author who splits correctly must name the other half,
#                     and naming it must not re-flag the half that is clean.
#
# Shapes 2 and 3 are recognised per CLAUSE, never per record, and every use is
# printed in the MIX-SCOPE block of the report, exactly as NORM-ENUM is: the
# parser decided not to read a conclusion-shaped word as a conclusion, and that
# decision has to be visible and countable.  Both shapes are refused outright
# for any clause that states a level or a confidence of its own - a clause that
# grades something is a record, never a quotation of one.
#
# Shape 3 additionally requires the named id to EXIST as a record in the same
# document.  That is what makes it non-forgeable: "(см. LOG-0099i)" next to a
# conclusion buys nothing unless LOG-0099i is really there, so the exemption
# cannot be claimed without performing the split it claims to have performed.
# The hand-off vocabulary is deliberately narrow - it must SAY the conclusion is
# graded elsewhere.  A bare cross-reference ("см. LOG-0001i") is NOT enough:
# plan.md 10.1 says restating never promotes, and by the same token a citation
# does not discharge a claim the sentence still makes.

# Clause boundaries.  Only a sentence terminator followed by whitespace and an
# opening character counts, so a version dot ("plan.md исправлено") and a
# decimal point never split.  A colon deliberately does NOT split: "ограничение
# C-13: в репозиторий не попадают ..." is one clause, and cutting at the colon
# would throw away the very words that identify it as a rule.  Splitting too
# eagerly can only make the exemptions HARDER to earn, never easier, because
# every condition below is a search inside one clause.
_CLAUSE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+(?=[«\"'(\[A-ZА-ЯЁ\d])")

# A clause that grades something itself.  Kept local and self-contained rather
# than reusing the level/confidence regexes of section 6b, so this decision can
# be read without chasing forward references.
_CLAUSE_GRADES_RE = re.compile(
    r"\b(?:OBSERVED|INFERRED|HYPOTHESIS|UNKNOWN|REFUTED)\b"
    r"|(?:confidence|conf\.|уверенность)\s*[:=]?\s*[<>≤≥~≈]{0,2}\s*\d")

# The prohibition / requirement that OPENS the scope a marker sits in.  Order
# matters: this is searched only in the clause text BEFORE the marker, so
# "контейнер зашифрован, поэтому его содержимое не попадает в репозиторий" is
# NOT exempt - there the assertion comes first and the prohibition after it.
PROHIBITION_SCOPE_RE = re.compile(
    r"(?:не\s+попада\w*|не\s+вкл\w*|не\s+буд\w*|нет\s+и\s+не\s+будет|"
    r"не\s+должн\w*|не\s+допуска\w*|не\s+хран\w*|не\s+публику\w*|"
    r"запрещ\w*|исключ\w*|никогда\s+не|ни\s+одного?\s+\w+\s+не|"
    r"must\s+not|shall\s+not|never\s+\w+|forbid\w*|prohibit\w*|excluded)",
    re.IGNORECASE)

# The clause must also ANCHOR the prohibition to a norm: a constraint or
# decision id, a document that states rules, or the vocabulary of a stated
# rule.  Without this a plain negation ("контейнер не расшифрован") would earn
# the exemption, and that sentence is a claim about the container.
NORM_ANCHOR_RE = re.compile(
    r"(?:\b[CDRT]-\d{2}\b|NOTICE\.md|AGENTS\.md|LICENSE\b|"
    r"ограничени\w*|требовани\w*|правил[оа]\w*|политик\w*|решени\w*|"
    r"формулиру\w*|оговорк\w*|"
    r"constraint\w*|requirement\w*|policy|forbids?|prohibits?)",
    re.IGNORECASE)

# The hand-off that DISCHARGES a conclusion onto another record.  It must state
# that the conclusion is graded elsewhere; a bare "см." / "see" is excluded on
# purpose (see the note above).
# The list is narrow deliberately, and the words for the ACT of splitting
# ("разделено", "расщеплено") are NOT in it: they describe what was done to some
# record, which is not the same as saying that THIS conclusion is graded
# somewhere else.  Both stems were in the first draft and both produced
# exemptions on records that were already class I by evidence_level - noise in
# the report that claimed a decision the parser had not really made.
HANDOFF_RE = re.compile(
    r"(?:градуирован\w*|градуиру\w*|"
    r"оценен\w*\s+отдельно|оценён\w*\s+отдельно|"
    r"вынесен\w*\s+(?:в|отдельно)|отдельн\w*\s+(?:запис\w*|градуировк\w*)|"
    r"graded\s+separately|split\s+(?:out|into)|separate\s+record)",
    re.IGNORECASE)

# A record id as these documents write them: LOG-0004i, RA-39, A-07, T-02.
# The optional trailing lowercase letter is the interpretive-counterpart suffix
# this repository uses (LOG-0004 / LOG-0004i).
_RECORD_ID_RE = re.compile(r"\b([A-Z]{1,5}-\d{2,4}[a-z]?)\b")

MIX_SCOPE_QUOTED_RULE = "quoted-rule"
MIX_SCOPE_DELEGATED = "delegated"


def _clauses(text: str) -> list[str]:
    """Split a record's claim text into clause-sized spans."""
    return [part for part in _CLAUSE_BOUNDARY_RE.split(text or "") if part.strip()]


def _mention_reason(clause: str, match: re.Match[str],
                    counterpart_ids: set[str]) -> str | None:
    """Why this conclusion marker is a MENTION, or None if it is asserted."""
    if _CLAUSE_GRADES_RE.search(clause):
        # The clause states a level or a confidence: it is a record, and a
        # record's own conclusion is never a quotation of somebody else's.
        return None
    if PROHIBITION_SCOPE_RE.search(clause[:match.start()]) \
            and NORM_ANCHOR_RE.search(clause):
        return MIX_SCOPE_QUOTED_RULE
    if counterpart_ids and HANDOFF_RE.search(clause):
        named = [ident for ident in _RECORD_ID_RE.findall(clause)
                 if ident.upper() in counterpart_ids]
        if named:
            return f"{MIX_SCOPE_DELEGATED}:{named[0]}"
    return None


def scope_conclusion_markers(
    claim_text: str,
    counterpart_ids: Collection[str] = (),
) -> tuple[list[str], list[tuple[str, str, str]]]:
    """Split the conclusion markers of a claim into asserted and mentioned.

    Returns (asserted markers, [(marker, reason, clause excerpt)]).  The second
    list is what the report prints: an exemption nobody can count is an
    exemption nobody can audit.
    """
    text = str(claim_text or "")
    known = {str(ident).strip().upper() for ident in counterpart_ids if str(ident).strip()}
    asserted: list[str] = []
    mentioned: list[tuple[str, str, str]] = []
    for clause in _clauses(text):
        for match in SEMANTIC_CONCLUSION_RE.finditer(clause):
            reason = _mention_reason(clause, match, known)
            if reason is None:
                asserted.append(match.group(0))
            else:
                mentioned.append((match.group(0), reason,
                                  " ".join(clause.split())[:160]))
    return asserted, mentioned


# plan.md 10.3 criterion 2: "Метод перезапущен и результат воспроизведён хотя
# бы один раз".  A document can satisfy this by SAYING so, which is the only
# thing a text linter can check.
# The trailing \w* matters: these are stems, and a stem match that leaves the
# inflection behind ("повторено" -> "ено") makes is_reproduction_note() below
# think the entry still names a method.
REPRODUCED_RE = re.compile(
    r"(?:воспроизвед|повтор|перезапущ|перепроверен|дважды|два\s+раза|двух\s+запуск|"
    r"run\s*-?\s*[12]|reproduc|re-?run|twice|×\s*2|x2)\w*",
    re.IGNORECASE)

# plan.md 10.3 criterion 5: a steam-metadata claim says "Steam records X", not
# "X is true of the disk".  The second is class I and additionally needs
# `filesystem` (10.5 matrix row "то, что лежит на диске, есть то, что обещает
# Steam").
DISK_ASSERTION_RE = re.compile(
    r"(?:на\s+диске|фактическ|в\s+установке\s+действительно|реально\s+установлен|"
    r"файлы\s+присутствуют|on\s+disk|actually\s+installed)",
    re.IGNORECASE)
STEAM_RECORDS_RE = re.compile(
    r"(?:steam\s+(?:запис|указыв|соббщ|records?|reports?|claims?)|"
    r"по\s+данным\s+steam|согласно\s+(?:steam|appmanifest)|appmanifest\s+(?:запис|содержит))",
    re.IGNORECASE)

# A saved raw artifact under research/evidence/ (plan.md 10.3 class I
# criterion 3).
EVIDENCE_ARTIFACT_RE = re.compile(r"research/evidence/[\w./\\-]+")

# plan.md 10.3 class I criterion 5: "Явно указан `build_key`".  Any notation
# that names the key counts, including "build_key=UNKNOWN" - C-07 asks for the
# field to be named rather than guessed.
BUILD_KEY_MENTION_RE = re.compile(r"build[_\s-]?key", re.IGNORECASE)

# plan.md 10.3 class I criterion 6: "Проведена попытка опровержения, и она
# описана (\"что бы мы увидели, если бы это было неверно\")".  Like criteria 2
# and 4 this is an attestation about process, so what a text linter can check
# is whether the record SAYS an attempt was made.  The markers are the words a
# refutation attempt is actually written with in this repository.
REFUTATION_ATTEMPT_RE = re.compile(
    r"(?:опроверж|опровергн|контрпример|контр-пример|если\s+бы\s+это\s+было\s+неверно|"
    r"что\s+бы\s+мы\s+увидели|проверка\s+на\s+ложн|falsif|refut|counter-?example|"
    r"disconfirm|negative\s+control)\w*",
    re.IGNORECASE)


# plan.md 10.3 class P criterion 1: "Записан точный метод - команда или
# операция, воспроизводимая КАК НАПИСАНА, без домысливания".  An entry of a
# method field counts towards EV-03 only when it names such an operation.
#
# This exists because the method field of a markdown record is free prose, and
# EV-03 used to count every clause of it as another independent method.
# research/RESEARCH_LOG.md LOG-0001i is the case that proves the point: it
# states in its own Method field "Один метод, не два", and the validator
# counted three, because the paragraph contains two clause boundaries.  A
# record that argues about its own grading is not thereby better evidenced.
#
# The test is a POSITIVE signal, not a length limit: a short clause of
# commentary would slip through a length limit, and a long sentence that does
# name a command would be rejected by it.  A method is recognised by a code
# span, a path or file name, a method/experiment id, or a word that names an
# operation.  The vocabulary below is drawn from the method fields actually
# written in this repository; extend it when a real method is rejected, never
# to make a particular record pass.
METHOD_CODE_SPAN_RE = re.compile(r"`[^`]+`")
METHOD_PATH_RE = re.compile(
    r"(?:[\w.-]+[/\\][\w./\\-]+|\b\w+\.(?:exe|dll|pak|utoc|ucas|acf|vdf|ini|json|"
    r"jsonl|md|log|py|txt|sha256)\b)", re.IGNORECASE)
METHOD_OPERATION_RE = re.compile(
    r"(?:чтени|читал|прочит|перечит|обход|перечёт|перечет|пересчёт|пересчет|счита|"
    r"запуск|запустил|прогон|парсин|разбор|разобра|проверк|проверил|сверк|сверил|"
    r"сравнени|сравнил|измерени|измерил|замер|дамп|снимок|хэширован|хеширован|"
    r"вычислен|вычислил|поиск|искал|grep|инвентар|перебор|осмотр|наблюдени|"
    r"разност|вычитан|объединен|пересечен|множеств|группиров|сортиров|фильтр|строк|"
    r"сумм|дизассембл|декомпил|strings\b|"
    r"наблюдал|эксперимент|команда|скрипт|утилита|инструмент|"
    r"get-|measure-|select-|test-|где-|find|ls\b|dir\b|git\b|python\b|"
    r"powershell\b|ghidra|analyzeheadless|hexdump|xxd|certutil|"
    r"read|scan|parse|walk|dump|hash|count|run\b|inspect|observe|measure|"
    r"compare|verify|experiment|command|script|tool)",
    re.IGNORECASE)


def is_method_entry(entry: str) -> bool:
    """True when one entry of a PROSE method field actually NAMES a method.

    plan.md 10.3 criterion 1 and 10.4/EV-03.  Rejecting an entry never lowers
    the bar: it means EV-03 counts fewer methods and therefore reports MORE,
    which is the safe direction for a gate.  The unsafe direction - crediting a
    clause of reasoning as a second measurement - is what made EV-03
    unfalsifiable in the markdown notations.

    Applied to prose only.  A JSON `sources[]` array is already an explicit
    enumeration written by the author, so every element of it is counted; a
    markdown method field is one paragraph, and which of its clauses are
    methods has to be recognised rather than assumed.
    """
    if is_reproduction_note(entry):
        return False
    text = str(entry)
    return bool(METHOD_CODE_SPAN_RE.search(text)
                or METHOD_PATH_RE.search(_clean_md(text))
                or METHOD_OPERATION_RE.search(_clean_md(text)))


def is_reproduction_note(entry: str) -> bool:
    """True when a method entry says only "reproduced", naming no method.

    The documents write the method cell as "обход ФС; повторено 2026-08-22".
    Splitting on ";" turns the reproduction note into a second entry, and
    counting it as a second METHOD would satisfy EV-03 with one method plus a
    promise - the same defect as counting an Evidence path.  The note still
    feeds the class P criterion 2 check, where it belongs.
    """
    remainder = REPRODUCED_RE.sub(" ", str(entry))
    return not re.sub(r"[\d\s.,:;/(){}\[\]«»\"'`–—_-]", "", remainder)


def normalise_claim_class(raw: str | None) -> tuple[str | None, bool]:
    """Return (canonical class, recognised).  ("", False) for an unreadable value."""
    if raw is None:
        return None, True
    key = " ".join(str(raw).strip().strip("`*_.,;:").lower().split())
    if not key:
        return None, True
    if key.upper() in CLAIM_CLASSES:
        return key.upper(), True
    if key in CLAIM_CLASS_ALIASES:
        return CLAIM_CLASS_ALIASES[key], True
    return None, False


@dataclass(frozen=True)
class ClassVerdict:
    """The derived claim class plus why, so a finding can quote the reason."""

    claim_class: str
    reason: str
    # A primitive claim that also carries a semantic conclusion: plan.md 10.3
    # "Смешанные утверждения обязаны разделяться".
    mixed: bool = False
    has_primitive_part: bool = False
    # True when the evidence_level alone decided the class (plan.md 10.3 v2.3).
    # Recorded so a finding can say WHICH input settled it, and so the rules
    # that only make sense for a class derived from oracle/claim_type can tell
    # the two apart.
    level_decided: bool = False


def derive_claim_class(
    oracles: set[str],
    claim_type: str | None = None,
    claim_text: str = "",
    evidence_level: str | None = None,
    counterpart_ids: Collection[str] = (),
) -> ClassVerdict:
    """Derive P or I from evidence_level FIRST, then oracle + claim_type.

    plan.md 10.3 "Уровень доказательства определяет класс, а не наоборот"
    (правка v2.3) is the decisive rule and is applied before anything else:

        Класс P допустим только при `evidence_level = OBSERVED`.
        `INFERRED` и `HYPOTHESIS` ... - такая запись ВСЕГДА класс I,
        независимо от того, какие у неё oracle и как сформулирован текст.

    Until validator 3.2.0 this function never received the evidence level, so a
    claim its author had honestly graded INFERRED derived as class P whenever
    its oracles fell inside CLASS_P_ORACLES and its wording happened not to
    match SEMANTIC_CONCLUSION_RE.  Because the derived class is authoritative,
    an author who then labelled the record class I got an EV-05 ERROR telling
    them to change the oracle, the claim_type or the wording rather than the
    label - the gate punished the correct label and rewarded the incorrect one,
    and it did so quietly, emitting only a mild class-P warning.  Three live
    records (RA-38, RA-39, RA-40) went through that hole.

    plan.md 10.4/EV-05 still holds: the derivation is the authority and this
    function never consults the explicit `claim_class` field.  What changed is
    the order of the inputs, and that the wording heuristic
    (SEMANTIC_CONCLUSION_RE) now only SUPPLEMENTS the rule - it can push an
    OBSERVED record towards needing a split, and it can never turn an INFERRED
    record into a measurement.
    """
    # Section 2d: a conclusion MARKER is not a graded conclusion.  Only the
    # markers this record actually asserts count; the ones it quotes from a rule
    # or hands to a named counterpart record do not (MIX-SCOPE).
    asserted, _mentioned = scope_conclusion_markers(claim_text, counterpart_ids)
    conclusion = bool(asserted)
    primitive = PRIMITIVE_CLAIM_RE.search(claim_text) is not None
    resolved = resolve_claim_type(claim_type) if claim_type else None
    level = (evidence_level or "").strip().upper() or None

    # --- 1. the evidence level, before oracle and claim_type -------------
    if level in CLASS_I_EVIDENCE_LEVELS:
        return ClassVerdict(
            CLASS_I,
            f"evidence_level is {level}, and plan.md 10.3 v2.3 admits class P only at "
            f"{CLASS_P_EVIDENCE_LEVEL}: {level} means a conclusion beyond direct "
            "observation was drawn, so the interpretation step has already happened by "
            "definition - such a record is ALWAYS class I, whatever its oracles are and "
            "however its text is worded",
            level_decided=True,
            has_primitive_part=primitive)
    if level is not None and level in CLASS_UNDETERMINED_LEVELS:
        return ClassVerdict(
            CLASS_UNDETERMINED,
            f"evidence_level is {level}, which claims nothing, so there is no claim to "
            "classify (plan.md 10.1); class P needs "
            f"{CLASS_P_EVIDENCE_LEVEL} and class I needs a conclusion to have been drawn",
            level_decided=True,
            has_primitive_part=primitive)
    # level is OBSERVED, absent, or an unknown token.  An absent or unreadable
    # level is already an EV-LEVEL finding; falling through to the oracle-based
    # derivation here keeps that record classified instead of silently exempt.

    if not oracles and resolved is None:
        return ClassVerdict(
            CLASS_UNDETERMINED,
            "no oracle and no claim_type are named, so the class cannot be derived "
            "(plan.md 10.4/EV-05 derives it from oracle + claim_type once the "
            "evidence level has not already decided it)",
            has_primitive_part=primitive)

    # --- 2. claim_type -----------------------------------------------------
    if resolved is not None and resolved not in CLASS_P_CLAIM_TYPES:
        return ClassVerdict(
            CLASS_I,
            f"claim_type {resolved!r} is not one of the primitive-measurement rows "
            f"{sorted(CLASS_P_CLAIM_TYPES)} (plan.md 10.3 / 10.5 v2.1)",
            has_primitive_part=primitive)

    # --- 3. oracle ---------------------------------------------------------
    p_oracles = bool(oracles) and oracles <= CLASS_P_ORACLES
    if not p_oracles:
        detail = (f"oracle(s) {sorted(oracles)} include a semantics-bearing source"
                  if oracles else "no oracle is named, so no primitive reading is shown")
        return ClassVerdict(
            CLASS_I,
            f"{detail}; class P admits only {sorted(CLASS_P_ORACLES_UNCONDITIONAL)} "
            f"unconditionally and {sorted(CLASS_P_ORACLES_OFFSET_CONDITIONAL)} only for a "
            "literal read at a stated offset (plan.md 10.3, правка v2.4)",
            has_primitive_part=primitive)

    # --- 3b. plan.md 10.3 v2.4: the offset condition ----------------------
    # binary-analysis and container-metadata are admissible in class P, but ONLY
    # for a literal read at a determinate address.  Two things have to hold, and
    # they are checked separately because they fail for different reasons and
    # have different remedies:
    #   * the claim states an address AND a length - otherwise the read is not
    #     reproducible as written and the remedy is to write the offset down;
    #   * the claim does not name WHAT the bytes are - otherwise the
    #     interpretation step has already been taken and the remedy is to split
    #     the record (10.3 "Смешанные утверждения обязаны разделяться").
    # The order matters: without an address there is no admissible primitive
    # half to split OFF, so telling the author to split would be unactionable.
    conditional = oracles & CLASS_P_ORACLES_OFFSET_CONDITIONAL
    if conditional:
        if level != CLASS_P_EVIDENCE_LEVEL:
            # v2.3 stays dominant, and the NEW admission does not inherit the
            # older tolerance for a missing level: a literal read that does not
            # say it was observed is not a literal read on the record.
            return ClassVerdict(
                CLASS_I,
                f"oracle(s) {sorted(conditional)} are admissible in class P only for a "
                f"literal read at a stated offset, and only at evidence_level "
                f"{CLASS_P_EVIDENCE_LEVEL}; this record states "
                f"{level or 'no evidence level'} (plan.md 10.3 v2.3 + v2.4)",
                has_primitive_part=primitive)
        if not states_determinate_address(claim_text):
            return ClassVerdict(
                CLASS_I,
                f"oracle(s) {sorted(conditional)} read the CONTENT of a binary file, and "
                "plan.md 10.3 v2.4 admits that reading into class P only under one "
                "additional mandatory condition: the claim must state the offset (or "
                "another determinate address) AND the length. This claim states neither "
                "both nor a byte range, so the read is not reproducible as written and "
                "class P is inadmissible. This is not a judgement about the fact - write "
                "the address and the extent (\"четыре байта по смещению 48\", \"16 байт по "
                "смещению 64\", \"bytes 0x30..0x33\") and the same claim becomes class P",
                has_primitive_part=primitive)
        if names_what_the_bytes_are(claim_text):
            # The offset is there AND the field is named: this is exactly the
            # canonical A-07 pair written as one record.  MIX-SPLIT is the
            # actionable finding, and v2.4 is what finally makes the split
            # performable - the primitive half now has an admissible oracle.
            return ClassVerdict(
                CLASS_I,
                f"oracle(s) {sorted(conditional)} with a stated offset would be class P, "
                "but the claim also names WHAT was read - a field, a layout, a type or a "
                "signature - and plan.md 10.3 v2.4 puts that step in class I: "
                "\"как только утверждение называет, чем прочитанное является, что оно "
                "значит, или опирается на внешнюю раскладку\". Split it: the bytes at the "
                "offset are class P at OBSERVED, the named field and its decoded value are "
                "class I at INFERRED with an external-doc oracle for the layout",
                mixed=True,
                has_primitive_part=True)

    # --- 4. the wording heuristic, as a supplement ------------------------
    if conclusion:
        # Criterion 3 fails: the statement carries a semantic conclusion while
        # resting on a primitive oracle.  If a primitive half is present too,
        # this is the canonical mixed record that must be split (the A-07 case);
        # if not, the claim is simply class I graded on a class-P oracle.
        return ClassVerdict(
            CLASS_I,
            "the statement carries a semantic conclusion, which plan.md 10.3 "
            "criterion 3 excludes from class P",
            mixed=primitive,
            has_primitive_part=primitive)

    # --- 5. the disk-versus-Steam cross-check -----------------------------
    # plan.md 10.5 matrix row 4 ("на диске лежит то, что Steam обещает") needs
    # BOTH filesystem and steam-metadata, and 10.3 class P criterion 5 says a
    # steam-metadata claim may only report what Steam RECORDS.  Naming both
    # oracles at once is therefore the cross-check claim by construction, and
    # the cross-check is a conclusion about two sources agreeing.  In JSON that
    # follows from claim_type=disk-matches-steam-metadata, which is deliberately
    # outside CLASS_P_CLAIM_TYPES; deriving it from the oracle pair as well is
    # what makes the same claim get the same class in both notations.
    if CROSS_CHECK_ORACLES <= oracles:
        return ClassVerdict(
            CLASS_I,
            f"oracle(s) {sorted(CROSS_CHECK_ORACLES)} are named together, which is the "
            "plan.md 10.5 matrix row \"на диске лежит то, что Steam обещает\" - a claim "
            "that two sources agree is a conclusion about both, not a reading of either "
            "(10.3 class P criterion 5). In JSON the same claim carries "
            "claim_type='disk-matches-steam-metadata', which is likewise outside class P",
            has_primitive_part=primitive)

    return ClassVerdict(
        CLASS_P,
        f"oracle(s) {sorted(oracles)} are primitive readings, evidence_level is "
        f"{level or 'unstated'} and the statement contains no semantic conclusion "
        "(plan.md 10.3)"
        + (f"; {sorted(conditional)} cleared the plan.md 10.3 v2.4 condition - the claim "
           "states a determinate address and a length and does not name what the bytes are"
           if conditional else ""),
        has_primitive_part=primitive)


@dataclass(frozen=True)
class OracleRequirement:
    """One row of the plan.md 10.5 matrix "claim type -> required oracles"."""

    claim_type: str
    description: str
    # every oracle in all_of must be present
    all_of: frozenset[str] = frozenset()
    # at least one oracle from any_of must be present
    any_of: frozenset[str] = frozenset()
    # missing -> warning only ("желательно" in the plan)
    recommended: frozenset[str] = frozenset()
    requires_build_key: bool = True
    # E-3b: "только фактический запуск" -> an experiment reference is required
    requires_experiment: bool = False
    # 10.5 v2.1 vcs-history row: "коммит обязан быть достижим из HEAD"
    requires_reachable_commit: bool = False
    # The catch-all row: using it must cost a written sentence, see the "other"
    # entry below for why.
    requires_justification: bool = False
    provenance: str = ""


# The matrix below is DATA on purpose: when plan.md section 10.5 changes,
# this dict is the single place to update.  `provenance` records where each
# row came from, so a validator-local extension can never be mistaken for a
# plan rule.
#
# The keys are exactly the `claim_type` enum of
# research/schema/kb-record.schema.json, so a record can never satisfy one
# layer and fail the other on vocabulary alone.  Older spellings are accepted
# through CLAIM_TYPE_ALIASES below.
CLAIM_TYPE_ORACLE_MATRIX: dict[str, OracleRequirement] = {
    # ---- rows added by plan.md 10.5 "Правка v2.1" ------------------------
    "file-exists": OracleRequirement(
        claim_type="file-exists",
        description="file X exists / is absent, has size S and hash H",
        all_of=frozenset({"filesystem"}),
        requires_build_key=False,
        provenance="plan.md 10.5 v2.1 matrix row 1 (one oracle is enough)",
    ),
    "install-file-count": OracleRequirement(
        claim_type="install-file-count",
        description="the installation consists of N files / M directories",
        all_of=frozenset({"filesystem"}),
        provenance="plan.md 10.5 v2.1 matrix row 2 (one oracle is enough); the "
                   "count is a property of one build, hence build_key",
    ),
    "steam-metadata-fact": OracleRequirement(
        claim_type="steam-metadata-fact",
        description="Steam records buildid B / depot D / manifest M for the app",
        all_of=frozenset({"steam-metadata"}),
        provenance="plan.md 10.5 v2.1 matrix row 3 (one oracle is enough, and it "
                   "proves only what Steam recorded)",
    ),
    "disk-matches-steam-metadata": OracleRequirement(
        claim_type="disk-matches-steam-metadata",
        description="what lies on disk is what Steam promises",
        all_of=frozenset({"filesystem", "steam-metadata"}),
        provenance="plan.md 10.5 v2.1 matrix row 4: BOTH are required - that is "
                   "the whole content of the claim",
    ),
    "commit-content": OracleRequirement(
        claim_type="commit-content",
        description="the repository contains commit C with content Y",
        all_of=frozenset({"vcs-history"}),
        requires_build_key=False,
        requires_reachable_commit=True,
        provenance="plan.md 10.5 v2.1 matrix row 5: one oracle is enough, but the "
                   "commit must be reachable from HEAD at the time of writing",
    ),
    # ---- rows present since the first edition of 10.5 --------------------
    "native-class-exists": OracleRequirement(
        claim_type="native-class-exists",
        description="the build contains native/script object name X",
        any_of=frozenset({"global-ucas", "runtime-reflection"}),
        provenance="plan.md 10.5 matrix row 1",
    ),
    "asset-exists": OracleRequirement(
        claim_type="asset-exists",
        description="the game contains asset/package X (/Game/...)",
        any_of=frozenset({"asset-registry", "runtime-reflection"}),
        provenance="plan.md 10.5 matrix row 2, PLUS the one exception 10.5 writes out "
                   "itself: \"Имя вида BP_Something_C, найденное в пуле имён, даёт только "
                   "HYPOTHESIS о существовании соответствующего asset-а, с confidence "
                   "<= 0.4\". So global-ucas alone carries exactly that record and nothing "
                   "stronger; asset-registry or runtime-reflection is required for the "
                   "assertion. Until validator 3.2.0 the row was unconditional and "
                   "rejected the plan's own canonical correct example "
                   "(research/evidence-model.md), which is the failure mode of a gate "
                   "stricter than its rule book. The caps stay enforced by C-11",
    ),
    "class-inherits-from": OracleRequirement(
        claim_type="class-inherits-from",
        description="class X derives from Y",
        all_of=frozenset({"runtime-reflection"}),
        provenance="plan.md 10.5 matrix row 3",
    ),
    "class-property": OracleRequirement(
        claim_type="class-property",
        description="X has property Y of type T at offset O, ordinal N",
        all_of=frozenset({"runtime-reflection"}),
        requires_build_key=True,
        provenance="plan.md 10.5 matrix row 4 (offset always bound to build_key)",
    ),
    "function-behavior": OracleRequirement(
        claim_type="function-behavior",
        description="function X does Z",
        all_of=frozenset({"binary-analysis", "runtime-reflection"}),
        provenance="plan.md 10.5 matrix row 5 (one oracle is NOT enough)",
    ),
    "container-format": OracleRequirement(
        claim_type="container-format",
        description="container has flag/format F",
        all_of=frozenset({"container-metadata"}),
        provenance="plan.md 10.5 matrix row 6",
    ),
    "container-mounted-at-runtime": OracleRequirement(
        claim_type="container-mounted-at-runtime",
        description="the game mounts container C at runtime",
        all_of=frozenset({"runtime-reflection"}),
        provenance="plan.md 10.5 matrix row 7 (container-metadata does not prove it)",
    ),
    "item-registration-mechanism": OracleRequirement(
        claim_type="item-registration-mechanism",
        description="the game registers item definitions by mechanism M (CR-01)",
        all_of=frozenset({"runtime-reflection", "asset-registry"}),
        recommended=frozenset({"binary-analysis"}),
        provenance="plan.md 10.5 matrix row 8 (at least two oracles)",
    ),
    "cooked-bp-from-external-container-works": OracleRequirement(
        claim_type="cooked-bp-from-external-container-works",
        description="a cooked BP from an external container works (E-3b)",
        all_of=frozenset({"runtime-reflection"}),
        requires_experiment=True,
        provenance="plan.md 10.5 matrix row 9 (experiment + runtime-reflection)",
    ),
    # ---- bookkeeping rows -----------------------------------------------
    # plan.md 10.5 has no matrix row for these, yet the artifacts of plan.md 19
    # need them.  They exist in the kb-record schema enum; the oracle sets here
    # are VALIDATOR-LOCAL and marked as such, so nobody mistakes them for plan
    # rules.  Replace them the moment plan.md 10.5 grows the corresponding rows.
    "engine-identity": OracleRequirement(
        claim_type="engine-identity",
        description="engine version / CL / branch / configuration of this build",
        any_of=frozenset({"binary-analysis", "runtime-reflection", "container-metadata"}),
        provenance="VALIDATOR-LOCAL (plan gap: 10.5 has no row for section 4 claims). "
                   "filesystem is deliberately NOT accepted here: a file's name and "
                   "size say nothing about which engine built it",
    ),
    "build-identity": OracleRequirement(
        claim_type="build-identity",
        description="filesystem/PE/Steam-level fact about this install "
                    "(path, size, hash, PE section, manifest anomaly)",
        any_of=frozenset({"filesystem", "steam-metadata",
                          "container-metadata", "binary-analysis"}),
        provenance="plan.md 10.5 v2.1 rows 1-3 for the path/size/hash and Steam "
                   "parts; PE-section and manifest-anomaly parts additionally "
                   "admit binary-analysis / container-metadata. Prefer the "
                   "narrower file-exists / install-file-count / "
                   "steam-metadata-fact rows when the claim fits one of them",
    ),
    "layout-observation": OracleRequirement(
        claim_type="layout-observation",
        description="recovered memory layout of a structure",
        any_of=frozenset({"runtime-reflection", "binary-analysis"}),
        requires_build_key=True,
        provenance="plan.md 6.3 final rule: an offset from static analysis is a "
                   "HYPOTHESIS; only a runtime dump yields OBSERVED (enforced "
                   "separately as rule EV-LAYOUT)",
    ),
    "other": OracleRequirement(
        claim_type="other",
        description="bookkeeping row: anything the matrix does not cover, including "
                    "vanilla-UE reference statements",
        any_of=frozenset(ORACLES),
        requires_build_key=False,
        requires_justification=True,
        provenance="VALIDATOR-LOCAL catch-all; the only rule left is that some oracle "
                   "must be named (plan.md 10.5) and C-12 still caps external-doc-only "
                   "confidence at 0.7. Since validator 3.2.0 it also requires a written "
                   "justification: this is the one catch-all in the rule set and "
                   "therefore a route past both the specific oracle pairings and the "
                   "build_key requirement. It is NOT narrowed away, because a research "
                   "vocabulary that cannot say \"the matrix has no row for this yet\" "
                   "pushes authors to mislabel instead - and a mislabelled row is "
                   "invisible where an honest 'other' is countable. What is removed is "
                   "the free ride: naming it costs one sentence saying why no row fits, "
                   "which is also the text that tells a later reader which 10.5 row is "
                   "missing",
    ),
}

# Fields accepted as the written justification for claim_type='other'.
JUSTIFICATION_KEYS: tuple[str, ...] = (
    "claim_type_note",
    "claim_type_justification",
    "matrix_gap",
    "justification",
)

# The same justification, written in prose: a markdown record has no fields, so
# it names one of the keys above or says outright which 10.5 row is missing.
JUSTIFICATION_MENTION_RE = re.compile(
    r"(?:claim[_\s-]?type[_\s-]?note|claim[_\s-]?type[_\s-]?justification|"
    r"matrix[_\s-]?gap|нет\s+строки\s+в\s+матрице|матрица\s+10\.5\s+не\s+содержит|"
    r"no\s+matrix\s+row)",
    re.IGNORECASE)

# Accepted older/alternative spellings -> canonical key above.  Kept so the
# vocabulary can evolve without invalidating already written records.
CLAIM_TYPE_ALIASES: dict[str, str] = {
    "filesystem-fact": "file-exists",
    "file-absent": "file-exists",
    "install-inventory-fact": "install-file-count",
    "steam-fact": "steam-metadata-fact",
    "commit-exists": "commit-content",
    "vcs-history-fact": "commit-content",
    "class-inheritance": "class-inherits-from",
    "property-layout": "class-property",
    "container-mounted-runtime": "container-mounted-at-runtime",
    "registration-mechanism": "item-registration-mechanism",
    "external-container-bp-works": "cooked-bp-from-external-container-works",
    "install-layout-fact": "build-identity",
    "engine-build-identity": "engine-identity",
    "vanilla-ue-reference": "other",
}


def resolve_claim_type(claim_type: str) -> str:
    return CLAIM_TYPE_ALIASES.get(claim_type, claim_type)


def normalise_claim_type(raw: str | None) -> str | None:
    """Canonicalise a claim_type as written in a document.

    Markdown authors write the value with backticks, in a table cell, sometimes
    with an underscore and sometimes with a hyphen.  Returns None for an empty
    value; an unknown value is returned as written so the caller can report it.
    """
    if raw is None:
        return None
    key = " ".join(str(raw).strip().strip("`*_.,;:").lower().split())
    if not key or key in NON_CLAIMED_CELL:
        return None
    key = key.replace(" ", "-").replace("_", "-")
    return resolve_claim_type(key)


def claim_type_candidates(oracles: set[str]) -> list[str]:
    """The plan.md 10.5 matrix rows whose oracle requirement this record meets.

    Not a guess at the record's claim_type - the validator must never invent
    one, because a claim_type decides the class and inventing it would derive a
    class from missing data.  It is the SHORTLIST the author has to choose from,
    which is what turns "this record has no claim_type" into an actionable
    remedy instead of a standing disclosure.
    """
    matches: list[str] = []
    for name, row in CLAIM_TYPE_ORACLE_MATRIX.items():
        if row.requires_justification:
            continue
        if row.all_of and not row.all_of <= oracles:
            continue
        if row.any_of and not (row.any_of & oracles):
            continue
        matches.append(name)
    return sorted(matches)


def claim_type_gap_remedy(notation: str, oracles: set[str]) -> str:
    """One sentence saying what would close the claim_type gap for a record."""
    where = CLAIM_TYPE_FIELD_BY_NOTATION.get(
        notation, "give this record a claim_type field")
    oracle_bit = ", ".join(sorted(oracles)) or "no oracle named"
    candidates = claim_type_candidates(oracles)
    if candidates:
        rows = ", ".join(
            f"{name} ({CLASS_P if name in CLASS_P_CLAIM_TYPES else CLASS_I})"
            for name in candidates)
        choice = (f"rows admissible on oracle {{{oracle_bit}}}: {rows}")
    else:
        choice = (f"NO matrix row is satisfiable on oracle {{{oracle_bit}}}, so the "
                  "honest value is `other`, which plan.md 10.5 admits only with a "
                  "written justification in the record")
    return f"{where}; {choice}"


def check_claim_type_matrix(
    pointer: str,
    claim_type: str,
    oracles: set[str],
    record_text: str = "",
    has_justification: bool = False,
    evidence_level: str | None = None,
    confidence: float | None = None,
) -> tuple[OracleRequirement | None, list[Finding]]:
    """The plan.md 10.5 "claim type -> required oracles" matrix, for ONE record.

    Shared by the JSON and the markdown layer since validator 3.2.0.  Before
    that the matrix lived inside lint_record() and so applied to JSON records
    only, which meant the same claim got a different class in the two
    notations: "what is on disk matches what Steam records" has claim_type
    `disk-matches-steam-metadata`, deliberately outside the class P claim
    types, so in JSON it derived class I - while in markdown, where nothing
    consulted a claim_type at all, it derived class P because both its oracles
    are primitive.  Markdown carries 216 of the 228 records in this
    repository, so that gap was where the rule stopped applying.
    """
    findings: list[Finding] = []
    err = lambda rule, msg: findings.append(Finding(SEVERITY_ERROR, rule, pointer, msg))  # noqa: E731
    warn = lambda rule, msg: findings.append(Finding(SEVERITY_WARN, rule, pointer, msg))  # noqa: E731

    if claim_type not in CLAIM_TYPE_ORACLE_MATRIX:
        err("EV-04", f"unknown claim_type {claim_type!r}; known: "
                     f"{', '.join(sorted(CLAIM_TYPE_ORACLE_MATRIX))}")
        return None, findings

    requirement = CLAIM_TYPE_ORACLE_MATRIX[claim_type]

    # plan.md 10.5 "Обязательное правило" spells out ONE case the matrix row for
    # asset-exists would otherwise reject: "Имя вида `BP_Something_C`, найденное
    # в пуле имён, даёт только HYPOTHESIS о существовании соответствующего
    # asset-а, с confidence <= 0.4".  So the plan permits exactly that record on
    # global-ucas alone, and requires asset-registry / runtime-reflection for
    # anything stronger.  Until validator 3.2.0 the matrix row was unconditional
    # and validator-local-stricter than the plan on a case the plan writes out,
    # which made the correctly written record the one that failed - and the
    # canonical correct example in research/evidence-model.md is that record.
    # The caps themselves are not relaxed: rule C-11 still enforces HYPOTHESIS
    # and <= 0.4 for a /Game or Blueprint-shaped name known only from global.ucas.
    if claim_type == "asset-exists" and oracles == {"global-ucas"} \
            and (evidence_level or "").strip().upper() == "HYPOTHESIS" \
            and confidence is not None \
            and confidence <= GLOBAL_UCAS_ASSET_MAX_CONFIDENCE:
        return requirement, findings

    if oracles:
        missing_all = sorted(requirement.all_of - oracles)
        if missing_all:
            err("EV-04", f"claim_type {claim_type!r} requires oracle(s) {missing_all}, "
                         f"record has {sorted(oracles)} [{requirement.provenance}]")
        if requirement.any_of and not (requirement.any_of & oracles):
            err("EV-04", f"claim_type {claim_type!r} requires at least one of "
                         f"{sorted(requirement.any_of)}, record has {sorted(oracles)} "
                         f"[{requirement.provenance}]")
        missing_reco = sorted(requirement.recommended - oracles)
        if missing_reco:
            warn("EV-04", f"claim_type {claim_type!r}: oracle(s) {missing_reco} are "
                          f"recommended but absent [{requirement.provenance}]")
    if requirement.requires_justification and not has_justification:
        err("EV-04", f"claim_type {claim_type!r} is the catch-all row of the plan.md 10.5 "
                     "matrix, and it is the one route past both the specific oracle "
                     "pairings and the build_key requirement. Using it requires a written "
                     f"justification - one of the fields {list(JUSTIFICATION_KEYS)} in "
                     "JSON, or a sentence in the record naming the 10.5 row that is "
                     "missing - so that the choice is a deliberate, auditable act and the "
                     "gap it stands for is recorded where the next author will find it")
    return requirement, findings

# Keys whose presence means the record claims memory layout / ordering.
# C-11: such a claim can never rest on global-ucas alone.
LAYOUT_KEYS: tuple[str, ...] = (
    "offset",
    "offsets",
    "byte_offset",
    "property_offset",
    "size",
    "struct_size",
    "element_size",
    "alignment",
    "index",
    "property_index",
    "ordinal",
    "order",
    "vtable_index",
    "rep_index",
)

# Values that mean "deliberately not claimed" and therefore do not trip C-11.
NON_CLAIMING_VALUES = (None, "UNKNOWN", "unknown", "")

# Keys scanned for /Game references.
ASSET_PATH_KEYS: tuple[str, ...] = (
    "package",
    "package_path",
    "asset",
    "asset_path",
    "object_path",
    "path",
    "raw_name",
    "name",
    "outer",
)

BUILD_KEY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MARKER_KEYS: tuple[str, ...] = ("evidence_level", "claim_type", "oracle", "confidence")


# ---------------------------------------------------------------------------
# 3. Findings
# ---------------------------------------------------------------------------

SEVERITY_ERROR = "ERROR"
SEVERITY_WARN = "WARN"


@dataclass
class Finding:
    severity: str
    rule: str
    pointer: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "pointer": self.pointer,
            "message": self.message,
        }


@dataclass
class FileReport:
    path: str
    kind: str | None = None
    schema: str | None = None
    schema_status: str = "not-applicable"
    record_count: int = 0
    # How many of `record_count` were the REDUCED annotation envelope of
    # kb-record.schema.json#/$defs/annotation rather than a full record (see
    # section 5b).  Counted and printed on purpose: an annotation is linted by a
    # smaller rule set, and a reclassification nobody can see is a hole.
    annotation_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    # markdown layer bookkeeping (section 6b)
    unparseable_count: int = 0
    suppressed_count: int = 0
    non_fact_tables: int = 0
    exempt: bool = False
    # Named DEF-TABLE exemptions, one string per exempted table, printed in the
    # EXEMPTIONS block so no table is ever skipped invisibly.
    definition_tables: list[str] = field(default_factory=list)
    # Records marked `<!-- kb-validate: quoted-example -->`, one string each.
    # Printed in the same EXEMPTIONS block: a quoted example is excused from the
    # rules, so every use of the marker is named, counted and auditable.
    quoted_examples: list[str] = field(default_factory=list)
    # Spans recognised as a NORMATIVE ENUMERATION of permitted levels rather
    # than as a record (see is_normative_level_enumeration).  Printed in the
    # EXEMPTIONS block for the same reason: the parser decided not to read a
    # graded-looking span as a fact, and that decision has to be visible.
    normative_enumerations: list[str] = field(default_factory=list)
    # Conclusion markers that section 2d read as MENTIONED rather than asserted,
    # one string per marker with the clause it sits in.  Printed in the
    # EXEMPTIONS block: MIX-SPLIT is an ERROR, so every marker the parser
    # declined to count towards it has to be visible and countable.
    mix_scope_spans: list[str] = field(default_factory=list)
    # Markdown records at confidence >= 0.95 that carry no claim_type, so the
    # plan.md 10.5 matrix could not be applied to them.  Named per record
    # instead of disclosed in aggregate.
    claim_type_gaps: list[str] = field(default_factory=list)
    # (remedy sentence, "path:Lnnn") for each of those records, so the block can
    # say WHAT would close each one and not only that a gap exists.  Grouped by
    # remedy at print time - the same remedy usually covers a whole table.
    claim_type_gap_remedies: list[tuple[str, str]] = field(default_factory=list)
    notation_counts: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.severity == SEVERITY_ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == SEVERITY_WARN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "schema": self.schema,
            "schema_status": self.schema_status,
            "record_count": self.record_count,
            "annotation_count": self.annotation_count,
            "unparseable_count": self.unparseable_count,
            "suppressed_count": self.suppressed_count,
            "non_fact_tables": self.non_fact_tables,
            "exempt": self.exempt,
            "definition_tables": list(self.definition_tables),
            "quoted_examples": list(self.quoted_examples),
            "normative_enumerations": list(self.normative_enumerations),
            "mix_scope_spans": list(self.mix_scope_spans),
            "claim_type_gaps": list(self.claim_type_gaps),
            "notations": dict(self.notation_counts),
            "errors": self.errors,
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# 4. Built-in minimal JSON Schema validator (fallback)
# ---------------------------------------------------------------------------

class MinimalSchemaValidator:
    """Deliberately small JSON Schema subset validator.

    Enforced: type, required, properties, additionalProperties (bool),
    items, contains, enum, const, minimum/maximum, exclusiveMinimum/
    exclusiveMaximum, minLength/maxLength, minItems/maxItems, uniqueItems,
    pattern, allOf, anyOf, oneOf, not, if/then/else, and $ref both local and
    to a sibling file in research/schema/.  Everything else - notably
    unevaluatedProperties and format - is recorded in `ignored_keywords` and
    reported, never silently dropped.
    """

    SUPPORTED = frozenset({
        "$ref", "type", "required", "properties", "additionalProperties",
        "items", "contains", "enum", "const", "minimum", "maximum",
        "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength",
        "minItems", "maxItems", "uniqueItems", "pattern", "allOf", "anyOf",
        "oneOf", "not", "if", "then", "else",
        # metadata keywords, nothing to enforce
        "$schema", "$id", "$defs", "definitions", "title", "description",
        "examples", "default", "comment", "$comment", "deprecated",
    })

    TYPE_MAP: dict[str, tuple[type, ...]] = {
        "object": (dict,),
        "array": (list,),
        "string": (str,),
        "boolean": (bool,),
        "null": (type(None),),
    }

    def __init__(self, schema: dict[str, Any], schema_dir: Path | None = None) -> None:
        self.schema = schema
        self.schema_dir = schema_dir
        self.ignored_keywords: set[str] = set()
        self._sibling_cache: dict[str, dict[str, Any] | None] = {}

    def iter_errors(self, instance: Any) -> Iterator[tuple[str, str]]:
        yield from self._validate(instance, self.schema, "$", self.schema)

    # -- internals ------------------------------------------------------
    def _load_sibling(self, filename: str) -> dict[str, Any] | None:
        """Load another schema file from research/schema/ for a cross-file $ref."""
        if filename in self._sibling_cache:
            return self._sibling_cache[filename]
        document: dict[str, Any] | None = None
        if self.schema_dir is not None:
            path = self.schema_dir / filename
            if path.is_file():
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError, UnicodeDecodeError):
                    loaded = None
                if isinstance(loaded, dict):
                    document = loaded
        self._sibling_cache[filename] = document
        return document

    def _resolve(
        self, ref: str, base: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Resolve '#/a/b', 'file.schema.json#/a/b' and '<$id>#/a/b'.

        Returns (subschema, new base document).  Following a cross-file $ref
        switches the base, so that local '#/$defs/...' refs *inside* the
        imported subschema resolve against the file they came from.
        """
        head, _, fragment = ref.partition("#")
        root: Any = base
        if head:
            filename = head.rstrip("/").rsplit("/", 1)[-1]
            if not filename:
                return None
            root = self._load_sibling(filename)
            if root is None:
                return None
        node: Any = root
        for token in fragment.strip("/").split("/"):
            if token == "":
                continue
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and token in node:
                node = node[token]
            else:
                return None
        if not isinstance(node, dict):
            return None
        return node, root

    def _check_type(self, instance: Any, expected: str) -> bool:
        if expected == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if expected == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        if expected == "boolean":
            return isinstance(instance, bool)
        types = self.TYPE_MAP.get(expected)
        if types is None:
            self.ignored_keywords.add(f"type:{expected}")
            return True
        if isinstance(instance, bool):
            # bool is a subclass of int; only "boolean" accepts it
            return False
        return isinstance(instance, types)

    def _validate(
        self, instance: Any, schema: Any, ptr: str, base: dict[str, Any]
    ) -> Iterator[tuple[str, str]]:
        if schema is True or schema == {}:
            return
        if schema is False:
            yield ptr, "schema forbids any value here"
            return
        if not isinstance(schema, dict):
            yield ptr, f"malformed schema node (expected object, got {type(schema).__name__})"
            return

        for key in schema:
            if key not in self.SUPPORTED:
                self.ignored_keywords.add(key)

        if "$ref" in schema:
            resolved = self._resolve(schema["$ref"], base)
            if resolved is None:
                self.ignored_keywords.add(f"$ref:{schema['$ref']}")
            else:
                target, new_base = resolved
                yield from self._validate(instance, target, ptr, new_base)

        if "type" in schema:
            expected = schema["type"]
            candidates = expected if isinstance(expected, list) else [expected]
            if not any(self._check_type(instance, str(t)) for t in candidates):
                yield ptr, f"type mismatch: expected {expected}, got {type(instance).__name__}"
                return  # further keyword checks would be noise

        if "enum" in schema and instance not in schema["enum"]:
            yield ptr, f"value {instance!r} not in enum {schema['enum']!r}"

        if "const" in schema and instance != schema["const"]:
            yield ptr, f"value {instance!r} != const {schema['const']!r}"

        if isinstance(instance, dict):
            for name in schema.get("required", []) or []:
                if name not in instance:
                    yield ptr, f"missing required property {name!r}"
            props = schema.get("properties") or {}
            for name, subschema in props.items():
                if name in instance:
                    yield from self._validate(instance[name], subschema,
                                              f"{ptr}.{name}", base)
            extra = schema.get("additionalProperties", None)
            if extra is False:
                unknown = sorted(set(instance) - set(props))
                for name in unknown:
                    yield ptr, f"additional property {name!r} is not allowed"

        if isinstance(instance, list):
            items = schema.get("items")
            if isinstance(items, dict) or isinstance(items, bool):
                for i, item in enumerate(instance):
                    yield from self._validate(item, items, f"{ptr}[{i}]", base)
            if "minItems" in schema and len(instance) < schema["minItems"]:
                yield ptr, f"array too short: {len(instance)} < minItems {schema['minItems']}"
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                yield ptr, f"array too long: {len(instance)} > maxItems {schema['maxItems']}"
            if schema.get("uniqueItems") is True:
                seen: list[Any] = []
                for item in instance:
                    if item in seen:
                        yield ptr, f"array has duplicate item {item!r} but uniqueItems is set"
                        break
                    seen.append(item)
            contains = schema.get("contains")
            if isinstance(contains, (dict, bool)):
                if not any(not list(self._validate(item, contains, ptr, base))
                           for item in instance):
                    yield ptr, "no array item satisfies the 'contains' schema"

        if isinstance(instance, str):
            if "minLength" in schema and len(instance) < schema["minLength"]:
                yield ptr, f"string too short: {len(instance)} < minLength {schema['minLength']}"
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                yield ptr, f"string too long: {len(instance)} > maxLength {schema['maxLength']}"
            if "pattern" in schema:
                try:
                    if re.search(schema["pattern"], instance) is None:
                        yield ptr, f"string does not match pattern {schema['pattern']!r}"
                except re.error:
                    self.ignored_keywords.add("pattern:invalid-regex")

        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                yield ptr, f"{instance} < minimum {schema['minimum']}"
            if "maximum" in schema and instance > schema["maximum"]:
                yield ptr, f"{instance} > maximum {schema['maximum']}"
            if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
                yield ptr, f"{instance} <= exclusiveMinimum {schema['exclusiveMinimum']}"
            if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
                yield ptr, f"{instance} >= exclusiveMaximum {schema['exclusiveMaximum']}"

        for subschema in schema.get("allOf", []) or []:
            yield from self._validate(instance, subschema, ptr, base)

        for keyword in ("anyOf", "oneOf"):
            branches = schema.get(keyword)
            if not branches:
                continue
            matches = 0
            for subschema in branches:
                if not list(self._validate(instance, subschema, ptr, base)):
                    matches += 1
            if matches == 0:
                yield ptr, f"value satisfies none of the {keyword} branches"
            elif keyword == "oneOf" and matches > 1:
                yield ptr, f"value satisfies {matches} oneOf branches, expected exactly 1"

        negated = schema.get("not")
        if isinstance(negated, (dict, bool)) and not list(
                self._validate(instance, negated, ptr, base)):
            yield ptr, "value matches the 'not' schema but must not"

        # if / then / else: the conditional form kb-record.schema.json uses to
        # encode EV-03 and the oracle matrix declaratively.
        if "if" in schema:
            condition_holds = not list(self._validate(instance, schema["if"], ptr, base))
            branch = schema.get("then") if condition_holds else schema.get("else")
            if isinstance(branch, (dict, bool)):
                yield from self._validate(instance, branch, ptr, base)


def _jsonschema_registry(schema_dir: Path | None):  # pragma: no cover - needs jsonschema
    """Registry of every local schema, so cross-file $refs resolve offline.

    kb-record.schema.json states that domain schemas will $ref it by $id; no
    network lookup is ever acceptable, so every sibling file is registered
    under both its $id and its bare filename.
    """
    if schema_dir is None or not schema_dir.is_dir():
        return None
    try:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except Exception:  # noqa: BLE001
        return None
    resources = []
    for path in sorted(schema_dir.glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        # default_specification must be a referencing Specification, NOT a
        # meta-schema dict: Resource.from_contents() calls
        # default_specification.detect(contents) unconditionally, so a dict
        # raises AttributeError("'dict' object has no attribute 'detect'") and
        # the caller misreports it as "schema itself is invalid".
        resource = Resource.from_contents(document, default_specification=DRAFT202012)
        for uri in {document.get("$id"), path.name}:
            if uri:
                resources.append((uri, resource))
    return Registry().with_resources(resources) if resources else None


def validate_against_schema(
    instance: Any,
    schema: dict[str, Any],
    pointer_prefix: str = "$",
    schema_dir: Path | None = None,
) -> tuple[list[tuple[str, str]], set[str], str]:
    """Validate `instance`; returns (errors, ignored_keywords, backend)."""
    if HAVE_JSONSCHEMA:  # pragma: no cover - environment dependent
        errors: list[tuple[str, str]] = []
        ignored: set[str] = set()
        try:
            cls = _jsonschema.validators.validator_for(schema)  # type: ignore[union-attr]
            cls.check_schema(schema)
            registry = _jsonschema_registry(schema_dir)
            validator = cls(schema, registry=registry) if registry is not None else cls(schema)
        except Exception as exc:  # noqa: BLE001
            return ([(pointer_prefix, f"schema itself is invalid: {exc}")], set(), "jsonschema")
        try:
            found = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
        except Exception as exc:  # noqa: BLE001 - unresolvable $ref, recursion, ...
            return ([(pointer_prefix, f"schema could not be applied: {exc}")],
                    {"cross-file-$ref"}, "jsonschema")
        for err in found:
            path = pointer_prefix
            for part in err.absolute_path:
                path += f"[{part}]" if isinstance(part, int) else f".{part}"
            errors.append((path, err.message))
        return errors, ignored, "jsonschema"

    validator = MinimalSchemaValidator(schema, schema_dir=schema_dir)
    errors = [
        (pointer_prefix + ptr[1:] if ptr.startswith("$") else ptr, msg)
        for ptr, msg in validator.iter_errors(instance)
    ]
    return errors, validator.ignored_keywords, "builtin-minimal"


# ---------------------------------------------------------------------------
# 5. Record extraction
# ---------------------------------------------------------------------------

def _looks_like_claim_value(value: Any) -> bool:
    """Reject schema-shaped values: a marker key mapped to an object/nested list.

    Without this, a JSON Schema's own `properties: {claim_type: {...}}` would be
    mistaken for a knowledge-base record.
    """
    if isinstance(value, dict):
        return False
    if isinstance(value, list):
        return all(not isinstance(item, (dict, list)) for item in value)
    return True


def is_record(node: Any) -> bool:
    """A dict is an evidence-bearing record if it carries any marker key."""
    if not isinstance(node, dict):
        return False
    return any(key in node and _looks_like_claim_value(node[key]) for key in MARKER_KEYS)


# ---------------------------------------------------------------------------
# 5b. The REDUCED annotation envelope
# ---------------------------------------------------------------------------
# WHY THIS EXISTS.  is_record() fires on any dict carrying `oracle`, and that is
# correct: an oracle is a claim about where knowledge came from.  But
# kb-record.schema.json defines TWO evidence-bearing shapes, not one:
#
#   #/$defs/envelope    the FULL knowledge-base record - record_id, recorded_at,
#                       statement, claim_type, build_key, ...
#   #/$defs/annotation  a REDUCED envelope for ATTACHING evidence metadata to a
#                       SUB-OBJECT of a larger artifact, "where the full envelope
#                       with recorded_at and build_key would be redundant because
#                       the enclosing document already states them"
#
# Until validator 3.4.0 only the first shape existed here, so every annotation
# inside research/builds/<build-id>/fingerprint.json was linted as a full record
# and asked for `claim_type` and `build_key`.  The annotation schema neither
# defines those two properties nor permits them - it is additionalProperties
# false - so the validator demanded exactly what the schema forbids, and no
# document could satisfy both.  Measured on the fingerprint.json of task F-03:
# 2 errors per annotation, unfixable from the document side.  Task F-02 shipped
# a `--no-entry-evidence` switch to dodge it, which bought a clean run by
# DELETING the grading - the wrong trade.
#
# THE LINE THIS FIX DRAWS.  An annotation is linted by every rule whose remedy
# the annotation schema permits, and by no rule whose remedy it forbids:
#
#   kept     EV-LEVEL, EV-CONF, EV-03 (sources), EV-04 (oracle vocabulary),
#            EV-05 / MIX-SPLIT / CLASS-P / CLASS-I, C-11, C-12, EV-LAYOUT
#   dropped  the plan.md 10.5 claim_type matrix and EV-BUILD - `claim_type` and
#            `build_key` are the two properties the reduced envelope forbids
#
# Dropping the matrix is not a loophole, it is what the schema says the shape
# means: "an annotation inherits its matrix row from the enclosing document"
# (kb-record.schema.json#/$defs/annotation, $comment).  The enclosing document
# states build_key once - fingerprint.json carries it in identity.build_key -
# and repeating it on every sub-object would be the redundancy the reduced
# envelope exists to remove.  Every annotation the run linted is COUNTED and
# printed, so the reclassification is never invisible.

# The closed property set of kb-record.schema.json#/$defs/annotation.  It is
# duplicated here rather than read from the schema at runtime because the
# validator must work with the schema directory missing or unreadable; the
# duplication is pinned to the schema by a contract test, so the two cannot
# drift apart silently.
ANNOTATION_KEYS: frozenset[str] = frozenset({
    "evidence_level", "claim_class", "confidence", "sources", "oracle",
    "read_locus", "note",
})

# The properties that make a dict a FULL record.  Present here only as
# documentation of what the subset test above excludes: any one of these keys
# takes the object out of the annotation shape, because the annotation schema
# would reject it outright.
FULL_RECORD_ONLY_KEYS: frozenset[str] = frozenset({
    "claim_type", "build_key", "record_id", "recorded_at", "statement",
    "refuted_by",
})


def is_annotation(node: Any, *, at_root: bool = False) -> bool:
    """True when *node* is the reduced annotation envelope, not a full record.

    Three conditions, all required:

    1. it is evidence-bearing at all (``is_record``) - a plain sub-object with
       no marker key is not linted either way;
    2. every key it carries is one the annotation schema defines.  One key
       outside that set (``claim_type``, ``build_key``, ``record_id``, a
       ``statement`` ...) means the author wrote a full record, and a full
       record is held to the full rules;
    3. it is NOT the root of its document.  The schema calls the annotation a
       shape for a SUB-OBJECT of a larger artifact; a file whose whole content
       is one graded object is a standalone knowledge-base record
       (ARTIFACT_SCHEMA_MAP maps research/kb/*.json to the full envelope), and
       it has nowhere to inherit a build_key from.
    """
    if at_root or not is_record(node):
        return False
    return set(node) <= ANNOTATION_KEYS


def iter_records(data: Any, pointer: str = "$") -> Iterator[tuple[str, dict[str, Any]]]:
    """Walk a decoded JSON document, yielding (json-pointer, record).

    Both shapes are yielded; the caller decides which rule set applies by asking
    :func:`is_annotation`.  Keeping the walk shape-blind means an annotation is
    never silently skipped - it is linted, counted and printed either way.
    """
    if isinstance(data, dict):
        if is_record(data):
            yield pointer, data
        for key, value in data.items():
            yield from iter_records(value, f"{pointer}.{key}")
    elif isinstance(data, list):
        for i, value in enumerate(data):
            yield from iter_records(value, f"{pointer}[{i}]")


def get_sources(record: dict[str, Any]) -> tuple[list[Any] | None, str | None]:
    """Return (sources list, key used).

    Canonical key is `sources` (plan.md 10.4/EV-02).  plan.md 6.3 shows the
    reflection example using `source`, so both are accepted.
    """
    for key in ("sources", "source"):
        if key in record:
            value = record[key]
            if isinstance(value, list):
                return value, key
            return None, key
    return None, None


def get_oracles(record: dict[str, Any]) -> tuple[set[str], bool]:
    """Return (oracle set, present flag).  `oracle` may be a str or a list."""
    if "oracle" not in record:
        return set(), False
    value = record["oracle"]
    if isinstance(value, str):
        return {value}, True
    if isinstance(value, list):
        return {v for v in value if isinstance(v, str)}, True
    return set(), True


def mentions_game_asset(record: dict[str, Any]) -> tuple[str, str] | None:
    """Find a /Game reference in a record (key, value) or None."""
    for key in ASSET_PATH_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value.startswith("/Game"):
            return key, value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.startswith("/Game"):
                    return key, item
    return None


def looks_like_blueprint_name(record: dict[str, Any]) -> str | None:
    for key in ("raw_name", "name", "class_name"):
        value = record.get(key)
        if isinstance(value, str) and value.endswith("_C") and len(value) > 2:
            return value
    return None


def claims_layout(record: dict[str, Any]) -> list[str]:
    hits = []
    for key in LAYOUT_KEYS:
        if key not in record:
            continue
        value = record[key]
        if isinstance(value, str) and value in NON_CLAIMING_VALUES:
            continue
        if value is None:
            continue
        hits.append(key)
    return hits


# ---------------------------------------------------------------------------
# 6. Lint rules
# ---------------------------------------------------------------------------

COMMIT_KEYS: tuple[str, ...] = ("commit", "commit_hash", "commit_id", "revision")


def lint_claim_class(
    pointer: str,
    *,
    oracles: set[str],
    claim_type: str | None,
    claim_text: str,
    confidence: float | None,
    explicit_raw: str | None,
    sources: list[Any] | None,
    sources_checkable: bool,
    evidence_level: str | None = None,
    build_key: str | None = None,
    evidence_refs: Sequence[str] = (),
    method_present: bool = True,
    notation: str = "json",
    counterpart_ids: Collection[str] = (),
    build_key_field_available: bool = True,
) -> tuple[ClassVerdict, list[Finding]]:
    """Derive the claim class and apply the criteria plan.md 10.3 v2.2 attaches.

    ONE implementation, shared by the JSON and the markdown layer, so the two
    can never drift into grading the same claim differently.  Returns the
    verdict as well as the findings, so the caller can report the class.

    Rules applied here:
      EV-05      an explicit `claim_class` that contradicts the derived one, or
                 a value outside {P, I}
      MIX-SPLIT  one record packing a primitive and an interpretive claim
                 ("Смешанные утверждения обязаны разделяться")
      EV-03      class I: >= 2 independent methods from confidence 0.80.
                 class P: ONE method suffices - but there must BE one, and a
                 second reading of the same primitive is not a second method
      CLASS-P    criteria 2 and 5 (reproduced at least once; a steam-metadata
                 claim says what Steam records, not what is true of the disk)
      CLASS-I    the "допустимые oracle" row (an interpretive claim needs a
                 semantics-bearing source), and criteria 3-6 (a saved raw
                 artifact, reproduced twice, an explicit build_key, a described
                 refutation attempt)
    """
    findings: list[Finding] = []
    err = lambda rule, msg: findings.append(Finding(SEVERITY_ERROR, rule, pointer, msg))  # noqa: E731
    warn = lambda rule, msg: findings.append(Finding(SEVERITY_WARN, rule, pointer, msg))  # noqa: E731

    verdict = derive_claim_class(oracles, claim_type, claim_text, evidence_level,
                                 counterpart_ids)

    if verdict.claim_class == CLASS_UNDETERMINED:
        # Reported only where a criterion was actually skipped, i.e. in the band
        # where 10.3 attaches class-dependent requirements.  Below 0.80 nothing
        # was skipped, so saying so would be noise on top of the EV-04 finding
        # that already names the missing oracle.
        if confidence is not None and confidence >= EV03_CONFIDENCE_THRESHOLD:
            warn("EV-05", f"claim class not derivable: {verdict.reason}. This record sits "
                          f"at confidence {confidence}, where plan.md 10.3 attaches "
                          "class-dependent requirements, so EV-03's method count and the "
                          "class P / class I criteria were NOT applied to it. Fix the "
                          "missing oracle first and re-run; do not read the absence of "
                          "those findings as compliance")
        return verdict, findings

    # --- EV-05: the explicit field versus the derivation -------------------
    explicit, recognised = normalise_claim_class(explicit_raw)
    if not recognised:
        err("EV-05", f"claim_class {explicit_raw!r} is not one of {', '.join(CLAIM_CLASSES)} "
                     "(plan.md 10.3 v2.2: P = primitive measurement, I = interpretive claim)")
    elif explicit is not None and explicit != verdict.claim_class:
        err("EV-05", f"claim_class is written as {explicit!r} but derives as "
                     f"{verdict.claim_class!r}: {verdict.reason}. plan.md 10.4/EV-05 makes an "
                     "explicit value contradicting the derived one a violation in itself. "
                     + ("The evidence_level decided this (plan.md 10.3 v2.3), so the label "
                        "is what has to change - or the level, if the record really is a "
                        "direct observation."
                        if verdict.level_decided else
                        "The class follows from evidence_level first, then claim_type and "
                        "oracle, so change one of those or the wording of the claim, not "
                        "the label."))

    # --- the mixed claim must be split ------------------------------------
    if verdict.mixed:
        err("MIX-SPLIT", "this record grades a primitive measurement and a semantic "
                         "conclusion under ONE level/confidence pair. plan.md 10.3 v2.2: "
                         "\"Смешанные утверждения обязаны разделяться\" - write two "
                         "records (the canonical case is A-07: header bytes are class P at "
                         "OBSERVED 0.99, the decoded field values and the encryption "
                         "conclusion are class I at INFERRED 0.85). Averaging the two into "
                         "one grade is incorrect by construction, not merely imprecise. "
                         "The class-dependent criteria of 10.3 are NOT applied to this "
                         "record: the derived class describes a record that should not "
                         "exist as one record, so \"name a second method\" and \"split "
                         "this row\" would be two contradictory instructions on the same "
                         "line. Split it, then re-run and answer the criteria of each "
                         "half separately")

    # A mixed record is not held to the class-dependent criteria - see the
    # MIX-SPLIT message above for why.  This is not an escape hatch: MIX-SPLIT
    # is itself an ERROR, so the gate still fails, and it fails naming the
    # defect whose remedy actually applies.
    if confidence is None or verdict.mixed:
        return verdict, findings

    # --- EV-03, split by class -------------------------------------------
    if notation == "json":
        # An explicit array written by the author: every element is a method id.
        methods = [s for s in (sources or []) if not is_reproduction_note(str(s))]
    else:
        # One paragraph of prose: which clauses name a method is recognised,
        # never assumed (see is_method_entry).
        methods = [s for s in (sources or []) if is_method_entry(str(s))]
    count = len(methods)
    if confidence >= EV03_CONFIDENCE_THRESHOLD and sources_checkable:
        if verdict.claim_class == CLASS_I:
            # plan.md 10.4/EV-03 counts ACTS OF MEASUREMENT.  An oracle is a
            # KIND of source, not an act of measurement, so naming a second
            # oracle does not add a method - exactly as an artifact path in an
            # Evidence field does not.  Until validator 3.2.0 the count was
            # `len(methods) + max(0, len(oracles) - 1)`, which handed every
            # two-oracle record a free second method: research/RESEARCH_LOG.md
            # LOG-0001i says about itself that it used one method and not two,
            # and explains that its `external-doc` oracle is PARTICIPATING
            # rather than corroborating - without it the bytes cannot be
            # interpreted at all - and the validator passed it at 0.85 anyway.
            independent = count
            if independent < EV03_MIN_SOURCES:
                err("EV-03", f"class I claim at confidence {confidence} with {independent} "
                             f"method(s) named; plan.md 10.3 v2.2 requires >= "
                             f"{EV03_MIN_SOURCES} independent methods for an interpretive "
                             f"claim from {EV03_CONFIDENCE_THRESHOLD} up. Derived as class I "
                             f"because {verdict.reason}. Counted here as the entries of the "
                             "method field that actually NAME an operation - a command, a "
                             "path, a named measurement (plan.md 10.3 criterion 1). A clause "
                             "of reasoning about the grading is not a method; an artifact "
                             "path in an Evidence field is NOT a second method (it is where "
                             "the result was written down), "
                             f"and neither is a second oracle - oracle(s) {sorted(oracles)} "
                             "name the KINDS of source consulted, not the acts of "
                             "measurement performed"
                             + (f" (ignored as sources: {list(evidence_refs)[:2]})"
                                if evidence_refs else "")
                             + ". Either name the second method, or lower the confidence to "
                             "the band one method supports (plan.md 10.2)")
        elif count == 0 and method_present:
            err("EV-03", f"class P claim at confidence {confidence} names NO method. "
                         "plan.md 10.3 v2.2 lets one method carry a primitive measurement "
                         "all the way to 0.99, but criterion 1 requires that method to be "
                         "recorded exactly and re-runnable as written"
                         + (f"; the Evidence entr{'y' if len(evidence_refs) == 1 else 'ies'} "
                            f"{list(evidence_refs)[:2]} record where the result was written, "
                            "which is not a method"
                            if evidence_refs else ""))
        elif count == 0:
            warn("EV-03", f"class P claim at confidence {confidence} in the {notation} "
                          "notation, which has no field for the method; plan.md 10.3 "
                          "criterion 1 still requires one, so move the claim to a notation "
                          "that can carry it")

    # --- class P criteria 2 and 5 ----------------------------------------
    if verdict.claim_class == CLASS_P and confidence >= EV03_CONFIDENCE_THRESHOLD:
        haystack = " ".join([claim_text, *[str(s) for s in (sources or [])],
                             *[str(e) for e in evidence_refs]])
        if not REPRODUCED_RE.search(haystack):
            warn("CLASS-P", f"class P claim at confidence {confidence} does not say the "
                            "method was re-run and the result reproduced. plan.md 10.3 "
                            "criterion 2 makes that mandatory for the whole 0.80-0.99 band "
                            "- it is cheap for a primitive reading and it catches a typo or "
                            "a transient state. Say so in the method text (\"re-run, "
                            "reproduced\", \"run1/run2\")")
        if oracles == {"steam-metadata"} and DISK_ASSERTION_RE.search(claim_text) \
                and not STEAM_RECORDS_RE.search(claim_text):
            err("CLASS-P", "the claim rests on steam-metadata alone but asserts something "
                           "about the DISK. plan.md 10.3 criterion 5: a steam-metadata claim "
                           "says \"Steam records X\", not \"X is true of the disk\"; the "
                           "second is class I and additionally needs the filesystem oracle "
                           f"(10.5 boundary - {ORACLE_BOUNDARIES['steam-metadata']})")

    # --- class I: the "допустимые oracle" row -----------------------------
    # plan.md 10.3, class I column: "любые, включая перечисленные - но ВМЕСТЕ с
    # источником, несущим семантику".  A record whose author states that a
    # conclusion beyond direct observation was drawn, and which rests only on
    # primitive readings, has no source for the step that makes it
    # interpretive.  RA-39 is the live example: it concedes in its own text that
    # the full conclusion needs binary-analysis, and it names only filesystem.
    #
    # Applied ONLY where the evidence_level decided the class, and only where
    # the claim_type does not itself prescribe a primitive-only oracle set.
    # Both restrictions matter:
    #   * the plan's own 10.5 matrix contains a class I row whose required
    #     oracles are both primitive - "на диске лежит то, что Steam обещает"
    #     needs filesystem AND steam-metadata and nothing else. Applying the
    #     rule there would make a prescribed matrix row unsatisfiable;
    #   * a class derived from the WORDING heuristic is a supplement (10.3
    #     v2.3), and MIX-SPLIT already names the remedy for those records.
    # Bound to the same 0.80 band as the two-method rule: below it the plan
    # allows a weakly supported interpretive claim, and repo-audit.md RA-02i is
    # the honest example (INFERRED 0.70, one filesystem method, and it says so).
    requirement_row = (CLAIM_TYPE_ORACLE_MATRIX.get(resolve_claim_type(claim_type))
                       if claim_type else None)
    prescribed = (requirement_row.all_of | requirement_row.any_of) \
        if requirement_row is not None else frozenset()
    primitive_row = bool(prescribed) and prescribed <= CLASS_P_ORACLES_UNCONDITIONAL
    if verdict.claim_class == CLASS_I and verdict.level_decided and not primitive_row \
            and confidence >= EV03_CONFIDENCE_THRESHOLD \
            and oracles and not (oracles & SEMANTIC_ORACLES):
        err("CLASS-I", f"class I claim at confidence {confidence} rests only on primitive "
                       f"oracle(s) {sorted(oracles)}. plan.md 10.3, class I row "
                       "\"Допустимые oracle\": any oracle is admissible, but only TOGETHER "
                       "with a source that carries semantics "
                       f"({', '.join(sorted(SEMANTIC_ORACLES))}). Derived as class I "
                       f"because {verdict.reason}. A primitive reading proves the path, the "
                       "size or the absence of a file; the conclusion drawn from it needs a "
                       "source for the conclusion. Either name that source, or lower the "
                       f"confidence below {EV03_CONFIDENCE_THRESHOLD}, where plan.md 10.2 "
                       "permits an interpretive claim with one weak method")

    # --- class I criteria 3-6 at the 0.95+ band ---------------------------
    if verdict.claim_class == CLASS_I and confidence >= CRITERIA_STRICT_THRESHOLD:
        haystack = " ".join([claim_text, *[str(s) for s in (sources or [])],
                             *[str(e) for e in evidence_refs]])
        if not EVIDENCE_ARTIFACT_RE.search(haystack):
            warn("CLASS-I", f"class I claim at confidence {confidence} >= "
                            f"{CRITERIA_STRICT_THRESHOLD} names no saved raw artifact under "
                            "research/evidence/. plan.md 10.3 makes all six class I criteria "
                            "mandatory in that band: two independent methods, one of them a "
                            "runtime observation or a format check, a stored artifact, "
                            "reproduced twice, an explicit build_key, and a described "
                            "refutation attempt")
        if not REPRODUCED_RE.search(haystack):
            warn("CLASS-I", f"class I claim at confidence {confidence} >= "
                            f"{CRITERIA_STRICT_THRESHOLD} does not say it was reproduced "
                            "twice (plan.md 10.3 class I criterion 4; for runtime claims "
                            "that means two separate game runs)")
        # Criterion 5: "Явно указан build_key".  The whole record is searched,
        # because every notation writes it somewhere different (a JSON field, a
        # log-entry `Build` line, a sentence in a table cell), and "UNKNOWN"
        # counts as stated: plan.md C-07 wants the field named, not invented.
        if not build_key_field_available:
            # The reduced annotation envelope has no build_key property and
            # forbids one (kb-record.schema.json#/$defs/annotation,
            # additionalProperties false).  Criterion 5 is satisfied by the
            # ENCLOSING document, which is where the annotation inherits its
            # build identity from; demanding the key here would be the same
            # schema/linter contradiction this branch exists to remove.
            pass
        elif not (build_key or "").strip() and not BUILD_KEY_MENTION_RE.search(haystack):
            warn("CLASS-I", f"class I claim at confidence {confidence} >= "
                            f"{CRITERIA_STRICT_THRESHOLD} names no build_key (plan.md 10.3 "
                            "class I criterion 5). An interpretive claim in the strictest "
                            "band is a claim about a PARTICULAR build; without the key it "
                            "cannot be re-checked against the build it came from. Write "
                            "build_key=<sha256:...>, or build_key=UNKNOWN with the reason")
        # Criterion 6: "Проведена попытка опровержения, и она описана".
        if not REFUTATION_ATTEMPT_RE.search(haystack):
            warn("CLASS-I", f"class I claim at confidence {confidence} >= "
                            f"{CRITERIA_STRICT_THRESHOLD} describes no refutation attempt "
                            "(plan.md 10.3 class I criterion 6): say what we would have "
                            "seen if the claim were false, and what was done to look for "
                            "it. This is the criterion that separates a confirmed claim "
                            "from an unchallenged one")

    return verdict, findings


def lint_record(
    pointer: str,
    record: dict[str, Any],
    allow_untyped_claims: bool = False,
    reachability: "CommitReachability | None" = None,
) -> list[Finding]:
    """Apply every project lint rule to one record.

    `allow_untyped_claims` downgrades "missing claim_type" from a violation to
    a warning.  kb-record.schema.json declares claim_type optional; this
    linter demands it by default, because without it the plan.md 10.5 matrix
    cannot be checked mechanically at all (task EV-04).
    """
    findings: list[Finding] = []
    err = lambda rule, msg: findings.append(Finding(SEVERITY_ERROR, rule, pointer, msg))  # noqa: E731
    warn = lambda rule, msg: findings.append(Finding(SEVERITY_WARN, rule, pointer, msg))  # noqa: E731

    # --- evidence_level (plan.md 10.1) -------------------------------------
    level = record.get("evidence_level")
    if level is None:
        err("EV-LEVEL", "missing evidence_level (plan.md 10.1); "
                        f"expected one of {', '.join(EVIDENCE_LEVELS)}")
    elif level not in EVIDENCE_LEVELS:
        err("EV-LEVEL", f"evidence_level {level!r} is not one of "
                        f"{', '.join(EVIDENCE_LEVELS)} (plan.md 10.1)")

    # plan.md 10.1: refutations are kept, not deleted - so a REFUTED record has
    # to name what refuted it, otherwise it cannot be reused.
    if level == "REFUTED" and not record.get("refuted_by"):
        err("EV-REFUTED", "evidence_level REFUTED without refuted_by[]; plan.md 10.1 "
                          "keeps refutations as first-class knowledge, which requires "
                          "naming the record or experiment that refuted this one")

    # --- confidence (plan.md 10.2) -----------------------------------------
    confidence = record.get("confidence")
    if confidence is None:
        err("EV-CONF", "missing confidence (plan.md 10.2)")
    elif isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        err("EV-CONF", f"confidence must be a number in [0.0, 1.0), got {confidence!r}")
        confidence = None
    else:
        confidence = float(confidence)
        if confidence < CONFIDENCE_FLOOR or confidence > MAX_CONFIDENCE_EXCLUSIVE:
            err("EV-CONF", f"confidence {confidence} outside the scale "
                           f"[{CONFIDENCE_FLOOR:.2f}, {CONFIDENCE_CEILING}] (plan.md 10.2)")
        elif exceeds_ceiling(confidence):
            err("EV-CONF", ceiling_message(confidence))

    # --- EV-03 / EV-05: sources and the claim class ------------------------
    sources, sources_key = get_sources(record)
    if sources_key is None:
        err("EV-03", "missing sources[] (plan.md 10.4/EV-02); every record must "
                     "name the methods that produced it")
    elif sources is None:
        err("EV-03", f"{sources_key!r} must be an array of method ids, got "
                     f"{type(record[sources_key]).__name__}")
    if sources is not None and len(set(map(repr, sources))) != len(sources):
        warn("EV-03", f"{sources_key}[] contains duplicates; duplicates are not "
                      "independent methods (plan.md 10.3 rule 1)")

    # --- EV-04: oracle presence, vocabulary, and the 10.5 matrix ----------
    oracles, oracle_present = get_oracles(record)
    if not oracle_present:
        err("EV-04", "missing oracle field; plan.md 10.5 requires every record to "
                     f"carry one or more of: {', '.join(ORACLES)}")
    elif not oracles:
        err("EV-04", "oracle field is empty or malformed; expected a string or a "
                     f"non-empty array of {', '.join(ORACLES)}")
    else:
        unknown = sorted(oracles - set(ORACLES))
        if unknown:
            err("EV-04", f"unknown oracle value(s) {unknown}; the plan.md 10.5 list is "
                         f"closed: {', '.join(ORACLES)}")

    claim_type = record.get("claim_type")
    requirement: OracleRequirement | None = None
    if claim_type is None:
        severity = SEVERITY_WARN if allow_untyped_claims else SEVERITY_ERROR
        findings.append(Finding(
            severity, "EV-04", pointer,
            "missing claim_type; without it the plan.md 10.5 matrix cannot be applied. "
            f"Known claim types: {', '.join(sorted(CLAIM_TYPE_ORACLE_MATRIX))}"))
    elif not isinstance(claim_type, str):
        err("EV-04", f"claim_type must be a string, got {type(claim_type).__name__}")
    else:
        claim_type = resolve_claim_type(claim_type)
        requirement, matrix_findings = check_claim_type_matrix(
            pointer, claim_type, oracles,
            has_justification=any(str(record.get(key, "")).strip()
                                  for key in JUSTIFICATION_KEYS),
            evidence_level=level if isinstance(level, str) else None,
            confidence=confidence)
        findings.extend(matrix_findings)
    if requirement is not None:
        if requirement.requires_experiment:
            experiment = record.get("experiment") or record.get("experiment_id")
            if not experiment:
                err("EV-04", f"claim_type {claim_type!r} requires a reference to an actual "
                             "experiment run (field 'experiment' or 'experiment_id'); "
                             f"[{requirement.provenance}]")
        if requirement.requires_reachable_commit:
            cited = [str(record[key]) for key in COMMIT_KEYS if record.get(key)]
            if not cited:
                err("VCS-ORACLE", f"claim_type {claim_type!r} must name the commit it is "
                                  f"about in one of {list(COMMIT_KEYS)}; "
                                  f"[{requirement.provenance}]")
            for ref in cited:
                findings.extend(check_commit_claims(
                    pointer, f"commit {ref}", oracles, reachability))

    # --- EV-05 / EV-03: claim class and the criteria it selects -----------
    # plan.md 10.3 v2.2 + 10.4/EV-05.  The class is derived from oracle plus
    # claim_type; an explicit claim_class that contradicts the derivation is a
    # violation in itself, and a record mixing a primitive with an interpretive
    # claim is rejected with a demand to split it.
    claim_text = " ".join(
        str(record[key]) for key in ("statement", "claim", "text", "description",
                                     "summary", "note", "notes", "finding")
        if isinstance(record.get(key), str))
    evidence_refs_json = [
        str(item) for item in (record.get("evidence") if isinstance(record.get("evidence"), list)
                              else [record["evidence"]] if isinstance(record.get("evidence"), str)
                              else [])
    ]
    _class_verdict, class_findings = lint_claim_class(
        pointer,
        oracles=oracles,
        claim_type=claim_type if isinstance(claim_type, str) else None,
        claim_text=claim_text,
        confidence=confidence,
        explicit_raw=record.get("claim_class") if isinstance(record.get("claim_class"),
                                                             str) else None,
        sources=sources,
        sources_checkable=sources is not None,
        evidence_level=level if isinstance(level, str) else None,
        build_key=record.get("build_key") if isinstance(record.get("build_key"),
                                                        str) else None,
        evidence_refs=evidence_refs_json,
        method_present=sources is not None,
        notation="json",
    )
    findings.extend(class_findings)

    # --- C-12 rule 1: external-doc alone caps confidence at 0.7 -----------
    if oracles == {"external-doc"} and confidence is not None \
            and confidence > EXTERNAL_DOC_ONLY_MAX_CONFIDENCE:
        err("C-12", f"oracle is external-doc only, so confidence must be <= "
                     f"{EXTERNAL_DOC_ONLY_MAX_CONFIDENCE} for a claim about THIS build "
                     f"(plan.md 17.3/C-12 rule 1), got {confidence}")

    # --- C-11: global.ucas proves names, nothing else ---------------------
    if oracles == {"global-ucas"}:
        asset_ref = mentions_game_asset(record)
        bp_name = looks_like_blueprint_name(record)
        layout_hits = claims_layout(record)
        if asset_ref is not None:
            key, value = asset_ref
            err("C-11", f"oracle is global-ucas only, but the record claims a /Game asset "
                        f"({key}={value!r}). plan.md 10.5: a name in the global pool does not "
                        "prove existence or structure of a /Game asset; use asset-registry or "
                        "runtime-reflection")
        if layout_hits:
            err("C-11", f"oracle is global-ucas only, but the record carries layout field(s) "
                        f"{layout_hits}. plan.md 10.5: offsets, sizes and property ordering are "
                        "unobtainable from global.ucas in principle; they require "
                        "runtime-reflection")
        if (asset_ref is not None or bp_name is not None) and confidence is not None \
                and confidence > GLOBAL_UCAS_ASSET_MAX_CONFIDENCE:
            err("C-11", f"a /Game or Blueprint-shaped name known only from global.ucas is at "
                        f"most HYPOTHESIS with confidence <= {GLOBAL_UCAS_ASSET_MAX_CONFIDENCE} "
                        f"(plan.md 10.5 \"Обязательное правило\"), got {confidence}")
        if (asset_ref is not None or bp_name is not None) and level in ("OBSERVED", "INFERRED"):
            err("C-11", f"evidence_level {level} is not available for a /Game or "
                        "Blueprint-shaped name known only from global.ucas; plan.md 10.5 caps "
                        "it at HYPOTHESIS")

    # --- EV-LAYOUT: a statically recovered offset is a HYPOTHESIS ----------
    # plan.md 6.3: "офсеты фиксируются только при evidence_level = OBSERVED из
    # runtime-дампа ... Офсет из статического анализа = HYPOTHESIS."
    if claims_layout(record) and oracles and "runtime-reflection" not in oracles \
            and level in ("OBSERVED", "INFERRED"):
        err("EV-LAYOUT", f"layout field(s) {claims_layout(record)} recorded at "
                         f"evidence_level {level} without runtime-reflection; plan.md 6.3 "
                         "caps a statically recovered offset at HYPOTHESIS")

    # --- build_key (plan.md 3.2, 10.3 rule 5, 10.5 row 4) -----------------
    build_key = record.get("build_key")
    needs_build_key = True
    if requirement is not None:
        needs_build_key = requirement.requires_build_key
    layout_hits = claims_layout(record)
    if layout_hits:
        needs_build_key = True
    if needs_build_key:
        if build_key is None or build_key == "":
            reason = "the claim is build-specific"
            if layout_hits:
                reason = f"the record carries build-specific field(s) {layout_hits}"
            elif requirement is not None:
                reason = f"claim_type {claim_type!r} is build-specific " \
                         f"[{requirement.provenance}]"
            err("EV-BUILD", f"missing build_key: {reason} (plan.md 3.2, 10.3 rule 5)")
        elif not isinstance(build_key, str):
            err("EV-BUILD", f"build_key must be a string, got {type(build_key).__name__}")
        elif build_key != "UNKNOWN" and not BUILD_KEY_RE.match(build_key):
            err("EV-BUILD", f"build_key {build_key!r} is malformed; expected "
                            "'sha256:<64 lowercase hex>' (plan.md 3.2) or the literal "
                            "'UNKNOWN'")
    elif build_key in (None, "") and not str(record.get("notes") or "").strip():
        # kb-record.schema.json: "Null is allowed only for build-independent
        # records ... and such records must say so in 'notes'".
        warn("EV-BUILD", f"claim_type {claim_type!r} carries no build_key; say in "
                         "'notes' why this claim is build-independent "
                         "(kb-record.schema.json, plan.md 10.3 rule 5)")

    return findings


def lint_annotation(pointer: str, annotation: dict[str, Any]) -> list[Finding]:
    """Apply the ANNOTATION rules to one reduced envelope (see section 5b).

    The same rules as :func:`lint_record` minus exactly two, and only those two:
    the plan.md 10.5 claim-type matrix and EV-BUILD.  Those are the rules whose
    remedy is a property kb-record.schema.json#/$defs/annotation forbids, and a
    rule whose remedy is forbidden is not a rule, it is a deadlock.  Everything
    the reduced envelope CAN carry is still checked at full strength - an
    annotation is where a fingerprint grades its own sub-objects, so a loose
    pass here would be the cheapest place in the repository to launder an
    interpretation into a measurement.
    """
    findings: list[Finding] = []
    err = lambda rule, msg: findings.append(Finding(SEVERITY_ERROR, rule, pointer, msg))  # noqa: E731
    warn = lambda rule, msg: findings.append(Finding(SEVERITY_WARN, rule, pointer, msg))  # noqa: E731

    # --- evidence_level: the ONE property the annotation schema requires ----
    level = annotation.get("evidence_level")
    if level is None:
        err("EV-LEVEL", "missing evidence_level (plan.md 10.1); it is the one property "
                        "kb-record.schema.json#/$defs/annotation makes mandatory; "
                        f"expected one of {', '.join(EVIDENCE_LEVELS)}")
    elif level not in EVIDENCE_LEVELS:
        err("EV-LEVEL", f"evidence_level {level!r} is not one of "
                        f"{', '.join(EVIDENCE_LEVELS)} (plan.md 10.1)")
    elif level == "REFUTED":
        # EV-REFUTED demands refuted_by[], which the reduced envelope forbids.
        # Saying nothing would hide a refutation with no counterpart; the remedy
        # is a shape change, so that is what is named.
        warn("EV-REFUTED", "an annotation graded REFUTED cannot name what refuted it: "
                           "the reduced envelope has no refuted_by[] property and "
                           "forbids one. plan.md 10.1 keeps refutations as first-class "
                           "knowledge, so move this claim into a full record "
                           "(kb-record.schema.json#/$defs/envelope) where refuted_by[] "
                           "exists, and leave a pointer to it here")

    # --- confidence (plan.md 10.2) -----------------------------------------
    confidence = annotation.get("confidence")
    if confidence is None:
        err("EV-CONF", "missing confidence (plan.md 10.2); the annotation schema "
                       "defines the property, so an ungraded annotation is a gap in the "
                       "document and not a limit of the shape")
    elif isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        err("EV-CONF", f"confidence must be a number in [0.0, 1.0), got {confidence!r}")
        confidence = None
    else:
        confidence = float(confidence)
        if confidence < CONFIDENCE_FLOOR or confidence > MAX_CONFIDENCE_EXCLUSIVE:
            err("EV-CONF", f"confidence {confidence} outside the scale "
                           f"[{CONFIDENCE_FLOOR:.2f}, {CONFIDENCE_CEILING}] (plan.md 10.2)")
        elif exceeds_ceiling(confidence):
            err("EV-CONF", ceiling_message(confidence))

    # --- EV-03: sources ----------------------------------------------------
    sources, sources_key = get_sources(annotation)
    if sources_key is None:
        err("EV-03", "missing sources[] (plan.md 10.4/EV-02); the annotation schema "
                     "defines sources, so the methods behind this sub-claim have a "
                     "place to be named")
    elif sources is None:
        err("EV-03", f"{sources_key!r} must be an array of method ids, got "
                     f"{type(annotation[sources_key]).__name__}")
    if sources is not None and len(set(map(repr, sources))) != len(sources):
        warn("EV-03", f"{sources_key}[] contains duplicates; duplicates are not "
                      "independent methods (plan.md 10.3 rule 1)")

    # --- EV-04: the oracle vocabulary (the matrix itself is not applicable) -
    oracles, oracle_present = get_oracles(annotation)
    if not oracle_present:
        err("EV-04", "missing oracle field; plan.md 10.5 requires every graded claim to "
                     f"carry one or more of: {', '.join(ORACLES)}. The reduced envelope "
                     "defines the property, so this is a gap in the document")
    elif not oracles:
        err("EV-04", "oracle field is empty or malformed; expected a string or a "
                     f"non-empty array of {', '.join(ORACLES)}")
    else:
        unknown = sorted(oracles - set(ORACLES))
        if unknown:
            err("EV-04", f"unknown oracle value(s) {unknown}; the plan.md 10.5 list is "
                         f"closed: {', '.join(ORACLES)}")

    # The plan.md 10.5 claim_type matrix is deliberately NOT applied: the
    # reduced envelope has no claim_type property and forbids one, and the
    # schema's own $comment says why that is right - "an annotation inherits its
    # matrix row from the enclosing document".  This is disclosed in the
    # DISCLOSURES block of every run, not only here.

    # --- EV-05 / MIX-SPLIT / CLASS-P / CLASS-I -----------------------------
    claim_text = " ".join(
        str(annotation[key]) for key in ("note",)
        if isinstance(annotation.get(key), str))
    _class_verdict, class_findings = lint_claim_class(
        pointer,
        oracles=oracles,
        claim_type=None,
        claim_text=claim_text,
        confidence=confidence,
        explicit_raw=(annotation.get("claim_class")
                      if isinstance(annotation.get("claim_class"), str) else None),
        sources=sources,
        sources_checkable=sources is not None,
        evidence_level=level if isinstance(level, str) else None,
        build_key=None,
        evidence_refs=[],
        method_present=sources is not None,
        notation="json",
        build_key_field_available=False,
    )
    findings.extend(class_findings)

    # --- C-12 rule 1: external-doc alone caps confidence at 0.7 ------------
    if oracles == {"external-doc"} and confidence is not None \
            and confidence > EXTERNAL_DOC_ONLY_MAX_CONFIDENCE:
        err("C-12", f"oracle is external-doc only, so confidence must be <= "
                    f"{EXTERNAL_DOC_ONLY_MAX_CONFIDENCE} for a claim about THIS build "
                    f"(plan.md 17.3/C-12 rule 1), got {confidence}")

    # --- C-11 / EV-LAYOUT --------------------------------------------------
    # Both are keyword-driven and read fields the annotation shape does not
    # define, so they are vacuous today.  They are wired up anyway: the day a
    # `note` or a `read_locus` starts carrying an offset claim on global-ucas,
    # the rule must already be here rather than be remembered.
    if oracles == {"global-ucas"}:
        asset_ref = mentions_game_asset(annotation)
        layout_hits = claims_layout(annotation)
        if asset_ref is not None:
            key, value = asset_ref
            err("C-11", f"oracle is global-ucas only, but the annotation claims a /Game "
                        f"asset ({key}={value!r}); plan.md 10.5: a name in the global "
                        "pool proves neither existence nor structure")
        if layout_hits:
            err("C-11", f"oracle is global-ucas only, but the annotation carries layout "
                        f"field(s) {layout_hits}; plan.md 10.5: offsets and sizes are "
                        "unobtainable from global.ucas in principle")
    layout_hits = claims_layout(annotation)
    if layout_hits and oracles and "runtime-reflection" not in oracles \
            and level in ("OBSERVED", "INFERRED"):
        err("EV-LAYOUT", f"layout field(s) {layout_hits} recorded at evidence_level "
                         f"{level} without runtime-reflection; plan.md 6.3 caps a "
                         "statically recovered offset at HYPOTHESIS")

    return findings


# ---------------------------------------------------------------------------
# 6b. Markdown fact extraction (BLOCKER-2)
# ---------------------------------------------------------------------------
# WHY THIS EXISTS.  Up to validator version 1.0.0 this file globbed only
# *.json / *.jsonl under research/, and iter_records() only recognised objects
# carrying evidence_level / claim_type / oracle / confidence.  No M0 artifact
# carries any of those keys, so the validator reported
#     files: 9, records: 0, violations: 0
# while 100% of the M0 facts lived in markdown prose it never opened.
# Transition rule 18.3 item 5 ("every recorded fact carries an oracle and the
# validator reports no matrix violation") was therefore satisfied vacuously,
# and four real violations went undetected precisely because of this gap.
#
# The fix is NOT to mirror the facts into a parallel JSONL file: that creates
# two sources of truth for one fact, and they drift.  The fix is to read the
# notation the documents already use.  Three forms exist today:
#
#   NOTATION_TABLE   a markdown table whose header carries an oracle column
#                    plus an evidence-level and/or confidence column
#                    (research/repo-audit.md, research/evidence-model.md).
#   NOTATION_INLINE  an annotation attached to a prose sentence:
#                    *(OBSERVED, confidence 0.99, oracle: filesystem)* and the
#                    bold variant **HYPOTHESIS, confidence 0.65, oracle:
#                    binary-analysis + external-doc** (research/decisions.md,
#                    research/unknowns.md, docs/toolchain.md).
#   NOTATION_LOG     a section 9.3 entry block whose fields are
#                    "- **Evidence level:** ...", "- **Confidence:** ...",
#                    "- **Oracle:** ..." (research/RESEARCH_LOG.md).
#
# Anything that looks like one of the three but cannot be read is counted as
# an UNPARSEABLE CANDIDATE and reported as a violation, never skipped: "the
# validator could not read this fact" is exactly the failure mode that hid the
# earlier violations.
#
# DELIBERATE LIMITS, so nobody mistakes silence for coverage:
#   * fenced code blocks are skipped - they hold templates and examples, not
#     facts (the 9.3 template in RESEARCH_LOG.md is one);
#   * a markdown record carries no claim_type, so the full 10.5 matrix cannot
#     be applied to it.  What IS applied: the oracle vocabulary, the level and
#     confidence ranges, C-11, C-12, and the vcs-history rules, which are
#     shape-detectable from the claim text;
#   * EV-03 needs a sources[] list.  Fact-table rows have a "Метод" column and
#     log entries have Method/Evidence fields, so EV-03 runs there.  An inline
#     annotation has no sources field at all; instead of pretending otherwise,
#     the report states per file how many inline records at confidence >= 0.8
#     could not be checked against EV-03.

NOTATION_TABLE = "table-row"
NOTATION_INLINE = "inline-annotation"
NOTATION_LOG = "log-entry"

# How each markdown notation can carry a claim_type at all.  Read by
# claim_type_gap_remedy(): the inline annotation cannot carry one, and saying so
# is part of the remedy rather than an excuse - such a record has to move to a
# notation that has a field for it.
CLAIM_TYPE_FIELD_BY_NOTATION: dict[str, str] = {
    NOTATION_TABLE: "add a `Claim type` column to this table and fill it in",
    NOTATION_LOG: "add a `- **Claim type:** ...` field to this entry",
    NOTATION_INLINE: "the inline annotation notation has NO claim_type field, so the "
                     "remedy is to move this record into a fact table or a log entry",
}

MARKDOWN_SUFFIX = ".md"

# Opt-out directives.  A didactic document (research/evidence-model.md shows
# deliberately WRONG records next to correct ones) must be able to exempt an
# example without the validator going quiet about it: every suppression is
# counted and printed.
DIRECTIVE_RE = re.compile(r"<!--\s*kb-validate:\s*(?P<what>[a-z-]+)\s*-->")
DIRECTIVE_IGNORE_FILE = "ignore-file"
DIRECTIVE_IGNORE_NEXT = "ignore-next"
# A document that TEACHES the rules has to be able to quote a bad record.
# research/evidence-model.md describes two defects adversarial review already
# found and fixed, and quotes one of them as "OBSERVED 1.00" inside the
# sentence; the inline extractor read that as a live graded record at the
# forbidden ceiling.  Two opposite harms followed: a reader trusting the count
# believed a forbidden 1.00 still existed, and the cheapest way to clear the
# finding was to DELETE an honest disclosure of a past defect in order to quiet
# the tool.  So the fix belongs here, not in the document.
#
# The convention, and why it is shaped this way:
#   * it is an EXPLICIT marker, never an inference.  The parser is not allowed
#     to guess "this looks like a quotation" - guessing would let any record
#     escape by being phrased as prose;
#   * it is one line of source a reviewer can grep for and audit;
#   * it does NOT suppress the record.  The record is still parsed and still
#     counted, and every use is listed by file and line in the EXEMPTIONS block
#     of the report, next to DEF-TABLE.  An exemption that is invisible is a
#     hole; an exemption that is named and counted is a decision.
DIRECTIVE_QUOTED_EXAMPLE = "quoted-example"

LEVEL_TOKEN_RE = re.compile(r"\b(OBSERVED|INFERRED|HYPOTHESIS|UNKNOWN|REFUTED)\b")

# ---------------------------------------------------------------------------
# A NORMATIVE sentence that names the permitted levels, versus a RECORD
# ---------------------------------------------------------------------------
# plan.md line 533 reads, in substance: "Exit criteria: for every target in 7.4
# there is either a confirmed record (`OBSERVED`/`INFERRED` with confidence
# >= 0.7 and a signature) or an explicit entry in unknowns.md".  The inline
# reader saw a parenthesis carrying two evidence levels and raised PARSE-MD
# "annotation packs 2 evidence levels into one span".
#
# It is not a record.  It states the RULE that records must satisfy, and a
# document that states the rules has to be able to NAME the levels without
# being read as asserting a fact about them - the same principle the
# `quoted-example` marker already carries for a grade quoted as a teaching
# example.  The difference is that this shape is recognisable from the text, so
# it does not need a marker: the plan will grow more exit criteria, and a
# per-line marker convention would make the parser's appetite the reason the
# plan is annotated, which inverts which artifact serves which.
#
# Three conditions, ALL required.  Any one of them alone is far too loose; the
# conjunction is what makes the shape a shape:
#
#   1. the levels form a contiguous ENUMERATION - between the first and the
#      last level token there is nothing but a separator ("/", ",", "или",
#      "либо", "or", backticks, whitespace).  A record that grades two claims
#      has prose between its two levels; a rule that lists the admissible
#      levels does not;
#   2. every confidence in the span is a THRESHOLD, not a value: a comparison
#      operator or a bound word stands immediately before the number ("≥ 0.7",
#      "не ниже 0.8", "at least 0.7").  A span with no confidence at all also
#      passes, because nothing is being graded.  A bare "0.85" fails - that is
#      a grade, and a grade belongs to a record;
#   3. the line carries requirement vocabulary from a closed list ("exit
#      criteria", "критерий", "требуется", "обязан", "допустим", "must", ...).
#
# Condition 2 is the load-bearing one.  A real record that packed two levels
# into one span would have to state its confidence as an inequality and sit on
# a line phrased as a requirement before it could escape through here, and such
# a record would be unreadable as a record anyway.
_LEVEL_ENUM_SEPARATOR_RE = re.compile(
    r"^[\s`'\"*()\[\]|/,;·•]*"
    r"(?:(?:или|либо|and|or|и)[\s`'\"*()\[\]|/,;]*)*$",
    re.IGNORECASE)

# A number introduced by a comparison operator or a bound word.  "до 0.99" and
# "up to 0.99" are ceilings, i.e. still thresholds and not grades.
_THRESHOLD_PREFIX_RE = re.compile(
    r"(?:[<>≤≥⩽⩾]=?|не\s+ниже|не\s+менее|не\s+выше|не\s+более|не\s+меньше|"
    r"минимум|максимум|как\s+минимум|как\s+максимум|до|от|начиная\s+с|"
    r"at\s+least|at\s+most|no\s+less\s+than|no\s+more\s+than|up\s+to|from)"
    r"\s*\*{0,2}`?\s*$",
    re.IGNORECASE)

# The closed list of words that make a sentence a REQUIREMENT rather than an
# assertion.  Kept closed on purpose: this is the condition that decides
# whether a graded-looking span is read at all, and a list that grew by
# convenience would become the hole.
NORMATIVE_REQUIREMENT_RE = re.compile(
    r"(?:exit\s+criteri\w*|критери\w*|требуе\w*|требован\w*|требует\w*|"
    r"обязан\w*|обязательн\w*|должн\w*|допустим\w*|допуска\w*|недопустим\w*|"
    r"не\s+может|запрещ\w*|правил[оа]\b|условие\b|условия\b|порог\w*|"
    r"must\b|shall\b|required\b|requirement\w*|criteri\w*|rule\b|"
    r"threshold\w*|permitted\b|admissible\b|forbidden\b)",
    re.IGNORECASE)

# A number in confidence shape, used to test whether EVERY one of them in a
# span is introduced as a threshold.
_ANY_CONF_NUMBER_RE = re.compile(r"\d(?:[.,]\d{1,3})?")


def _levels_form_enumeration(span: str) -> bool:
    """True when the level tokens in `span` are a list, not two graded claims."""
    matches = list(LEVEL_TOKEN_RE.finditer(span))
    if len(matches) < 2:
        return False
    for first, second in zip(matches, matches[1:]):
        if not _LEVEL_ENUM_SEPARATOR_RE.match(span[first.end():second.start()]):
            return False
    return True


def _confidences_are_thresholds(span: str) -> bool:
    """True when every confidence-shaped number in `span` is a THRESHOLD.

    A span with no such number passes: it grades nothing.  Section and item
    numbers ("§7.4", "10.3") are skipped - they are references, not grades.
    """
    for match in _ANY_CONF_NUMBER_RE.finditer(span):
        before = span[:match.start()]
        # a section / clause reference, not a confidence
        if re.search(r"(?:§|п\.|пп\.|item|section)\s*[\d.]*$", before, re.IGNORECASE):
            continue
        if not _THRESHOLD_PREFIX_RE.search(before):
            return False
    return True


def is_normative_level_enumeration(span: str, line_text: str) -> bool:
    """True when a multi-level span states a REQUIREMENT instead of a record.

    `span` is the parenthesis or bold run the inline reader found; `line_text`
    is the whole source line it sits on, because the requirement vocabulary
    ("Exit criteria:", "критерий") normally stands outside the parenthesis.
    """
    return (_levels_form_enumeration(span)
            and _confidences_are_thresholds(span)
            and NORMATIVE_REQUIREMENT_RE.search(line_text) is not None)

# A minus sign glued to the number.  It MUST be captured rather than skipped:
# a confidence regex that starts matching at the first digit reads "-0.5" as
# 0.5, which turns "somebody wrote a nonsensical negative confidence" into a
# silently accepted valid one.  Only an ASCII hyphen and U+2212 count, and only
# with no space before the digit, so the dash separator in "OBSERVED - 0.9" and
# the "not applicable" em dash in "0.95 / —" keep their existing meanings.
SIGN_GROUP = r"(?P<sign>-|−)?"

# "confidence 0.99", "conf 0.9", "confidence **0.65**", "уверенность ≤0.4"
CONF_KEYWORD_RE = re.compile(
    r"(?:confidence|conf\.?|уверенность)\s*[:=]?\s*"
    r"(?P<bound>[<>≤≥~≈]{0,2})\s*\*{0,2}`?" + SIGN_GROUP + r"(?P<value>\d(?:[.,]\d{1,3})?)",
    re.IGNORECASE)
# "OBSERVED 1.00", "(HYPOTHESIS, 0.65)", "(OBSERVED, ~0.95)", "OBSERVED - 0.9"
#
# A hyphen here is ambiguous, so the two readings are separated by position:
#   glued to the level token or followed by a space  -> DASH SEPARATOR
#       "OBSERVED-0.99", "OBSERVED - 0.9"  =>  0.99 / 0.9
#   preceded by a space and glued to the digit       -> MINUS SIGN
#       "OBSERVED -0.5"                    => -0.5
# Getting this wrong in either direction is a silent value corruption, which is
# why it is spelled out rather than left to the greediness of one character
# class.
LEVEL_ADJACENT_CONF_RE = re.compile(
    r"\b(?:OBSERVED|INFERRED|HYPOTHESIS|UNKNOWN|REFUTED)\b"
    r"[`'\"*)\]]*[\s,;:—–]*(?:-\s+|(?<=[^\s])-(?=\d))?"
    r"(?P<bound>[<>≤≥~≈]{0,2})\s*\*{0,2}"
    r"(?P<sign>(?<=[\s(\[])[-−])?(?P<value>\d[.,]\d{1,3})")
BARE_CONF_RE = re.compile(
    r"^(?P<bound>[<>≤≥~≈]{0,2})\s*" + SIGN_GROUP + r"(?P<value>\d(?:[.,]\d{1,3})?)$")

# An ALL-CAPS single word in level position - the first comma-separated part of
# an annotation that also carries a confidence or an oracle field - which is
# not one of the five levels.  plan.md 10.1 closes that list, so an invented
# level must be reported rather than dropped: dropping it made the annotation
# read as "no level stated", which is a different and much milder defect.
LEVEL_SHAPED_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
# Identifier shapes that legitimately open an annotation part (A-07, EV-03,
# C-11, Q-8, RISK-09, LOG-0004, T-02, M0): those are record ids, not levels.
IDENT_SHAPED_TOKEN_RE = re.compile(r"^[A-Z]{1,4}-?\d")

ORACLE_KEYWORD_RE = re.compile(r"\boracle\b\s*[:=]?\s*", re.IGNORECASE)
# Characters that may precede the keyword when it opens an annotation FIELD.
# Without this, prose like "(282-МБ exe — read-only oracle, интерпретация
# остаётся HYPOTHESIS)" would be read as an oracle field and its prose
# reported as an unknown oracle value.
ORACLE_FIELD_OPENERS = ",;(*—–|"

# The claim-CLASS field of an inline annotation: "*(OBSERVED, confidence 0.99,
# oracle: container-metadata, класс P)*".  Until validator 3.2.1 the inline
# reader had no notion of this field, and because the class is written after the
# oracle it was swallowed by the oracle segment - "container-metadata, класс P"
# split into two tokens and "класс P" was reported as an unknown oracle value.
# That is a parser defect and it produced two EV-04 ERRORS against the canonical
# class P / class I example pair of plan.md 10.3 itself: the two records that
# section 10.3 v2.4 exists to demonstrate were failing the gate for stating
# their own class.  Reading the field instead of guessing around it also gains a
# check - EV-05 now compares the stated class against the derived one for inline
# annotations too, which is strictly more than ignoring the token would give.
#
# Field position only: preceded by the start of the span or by a separator, so
# the word "класс" inside a sentence ("класс P допустим только при OBSERVED")
# does not turn into a field.  The value is a single letter, and the accepted
# spellings live in CLAIM_CLASS_ALIASES.
# Everything that may stand between the start of a line and an annotation that
# is ALONE on that line: blockquote markers, list bullets, ordinal markers and
# the emphasis characters of the annotation itself.  Used by _sentence_around to
# recognise "this annotation grades the line above it".
_ANNOTATION_ALONE_PREFIX_RE = re.compile(r"^[\s>*_`+•-]*(?:\d+[.)]\s*)?[\s>*_`]*$")

INLINE_CLAIM_CLASS_RE = re.compile(
    r"(?:^|(?<=[,;(|*—–])|(?<=\s))\s*(?:claim[_\s-]?class|класс|class)"
    r"\s*[:=]?\s*\*{0,2}`?(?P<value>[PI])`?\*{0,2}(?![\w-])",
    re.IGNORECASE)


def extract_claim_class_field(span: str) -> tuple[str | None, str]:
    """Split an annotation span into (claim class, span without that field)."""
    match = INLINE_CLAIM_CLASS_RE.search(span or "")
    if match is None:
        return None, span
    remainder = (span[:match.start()].rstrip(" ,;") + " "
                 + span[match.end():].lstrip(" ,;")).strip()
    return match.group("value").upper(), remainder

# A commit-shaped hex token: 7..40 lowercase hex with at least one a-f digit,
# not glued to a longer identifier and not preceded by "0x", ":" or "-" (which
# would make it part of a build id, a sha256:... build_key or a hex constant).
#
# The trailing guard used to forbid a following "." outright, which excluded
# the single most common way a commit is cited in prose: at the END OF A
# SENTENCE - "зафиксировано в коммите a2a6385." - so the reachability rule
# never saw exactly the citations a reader is most likely to write.  The guard
# now rejects only a dot that CONTINUES an identifier ("tbbmalloc1.dll",
# "5.4.4"), which is what it was actually for.
COMMIT_HASH_RE = re.compile(
    r"(?<![0-9A-Za-z:/\-.])(?=[0-9a-f]{0,39}[a-f])[0-9a-f]{7,40}"
    r"(?![0-9A-Za-z/\-])(?!\.[0-9A-Za-z])")
COMMIT_KEYWORD_RE = re.compile(
    r"(?:\bcommits?\b|коммит|git\s+(?:log|show|ls-tree|rev-parse|cat-file|diff)|\bHEAD\b)",
    re.IGNORECASE)

# Words that make a claim a layout claim (C-11 / plan.md 6.3).  "размер" is
# deliberately absent: in this repository it almost always means file size,
# which is a filesystem fact, not a memory layout.
LAYOUT_WORDS_RE = re.compile(
    r"(?:офсет|оффсет|смещени|offset|порядок\s+свойств|property\s+order|"
    r"vtable|struct\s+size|размер\s+структуры)", re.IGNORECASE)
GAME_PATH_RE = re.compile(r"/Game[/\w]*")
BP_NAME_RE = re.compile(r"\b[A-Z][A-Za-z0-9]*_C\b")

TABLE_LEVEL_HEADERS = ("level", "уровень", "evidence level", "evidence_level")
TABLE_CONF_HEADERS = ("conf", "conf.", "confidence", "уверенность")
TABLE_ORACLE_HEADERS = ("oracle", "оракул")
# plan.md 10.4/EV-03: "путь к артефакту в поле Evidence НЕ является вторым
# методом - это место, куда записан результат, а не второй способ его
# получить".  The two column families are therefore kept apart: only the
# method family feeds sources[], the evidence family is recorded and
# explicitly NOT counted.  "evidence" used to sit in the method tuple, which
# made every artifact path a free second source and defeated EV-03.
TABLE_METHOD_HEADERS = ("метод", "method", "sources", "источник", "источники",
                        "методы")
TABLE_EVIDENCE_HEADERS = ("evidence", "артефакт", "артефакты", "доказательство",
                          "артефакт-доказательство", "artifact", "raw artifact",
                          "сырой артефакт")
TABLE_CLAIM_TYPE_HEADERS = ("claim type", "claim_type", "claim-type",
                            "тип утверждения", "тип claim", "claim type (10.5)")
TABLE_CLASS_HEADERS = ("claim class", "claim_class", "класс", "класс утверждения",
                       "class")
TABLE_ID_HEADERS = ("id", "#", "ид")
# Headers of a table that DEFINES a vocabulary rather than grading claims.
# See DEF-TABLE in TableHeader.is_definition_table.
TABLE_DEFINITION_HEADERS = ("определение", "definition", "смысл", "meaning",
                            "примеры", "examples", "что означает", "что это",
                            "что разрешено")
TABLE_CLAIM_HEADERS = ("утверждение", "claim", "наблюдение", "факт", "вопрос",
                       "ресурс", "интерпретация")

LOG_FIELD_RE = re.compile(r"^\s*[-*]\s*\*\*(?P<name>[^*]+?)\s*:?\*\*:?\s*(?P<value>.*)$")
LOG_FIELD_LEVEL = "evidence level"
LOG_FIELD_CONF = "confidence"
LOG_FIELD_ORACLE = "oracle"
LOG_FIELD_METHOD = "method"
LOG_FIELD_EVIDENCE = "evidence"
LOG_FIELD_BUILD = "build"
LOG_FIELD_ID = "id"
# plan.md 10.5 claim_type in a RESEARCH_LOG entry.  Any of these spellings is
# read, so the field can be added to the template without a validator change.
LOG_FIELD_CLAIM_TYPE = ("claim type", "claim_type", "claim-type",
                        "тип утверждения")


def _log_claim_type(fields: dict[str, str]) -> str:
    for name in LOG_FIELD_CLAIM_TYPE:
        value = fields.get(name)
        if value and value.strip():
            return value
    return ""

MAX_SPAN_CHARS = 400

# Everything below 0x20 except tab / LF / CR, plus DEL.
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Cells that explicitly claim nothing.
NON_CLAIMED_CELL: frozenset[str] = frozenset({
    "", "-", "--", "—", "–", "n/a", "n/д", "na", "нет", "?", "не применимо",
    "не применим",
})


@dataclass
class MarkdownRecord:
    """One fact read out of markdown prose."""

    notation: str
    line: int
    pointer: str
    ident: str | None
    text: str                       # everything the rules may look at
    # Just the claim, without the method / evidence / oracle columns.  The
    # class-P "no semantic conclusion" criterion must be judged on the CLAIM,
    # not on the sentence that describes how it was measured.
    claim_text: str = ""
    level: str | None = None
    confidence: float | None = None
    confidence_is_bound: bool = False
    oracle_present: bool = False
    oracle: OracleCell = field(default_factory=lambda: OracleCell())
    oracle_raw: str = ""
    sources: list[str] = field(default_factory=list)
    # Artifact paths from an Evidence column/field.  Recorded, and deliberately
    # NOT counted as sources (plan.md 10.4/EV-03).
    evidence_refs: list[str] = field(default_factory=list)
    sources_checkable: bool = False
    method_column_present: bool = False
    # Explicit claim_class as written in the document, before validation.
    claim_class_raw: str | None = None
    # plan.md 10.5 claim_type as written in the document, and canonicalised.
    # None means the notation carried no claim_type - which is a reported gap,
    # not a licence to skip the 10.5 matrix silently.
    claim_type_raw: str | None = None
    claim_type: str | None = None
    build_raw: str | None = None
    # True for an annotation found inside a register of questions/resources
    # (a table with an oracle column but no level/confidence column).  There
    # the Oracle column states which oracle the answer WILL need, not which
    # oracle backs a claim, so demanding an oracle on the annotation itself
    # would be a demand for evidence that does not exist yet.
    in_register: bool = False

    @property
    def oracles(self) -> set[str]:
        return self.oracle.oracles


@dataclass
class Unparseable:
    line: int
    notation: str
    reason: str
    excerpt: str


def _clean_md(text: str) -> str:
    """Strip the markdown decoration that carries no meaning for a value."""
    text = text.replace("<br>", " ").replace("<br/>", " ")
    text = text.replace("**", "").replace("`", "")
    text = text.replace("«", "").replace("»", "")
    text = re.sub(r"(?<!\w)\*(?!\*)", "", text)
    return " ".join(text.split())


def _strip_parens(text: str) -> str:
    """Remove parenthesised prose, innermost first."""
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"\([^()]*\)", " ", text)
    return " ".join(text.split())


def _signed(match: re.Match[str]) -> float:
    """The matched confidence value WITH its sign.

    Every confidence regex above carries a `sign` group; honouring it is what
    makes a negative confidence a rejected value instead of a positive one.
    """
    value = float(match.group("value").replace(",", "."))
    return -value if match.group("sign") else value


def _parse_confidence(text: str) -> tuple[list[float], bool]:
    """Return (values found, bound_flag).  More than one value = ambiguous."""
    values: list[float] = []
    bound = False
    for match in CONF_KEYWORD_RE.finditer(text):
        values.append(_signed(match))
        bound = bound or bool(match.group("bound"))
    if not values:
        for match in LEVEL_ADJACENT_CONF_RE.finditer(text):
            values.append(_signed(match))
            bound = bound or bool(match.group("bound"))
    return values, bound


def find_oracle_segment(text: str) -> str | None:
    """The value part of an "oracle: ..." field inside an annotation.

    The keyword only counts in field position - at the start of the span or
    right after a separator - so the word "oracle" used in a sentence does not
    turn the rest of that sentence into an oracle value.
    """
    for match in ORACLE_KEYWORD_RE.finditer(text):
        before = text[:match.start()].rstrip()
        if before and before[-1] not in ORACLE_FIELD_OPENERS:
            continue
        segment = text[match.end():].strip()
        if segment:
            return segment
    return None


def cut_oracle_commentary(text: str) -> str:
    """Keep the oracle VALUES, drop the sentence that explains them.

    Real cells look like "`external-doc` (сверка sha256 с release notes).
    Утверждение относится к нашему окружению, а не к сборке игры" - the value
    is the head, everything after the first sentence break is commentary.  A
    version-like dot ("global.ucas", "12.1.3") is never followed by a space,
    so cutting on ". " is safe.
    """
    for separator in (". ", "; ", " — ", " – ", " -- "):
        index = text.find(separator)
        if index > 0:
            text = text[:index]
    return text.strip(" .;")


def normalise_oracle_token(token: str) -> tuple[str | None, str | None]:
    """Map one raw oracle token onto the vocabulary.

    Returns (canonical value, alias source).  Both None means "not a value".
    """
    key = token.strip().strip(".,;:*_ ").lower()
    key = " ".join(key.split())
    if key in ORACLES:
        return key, None
    if key in ORACLE_ALIASES:
        return ORACLE_ALIASES[key], key
    return None, None


@dataclass
class OracleCell:
    """The outcome of reading one oracle cell / field / segment."""

    oracles: set[str] = field(default_factory=set)
    unknown: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    prose: dict[str, list[str]] = field(default_factory=dict)
    not_applicable: bool = False


def parse_oracle_cell(raw: str) -> OracleCell:
    """Parse an oracle cell / field / inline segment.

    Each `+`/`,`/`/`-separated part is treated as ONE candidate: keeping a
    prose part whole ("PE-заголовки", "требуется runtime-reflection") produces
    one readable finding instead of a shower of word-sized ones.  A part that
    WRAPS a vocabulary value in prose is accepted with a warning - the value
    is there, the formatting is not - while a part with no vocabulary value in
    it at all is an unknown oracle and a violation.
    """
    text = _strip_parens(_clean_md(raw))
    text = re.sub(r"§\s*\d+(?:\.\d+)*", " ", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}", " ", text)
    text = cut_oracle_commentary(text)
    result = OracleCell()
    parts = re.split(r"[+,;/]|\bи\b|\bили\b|\band\b|\bor\b|\bплюс\b", text)
    for part in parts:
        token = part.strip().strip(".,;:*_ ")
        if not token:
            continue
        lowered = " ".join(token.lower().split())
        if lowered in ORACLE_NOT_APPLICABLE:
            result.not_applicable = True
            continue
        if re.fullmatch(r"[\d\s.,%-]+", lowered):
            continue
        canonical, alias = normalise_oracle_token(token)
        if canonical is not None:
            result.oracles.add(canonical)
            if alias is not None:
                result.aliases[alias] = canonical
            continue
        embedded = [value for value in ORACLES
                    if re.search(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])", lowered)]
        if embedded:
            result.oracles.update(embedded)
            result.prose[token[:80]] = embedded
            continue
        result.unknown.append(token[:80])
    return result


def _balanced_spans(text: str, opener: str, closer: str) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, inner) for every balanced opener/closer span."""
    stack: list[int] = []
    for index, char in enumerate(text):
        if char == opener:
            stack.append(index)
        elif char == closer and stack:
            start = stack.pop()
            if not stack:
                yield start, index, text[start + 1:index]


def strip_fenced_blocks(lines: list[str]) -> list[str]:
    """Blank out fenced code blocks, preserving line numbering."""
    out: list[str] = []
    fence: str | None = None
    for line in lines:
        stripped = line.lstrip()
        marker = None
        if stripped.startswith("```"):
            marker = "```"
        elif stripped.startswith("~~~"):
            marker = "~~~"
        if fence is None and marker is not None:
            fence = marker
            out.append("")
            continue
        if fence is not None:
            if marker == fence:
                fence = None
            out.append("")
            continue
        out.append(line)
    return out


def split_table_row(line: str) -> list[str] | None:
    """Split a markdown table row, honouring the `\\|` escape.

    An escaped pipe is legitimate inside a cell (a shell pipeline in the
    "Метод" column), and treating it as a column separator would make the row
    look malformed - a false unparseable-record report.
    """
    stripped = line.strip()
    if not stripped.startswith("|"):
        return None
    body = stripped[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells = re.split(r"(?<!\\)\|", body)
    return [cell.replace("\\|", "|").strip() for cell in cells]


def is_table_separator(cells: Sequence[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c.strip()) for c in cells if c.strip())


@dataclass
class TableHeader:
    level: int | None
    confidence: int | None
    oracle: int | None
    method: int | None
    evidence: int | None
    claim_class: int | None
    ident: int | None
    claim: int | None
    definition: int | None
    width: int
    # plan.md 10.5 claim_type, if the table carries a column for it.  Since
    # validator 3.2.0 a markdown table CAN, which is what lets the 10.5 matrix
    # apply to the 216 markdown records instead of the 12 JSON ones.
    claim_type: int | None = None

    @property
    def is_graded(self) -> bool:
        """The table grades its rows: it has a level and/or a confidence column.

        An ORACLE COLUMN IS NOT REQUIRED.  Requiring one is how plan.md
        Appendix A - fifteen graded pre-flight observations under the headers
        `ID | Наблюдение | Метод | Level | Conf.` - stayed invisible to this
        validator: no Oracle column meant the whole table was skipped, so the
        rows that most needed EV-04 were the exact rows never checked.  A
        graded row with no oracle is a finding, not a reason to look away.
        """
        return self.level is not None or self.confidence is not None

    @property
    def is_register(self) -> bool:
        """An oracle column but no grading: a register of questions/resources.

        research/unknowns.md lists open questions with the oracle their ANSWER
        will need.  Those rows carry no claim yet, so they are counted and
        reported, never linted as facts.
        """
        return self.oracle is not None and not self.is_graded

    @property
    def is_definition_table(self) -> bool:
        """DEF-TABLE: the table defines the level vocabulary, it does not use it.

        plan.md 10.1 is a table `Уровень | Определение | Примеры` whose level
        column IS the subject of each row - the row defines what OBSERVED
        means.  Reading those four rows as four ungraded facts would produce
        four EV-04 findings against the section that defines EV-04, which is
        noise, and noise is how a gate gets switched off (plan.md 10.3 v2.2).
        The exemption is deliberately narrow: a level column, NO confidence,
        NO oracle and NO method column, plus a definitional header.  Any table
        that names a method or an oracle is a fact table and is linted.  Every
        table exempted this way is COUNTED AND PRINTED by file and line - see
        the EXEMPTIONS block of the report.  The caller additionally requires
        the level cells to enumerate distinct known levels.
        """
        return (self.level is not None
                and self.confidence is None
                and self.oracle is None
                and self.method is None
                and self.definition is not None)


def parse_table_header(cells: Sequence[str]) -> TableHeader:
    def find(candidates: Sequence[str], prefix: bool = False,
             exclude: Sequence[int | None] = ()) -> int | None:
        blocked = {index for index in exclude if index is not None}
        for index, cell in enumerate(cells):
            if index in blocked:
                continue
            name = _clean_md(cell).lower().strip()
            name = re.sub(r"\(.*?\)", "", name).strip()
            if name in candidates:
                return index
            if prefix and any(name.startswith(c) for c in candidates):
                return index
        return None

    # Found first and excluded from the prefix-matched claim search: "Claim
    # type" starts with "claim", so without the exclusion a claim_type column
    # would be read as the claim column and the claim text would be lost.
    claim_type = find(TABLE_CLAIM_TYPE_HEADERS)
    return TableHeader(
        claim_type=claim_type,
        level=find(TABLE_LEVEL_HEADERS),
        confidence=find(TABLE_CONF_HEADERS),
        oracle=find(TABLE_ORACLE_HEADERS, prefix=True),
        method=find(TABLE_METHOD_HEADERS, prefix=True),
        # Exact match on purpose: with prefix matching an "Evidence level"
        # column matches the evidence family and the level column at once, so
        # the level value ends up in evidence_refs and the row looks as if it
        # had a place to name a method.
        evidence=find(TABLE_EVIDENCE_HEADERS),
        claim_class=find(TABLE_CLASS_HEADERS),
        ident=find(TABLE_ID_HEADERS),
        claim=find(TABLE_CLAIM_HEADERS, prefix=True, exclude=(claim_type,)),
        definition=find(TABLE_DEFINITION_HEADERS, prefix=True),
        width=len(cells),
    )


def _levels_in(text: str) -> list[str]:
    seen: list[str] = []
    for match in LEVEL_TOKEN_RE.finditer(text):
        if match.group(1) not in seen:
            seen.append(match.group(1))
    return seen


def _invented_level_in(span: str) -> str | None:
    """An annotation-shaped span whose level slot holds a made-up level.

    The span must LOOK like a graded annotation - it carries a confidence value
    or an `oracle:` field - and its first comma-separated part must be a single
    ALL-CAPS word that is not one of the five plan.md 10.1 levels and not a
    record identifier.  Without this test an invented level was simply not
    matched by LEVEL_TOKEN_RE and the whole annotation vanished from the run.
    """
    if not (_parse_confidence(span)[0] or find_oracle_segment(span)):
        return None
    head = _clean_md(span.split(",")[0]).strip(" .;:*_`()[]")
    if not head or " " in head:
        return None
    if head in EVIDENCE_LEVELS or IDENT_SHAPED_TOKEN_RE.match(head):
        return None
    if LEVEL_SHAPED_TOKEN_RE.match(head):
        return head
    return None


def _split_sources(text: str) -> list[str]:
    """Split a Method / Evidence field into entries.

    Splits on ';' and newline only.  Until validator 3.2.0 it also split on the
    Russian conjunction "и", so one sentence of prose became two entries - and
    since every entry was counted as an independent method, EV-03 handed a free
    second method to any record whose method field contained the word "and".
    That is the same defect shape as counting an Evidence path or a second
    oracle: a clause boundary is not an act of measurement.

    Markdown decoration is deliberately NOT stripped here.  A backticked span
    is the signal that an entry names a command, and is_method_entry() below
    needs to see it.
    """
    parts = [p.strip(" .;") for p in re.split(r"[;\n]", text)]
    return [p for p in parts if len(_clean_md(p)) > 2]


class MarkdownExtractor:
    """Pull MarkdownRecords out of one document."""

    def __init__(self, relpath: str, text: str) -> None:
        self.relpath = relpath
        # Deliberately NOT str.splitlines(): it also breaks on \v, \f and
        # U+2028, so a stray control byte in a document would shift every
        # following line number and silently truncate a field.
        self.raw_lines = re.split(r"\r\n|\n|\r", text)
        self.lines = strip_fenced_blocks(self.raw_lines)
        self.records: list[MarkdownRecord] = []
        self.unparseable: list[Unparseable] = []
        self.suppressed = 0
        self.non_fact_tables = 0
        # (header line number, row count) of every table exempted as DEF-TABLE
        self.definition_tables: list[tuple[int, int]] = []
        self.file_exempt = False
        # (line number, excerpt) of every record marked as a quoted example
        self.quoted_examples: list[tuple[int, str]] = []
        # (line number, excerpt) of every span read as a normative enumeration
        # of permitted levels rather than as a record
        self.normative_enumerations: list[tuple[int, str]] = []
        self._quoted_example_lines: set[int] = set()
        self._ignored_lines: set[int] = set()
        self._table_row_lines: set[int] = set()
        self._register_row_lines: set[int] = set()

    # -- driver ---------------------------------------------------------
    def run(self) -> None:
        self._read_directives()
        if self.file_exempt:
            return
        self._scan_tables()
        self._scan_log_entries()
        self._scan_inline()
        self._split_quoted_examples()

    def _split_quoted_examples(self) -> None:
        """Move every record on a `quoted-example` line out of the linted set.

        Done after extraction rather than during it, so that a quoted example is
        still PARSED - the marker says "this grade belongs to someone else's
        record", not "stop reading here".  A malformed quotation is moved out
        the same way: a document teaching the rules may need to quote a record
        that cannot be parsed at all, which is often the whole point.
        """
        if not self._quoted_example_lines:
            return
        kept_records: list[MarkdownRecord] = []
        for record in self.records:
            if record.line in self._quoted_example_lines:
                self.quoted_examples.append((record.line, record.text[:120]))
            else:
                kept_records.append(record)
        self.records = kept_records
        kept_unparseable: list[Unparseable] = []
        for candidate in self.unparseable:
            if candidate.line in self._quoted_example_lines:
                self.quoted_examples.append((candidate.line, candidate.excerpt[:120]))
            else:
                kept_unparseable.append(candidate)
        self.unparseable = kept_unparseable
        self.quoted_examples.sort()

    # -- directives -----------------------------------------------------
    def _read_directives(self) -> None:
        pending: str | None = None
        for number, line in enumerate(self.lines, start=1):
            match = DIRECTIVE_RE.search(line)
            if match:
                what = match.group("what")
                if what == DIRECTIVE_IGNORE_FILE:
                    self.file_exempt = True
                    return
                if what in (DIRECTIVE_IGNORE_NEXT, DIRECTIVE_QUOTED_EXAMPLE):
                    # A trailing directive marks the line it sits on; a
                    # directive alone on its line marks the next one.  Both
                    # spellings are accepted because a quoted example is
                    # usually one sentence inside a paragraph, where an
                    # own-line comment would break the paragraph.
                    if DIRECTIVE_RE.sub("", line).strip():
                        self._mark(number, what)
                    else:
                        pending = what
                continue
            if pending is not None and line.strip():
                self._mark(number, pending)
                pending = None

    def _mark(self, number: int, what: str) -> None:
        """Apply a line-scoped directive to line `number` (a table: its rows)."""
        target = self._ignored_lines if what == DIRECTIVE_IGNORE_NEXT \
            else self._quoted_example_lines
        line = self.lines[number - 1] if number - 1 < len(self.lines) else ""
        if line.strip().startswith("|"):
            # a table header swallows the whole table, a prose line only itself
            index = number
            while index <= len(self.lines) and \
                    self.lines[index - 1].strip().startswith("|"):
                target.add(index)
                index += 1
        else:
            target.add(number)

    # -- tables ---------------------------------------------------------
    def _scan_tables(self) -> None:
        index = 0
        total = len(self.lines)
        while index < total:
            header_cells = split_table_row(self.lines[index])
            if header_cells is None or index + 1 >= total:
                index += 1
                continue
            separator = split_table_row(self.lines[index + 1])
            if separator is None or not is_table_separator(separator):
                index += 1
                continue
            header = parse_table_header(header_cells)
            row_index = index + 2
            rows: list[tuple[int, list[str]]] = []
            while row_index < total:
                cells = split_table_row(self.lines[row_index])
                if cells is None:
                    break
                rows.append((row_index + 1, cells))
                row_index += 1
            if not header.is_graded:
                if header.is_register:
                    self.non_fact_tables += 1
                    for line_no, _cells in rows:
                        self._register_row_lines.add(line_no)
                index = row_index
                continue
            if header.is_definition_table and self._enumerates_levels(header, rows):
                self.definition_tables.append((index + 1, len(rows)))
                for line_no, _cells in rows:
                    self._table_row_lines.add(line_no)
                index = row_index
                continue
            for line_no, cells in rows:
                self._table_row_lines.add(line_no)
                if line_no in self._ignored_lines:
                    self.suppressed += 1
                    continue
                self._record_from_row(header, line_no, cells)
            index = row_index

    @staticmethod
    def _enumerates_levels(header: TableHeader,
                           rows: Sequence[tuple[int, list[str]]]) -> bool:
        """True when the level column lists each level once: a vocabulary table.

        Second half of the DEF-TABLE test.  A table that repeats a level, or
        puts anything other than a bare level in that column, is grading
        claims and is linted normally.
        """
        seen: list[str] = []
        for _line_no, cells in rows:
            if header.level is None or header.level >= len(cells):
                return False
            found = _levels_in(_clean_md(cells[header.level]))
            if len(found) != 1 or found[0] in seen:
                return False
            seen.append(found[0])
        return bool(seen)

    def _record_from_row(self, header: TableHeader, line_no: int,
                         cells: list[str]) -> None:
        joined = " | ".join(cells)
        if len(cells) != header.width:
            self.unparseable.append(Unparseable(
                line_no, NOTATION_TABLE,
                f"row has {len(cells)} cell(s) but the header declares "
                f"{header.width}; the level/confidence/oracle columns cannot be "
                "addressed reliably",
                joined[:160]))
            return

        def cell(position: int | None) -> str:
            return cells[position] if position is not None else ""

        ident = _clean_md(cell(header.ident)) or None
        level_raw = cell(header.level)
        conf_raw = _clean_md(_strip_parens(cell(header.confidence)))
        oracle_raw = cell(header.oracle)

        level: str | None = None
        if header.level is not None:
            found = _levels_in(_clean_md(level_raw))
            if len(found) > 1:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_TABLE,
                    f"level cell names {len(found)} evidence levels {found}: one "
                    "row must carry exactly one graded claim. plan.md 10.3 v2.2 "
                    "\"Смешанные утверждения обязаны разделяться\" - a fact with "
                    "a primitive and an interpretive part is written as TWO "
                    "records, so split the row instead of grading both halves "
                    "in one cell",
                    joined[:160]))
                return
            if found:
                level = found[0]
            elif _clean_md(level_raw).lower() not in NON_CLAIMED_CELL:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_TABLE,
                    f"level cell {level_raw!r} is not one of "
                    f"{', '.join(EVIDENCE_LEVELS)}",
                    joined[:160]))
                return

        confidence: float | None = None
        bound = False
        if header.confidence is not None and conf_raw.lower() not in NON_CLAIMED_CELL:
            match = BARE_CONF_RE.match(conf_raw.replace(" ", ""))
            if match is None:
                values, bound = _parse_confidence(conf_raw)
                if len(values) == 1:
                    confidence = values[0]
                else:
                    self.unparseable.append(Unparseable(
                        line_no, NOTATION_TABLE,
                        f"confidence cell {conf_raw!r} is not a single number in "
                        "[0.00, 0.99]",
                        joined[:160]))
                    return
            else:
                confidence = _signed(match)
                bound = bool(match.group("bound"))

        # EV-03: only the method column feeds sources[].  The evidence column
        # is where the result was written down, not a second way to obtain it
        # (plan.md 10.4/EV-03).
        sources = _split_sources(cell(header.method)) if header.method is not None else []
        evidence_refs = (_split_sources(cell(header.evidence))
                         if header.evidence is not None else [])
        record = MarkdownRecord(
            notation=NOTATION_TABLE,
            line=line_no,
            pointer=f"$#L{line_no}" + (f" [{ident}]" if ident else ""),
            ident=ident,
            text=_clean_md(joined),
            claim_text=_clean_md(cell(header.claim)) or _clean_md(joined),
            level=level,
            confidence=confidence,
            confidence_is_bound=bound,
            oracle_present=bool(_clean_md(oracle_raw)),
            oracle=parse_oracle_cell(oracle_raw),
            oracle_raw=_clean_md(oracle_raw)[:120],
            sources=sources,
            evidence_refs=evidence_refs,
            # There is somewhere to name a method as soon as EITHER column
            # exists: with only an Evidence column the row names zero methods,
            # and EV-03 saying so is the correct outcome, not a gap.
            sources_checkable=header.method is not None or header.evidence is not None,
            method_column_present=header.method is not None,
            claim_class_raw=_clean_md(cell(header.claim_class)) or None,
            claim_type_raw=_clean_md(cell(header.claim_type)) or None,
            claim_type=normalise_claim_type(_clean_md(cell(header.claim_type))),
        )
        self.records.append(record)

    # -- RESEARCH_LOG entry blocks -------------------------------------
    def _scan_log_entries(self) -> None:
        blocks: list[tuple[int, dict[str, str]]] = []
        current: dict[str, str] | None = None
        current_line = 0
        current_field: str | None = None
        for number, line in enumerate(self.lines, start=1):
            if re.match(r"^#{1,6}\s", line):
                if current:
                    blocks.append((current_line, current))
                current = {}
                current_line = number
                current_field = None
                continue
            if current is None:
                continue
            match = LOG_FIELD_RE.match(line)
            if match:
                current_field = _clean_md(match.group("name")).lower().strip(": ")
                current[current_field] = match.group("value").strip()
                current.setdefault("__line__" + current_field, str(number))
                continue
            if current_field and line.strip() and line.startswith((" ", "\t")):
                current[current_field] += " " + line.strip()
        if current:
            blocks.append((current_line, current))

        for start_line, fields in blocks:
            if not any(key in fields for key in
                       (LOG_FIELD_LEVEL, LOG_FIELD_CONF, LOG_FIELD_ORACLE)):
                continue
            self._record_from_log_block(start_line, fields)

    def _record_from_log_block(self, start_line: int, fields: dict[str, str]) -> None:
        line_no = int(fields.get("__line__" + LOG_FIELD_LEVEL, start_line))
        if line_no in self._ignored_lines or start_line in self._ignored_lines:
            self.suppressed += 1
            return
        ident = _clean_md(fields.get(LOG_FIELD_ID, "")) or None
        text_parts = [value for key, value in fields.items()
                      if not key.startswith("__line__")]
        text = _clean_md(" ".join(text_parts))

        level: str | None = None
        if LOG_FIELD_LEVEL in fields:
            found = _levels_in(_clean_md(fields[LOG_FIELD_LEVEL]))
            if len(found) > 1:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_LOG,
                    f"the 'Evidence level' field grades {len(found)} different levels "
                    f"{found} in one entry. Keeping the split is right (plan.md 10.1: a "
                    "level is never promoted by restating it) but it is not "
                    "machine-readable here: give each graded claim its own entry, or "
                    "annotate each Finding item inline as *(LEVEL, confidence X, "
                    "oracle: Y)*, which this validator does read",
                    (ident or "") + " " + fields[LOG_FIELD_LEVEL][:110]))
                return
            if not found:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_LOG,
                    f"the 'Evidence level' field names none of "
                    f"{', '.join(EVIDENCE_LEVELS)}",
                    (ident or "") + " " + fields[LOG_FIELD_LEVEL][:110]))
                return
            level = found[0]

        confidence: float | None = None
        bound = False
        if LOG_FIELD_CONF in fields:
            raw = _clean_md(_strip_parens(fields[LOG_FIELD_CONF]))
            match = BARE_CONF_RE.match(raw.replace(" ", ""))
            if match is not None:
                confidence = _signed(match)
                bound = bool(match.group("bound"))
            else:
                values, bound = _parse_confidence(raw)
                if len(values) == 1:
                    confidence = values[0]
                elif raw.lower() not in NON_CLAIMED_CELL:
                    self.unparseable.append(Unparseable(
                        line_no, NOTATION_LOG,
                        f"'Confidence' field {fields[LOG_FIELD_CONF]!r} is not a "
                        "single number in [0.00, 0.99]",
                        (ident or "") + " " + raw[:120]))
                    return

        oracle_raw = fields.get(LOG_FIELD_ORACLE, "")
        # plan.md 10.4/EV-03: the Evidence field holds the path the result was
        # written to.  It is NOT a second method, so it does not feed sources[].
        # Until validator 3.0.1 it did, which handed every log entry a free
        # second source and made EV-03 unfalsifiable in this notation.
        sources = _split_sources(fields.get(LOG_FIELD_METHOD, ""))
        evidence_refs = _split_sources(fields.get(LOG_FIELD_EVIDENCE, ""))
        self.records.append(MarkdownRecord(
            notation=NOTATION_LOG,
            line=line_no,
            pointer=f"$#L{line_no}" + (f" [{ident}]" if ident else ""),
            ident=ident,
            text=text,
            claim_text=_clean_md(fields.get("claim", "")
                                 or fields.get("утверждение", "")
                                 or fields.get("finding", "")
                                 or fields.get("findings", "")
                                 or text),
            level=level,
            confidence=confidence,
            confidence_is_bound=bound,
            oracle_present=bool(_clean_md(oracle_raw)),
            oracle=parse_oracle_cell(oracle_raw),
            oracle_raw=_clean_md(oracle_raw)[:120],
            sources=sources,
            evidence_refs=evidence_refs,
            sources_checkable=True,
            method_column_present=LOG_FIELD_METHOD in fields,
            claim_class_raw=_clean_md(fields.get("claim class", "")
                                      or fields.get("claim_class", "")
                                      or fields.get("класс", "")) or None,
            claim_type_raw=_clean_md(_log_claim_type(fields)) or None,
            claim_type=normalise_claim_type(_clean_md(_log_claim_type(fields))),
            build_raw=fields.get(LOG_FIELD_BUILD),
        ))

    # -- inline annotations --------------------------------------------
    def _scan_inline(self) -> None:
        text = "\n".join(self.lines)
        offsets = self._line_offsets(text)
        spans: list[tuple[int, int, str, str]] = []
        for start, end, inner in _balanced_spans(text, "(", ")"):
            spans.append((start, end, inner, "()"))
        # Only a parenthesis that itself carries a level competes with a bold
        # span: "**Что наблюдается (OBSERVED, ~0.95).**" must yield ONE record,
        # while "**HYPOTHESIS, confidence 0.65, oracle: binary-analysis
        # (секции)**" must still yield its bold one.
        graded_parens = [(s, e) for s, e, inner, _kind in spans if _levels_in(inner)]
        for match in re.finditer(r"\*\*(.+?)\*\*", text, re.DOTALL):
            start, end = match.start(), match.end() - 1
            if any(ps < end and pe > start for ps, pe in graded_parens):
                continue
            spans.append((start, end, match.group(1), "**"))
        for start, end, inner, kind in sorted(spans):
            if len(inner) > MAX_SPAN_CHARS or "\n\n" in inner:
                continue
            levels = _levels_in(inner)
            if not levels:
                invented = _invented_level_in(inner)
                if invented is not None:
                    line_no = self._line_of(offsets, start)
                    if line_no in self._table_row_lines \
                            or line_no in self._ignored_lines:
                        continue
                    self.unparseable.append(Unparseable(
                        line_no, NOTATION_INLINE,
                        f"annotation grades a claim {invented!r}, which is not one of "
                        f"{', '.join(EVIDENCE_LEVELS)}. plan.md 10.1 closes that list, "
                        "so an invented level is a violation and not a record with a "
                        "missing level - use the nearest real level and say in prose "
                        "what the extra shading was meant to add",
                        _clean_md(inner)[:160]))
                continue
            line_no = self._line_of(offsets, start)
            if line_no in self._table_row_lines:
                # already covered by the fact-table record on that row
                continue
            in_register = line_no in self._register_row_lines
            if line_no in self._ignored_lines:
                self.suppressed += 1
                continue
            # A normative sentence naming the permitted levels is not a record.
            # Checked BEFORE anything is built from the span, so such a sentence
            # neither becomes a record nor becomes an unparseable candidate; it
            # is counted and printed in the EXEMPTIONS block instead.
            if len(levels) > 1:
                line_source = self.lines[line_no - 1] \
                    if line_no - 1 < len(self.lines) else ""
                if is_normative_level_enumeration(inner, line_source):
                    self.normative_enumerations.append(
                        (line_no, _clean_md(inner)[:120]))
                    continue
            segment = find_oracle_segment(inner)
            has_oracle = segment is not None
            conf_values, bound = _parse_confidence(inner)
            if kind == "**" and not has_oracle and not conf_values:
                # bold emphasis on a word, not an annotation
                continue
            if not has_oracle and not conf_values:
                self.records.append(MarkdownRecord(
                    notation=NOTATION_INLINE,
                    line=line_no,
                    pointer=f"$#L{line_no}",
                    ident=None,
                    text=_clean_md(inner),
                    level=levels[0] if len(levels) == 1 else None,
                    confidence=None,
                    oracle_present=False,
                    oracle_raw="",
                    sources_checkable=False,
                    in_register=in_register,
                ))
                continue
            if len(levels) > 1:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_INLINE,
                    f"annotation packs {len(levels)} evidence levels {levels} into "
                    "one span: which confidence and oracle belong to which claim "
                    "cannot be read. Split it into one annotation per claim "
                    "(plan.md 10.1: a level is never promoted by restating it)",
                    _clean_md(inner)[:160]))
                continue
            if len(conf_values) > 1:
                self.unparseable.append(Unparseable(
                    line_no, NOTATION_INLINE,
                    f"annotation carries {len(conf_values)} confidence values "
                    f"{conf_values} for one level",
                    _clean_md(inner)[:160]))
                continue
            oracle_raw = segment.split(";")[0] if segment else ""
            # The class field trails the oracle field in this notation, so it
            # has to be taken OUT of the oracle segment before the segment is
            # parsed - otherwise "класс P" reads as an oracle value.
            class_raw, oracle_raw = extract_claim_class_field(oracle_raw)
            if class_raw is None:
                class_raw, _rest = extract_claim_class_field(inner)
            self.records.append(MarkdownRecord(
                notation=NOTATION_INLINE,
                line=line_no,
                pointer=f"$#L{line_no}",
                ident=None,
                text=_clean_md(self._sentence_around(text, start)),
                level=levels[0],
                confidence=conf_values[0] if conf_values else None,
                confidence_is_bound=bound,
                oracle_present=bool(_clean_md(oracle_raw)),
                oracle=parse_oracle_cell(oracle_raw),
                oracle_raw=_clean_md(oracle_raw)[:120],
                sources=[],
                sources_checkable=False,
                claim_class_raw=class_raw,
                in_register=in_register,
            ))

    @staticmethod
    def _line_offsets(text: str) -> list[int]:
        offsets = [0]
        for index, char in enumerate(text):
            if char == "\n":
                offsets.append(index + 1)
        return offsets

    @staticmethod
    def _line_of(offsets: list[int], position: int) -> int:
        low, high = 0, len(offsets) - 1
        while low < high:
            middle = (low + high + 1) // 2
            if offsets[middle] <= position:
                low = middle
            else:
                high = middle - 1
        return low + 1

    @staticmethod
    def _sentence_around(text: str, position: int) -> str:
        """The sentence an annotation at `position` grades.

        An annotation normally TRAILS its sentence - "...в коммите a2a6385.
        *(OBSERVED, ...)*" - so the sentence terminator sitting immediately
        before it belongs to the annotated sentence and must not be mistaken
        for the separator that starts it.  Cutting there returned only the
        annotation itself, which silently emptied every text-based rule
        (C-11, the commit rules) for end-of-sentence annotations.

        An annotation can also stand ALONE on its line, under the sentence it
        grades - the shape plan.md 10.3 uses for the canonical A-07 pair:

            > Четыре байта по смещению 48 в `MISERY-Windows.utoc` равны ...
            > *(OBSERVED, confidence 0.99, oracle: container-metadata, класс P)*

        Read line-locally, such a record's claim text is the annotation itself,
        which empties every text-based rule for it exactly as the trailing case
        did: the v2.4 offset condition saw no offset, so a correctly written
        class P record derived as class I and its own stated class became an
        EV-05 violation.  ONE preceding line is taken in that case, and only
        when it is not blank - the sentence directly above is the claim, while a
        blank line means the annotation stands alone and nothing is guessed.
        """
        line_start = text.rfind("\n", 0, position) + 1
        if line_start > 0 and _ANNOTATION_ALONE_PREFIX_RE.match(
                text[line_start:position]):
            previous_start = text.rfind("\n", 0, line_start - 1) + 1
            if text[previous_start:line_start - 1].strip(" \t>*_-+•"):
                line_start = previous_start
        cut = position
        # The emphasis markers of the annotation itself sit between the
        # terminator and the span ("...a2a6385. *(OBSERVED..."), so they must be
        # trimmed before testing for the terminator - otherwise the sentence is
        # cut anyway and the claim text is lost.
        head = text[line_start:position].rstrip().rstrip("*_`\"' ")
        if head.endswith("."):
            cut = line_start + len(head) - 1
        start = text.rfind(". ", line_start, cut)
        start = line_start if start < 0 else start + 2
        end = text.find("\n", position)
        end = len(text) if end < 0 else end
        return text[start:end]


# ---------------------------------------------------------------------------
# 6c. vcs-history reachability (plan.md 10.5 v2.1, C-11 adjacent)
# ---------------------------------------------------------------------------

class CommitReachability:
    """Answers "is this commit reachable from HEAD?" via git itself.

    plan.md 10.5 v2.1: vcs-history proves what the repository records NOW, and
    history is rewritable - "коммит, зафиксированный как факт, может стать
    недостижимым после amend/rebase, и тогда факт перестаёт воспроизводиться".
    A knowledge-base claim citing an unreachable commit is therefore not a
    weak claim, it is an unverifiable one.
    """

    STATUS_REACHABLE = "reachable"
    STATUS_UNREACHABLE = "unreachable"
    STATUS_MISSING = "missing-object"
    STATUS_NOT_A_COMMIT = "not-a-commit"
    STATUS_NO_GIT = "no-git"

    def __init__(self, repo_root: Path, enabled: bool = True) -> None:
        self.repo_root = repo_root
        self.enabled = enabled
        self._cache: dict[str, str] = {}
        self._git_ok: bool | None = None

    def _git(self, *args: str) -> tuple[int, str]:
        try:
            done = subprocess.run(
                ["git", "-C", str(self.repo_root), *args],
                capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return 127, ""
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    def available(self) -> bool:
        if not self.enabled:
            return False
        if self._git_ok is None:
            code, _out = self._git("rev-parse", "--verify", "HEAD")
            self._git_ok = code == 0
        return self._git_ok

    def status(self, ref: str) -> str:
        if not self.available():
            return self.STATUS_NO_GIT
        if ref in self._cache:
            return self._cache[ref]
        code, out = self._git("cat-file", "-t", ref)
        kind = out.strip().splitlines()[0] if code == 0 and out.strip() else ""
        if code != 0:
            result = self.STATUS_MISSING
        elif kind != "commit":
            # A tree or blob hash is a legitimate - in fact a MORE stable -
            # vcs-history citation: amending a commit does not change its tree.
            # Nothing to check for reachability, so say so instead of claiming
            # the object is missing.
            result = self.STATUS_NOT_A_COMMIT
        else:
            code, _out = self._git("merge-base", "--is-ancestor", ref, "HEAD")
            result = self.STATUS_REACHABLE if code == 0 else self.STATUS_UNREACHABLE
        self._cache[ref] = result
        return result


def commit_hashes_in(text: str) -> list[str]:
    """Commit-shaped tokens in a text that actually talks about commits.

    Abbreviations are folded into the full hash they prefix, so citing both
    `9407f22` and `9407f2217e8b...` in one record yields one finding.
    """
    if not COMMIT_KEYWORD_RE.search(text):
        return []
    seen: list[str] = []
    for match in COMMIT_HASH_RE.finditer(text):
        token = match.group(0)
        if token not in seen:
            seen.append(token)
    kept: list[str] = []
    for token in sorted(seen, key=len, reverse=True):
        if any(other.startswith(token) for other in kept):
            continue
        kept.append(token)
    return kept


# A record that itself states the history was rewritten is not making an
# unverifiable claim - it is documenting the rewrite, which plan.md 10.5 v2.1
# explicitly asks for ("сопровождаться пометкой, если история переписывалась").
REWRITE_ACKNOWLEDGED_RE = re.compile(
    r"(?:не\s*достижим|недостижим|unreachable|аменд|amend|rebase|перепис|rewritten|"
    r"прежний|former|dangling|loose-объект)", re.IGNORECASE)


def check_commit_claims(
    pointer: str,
    text: str,
    oracles: set[str],
    reachability: CommitReachability | None,
) -> list[Finding]:
    """The C-11-adjacent rule implied by the vcs-history oracle.

    Two separate defects are possible and both are reported:
      VCS-ORACLE  a claim about repository history graded on another oracle -
                  `filesystem` proves that files exist, not what a commit
                  records, so the grading mislabels the source;
      VCS-REACH   a cited commit that is not reachable from HEAD, i.e. a fact
                  that can no longer be reproduced.
    """
    findings: list[Finding] = []
    hashes = commit_hashes_in(text)
    if not hashes:
        return findings
    if oracles and "vcs-history" not in oracles:
        findings.append(Finding(
            SEVERITY_ERROR, "VCS-ORACLE", pointer,
            f"claim cites commit(s) {hashes} but names oracle(s) {sorted(oracles)}; "
            "a statement about repository history requires oracle 'vcs-history' "
            "(plan.md 10.5 v2.1 matrix row 'в репозитории есть коммит C'). "
            f"{'filesystem: ' + ORACLE_BOUNDARIES['filesystem'] if 'filesystem' in oracles else ''}"
            .strip()))
    if reachability is None:
        return findings
    acknowledged = REWRITE_ACKNOWLEDGED_RE.search(text) is not None
    for ref in hashes:
        status = reachability.status(ref)
        if status in (CommitReachability.STATUS_REACHABLE,
                      CommitReachability.STATUS_NOT_A_COMMIT):
            continue
        if status == CommitReachability.STATUS_NO_GIT:
            findings.append(Finding(
                SEVERITY_WARN, "VCS-REACH", pointer,
                f"cannot verify commit {ref}: git is unavailable or this is not a "
                "repository, so the 10.5 reachability requirement is unchecked here"))
            continue
        detail = ("is not an object in this repository at all"
                  if status == CommitReachability.STATUS_MISSING
                  else "exists as a loose object but is NOT reachable from HEAD")
        if acknowledged:
            findings.append(Finding(
                SEVERITY_WARN, "VCS-REACH", pointer,
                f"commit {ref} {detail}. The record itself notes the rewrite, which is "
                "what plan.md 10.5 v2.1 asks for, so this is not counted as a "
                "violation - keep the note in the same record, because the hash stops "
                "resolving entirely after the first `git gc`"))
            continue
        findings.append(Finding(
            SEVERITY_ERROR, "VCS-REACH", pointer,
            f"commit {ref} {detail}, so the claim cannot be reproduced. plan.md 10.5 "
            "v2.1: history is rewritable, and a commit recorded as a fact can be made "
            "unreachable by amend/rebase - say plainly that the commit was amended and "
            "why, and cite the commit reachable from HEAD now; do not silently swap "
            "the hash"))
    return findings


# ---------------------------------------------------------------------------
# 6d. Lint rules for markdown records
# ---------------------------------------------------------------------------

def lint_markdown_record(
    record: MarkdownRecord,
    reachability: CommitReachability | None = None,
    counterpart_ids: Collection[str] = (),
) -> list[Finding]:
    """Apply the rules that a prose record can actually be held to.

    Enforced: EV-LEVEL, EV-CONF (range plus the 0.99 ceiling), EV-04 (the nine
    value vocabulary), EV-03 where a sources column exists, C-11, C-12, and the
    vcs-history rules.  NOT enforced: the full 10.5 claim-type matrix, because
    a prose record carries no claim_type - that gap is stated in the report
    rather than hidden.
    """
    pointer = record.pointer
    findings: list[Finding] = []
    err = lambda rule, msg: findings.append(Finding(SEVERITY_ERROR, rule, pointer, msg))  # noqa: E731
    warn = lambda rule, msg: findings.append(Finding(SEVERITY_WARN, rule, pointer, msg))  # noqa: E731

    # --- a graded claim with neither confidence nor oracle ----------------
    if not record.oracle_present and record.confidence is None \
            and record.notation == NOTATION_INLINE:
        warn("MD-BARE",
             f"evidence level {record.level or '?'} stated with no confidence and no "
             "oracle; plan.md 18.3 item 5 requires every recorded fact to carry an "
             "oracle, so either complete the annotation or drop the level marker")
        return findings

    # --- evidence_level (plan.md 10.1) ------------------------------------
    if record.level is None:
        err("EV-LEVEL", "record carries confidence/oracle but no evidence_level "
                        f"(plan.md 10.1); expected one of {', '.join(EVIDENCE_LEVELS)}")
    elif record.level not in EVIDENCE_LEVELS:
        err("EV-LEVEL", f"evidence_level {record.level!r} is not one of "
                        f"{', '.join(EVIDENCE_LEVELS)}")

    # --- confidence (plan.md 10.2) ---------------------------------------
    confidence = record.confidence
    if confidence is None:
        if record.level == "UNKNOWN":
            warn("EV-CONF", "no confidence given; for an UNKNOWN this is defensible, "
                            "but say so explicitly (plan.md 10.2 band 0.00-0.29) "
                            "instead of leaving the cell empty")
        else:
            err("EV-CONF", f"evidence_level {record.level} without a confidence value "
                           "(plan.md 10.2)")
    elif confidence < CONFIDENCE_FLOOR or confidence > MAX_CONFIDENCE_EXCLUSIVE:
        err("EV-CONF", f"confidence {confidence} outside the scale "
                       f"[{CONFIDENCE_FLOOR:.2f}, {CONFIDENCE_CEILING}] (plan.md 10.2)")
    elif exceeds_ceiling(confidence):
        err("EV-CONF", ceiling_message(confidence))

    # --- EV-04: oracle presence and vocabulary ---------------------------
    if not record.oracle_present:
        if record.in_register:
            warn("EV-04", "graded annotation inside a register of questions/resources "
                          "names no oracle of its own. The table's Oracle column states "
                          "which oracle the ANSWER will need, which is not the same "
                          "thing; when this becomes a fact, move it to a fact table or "
                          "complete the annotation (plan.md 18.3 item 5)")
        elif record.notation == NOTATION_INLINE:
            # Prose can hold a level+confidence pair for two other reasons: it
            # cites a record graded elsewhere, or it discusses the notation
            # itself.  The validator cannot tell those from a fresh fact, so it
            # warns instead of failing - unlike a fact-table row or a log entry,
            # where an empty oracle field is unambiguous.
            warn("EV-04", "annotation states a confidence but names no oracle "
                          f"(plan.md 10.5 vocabulary: {', '.join(ORACLES)}). If this is "
                          "a fresh fact, complete it; if it cites a record graded "
                          "elsewhere, cite that record's id instead of restating its "
                          "level and confidence (plan.md 10.1: restating never promotes)")
        else:
            err("EV-04", "no oracle named; plan.md 10.5 requires every record to carry "
                         f"one or more of: {', '.join(ORACLES)} (plan.md 18.3 item 5 "
                         "makes this a milestone gate)")
    else:
        cell = record.oracle
        if cell.not_applicable:
            err("EV-04", f"oracle {record.oracle_raw!r} declares that no oracle applies. "
                         "plan.md 10.5 v2.1 removed that excuse: a fact about our own "
                         "file tree is 'filesystem', Steam bookkeeping is "
                         "'steam-metadata', our own git history is 'vcs-history'. "
                         "Name the actual oracle")
        for alias, canonical in sorted(cell.aliases.items()):
            warn("ORA-ALIAS", f"oracle {alias!r} is a draft spelling; plan.md 10.5 v2.1 "
                              f"normalises it to {canonical!r} - update the document text")
        for token, embedded in sorted(cell.prose.items()):
            warn("ORA-PROSE", f"oracle value(s) {embedded} are wrapped in prose "
                              f"({token!r}); the field must carry the bare value(s), with "
                              "any qualification moved to the claim or method text")
        if cell.unknown:
            shown = ", ".join(repr(token) for token in cell.unknown[:2])
            more = f" (+{len(cell.unknown) - 2} more)" if len(cell.unknown) > 2 else ""
            err("EV-04", f"unknown oracle value(s) {shown}{more}; the plan.md 10.5 list "
                         f"is closed: {', '.join(ORACLES)}")
        if not cell.oracles and not cell.unknown and not cell.not_applicable:
            err("EV-04", f"oracle cell {record.oracle_raw!r} yields no vocabulary value")

    # --- EV-04: the 10.5 claim-type matrix, when the record carries a type -
    # Since validator 3.2.0 a markdown table column or a log-entry field can
    # carry claim_type, and when it does the SAME matrix runs as for a JSON
    # record.  A record without one is not silently exempt: it is counted and
    # named in the report's per-file gap line.
    if record.claim_type is not None:
        _requirement, matrix_findings = check_claim_type_matrix(
            pointer, record.claim_type, record.oracles,
            record_text=record.text,
            has_justification=bool(JUSTIFICATION_MENTION_RE.search(record.text)),
            evidence_level=record.level, confidence=confidence)
        findings.extend(matrix_findings)

    # --- EV-03 / EV-05: claim class and the criteria it selects -----------
    # The class is derived from evidence_level first (plan.md 10.3 v2.3), then
    # from claim_type where the notation carries one, then from the oracle plus
    # the wording of the claim (plan.md 10.3 criterion 3).
    _verdict, class_findings = lint_claim_class(
        pointer,
        oracles=record.oracles,
        claim_type=record.claim_type,
        claim_text=record.claim_text or record.text,
        confidence=confidence,
        explicit_raw=record.claim_class_raw,
        sources=list(record.sources),
        sources_checkable=record.sources_checkable,
        evidence_level=record.level,
        build_key=record.build_raw,
        evidence_refs=record.evidence_refs,
        method_present=record.method_column_present,
        notation=record.notation,
        counterpart_ids=counterpart_ids,
    )
    findings.extend(class_findings)

    # --- C-12: external-doc alone caps confidence at 0.7 ------------------
    if record.oracles == {"external-doc"} and confidence is not None \
            and confidence > EXTERNAL_DOC_ONLY_MAX_CONFIDENCE:
        err("C-12", f"oracle is external-doc only, so confidence must be <= "
                    f"{EXTERNAL_DOC_ONLY_MAX_CONFIDENCE} for a claim about THIS build "
                    f"(plan.md 17.3/C-12 rule 1, 10.5: {ORACLE_BOUNDARIES['external-doc']}), "
                    f"got {confidence}")

    # --- C-11: global.ucas proves names, nothing else --------------------
    # A prose record has no claim_type, so - unlike the JSON layer, where
    # claim_type=asset-exists is an explicit assertion - the mere appearance of
    # a /Game path is not itself the claim.  What is enforced here is exactly
    # the plan's "Обязательное правило": such a name may be carried at
    # HYPOTHESIS with confidence <= 0.4 and no higher.
    if record.oracles == {"global-ucas"}:
        asset = GAME_PATH_RE.search(record.text)
        blueprint = BP_NAME_RE.search(record.text)
        layout = LAYOUT_WORDS_RE.search(record.text)
        if layout is not None:
            err("C-11", f"oracle is global-ucas only, but the claim is about layout "
                        f"({layout.group(0)!r}); offsets, sizes and property order are "
                        "unobtainable from global.ucas in principle and require "
                        "runtime-reflection")
        if (asset is not None or blueprint is not None) and confidence is not None \
                and confidence > GLOBAL_UCAS_ASSET_MAX_CONFIDENCE:
            err("C-11", "a /Game or Blueprint-shaped name known only from global.ucas is "
                        f"at most HYPOTHESIS with confidence <= {GLOBAL_UCAS_ASSET_MAX_CONFIDENCE} "
                        f"(plan.md 10.5 \"Обязательное правило\"), got {confidence}")
        if (asset is not None or blueprint is not None) \
                and record.level in ("OBSERVED", "INFERRED"):
            err("C-11", f"evidence_level {record.level} is not available for a /Game or "
                        "Blueprint-shaped name known only from global.ucas; plan.md 10.5 "
                        "caps it at HYPOTHESIS")

    # --- 9.3: every field of the log template is mandatory ----------------
    if record.notation == NOTATION_LOG and not (record.build_raw or "").strip():
        warn("EV-BUILD", "log entry carries no 'Build' field; plan.md 9.3 makes every "
                         "field of the template mandatory - write build_key=..., or "
                         "'UNKNOWN', or say why the record is not about the game build, "
                         "but do not omit the line (C-07)")

    # --- vcs-history rules ------------------------------------------------
    findings.extend(check_commit_claims(pointer, record.text, record.oracles,
                                        reachability))
    return findings


def validate_markdown_file(
    path: Path,
    display_path: str,
    reachability: CommitReachability | None = None,
) -> FileReport:
    report = FileReport(path=display_path, kind=KIND_MARKDOWN, schema=None,
                        schema_status="not-applicable")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        report.findings.append(Finding(SEVERITY_ERROR, "IO", "$", f"cannot read file: {exc}"))
        return report
    except UnicodeDecodeError as exc:
        report.findings.append(Finding(SEVERITY_ERROR, "IO", "$",
                                       f"file is not valid UTF-8: {exc}"))
        return report
    if text.startswith("\ufeff"):
        report.findings.append(Finding(
            SEVERITY_ERROR, "IO", "$",
            "file starts with a UTF-8 BOM; repository documents are BOM-free UTF-8"))
        text = text.lstrip("\ufeff")

    # C0 control bytes are almost always a shell escape that got interpreted
    # ("\v" in a path becoming a vertical tab).  They corrupt line numbering
    # and truncate whatever field they land in, so they are reported and then
    # neutralised rather than parsed around.
    control = list(CONTROL_CHAR_RE.finditer(text))
    if control:
        places = []
        for match in control[:3]:
            line_no = text.count("\n", 0, match.start()) + 1
            places.append(f"line {line_no} (0x{ord(match.group(0)):02x})")
        report.findings.append(Finding(
            SEVERITY_ERROR, "IO", "$",
            f"{len(control)} C0 control character(s) in a text document: "
            f"{', '.join(places)}"
            f"{' ...' if len(control) > 3 else ''}. Almost certainly a shell escape "
            "that was interpreted - e.g. '\\v' inside a Windows path became a "
            "vertical tab. The byte truncates the field it sits in and shifts line "
            "numbers; write the file with the Write/Edit tools, not shell "
            "redirection"))
        text = CONTROL_CHAR_RE.sub(" ", text)

    extractor = MarkdownExtractor(display_path, text)
    extractor.run()
    report.exempt = extractor.file_exempt
    report.suppressed_count = extractor.suppressed
    report.non_fact_tables = extractor.non_fact_tables
    report.definition_tables = [
        f"{display_path}:L{line} ({rows} row(s))"
        for line, rows in extractor.definition_tables
    ]
    report.quoted_examples = [
        f"{display_path}:L{line}  {' '.join(excerpt.split())[:100]!r}"
        for line, excerpt in extractor.quoted_examples
    ]
    report.normative_enumerations = [
        f"{display_path}:L{line}  {' '.join(excerpt.split())[:100]!r}"
        for line, excerpt in extractor.normative_enumerations
    ]
    if extractor.file_exempt:
        return report

    for candidate in extractor.unparseable:
        report.unparseable_count += 1
        excerpt = " ".join(candidate.excerpt.split())[:120]
        report.findings.append(Finding(
            SEVERITY_ERROR, "PARSE-MD", f"$#L{candidate.line}",
            f"{candidate.notation}: {candidate.reason}. Excerpt: {excerpt!r}"))

    # Every record id this document defines.  It is the white list the MIX-SCOPE
    # "delegated" shape checks a named counterpart against (section 2d): a record
    # may hand a conclusion to its counterpart only if that counterpart really
    # exists here.  Collected from the whole extraction before any linting, so
    # the order of records in the file does not matter - LOG-0004 may point at
    # LOG-0004i, which is written after it.
    counterpart_ids = frozenset(
        record.ident.upper() for record in extractor.records if record.ident)

    unchecked_ev03 = 0
    for record in extractor.records:
        report.record_count += 1
        report.notation_counts[record.notation] = \
            report.notation_counts.get(record.notation, 0) + 1
        report.findings.extend(lint_markdown_record(
            record, reachability=reachability, counterpart_ids=counterpart_ids))
        # MIX-SCOPE: every conclusion marker this record MENTIONS rather than
        # asserts, named with the clause it sits in.  Recomputed here rather
        # than returned through the lint, so the report and the decision read
        # the same function (scope_conclusion_markers) and cannot drift.
        _asserted, mentioned = scope_conclusion_markers(
            record.claim_text or record.text, counterpart_ids)
        for marker, reason, excerpt in mentioned:
            report.mix_scope_spans.append(
                f"{display_path}:L{record.line}"
                + (f" [{record.ident}]" if record.ident else "")
                + f"  {reason}  marker={marker!r}  {excerpt!r}")
        if not record.sources_checkable and record.confidence is not None \
                and record.confidence >= EV03_CONFIDENCE_THRESHOLD:
            unchecked_ev03 += 1
        # The residual claim_type gap, named per record rather than disclosed in
        # aggregate.  Narrowed to where the missing claim_type actually changes
        # the outcome: confidence >= 0.95 (the band whose criteria are all
        # mandatory) AND a derived class of P or undetermined - because a record
        # that already derives class I is held to the interpretive criteria
        # whether or not it names a claim_type, while a class P record at 0.95+
        # is precisely the one a claim_type outside the primitive-measurement
        # rows would have moved into class I.  RA-09 was that case; the
        # filesystem+steam-metadata cross-check rule now catches it without a
        # claim_type, and what is listed here is what remains.
        if record.claim_type is None and record.confidence is not None \
                and record.confidence >= CRITERIA_STRICT_THRESHOLD:
            verdict = derive_claim_class(record.oracles, None,
                                         record.claim_text or record.text,
                                         record.level, counterpart_ids)
            if verdict.claim_class != CLASS_I:
                report.claim_type_gaps.append(
                    f"L{record.line}"
                    + (f" [{record.ident}]" if record.ident else "")
                    + f" {record.confidence} class {verdict.claim_class}")
                report.claim_type_gap_remedies.append((
                    claim_type_gap_remedy(record.notation, record.oracles),
                    f"{display_path}:L{record.line}"
                    + (f" [{record.ident}]" if record.ident else "")))
    if unchecked_ev03:
        report.findings.append(Finding(
            SEVERITY_WARN, "EV-03", "$",
            f"{unchecked_ev03} inline annotation(s) at confidence >= "
            f"{EV03_CONFIDENCE_THRESHOLD} carry no sources[] field, so EV-03 could not "
            "be checked mechanically for them; the inline notation has no place to "
            "name the two independent methods plan.md 10.3 rule 1 demands"))
    return report


# ---------------------------------------------------------------------------
# 7. File-level validation
# ---------------------------------------------------------------------------

def match_pattern(pattern: str, relpath: str) -> bool:
    """Segment-wise glob: '*' never crosses a path separator."""
    pat_parts = pattern.split("/")
    path_parts = relpath.split("/")
    if len(pat_parts) != len(path_parts):
        return False
    return all(fnmatch.fnmatchcase(p, q) for p, q in zip(path_parts, pat_parts))


def lookup_rule(relpath: str) -> ArtifactRule | None:
    relpath = relpath.replace("\\", "/")
    for rule in ARTIFACT_SCHEMA_MAP:
        if match_pattern(rule.pattern, relpath):
            return rule
    return None


def load_schema(schema_dir: Path, name: str) -> tuple[dict[str, Any] | None, str]:
    path = schema_dir / name
    if not path.is_file():
        return None, "missing"
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh), "loaded"
    except (OSError, ValueError) as exc:
        return None, f"unreadable: {exc}"


def validate_file(
    path: Path,
    relpath: str,
    schema_dir: Path,
    ignored_keywords: set[str],
    allow_untyped_claims: bool = False,
    reachability: CommitReachability | None = None,
) -> FileReport:
    rule = lookup_rule(relpath)
    report = FileReport(path=relpath)

    if rule is None:
        report.kind = KIND_JSONL if relpath.endswith(".jsonl") else KIND_JSON
        report.findings.append(Finding(
            SEVERITY_WARN, "MAP",
            "$",
            "no entry in ARTIFACT_SCHEMA_MAP for this path; add one to "
            "tools/kb/validate.py so the artifact is covered",
        ))
    else:
        report.kind = rule.kind
        report.schema = rule.schema

    kind = report.kind
    documents: list[tuple[str, Any]] = []

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        report.findings.append(Finding(SEVERITY_ERROR, "IO", "$", f"cannot read file: {exc}"))
        return report
    except UnicodeDecodeError as exc:
        report.findings.append(Finding(SEVERITY_ERROR, "IO", "$",
                                       f"file is not valid UTF-8: {exc}"))
        return report

    if text.startswith("\ufeff"):
        report.findings.append(Finding(
            SEVERITY_ERROR, "IO", "$",
            "file starts with a UTF-8 BOM; machine-readable artifacts must be "
            "BOM-free UTF-8",
        ))
        text = text.lstrip("\ufeff")

    if kind == KIND_JSONL:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                documents.append((f"$#L{lineno}", json.loads(line)))
            except ValueError as exc:
                report.findings.append(Finding(SEVERITY_ERROR, "PARSE", f"$#L{lineno}",
                                               f"invalid JSON on line {lineno}: {exc}"))
    else:
        try:
            documents.append(("$", json.loads(text)))
        except ValueError as exc:
            report.findings.append(Finding(SEVERITY_ERROR, "PARSE", "$",
                                           f"invalid JSON: {exc}"))

    # -- layer 1: schema ------------------------------------------------
    if rule is not None and rule.schema:
        schema, status = load_schema(schema_dir, rule.schema)
        report.schema_status = status
        if schema is None:
            severity = SEVERITY_WARN if status == "missing" else SEVERITY_ERROR
            report.findings.append(Finding(
                severity, "SCHEMA", "$",
                f"schema {rule.schema} {status} in {schema_dir.as_posix()}; "
                "schema layer skipped for this file (lint layer still ran)",
            ))
        else:
            for pointer, document in documents:
                errors, ignored, _backend = validate_against_schema(
                    document, schema, pointer, schema_dir=schema_dir)
                ignored_keywords.update(ignored)
                for ptr, msg in errors:
                    report.findings.append(Finding(SEVERITY_ERROR, "SCHEMA", ptr, msg))
    elif rule is not None:
        report.schema_status = "not-applicable"

    # -- layer 2: project lint -----------------------------------------
    # Two shapes, two rule sets (section 5b).  The reduced annotation envelope
    # is linted by lint_annotation, which drops exactly the two rules whose
    # remedy that schema forbids; everything else is a full record.
    for pointer, document in documents:
        for rec_pointer, record in iter_records(document, pointer):
            report.record_count += 1
            if is_annotation(record, at_root=rec_pointer == pointer):
                report.annotation_count += 1
                report.findings.extend(lint_annotation(rec_pointer, record))
            else:
                report.findings.extend(
                    lint_record(rec_pointer, record,
                                allow_untyped_claims=allow_untyped_claims,
                                reachability=reachability))

    return report


# ---------------------------------------------------------------------------
# 8. Discovery / driver
# ---------------------------------------------------------------------------

def is_ignored(relpath: str) -> bool:
    relpath = relpath.replace("\\", "/")
    return (relpath.startswith(IGNORED_PATH_PREFIXES)
            or relpath.endswith(IGNORED_SUFFIXES))


def check_schema_dir(schema_dir: Path) -> list[FileReport]:
    """Cheap sanity pass over research/schema/: every schema must parse.

    Schemas are not knowledge-base records, so they are never linted; but an
    unparseable schema would silently disable a whole artifact's schema layer,
    which is exactly the kind of silent gap this project forbids.
    """
    reports: list[FileReport] = []
    if not schema_dir.is_dir():
        return reports
    for path in sorted(schema_dir.glob("*.json")):
        report = FileReport(path=path.as_posix(), kind="schema", schema=None,
                            schema_status="self-check")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            report.findings.append(Finding(SEVERITY_ERROR, "SCHEMA", "$",
                                           f"cannot read schema: {exc}"))
        except ValueError as exc:
            report.findings.append(Finding(SEVERITY_ERROR, "SCHEMA", "$",
                                           f"schema is not valid JSON: {exc}"))
        else:
            if not isinstance(document, dict):
                report.findings.append(Finding(
                    SEVERITY_ERROR, "SCHEMA", "$",
                    f"schema root must be an object, got {type(document).__name__}"))
            elif not path.name.endswith(".schema.json"):
                report.findings.append(Finding(
                    SEVERITY_WARN, "SCHEMA", "$",
                    "file lives in research/schema/ but is not named *.schema.json, "
                    "so ARTIFACT_SCHEMA_MAP will never reference it"))
            if isinstance(document, dict):
                report.findings.extend(check_schema_confidence_bound(document))
                report.findings.extend(check_schema_class_p_oracles(document))
        reports.append(report)
    return reports


def check_schema_confidence_bound(document: Any, pointer: str = "$") -> list[Finding]:
    """Does the schema's own numeric bound agree with the plan.md 10.2 ceiling?

    This exists because of the exact defect the third adversarial review found:
    the 0.99 ceiling was STATED in three artifacts and compared against in
    none.  A schema whose prose says "the practical ceiling of the scale is
    0.99" while its keyword says `exclusiveMaximum: 1` accepts 0.995 and 0.999,
    and the prose then convinces the reader that a check happened.

    Reported as a WARN rather than an ERROR on purpose: the schema is not this
    file's to fix, and a rule the validator has just started enforcing should
    not turn into a gate failure against a document whose owner has not been
    told yet.  Naming it on every run is the point.
    """
    findings: list[Finding] = []
    if not isinstance(document, dict):
        return findings
    for key, value in document.items():
        if key == "confidence" or (isinstance(key, str) and key.endswith("confidence")):
            if isinstance(value, dict):
                bound = value.get("maximum")
                exclusive = value.get("exclusiveMaximum")
                ok = (isinstance(bound, (int, float)) and not isinstance(bound, bool)
                      and abs(float(bound) - CONFIDENCE_CEILING) < 1e-9)
                if not ok and (bound is not None or exclusive is not None):
                    findings.append(Finding(
                        SEVERITY_WARN, "SCHEMA", f"{pointer}.{key}",
                        f"the confidence bound is maximum={bound!r} / "
                        f"exclusiveMaximum={exclusive!r}, which admits values in the "
                        f"open interval ({CONFIDENCE_CEILING}, "
                        f"{MAX_CONFIDENCE_EXCLUSIVE:.2f}) such as 0.995 and 0.999. "
                        "plan.md 10.2 v2.3 makes the ceiling a COMPARISON: the "
                        f"checkable condition is {CONFIDENCE_FLOOR:.2f} <= confidence "
                        f"<= {CONFIDENCE_CEILING}, and those values are forbidden "
                        "exactly as 1.00 is, because they express a precision the "
                        f"scale does not have. Write \"maximum\": {CONFIDENCE_CEILING} "
                        "and drop exclusiveMaximum. Until then this schema states a "
                        "ceiling it does not enforce, and a rule stated and not "
                        "compared is worse than an absent one"))
    for value in document.values():
        if isinstance(value, dict):
            findings.extend(check_schema_confidence_bound(value, pointer))
    return findings


def check_schema_class_p_oracles(document: Any, pointer: str = "$") -> list[Finding]:
    """Does the schema's class P oracle list agree with plan.md 10.3 v2.4?

    The same defect shape as check_schema_confidence_bound, one rule later.
    plan.md 10.3 правка v2.4 admits `binary-analysis` and `container-metadata`
    into class P for a literal read at a stated offset and length; this file
    implements that (CLASS_P_ORACLES_OFFSET_CONDITIONAL, derive_claim_class step
    3b).  A schema whose class P shape still enumerates only the pre-v2.4 white
    list REJECTS the very records the plan now admits - and it does so quietly,
    because the markdown layer and the JSON layer would then disagree about the
    same claim: plan.md 10.3's own canonical primitive half ("четыре байта по
    смещению 48 ... oracle: container-metadata, класс P") validates here and
    fails there.

    Two things are checked on every oracle enum in the schema:

      * an enum EQUAL to the unconditional white list, where the plan now has
        five admissible values - the pre-v2.4 white list, left behind;
      * any value outside the plan.md 10.5 vocabulary of nine - drift in the
        closed list itself, in either direction.

    WARN and not ERROR, deliberately and for the same reason as the confidence
    bound: research/schema/*.schema.json is not this file's to edit, and a rule
    the validator has just started applying must not become a gate failure
    against a document whose owner has not been told yet.  Naming it on every
    run until it agrees is the whole point; it falls silent by itself the moment
    the schema lands v2.4.
    """
    findings: list[Finding] = []
    if not isinstance(document, dict):
        return findings
    for key, value in document.items():
        if key == "oracle" and isinstance(value, dict):
            enum = value.get("enum")
            if not isinstance(enum, list):
                item = value.get("items")
                enum = item.get("enum") if isinstance(item, dict) else None
            if isinstance(enum, list):
                values = {v for v in enum if isinstance(v, str)}
                unknown = sorted(values - set(ORACLES))
                if unknown:
                    findings.append(Finding(
                        SEVERITY_WARN, "SCHEMA", f"{pointer}.{key}",
                        f"oracle enum contains {unknown}, which the plan.md 10.5 v2.1 "
                        f"vocabulary does not: the closed list is "
                        f"{', '.join(ORACLES)}. tools/kb/validate.py rule EV-04 applies "
                        "that list to markdown records, so a value only this schema "
                        "knows is accepted in JSON and rejected in prose"))
                if values == set(CLASS_P_ORACLES_UNCONDITIONAL):
                    findings.append(Finding(
                        SEVERITY_WARN, "SCHEMA", f"{pointer}.{key}",
                        "this oracle enum is exactly the pre-v2.4 class P white list "
                        f"{sorted(CLASS_P_ORACLES_UNCONDITIONAL)}. plan.md 10.3 правка "
                        f"v2.4 additionally admits "
                        f"{sorted(CLASS_P_ORACLES_OFFSET_CONDITIONAL)} into class P for "
                        "a literal read that states a determinate address AND a length "
                        "(\"четыре байта по смещению 48\"), which is how plan.md 10.3 "
                        "writes its own canonical primitive record. As it stands the "
                        "schema rejects a record this validator derives as class P, so "
                        "the JSON layer and the markdown layer disagree about one claim. "
                        "Add the two values and express the offset condition (the plan "
                        "attaches it to the WORDING of the claim, not to the oracle "
                        f"field); this warning goes silent when the enum admits "
                        f"{sorted(CLASS_P_ORACLES)}"))
    for value in document.values():
        if isinstance(value, dict):
            findings.extend(check_schema_class_p_oracles(value, pointer))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    findings.extend(check_schema_class_p_oracles(item, pointer))
    return findings


JSON_EXTENSIONS: tuple[str, ...] = ("*.json", "*.jsonl")
MARKDOWN_EXTENSIONS: tuple[str, ...] = ("*.md",)

# ---------------------------------------------------------------------------
# Repository-root documents (BLOCKER, second review)
# ---------------------------------------------------------------------------
# Up to validator 3.0.0 discovery walked research/ and docs/ only.  plan.md,
# AGENTS.md, README.md and NOTICE.md were therefore never opened in a default
# run - and plan.md holds the densest concentration of graded facts in the
# project: Appendix A is a table of pre-flight observations with Level and
# Conf. columns, and section 10 defines the very rules this file enforces.
# All four violations the first review found by hand were in plan.md.  A
# validator that prints OK while never reading the document carrying the
# plan's own evidence table gives false assurance, which is worse than no
# validator at all.
#
# The root is scanned NON-recursively and by extension, not by an allow-list of
# four names: a new root-level document must be covered the day it is added,
# not the day somebody remembers to edit this tuple.  Directories that are not
# ours (.git, workspace caches, third-party trees) are never entered, because
# rglob is not used here at all.
#
# ROOT_DOCUMENTS_EXPECTED is the coverage assertion, not the scan list: these
# four files exist today, the report states whether each was actually scanned,
# and a test asserts they are in the scanned set.
ROOT_DOCUMENTS_EXPECTED: tuple[str, ...] = (
    "plan.md",
    "AGENTS.md",
    "README.md",
    "NOTICE.md",
)


def discover_root_documents(repo_root: Path) -> list[Path]:
    """Markdown documents sitting directly in the repository root."""
    if not repo_root.is_dir():
        return []
    return sorted(p for p in repo_root.glob("*.md") if p.is_file())


def discover_files(research_dir: Path, docs_dir: Path | None = None,
                   markdown: bool = True, repo_root: Path | None = None) -> list[Path]:
    """Every artifact the validator is responsible for.

    research/ contributes JSON, JSONL and markdown; docs/ and the repository
    root contribute markdown only (neither holds machine-readable artifacts).
    Markdown is in scope because that is where the M0 facts actually are - see
    section 6b - and the repository root is in scope because plan.md is where
    the densest graded facts are.
    """
    found: list[Path] = []
    extensions = JSON_EXTENSIONS + (MARKDOWN_EXTENSIONS if markdown else ())
    for ext in extensions:
        found.extend(research_dir.rglob(ext))
    if markdown and docs_dir is not None and docs_dir.is_dir():
        for ext in MARKDOWN_EXTENSIONS:
            found.extend(docs_dir.rglob(ext))
    if markdown and repo_root is not None:
        found.extend(discover_root_documents(repo_root))
    unique: dict[str, Path] = {}
    for path in found:
        if path.is_file():
            unique.setdefault(path.resolve().as_posix(), path)
    return sorted(unique.values())


def expand_targets(targets: Sequence[str], repo_root: Path, research_dir: Path,
                   docs_dir: Path | None = None, markdown: bool = True) -> list[Path]:
    if not targets:
        return discover_files(research_dir, docs_dir, markdown=markdown,
                              repo_root=repo_root)
    extensions = JSON_EXTENSIONS + (MARKDOWN_EXTENSIONS if markdown else ())
    files: list[Path] = []
    for raw in targets:
        path = Path(raw)
        if not path.is_absolute():
            path = (repo_root / raw).resolve()
        if path.is_dir():
            for ext in extensions:
                files.extend(sorted(p for p in path.rglob(ext) if p.is_file()))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(raw)
    return files


def relative_to(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def run(
    repo_root: Path,
    research_dir: Path,
    schema_dir: Path,
    targets: Sequence[str] = (),
    allow_untyped_claims: bool = False,
    docs_dir: Path | None = None,
    markdown: bool = True,
    check_commits: bool = True,
) -> tuple[list[FileReport], set[str]]:
    """Validate every requested artifact.

    Two paths are tracked per file: the *display* path (relative to the repo
    root when possible) and the *mapping* path (relative to research/, which
    is what ARTIFACT_SCHEMA_MAP patterns are written against).
    """
    ignored_keywords: set[str] = set()
    if docs_dir is None:
        candidate = repo_root / "docs"
        docs_dir = candidate if candidate.is_dir() else None
    reachability = CommitReachability(repo_root, enabled=check_commits)
    files = expand_targets(targets, repo_root, research_dir, docs_dir, markdown=markdown)
    reports: list[FileReport] = []
    if not targets:
        for report in check_schema_dir(schema_dir):
            report.path = relative_to(Path(report.path), repo_root) or report.path
            reports.append(report)
    for path in files:
        mapping_path = relative_to(path, research_dir)
        if mapping_path is None:
            # target outside research/: map by basename only, so a file passed
            # explicitly (e.g. in a test fixture) still hits the table
            mapping_path = path.name
        display_path = relative_to(path, repo_root) or path.resolve().as_posix()
        if is_ignored(mapping_path):
            continue
        if path.suffix.lower() == MARKDOWN_SUFFIX:
            if not markdown:
                continue
            report = validate_markdown_file(path, display_path,
                                            reachability=reachability)
        else:
            report = validate_file(path, mapping_path, schema_dir, ignored_keywords,
                                   allow_untyped_claims=allow_untyped_claims,
                                   reachability=reachability)
            report.path = display_path
        reports.append(report)
    return reports, ignored_keywords


# ---------------------------------------------------------------------------
# 9. Reporting
# ---------------------------------------------------------------------------

DEGRADED_BACKEND_BANNER = (
    "schema backend: BUILT-IN MINIMAL VALIDATOR - the 'jsonschema' package is "
    "not importable in this interpreter. Enforced: required, type, enum, const, "
    "bounds, pattern, items, contains, uniqueItems, allOf/anyOf/oneOf/not, "
    "if-then-else, and $ref (local or sibling file). Install jsonschema for "
    "full coverage.")


def backend_note(ignored_keywords: set[str]) -> str:
    if HAVE_JSONSCHEMA:
        return "schema backend: jsonschema (full JSON Schema validation)"
    note = DEGRADED_BACKEND_BANNER
    if ignored_keywords:
        note += f"\n  ignored schema keywords: {', '.join(sorted(ignored_keywords))}"
    return note


def degraded_backend_report(ignored_keywords: set[str], as_error: bool) -> FileReport:
    """A first-class finding for "the validator itself is running degraded".

    A degraded validator that prints "0 violations" is worse than one that
    fails, because the zero is then read as evidence.  So the fallback backend
    is not only announced in the banner: it becomes a counted finding that
    --strict (or --require-jsonschema) turns into a non-zero exit.
    """
    report = FileReport(path="(validator self-check)", kind="validator",
                        schema_status="self-check")
    severity = SEVERITY_ERROR if as_error else SEVERITY_WARN
    report.findings.append(Finding(
        severity, "BACKEND", "$",
        "the JSON Schema layer ran on the built-in minimal fallback, NOT on the "
        "'jsonschema' package. Keywords it cannot enforce are listed as ignored "
        "above; anything in that list was not checked at all. Do not read this "
        "run's result as full schema coverage - install the dependency from "
        "requirements.txt and re-run"
        + (f". Ignored keywords: {', '.join(sorted(ignored_keywords))}"
           if ignored_keywords else "")))
    return report


def scan_coverage(reports: list[FileReport]) -> dict[str, Any]:
    """What was actually opened, grouped by area, plus the root-document check.

    Printed at the top of every report.  A reader must be able to see at a
    glance whether plan.md was in the run: for most of this validator's life it
    was not, and the report said nothing about that.
    """
    areas: dict[str, list[str]] = {}
    scanned: set[str] = set()
    for report in reports:
        path = report.path
        if report.kind in ("validator",) or path.startswith("("):
            continue
        scanned.add(path)
        area = path.split("/")[0] + "/" if "/" in path else "(repository root)"
        areas.setdefault(area, []).append(path)
    missing = [name for name in ROOT_DOCUMENTS_EXPECTED if name not in scanned]
    return {
        "areas": {area: sorted(paths) for area, paths in sorted(areas.items())},
        "root_documents_expected": list(ROOT_DOCUMENTS_EXPECTED),
        "root_documents_scanned": sorted(
            name for name in ROOT_DOCUMENTS_EXPECTED if name in scanned),
        "root_documents_missing": missing,
    }


# What this validator does and does not check mechanically.  Printed on every
# run: a limit that lives only in a docstring is a limit nobody reads, and a
# reader who believes a clean run means "all rules enforced" is worse off than
# one who knows where the holes are.
DISCLOSURES: tuple[str, ...] = (
    "the plan.md 10.5 claim-type -> oracle matrix runs on any record that "
    "carries a claim_type, in JSON and in markdown alike: a markdown table may "
    "have a `Claim type` column and a RESEARCH_LOG entry a `Claim type` field. "
    "Where a markdown record has none, the matrix cannot be applied to it - and "
    "such records at confidence >= 0.95 are listed one by one in the CLAIM_TYPE "
    "GAP block rather than disclosed as a number. Two matrix consequences are "
    "additionally derived without a claim_type: naming filesystem AND "
    "steam-metadata together is the 10.5 cross-check row and yields class I, and "
    "an INFERRED/HYPOTHESIS record is class I by 10.3 v2.3 regardless",
    "a REDUCED evidence annotation (kb-record.schema.json#/$defs/annotation - "
    "the shape a fingerprint.json attaches to one container, one anomaly, one "
    "sub-object) is NOT checked against the plan.md 10.5 claim_type matrix and "
    "not asked for a build_key. That schema defines neither property and, being "
    "additionalProperties false, forbids both, so demanding them was a deadlock "
    "no document could clear - it is the defect validator 3.4.0 fixes. The "
    "annotation inherits its matrix row and its build identity from the "
    "enclosing document, which states them once. Everything else - the level, "
    "the confidence ceiling, sources[], the oracle vocabulary, EV-05, "
    "MIX-SPLIT, the class P and class I criteria, C-11, C-12 - is applied to an "
    "annotation at full strength, and the number of annotations linted this way "
    "is printed in the summary",
    "claim_class is DERIVED, and from evidence_level FIRST (plan.md 10.3 v2.3: "
    "class P only at OBSERVED; INFERRED and HYPOTHESIS are always class I), then "
    "from claim_type and oracle, then supplemented by the wording of the claim "
    "for criterion 3. An explicit value that contradicts the derivation is "
    "reported as EV-05; the derivation, not the label, governs which criteria "
    "are applied",
    "plan.md 10.3 class P criterion 2 (method re-run and reproduced) and class I "
    "criteria 3, 4, 5 and 6 are attestations about process. This file can only "
    "check whether the document SAYS so, so they are reported as WARN, not "
    "ERROR; --strict turns them into violations",
    "an artifact path in an Evidence field/column is never counted as a source, "
    "and neither is an additional oracle. plan.md 10.4/EV-03 counts acts of "
    "measurement: an Evidence path records where the result was written, and an "
    "oracle names the KIND of source consulted - research/RESEARCH_LOG.md "
    "LOG-0001i is the record that says this about itself",
    "the inline annotation notation has no field for sources[], so EV-03 cannot "
    "be checked there at all; the count of unchecked inline records is printed "
    "per file",
    "fenced code blocks are not scanned - they hold templates and examples "
    "(plan.md Appendix B is a fenced seed listing, so it contributes no records)",
    "a grade quoted as a teaching example, or disclosed as a past defect, is "
    "exempt ONLY when the author marks it `<!-- kb-validate: quoted-example -->`. "
    "The parser never infers that a grade is a quotation; every marked line is "
    "listed by file and line in the EXEMPTIONS block",
    "confidence bounds ('<= 0.4') are read as the stated value; a bound is not "
    "the same claim as an exact grade, and this validator does not distinguish "
    "them beyond recording the flag",
    "a span that enumerates the permitted evidence levels as part of a stated "
    "REQUIREMENT (an exit criterion, a rule) is not read as a record. Unlike "
    "quoted-example this is inferred from the shape and needs no marker, so the "
    "three conditions are narrow and are printed with every use in the NORM-ENUM "
    "block: a contiguous list of levels, every confidence given as a threshold "
    "rather than a value, and requirement vocabulary on the line. A grade stated "
    "as a value is never exempt here",
    "class P for the binary-analysis and container-metadata oracles is admitted "
    "only when the claim states a determinate address AND a length, and does not "
    "name what the bytes are (plan.md 10.3 v2.4). The detection is deliberately "
    "strict: a claim that states an offset without an extent, or names a field, a "
    "layout, a type or a signature, derives class I. A false negative costs the "
    "author one clause; a false positive would admit an interpretation as a "
    "measurement, which is the defect v2.4 exists to prevent",
)


def rule_histogram(reports: list[FileReport]) -> dict[str, dict[str, int]]:
    """Violations and warnings per rule id, for the summary."""
    table: dict[str, dict[str, int]] = {}
    for report in reports:
        for finding in report.findings:
            row = table.setdefault(finding.rule, {"errors": 0, "warnings": 0})
            if finding.severity == SEVERITY_ERROR:
                row["errors"] += 1
            else:
                row["warnings"] += 1
    return dict(sorted(table.items(),
                       key=lambda item: (-item[1]["errors"], -item[1]["warnings"],
                                         item[0])))


def print_report(reports: list[FileReport], ignored_keywords: set[str], strict: bool) -> None:
    print(f"MISERY knowledge-base validator {VALIDATOR_VERSION}")
    print(f"  rules from: {PLAN_REFERENCE}")
    print(f"  {backend_note(ignored_keywords)}")
    print()

    coverage = scan_coverage(reports)
    print("scanned set (coverage at a glance):")
    for area, paths in coverage["areas"].items():
        head = f"  {area:<22} {len(paths)} file(s): "
        body = textwrap.fill(", ".join(paths), width=100,
                             initial_indent="", subsequent_indent=" " * len(head))
        print(head + body)
    if coverage["root_documents_missing"]:
        print(f"  !! repository-root documents NOT scanned: "
              f"{', '.join(coverage['root_documents_missing'])} - discovery is "
              "incomplete, and a fact in an unscanned document is an unchecked fact")
    else:
        print(f"  repository-root documents scanned: "
              f"{', '.join(coverage['root_documents_scanned'])}")
    print()

    if not reports:
        print("no artifacts found under research/, docs/ or the repository root "
              "- nothing to validate")
        print()

    total_errors = total_warnings = total_records = total_annotations = 0
    total_unparseable = total_suppressed = total_non_fact = 0
    notation_totals: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for report in reports:
        total_errors += report.errors
        total_warnings += report.warnings
        total_records += report.record_count
        total_annotations += report.annotation_count
        total_unparseable += report.unparseable_count
        total_suppressed += report.suppressed_count
        total_non_fact += report.non_fact_tables
        kind_counts[report.kind or "?"] = kind_counts.get(report.kind or "?", 0) + 1
        for notation, count in report.notation_counts.items():
            notation_totals[notation] = notation_totals.get(notation, 0) + count
        annotation_bit = (f", {report.annotation_count} annotation(s)"
                          if report.annotation_count else "")
        if not report.findings:
            suffix = " EXEMPT (kb-validate: ignore-file)" if report.exempt else ""
            print(f"OK   {report.path}  ({report.record_count} record(s)"
                  f"{annotation_bit}){suffix}")
            continue
        print(f"---- {report.path}")
        schema_bit = report.schema or "-"
        print(f"     kind={report.kind} schema={schema_bit} [{report.schema_status}] "
              f"records={report.record_count} annotations={report.annotation_count} "
              f"unparseable={report.unparseable_count}")
        for finding in report.findings:
            print(f"     {finding.severity:<5} [{finding.rule}] {finding.pointer}: "
                  f"{finding.message}")
        print()

    print("summary:")
    print(f"  files:      {len(reports)}"
          f"  ({', '.join(f'{k}={v}' for k, v in sorted(kind_counts.items()))})")
    print(f"  records:    {total_records}"
          + (f"  ({', '.join(f'{k}={v}' for k, v in sorted(notation_totals.items()))}"
             f", json={total_records - sum(notation_totals.values())})"
             if notation_totals else ""))
    if total_annotations:
        print(f"  of which reduced evidence annotations: {total_annotations}"
              "   <- kb-record.schema.json#/$defs/annotation; linted by "
              "lint_annotation(), which drops the plan.md 10.5 claim_type matrix "
              "and EV-BUILD because that schema forbids both properties")
    print(f"  unparseable candidate records: {total_unparseable}"
          "   <- counted as violations: a fact the validator cannot read is a "
          "problem, not an absence")
    if total_suppressed:
        print(f"  suppressed by kb-validate directives: {total_suppressed}")
    if total_non_fact:
        print(f"  markdown tables with an oracle column but no level/confidence "
              f"column (registers of questions/resources, not facts): {total_non_fact}")
    definition_tables = [entry for report in reports for entry in report.definition_tables]
    quoted_examples = [entry for report in reports for entry in report.quoted_examples]
    normative_enums = [entry for report in reports
                       for entry in report.normative_enumerations]
    mix_scope = [entry for report in reports for entry in report.mix_scope_spans]
    if definition_tables or quoted_examples or normative_enums or mix_scope:
        print()
        print("  EXEMPTIONS (named, counted, not silent):")
    if mix_scope:
        print(f"    MIX-SCOPE x{len(mix_scope)}: a conclusion MARKER that this record "
              "mentions without grading a conclusion, so it does not count towards "
              "MIX-SPLIT (plan.md 10.3 \"Смешанные утверждения обязаны разделяться\" is "
              "a rule about what a record GRADES, not about which words appear in it). "
              "Two shapes are recognised, per CLAUSE and never per record, and both are "
              "refused for any clause that states a level or a confidence of its own. "
              "\"quoted-rule\": a prohibition or requirement is opened BEFORE the marker "
              "in the same clause AND the clause anchors it to a norm - a C-/D- id, "
              "NOTICE.md, or the words for a constraint/rule/decision; the record states "
              "that the rule exists, it does not conclude that something was decrypted. "
              "\"delegated:<id>\": the clause says the conclusion is graded ELSEWHERE and "
              "names a counterpart record that EXISTS in this document, which is exactly "
              "what an author who performs the split has to write. A bare cross-reference "
              "does not qualify (plan.md 10.1: restating never promotes), and a named id "
              "that is not a real record here does not either - the exemption cannot be "
              "claimed without having performed the split. This is a recognised SHAPE and "
              "not a marker, for the same reason NORM-ENUM is: `quoted-example` would "
              "remove these LIVE records from the linted set, and a correct record must "
              "not be reworded to satisfy the parser that reads it.")
        for entry in mix_scope:
            print(f"      - {entry}")
    if normative_enums:
        print(f"    NORM-ENUM x{len(normative_enums)}: a span that ENUMERATES the "
              "permitted evidence levels as part of a REQUIREMENT - \"Exit criteria: "
              "... подтверждённая запись (OBSERVED/INFERRED с confidence >= 0.7 и "
              "сигнатурой)\" - states the rule records must satisfy, and is not itself "
              "a record. It is read as such only when all three conditions hold: the "
              "levels are a contiguous list separated by nothing but \"/\", a comma or "
              "\"или\"; EVERY confidence in the span is introduced by a comparison or a "
              "bound word (\">= 0.7\", \"не ниже 0.8\", \"до 0.99\") rather than stated "
              "as a value; and the line carries requirement vocabulary from a closed "
              "list (exit criteria, критерий, требуется, обязан, допустим, must, ...). "
              "A grade stated as a value never qualifies, so no record escapes here. "
              "This is a recognised SHAPE and not a marker: the plan states the rules, "
              "and a normative sentence must not have to be reworded to satisfy the "
              "parser that reads records.")
        for entry in normative_enums:
            print(f"      - {entry}")
    if quoted_examples:
        print(f"    QUOTED-EXAMPLE x{len(quoted_examples)}: a record marked "
              "`<!-- kb-validate: quoted-example -->` is a grade QUOTED from "
              "somewhere else - a bad record shown as a teaching example, or a defect "
              "disclosed after it was fixed. It is still parsed and it is listed here by "
              "file and line; it is not linted, because the rules apply to the record it "
              "quotes and not to the sentence quoting it. The marker is explicit on "
              "purpose: the parser never infers that a grade is a quotation, so no live "
              "record can escape by being phrased as prose. Put the comment at the end "
              "of the line, or alone on the line before it.")
        for entry in quoted_examples:
            print(f"      - {entry}")
    if definition_tables:
        print(f"    DEF-TABLE x{len(definition_tables)}: a table whose level column "
              "enumerates the level VOCABULARY (plan.md 10.1 `Уровень | Определение | "
              "Примеры`) defines the levels instead of grading claims, so its rows are "
              "not records. The test is narrow: a level column, no confidence, no "
              "oracle, no method column, and each level named exactly once. Any table "
              "naming a method or an oracle is linted.")
        for entry in definition_tables:
            print(f"      - {entry}")
        print("    plan.md 10.2 states that the 1.00 ban applies to the tables inside "
              "plan.md itself, including Appendix A, so NOTHING in plan.md is exempt "
              "as a graded fact. The 10.2 scale table, where the literal 1.00 is the "
              "DEFINITION of the forbidden value, carries no level/confidence/oracle "
              "column and therefore yields no record - it needs no exemption.")
    gap_total = sum(len(report.claim_type_gaps) for report in reports)
    if gap_total:
        print()
        print(f"  CLAIM_TYPE GAP - {gap_total} markdown record(s) at confidence >= "
              f"{CRITERIA_STRICT_THRESHOLD} that derive class P (or no class) and carry "
              "no claim_type, so the plan.md 10.5 matrix could not be applied to them "
              "individually. A markdown table CAN carry a `Claim type` column and a log "
              "entry a `Claim type` field; these records do not, and a claim_type outside "
              "the primitive-measurement rows would have moved them into class I with its "
              "six mandatory criteria. Records that already derive class I are not listed: "
              "they are held to those criteria either way. Named record by record on "
              "purpose - an aggregate sentence lets the gap grow without anyone noticing "
              "which claims are in it.")
        for report in reports:
            if not report.claim_type_gaps:
                continue
            print(f"      - {report.path} ({len(report.claim_type_gaps)} record(s)):")
            print(textwrap.fill(", ".join(report.claim_type_gaps), width=100,
                                initial_indent=" " * 10, subsequent_indent=" " * 10))
        # WHAT WOULD CLOSE EACH.  The gap cannot be closed from inside this file:
        # a claim_type decides the class, so inferring one from the oracle set
        # would be deriving a class from missing data - the move plan.md forbids
        # everywhere else, and the move that produced the RA-38/RA-39/RA-40 hole.
        # What CAN be done mechanically is name the remedy per record: which
        # field the notation has for it, and which matrix rows are admissible on
        # the oracle set the record already states.  Grouped, because one remedy
        # normally covers a whole table and 126 identical sentences would hide
        # the three that differ.
        remedies: dict[str, list[str]] = {}
        for report in reports:
            for remedy, where in report.claim_type_gap_remedies:
                remedies.setdefault(remedy, []).append(where)
        if remedies:
            print("    WHAT WOULD CLOSE EACH - the records above, grouped by the remedy "
                  "that applies to them. The validator does NOT infer a claim_type: the "
                  "value decides the class, so guessing it would derive a class from "
                  "missing data. It names the field the notation has for it and the "
                  "plan.md 10.5 rows that are admissible on the oracle set the record "
                  "already states, with the class each row implies in brackets.")
            for remedy, places in sorted(remedies.items(),
                                         key=lambda item: (-len(item[1]), item[0])):
                print(textwrap.fill(f"* {remedy}", width=100,
                                    initial_indent=" " * 6,
                                    subsequent_indent=" " * 8))
                print(textwrap.fill(f"{len(places)} record(s): "
                                    + ", ".join(places), width=100,
                                    initial_indent=" " * 8,
                                    subsequent_indent=" " * 10))
    print(f"  violations: {total_errors}")
    print(f"  warnings:   {total_warnings}"
          f"{' (strict mode: counted as violations)' if strict else ''}")

    histogram = rule_histogram(reports)
    if histogram:
        print()
        print("  by rule:")
        for rule, counts in histogram.items():
            print(f"    {rule:<12} violations={counts['errors']:<4} "
                  f"warnings={counts['warnings']}")

    print()
    print("  DISCLOSURES - what this run did NOT check:")
    for item in DISCLOSURES:
        print(f"    * {item}")

    if not HAVE_JSONSCHEMA:
        print()
        print("=" * 78)
        print("!! DEGRADED RUN - THE JSON SCHEMA LAYER USED THE BUILT-IN FALLBACK !!")
        print("=" * 78)
        print(DEGRADED_BACKEND_BANNER)
        if ignored_keywords:
            print(f"  not enforced at all: {', '.join(sorted(ignored_keywords))}")
        print("A clean result from this run is NOT evidence of schema conformance.")
        print("Install the pinned dependency (requirements.txt) and run again.")
        print("=" * 78)


def exit_code(reports: list[FileReport], strict: bool) -> int:
    errors = sum(r.errors for r in reports)
    warnings = sum(r.warnings for r in reports)
    if errors or (strict and warnings):
        return 1
    return 0


def build_json_output(
    reports: list[FileReport], ignored_keywords: set[str], strict: bool
) -> dict[str, Any]:
    notation_totals: dict[str, int] = {}
    for report in reports:
        for notation, count in report.notation_counts.items():
            notation_totals[notation] = notation_totals.get(notation, 0) + count
    return {
        "validator": "tools/kb/validate.py",
        "validator_version": VALIDATOR_VERSION,
        "plan_reference": PLAN_REFERENCE,
        "schema_backend": SCHEMA_BACKEND,
        "jsonschema_available": HAVE_JSONSCHEMA,
        "schema_backend_degraded": not HAVE_JSONSCHEMA,
        "ignored_schema_keywords": sorted(ignored_keywords),
        "strict": strict,
        "coverage": scan_coverage(reports),
        "disclosures": list(DISCLOSURES),
        "summary": {
            "files": len(reports),
            "records": sum(r.record_count for r in reports),
            "annotations": sum(r.annotation_count for r in reports),
            "records_by_notation": notation_totals,
            "unparseable_records": sum(r.unparseable_count for r in reports),
            "suppressed_records": sum(r.suppressed_count for r in reports),
            "non_fact_tables": sum(r.non_fact_tables for r in reports),
            "definition_tables_exempt": [entry for r in reports
                                         for entry in r.definition_tables],
            "quoted_examples_exempt": [entry for r in reports
                                       for entry in r.quoted_examples],
            "normative_enumerations_exempt": [entry for r in reports
                                              for entry in r.normative_enumerations],
            "mix_scope_spans": [entry for r in reports for entry in r.mix_scope_spans],
            "claim_type_gaps": [f"{r.path}:{entry}" for r in reports
                                for entry in r.claim_type_gaps],
            "violations": sum(r.errors for r in reports),
            "warnings": sum(r.warnings for r in reports),
            "by_rule": rule_histogram(reports),
            "exit_code": exit_code(reports, strict),
        },
        "files": [r.to_dict() for r in reports],
    }


MARKUP_CONVENTIONS = """\
markdown conventions this validator reads (see also the DISCLOSURES block of
every report):

  <!-- kb-validate: quoted-example -->
      Marks a grade that is QUOTED, not claimed: a bad record shown as a
      teaching example, or a defect disclosed after it was fixed.  A document
      that teaches the rules has to be able to quote a record that breaks them,
      and the alternative - deleting the sentence so the tool goes quiet - would
      destroy an honest disclosure to buy a clean run.
      Place it at the END of the line that carries the grade, or ALONE on the
      line immediately before it.  On a table header it covers the whole table.
      The record is still parsed and still shown: every marked line is printed
      by file and line in the report's EXEMPTIONS block, so using the marker is
      a visible, auditable act.  It is never inferred - the parser will not
      decide on its own that a grade "looks like a quotation".
      Example:
          В decisions.md A-07 был пересказан как OBSERVED 1.00. <!-- kb-validate: quoted-example -->

  <!-- kb-validate: ignore-next -->
      Suppresses the next line (or, on a table header, the whole table)
      entirely.  Blunter than quoted-example and counted separately as
      "suppressed by kb-validate directives".

  <!-- kb-validate: ignore-file -->
      Exempts the whole file.  Reported as EXEMPT next to the file name.

  a `Claim type` table column, or a `- **Claim type:** ...` log-entry field
      Carries the plan.md 10.5 claim_type in markdown.  With it, the full
      claim-type -> oracle matrix applies to a prose record exactly as it does
      to a JSON one; without it, that matrix cannot be applied to the record,
      and records at confidence >= 0.95 with no claim_type are listed one by one
      in the CLAIM_TYPE GAP block.

  claim_type='other'
      The catch-all row.  It requires a written justification: one of the JSON
      fields claim_type_note / claim_type_justification / matrix_gap /
      justification, or - in markdown - a sentence naming the 10.5 row that is
      missing ("нет строки в матрице", "matrix_gap", "no matrix row").
"""


def default_repo_root() -> Path:
    # tools/kb/validate.py -> repo root is two levels up
    return Path(__file__).resolve().parents[2]


def _force_utf8_stdout() -> None:
    """Findings quote Russian document text; a cp1251 console must not crash.

    Without this, print() raises UnicodeEncodeError on the first quoted "→" and
    the whole report is lost - a validator that dies while reporting is as
    useless as one that reports nothing.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (OSError, ValueError):  # pragma: no cover - exotic streams
            pass


def main(argv: Sequence[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = argparse.ArgumentParser(
        description="Validate the MISERY research knowledge base "
                    "(plan.md K-03, EV-03, EV-04, C-11).",
        epilog=MARKUP_CONVENTIONS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*",
                        help="specific files or directories to validate "
                             "(default: everything under research/)")
    parser.add_argument("--repo-root", default=None,
                        help="repository root (default: two levels above this script)")
    parser.add_argument("--research-dir", default=None,
                        help="research directory (default: <repo-root>/research)")
    parser.add_argument("--schema-dir", default=None,
                        help="JSON Schema directory (default: <research-dir>/schema)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="machine-readable output on stdout")
    parser.add_argument("--strict", action="store_true",
                        help="treat warnings as violations")
    parser.add_argument("--allow-untyped-claims", action="store_true",
                        help="downgrade a missing claim_type from a violation to a "
                             "warning (kb-record.schema.json declares the field "
                             "optional; without it the 10.5 matrix cannot be checked)")
    parser.add_argument("--docs-dir", default=None,
                        help="documentation directory scanned for markdown facts "
                             "(default: <repo-root>/docs)")
    parser.add_argument("--no-markdown", action="store_true",
                        help="skip the markdown fact layer (section 6b). Diagnostic "
                             "only: with it, 100%% of the M0 facts go unchecked")
    parser.add_argument("--no-commit-check", action="store_true",
                        help="skip the vcs-history reachability check (needs git)")
    parser.add_argument("--require-jsonschema", action="store_true",
                        help="fail if the JSON Schema layer had to fall back to the "
                             "built-in minimal validator")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve() if args.repo_root else default_repo_root()
    research_dir = (Path(args.research_dir).resolve() if args.research_dir
                    else repo_root / "research")
    schema_dir = (Path(args.schema_dir).resolve() if args.schema_dir
                  else research_dir / "schema")
    docs_dir = Path(args.docs_dir).resolve() if args.docs_dir else None

    try:
        reports, ignored = run(repo_root, research_dir, schema_dir, args.targets,
                               allow_untyped_claims=args.allow_untyped_claims,
                               docs_dir=docs_dir,
                               markdown=not args.no_markdown,
                               check_commits=not args.no_commit_check)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2

    if not HAVE_JSONSCHEMA:
        reports.append(degraded_backend_report(ignored, as_error=args.require_jsonschema))

    if args.as_json:
        print(json.dumps(build_json_output(reports, ignored, args.strict),
                         indent=2, ensure_ascii=False))
    else:
        print_report(reports, ignored, args.strict)

    return exit_code(reports, args.strict)


if __name__ == "__main__":
    sys.exit(main())
