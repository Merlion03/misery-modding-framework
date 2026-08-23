#!/usr/bin/env python3
"""Cost measurement for a headless Ghidra project (plan.md task T-05, method S-02).

The question this tool exists to answer
---------------------------------------
plan.md row T-05 and RISK-13 ask a single, narrow, empirical question: what does
a Ghidra project for ``MISERY-Win64-Shipping.exe`` (134 658 048 bytes) actually
cost in wall-clock time and in bytes on disk? M2s exit criterion 3 is that this
is *measured*, and every later decision about how much Ghidra work the project
can afford rests on the numbers this tool produces. Nobody knows them yet, and
the risk register says the plausible answers span "a few minutes and a few
hundred megabytes" to "many hours and many gigabytes on a disk that has already
been full once".

So this is a measurement harness, not an analysis project. It answers *how
expensive*, and deliberately answers nothing about what is inside the binary.

What it is a wrapper around, and what it must never become
---------------------------------------------------------
It drives ``support\\analyzeHeadless.bat`` as a subprocess and times it. It does
not reimplement import, disassembly, or analysis, and it must not grow into
something that does: the number being measured is the cost of *Ghidra's* work,
and a reimplementation would measure the cost of ours. The only Ghidra-side
logic that belongs to this tool is ``ghidra_scripts/SetAnalyzerSet.java``, whose
whole job is to edit the analyzer enablement flags before analysis starts,
because analyzeHeadless has no command-line flag for a partial analyzer set.

That one script is Java rather than Python, which is the exception plan.md 7.2
allows ("Java-скрипты остаются резервным вариантом, если какой-то API окажется
недоступен через мост jpype") and the reason is mechanical rather than a
preference: a ``-preScript`` runs *inside* the analyzeHeadless JVM, before
analysis, and ``analyzeHeadless.bat`` does not configure the PyGhidra
interpreter bridge -- ``pyghidraRun`` is the launcher that does. Ghidra compiles
the .java script itself at run time (the compiled bundle lands in the redirected
settings directory, which is one more thing that would otherwise have gone to
C:). Every S-03..S-10 script that runs against a *finished* project stays Python
through PyGhidra as the plan says; this one cannot, because it has to be in the
room before analysis starts.

Why a curve and not a number
----------------------------
"How long does Ghidra take" has no single answer; it has a cost per unit of work
enabled. The tool therefore runs named *stages*, each an independent project so
that the numbers are comparable rather than cumulative:

``import-only``
    ``-noanalysis``. Measures load, language selection, PE parsing and the
    database write, with the analyzers off. This is the floor: no configuration
    of Ghidra can cost less than this and still have the image in a project.

``minimal-analysis``
    A deliberately small analyzer set (:data:`MINIMAL_ANALYZERS`), applied by
    the pre-script. Measures the cheap end of useful: functions, strings,
    references, RTTI -- the things M2s tasks S-03..S-10 actually consume --
    without the decompiler-driven analyzers that dominate the default set.

``default-analysis``
    Ghidra's default analyzer set, unchanged. Measures what an unthinking
    ``-import`` costs. Run only if ``minimal-analysis`` makes it look
    affordable; that judgement is the caller's, which is why stages are
    selected explicitly rather than always all three.

Each stage is also run against a small control target (a DLL from the same
installation) so that the 134 MB numbers have something to scale from. Two
points on a size axis do not give a law, but they do distinguish "cost grows
roughly with file size" from "cost explodes", and that distinction is what
RISK-13 needs.

A timeout is a result, not a failure
------------------------------------
A stage that does not finish is still evidence, and the honest record of it is
"exceeded N seconds, aborted", not a hung terminal and no report. Two
independent limits are therefore imposed, and they do different jobs:

* ``-analysisTimeoutPerFile`` -- Ghidra's own soft limit. Analysis stops, the
  analyzers that finished keep their results, and the program is *saved*. The
  project is therefore still there to be measured, and the stage yields both a
  time bound and a real size. This is the preferred limit and the reason the
  soft budget is set below the hard one.
* a hard subprocess timeout -- ours, a backstop for the case where the process
  hangs somewhere the soft limit does not cover (import, save, script
  compilation). On expiry the process *tree* is killed, because killing
  ``analyzeHeadless.bat`` alone leaves the JVM running and holding the project
  lock.

Both outcomes are recorded in the report as an ``outcome`` string. Nothing about
a timeout is treated as an error exit of this tool: the run produced a bound,
and a bound is a measurement.

Containment: C: has 6.3 GiB free and must not be filled
-------------------------------------------------------
Ghidra scatters large, long-lived state outside its project directory, and every
default location for it is on the system drive: ``%APPDATA%\\ghidra`` for
settings, exports caches and compiled scripts, ``%LOCALAPPDATA%\\ghidra`` for
the packed-database cache, and ``%TEMP%`` for the decompiler's and the JVM's
scratch files. On this machine that is a disk with 6.3 GiB free, and RISK-13
exists because it has been full before.

All four are redirected onto D: by JVM system properties, passed through the
``GHIDRA_HEADLESS_JAVA_OPTIONS`` environment variable that ``analyzeHeadless.bat``
appends to its VM argument list. That variable lands in ``VMARGS_FROM_CALLER``,
which ``launch.bat`` places *last* on the java command line, so these values win
over the same properties in ``support\\launch.properties``:

    -Dapplication.settingsdir=...   settings, symbol exports, compiled scripts
    -Dapplication.cachedir=...      packed-db-cache
    -Dapplication.tempdir=...       Ghidra's own scratch area
    -Djava.io.tmpdir=...            everything else, including the decompiler

The redirection is not asserted, it is *checked*: free space on both volumes is
sampled about once a second for the whole of every stage, and the report records
free space before, the minimum seen during, and after, per volume. If C: dropped
materially, the report says so with numbers instead of a claim that it did not.

The one thing this cannot redirect is the file ``LaunchSupport`` writes to record
which JDK was chosen: ``launch.bat`` invokes it without our VM arguments, so it
uses the default settings directory. That file is a few hundred bytes and its
path is reported rather than glossed over.

JDK 21 only
-----------
Ghidra 12.1.3 crashes on JDK 25 inside Apache Felix before any user logic runs
(plan.md 17.1a, assumption A-15), and a Java 8 JRE is first on this machine's
PATH. The JDK is therefore pinned explicitly rather than inherited: ``JAVA_HOME``
is set and the pinned ``bin`` directory is prepended to ``PATH`` for the child
process, so the bootstrap ``java.exe`` that ``launch.bat`` uses to run
``LaunchSupport`` is the pinned one too. Before any stage runs, ``java -version``
is executed on the pinned JDK and the major version is parsed; a major version
other than :data:`REQUIRED_JDK_MAJOR` aborts the run instead of producing
numbers that measure a crash.

The copy is mandatory (plan.md 1.5 layer 2, decision D-01)
----------------------------------------------------------
Ghidra opens the file it imports read-write. Pointing it at the installation is
therefore forbidden outright, not merely discouraged, and this tool enforces it
in both directions:

* the *import* path is checked against the same protected roots
  ``pathguard`` uses for output paths (:func:`check_import_path`) -- an import
  path inside any known or structurally detected installation is refused before
  anything is opened;
* the copy is verified by sha256 against a caller-supplied expected digest
  before it is imported, so "we analysed a copy of the build we think we
  analysed" is a checked statement rather than an assumption.

Output paths -- the report, the raw logs, the redacted logs, the project root --
all go through ``pathguard.check_output_path`` (layer 1, D-01).

C-13: the raw log cannot be committed
-------------------------------------
``analyzeHeadless`` prints literal user-profile paths, the account name on every
file it creates, and a verbatim dump of the machine PATH. The repository is
public, so the artifact that lands under ``research/evidence/`` is the redacted
form. The redaction rules already exist, once, in
``research/evidence/T-02/redact-log.py``, and they are *imported from there by
path* rather than copied: a second copy of a privacy filter drifts from the
first, and the first is the one T-02's documented reproduction procedure uses.
The import is by file path because that file's name contains a hyphen and cannot
be imported as a module name; see :func:`load_redactor`. If the redactor cannot
be loaded, no log is written into the repository at all -- the guard fails
closed. (That the redactor lives under ``research/evidence/`` rather than under
``tools/`` is a wart. Moving it would break T-02's published procedure, so it is
recorded here as a debt instead of fixed silently.)

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. The report is a
record of a timed experiment, so it is *not* reproducible byte for byte: times,
sizes and free-space samples differ between runs by their nature. Everything
that can be stable is -- argv, VM options, analyzer sets, target digests,
containment paths -- and the volatile fields are grouped so a diff can ignore
them.

Standard library only.

CLI
---
    python tools/static/ghidra_import.py --plan
    python tools/static/ghidra_import.py --target <exe> --expect-sha256 <hex> \\
        --stage import-only --out research/evidence/T-05/report.json
    python tools/static/ghidra_import.py --control <dll> --stage all

Exit codes: 0 every selected stage produced a record (including stages whose
record says "exceeded the timeout"); 2 usage error, refused path, digest
mismatch, wrong JDK, or a missing prerequisite -- that is, the cases where no
trustworthy measurement could be started.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
_REPO = os.path.dirname(_TOOLS)
for _extra in (os.path.join(_TOOLS, "inventory"),):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented: pathguard is the single place where "is this path inside the
# game installation" is decided, and this tool asks it two different questions
# (may I write here, may I import from here) using the same root set.
import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/static/ghidra_import.py"
GENERATOR_VERSION = "1.0.0"

QUESTION = (
    "plan.md T-05 / RISK-13: what does a headless Ghidra project for the "
    "134 658 048-byte MISERY-Win64-Shipping.exe cost in wall-clock seconds and "
    "in bytes on disk, measured in stages so the answer is a curve?"
)


# --------------------------------------------------------------------------- #
# environment: where the tools are, and the one JDK that works
# --------------------------------------------------------------------------- #

DEFAULT_GHIDRA_ROOT = r"D:\Tools\ghidra_12.1.3_PUBLIC"
DEFAULT_JDK_HOME = r"D:\Tools\jdk-21"

# Ghidra 12.1.3 dies inside Apache Felix on JDK 25 before any user logic runs
# (plan.md 17.1a / A-15). This is a hard gate, not a warning: a run on the wrong
# JVM measures the cost of a crash.
REQUIRED_JDK_MAJOR = 21

# analyzeHeadless.bat defaults the headless heap to 2G. Left explicit because the
# heap is a variable of the measurement, not a detail: a stage that spends its
# time in garbage collection has been measured under a stated heap or not at all.
DEFAULT_MAXMEM = "4G"


# --------------------------------------------------------------------------- #
# containment: everything Ghidra would otherwise put on C:
# --------------------------------------------------------------------------- #

# The default locations are %APPDATA%\ghidra, %LOCALAPPDATA%\ghidra and %TEMP%,
# all on the system volume, which has 6.3 GiB free (assumption A-14, RISK-13).
DEFAULT_CONTAINMENT_ROOT = r"D:\Tools\ghidra-workspace"

CONTAINMENT_DIRS = (
    # (report key, subdirectory, JVM property)
    ("settings_dir", "ghidra-settings", "application.settingsdir"),
    ("cache_dir", "ghidra-cache", "application.cachedir"),
    ("ghidra_temp_dir", "ghidra-temp", "application.tempdir"),
    ("java_tmpdir", "java-tmp", "java.io.tmpdir"),
)

# Volumes whose free space is sampled for the whole of every stage. C: is the one
# the containment exists to protect; D: is the one that pays.
WATCHED_VOLUMES = ("C:\\", "D:\\")

# How often free space is sampled, in seconds. Fast enough to see a transient
# multi-gigabyte temporary file, slow enough to cost nothing.
DISK_SAMPLE_INTERVAL = 1.0


# --------------------------------------------------------------------------- #
# the analyzer sets
# --------------------------------------------------------------------------- #

# The deliberately minimal set. Chosen for what M2s consumes -- functions,
# strings, cross-references, RTTI (S-03..S-10) -- and excluding the analyzers
# that dominated the control measurement of the default set: the two decompiler
# passes, Stack, the constant-reference analyzer, Function ID and the data-type
# archive application. The names are Ghidra's display names for the analyzers, as
# printed in its own timing table.
#
# This list is a HYPOTHESIS about which analyzers are worth their cost, not a
# finding. It exists to put one measured point between "nothing" and
# "everything"; SetAnalyzerSet.java prints the set it actually applied, so the
# log records the configuration rather than this constant standing in for it.
#
# "Create Function" is deliberately left in even though it is NOT one of the 32
# enablement toggles Ghidra exposes -- it runs regardless of the option state,
# as the control measurement showed. Keeping the name here makes the pre-script
# emit a WARNING line naming it, which is how the log comes to record that fact;
# dropping the name would silence the line and leave the same analyzer running
# unexplained in the timing table.
MINIMAL_ANALYZERS = (
    "ASCII Strings",
    "Create Function",
    "Data Reference",
    "Demangler Microsoft",
    "Disassemble Entry Points",
    "External Entry References",
    "Function Start Search",
    "Reference",
    "Windows x86 PE RTTI Analyzer",
)

PRESCRIPT_NAME = "SetAnalyzerSet.java"
PRESCRIPT_DIR = os.path.join(_HERE, "ghidra_scripts")

# analyzeHeadless.bat and launch.bat pass VM arguments and script arguments
# through cmd.exe string plumbing that is not quoting-safe. A path or an analyzer
# name containing any of these would be silently mangled -- or, with '!', would
# be eaten by delayed expansion -- and a mangled argument produces a measurement
# of a configuration nobody chose. Refused up front with the character named.
CMD_HOSTILE_CHARS = ' !%^&()"'


# --------------------------------------------------------------------------- #
# the stages
# --------------------------------------------------------------------------- #

# Per-stage defaults. `soft_timeout` becomes -analysisTimeoutPerFile, which stops
# analysis but still saves the program, so a stage that hits it yields both a
# time bound AND a measured project size. `hard_timeout` is the backstop that
# kills the process tree; it is deliberately larger, so the soft limit is the one
# that normally fires.
STAGES: dict[str, dict] = {
    "import-only": {
        "description": (
            "import with -noanalysis: load, language selection, PE parse and "
            "database write, with every analyzer off. The floor of the cost curve."
        ),
        "analysis": False,
        "analyzers": None,
        "soft_timeout": None,
        "hard_timeout": 3600,
    },
    "minimal-analysis": {
        "description": (
            "import plus a deliberately minimal analyzer set applied by "
            "SetAnalyzerSet.java: functions, strings, references, RTTI."
        ),
        "analysis": True,
        "analyzers": MINIMAL_ANALYZERS,
        "soft_timeout": 3600,
        "hard_timeout": 4500,
    },
    "default-analysis": {
        "description": (
            "import plus Ghidra's default analyzer set, unchanged. What an "
            "unthinking -import costs."
        ),
        "analysis": True,
        "analyzers": None,
        "soft_timeout": 7200,
        "hard_timeout": 8100,
    },
}

STAGE_ORDER = ("import-only", "minimal-analysis", "default-analysis")

# Project names are per stage and per target role, so no two measurements share a
# directory and each size reading belongs to exactly one configuration.
PROJECT_PREFIX = "T05"

DEFAULT_PROJECT_ROOT = r"D:\Tools\ghidra-projects"
DEFAULT_RAW_LOG_DIR = os.path.join(_REPO, "workspace", "T-05")
DEFAULT_EVIDENCE_DIR = os.path.join(_REPO, "research", "evidence", "T-05")

REDACTOR_PATH = os.path.join(_REPO, "research", "evidence", "T-02", "redact-log.py")

# Read in 8 MiB blocks: the primary target is 128 MiB and hashing it should not
# be a memory event.
HASH_CHUNK = 8 << 20


class PrerequisiteError(Exception):
    """A precondition of the measurement is not met, so nothing was started."""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def sha256_file(path: str) -> str:
    """Digest a file, reading it and nothing else. Opened read-only."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(HASH_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def significant(value: float, digits: int = 6) -> float:
    """Round to *digits* significant figures rather than decimal places.

    The derived ratios in this report span many orders of magnitude: project
    bytes per target byte is a number like 30 for a heavily analysed image and
    like 0.00003 for a fixture. Rounding to a fixed number of DECIMAL places
    turns the small end into 0.0 -- which is not a rounded number, it is a wrong
    one, and it was written that way here until a test caught it.
    """
    if value == 0 or not (value == value) or value in (float("inf"),
                                                       float("-inf")):
        return float(value)
    import math
    exponent = math.floor(math.log10(abs(value)))
    return round(value, -(exponent - (digits - 1)))


def cmd_hostile_char(value: str) -> str | None:
    """The first character of *value* the batch plumbing would mangle, or None."""
    for char in value:
        if char in CMD_HOSTILE_CHARS:
            return char
    return None


def require_cmd_safe(value: str, what: str) -> str:
    """Refuse a value the batch launcher cannot carry intact.

    This is a real constraint of the thing being wrapped, not a stylistic one:
    ``analyzeHeadless.bat`` interpolates its arguments into unquoted cmd.exe
    variables. Discovering that at parse time with the offending character named
    is much cheaper than discovering it from a Ghidra error four minutes into a
    134 MB import -- or, worse, not discovering it at all because the run
    "succeeded" with a truncated argument.
    """
    bad = cmd_hostile_char(value)
    if bad is not None:
        raise PrerequisiteError(
            "%s contains the character %r, which analyzeHeadless.bat and "
            "launch.bat cannot pass through intact (they interpolate arguments "
            "into unquoted cmd.exe variables, and '!' is additionally consumed by "
            "delayed expansion). Value: %s. Choose a path or a name without any of "
            "%r." % (what, bad, value, CMD_HOSTILE_CHARS)
        )
    return value


def directory_usage(path: str) -> dict:
    """Total bytes, file count and directory count under *path*.

    Apparent size is summed, not allocated size: the number that matters for
    RISK-13 is how much of the volume the project occupies, and on NTFS without
    compression those agree closely enough that the difference is not what
    decides whether a full-image analysis is affordable. Unreadable entries are
    counted as errors rather than skipped silently, because a size reading with
    unexplained holes in it is not a size reading.
    """
    total = 0
    files = 0
    dirs = 0
    errors: list[str] = []
    if not os.path.exists(path):
        return {"path": path, "exists": False, "bytes": 0, "files": 0,
                "dirs": 0, "errors": []}
    if os.path.isfile(path):
        try:
            return {"path": path, "exists": True, "bytes": os.path.getsize(path),
                    "files": 1, "dirs": 0, "errors": []}
        except OSError as error:
            return {"path": path, "exists": True, "bytes": 0, "files": 0,
                    "dirs": 0, "errors": ["%s: %s" % (path, error)]}

    for root, subdirs, names in os.walk(path, onerror=lambda e: errors.append(str(e))):
        dirs += len(subdirs)
        for name in names:
            full = os.path.join(root, name)
            try:
                total += os.path.getsize(full)
                files += 1
            except OSError as error:
                errors.append("%s: %s" % (full, error))
    return {"path": path, "exists": True, "bytes": total, "files": files,
            "dirs": dirs, "errors": errors}


def project_usage(project_root: str, project_name: str) -> dict:
    """Bytes a Ghidra project occupies: the ``.gpr`` file plus the ``.rep`` tree.

    Both halves are reported separately because they answer different questions:
    the ``.rep`` directory is the database and is where the gigabytes would be,
    and the ``.gpr`` is bookkeeping. A total that hid the split would make a
    surprising number harder to explain.
    """
    gpr = os.path.join(project_root, project_name + ".gpr")
    rep = os.path.join(project_root, project_name + ".rep")
    gpr_usage = directory_usage(gpr)
    rep_usage = directory_usage(rep)
    return {
        "project_root": project_root,
        "project_name": project_name,
        "gpr": gpr_usage,
        "rep": rep_usage,
        "bytes": gpr_usage["bytes"] + rep_usage["bytes"],
        "files": gpr_usage["files"] + rep_usage["files"],
        "exists": gpr_usage["exists"] or rep_usage["exists"],
    }


# --------------------------------------------------------------------------- #
# free-space sampling -- the check that C: was really protected
# --------------------------------------------------------------------------- #

class FreeSpaceSampler:
    """Samples free space on the watched volumes for the life of a stage.

    The point is not telemetry. The containment configuration in
    :func:`build_vm_options` is a *claim* that Ghidra's large temporary files
    landed on D:, and the only way to check a claim about a transient file is to
    look while it exists. A minimum-free reading on C: that is indistinguishable
    from the before-and-after readings is evidence for the claim; a dip of
    several gigabytes would refute it, and the tool would then be reporting a
    problem rather than concealing one.
    """

    def __init__(self, volumes: tuple[str, ...] = WATCHED_VOLUMES,
                 interval: float = DISK_SAMPLE_INTERVAL) -> None:
        self.volumes = volumes
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: dict[str, list[int]] = {v: [] for v in volumes}
        self._unreadable: dict[str, str] = {}

    def _read(self) -> None:
        for volume in self.volumes:
            try:
                self._samples[volume].append(shutil.disk_usage(volume).free)
            except OSError as error:
                self._unreadable.setdefault(volume, str(error))

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._read()

    def start(self) -> "FreeSpaceSampler":
        self._read()                     # the "before" sample
        self._thread = threading.Thread(target=self._loop, name="freespace",
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval * 5)
        self._read()                     # the "after" sample
        report: dict = {}
        for volume in self.volumes:
            series = self._samples[volume]
            if not series:
                report[volume] = {"unreadable": self._unreadable.get(volume,
                                                                     "no samples")}
                continue
            report[volume] = {
                "free_before_bytes": series[0],
                "free_after_bytes": series[-1],
                "free_min_bytes": min(series),
                "free_max_bytes": max(series),
                "consumed_peak_bytes": series[0] - min(series),
                "samples": len(series),
                "sample_interval_seconds": self.interval,
            }
            if volume in self._unreadable:
                report[volume]["unreadable_note"] = self._unreadable[volume]
        return report


# --------------------------------------------------------------------------- #
# prerequisites: the JDK, Ghidra, the pre-script
# --------------------------------------------------------------------------- #

_JAVA_VERSION_RE = re.compile(r'version "(?P<full>(?P<major>\d+)[^"]*)"')


def parse_java_major(text: str) -> tuple[int | None, str | None]:
    """Major version and full version string from ``java -version`` output.

    ``java -version`` writes to stderr and its format is a third-party
    behaviour, so the parse is deliberately narrow: the quoted version string
    and nothing else. An unparseable banner returns (None, None) and the caller
    refuses to run -- an unidentified JVM is exactly the condition A-15 says
    produces a crash before any user logic.
    """
    match = _JAVA_VERSION_RE.search(text or "")
    if not match:
        return None, None
    try:
        return int(match.group("major")), match.group("full")
    except ValueError:
        return None, match.group("full")


def probe_jdk(jdk_home: str, *, required_major: int = REQUIRED_JDK_MAJOR) -> dict:
    """Verify the pinned JDK, or raise.

    Pinning by path and then *checking* is not belt-and-braces pedantry here:
    ``launch.properties`` in the Ghidra installation also names a JDK, PATH on
    this machine begins with a Java 8 JRE, and JDK 25 makes Ghidra abort inside
    Apache Felix. Three ways to end up on the wrong JVM, one of which produces a
    stack trace that looks nothing like a version problem.
    """
    java = os.path.join(jdk_home, "bin", "java.exe")
    if not os.path.isfile(java):
        java_posix = os.path.join(jdk_home, "bin", "java")
        if os.path.isfile(java_posix):
            java = java_posix
        else:
            raise PrerequisiteError(
                "no java executable under the pinned JDK home: %s (looked for "
                "bin\\java.exe and bin/java). JDK %d is required (plan.md 17.1a / "
                "A-15: Ghidra 12.1.3 crashes on JDK 25 inside Apache Felix)."
                % (jdk_home, required_major))
    try:
        completed = subprocess.run([java, "-version"], capture_output=True,
                                   text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise PrerequisiteError("cannot run %s -version: %s" % (java, error))

    banner = (completed.stderr or "") + (completed.stdout or "")
    major, full = parse_java_major(banner)
    if major is None:
        raise PrerequisiteError(
            "cannot parse a version out of the output of %s -version, so the JVM "
            "is unidentified and the run is refused. First line was: %s"
            % (java, (banner.splitlines() or ["<empty>"])[0]))
    if major != required_major:
        raise PrerequisiteError(
            "pinned JDK at %s reports major version %d (%s), but %d is required. "
            "plan.md 17.1a / A-15: Ghidra 12.1.3 aborts inside Apache Felix on "
            "JDK 25 before any user logic runs, so a measurement on the wrong JVM "
            "would time the crash. Nothing was started."
            % (jdk_home, major, full, required_major))
    return {"java_home": jdk_home, "java_executable": java,
            "version": full, "major": major,
            "banner_first_line": (banner.splitlines() or [""])[0].strip()}


def locate_analyze_headless(ghidra_root: str) -> str:
    """Path to ``support/analyzeHeadless(.bat)``, or raise."""
    for name in ("analyzeHeadless.bat", "analyzeHeadless"):
        candidate = os.path.join(ghidra_root, "support", name)
        if os.path.isfile(candidate):
            return candidate
    raise PrerequisiteError(
        "no analyzeHeadless launcher under %s\\support. This tool is a wrapper "
        "around that launcher and has no fallback: reimplementing import and "
        "analysis would measure our cost instead of Ghidra's."
        % ghidra_root)


def ghidra_version(ghidra_root: str) -> dict:
    """Read ``Ghidra/application.properties`` -- what the installation says it is.

    Recorded because a cost measurement is only reusable if the reader knows
    which build produced it, and because re-running T-02's smoke test is a
    documented obligation on any Ghidra upgrade.
    """
    path = os.path.join(ghidra_root, "Ghidra", "application.properties")
    fields: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()
    except OSError as error:
        return {"install_dir": ghidra_root, "properties_path": path,
                "unreadable": str(error)}
    return {
        "install_dir": ghidra_root,
        "properties_path": path,
        "application_name": fields.get("application.name"),
        "application_version": fields.get("application.version"),
        "release_name": fields.get("application.release.name"),
        "build_date": fields.get("application.build.date"),
    }


# --------------------------------------------------------------------------- #
# the copy discipline (plan.md 1.5 layer 2 / D-01)
# --------------------------------------------------------------------------- #

def check_import_path(import_path: str, install_root: str | None,
                      *, repo_root: str | None = None) -> str:
    """Return the resolved import path, or raise if it is inside an installation.

    ``pathguard.check_output_path`` answers "may I write here". This answers "may
    Ghidra *open* this", which for Ghidra is the same question: the importer
    opens its input read-write, so an import from the installation is a write to
    the installation. The protected-root set is pathguard's, deliberately: two
    opinions about where the game lives is exactly the drift that module's
    docstring warns about.
    """
    resolved = pathguard.resolve_real(import_path)
    key = os.path.normcase(resolved)
    for source, root in pathguard.protected_roots(install_root, out_path=resolved,
                                                  repo_root=repo_root):
        if key == os.path.normcase(root) or key.startswith(
                os.path.normcase(root).rstrip("\\/") + os.sep):
            raise pathguard.OutputPathRefused(
                "refusing to import from inside the game installation: \"%s\" "
                "resolves to %s, which is inside the installation root %s "
                "(protected because: %s). Ghidra opens the file it imports "
                "READ-WRITE, so this is a write to a read-only research target "
                "(plan.md decision D-01; safety model 1.5 layer 2 requires a "
                "copy). Nothing was started. Copy the file under "
                "D:\\Tools\\ghidra-workspace and import the copy."
                % (str(import_path), resolved, root, source))
    return resolved


def prepare_copy(source: str, destination: str, expected_sha256: str | None,
                 *, install_root: str | None = None,
                 repo_root: str | None = None) -> dict:
    """Copy *source* to *destination* if needed and verify the digest.

    The digest check is the whole point and it is done on the *copy*, after the
    copy, every time -- including when the copy already existed. A copy made in
    an earlier session, on a disk that has been full, is exactly the artifact
    that should not be trusted on the strength of its filename.

    A mismatch raises. There is no flag to proceed anyway: a measurement of the
    wrong bytes is worse than no measurement, because it looks like one.
    """
    checked_destination = pathguard.check_output_path(
        destination, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what="analysis copy", repo_root=repo_root)
    require_cmd_safe(checked_destination, "the analysis copy path")

    if not os.path.isfile(source):
        raise PrerequisiteError("target does not exist or is not a file: %s" % source)

    parent = os.path.dirname(checked_destination)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    source_bytes = os.path.getsize(source)
    reused = False
    copy_seconds = 0.0
    if (os.path.isfile(checked_destination)
            and os.path.getsize(checked_destination) == source_bytes):
        reused = True
    else:
        started = time.monotonic()
        shutil.copyfile(source, checked_destination)
        copy_seconds = time.monotonic() - started

    digest = sha256_file(checked_destination)
    record = {
        "source": source,
        "copy": checked_destination,
        "bytes": os.path.getsize(checked_destination),
        "sha256": digest,
        "sha256_expected": expected_sha256,
        "sha256_matches": (expected_sha256 is None
                           or digest.lower() == expected_sha256.lower()),
        "reused_existing_copy": reused,
        "copy_seconds": round(copy_seconds, 3),
    }
    if not record["sha256_matches"]:
        raise PrerequisiteError(
            "sha256 mismatch on the analysis copy: %s hashes to %s but %s was "
            "expected. Either the copy is stale or the source is not the build "
            "this measurement claims to be about. Refusing to import it -- a "
            "measurement of the wrong bytes is worse than none, because it looks "
            "like one." % (checked_destination, digest, expected_sha256))

    # Belt and braces: even a verified copy must not be inside an installation.
    check_import_path(checked_destination, install_root, repo_root=repo_root)
    return record


# --------------------------------------------------------------------------- #
# building the invocation
# --------------------------------------------------------------------------- #

def containment_paths(root: str) -> dict[str, str]:
    """The four redirected directories, keyed by report key."""
    return {key: os.path.join(root, sub) for key, sub, _prop in CONTAINMENT_DIRS}


def build_vm_options(root: str, *, maxmem: str = DEFAULT_MAXMEM) -> list[str]:
    """JVM properties that keep Ghidra's large state off the system volume.

    Order is stable so two runs produce comparable argv records. The values are
    validated for cmd-hostile characters here rather than at use, because this is
    the function a caller overriding the containment root will reach for.
    """
    paths = containment_paths(root)
    options: list[str] = []
    for key, _sub, prop in CONTAINMENT_DIRS:
        value = paths[key]
        require_cmd_safe(value, "containment directory %s (-D%s)" % (key, prop))
        options.append("-D%s=%s" % (prop, value))
    if maxmem:
        require_cmd_safe(maxmem, "--maxmem")
    return options


def ensure_containment(root: str, *, install_root: str | None = None,
                       repo_root: str | None = None) -> dict:
    """Create the redirected directories, guarding every path.

    They must exist before the JVM starts: ``java.io.tmpdir`` pointing at a
    missing directory does not fail loudly, it falls back, and a silent fallback
    to ``%TEMP%`` on C: would defeat the whole containment while the report
    happily recorded the intended value.
    """
    created: dict[str, str] = {}
    for key, value in containment_paths(root).items():
        checked = pathguard.check_output_path(
            value, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what="containment directory %s" % key, repo_root=repo_root)
        os.makedirs(checked, exist_ok=True)
        created[key] = checked
    return created


def build_environment(jdk_home: str, vm_options: list[str], *,
                      maxmem: str = DEFAULT_MAXMEM,
                      base: dict[str, str] | None = None) -> dict[str, str]:
    """The child environment: pinned JDK, contained state, stated heap.

    ``GHIDRA_HEADLESS_JAVA_OPTIONS`` is the documented hook in
    ``analyzeHeadless.bat``; ``launch.bat`` places it last on the java command
    line, after the properties from ``launch.properties``, so these values win.
    ``JAVA_HOME`` and the PATH prefix cover the *bootstrap* java that runs
    ``LaunchSupport`` -- without them that step uses whatever is first on PATH,
    which on this machine is a Java 8 JRE.
    """
    env = dict(os.environ if base is None else base)
    env["JAVA_HOME"] = jdk_home
    env["PATH"] = os.path.join(jdk_home, "bin") + os.pathsep + env.get("PATH", "")
    env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = " ".join(vm_options)
    env["GHIDRA_HEADLESS_MAXMEM"] = maxmem
    return env


def project_name_for(stage: str, target_role: str) -> str:
    """A distinct project per (stage, target), so no size reading is shared."""
    return "%s-%s-%s" % (PROJECT_PREFIX, target_role, stage)


def build_argv(launcher: str, project_root: str, project_name: str,
               import_path: str, stage: str, *,
               prescript_dir: str = PRESCRIPT_DIR,
               soft_timeout: int | None = None) -> list[str]:
    """The analyzeHeadless command line for one stage.

    ``-deleteProject`` is never passed. It would delete the project after the
    run, and the project size is half of what is being measured; deletion is this
    tool's own step, after the measurement, through a guarded path.
    """
    if stage not in STAGES:
        raise PrerequisiteError(
            "unknown stage %r; known stages are %s"
            % (stage, ", ".join(STAGE_ORDER)))
    spec = STAGES[stage]

    argv = [launcher, project_root, project_name, "-import", import_path]

    if not spec["analysis"]:
        argv.append("-noanalysis")
    else:
        analyzers = spec["analyzers"]
        if analyzers:
            for name in analyzers:
                require_cmd_safe(name.replace(" ", "_"), "analyzer name %r" % name)
            require_cmd_safe(prescript_dir, "--prescript-dir")
            argv += ["-scriptPath", prescript_dir,
                     "-preScript", PRESCRIPT_NAME, ";".join(analyzers)]
        budget = spec["soft_timeout"] if soft_timeout is None else soft_timeout
        if budget:
            argv += ["-analysisTimeoutPerFile", str(int(budget))]
    return argv


# --------------------------------------------------------------------------- #
# running one stage
# --------------------------------------------------------------------------- #

def kill_process_tree(pid: int) -> str:
    """Kill *pid* and its descendants; return a note about how it went.

    Killing the launcher alone is not enough on Windows: ``analyzeHeadless.bat``
    is a batch file that runs java as a child, and terminating cmd.exe leaves the
    JVM alive, still writing to the project and still holding its lock. The next
    stage would then measure a directory somebody else is writing to.
    """
    try:
        completed = subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                                   capture_output=True, text=True, timeout=120)
        return "taskkill /T /F exited %d" % completed.returncode
    except (OSError, subprocess.SubprocessError) as error:
        return "taskkill failed: %s" % error


def run_process(argv: list[str], env: dict[str, str], timeout: int) -> dict:
    """Run *argv*, capturing stdout and stderr interleaved into one stream.

    Interleaved on purpose: analyzeHeadless writes its log lines to one stream
    and some warnings to the other, and the order between them is information
    about what happened when. Two separate captures would lose it.
    """
    started = time.monotonic()
    handle = subprocess.Popen(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env, text=True,
                              encoding="utf-8", errors="replace")
    timed_out = False
    kill_note = None
    try:
        output, _ = handle.communicate(timeout=timeout)
        exit_code = handle.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_note = kill_process_tree(handle.pid)
        try:
            output, _ = handle.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            handle.kill()
            output, _ = handle.communicate()
        exit_code = handle.returncode
    elapsed = time.monotonic() - started
    return {
        "exit_code": exit_code,
        "output": output or "",
        "wall_clock_seconds": round(elapsed, 3),
        "timed_out": timed_out,
        "kill_note": kill_note,
    }


_ANALYZER_TIME_RE = re.compile(r"^\s{2,}(?P<name>\S.*?)\s{2,}(?P<secs>[\d.]+) secs\s*$")
_TOTAL_TIME_RE = re.compile(r"^\s*Total Time\s+(?P<secs>\d+)\s+secs\s*$")

# Ghidra ends every log line with the emitting class in parentheses, e.g.
# "... (HeadlessAnalyzer)" or "... (GhidraScript)". It is noise inside an
# extracted value -- an analyzer name that carries "(GhidraScript)" on the end
# will not compare equal to the same analyzer name from anywhere else, and the
# report would then contain two spellings of one analyzer. Only a trailing
# single-token group is removed, so a name that legitimately contains
# parentheses (there is one: the TEB analyzer) keeps them.
_LOGGER_SUFFIX_RE = re.compile(r"\s*\([A-Za-z_][A-Za-z0-9_.$]*\)\s*$")


def strip_logger_suffix(line: str) -> str:
    return _LOGGER_SUFFIX_RE.sub("", line).strip()


def parse_ghidra_report(output: str) -> dict:
    """Pull the facts Ghidra states about itself out of its own log.

    Kept strictly to lines Ghidra prints. The per-analyzer table and
    ``Total Time`` are Ghidra's own accounting and are a useful independent
    reading against our wall clock -- they exclude JVM startup, class search and
    the final save, so the two numbers *should* differ, and the size of the gap
    is itself informative about where the time goes.

    ``total_time_seconds`` of None does not mean the parse failed. Ghidra prints
    the table only when analysis took at least a second: the control target's
    minimal-analysis stage finished under that threshold and printed no table at
    all, while its default-analysis stage printed one. A None here therefore
    means "Ghidra reported no table", which for a fast stage is the truth.
    """
    analyzers: dict[str, float] = {}
    total = None
    reports: list[str] = []
    prescript: list[str] = []
    warnings = 0
    errors = 0
    for line in (output or "").splitlines():
        stripped = line.rstrip()
        match = _TOTAL_TIME_RE.match(stripped)
        if match:
            total = int(match.group("secs"))
            continue
        match = _ANALYZER_TIME_RE.match(stripped)
        if match and "secs" in stripped:
            try:
                analyzers[match.group("name").strip()] = float(match.group("secs"))
            except ValueError:
                pass
            continue
        if "REPORT:" in stripped:
            reports.append(strip_logger_suffix(stripped.split("REPORT:", 1)[1]))
        if "SETANALYZERSET:" in stripped:
            prescript.append(strip_logger_suffix(
                stripped.split("SETANALYZERSET:", 1)[1]))
        if stripped.startswith("WARN "):
            warnings += 1
        if stripped.startswith("ERROR ") or stripped.startswith("SEVERE "):
            errors += 1
    enabled = sorted(item.split("=", 1)[1] for item in prescript
                     if item.startswith("enabled="))
    return {
        "analyzer_seconds": analyzers,
        "analyzer_count": len(analyzers),
        "total_time_seconds": total,
        "report_lines": reports,
        "warn_lines": warnings,
        "error_lines": errors,
        "prescript_lines": len(prescript),
        "prescript_enabled_analyzers": enabled,
        "prescript_enabled_count": len(enabled) if prescript else None,
        "analysis_succeeded_line": any(line.startswith("Analysis succeeded")
                                       for line in reports),
        "import_succeeded_line": any(line.startswith("Import succeeded")
                                     for line in reports),
    }


def load_redactor(path: str = REDACTOR_PATH):
    """Load the C-13 redactor from T-02 by file path.

    Its filename contains a hyphen, so it is not importable by module name; and
    it lives under ``research/evidence/T-02/`` because T-02's published
    reproduction procedure names that path. Copying its rules here would give the
    repository two privacy filters that drift apart, which is the failure mode
    ``pathguard``'s docstring is written about. Debt, recorded rather than
    papered over: the redactor should eventually move under ``tools/`` with
    T-02's procedure updated in the same change.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("t02_redact_log", path)
    if spec is None or spec.loader is None:
        raise PrerequisiteError("cannot load the C-13 redactor from %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "redact"):
        raise PrerequisiteError(
            "%s does not expose redact(); refusing to write a log into a public "
            "repository without it (C-13)." % path)
    return module


_RESIDUAL_PROFILE_RE = re.compile(r"[A-Za-z]:[\\/]Users[\\/]")


def redact_log(text: str, redactor) -> tuple[str, int]:
    """Redacted text and the count of literal profile paths still in it.

    The residual count is returned rather than raised on, so the caller decides.
    The caller in this tool refuses to write the file: a log with a live profile
    path in it is a C-13 violation whether or not the run that produced it went
    well.
    """
    redacted = redactor.redact(text).replace("\r\n", "\n").replace("\r", "\n")
    return redacted, len(_RESIDUAL_PROFILE_RE.findall(redacted))


def write_text(text: str, out_path: str, install_root: str | None, what: str,
               *, repo_root: str | None = None) -> str:
    """Write *text* to *out_path*, refusing any path inside an installation."""
    target = pathguard.check_output_path(
        out_path, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what=what, repo_root=repo_root)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def classify_outcome(result: dict, project: dict, soft_timeout: int | None,
                     parsed: dict) -> str:
    """One word for what the stage did. A timeout is a result, not a failure.

    The distinction between the two timeout outcomes matters for planning:
    ``soft-timeout-analysis-aborted`` still leaves a saved, measurable project
    and a partially analysed program, whereas ``hard-timeout-process-killed``
    leaves a project of unknown consistency and a size reading that may be a
    snapshot of a half-written database.
    """
    if result["timed_out"]:
        return "hard-timeout-process-killed"
    if result["exit_code"] != 0:
        return "nonzero-exit"
    if (soft_timeout is not None and parsed["total_time_seconds"] is not None
            and parsed["total_time_seconds"] >= soft_timeout):
        return "soft-timeout-analysis-aborted"
    if not project["exists"]:
        return "completed-no-project-on-disk"
    return "completed"


def run_stage(stage: str, target: dict, *, launcher: str, project_root: str,
              env: dict[str, str], vm_options: list[str],
              raw_log_dir: str, evidence_dir: str | None,
              redactor, install_root: str | None = None,
              repo_root: str | None = None,
              hard_timeout: int | None = None,
              soft_timeout: int | None = None,
              keep_project: bool = False,
              prescript_dir: str = PRESCRIPT_DIR,
              containment_root: str | None = None,
              runner=run_process) -> dict:
    """Run one stage against one target and return its record.

    *runner* is injected so the report shape can be exercised without a real
    134 MB analysis: the tests drive this function with a fake runner that
    returns canned analyzeHeadless output. That is the only reason the seam
    exists -- there is no production alternative runner, and adding one would
    mean this tool had started to reimplement analysis.
    """
    spec = STAGES[stage]
    effective_soft = spec["soft_timeout"] if soft_timeout is None else soft_timeout
    effective_hard = spec["hard_timeout"] if hard_timeout is None else hard_timeout
    name = project_name_for(stage, target["role"])

    checked_project_root = pathguard.check_output_path(
        project_root, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what="--project-root", repo_root=repo_root)
    require_cmd_safe(checked_project_root, "--project-root")
    os.makedirs(checked_project_root, exist_ok=True)

    argv = build_argv(launcher, checked_project_root, name, target["copy"], stage,
                      prescript_dir=prescript_dir, soft_timeout=effective_soft)

    started_at = now_iso_utc()
    sampler = FreeSpaceSampler().start()
    try:
        result = runner(argv, env, effective_hard)
    finally:
        disk = sampler.stop()

    parsed = parse_ghidra_report(result["output"])
    project = project_usage(checked_project_root, name)
    outcome = classify_outcome(result, project, effective_soft, parsed)

    # The raw capture stays outside git (C-13); only the redacted form may be
    # committed, and only if the redaction left nothing behind.
    slug = "%s-%s" % (target["role"], stage)
    raw_path = write_text(result["output"],
                          os.path.join(raw_log_dir, "raw-%s.log" % slug),
                          install_root, "raw log", repo_root=repo_root)
    log_record = {
        "raw_path": raw_path,
        "raw_bytes": len(result["output"].encode("utf-8")),
        "raw_sha256": sha256_text(result["output"]),
    }
    redacted, residual = redact_log(result["output"], redactor)
    log_record["redaction_residual_profile_paths"] = residual
    if evidence_dir is None:
        log_record["redacted_path"] = None
        log_record["redacted_note"] = "no evidence directory given; nothing committed"
    elif residual:
        log_record["redacted_path"] = None
        log_record["redacted_note"] = (
            "REFUSED to write the redacted log: %d literal profile path(s) "
            "survived redaction, which would be a C-13 violation in a public "
            "repository. The raw capture is outside git at the path above."
            % residual)
    else:
        redacted_path = write_text(
            redacted, os.path.join(evidence_dir, "%s.log" % slug),
            install_root, "redacted log", repo_root=repo_root)
        log_record["redacted_path"] = redacted_path
        log_record["redacted_bytes"] = len(redacted.encode("utf-8"))
        log_record["redacted_sha256"] = sha256_text(redacted)

    record = {
        "stage": stage,
        "description": spec["description"],
        "target_role": target["role"],
        "target_copy": target["copy"],
        "target_bytes": target["bytes"],
        "target_sha256": target["sha256"],
        "project": project,
        "project_kept": keep_project,
        "analysis_enabled": spec["analysis"],
        "analyzers_requested": list(spec["analyzers"]) if spec["analyzers"] else None,
        "soft_analysis_timeout_seconds": effective_soft,
        "hard_process_timeout_seconds": effective_hard,
        "argv": argv,
        "vm_options": list(vm_options),
        "started_at": started_at,
        "wall_clock_seconds": result["wall_clock_seconds"],
        "exit_code": result["exit_code"],
        "timed_out_hard": result["timed_out"],
        "kill_note": result.get("kill_note"),
        "outcome": outcome,
        "ghidra_reported": parsed,
        "disk": disk,
        "log": log_record,
    }

    # The redirected directories are measured AFTER the stage, because the first
    # 134 MB run showed that the project directory is not where the bytes are
    # while the work is happening: 753 MiB sat in the redirected temp directory
    # mid-analysis while the .rep was still 4 KiB, because Ghidra writes the
    # database at save time. A report that gave only the final project size would
    # therefore understate the transient footprint by orders of magnitude -- and
    # the transient footprint is the thing RISK-13 is about, since it is what
    # would have filled C:.
    if containment_root:
        record["containment_usage_after"] = {
            key: directory_usage(value)
            for key, value in containment_paths(containment_root).items()
        }
    if target["bytes"]:
        record["seconds_per_megabyte"] = significant(
            result["wall_clock_seconds"] / (target["bytes"] / (1 << 20)))
        if project["bytes"]:
            record["project_bytes_per_target_byte"] = significant(
                project["bytes"] / target["bytes"])

    if not keep_project and project["exists"]:
        record["project_deleted"] = delete_project(
            checked_project_root, name, install_root=install_root,
            repo_root=repo_root)
    return record


def delete_project(project_root: str, project_name: str, *,
                   install_root: str | None = None,
                   repo_root: str | None = None) -> dict:
    """Remove a measured project, after its size has been recorded.

    Deleting by default is a disk-safety decision, not tidiness: three projects
    for a 134 MB image could plausibly outweigh the free space this measurement
    exists to protect, and the size has already been read by the time this runs.
    The path goes through the output guard even though it is a delete -- the
    guard's protected-root set is the repository's one answer to "is this inside
    the installation", and a delete inside the installation is the worst
    imaginable outcome of a tool like this.
    """
    removed: list[str] = []
    errors: list[str] = []
    for suffix in (".rep", ".gpr", ".lock", ".lock~"):
        path = os.path.join(project_root, project_name + suffix)
        if not os.path.exists(path):
            continue
        try:
            checked = pathguard.check_output_path(
                path, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="project deletion", repo_root=repo_root)
        except (pathguard.OutputPathRefused, ValueError) as error:
            errors.append(str(error))
            continue
        try:
            if os.path.isdir(checked):
                shutil.rmtree(checked)
            else:
                os.remove(checked)
            removed.append(checked)
        except OSError as error:
            errors.append("%s: %s" % (checked, error))
    return {"removed": removed, "errors": errors}


# --------------------------------------------------------------------------- #
# the report
# --------------------------------------------------------------------------- #

def build_document(*, targets: list[dict], stages: list[dict],
                   jdk: dict, ghidra: dict, containment: dict,
                   vm_options: list[str], maxmem: str,
                   notes: list[str] | None = None) -> dict:
    """Assemble the report. Shape is stable; the numbers are not, by nature."""
    return {
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": now_iso_utc(),
        "question": QUESTION,
        "task": "plan.md T-05 (method S-02), risk RISK-13, M2s exit criterion 3",
        "what_this_measures": (
            "wall-clock seconds and bytes on disk for a headless Ghidra import "
            "and analysis, per stage, per target. It measures COST and nothing "
            "about the contents of the binary."
        ),
        "environment": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(),
            "jdk": jdk,
            "ghidra": ghidra,
            "headless_maxmem": maxmem,
        },
        "containment": {
            "why": (
                "Ghidra's default settings, cache and temp locations are all on "
                "the system volume, which has ~6.3 GiB free (A-14, RISK-13). All "
                "four are redirected onto D: via GHIDRA_HEADLESS_JAVA_OPTIONS, "
                "which launch.bat places last on the java command line so it "
                "overrides support\\launch.properties."
            ),
            "directories": containment,
            "vm_options": list(vm_options),
            "not_redirected": (
                "the file LaunchSupport writes to remember which JDK was chosen: "
                "launch.bat invokes LaunchSupport without our VM arguments, so it "
                "uses the default settings directory. A few hundred bytes."
            ),
            "verification": (
                "free space on every watched volume is sampled about once a second "
                "for the whole of each stage; per-stage disk.free_min_bytes is the "
                "measurement that says whether C: was really protected."
            ),
        },
        "targets": targets,
        "stages": stages,
        "notes": list(notes or []),
    }


def format_bytes(value: int | None) -> str:
    if value is None:
        return "n/a"
    if value < 1024:
        return "%d B" % value
    for unit, scale in (("KiB", 1 << 10), ("MiB", 1 << 20), ("GiB", 1 << 30)):
        if value < scale * 1024 or unit == "GiB":
            return "%.2f %s" % (value / scale, unit)
    return "%d B" % value


def format_summary(document: dict) -> str:
    lines: list[str] = []
    lines.append("T-05 Ghidra cost measurement (%s %s)"
                 % (document["generator"], document["generator_version"]))
    env = document["environment"]
    lines.append("  JDK      : %s (major %s)"
                 % (env["jdk"].get("version"), env["jdk"].get("major")))
    lines.append("  Ghidra   : %s %s"
                 % (env["ghidra"].get("application_name"),
                    env["ghidra"].get("application_version")))
    lines.append("  heap     : %s   cpus: %s"
                 % (env["headless_maxmem"], env["cpu_count"]))

    lines.append("")
    lines.append("targets")
    for target in document["targets"]:
        lines.append("  %-8s %s  %s  sha256 %s%s"
                     % (target["role"], format_bytes(target["bytes"]),
                        os.path.basename(target["copy"]), target["sha256"][:16],
                        "" if target["sha256_matches"] else "  DIGEST MISMATCH"))

    lines.append("")
    header = ("  %-8s %-17s %10s %12s %10s %10s %s"
              % ("target", "stage", "wall s", "project", "C: dip", "D: dip",
                 "outcome"))
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for stage in document["stages"]:
        disk = stage.get("disk", {})
        c_dip = disk.get("C:\\", {}).get("consumed_peak_bytes")
        d_dip = disk.get("D:\\", {}).get("consumed_peak_bytes")
        lines.append("  %-8s %-17s %10.1f %12s %10s %10s %s"
                     % (stage["target_role"], stage["stage"],
                        stage["wall_clock_seconds"],
                        format_bytes(stage["project"]["bytes"]),
                        format_bytes(c_dip), format_bytes(d_dip),
                        stage["outcome"]))
        reported = stage["ghidra_reported"]
        if reported["total_time_seconds"] is not None:
            lines.append("           ghidra Total Time %d s over %d analyzers"
                         % (reported["total_time_seconds"],
                            reported["analyzer_count"]))
        if reported["prescript_enabled_count"] is not None:
            lines.append("           pre-script left %d analyzers enabled"
                         % reported["prescript_enabled_count"])
        if stage["exit_code"] != 0 or stage["timed_out_hard"]:
            lines.append("           exit_code %s  timed_out_hard %s"
                         % (stage["exit_code"], stage["timed_out_hard"]))

    if document["notes"]:
        lines.append("")
        lines.append("notes")
        for note in document["notes"]:
            lines.append("  * %s" % note)
    return "\n".join(lines)


def format_plan(stages: list[str], targets: list[dict], launcher: str,
                project_root: str, vm_options: list[str]) -> str:
    """What --plan prints: every command, and nothing run.

    A dry run exists because the cheapest measurement mistake to fix is the one
    caught before a multi-hour stage starts, and because the tests need the
    command line without a Ghidra installation.
    """
    lines = ["planned invocations (nothing was run)"]
    for option in vm_options:
        lines.append("  vmarg %s" % option)
    for target in targets:
        for stage in stages:
            spec = STAGES[stage]
            name = project_name_for(stage, target["role"])
            argv = build_argv(launcher, project_root, name, target["copy"], stage)
            lines.append("")
            lines.append("  %s / %s  (hard timeout %d s, soft %s)"
                         % (target["role"], stage, spec["hard_timeout"],
                            spec["soft_timeout"]))
            lines.append("    " + " ".join(
                arg if " " not in arg else '"%s"' % arg for arg in argv))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghidra_import.py",
        description=(
            "Measure the wall-clock time and disk cost of a headless Ghidra "
            "project, in stages (plan.md T-05, method S-02, risk RISK-13). "
            "Imports a COPY of the target -- never the installation -- and "
            "refuses any output path inside a game installation (D-01)."),
    )
    parser.add_argument("--target", default=None,
                        help="primary target to measure (a copy is made first)")
    parser.add_argument("--expect-sha256", default=None, metavar="HEX",
                        help=("sha256 the copy must have; a mismatch aborts before "
                              "anything is imported"))
    parser.add_argument("--control", default=None,
                        help=("a small file measured through the same stages, so "
                              "the large numbers have something to scale from"))
    parser.add_argument("--control-expect-sha256", default=None, metavar="HEX",
                        help="sha256 the control copy must have")
    parser.add_argument("--stage", action="append", default=None,
                        metavar="NAME",
                        help=("stage to run; repeatable. One of %s, or 'all'. "
                              "Default: import-only"
                              % ", ".join(STAGE_ORDER)))
    parser.add_argument("--ghidra-root", default=DEFAULT_GHIDRA_ROOT,
                        help="Ghidra installation directory")
    parser.add_argument("--jdk-home", default=DEFAULT_JDK_HOME,
                        help=("JDK to pin; its major version must be %d "
                              "(plan.md 17.1a / A-15)" % REQUIRED_JDK_MAJOR))
    parser.add_argument("--project-root", default=DEFAULT_PROJECT_ROOT,
                        help="where Ghidra projects are created")
    parser.add_argument("--copy-dir", default=os.path.join(
                            DEFAULT_CONTAINMENT_ROOT, "bin"),
                        help="where the analysis copies live")
    parser.add_argument("--containment-root", default=DEFAULT_CONTAINMENT_ROOT,
                        help=("root of the redirected settings/cache/temp "
                              "directories that keep Ghidra off C:"))
    parser.add_argument("--raw-log-dir", default=DEFAULT_RAW_LOG_DIR,
                        help="where unredacted captures go (must stay out of git)")
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR,
                        help="where redacted logs and the report go")
    parser.add_argument("--no-evidence", action="store_true",
                        help="do not write redacted logs anywhere")
    parser.add_argument("--maxmem", default=DEFAULT_MAXMEM,
                        help="headless JVM heap (GHIDRA_HEADLESS_MAXMEM)")
    parser.add_argument("--hard-timeout", type=int, default=None, metavar="SEC",
                        help="override the per-stage hard process timeout")
    parser.add_argument("--soft-timeout", type=int, default=None, metavar="SEC",
                        help="override -analysisTimeoutPerFile")
    parser.add_argument("--keep-project", action="store_true",
                        help=("keep each project after measuring it; by default "
                              "projects are deleted once their size is recorded, "
                              "to bound disk use"))
    parser.add_argument("--install-dir", default=None,
                        help="installation root the path guards check against")
    parser.add_argument("--out", default=None,
                        help="write the JSON report here")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON report instead of the summary")
    parser.add_argument("--plan", action="store_true",
                        help=("print the invocations and exit without running "
                              "anything or touching Ghidra"))
    parser.add_argument("--note", action="append", default=None, metavar="TEXT",
                        help="free-text note recorded in the report; repeatable")
    return parser


def resolve_stages(values: list[str] | None) -> list[str]:
    """Stage names in canonical order, de-duplicated. 'all' expands."""
    if not values:
        return ["import-only"]
    wanted: set[str] = set()
    for value in values:
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            if part == "all":
                wanted.update(STAGE_ORDER)
            elif part in STAGES:
                wanted.add(part)
            else:
                raise PrerequisiteError(
                    "unknown stage %r; known stages are %s, or 'all'"
                    % (part, ", ".join(STAGE_ORDER)))
    return [name for name in STAGE_ORDER if name in wanted]


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    install_root = args.install_dir

    try:
        stages = resolve_stages(args.stage)
        if not args.target and not args.control:
            raise PrerequisiteError(
                "nothing to measure: give --target and/or --control")

        # Layer 1 first, before anything is created or opened, so a refused path
        # costs nothing and leaves nothing behind.
        for flag, value in (("--out", args.out),
                            ("--raw-log-dir", args.raw_log_dir),
                            ("--evidence-dir",
                             None if args.no_evidence else args.evidence_dir)):
            if value:
                pathguard.check_output_path(
                    value, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
                    what=flag)

        vm_options = build_vm_options(args.containment_root, maxmem=args.maxmem)

        targets: list[dict] = []
        if args.target:
            record = prepare_copy(
                args.target,
                os.path.join(args.copy_dir, os.path.basename(args.target)),
                args.expect_sha256, install_root=install_root)
            record["role"] = "primary"
            targets.append(record)
        if args.control:
            record = prepare_copy(
                args.control,
                os.path.join(args.copy_dir, os.path.basename(args.control)),
                args.control_expect_sha256, install_root=install_root)
            record["role"] = "control"
            targets.append(record)

        if args.plan:
            print(format_plan(stages, targets,
                              os.path.join(args.ghidra_root, "support",
                                           "analyzeHeadless.bat"),
                              args.project_root, vm_options))
            return 0

        launcher = locate_analyze_headless(args.ghidra_root)
        jdk = probe_jdk(args.jdk_home)
        ghidra = ghidra_version(args.ghidra_root)
        containment = ensure_containment(args.containment_root,
                                         install_root=install_root)
        redactor = load_redactor()
        env = build_environment(args.jdk_home, vm_options, maxmem=args.maxmem)
    except PrerequisiteError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except (pathguard.OutputPathRefused, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    # Control first when both are present: it is seconds rather than hours, and a
    # broken configuration should be found on the cheap target.
    ordered = sorted(targets, key=lambda t: 0 if t["role"] == "control" else 1)

    records: list[dict] = []
    for target in ordered:
        for stage in stages:
            try:
                records.append(run_stage(
                    stage, target, launcher=launcher,
                    project_root=args.project_root, env=env,
                    vm_options=vm_options, raw_log_dir=args.raw_log_dir,
                    evidence_dir=None if args.no_evidence else args.evidence_dir,
                    redactor=redactor, install_root=install_root,
                    hard_timeout=args.hard_timeout,
                    soft_timeout=args.soft_timeout,
                    containment_root=args.containment_root,
                    keep_project=args.keep_project))
            except (pathguard.OutputPathRefused, PrerequisiteError) as error:
                print("error: %s / %s: %s" % (target["role"], stage, error),
                      file=sys.stderr)
                return 2
            except OSError as error:
                print("error: %s / %s: %s" % (target["role"], stage, error),
                      file=sys.stderr)
                return 2
            # Print as we go: a stage can take an hour, and a report that only
            # exists at the end is a report that a Ctrl-C destroys.
            print("done: %s / %s -> %s in %.1f s, project %s"
                  % (target["role"], stage, records[-1]["outcome"],
                     records[-1]["wall_clock_seconds"],
                     format_bytes(records[-1]["project"]["bytes"])),
                  file=sys.stderr)

    document = build_document(targets=targets, stages=records, jdk=jdk,
                              ghidra=ghidra, containment=containment,
                              vm_options=vm_options, maxmem=args.maxmem,
                              notes=args.note)

    written = None
    if args.out:
        try:
            written = write_text(dump_json(document), args.out, install_root,
                                 "--out")
        except (pathguard.OutputPathRefused, OSError) as error:
            print("error: cannot write report: %s" % error, file=sys.stderr)
            return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        print(format_summary(document))
        if written:
            print("\nwritten: %s" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
